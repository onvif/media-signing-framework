/************************************************************************************
 * Copyright (c) 2024 ONVIF.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of ONVIF nor the names of its contributors may be
 *      used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ONVIF BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ************************************************************************************/

/**
 * This application validates the authenticity of a video from a file. The result is
 * written on screen and in addition, a summary is written to the file
 * validation_results.txt.
 *
 * Supported video codecs are H26x and the recording should be either an .mp4, or a .mkv
 * file. Other formats may also work, but have not been tested.
 *
 * Example to validate the authenticity of an h264 video stored in file.mp4
 *   $ ./validator.exe -c h264 /path/to/file.mp4
 */

#include <glib.h>
#include <gst/app/gstappsink.h>
#include <gst/gst.h>

#include "lib/src/includes/onvif_media_signing_common.h"
#include "lib/src/includes/onvif_media_signing_validator.h"
// #include <signed-media-framework/onvif_media_signing_common.h>
// #include <signed-media-framework/onvif_media_signing_validator.h>
#include <stdio.h>  // FILE, fopen, fclose
#include <string.h>  // strcpy, strcat, strcmp, strlen
#include <time.h>  // time_t, struct tm, strftime, gmtime

#define RESULTS_FILE "validation_results.txt"
// Increment VALIDATOR_VERSION when a change is affecting the code.
#define VALIDATOR_VERSION "v0.0.0"  // Requires at least signed-media-framework v0.0.0

typedef struct {
  GMainLoop *loop;
  GstElement *source;
  GstElement *sink;

  onvif_media_signing_t *sv;
  onvif_media_signing_authenticity_t *auth_report;
  onvif_media_signing_product_info_t *product_info;
  char *version_on_signing_side;
  char *this_version;
  bool no_container;
  MediaSigningCodec codec;
  gsize total_bytes;
  gsize sei_bytes;

  gint valid_gops;
  gint valid_gops_with_missing;
  gint invalid_gops;
  gint no_sign_gops;
} ValidationData;

#define STR_PREFACE_SIZE 11  // Largest possible size including " : "
#define VALIDATION_VALID "valid    : "
#define VALIDATION_INVALID "invalid  : "
#define VALIDATION_UNSIGNED "unsigned : "
#define VALIDATION_SIGNED "signed   : "
#define VALIDATION_MISSING "missing  : "
#define VALIDATION_ERROR "error    : "
#define NALU_TYPES_PREFACE "   nalus : "

#define VALIDATION_STRUCTURE_NAME "validation-result"
#define VALIDATION_FIELD_NAME "result"

/* Need to be the same as in signed-media-framework. */
static const uint8_t kUuidONVIFMediaSigning[16] = {0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
    0x20, 0x56, 0x69, 0x64, 0x65, 0x6f, 0x2e, 0x2e, 0x2e, 0x30};

/* Helper function that copies a string and (re)allocates memory if necessary. */
static gint
reallocate_memory_and_copy_string(gchar **dst_str, const gchar *src_str)
{
  if (!dst_str) return 0;
  // If the |src_str| is a NULL pointer make sure to copy an empty string.
  if (!src_str) src_str = "";

  gint success = 0;
  const gsize src_size = strlen(src_str) + 1;
  if (!(*dst_str)) *dst_str = calloc(1, src_size);
  if (!(*dst_str)) goto done;

  gsize dst_size = strlen(*dst_str) + 1;
  if (src_size != dst_size) {
    free(*dst_str);
    *dst_str = NULL;
    gchar *dst_str = calloc(1, src_size);
    if (!(*dst_str)) goto done;
    dst_size = src_size;
  }
  strcpy(*dst_str, src_str);
  success = 1;

done:
  if (!success) {
    free(*dst_str);
    *dst_str = NULL;
  }

  return success;
}

/* Helper function to copy onvif_media_signing_product_info_t. */
static gint
copy_product_info(onvif_media_signing_product_info_t *dst,
    const onvif_media_signing_product_info_t *src)
{
  if (!src) return 0;

  gint success = 0;
  if (!reallocate_memory_and_copy_string(&dst->firmware_version, src->firmware_version))
    goto done;
  if (!reallocate_memory_and_copy_string(&dst->serial_number, src->serial_number))
    goto done;
  if (!reallocate_memory_and_copy_string(&dst->manufacturer, src->manufacturer))
    goto done;

  success = 1;

done:

  return success;
}

static void
post_validation_result_message(GstAppSink *sink, GstBus *bus, const gchar *result)
{
  GstStructure *structure = gst_structure_new(
      VALIDATION_STRUCTURE_NAME, VALIDATION_FIELD_NAME, G_TYPE_STRING, result, NULL);

  if (!gst_bus_post(bus, gst_message_new_element(GST_OBJECT(sink), structure))) {
    g_error("failed to post validation results message");
  }
}

/* Checks if the |nalu| is a SEI generated by Signed Video. */
static bool
is_media_signing_sei(const guint8 *nalu, MediaSigningCodec codec)
{
  int num_zeros = 0;
  int idx = 0;
  bool is_sei_user_data_unregistered = false;

  // Check first (at most) 4 bytes for a start code.
  while (nalu[idx] == 0 && idx < 4) {
    num_zeros++;
    idx++;
  }
  if (num_zeros == 4) {
    // This is simply wrong.
    return false;
  } else if ((num_zeros == 3 || num_zeros == 2) && (nalu[idx] == 1)) {
    // Start code present. Move to next byte.
    idx++;
  } else {
    // Start code NOT present. Assume the first 4 bytes have been replaced with size,
    // which is common in, e.g., gStreamer.
    idx = 4;
  }

  // Determine if this is a SEI of type user data unregistered.
  if (codec == OMS_CODEC_H264) {
    // H.264: 0x06 0x05
    is_sei_user_data_unregistered = (nalu[idx] == 6) && (nalu[idx + 1] == 5);
    idx += 2;
  } else if (codec == OMS_CODEC_H265) {
    // H.265: 0x4e 0x?? 0x05
    is_sei_user_data_unregistered =
        ((nalu[idx] & 0x7e) >> 1 == 39) && (nalu[idx + 2] == 5);
    idx += 3;
  }
  if (!is_sei_user_data_unregistered) return false;

  // Move past payload size
  while (nalu[idx] == 0xff) {
    idx++;
  }
  idx++;

  // Verify Signed Video UUID (16 bytes).
  return memcmp(&nalu[idx], kUuidONVIFMediaSigning, 16) == 0 ? true : false;
}

/* Called when the appsink notifies us that there is a new buffer ready for processing. */
static GstFlowReturn
on_new_sample_from_sink(GstElement *elt, ValidationData *data)
{
  g_assert(elt != NULL);

  GstAppSink *sink = GST_APP_SINK(elt);
  GstSample *sample = NULL;
  GstBuffer *buffer = NULL;
  GstBus *bus = NULL;
  GstMapInfo info;
  MediaSigningReturnCode status = OMS_UNKNOWN_FAILURE;

  // Get the sample from appsink.
  sample = gst_app_sink_pull_sample(sink);
  // If sample is NULL the appsink is stopped or EOS is reached. Both are valid, hence
  // proceed.
  if (sample == NULL) return GST_FLOW_OK;

  buffer = gst_sample_get_buffer(sample);

  if ((buffer == NULL) || (gst_buffer_n_memory(buffer) == 0)) {
    g_debug("no buffer, or no memories in buffer");
    gst_sample_unref(sample);
    return GST_FLOW_ERROR;
  }

  bus = gst_element_get_bus(elt);
  for (guint i = 0; i < gst_buffer_n_memory(buffer); i++) {
    GstMemory *mem = gst_buffer_peek_memory(buffer, i);
    if (!gst_memory_map(mem, &info, GST_MAP_READ)) {
      g_debug("failed to map memory");
      gst_object_unref(bus);
      gst_sample_unref(sample);
      return GST_FLOW_ERROR;
    }

    // Update the total video and SEI sizes.
    data->total_bytes += info.size;
    data->sei_bytes += is_media_signing_sei(info.data, data->codec) ? info.size : 0;

    if (data->no_container) {
      status = onvif_media_signing_add_nalu_and_authenticate(
          data->sv, info.data, info.size, &(data->auth_report));
    } else {
      // Pass nalu to the signed video session, excluding 4 bytes start code, since it
      // might have been replaced by the size of buffer.
      // TODO: First, a check for 3 or 4 byte start code should be done.
      status = onvif_media_signing_add_nalu_and_authenticate(
          data->sv, info.data + 4, info.size - 4, &(data->auth_report));
    }
    if (status != OMS_OK) {
      g_critical("error during verification of signed video: %d", status);
      post_validation_result_message(sink, bus, VALIDATION_ERROR);
    } else if (data->auth_report) {
      gsize str_size = 1;  // starting with a new-line character to align strings
      str_size += STR_PREFACE_SIZE;
      str_size += strlen(data->auth_report->latest_validation.validation_str);
      str_size += 1;  // new-line character
      str_size += STR_PREFACE_SIZE;
      str_size += strlen(data->auth_report->latest_validation.nalu_str);
      str_size += 1;  // null-terminated
      gchar *result = g_malloc0(str_size);
      strcpy(result, "\n");
      strcat(result, NALU_TYPES_PREFACE);
      strcat(result, data->auth_report->latest_validation.nalu_str);
      strcat(result, "\n");
      switch (data->auth_report->latest_validation.authenticity) {
        case OMS_AUTHENTICITY_OK:
          data->valid_gops++;
          strcat(result, VALIDATION_VALID);
          break;
        case OMS_AUTHENTICITY_NOT_OK:
        case OMS_PROVENANCE_NOT_OK:
          data->invalid_gops++;
          strcat(result, VALIDATION_INVALID);
          break;
        case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
          data->valid_gops_with_missing++;
          g_debug("gops with missing info since last verification");
          strcat(result, VALIDATION_MISSING);
          break;
        case OMS_NOT_SIGNED:
          data->no_sign_gops++;
          g_debug("gop is not signed");
          strcat(result, VALIDATION_UNSIGNED);
          break;
        case OMS_AUTHENTICITY_NOT_FEASIBLE:
          g_debug("gop is signed, but not yet validated");
          strcat(result, VALIDATION_SIGNED);
          break;
        default:
          break;
      }
      strcat(result, data->auth_report->latest_validation.validation_str);
      post_validation_result_message(sink, bus, result);
      // Allocate memory for |product_info| the first time it will be copied from the
      // authenticity report.
      if (!data->product_info) {
        data->product_info = (onvif_media_signing_product_info_t *)g_malloc0(
            sizeof(onvif_media_signing_product_info_t));
      }
      if (!copy_product_info(data->product_info, &(data->auth_report->product_info))) {
        g_warning("product info could not be transfered from authenticity report");
      }
      // Allocate memory and copy version strings.
      if (!data->this_version && strlen(data->auth_report->this_version) > 0) {
        data->this_version = g_malloc0(strlen(data->auth_report->this_version) + 1);
        if (!data->this_version) {
          g_warning("failed allocating memory for this_version");
        } else {
          strcpy(data->this_version, data->auth_report->this_version);
        }
      }
      if (!data->version_on_signing_side &&
          (strlen(data->auth_report->version_on_signing_side) > 0)) {
        data->version_on_signing_side =
            g_malloc0(strlen(data->auth_report->version_on_signing_side) + 1);
        if (!data->version_on_signing_side) {
          g_warning("failed allocating memory for version_on_signing_side");
        } else {
          strcpy(
              data->version_on_signing_side, data->auth_report->version_on_signing_side);
        }
      }
      onvif_media_signing_authenticity_report_free(data->auth_report);
      g_free(result);
    }
    gst_memory_unmap(mem, &info);
  }

  gst_object_unref(bus);
  gst_sample_unref(sample);

  return GST_FLOW_OK;
}

/* Called when a GstMessage is received from the source pipeline. */
static gboolean
on_source_message(GstBus __attribute__((unused)) * bus,
    GstMessage *message,
    ValidationData *data)
{
  FILE *f = NULL;
  char *this_version = data->this_version;
  char *signing_version = data->version_on_signing_side;
  char first_ts_str[80] = {'\0'};
  char last_ts_str[80] = {'\0'};
  bool has_timestamp = false;
  float bitrate_increase = 0.0f;

  if (data->total_bytes) {
    bitrate_increase =
        100.0f * data->sei_bytes / (float)(data->total_bytes - data->sei_bytes);
  }

  switch (GST_MESSAGE_TYPE(message)) {
    case GST_MESSAGE_EOS:
      data->auth_report = onvif_media_signing_get_authenticity_report(data->sv);
      if (data->auth_report && data->auth_report->accumulated_validation.last_timestamp) {
        time_t first_sec =
            data->auth_report->accumulated_validation.first_timestamp / 1000000;
        struct tm first_ts = *gmtime(&first_sec);
        strftime(
            first_ts_str, sizeof(first_ts_str), "%a %Y-%m-%d %H:%M:%S %Z", &first_ts);
        time_t last_sec =
            data->auth_report->accumulated_validation.last_timestamp / 1000000;
        struct tm last_ts = *gmtime(&last_sec);
        strftime(last_ts_str, sizeof(last_ts_str), "%a %Y-%m-%d %H:%M:%S %Z", &last_ts);
        has_timestamp = true;
      }
      onvif_media_signing_authenticity_report_free(data->auth_report);
      g_debug("received EOS");
      f = fopen(RESULTS_FILE, "w");
      if (!f) {
        g_warning("Could not open %s for writing", RESULTS_FILE);
        g_main_loop_quit(data->loop);
        return FALSE;
      }
      fprintf(f, "-----------------------------\n");
      if (data->auth_report) {
        if (data->auth_report->accumulated_validation.authenticity ==
            OMS_PROVENANCE_NOT_OK) {
          fprintf(f, "PUBLIC KEY IS NOT VALID!\n");
        } else if (!data->auth_report->accumulated_validation.public_key_has_changed) {
          fprintf(f, "PUBLIC KEY IS VALID!\n");
        } else {
          fprintf(f, "PUBLIC KEY COULD NOT BE VALIDATED!\n");
        }
      } else {
        fprintf(f, "PUBLIC KEY COULD NOT BE VALIDATED!\n");
      }
      fprintf(f, "-----------------------------\n");
      if (data->invalid_gops > 0) {
        fprintf(f, "VIDEO IS INVALID!\n");
      } else if (data->no_sign_gops > 0) {
        fprintf(f, "VIDEO IS NOT SIGNED!\n");
      } else if (data->valid_gops_with_missing > 0) {
        fprintf(f, "VIDEO IS VALID, BUT HAS MISSING FRAMES!\n");
      } else if (data->valid_gops > 0) {
        fprintf(f, "VIDEO IS VALID!\n");
      } else {
        fprintf(f, "NO COMPLETE GOPS FOUND!\n");
      }
      fprintf(f, "Number of valid GOPs: %d\n", data->valid_gops);
      fprintf(f, "Number of valid GOPs with missing NALUs: %d\n",
          data->valid_gops_with_missing);
      fprintf(f, "Number of invalid GOPs: %d\n", data->invalid_gops);
      fprintf(f, "Number of GOPs without signature: %d\n", data->no_sign_gops);
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nProduct Info\n");
      fprintf(f, "-----------------------------\n");
      if (data->product_info) {
        fprintf(f, "Serial Number:    %s\n", data->product_info->serial_number);
        fprintf(f, "Firmware version: %s\n", data->product_info->firmware_version);
        fprintf(f, "Manufacturer:     %s\n", data->product_info->manufacturer);
      } else {
        fprintf(f, "NOT PRESENT!\n");
      }
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nMedia Signing timestamps\n");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "First frame:           %s\n", has_timestamp ? first_ts_str : "N/A");
      fprintf(f, "Last validated frame:  %s\n", has_timestamp ? last_ts_str : "N/A");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nMedia Signing size footprint\n");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "Total video:       %8zu B\n", data->total_bytes);
      fprintf(f, "Media Signing data: %7zu B\n", data->sei_bytes);
      fprintf(f, "Bitrate increase: %9.2f %%\n", bitrate_increase);
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nVersions of signed-media-framework\n");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "Validator (%s) runs: %s\n", VALIDATOR_VERSION,
          this_version ? this_version : "N/A");
      fprintf(
          f, "Camera runs:             %s\n", signing_version ? signing_version : "N/A");
      fprintf(f, "-----------------------------\n");
      fclose(f);
      g_message("Validation performed with Media Signing version %s", this_version);
      if (signing_version) {
        g_message("Signing was performed with Media Signing version %s", signing_version);
      }
      g_message("Validation complete. Results printed to '%s'.", RESULTS_FILE);
      g_main_loop_quit(data->loop);
      break;
    case GST_MESSAGE_ERROR:
      g_debug("received error");
      g_main_loop_quit(data->loop);
      break;
    case GST_MESSAGE_ELEMENT: {
      const GstStructure *s = gst_message_get_structure(message);
      if (strcmp(gst_structure_get_name(s), VALIDATION_STRUCTURE_NAME) == 0) {
        const gchar *result = gst_structure_get_string(s, VALIDATION_FIELD_NAME);
        g_message("Latest authenticity result:\t%s", result);
      }
    } break;
    default:
      break;
  }
  return TRUE;
}

int
main(int argc, char **argv)
{
  int status = 1;
  GError *error = NULL;
  GstElement *validatorsink = NULL;
  GstBus *bus = NULL;
  ValidationData *data = NULL;
  MediaSigningCodec codec = -1;

  int arg = 1;
  gchar *codec_str = "h264";
  gchar *demux_str = "";  // No container by default
  gchar *filename = NULL;
  gchar *pipeline = NULL;
  gchar *usage = g_strdup_printf(
      "Usage:\n%s [-h] [-c codec] filename\n\n"
      "Optional\n"
      "  -c codec  : 'h264' (default) or 'h265'\n"
      "Required\n"
      "  filename  : Name of the file to be validated.\n",
      argv[0]);

  // Initialization.
  if (!gst_init_check(NULL, NULL, &error)) {
    g_warning("gst_init failed: %s", error->message);
    goto out;
  }

  // Parse options from command-line.
  while (arg < argc) {
    if (strcmp(argv[arg], "-h") == 0) {
      g_message("\n%s\n", usage);
      status = 0;
      goto out;
    } else if (strcmp(argv[arg], "-c") == 0) {
      arg++;
      codec_str = argv[arg];
    } else if (strncmp(argv[arg], "-", 1) == 0) {
      // Unknown option.
      g_message("Unknown option: %s\n%s", argv[arg], usage);
    } else {
      // End of options.
      break;
    }
    arg++;
  }

  // Parse filename.
  if (arg < argc) filename = argv[arg];
  if (!filename) {
    g_warning("no filename was specified\n%s", usage);
    goto out;
  }
  g_free(usage);
  usage = NULL;

  // Determine if file is a container
  if (strstr(filename, ".mkv")) {
    // Matroska container (.mkv)
    demux_str = "! matroskademux";
  } else if (strstr(filename, ".mp4")) {
    // MP4 container (.mp4)
    demux_str = "! qtdemux";
  }

  // Set codec.
  if (strcmp(codec_str, "h264") == 0 || strcmp(codec_str, "h265") == 0) {
    codec = (strcmp(codec_str, "h264") == 0) ? OMS_CODEC_H264 : OMS_CODEC_H265;
  } else {
    g_warning("unsupported codec format '%s'", codec_str);
    goto out;
  }

  if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
    pipeline = g_strdup_printf(
        "filesrc location=\"%s\" %s ! %sparse ! "
        "video/x-%s,stream-format=byte-stream,alignment=(string)nal ! appsink "
        "name=validatorsink",
        filename, demux_str, codec_str, codec_str);
  } else {
    g_warning("file '%s' does not exist", filename);
    goto out;
  }
  g_message("GST pipeline: %s", pipeline);

  data = g_new0(ValidationData, 1);
  // Initialize data.
  data->valid_gops = 0;
  data->valid_gops_with_missing = 0;
  data->invalid_gops = 0;
  data->no_sign_gops = 0;
  data->sv = onvif_media_signing_create(codec);
  data->loop = g_main_loop_new(NULL, FALSE);
  data->source = gst_parse_launch(pipeline, NULL);
  data->no_container = (strlen(demux_str) == 0);
  data->codec = codec;
  g_free(pipeline);
  pipeline = NULL;

  if (data->source == NULL || data->loop == NULL || data->sv == NULL) {
    g_message("init failed: source = (%p), loop = (%p), sv = (%p)", data->source,
        data->loop, data->sv);
    goto out;
  }
  // To be notified of messages from this pipeline; error, EOS and live validation.
  bus = gst_element_get_bus(data->source);
  gst_bus_add_watch(bus, (GstBusFunc)on_source_message, data);

  // Use appsink in push mode. It sends a signal when data is available and pulls out the
  // data in the signal callback. Set the appsink to push as fast as possible, hence set
  // sync=false.
  validatorsink = gst_bin_get_by_name(GST_BIN(data->source), "validatorsink");
  g_object_set(G_OBJECT(validatorsink), "emit-signals", TRUE, "sync", FALSE, NULL);
  g_signal_connect(
      validatorsink, "new-sample", G_CALLBACK(on_new_sample_from_sink), data);
  gst_object_unref(validatorsink);

  // Launching things.
  if (gst_element_set_state(data->source, GST_STATE_PLAYING) ==
      GST_STATE_CHANGE_FAILURE) {
    // Check if there is an error message with details on the bus.
    GstMessage *msg = gst_bus_poll(bus, GST_MESSAGE_ERROR, 0);
    if (msg) {
      gst_message_parse_error(msg, &error, NULL);
      g_printerr("Failed to start up source: %s", error->message);
      gst_message_unref(msg);
    } else {
      g_error("Failed to start up source!");
    }
    goto out;
  }

  // Let's run!
  // This loop will quit when the sink pipeline goes EOS or when an error occurs in sink
  // pipelines.
  g_main_loop_run(data->loop);

  gst_element_set_state(data->source, GST_STATE_NULL);

  status = 0;
out:
  // End of session. Free objects.
  if (bus) {
    gst_object_unref(bus);
  }
  g_free(usage);
  g_free(pipeline);
  if (error) g_error_free(error);
  if (data) {
    gst_object_unref(data->source);
    g_main_loop_unref(data->loop);
    onvif_media_signing_free(data->sv);
    g_free(data->product_info);
    g_free(data->this_version);
    g_free(data->version_on_signing_side);
    g_free(data);
  }

  return status;
}
