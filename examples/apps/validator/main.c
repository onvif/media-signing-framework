/**
 * MIT License
 *
 * Copyright (c) 2025 ONVIF. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph)
 * shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * This application validates the authenticity of a video from a file. The result is
 * written on screen and in addition, a summary is written to the file
 * validation_results.txt.
 *
 * Supported video codecs are H26x and the recording should be either an .mp4, or a .mkv
 * file. Other formats may also work, but have not been tested.
 *
 * Example to validate the authenticity of an h264 video stored in file.mp4
 *   $ ./validator -c h264 /path/to/file.mp4
 */

#include <glib.h>
#include <gst/app/gstappsink.h>
#include <gst/gst.h>
#include <stdio.h>  // FILE, fopen, fclose
#include <string.h>  // strcpy, strcat, strcmp, strlen
#include <time.h>  // time_t, struct tm, strftime, gmtime

#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_helpers.h"
#include "includes/onvif_media_signing_validator.h"

#define RESULTS_FILE "validation_results.txt"

#ifndef ATTR_UNUSED
#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
#endif

typedef struct {
  GMainLoop *loop;
  GstElement *source;
  GstElement *sink;

  onvif_media_signing_t *oms;
  onvif_media_signing_authenticity_t *auth_report;
  onvif_media_signing_vendor_info_t *vendor_info;
  char *version_on_signing_side;
  char *this_version;
  bool batch_run;
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

/* Helper function to copy onvif_media_signing_vendor_info_t. */
static void
copy_vendor_info(onvif_media_signing_vendor_info_t *dst,
    const onvif_media_signing_vendor_info_t *src)
{
  if (!src || !dst)
    return;

  // Reset strings
  strcpy(dst->firmware_version, src->firmware_version);
  strcpy(dst->serial_number, src->serial_number);
  strcpy(dst->manufacturer, src->manufacturer);
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

/* Called when the appsink notifies us that there is a new buffer ready for processing. */
static GstFlowReturn
on_new_sample_from_sink(GstElement *elt, ValidationData *data)
{
  g_assert(elt != NULL);

  GstFlowReturn ret_val = GST_FLOW_OK;
  GstAppSink *sink = GST_APP_SINK(elt);
  GstSample *sample = NULL;
  GstBuffer *buffer = NULL;
  GstMapInfo info;
  MediaSigningReturnCode status = OMS_UNKNOWN_FAILURE;
  onvif_media_signing_authenticity_t **auth_report =
      data->batch_run ? NULL : &(data->auth_report);

  // Check if there are samples available
  if (gst_app_sink_is_eos(sink)) {
    g_debug("Reached EOS or pipline is not running");
    goto out;
  }
  // Get the sample from appsink.
  sample = gst_app_sink_pull_sample(sink);
  // If sample is NULL the appsink is stopped or EOS is reached. Both are valid, hence
  // proceed.
  if (sample == NULL) {
    goto out;
  }

  buffer = gst_sample_get_buffer(sample);

  if ((buffer == NULL) || (gst_buffer_n_memory(buffer) == 0)) {
    g_debug("no buffer, or no memories in buffer");
    goto out_no_buffer;
  }

  for (guint i = 0; i < gst_buffer_n_memory(buffer); i++) {
    GstMemory *mem = gst_buffer_peek_memory(buffer, i);
    if (!gst_memory_map(mem, &info, GST_MAP_READ)) {
      gst_memory_unmap(mem, &info);
      g_debug("failed to map memory");
      ret_val = GST_FLOW_ERROR;
      goto error_memory_map;
    }

    // At this point |info.data| includes a complete NAL of size |info.size|. If the input
    // is encoded video that is NOT put in a container format like mp4 or mkv, the
    // |info.data| includes the start code. For videos within a container format the start
    // code bytes are often replaced by size bytes.
    //
    // Each NAL is added to the ONVIF Media Signing session through the API
    // onvif_media_signing_add_nalu_and_authenticate(...)
    // It is possible to get an authenticity report from the session every time validation
    // of a GOP (partial or multiple) has been performed.

    // Update the total video and SEI sizes.
    data->total_bytes += info.size;
    data->sei_bytes +=
        onvif_media_signing_is_sei(data->oms, info.data, info.size) > 0 ? info.size : 0;

    if (data->no_container) {
      status = onvif_media_signing_add_nalu_and_authenticate(
          data->oms, info.data, info.size, auth_report);
    } else {
      // Pass nalu to the signed video session, excluding 4 bytes start code, since it
      // might have been replaced by the size of buffer.
      // TODO: First, a check for 3 or 4 byte start code should be done.
      status = onvif_media_signing_add_nalu_and_authenticate(
          data->oms, info.data + 4, info.size - 4, auth_report);
    }
    if (status != OMS_OK) {
      g_critical("error during verification of signed video: %d", status);
      GstBus *bus = gst_element_get_bus(elt);
      post_validation_result_message(sink, bus, VALIDATION_ERROR);
      gst_object_unref(bus);
    } else if (!data->batch_run && *auth_report) {
      // Print intermediate validation if not running in batch mode.
      gsize str_size = 1;  // starting with a new-line character to align strings
      str_size += STR_PREFACE_SIZE;
      str_size += strlen((*auth_report)->latest_validation.validation_str);
      str_size += 1;  // new-line character
      str_size += STR_PREFACE_SIZE;
      str_size += strlen((*auth_report)->latest_validation.nalu_str);
      str_size += 1;  // null-terminated
      gchar *result = g_malloc0(str_size);
      strcpy(result, "\n");
      strcat(result, NALU_TYPES_PREFACE);
      strcat(result, (*auth_report)->latest_validation.nalu_str);
      strcat(result, "\n");
      switch ((*auth_report)->latest_validation.authenticity) {
        case OMS_AUTHENTICITY_OK:
          data->valid_gops++;
          strcat(result, VALIDATION_VALID);
          break;
        case OMS_AUTHENTICITY_NOT_OK:
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
      strcat(result, (*auth_report)->latest_validation.validation_str);
      GstBus *bus = gst_element_get_bus(elt);
      post_validation_result_message(sink, bus, result);
      gst_object_unref(bus);
      // Allocate memory for |vendor_info| the first time it will be copied from the
      // authenticity report.
      if (!data->vendor_info) {
        data->vendor_info = g_malloc0(sizeof(onvif_media_signing_vendor_info_t));
      }
      copy_vendor_info(data->vendor_info, &((*auth_report)->vendor_info));
      // Allocate memory and copy camera version string.
      if (!data->version_on_signing_side &&
          (strlen((*auth_report)->version_on_signing_side) > 0)) {
        data->version_on_signing_side =
            g_malloc0(strlen((*auth_report)->version_on_signing_side) + 1);
        if (!data->version_on_signing_side) {
          g_warning("failed allocating memory for version_on_signing_side");
        } else {
          strcpy(data->version_on_signing_side, (*auth_report)->version_on_signing_side);
        }
      }
      g_free(result);
    }
    if (auth_report && *auth_report) {
      onvif_media_signing_authenticity_report_free(*auth_report);
      *auth_report = NULL;
    }
    gst_memory_unmap(mem, &info);
  }

error_memory_map:
out_no_buffer:
  gst_sample_unref(sample);
out:
  return ret_val;
}

/* Called when a GstMessage is received from the source pipeline. */
static gboolean
on_source_message(GstBus ATTR_UNUSED *bus, GstMessage *message, ValidationData *data)
{
  FILE *f = NULL;
  gchar *this_version = data->this_version;
  gchar *signing_version = data->version_on_signing_side;
  gchar first_ts_str[80] = {'\0'};
  gchar last_ts_str[80] = {'\0'};
  gfloat bitrate_increase = 0.0f;
  gboolean end_loop = false;

  if (data->total_bytes) {
    bitrate_increase =
        100.0f * data->sei_bytes / (float)(data->total_bytes - data->sei_bytes);
  }

  switch (GST_MESSAGE_TYPE(message)) {
    case GST_MESSAGE_EOS:
      data->auth_report = onvif_media_signing_get_authenticity_report(data->oms);
      if (!data->auth_report) {
        g_debug("No authenticity report produced by Media Signing");
        end_loop = true;
        break;
      }
      if (data->auth_report->accumulated_validation.last_timestamp) {
        time_t first_sec =
            data->auth_report->accumulated_validation.first_timestamp / 1000000;
        struct tm first_ts = *gmtime(&first_sec);
        strftime(
            first_ts_str, sizeof(first_ts_str), "%a %Y-%m-%d %H:%M:%S %Z", &first_ts);
        time_t last_sec =
            data->auth_report->accumulated_validation.last_timestamp / 1000000;
        struct tm last_ts = *gmtime(&last_sec);
        strftime(last_ts_str, sizeof(last_ts_str), "%a %Y-%m-%d %H:%M:%S %Z", &last_ts);
      }
      g_debug("received EOS");
      f = fopen(RESULTS_FILE, "w");
      if (!f) {
        g_warning("Could not open %s for writing", RESULTS_FILE);
        end_loop = true;
        break;
      }
      fprintf(f, "-----------------------------\n");
      if (data->auth_report->accumulated_validation.provenance == OMS_PROVENANCE_NOT_OK) {
        fprintf(f, "PUBLIC KEY IS NOT VALID!\n");
      } else if (data->auth_report->accumulated_validation.provenance ==
          OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED) {
        fprintf(f, "PUBLIC KEY VERIFIABLE WITHOUT TRUSTED CERT!\n");
      } else if (data->auth_report->accumulated_validation.provenance ==
          OMS_PROVENANCE_OK) {
        fprintf(f, "PUBLIC KEY IS VALID!\n");
      } else {
        fprintf(f, "PUBLIC KEY COULD NOT BE VALIDATED!\n");
      }
      fprintf(f, "-----------------------------\n");
      if (data->batch_run) {
        onvif_media_signing_accumulated_validation_t *acc_validation =
            &(data->auth_report->accumulated_validation);
        if (acc_validation->authenticity == OMS_NOT_SIGNED) {
          fprintf(f, "VIDEO IS NOT SIGNED!\n");
        } else if (acc_validation->authenticity == OMS_AUTHENTICITY_NOT_OK) {
          fprintf(f, "VIDEO IS INVALID!\n");
        } else if (acc_validation->authenticity ==
            OMS_AUTHENTICITY_OK_WITH_MISSING_INFO) {
          fprintf(f, "VIDEO IS VALID, BUT HAS MISSING FRAMES!\n");
        } else if (acc_validation->authenticity == OMS_AUTHENTICITY_OK) {
          fprintf(f, "VIDEO IS VALID!\n");
        } else {
          fprintf(f, "PUBLIC KEY COULD NOT BE VALIDATED!\n");
        }
        fprintf(f, "Number of received NAL Units : %u\n",
            acc_validation->number_of_received_nalus);
        fprintf(f, "Number of validated NAL Units: %u\n",
            acc_validation->number_of_validated_nalus);
        fprintf(f, "Number of pending NAL Units  : %u\n",
            acc_validation->number_of_pending_nalus);
      } else {
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
      }
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nVendor Info\n");
      fprintf(f, "-----------------------------\n");
      onvif_media_signing_vendor_info_t *vendor_info =
          data->batch_run ? &(data->auth_report->vendor_info) : data->vendor_info;
      if (vendor_info) {
        fprintf(f, "Serial Number:    %s\n",
            strlen(vendor_info->serial_number) > 0 ? vendor_info->serial_number : "N/A");
        fprintf(f, "Firmware version: %s\n", vendor_info->firmware_version);
        fprintf(f, "Manufacturer:     %s\n", vendor_info->manufacturer);
      } else {
        fprintf(f, "NOT PRESENT!\n");
      }
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nMedia Signing timestamps\n");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "First frame:           %s\n",
          strlen(first_ts_str) > 0 ? first_ts_str : "N/A");
      fprintf(f, "Last validated frame:  %s\n",
          strlen(last_ts_str) > 0 ? last_ts_str : "N/A");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nMedia Signing size footprint\n");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "Total video:       %8zu B\n", data->total_bytes);
      fprintf(f, "Media Signing data: %7zu B\n", data->sei_bytes);
      fprintf(f, "Bitrate increase: %9.2f %%\n", bitrate_increase);
      fprintf(f, "-----------------------------\n");
      fprintf(f, "\nVersions of media-signing-framework\n");
      fprintf(f, "-----------------------------\n");
      fprintf(f, "Validator runs: %s\n", this_version);
      fprintf(
          f, "Camera runs:             %s\n", signing_version ? signing_version : "N/A");
      fprintf(f, "-----------------------------\n");
      fclose(f);
      if (data->batch_run) {
        this_version = data->auth_report->this_version;
        signing_version = data->auth_report->version_on_signing_side;
        g_message("Validation performed in batch mode");
      }
      g_message("Validation performed with Media Signing version %s", this_version);
      if (signing_version) {
        g_message("Signing was performed with Media Signing version %s", signing_version);
      }
      g_message("Validation complete. Results printed to '%s'.", RESULTS_FILE);
      onvif_media_signing_authenticity_report_free(data->auth_report);
      data->auth_report = NULL;
      end_loop = true;
      break;
    case GST_MESSAGE_ERROR:
      g_debug("received error");
      end_loop = true;
      break;
    case GST_MESSAGE_ELEMENT: {
#if 1
      const GstStructure *s = gst_message_get_structure(message);
      if (strcmp(gst_structure_get_name(s), VALIDATION_STRUCTURE_NAME) == 0) {
        const gchar *result = gst_structure_get_string(s, VALIDATION_FIELD_NAME);
        g_message("Latest authenticity result:\t%s", result);
      }
#endif
    } break;
    default:
      break;
  }

  if (end_loop) {
    g_main_loop_quit(data->loop);
  }

  return TRUE;
}

onvif_media_signing_t *
setup_media_signing(MediaSigningCodec codec, const char *cert_filename)
{
  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  if (!oms) {
    goto out;
  }
  if (!cert_filename || strlen(cert_filename) == 0) {
    g_message("No trusted certificate set.");
    goto out;
  }

  // Add trusted certificate to signing session.
  char *trusted_certificate = NULL;
  size_t trusted_certificate_size = 0;
  bool success = false;
  if (strcmp(cert_filename, "test") == 0) {
    // Read pre-generated test trusted certificate.
    success = oms_read_test_trusted_certificate(
        &trusted_certificate, &trusted_certificate_size);
  } else {
    // Read trusted CA certificate.
    FILE *fp = fopen(cert_filename, "rb");
    if (!fp) {
      goto ca_file_done;
    }

    fseek(fp, 0L, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);
    if (file_size == 0) {
      goto ca_file_done;
    }
    trusted_certificate = g_malloc0(file_size);
    fread(trusted_certificate, sizeof(char), file_size / sizeof(char), fp);
    trusted_certificate_size = file_size;

    success = true;

  ca_file_done:
    if (!fp) {
      fclose(fp);
    }
  }
  if (success) {
    if (onvif_media_signing_set_trusted_certificate(
            oms, trusted_certificate, trusted_certificate_size, false) != OMS_OK) {
      g_message("Failed setting trusted certificate. Validating without one.");
    }
  } else {
    g_message("Failed reading trusted certificate. Validating without one.");
  }
  g_free(trusted_certificate);
out:
  return oms;
}

int
main(int argc, char **argv)
{
  int status = 1;
  int arg = 1;
  MediaSigningCodec codec = -1;
  ValidationData *data = NULL;
  GError *error = NULL;
  GstBus *bus = NULL;
  GstElement *validatorsink = NULL;

  bool batch_run = false;
  gchar *codec_str = "h264";
  gchar *demux_str = "";  // No container by default
  gchar *CAfilename = NULL;
  gchar *filename = NULL;
  gchar *pipeline = NULL;
  gchar *usage = g_strdup_printf(
      "Usage:\n%s [-h] [-b] [-c codec] [-C CAfilename] filename\n\n"
      "Optional\n"
      "  -h, --help    : This usage print.\n"
      "  -c codec      : 'h264' (default if omitted) or 'h265'.\n"
      "  -C CAfilename : Location of the trusted CA to use and set. Name 'test' is "
      "reserved and will get the test CA.\n"
      "  -b            : Batch validation, i.e., no intermediate validation results. "
      "Instead one single authenticity report at end\n"
      "Required\n"
      "  filename      : Name of the file to be validated.\n"
      "Output\n"
      "  text file     : A validation report is written to validation_results.txt.\n",
      argv[0]);

  // Parse options from command-line.
  while (arg < argc) {
    if ((strcmp(argv[arg], "-h") == 0) || (strcmp(argv[arg], "--help") == 0)) {
      g_message("\n%s\n", usage);
      status = 0;
      goto out_at_once;
    } else if (strcmp(argv[arg], "-c") == 0) {
      arg++;
      codec_str = argv[arg];
    } else if (strcmp(argv[arg], "-C") == 0) {
      arg++;
      CAfilename = argv[arg];
    } else if (strcmp(argv[arg], "-b") == 0) {
      batch_run = true;
    } else if (strncmp(argv[arg], "-", 1) == 0) {
      // Unknown option.
      g_message("Unknown option: %s\n%s", argv[arg], usage);
      goto out_at_once;
    } else {
      // End of options.
      break;
    }
    arg++;
  }

  // Parse filename.
  if (arg + 1 < argc) {
    g_warning("options specified after filename\n%s", usage);
    goto out_at_once;
  }
  if (arg < argc) {
    filename = argv[arg];
  }
  if (!filename) {
    g_warning("no filename was specified\n%s", usage);
    goto out_at_once;
  }

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
    goto out_at_once;
  }

  if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
    pipeline = g_strdup_printf(
        "filesrc location=\"%s\" %s ! %sparse ! "
        "video/x-%s,stream-format=byte-stream,alignment=(string)nal ! appsink "
        "name=validatorsink",
        filename, demux_str, codec_str, codec_str);
  } else {
    // TODO: Turn to warning when signer can generate outputs.
    g_message("file '%s' does not exist", filename);
    goto out_at_once;
  }
  g_message("GST pipeline: %s", pipeline);

  // Initialization.
  if (!gst_init_check(NULL, NULL, &error)) {
    g_warning("gst_init failed: %s", error->message);
    goto error_gst_init;
  }

  data = g_new0(ValidationData, 1);
  // Initialize data.
  data->valid_gops = 0;
  data->valid_gops_with_missing = 0;
  data->invalid_gops = 0;
  data->no_sign_gops = 0;
  data->no_container = (strlen(demux_str) == 0);
  data->batch_run = batch_run;
  data->codec = codec;
  data->this_version = g_malloc0(strlen(onvif_media_signing_get_version()) + 1);
  strcpy(data->this_version, onvif_media_signing_get_version());
  // Create an ONVIF Media Session for this codec.
  data->oms = setup_media_signing(codec, CAfilename);
  if (!data->oms) {
    g_error("Could not create Media Signing session");
    goto error_oms_create;
  }
  data->loop = g_main_loop_new(NULL, FALSE);
  data->source = gst_parse_launch(pipeline, NULL);
  if (!data->source) {
    g_error("Failed creating the gStreamer pipeline");
    goto error_pipeline;
  }

  // To be notified of messages from this pipeline; error, EOS and live validation.
  bus = gst_element_get_bus(data->source);
  if (!bus) {
    g_error("Pipeline has no bus");
    goto error_bus;
  }
  guint event_id = gst_bus_add_watch(bus, (GstBusFunc)on_source_message, data);
  if (event_id == 0) {
    gst_object_unref(bus);
    g_error("Failed to add watch to bus");
    goto error_add_watch;
  }
  gst_object_unref(bus);
  bus = NULL;

  // Use appsink in push mode. It sends a signal when data is available and pulls out the
  // data in the signal callback. Set the appsink to push as fast as possible, hence set
  // sync=false.
  validatorsink = gst_bin_get_by_name(GST_BIN(data->source), "validatorsink");
  if (!validatorsink) {
    g_error("Failed getting 'validatorsink' from pipeline");
    goto error_validatorsink;
  }
  g_object_set(G_OBJECT(validatorsink), "emit-signals", TRUE, "sync", FALSE, NULL);
  g_signal_connect(
      validatorsink, "new-sample", G_CALLBACK(on_new_sample_from_sink), data);
  gst_object_unref(validatorsink);

  // Launching things.
  GstStateChangeReturn state_change =
      gst_element_set_state(data->source, GST_STATE_PLAYING);
  if (state_change == GST_STATE_CHANGE_FAILURE) {
    // Check if there is an error message with details on the bus.
    bus = gst_element_get_bus(data->source);
    GstMessage *msg = gst_bus_pop_filtered(bus, GST_MESSAGE_ERROR);
    gst_object_unref(bus);
    if (msg) {
      gst_message_parse_error(msg, &error, NULL);
      g_printerr("Failed to start up source: %s", error->message);
      gst_message_unref(msg);
    } else {
      g_error("Failed to start up source!");
    }
    goto error_set_playing;
  } else if (state_change == GST_STATE_CHANGE_ASYNC) {
    GstState state;
    state_change = gst_element_get_state(data->source, &state, NULL, GST_CLOCK_TIME_NONE);
    if (state_change != GST_STATE_CHANGE_SUCCESS) {
      g_error("GOT WRONG STATES!");
      goto error_set_playing;
    }
  }

  // Let's run!
  // This loop will quit when the sink pipeline goes EOS or when an error occurs in sink
  // pipelines.
  g_main_loop_run(data->loop);

  state_change = gst_element_set_state(data->source, GST_STATE_NULL);
  if (state_change == GST_STATE_CHANGE_FAILURE) {
    g_message("Failed to stop pipeline!");
    // Check if there is an error message with details on the bus.
    bus = gst_pipeline_get_bus(GST_PIPELINE(data->source));
    GstMessage *msg = gst_bus_poll(bus, GST_MESSAGE_ERROR, 0);
    gst_object_unref(bus);
    if (msg) {
      gst_message_parse_error(msg, &error, NULL);
      g_printerr("Failed to stop pipeline: %s", error->message);
      gst_message_unref(msg);
    } else {
      g_error("No message on the bus");
    }
    g_main_loop_quit(data->loop);
    goto error_set_stop_state;
  } else if (state_change == GST_STATE_CHANGE_ASYNC) {
    GstState state;
    state_change = gst_element_get_state(data->source, &state, NULL, GST_CLOCK_TIME_NONE);
    if (state_change != GST_STATE_CHANGE_SUCCESS) {
      g_main_loop_quit(data->loop);
      g_error("GOT WRONG STATES!");
      goto error_set_stop_state;
    }
  }

  status = 0;
error_set_stop_state:
  g_free(data->vendor_info);
  g_free(data->version_on_signing_side);
error_set_playing:
  if (error) {
    g_error_free(error);
  }
error_validatorsink:
error_add_watch:
error_bus:
  gst_object_unref(data->source);
error_pipeline:
  g_main_loop_unref(data->loop);
  onvif_media_signing_free(data->oms);  // Free the session
error_oms_create:
  g_free(data->this_version);
  g_free(data);
  gst_deinit();
error_gst_init:
  g_free(pipeline);
out_at_once:
  g_free(usage);

  return status;
}
