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
 * This lib has the functions to validate the authenticity of a video from a file.
 * it is working together with the ONVIFPlayer.
 *
 * Supported video codecs are H26x and the recording should be either an .mp4, or a .mkv
 * file. Other formats may also work, but have not been tested.
 *
 */

#include "includes/onvif_validator.h"

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
#define RESULTS_FILES_COUNT 2
#define RESULTS_FILE_NAME_LENGTH 1024
// Increment VALIDATOR_VERSION when a change is affecting the code.
#define VALIDATOR_VERSION "v0.0.0"  // Requires at least signed-media-framework v0.0.0

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
  bool bulk_run;
  bool no_container;
  MediaSigningCodec codec;
  gsize total_bytes;
  gsize sei_bytes;

  gint valid_gops;
  gint valid_gops_with_missing;
  gint invalid_gops;
  gint no_sign_gops;

  // Path to several files where to store results and different validation information
  char results_file_names_array[RESULTS_FILES_COUNT][RESULTS_FILE_NAME_LENGTH];
} ValidationData;

ValidationResult *validation_result = NULL;

ValidationCallback validation_callback_ptr = NULL;

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
static const uint8_t kUuidONVIFMediaSigning[16] = {0x00, 0x5b, 0xc9, 0x3f, 0x2d, 0x71,
    0x5e, 0x95, 0xad, 0xa4, 0x79, 0x6f, 0x90, 0x87, 0x7a, 0x6f};

/* Helper function to copy onvif_media_signing_vendor_info_t. */
static void
copy_vendor_info(onvif_media_signing_vendor_info_t *dst,
    const onvif_media_signing_vendor_info_t *src)
{
  if (!src || !dst)
    return;

  // Reset strings
  memset(dst->firmware_version, 0, 257);
  memset(dst->serial_number, 0, 257);
  memset(dst->manufacturer, 0, 257);
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
  if (!is_sei_user_data_unregistered)
    return false;

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
  onvif_media_signing_authenticity_t **auth_report =
      data->bulk_run ? NULL : &(data->auth_report);

  // Get the sample from appsink.
  sample = gst_app_sink_pull_sample(sink);
  // If sample is NULL the appsink is stopped or EOS is reached. Both are valid, hence
  // proceed.
  if (sample == NULL)
    return GST_FLOW_OK;

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
    data->sei_bytes += is_media_signing_sei(info.data, data->codec) ? info.size : 0;

    if (data->no_container) {
      status = onvif_media_signing_add_nalu_and_authenticate(
          data->oms, info.data, info.size, auth_report);
    } else {
      // Pass nalu to the signed video session, excluding 4 bytes start code, since it
      // might have been replaced by the size of buffer.
      // TODO: First, a check for 3 or 4 byte start code should be done.

      // TODO Kasper - has exception
      
      status = onvif_media_signing_add_nalu_and_authenticate(
          data->oms, info.data + 4, info.size - 4, auth_report);
          
    }
    if (status != OMS_OK) {
      g_critical("error during verification of signed video: %d", status);
      post_validation_result_message(sink, bus, VALIDATION_ERROR);
    } else if (!data->bulk_run && data->auth_report) {
      // Print intermediate validation if not running in bulk mode.
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
      // Allocate memory for |vendor_info| the first time it will be copied from the
      // authenticity report.
      if (!data->vendor_info) {
        data->vendor_info = g_malloc0(sizeof(onvif_media_signing_vendor_info_t));
      }
      copy_vendor_info(data->vendor_info, &(data->auth_report->vendor_info));
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

// This function will write information to all configured results files
void
storeValidationMessage(FILE *files[RESULTS_FILES_COUNT], const char *message)
{
  for (int i = 0; i < RESULTS_FILES_COUNT; ++i) {
    if (files[i] != NULL) {
      fprintf(files[i], message);
    }
  }
}

/* building the log file report without gui*/
static gboolean
on_source_message(GstBus ATTR_UNUSED *bus, GstMessage *message, ValidationData *data)
{
  // Array of results files
  FILE *resultsFiles[RESULTS_FILES_COUNT];
  memset(resultsFiles, 0, RESULTS_FILES_COUNT);
  char *this_version = data->this_version;
  char *signing_version = data->version_on_signing_side;
  char first_ts_str[80] = {'\0'};
  char last_ts_str[80] = {'\0'};
  bool has_timestamp = false;
  float bitrate_increase = 0.0f;

  char *temp_str = "";

  if (data->total_bytes) {
    bitrate_increase =
        100.0f * data->sei_bytes / (float)(data->total_bytes - data->sei_bytes);
  }

  switch (GST_MESSAGE_TYPE(message  )) {
    case GST_MESSAGE_EOS:
      data->auth_report = onvif_media_signing_get_authenticity_report(data->oms);

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

      // time stamps for gui
      if (has_timestamp) {
        strcpy(validation_result->media_info.first_valid_frame, first_ts_str);
        strcpy(validation_result->media_info.last_valid_frame, last_ts_str);
        // validation_result->media_info.first_valid_frame = first_ts_str;
        // validation_result->media_info.last_valid_frame = last_ts_str;
      }

      // TODO send to gui if opening file failed.
      // TODO make a gui function that does not print to file
      g_debug("received EOS");
      for (int i = 0; i < RESULTS_FILES_COUNT; ++i) {
        resultsFiles[i] = fopen(data->results_file_names_array[i], "w");
        if (!resultsFiles[i]) {
          g_warning("Could not open %s for writing", RESULTS_FILE);
          strcpy(validation_result->video_error_str,
              "could not open output file for writing");
          if (validation_callback_ptr != NULL) {
            validation_callback_ptr(*validation_result);
          }
          g_main_loop_quit(data->loop);
          return FALSE;
        }
      }

      storeValidationMessage(resultsFiles, "-----------------------------\n");

      if (data->auth_report) {  // check public key
        // for qt
        validation_result->provenance_result =
            data->auth_report->accumulated_validation.provenance;

        if (data->auth_report->accumulated_validation.provenance ==
            OMS_PROVENANCE_NOT_OK) {
          temp_str = "PUBLIC KEY IS NOT VALID!\n";
          storeValidationMessage(resultsFiles, temp_str);
        } else if (data->auth_report->accumulated_validation.provenance ==
            OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED) {
          temp_str = "PUBLIC KEY VERIFIABLE WITHOUT TRUSTED CERT!\n";
          storeValidationMessage(resultsFiles, temp_str);
          validation_result->public_key_is_valid = true;

        } else if (data->auth_report->accumulated_validation.provenance ==
            OMS_PROVENANCE_OK) {
          temp_str = "PUBLIC KEY IS VALID!\n";
          storeValidationMessage(resultsFiles, temp_str);
          validation_result->public_key_is_valid = true;

        } else {
          temp_str = "PUBLIC KEY COULD NOT BE VALIDATED!\n";
          storeValidationMessage(resultsFiles, temp_str);
        }
      } else {
        temp_str = "PUBLIC KEY COULD NOT BE VALIDATED!\n";
        storeValidationMessage(resultsFiles, temp_str);
      }

      storeValidationMessage(resultsFiles, temp_str);
      storeValidationMessage(resultsFiles, "\n");
      strcpy(validation_result->key_validation_str, temp_str);
      strcpy(validation_result->provenance_str, temp_str);

      storeValidationMessage(resultsFiles, "-----------------------------\n");
      if (data->auth_report == NULL)
      {
        temp_str = "NO DATA FOR BULK RUN!\n";
        storeValidationMessage(resultsFiles, temp_str);
        storeValidationMessage(resultsFiles, "\n");
        strcpy(validation_result->bulk_str, temp_str);
      }
      if (data->bulk_run && data->auth_report) {  // check bulk run
        onvif_media_signing_accumulated_validation_t *acc_validation =
            &(data->auth_report->accumulated_validation);

        // qt gui
        validation_result->accumulated_validation =
            &(data->auth_report->accumulated_validation);

        if (acc_validation->authenticity == OMS_NOT_SIGNED) {
          temp_str = "VIDEO IS NOT SIGNED!\n";
          storeValidationMessage(resultsFiles, temp_str);

        } else if (acc_validation->authenticity == OMS_AUTHENTICITY_NOT_OK) {
          temp_str = "VIDEO IS INVALID!\n";
          storeValidationMessage(resultsFiles, temp_str);

        } else if (acc_validation->authenticity ==
            OMS_AUTHENTICITY_OK_WITH_MISSING_INFO) {
          temp_str = "VIDEO IS VALID, BUT HAS MISSING FRAMES!\n";
          storeValidationMessage(resultsFiles, temp_str);

          validation_result->video_is_valid = true;

        } else if (acc_validation->authenticity == OMS_AUTHENTICITY_OK) {
          temp_str = "VIDEO IS VALID!\n";
          storeValidationMessage(resultsFiles, temp_str);

          validation_result->video_is_valid = true;

        } else {
          temp_str = "PUBLIC KEY COULD NOT BE VALIDATED!\n";
          storeValidationMessage(resultsFiles, temp_str);
        }
        strcpy(validation_result->video_valid_str, temp_str);
        // validation_result->video_valid_str = temp_str;
        fprintf(resultsFiles[0], "Number of received NAL Units : %u\n",
            acc_validation->number_of_received_nalus);
        fprintf(resultsFiles[0], "Number of validated NAL Units: %u\n",
            acc_validation->number_of_validated_nalus);
        fprintf(resultsFiles[0], "Number of pending NAL Units  : %u\n",
            acc_validation->number_of_pending_nalus);
      }  // end bulk run

      // not bulk run
      else {
        if (data->invalid_gops > 0) {
          temp_str = "VIDEO IS INVALID!\n";
          storeValidationMessage(resultsFiles, temp_str);
        } else if (data->no_sign_gops > 0) {
          temp_str = "VIDEO IS NOT SIGNED\n";
          storeValidationMessage(resultsFiles, temp_str);
        } else if (data->valid_gops_with_missing > 0) {
          temp_str = "VIDEO IS VALID, BUT HAS MISSING FRAMES!\n";
          storeValidationMessage(resultsFiles, temp_str);
          validation_result->video_is_valid = true;
        } else if (data->valid_gops > 0) {
          temp_str = "VIDEO IS VALID!\n";
          storeValidationMessage(resultsFiles, temp_str);
          validation_result->video_is_valid = true;
        } else {
          temp_str = "NO COMPLETE GOPS FOUND!\n";
          storeValidationMessage(resultsFiles, temp_str);
        }
        fprintf(resultsFiles[0], "Number of valid GOPs: %d\n", data->valid_gops);
        validation_result->gop_info.valid_gops_count = data->valid_gops;

        fprintf(resultsFiles[0], "Number of valid GOPs with missing NALUs: %d\n",
            data->valid_gops_with_missing);
        validation_result->gop_info.valid_gops_with_missing_nalu_count =
            data->valid_gops_with_missing;

        fprintf(resultsFiles[0], "Number of invalid GOPs: %d\n", data->invalid_gops);
        validation_result->gop_info.invalid_gops_count = data->invalid_gops;

        fprintf(resultsFiles[0], "Number of GOPs without signature: %d\n",
            data->no_sign_gops);
        validation_result->gop_info.gops_without_signature_count = data->no_sign_gops;

        strcpy(validation_result->video_valid_str, temp_str);
      }
      storeValidationMessage(resultsFiles, "-----------------------------\n");
      storeValidationMessage(resultsFiles, "\nVendor Info\n");
      storeValidationMessage(resultsFiles, "-----------------------------\n");

      // get vender info
      if (data->auth_report == NULL) {
        temp_str = "NO DATA FOR VENDOR INFO!\n";
        storeValidationMessage(resultsFiles, temp_str);
        storeValidationMessage(resultsFiles, "\n");
        strcpy(validation_result->bulk_str, temp_str);
      }
      onvif_media_signing_vendor_info_t *vendor_info =
          data->bulk_run ? &(data->auth_report->vendor_info) : data->vendor_info;
     
      if (vendor_info && data->auth_report) {
        storeValidationMessage(resultsFiles, "Serial Number:    %s\n", vendor_info->serial_number);
        storeValidationMessage(resultsFiles, "Firmware version: %s\n", vendor_info->firmware_version);
        storeValidationMessage(resultsFiles, "Manufacturer:     %s\n", vendor_info->manufacturer);

        strcpy(validation_result->vendor_info.serial_number, vendor_info->serial_number);
        strcpy(validation_result->vendor_info.firmware_version,
            vendor_info->firmware_version);
        strcpy(validation_result->vendor_info.manufacturer, vendor_info->manufacturer);
        // validation_result->vendor_info.serial_number = vendor_info->serial_number;
        // validation_result->vendor_info.firmware_version =
        // vendor_info->firmware_version; validation_result->vendor_info.manufacturer =
        // vendor_info->manufacturer;
        validation_result->vendor_info_is_present = true;

      } else {
        storeValidationMessage(resultsFiles, "NOT PRESENT!\n");
        validation_result->vendor_info_is_present = false;
      }

      storeValidationMessage(resultsFiles, "-----------------------------\n");
      storeValidationMessage(resultsFiles, "\nMedia Signing timestamps\n");
      storeValidationMessage(resultsFiles, "-----------------------------\n");
      storeValidationMessage(resultsFiles, "First frame:           %s\n", has_timestamp ? first_ts_str : "N/A");
      storeValidationMessage(resultsFiles, "Last validated frame:  %s\n", has_timestamp ? last_ts_str : "N/A");
      strcpy(validation_result->media_info.first_valid_frame,
          has_timestamp ? first_ts_str : "N/A");
      strcpy(validation_result->media_info.last_valid_frame,
          has_timestamp ? last_ts_str : "N/A");

      // validation_result->media_info.first_valid_frame = has_timestamp ? first_ts_str :
      // "N/A"; validation_result->media_info.last_valid_frame = has_timestamp ?
      // last_ts_str : "N/A";

      fprintf(resultsFiles[0], "-----------------------------\n");
      fprintf(resultsFiles[0], "\nMedia Signing size footprint\n");
      fprintf(resultsFiles[0], "-----------------------------\n");
      fprintf(resultsFiles[0], "Total video:       %8zu B\n", data->total_bytes);
      fprintf(resultsFiles[0], "Media Signing data: %7zu B\n", data->sei_bytes);
      fprintf(resultsFiles[0], "Bitrate increase: %9.2f %%\n", bitrate_increase);

      validation_result->media_info.total_bytes = data->total_bytes;
      validation_result->media_info.sei_bytes = data->sei_bytes;
      validation_result->media_info.bitrate_increase = bitrate_increase;

      fprintf(resultsFiles[0], "-----------------------------\n");
      fprintf(resultsFiles[0], "\nVersions of signed-media-framework\n");
      fprintf(resultsFiles[0], "-----------------------------\n");
      fprintf(resultsFiles[0], "Validator (%s) runs: %s\n", VALIDATOR_VERSION,
          this_version ? this_version : "N/A");

      // validation_result->vendor_info.validator_version = VALIDATOR_VERSION;
      // validation_result->vendor_info.this_version =
      // this_version ? this_version : "N/A";

      strcpy(validation_result->vendor_info.validator_version, VALIDATOR_VERSION);
      strcpy(validation_result->vendor_info.this_version,
          this_version ? this_version : "N/A");

      fprintf(resultsFiles[0], "Camera runs: %s\n",
          signing_version ? signing_version : "N/A");

      // validation_result->vendor_info.version_on_signing_side =
      // signing_version ? signing_version : "N/A";

      strcpy(validation_result->vendor_info.version_on_signing_side,
          signing_version ? signing_version : "N/A");

      fprintf(resultsFiles[0], "-----------------------------\n");
      for (int i = 0; i < RESULTS_FILES_COUNT; ++i) {
        if (resultsFiles[i] != NULL) {
          fclose(resultsFiles[i]);
        }
      }
      if (data->bulk_run && data->auth_report) {
        this_version = data->auth_report->this_version;
        signing_version = data->auth_report->version_on_signing_side;
        g_message("Validation performed in bulk mode");
      }
      g_message("Validation performed with Media Signing version %s", this_version);
      if (signing_version) {
        g_message("Signing was performed with Media Signing version %s", signing_version);
      }
      g_message("Validation complete. Results printed to '%s'.", RESULTS_FILE);

      if (validation_callback_ptr != NULL) {
        validation_callback_ptr(*validation_result);
      }

      onvif_media_signing_authenticity_report_free(data->auth_report);
      g_main_loop_quit(data->loop);
      break;
    case GST_MESSAGE_ERROR:
      g_debug("received error");
      strcpy(validation_result->video_error_str, "gstreamer loop error");
      if (validation_callback_ptr != NULL) {
        validation_callback_ptr(*validation_result);
      }
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

void
init_validation_result()
{
  // Initialize data.
  validation_result = g_new0(ValidationResult, 1);
  validation_result->gop_info.valid_gops_count = 0;
  validation_result->gop_info.valid_gops_with_missing_nalu_count = 0;
  validation_result->gop_info.invalid_gops_count = 0;
  validation_result->gop_info.gops_without_signature_count = 0;

  memset(validation_result->vendor_info.serial_number, 0, 256);
  memset(validation_result->vendor_info.firmware_version, 0, 256);
  memset(validation_result->vendor_info.manufacturer, 0, 256);
  memset(validation_result->vendor_info.validator_version, 0, 256);
  memset(validation_result->vendor_info.version_on_signing_side, 0, 256);
  memset(validation_result->vendor_info.this_version, 0, 256);

  // validation_result->vendor_info.serial_number = "";
  // validation_result->vendor_info.firmware_version = "";
  // validation_result->vendor_info.manufacturer = "";
  // validation_result->vendor_info.validator_version = "";
  // validation_result->vendor_info.version_on_signing_side = "";
  // validation_result->vendor_info.this_version = "";

  validation_result->media_info.codec = OMS_CODEC_H264;
  // validation_result->media_info.first_valid_frame = "NA";
  // validation_result->media_info.last_valid_frame = "NA";
  memset(validation_result->media_info.first_valid_frame, 0, 256);
  memset(validation_result->media_info.last_valid_frame, 0, 256);

  validation_result->media_info.total_bytes = 0;
  validation_result->media_info.sei_bytes = 0;
  validation_result->media_info.bitrate_increase = 0.f;

  validation_result->public_key_is_valid = false;
  validation_result->video_is_valid = false;
  validation_result->bulk_run = false;
  validation_result->vendor_info_is_present = false;

  memset(validation_result->provenance_str, 0, 256);
  memset(validation_result->video_valid_str, 0, 256);
  memset(validation_result->key_validation_str, 0, 256);
  memset(validation_result->video_error_str, 0, 256);

  validation_result->accumulated_validation = NULL;
  validation_result->provenance_result = OMS_PROVENANCE_NOT_FEASIBLE;

  validation_result->media_info.codec = -1;
}

void
validation_callback(ValidationCallback validation_callback)
{
  validation_callback_ptr = validation_callback;
}

int
validate(gchar *_codec_str,
    gchar *_certificate_str,
    gchar *_filename,
    bool _is_bulkrun,
    const char *_results_file_name)
{
  g_print("start validating media!\n");
  printf("%s - %s -%s\n", _codec_str, _certificate_str, _filename);

  // init the gui validation struct.
  init_validation_result();

  int status = 1;
  GError *error = NULL;
  GstElement *validatorsink = NULL;
  GstBus *bus = NULL;
  ValidationData *data = NULL;
  MediaSigningCodec codec = -1;

  bool bulk_run = _is_bulkrun;
  gchar *demux_str = "";  // No container by default
  gchar *pipeline = NULL;

  gchar *codec_str = _codec_str;
  gchar *filename = _filename;
  gchar *CAfilename = _certificate_str; 

  //gchar *codec_str = "h264";
  // gchar *CAfilename = "";  // ca.pem
  //gchar *CAfilename = "c:/gstreamer/1.0/msvc_x86_64/bin/ca.pem";  // ca.pem
  //gchar *filename = "c:/gstreamer/1.0/msvc_x86_64/bin/test_signed_h264.mp4";
  // gchar *filename = _filename;

  // Initialization.
  if (!gst_init_check(NULL, NULL, &error)) {
    g_warning("gst_init failed: %s", error->message);
    strcpy(validation_result->video_error_str, "gst_init failed: ");
    strcat(validation_result->video_error_str, error->message);
    if (validation_callback_ptr != NULL) {
      validation_callback_ptr(*validation_result);
    }
    goto out;
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
    strcpy(validation_result->video_error_str, "unsupported codec format: ");
    strcat(validation_result->video_error_str, codec_str);
    if (validation_callback_ptr != NULL) {
      validation_callback_ptr(*validation_result);
    }
    goto out;
  }

  // rewrite
  gboolean hr = g_file_test(filename, G_FILE_TEST_EXISTS);
  if (hr == false) {
    // TODO: Turn to warning when signer can generate outputs.
    g_message("file '%s' does not exist", filename);
    strcpy(validation_result->video_error_str, "file does not exist : ");
    strcat(validation_result->video_error_str, filename);
    if (validation_callback_ptr != NULL) {
      validation_callback_ptr(*validation_result);
    }
    goto out;
  }

  // crete pipeline
  pipeline = g_strdup_printf(
      "filesrc location=\"%s\" %s ! %sparse ! "
      "video/x-%s,stream-format=byte-stream,alignment=(string)nal ! appsink "
      "name=validatorsink",
      filename, demux_str, codec_str, codec_str);

  // if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
  //   pipeline = g_strdup_printf(
  //       "filesrc location=\"%s\" %s ! %sparse ! "
  //       "video/x-%s,stream-format=byte-stream,alignment=(string)nal ! appsink "
  //       "name=validatorsink",
  //       filename, demux_str, codec_str, codec_str);
  // } else {
  //   // TODO: Turn to warning when signer can generate outputs.
  //   g_message("file '%s' does not exist", filename);
  //   goto out;
  // }

  g_message("GST pipeline: %s", pipeline);

  // Initialize data.
  data = g_new0(ValidationData, 1);
  data->valid_gops = 0;
  data->valid_gops_with_missing = 0;
  data->invalid_gops = 0;
  data->no_sign_gops = 0;

  // Create an ONVIF Media Session for this codec.
  data->oms = onvif_media_signing_create(codec);
  data->loop = g_main_loop_new(NULL, FALSE);
  data->source = gst_parse_launch(pipeline, NULL);
  data->no_container = (strlen(demux_str) == 0);
  data->bulk_run = bulk_run;
  data->codec = codec;
  for (int i = 0; i < RESULTS_FILES_COUNT; ++i)
    memset(data->results_file_names_array[i], 0, RESULTS_FILES_COUNT);
  // Always use default RESULTS_FILE
  strcpy(data->results_file_names_array[0], RESULTS_FILE);
  // Maybe use additional file from OXFPlayer
  if (_results_file_name != NULL) {
    strcpy(data->results_file_names_array[1], _results_file_name);
  }
  g_free(pipeline);
  pipeline = NULL;

  validation_result->media_info.codec = codec;
  validation_result->bulk_run = bulk_run;

  if (data->source == NULL || data->loop == NULL || data->oms == NULL) {
    // TODO: Turn to warning when sessions can be created.
    g_message("init failed: source = (%p), loop = (%p), oms = (%p)", data->source,
        data->loop, data->oms);
    strcpy(validation_result->video_error_str, "gstreamer init failed: ");
    if (validation_callback_ptr != NULL) {
      validation_callback_ptr(*validation_result);
    }
    goto out;
  }

  // set up the bus
  //  To be notified of messages from this pipeline; error, EOS and live validation.
  bus = gst_element_get_bus(data->source);
  // setup callback
  gst_bus_add_watch(bus, (GstBusFunc)on_source_message, data);

  // Use appsink in push mode. It sends a signal when data is available and pulls out
  // the data in the signal callback. Set the appsink to push as fast as possible, hence
  // set sync=false.
  validatorsink = gst_bin_get_by_name(GST_BIN(data->source), "validatorsink");
  g_object_set(G_OBJECT(validatorsink), "emit-signals", TRUE, "sync", FALSE, NULL);
  g_signal_connect(
      validatorsink, "new-sample", G_CALLBACK(on_new_sample_from_sink), data);
  gst_object_unref(validatorsink);

  // set play state and check for error
  if (gst_element_set_state(data->source, GST_STATE_PLAYING) ==
      GST_STATE_CHANGE_FAILURE) {
    // Check if there is an error message with details on the bus.
    GstMessage *msg = gst_bus_poll(bus, GST_MESSAGE_ERROR, 0);
    if (msg) {
      gst_message_parse_error(msg, &error, NULL);
      g_printerr("Failed to start up source: %s", error->message);
      strcpy(validation_result->video_error_str, "Failed to start up source: ");
      strcat(validation_result->video_error_str, error->message);

      gst_message_unref(msg);
    } else {
      g_error("Failed to start up source!");
      strcpy(validation_result->video_error_str, "Failed to start up source: ");
    }
    if (validation_callback_ptr != NULL) {
      validation_callback_ptr(*validation_result);
    }
    goto out;
  }

  // Add trusted certificate to signing session.
  char *trusted_certificate = NULL;
   size_t trusted_certificate_size = 0;
    if (CAfilename) {
      bool success = false;
      if (strcmp(CAfilename, "test") == 0) {
        // Read pre-generated test trusted certificate.
        success = oms_read_test_trusted_certificate(
            &trusted_certificate, &trusted_certificate_size);
      } else {
        // Read trusted CA certificate.
        FILE *fp = fopen(CAfilename, "rb");
        if (!fp) {
          strcpy(validation_result->video_error_str, "failed opening certificate");
          goto ca_file_done;
        }

      fseek(fp, 0L, SEEK_END);
      size_t file_size = ftell(fp);
      rewind(fp);
      trusted_certificate = g_malloc0(file_size);
      if (!trusted_certificate) {
        strcpy(validation_result->video_error_str, "failed allocation for certificate");
        goto ca_file_done;
      }
      fread(trusted_certificate, sizeof(char), file_size / sizeof(char), fp);
      trusted_certificate_size = file_size;

      success = true;

    ca_file_done:
      if (fp) {
        fclose(fp);
      }
    }
    if (success) {
      if (onvif_media_signing_set_trusted_certificate(data->oms, trusted_certificate,
              trusted_certificate_size, false) != OMS_OK) {
        g_message("Failed setting trusted certificate. Validating without one.");
        strcpy(validation_result->video_error_str,
            "Failed setting trusted certificate. Validating without one.");

      }
    } else {
      g_message("Failed reading trusted certificate. Validating without one.");
      strcpy(validation_result->video_error_str,
          "Failed reading trusted certificate. Validating without one.");
    }
  } else {
    g_message("No trusted certificate set.");
    strcpy(validation_result->video_error_str, "No trusted certificate set.");
  }
   g_free(trusted_certificate);

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
  g_free(pipeline);
  if (error)
    g_error_free(error);
  if (data) {
    if (data->source) {
      gst_object_unref(data->source);
    }
    g_main_loop_unref(data->loop);
    // TODO Kasper, wait with freeing untill certficate section works
    if (data->oms) {
      onvif_media_signing_free(data->oms);  // Free the session
    }
    g_free(data->vendor_info);
    g_free(data->this_version);
    g_free(data->version_on_signing_side);
    g_free(data);
  }

  validation_result_free();

  return status;
}

// call from gui to clear memory
void
validation_result_free()
{

  // End of session. Free objects.

  if (validation_result) {
    g_free(validation_result->accumulated_validation);
    g_free(validation_result);
    // g_free(validation_result->video_valid_str);
    // g_free(validation_result->provenance_str);
    // g_free(validation_result->key_validation_str);
    // g_free(validation_result->video_error_str);
    // g_free(validation_result->media_info.first_valid_frame);
    // g_free(validation_result->media_info.last_valid_frame);
    // g_free(validation_result->vendor_info.serial_number);
    // g_free(validation_result->vendor_info.firmware_version);
    // g_free(validation_result->vendor_info.manufacturer);
    // g_free(validation_result->vendor_info.validator_version);
    // g_free(validation_result->vendor_info.version_on_signing_side);
    // g_free(validation_result->vendor_info.this_version);
  }
}
