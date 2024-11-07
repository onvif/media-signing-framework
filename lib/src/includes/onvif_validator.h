#ifndef __ONVIF_VALIDATOR_H__
#define __ONVIF_VALIDATOR_H__

#include <stdbool.h>
#include <gst/gst.h>
#include <time.h>

#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_helpers.h"
#include "includes/onvif_media_signing_validator.h"


#ifdef __cplusplus
extern "C" {
#endif

int
validate(gchar* _codec_str, gchar* _certificate_str, gchar* _filename);

// Validation structures
typedef struct {
  char serial_number[256];
  char firmware_version[256];
  char manufacturer[256];
  char validator_version[256];

  char version_on_signing_side[256];
  char this_version[256];
} VendorInfo;

typedef struct {
  gint valid_gops_count;
  gint valid_gops_with_missing_nalu_count;
  gint invalid_gops_count;
  gint gops_without_signature_count;
} GOPInfo;

typedef struct {
  MediaSigningCodec codec;
  char first_valid_frame[256];
  char last_valid_frame[256];
  gsize total_bytes;
  gsize sei_bytes;
  float bitrate_increase;

} MediaInfo;

typedef struct {
  bool public_key_is_valid;
  bool video_is_valid;
  bool bulk_run;
  bool vendor_info_is_present;
  char provenance_str[256];
  char video_valid_str[256];
  char key_validation_str[256];
  char video_error_str[256];
  onvif_media_signing_accumulated_validation_t* accumulated_validation;
  MediaSigningProvenanceResult provenance_result;
  MediaInfo media_info;
  VendorInfo vendor_info;
  GOPInfo gop_info;
} ValidationResult;


typedef struct {
  onvif_media_signing_t *oms;
  onvif_media_signing_authenticity_t *auth_report;
  onvif_media_signing_vendor_info_t *vendor_info;
  bool no_container;
 
} PostMediaData;
//PostMediaData *postdata = NULL;



typedef void (*ValidationCallback)(ValidationResult);

void
validation_callback(ValidationCallback validation_callback);

void
init_validation_result();

void
validation_result_free();

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_VALIDATOR_H__