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
  const char* serial_number;
  const char* firmware_version;
  const char* manufacturer;
  const char* validator_version;

  char* version_on_signing_side;
  char* this_version;
} VendorInfo;

typedef struct {
  gint valid_gops_count;
  gint valid_gops_with_missing_nalu_count;
  gint invalid_gops_count;
  gint gops_without_signature_count;
} GOPInfo;

typedef struct {
  MediaSigningCodec codec;
  const char* first_valid_frame;
  const char* last_valid_frame;
  gsize total_bytes;
  gsize sei_bytes;
  float bitrate_increase;

} MediaInfo;

typedef struct {
  bool public_key_is_valid;
  bool video_is_valid;
  bool bulk_run;
  bool vendor_info_is_present;
  const char* provenance_str;
  const char* video_valid_str;
  const char* key_validation_str;
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

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_VALIDATOR_H__