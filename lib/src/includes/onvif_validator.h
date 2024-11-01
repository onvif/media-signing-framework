#ifndef __ONVIF_VALIDATOR_H__
#define __ONVIF_VALIDATOR_H__

#include <stdbool.h>
#include <gst/gst.h>


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
} VendorInfo;

typedef struct {
  int valid_gops_count;
  int valid_gops_with_missing_nalu_count;
  int invalid_gops_count;
  int gops_without_signature_count;
} GOPInfo;

typedef struct {
  bool public_key_is_valid;
  bool video_is_valid;
  VendorInfo vendor_info;
  GOPInfo gop_info;
} ValidationResult;

typedef void (*ValidationCallback)(ValidationResult);

void
validation_callback(ValidationCallback validation_callback);

void
init_postmedia_data();

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_VALIDATOR_H__