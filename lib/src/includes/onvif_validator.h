#ifndef __ONVIF_VALIDATOR_H__
#define __ONVIF_VALIDATOR_H__

#include <gst/gst.h>

#ifdef __cplusplus
extern "C" {
#endif

void
validate(gchar* codec_str, gchar* certificate_str, gchar* filename);

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_VALIDATOR_H__