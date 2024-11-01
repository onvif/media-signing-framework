#ifndef __ONVIF_VALIDATOR_H__
#define __ONVIF_VALIDATOR_H__

#include <gst/gst.h>

#ifdef __cplusplus
extern "C" {
#endif

int
validate(gchar* _codec_str, gchar* _certificate_str, gchar* _filename);

void
callback_to_gui(void(*qt_func));

void
init_postmedia_data();

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_VALIDATOR_H__