#ifndef VALIDATOR_JSON_REPORT_H
#define VALIDATOR_JSON_REPORT_H

#include <glib.h>

#include "includes/onvif_media_signing_validator.h"

gchar *
validator_json_serialize_error(const char *message);
gchar *
validator_json_serialize_report(const onvif_media_signing_authenticity_t *report);
void
validator_json_print_error(const char *message);
void
validator_json_print_report(const onvif_media_signing_authenticity_t *report);

#endif  // VALIDATOR_JSON_REPORT_H