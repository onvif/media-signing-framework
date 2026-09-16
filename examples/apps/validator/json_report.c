#include "json_report.h"

#include <glib.h>
#include <json-glib/json-glib.h>
#include <stdio.h>

#define WINDOWS_TO_UNIX_EPOCH_100NS 116444736000000000LL
#define TICKS_100NS_PER_SECOND 10000000LL

static void
add_string_member(JsonBuilder *builder, const char *name, const char *value)
{
  json_builder_set_member_name(builder, name);
  json_builder_add_string_value(builder, value ? value : "");
}

static void
add_timestamp_member(JsonBuilder *builder, const char *name, gint64 timestamp)
{
  json_builder_set_member_name(builder, name);
  if (timestamp <= 0) {
    json_builder_add_null_value(builder);
    return;
  }

  gint64 unix_ticks = timestamp - WINDOWS_TO_UNIX_EPOCH_100NS;
  gint64 unix_seconds = unix_ticks / TICKS_100NS_PER_SECOND;
  gint64 fractional_ticks = unix_ticks % TICKS_100NS_PER_SECOND;
  if (fractional_ticks < 0) {
    unix_seconds--;
    fractional_ticks += TICKS_100NS_PER_SECOND;
  }
  GDateTime *date_time = g_date_time_new_from_unix_utc(unix_seconds);
  gchar *seconds = date_time ? g_date_time_format(date_time, "%Y-%m-%dT%H:%M:%S") : NULL;
  gchar *utc = seconds
      ? g_strdup_printf("%s.%07" G_GINT64_FORMAT "Z", seconds, fractional_ticks)
      : NULL;
  gchar *ticks = g_strdup_printf("%" G_GINT64_FORMAT, timestamp);

  json_builder_begin_object(builder);
  add_string_member(builder, "ticks_100ns_since_1601", ticks);
  json_builder_set_member_name(builder, "utc");
  if (utc)
    json_builder_add_string_value(builder, utc);
  else
    json_builder_add_null_value(builder);
  json_builder_end_object(builder);

  g_free(ticks);
  g_free(utc);
  g_free(seconds);
  if (date_time)
    g_date_time_unref(date_time);
}

static const char *
authenticity_name(MediaSigningAuthenticityResult result)
{
  switch (result) {
    case OMS_AUTHENTICITY_OK:
      return "authentic";
    case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
      return "authentic_with_missing_information";
    case OMS_AUTHENTICITY_NOT_OK:
      return "not_authentic";
    case OMS_NOT_SIGNED:
      return "not_signed";
    case OMS_AUTHENTICITY_NOT_FEASIBLE:
      return "not_feasible";
    case OMS_AUTHENTICITY_VERSION_MISMATCH:
      return "version_mismatch";
    default:
      return "unknown";
  }
}

static const char *
provenance_name(MediaSigningProvenanceResult result)
{
  switch (result) {
    case OMS_PROVENANCE_OK:
      return "trusted";
    case OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED:
      return "verifiable_without_trusted_ca";
    case OMS_PROVENANCE_NOT_OK:
      return "not_trusted";
    case OMS_PROVENANCE_NOT_FEASIBLE:
      return "not_feasible";
    default:
      return "unknown";
  }
}

static const char *
combined_result_name(MediaSigningAuthenticityAndProvenance result)
{
  switch (result) {
    case OMS_AUTHENTICITY_AND_PROVENANCE_OK:
      return "authentic_and_trusted";
    case OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO:
      return "authentic_and_trusted_with_missing_information";
    case OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK:
      return "not_authentic_or_not_trusted";
    case OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE:
      return "not_feasible";
    default:
      return "unknown";
  }
}

static const char *
normalized_status(const onvif_media_signing_accumulated_validation_t *validation)
{
  switch (validation->authenticity) {
    case OMS_AUTHENTICITY_OK:
      return "authentic";
    case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
      return "integrity_warning";
    case OMS_AUTHENTICITY_NOT_OK:
      return "not_authentic";
    case OMS_NOT_SIGNED:
      return "not_signed";
    default:
      return "validation_error";
  }
}

static gchar *
serialize_builder(JsonBuilder *builder)
{
  JsonGenerator *generator = json_generator_new();
  JsonNode *root = json_builder_get_root(builder);

  json_generator_set_root(generator, root);
  gchar *json = json_generator_to_data(generator, NULL);

  json_node_free(root);
  g_object_unref(generator);
  return json;
}

gchar *
validator_json_serialize_error(const char *message)
{
  JsonBuilder *builder = json_builder_new();

  json_builder_begin_object(builder);
  add_string_member(builder, "status", "validation_error");
  json_builder_set_member_name(builder, "is_authentic");
  json_builder_add_boolean_value(builder, FALSE);
  add_string_member(builder, "error", message);
  json_builder_end_object(builder);
  gchar *json = serialize_builder(builder);

  g_object_unref(builder);
  return json;
}

gchar *
validator_json_serialize_report(const onvif_media_signing_authenticity_t *report)
{
  const onvif_media_signing_accumulated_validation_t *validation =
      &report->accumulated_validation;
  const onvif_media_signing_latest_validation_t *latest = &report->latest_validation;
  JsonBuilder *builder = json_builder_new();

  json_builder_begin_object(builder);
  add_string_member(builder, "status", normalized_status(validation));
  json_builder_set_member_name(builder, "is_authentic");
  json_builder_add_boolean_value(
      builder, validation->authenticity == OMS_AUTHENTICITY_OK);
  add_string_member(
      builder, "raw_authenticity", authenticity_name(validation->authenticity));
  add_string_member(builder, "raw_provenance", provenance_name(validation->provenance));
  add_string_member(builder, "raw_authenticity_and_provenance",
      combined_result_name(validation->authenticity_and_provenance));
  json_builder_set_member_name(builder, "raw_authenticity_and_provenance_code");
  json_builder_add_int_value(builder, validation->authenticity_and_provenance);
  json_builder_set_member_name(builder, "raw_authenticity_code");
  json_builder_add_int_value(builder, validation->authenticity);
  json_builder_set_member_name(builder, "raw_provenance_code");
  json_builder_add_int_value(builder, validation->provenance);
  json_builder_set_member_name(builder, "public_key_has_changed");
  json_builder_add_boolean_value(builder, validation->public_key_has_changed);
  add_string_member(builder, "validator_version", report->this_version);
  add_string_member(builder, "signing_version", report->version_on_signing_side);

  json_builder_set_member_name(builder, "vendor");
  json_builder_begin_object(builder);
  add_string_member(builder, "manufacturer", report->vendor_info.manufacturer);
  add_string_member(builder, "serial_number", report->vendor_info.serial_number);
  add_string_member(builder, "firmware_version", report->vendor_info.firmware_version);
  json_builder_end_object(builder);

  json_builder_set_member_name(builder, "statistics");
  json_builder_begin_object(builder);
  json_builder_set_member_name(builder, "received_nalus");
  json_builder_add_int_value(builder, validation->number_of_received_nalus);
  json_builder_set_member_name(builder, "validated_nalus");
  json_builder_add_int_value(builder, validation->number_of_validated_nalus);
  json_builder_set_member_name(builder, "pending_nalus");
  json_builder_add_int_value(builder, validation->number_of_pending_nalus);
  json_builder_set_member_name(builder, "received_frames");
  json_builder_add_int_value(builder, validation->number_of_received_frames);
  json_builder_set_member_name(builder, "validated_frames");
  json_builder_add_int_value(builder, validation->number_of_validated_frames);
  json_builder_set_member_name(builder, "pending_frames");
  json_builder_add_int_value(builder, validation->number_of_pending_frames);
  json_builder_end_object(builder);

  json_builder_set_member_name(builder, "timestamps");
  json_builder_begin_object(builder);
  add_timestamp_member(builder, "first", validation->first_timestamp);
  add_timestamp_member(builder, "last", validation->last_timestamp);
  json_builder_end_object(builder);

  json_builder_set_member_name(builder, "latest_validation");
  json_builder_begin_object(builder);
  add_string_member(builder, "raw_authenticity", authenticity_name(latest->authenticity));
  add_string_member(builder, "raw_provenance", provenance_name(latest->provenance));
  add_string_member(builder, "raw_authenticity_and_provenance",
      combined_result_name(latest->authenticity_and_provenance));
  json_builder_set_member_name(builder, "raw_authenticity_and_provenance_code");
  json_builder_add_int_value(builder, latest->authenticity_and_provenance);
  json_builder_set_member_name(builder, "raw_authenticity_code");
  json_builder_add_int_value(builder, latest->authenticity);
  json_builder_set_member_name(builder, "raw_provenance_code");
  json_builder_add_int_value(builder, latest->provenance);
  json_builder_set_member_name(builder, "public_key_has_changed");
  json_builder_add_boolean_value(builder, latest->public_key_has_changed);
  json_builder_set_member_name(builder, "expected_hashable_nalus");
  json_builder_add_int_value(builder, latest->number_of_expected_hashable_nalus);
  json_builder_set_member_name(builder, "received_hashable_nalus");
  json_builder_add_int_value(builder, latest->number_of_received_hashable_nalus);
  json_builder_set_member_name(builder, "pending_hashable_nalus");
  json_builder_add_int_value(builder, latest->number_of_pending_hashable_nalus);
  add_string_member(builder, "validation", latest->validation_str);
  add_string_member(builder, "nalu_types", latest->nalu_str);
  json_builder_set_member_name(builder, "timestamps");
  json_builder_begin_object(builder);
  add_timestamp_member(builder, "start", latest->start_timestamp);
  add_timestamp_member(builder, "end", latest->end_timestamp);
  json_builder_end_object(builder);
  json_builder_end_object(builder);
  json_builder_end_object(builder);

  gchar *json = serialize_builder(builder);
  g_object_unref(builder);
  return json;
}

void
validator_json_print_error(const char *message)
{
  gchar *json = validator_json_serialize_error(message);
  puts(json);
  g_free(json);
}

void
validator_json_print_report(const onvif_media_signing_authenticity_t *report)
{
  gchar *json = validator_json_serialize_report(report);
  puts(json);
  g_free(json);
}