#include "json_report.h"

#include <json-glib/json-glib.h>
#include <string.h>

static void
test_complete_report(void)
{
  onvif_media_signing_authenticity_t report = {0};
  report.version_on_signing_side = "r1\"signed";
  report.this_version = "r2";
  strcpy(report.vendor_info.manufacturer, "Vendor\nName");
  strcpy(report.vendor_info.serial_number, "serial-1");
  strcpy(report.vendor_info.firmware_version, "firmware-1");
  report.accumulated_validation.authenticity_and_provenance =
      OMS_AUTHENTICITY_AND_PROVENANCE_OK;
  report.accumulated_validation.provenance = OMS_PROVENANCE_OK;
  report.accumulated_validation.authenticity = OMS_AUTHENTICITY_OK;
  report.accumulated_validation.public_key_has_changed = true;
  report.accumulated_validation.number_of_received_nalus = 11;
  report.accumulated_validation.number_of_validated_nalus = 10;
  report.accumulated_validation.number_of_pending_nalus = 1;
  report.accumulated_validation.number_of_received_frames = 8;
  report.accumulated_validation.number_of_validated_frames = 7;
  report.accumulated_validation.number_of_pending_frames = 1;
  report.accumulated_validation.first_timestamp = 133859808301234567;
  report.accumulated_validation.last_timestamp = 133859808305234567;
  report.latest_validation.authenticity_and_provenance =
      OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO;
  report.latest_validation.provenance = OMS_PROVENANCE_NOT_OK;
  report.latest_validation.authenticity = OMS_AUTHENTICITY_OK_WITH_MISSING_INFO;
  report.latest_validation.public_key_has_changed = true;
  report.latest_validation.number_of_expected_hashable_nalus = 5;
  report.latest_validation.number_of_received_hashable_nalus = 4;
  report.latest_validation.number_of_pending_hashable_nalus = 1;
  report.latest_validation.validation_str = ".M.P";
  report.latest_validation.nalu_str = "IP S";

  gchar *json = validator_json_serialize_report(&report);
  JsonParser *parser = json_parser_new();
  g_assert_true(json_parser_load_from_data(parser, json, -1, NULL));
  JsonObject *root = json_node_get_object(json_parser_get_root(parser));
  g_assert_cmpstr(json_object_get_string_member(root, "status"), ==, "authentic");
  g_assert_true(json_object_get_boolean_member(root, "is_authentic"));
  g_assert_true(json_object_get_boolean_member(root, "public_key_has_changed"));
  g_assert_cmpstr(json_object_get_string_member(root, "raw_authenticity_and_provenance"),
      ==, "authentic_and_trusted");
  g_assert_cmpstr(
      json_object_get_string_member(root, "signing_version"), ==, "r1\"signed");

  JsonObject *timestamps = json_object_get_object_member(root, "timestamps");
  JsonObject *first = json_object_get_object_member(timestamps, "first");
  g_assert_cmpstr(json_object_get_string_member(first, "ticks_100ns_since_1601"), ==,
      "133859808301234567");
  g_assert_cmpstr(
      json_object_get_string_member(first, "utc"), ==, "2025-03-09T08:00:30.1234567Z");

  JsonObject *latest = json_object_get_object_member(root, "latest_validation");
  g_assert_cmpstr(
      json_object_get_string_member(latest, "raw_provenance"), ==, "not_trusted");
  g_assert_cmpstr(json_object_get_string_member(latest, "validation"), ==, ".M.P");
  JsonObject *latest_timestamps = json_object_get_object_member(latest, "timestamps");
  g_assert_true(json_object_get_null_member(latest_timestamps, "start"));
  g_assert_true(json_object_get_null_member(latest_timestamps, "end"));

  g_object_unref(parser);
  g_free(json);
}

static void
test_pre_unix_epoch_timestamp(void)
{
  onvif_media_signing_authenticity_t report = {0};
  report.accumulated_validation.first_timestamp = 116444735999999999;

  gchar *json = validator_json_serialize_report(&report);
  JsonParser *parser = json_parser_new();
  g_assert_true(json_parser_load_from_data(parser, json, -1, NULL));
  JsonObject *root = json_node_get_object(json_parser_get_root(parser));
  JsonObject *timestamps = json_object_get_object_member(root, "timestamps");
  JsonObject *first = json_object_get_object_member(timestamps, "first");
  g_assert_cmpstr(
      json_object_get_string_member(first, "utc"), ==, "1969-12-31T23:59:59.9999999Z");

  g_object_unref(parser);
  g_free(json);
}

static void
test_error_report(void)
{
  gchar *json = validator_json_serialize_error("bad \"input\"");
  JsonParser *parser = json_parser_new();
  g_assert_true(json_parser_load_from_data(parser, json, -1, NULL));
  JsonObject *root = json_node_get_object(json_parser_get_root(parser));
  g_assert_cmpstr(json_object_get_string_member(root, "status"), ==, "validation_error");
  g_assert_false(json_object_get_boolean_member(root, "is_authentic"));
  g_assert_cmpstr(json_object_get_string_member(root, "error"), ==, "bad \"input\"");
  g_object_unref(parser);
  g_free(json);
}

int
main(int argc, char **argv)
{
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/validator/json/complete-report", test_complete_report);
  g_test_add_func("/validator/json/error-report", test_error_report);
  g_test_add_func(
      "/validator/json/pre-unix-epoch-timestamp", test_pre_unix_epoch_timestamp);
  return g_test_run();
}