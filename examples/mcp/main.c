#include <glib.h>
#include <gst/app/gstappsink.h>
#include <gst/gst.h>
#include <gst/pbutils/pbutils.h>
#include <json-glib/json-glib.h>
#include <media-signing-framework/onvif_media_signing_common.h>
#include <media-signing-framework/onvif_media_signing_validator.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
  onvif_media_signing_t *session;
  gchar *error_message;
} ValidationData;

typedef struct {
  GstElement *parser;
  const gchar *media_type;
} DemuxData;

static void
add_string_member(JsonBuilder *builder, const gchar *name, const gchar *value)
{
  json_builder_set_member_name(builder, name);
  json_builder_add_string_value(builder, value ? value : "");
}

static void
print_json(JsonBuilder *builder)
{
  JsonGenerator *generator = json_generator_new();
  JsonNode *root = json_builder_get_root(builder);
  gchar *json;

  json_generator_set_root(generator, root);
  json = json_generator_to_data(generator, NULL);
  puts(json);

  g_free(json);
  json_node_free(root);
  g_object_unref(generator);
}

static const gchar *
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

static const gchar *
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

static const gchar *
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

static void
print_error(const gchar *message)
{
  JsonBuilder *builder = json_builder_new();

  json_builder_begin_object(builder);
  add_string_member(builder, "status", "validation_error");
  json_builder_set_member_name(builder, "is_authentic");
  json_builder_add_boolean_value(builder, FALSE);
  add_string_member(builder, "error", message);
  json_builder_end_object(builder);
  print_json(builder);

  g_object_unref(builder);
}

static void
print_report(const onvif_media_signing_authenticity_t *report)
{
  const onvif_media_signing_accumulated_validation_t *validation =
      &report->accumulated_validation;
  const gchar *status = normalized_status(validation);
  gboolean authentic = validation->authenticity == OMS_AUTHENTICITY_OK;
  JsonBuilder *builder = json_builder_new();

  json_builder_begin_object(builder);
  add_string_member(builder, "status", status);
  json_builder_set_member_name(builder, "is_authentic");
  json_builder_add_boolean_value(builder, authentic);
  add_string_member(
      builder, "raw_authenticity", authenticity_name(validation->authenticity));
  add_string_member(builder, "raw_provenance", provenance_name(validation->provenance));
  json_builder_set_member_name(builder, "raw_authenticity_and_provenance_code");
  json_builder_add_int_value(builder, validation->authenticity_and_provenance);
  json_builder_set_member_name(builder, "raw_authenticity_code");
  json_builder_add_int_value(builder, validation->authenticity);
  json_builder_set_member_name(builder, "raw_provenance_code");
  json_builder_add_int_value(builder, validation->provenance);
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
  json_builder_end_object(builder);

  print_json(builder);
  g_object_unref(builder);
}

static GstFlowReturn
on_new_sample(GstAppSink *sink, ValidationData *data)
{
  GstSample *sample = gst_app_sink_pull_sample(sink);
  GstBuffer *buffer;
  GstMapInfo map;

  if (!sample)
    return GST_FLOW_OK;
  buffer = gst_sample_get_buffer(sample);
  if (!buffer || !gst_buffer_map(buffer, &map, GST_MAP_READ)) {
    gst_sample_unref(sample);
    return GST_FLOW_ERROR;
  }
  if (map.size <= 4 ||
      onvif_media_signing_add_nalu_and_authenticate(
          data->session, map.data + 4, map.size - 4, NULL) != OMS_OK) {
    g_clear_pointer(&data->error_message, g_free);
    data->error_message = g_strdup("Media Signing Framework rejected a video NAL unit");
  }
  gst_buffer_unmap(buffer, &map);
  gst_sample_unref(sample);
  return GST_FLOW_OK;
}

static void
on_demux_pad_added(GstElement *demuxer, GstPad *pad, DemuxData *data)
{
  GstPad *sink_pad = gst_element_get_static_pad(data->parser, "sink");
  GstCaps *caps = gst_pad_get_current_caps(pad);
  const GstStructure *structure = caps ? gst_caps_get_structure(caps, 0) : NULL;
  const gchar *name = structure ? gst_structure_get_name(structure) : NULL;

  if (g_strcmp0(name, data->media_type) == 0 && !gst_pad_is_linked(sink_pad))
    gst_pad_link(pad, sink_pad);
  if (caps)
    gst_caps_unref(caps);
  gst_object_unref(sink_pad);
  (void)demuxer;
}

static MediaSigningCodec
detect_codec(const gchar *path, gchar **error_message)
{
  GError *error = NULL;
  GstDiscoverer *discoverer = gst_discoverer_new(5 * GST_SECOND, &error);
  gchar *uri;
  GstDiscovererInfo *info;
  GList *streams;
  MediaSigningCodec codec = OMS_CODEC_NUM;

  if (!discoverer) {
    *error_message =
        g_strdup(error ? error->message : "Could not create media discoverer");
    g_clear_error(&error);
    return OMS_CODEC_NUM;
  }
  uri = g_filename_to_uri(path, NULL, &error);
  if (!uri) {
    *error_message = g_strdup(error->message);
    g_clear_error(&error);
    g_object_unref(discoverer);
    return OMS_CODEC_NUM;
  }
  info = gst_discoverer_discover_uri(discoverer, uri, &error);
  g_free(uri);
  g_object_unref(discoverer);
  if (!info) {
    *error_message = g_strdup(error ? error->message : "Could not inspect media file");
    g_clear_error(&error);
    return OMS_CODEC_NUM;
  }
  streams = gst_discoverer_info_get_video_streams(info);
  for (GList *item = streams; item; item = item->next) {
    GstCaps *caps = gst_discoverer_stream_info_get_caps(item->data);
    const GstStructure *structure = caps ? gst_caps_get_structure(caps, 0) : NULL;
    const gchar *name = structure ? gst_structure_get_name(structure) : NULL;
    if (g_strcmp0(name, "video/x-h264") == 0)
      codec = OMS_CODEC_H264;
    else if (g_strcmp0(name, "video/x-h265") == 0)
      codec = OMS_CODEC_H265;
    if (caps)
      gst_caps_unref(caps);
    if (codec != OMS_CODEC_NUM)
      break;
  }
  gst_discoverer_stream_info_list_free(streams);
  gst_discoverer_info_unref(info);
  if (codec == OMS_CODEC_NUM)
    *error_message = g_strdup("Only H.264 and H.265 MP4 video is supported");
  return codec;
}

static onvif_media_signing_t *
create_session(MediaSigningCodec codec, const gchar *ca_path, gchar **error_message)
{
  gchar *certificate = NULL;
  gsize certificate_size = 0;
  onvif_media_signing_t *session = onvif_media_signing_create(codec);

  if (!session) {
    *error_message = g_strdup("Could not create Media Signing Framework session");
    return NULL;
  }
  if (ca_path && !g_file_get_contents(ca_path, &certificate, &certificate_size, NULL)) {
    *error_message = g_strdup("Could not read the trusted CA certificate");
    onvif_media_signing_free(session);
    return NULL;
  }
  if (certificate &&
      onvif_media_signing_set_trusted_certificate(
          session, certificate, certificate_size) != OMS_OK) {
    *error_message = g_strdup("Could not set the trusted CA certificate");
    g_free(certificate);
    onvif_media_signing_free(session);
    return NULL;
  }
  g_free(certificate);
  return session;
}

int
main(int argc, char **argv)
{
  ValidationData data = {0};
  DemuxData demux_data = {0};
  GError *error = NULL;
  GstElement *pipeline = NULL;
  GstElement *source = NULL;
  GstElement *demuxer = NULL;
  GstElement *parser = NULL;
  GstElement *capsfilter = NULL;
  GstElement *sink = NULL;
  GstBus *bus = NULL;
  MediaSigningCodec codec;
  const gchar *parser_name;
  int exit_code = 1;

  if (argc < 2 || argc > 3 || !g_path_is_absolute(argv[1]) ||
      !g_file_test(argv[1], G_FILE_TEST_IS_REGULAR)) {
    print_error(
        "Usage: media-signing-mcp-validator ABSOLUTE_MEDIA_PATH [ABSOLUTE_CA_PATH]");
    return 2;
  }
  if (argc == 3 && !g_path_is_absolute(argv[2])) {
    print_error("CA certificate path must be absolute");
    return 2;
  }
  if (!g_str_has_suffix(argv[1], ".mp4")) {
    print_error("Only lowercase .mp4 files are supported");
    return 2;
  }
  if (!gst_init_check(NULL, NULL, &error)) {
    print_error(error->message);
    g_clear_error(&error);
    return 1;
  }
  codec = detect_codec(argv[1], &data.error_message);
  if (codec == OMS_CODEC_NUM)
    goto out;
  data.session = create_session(codec, argc == 3 ? argv[2] : NULL, &data.error_message);
  if (!data.session)
    goto out;
  parser_name = codec == OMS_CODEC_H264 ? "h264parse" : "h265parse";
  demux_data.media_type = codec == OMS_CODEC_H264 ? "video/x-h264" : "video/x-h265";
  pipeline = gst_pipeline_new("media-signing-mcp-validation");
  source = gst_element_factory_make("filesrc", NULL);
  demuxer = gst_element_factory_make("qtdemux", NULL);
  parser = gst_element_factory_make(parser_name, NULL);
  capsfilter = gst_element_factory_make("capsfilter", NULL);
  sink = gst_element_factory_make("appsink", NULL);
  if (!pipeline || !source || !demuxer || !parser || !capsfilter || !sink) {
    data.error_message = g_strdup("Required GStreamer element is unavailable");
    goto out;
  }
  g_object_set(source, "location", argv[1], NULL);
  g_object_set(sink, "emit-signals", TRUE, "sync", FALSE, NULL);
  GstCaps *caps = gst_caps_new_simple(
      codec == OMS_CODEC_H264 ? "video/x-h264" : "video/x-h265", "stream-format",
      G_TYPE_STRING, "byte-stream", "alignment", G_TYPE_STRING, "nal", NULL);
  g_object_set(capsfilter, "caps", caps, NULL);
  gst_caps_unref(caps);
  gst_bin_add_many(GST_BIN(pipeline), source, demuxer, parser, capsfilter, sink, NULL);
  if (!gst_element_link(source, demuxer) ||
      !gst_element_link_many(parser, capsfilter, sink, NULL)) {
    data.error_message = g_strdup("Could not link GStreamer validation pipeline");
    goto out;
  }
  demux_data.parser = parser;
  g_signal_connect(demuxer, "pad-added", G_CALLBACK(on_demux_pad_added), &demux_data);
  g_signal_connect(sink, "new-sample", G_CALLBACK(on_new_sample), &data);
  if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE) {
    data.error_message = g_strdup("Could not start GStreamer validation pipeline");
    goto out;
  }
  bus = gst_element_get_bus(pipeline);
  while (TRUE) {
    GstMessage *message = gst_bus_timed_pop_filtered(
        bus, GST_CLOCK_TIME_NONE, GST_MESSAGE_ERROR | GST_MESSAGE_EOS);
    if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
      gst_message_parse_error(message, &error, NULL);
      data.error_message = g_strdup(error->message);
      g_clear_error(&error);
      gst_message_unref(message);
      goto out;
    }
    gst_message_unref(message);
    break;
  }
  if (data.error_message)
    goto out;
  onvif_media_signing_authenticity_t *report =
      onvif_media_signing_get_authenticity_report(data.session);
  if (!report) {
    data.error_message =
        g_strdup("Media Signing Framework returned no authenticity report");
    goto out;
  }
  print_report(report);
  onvif_media_signing_authenticity_report_free(report);
  exit_code = 0;

out:
  if (exit_code != 0)
    print_error(data.error_message ? data.error_message : "Validation failed");
  if (bus)
    gst_object_unref(bus);
  if (pipeline) {
    gst_element_set_state(pipeline, GST_STATE_NULL);
    gst_object_unref(pipeline);
  }
  if (data.session)
    onvif_media_signing_free(data.session);
  g_free(data.error_message);
  gst_deinit();
  return exit_code;
}
