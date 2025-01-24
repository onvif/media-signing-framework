/**
 * MIT License
 *
 * Copyright (c) 2024 ONVIF. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph)
 * shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * SECTION:element-signing
 *
 * Add SEIs containing signatures for authentication.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "gstsigning.h"
#include "gstsigning_defines.h"
#include "lib/src/includes/onvif_media_signing_common.h"
#include "lib/src/includes/onvif_media_signing_helpers.h"
#include "lib/src/includes/onvif_media_signing_signer.h"

GST_DEBUG_CATEGORY_STATIC(gst_signing_debug);
#define GST_CAT_DEFAULT gst_signing_debug

enum {
  PROP_0,
  PROP_BASETIME
};

struct _GstSigningPrivate {
  onvif_media_signing_t *media_signing;
  MediaSigningCodec codec;
  GstClockTime last_pts;
  GstClockTime basetime;
};

#define TEMPLATE_CAPS \
  GST_STATIC_CAPS( \
      "video/x-h264, alignment=au; " \
      "video/x-h265, alignment=au")

static GstStaticPadTemplate sink_template =
    GST_STATIC_PAD_TEMPLATE("sink", GST_PAD_SINK, GST_PAD_ALWAYS, TEMPLATE_CAPS);

static GstStaticPadTemplate src_template =
    GST_STATIC_PAD_TEMPLATE("src", GST_PAD_SRC, GST_PAD_ALWAYS, TEMPLATE_CAPS);

G_DEFINE_TYPE_WITH_PRIVATE(GstSigning, gst_signing, GST_TYPE_BASE_TRANSFORM);

static void
gst_signing_finalize(GObject *object);
static gboolean
gst_signing_start(GstBaseTransform *trans);
static gboolean
gst_signing_stop(GstBaseTransform *trans);
static gboolean
gst_signing_set_caps(GstBaseTransform *trans, GstCaps *incaps, GstCaps *outcaps);
static GstFlowReturn
gst_signing_transform_ip(GstBaseTransform *trans, GstBuffer *buffer);
static gboolean
gst_signing_sink_event(GstBaseTransform *trans, GstEvent *event);
static gboolean
setup_signing(GstSigning *signing, GstCaps *caps);
static gboolean
terminate_signing(GstSigning *signing);

static void
gst_signing_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
  GstSigning *signing = GST_SIGNING(object);

  GST_OBJECT_LOCK(signing);
  switch (prop_id) {
    case PROP_BASETIME:
      g_value_set_uint64(value, signing->priv->basetime);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
      break;
  }
  GST_OBJECT_UNLOCK(signing);
}

static void
gst_signing_set_property(GObject *object,
    guint prop_id,
    const GValue *value,
    GParamSpec *pspec)
{
  GstSigning *signing = GST_SIGNING(object);
  GstSigningPrivate *priv = signing->priv;

  GST_OBJECT_LOCK(signing);
  switch (prop_id) {
    case PROP_BASETIME:
      priv->basetime = g_value_get_uint64(value);
      GST_DEBUG_OBJECT(object, "new basetime: %lu", priv->basetime);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
      break;
  }
  GST_OBJECT_UNLOCK(signing);
}

static void
gst_signing_class_init(GstSigningClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS(klass);
  GstBaseTransformClass *transform_class = GST_BASE_TRANSFORM_CLASS(klass);

  GST_DEBUG_CATEGORY_INIT(gst_signing_debug, "signing", 0,
      "Add SEIs containing signatures for authentication");

  transform_class->start = GST_DEBUG_FUNCPTR(gst_signing_start);
  transform_class->stop = GST_DEBUG_FUNCPTR(gst_signing_stop);
  transform_class->set_caps = GST_DEBUG_FUNCPTR(gst_signing_set_caps);
  transform_class->transform_ip = GST_DEBUG_FUNCPTR(gst_signing_transform_ip);
  transform_class->sink_event = GST_DEBUG_FUNCPTR(gst_signing_sink_event);

  gst_element_class_set_static_metadata(element_class, "Media Signing", "Formatter/Video",
      "Add SEIs containing signatures for authentication.",
      "Media Signing Framework <github.com/onvif/media-signing-framework>");

  gst_element_class_add_static_pad_template(element_class, &sink_template);
  gst_element_class_add_static_pad_template(element_class, &src_template);

  gobject_class->finalize = gst_signing_finalize;
  gobject_class->get_property = gst_signing_get_property;
  gobject_class->set_property = gst_signing_set_property;
  // Install properties
  g_object_class_install_property(gobject_class, PROP_BASETIME,
      g_param_spec_uint64("basetime", "Default basetime", "Basetime", 0, UINT64_MAX, 0,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gst_signing_init(GstSigning *signing)
{
  signing->priv = gst_signing_get_instance_private(signing);
  signing->priv->last_pts = GST_CLOCK_TIME_NONE;
}

static void
gst_signing_finalize(GObject *object)
{
  GstSigning *signing = GST_SIGNING(object);

  GST_DEBUG_OBJECT(object, "finalized");
  terminate_signing(signing);

  G_OBJECT_CLASS(gst_signing_parent_class)->finalize(object);
}

static gboolean
gst_signing_start(GstBaseTransform *trans)
{
  GstSigning *signing = GST_SIGNING(trans);
  GstCaps *caps = NULL;
  gboolean res = TRUE;

  GST_DEBUG_OBJECT(signing, "start");
  caps = gst_pad_get_current_caps(GST_BASE_TRANSFORM_SRC_PAD(trans));
  if (caps != NULL) {
    res = setup_signing(signing, caps);
    gst_caps_unref(caps);
  } else {
    GST_DEBUG_OBJECT(signing, "caps not configured yet");
  }

  return res;
}

static gboolean
gst_signing_stop(GstBaseTransform *trans)
{
  GstSigning *signing = GST_SIGNING(trans);

  GST_DEBUG_OBJECT(signing, "stop");
  return terminate_signing(signing);
}

static gboolean
gst_signing_set_caps(GstBaseTransform *trans,
    G_GNUC_UNUSED GstCaps *incaps,
    GstCaps *outcaps)
{
  GstSigning *signing = GST_SIGNING(trans);

  GST_DEBUG_OBJECT(signing, "set_caps");
  return setup_signing(signing, outcaps);
}

static GstBuffer *
create_buffer_with_current_time(GstSigning *signing)
{
  GstSigningPrivate *priv = signing->priv;
  GstBuffer *buf = NULL;

  buf = gst_buffer_new();
  GST_BUFFER_PTS(buf) = priv->last_pts;
  return buf;
}

/* Add SEIs pulled from Media Signing. Returns the number of SEIs that were added to
 * |current_au|, or -1 on error. */
static gint
add_seis(GstSigning *signing,
    GstBuffer *current_au,
    gint idx,
    const guint8 *peek_nalu,
    gsize peek_nalu_size)
{
  MediaSigningReturnCode oms_rc = OMS_UNKNOWN_FAILURE;
  guint8 *sei = NULL;
  gsize sei_size = 0;
  gint add_count = 0;
  unsigned num_pending_seis = 0;

  oms_rc = onvif_media_signing_get_sei(signing->priv->media_signing, &sei, &sei_size,
      peek_nalu, peek_nalu_size, &num_pending_seis);
  while (oms_rc == OMS_OK && sei_size > 0) {
    GstMemory *prepend_mem;

#ifdef PRINT_DECODED_SEI
    onvif_media_signing_parse_sei(sei, sei_size, signing->priv->codec);
#endif
    // Write size into NALU header. The size value should be the data size, minus the size
    // of the size value itself
    GST_WRITE_UINT32_BE(sei, (guint32)(sei_size - sizeof(guint32)));

    GST_DEBUG_OBJECT(signing, "create a %" G_GSIZE_FORMAT "bytes SEI to add", sei_size);
    prepend_mem = gst_memory_new_wrapped(0, sei, sei_size, 0, sei_size, sei, g_free);
    gst_buffer_insert_memory(current_au, idx, prepend_mem);
    add_count++;

    oms_rc = onvif_media_signing_get_sei(signing->priv->media_signing, &sei, &sei_size,
        peek_nalu, peek_nalu_size, &num_pending_seis);
  }

  if (oms_rc != OMS_OK)
    goto get_nalu_failed;

  return add_count;

get_nalu_failed:
  GST_ERROR_OBJECT(signing, "onvif_media_signing_get_sei failed");
  return -1;
}

static GstFlowReturn
gst_signing_transform_ip(GstBaseTransform *trans, GstBuffer *buf)
{
  GstSigning *signing = GST_SIGNING(trans);
  GstSigningPrivate *priv = signing->priv;
  guint idx = 0;
  GstMemory *nalu_mem = NULL;
  GstMapInfo map_info;
  gint add_count = 0;
  gboolean added_sei = false;

  priv->last_pts = GST_BUFFER_PTS(buf);
  // last_pts is an GstClockTime object, which is measured in nanoseconds.
  GstClockTime cur_pts = priv->last_pts + priv->basetime;
  const gint64 timestamp_100nsec = (const gint64)(cur_pts / 100);
  // TODO: Convert to ONVIF timestamp format

  GST_DEBUG_OBJECT(signing, "got buffer with %d memories", gst_buffer_n_memory(buf));
  while (idx < gst_buffer_n_memory(buf)) {
    MediaSigningReturnCode oms_rc;

    nalu_mem = gst_buffer_peek_memory(buf, idx);

    if (G_UNLIKELY(!gst_memory_map(nalu_mem, &map_info, GST_MAP_READ))) {
      GST_ELEMENT_ERROR(signing, RESOURCE, FAILED, ("failed to map memory"), (NULL));
      goto map_failed;
    }

    // Depending on bitstream format the start code is optional, hence
    // media-signing-framework supports both. Therefore, since the start code in the
    // pipeline temporarily may have been replaced by the picture data size this format is
    // violated. To pass in valid input data, skip the first four bytes.
    add_count = add_seis(signing, buf, idx, &(map_info.data[4]), map_info.size - 4);
    if (add_count < 0) {
      GST_ELEMENT_ERROR(signing, STREAM, FAILED, ("failed to add nalus"), (NULL));
      goto get_seis_failed;
    }
    if (add_count > 0) {
      added_sei = true;
      gst_memory_unmap(nalu_mem, &map_info);
      nalu_mem = gst_buffer_peek_memory(buf, idx);
      if (G_UNLIKELY(!gst_memory_map(nalu_mem, &map_info, GST_MAP_READ))) {
        GST_ELEMENT_ERROR(signing, RESOURCE, FAILED, ("failed to map memory"), (NULL));
        goto map_failed;
      }
    }

    oms_rc = onvif_media_signing_add_nalu_for_signing(signing->priv->media_signing,
        &(map_info.data[4]), map_info.size - 4, timestamp_100nsec);
    if (oms_rc != OMS_OK) {
      GST_ELEMENT_ERROR(signing, STREAM, FAILED,
          ("failed to add nal unit for signing, error %d", oms_rc), (NULL));
      goto add_nalu_failed;
    }

    gst_memory_unmap(nalu_mem, &map_info);

    idx++;  // Go to next nalu
  }

  if (added_sei) {
    // Push an event to produce a message saying SEIs have been added.
    GstStructure *structure = gst_structure_new(
        SIGNING_STRUCTURE_NAME, SIGNING_FIELD_NAME, G_TYPE_STRING, "signed", NULL);
    if (!gst_element_post_message(GST_ELEMENT(trans),
            gst_message_new_element(GST_OBJECT(signing), structure))) {
      GST_ELEMENT_ERROR(signing, STREAM, FAILED, ("failed to push message"), (NULL));
    }
  }
  GST_DEBUG_OBJECT(signing, "push AU with %d nalus", gst_buffer_n_memory(buf));

  return GST_FLOW_OK;

get_seis_failed:
add_nalu_failed:
  gst_memory_unmap(nalu_mem, &map_info);
map_failed:
  return GST_FLOW_ERROR;
}

static void
push_access_unit_at_eos(GstSigning *signing)
{
  GstBaseTransform *trans = GST_BASE_TRANSFORM(signing);
  GstBuffer *au = NULL;

  if (onvif_media_signing_set_end_of_stream(signing->priv->media_signing) != OMS_OK) {
    GST_ERROR_OBJECT(signing, "failed to set EOS");
    goto eos_failed;
  }

  au = create_buffer_with_current_time(signing);
  if (add_seis(signing, au, 0, NULL, 0) < 0) {
    GST_ERROR_OBJECT(signing, "failed to add seis");
    goto add_sei_failed;
  }

  GST_DEBUG_OBJECT(signing, "push AU at EOS: %" GST_PTR_FORMAT, au);
  gst_pad_push(GST_BASE_TRANSFORM_SRC_PAD(trans), au);

  return;

add_sei_failed:
  gst_buffer_unref(au);
eos_failed:
  return;
}

static gboolean
terminate_signing(GstSigning *signing)
{
  GstSigningPrivate *priv = signing->priv;

  if (priv->media_signing != NULL) {
    onvif_media_signing_free(priv->media_signing);
    priv->media_signing = NULL;
  }

  return TRUE;
}

static gboolean
setup_signing(GstSigning *signing, GstCaps *caps)
{
  GstSigningPrivate *priv = signing->priv;
  GstStructure *structure = NULL;
  const gchar *media_type = NULL;
  MediaSigningCodec codec;
  char *private_key = NULL;
  size_t private_key_size = 0;
  char *certificate_chain = NULL;
  size_t certificate_chain_size = 0;

  g_assert(caps != NULL);

  if (priv->media_signing != NULL) {
    GST_DEBUG("already set-up");
    return TRUE;
  }

  GST_DEBUG("set up ONVIF Media Signing with caps %" GST_PTR_FORMAT, caps);

  structure = gst_caps_get_structure(caps, 0);
  media_type = gst_structure_get_name(structure);
  if (!g_strcmp0(media_type, "video/x-h264")) {
    codec = OMS_CODEC_H264;
  } else if (!g_strcmp0(media_type, "video/x-h265")) {
    codec = OMS_CODEC_H265;
  } else {
    GST_ERROR_OBJECT(signing, "unsupported video codec");
    goto unsupported_codec;
  }
  priv->codec = codec;

  GST_DEBUG_OBJECT(signing, "create ONVIF Media Signing object");
  priv->media_signing = onvif_media_signing_create(codec);
  if (!priv->media_signing) {
    GST_ERROR_OBJECT(signing, "could not create ONVIF Media Signing object");
    goto create_failed;
  }
  // Read pre-generated test EC key and certificate.
  if (!oms_read_test_private_key_and_certificate(true, &private_key, &private_key_size,
          &certificate_chain, &certificate_chain_size)) {
    GST_DEBUG_OBJECT(signing, "failed to read key and certificate files");
    goto read_private_key_failed;
  }
  if (onvif_media_signing_set_signing_key_pair(priv->media_signing, private_key,
          private_key_size, certificate_chain, certificate_chain_size, false) != OMS_OK) {
    GST_DEBUG_OBJECT(signing, "failed to set private key and certificate content");
    goto set_private_key_failed;
  }

  // Send properties information to video library.
  onvif_media_signing_vendor_info_t vendor_info = {0};
  strcpy(vendor_info.firmware_version, onvif_media_signing_get_version());
  strcpy(vendor_info.serial_number, "N/A");
  strcpy(vendor_info.manufacturer, "Media Signing Framework");
  if (onvif_media_signing_set_vendor_info(priv->media_signing, &vendor_info) != OMS_OK) {
    GST_ERROR_OBJECT(signing, "failed to set properties");
    goto vendor_info_failed;
  }

  g_free(certificate_chain);
  g_free(private_key);

  return TRUE;

vendor_info_failed:
set_private_key_failed:
read_private_key_failed:
  g_free(certificate_chain);
  g_free(private_key);
  onvif_media_signing_free(priv->media_signing);
  priv->media_signing = NULL;
create_failed:
unsupported_codec:
  return FALSE;
}

static gboolean
gst_signing_sink_event(GstBaseTransform *trans, GstEvent *event)
{
  GstSigning *signing = GST_SIGNING(trans);

  switch (GST_EVENT_TYPE(event)) {
    case GST_EVENT_EOS:
      push_access_unit_at_eos(signing);
      break;
    default:
      break;
  }

  return GST_BASE_TRANSFORM_CLASS(gst_signing_parent_class)->sink_event(trans, event);
}
