/************************************************************************************
 * Copyright (c) 2024 ONVIF.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of ONVIF nor the names of its contributors may be
 *      used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ONVIF BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ************************************************************************************/

#include "test_helpers.h"

#include <assert.h>  // assert
#include <check.h>

#include "lib/src/includes/onvif_media_signing_helpers.h"
#include "lib/src/oms_internal.h"
#include "lib/src/oms_tlv.h"

#define RSA_PRIVATE_KEY_ALLOC_BYTES 2000
#define ECDSA_PRIVATE_KEY_ALLOC_BYTES 1000

#define EC_KEY oms_generate_ecdsa_private_key

const int64_t g_testTimestamp = 133620480301234567;  // 08:00:30.1234567 UTC June 5, 2024

struct oms_setting settings[NUM_SETTINGS] = {
    {OMS_CODEC_H264, EC_KEY, NULL, false, false, 0, false, 0},
    {OMS_CODEC_H265, EC_KEY, NULL, false, false, 0, false, 0},
    {OMS_CODEC_H264, EC_KEY, NULL, true, false, 0, false, 0},
    {OMS_CODEC_H265, EC_KEY, NULL, true, false, 0, false, 0},
    {OMS_CODEC_H264, EC_KEY, NULL, false, true, 0, false, 0},
    {OMS_CODEC_H265, EC_KEY, NULL, false, true, 0, false, 0},
    {OMS_CODEC_H264, EC_KEY, NULL, true, true, 0, false, 0},
    {OMS_CODEC_H265, EC_KEY, NULL, true, true, 0, false, 0},
    // Special cases
    {OMS_CODEC_H264, EC_KEY, "sha512", false, true, 0, false, 0},
};

static char private_key_ecdsa[ECDSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t private_key_size_ecdsa;
static char certificate_chain_ecdsa[ECDSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t certificate_chain_size_ecdsa;
static char private_key_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t private_key_size_rsa;
static char certificate_chain_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t certificate_chain_size_rsa;

onvif_media_signing_t *
get_initialized_media_signing(MediaSigningCodec codec,
    generate_key_fcn_t generate_key,
    bool new_private_key)
{
  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);
  char *private_key = NULL;
  size_t private_key_size = 0;
  char *certificate_chain = NULL;
  size_t certificate_chain_size = 0;
  MediaSigningReturnCode rc;

  if (generate_key == oms_generate_ecdsa_private_key) {
    private_key = private_key_ecdsa;
    private_key_size = private_key_size_ecdsa;
    certificate_chain = certificate_chain_ecdsa;
    certificate_chain_size = certificate_chain_size_ecdsa;
  } else if (generate_key == oms_generate_rsa_private_key) {
    private_key = private_key_rsa;
    private_key_size = private_key_size_rsa;
    certificate_chain = certificate_chain_rsa;
    certificate_chain_size = certificate_chain_size_rsa;
  } else {
    onvif_media_signing_free(oms);
    return NULL;
  }

  // Generating private keys takes some time. In unit tests a new private key is only
  // generated if it is really needed. One RSA key and one ECDSA key is stored globally to
  // handle the scenario.
  if (private_key_size == 0 || new_private_key || certificate_chain_size == 0) {
    char *tmp_key = NULL;
    size_t tmp_key_size = 0;
    char *tmp_cert = NULL;
    size_t tmp_cert_size = 0;
    rc = generate_key("./", &tmp_key, &tmp_key_size, &tmp_cert, &tmp_cert_size);
    ck_assert_int_eq(rc, OMS_OK);
    memcpy(private_key, tmp_key, tmp_key_size);
    private_key_size = tmp_key_size;
    free(tmp_key);
    memcpy(certificate_chain, tmp_cert, tmp_cert_size);
    certificate_chain_size = tmp_cert_size;
    free(tmp_cert);
  }
  ck_assert(private_key && private_key_size > 0);
  ck_assert(certificate_chain && certificate_chain_size > 0);
  rc = onvif_media_signing_set_signing_key_pair(oms, private_key, private_key_size,
      certificate_chain, certificate_chain_size, false);
  ck_assert_int_eq(rc, OMS_OK);

  onvif_media_signing_vendor_info_t vendor_info = {0};
  strcpy(vendor_info.firmware_version, FW_VER);
  strcpy(vendor_info.serial_number, SER_NO);
  strcpy(vendor_info.manufacturer, MANUFACT);
  rc = onvif_media_signing_set_vendor_info(oms, &vendor_info);
  ck_assert_int_eq(rc, OMS_OK);

  return oms;
}

onvif_media_signing_t *
get_initialized_media_signing_by_setting(struct oms_setting setting, bool new_private_key)
{
  MediaSigningReturnCode omsrc = OMS_UNKNOWN_FAILURE;
  onvif_media_signing_t *oms =
      get_initialized_media_signing(setting.codec, setting.generate_key, new_private_key);
  ck_assert(oms);
  ck_assert_int_eq(
      onvif_media_signing_set_low_bitrate_mode(oms, setting.low_bitrate_mode), OMS_OK);
  ck_assert_int_eq(
      onvif_media_signing_set_low_bitrate_mode(oms, setting.low_bitrate_mode), OMS_OK);
  ck_assert_int_eq(onvif_media_signing_set_hash_algo(oms, setting.hash_algo), OMS_OK);
  omsrc = onvif_media_signing_set_emulation_prevention_before_signing(
      oms, setting.ep_before_signing);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = onvif_media_signing_set_max_sei_payload_size(oms, setting.max_sei_payload_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  return oms;
}

/* Pull SEIs from the onvif_media_signing_t session |oms| and prepend them to the test
 * stream |item|. */
static void
pull_seis(onvif_media_signing_t *oms, test_stream_item_t *item)
{
  size_t sei_size = 0;
  MediaSigningReturnCode rc =
      onvif_media_signing_get_sei(oms, NULL, &sei_size, NULL, 0, NULL);
  ck_assert_int_eq(rc, OMS_OK);

  while (rc == OMS_OK && sei_size != 0) {
    uint8_t *sei = malloc(sei_size);
    ck_assert_int_eq(
        onvif_media_signing_get_sei(oms, sei, &sei_size, NULL, 0, NULL), OMS_OK);
    // ck_assert(!signed_video_is_golden_sei(oms, sei, sei_size));
    // Generate a new test stream item with this SEI.
    test_stream_item_t *new_item = test_stream_item_create(sei, sei_size, oms->codec);
    // Prepend the |item| with this |new_item|.
    test_stream_item_prepend(item, new_item);
    // Ask for next completed SEI.
    rc = onvif_media_signing_get_sei(oms, NULL, &sei_size, NULL, 0, NULL);
    ck_assert_int_eq(rc, OMS_OK);
  }
}

/* Generates a Media Signing test stream for a user-owned onvif_media_signing_t session.
 *
 * Takes a string of NAL Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates NAL Unit data for these. Then adds these NAL Units to the input session. The
 * generated SEIs are added to the stream. */
test_stream_t *
create_signed_nalus_with_oms(onvif_media_signing_t *oms,
    const char *str,
    bool split_nalus,
    bool get_seis_at_end)
{
  MediaSigningReturnCode rc = OMS_UNKNOWN_FAILURE;
  ck_assert(oms);

  // Create a test stream given the input string.
  test_stream_t *list = test_stream_create(str, oms->codec);
  test_stream_item_t *item = list->first_item;

  // Loop through the NAL Units and add for signing.
  while (item) {
    // ck_assert(!onvif_media_signing_is_golden_sei(oms, item->data, item->data_size));
    if (split_nalus) {
      // Split the NAL Unit into 2 parts, where the last part inlcudes the ID and the stop
      // bit.
      rc = onvif_media_signing_add_nalu_part_for_signing(
          oms, item->data, item->data_size - 2, g_testTimestamp, false);
      ck_assert_int_eq(rc, OMS_OK);
      rc = onvif_media_signing_add_nalu_part_for_signing(
          oms, &item->data[item->data_size - 2], 2, g_testTimestamp, true);
    } else {
      rc = onvif_media_signing_add_nalu_part_for_signing(
          oms, item->data, item->data_size, g_testTimestamp, true);
    }
    ck_assert_int_eq(rc, OMS_OK);
    // Pull all SEIs and add them into the test stream.
    if (!get_seis_at_end) {
      pull_seis(oms, item);
    }

    if (item->next == NULL) {
      if (get_seis_at_end) {
        pull_seis(oms, item);
      }
      break;
    }
    item = item->next;
  }

  // Since we have prepended individual items in the list, we have lost the list state and
  // need to update it.
  test_stream_refresh(list);

  return list;
}

/* Generates a Media Signing test stream for the selected setting. The stream is returned
 * as a test_stream_t.
 *
 * Takes a string of NAL Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates NAL Unit data for these. Then a onvif_media_signing_t session is created
 * given the input |setting|. The generated NAL Units are then passed through the signing
 * process and corresponding generated SEIs are added to the test stream. If
 * |new_private_key| is 'true' then a new private key is generated else an already
 * generated private key is used. If the NAL Unit data should be split into parts, mark
 * the |split_nalus| flag. */
static test_stream_t *
create_signed_splitted_nalus_int(const char *str,
    struct oms_setting setting,
    bool new_private_key,
    bool split_nalus)
{
  if (!str)
    return NULL;

  MediaSigningReturnCode omsrc = OMS_UNKNOWN_FAILURE;
  onvif_media_signing_t *oms =
      get_initialized_media_signing(setting.codec, setting.generate_key, new_private_key);
  ck_assert(oms);
  ck_assert_int_eq(
      onvif_media_signing_set_low_bitrate_mode(oms, setting.low_bitrate_mode), OMS_OK);
  ck_assert_int_eq(
      onvif_media_signing_set_low_bitrate_mode(oms, setting.low_bitrate_mode), OMS_OK);
  ck_assert_int_eq(onvif_media_signing_set_hash_algo(oms, setting.hash_algo), OMS_OK);
  omsrc = onvif_media_signing_set_emulation_prevention_before_signing(
      oms, setting.ep_before_signing);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = onvif_media_signing_set_max_sei_payload_size(oms, setting.max_sei_payload_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = onvif_media_signing_set_max_signing_nalus(oms, setting.max_signing_nalus);
  ck_assert_int_eq(omsrc, OMS_OK);

  // Create a test stream of NAL Units given the input string.
  test_stream_t *list = create_signed_nalus_with_oms(oms, str, split_nalus, false);
  onvif_media_signing_free(oms);

  return list;
}

/* See function create_signed_nalus_int */
test_stream_t *
create_signed_nalus(const char *str, struct oms_setting setting)
{
  return create_signed_splitted_nalus_int(str, setting, false, false);
}

/* See function create_signed_nalus_int, with the diffrence that each NAL Unit is split in
 * two parts. */
test_stream_t *
create_signed_splitted_nalus(const char *str, struct oms_setting setting)
{
  return create_signed_splitted_nalus_int(str, setting, false, true);
}

/* Creates a test_stream_t with all the NAL Units produced after signing. This mimic what
 * leaves the camera.
 *
 * The input is a string of characters representing the type of NAL Units passed into the
 * signing session.
 * Example-1: 'IPPIPP' will push two identical GOPs
 *   I-nalu, P-nalu, P-nalu.
 * Example-2: for multi slice, 'IiPpPpIiPpPp' will push two identical GOPs
 *   I-nalu, i-nalu, P-nalu, p-nalu, P-nalu, p-nalu.
 * Valid characters are:
 *   I: I-nalu Indicates first slice in the current I nalu
 *   i: i-nalu Indicates other than first slice. Example: second and third slice
 *   P: P-nalu Indicates first slice in the current P nalu
 *   p: p-nalu Indicates other than first slice. Example: second and third slice
 *   S: Non signed-video-framework SEI
 *   X: Invalid nalu, i.e., not a H.26x nalu.
 *
 * setting = the session setup for this test.
 * new_private_key = Generate a new private key or not.
 */
test_stream_t *
create_signed_nalus_int(const char __attribute__((unused)) * str,
    struct oms_setting __attribute__((unused)) setting,
    bool __attribute__((unused)) new_private_key)
{
  return NULL;
}

/* Removes the NAL Unit item with position |item_number| from the test stream |list|. The
 * item is, after a check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t __attribute__((unused)) * list,
    int __attribute__((unused)) item_number,
    char __attribute__((unused)) type)
{
}

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t __attribute__((unused)) * list,
    int __attribute__((unused)) item_number,
    char __attribute__((unused)) type)
{
}

bool
tlv_has_optional_tags(const uint8_t *tlv_data, size_t tlv_data_size)
{
  bool has_optional_tags = false;
  size_t num_tags = 0;
  const oms_tlv_tag_t *tags = get_optional_tags(&num_tags);
  for (size_t ii = 0; ii < num_tags; ii++) {
    const uint8_t *this_tag = tlv_find_tag(tlv_data, tlv_data_size, tags[ii], false);
    has_optional_tags |= (this_tag != NULL);
  }
  return has_optional_tags;
}

bool
tlv_has_mandatory_tags(const uint8_t *tlv_data, size_t tlv_data_size)
{
  bool has_mandatory_tags = false;
  size_t num_tags = 0;
  const oms_tlv_tag_t *tags = get_mandatory_tags(&num_tags);
  for (size_t ii = 0; ii < num_tags; ii++) {
    const uint8_t *this_tag = tlv_find_tag(tlv_data, tlv_data_size, tags[ii], false);
    has_mandatory_tags |= (this_tag != NULL);
  }
  return has_mandatory_tags;
}
