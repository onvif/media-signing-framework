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

#define EC_PRIVATE_KEY_ALLOC_BYTES 1000
#define RSA_PRIVATE_KEY_ALLOC_BYTES 2000

const int64_t g_testTimestamp = 133620480301234567;  // 08:00:30.1234567 UTC June 5, 2024

static unsigned int num_gops_until_signing = 0;
static unsigned int delay_until_pull = 0;

// struct oms_setting {
//   MediaSigningCodec codec;
//   bool ec_key;
//   const char* hash_algo;
//   bool low_bitrate_mode;
//   bool ep_before_signing;
//   size_t max_sei_payload_size;
//   bool with_certificate_sei;
//   unsigned max_signing_nalus;
//   unsigned signing_frequency;
//   int delay;
//   bool get_seis_at_end;
//   bool force_no_ep;
// };
struct oms_setting settings[NUM_SETTINGS] = {
    {OMS_CODEC_H264, true, NULL, false, false, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H265, true, NULL, false, false, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H264, true, NULL, true, false, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H265, true, NULL, true, false, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H264, true, NULL, false, true, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H265, true, NULL, false, true, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H264, true, NULL, true, true, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H265, true, NULL, true, true, 0, false, 0, 1, 0, false, false},
    // Special cases
    {OMS_CODEC_H264, true, "sha512", false, true, 0, false, 0, 1, 0, false, false},
    {OMS_CODEC_H264, false, NULL, false, false, 0, false, 0, 1, 0, false, false},
};

static char private_key_ec[EC_PRIVATE_KEY_ALLOC_BYTES];
static size_t private_key_size_ec;
static char certificate_chain_ec[EC_PRIVATE_KEY_ALLOC_BYTES];
static size_t certificate_chain_size_ec;
static char private_key_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t private_key_size_rsa;
static char certificate_chain_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t certificate_chain_size_rsa;

onvif_media_signing_t *
get_initialized_media_signing(MediaSigningCodec codec, bool ec_key, bool new_private_key)
{
  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);
  char *private_key = NULL;
  size_t *private_key_size = NULL;
  char *certificate_chain = NULL;
  size_t *certificate_chain_size = NULL;
  MediaSigningReturnCode rc;

  if (ec_key) {
    private_key = private_key_ec;
    private_key_size = &private_key_size_ec;
    certificate_chain = certificate_chain_ec;
    certificate_chain_size = &certificate_chain_size_ec;
  } else {
    private_key = private_key_rsa;
    private_key_size = &private_key_size_rsa;
    certificate_chain = certificate_chain_rsa;
    certificate_chain_size = &certificate_chain_size_rsa;
  }

  // Generating private keys takes some time. In unit tests a new private key is only
  // generated if it is really needed. One RSA key and one ECDSA key is stored globally to
  // handle the scenario.
  if (*private_key_size == 0 || new_private_key || *certificate_chain_size == 0) {
    char *tmp_key = NULL;
    size_t tmp_key_size = 0;
    char *tmp_cert = NULL;
    size_t tmp_cert_size = 0;
    ck_assert(oms_read_test_private_key_and_certificate(
        ec_key, &tmp_key, &tmp_key_size, &tmp_cert, &tmp_cert_size));
    memcpy(private_key, tmp_key, tmp_key_size);
    *private_key_size = tmp_key_size;
    free(tmp_key);
    memcpy(certificate_chain, tmp_cert, tmp_cert_size);
    *certificate_chain_size = tmp_cert_size;
    free(tmp_cert);
  }
  ck_assert(private_key && *private_key_size > 0);
  ck_assert(certificate_chain && *certificate_chain_size > 0);
  rc = onvif_media_signing_set_signing_key_pair(oms, private_key, *private_key_size,
      certificate_chain, *certificate_chain_size, false);
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
      get_initialized_media_signing(setting.codec, setting.ec_key, new_private_key);
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
 * stream |item|. Using test stream item as peek NAL Unit. */
static int
pull_seis(onvif_media_signing_t *oms,
    test_stream_item_t **item,
    bool apply_ep,
    unsigned int delay)
{
  bool no_delay = (delay_until_pull == 0);
  int num_seis = 0;
  size_t sei_size = 0;
  uint8_t *peek_nalu = (*item)->data;
  size_t peek_nalu_size = (*item)->data_size;
  MediaSigningReturnCode rc =
      onvif_media_signing_get_sei(oms, NULL, &sei_size, peek_nalu, peek_nalu_size, NULL);
  ck_assert_int_eq(rc, OMS_OK);
  // To be really correct only I- & P-frames should be counted, but since this is in test
  // code it is of less importance. It only means that the SEI shows up earlier in the
  // test_stream.
  if (!no_delay && sei_size != 0) {
    delay_until_pull--;
  }

  while (rc == OMS_OK && sei_size != 0 && no_delay) {
    uint8_t *sei = malloc(sei_size);
    rc =
        onvif_media_signing_get_sei(oms, sei, &sei_size, peek_nalu, peek_nalu_size, NULL);
    ck_assert_int_eq(rc, OMS_OK);
    // Handle delay counters.
    if (num_gops_until_signing == 0) {
      num_gops_until_signing = oms->signing_frequency;
    }
    num_gops_until_signing--;
    if (num_gops_until_signing == 0) {
      delay_until_pull = delay;
    }
    no_delay = delay_until_pull == 0;
    // Apply emulation prevention.
    if (apply_ep) {
      uint8_t *tmp = malloc(sei_size * 4 / 3);
      memcpy(tmp, sei, 4);  // Copy start code
      uint8_t *tmp_ptr = tmp + 4;
      const uint8_t *sei_ptr = sei + 4;
      while ((size_t)(sei_ptr - sei) < sei_size) {
        if (*(tmp_ptr - 2) == 0 && *(tmp_ptr - 1) == 0 && !(*sei_ptr & 0xfc)) {
          // Add emulation prevention byte
          *tmp_ptr = 3;
          tmp_ptr++;
        }
        *tmp_ptr = *sei_ptr;
        tmp_ptr++;
        sei_ptr++;
      }
      // Update size, free the old SEI and assign the new.
      sei_size = (tmp_ptr - tmp);
      free(sei);
      sei = tmp;
    }
    // Generate a new test stream item with this SEI.
    test_stream_item_t *new_item = test_stream_item_create(sei, sei_size, oms->codec);
    // Prepend the |item| with this |new_item|.
    test_stream_item_prepend(*item, new_item);
    num_seis++;
    // Ask for next completed SEI.
    rc = onvif_media_signing_get_sei(
        oms, NULL, &sei_size, peek_nalu, peek_nalu_size, NULL);
    ck_assert_int_eq(rc, OMS_OK);
  }
  int pulled_seis = num_seis;
  while (num_seis > 0) {
    *item = (*item)->prev;
    num_seis--;
  }
  return pulled_seis;
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
    bool get_seis_at_end,
    bool apply_ep,
    int delay)
{
  MediaSigningReturnCode rc = OMS_UNKNOWN_FAILURE;
  ck_assert(oms);

  // Create a test stream given the input string.
  test_stream_t *list = test_stream_create(str, oms->codec);
  test_stream_item_t *item = list->first_item;
  int64_t timestamp = g_testTimestamp;
  num_gops_until_signing = oms->signing_frequency - 1;
  delay_until_pull = num_gops_until_signing ? 0 : delay;

  // Loop through the NAL Units and add for signing.
  while (item) {
    // Pull all SEIs and add them into the test stream.
    int pulled_seis = 0;
    if (!get_seis_at_end || (get_seis_at_end && item->next == NULL)) {
      pulled_seis = pull_seis(oms, &item, apply_ep, delay);
    }
    if (split_nalus && pulled_seis == 0) {
      // Split the NAL Unit into 2 parts, where the last part inlcudes the ID and the stop
      // bit.
      rc = onvif_media_signing_add_nalu_part_for_signing(
          oms, item->data, item->data_size - 2, timestamp, false);
      ck_assert_int_eq(rc, OMS_OK);
      rc = onvif_media_signing_add_nalu_part_for_signing(
          oms, &item->data[item->data_size - 2], 2, timestamp, true);
    } else {
      rc = onvif_media_signing_add_nalu_part_for_signing(
          oms, item->data, item->data_size, timestamp, true);
    }
    ck_assert_int_eq(rc, OMS_OK);
    timestamp += 400000;  // One frame if 25 fps.

    if (item->next == NULL) {
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
      get_initialized_media_signing(setting.codec, setting.ec_key, new_private_key);
  ck_assert(oms);
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
  omsrc = onvif_media_signing_set_signing_frequency(oms, setting.signing_frequency);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = onvif_media_signing_set_use_certificate_sei(oms, setting.with_certificate_sei);
  ck_assert_int_eq(omsrc, OMS_OK);
  if (setting.with_certificate_sei) {
    omsrc = onvif_media_signing_generate_certificate_sei(oms);
    ck_assert_int_eq(omsrc, OMS_OK);
  }

  // Create a test stream of NAL Units given the input string.
  bool apply_ep = !setting.ep_before_signing && !setting.force_no_ep;
  test_stream_t *list = create_signed_nalus_with_oms(
      oms, str, split_nalus, setting.get_seis_at_end, apply_ep, setting.delay);
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
remove_item_then_check_and_free(test_stream_t *list, int item_number, char type)
{
  if (!list) {
    return;
  }
  test_stream_item_t *item = test_stream_item_remove(list, item_number);
  test_stream_item_check_type(item, type);
  test_stream_item_free(item);
}

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t *list, int item_number, char type)
{
  if (!list) {
    return;
  }
  test_stream_item_t *item = test_stream_item_get(list, item_number);
  test_stream_item_check_type(item, type);
  // Modifying id byte by bit flipping it
  item->data[item->data_size - 2] = ~item->data[item->data_size - 2];
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

bool
test_helper_set_trusted_certificate(onvif_media_signing_t *oms)
{
  char *trusted_certificate = NULL;
  size_t trusted_certificate_size = 0;
  ck_assert(
      oms_read_test_trusted_certificate(&trusted_certificate, &trusted_certificate_size));

  MediaSigningReturnCode oms_rc = onvif_media_signing_set_trusted_certificate(
      oms, trusted_certificate, trusted_certificate_size, false);
  free(trusted_certificate);
  return (oms_rc == OMS_OK);
}
