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

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "lib/src/includes/onvif_media_signing_common.h"
#include "lib/src/includes/onvif_media_signing_helpers.h"
#include "lib/src/includes/onvif_media_signing_signer.h"
#include "lib/src/oms_internal.h"
#include "lib/src/oms_tlv.h"
#include "test_helpers.h"
#include "test_stream.h"

#define TEST_DATA_SIZE 42
// static const char test_data[TEST_DATA_SIZE] = {0};
// static const uint8_t *nalu = (uint8_t *)test_data;

static onvif_media_signing_vendor_info_t vendor_info = {0};

static void
setup()
{
  strcpy(vendor_info.firmware_version, "signer tests: firmware_version");
  strcpy(vendor_info.serial_number, "signer tests: serial_number");
  strcpy(vendor_info.manufacturer, "signer tests: manufacturer");
}

static void
teardown()
{
}

static void
verify_seis(test_stream_t *list, struct oms_setting setting)
{
  if (!list) {
    return;
  }
  int num_seis = 0;
  test_stream_item_t *item = list->first_item;
  while (item) {
    nalu_info_t nalu_info =
        parse_nalu_info(item->data, item->data_size, list->codec, false, true);
    if (nalu_info.is_oms_sei) {
      num_seis++;
      const uint8_t *signature_ptr =
          tlv_find_tag(nalu_info.tlv_data, nalu_info.tlv_size, SIGNATURE_TAG, false);
      const uint8_t *hash_list_ptr =
          tlv_find_tag(nalu_info.tlv_data, nalu_info.tlv_size, HASH_LIST_TAG, false);
      bool has_optional_tags =
          tlv_has_optional_tags(nalu_info.tlv_data, nalu_info.tlv_size);
      bool has_mandatory_tags =
          tlv_has_mandatory_tags(nalu_info.tlv_data, nalu_info.tlv_size);

      ck_assert_int_eq(nalu_info.with_epb, setting.ep_before_signing);
      if (setting.max_sei_payload_size > 0) {
        // Verify te SEI size. This overrides the low_bitrate_mode.
        ck_assert_uint_le(nalu_info.payload_size, setting.max_sei_payload_size);
      } else if (!nalu_info.is_golden_sei) {
        // Check that there is no hash list in low bitrate mode.
        setting.low_bitrate_mode ? ck_assert(!hash_list_ptr) : ck_assert(hash_list_ptr);
      }
      // Verify that a golden SEI can only occur as a first SEI (in tests).
      if (num_seis == 1) {
        ck_assert_int_eq(nalu_info.is_golden_sei, setting.with_golden_sei);
      } else {
        ck_assert_int_eq(nalu_info.is_golden_sei, false);
      }
      // Verify that a golden SEI does not have mandatory tags, but all others do.
      ck_assert(nalu_info.is_golden_sei ^ has_mandatory_tags);
      // When a stream is set up to use golden SEIs only the golden SEI should include the
      // partial tags.
      if (setting.with_golden_sei) {
        ck_assert(!(nalu_info.is_golden_sei ^ has_optional_tags));
      } else {
        ck_assert(has_optional_tags);
        // Verify that a golden SEI can only occur as a first SEI (in tests).
        if (num_seis % setting.signing_frequency == 0) {
          ck_assert(nalu_info.is_signed);
        } else {
          ck_assert(!nalu_info.is_signed);
        }
      }
      // Verify that a golden SEI has a signature.
      if (nalu_info.is_golden_sei) {
        ck_assert(signature_ptr);
      }
#ifdef PRINT_DECODED_SEI
      printf("\n--- SEI # %d ---\n", num_seis);
      onvif_media_signing_parse_sei(item->data, item->data_size, list->codec);
#endif
    }
    free(nalu_info.nalu_wo_epb);
    item = item->next;
  }
}

/* Test description
 * All public APIs are checked for invalid parameters, and valid NULL pointer inputs. This
 * is done for both H.264 and H.265.
 */
START_TEST(api_inputs)
{
  // MediaSigningReturnCode oms_rc;
  MediaSigningCodec codec = settings[_i].codec;
  char *private_key = NULL;
  size_t private_key_size = 0;
  char *certificate_chain = NULL;
  size_t certificate_chain_size = 0;

  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);

  // Read content of private_key.
  ck_assert(oms_read_private_key_and_certificate(settings[_i].ec_key, &private_key,
      &private_key_size, &certificate_chain, &certificate_chain_size));
#if 0
  oms_rc = onvif_media_signing_set_signing_key_pair(
      NULL, test_data, TEST_DATA_SIZE, test_data, TEST_DATA_SIZE, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_signing_key_pair(
      oms, NULL, TEST_DATA_SIZE, test_data, TEST_DATA_SIZE, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_signing_key_pair(
      oms, test_data, 0, test_data, TEST_DATA_SIZE, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_signing_key_pair(
      oms, test_data, TEST_DATA_SIZE, NULL, TEST_DATA_SIZE, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_signing_key_pair(
      oms, test_data, TEST_DATA_SIZE, test_data, 0, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  // TODO: Remove when supported
  oms_rc = onvif_media_signing_set_signing_key_pair(
      oms, test_data, TEST_DATA_SIZE, test_data, TEST_DATA_SIZE, true);
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);
  oms_rc = onvif_media_signing_set_signing_key_pair(oms, private_key, private_key_size,
      certificate_chain, certificate_chain_size, false);
  ck_assert_int_eq(oms_rc, OMS_OK);

  oms_rc = onvif_media_signing_generate_golden_sei(NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_generate_golden_sei(oms);
  ck_assert_int_eq(oms_rc, OMS_OK);

  // Check configuration setters
  oms_rc = onvif_media_signing_set_signing_frequency(NULL, 1);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_signing_frequency(oms, 0);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_max_signing_nalus(NULL, 1);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_use_golden_sei(NULL, true);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_low_bitrate_mode(NULL, settings[_i].low_bitrate_mode);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_max_sei_payload_size(NULL, 1);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_emulation_prevention_before_signing(NULL, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_hash_algo(NULL, settings[_i].hash_algo);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_hash_algo(oms, "bogus-algo");
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_vendor_info(NULL, &vendor_info);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_vendor_info(oms, NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_add_nalu_for_signing(
      NULL, nalu, TEST_DATA_SIZE, g_testTimestamp);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_add_nalu_for_signing(
      oms, NULL, TEST_DATA_SIZE, g_testTimestamp);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_add_nalu_for_signing(oms, nalu, 0, g_testTimestamp);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_add_nalu_part_for_signing(
      NULL, nalu, TEST_DATA_SIZE, g_testTimestamp, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_add_nalu_part_for_signing(
      oms, NULL, TEST_DATA_SIZE, g_testTimestamp, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc =
      onvif_media_signing_add_nalu_part_for_signing(oms, nalu, 0, g_testTimestamp, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  size_t sei_size = 0;
  oms_rc = onvif_media_signing_get_sei(NULL, NULL, &sei_size, NULL, 0, NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_get_sei(oms, NULL, 0, NULL, 0, NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  // Checking onvif_media_signing_set_end_of_stream() for NULL pointers.
  oms_rc = onvif_media_signing_set_end_of_stream(NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
#endif
  free(private_key);
  free(certificate_chain);
  onvif_media_signing_free(oms);
}
END_TEST

/* Test description
 * If the user does not follow the correct operation OMS_NOT_SUPPORTED should be returned.
 */
START_TEST(incorrect_operation)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  MediaSigningReturnCode oms_rc;
  MediaSigningCodec codec = settings[_i].codec;
  char *private_key = NULL;
  size_t private_key_size = 0;
  char *certificate_chain = NULL;
  size_t certificate_chain_size = 0;

  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);

  ck_assert(oms_read_private_key_and_certificate(settings[_i].ec_key, &private_key,
      &private_key_size, &certificate_chain, &certificate_chain_size));

  // Operations that requires a signing key
  oms_rc = onvif_media_signing_generate_golden_sei(oms);
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);
  oms_rc = onvif_media_signing_add_nalu_for_signing(
      oms, i_nalu->data, i_nalu->data_size, g_testTimestamp);
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);

  oms_rc = onvif_media_signing_set_signing_key_pair(oms, private_key, private_key_size,
      certificate_chain, certificate_chain_size, false);
  ck_assert_int_eq(oms_rc, OMS_OK);
  oms_rc = onvif_media_signing_set_hash_algo(oms, settings[_i].hash_algo);
  ck_assert_int_eq(oms_rc, OMS_OK);
  oms_rc = onvif_media_signing_set_low_bitrate_mode(oms, settings[_i].low_bitrate_mode);
  ck_assert_int_eq(oms_rc, OMS_OK);

  // Ending stream before it has started is not supported.
  oms_rc = onvif_media_signing_set_end_of_stream(oms);
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);

  oms_rc = onvif_media_signing_add_nalu_for_signing(
      oms, i_nalu->data, i_nalu->data_size, g_testTimestamp);
  ck_assert_int_eq(oms_rc, OMS_OK);

  // Verify not supported actions after a session has started.
  oms_rc = onvif_media_signing_set_use_golden_sei(oms, true);
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);
  oms_rc = onvif_media_signing_set_hash_algo(oms, "sha512");
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);

  // Free test stream item, session and private key pair.
  test_stream_item_free(i_nalu);
  onvif_media_signing_free(oms);
  free(private_key);
  free(certificate_chain);
}
END_TEST

/* Test description
 * In this test checks that SEIs are generated when they should.
 * No EOS is set after the last NAL Unit.
 */
START_TEST(correct_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPP");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

#if 0
START_TEST(correct_nalu_sequence_with_eos)
{
  /* This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
   * in |settings|; See test_helpers.h. */

  test_stream_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPS");
  test_stream_free(list);
}
END_TEST
#endif

/* Test description
 * In this test checks that SEIs are generated when they should for a multi sliced video.
 * No EOS is set after the last NAL Unit.
 */
START_TEST(correct_multislice_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPpIiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "IiPpPpIiSPpPpIiSPpPpIiSPpPp");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

#if 0
// TODO: Enabled when we have better support and knowledge about EOS.
START_TEST(correct_multislice_sequence_with_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
  // in |settings|; See test_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "SIiPpPpSIiPpPpS");
  test_stream_free(list);
}
END_TEST
#endif

/* Test description
 * Add
 *   IPPIPPPPPI
 * which results in
 *   SIPPSIPPPPPSI
 * When the gop length increases, the size of the generated SEI also increases unless
 * the low_bitrate_mode is enabled for which it is independent of the gop length.
 *
 * In this test a test stream is generated with five SEI, where the last GOP is longer
 * than the previous. Before both the GOP hash and the linked hash are present there will
 * be too many emulation prevention bytes for comparing sizes.
 */
START_TEST(sei_increase_with_gop_length)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPPPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPPPPISP");
  verify_seis(list, settings[_i]);
  test_stream_item_t *sei_long_gop = test_stream_item_remove(list, 20);
  test_stream_item_check_type(sei_long_gop, 'S');
  test_stream_item_t *sei_short_gop = test_stream_item_remove(list, 13);
  test_stream_item_check_type(sei_short_gop, 'S');
  if (settings[_i].low_bitrate_mode) {
    // Verify constant size. Note that the size differs if more emulation prevention bytes
    // have been added in one SEI compared to the other. Allow for one extra byte.
    // ck_assert_int_le(abs((int)sei_1->data_size - (int)sei_2->data_size), 1);
    ck_assert_int_le(
        abs((int)sei_long_gop->data_size - (int)sei_short_gop->data_size), 1);
  } else {
    // Verify increased size.
    ck_assert_uint_lt(sei_short_gop->data_size, sei_long_gop->data_size);
  }
  test_stream_item_free(sei_short_gop);
  test_stream_item_free(sei_long_gop);
  test_stream_free(list);
}
END_TEST

/* Test description
 * In this test we check if an undefined NAL Unit is passed through silently.
 * Add
 *   IPXPIPP
 * Then we should get
 *   SIPXPSIPPS
 */
START_TEST(undefined_nalu_in_sequence)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  test_stream_t *list = create_signed_nalus("IPXPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPXPISPPISP");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that SEIs are emitted in correct order.
 * The operation is as follows:
 * 1. Setup a onvif_media_signing_t session
 * 2. Add 2 GOPs of different length and an extra I-frame to trigger 2 SEIs
 * 3. Get the SEIs
 * 4. Check by size that the SEIs are emitted in correct order
 *
 * Note that this only applies when low bitrate mode is disabled.
 */
START_TEST(get_seis_in_correct_order)
{
  // By construction, run the test when not in low bitrate mode.
  if (settings[_i].low_bitrate_mode) {
    return;
  }

  onvif_media_signing_t *oms =
      get_initialized_media_signing_by_setting(settings[_i], false);
  ck_assert(oms);

  test_stream_t *list = create_signed_nalus_with_oms(oms, "IIPPIP", false, true);
  test_stream_check_types(list, "IIPPISSP");
  verify_seis(list, settings[_i]);

  // Analyze SEIs in order
  size_t sei_sizes[2] = {0};
  for (int ii = 0; ii < 2; ii++) {
    test_stream_item_t *sei = test_stream_item_remove(list, 6);
    test_stream_item_check_type(sei, 'S');
    sei_sizes[ii] = sei->data_size;
    test_stream_item_free(sei);
  }
  // The second SEI has a larger |hash_list|, hence larger size
  ck_assert_int_lt(sei_sizes[0], sei_sizes[1]);

  test_stream_free(list);
  onvif_media_signing_free(oms);
}
END_TEST

/* Test description
 * Generates a golden SEI before starting a test stream.
 */
START_TEST(start_stream_with_golden_sei)
{
  struct oms_setting setting = settings[_i];
  setting.with_golden_sei = true;
  onvif_media_signing_t *oms = get_initialized_media_signing_by_setting(setting, false);
  ck_assert(oms);

  MediaSigningReturnCode omsrc;
  // Configuring to use golden SEIs should not affect generating it.
  omsrc = onvif_media_signing_set_use_golden_sei(oms, setting.with_golden_sei);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = onvif_media_signing_generate_golden_sei(oms);
  ck_assert_int_eq(omsrc, OMS_OK);

  test_stream_t *list = create_signed_nalus_with_oms(oms, "IPPIPPPIP", false, false);
  test_stream_check_types(list, "GIPPISPPPISP");
  verify_seis(list, setting);
  test_stream_free(list);

  onvif_media_signing_free(oms);
}
END_TEST

/* Test description
 * Same as correct_nalu_sequence_without_eos, but with splitted NAL Unit data.
 */
START_TEST(correct_signing_nalus_in_parts)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  test_stream_t *list = create_signed_splitted_nalus("IPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISP");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify the setter for generating SEI frames with or without emulation prevention bytes.
 */
#define NUM_EPB_CASES 2
START_TEST(w_wo_emulation_prevention_bytes)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  struct oms_setting setting = settings[_i];
  size_t sei_sizes[NUM_EPB_CASES] = {0, 0};
  bool with_emulation_prevention[NUM_EPB_CASES] = {true, false};

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    setting.ep_before_signing = with_emulation_prevention[ii];
    onvif_media_signing_t *oms = get_initialized_media_signing_by_setting(setting, false);
    ck_assert(oms);

    test_stream_t *list = create_signed_nalus_with_oms(oms, "IIP", false, true);
    test_stream_check_types(list, "IISP");
    verify_seis(list, setting);

    test_stream_item_t *sei = test_stream_item_remove(list, 3);
    test_stream_item_check_type(sei, 'S');
    sei_sizes[ii] = sei->data_size;
    test_stream_item_free(sei);
    test_stream_free(list);
    onvif_media_signing_free(oms);
  }

  // Verify that the SEI sizes differ. By construction, the first SEI will include
  // emulation prevention since the linked hash is empty.
  ck_assert(sei_sizes[0] > sei_sizes[1]);
}
END_TEST

/* Test description
 * Verify the setter for maximum SEI payload size. */
START_TEST(limited_sei_payload_size)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  // No need to run this in low bitrate mode, since the size cannot dynamically change.
  if (settings[_i].low_bitrate_mode) {
    return;
  }

  struct oms_setting setting = settings[_i];
  // Select an upper payload limit which is less then the size of the last SEI.
  size_t max_sei_payload_size = 1000;
  if (!setting.ec_key) {
    max_sei_payload_size += 750;  // Extra for RSA keys being larger than EC
  }
  setting.max_sei_payload_size = max_sei_payload_size;
  test_stream_t *list = create_signed_nalus("IPPIPPPPPPPPPPPPIP", setting);
  test_stream_check_types(list, "IPPISPPPPPPPPPPPPISP");
  verify_seis(list, setting);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify the setter for maximum signing NAL Units, that is, trigger signing partial
 * GOPs. */
START_TEST(signing_partial_gops)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  struct oms_setting setting = settings[_i];
  // Select an upper payload limit which is less then the size of the last SEI.
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPIPPPPPPPPPPPPIPPPIP", setting);
  test_stream_check_types(list, "IPPISPPPPSPPPPSPPPPSISPPPISP");
  verify_seis(list, setting);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify the signing frequency setter, that is, signing multiple GOPs. */
START_TEST(signing_multiple_gops)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned signing_frequency = 2;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPISPPIsPPISP");
  verify_seis(list, setting);

  test_stream_free(list);
}
END_TEST

/* Verifies that SEIs are always displayed if not using NAL Unit peek. */
START_TEST(display_sei_if_not_peek)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See test_helpers.h.

  MediaSigningReturnCode omsrc;
  struct oms_setting setting = settings[_i];
  test_stream_item_t *Is[3] = {0};
  onvif_media_signing_t *oms = get_initialized_media_signing_by_setting(setting, false);
  ck_assert(oms);

  Is[0] = test_stream_item_create_from_type('I', 1, setting.codec);
  Is[1] = test_stream_item_create_from_type('i', 2, setting.codec);
  Is[2] = test_stream_item_create_from_type('I', 3, setting.codec);
  for (int ii = 0; ii < 3; ii++) {
    omsrc = onvif_media_signing_add_nalu_for_signing(
        oms, Is[ii]->data, Is[ii]->data_size, g_testTimestamp);
    ck_assert_int_eq(omsrc, OMS_OK);
  }
  size_t sei_size = 0;
  unsigned num_pending_seis = 0;
  omsrc = onvif_media_signing_get_sei(oms, NULL, &sei_size, NULL, 0, &num_pending_seis);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert_int_eq(num_pending_seis, 1);
  ck_assert_int_gt(sei_size, 0);

  for (int ii = 0; ii < 3; ii++) {
    test_stream_item_free(Is[ii]);
  }
  onvif_media_signing_free(oms);
}
END_TEST

static Suite *
onvif_media_signing_signer_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("ONVIF Media Signing signer tests");
  TCase *tc = tcase_create("ONVIF Media Signing standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}

  int s = 0;
  int e = 0;  // NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, api_inputs, s, 1);
  tcase_add_loop_test(tc, incorrect_operation, s, e);
  tcase_add_loop_test(tc, correct_nalu_sequence_without_eos, s, e);
  tcase_add_loop_test(tc, correct_multislice_nalu_sequence_without_eos, s, e);
  //   tcase_add_loop_test(tc, correct_nalu_sequence_with_eos, s, e);
  //   tcase_add_loop_test(tc, correct_multislice_sequence_with_eos, s, e);
  tcase_add_loop_test(tc, sei_increase_with_gop_length, s, e);
  tcase_add_loop_test(tc, get_seis_in_correct_order, s, e);
  tcase_add_loop_test(tc, undefined_nalu_in_sequence, s, e);
  tcase_add_loop_test(tc, correct_signing_nalus_in_parts, s, e);
  tcase_add_loop_test(tc, start_stream_with_golden_sei, s, e);
  tcase_add_loop_test(tc, w_wo_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, limited_sei_payload_size, s, e);
  tcase_add_loop_test(tc, signing_partial_gops, s, e);
  tcase_add_loop_test(tc, signing_multiple_gops, s, e);
  tcase_add_loop_test(tc, display_sei_if_not_peek, s, e);

  // Add test case to suit
  suite_add_tcase(suite, tc);
  return suite;
}

int
main(void)
{
  // Create suite runner and run
  int failed_tests = 0;
  SRunner *sr = srunner_create(NULL);
  srunner_add_suite(sr, onvif_media_signing_signer_suite());
  srunner_run_all(sr, CK_ENV);
  failed_tests = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (failed_tests == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
