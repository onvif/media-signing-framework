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
#include "test_helpers.h"

#define TEST_DATA_SIZE 42
static const char test_data[TEST_DATA_SIZE] = {0};
static const uint8_t *nalu = (uint8_t *)test_data;

static onvif_media_signing_vendor_info_t vendor_info = {0};

static void
setup()
{
  strcpy(vendor_info.firmware_version, "firmware_version");
  strcpy(vendor_info.serial_number, "serial_number");
  strcpy(vendor_info.manufacturer, "manufacturer");
}

static void
teardown()
{
}

/* Test description
 * All public APIs are checked for invalid parameters, and valid NULL pointer inputs. This
 * is done for both H.264 and H.265.
 */
START_TEST(api_inputs)
{
  MediaSigningReturnCode oms_rc;
  MediaSigningCodec codec = settings[_i].codec;
  char *private_key = NULL;
  size_t private_key_size = 0;
  char *certificate_chain = NULL;
  size_t certificate_chain_size = 0;

  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);

  // Read content of private_key.
  oms_rc = settings[_i].generate_key("./", NULL, NULL, NULL, NULL);
  ck_assert_int_eq(oms_rc, OMS_OK);
  oms_rc = settings[_i].generate_key(
      NULL, &private_key, &private_key_size, &certificate_chain, &certificate_chain_size);
  ck_assert_int_eq(oms_rc, OMS_OK);

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

  oms_rc = settings[_i].generate_key(
      NULL, &private_key, &private_key_size, &certificate_chain, &certificate_chain_size);
  ck_assert_int_eq(oms_rc, OMS_OK);

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
 * No EOS is set after the last NAL Unit
 */
START_TEST(correct_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPSIPPSIPPSIPPSIPP");
  test_stream_free(list);
}
END_TEST

#if 0
// TODO: Enabled when we have better support and knowledge about EOS.
START_TEST(correct_nalu_sequence_with_eos)
{
  /* This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
   * in |settings|; See signed_video_helpers.h. */

  test_stream_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPS");
  test_stream_free(list);
}
END_TEST

/* Test description
 * In this test we check for number of multislice to prepend during two GOPs.
 * Add
 *   IiPpPpIiPpPp
 * followed by signed_video_set_end_of_stream(...)
 * Then we should get
 *   SIiPpPpSIiPpPp(S)
 * where
 * S = SEI-NALU,
 * I = I-NALU (Primary I slice or first slice in the current NAL Unit),
 * i = i-NALU (Non-primary I slices)
 * P = P-NALU (Primary P slice)
 * p = p-NALU (Non-primary P slice)
 */
// TODO: Enabled when we have better support and knowledge about EOS.
START_TEST(correct_multislice_sequence_with_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
  // in |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "SIiPpPpSIiPpPpS");
  test_stream_free(list);
}
END_TEST

START_TEST(correct_multislice_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "SIiPpPpSIiPpPp");
  test_stream_free(list);
}
END_TEST

/* Test description
 * Add
 *   IPPIPPPPPI
 * Then we should get
 *   SIPPSIPPPPPSI
 * When the gop length increase, the size of the generated SEI also increases for
 * SV_AUTHENTICITY_LEVEL_FRAME, but for SV_AUTHENTICITY_LEVEL_GOP it is independent of
 * the gop length.
 *
 * In this test we generate a test stream with three SEIs, each corresponding to an
 * increased gop length. Then the SEIs (S's) are fetched and their sizes are compared.
 */
START_TEST(sei_increase_with_gop_length)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoAuthenticityLevel auth_level = settings[_i].auth_level;

  test_stream_t *list = create_signed_nalus("IPPIPPPPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPPPSI");
  test_stream_item_t *sei_3 = test_stream_item_remove(list, 12);
  test_stream_item_check_type(sei_3, 'S');
  test_stream_item_t *sei_2 = test_stream_item_remove(list, 5);
  test_stream_item_check_type(sei_2, 'S');
  test_stream_item_t *sei_1 = test_stream_item_remove(list, 1);
  test_stream_item_check_type(sei_1, 'S');
  if (auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    // Verify constant size. Note that the size differs if more emulation prevention bytes have
    // been added in one SEI compared to the other. Allow for one extra byte.
    ck_assert_int_le(abs((int)sei_1->data_size - (int)sei_2->data_size), 1);
    ck_assert_int_le(abs((int)sei_2->data_size - (int)sei_3->data_size), 1);
  } else if (auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    // Verify increased size.
    ck_assert_uint_lt(sei_1->data_size, sei_2->data_size);
    ck_assert_uint_lt(sei_2->data_size, sei_3->data_size);
  } else {
    // We should not end up here.
    ck_assert(false);
  }
  test_stream_item_free(sei_1);
  test_stream_item_free(sei_2);
  test_stream_item_free(sei_3);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Add some NAL Units to a test stream, where the last one is super long. Too long for
 * SV_AUTHENTICITY_LEVEL_FRAME to handle it. Note that in tests we run with a shorter max hash list
 * size, namely 10; See meson file.
 *
 * With
 *   IPPIPPPPPPPPPPPPPPPPPPPPPPPPI
 *
 * we automatically fall back on SV_AUTHENTICITY_LEVEL_GOP in at the third "I".
 *
 * We test this by examine if the generated SEI has the HASH_LIST_TAG present or not.
 */
START_TEST(fallback_to_gop_level)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  const size_t kFallbackSize = 10;
  onvif_media_signing_t *oms =
      get_initialized_signed_video(settings[_i].codec, settings[_i].generate_key, false);
  ck_assert(oms);
  ck_assert_int_eq(signed_video_set_authenticity_level(oms, settings[_i].auth_level), OMS_OK);
  // If the true hash size is different from the default one, the test should still pass.
  ck_assert_int_eq(set_hash_list_size(oms->gop_info, kFallbackSize * DEFAULT_HASH_SIZE), OMS_OK);

  // Create a test stream given the input string.
  test_stream_t *list = create_signed_nalus_with_sv(oms, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPI", false);
  test_stream_check_types(list, "SIPPSIPPPPPPPPPPPPPPPPPPPPPPPPSI");
  test_stream_item_t *sei_3 = test_stream_item_remove(list, 31);
  test_stream_item_check_type(sei_3, 'S');
  test_stream_item_t *sei_2 = test_stream_item_remove(list, 5);
  test_stream_item_check_type(sei_2, 'S');
  test_stream_item_t *sei_1 = test_stream_item_remove(list, 1);
  test_stream_item_check_type(sei_1, 'S');

  // Verify that the HASH_LIST_TAG is present in the SEI when it should.
  ck_assert(tag_is_present(sei_1, settings[_i].codec, HASH_LIST_TAG));
  ck_assert(tag_is_present(sei_2, settings[_i].codec, HASH_LIST_TAG));
  ck_assert(!tag_is_present(sei_3, settings[_i].codec, HASH_LIST_TAG));

  test_stream_item_free(sei_1);
  test_stream_item_free(sei_2);
  test_stream_item_free(sei_3);
  test_stream_free(list);
  signed_video_free(oms);
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
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPXPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPXPSIPPSI");
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that after 2 completed SEIs have been created, they are emitted in correct order.
 * The operation is as follows:
 * 1. Setup a onvif_media_signing_t session
 * 2. Add 2 I NAL Units for signing that will trigger 2 SEIs
 * 3. Get the SEIs
 * 4. Check that the SEIs were emitted in correct order
 */
START_TEST(two_completed_seis_pending)
{
  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  MediaSigningCodec codec = settings[_i].codec;
  MediaSigningReturnCode omsrc;
  size_t sei_size_1 = 0;
  size_t sei_size_2 = 0;
  size_t sei_size_3 = 0;
  onvif_media_signing_t *oms = signed_video_create(codec);
  ck_assert(oms);

  // Enable testing mode to add multiple SEIs.
  oms->sv_test_on = true;

  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu_1 = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, codec);
  // Setup the key
  omsrc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  omsrc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_set_authenticity_level(oms, settings[_i].auth_level);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_add_nalu_for_signing(oms, i_nalu_1->data, i_nalu_1->data_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_add_nalu_for_signing(oms, i_nalu_2->data, i_nalu_2->data_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  // Now 2 SEIs should be available. Get the first one.
  omsrc = signed_video_get_sei(oms, NULL, &sei_size_1);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert(sei_size_1 != 0);
  uint8_t *sei_1 = malloc(sei_size_1);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_sei(oms, sei_1, &sei_size_1);
  ck_assert_int_eq(omsrc, OMS_OK);
  // Now get the second one.
  omsrc = signed_video_get_sei(oms, NULL, &sei_size_2);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert(sei_size_2 != 0);
  uint8_t *sei_2 = malloc(sei_size_2);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_sei(oms, sei_2, &sei_size_2);
  ck_assert_int_eq(omsrc, OMS_OK);
  // There should not be a third one.
  omsrc = signed_video_get_sei(oms, NULL, &sei_size_3);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert_int_eq(sei_size_3, 0);

  // Verify the transfer order of NAL Units
  // Expect |sei_size_1| to be less than |sei_size_2| because the second SEI includes one
  // additional hash compared to the first, affecting their respective sizes.
  ck_assert(sei_size_1 < sei_size_2);

  test_stream_item_free(i_nalu_1);
  test_stream_item_free(i_nalu_2);
  signed_video_free(oms);
  free(private_key);
  free(sei_1);
  free(sei_2);
}
END_TEST

/* Test description
 * Generates a golden SEI and fetches it from the library. Then verifies that the corresponding
 * flag is set.
 */
START_TEST(golden_sei_created)
{

  MediaSigningCodec codec = settings[_i].codec;
  MediaSigningReturnCode omsrc;
  onvif_media_signing_t *oms = signed_video_create(codec);
  ck_assert(oms);
  char *private_key = NULL;
  size_t private_key_size = 0;
  // Setup the key
  omsrc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  omsrc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_set_hash_algo(oms, settings[_i].hash_algo_name);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_generate_golden_sei(oms);
  ck_assert_int_eq(omsrc, OMS_OK);

  size_t sei_size = 0;
  omsrc = signed_video_get_sei(oms, NULL, &sei_size);
  ck_assert(sei_size != 0);
  uint8_t *sei = malloc(sei_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_sei(oms, sei, &sei_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  // Verify the golden SEI
  ck_assert(signed_video_is_golden_sei(oms, sei, sei_size));

  signed_video_free(oms);
  free(private_key);
  free(sei);
}
END_TEST

/* Test description
 * Verify that after 2 completed SEIs created ,they will be emitted in correct order
 * The operation is as follows:
 * 1. Setup a onvif_media_signing_t session
 * 2. Add 2 I NAL Units for signing that will trigger 2 SEIs
 * 3. Get the SEIs using the legacy API
 * 4. Check that the SEIs were emitted in correct order
 */
START_TEST(two_completed_seis_pending_legacy)
{
  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  MediaSigningCodec codec = settings[_i].codec;
  MediaSigningReturnCode omsrc;
  signed_video_nalu_to_prepend_t nalu_to_prepend_1 = {0};
  signed_video_nalu_to_prepend_t nalu_to_prepend_2 = {0};
  signed_video_nalu_to_prepend_t nalu_to_prepend_3 = {0};

  onvif_media_signing_t *oms = signed_video_create(codec);
  ck_assert(oms);

  oms->sv_test_on = true;

  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu_1 = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, codec);
  // Setup the key
  omsrc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  omsrc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_set_authenticity_level(oms, settings[_i].auth_level);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_add_nalu_for_signing(oms, i_nalu_1->data, i_nalu_1->data_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_add_nalu_for_signing(oms, i_nalu_2->data, i_nalu_2->data_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  // After 2 seis are created, SEIs can be copied
  omsrc = signed_video_get_nalu_to_prepend(oms, &nalu_to_prepend_1);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_nalu_to_prepend(oms, &nalu_to_prepend_2);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_nalu_to_prepend(oms, &nalu_to_prepend_3);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert_int_eq(nalu_to_prepend_3.prepend_instruction, SIGNED_VIDEO_PREPEND_NOTHING);
  // Verify the transfer order of NAL Units
  // Expect |nalu_to_prepend_2.nalu_data_size| to be less than |nalu_to_prepend_1.nalu_data_size|
  // because the first SEI includes one additional hash compared to the second, affecting their
  // respective sizes.
  ck_assert(nalu_to_prepend_1.nalu_data_size > nalu_to_prepend_2.nalu_data_size);

  test_stream_item_free(i_nalu_1);
  test_stream_item_free(i_nalu_2);
  signed_video_free(oms);
  free(private_key);
  free(nalu_to_prepend_1.nalu_data);
  free(nalu_to_prepend_2.nalu_data);
}
END_TEST

/* Test description
 * Verify that the new API for adding a timestamp with the NAL Unit for signing does not
 * change the result when the timestamp is not present (NULL) compared to the old API.
 * The operation is as follows:
 * 1. Setup two onvif_media_signing_t sessions
 * 2. Add a NAL Unit for signing with the new and old API supporting timestamp
 * 3. Get the SEI
 * 4. Check that the sizes and contents of hashable data are identical
 */
START_TEST(correct_timestamp)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  MediaSigningCodec codec = settings[_i].codec;
  MediaSigningReturnCode omsrc;

  onvif_media_signing_t *oms = signed_video_create(codec);
  onvif_media_signing_t *sv_ts = signed_video_create(codec);
  ck_assert(oms);
  ck_assert(sv_ts);
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  size_t sei_size = 0;
  size_t sei_size_ts = 0;
  // Setup the key
  omsrc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  omsrc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_set_authenticity_level(oms, settings[_i].auth_level);
  ck_assert_int_eq(omsrc, OMS_OK);

  omsrc = signed_video_set_private_key_new(sv_ts, private_key, private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_set_authenticity_level(sv_ts, settings[_i].auth_level);
  ck_assert_int_eq(omsrc, OMS_OK);

  // Test old API without timestamp
  omsrc = signed_video_add_nalu_for_signing(oms, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_sei(oms, NULL, &sei_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  uint8_t *sei = malloc(sei_size);
  omsrc = signed_video_get_sei(oms, sei, &sei_size);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert(sei_size > 0);

  // Test new API with timestamp as NULL. It should give the same result as the old API
  omsrc = signed_video_add_nalu_for_signing_with_timestamp(
      sv_ts, i_nalu->data, i_nalu->data_size, NULL);
  ck_assert_int_eq(omsrc, OMS_OK);
  omsrc = signed_video_get_sei(sv_ts, NULL, &sei_size_ts);
  ck_assert_int_eq(omsrc, OMS_OK);
  uint8_t *sei_ts = malloc(sei_size_ts);
  omsrc = signed_video_get_sei(sv_ts, sei_ts, &sei_size_ts);
  ck_assert_int_eq(omsrc, OMS_OK);
  ck_assert(sei_size_ts > 0);

  // Verify the sizes of the nalus
  ck_assert(sei_size > 0);
  ck_assert(sei_size_ts > 0);
  ck_assert(sei_size == sei_size_ts);

  // Get the hashable data (includes the signature)
  h26x_nalu_t nalu = parse_nalu_info(sei, sei_size, codec, false, true);
  h26x_nalu_t nalu_ts = parse_nalu_info(sei_ts, sei_size, codec, false, true);

  // Remove the signature
  update_hashable_data(&nalu);
  update_hashable_data(&nalu_ts);

  // Verify that hashable data sizes and data contents are identical
  ck_assert(nalu.hashable_data_size == nalu_ts.hashable_data_size);
  ck_assert(nalu.hashable_data_size > 0);
  ck_assert(!memcmp(nalu.hashable_data, nalu_ts.hashable_data, nalu.hashable_data_size));

  free(nalu.nalu_data_wo_epb);
  free(nalu_ts.nalu_data_wo_epb);
  test_stream_item_free(i_nalu);
  signed_video_free(oms);
  signed_video_free(sv_ts);
  free(private_key);
  free(sei);
  free(sei_ts);
}
END_TEST

/* Test description
 * Same as correct_nalu_sequence_without_eos, but with splitted NAL Unit data.
 */
START_TEST(correct_signing_nalus_in_parts)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_splitted_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPP");
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
  // |settings|; See signed_video_helpers.h.

  MediaSigningCodec codec = settings[_i].codec;
  MediaSigningReturnCode omsrc;

  h26x_nalu_t nalus[NUM_EPB_CASES] = {0};
  uint8_t *seis[NUM_EPB_CASES] = {NULL, NULL};
  size_t sei_sizes[NUM_EPB_CASES] = {0, 0};
  bool with_emulation_prevention[NUM_EPB_CASES] = {true, false};
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  size_t sei_size = 0;

  // Generate a Private key.
  omsrc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(omsrc, OMS_OK);

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    onvif_media_signing_t *oms = signed_video_create(codec);
    ck_assert(oms);

    // Apply settings to session.
    omsrc = signed_video_set_private_key_new(oms, private_key, private_key_size);
    ck_assert_int_eq(omsrc, OMS_OK);
    omsrc = signed_video_set_authenticity_level(oms, settings[_i].auth_level);
    ck_assert_int_eq(omsrc, OMS_OK);
    omsrc = signed_video_set_sei_epb(oms, with_emulation_prevention[ii]);
    ck_assert_int_eq(omsrc, OMS_OK);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    const size_t attestation_size = 2;
    void *attestation = calloc(1, attestation_size);
    // Setting |attestation| and |certificate_chain|.
    omsrc = sv_vendor_axis_communications_set_attestation_report(
        oms, attestation, attestation_size, axisDummyCertificateChain);
    ck_assert_int_eq(omsrc, OMS_OK);
    free(attestation);
#endif

    // Add I-frame for signing and get SEI frame
    omsrc = signed_video_add_nalu_for_signing_with_timestamp(
        oms, i_nalu->data, i_nalu->data_size, &g_testTimestamp);
    ck_assert_int_eq(omsrc, OMS_OK);
    omsrc = signed_video_get_sei(oms, NULL, &sei_size);
    ck_assert_int_eq(omsrc, OMS_OK);
    ck_assert(sei_size > 0);
    seis[ii] = malloc(sei_size);
    omsrc = signed_video_get_sei(oms, seis[ii], &sei_size);
    ck_assert_int_eq(omsrc, OMS_OK);
    ck_assert(seis[ii]);
    sei_sizes[ii] = sei_size;
    nalus[ii] = parse_nalu_info(seis[ii], sei_sizes[ii], codec, false, true);
    update_hashable_data(&nalus[ii]);
    signed_video_free(oms);
    oms = NULL;
  }

  // Verify that hashable data sizes and data contents are not identical
  ck_assert(nalus[0].hashable_data_size > nalus[1].hashable_data_size);
  ck_assert(nalus[1].hashable_data_size > 0);
  ck_assert(memcmp(nalus[0].hashable_data, nalus[1].hashable_data, nalus[1].hashable_data_size));

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    free(nalus[ii].nalu_data_wo_epb);
    free(seis[ii]);
  }
  test_stream_item_free(i_nalu);
  free(private_key);
}
END_TEST

/* Test description
 * Verify the setter for maximum SEI payload size. */
START_TEST(limited_sei_payload_size)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // No need to run this with GOP level authentication, since only frame level
  // authentication can dynamically affect the payload size.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  // Select an upper payload limit which is less then the size of the last SEI.
  const size_t max_sei_payload_size = 1000;
  settings[_i].max_sei_payload_size = max_sei_payload_size;
  test_stream_t *list = create_signed_nalus("IPPIPPPPPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPPPPSI");

  // Extract the SEIs and check their sizes, which should be smaller than |max_sei_payload_size|.
  int sei_idx[3] = {13, 5, 1};
  for (int ii = 0; ii < 3; ii++) {
    test_stream_item_t *sei = test_stream_item_remove(list, sei_idx[ii]);
    ck_assert_int_eq(sei->type, 'S');
    ck_assert_uint_le(sei->data_size, max_sei_payload_size);
    test_stream_item_free(sei);
    sei = NULL;
  }

  test_stream_free(list);
}
END_TEST
#endif

static Suite *
onvif_media_signing_signer_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("ONVIF Media Signing signer tests");
  TCase *tc = tcase_create("ONVIF Media Signing standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}

  MediaSigningCodec s = 0;
  MediaSigningCodec e = NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, api_inputs, s, e);
  tcase_add_loop_test(tc, incorrect_operation, s, e);
  tcase_add_loop_test(tc, correct_nalu_sequence_without_eos, s, e);
  //   tcase_add_loop_test(tc, correct_multislice_nalu_sequence_without_eos, s, e);
  //   tcase_add_loop_test(tc, correct_nalu_sequence_with_eos, s, e);
  //   tcase_add_loop_test(tc, correct_multislice_sequence_with_eos, s, e);
  //   tcase_add_loop_test(tc, sei_increase_with_gop_length, s, e);
  //   tcase_add_loop_test(tc, fallback_to_gop_level, s, e);
  //   tcase_add_loop_test(tc, two_completed_seis_pending, s, e);
  //   tcase_add_loop_test(tc, two_completed_seis_pending_legacy, s, e);
  //   tcase_add_loop_test(tc, undefined_nalu_in_sequence, s, e);
  //   tcase_add_loop_test(tc, correct_timestamp, s, e);
  //   tcase_add_loop_test(tc, correct_signing_nalus_in_parts, s, e);
  //   tcase_add_loop_test(tc, golden_sei_created, s, e);
  //   tcase_add_loop_test(tc, w_wo_emulation_prevention_bytes, s, e);
  //   tcase_add_loop_test(tc, limited_sei_payload_size, s, e);

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
