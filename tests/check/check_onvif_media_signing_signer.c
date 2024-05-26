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

static onvif_media_signing_product_info_t product_info = {0};

static void
setup()
{
  strcpy(product_info.firmware_version, "firmware_version");
  strcpy(product_info.serial_number, "serial_number");
  strcpy(product_info.manufacturer, "manufacturer");
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

  oms_rc = onvif_media_signing_set_max_signing_nalus(NULL, 1);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_use_golden_sei(NULL, true);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_low_bitrate_mode(NULL, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_max_sei_payload_size(NULL, 1);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_emulation_prevention_before_signing(NULL, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_set_hash_algo(NULL, "sha512");
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_hash_algo(oms, "bogus-algo");
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);

  oms_rc = onvif_media_signing_set_product_info(NULL, &product_info);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_set_product_info(oms, NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  // onvif_media_signing_add_nalu_for_signing()
  oms_rc = onvif_media_signing_add_nalu_for_signing(NULL, NULL, 0, 0);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_add_nalu_part_for_signing(NULL, NULL, 0, 0, false);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);

  oms_rc = onvif_media_signing_get_sei(oms, NULL);
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
  // test_stream_item_t *p_nalu = test_stream_item_create_from_type('P', 0, codec);
  // test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);

  oms_rc = settings[_i].generate_key(
      NULL, &private_key, &private_key_size, &certificate_chain, &certificate_chain_size);
  ck_assert_int_eq(oms_rc, OMS_OK);

  // Operations that requires a signing key
  oms_rc = onvif_media_signing_generate_golden_sei(oms);
  ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);

  // MediaSigningReturnCode oms_rc =
  //     onvif_media_signing_add_nalu_for_signing(oms, i_nalu->data, i_nalu->data_size);
  // ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);
  // oms_rc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // oms_rc = signed_video_set_authenticity_level(oms, settings[_i].auth_level);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // oms_rc = signed_video_add_nalu_for_signing(oms, i_nalu->data, i_nalu->data_size);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // // signed_video_get_sei(...) should be called after each
  // signed_video_add_nalu_for_signing(...).
  // // After a P-nalu it is in principle OK, since there are no SEIs to get, due to an
  // unthreaded
  // // signing plugin.

  // oms_rc = signed_video_add_nalu_for_signing(oms, p_nalu->data, p_nalu->data_size);
  // ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);
  // // This is the first NAL Unit of the stream. We should have 1 NAL Unit to prepend.
  // Pulling only
  // // one should not be enough.

  // oms_rc = get_seis(oms, 1, NULL);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // oms_rc = signed_video_add_nalu_for_signing(oms, p_nalu->data, p_nalu->data_size);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // // Adding another P-nalu without getting SEIs is fine.
  // oms_rc = signed_video_add_nalu_for_signing(oms, p_nalu->data, p_nalu->data_size);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // // Pull all SEIs.
  // oms_rc = get_seis(oms, -1, NULL);
  // ck_assert_int_eq(oms_rc, OMS_OK);
  // // Free test stream items, session and private key.

  // oms_rc = onvif_media_signing_set_use_golden_sei(oms, true);
  // ck_assert_int_eq(oms_rc, OMS_NOT_SUPPORTED);

  // test_stream_item_free(p_nalu);
  // test_stream_item_free(i_nalu);
  onvif_media_signing_free(oms);
  free(private_key);
  free(certificate_chain);
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

  MediaSigningCodec s = 0;
  MediaSigningCodec e = NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, api_inputs, s, e);
  tcase_add_loop_test(tc, incorrect_operation, s, e);

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
