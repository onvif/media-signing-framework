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

#include <check.h>  // START_TEST, END_TEST
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE

#include "lib/src/includes/onvif_media_signing_common.h"
#include "lib/src/includes/onvif_media_signing_validator.h"
#include "test_helpers.h"

#define TEST_DATA_SIZE 42
static const char test_data[TEST_DATA_SIZE] = {0};
static const uint8_t *test_nalu = (uint8_t *)test_data;

static void
setup()
{
}

static void
teardown()
{
}

/* Test description
 * The public APIs are checked for invalid parameters.
 */
START_TEST(invalid_api_inputs)
{
  // For this test, the authenticity level has no meaning, since it is a setting for the
  // signing side, and we do not use a signed stream here.
  MediaSigningCodec codec = settings[_i].codec;

  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);

  onvif_media_signing_authenticity_t *report =
      onvif_media_signing_get_authenticity_report(NULL);
  ck_assert(!report);

  ck_assert(!onvif_media_signing_is_golden_sei(NULL, test_nalu, TEST_DATA_SIZE));
  ck_assert(!onvif_media_signing_is_golden_sei(oms, NULL, TEST_DATA_SIZE));
  ck_assert(!onvif_media_signing_is_golden_sei(oms, test_nalu, 0));

  MediaSigningReturnCode omsrc = onvif_media_signing_set_root_certificate(NULL, NULL, 0);
  ck_assert_int_eq(omsrc, OMS_INVALID_PARAMETER);

  omsrc = onvif_media_signing_add_nalu_and_authenticate(NULL, NULL, 0, NULL);
  ck_assert_int_eq(omsrc, OMS_INVALID_PARAMETER);

  onvif_media_signing_free(oms);
}
END_TEST

static Suite *
onvif_media_signing_validator_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("ONVIF Media Signing validator tests");
  TCase *tc = tcase_create("ONVIF Media Signing standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}

  MediaSigningCodec s = 0;
  MediaSigningCodec e = NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, invalid_api_inputs, s, e);

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
  srunner_add_suite(sr, onvif_media_signing_validator_suite());
  srunner_run_all(sr, CK_ENV);
  failed_tests = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (failed_tests == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
