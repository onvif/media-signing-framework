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

#include "lib/src/includes/onvif_media_signing_common.h"

static void
setup()
{
}

static void
teardown()
{
}

/* Test description
 * All public APIs are checked for invalid parameters.
 */
START_TEST(create_free_reset)
{
  // This test is run in a loop with loop index _i, corresponding to codec.*/
  MediaSigningCodec codec = _i;

  onvif_media_signing_t *oms = NULL;

  // Check invalid codecs
  oms = onvif_media_signing_create(-1);
  ck_assert(!oms);
  // Check that OMS_CODEC_NUM is the highest invalid codec in the enum
  oms = onvif_media_signing_create(OMS_CODEC_NUM);
  ck_assert(!oms);
  oms = onvif_media_signing_create(OMS_CODEC_NUM + 1);
  ck_assert(!oms);

  oms = onvif_media_signing_create(codec);
  // Not yet implemented
  ck_assert(oms);

  MediaSigningReturnCode oms_rc = onvif_media_signing_reset(NULL);
  ck_assert_int_eq(oms_rc, OMS_INVALID_PARAMETER);
  oms_rc = onvif_media_signing_reset(oms);
  ck_assert_int_eq(oms_rc, OMS_OK);

  onvif_media_signing_free(oms);
}
END_TEST

/* Test description
 * Format check for the current software version.
 */
START_TEST(onvif_media_signing_version)
{
  // Check output for different versions.
  const char *kVer1 = "v0.1.0";
  const char *kVer2 = "v0.10.0";
  const char *kVer3 = "0.1.0";

  // Incorrect usage
  ck_assert_int_eq(onvif_media_signing_compare_versions(kVer1, NULL), -1);
  ck_assert_int_eq(onvif_media_signing_compare_versions(NULL, kVer2), -1);
  ck_assert_int_eq(onvif_media_signing_compare_versions(kVer1, kVer3), -1);

  // Correct usage
  ck_assert_int_eq(onvif_media_signing_compare_versions(kVer1, kVer1), 0);
  ck_assert_int_eq(onvif_media_signing_compare_versions(kVer2, kVer1), 1);
  ck_assert_int_eq(onvif_media_signing_compare_versions(kVer1, kVer2), 2);

  // Make sure the version starts with letter 'v'
  const char *version = onvif_media_signing_get_version();
  ck_assert(version);
  ck_assert(version[0] == 'v');
}
END_TEST

static Suite *
onvif_media_signing_common_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("ONVIF Media Signing common tests");
  TCase *tc = tcase_create("ONVIF Media Signing standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}
  MediaSigningCodec s = OMS_CODEC_H264;
  MediaSigningCodec e = OMS_CODEC_NUM;

  // Add tests
  tcase_add_loop_test(tc, create_free_reset, s, e);
  tcase_add_loop_test(tc, onvif_media_signing_version, s, e);

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
  srunner_add_suite(sr, onvif_media_signing_common_suite());
  srunner_run_all(sr, CK_ENV);
  failed_tests = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (failed_tests == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
