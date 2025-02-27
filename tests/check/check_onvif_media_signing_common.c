/**
 * MIT License
 *
 * Copyright (c) 2025 ONVIF. All rights reserved.
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
