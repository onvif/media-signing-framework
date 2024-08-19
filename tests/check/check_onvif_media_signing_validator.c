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

/* Struct to accumulate validation results used to compare against expected values. */
struct validation_stats {
  int valid;
  int valid_with_missing_info;
  int invalid;
  int unsigned_gops;
  int missed_nalus;
  int pending_nalus;
  int has_sei;
  bool public_key_has_changed;
  bool has_no_timestamp;
  onvif_media_signing_accumulated_validation_t *final_validation;
};

/* validate_test_stream(...)
 *
 * Helper function to validate the authentication result.
 * It takes a test stream |list| as input together with |expected| values of
 *   valid gops
 *   invalid gops
 *   unsigned gops, that is gops without signature
 *   missed number of gops
 *   etc
 *
 * Note that the items in the |list| are consumed, that is, deleted after usage.
 *
 * If a NULL pointer |list| is passed in no action is taken.
 * If a NULL pointer |oms| is passed in a new session is created. This is
 * convenient if there are no other actions to take on |oms| outside this scope,
 * like reset.
 */
static void
validate_test_stream(onvif_media_signing_t *oms,
    test_stream_t *list,
    struct validation_stats expected)
{
  if (!list)
    return;

  bool internal_oms = false;
  if (!oms) {
    oms = onvif_media_signing_create(list->codec);
    internal_oms = true;
  }

  onvif_media_signing_authenticity_t *auth_report = NULL;
  onvif_media_signing_latest_validation_t *latest = NULL;

  int valid = 0;
  int valid_with_missing_info = 0;
  int invalid = 0;
  int unsigned_gops = 0;
  int missed_nalus = 0;
  int pending_nalus = 0;
  int has_sei = 0;
  bool public_key_has_changed = false;
  int64_t first_ts = -1;
  int64_t last_ts = 0;

  // Pop one NAL Unit at a time.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  while (item) {
    MediaSigningReturnCode rc = onvif_media_signing_add_nalu_and_authenticate(
        oms, item->data, item->data_size, &auth_report);
    ck_assert_int_eq(rc, OMS_OK);

    if (auth_report) {
      latest = &(auth_report->latest_validation);
      ck_assert(latest);
      if (latest->number_of_expected_hashable_nalus >= 0) {
        missed_nalus += latest->number_of_expected_hashable_nalus -
            latest->number_of_received_hashable_nalus;
      }
      pending_nalus += latest->number_of_pending_hashable_nalus;
      switch (latest->authenticity) {
        case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
          valid_with_missing_info++;
          break;
        case OMS_AUTHENTICITY_OK:
          valid++;
          break;
        case OMS_AUTHENTICITY_NOT_OK:
          invalid++;
          break;
        case OMS_AUTHENTICITY_NOT_FEASIBLE:
          has_sei++;
          break;
        case OMS_NOT_SIGNED:
          unsigned_gops++;
          break;
        default:
          break;
      }
      public_key_has_changed |= latest->public_key_has_changed;
      if (first_ts < 0) {
        first_ts = latest->timestamp;
      }
      last_ts = latest->timestamp;

      // Check if vendor_info has been received and set correctly.
      if ((latest->authenticity != OMS_NOT_SIGNED) &&
          (latest->authenticity != OMS_AUTHENTICITY_NOT_FEASIBLE)) {
        ck_assert_int_eq(strcmp(auth_report->vendor_info.firmware_version, FW_VER), 0);
        ck_assert_int_eq(strcmp(auth_report->vendor_info.serial_number, SER_NO), 0);
        ck_assert_int_eq(strcmp(auth_report->vendor_info.manufacturer, MANUFACT), 0);
        // Check if code version used when signing the video is equal to the code version
        // used when validating the authenticity.
        if (strlen(auth_report->version_on_signing_side) > 0) {
          ck_assert(!onvif_media_signing_compare_versions(
              auth_report->version_on_signing_side, auth_report->this_version));
        }
      }
      // Tests can currently not validate the provenance since there is no root
      // certificate to verify against.
      ck_assert_int_eq(latest->provenance, OMS_PROVENANCE_NOT_FEASIBLE);

      // Get an authenticity report from separate API and compare accumulated results.
      onvif_media_signing_authenticity_t *extra_auth_report =
          onvif_media_signing_get_authenticity_report(oms);
      ck_assert_int_eq(memcmp(&auth_report->accumulated_validation,
                           &extra_auth_report->accumulated_validation,
                           sizeof(onvif_media_signing_accumulated_validation_t)),
          0);
      onvif_media_signing_authenticity_report_free(extra_auth_report);

      // Done with auth_report.
      latest = NULL;
      onvif_media_signing_authenticity_report_free(auth_report);
    }
    // Free item and pop a new one.
    test_stream_item_free(item);
    item = test_stream_pop_first_item(list);
  }
  // Check GOP statistics against expected.
  ck_assert_int_eq(valid, expected.valid);
  ck_assert_int_eq(valid_with_missing_info, expected.valid_with_missing_info);
  ck_assert_int_eq(invalid, expected.invalid);
  ck_assert_int_eq(unsigned_gops, expected.unsigned_gops);
  ck_assert_int_eq(missed_nalus, expected.missed_nalus);
  ck_assert_int_eq(pending_nalus, expected.pending_nalus);
  ck_assert_int_eq(has_sei, expected.has_sei);
  ck_assert_int_eq(public_key_has_changed, expected.public_key_has_changed);

  // Get the authenticity report and compare the stats against expected.
  if (expected.final_validation) {
    auth_report = onvif_media_signing_get_authenticity_report(oms);
    ck_assert_int_eq(auth_report->accumulated_validation.provenance,
        expected.final_validation->provenance);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed,
        expected.final_validation->public_key_has_changed);
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity,
        expected.final_validation->authenticity);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus,
        expected.final_validation->number_of_received_nalus);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus,
        expected.final_validation->number_of_validated_nalus);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus,
        expected.final_validation->number_of_pending_nalus);
    // ck_assert_int_eq(auth_report->accumulated_validation.public_key_validation,
    //     expected.final_validation->public_key_validation);
    ck_assert_int_eq(auth_report->accumulated_validation.first_timestamp, first_ts);
    ck_assert_int_eq(auth_report->accumulated_validation.last_timestamp, last_ts);
    ck_assert_int_gt(auth_report->accumulated_validation.last_timestamp,
        auth_report->accumulated_validation.first_timestamp);
    onvif_media_signing_authenticity_report_free(auth_report);
  }

  if (internal_oms)
    onvif_media_signing_free(oms);
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

/* Test description
 * Verify that we get a valid authentication if all NAL Units are added in the correct
 * order. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a list of NAL Units given the input string.
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // IPPISPPISPPISPPISPPISPPISP
  //
  // IPPIS                       ...P.                      (valid, 1 pending)
  //    ISPPIS                      ....P.                  (valid, 1 pending)
  //        ISPPIS                      ....P.              (valid, 1 pending)
  //            ISPPIS                      ....P.          (valid, 1 pending)
  //                ISPPIS                      ....P.      (valid, 1 pending)
  //                    ISPPISP                     ....P.  (valid, 1 pending)
  //                                                                6 pending
  //                        ISP                         P.P (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 26, 23, 3, 0, 0};
  struct validation_stats expected = {
      .valid = 6, .pending_nalus = 6, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_multislice_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPpIiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpPpIiSPpPpIiSPpPpIiSPpPpIiSPp");

  // IiPpPpIiSPpPpIiSPpPpIiSPpPpIiSPp
  //
  // IiPpPpIiS                       ......PP.                     (valid, 2 pending)
  //       IiSPpPpIiS                      ......PP.               (valid, 2 pending)
  //              IiSPpPpIiS                     ......PP.         (valid, 2 pending)
  //                     IiSPpPpIiS                    ......PP.   (valid, 2 pending)
  //                                                                       8 pending
  //                            IiSPp                        PP.PP (valid, 4 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 32, 27, 5, 0, 0};
  struct validation_stats expected = {
      .valid = 4, .pending_nalus = 8, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_stream_with_splitted_nalus)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a list of NAL Units given the input string.
  test_stream_t *list = create_signed_splitted_nalus("IPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISP");

  // IPPISPPISPPISPPISPPISPPISP
  //
  // IPPIS                       ...P.                      (valid, 1 pending)
  //    ISPPIS                      ....P.                  (valid, 1 pending)
  //        ISPPIS                      ....P.              (valid, 1 pending)
  //            ISPPIS                      ....P.          (valid, 1 pending)
  //                ISPPIS                      ....P.      (valid, 1 pending)
  //                                                                5 pending
  //                    ISP                         P.P     (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 22, 19, 3, 0, 0};
  // For expected values see the "intact_stream" test above.
  struct validation_stats expected = {
      .valid = 5, .pending_nalus = 5, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* PPS, SPS and VPS should be ignored by Media Signing. */
START_TEST(intact_stream_with_pps_nalu_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("VIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "VIPPISPPISP");

  // VIPPISPPISP
  //
  // VIPPIS       _...P.          (valid, 1 pending)
  //     ISPPIS       ....P.      (valid, 1 pending)
  //                                      2 pending
  //         ISP          P.P     (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 11, 8, 3, 0, 0};
  struct validation_stats expected = {
      .valid = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_nalu_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("VIiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "VIiPpPpIiSPpPpIiSPp");

  // VIiPpPpIiSPpPpIiSPp
  //
  // VIiPpPpIiS            _......PP.              (valid, 2 pending)
  //        IiSPpPpIiS            .......PP.       (valid, 2 pending)
  //                                                       4 pending
  //               IiSPp                 PP.PP     (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 19, 14, 5, 0, 0};
  struct validation_stats expected = {
      .valid = 2, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that the stream is correctly validated if one undefined NAL Unit is present in
 * the test stream. */
START_TEST(intact_with_undefined_nalu_in_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPXPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPXPISPPISP");

  // IPXPISPPISP
  //
  // IPXPIS       .._.P.          (valid, 1 pending)
  //     ISPPIS       ....P.      (valid, 1 pending)
  //                                      2 pending
  //         ISP          P.P     (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 11, 8, 3, 0, 0};
  struct validation_stats expected = {
      .valid = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_with_undefined_multislice_nalu_in_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpXPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpXPpIiSPpPpIiSPp");

  // IiPpXPpIiSPpPpIiSPp
  //
  // IiPpXPpIiS           ...._..PP.              (valid, 2 pending)
  //        IiSPpPpIiS           .......PP.       (valid, 2 pending)
  //                                                      4 pending
  //               IiSPp                PP.PP     (valid, 4 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 19, 14, 5, 0, 0};
  struct validation_stats expected = {
      .valid = 2, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that invalid authentication is produced if one 'P' is removed. The operation is
 * as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Remove one 'P' in the middle GOP.
 * 3. Check the authentication result
 */
START_TEST(remove_one_p_nalu)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Item counting starts at 1.  Middle 'P' in second non-empty GOP: IPPISP P PISPPISP
  const int remove_nalu_number = 7;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPISPPISPPISP");

  // IPPISPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPIS                      ...M.P.          (missing, 1 pending, 1 missing)
  //        ISPPIS                       ....P.      (  valid, 1 pending)
  //                                                           3 pending
  //            ISP                          P.P     (missing, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK_WITH_MISSING_INFO, 14, 11,
      3, 0, 0};
  // One pending NAL Unit per GOP.
  struct validation_stats expected = {.valid = 2,
      .valid_with_missing_info = 1,
      .missed_nalus = 1,
      .pending_nalus = 3,
      .final_validation = &final_validation};
  // In low bitrate mode it is not possible to identify individual missing frames.
  if (settings[_i].low_bitrate_mode) {
    // IPPISPPISPPISP
    //
    // IPPIS                       ...P.              (  valid, 1 pending)
    //    ISPPIS                      ....MP.         (invalid, 1 pending, 1 missing)
    //        ISPPIS                       ....P.     (  valid, 1 pending)
    //                                                          3 pending
    //            ISP                          P.P    (invalid, 2 pending)
    expected.invalid = 1;
    expected.valid_with_missing_info = 0,
    expected.final_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

#if 0
/* Test description
 * Verify that we get invalid authentication if we interchange two 'P's.
 */
START_TEST(interchange_two_p_nalus)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPSIPPSI");

  // Item counting starts at 1.  Middle 'P' in second non-empty GOP: SIPPSIP P PSIPPSI
  const int nalu_number = 8;
  test_stream_item_t *item = test_stream_item_remove(list, nalu_number);
  test_stream_item_check_type(item, 'P');

  // Inject the item again, but at position nalu_number + 1, that is, append the list item at
  // position nalu_number.
  test_stream_append_item(list, item, nalu_number);
  test_stream_check_types(list, "SIPPSIPPPSIPPSI");

  // All NAL Units but the last 'I' are validated and since two NAL Units have been moved the
  // authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP.
  struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level we can identify the I NAL Unit, hence the linking between GOPs is intact.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid = 3;
    expected.invalid = 1;
    expected.final_validation->number_of_validated_nalus = 14;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that if we manipulate a NAL Unit, the authentication should become invalid. We do this for
 * both a P- and an 'I', by replacing the NAL Unit data with a modified NAL Unit.
 */
START_TEST(modify_one_p_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPSIPPSI");

  // Second 'P' in first non-empty GOP: SIP P SIPPPSIPPSI
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, 'P');

  // All NAL Units but the last 'I' are validated and since one NAL Unit has been modified the
  // authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP.
  struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level we can identify the I NAL Unit, hence the linking between GOPs is intact.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid = 3;
    expected.invalid = 1;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPSIPPSI");

  // Modify the 'I' in second non-empty GOP: SIPPS I PPPSIPPSI
  const int modify_nalu_number = 6;
  modify_list_item(list, modify_nalu_number, 'I');

  // All NAL Units but the last 'I' are validated and since one 'I' has been modified the
  // authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP. Note that a modified 'I' affects two GOPs due to linked hashes,
  // but it will also affect a third if we validate with a gop_hash.
  struct validation_stats expected = {.valid = 1,
      .invalid = 3,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level, the first GOP will be marked as valid with missing info since we cannot
  // correctly validate the last NAL Unit (the modified I).
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid = 2;
    expected.invalid = 2;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove a SEI or an 'I'. The operation is
 * as follows:
 * 1. Generate a test stream with a sequence of four signed GOPs.
 * 2. Remove a SEI or an 'I' after the second GOP.
 * 3. Check the authentication result */
START_TEST(remove_the_g_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPSIPPSIPPSI");

  // SEI of second non-empty GOP: SIPPSIPP S IPPSIPPSI.
  const int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "SIPPSIPPIPPSIPPSI");

  // SIPPSIPPIPPSIPPSI
  //
  // SI                ->   (valid) -> .P
  //  IPPSI            ->   (valid) -> ....P
  //      IPPIPPS      -> (invalid) -> NNNPPPP
  //         IPPSI     -> (invalid) -> N...P
  //             IPPSI ->   (valid) -> ....P
  // All NAL Units but the last 'I' are validated and since one SEI has been removed the
  // authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 3,
      .invalid = 2,
      .pending_nalus = 8,
      .final_validation = &final_validation};

  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_the_i_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPSIPPSIPPSI");

  // 'I' of third non-empty GOP: SIPPSIPPS I PPSIPPSI.
  const int remove_nalu_number = 10;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "SIPPSIPPSPPSIPPSI");

  // All NAL Units but the last 'I' are validated and since one 'I' has been removed the
  // authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP. A missing I NAL Unit will affect two GOPs, since it is part of
  // two gop_hashes. At GOP level the missing NAL Unit will make the GOP invalid, but for Frame
  // level we can identify the missed NAL Unit when the I NAL Unit is not the reference, that is,
  // the first GOP is valid with missing info, whereas the second becomes invalid. SIPPSIPPSPPSIPPSI
  //
  // SI                ->   (valid) -> .P
  //  IPPSI            ->   (valid) -> ....P
  //      IPPSP        -> (invalid) -> NNNNP
  //          PPSI     -> (invalid) -> MNNNP (1 missing)
  //             IPPSI -> (invalid) -> N...P
  struct validation_stats expected = {.valid = 2,
      .invalid = 3,
      .missed_nalus = 1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    // SI                ->   (valid) -> .P
    //  IPPSI            ->   (valid) -> ....P
    //      IPPSP        ->   (valid) -> ....P
    //          PPSI     -> (invalid) -> MNNNP (1 missing)
    //             IPPSI -> (invalid) -> N...P
    expected.valid = 3;
    expected.invalid = 2;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_the_gi_nalus)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPSIPPSIPPSI");

  // SEI of second non-empty GOP: SIPPSIPP S IPPSIPPSI.
  int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  // Note that we have removed an item before this one, hence the 'I' is now at place 9:
  // SIPPSIPP I PPSIPPS.
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "SIPPSIPPPPSIPPSI");

  // All NAL Units but the last 'I' are validated and since one couple of SEI and 'I' have been
  // removed the authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 16, 15, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per detected GOP. Note that we lose one 'true' GOP since the transition is
  // lost. We have now two incomplete GOPs; second (missing S) and third (missing I). In fact, we
  // miss the transition between GOP two and three, but will detect it later through the gop
  // counter. Unfortunately, the authentication result does not cover the case "invalid gop" and
  // "missing gops", so we cannot get that information. This will be solved when changing to a more
  // complete authentication report.
  struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .missed_nalus = -2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity if the SEI arrives late. This is simulated by
 * moving the SEI to a 'P' in the next GOP.
 */
START_TEST(sei_arrives_late)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPPIPPPIPPPI", settings[_i]);
  test_stream_check_types(list, "SIPPPSIPPPSIPPPSI");

  // Remove the second SEI, that is, number 6 in the list: SIPPP (S) IPPPSIPPPSI.
  test_stream_item_t *sei = test_stream_item_remove(list, 6);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "SIPPPIPPPSIPPPSI");

  // Prepend the middle P of the next GOP: SIPPPIP (S)P PSIPPPSI. This is equivalent with appending
  // the first P of the same GOP, that is, number 7.
  test_stream_append_item(list, sei, 7);
  test_stream_check_types(list, "SIPPPIPSPPSIPPPSI");

  // All NAL Units but the last 'I' are validated as OK, which is pending.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP + the extra P before (S). The late arrival SEI will introduce one
  // pending NAL Unit (the P frame right before).
  struct validation_stats expected = {
      .valid = 4, .pending_nalus = 5, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

// TODO: Generalize this function.
/* Helper function that generates a fixed list with delayed SEIs. */
static test_stream_t *
generate_delayed_sei_list(struct sv_setting setting, bool extra_delay)
{
  // Make first GOP one P-frame longer to trigger recurrence on second I-frame.
  test_stream_t *list = create_signed_nalus("IPPPPIPPPIPPPIPPPIP", setting);
  test_stream_check_types(list, "SIPPPPSIPPPSIPPPSIPPPSIP");

  // Remove each SEI in the list and append it 2 items later (which in practice becomes 1 item later
  // since we just removed the SEI).
  int extra_offset = extra_delay ? 5 : 0;
  int extra_correction = extra_delay ? 1 : 0;
  test_stream_item_t *sei = test_stream_item_remove(list, 1);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 2 + extra_offset);
  sei = test_stream_item_remove(list, 7 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 8 + extra_offset);
  sei = test_stream_item_remove(list, 12 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 13 + extra_offset);
  sei = test_stream_item_remove(list, 17 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 18 + extra_offset);
  sei = test_stream_item_remove(list, 22 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 23);

  if (extra_delay) {
    test_stream_check_types(list, "IPPPPISPPPIPSPPIPSPPIPSS");
  } else {
    test_stream_check_types(list, "IPSPPPIPSPPIPSPPIPSPPIPS");
  };
  return list;
}

/* Test description
 * Verify that we can validate authenticity if all SEIs arrive late. This is simulated by moving
 * each SEI to a P in the next GOP.
 */
START_TEST(all_seis_arrive_late)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);

  // IPPPPISPPPIPSPPIPSPPIPSS
  //
  // IPPPPI                   -> (no signature) -> PPPPPP         6 pending
  // IPPPPIS                  ->        (valid) -> PPPPPP.        6 pending
  // IPPPPISPPPIPS            ->        (valid) -> .....P.PPPPP.  6 pending
  //      ISPPPIPSPPIPS       ->        (valid) -> .....PP.PPPP.  6 pending
  //           IPSPPIPSPPIPS  ->        (valid) -> .....PP.PPPP.  6 pending
  //                IPSPPIPSS ->        (valid) -> .....PP..      2 pending
  //                                                32 pending
  // All NAL Units but the last 'I', 'P' and 2 SEIs are validated as OK, hence four pending NAL
  // Units.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 24, 20, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 5,
      .unsigned_gops = 1,
      .pending_nalus = 32,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_first_gop_scrapped)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);

  test_stream_item_t *item = test_stream_pop_first_item(list);
  test_stream_item_check_type(item, 'I');
  test_stream_check_types(list, "PPPPISPPPIPSPPIPSPPIPSS");
  test_stream_item_free(item);
  item = test_stream_pop_first_item(list);
  test_stream_item_check_type(item, 'P');
  test_stream_check_types(list, "PPPISPPPIPSPPIPSPPIPSS");
  test_stream_item_free(item);
  item = test_stream_pop_first_item(list);
  test_stream_item_check_type(item, 'P');
  test_stream_check_types(list, "PPISPPPIPSPPIPSPPIPSS");
  test_stream_item_free(item);
  item = test_stream_pop_first_item(list);
  test_stream_item_check_type(item, 'P');
  test_stream_check_types(list, "PISPPPIPSPPIPSPPIPSS");
  test_stream_item_free(item);
  item = test_stream_pop_first_item(list);
  test_stream_item_check_type(item, 'P');
  test_stream_check_types(list, "ISPPPIPSPPIPSPPIPSS");
  test_stream_item_free(item);

  // ISPPPIPSPPIPSPPIPSS
  //
  // IS                  ->    (signature) -> PU             1 pending
  // ISPPPIPS            ->    (signature) -> PUPPPPPU       6 pending
  // ISPPPIPSPPIPS       ->        (valid) -> .U...PPUPPPP.  6 pending
  //      IPSPPIPSPPIPS  ->        (valid) -> ..U..PP.PPPP.  6 pending
  //           IPSPPIPSS ->        (valid) -> .....PP..      2 pending
  //                                                        21 pending
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 19, 15, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 3,
      .has_sei = 2,
      .pending_nalus = 21,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if the SEI arrives late with a lost SEI
 * the GOP before.
 */
START_TEST(lost_g_before_late_sei_arrival)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPPIPPPIPPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPPSIPPPSIPPPSIPPSI");

  // Remove the third SEI, that is, number 11 in the list: SIPPPSIPPP (S) IPPPSIPPSI.
  test_stream_item_t *sei = test_stream_item_remove(list, 11);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "SIPPPSIPPPIPPPSIPPSI");

  // Prepend the middle P of the next GOP: SIPPPSIPPPIP (S)P PSIPPSI. This is equivalent with
  // appending the first P of the same GOP, that is, number 12.

  test_stream_append_item(list, sei, 12);
  test_stream_check_types(list, "SIPPPSIPPPIPSPPSIPPSI");

  // Remove the second SEI, i.e., number 6 in the list: SIPPP (S) IPPPIPSPPSIPPSI.
  remove_item_then_check_and_free(list, 6, 'S');
  test_stream_check_types(list, "SIPPPIPPPIPSPPSIPPSI");

  // SI                   ->   (valid) -> .P           1 pending
  //  IPPPIPPPIPS         -> (invalid) -> NNNNN...PP.  2 pending (two GOPs in one validation)
  //          IPSPPSI     ->   (valid) -> ......P      1 pending
  //                IPPSI ->   (valid) -> ....P        1 pending
  //                                             5 pending
  // All NAL Units but the last 'I' are validated. Since a SEI is lost the authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 20, 19, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 3,
      .invalid = 1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Consider a scenario where the validation side starts recording a video stream from the second
 * GOP, and the SEIs arrive late. This test validates proper results if the second SEI is lost and
 * the first SEI arrives inside the second GOP.
 */
START_TEST(lost_g_and_gop_with_late_sei_arrival)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  if (TMP_FIX_TO_ALLOW_TWO_INVALID_SEIS_AT_STARTUP) return;

  test_stream_t *list = create_signed_nalus("IPIPPPIPPPIP", settings[_i]);
  test_stream_check_types(list, "SIPSIPPPSIPPPSIP");

  // Get the first SEI, to be added back later.
  test_stream_item_t *sei = test_stream_pop_first_item(list);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPSIPPPSIPPPSIP");

  // Remove the first GOP to mimic the start of the validation side.
  remove_item_then_check_and_free(list, 1, 'I');
  test_stream_check_types(list, "PSIPPPSIPPPSIP");
  remove_item_then_check_and_free(list, 1, 'P');
  test_stream_check_types(list, "SIPPPSIPPPSIP");
  remove_item_then_check_and_free(list, 1, 'S');
  test_stream_check_types(list, "IPPPSIPPPSIP");

  // Inject the SEI into the second GOP.
  test_stream_append_item(list, sei, 2);
  test_stream_check_types(list, "IPSPPSIPPPSIP");

  // Move the remaining SEIs.
  sei = test_stream_item_remove(list, 6);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPSPPIPPPSIP");
  test_stream_append_item(list, sei, 7);
  test_stream_check_types(list, "IPSPPIPSPPSIP");

  sei = test_stream_item_remove(list, 11);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPSPPIPSPPIP");
  test_stream_append_item(list, sei, 12);
  test_stream_check_types(list, "IPSPPIPSPPIPS");

  // IPS            -> (signature) -> PPU
  // IPSPPIPS*      ->     (valid) -> ..U..PP.
  //      IPS*PPIPS ->     (valid) -> .....PP.
  // All NAL Units but the last three NAL Units are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 13, 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 2,
      .pending_nalus = 6,
      .has_sei = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if we lose all NAL Units between two SEIs. */
START_TEST(lost_all_nalus_between_two_seis)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPPIPPPIPPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPPSIPPPSIPPPSIPPSI");

  // Remove IPPP between the second and third S.
  remove_item_then_check_and_free(list, 7, 'I');
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'P');
  test_stream_check_types(list, "SIPPPSSIPPPSIPPSI");

  // All NAL Units but the last 'I' are validated. Since all NAL Units between two SEIs are lost the
  // authenticity is NOT OK.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // We have NAL Units from 5 GOPs present and each GOP will produce one pending NAL Unit. The lost
  // NAL Units (IPPP) will be detected, but for SV_AUTHENTICITY_LEVEL_FRAME we will measure one
  // extra missing NAL Unit. This is a descrepancy in the way we count NAL Units by excluding SEIs.
  //
  // SIPPPSSIPPPSIPPSI
  //
  // SI                ->   (valid) -> .P
  //  IPPPSS           -> (invalid) -> NNNNNP
  //       SI          -> (invalid) -> MMMMNP (4 missed)
  //        IPPPSI     -> (invalid) -> N....P
  //             IPPSI ->   (valid) -> ....P
  struct validation_stats expected = {.valid = 2,
      .invalid = 3,
      .missed_nalus = 4,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    // SIPPPSSIPPPSIPPSI
    //
    // SI                ->   (valid) -> .P
    //  IPPPSS           ->   (valid) -> .....P
    //       SI          -> (invalid) -> MMMM.P (4 missed)
    //        IPPPSI     -> (invalid) -> N....P
    //             IPPSI ->   (valid) -> ....P
    expected.valid = 3;
    expected.invalid = 2;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if a SEI has been added between signing and
 * authentication.
 */
START_TEST(add_one_sei_nalu_after_signing)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPSIPPSI");

  const uint8_t id = 0;
  test_stream_item_t *sei = test_stream_item_create_from_type('Z', id, settings[_i].codec);

  // Middle 'P' in second non-empty GOP: SIPPSIP P(Z) PSIPPSI
  const int append_nalu_number = 8;
  test_stream_append_item(list, sei, append_nalu_number);
  test_stream_check_types(list, "SIPPSIPPZPSIPPSI");

  // All NAL Units but the last 'I' are validated as OK. The last one is pending.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 16, 15, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP.
  struct validation_stats expected = {
      .valid = 4, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we do get a valid authentication if the signing on the camera was reset. From a
 * signed video perspective this action is correct as long as recorded NAL Units are not transmitted
 * while the signing is down. That would on the other hand be detected at the client side through a
 * failed validation. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Generate a second test stream with a sequence of signed GOPs and concatenate lists.
 * 3. Run all NAL Units through the validator.
 */
START_TEST(camera_reset_on_signing_side)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Generate 2 GOPs
  test_stream_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPP");

  // Generate another GOP from scratch
  test_stream_t *list_after_reset = create_signed_nalus_int("IPPPI", settings[_i], true);
  test_stream_check_types(list_after_reset, "SIPPPSI");

  test_stream_append(list, list_after_reset);
  test_stream_check_types(list, "SIPPSIPPSIPPPSI");

  // Final validation is NOT OK and all received NAL Units, but the last, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, true, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP. Note that the mid GOP (IPPSI) includes the reset on the camera.
  // It will be marked as invalid and compute 3 more NAL Units than expected. In S it is
  // communicated there is only 2 NAL Units present (SI). So missed NAL Units equals -3 (IPP).
  // TODO: public_key_has_changed is expected to be true now when we have changed the behavior in
  // generate private key.
  const struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .missed_nalus = -3,
      .pending_nalus = 4,
      .public_key_has_changed = true,
      .final_validation = &final_validation};

  validate_test_stream(NULL, list, expected);
  test_stream_free(list);
}
END_TEST

/* Test description
 */
START_TEST(detect_change_of_public_key)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Generate 2 GOPs
  test_stream_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPP");

  // Generate another GOP from scratch
  // This will generate a new private key, hence transmit a different public key.
  test_stream_t *list_with_new_public_key = create_signed_nalus_int("IPPPI", settings[_i], true);
  test_stream_check_types(list_with_new_public_key, "SIPPPSI");

  test_stream_append(list, list_with_new_public_key);
  test_stream_check_types(list, "SIPPSIPPSIPPPSI");

  // Final validation is NOT OK and all received NAL Units, but the last, are validated. The
  // |public_key_has_changed| flag has been set.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, true, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // The list will be validated successfully up to the third SEI (S) which has the new Public key.
  //
  //   SI      -> .P     (valid, 1 pending, public_key_has_changed = false)
  //   IPPSI   -> ....P  (valid, 1 pending, public_key_has_changed = false)
  //   IPPS*I  -> NNN.P  (invalid, 1 pending, public_key_has_changed = true, -3 missing)
  //   IPPPS*I -> N....P (invalid, 1 pending, public_key_has_changed = false)
  // where S* has the new Public key. Note that we get -3 missing since we receive 3 more than what
  // is expected according to S*.
  const struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .missed_nalus = -3,
      .pending_nalus = 4,
      .public_key_has_changed = true,
      .final_validation = &final_validation};

  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Fast forward a recording will move to a new location, but only at 'I'. If we use the access
 * unit (AU) format 'I's may be prepended with SEIs. When fast forwarding the user has to
 * call the signed_video_reset function otherwise the first verification will become invalid. We
 * test both cases.
 *
 * The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Pop a new list from it with one complete GOP of nalus. Validate the new list.
 * 3. Remove all NAL Units until the next SEI. With the access unit format, the SEI is
 *    sent together with the 'I'.
 * 4a. Reset the session, and validate.
 * 4b. Validate without a reset.
 */
static test_stream_t *
mimic_au_fast_forward_and_get_list(onvif_media_signing_t *oms, struct sv_setting setting)
{
  test_stream_t *list = create_signed_nalus("IPPPPIPPPIPPPIPPPIPPPI", setting);
  test_stream_check_types(list, "SIPPPPSIPPPSIPPPSIPPPSIPPPSI");

  // Extract the first 9 NAL Units from the list. This should be the empty GOP, a full GOP and in
  // the middle of the next GOP: SIPPPPSIP PPSIPPPSIPPPSI. These are the NAL Units to be processed
  // before the fast forward.
  test_stream_t *pre_fast_forward = test_stream_pop(list, 9);
  test_stream_check_types(pre_fast_forward, "SIPPPPSIP");
  test_stream_check_types(list, "PPSIPPPSIPPPSIPPPSI");

  // Final validation of |pre_fast_forward| is OK and all received NAL Units, but the last two, are
  // validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 9, 7, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |oms|.
  //
  // SI      -> .P          (valid)
  // IPPPPSI ->  .....P     (valid)
  //
  // Total number of pending NAL Units = 1 + 1 = 2
  struct validation_stats expected = {
      .valid = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_test_stream(oms, pre_fast_forward, expected);
  test_stream_free(pre_fast_forward);

  // Mimic fast forward by removing 7 NAL Units ending up at the second next SEI: PSIPP SIPPSIPPSI.
  // A fast forward is always done to an 'I', and if we use the access unit (AU) format, also the
  // preceding SEI will be present.
  int remove_items = 7;
  while (remove_items--) {
    test_stream_item_t *item = test_stream_pop_first_item(list);
    test_stream_item_free(item);
  }
  test_stream_check_types(list, "SIPPPSIPPPSI");

  return list;
}

START_TEST(fast_forward_stream_with_reset)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a session.
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(oms);
  ck_assert_int_eq(signed_video_set_authenticity_level(oms, settings[_i].auth_level), OMS_OK);
  test_stream_t *list = mimic_au_fast_forward_and_get_list(oms, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(oms), OMS_OK);

  // Final validation is OK and all received NAL Units, but the last one, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 12, 11, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate SIPPPSIPPPSI:
  //
  // SI      -> UP           (OMS_AUTHENTICITY_NOT_FEASIBLE)
  // SIPPPSI -> U.....P      (valid)
  // IPPPSI  ->       .....P (valid)
  //
  // Total number of pending NAL Units = 1 + 1 + 1 = 3
  const struct validation_stats expected = {.valid = 2,
      .pending_nalus = 3,
      .has_sei = 1,
      .final_validation = &final_validation};

  validate_test_stream(oms, list, expected);
  // Free list and session.
  onvif_media_signing_free(oms);
  test_stream_free(list);
}
END_TEST

START_TEST(fast_forward_stream_without_reset)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a session.
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(oms);
  ck_assert_int_eq(signed_video_set_authenticity_level(oms, settings[_i].auth_level), OMS_OK);
  test_stream_t *list = mimic_au_fast_forward_and_get_list(oms, settings[_i]);

  // Final validation is NOT OK and all received NAL Units, but the last one, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 21, 20, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate IP SIPPPSIPPPSI (without reset, i.e., started with IP before fast forward):
  //
  // SI      -> NMMUP           (invalid, 2 missing)
  // SIPPPSI ->    UN....P      (invalid)
  // IPPPSI  ->          .....P (valid)
  //
  // Total number of pending NAL Units = 1 + 1 + 1 = 3
  const struct validation_stats expected = {.valid = 1,
      .invalid = 2,
      .missed_nalus = 2,
      .pending_nalus = 3,
      .final_validation = &final_validation};

  validate_test_stream(oms, list, expected);

  // Free list and session.
  test_stream_free(list);
  onvif_media_signing_free(oms);
}
END_TEST

static test_stream_t *
mimic_au_fast_forward_on_late_seis_and_get_list(onvif_media_signing_t *oms, struct sv_setting setting)
{
  test_stream_t *list = generate_delayed_sei_list(setting, false);
  test_stream_check_types(list, "IPSPPPIPSPPIPSPPIPSPPIPS");

  // Extract the first 9 NAL Units from the list. This should be the empty GOP, a full GOP and in
  // the middle of the next GOP: IPSPPPIPS PPIPSPPIPSPPIPS. These are the NAL Units to be processed
  // before the fast forward.
  test_stream_t *pre_fast_forward = test_stream_pop(list, 9);
  test_stream_check_types(pre_fast_forward, "IPSPPPIPS");
  test_stream_check_types(list, "PPIPSPPIPSPPIPS");

  // Final validation of |pre_fast_forward| is OK and all received NAL Units, but the last three,
  // are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 9, 6, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |oms|.
  //
  // IPS         -> PP.         (valid)
  // IPSPPPIPS   -> ......PP.   (valid)
  //
  // Total number of pending NAL Units = 2 + 2 = 4
  struct validation_stats expected = {
      .valid = 2, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(oms, pre_fast_forward, expected);
  test_stream_free(pre_fast_forward);

  // Mimic fast forward by removing 7 NAL Units ending up at the start of a later GOP: PPIPSPP
  // IPSPPIPS. A fast forward is always done to an 'I'. The first SEI showing up is associated with
  // the now removed NAL Units.
  int remove_items = 7;
  while (remove_items--) {
    test_stream_item_t *item = test_stream_pop_first_item(list);
    test_stream_item_free(item);
  }
  test_stream_check_types(list, "IPSPPIPS");

  return list;
}

START_TEST(fast_forward_stream_with_delayed_seis)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a new session.
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(oms);
  ck_assert_int_eq(signed_video_set_authenticity_level(oms, settings[_i].auth_level), OMS_OK);
  test_stream_t *list = mimic_au_fast_forward_on_late_seis_and_get_list(oms, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(oms), OMS_OK);

  // Final validation is OK and all received NAL Units, but the last three, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 8, 5, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate IPSPPIPS:
  //
  // IPS      -> PPU           (OMS_AUTHENTICITY_NOT_FEASIBLE)
  // IPSPPIPS -> ..U..PP.      (valid)
  //
  // Total number of pending NAL Units = 2 + 2 = 4
  struct validation_stats expected = {.valid = 1,
      .pending_nalus = 4,
      .has_sei = 1,
      .final_validation = &final_validation};

  validate_test_stream(oms, list, expected);
  // Free list and session.
  onvif_media_signing_free(oms);
  test_stream_free(list);
}
END_TEST

/* Export-to-file tests descriptions
 * The main scenario for usage is to validate authenticity on exported files. The stream then looks
 * a little different since we have no start reference.
 *
 * Below is a helper function that creates a stream of NAL Units and exports the middle part by
 * pop-ing GOPs at the beginning and at the end.
 *
 * As an additional piece, the stream starts with a PPS/SPS/VPS NAL Unit, which is moved to the
 * beginning of the "file" as well. That should not affect the validation. */
static test_stream_t *
mimic_file_export(struct sv_setting setting, bool include_i_nalu_at_end, bool delayed_seis)
{
  test_stream_t *pre_export = NULL;
  test_stream_t *list = create_signed_nalus("VIPPIPPIPPIPPIPPIPP", setting);
  test_stream_check_types(list, "VSIPPSIPPSIPPSIPPSIPPSIPP");

  // Remove the initial PPS/SPS/VPS NAL Unit to add back later
  test_stream_item_t *ps = test_stream_pop_first_item(list);
  test_stream_item_check_type(ps, 'V');

  if (delayed_seis) {
    int out[4] = {1, 4, 7, 10};
    for (int i = 0; i < 4; i++) {
      test_stream_item_t *sei = test_stream_item_remove(list, out[i]);
      test_stream_item_check_type(sei, 'S');
      test_stream_append_item(list, sei, 13);
    }
    test_stream_check_types(list, "IPPIPPIPPISSSSPPSIPPSIPP");
    pre_export = test_stream_pop(list, 6);
    test_stream_check_types(pre_export, "IPPIPP");
    test_stream_check_types(list, "IPPISSSSPPSIPPSIPP");
  } else {
    // Remove the first 4 NAL Units from the list. This should be the first complete GOP: SIPP
    // SIPPSIPPSIPPSIPP. These are the NAL Units to be processed before the fast forward.
    pre_export = test_stream_pop(list, 4);
    test_stream_check_types(pre_export, "SIPP");
    test_stream_check_types(list, "SIPPSIPPSIPPSIPPSIPP");
  }

  // Mimic end of file export by removing items at the end of the list. Here we can take two
  // approaches, that is, include the 'I' at the end and not. The latter being the standard
  // operation, which creates a dangling end. The list of NAL Units will after this have 3 GOPs:
  // SIPPSIPPSIPP(SI).
  int remove_items = include_i_nalu_at_end ? 2 : 4;
  while (remove_items--) {
    test_stream_item_t *item = test_stream_pop_last_item(list);
    test_stream_item_free(item);
  }
  // Prepend list with PPS/SPS/VPS NAL Unit
  test_stream_prepend_first_item(list, ps);

  if (delayed_seis) {
    test_stream_check_types(list, include_i_nalu_at_end ? "VIPPISSSSPPSIPPSI" : "VIPPISSSSPPSIPP");
  } else {
    test_stream_check_types(
        list, include_i_nalu_at_end ? "VSIPPSIPPSIPPSIPPSI" : "VSIPPSIPPSIPPSIPP");
  }
  test_stream_free(pre_export);

  return list;
}

START_TEST(file_export_with_dangling_end)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = mimic_file_export(settings[_i], false, false);

  // Create a new session and validate the authenticity of the file.
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(oms);
  // VSIPPSIPPSIPPSIPP (17 NAL Units)
  //
  // VSI             -> (signature) -> _UP
  //   IPPSI         ->     (valid) -> ....P
  //       IPPSI     ->     (valid) -> ....P
  //           IPPSI ->     (valid) -> ....P
  //
  // One pending NAL Unit per GOP.
  // Final validation is OK and all received NAL Units, but the last three, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 17, 14, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 3,
      .pending_nalus = 4,
      .has_sei = 1,
      .final_validation = &final_validation};

  validate_test_stream(oms, list, expected);

  // Free list and session.
  onvif_media_signing_free(oms);
  test_stream_free(list);
}
END_TEST

START_TEST(file_export_without_dangling_end)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = mimic_file_export(settings[_i], true, false);

  // Create a new session and validate the authenticity of the file.
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(oms);
  // VSIPPSIPPSIPPSIPPSI (19 NAL Units)
  //
  // VSI                 -> (signature) -> _UP
  //   IPPSI             ->     (valid) -> ....P
  //       IPPSI         ->     (valid) -> ....P
  //           IPPSI     ->     (valid) -> ....P
  //               IPPSI ->     (valid) -> ....P
  //
  // One pending NAL Unit per GOP.
  // Final validation is OK and all received NAL Units, but the last one, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 19, 18, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid = 4,
      .pending_nalus = 5,
      .has_sei = 1,
      .final_validation = &final_validation};
  validate_test_stream(oms, list, expected);
  // Free list and session.
  onvif_media_signing_free(oms);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we do not get any authentication if the stream has no signature
 */
START_TEST(no_signature)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = test_stream_create("IPPIPPIPPIPPI", settings[_i].codec);
  test_stream_check_types(list, "IPPIPPIPPIPPI");

  // Video is not signed, hence all NAL Units are pending.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_NOT_SIGNED, false, 13, 0, 13, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // Note that we are one frame off. The start of a GOP (the I) is reported as end of the previous
  // GOP. This is not a big deal, since the message is still clear; We have no signed video. We will
  // always have one GOP pending validation, since we wait for a potential SEI, and will validate
  // upon the 'next' GOP transition.
  //
  // IPPI          -> (PPPP)  (pending, pending, pending, pending)
  // IPPIPPI       -> (PPPPPPP)
  // IPPIPPIPPI    -> (PPPPPPPPPP)
  // IPPIPPIPPIPPI -> (PPPPPPPPPPPPP)
  //
  // pending_nalus = 4 + 7 + 10 + 13 = 34
  const struct validation_stats expected = {.unsigned_gops = 4,
      .pending_nalus = 34,
      .has_no_timestamp = true,
      .final_validation = &final_validation};

  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(multislice_no_signature)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = test_stream_create("IiPpPpIiPpPpIiPpPpIiPpPpIi", settings[_i].codec);
  test_stream_check_types(list, "IiPpPpIiPpPpIiPpPpIiPpPpIi");

  // Video is not signed, hence all NAL Units are pending.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_NOT_SIGNED, false, 26, 0, 26, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // We will always have one GOP pending validation, since we wait for a potential SEI, and will
  // validate upon the 'next' GOP transition.
  //
  // IiPpPpI                   -> (PPPPPPP)  (pending, pending, pending, pending, pending, pending)
  // IiPpPpIiPpPpI             -> (PPPPPPPPPPPPP)
  // IiPpPpIiPpPpIiPpPpI       -> (PPPPPPPPPPPPPPPPPPP)
  // IiPpPpIiPpPpIiPpPpIiPpPpI -> (PPPPPPPPPPPPPPPPPPPPPPPPP)
  //
  // pending_nalus = 7 + 13 + 19 + 25 = 64
  const struct validation_stats expected = {.unsigned_gops = 4,
      .pending_nalus = 64,
      .has_no_timestamp = true,
      .final_validation = &final_validation};

  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Check authentication if public key arrives late and a sei is missing before public key arrives.
 *
 * The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Check the sequence of NAL Units.
 * 3. Remove the first GOP containing the public key.
 * 4. Remove a sei before public key arrives.
 * 5. Check the authentication result.
 */
START_TEST(late_public_key_and_no_sei_before_key_arrives)
{
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPI", settings[_i]);

  ck_assert(list);
  test_stream_check_types(list, "SIPPSIPPSIPPSIPPSIPPSIPPSI");

  test_stream_item_t *g_1 = test_stream_item_remove(list, 5);
  test_stream_item_check_type(g_1, 'S');
  test_stream_check_types(list, "SIPPIPPSIPPSIPPSIPPSIPPSI");
  // First public key now exist in item 8 if SV_RECURRENCE_EIGHT and SV_RECURRENCE_OFFSET_THREE

  // Final validation is NOT OK and all received NAL Units, but the last one, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_NOT_OK, false, 25, 24, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NAL Unit per GOP.
  struct validation_stats expected = {.valid = 5,
      .invalid = 2,
      .pending_nalus = 10,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_item_free(g_1);
  test_stream_free(list);
}
END_TEST

static onvif_media_signing_t *
generate_and_set_private_key_on_camera_side(struct sv_setting setting,
    bool add_public_key_to_sei,
    test_stream_item_t **sei_item)
{
  MediaSigningReturnCode sv_rc;
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, setting.codec);
  onvif_media_signing_t *oms = onvif_media_signing_create(setting.codec);
  ck_assert(oms);
  // Read and set content of private_key.
  sv_rc = setting.generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, OMS_OK);
  sv_rc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, OMS_OK);

  sv_rc = signed_video_add_public_key_to_sei(oms, add_public_key_to_sei);
  ck_assert_int_eq(sv_rc, OMS_OK);
  sv_rc = signed_video_set_authenticity_level(oms, setting.auth_level);
  ck_assert_int_eq(sv_rc, OMS_OK);

  // Add an 'I' to trigger a SEI.
  sv_rc = signed_video_add_nalu_for_signing(oms, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, OMS_OK);

  size_t sei_size = 0;
  sv_rc = signed_video_get_sei(oms, NULL, &sei_size);
  ck_assert(sei_size > 0);
  ck_assert_int_eq(sv_rc, OMS_OK);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(oms, sei, &sei_size);
  ck_assert_int_eq(sv_rc, OMS_OK);
  *sei_item = test_stream_item_create(sei, sei_size, setting.codec);
  sv_rc = signed_video_get_sei(oms, NULL, &sei_size);

  ck_assert_int_eq(sv_rc, OMS_OK);
  ck_assert(sei_size == 0);
  ck_assert(tag_is_present(*sei_item, setting.codec, PUBLIC_KEY_TAG) == add_public_key_to_sei);

  test_stream_item_free(i_nalu);
  free(private_key);
  return oms;
}

static void
validate_public_key_scenario(onvif_media_signing_t *oms,
    test_stream_item_t *sei,
    bool wrong_key,
    pem_pkey_t *public_key)
{
  MediaSigningReturnCode sv_rc;
  SignedVideoCodec codec = oms->codec;
  bool public_key_present = oms->has_public_key;

  // Validate this first GOP.
  onvif_media_signing_authenticity_t *auth_report = NULL;
  onvif_media_signing_latest_validation_t *latest = NULL;

  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  sv_rc = onvif_media_signing_add_nalu_and_authenticate(oms, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, OMS_OK);
  ck_assert(!auth_report);

  // Late public key
  if (public_key) {
    sv_rc = signed_video_set_public_key(oms, public_key->key, public_key->key_size);
    ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
    // Since setting a public key after the session start is not supported, there is no point in
    // adding the i_nalu and authenticate.
  } else {
    sv_rc =
        onvif_media_signing_add_nalu_and_authenticate(oms, i_nalu->data, i_nalu->data_size, &auth_report);

    if (public_key_present) {
      ck_assert_int_eq(sv_rc, OMS_OK);
    } else {
      ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
    }

    if (public_key_present) {
      ck_assert(auth_report);
      latest = &(auth_report->latest_validation);
      ck_assert(latest);
      if (tag_is_present(sei, codec, PUBLIC_KEY_TAG)) {
        // |public_key_has_changed| is true if another public key is added.
        ck_assert(latest->public_key_has_changed == wrong_key);
      }

      if (wrong_key) {
        ck_assert_int_eq(latest->authenticity, OMS_AUTHENTICITY_NOT_OK);
      } else {
        ck_assert_int_eq(latest->authenticity, OMS_AUTHENTICITY_OK);
      }
    }
    // We are done with auth_report
    onvif_media_signing_authenticity_report_free(auth_report);
  }
  // Free nalu_list_item and session.
  test_stream_item_free(i_nalu);
}

/* Test description
 * Check if the API signed_video_add_public_key_to_sei can add a public key to the SEI and if
 * signed_video_add_public_key_to_sei can set a public key on the auth side.
 *
 * Verify that it is not valid to add a manipulated key or set a public key in the middle of a
 * stream.
 *
 * Default is when a public key is added to the SEI.
 */
START_TEST(test_public_key_scenarios)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  struct pk_setting {
    bool pk_in_sei;
    bool use_wrong_pk;
    bool set_pk_before_session_start;
    bool set_pk_after_session_start;
  };

  struct pk_setting pk_tests[] = {
      // No public key in SEI. The correct public key is added to Signed Video before starting the
      // session.
      {false, false, true, false},
      // Public key present in SEI. The correct public key is also added to Signed Video before
      // starting the session.
      {true, false, true, false},
      // No public key in SEI and no public key added to Signed Video.
      {false, false, false, false},
      // No public key in SEI. The correct public key is added to Signed Video after the session has
      // started.
      {false, false, false, true},
      // Public key present in SEI. The correct public key is also added to Signed Video after the
      // session has started.
      {true, false, false, true},
      // Public key present in SEI. A manipulated public key is also added to Signed Video before
      // starting the session.
      {true, true, true, false},
      // Activate when TODO in the test below is fixed.
      //    {false, true, false, true},
  };

  for (size_t j = 0; j < sizeof(pk_tests) / sizeof(*pk_tests); j++) {
    MediaSigningReturnCode sv_rc;
    SignedVideoCodec codec = settings[_i].codec;
    test_stream_item_t *sei = NULL;
    onvif_media_signing_t *sv_camera = NULL;
    char *tmp_private_key = NULL;
    size_t tmp_private_key_size = 0;
    pem_pkey_t wrong_public_key = {0};

    sv_camera =
        generate_and_set_private_key_on_camera_side(settings[_i], pk_tests[j].pk_in_sei, &sei);

    // On validation side
    onvif_media_signing_t *sv_vms = onvif_media_signing_create(codec);

    sign_or_verify_data_t sign_data_wrong_key = {0};
    // Generate a new private key in order to extract a bad private key (a key not compatible with
    // the one generated on the camera side)
    settings[_i].generate_key(NULL, &tmp_private_key, &tmp_private_key_size);
    sv_rc = openssl_private_key_malloc(&sign_data_wrong_key, tmp_private_key, tmp_private_key_size);
    ck_assert_int_eq(sv_rc, OMS_OK);
    openssl_read_pubkey_from_private_key(&sign_data_wrong_key, &wrong_public_key);

    pem_pkey_t *public_key = &sv_camera->pem_public_key;
    if (pk_tests[j].use_wrong_pk) {
      public_key = &wrong_public_key;
    }
    if (pk_tests[j].set_pk_before_session_start) {
      sv_rc = signed_video_set_public_key(sv_vms, public_key->key, public_key->key_size);
      ck_assert_int_eq(sv_rc, OMS_OK);
    }
    if (!pk_tests[j].set_pk_after_session_start) {
      public_key = NULL;
    }
    validate_public_key_scenario(sv_vms, sei, pk_tests[j].use_wrong_pk, public_key);

    onvif_media_signing_free(sv_camera);
    onvif_media_signing_free(sv_vms);
    free(tmp_private_key);
    openssl_free_key(sign_data_wrong_key.key);
    free(sign_data_wrong_key.signature);
    free(wrong_public_key.key);
    test_stream_item_free(sei);
  }
}
END_TEST

/* Test validation if emulation prevention bytes are added later, by for example an encoder.
 * We only run the case where emulation prevention bytes are not added when writing the SEI, since
 * the other case is the default and executed for all other tests. */
START_TEST(no_emulation_prevention_bytes)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoCodec codec = settings[_i].codec;
  MediaSigningReturnCode sv_rc;

  // Create a video with a single I-frame, and a SEI (to be created later).
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *sei_item = NULL;

  size_t sei_size;
  // Signing side
  // Generate a Private key.
  char *private_key = NULL;
  size_t private_key_size = 0;
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, OMS_OK);

  // Create a session.
  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);

  // Apply settings to session.
  sv_rc = signed_video_set_private_key_new(oms, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, OMS_OK);
  sv_rc = signed_video_set_authenticity_level(oms, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, OMS_OK);
  sv_rc = signed_video_set_sei_epb(oms, false);
  ck_assert_int_eq(sv_rc, OMS_OK);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  const size_t attestation_size = 2;
  void *attestation = calloc(1, attestation_size);
  // Setting |attestation| and |certificate_chain|.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(
      oms, attestation, attestation_size, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, OMS_OK);
  free(attestation);
#endif

  // Add I-frame for signing and get SEI frame.
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      oms, i_nalu->data, i_nalu->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, OMS_OK);

  sv_rc = signed_video_get_sei(oms, NULL, &sei_size);
  ck_assert_int_eq(sv_rc, OMS_OK);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(oms, sei, &sei_size);

  ck_assert(sei_size != 0);
  ck_assert_int_eq(sv_rc, OMS_OK);

  // Allocate memory for a new buffer to write to, and add emulation prevention bytes.
  uint8_t *sei_with_epb = malloc(sei_size * 4 / 3);
  uint8_t *sei_p = sei_with_epb;
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  memcpy(sei_p, sei, 4);
  sei_p += 4;  // Move past the start code to avoid an incorrect emulation prevention byte.
  char *src = (char *)(sei + 4);
  size_t src_size = sei_size - 4;
  write_byte_many(&sei_p, src, src_size, &last_two_bytes, true);
  size_t sei_with_epb_size = sei_p - sei_with_epb;
  signed_video_nalu_data_free(sei);

  // Create a SEI.
  sei_item = test_stream_item_create(sei_with_epb, sei_with_epb_size, codec);

  sv_rc = signed_video_get_sei(oms, sei, &sei_size);
  ck_assert_int_eq(sv_rc, OMS_OK);
  ck_assert(sei_size == 0);

  // Close signing side.
  onvif_media_signing_free(oms);
  oms = NULL;

  // End of signing side. Start a new session on the validation side.
  oms = onvif_media_signing_create(codec);
  ck_assert(oms);

  // Validate this first GOP.
  onvif_media_signing_authenticity_t *auth_report = NULL;
  onvif_media_signing_latest_validation_t *latest = NULL;

  // Assume we receive a single AU with a SEI and an 'I'.
  // Pass in the SEI.
  sv_rc =
      onvif_media_signing_add_nalu_and_authenticate(oms, sei_item->data, sei_item->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, OMS_OK);
  ck_assert(!auth_report);
  // Pass in the I-frame.
  sv_rc = onvif_media_signing_add_nalu_and_authenticate(oms, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, OMS_OK);
  // Read the authenticity report.
  if (auth_report) {
    latest = &(auth_report->latest_validation);
    ck_assert(latest);
    ck_assert_int_eq(strcmp(latest->validation_str, ".P"), 0);
    // Public key validation is not feasible since there is no Product information.
    ck_assert_int_eq(latest->public_key_validation, SV_PUBKEY_VALIDATION_NOT_FEASIBLE);
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity, OMS_AUTHENTICITY_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed, false);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus, 2);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus, 1);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus, 1);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_validation,
        SV_PUBKEY_VALIDATION_NOT_FEASIBLE);
    // We are done with auth_report.
    latest = NULL;
    onvif_media_signing_authenticity_report_free(auth_report);
    auth_report = NULL;
  } else {
    ck_assert(false);
  }

  // End of validation, free memory.
  test_stream_item_free(sei_item);
  test_stream_item_free(i_nalu);
  onvif_media_signing_free(oms);
  free(private_key);
}
END_TEST
#endif

/* Test description
 * This test generates a stream with five SEIs and moves them in time to simulate a
 * signing delay.
 */
START_TEST(with_blocked_signing)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPP");
  // Manually delay the SEIs
  test_stream_item_t *sei = test_stream_item_remove(list, 21);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 21);
  sei = test_stream_item_remove(list, 17);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 19);
  sei = test_stream_item_remove(list, 13);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 17);
  sei = test_stream_item_remove(list, 9);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 15);
  test_stream_check_types(list, "IPPISPPIPPIPPIPSPSISPSP");

  // IPPISPPIPPIPPIPSPSISPSP
  //
  // IPPIS                     .P                     (valid, 1 pending)
  //    ISPPIPPIPPIPS           ....PPPPPPPP.         (valid, 8 pending)
  //        IPPIPPIPSPS             ...PPPPP.P.       (valid, 6 pending)
  //           IPPIPSPSIS              ...PP.P.P.     (valid, 4 pending)
  //              IPSPSISPS               .....P.P.   (valid, 2 pending)
  //                                                       = 21 pending
  //                   ISPSP                   P.P.P  (valid, 3 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 23, 18, 5, 0, 0};
  struct validation_stats expected = {
      .valid = 5, .pending_nalus = 21, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Generates SEIs using golden SEI prinsiple and verifies them.
 * The operation is as follows:
 * 1. Generate and store golden SEI
 * 2. Enable golden SEI principle
 * 3. Create a test stream.
 * 4. Insert golden SEI to test stream
 * 5. Validate the test stream
 */
START_TEST(golden_sei_first)
{
  // Device side
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

  test_stream_t *list = create_signed_nalus_with_oms(oms, "IPPIPPPIPPPIP", false, false);
  onvif_media_signing_free(oms);
  test_stream_check_types(list, "GIPPISPPPISPPPISP");

  // Client side

  // GIPPISPPPISPPPISP
  //
  // G                  .                   (valid, 0 pending)
  //  IPPIS              ...P.              (valid, 1 pending)
  //     ISPPPIS            .....P.         (valid, 1 pending)
  //          ISPPPIS            .....P.    (valid, 1 pending)
  //                                                3 pending
  //               ISP                P.P   (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 17, 14, 3, 0, 0};
  struct validation_stats expected = {
      .valid = 4, .pending_nalus = 3, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(golden_sei_later)
{
  // Device side
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

  test_stream_t *list = create_signed_nalus_with_oms(oms, "IPPIPPPIPPPIP", false, false);
  onvif_media_signing_free(oms);
  test_stream_check_types(list, "GIPPISPPPISPPPISP");
  test_stream_item_t *golden_sei = test_stream_pop_first_item(list);
  test_stream_item_check_type(golden_sei, 'G');
  // Insert the Golden SEI after the I-frame.
  test_stream_append_item(list, golden_sei, 1);
  test_stream_check_types(list, "IGPPISPPPISPPPISP");

  // Client side

  // IGPPISPPPISPPPISP
  //
  // IG                 P.                  (valid, 1 pending)
  // IGPPIS             ....P.              (valid, 1 pending)
  //     ISPPPIS            .....P.         (valid, 1 pending)
  //          ISPPPIS            .....P.    (valid, 1 pending)
  //                                                4 pending
  //               ISP                P.P   (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 17, 14, 3, 0, 0};
  struct validation_stats expected = {
      .valid = 4, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(sign_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Client side

  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     (signed, 5 pending)
  // IPPIsPPIsPPIS     ...........P.             ( valid, 1 pending)
  //            ISPPIsPPIsPPIS    ...........P.  ( valid, 1 pending)
  //                                                      7 pending
  //                        ISP              P.P ( valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 26, 23, 3, 0, 0};
  struct validation_stats expected = {.valid = 2,
      .pending_nalus = 7,
      .has_sei = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_p_nalu_mulitple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Remove second 'P' in second GOP: IPPIsP P IsPPISPPIsPPIsPPISP
  const int remove_nalu_number = 7;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPIsPIsPPISPPIsPPIsPPISP");

  // Client side

  // IPPIsPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPIsPPIS      ......M....P.             (missing, 1 pending, 1 missing)
  //           ISPPIsPPIsPPIS     ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                       ISP               P.P (  valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK_WITH_MISSING_INFO, 25, 22,
      3, 0, 0};
  struct validation_stats expected = {.valid = 1,
      .valid_with_missing_info = 1,
      .has_sei = 1,
      .missed_nalus = 1,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  if (settings[_i].low_bitrate_mode) {
    // IPPIsPIsPPISPPIsPPIsPPISP
    //
    // IPPIs             PPPPP                     ( signed, 5 pending)
    // IPPIsPIsPPIS      NNNNNNM....P.             (invalid, 1 pending, 1 missing)
    //           ISPPIsPPIsPPIS     ...........P.  (  valid, 1 pending)
    //                                                       7 pending
    //                       ISP               P.P (  valid, 2 pending)
    expected.invalid = 1;
    expected.valid_with_missing_info = 0,
    expected.final_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(sign_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Client side

  // IPPPPSPISPPISPPPPSPISP
  //
  // IPPPPS                 ....P.                   (valid, 1 pending)
  //     PSPIS                  ...P.                (valid, 1 pending)
  //        ISPPIS                 ....P.            (valid, 1 pending)
  //            ISPPPPS                .....P.       (valid, 1 pending)
  //                 PSPIS                  ...P.    (valid, 1 pending)
  //                                                         5 pending
  //                    ISP                    P.P   (valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK, 22, 19, 3, 0, 0};
  struct validation_stats expected = {
      .valid = 5, .pending_nalus = 5, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_p_nalu_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Item counting starts at 1.  Remove second 'P' in third GOP: IPPPPSPISPPISP P PPSPISP
  const int remove_nalu_number = 15;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPPPSPISPPISPPPSPISP");

  // Client side

  // IPPPPSPISPPISPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPS                ...M.P.       (missing, 1 pending, 1 missing)
  //                PSPIS                  ...P.    (  valid, 1 pending)
  //                                                          5 pending
  //                   ISP                    P.P   (  valid, 2 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_NOT_FEASIBLE, false, OMS_AUTHENTICITY_OK_WITH_MISSING_INFO, 21, 18,
      3, 0, 0};
  struct validation_stats expected = {.valid = 4,
      .valid_with_missing_info = 1,
      .missed_nalus = 1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  if (settings[_i].low_bitrate_mode) {
    // IPPPPSPISPPISPPPSPISP
    //
    // IPPPPS                 ....P.                  (  valid, 1 pending)
    //     PSPIS                  ...P.               (  valid, 1 pending)
    //        ISPPIS                 ....P.           (  valid, 1 pending)
    //            ISPPPS                ....N.        (invalid, 0 pending)
    //                  PIS                   M.P.    (invalid, 1 pending, 1 missing)
    //                                                          4 pending
    //                   ISP                    P.P   (  valid, 2 pending)
    expected.valid = 3;
    expected.invalid = 2;
    expected.pending_nalus = 4;
    expected.valid_with_missing_info = 0,
    expected.final_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
  }
  validate_test_stream(NULL, list, expected);

  test_stream_free(list);
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

  int s = 0;
  int e = NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, invalid_api_inputs, s, e);
  tcase_add_loop_test(tc, intact_stream, s, e);
  tcase_add_loop_test(tc, intact_multislice_stream, s, e);
  tcase_add_loop_test(tc, intact_stream_with_splitted_nalus, s, e);
  tcase_add_loop_test(tc, intact_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_ms_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_multislice_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, remove_one_p_nalu, s, e);
  // tcase_add_loop_test(tc, interchange_two_p_nalus, s, e);
  // tcase_add_loop_test(tc, modify_one_p_nalu, s, e);
  // tcase_add_loop_test(tc, modify_one_i_nalu, s, e);
  // tcase_add_loop_test(tc, remove_the_g_nalu, s, e);
  // tcase_add_loop_test(tc, remove_the_i_nalu, s, e);
  // tcase_add_loop_test(tc, remove_the_gi_nalus, s, e);
  // tcase_add_loop_test(tc, sei_arrives_late, s, e);
  // tcase_add_loop_test(tc, all_seis_arrive_late, s, e);
  // tcase_add_loop_test(tc, all_seis_arrive_late_first_gop_scrapped, s, e);
  // tcase_add_loop_test(tc, lost_g_before_late_sei_arrival, s, e);
  // tcase_add_loop_test(tc, lost_g_and_gop_with_late_sei_arrival, s, e);
  // tcase_add_loop_test(tc, lost_all_nalus_between_two_seis, s, e);
  // tcase_add_loop_test(tc, add_one_sei_nalu_after_signing, s, e);
  // tcase_add_loop_test(tc, camera_reset_on_signing_side, s, e);
  // tcase_add_loop_test(tc, detect_change_of_public_key, s, e);
  // tcase_add_loop_test(tc, fast_forward_stream_with_reset, s, e);
  // tcase_add_loop_test(tc, fast_forward_stream_without_reset, s, e);
  // tcase_add_loop_test(tc, fast_forward_stream_with_delayed_seis, s, e);
  // tcase_add_loop_test(tc, file_export_with_dangling_end, s, e);
  // tcase_add_loop_test(tc, file_export_without_dangling_end, s, e);
  // tcase_add_loop_test(tc, no_signature, s, e);
  // tcase_add_loop_test(tc, multislice_no_signature, s, e);
  // tcase_add_loop_test(tc, late_public_key_and_no_sei_before_key_arrives, s, e);
  // tcase_add_loop_test(tc, test_public_key_scenarios, s, e);
  tcase_add_loop_test(tc, golden_sei_first, s, e);
  tcase_add_loop_test(tc, golden_sei_later, s, e);
  // tcase_add_loop_test(tc, no_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, with_blocked_signing, s, e);
  tcase_add_loop_test(tc, sign_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_one_p_nalu_mulitple_gops, s, e);
  tcase_add_loop_test(tc, sign_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_p_nalu_partial_gops, s, e);

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
