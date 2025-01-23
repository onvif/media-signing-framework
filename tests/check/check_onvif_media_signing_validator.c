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
#include "lib/src/oms_defines.h"  // ATTR_UNUSED
#include "lib/src/oms_internal.h"
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
 * If a NULL pointer |list| is passed in no action is taken.
 * If a NULL pointer |oms| is passed in a new session is created. This is convenient if
 * there are no other actions to take on |oms| outside this scope, like reset, or if no
 * trusted certificate should be set. */
static void
validate_test_stream(onvif_media_signing_t *oms,
    test_stream_t *list,
    struct validation_stats expected,
    ATTR_UNUSED bool ec_key)
{
  if (!list) {
    return;
  }

  bool internal_oms = false;
  if (!oms) {
    oms = onvif_media_signing_create(list->codec);
    internal_oms = true;
    if (!test_helper_set_trusted_certificate(oms)) {
      goto done;
    }
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

  // Loop through all NAL Units one by one.
  const test_stream_item_t *item = list->first_item;
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
    // Move to next NAL Unit.
    item = item->next;
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
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity_and_provenance,
        expected.final_validation->authenticity_and_provenance);
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
    if (auth_report->accumulated_validation.first_timestamp >= 0) {
      ck_assert_int_eq(auth_report->accumulated_validation.first_timestamp, first_ts);
      ck_assert_int_eq(auth_report->accumulated_validation.last_timestamp, last_ts);
    }
    if (!(auth_report->accumulated_validation.authenticity == OMS_NOT_SIGNED ||
            auth_report->accumulated_validation.authenticity ==
                OMS_AUTHENTICITY_NOT_FEASIBLE)) {
      // TODO: Make this ck_assert_int_gt(...) when tests are guranateeed to validate more
      // than one GOP.
      ck_assert_int_ge(auth_report->accumulated_validation.last_timestamp,
          auth_report->accumulated_validation.first_timestamp);
    }
    onvif_media_signing_authenticity_report_free(auth_report);
  }

done:
  if (internal_oms)
    onvif_media_signing_free(oms);
}

/* Test description
 * The public APIs are checked for invalid parameters. */
START_TEST(invalid_api_inputs)
{
  // All test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  MediaSigningCodec codec = settings[_i].codec;
  onvif_media_signing_t *oms = onvif_media_signing_create(codec);
  ck_assert(oms);

  onvif_media_signing_authenticity_t *report =
      onvif_media_signing_get_authenticity_report(NULL);
  ck_assert(!report);

  ck_assert_int_eq(onvif_media_signing_is_sei(NULL, test_nalu, TEST_DATA_SIZE), 0);
  ck_assert_int_eq(onvif_media_signing_is_sei(oms, NULL, TEST_DATA_SIZE), 0);
  ck_assert_int_eq(onvif_media_signing_is_sei(oms, test_nalu, 0), 0);

  MediaSigningReturnCode omsrc =
      onvif_media_signing_set_trusted_certificate(NULL, NULL, 0, false);
  ck_assert_int_eq(omsrc, OMS_INVALID_PARAMETER);
  omsrc =
      onvif_media_signing_set_trusted_certificate(oms, test_data, TEST_DATA_SIZE, true);
  ck_assert_int_eq(omsrc, OMS_NOT_SUPPORTED);
  // Set a trusted certificate. Note that true certificate data has to be set. This helper
  // function reads a certificate and sets it.
  ck_assert(test_helper_set_trusted_certificate(oms));
  // Setting the trusted certificate a second time should fail.
  ck_assert(!test_helper_set_trusted_certificate(oms));

  omsrc = onvif_media_signing_add_nalu_and_authenticate(
      NULL, test_nalu, TEST_DATA_SIZE, NULL);
  ck_assert_int_eq(omsrc, OMS_INVALID_PARAMETER);
  omsrc = onvif_media_signing_add_nalu_and_authenticate(oms, NULL, TEST_DATA_SIZE, NULL);
  ck_assert_int_eq(omsrc, OMS_INVALID_PARAMETER);
  omsrc = onvif_media_signing_add_nalu_and_authenticate(oms, test_nalu, 0, NULL);
  ck_assert_int_eq(omsrc, OMS_INVALID_PARAMETER);

  onvif_media_signing_free(oms);
}
END_TEST

// Standard signed GOPs

/* Test description
 * Verifies that a valid authentication is reported if all NAL Units are added in the
 * correct order. */
START_TEST(intact_stream)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // Client side
  //
  // IPPISPPISPPISPPISPPISPPISP
  //
  // IPPIS                       ...P.                      (valid, 1 pending)
  //    ISPPIS                      ....P.                  (valid, 1 pending)
  //        ISPPIS                      ....P.              (valid, 1 pending)
  //            ISPPIS                      ....P.          (valid, 1 pending)
  //                ISPPIS                      ....P.      (valid, 1 pending)
  //                    ISPPISP                     ....P.  (valid, 1 pending)
  //                                                                6 pending
  //                        ISP                         P.P (valid, 3 pending)
  // NOTE: Currently marking the valid SEI as 'pending'. This makes it easier for the
  // user to know how many NAL Units to mark as 'valid' and render. This is common for all
  // tests.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      26, 23, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 6, .pending_nalus = 6, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_multislice_stream)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPpIiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpPpIiSPpPpIiSPpPpIiSPpPpIiSPp");

  // Client side
  //
  // IiPpPpIiSPpPpIiSPpPpIiSPpPpIiSPp
  //
  // IiPpPpIiS                       ......PP.                     (valid, 2 pending)
  //       IiSPpPpIiS                      ......PP.               (valid, 2 pending)
  //              IiSPpPpIiS                     ......PP.         (valid, 2 pending)
  //                     IiSPpPpIiS                    ......PP.   (valid, 2 pending)
  //                                                                       8 pending
  //                            IiSPp                        PP.PP (valid, 5 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      32, 27, 5, 0, 0};
  const struct validation_stats expected = {
      .valid = 4, .pending_nalus = 8, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_stream_with_splitted_nalus)
{
  // Device side
  test_stream_t *list = create_signed_splitted_nalus("IPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISP");

  // Client side
  //
  // IPPISPPISPPISPPISPPISP
  //
  // IPPIS                       ...P.                      (valid, 1 pending)
  //    ISPPIS                      ....P.                  (valid, 1 pending)
  //        ISPPIS                      ....P.              (valid, 1 pending)
  //            ISPPIS                      ....P.          (valid, 1 pending)
  //                ISPPIS                      ....P.      (valid, 1 pending)
  //                                                                5 pending
  //                    ISP                         P.P     (valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      22, 19, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 5, .pending_nalus = 5, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* PPS, SPS and VPS should be ignored by Media Signing. */
START_TEST(intact_stream_with_pps_nalu_stream)
{
  // Device side
  test_stream_t *list = create_signed_nalus("VIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "VIPPISPPISP");

  // Client side
  //
  // VIPPISPPISP
  //
  // VIPPIS       _...P.          (valid, 1 pending)
  //     ISPPIS       ....P.      (valid, 1 pending)
  //                                      2 pending
  //         ISP          P.P     (valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      11, 8, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_nalu_stream)
{
  // Device side
  test_stream_t *list = create_signed_nalus("VIiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "VIiPpPpIiSPpPpIiSPp");

  // Client side
  //
  // VIiPpPpIiSPpPpIiSPp
  //
  // VIiPpPpIiS            _......PP.              (valid, 2 pending)
  //        IiSPpPpIiS            .......PP.       (valid, 2 pending)
  //                                                       4 pending
  //               IiSPp                 PP.PP     (valid, 5 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      19, 14, 5, 0, 0};
  const struct validation_stats expected = {
      .valid = 2, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that the stream is correctly validated if one undefined NAL Unit is present in
 * the test stream. */
START_TEST(intact_with_undefined_nalu_in_stream)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPXPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPXPISPPISP");

  // Client side
  //
  // IPXPISPPISP
  //
  // IPXPIS       .._.P.          (valid, 1 pending)
  //     ISPPIS       ....P.      (valid, 1 pending)
  //                                      2 pending
  //         ISP          P.P     (valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      11, 8, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_with_undefined_multislice_nalu_in_stream)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IiPpXPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpXPpIiSPpPpIiSPp");

  // Client side
  //
  // IiPpXPpIiSPpPpIiSPp
  //
  // IiPpXPpIiS           ...._..PP.              (valid, 2 pending)
  //        IiSPpPpIiS           .......PP.       (valid, 2 pending)
  //                                                      4 pending
  //               IiSPp                PP.PP     (valid, 5 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      19, 14, 5, 0, 0};
  const struct validation_stats expected = {
      .valid = 2, .pending_nalus = 4, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that ONVIF Media Signing validation is unaffected by other types of SEIs. */
START_TEST(add_non_onvif_sei_after_signing)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  const uint8_t id = 100;
  test_stream_item_t *sei =
      test_stream_item_create_from_type('z', id, settings[_i].codec);

  // Middle 'P' in second non-empty GOP: IPPISP ZP PISPPISP
  const int append_nalu_number = 6;
  test_stream_append_item(list, sei, append_nalu_number);
  test_stream_check_types(list, "IPPISPzPPISPPISP");

  // Client side
  //
  // IPPISPzPPISPPISP
  //
  // IPPIS                 ...P.                 (valid, 1 pending)
  //    ISPzPPIS              ..._..P.           (valid, 1 pending)
  //          ISPPIS                ....P.       (valid, 1 pending)
  //                                                     3 pending
  //              ISP                   P.P      (valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      16, 13, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that validation is successful even if SEIs are delayed by 3 frames. */
START_TEST(all_seis_arrive_late)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const int delay = 3;
  setting.delay = delay;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPPPPIPPPP", setting);
  test_stream_check_types(list, "IPPIPPISPPISPPISPPISPPPSPPIPPPSP");

  // Client side
  //
  // IPPIPPISPPISPPISPPISPPPSPPIPPPSP
  //
  // IPPIPPIS                       ...PPPP.                         (   valid, 4 pending)
  //    IPPISPPIS                      ...P.PPP.                     (   valid, 4 pending)
  //       ISPPISPPIS                     ....P.PPP.                 (   valid, 4 pending)
  //           ISPPISPPIS                     ....P.PPP.             (   valid, 4 pending)
  //               ISPPISPPPS                     ....P.PPP.         (   valid, 4 pending)
  //                   ISPPPSPPIPPPS                  ........PPPP.  (   valid, 4 pending)
  //                                                                           24 pending
  //                           IPPPSP                         PPPP.P (   valid, 6 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      32, 26, 6, 0, 0};
  const struct validation_stats expected = {
      .valid = 6, .pending_nalus = 24, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * This test generates a stream with five SEIs and moves them in time to simulate a
 * signing delay. */
START_TEST(with_blocked_signing)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPP");
  // Manually delay the SEIs.
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

  // Client side
  //
  // IPPISPPIPPIPPIPSPSISPSP
  //
  // IPPIS                     .P                     (valid, 1 pending)
  //    ISPPIPPIPPIPS           ....PPPPPPPP.         (valid, 8 pending)
  //        IPPIPPIPSPS             ...PPPPP.P.       (valid, 6 pending)
  //           IPPIPSPSIS              ...PP.P.P.     (valid, 4 pending)
  //              IPSPSISPS               .....P.P.   (valid, 2 pending)
  //                                                         21 pending
  //                   ISPSP                   P.P.P  (valid, 5 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      23, 18, 5, 0, 0};
  const struct validation_stats expected = {
      .valid = 5, .pending_nalus = 21, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Helper function that creates a stream of NAL Units and exports the end part by pop-ing
 * the first GOP.
 *
 * As an additional piece, the stream starts with a PPS/SPS/VPS NAL Unit, which is moved
 * to the beginning of the "file" as well. That should not affect the validation. */
static test_stream_t *
mimic_file_export(struct oms_setting setting)
{
  test_stream_t *pre_export = NULL;
  test_stream_t *list =
      create_signed_nalus("VIPPIPPPPPIPPIPPPPPPPPPIPPPPPIPIPP", setting);
  if (setting.signing_frequency == 3) {
    // Only works for hard coded signing frequency.
    test_stream_check_types(list, "VIPPIsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP");
  } else if (setting.max_signing_nalus == 4) {
    // Only works for hard coded max signing nalus.
    test_stream_check_types(list, "VIPPISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP");
  } else {
    test_stream_check_types(list, "VIPPISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP");
  }

  // Remove the initial PPS/SPS/VPS NAL Unit to add back later.
  test_stream_item_t *ps = test_stream_pop_first_item(list);
  test_stream_item_check_type(ps, 'V');

  // Remove the first GOP from the list.
  pre_export = test_stream_pop(list, 3);
  test_stream_check_types(pre_export, "IPP");

  // Prepend list with PPS/SPS/VPS NAL Unit.
  test_stream_prepend_first_item(list, ps);
  if (setting.signing_frequency == 3) {
    test_stream_check_types(list, "VIsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP");
  } else if (setting.max_signing_nalus == 4) {
    test_stream_check_types(list, "VISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP");
  } else {
    test_stream_check_types(list, "VISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP");
  }

  test_stream_free(pre_export);

  return list;
}

/* The file_export_and_scrubbing tests generate a file export test stream then
 * 1) validates the full test stream
 * 2) scrubs back to the beginning
 * 3) resets and validates the entire file again
 * 4) scrubs back to the beginning
 * 5) resets and validates the first two GOPs
 * 6) scrubs forward one GOP
 * 7) resets and validates remaining GOPs */
START_TEST(file_export_and_scrubbing)
{
  // Device side
  test_stream_t *list = mimic_file_export(settings[_i]);

  // Client side
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(test_helper_set_trusted_certificate(oms));

  // VISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP
  //
  // VIS                    _P.                                      (signed, 1 pending)
  //  ISPPPPPIS              .......P.                               ( valid, 1 pending)
  //         ISPPIS                 ....P.                           ( valid, 1 pending)
  //             ISPPPPPPPPPIS          ...........P.                ( valid, 1 pending)
  //                        ISPPPPPIS              .......P.         ( valid, 1 pending)
  //                               ISPIS                  ...P.      ( valid, 1 pending)
  //                                                                          6 pending
  //                                  ISPP                   P.PP    ( valid, 4 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      37, 33, 4, 0, 0};
  struct validation_stats expected = {.valid = 5,
      .has_sei = 1,
      .pending_nalus = 6,
      .final_validation = &final_validation};
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  // 2) Scrub to the beginning and remove the parameter set NAL Unit at the beginning.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  test_stream_item_free(item);
  // ISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP
  final_validation.number_of_received_nalus--;
  final_validation.number_of_validated_nalus--;
  // The first report of stream being signed is now skipped, since it is already known.
  expected.pending_nalus--;
  expected.has_sei--;
  // 3) Reset and validate file again.
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  validate_test_stream(oms, list, expected, settings[_i].ec_key);
  // 4) Scrub to the beginning.
  // Get the first two GOPs.
  test_stream_t *first_list = test_stream_pop_gops(list, 2);
  // ISPPPPPISPP
  final_validation.number_of_received_nalus = 11;
  final_validation.number_of_validated_nalus = 7;
  final_validation.number_of_pending_nalus = 4;
  expected.valid = 1;
  expected.pending_nalus = 1;
  // 5) Reset and validate the first two GOPs.
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  validate_test_stream(oms, first_list, expected, settings[_i].ec_key);
  test_stream_free(first_list);
  // 6) Scrub forward one GOP.
  test_stream_t *scrubbed_list = test_stream_pop_gops(list, 1);
  test_stream_free(scrubbed_list);
  // ISPPPPPISPISPP
  final_validation.number_of_received_nalus = 14;
  final_validation.number_of_validated_nalus = 10;
  final_validation.number_of_pending_nalus = 4;
  expected.valid = 2;
  expected.pending_nalus = 2;
  // 7) Reset and validate the rest of the file.
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  test_stream_free(list);
  onvif_media_signing_free(oms);
}
END_TEST

/* Test description
 * Generates a certificate SEI and puts it as a first NAL Unit and verifies the stream. */
START_TEST(certificate_sei_first)
{
  // Device side
  struct oms_setting setting = settings[_i];
  setting.with_certificate_sei = true;
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPPIP", setting);
  test_stream_check_types(list, "CIPPISPPPISPPPISP");

  // Client side
  //
  // CIPPISPPPISPPPISP
  //
  // C                  .                   (valid, 0 pending)
  //  IPPIS              ...P.              (valid, 1 pending)
  //     ISPPPIS            .....P.         (valid, 1 pending)
  //          ISPPPIS            .....P.    (valid, 1 pending)
  //                                                3 pending
  //               ISP                P.P   (valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      17, 14, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 4, .pending_nalus = 3, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Generates a certificate SEI and adds it later and verifies the stream. */
START_TEST(certificate_sei_later)
{
  // Device side
  struct oms_setting setting = settings[_i];
  setting.with_certificate_sei = true;
  setting.delay = 1;
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPPIPP", setting);
  test_stream_check_types(list, "ICPPIPSPPIPSPPIPSP");

  // Client side
  //
  // ICPPIPSPPIPSPPIPSP
  //
  // IC                 P.                  (valid, 1 pending)
  // ICPPIPS            ....PP.             (valid, 2 pending)
  //     IPSPPIPS           .....PP.        (valid, 2 pending)
  //          IPSPPIPS           .....PP.   (valid, 2 pending)
  //                                                7 pending
  //               IPSP               PP.P  (valid, 4 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      18, 14, 4, 0, 0};
  const struct validation_stats expected = {
      .valid = 4, .pending_nalus = 7, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(no_trusted_certificate_added)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // Client side
  onvif_media_signing_t *oms = onvif_media_signing_create(list->codec);

  // See "intact_stream" for a description.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_NOT_OK, false,
      OMS_AUTHENTICITY_OK, 26, 23, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 6, .pending_nalus = 6, .final_validation = &final_validation};
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  onvif_media_signing_free(oms);
  test_stream_free(list);
}
END_TEST

// Tampering cases

/* Test description
 * Verifies that invalid authentication is reported if two P-frames are interchanged. */
START_TEST(interchange_two_p_frames)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Interchange the second and third 'P in second GOP: IPPISP P P ISPPISP
  const int nalu_number = 7;
  test_stream_item_t *item = test_stream_item_remove(list, nalu_number);
  test_stream_item_check_type(item, 'P');

  // Inject the item again, but at position nalu_number + 1, that is, append the list item
  // at position nalu_number.
  test_stream_append_item(list, item, nalu_number);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Client side
  //
  // IPPISPPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPPIS                     ...M.NP.         (invalid, 1 pending)
  //    ISPPPIS                     N.N NNP.                           [low bitrate mode]
  //         ISPPIS                       ....P.     (  valid, 1 pending)
  //                                                           3 pending
  //             ISP                          P.P    (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 15, 12, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .invalid = 1,
      .pending_nalus = 3,
      .missed_nalus = 0,  // A missing item is displayed 'M', but not counted since the
      // number of received NAL Units match the number of sent NAL Units.
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that when manipulating a NAL Unit, the authentication becomes invalid. This is
 * done for both 'P' and 'I' (in separate tests), by changing the id byte. And for SEI by
 * changing the signature. */
START_TEST(modify_one_p_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Modify second 'P' in first GOP: IP P ISPPPISPPISP
  const int modify_nalu_number = 3;
  modify_list_item(list, modify_nalu_number, 'P');

  // Client side
  //
  // IPPISPPPISPPISP
  //
  // IPPIS                       ..NP.               (invalid, 1 pending)
  // IPPIS                       NNNP.                                 [low bitrate mode]
  //    ISPPPIS                     .....P.          (  valid, 1 pending)
  //         ISPPIS                      ....P.      (  valid, 1 pending)
  //                                                           3 pending
  //             ISP                         P.P     (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 15, 12, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .invalid = 1,
      .pending_nalus = 3,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that invalid authentication is produced if one 'P' is removed. */
START_TEST(remove_one_p_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Remove the middle 'P' in second GOP: IPPISP P PISPPISP
  const int remove_nalu_number = 7;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPISPPISPPISP");

  // Client side
  //
  // IPPISPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPIS                      ...M.P.          (missing, 1 pending, 1 missing)
  //        ISPPIS                       ....P.      (  valid, 1 pending)
  //                                                           3 pending
  //            ISP                          P.P     (missing, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_OK_WITH_MISSING_INFO, 14, 11, 3, 0, 0};
  struct validation_stats expected = {.valid = 2,
      .valid_with_missing_info = 1,
      .missed_nalus = 1,
      .pending_nalus = 3,
      .final_validation = &final_validation};
  if (settings[_i].low_bitrate_mode) {
    // In low bitrate mode it is not possible to identify individual missing frames.
    // IPPISPPISPPISP
    //
    // IPPIS                       ...P.              (  valid, 1 pending)
    //    ISPPIS                      ....MP.         (invalid, 1 pending, 1 missing)
    //        ISPPIS                       ....P.     (  valid, 1 pending)
    //                                                          3 pending
    //            ISP                          P.P    (invalid, 3 pending)
    expected.invalid = 1;
    expected.valid_with_missing_info = 0,
    expected.final_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
    expected.final_validation->authenticity_and_provenance =
        OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK;
  }
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(add_one_p_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISP");

  // Add a middle 'P' in second GOP: IPPISP P PISPPISP
  test_stream_item_t *p = test_stream_item_create_from_type('P', 100, settings[_i].codec);
  const int append_nalu_number = 6;
  test_stream_append_item(list, p, append_nalu_number);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Client side
  //
  // IPPISPPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPPIS                     ...N.P.          (invalid, 1 pending, -1 missing)
  //    ISPPPIS                     N.NNNP.                            [low bitrate mode]
  //         ISPPIS                      ....P.      (  valid, 1 pending)
  //                                                           3 pending
  //             ISP                         P.P     (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 15, 12, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .invalid = 1,
      .missed_nalus = -1,  // One frame added
      .pending_nalus = 3,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISP");

  // Modify second 'I': IPP I SPPPISPPISPPISP
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, 'I');

  // Client side
  //
  // IPPISPPPISPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPPIS                     N.NNNP.          (invalid, 1 pending)
  //         ISPPIS                      N.NNP.      (invalid, 1 pending, wrong link)
  //             ISPPIS                      ....P.  (  valid, 1 pending)
  //                                                           4 pending
  //                 ISP                         P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 19, 16, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_i_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISPISP");

  // Remove the third 'I': IPPISPPP I SPPISPPISPISP.
  const int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "IPPISPPPSPPISPPISPISP");

  // Client side
  //
  // IPPISPPPSPPISPPISPISP
  //
  // IPPIS                   ...P.                  (  valid, 1 pending)
  //    ISPPPS                  ......              (  valid, 0 pending)
  //          PPIS                    NNMP.         (invalid, 1 pending, 1 missing)
  //            ISPPIS                   N.NNP.     (invalid, 1 pending, wrong link)
  //                ISPIS                    ...P.  (  valid, 1 pending)
  //                                                          4 pending
  //                   ISP                      P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 21, 18, 3, 0, 0};
  const struct validation_stats expected = {.valid = 3,
      .invalid = 2,
      .pending_nalus = 4,
      .missed_nalus = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_sei_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISP");

  // Modify second 'S': IPPISPPPI S PPISPPISP
  const int modify_nalu_number = 10;
  test_stream_item_t *sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 'S');
  // Modify the signature by flipping the bits in one byte. Count 50 bytes from the end of
  // the SEI, which works for both EC and RSA keys.
  sei->data[sei->data_size - 50] = ~sei->data[sei->data_size - 50];

  // Client side
  //
  // IPPISPPPISPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPPIS                     N.NNNPN          (invalid, 1 pending)
  //         ISPPIS                      .N..P.      (  valid, 1 pending)
  //             ISPPIS                      ....P.  (  valid, 1 pending)
  //                                                           4 pending
  //                 ISP                         P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 19, 16, 3, 0, 0};
  const struct validation_stats expected = {.valid = 3,
      .invalid = 1,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that invalid authentication is reported if one SEI is removed. */
START_TEST(remove_one_sei_frame)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISPISP");

  // Remove the second SEI: IPPISPPPI S PPISPPISPISP.
  const int remove_nalu_number = 10;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPISPPPIPPISPPISPISP");

  // Client side
  //
  // IPPISPPPIPPISPPISPISP
  //
  // IPPIS                   ...P.                  (  valid, 1 pending)
  //    ISPPPIPPIS              N.NNN...P.          (invalid, 1 pending)
  //            ISPPIS                   ....P.     (  valid, 1 pending)
  //                ISPIS                    ...P.  (  valid, 1 pending)
  //                                                          4 pending
  //                   ISP                      P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 21, 18, 3, 0, 0};
  const struct validation_stats expected = {.valid = 3,
      .invalid = 1,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies that interchanging two SEIs gives an invalid authentication. */
START_TEST(interchange_two_seis)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISP");

  // Interchange the second and third 'S': IPPISPPPI S PPI S PPISP
  const int second_sei = 10;
  const int third_sei = 14;
  test_stream_item_t *sei = test_stream_item_remove(list, third_sei);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, second_sei);
  test_stream_check_types(list, "IPPISPPPISSPPIPPISP");
  sei = test_stream_item_remove(list, second_sei);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, third_sei - 1);
  test_stream_check_types(list, "IPPISPPPISPPISPPISP");

  // Client side
  //
  // IPPISPPPISPPISPPISP
  //
  // IPPIS                       ...P.               (  valid, 1 pending)
  //    ISPPPIS                     N.NNNP.          (invalid, 1 pending)
  //         ISPPIS                      N.NNP.      (invalid, 1 pending)
  //             ISPPIS                      ....P.  (  valid, 1 pending)
  //                                                           4 pending
  //             ISP                          P.P    (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 19, 16, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_both_i_and_sei)
{
  // Device side
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISPISP");

  // Remove the third 'I': IPPISPPP I SPPISPPISPISP.
  const int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "IPPISPPPSPPISPPISPISP");

  // Remove the second 'S': IPPISPPP S PPISPPISPISP.
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPISPPPPPISPPISPISP");

  // Client side
  //
  // IPPISPPPPPISPPISPISP
  //
  // IPPIS                   ...P.                (  valid, 1 pending)
  //    ISPPPPPIS               N.NNNNNP.         (invalid, 1 pending)
  //           ISPPIS                  N.NNP.     (invalid, 1 pending, wrong link)
  //               ISPIS                   ...P.  (  valid, 1 pending)
  //                                                        4 pending
  //                  ISP                     P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 20, 17, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .invalid = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

#if 0
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

START_TEST(late_seis_and_first_gop_scrapped)
{
  // Device side
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

  // Client side
  //
  // ISPPPIPSPPIPSPPIPSS
  //
  // IS                  ->    (signature) -> PU             1 pending
  // ISPPPIPS            ->    (signature) -> PUPPPPPU       6 pending
  // ISPPPIPSPPIPS       ->        (valid) -> .U...PPUPPPP.  6 pending
  //      IPSPPIPSPPIPS  ->        (valid) -> ..U..PP.PPPP.  6 pending
  //           IPSPPIPSS ->        (valid) -> .....PP..      2 pending
  //                                                        21 pending
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK, 19, 15, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid = 3,
      .has_sei = 2,
      .pending_nalus = 21,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

/* Test description
 */
START_TEST(detect_change_of_public_key)
{
  // Device side
  // Generate 2 GOPs
  test_stream_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPP");

  // Generate another GOP from scratch
  // This will generate a new private key, hence transmit a different public key.
  test_stream_t *list_with_new_public_key = create_signed_nalus_int("IPPPI", settings[_i], true);
  test_stream_check_types(list_with_new_public_key, "SIPPPSI");

  test_stream_append(list, list_with_new_public_key);
  test_stream_check_types(list, "SIPPSIPPSIPPPSI");

  // Client side
  //
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

  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

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

  // Client side
  //
  // Final validation of |pre_fast_forward| is OK and all received NAL Units, but the last two, are
  // validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK, 9, 7, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |oms|.
  //
  // SI      -> .P          (valid)
  // IPPPPSI ->  .....P     (valid)
  //
  // Total number of pending NAL Units = 1 + 1 = 2
  const struct validation_stats expected = {
      .valid = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_test_stream(oms, pre_fast_forward, expected, settings[_i].ec_key);
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
  // Device side
  onvif_media_signing_t *oms = onvif_media_signing_create(settings[_i].codec);
  ck_assert(oms);
  ck_assert_int_eq(signed_video_set_authenticity_level(oms, settings[_i].auth_level), OMS_OK);
  test_stream_t *list = mimic_au_fast_forward_and_get_list(oms, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(oms), OMS_OK);

  // Client side
  //
  // Final validation is OK and all received NAL Units, but the last one, are validated.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK, 12, 11, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate SIPPPSIPPPSI:
  //
  // SI      -> UP           (OMS_AUTHENTICITY_NOT_FEASIBLE)
  // SIPPPSI -> U.....P      (valid)
  // IPPPSI  ->       .....P (valid)
  //
  // Total number of pending NAL Units = 1 + 1 + 1 = 3
  const const struct validation_stats expected = {.valid = 2,
      .pending_nalus = 3,
      .has_sei = 1,
      .final_validation = &final_validation};

  validate_test_stream(oms, list, expected, settings[_i].ec_key);
  // Free list and session.
  onvif_media_signing_free(oms);
  test_stream_free(list);
}
END_TEST
#endif

// Signed multiple GOPs

/* Test description
 * Verifies intact and tampered streams when the device signs multiple GOPs. */
START_TEST(sign_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;  // Sign every third GOP.
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     (signed, 5 pending)
  // IPPIsPPIsPPIS     ...........P.             ( valid, 1 pending)
  //            ISPPIsPPIsPPIS    ...........P.  ( valid, 1 pending)
  //                                                      7 pending
  //                        ISP              P.P ( valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      26, 23, 3, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .pending_nalus = 7,
      .has_sei = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  const int delay = 3;
  setting.delay = delay;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIPPPP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPIPPISsPPIsPPIPPPSP");

  // Client side
  //
  // IPPIsPPIsPPIPPISsPPIsPPIPPPSP
  //
  // IPPIs                         PPPPP                          (signed, 5 pending)
  // IPPIsPPIsPPIPPIS              ...........PPPP.               ( valid, 4 pending)
  //            IPPISsPPIsPPIPPPS             ............PPPP.   ( valid, 4 pending)
  //                                                                      13 pending
  //                        IPPPSP                        PPPP.P  ( valid, 6 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      29, 23, 6, 0, 0};
  const struct validation_stats expected = {.valid = 2,
      .pending_nalus = 13,
      .has_sei = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(file_export_and_scrubbing_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = mimic_file_export(setting);

  // Client side
  onvif_media_signing_t *oms = onvif_media_signing_create(setting.codec);
  ck_assert(test_helper_set_trusted_certificate(oms));

  // VIsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP
  //
  // VIs                        _PP                                   (signed, 2 pending)
  //  IsPPPPPIsPPIS              ...........P.                        ( valid, 1 pending)
  //             ISPPPPPPPPPIsPPPPPIsPIS    .....................P.   ( valid, 1 pending)
  //                                                                           4 pending
  //                                  ISPP                       P.PP ( valid, 4 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      37, 33, 4, 0, 0};
  struct validation_stats expected = {.valid = 2,
      .has_sei = 1,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  // 2) Scrub to the beginning and remove the parameter set NAL Unit at the beginning.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  test_stream_item_free(item);
  // IsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP
  final_validation.number_of_received_nalus--;
  final_validation.number_of_validated_nalus--;
  expected.pending_nalus = 2;  // No report on the first unsigned SEI.
  expected.has_sei = 0;
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  // 3) Validate after reset.
  validate_test_stream(oms, list, expected, settings[_i].ec_key);
  // 4) Scrub to the beginning.
  // Get the first two GOPs.
  test_stream_t *first_list = test_stream_pop_gops(list, 2);
  // IsPPPPPIsPP
  // No report triggered.
  onvif_media_signing_accumulated_validation_t tmp_final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE, OMS_PROVENANCE_NOT_FEASIBLE, false,
      OMS_AUTHENTICITY_NOT_FEASIBLE, 11, 0, 11, -1, -1};
  expected.final_validation = &tmp_final_validation;
  expected.valid = 0;
  expected.pending_nalus = 0;  // No report triggered.
  expected.has_sei = 0;
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  // 5) Reset and validate the first two GOPs.
  validate_test_stream(oms, first_list, expected, settings[_i].ec_key);
  test_stream_free(first_list);
  // 6) Scrub forward one GOP.
  test_stream_t *scrubbed_list = test_stream_pop_gops(list, 1);
  test_stream_free(scrubbed_list);
  // IsPPPPPIsPISPP
  expected.final_validation = &final_validation;
  final_validation.number_of_received_nalus = 14;
  final_validation.number_of_validated_nalus = 10;
  final_validation.number_of_pending_nalus = 4;
  expected.valid = 1;
  expected.pending_nalus = 1;  // No report on the first unsigned SEI.
  expected.has_sei = 0;
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  // 7) Reset and validate the rest of the file.
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  test_stream_free(list);
  onvif_media_signing_free(oms);
}
END_TEST

START_TEST(modify_one_p_frame_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Modify second 'P' in second GOP: IPPIsP P IsPPISPPIsPPIsPPISP
  const int modify_nalu_number = 7;
  modify_list_item(list, modify_nalu_number, 'P');

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPPIsPPIS     ......N....P.             (invalid, 1 pending)
  // IPPIsPPIsPPIS     NNNNNNN....P.                                 [low bitrate mode]
  //            ISPPIsPPIsPPIS    ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                        ISP              P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 26, 23, 3, 0, 0};
  const struct validation_stats expected = {.valid = 1,
      .invalid = 1,
      .has_sei = 1,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_p_frame_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Remove second 'P' in second GOP: IPPIsP P IsPPISPPIsPPIsPPISP
  const int remove_nalu_number = 7;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPIsPIsPPISPPIsPPIsPPISP");

  // Client side
  //
  // IPPIsPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPIsPPIS      ......M....P.             (missing, 1 pending, 1 missing)
  //           ISPPIsPPIsPPIS     ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                       ISP               P.P (missing, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_OK_WITH_MISSING_INFO, 25, 22, 3, 0, 0};
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
    //                       ISP               P.P (invalid, 3 pending)
    expected.invalid = 1;
    expected.valid_with_missing_info = 0,
    expected.final_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
    expected.final_validation->authenticity_and_provenance =
        OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK;
  }
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(add_one_p_frame_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Add a middle 'P' in second GOP: IPPIsP P PIsPPISPPIsPPIsPPISP
  test_stream_item_t *p = test_stream_item_create_from_type('P', 100, settings[_i].codec);
  const int append_nalu_number = 6;
  test_stream_append_item(list, p, append_nalu_number);
  test_stream_check_types(list, "IPPIsPPPIsPPISPPIsPPIsPPISP");

  // Client side
  //
  // IPPIsPPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                      ( signed, 5 pending)
  // IPPIsPPPIsPPIS    ......N.....P.             (invalid, 1 pending, -1 missing)
  // IPPIsPPPIsPPIS    NNNNNNNN....P.                                 [low bitrate mode]
  //             ISPPIsPPIsPPIS    ...........P.  (  valid, 1 pending)
  //                                                        7 pending
  //                         ISP              P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 27, 24, 3, 0, 0};
  const struct validation_stats expected = {.valid = 1,
      .invalid = 1,
      .has_sei = 1,
      .missed_nalus = -1,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_frame_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Modify second 'I' in second GOP: IPP I sPPIsPPISPPIsPPIsPPISP
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, 'I');

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPPIsPPIS     NNNNNNNNNNNP.             (invalid, 1 pending, wrong link)
  //            ISPPIsPPIsPPIS    ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                        ISP              P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 26, 23, 3, 0, 0};
  const struct validation_stats expected = {.valid = 1,
      .invalid = 1,
      .has_sei = 1,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_i_frame_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIIIIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISIsIsISP");

  // Remove third 'I': IPPIsPP I sPPISPPIsPPIsPPISP
  const int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "IPPIsPPsPPISPPIsPPIsPPISIsIsISP");

  // Client side
  //
  // IPPIsPPsPPISPPIsPPIsPPISIsIsISP
  //
  // IPPIs             PPPPP                            ( signed, 5 pending)
  // IPPIsPPsPPIS      .......M.NNP.                    (invalid, 1 pending, 1 missing)
  // IPPIsPPsPPIS      NNNNNNNNNNMP.                                   [low bitrate mode]
  //           ISPPIsPPIsPPIS      N.NN.......P.        (invalid, 1 pending, wrong link)
  //                       ISIsIsIS           ......P.  (  valid, 1 pending)
  //                                                              8 pending
  //                             ISP                P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 31, 28, 3, 0, 0};
  const struct validation_stats expected = {.valid = 1,
      .invalid = 2,
      .has_sei = 1,
      .pending_nalus = 8,
      .missed_nalus = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_sei_frames_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Modify first 'S': IPPIsPPIsPPI S PPIsPPIsPPISP
  int modify_nalu_number = 13;
  test_stream_item_t *sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 'S');
  // Modify the signature by flipping the bits in one byte. Count 50 bytes from the end of
  // the SEI, which works for both EC and RSA keys.
  sei->data[sei->data_size - 50] = ~sei->data[sei->data_size - 50];
  // Modify third 's': IPPIsPPIsPPISPPI s PPIsPPISP
  modify_nalu_number = 17;
  sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 's');
  // Modify the reserved byte by setting a bit that is currently not yet used.
  nalu_info_t nalu_info =
      parse_nalu_info(sei->data, sei->data_size, list->codec, false, true);
  uint8_t *reserved_byte = (uint8_t *)&nalu_info.payload[16];
  *reserved_byte |= 0x02;

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPPIsPPIS     NNNNNNNNNNNPN             (invalid, 1 pending)
  //            ISPPIsPPIsPPIS    NNNN.N.....P.  (invalid, 1 pending)
  //                                                       7 pending
  //                        ISP              P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 26, 23, 3, 0, 0};
  const struct validation_stats expected = {.valid = 0,
      .invalid = 2,
      .has_sei = 1,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  free(nalu_info.nalu_wo_epb);
  test_stream_free(list);
}
END_TEST

START_TEST(remove_sei_frames_multiple_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIIIIIIIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISIsIsISIsIsISP");

  // Remove third and eighth 'S' and 's': IPPIsPPIsPPI S PPIsPPIsPPISIsI s ISIsIsISP
  int remove_nalu_number = 29;
  remove_item_then_check_and_free(list, remove_nalu_number, 's');
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISIsIISIsIsISP");
  remove_nalu_number = 13;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPIsPPIsPPIPPIsPPIsPPISIsIISIsIsISP");

  // Client side
  //
  // IPPIsPPIsPPIPPIsPPIsPPISIsIISIsIsISP
  //
  // IPPIs                       PPPPP                              ( signed, 5 pending)
  // IPPIsPPIsPPIPPIsPPIsPPIS    NNNNNNNNNNN........P.              (invalid, 1 pending)
  //                       ISIsIIS                  N.NN.MP.        (invalid, 1 p, 1 miss)
  //                            ISIsIsIS                  ......P.  (  valid, 1 pending)
  //                                                                          8 pending
  //                                  ISP                       P.P (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 36, 33, 3, 0, 0};
  const struct validation_stats expected = {.valid = 1,
      .invalid = 2,
      .has_sei = 1,
      .pending_nalus = 8,
      .missed_nalus = 0,  // Since the missing is part of an invalid report it is not
      // reported. The reason is that it is not known if there are any missing NAL Units
      // among the invalid ones as well.
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

// Signed partial GOPs

/* Test description
 * Verifies intact and tampered streams when the device signs partial GOPs. */
START_TEST(sign_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;  // Trigger signing after reaching 4 NAL Units.
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPPPPSPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPPSPPPPSPISP
  //
  // IPPPPS                 ....P.                       (valid, 1 pending)
  //     PSPIS                  ...P.                    (valid, 1 pending)
  //        ISPPIS                 ....P.                (valid, 1 pending)
  //            ISPPPPS                .....P.           (valid, 1 pending)
  //                 PSPPPPS                .....P.      (valid, 1 pending)
  //                      PSPIS                  ...P.   (valid, 1 pending)
  //                                                             6 pending
  //                         ISP                    P.P  (valid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      27, 24, 3, 0, 0};
  const struct validation_stats expected = {
      .valid = 6, .pending_nalus = 6, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  const int delay = 3;
  setting.delay = delay;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPPPPPIPPPPP", setting);
  test_stream_check_types(list, "IPPPPPIPSPIPSPPPSPPPSPPIPSPPPSP");

  // Client side
  //
  // IPPPPPIPSPIPSPPPSPPPSPPIPSPPPSP
  //
  // IPPPPPIPS                   ....PPPP.                           (valid, 4 pending)
  //     PPIPSPIPS                   ..PP.PPP.                       (valid, 5 pending)
  //       IPSPIPSPPPS                 ....PP.PPP.                   (valid, 5 pending)
  //           IPSPPPSPPPS                 .....P.PPP.               (valid, 4 pending)
  //                PSPPPSPPIPS                 ......PPPP.          (valid, 4 pending)
  //                      PPIPSPPPS                   ..PP.PPP.      (valid, 5 pending)
  //                                                                        27 pending
  //                        IPSPPPSP                    PP.PPP.P     (valid, 8 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      31, 23, 8, 0, 0};
  const struct validation_stats expected = {
      .valid = 6, .pending_nalus = 27, .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(file_export_and_scrubbing_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = mimic_file_export(setting);

  // Client side
  onvif_media_signing_t *oms = onvif_media_signing_create(setting.codec);
  ck_assert(test_helper_set_trusted_certificate(oms));

  // VISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP
  //
  // VIS                    _P.                                       (signed, 1 pending)
  //  ISPPPPS                .....P.                                  ( valid, 1 pending)
  //       PSPIS                  ...P.                               ( valid, 1 pending)
  //          ISPPIS                 ....P.                           ( valid, 1 pending)
  //              ISPPPPS                .....P.                      ( valid, 1 pending)
  //                   PSPPPPS                .....P.                 ( valid, 1 pending)
  //                        PSPIS                  ...P.              ( valid, 1 pending)
  //                           ISPPPPS                .....P.         ( valid, 1 pending)
  //                                PSPIS                  ...P.      ( valid, 1 pending)
  //                                   ISPIS                  ...P.   ( valid, 1 pending)
  //                                                                          10 pending
  //                                      ISPP                   P.PP ( valid, 4 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK, OMS_PROVENANCE_OK, false, OMS_AUTHENTICITY_OK,
      41, 37, 4, 0, 0};
  struct validation_stats expected = {.valid = 9,
      .has_sei = 1,
      .pending_nalus = 10,
      .final_validation = &final_validation};
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  // 2) Scrub to the beginning and remove the parameter set NAL Unit at the beginning.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  test_stream_item_free(item);
  // ISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP
  final_validation.number_of_received_nalus--;
  final_validation.number_of_validated_nalus--;
  // The first report of stream being signed is now skipped, since it is already known.
  expected.pending_nalus--;
  expected.has_sei--;
  // 3) Validate after reset.
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  validate_test_stream(oms, list, expected, settings[_i].ec_key);
  // 4) Scrub to the beginning.
  // Get the first two GOPs.
  test_stream_t *first_list = test_stream_pop_gops(list, 2);
  // ISPPPPSPISPP
  // No report triggered.
  final_validation.number_of_received_nalus = 12;
  final_validation.number_of_validated_nalus = 8;
  expected.valid = 2;
  expected.pending_nalus = 2;
  // 5) Reset and validate the first two GOPs.
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  validate_test_stream(oms, first_list, expected, settings[_i].ec_key);
  test_stream_free(first_list);
  // 6) Scrub forward one GOP.
  test_stream_t *scrubbed_list = test_stream_pop_gops(list, 1);
  test_stream_free(scrubbed_list);
  // ISPPPPSPISPISPP
  final_validation.number_of_received_nalus = 15;
  final_validation.number_of_validated_nalus = 11;
  expected.valid = 3;
  expected.pending_nalus = 3;
  // 7) Reset and validate the rest of the file.
  ck_assert_int_eq(onvif_media_signing_reset(oms), OMS_OK);
  validate_test_stream(oms, list, expected, settings[_i].ec_key);

  test_stream_free(list);
  onvif_media_signing_free(oms);
}
END_TEST

START_TEST(modify_one_p_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Modify second 'P' in third GOP: IPPPPSPISPPISP P PPSPISP
  const int modify_nalu_number = 15;
  modify_list_item(list, modify_nalu_number, 'P');

  // Client side
  //
  // IPPPPSPISPPISPPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPPS                ...N.P.      (invalid, 1 pending)
  //            ISPPPPS                N.NNNP.                         [low bitrate mode]
  //                 PSPIS                  ...P.   (  valid, 1 pending)
  //                                                          5 pending
  //                    ISP                   P.P   (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 22, 19, 3, 0, 0};
  const struct validation_stats expected = {.valid = 4,
      .invalid = 1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_p_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Remove second 'P' in third GOP: IPPPPSPISPPISP P PPSPISP
  const int remove_nalu_number = 15;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPPPSPISPPISPPPSPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPS                ...M.P.       (missing, 1 pending, 1 missing)
  //                PSPIS                  ...P.    (  valid, 1 pending)
  //                                                          5 pending
  //                   ISP                    P.P   (missing, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_OK_WITH_MISSING_INFO, 21, 18, 3, 0, 0};
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
    //                   ISP                    P.P   (invalid, 2 pending)
    expected.valid = 3;
    expected.invalid = 2;
    expected.pending_nalus = 4;
    expected.valid_with_missing_info = 0,
    expected.final_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
    expected.final_validation->authenticity_and_provenance =
        OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK;
  }
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(add_one_p_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Add a middle 'P' in third GOP: IPPPPSPISPPISP P PPPSPISP
  test_stream_item_t *p = test_stream_item_create_from_type('P', 100, settings[_i].codec);
  const int append_nalu_number = 14;
  test_stream_append_item(list, p, append_nalu_number);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPPSPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPPPS               ...N..P.     (invalid, 1 pending, -1 missing)
  //                  PSPIS                  ...P.  (  valid, 1 pending)
  //                                                          5 pending
  //                   ISP                    P.P   (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 23, 20, 3, 0, 0};
  struct validation_stats expected = {.valid = 4,
      .invalid = 1,
      .missed_nalus = -1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  if (settings[_i].low_bitrate_mode) {
    // IPPPPSPISPPISPPPPPSPISP
    //
    // IPPPPS                 ....P.                  (  valid, 1 pending)
    //     PSPIS                  ...P.               (  valid, 1 pending)
    //        ISPPIS                 ....P.           (  valid, 1 pending)
    //            ISPPPPPS               N.NNNPP.     (invalid, 2 pending)
    //                 PPSPIS                 NN.NP.  (invalid, 1 pending, -1 missing)
    //                                                          6 pending
    //                   ISP                    P.P   (invalid, 3 pending)
    expected.valid = 3;
    expected.invalid = 2;
    expected.pending_nalus = 6;
  }
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Modify third 'I': IPPPPSPISPP I SPPPPSPISPPISPISP
  const int modify_nalu_number = 12;
  modify_list_item(list, modify_nalu_number, 'I');

  // Client side
  //
  // IPPPPSPISPPISPPPPSPISPPISPISP
  //
  // IPPPPS                 ....P.                        (  valid, 1 pending)
  //     PSPIS                  ...P.                     (  valid, 1 pending)
  //        ISPPIS                 ....P.                 (  valid, 1 pending)
  //            ISPPPPS                N.NNNP.            (invalid, 1 pending)
  //                 PSPIS                  N.NP.         (invalid, 1 pending)
  //                    ISPPIS                 N.NNP.     (invalid, 1 pending, wrong link)
  //                        ISPIS                 ...P.   (  valid, 1 pending)
  //                                                                7 pending
  //                           ISP                   P.P  (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 29, 26, 3, 0, 0};
  const struct validation_stats expected = {.valid = 4,
      .invalid = 3,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_i_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Remove third 'I': IPPPPSPISPP I SPPPPSPISPPISPISP
  const int remove_nalu_number = 12;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "IPPPPSPISPPSPPPPSPISPPISPISP");

  // Client side
  //
  // IPPPPSPISPPSPPPPSPISPPISPISP
  //
  // IPPPPS     ....P.                         (  valid, 1 pending)
  //     PSPIS      ...P.                      (  valid, 1 pending)
  //        ISPPS      .....                   (  valid, 0 pending)
  //             PPPPS      NNNN.              (invalid, 0 pending)
  //                  PIS        NMP.          (invalid, 1 pending, 1 missing, wrong link)
  //                   ISPPIS      N.NNP.      (invalid, 1 pending, wrong link)
  //                       ISPIS       ...P.   (  valid, 1 pending)
  //                                                     5 pending
  //                          ISP         P.P  (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 28, 25, 3, 0, 0};
  const struct validation_stats expected = {.valid = 4,
      .invalid = 3,
      .pending_nalus = 5,
      .missed_nalus = 1,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_sei_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Modify fourth 'S': IPPPPSPISPPISPPPP S PISPPISPISP
  const int modify_nalu_number = 18;
  test_stream_item_t *sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 'S');
  // Modify the signature by flipping the bits in one byte. Count 50 bytes from the end of
  // the SEI, which works for both EC and RSA keys.
  sei->data[sei->data_size - 50] = ~sei->data[sei->data_size - 50];

  // Client side
  //
  // IPPPPSPISPPISPPPPSPISPPISPISP
  //
  // IPPPPS                 ....P.                        (  valid, 1 pending)
  //     PSPIS                  ...P.                     (  valid, 1 pending)
  //        ISPPIS                 ....P.                 (  valid, 1 pending)
  //            ISPPPPS                N.NNNPN            (invalid, 1 pending)
  //                 PSPIS                  .N.P.         (  valid, 1 pending)
  //                    ISPPIS                 ....P.     (  valid, 1 pending)
  //                        ISPIS                 ...P.   (  valid, 1 pending)
  //                                                                7 pending
  //                           ISP                   P.P  (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 29, 26, 3, 0, 0};
  const struct validation_stats expected = {.valid = 6,
      .invalid = 1,
      .pending_nalus = 7,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_sei_frame_partial_gops)
{
  // Device side
  struct oms_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned max_signing_nalus = 4;
  setting.max_signing_nalus = max_signing_nalus;
  test_stream_t *list = create_signed_nalus("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Remove forth 'S': IPPPPSPISPPISPPPP S PISPPISPISP
  const int remove_nalu_number = 18;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPPPSPISPPISPPPPPISPPISPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPPPISPPISPISP
  //
  // IPPPPS     ....P.                         (  valid, 1 pending)
  //     PSPIS      ...P.                      (  valid, 1 pending)
  //        ISPPIS     ....P.                  (  valid, 1 pending)
  //            ISPPPPPIS  N.NNN..P.           (invalid, 1 pending)
  //                   ISPPIS     ....P.       (  valid, 1 pending)
  //                       ISPIS       ...P.   (  valid, 1 pending)
  //                                                     6 pending
  //                          ISP         P.P  (invalid, 3 pending)
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK, OMS_PROVENANCE_OK, false,
      OMS_AUTHENTICITY_NOT_OK, 28, 25, 3, 0, 0};
  const struct validation_stats expected = {.valid = 5,
      .invalid = 1,
      .pending_nalus = 6,
      .final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, setting.ec_key);

  test_stream_free(list);
}
END_TEST

// Unsigned streams

/* Test description
 * Verifies that correct authentication is reported if the stream has no signature. */
START_TEST(unsigned_stream)
{
  // Device side
  test_stream_t *list = test_stream_create("IPPIPPIPPIPPI", settings[_i].codec);
  test_stream_check_types(list, "IPPIPPIPPIPPI");

  // Client side
  //
  // IPPIPPIPPIPPI
  //
  //                                                           0 pending
  // IPPIPPIPPIPPI               PPPPPPPPPPPP      (unsigned, 13 pending)
  // Video is not signed, hence no intermediate results are provided.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE, OMS_PROVENANCE_NOT_FEASIBLE, false,
      OMS_NOT_SIGNED, 13, 0, 13, -1, -1};
  const struct validation_stats expected = {.final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

  test_stream_free(list);
}
END_TEST

START_TEST(unsigned_multislice_stream)
{
  // Device side
  test_stream_t *list =
      test_stream_create("IiPpPpIiPpPpIiPpPpIiPpPpIi", settings[_i].codec);
  test_stream_check_types(list, "IiPpPpIiPpPpIiPpPpIiPpPpIi");

  // Client side
  //
  // IiPpPpIiPpPpIiPpPpIiPpPpIi
  //
  //                                                                       0 pending
  // IiPpPpIiPpPpIiPpPpIiPpPpIi    PPPPPPPPPPPPPPPPPPPPPPPPPP  (unsigned, 26 pending)
  // Video is not signed, hence no intermediate results are provided.
  onvif_media_signing_accumulated_validation_t final_validation = {
      OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE, OMS_PROVENANCE_NOT_FEASIBLE, false,
      OMS_NOT_SIGNED, 26, 0, 26, -1, -1};
  const struct validation_stats expected = {.final_validation = &final_validation};
  validate_test_stream(NULL, list, expected, settings[_i].ec_key);

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
  // Standard signed GOPs
  tcase_add_loop_test(tc, intact_stream, s, e);
  tcase_add_loop_test(tc, intact_multislice_stream, s, e);
  tcase_add_loop_test(tc, intact_stream_with_splitted_nalus, s, e);
  tcase_add_loop_test(tc, intact_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_ms_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_multislice_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, add_non_onvif_sei_after_signing, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late, s, e);
  tcase_add_loop_test(tc, with_blocked_signing, s, e);
  tcase_add_loop_test(tc, file_export_and_scrubbing, s, e);
  tcase_add_loop_test(tc, certificate_sei_first, s, e);
  tcase_add_loop_test(tc, certificate_sei_later, s, e);
  tcase_add_loop_test(tc, no_trusted_certificate_added, s, e);
  // Tampering cases
  tcase_add_loop_test(tc, interchange_two_p_frames, s, e);
  tcase_add_loop_test(tc, modify_one_p_frame, s, e);
  tcase_add_loop_test(tc, remove_one_p_frame, s, e);
  tcase_add_loop_test(tc, add_one_p_frame, s, e);
  tcase_add_loop_test(tc, modify_one_i_frame, s, e);
  tcase_add_loop_test(tc, remove_one_i_frame, s, e);
  tcase_add_loop_test(tc, modify_one_sei_frame, s, e);
  tcase_add_loop_test(tc, remove_one_sei_frame, s, e);
  tcase_add_loop_test(tc, interchange_two_seis, s, e);
  tcase_add_loop_test(tc, remove_both_i_and_sei, s, e);
  // tcase_add_loop_test(tc, late_seis_and_first_gop_scrapped, s, e);
  // tcase_add_loop_test(tc, lost_a_gop, s, e);
  // tcase_add_loop_test(tc, detect_change_of_public_key, s, e);
  // Signed multiple GOPs
  tcase_add_loop_test(tc, sign_multiple_gops, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_multiple_gops, s, e);
  tcase_add_loop_test(tc, file_export_and_scrubbing_multiple_gops, s, e);
  tcase_add_loop_test(tc, modify_one_p_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_one_p_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, add_one_p_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, modify_one_i_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_one_i_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, modify_sei_frames_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_sei_frames_multiple_gops, s, e);
  // Signed partial GOPs
  tcase_add_loop_test(tc, sign_partial_gops, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_partial_gops, s, e);
  tcase_add_loop_test(tc, file_export_and_scrubbing_partial_gops, s, e);
  tcase_add_loop_test(tc, modify_one_p_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_p_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, add_one_p_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, modify_one_i_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_i_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, modify_one_sei_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_sei_frame_partial_gops, s, e);
  // Unsigned streams
  tcase_add_loop_test(tc, unsigned_stream, s, e);
  tcase_add_loop_test(tc, unsigned_multislice_stream, s, e);

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
