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

// #include <assert.h>  // assert
#include <stdlib.h>  // free, size_t

#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_validator.h"
#include "oms_authenticity_report.h"  // create_local_authenticity_report_if_needed()
#include "oms_defines.h"
#include "oms_internal.h"
#include "oms_nalu_list.h"
#include "oms_tlv.h"

static void
extract_crypto_info_from_sei(onvif_media_signing_t *self, nalu_list_item_t *item);
static oms_rc
verify_sei_signature(onvif_media_signing_t *self,
    nalu_list_item_t *item,
    int *verified_result);

static bool
verify_gop_hash(onvif_media_signing_t *self);
static void
validate_authenticity(onvif_media_signing_t *self, nalu_list_item_t *sei);
static void
remove_sei_association(nalu_list_t *nalu_list);
static void
mark_associated_items(nalu_list_t *nalu_list, bool valid, nalu_list_item_t *sei);
static oms_rc
compute_gop_hash(onvif_media_signing_t *self, nalu_list_item_t *sei);
static oms_rc
prepare_for_validation(onvif_media_signing_t *self, nalu_list_item_t **sei);
static bool
has_pending_partial_gop(onvif_media_signing_t *self);
static bool
validation_is_feasible(const nalu_list_item_t *item);
static oms_rc
decode_sei_data(onvif_media_signing_t *self, const uint8_t *tlv, size_t tlv_size);

#if 0
static bool
verify_hashes_with_hash_list(onvif_media_signing_t *self,
    int *num_expected_nalus,
    int *num_received_nalus);
static int
set_validation_status_of_items_used_in_gop_hash(nalu_list_t *nalu_list,
    char validation_status);
static bool
verify_hashes_with_gop_hash(onvif_media_signing_t *self, int *num_expected_nalus, int *num_received_nalus);
static bool
verify_hashes_without_sei(onvif_media_signing_t *self);
#endif

#ifdef ONVIF_MEDIA_SIGNING_DEBUG
const char *kAuthResultValidStr[OMS_AUTHENTICITY_NUM_STATES] = {
    "MEDIA SIGNING NOT PRESENT", "MEDIA SIGNING PRESENT", "PROVENANCE NOT OK", "NOT OK",
    "OK WITH MISSING INFO", "OK", "VERSION MISMATCH"};
#endif

/**
 * The function is called when a SEI is received that  holds all the GOP information such
 * as a signed hash. The TLV data is decoded and the signature hash is verified.
 */
static oms_rc
decode_sei_data(onvif_media_signing_t *self, const uint8_t *tlv, size_t tlv_size)
{
  assert(self && tlv && (tlv_size > 0));
  // Get the last GOP counter before updating.
  uint32_t last_gop_number = self->gop_info->current_gop;
  uint32_t exp_gop_number = last_gop_number + 1;
  DEBUG_LOG("SEI TLV data size = %zu, exp gop number = %u", tlv_size, exp_gop_number);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_WITH_MSG(tlv_decode(self, tlv, tlv_size), "Failed decoding SEI TLV data");

    // Compare new with last number of GOPs to detect potentially lost SEIs.
    uint32_t new_gop_number = self->gop_info->current_gop;
    int64_t potentially_missed_gops = (int64_t)new_gop_number - exp_gop_number;
    // If number of |potentially_missed_gops| is negative, we have either lost SEIs
    // together with a wraparound of |current_gop|, or a reset of Media Signing was done
    // on the device. The correct number of lost SEIs is of less importance, since it is
    // only neccessary to know IF there is a lost SEI. Therefore, make sure to map the
    // value into the positive side only. It is possible to signal to the validation side
    // that a reset was done on the device, but it is still not possible to validate
    // pending NAL Units.
    if (potentially_missed_gops < 0)
      potentially_missed_gops += INT64_MAX;
    // It is only possible to know if a SEI has been lost if the |current_gop| is in sync.
    // Otherwise, the counter cannot be trusted.
    // self->gop_state.has_lost_sei =
    //     (potentially_missed_gops > 0) && self->gop_info->global_gop_counter_is_synced;

    // Every SEI is associated with a GOP. If a lost SEI has been detected, and no GOP end
    // has been found prior to this SEI, it means both a SEI and an I-frame was lost. This
    // is defined as a lost GOP transition.
    // if (self->gop_state.no_gop_end_before_sei && self->gop_state.has_lost_sei) {
    //   self->gop_state.gop_transition_is_lost = true;
    // }

  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

#if 0
/* Verifies the hashes of the oldest pending GOP from a hash list.
 *
 * If the |document_hash| in the SEI is verified successfully with the signature and the Public key,
 * the hash list is valid. By looping through the NALUs in the |nalu_list| we compare individual
 * hashes with the ones in the hash list. Items are marked as OK ('.') if we can find its twin in
 * correct order. Otherwise, they become NOT OK ('N').
 *
 * If we detect missing/lost NALUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received NALUs are computed. These can be
 * output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
verify_hashes_with_hash_list(onvif_media_signing_t *self, int *num_expected_nalus, int *num_received_nalus)
{
  assert(self);

  const size_t hash_size = self->verify_data->hash_size;
  assert(hash_size > 0);
  // Expected hashes.
  uint8_t *expected_hashes = self->gop_info->hash_list;
  const int num_expected_hashes = self->gop_info->list_idx / hash_size;

  nalu_list_t *nalu_list = self->nalu_list;
  nalu_list_item_t *last_used_item = NULL;

  if (!expected_hashes || !nalu_list) return false;

  nalu_list_print(nalu_list);

  // Get the SEI associated with the oldest pending GOP.
  nalu_list_item_t *sei = nalu_list_get_next_sei_item(nalu_list);
  // TODO: Investigate if we can end up without finding a SEI. If so, should we fail the validation
  // or call verify_hashes_without_sei()?
  if (!sei) return false;

  // First of all we need to know if the SEI itself is authentic, that is, the SEI |document_hash|
  // has successfully been verified (= 1). If the document could not be verified sucessfully, that
  // is, the SEI NALU is invalid, all NALUs become invalid. Hence, verify_hashes_without_sei().
  switch (self->gop_info->verified_signature) {
    case -1:
      sei->validation_status = 'E';
      return verify_hashes_without_sei(self);
    case 0:
      sei->validation_status = 'N';
      return verify_hashes_without_sei(self);
    case 1:
      assert(sei->validation_status == 'P');
      break;
    default:
      // We should not end up here.
      assert(false);
      return false;
  }

  // The next step is to verify the hashes of the NALUs in the |nalu_list| until we hit a transition
  // to the next GOP, but no further than to the item after the |sei|.

  // Statistics tracked while verifying hashes.
  int num_invalid_nalus_since_latest_match = 0;
  int num_verified_hashes = 0;
  // Initialization
  int latest_match_idx = -1;  // The latest matching hash in |hash_list|
  int compare_idx = 0;  // The offset in |hash_list| selecting the hash to compared
                        // against the |hash_to_verify|
  bool found_next_gop = false;
  bool found_item_after_sei = false;
  nalu_list_item_t *item = nalu_list->first_item;
  // This while-loop selects items from the oldest pending GOP. Each item hash is then verified
  // against the feasible hashes in the received |hash_list|.
  while (item && !(found_next_gop || found_item_after_sei)) {
    // If this item is not Pending, move to the next one.
    if (item->validation_status != 'P') {
      DEBUG_LOG("Skipping non-pending NALU");
      item = item->next;
      continue;
    }
    // Only a missing item has a null pointer NALU, but they are skipped.
    assert(item->nalu_info);
    // Check if this is the item right after the |sei|.
    found_item_after_sei = (item->prev == sei);
    // Check if this |is_first_nalu_in_gop|, but not used before.
    found_next_gop = (item->nalu_info->is_first_nalu_in_gop && !item->need_second_verification);
    // If this is a SEI, it is not part of the hash list and should not be verified.
    if (item->nalu_info->is_oms_sei) {
      DEBUG_LOG("Skipping SEI");
      item = item->next;
      continue;
    }

    last_used_item = item;
    num_verified_hashes++;

    // Fetch the |hash_to_verify|, which normally is the item->hash, but if this is NALU has been
    // used in a previous verification we use item->second_hash.
    uint8_t *hash_to_verify = item->need_second_verification ? item->second_hash : item->hash;

    // Compare |hash_to_verify| against all the |expected_hashes| since the |latest_match_idx|. Stop
    // when we get a match or reach the end.
    compare_idx = latest_match_idx + 1;
    // This while-loop searches for a match among the feasible hashes in |hash_list|.
    while (compare_idx < num_expected_hashes) {
      uint8_t *expected_hash = &expected_hashes[compare_idx * hash_size];

      if (memcmp(hash_to_verify, expected_hash, hash_size) == 0) {
        // We have a match. Set validation_status and add missing nalus if we have detected any.
        if (item->second_hash && !item->need_second_verification &&
            item->nalu_info->is_first_nalu_in_gop) {
          // If this |is_first_nalu_in_gop| it should be verified twice. If this the first time we
          // signal that we |need_second_verification|.
          DEBUG_LOG("This NALU needs a second verification");
          item->need_second_verification = true;
        } else {
          item->validation_status = item->first_verification_not_authentic ? 'N' : '.';
          item->need_second_verification = false;
        }
        // Add missing items to |nalu_list|.
        int num_detected_missing_nalus =
            (compare_idx - latest_match_idx) - 1 - num_invalid_nalus_since_latest_match;
        // No need to check the return value. A failure only affects the statistics. In the worst
        // case we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
        h26x_nalu_list_add_missing(nalu_list, num_detected_missing_nalus, false, item);
        // Reset counters and latest_match_idx.
        latest_match_idx = compare_idx;
        num_invalid_nalus_since_latest_match = 0;
        break;
      }
      compare_idx++;
    }  // Done comparing feasible hashes.

    // Handle the non-match case.
    if (latest_match_idx != compare_idx) {
      // We have compared against all feasible hashes in |hash_list| without a match. Mark as NOT
      // OK, or keep pending for second use.
      if (item->second_hash && !item->need_second_verification) {
        item->need_second_verification = true;
        // If this item will be used in a second verification the flag
        // |first_verification_not_authentic| is set.
        item->first_verification_not_authentic = true;
      } else {
        // Reset |need_second_verification|.
        item->need_second_verification = false;
        item->validation_status = 'N';
      }
      // Update counters.
      num_invalid_nalus_since_latest_match++;
    }
    item = item->next;
  }  // Done looping through pending GOP.

  // Check if we had no matches at all. See if we should fill in with missing NALUs. This is of less
  // importance since the GOP is not authentic, but if we can we should provide proper statistics.
  if (latest_match_idx == -1) {
    DEBUG_LOG("Never found a matching hash at all");
    int num_missing_nalus = num_expected_hashes - num_invalid_nalus_since_latest_match;
    // We do not know where in the sequence of NALUs they were lost. Simply add them before the
    // first item. If the first item needs a second opinion, that is, it has already been verified
    // once, we append that item. Otherwise, prepend it with missing items.
    const bool append =
        nalu_list->first_item->second_hash && !nalu_list->first_item->need_second_verification;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    h26x_nalu_list_add_missing(nalu_list, num_missing_nalus, append, nalu_list->first_item);
  }

  // If the last invalid NALU is the first NALU in a GOP or the NALU after the SEI, keep it
  // pending. If the last NALU is valid and there are more expected hashes we either never
  // verified any hashes or we have missing NALUs.
  if (last_used_item) {
    if (latest_match_idx != compare_idx) {
      // Last verified hash is invalid.
      last_used_item->first_verification_not_authentic = true;
      // Give this NALU a second verification because it could be that it is present in the next GOP
      // and brought in here due to some lost NALUs.
      last_used_item->need_second_verification = true;
    } else {
      // Last received hash is valid. Check if there are unused hashes in |hash_list|. Note that the
      // index of the hashes span from 0 to |num_expected_hashes| - 1, so if |latest_match_idx| =
      // |num_expected_hashes| - 1, we have no pending nalus.
      int num_unused_expected_hashes = num_expected_hashes - 1 - latest_match_idx;
      // We cannot mark the last item as Missing since it will be handled a second time in the next
      // GOP.
      num_unused_expected_hashes--;
      if (num_unused_expected_hashes >= 0) {
        // Avoids reporting the lost linked hash twice.
        num_verified_hashes++;
      }
      // No need to check the return value. A failure only affects the statistics. In the worst case
      // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
      h26x_nalu_list_add_missing(nalu_list, num_unused_expected_hashes, true, last_used_item);
    }
  }

  // Done with the SEI. Mark as valid, because if we failed verifying the |document_hash| we would
  // not be here.
  sei->validation_status = '.';

  if (num_expected_nalus) *num_expected_nalus = num_expected_hashes;
  if (num_received_nalus) *num_received_nalus = num_verified_hashes;

  return true;
}

/* Sets the |validation_status| of all items in |nalu_list| that are |used_in_gop_hash|.
 *
 * Returns the number of items marked and -1 upon failure. */
static int
set_validation_status_of_items_used_in_gop_hash(nalu_list_t *nalu_list, char validation_status)
{
  if (!nalu_list) return -1;

  int num_marked_items = 0;

  // Loop through the |nalu_list| and set the |validation_status| if the item is |used_in_gop_hash|
  nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    if (item->used_in_gop_hash) {
      // Items used in two verifications should not have |validation_status| set until it has been
      // used twice. If this is the first time we set the flag |first_verification_not_authentic|.
      if (item->second_hash && !item->need_second_verification) {
        DEBUG_LOG("This NALU needs a second verification");
        item->need_second_verification = true;
        item->first_verification_not_authentic = (validation_status != '.') ? true : false;
      } else {
        item->validation_status = item->first_verification_not_authentic ? 'N' : validation_status;
        item->need_second_verification = false;
        num_marked_items++;
      }
    }

    item->used_in_gop_hash = false;
    item = item->next;
  }

  return num_marked_items;
}

/* Verifies the hashes of the oldest pending GOP from a gop_hash.
 *
 * Since the gop_hash is one single hash representing the entire GOP we mark all of them as OK ('.')
 * if we can verify the gop_hash with the signature and Public key. Otherwise, they all become NOT
 * OK ('N').
 *
 * If we detect missing/lost NALUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received NALUs are computed. These can be
 * output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
verify_hashes_with_gop_hash(onvif_media_signing_t *self, int *num_expected_nalus, int *num_received_nalus)
{
  assert(self);

  // Initialize to "Unknown"
  int num_expected_hashes = -1;
  int num_received_hashes = -1;
  char validation_status = 'P';

  // The verification of the gop_hash (|verified_signature|) determines the |validation_status|
  // of the entire GOP.
  switch (self->gop_info->verified_signature) {
    case 1:
      validation_status = '.';
      break;
    case 0:
      validation_status = 'N';
      break;
    case -1:
    default:
      // Got an error when verifying the signature. Verify without a SEI.
      validation_status = 'E';
      return false;  // verify_hashes_without_sei(self);
  }

  // TODO: Investigate if we have a flaw in the ability to detect missing NALUs. Note that we can
  // only trust the information in the SEI if the |document_hash| (of the SEI) can successfully be
  // verified. This is only feasible if we have NOT lost any NALUs, hence we have a Catch 22
  // situation and can never add any missing NALUs.

  // The number of hashes part of the gop_hash was transmitted in the SEI.
  num_expected_hashes = (int)self->gop_info->num_sent_nalus;

  // Identify the first NALU used in the gop_hash. This will be used to add missing NALUs.
  nalu_list_item_t *first_gop_hash_item = self->nalu_list->first_item;
  while (first_gop_hash_item && !first_gop_hash_item->used_in_gop_hash) {
    first_gop_hash_item = first_gop_hash_item->next;
  }
  num_received_hashes =
      set_validation_status_of_items_used_in_gop_hash(self->nalu_list, validation_status);

  if (!self->validation_flags.is_first_validation && first_gop_hash_item) {
    int num_missing_nalus = num_expected_hashes - num_received_hashes;
    const bool append = first_gop_hash_item->nalu_info->is_first_nalu_in_gop;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    h26x_nalu_list_add_missing(self->nalu_list, num_missing_nalus, append, first_gop_hash_item);
  }

  if (num_expected_nalus) *num_expected_nalus = num_expected_hashes;
  if (num_received_nalus) *num_received_nalus = num_received_hashes;

  return true;
}

/* Verifying hashes without the SEI means that we have nothing to verify against. Therefore, we mark
 * all NALUs of the oldest pending GOP with |validation_status| = 'N'. This function is used both
 * for unsigned videos as well as when the SEI has been modified or lost.
 *
 * Returns false if we failed verifying hashes, which happens if there is no list or if there are no
 * pending NALUs. Otherwise, returns true. */
static bool
verify_hashes_without_sei(onvif_media_signing_t *self)
{
  assert(self);

  nalu_list_t *nalu_list = self->nalu_list;

  if (!nalu_list) return false;

  nalu_list_print(nalu_list);

  // Start from the oldest item and mark all pending items as NOT OK ('N') until we detect a new GOP
  int num_marked_items = 0;
  nalu_list_item_t *item = nalu_list->first_item;
  bool found_next_gop = false;
  while (item && !found_next_gop) {
    // Skip non-pending items.
    if (item->validation_status != 'P') {
      item = item->next;
      continue;
    }

    // A new GOP starts if the NALU |is_first_nalu_in_gop|. Such a NALU is hashed twice; as an
    // initial hash AND as a linking hash between GOPs. If this is the first time is is used in
    // verification it also marks the start of a new GOP.
    found_next_gop = item->nalu_info->is_first_nalu_in_gop && !item->need_second_verification;

    // Mark the item as 'Not Authentic' or keep it for a second verification.
    if (found_next_gop) {
      // Keep the item pending and mark the first verification as not authentic.
      item->need_second_verification = true;
      item->first_verification_not_authentic = true;
    } else if (item->validation_status == 'P') {
      item->need_second_verification = false;
      item->validation_status = 'N';
      num_marked_items++;
    }
    item = item->next;
  }

  // If we have verified a GOP without a SEI, we should increment the |current_gop|.
  if (self->validation_flags.signing_present && (num_marked_items > 0)) {
    self->gop_info->current_gop++;
  }

  return found_next_gop;
}
#endif

static bool
verify_gop_hash(onvif_media_signing_t *self)
{
  assert(self);
  size_t hash_size = self->verify_data->hash_size;
  uint8_t *computed_gop_hash = self->tmp_partial_gop_hash;
  uint8_t *received_gop_hash = self->gop_info->partial_gop_hash;
  return memcmp(computed_gop_hash, received_gop_hash, hash_size) == 0;
}

/* Validates the authenticity using hashes in the |nalu_list|.
 *
 * In brief, the validation verifies hashes and sets the |validation_status| given the
 * outcome. Verifying a hash means comparing two and check if they are identical. There
 * are three ways to verify hashes 1) verify_hashes_without_sei(): There is no SEI
 * available, hence no expected hash to compare exists. All the hashes we know cannot be
 * verified are then marked as 'N'. 2) verify_hashes_from_gop_hash(): A hash representing
 * all hashes of a GOP (a gop_hash) is generated. If this gop_hash verifies successful
 * against the signature all hashes are correct and each item, included in the gop_hash,
 * are marked as '.'. If the verification fails we mark all as 'N'. 3)
 * verify_hashes_from_hash_list(): We have access to all transmitted hashes and can verify
 * each and one of them against the received ones, and further, mark them correspondingly.
 *
 * If we during verification detect missing NALUs, we add empty items (marked 'M') to the
 * |nalu_list|.
 *
 * - After verification, hence the |validation_status| of each item in the list has been
 * updated, statistics are collected from the list, using nalu_list_get_stats().
 * - Based on the statistics a validation decision can be made.
 * - Update |latest_validation| with the validation result.
 */
static void
validate_authenticity(onvif_media_signing_t *self, nalu_list_item_t *sei)
{
  assert(self);

  // gop_state_t *gop_state = &(self->gop_state);
  // validation_flags_t *validation_flags = &(self->validation_flags);
  onvif_media_signing_latest_validation_t *latest = self->latest_validation;

  MediaSigningAuthenticityResult valid = OMS_AUTHENTICITY_NOT_OK;
  // Initialize to "Unknown"
  int num_expected_nalus = self->gop_info->num_sent_nalus;
  int num_received_nalus = self->tmp_num_nalus_in_partial_gop;
  int num_invalid_nalus = -1;
  int num_missed_nalus = -1;
  bool verify_success = false;

  // if (gop_state->has_lost_sei && !gop_state->gop_transition_is_lost) {
  //   DEBUG_LOG("We never received the SEI associated with this GOP");
  //   // We never received the SEI nalu, but we know we have passed a GOP transition.
  //   Hence, we cannot
  //   // verify this GOP. Marking this GOP as not OK by verify_hashes_without_sei().
  //   remove_sei_association(self->nalu_list);
  //   verify_success = verify_hashes_without_sei(self);
  // } else {
  verify_success = verify_gop_hash(self);
  mark_associated_items(self->nalu_list, verify_success, sei);
  if (!verify_success) {
    DEBUG_LOG("GOP hash could not be verified");
  }
  // verify_success = verify_hashes_with_hash_list(self, &num_expected_nalus,
  // &num_received_nalus);
  // }

  // Collect statistics from the nalu_list. This is used to validate the GOP and provide
  // additional information to the user. bool has_valid_nalus =
  nalu_list_get_stats(self->nalu_list, &num_invalid_nalus, &num_missed_nalus);
  DEBUG_LOG("Number of invalid NAL Units = %d.", num_invalid_nalus);
  DEBUG_LOG("Number of missed NAL Units = %d.", num_missed_nalus);

  valid = (num_invalid_nalus > 0) ? OMS_AUTHENTICITY_NOT_OK : OMS_AUTHENTICITY_OK;

  // Post-validation actions.
#if 0
  // If we lose an entire GOP (part from the associated SEI) it will be seen as valid. Here we fix
  // it afterwards.
  // TODO: Move this inside the verify_hashes_ functions. We should not need to perform any special
  // actions on the output.
  if (!validation_flags->is_first_validation) {
    if ((valid == SV_AUTH_RESULT_OK) && (num_expected_nalus > 1) &&
        (num_missed_nalus >= num_expected_nalus - 1)) {
      valid = SV_AUTH_RESULT_NOT_OK;
    }
    self->gop_info->global_gop_counter_is_synced = true;
  }
  // Determine if this GOP is valid, but has missing information. This happens if we have detected
  // missed NALUs or if the GOP is incomplete.
  if (valid == SV_AUTH_RESULT_OK && (num_missed_nalus > 0 && verify_success)) {
    valid = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
    DEBUG_LOG("Successful validation, but detected missing NALUs");
  }
  // The very first validation needs to be handled separately. If this is truly the start of a
  // stream we have all necessary information to successfully validate the authenticity. It can be
  // interpreted as being in sync with its signing counterpart. If this session validates the
  // authenticity of a segment of a stream, e.g., an exported file, we start out of sync. The first
  // SEI may be associated with a GOP prior to this segment.
  if (validation_flags->is_first_validation) {
    // Change status from SV_AUTH_RESULT_OK to SV_AUTH_RESULT_SIGNATURE_PRESENT if no valid NALUs
    // were found when collecting stats.
    if ((valid == SV_AUTH_RESULT_OK) && !has_valid_nalus) {
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
    }
    // If validation was successful, the |current_gop| is in sync.
    self->gop_info->global_gop_counter_is_synced = (valid == SV_AUTH_RESULT_OK);
    if (valid != SV_AUTH_RESULT_OK) {
      // We have validated the authenticity based on one single NALU, but failed. A success can only
      // happen if we are at the beginning of the original stream. For all other cases, for example,
      // if we validate the authenticity of an exported file, the first SEI may be associated with a
      // part of the original stream not present in the file. Hence, mark as
      // SV_AUTH_RESULT_SIGNATURE_PRESENT instead.
      DEBUG_LOG("This first validation cannot be performed");
      // Since we verify the linking hash twice we need to remove the set
      // |first_verification_not_authentic|. Otherwise, the false failure leaks into the next GOP.
      // Further, empty items marked 'M', may have been added at the beginning. These have no
      // meaning and may only confuse the user. These should be removed. This is handled in
      // h26x_nalu_list_remove_missing_items().
      h26x_nalu_list_remove_missing_items(self->nalu_list);
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      num_expected_nalus = -1;
      num_received_nalus = -1;
      // If validation was tried with the very first SEI in stream it cannot be part at.
      // Reset the first validation to be able to validate a segment in the middle of the stream.
      self->validation_flags.reset_first_validation = (self->gop_info->num_sent_nalus == 1);
    }
  }
#endif
  if (latest->public_key_has_changed)
    valid = OMS_AUTHENTICITY_NOT_OK;

  // Update |latest_validation| with the validation result.
  if (latest->authenticity <= OMS_AUTHENTICITY_NOT_FEASIBLE) {
    // Still either pending validation or video has no signature. Update with the current
    // result.
    latest->authenticity = valid;
  } else if (valid < latest->authenticity) {
    // Current validated a worse authenticity compared to what has been validated so
    // far. Update with this worse result, since that is what should rule the total
    // validation.
    latest->authenticity = valid;
  }
  latest->number_of_expected_hashable_nalus += num_expected_nalus;
  latest->number_of_received_hashable_nalus += num_received_nalus;
}

/* Removes the association with a SEI flag from all items. */
static void
remove_sei_association(nalu_list_t *nalu_list)
{
  if (!nalu_list)
    return;

  nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    item->associated_sei = NULL;
    item = item->next;
  }
}

static void
mark_associated_items(nalu_list_t *nalu_list, bool valid, nalu_list_item_t *sei)
{
  if (!nalu_list)
    return;

  nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    if (item->associated_sei == sei) {
      if (sei->validation_status_if_sei_ok != ' ') {
        item->validation_status_if_sei_ok = valid ? '.' : 'N';
      } else {
        bool valid_if_sei_ok = !(item->validation_status_if_sei_ok == 'N');
        item->validation_status = valid ? '.' : 'N';
        item->validation_status_if_sei_ok = ' ';
        if (item->nalu_info && item->nalu_info->is_oms_sei) {
          mark_associated_items(nalu_list, valid && valid_if_sei_ok, item);
        }
      }
    }
    item = item->next;
  }
}

/* Computes the gop_hash of the oldest pending GOP in the nalu_list. */
static oms_rc
compute_gop_hash(onvif_media_signing_t *self, nalu_list_item_t *sei)
{
  assert(self);

  nalu_list_t *nalu_list = self->nalu_list;

  // Expect a valid SEI and that it has been decoded.
  if (!(sei && sei->has_been_decoded))
    return OMS_INVALID_PARAMETER;
  if (!nalu_list)
    return OMS_INVALID_PARAMETER;

  nalu_list_item_t *item = NULL;
  // gop_info_t *gop_info = self->gop_info;

  nalu_list_print(nalu_list);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Initialize the gop_hash by resetting it.
    OMS_THROW(reset_gop_hash(self));
    // In general we do not know when the SEI, associated with a GOP, arrives. If it is
    // delayed we should collect all NALUs of the GOP, that is, stop adding hashes when we
    // find a new GOP. If the SEI is not delayed we need also the NALU right after the SEI
    // to complete the operation.

    // Loop through the items of |nalu_list| until we find a new GOP. If no new GOP is
    // found until we reach the SEI we stop at the NALU right after the SEI. Update the
    // gop_hash with each NALU hash and finalize the operation by updating with the hash
    // of the SEI.
    int num_gop_transitions = 0;
    item = nalu_list->first_item;
    while (item) {
      // If this item is not Pending, move to the next one.
      if (item->validation_status != 'P' || item->associated_sei) {
        item = item->next;
        continue;
      }
      // Only missing items can have a null pointer |nalu_info|, but they are not pending.
      assert(item->nalu_info);
      // Check if this |is_first_nalu_in_gop|, but used in verification for the first
      // time.
      num_gop_transitions += item->nalu_info->is_first_nalu_in_gop;
      if (num_gop_transitions > 1)
        break;
      // If this is the SEI associated with the GOP and has a signature it is skipped.
      if (item->nalu_info->is_oms_sei && item->nalu_info->is_signed) {
        item = item->next;
        continue;
      }
      // Skip NAL Units when exceeding the amount that the SEI has reported in the partial
      // GOP.
      if (self->tmp_num_nalus_in_partial_gop >= self->gop_info->num_sent_nalus) {
        item = item->next;
        continue;
      }

      // Update the onging gop_hash with this NAL Unit hash.
      OMS_THROW(update_gop_hash(self->crypto_handle, item->hash));
      self->tmp_num_nalus_in_partial_gop++;

      // Mark the item and move to next.
      item->associated_sei = sei;
      item = item->next;
    }
    OMS_THROW(finalize_gop_hash(self->crypto_handle, self->tmp_partial_gop_hash));
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
    printf("Received (partial) GOP hash: ");
    for (size_t i = 0; i < self->verify_data->hash_size; i++) {
      printf("%02x", self->gop_info->partial_gop_hash[i]);
    }
    printf("\n");
#endif
  OMS_CATCH()
  {
    // TODO: This should be done outside this function.
    // Failed computing the gop_hash. Remove all markers.
    remove_sei_association(nalu_list);
  }
  OMS_DONE(status)

  return status;
}

/* prepare_for_validation()
 *
 * 1) finds the oldest available and pending SEI in the |nalu_list|.
 * 2) decodes the TLV data from it if it has not been done already.
 * 3) points signature->hash to the location of either the document hash or the gop_hash.
 * This is needed to know which hash the signature will verify. 4) computes the gop_hash
 * from hashes in the list, if we perform GOP level authentication. 5) verify the
 * associated hash using the signature.
 */
static oms_rc
prepare_for_validation(onvif_media_signing_t *self, nalu_list_item_t **sei)
{
  assert(self);

  validation_flags_t *validation_flags = &(self->validation_flags);
  nalu_list_t *nalu_list = self->nalu_list;
  sign_or_verify_data_t *verify_data = self->verify_data;
  const size_t hash_size = verify_data->hash_size;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    *sei = nalu_list_get_next_sei_item(nalu_list);
    if (*sei && !(*sei)->has_been_decoded) {
      // Decode the SEI and set signature->hash
      const uint8_t *tlv_data = (*sei)->nalu_info->tlv_data;
      size_t tlv_size = (*sei)->nalu_info->tlv_size;

      OMS_THROW(decode_sei_data(self, tlv_data, tlv_size));
      (*sei)->has_been_decoded = true;
      memcpy(verify_data->hash, (*sei)->hash, hash_size);
      if ((*sei)->nalu_info->is_signed) {
        (*sei)->validation_status = (*sei)->verified_signature == 1 ? '.' : 'N';
      } else {
        (*sei)->validation_status_if_sei_ok = '.';
      }
      validation_flags->validate_golden_sei = (*sei)->nalu_info->is_golden_sei;
    }
    if (!validation_flags->validate_golden_sei) {
      OMS_THROW(compute_gop_hash(self, *sei));
    } else {
      self->latest_validation->authenticity =
          (*sei)->verified_signature == 1 ? OMS_AUTHENTICITY_OK : OMS_AUTHENTICITY_NOT_OK;
    }

    OMS_THROW_IF_WITH_MSG(validation_flags->signing_present && !self->has_public_key,
        OMS_NOT_SUPPORTED, "No public key present");

    // If we have received a SEI there is a signature to use for verification.
    //     if (self->gop_state.has_sei ||
    //     self->nalu_list->first_item->nalu_info->is_golden_sei) {
    // #ifdef ONVIF_MEDIA_SIGNING_DEBUG
    //       printf("Hash to verify against signature:\n");
    //       for (size_t i = 0; i < verify_data->hash_size; i++) {
    //         printf("%02x", verify_data->hash[i]);
    //       }
    //       printf("\n");
    // #endif
    //       OMS_THROW(openssl_verify_hash(verify_data,
    //       &self->gop_info->verified_signature));
    //     }
    if ((*sei)->nalu_info->is_signed) {
      self->gop_info->verified_signature = (*sei)->verified_signature;
    } else {
      self->gop_info->verified_signature = 1;
    }
    validation_flags->waiting_for_signature = !(*sei)->nalu_info->is_signed;
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

// If this is a Media Signing generated SEI, including a signature, decode all optional
// TLV information and verify the signature.
static void
extract_crypto_info_from_sei(onvif_media_signing_t *self, nalu_list_item_t *item)
{
  nalu_info_t *nalu_info = item->nalu_info;
  if (!nalu_info->is_oms_sei) {
    return;
  }
  // Even if a SEI without signature (signing multiple GOPs) could include optional
  // information like the public key it is not safe to use that until the SEI can be
  // verified. Therefore, a SEI is not decoded to get the cryptographic information if it
  // is not signed directly.
  if (!nalu_info->is_signed) {
    return;
  }

  const uint8_t *tlv_data = nalu_info->tlv_data;
  size_t tlv_size = nalu_info->tlv_size;
  tlv_find_and_decode_optional_tags(self, tlv_data, tlv_size);
}

static oms_rc
verify_sei_signature(onvif_media_signing_t *self,
    nalu_list_item_t *item,
    int *verified_result)
{
  nalu_info_t *nalu_info = item->nalu_info;
  if (!nalu_info->is_oms_sei || !nalu_info->is_signed) {
    return OMS_OK;
  }
  if (!tlv_find_and_decode_signature_tag(
          self, item->nalu_info->tlv_data, item->nalu_info->tlv_size)) {
    return OMS_OK;
  }
  memcpy(self->verify_data->hash, item->hash, self->verify_data->hash_size);

  return openssl_verify_hash(self->verify_data, verified_result);
}

/* Loops through the |nalu_list| to find out if there are GOPs that awaits validation. */
static bool
has_pending_partial_gop(onvif_media_signing_t *self)
{
  assert(self && self->nalu_list);
  // gop_state_t *gop_state = &(self->gop_state);
  nalu_list_item_t *item = self->nalu_list->first_item;
  // Statistics collected while looping through the NAL Units.
  int num_detected_gop_starts = 0;
  bool found_pending_oms_sei = false;
  bool found_pending_gop = false;

  // Reset the |gop_state| members before running through the NAL Units in |nalu_list|.
  // gop_state_reset(gop_state);

  while (item && !found_pending_gop) {
    nalu_info_t *nalu_info = item->nalu_info;
    if (!nalu_info || item->validation_status_if_sei_ok != ' ') {
      // Missing item or already validated item with an unsigned SEI; move on
      item = item->next;
      continue;
    }
    // gop_state_update(gop_state, item->nalu_info);
    // Golden SEIs can, and should, be validated at once.
    found_pending_gop = (item->validation_status == 'P' && nalu_info->is_golden_sei);
    // Collect statistics from pending and hashable NAL Units only. The others are either
    // out of date or not part of the validation.
    if (item->validation_status == 'P' && nalu_info->is_hashable) {
      num_detected_gop_starts += nalu_info->is_first_nalu_in_gop;
      found_pending_oms_sei |= nalu_info->is_oms_sei;
    }
    if (!self->validation_flags.signing_present) {
      // If the video is not signed at least 2 I-frames are needed to have a complete GOP.
      found_pending_gop |= (num_detected_gop_starts >= 2);
    } else {
      // When the video is signed it is time to validate when there is at least one GOP
      // and a Media Signing generated SEI.
      found_pending_gop |= (num_detected_gop_starts > 0) && found_pending_oms_sei;
    }
    item = item->next;
  }

  // gop_state->no_gop_end_before_sei = (num_detected_gop_starts < 2);

  return found_pending_gop;
}

/* Determines if the |item| is up for a validation.
 * The NALU should be hashable and pending validation.
 * If so, validation is triggered on any of the below
 *   - a SEI (since if the SEI arrives late, the SEI is the final piece for validation)
 *   - a new I-frame (since this marks the end of a GOP)
 *   - the first hashable NALU right after a pending SEI (if a SEI has not been validated,
 * we need at most one more hashable NALU) */
static bool
validation_is_feasible(const nalu_list_item_t *item)
{
  if (!item->nalu_info)
    return false;
  if (!item->nalu_info->is_hashable)
    return false;
  if (item->validation_status != 'P')
    return false;

  // Validation may be done upon a SEI.
  if (item->nalu_info->is_oms_sei)
    return true;
  // Validation may be done upon the end of a GOP.
  if (item->nalu_info->is_first_nalu_in_gop)
    return true;
    // NOTE: This is only possible if the client side is allowed to move a SEI to its
    // associated GOP.
    // Validation may be done upon a hashable NAL Unit right after a SEI. This happens
    // when the SEI was generated and attached to the same NAL Unit that triggered the
    // action.
#ifdef SUPPORT_MOVING_SEI_TO_ASSOCIATED_OP
  item = item->prev;
  while (item) {
    if (item->nalu_info && item->nalu_info->is_hashable) {
      break;
    }
    item = item->prev;
  }
  if (item && item->nalu_info->is_oms_sei && item->validation_status == 'P')
    return true;
#endif

  return false;
}

/* Validates the authenticity of the video since last time if the state says so. After the
 * validation the gop state is reset w.r.t. a new GOP. */
static oms_rc
maybe_validate_gop(onvif_media_signing_t *self, nalu_info_t *nalu_info)
{
  assert(self && nalu_info);

  validation_flags_t *validation_flags = &(self->validation_flags);
  onvif_media_signing_latest_validation_t *latest = self->latest_validation;
  nalu_list_t *nalu_list = self->nalu_list;
  bool validation_feasible = true;

  // Make sure the current NAL Unit can trigger a validation.
  validation_feasible &= validation_is_feasible(nalu_list->last_item);
  // Make sure there is enough information to perform validation.
  validation_feasible &= self->has_public_key;

  // Abort if validation is not feasible.
  if (!validation_feasible) {
    // If this is the first arrived SEI, but could still not validate the authenticity,
    // signal to the user that the Media Signing has been detected.
    if (validation_flags->is_first_sei) {
      latest->authenticity = OMS_AUTHENTICITY_NOT_FEASIBLE;
      latest->number_of_expected_hashable_nalus = -1;
      latest->number_of_received_hashable_nalus = -1;
      latest->number_of_pending_hashable_nalus =
          nalu_list_num_pending_items(nalu_list, NULL);
      latest->public_key_has_changed = false;
      self->validation_flags.has_auth_result = true;
    }
    return OMS_OK;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Keep validating as long as there are pending GOPs.
    bool stop_validating = false;
    while (has_pending_partial_gop(self) && !stop_validating) {
      nalu_list_item_t *sei = NULL;
      // Initialize latest validation if not validating intermediate GOPs.
      if (!validation_flags->waiting_for_signature) {
        latest->authenticity = OMS_AUTHENTICITY_NOT_FEASIBLE;
        latest->number_of_expected_hashable_nalus = 0;
        latest->number_of_received_hashable_nalus = 0;
        latest->number_of_pending_hashable_nalus = -1;
        latest->public_key_has_changed = false;
      }

      OMS_THROW(prepare_for_validation(self, &sei));

      if (!validation_flags->signing_present) {
        latest->authenticity = OMS_NOT_SIGNED;
        latest->number_of_expected_hashable_nalus = -1;
        latest->number_of_received_hashable_nalus = -1;
        // Since no validation is performed (all items are kept pending) a forced stop is
        // introduced to avoid a dead lock.
        stop_validating = true;
      } else if (!validation_flags->validate_golden_sei) {
        validate_authenticity(self, sei);
      }

      // The flag |is_first_validation| is used to ignore the first validation if we start
      // the validation in the middle of a stream. Now it is time to reset it.
      validation_flags->is_first_validation = !validation_flags->signing_present;

      // TODO: Enable when needed
      // if (validation_flags->reset_first_validation) {
      //   validation_flags->is_first_validation = true;
      //   nalu_list_item_t *item = self->nalu_list->first_item;
      //   while (item) {
      //     if (item->nalu_info && item->nalu_info->is_first_nalu_in_gop) {
      //       item->need_second_verification = false;
      //       item->first_verification_not_authentic = false;
      //       break;
      //     }
      //     item = item->next;
      //   }
      // }

      if (!validation_flags->waiting_for_signature) {
        self->gop_info->verified_signature = -1;
        validation_flags->has_auth_result = true;
        validation_flags->validate_golden_sei = false;
        // All statistics but pending NAL Units have already been collected.
        latest->number_of_pending_hashable_nalus =
            nalu_list_num_pending_items(nalu_list, NULL);

        DEBUG_LOG("Validated GOP as %s", kAuthResultValidStr[latest->authenticity]);
        DEBUG_LOG("Expected NAL Units = %d", latest->number_of_expected_hashable_nalus);
        DEBUG_LOG("Received NAL Units = %d", latest->number_of_received_hashable_nalus);
        DEBUG_LOG(" Pending NAL Units = %d", latest->number_of_pending_hashable_nalus);
      }
    }

  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/* This function updates the hashable part of the NAL Unit data. The default assumption is
 * that all bytes from NAL Unit header to stop bit are hashed. This holds for all NAL Unit
 * types but the Media Signing generated SEI NAL Units. For these, the last X bytes
 * storing the signature are not hashed.
 *
 * In this function the nalu_info_t member |hashable_data_size| is updated w.r.t. that.
 * The pointer to the start is still the same. */
void
update_hashable_data(nalu_info_t *nalu_info)
{
  assert(nalu_info && (nalu_info->is_valid > 0));
  if (!nalu_info->is_hashable || !nalu_info->is_oms_sei) {
    return;
  }

  // This is a Media Signing generated NAL Unit of type SEI. As payload it holds TLV data
  // where the last chunk is supposed to be the signature. That part should not be hashed,
  // hence re-calculate |hashable_data_size| by subtracting the number of bytes (including
  // potential emulation prevention bytes) coresponding to that tag. This is done by
  // scanning the TLV for that tag.
  const uint8_t *signature_tag_ptr = tlv_find_tag(nalu_info->tlv_start_in_nalu_data,
      nalu_info->tlv_size, SIGNATURE_TAG, nalu_info->with_epb);
  if (signature_tag_ptr) {
    nalu_info->hashable_data_size = signature_tag_ptr - nalu_info->hashable_data;
  }
}

/* A valid NAL Unit is registered by hashing and adding to the |item|. */
static oms_rc
register_nalu(onvif_media_signing_t *self, nalu_list_item_t *item)
{
  nalu_info_t *nalu_info = item->nalu_info;
  assert(self && nalu_info && nalu_info->is_valid >= 0);

  if (nalu_info->is_valid == 0)
    return OMS_OK;

  // Extract the cryptographic information like hash algorithm and Public key.
  extract_crypto_info_from_sei(self, item);
  update_hashable_data(nalu_info);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(hash_and_add_for_validation(self, item));
    if (nalu_info->is_signed) {
      OMS_THROW(verify_sei_signature(self, item, &item->verified_signature));
      // TODO: Decide what to do if verification fails. Should mark public key as not
      // present?
      DEBUG_LOG("Verified SEI signature with result %d", item->verified_signature);
    }
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/* All NAL Units in the |nalu_list| are re-registered by hashing them. */
static oms_rc
reregister_nalus(onvif_media_signing_t *self)
{
  assert(self);
  assert(self->validation_flags.hash_algo_known);

  nalu_list_t *nalu_list = self->nalu_list;
  nalu_list_item_t *item = nalu_list->first_item;
  oms_rc status = OMS_UNKNOWN_FAILURE;
  while (item) {
    if (item->nalu_info->is_valid <= 0) {
      item = item->next;
      continue;
    }
    status = hash_and_add_for_validation(self, item);
    if (status != OMS_OK) {
      break;
    }
    item = item->next;
  }

  return status;
}

#if 0
static void
validate_golden_sei(onvif_media_signing_t *self, nalu_list_t *nalu_list)
{
  // TODO: Authenticity result will be overwritten in |maybe_validate_gop| API.
  // It has to be fixed in a near future.

  // Check the status of the verified signature hash for the GOP info.
  switch (self->gop_info->verified_signature) {
    case 1:
      nalu_list->first_item->validation_status = '.';
      break;
    case 0:
      nalu_list->first_item->validation_status = 'N';
      self->latest_validation->authenticity = SV_AUTH_RESULT_NOT_OK;
      break;
    case -1:
    default:
      // Got an error when verifying the gop_hash. Verify without a SEI.
      nalu_list->first_item->validation_status = 'E';
      self->latest_validation->authenticity = SV_AUTH_RESULT_NOT_OK;
      self->has_public_key = false;
  }
}
#endif

/* The basic order of actions are:
 * 1. Every NAL Unit should be parsed and added to the |nalu_list|.
 * 2. Update validation flags given the added NAL Unit.
 * 3. Register NAL Unit, in general that means hash the NAL Unit if it is hashable and
 * store it.
 * 4. Validate pending NAL Units if possible. */
static oms_rc
add_nalu_and_validate(onvif_media_signing_t *self, const uint8_t *nalu, size_t nalu_size)
{
  if (!self || !nalu || (nalu_size == 0))
    return OMS_INVALID_PARAMETER;

  nalu_list_t *nalu_list = self->nalu_list;
  nalu_info_t nalu_info = parse_nalu_info(nalu, nalu_size, self->codec, true, true);
  DEBUG_LOG("Received a %s of size %zu B", nalu_type_to_str(&nalu_info), nalu_size);
  self->validation_flags.has_auth_result = false;

  self->accumulated_validation->number_of_received_nalus++;
  const bool nalus_pending_registration = !self->validation_flags.hash_algo_known;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // If there is no |nalu_list| we failed allocating memory for it.
    OMS_THROW_IF_WITH_MSG(!nalu_list, OMS_MEMORY, "Cannot validate authenticity");
    // Append the |nalu_list| with a new item holding a pointer to |nalu_info|. The
    // |validation_status| is set accordingly.
    OMS_THROW(nalu_list_append(nalu_list, &nalu_info));
    OMS_THROW_IF(nalu_info.is_valid < 0, OMS_UNKNOWN_FAILURE);
    update_validation_flags(&self->validation_flags, &nalu_info);
    OMS_THROW(register_nalu(self, nalu_list->last_item));
    // As soon as the first Media Signing SEI arrives (|signing_present| is true) and the
    // crypto TLV tag has been decoded it is feasible to hash the temporarily stored NAL
    // Units.
    if (nalus_pending_registration && self->validation_flags.hash_algo_known) {
      // Note: This is a temporary solution.
      // TODO: Handling of the golden SEI should be moved inside the
      // |prepare_for_validation| API.
      // if (nalu_info.is_golden_sei) {
      //   prepare_for_validation(self);
      //   validate_golden_sei(self, nalu_list);
      // }
      DEBUG_LOG("Got Hash algorithm, hence reregister NAL Units");
      OMS_THROW(reregister_nalus(self));
    }
    OMS_THROW(maybe_validate_gop(self, &nalu_info));
  OMS_CATCH()
  OMS_DONE(status)

  // Need to make a copy of the |nalu_info| independently of failure.
  oms_rc copy_nalu_status =
      nalu_list_copy_last_item(nalu_list, self->validation_flags.hash_algo_known);
  // Make sure to return the first failure if both operations failed.
  status = (status == OMS_OK) ? copy_nalu_status : status;
  if (status != OMS_OK) {
    nalu_list->last_item->validation_status = 'E';
  }

  free(nalu_info.nalu_wo_epb);

  return status;
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_and_authenticate(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    onvif_media_signing_authenticity_t **authenticity)
{
  if (!self || !nalu || nalu_size == 0) {
    return OMS_INVALID_PARAMETER;
  }

  // TODO: Start on first successfully parsed NAL Unit?
  self->authentication_started = true;

  // If the user requests an authenticity report, initialize to NULL.
  if (authenticity) {
    *authenticity = NULL;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(create_local_authenticity_report_if_needed(self));
    OMS_THROW(add_nalu_and_validate(self, nalu, nalu_size));

    if (self->validation_flags.has_auth_result) {
      update_authenticity_report(self);
      if (authenticity) {
        *authenticity = onvif_media_signing_get_authenticity_report(self);
      }
      // Reset the timestamp for the next report.
      // self->latest_validation->has_timestamp = false;
    }
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}
