/**
 * MIT License
 *
 * Copyright (c) 2024 ONVIF. All rights reserved.
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

#include <assert.h>  // assert
#include <stdlib.h>  // free, size_t

#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_validator.h"
#include "oms_authenticity_report.h"  // create_local_authenticity_report_if_needed()
#include "oms_defines.h"
#include "oms_internal.h"
#include "oms_nalu_list.h"  // nalu_list_append()
#include "oms_tlv.h"

#define MAX_NUM_UNHASHED_GOPS 5
#define NUM_UNSIGNED_GOPS_BEFORE_VALIDATION 2

static void
verify_indiviual_hashes(onvif_media_signing_t *self, const nalu_list_item_t *sei);
static void
associate_gop(onvif_media_signing_t *self, const nalu_list_item_t *sei);
static bool
hash_is_empty(const uint8_t *hash, size_t hash_size);
static bool
verify_linked_hash(const onvif_media_signing_t *self);
static bool
verify_gop_hash(const onvif_media_signing_t *self);
static void
mark_associated_items(nalu_list_t *nalu_list,
    bool set_valid,
    bool link_ok,
    nalu_list_item_t *sei);
static bool
verify_hashes_without_sei(onvif_media_signing_t *self, int num_skip_nalus);
static void
remove_sei_association(nalu_list_t *nalu_list, const nalu_list_item_t *sei);
static void
validate_authenticity(onvif_media_signing_t *self, nalu_list_item_t *sei);
static oms_rc
maybe_update_linked_hash(onvif_media_signing_t *self, const nalu_list_item_t *sei);
static oms_rc
compute_gop_hash(onvif_media_signing_t *self, const nalu_list_item_t *sei);
static oms_rc
decode_sei_data(onvif_media_signing_t *self, const uint8_t *tlv, size_t tlv_size);
static oms_rc
prepare_for_validation(onvif_media_signing_t *self, nalu_list_item_t **sei);
static bool
has_pending_partial_gop(onvif_media_signing_t *self);
static bool
validation_is_feasible(const nalu_list_item_t *item);
static oms_rc
maybe_validate_gop(onvif_media_signing_t *self, nalu_info_t *nalu_info);
static oms_rc
reregister_nalus(onvif_media_signing_t *self);
static oms_rc
verify_sei_signature(onvif_media_signing_t *self,
    nalu_list_item_t *item,
    int *verified_result);
static void
extract_crypto_info_from_sei(onvif_media_signing_t *self, nalu_list_item_t *item);
static oms_rc
register_nalu(onvif_media_signing_t *self, nalu_list_item_t *item);
static void
update_validation_flags(validation_flags_t *validation_flags, nalu_info_t *nalu_info);
static oms_rc
add_nalu_and_validate(onvif_media_signing_t *self, const uint8_t *nalu, size_t nalu_size);

#ifdef ONVIF_MEDIA_SIGNING_DEBUG
const char *kAuthResultValidStr[OMS_AUTHENTICITY_NUM_STATES] = {
    "MEDIA SIGNING NOT PRESENT", "MEDIA SIGNING PRESENT", "NOT OK",
    "OK WITH MISSING INFO", "OK", "VERSION MISMATCH"};
#endif

/* Decodes the TLV data from a SEI and determines if there are missing SEIs. */
static oms_rc
decode_sei_data(onvif_media_signing_t *self, const uint8_t *tlv, size_t tlv_size)
{
  assert(self && tlv && (tlv_size > 0));
  // Get the last GOP counter before updating.
  int64_t last_gop_number = self->gop_info->current_partial_gop;
  int64_t exp_gop_number = last_gop_number + 1;
  int64_t previous_next_partial_gop = (int64_t)self->gop_info->next_partial_gop;
  DEBUG_LOG("SEI TLV data size = %zu, exp gop number = %ld", tlv_size, exp_gop_number);
  // Reset hash list to make sure the list does not contain old hashes if not populated.
  self->gop_info->hash_list_idx = 0;

  oms_rc status = tlv_decode(self, tlv, tlv_size);
  // TODO: Investigate if it could cause any issues if trying to detect lost SEIs if the
  // decode operation failed.

  // Compare new with last number of GOPs to detect potentially lost SEIs.
  int64_t new_gop_number = (int64_t)self->gop_info->next_partial_gop;
  if (new_gop_number < previous_next_partial_gop) {
    // There is a potential wraparound, but it could also be due to re-ordering of SEIs.
    // Use the distance to determine between which of these options is most likely.
    if (((int64_t)1 << 31) < previous_next_partial_gop - new_gop_number) {
      self->gop_info->num_partial_gop_wraparounds++;
    } else {
      new_gop_number = previous_next_partial_gop;
    }
  }
  // Compensate for counter wraparounds.
  new_gop_number += (int64_t)self->gop_info->num_partial_gop_wraparounds << 32;
  int64_t potentially_lost_seis = new_gop_number - exp_gop_number;
  // Before the first SEI it is, by definition, not possible to detect number of lost
  // SEIs.
  if (self->validation_flags.is_first_sei) {
    potentially_lost_seis = 0;
  }
  // Check if any SEIs have been lost. Wraparound of 64 bits is not feasible in practice.
  // Hence, a negative value means that an older SEI has been received.
  self->validation_flags.num_lost_seis = potentially_lost_seis;
  self->validation_flags.sei_in_sync = (potentially_lost_seis == 0);

  return status;
}

/* Verifies the hashes from a hash list associated with the |sei|.
 *
 * If the GOP hash verification failed and there is a hash list present in the associated
 * |sei| verifying individual hashes is possible. By looping through the NAL Units in the
 * |nalu_list| this function compares individual hashes with the ones in the hash list.
 * Items are marked as OK ('.') if its hash is present and in correct order.
 *
 * If missing/lost NAL Units are detected, empty items marked 'M' are added. */
static void
verify_indiviual_hashes(onvif_media_signing_t *self, const nalu_list_item_t *sei)
{
  assert(self && sei);

  const size_t hash_size = self->verify_data->hash_size;
  assert(hash_size > 0);
  // Expected hashes.
  uint8_t *expected_hashes = self->gop_info->hash_list;
  const int num_expected_hashes = self->gop_info->hash_list_idx / hash_size;

  nalu_list_t *nalu_list = self->nalu_list;

  if (!expected_hashes || !nalu_list) {
    return;
  }

  // Statistics tracked while verifying hashes.
  int num_invalid_nalus_since_latest_match = 0;
  int num_verified_hashes = 0;
  // Initialization
  int latest_match_idx = -1;  // The latest matching hash in |hash_list|
  int compare_idx = 0;  // The offset in |hash_list| selecting the hash to compared
                        // against the |item->hash|
  nalu_list_item_t *item = nalu_list->first_item;
  // This while-loop selects items from the |nalu_list|. Each (associated) item hash is
  // then verified against the feasible hashes in the received |hash_list|.
  while (item) {
    if (self->gop_info->triggered_partial_gop &&
        !(num_verified_hashes < num_expected_hashes)) {
      break;
    }
    // Due to causuality it is not possible to validate NAL Units after the associated
    // SEI.
    if (item == sei) {
      break;
    }
    // If this item is not pending, or not associated with this SEI, move to the next one.
    if (item->validation_status != 'P' || item->associated_sei != sei) {
      item = item->next;
      continue;
    }
    // Only a missing item has a null pointer NALU, but they are skipped.
    assert(item->nalu_info);
    // If this is a signed SEI, it is not part of the hash list and should not be
    // verified.
    if (item->nalu_info->is_oms_sei && item->nalu_info->is_signed) {
      item = item->next;
      continue;
    }

    num_verified_hashes++;

    // Compare |item->hash| against all the |expected_hashes| starting from the
    // |latest_match_idx|. Stop when there is a match or reach the end.
    compare_idx = latest_match_idx + 1;
    // This while-loop searches for a match among the feasible hashes in |hash_list|.
    while (compare_idx < num_expected_hashes) {
      uint8_t *expected_hash = &expected_hashes[compare_idx * hash_size];

      if (memcmp(item->hash, expected_hash, hash_size) == 0) {
        // There is a match. Set validation_status and add missing NAL Units if that has
        // been detected.
        if (sei->nalu_info->is_signed) {
          item->validation_status = sei->validation_status;
        } else {
          item->validation_status_if_sei_ok = sei->validation_status_if_sei_ok;
        }
        // Add missing items to |nalu_list|.
        int num_detected_missing_nalus =
            (compare_idx - latest_match_idx) - 1 - num_invalid_nalus_since_latest_match;
        // No need to check the return value. A failure only affects the statistics. In
        // the worst case OMS_AUTHENTICITY_OK is sent instead of
        // OMS_AUTHENTICITY_OK_WITH_MISSING_INFO.
        // TODO: Do this properly.
        nalu_list_add_missing_items(
            nalu_list, num_detected_missing_nalus, false, item, sei);
        // Reset counters and latest_match_idx.
        latest_match_idx = compare_idx;
        num_invalid_nalus_since_latest_match = 0;
        num_verified_hashes += num_detected_missing_nalus;
        break;
      }
      compare_idx++;
    }  // Done comparing feasible hashes.

    // Handle the non-match case.
    if (latest_match_idx != compare_idx) {
      if (sei->nalu_info->is_signed) {
        item->validation_status = 'N';
      } else {
        item->validation_status_if_sei_ok = 'N';
      }
      // Update counters.
      num_invalid_nalus_since_latest_match++;
    }
    item = item->next;
  }  // Done looping through pending GOP.

  // If fewer hashes were verified than expected, add missing items at end of GOP.
  int num_missing_hashes = num_expected_hashes - num_verified_hashes;
  nalu_list_add_missing_items_at_end_of_partial_gop(nalu_list, num_missing_hashes, sei);

  // Remove SEI associations which were never used. This happens if there are missing NAL
  // Units within a partial GOP.
  while (item) {
    if (item->associated_sei == sei) {
      item->associated_sei = NULL;
      self->tmp_num_nalus_in_partial_gop--;
    }
    item = item->next;
  }
  // TODO: Investigate if we need to take special actions if there are no matches at all.
  // Check if there were no matches at all. See if any missing NAL Units shold be added.
  // This is of less importance since the GOP is not authentic, but it would provide
  // proper statistics.
}

/* Verifying hashes without the SEI means that there is nothing to verify against.
 * Therefore, mark all NAL Units of the oldest pending GOP with |validation_status| = 'N',
 * or 'U' if video is unsigned.
 * This function is used both for unsigned videos as well as when the SEI has been
 * modified or lost. */
static bool
verify_hashes_without_sei(onvif_media_signing_t *self, int num_skip_nalus)
{
  assert(self);
  nalu_list_t *nalu_list = self->nalu_list;
  if (!nalu_list) {
    return false;
  }

  // If there should be unmarked NAL Units in the GOP, for example, if a GOP is split in
  // several partial GOPs, determine the maximum of NAL Units to verify as 'N'.
  int num_gop_starts = 0;
  int num_nalus_in_gop = 0;
  // There could be more then one GOP present, e.g., when a SEI is lost. Therefore, track
  // both the total number of NAL Units of complete GOPs as well as the number of NAL
  // Units of the first GOP. The first GOP is the one to mark as validated.
  int num_nalus_in_first_gop = 0;
  int num_nalus_in_all_gops = 0;
  nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    // Skip non-pending items and items already associated with a SEI.
    if (item->validation_status != 'P' || item->associated_sei) {
      item = item->next;
      continue;
    }

    nalu_info_t *nalu_info = item->nalu_info;
    // Only (added) items marked as 'missing' ('M') have no |nalu_info|.
    assert(nalu_info);
    if (nalu_info->is_oms_sei && nalu_info->is_signed) {
      // Skip counting signed SEIs since they are verified by its signature.
      item = item->next;
      continue;
    }

    num_gop_starts += nalu_info->is_first_nalu_in_gop;
    if (nalu_info->is_first_nalu_in_gop && (num_gop_starts > 1)) {
      // Store |num_nalus_in_gop| and reset for the next GOP.
      num_nalus_in_all_gops += num_nalus_in_gop;
      if (num_nalus_in_first_gop == 0) {
        num_nalus_in_first_gop = num_nalus_in_gop;
      }
      num_nalus_in_gop = 0;
    }

    num_nalus_in_gop++;
    item = item->next;
  }

  // Determine number of items to mark given number of NAL Units to skip.
  int num_marked_items = 0;
  int max_marked_items = num_nalus_in_first_gop;
  if (num_nalus_in_all_gops == num_nalus_in_first_gop) {
    // Only one GOP present. Skip NAL Units from first GOP.
    max_marked_items -= num_skip_nalus;
    if (max_marked_items < 0) {
      max_marked_items = 0;
    }
  }

  // Start from the oldest item and mark all pending items as NOT OK ('N') until
  // |max_marked_items| have been marked.
  item = nalu_list->first_item;
  while (item && (num_marked_items < max_marked_items)) {
    // Skip non-pending items and items already associated with a SEI.
    if (item->validation_status != 'P' || item->associated_sei) {
      item = item->next;
      continue;
    }

    nalu_info_t *nalu_info = item->nalu_info;
    if (nalu_info->is_oms_sei && nalu_info->is_signed) {
      // Skip marking signed SEIs since they are verified by its signature.
      item = item->next;
      continue;
    }

    item->validation_status = self->validation_flags.signing_present ? 'N' : 'U';
    item->validation_status_if_sei_ok = ' ';
    if (item->nalu_info && item->nalu_info->is_oms_sei) {
      mark_associated_items(nalu_list, false, false, item);
    }

    num_marked_items++;
    item = item->next;
  }

  return (num_marked_items > 0);
}

static bool
verify_gop_hash(const onvif_media_signing_t *self)
{
  assert(self);
  const size_t hash_size = self->verify_data->hash_size;
  const uint8_t *computed_gop_hash = self->tmp_partial_gop_hash;
  const uint8_t *received_gop_hash = self->gop_info->partial_gop_hash;
  return memcmp(computed_gop_hash, received_gop_hash, hash_size) == 0;
}

static bool
hash_is_empty(const uint8_t *hash, size_t hash_size)
{
  const uint8_t no_linked_hash[MAX_HASH_SIZE] = {0};
  return (memcmp(hash, no_linked_hash, hash_size) == 0);
}

static bool
verify_linked_hash(const onvif_media_signing_t *self)
{
  assert(self);
  const size_t hash_size = self->verify_data->hash_size;
  const uint8_t *computed_linked_hash = self->gop_info->linked_hash;
  const uint8_t *received_linked_hash = self->tmp_linked_hash;
  return ((memcmp(computed_linked_hash, received_linked_hash, hash_size) == 0) ||
      hash_is_empty(computed_linked_hash, hash_size));
}

/* Validates the authenticity given a |sei| and the |nalu_list|.
 *
 * In brief, validates using the SEI if possible, otherwise without. This happens if SEIs
 * are lost or reordered.
 * If validating with the SEI, first try the gop_hash before using the hash_list, if
 * present in the SEI, to speed up and simplify the process.
 * Verifying a hash means comparing two and check if they are identical.
 *
 * The process mark items as either 'N' (not OK), '.' (OK), or possibly 'U' (unknown).
 * Later, statistics and validation statistics are gathered from thes validation statuses.
 *
 * If during verification missing NAL Units are detected, empty items (marked 'M') are
 * added to the |nalu_list|. */
static void
validate_authenticity(onvif_media_signing_t *self, nalu_list_item_t *sei)
{
  assert(self);
  onvif_media_signing_latest_validation_t *latest = self->latest_validation;
  MediaSigningAuthenticityResult valid = OMS_AUTHENTICITY_NOT_OK;
  // Initialize to "Unknown"
  int num_expected_nalus = self->gop_info->num_sent_nalus;
  int num_received_nalus = self->tmp_num_nalus_in_partial_gop;
  int num_invalid_nalus = -1;
  int num_missed_nalus = -1;
  bool verify_success = false;

  if (self->validation_flags.num_lost_seis > 0) {
    DEBUG_LOG("Lost a SEI. Mark (partial) GOP as not authentic.");
    remove_sei_association(self->nalu_list, sei);
    sei = NULL;
    verify_success = verify_hashes_without_sei(self, num_expected_nalus);
    // If a GOP was verified without a SEI, increment the |current_partial_gop|.
    if (self->validation_flags.signing_present && verify_success) {
      self->gop_info->current_partial_gop++;
    }
    num_expected_nalus = -1;
  } else if (self->validation_flags.num_lost_seis < 0) {
    DEBUG_LOG("Found an old SEI. Mark (partial) GOP as not authentic.");
    remove_sei_association(self->nalu_list, sei);
    sei = NULL;
    verify_success = verify_hashes_without_sei(self, 0);
    num_expected_nalus = -1;
  } else {
    bool sei_is_maybe_ok = (!sei->nalu_info->is_signed ||
        (sei->nalu_info->is_signed && sei->verified_signature == 1));
    bool gop_hash_ok = verify_gop_hash(self);
    bool linked_hash_ok = verify_linked_hash(self);
    self->validation_flags.sei_in_sync |= linked_hash_ok;
    // For complete and successful validation both the GOP hash and the linked hash have
    // to be correct (given that the signature could be verified successfully of course).
    // If the gop hash could not be verified correct, there is a second chance by
    // verifying individual hashes, if a hash list was sent in the SEI.
    verify_success = gop_hash_ok && sei_is_maybe_ok;
    if (linked_hash_ok && !gop_hash_ok && self->gop_info->hash_list_idx > 0) {
      // If the GOP hash could not successfully be verified and a hash list was
      // transmitted in the SEI, verify individual hashes.
      DEBUG_LOG("GOP hash could not be verified. Verifying individual hashes.");
      // Associate more items, since the failure can be due to added NAL Units.
      associate_gop(self, sei);
      verify_indiviual_hashes(self, sei);
      if (sei->nalu_info->is_signed) {
        // If the SEI is signed mark previous GOPs if there are any.
        mark_associated_items(self->nalu_list, true, linked_hash_ok, sei);
      }
    } else {
      nalu_list_add_missing_items_at_end_of_partial_gop(
          self->nalu_list, num_expected_nalus - num_received_nalus, sei);
      mark_associated_items(self->nalu_list, verify_success, linked_hash_ok, sei);
    }
  }

  // Collect statistics from the nalu_list. This is used to validate the GOP, verified
  // using the |sei|, and provide additional information to the user.
  bool has_valid_nalus =
      nalu_list_get_stats(self->nalu_list, sei, &num_invalid_nalus, &num_missed_nalus);
  // Stats may be collected across multiple GOPs, therefore, remove previous stats
  // when deciding upon validation result.
  num_invalid_nalus -= self->validation_flags.num_invalid_nalus;
  // TODO: Workaround for special cases where intermediate GOPs are verified without SEI.
  if (num_invalid_nalus < 0) {
    num_invalid_nalus = 0;
  }
  self->validation_flags.num_invalid_nalus += num_invalid_nalus;
  DEBUG_LOG("Number of invalid NAL Units = %d.", num_invalid_nalus);
  DEBUG_LOG("Number of missed NAL Units = %d.", num_missed_nalus);
  // Update the counted NAL Units part of this validation, since it may have changed.
  num_received_nalus = self->tmp_num_nalus_in_partial_gop;

  valid = (num_invalid_nalus > 0) ? OMS_AUTHENTICITY_NOT_OK : OMS_AUTHENTICITY_OK;

  // Determine if this GOP is valid, but has missing information.
  if (valid == OMS_AUTHENTICITY_OK && (num_missed_nalus > 0)) {  //} && verify_success)) {
    valid = OMS_AUTHENTICITY_OK_WITH_MISSING_INFO;
    DEBUG_LOG("Successful validation, but detected missing NAL Units");
  }

  // The very first validation needs to be handled separately. If this truly is the start
  // of a stream all necessary information to successfully validate the authenticity is
  // present. It can be interpreted as being in sync with its signing counterpart. If this
  // session validates the authenticity of a segment in the middle of a stream, e.g., an
  // exported file, the start of validation is out of sync. The first SEI may be
  // associated with a GOP prior to this segment.
  size_t hash_size = self->verify_data->hash_size;
  uint8_t *computed_linked_hash = self->gop_info->linked_hash;
  const uint8_t *received_linked_hash = self->tmp_linked_hash;
  bool is_start_of_stream = hash_is_empty(received_linked_hash, hash_size);
  if (self->validation_flags.is_first_validation &&
      (!is_start_of_stream ||
          (is_start_of_stream && self->validation_flags.lost_start_of_gop))) {
    if (valid != OMS_AUTHENTICITY_OK && !has_valid_nalus) {
      // If the first validation failed and no valid NAL Units were found the SEI belongs
      // to a GOP the is not present in this part of the stream. Reverse any validation
      // and mark as OMS_AUTHENTICITY_NOT_FEASIBLE instead.
      DEBUG_LOG("This first validation cannot be performed");
      remove_sei_association(self->nalu_list, sei);
      valid = OMS_AUTHENTICITY_NOT_FEASIBLE;
      num_expected_nalus = -1;
      num_received_nalus = -1;
      memcpy(computed_linked_hash + hash_size, computed_linked_hash, hash_size);
    }
  }

  if (latest->public_key_has_changed) {
    valid = OMS_AUTHENTICITY_NOT_OK;
  }

  if (valid == OMS_AUTHENTICITY_OK) {
    self->validation_flags.sei_in_sync = true;
  }
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
  latest->number_of_received_hashable_nalus += num_received_nalus;
  if (self->validation_flags.num_lost_seis > 0) {
    latest->number_of_expected_hashable_nalus = -1;
  } else if (latest->number_of_expected_hashable_nalus != -1) {
    latest->number_of_expected_hashable_nalus += num_expected_nalus;
  }
  // Update |current_partial_gop| and |num_lost_seis| w.r.t. if SEI is in sync.
  if (self->validation_flags.sei_in_sync) {
    self->gop_info->current_partial_gop = self->gop_info->next_partial_gop;
    self->validation_flags.num_lost_seis = 0;
  } else {
    self->validation_flags.num_lost_seis =
        self->gop_info->next_partial_gop - self->gop_info->current_partial_gop - 1;
  }
}

/* Removes the association with a specific SEI from the items. */
static void
remove_sei_association(nalu_list_t *nalu_list, const nalu_list_item_t *sei)
{
  if (!nalu_list) {
    return;
  }

  nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    if (sei && item->associated_sei == sei) {
      if (item->validation_status == 'M') {
        const nalu_list_item_t *item_to_remove = item;
        item = item->next;
        nalu_list_remove_and_free_item(nalu_list, item_to_remove);
        continue;
      }
      item->associated_sei = NULL;
      item->validation_status_if_sei_ok = ' ';
      item->validation_status = 'P';
    }
    item = item->next;
  }
}

/* Associates partial GOP with the set SEI. */
static void
associate_gop(onvif_media_signing_t *self, const nalu_list_item_t *sei)
{
  if (!sei) {
    return;
  }

  assert(self);
  if (!self->gop_info->triggered_partial_gop) {
    // This operation is only valid if the GOP has been split in parts.
    return;
  }

  // Loop through the items of |nalu_list| and associate the remaining items in the same
  // partial GOP.
  nalu_list_item_t *item = self->nalu_list->first_item;
  nalu_list_item_t *next_hashable_item = NULL;
  while (item) {
    // Due to causuality it is not possible to validate NAL Units after the associated
    // SEI.
    if (item == sei) {
      break;
    }
    // If this item is not pending, or already associated with this |sei|, move to the
    // next one.
    if (item->validation_status != 'P' || item->associated_sei) {
      item = item->next;
      continue;
    }
    // Stop if a new GOP is found.
    if (item->nalu_info->is_first_nalu_in_gop) {
      break;
    }
    // Stop if the current |item| is the last hashable in the GOP, otherwise no other
    // partial GOP is feasible.
    next_hashable_item = nalu_list_item_get_next_hashable(item);
    if (next_hashable_item && next_hashable_item->nalu_info->is_first_nalu_in_gop) {
      break;
    }
    // If this is a signed SEI it is skipped.
    if (item->nalu_info->is_oms_sei && item->nalu_info->is_signed) {
      item = item->next;
      continue;
    }

    // Mark the item and move to next.
    self->tmp_num_nalus_in_partial_gop++;  // Indicates how many items have been marked
    item->associated_sei = sei;
    item = item->next;
  }
}

/* Marks items associated with |sei| as |valid| (or overridden by the SEI verification)
 * recursively. */
static void
mark_associated_items(nalu_list_t *nalu_list,
    bool set_valid,
    bool link_ok,
    nalu_list_item_t *sei)
{
  if (!nalu_list) {
    return;
  }

  bool is_first_associated_item = true;
  nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    if (item->associated_sei == sei) {
      bool valid = set_valid && (is_first_associated_item ? link_ok : true);
      if (sei->validation_status_if_sei_ok != ' ') {
        bool valid_if_sei_ok = !(item->validation_status_if_sei_ok == 'N');
        item->validation_status_if_sei_ok = (valid && valid_if_sei_ok) ? '.' : 'N';
      } else {
        bool valid_if_sei_ok = !(item->validation_status_if_sei_ok == 'N');
        if (item->validation_status == 'P') {
          item->validation_status = (valid && valid_if_sei_ok) ? '.' : 'N';
        }
        item->validation_status_if_sei_ok = ' ';
        if (item->nalu_info && item->nalu_info->is_oms_sei) {
          mark_associated_items(nalu_list, valid && valid_if_sei_ok, link_ok, item);
        }
      }
      is_first_associated_item = false;
    }
    item = item->next;
  }
}

/* Computes the gop_hash of the oldest pending GOP in the nalu_list and associates all
 * used items with the |sei|. */
static oms_rc
compute_gop_hash(onvif_media_signing_t *self, const nalu_list_item_t *sei)
{
  assert(self);

  nalu_list_t *nalu_list = self->nalu_list;

  // Expect a valid SEI and that it has been decoded.
  if (!(sei && sei->has_been_decoded)) {
    return OMS_INVALID_PARAMETER;
  }
  if (!nalu_list) {
    return OMS_INVALID_PARAMETER;
  }

  nalu_list_item_t *item = NULL;
  gop_info_t *gop_info = self->gop_info;

  nalu_list_print(nalu_list);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Initialize the gop_hash by resetting it.
    OMS_THROW(reset_gop_hash(self));
    // Loop through the items of |nalu_list| until the end of a partial GOP is found.
    int num_gop_starts = 0;
    item = nalu_list->first_item;
    while (item) {
      // Due to causuality it is not possible to validate NAL Units after the associated
      // SEI.
      if (item == sei) {
        break;
      }
      // If this item is not pending, move to the next one.
      if (item->validation_status != 'P' || item->associated_sei) {
        item = item->next;
        continue;
      }
      // Only missing items can have a null pointer |nalu_info|, but they are not pending.
      assert(item->nalu_info);
      // Check if this |is_first_nalu_in_gop| and increment the GOP start counter.
      num_gop_starts += item->nalu_info->is_first_nalu_in_gop;
      if (num_gop_starts > 1) {
        // A GOP hash can at most include one entire GOP.
        break;
      }
      if (item->nalu_info->is_first_nalu_in_gop &&
          self->tmp_num_nalus_in_partial_gop > 0) {
        break;
      }
      // If this is the SEI associated with the GOP and has a signature it is skipped.
      if (item->nalu_info->is_oms_sei && item->nalu_info->is_signed) {
        item = item->next;
        continue;
      }
      // Skip NAL Units when exceeding the amount that the SEI has reported in the partial
      // GOP if the SEI was triggered by a partial GOP.
      if (gop_info->triggered_partial_gop &&
          (self->tmp_num_nalus_in_partial_gop >= gop_info->num_sent_nalus)) {
        break;
      }

      // Update the onging gop_hash with this NAL Unit hash.
      OMS_THROW(update_gop_hash(self->crypto_handle, item->hash));
      self->tmp_num_nalus_in_partial_gop++;

      // Mark the item and move to next.
      item->associated_sei = sei;
      item = item->next;
    }
    assert(item);  // Should have stopped latest at |sei|.
    if (!gop_info->triggered_partial_gop && !item->nalu_info->is_first_nalu_in_gop) {
      DEBUG_LOG("Lost an I-frame");
      self->validation_flags.lost_start_of_gop = true;
    }
    OMS_THROW(finalize_gop_hash(self->crypto_handle, self->tmp_partial_gop_hash));
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
    oms_print_hex_data(gop_info->partial_gop_hash, self->verify_data->hash_size,
        "Received (partial) GOP hash: ");
#endif
  OMS_CATCH()
  {
    // TODO: This should be done outside this function.
    // Failed computing the gop_hash. Remove all markers.
    remove_sei_association(nalu_list, sei);
  }
  OMS_DONE(status)

  return status;
}

/* Update the queue of linked hashes. */
static oms_rc
maybe_update_linked_hash(onvif_media_signing_t *self, const nalu_list_item_t *sei)
{
  assert(self);

  // Expect a valid SEI and that it has been decoded.
  if (!(sei && sei->has_been_decoded))
    return OMS_INVALID_PARAMETER;
  if (!self->nalu_list)
    return OMS_INVALID_PARAMETER;

  nalu_list_item_t *item = self->nalu_list->first_item;
  const size_t hash_size = self->verify_data->hash_size;

  // The first pending NAL Unit, prior in order to the |sei|, should be the pending
  // linked hash.
  while (item) {
    // If this item is not pending, move to the next one.
    if (item->validation_status != 'P' || item->validation_status_if_sei_ok != ' ') {
      item = item->next;
      continue;
    }
    if (item == sei) {
      break;
    }

    update_linked_hash(self, item->hash, hash_size);
    break;
  }
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
  oms_print_hex_data(self->gop_info->linked_hash, hash_size, "Computed linked hash: ");
  oms_print_hex_data(self->tmp_linked_hash, hash_size, "Received linked hash: ");
#endif

  return OMS_OK;
}

/* prepare_for_validation()
 *
 * 1) finds the oldest available and pending SEI in the |nalu_list|.
 * 2) decodes the TLV data from it if it has not been done already.
 * 3) computes the gop_hash from hashes in the |nalu_list|.
 * 4) updates the linked hash if possible. */
static oms_rc
prepare_for_validation(onvif_media_signing_t *self, nalu_list_item_t **sei)
{
  assert(self);

  validation_flags_t *validation_flags = &(self->validation_flags);
  nalu_list_t *nalu_list = self->nalu_list;
  sign_or_verify_data_t *verify_data = self->verify_data;
  const size_t hash_size = verify_data->hash_size;

  *sei = nalu_list_get_next_sei_item(nalu_list);
  if (!(*sei)) {
    // No reason to proceed with preparations if no pending SEI is found.
    return OMS_OK;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    if (!(*sei)->has_been_decoded) {
      // Decode the SEI and set signature->hash
      const uint8_t *tlv_data = (*sei)->nalu_info->tlv_data;
      size_t tlv_size = (*sei)->nalu_info->tlv_size;

      OMS_THROW_WITH_MSG(
          decode_sei_data(self, tlv_data, tlv_size), "Failed decoding SEI TLV data");
      (*sei)->has_been_decoded = true;
      memcpy(verify_data->hash, (*sei)->hash, hash_size);
    }
    if (validation_flags->num_lost_seis == 0) {
      if ((*sei)->nalu_info->is_signed) {
        (*sei)->validation_status = (*sei)->verified_signature == 1 ? '.' : 'N';
      } else {
        (*sei)->validation_status_if_sei_ok = '.';
      }
      validation_flags->validate_certificate_sei = (*sei)->nalu_info->is_certificate_sei;
    } else if (validation_flags->num_lost_seis < 0) {
      if ((*sei)->nalu_info->is_signed) {
        (*sei)->validation_status = 'N';
      } else {
        (*sei)->validation_status_if_sei_ok = 'N';
      }
      validation_flags->validate_certificate_sei = (*sei)->nalu_info->is_certificate_sei;
    }
    if (!validation_flags->validate_certificate_sei) {
      OMS_THROW(compute_gop_hash(self, *sei));
      OMS_THROW(maybe_update_linked_hash(self, *sei));
    } else {
      self->latest_validation->authenticity =
          (*sei)->verified_signature == 1 ? OMS_AUTHENTICITY_OK : OMS_AUTHENTICITY_NOT_OK;
    }

    OMS_THROW_IF_WITH_MSG(validation_flags->signing_present && !self->has_public_key,
        OMS_NOT_SUPPORTED, "No public key present");

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

// If this is a Media Signing generated SEI, including a signature, decode all the
// optional TLV information and verify the signature.
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
  nalu_list_item_t *item = self->nalu_list->first_item;
  // Statistics collected while looping through the NAL Units.
  int num_detected_gop_starts = 0;
  bool found_pending_signed_oms_sei = false;
  bool found_pending_oms_sei = false;
  bool found_pending_gop = false;

  while (item && !found_pending_gop && !found_pending_signed_oms_sei) {
    nalu_info_t *nalu_info = item->nalu_info;
    if (!nalu_info || item->validation_status_if_sei_ok != ' ') {
      // Missing item or already validated item with an unsigned SEI; move on
      item = item->next;
      continue;
    }
    // Certificate SEIs can, and should, be validated at once.
    found_pending_gop = (item->validation_status == 'P' && nalu_info->is_certificate_sei);
    // Collect statistics from pending and hashable NAL Units only. The others are either
    // out of date or not part of the validation.
    if (item->validation_status == 'P' && nalu_info->is_hashable) {
      num_detected_gop_starts += nalu_info->is_first_nalu_in_gop;
      found_pending_oms_sei |= nalu_info->is_oms_sei;
      found_pending_signed_oms_sei |= (nalu_info->is_oms_sei && nalu_info->is_signed);
    }
    if (!self->validation_flags.signing_present) {
      // If the video is not signed at least 2 I-frames are needed to have a complete GOP.
      found_pending_gop |= (num_detected_gop_starts >= 2);
    } else {
      // When the video is signed it is time to validate when there is at least one
      // partial GOP and a Media Signing generated SEI.
      found_pending_gop |= (num_detected_gop_starts > 0) && found_pending_oms_sei;
    }
    item = item->next;
  }

  return found_pending_gop || found_pending_signed_oms_sei;
}

/* Determines if the |item| is up for a validation.
 * The NAL Unit should be hashable and pending validation.
 * If so, validation is triggered on any of the below
 *   - a SEI (since if the SEI arrives late, the SEI is the final piece for validation)
 *   - a new I-frame (since this marks the end of a GOP)
 *   - TODO: A SEI could be moved to its associated GOP by prepending the last NAL Unit.
 *     If so, another NAL Unit is required for complete validation. */
static bool
validation_is_feasible(const nalu_list_item_t *item)
{
  if (!item->nalu_info || !item->nalu_info->is_hashable) {
    return false;
  }
  if (item->validation_status != 'P') {
    return false;
  }

  // Validation may be done upon a SEI.
  if (item->nalu_info->is_oms_sei) {
    return true;
  }
  // Validation may be done upon the end of a GOP.
  if (item->nalu_info->is_first_nalu_in_gop) {
    return true;
  }
  // NOTE: This is only possible if the client side is allowed to move a SEI to its
  // associated GOP.
  // Validation may be done upon a hashable NAL Unit right after a SEI.
#ifdef SUPPORT_MOVING_SEI_TO_ASSOCIATED_OP
  item = item->prev;
  while (item) {
    if (item->nalu_info && item->nalu_info->is_hashable) {
      break;
    }
    item = item->prev;
  }
  if (item && item->nalu_info->is_oms_sei && item->validation_status == 'P') {
    return true;
  }
#endif

  return false;
}

/* Validates the authenticity of the video since last time if possible. */
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
  // Make sure there is enough information to perform validation, such as havning a Public
  // key.
  validation_feasible &= self->has_public_key ||
      (!validation_flags->signing_present &&
          validation_flags->num_gop_starts > NUM_UNSIGNED_GOPS_BEFORE_VALIDATION);

  // Abort if validation is not feasible.
  if (!validation_feasible) {
    // If this is the first arrived SEI, but could still not validate the authenticity,
    // signal to the user that the Media Signing has been detected.
    if (validation_flags->is_first_sei && nalu_info->is_oms_sei) {
      latest->authenticity = OMS_AUTHENTICITY_NOT_FEASIBLE;
      latest->number_of_expected_hashable_nalus = -1;
      latest->number_of_received_hashable_nalus = -1;
      latest->number_of_pending_hashable_nalus =
          nalu_list_num_pending_items(nalu_list, NULL);
      latest->public_key_has_changed = false;
      self->validation_flags.has_auth_result = true;
      validation_flags->is_first_sei = false;
    }
    return OMS_OK;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    bool public_key_has_changed = false;
    // TODO: Keep a safe guard for infinite loops until "safe". Then remove.
    int max_loop = 10;
    // Keep validating as long as there are pending GOPs.
    bool stop_validating = false;
    while (has_pending_partial_gop(self) && !stop_validating && max_loop > 0) {
      nalu_list_item_t *sei = NULL;
      // Initialize latest validation if not validating intermediate GOPs.
      if (!validation_flags->waiting_for_signature &&
          !validation_flags->has_auth_result) {
        latest->authenticity = OMS_AUTHENTICITY_NOT_FEASIBLE;
        latest->number_of_expected_hashable_nalus = 0;
        latest->number_of_received_hashable_nalus = 0;
        latest->number_of_pending_hashable_nalus = -1;
        // TODO: Move to prepare_for_validation()
        latest->public_key_has_changed = public_key_has_changed;
        validation_flags->num_invalid_nalus = 0;
        validation_flags->lost_start_of_gop = false;
      }

      OMS_THROW(prepare_for_validation(self, &sei));

      if (!validation_flags->signing_present) {
        latest->authenticity = OMS_NOT_SIGNED;
        latest->number_of_expected_hashable_nalus = -1;
        latest->number_of_received_hashable_nalus = -1;
        // Since no validation is performed (all items are kept pending) a forced stop is
        // introduced to avoid a dead lock.
        stop_validating = true;
      } else if (!validation_flags->validate_certificate_sei) {
        validate_authenticity(self, sei);
      }

      // Update the provenance.
      switch (self->verified_pubkey) {
        case 1:
          latest->provenance = openssl_has_trusted_certificate(self->crypto_handle, false)
              ? OMS_PROVENANCE_OK
              : OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED;
          break;
        case 0:
          latest->provenance = OMS_PROVENANCE_NOT_OK;
          break;
        case -1:
        default:
          latest->provenance = OMS_PROVENANCE_NOT_FEASIBLE;
          break;
      }
      // The flag |is_first_validation| is used to ignore the first validation if the
      // validation starts in the middle of a stream. Now it is time to reset it.
      validation_flags->is_first_validation = !validation_flags->signing_present;
      validation_flags->is_first_sei &= !nalu_info->is_oms_sei;

      if (!validation_flags->waiting_for_signature) {
        self->gop_info->verified_signature = -1;
        validation_flags->has_auth_result = true;
        validation_flags->validate_certificate_sei = false;
        // All statistics but pending NAL Units have already been collected.
        latest->number_of_pending_hashable_nalus =
            nalu_list_num_pending_items(nalu_list, NULL);

        DEBUG_LOG("Validated GOP as %s", kAuthResultValidStr[latest->authenticity]);
        DEBUG_LOG("Expected NAL Units = %d", latest->number_of_expected_hashable_nalus);
        DEBUG_LOG("Received NAL Units = %d", latest->number_of_received_hashable_nalus);
        DEBUG_LOG(" Pending NAL Units = %d", latest->number_of_pending_hashable_nalus);
      }
      if (latest->authenticity == OMS_NOT_SIGNED) {
        // Only report "stream is unsigned" in the accumulated report.
        validation_flags->has_auth_result = false;
      }
      if (latest->authenticity == OMS_AUTHENTICITY_NOT_FEASIBLE) {
        // Do not report "stream is signed" more than once.
        validation_flags->has_auth_result =
            latest->authenticity != self->accumulated_validation->authenticity;
      }
      // Pass on public key failure.
      public_key_has_changed |= latest->public_key_has_changed;
      max_loop--;
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
  // where the last TLV chunk is supposed to be the signature. That part should not be
  // hashed, hence re-calculate |hashable_data_size| by subtracting the number of bytes
  // (including potential emulation prevention bytes) coresponding to that tag. This is
  // done by scanning the TLV for the signature tag.
  const uint8_t *signature_tag_ptr = tlv_find_tag(nalu_info->tlv_start_in_nalu_data,
      nalu_info->tlv_size, SIGNATURE_TAG, nalu_info->with_epb);
  if (signature_tag_ptr) {
    nalu_info->hashable_data_size = signature_tag_ptr - nalu_info->hashable_data;
  }
}

/* A valid NAL Unit is registered by hashing the |item| and adding it to the |hash_list|.
 */
static oms_rc
register_nalu(onvif_media_signing_t *self, nalu_list_item_t *item)
{
  nalu_info_t *nalu_info = item->nalu_info;
  assert(self && nalu_info && nalu_info->is_valid >= 0);

  if (nalu_info->is_valid == 0) {
    return OMS_OK;
  }

  // Extract the cryptographic information like hash algorithm and certificate chain.
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
validate_certificate_sei(onvif_media_signing_t *self, nalu_list_t *nalu_list)
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
      self->latest_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
      break;
    case -1:
    default:
      // Got an error when verifying the gop_hash. Verify without a SEI.
      nalu_list->first_item->validation_status = 'E';
      self->latest_validation->authenticity = OMS_AUTHENTICITY_NOT_OK;
      self->has_public_key = false;
  }
}
#endif

static void
update_validation_flags(validation_flags_t *validation_flags, nalu_info_t *nalu_info)
{
  if (!validation_flags || !nalu_info) {
    return;
  }

  // As soon as a SEI is received, Media Signing is present.
  validation_flags->signing_present |= nalu_info->is_oms_sei;
  validation_flags->num_gop_starts += nalu_info->is_first_nalu_in_gop;
}

/* The basic order of actions are:
 * 1. Every NAL Unit should be parsed and added to the |nalu_list|.
 * 2. Update validation flags given the added NAL Unit.
 * 3. Register NAL Unit, in general that means hash the NAL Unit if it is hashable and
 * store it.
 * 4. Validate pending NAL Units if possible. */
static oms_rc
add_nalu_and_validate(onvif_media_signing_t *self, const uint8_t *nalu, size_t nalu_size)
{
  if (!self || !nalu || (nalu_size == 0)) {
    return OMS_INVALID_PARAMETER;
  }

  nalu_list_t *nalu_list = self->nalu_list;
  nalu_info_t nalu_info = parse_nalu_info(nalu, nalu_size, self->codec, true, true);
  DEBUG_LOG("Received a %s of size %zu B", nalu_type_to_str(&nalu_info), nalu_size);
  self->validation_flags.has_auth_result = false;

  self->accumulated_validation->number_of_received_nalus++;
  const bool nalus_pending_registration = !self->validation_flags.hash_algo_known;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // If there is no |nalu_list| memory could not be allocating memory. This has no
    // impact for the signing side, hence no check is done upond session creation.
    OMS_THROW_IF_WITH_MSG(!nalu_list, OMS_MEMORY, "Cannot validate authenticity");
    // Append the |nalu_list| with a new item holding a pointer to |nalu_info|. The
    // |validation_status| is set accordingly.
    OMS_THROW(nalu_list_append(nalu_list, &nalu_info));
    OMS_THROW_IF(nalu_info.is_valid < 0, OMS_UNKNOWN_FAILURE);
    update_validation_flags(&self->validation_flags, &nalu_info);
    OMS_THROW(register_nalu(self, nalu_list->last_item));
    // To limit the memory usage before any SEI has been received start hashing using the
    // default hash algorithm after |MAX_NUM_UNHASHED_GOPS|.
    if (!self->validation_flags.signing_present &&
        self->validation_flags.num_gop_starts > MAX_NUM_UNHASHED_GOPS) {
      self->validation_flags.hash_algo_known = true;
    }
    // As soon as the first Media Signing SEI arrives (|signing_present| is true) and the
    // crypto TLV tag has been decoded it is feasible to hash the temporarily stored NAL
    // Units.
    if (nalus_pending_registration && self->validation_flags.hash_algo_known) {
      DEBUG_LOG("Got Hash algorithm, re-registering NAL Units");
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
  if (status != OMS_OK && nalu_list->last_item) {
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
    }
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_trusted_certificate(onvif_media_signing_t *self,
    const char *trusted_certificate,
    size_t trusted_certificate_size,
    bool user_provisioned)
{
  if (!self || !trusted_certificate || trusted_certificate_size == 0) {
    return OMS_INVALID_PARAMETER;
  }
  if (user_provisioned) {
    // User provisioned signing is not yet supported.
    return OMS_NOT_SUPPORTED;
  }

  return openssl_set_trusted_certificate(self->crypto_handle, trusted_certificate,
      trusted_certificate_size, user_provisioned);
}
