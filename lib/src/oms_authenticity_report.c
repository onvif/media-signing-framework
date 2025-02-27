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

#include "oms_authenticity_report.h"

#include <assert.h>
#include <stdlib.h>  // calloc, free, realloc
#include <string.h>  // strlen, strcpy, size_t, memcpy

#include "oms_internal.h"  // OMS_VERSION_MAX_STRLEN
#include "oms_nalu_list.h"  // nalu_list_get_str, nalu_list_clean_up

/* Helper functions. */
static oms_rc
allocate_memory_and_copy_string(char **dst_str, const char *src_str);
/* Transfer functions. */
static oms_rc
transfer_latest_validation(onvif_media_signing_latest_validation_t *dst,
    const onvif_media_signing_latest_validation_t *src);
static void
transfer_accumulated_validation(onvif_media_signing_accumulated_validation_t *dst,
    const onvif_media_signing_accumulated_validation_t *src);
static oms_rc
transfer_authenticity(onvif_media_signing_authenticity_t *dst,
    const onvif_media_signing_authenticity_t *src);
/* Init and update functions. */
static void
authenticity_report_init(onvif_media_signing_authenticity_t *authenticity_report);
static void
update_accumulated_validation(const onvif_media_signing_latest_validation_t *latest,
    onvif_media_signing_accumulated_validation_t *accumulated);
/* Create and free functions. */
static onvif_media_signing_authenticity_t *
authenticity_report_create();
/* Setters. */
static void
set_authenticity_shortcuts(onvif_media_signing_t *self);

/**
 * Helper functions.
 */

static oms_rc
allocate_memory_and_copy_string(char **dst_str, const char *src_str)
{
  if (!dst_str) {
    return OMS_INVALID_PARAMETER;
  }
  // If the |src_str| is a NULL pointer make sure to copy an empty string.
  if (!src_str) {
    src_str = "";
  }

  size_t dst_size = *dst_str ? strlen(*dst_str) + 1 : 0;
  const size_t src_size = strlen(src_str) + 1;

  if (src_size != dst_size) {
    char *new_dst_str = realloc(*dst_str, src_size);
    if (!new_dst_str) {
      goto catch_error;
    }

    *dst_str = new_dst_str;
  }
  if (src_size == 1) {
    **dst_str = '\0';
  } else {
    strcpy(*dst_str, src_str);
  }

  return OMS_OK;

catch_error:
  free(*dst_str);
  *dst_str = NULL;

  return OMS_MEMORY;
}

/**
 * Group of functions that performs transfer operations between structs.
 */

void
transfer_vendor_info(onvif_media_signing_vendor_info_t *dst,
    const onvif_media_signing_vendor_info_t *src)
{
  // For simplicity allow nullptrs for both |dst| and |src|. If so, take no action and
  // return OMS_OK.
  if (!src || !dst) {
    return;
  }

  memcpy(dst, src, sizeof(onvif_media_signing_vendor_info_t));
}

static oms_rc
transfer_latest_validation(onvif_media_signing_latest_validation_t *dst,
    const onvif_media_signing_latest_validation_t *src)
{
  assert(dst && src);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(allocate_memory_and_copy_string(&dst->nalu_str, src->nalu_str));
    OMS_THROW(allocate_memory_and_copy_string(&dst->validation_str, src->validation_str));
    dst->authenticity_and_provenance = src->authenticity_and_provenance;
    dst->provenance = src->provenance;
    dst->public_key_has_changed = src->public_key_has_changed;
    dst->authenticity = src->authenticity;
    dst->number_of_expected_hashable_nalus = src->number_of_expected_hashable_nalus;
    dst->number_of_received_hashable_nalus = src->number_of_received_hashable_nalus;
    dst->number_of_pending_hashable_nalus = src->number_of_pending_hashable_nalus;
    dst->timestamp = src->timestamp;
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

static void
transfer_accumulated_validation(onvif_media_signing_accumulated_validation_t *dst,
    const onvif_media_signing_accumulated_validation_t *src)
{
  assert(dst && src);

  dst->authenticity_and_provenance = src->authenticity_and_provenance;
  dst->provenance = src->provenance;
  dst->public_key_has_changed = src->public_key_has_changed;
  dst->authenticity = src->authenticity;
  dst->number_of_received_nalus = src->number_of_received_nalus;
  dst->number_of_validated_nalus = src->number_of_validated_nalus;
  dst->number_of_pending_nalus = src->number_of_pending_nalus;
  dst->first_timestamp = src->first_timestamp;
  dst->last_timestamp = src->last_timestamp;
}

static oms_rc
transfer_authenticity(onvif_media_signing_authenticity_t *dst,
    const onvif_media_signing_authenticity_t *src)
{
  assert(dst && src);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    strcpy(dst->version_on_signing_side, src->version_on_signing_side);
    strcpy(dst->this_version, ONVIF_MEDIA_SIGNING_VERSION);
    transfer_vendor_info(&dst->vendor_info, &src->vendor_info);
    OMS_THROW(
        transfer_latest_validation(&dst->latest_validation, &src->latest_validation));
    transfer_accumulated_validation(
        &dst->accumulated_validation, &src->accumulated_validation);
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * Group of functions that initializes or updates structs.
 */

void
latest_validation_init(onvif_media_signing_latest_validation_t *self)
{
  // If this call is made before an authenticity report exists, e.g., if a reset is done
  // right after creating a session, or done on the signing side, then silently return.
  if (!self) {
    return;
  }

  self->authenticity_and_provenance = OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE;
  self->provenance = OMS_PROVENANCE_NOT_FEASIBLE;
  self->public_key_has_changed = false;
  self->authenticity = OMS_NOT_SIGNED;
  self->number_of_expected_hashable_nalus = -1;
  self->number_of_received_hashable_nalus = -1;
  self->number_of_pending_hashable_nalus = 0;
  self->timestamp = -1;

  free(self->nalu_str);
  self->nalu_str = NULL;
  free(self->validation_str);
  self->validation_str = NULL;
}

void
accumulated_validation_init(onvif_media_signing_accumulated_validation_t *self)
{
  // If this call is made before an authenticity report exists, e.g., if a reset is done
  // right after creating a session, or done on the signing side, then silently return.
  if (!self)
    return;

  self->authenticity_and_provenance = OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE;
  self->provenance = OMS_PROVENANCE_NOT_FEASIBLE;
  self->public_key_has_changed = false;
  if (self->authenticity != OMS_NOT_SIGNED) {
    self->authenticity = OMS_AUTHENTICITY_NOT_FEASIBLE;
  }
  self->number_of_received_nalus = 0;
  self->number_of_validated_nalus = 0;
  self->number_of_pending_nalus = 0;
  self->first_timestamp = -1;
  self->last_timestamp = -1;
}

static void
authenticity_report_init(onvif_media_signing_authenticity_t *authenticity_report)
{
  assert(authenticity_report);
  assert(!authenticity_report->version_on_signing_side);
  assert(!authenticity_report->this_version);
  authenticity_report->version_on_signing_side = calloc(1, OMS_VERSION_MAX_STRLEN);
  authenticity_report->this_version = calloc(1, OMS_VERSION_MAX_STRLEN);

  latest_validation_init(&authenticity_report->latest_validation);
  accumulated_validation_init(&authenticity_report->accumulated_validation);
}

static void
update_accumulated_validation(const onvif_media_signing_latest_validation_t *latest,
    onvif_media_signing_accumulated_validation_t *accumulated)
{
  if (latest->authenticity_and_provenance < accumulated->authenticity_and_provenance) {
    // |latest| includes a "worse" validation than |accumulated|. Update with this worse
    // result, since that is what should rule the overall combined authenticity and
    // provenance.
    accumulated->authenticity_and_provenance = latest->authenticity_and_provenance;
  }

  if (accumulated->provenance == OMS_PROVENANCE_NOT_FEASIBLE) {
    // Still either pending validation or video has no signature. Update with the result
    // from |latest|.
    accumulated->provenance = latest->provenance;
  } else if (latest->provenance < accumulated->provenance) {
    // |latest| has validated a worse provenance compared to what has been validated so
    // far. Update with this worse result, since that is what should rule the total
    // provenance.
    accumulated->provenance = latest->provenance;
  }

  if (accumulated->authenticity <= OMS_AUTHENTICITY_NOT_FEASIBLE) {
    // Still either pending validation or video has no signature. Update with the result
    // from |latest|.
    accumulated->authenticity = latest->authenticity;
  } else if (latest->authenticity < accumulated->authenticity) {
    // |latest| has validated a worse authenticity compared to what has been validated so
    // far. Update with this worse result, since that is what should rule the total
    // validation.
    accumulated->authenticity = latest->authenticity;
  }

  accumulated->public_key_has_changed |= latest->public_key_has_changed;

  // Update timestamps if possible.
  if (accumulated->first_timestamp < 0) {
    // No previous timestamp has been set.
    accumulated->first_timestamp = latest->timestamp;
  }
  accumulated->last_timestamp = latest->timestamp;
}

void
update_authenticity_report(onvif_media_signing_t *self)
{
  assert(self && self->authenticity);

  char *nalu_str = nalu_list_get_str(self->nalu_list, NALU_STR);
  char *validation_str = nalu_list_get_str(self->nalu_list, VALIDATION_STR);

  // Transfer ownership of strings to |latest_validation| after freeing previous.
  free(self->latest_validation->nalu_str);
  self->latest_validation->nalu_str = nalu_str;
  DEBUG_LOG("NAL Unit types 'oldest -> latest' = %s", nalu_str);
  free(self->latest_validation->validation_str);
  self->latest_validation->validation_str = validation_str;
  DEBUG_LOG("Validation statuses               = %s", validation_str);

  // Check for version mismatch. If |version_on_signing_side| is newer than |this_version|
  // the authenticity result may not be reliable, hence change status.
  if (onvif_media_signing_compare_versions(self->authenticity->this_version,
          self->authenticity->version_on_signing_side) == 2) {
    self->authenticity->latest_validation.authenticity =
        OMS_AUTHENTICITY_VERSION_MISMATCH;
  }
  // Determine the combined authenticity and provenance result.
  onvif_media_signing_latest_validation_t *latest =
      &self->authenticity->latest_validation;
  if (latest->provenance == OMS_PROVENANCE_NOT_OK ||
      latest->provenance == OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED ||
      latest->authenticity == OMS_AUTHENTICITY_NOT_OK) {
    // Mark the overall authenticity as NOT OK if
    // - the provenance was not verified successfully or was verified successfully
    //   without trusted certificate
    // - the authenticity was not validated successfully
    latest->authenticity_and_provenance = OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK;
  } else if (latest->provenance == OMS_PROVENANCE_NOT_FEASIBLE ||
      latest->authenticity == OMS_AUTHENTICITY_NOT_FEASIBLE ||
      latest->authenticity == OMS_AUTHENTICITY_VERSION_MISMATCH ||
      latest->authenticity == OMS_NOT_SIGNED) {
    // Mark the overall authenticity as NOT FEASIBLE if
    // - the provenance could not be verified
    // - the authenticity could not be validated
    latest->authenticity_and_provenance = OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE;
  } else if (latest->authenticity == OMS_AUTHENTICITY_OK_WITH_MISSING_INFO) {
    // Mark the overall authenticity as OK WITH MISSING INFO if
    // - the authenticity was validated successfully subject to detected missing items
    latest->authenticity_and_provenance =
        OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO;
  } else {
    latest->authenticity_and_provenance = OMS_AUTHENTICITY_AND_PROVENANCE_OK;
  }
  // Remove validated items from the list.
  const unsigned int number_of_validated_nalus = nalu_list_clean_up(self->nalu_list);
  // Update the |accumulated_validation| w.r.t. the |latest_validation|.
  update_accumulated_validation(self->latest_validation, self->accumulated_validation);
  // Only update |number_of_validated_nalus| if the video is signed.
  if (self->accumulated_validation->authenticity != OMS_NOT_SIGNED) {
    self->accumulated_validation->number_of_validated_nalus += number_of_validated_nalus;
  }
}

/**
 * Sets shortcuts to parts in |authenticity|. No ownership is transferred so pointers can
 * safely be replaced.
 */
static void
set_authenticity_shortcuts(onvif_media_signing_t *self)
{
  assert(self && self->authenticity);
  self->latest_validation = &self->authenticity->latest_validation;
  self->accumulated_validation = &self->authenticity->accumulated_validation;
}

/**
 * Function to get an authenticity report.
 */
onvif_media_signing_authenticity_t *
onvif_media_signing_get_authenticity_report(onvif_media_signing_t *self)
{
  if (!self) {
    return NULL;
  }
  // Return a nullptr if no local authenticity report exists.
  if (self->authenticity == NULL) {
    return NULL;
  }

  onvif_media_signing_authenticity_t *authenticity_report = authenticity_report_create();

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(!authenticity_report, OMS_MEMORY);
    // Update |number_of_pending_nalus| since that may have changed since
    // |latest_validation|.
    onvif_media_signing_accumulated_validation_t *accumulated =
        self->accumulated_validation;
    if (accumulated->authenticity == OMS_NOT_SIGNED) {
      // If the video is (so far) not signed, number of pending NAL Units equals the
      // number of added NAL Units for validation.
      accumulated->number_of_pending_nalus = accumulated->number_of_received_nalus;
    } else {
      // At this point, all validated NAL Units up to the first pending NAL Unit have been
      // removed from the |nalu_list|, hence number of pending NAL Units equals number of
      // items in the |nalu_list|. Even though, there might exist SEIs that have been
      // "consumed" and then are no longer pending, these are still included in the set of
      // |number_of_pending_nalus|.
      accumulated->number_of_pending_nalus = self->nalu_list->num_items;
    }
    OMS_THROW(transfer_authenticity(authenticity_report, self->authenticity));
  OMS_CATCH()
  {
    onvif_media_signing_authenticity_report_free(authenticity_report);
    authenticity_report = NULL;
  }
  OMS_DONE(status)

  // Sanity check the output since not returning MediaSigningReturnCode.
  assert(((status == OMS_OK) ? (authenticity_report != NULL)
                             : (authenticity_report == NULL)));

  return authenticity_report;
}

/**
 * Functions to create and free authenticity reports and members.
 */

oms_rc
create_local_authenticity_report_if_needed(onvif_media_signing_t *self)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  // Already exists, return OMS_OK.
  if (self->authenticity) {
    return OMS_OK;
  }

  // Create a new one.
  onvif_media_signing_authenticity_t *authenticity_report = authenticity_report_create();
  if (authenticity_report == NULL) {
    return OMS_MEMORY;
  }

  // Transfer |vendor_info| from |self|.
  transfer_vendor_info(&authenticity_report->vendor_info, &self->vendor_info);

  self->authenticity = authenticity_report;
  set_authenticity_shortcuts(self);

  return OMS_OK;
}

static onvif_media_signing_authenticity_t *
authenticity_report_create()
{
  onvif_media_signing_authenticity_t *authenticity_report =
      calloc(1, sizeof(onvif_media_signing_authenticity_t));
  if (!authenticity_report) {
    return NULL;
  }

  authenticity_report_init(authenticity_report);

  return authenticity_report;
}

void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t *authenticity_report)
{
  if (!authenticity_report) {
    return;
  }

  free(authenticity_report->version_on_signing_side);
  free(authenticity_report->this_version);
  free(authenticity_report->latest_validation.nalu_str);
  free(authenticity_report->latest_validation.validation_str);

  free(authenticity_report);
}
