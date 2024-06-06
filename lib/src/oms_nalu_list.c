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

#include "oms_nalu_list.h"

// #include <assert.h>
// #ifdef SIGNED_VIDEO_DEBUG
// #include <stdio.h>  // printf

// #include "signed_video_internal.h"  // SHA_HASH_SIZE
// #endif
// #include <stdint.h>
// #include <stdlib.h>  // calloc, malloc, free, size_t
// #include <string.h>  // memcpy

/* Declarations of static nalu_list_item_t functions. */
static nalu_list_item_t *
nalu_list_item_create(const nalu_info_t *nalu);
static void
nalu_list_item_free(nalu_list_item_t *item);
static void
nalu_list_item_append_item(nalu_list_item_t *list_item, nalu_list_item_t *new_item);
/* Declarations of static nalu_list_t functions. */
static void
nalu_list_refresh(nalu_list_t *list);
static void
nalu_list_remove_and_free_item(nalu_list_t *list, const nalu_list_item_t *item_to_remove);
#if 0
static void
h26x_nalu_list_item_prepend_item(nalu_list_item_t *list_item, nalu_list_item_t *new_item);
#ifdef SIGNED_VIDEO_DEBUG
static void
h26x_nalu_list_item_print(const nalu_list_item_t *item);
#endif


/* Helper functions. */

/* Determines and returns the validation status character from a nalu_info_t object.
 */
static char
get_validation_status_from_nalu(const nalu_info_t *nalu)
{
  if (!nalu) return '\0';

  // Currently there is some redundancy between |is_valid| and |is_hashable|. Basically there are
  // three kinds of NALUs;
  //  1) |nalu| could not be parsed into an H26x NAL Unit -> is_valid = 0
  //  2) |nalu| could successfully be parsed into an H26x NAL Unit -> is_valid = 1
  //  3) |nalu| is used in the hashing scheme -> is_hashable = true (and is_valid = 1)
  //  4) an error occured -> is_valid < 0

  if (nalu->is_valid < 0) return 'E';
  if (nalu->is_valid == 0) return 'U';
  if (nalu->is_hashable) {
    return 'P';
  } else {
    return '_';
  }
}
#endif

/**
 * Static nalu_list_item_t functions.
 */

/* Creates a new NAL Unit list item and sets the pointer to the |nalu|. A NULL pointer is
 * a valid input, which will create an empty item. */
static nalu_list_item_t *
nalu_list_item_create(const nalu_info_t *nalu)
{
  nalu_list_item_t *item = calloc(1, sizeof(nalu_list_item_t));
  if (!item)
    return NULL;

  item->nalu = (nalu_info_t *)nalu;
  // item->taken_ownership_of_nalu = false;
  // item->validation_status = get_validation_status_from_nalu(nalu);

  return item;
}

/* Frees the |item|. Also frees the |nalu| data, hence this operation should be used with
 * care if it is used by others. */
static void
nalu_list_item_free(nalu_list_item_t *item)
{
  if (!item)
    return;

  // If we have |nalu| data we free the temporarily used TLV memory slot.
  // if (item->taken_ownership_of_nalu) {
  //   if (item->nalu) {
  //     free(item->nalu->nalu_wo_epb);
  //     free(item->nalu->pending_hashable_data);
  //   }
  //   free(item->nalu);
  // }
  // free(item->second_hash);
  free(item);
}

/* Appends a |list_item| with a |new_item|. Assumes |list_item| and |new_item| exists. */
static void
nalu_list_item_append_item(nalu_list_item_t *list_item, nalu_list_item_t *new_item)
{
  assert(list_item && new_item);

  nalu_list_item_t *next_item = list_item->next;

  if (next_item != NULL) {
    next_item->prev = new_item;
    new_item->next = next_item;
  }
  new_item->prev = list_item;
  list_item->next = new_item;
}

#if 0
/* Prepends a |list_item| with a |new_item|. Assumes |list_item| and |new_item| exists. */
static void
h26x_nalu_list_item_prepend_item(nalu_list_item_t *list_item, nalu_list_item_t *new_item)
{
  assert(list_item && new_item);

  nalu_list_item_t *prev_item = list_item->prev;

  if (prev_item != NULL) {
    new_item->prev = prev_item;
    prev_item->next = new_item;
  }
  list_item->prev = new_item;
  new_item->next = list_item;
}

#ifdef SIGNED_VIDEO_DEBUG
/* Prints the members of an |item|. */
static void
h26x_nalu_list_item_print(const nalu_list_item_t *item)
{
  // nalu_info_t *nalu;
  // char validation_status;
  // uint8_t hash[MAX_HASH_SIZE];
  // uint8_t *second_hash;
  // bool taken_ownership_of_nalu;
  // bool need_second_verification;
  // bool first_verification_not_authentic;
  // bool has_been_decoded;
  // bool used_in_gop_hash;

  if (!item) return;

  char *nalu_type_str = !item->nalu
      ? "This NAL Unit is missing"
      : (item->nalu->is_gop_sei ? "SEI" : (item->nalu->is_first_nalu_in_gop ? "I" : "Other"));
  char validation_status_str[2] = {'\0'};
  memcpy(validation_status_str, &item->validation_status, 1);

  printf("NAL Unit type = %s\n", nalu_type_str);
  printf("validation_status = %s%s%s%s%s%s\n", validation_status_str,
      (item->taken_ownership_of_nalu ? ", taken_ownership_of_nalu" : ""),
      (item->need_second_verification ? ", need_second_verification" : ""),
      (item->first_verification_not_authentic ? ", first_verification_not_authentic" : ""),
      (item->has_been_decoded ? ", has_been_decoded" : ""),
      (item->used_in_gop_hash ? ", used_in_gop_hash" : ""));
  printf("item->hash     ");
  for (size_t i = 0; i < item->hash_size; i++) {
    printf("%02x", item->hash[i]);
  }
  if (item->second_hash) {
    printf("\nitem->second_hash ");
    for (size_t i = 0; i < item->hash_size; i++) {
      printf("%02x", item->second_hash[i]);
    }
  }
  printf("\n");
}
#endif
#endif

/**
 * Static nalu_list_t functions.
 */

/* Finds and removes |item_to_remove| from the |list|. The |item_to_remove| is then freed.
 */
static void
nalu_list_remove_and_free_item(nalu_list_t *list, const nalu_list_item_t *item_to_remove)
{
  // Find the |item_to_remove|.
  nalu_list_item_t *item = list->first_item;
  while (item && (item != item_to_remove)) {
    item = item->next;
  }

  if (!item) {
    return;  // Did not find the |item_to_remove|.
  }

  // Connect the previous and next items in the list. This removes the |item_to_remove|
  // from the |list|.
  if (item->prev) {
    item->prev->next = item->next;
  }
  if (item->next) {
    item->next->prev = item->prev;
  }

  // Fix the broken list. To use nalu_list_refresh(), first_item needs to be part of the
  // list. If |item_to_remove| was that first_item, we need to set a new one.
  if (list->first_item == item) {
    list->first_item = item->next;
  }
  if (list->last_item == item) {
    list->last_item = item->prev;
  }
  nalu_list_refresh(list);

  nalu_list_item_free(item);
}

/* Makes a refresh on the list. Helpful if the list is out of sync. Rewinds the
 * |first_item| to the beginning and loops through all items to compute |num_items| and
 * set the |last_item|. Note that the |first_item| has to be represented somewhere in the
 * |list|. */
static void
nalu_list_refresh(nalu_list_t *list)
{
  if (!list)
    return;

  // Start from scratch, that is, reset num_items.
  list->num_items = 0;
  // Rewind first_item to get the 'true' first list item.
  while (list->first_item && (list->first_item)->prev) {
    list->first_item = (list->first_item)->prev;
  }
  // Start from the first_item and count num_items.
  nalu_list_item_t *item = list->first_item;
  while (item) {
    list->num_items++;

    if (!item->next)
      break;
    item = item->next;
  }
  list->last_item = item;
}

#if 0
/* Checks if the |item_to_find| is an item in the |list|. Returns true if so, otherwise false. */
static bool
is_in_list(const nalu_list_t *list, const nalu_list_item_t *item_to_find)
{
  bool found_item = false;
  const nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item == item_to_find) {
      found_item = true;
      break;
    }
    item = item->next;
  }
  return found_item;
}
#endif

/**
 * Public nalu_list_t functions.
 */

/* Creates and returns a nalu list. */
nalu_list_t *
nalu_list_create()
{
  return calloc(1, sizeof(nalu_list_t));
}

/* Frees all the items in the list and the list itself. */
void
nalu_list_free(nalu_list_t *list)
{
  if (!list) {
    return;
  }
  nalu_list_free_items(list);
  free(list);
}

/* Removes and frees all the items in the |list|. */
void
nalu_list_free_items(nalu_list_t *list)
{
  if (!list) {
    return;
  }
  // Pop all items and free them.
  while (list->first_item) {
    nalu_list_remove_and_free_item(list, list->first_item);
  }
}

/* Appends the |last_item| of the |list| with a new item. The new item has a pointer to
 * |nalu|, but does not take ownership of it. */
oms_rc
nalu_list_append(nalu_list_t *list, const nalu_info_t *nalu)
{
  if (!list || !nalu)
    return OMS_INVALID_PARAMETER;

  nalu_list_item_t *new_item = nalu_list_item_create(nalu);
  if (!new_item)
    return OMS_MEMORY;

  // List is empty. Set |new_item| as first_item. The nalu_list_refresh() call will fix
  // the rest of the list.
  if (!list->first_item)
    list->first_item = new_item;
  if (list->last_item)
    nalu_list_item_append_item(list->last_item, new_item);

  nalu_list_refresh(list);

  return OMS_OK;
}

/* Replaces the |nalu| of the |last_item| in the list with a copy of itself. All pointers
 * that are not needed are set to NULL, since no ownership is transferred. The ownership
 * of |nalu| is released. If the |nalu| could not be copied it will be a NULL pointer. If
 * hash algo is not known the |hashable_data| is copied so the NAL Unit can be hashed
 * later. */
oms_rc
nalu_list_copy_last_item(nalu_list_t *list, bool hash_algo_known)
{
  if (!list) {
    return OMS_INVALID_PARAMETER;
  }

  nalu_info_t *copied_nalu = NULL;
  uint8_t *hashable_data = NULL;
  uint8_t *nalu_wo_epb = NULL;
  nalu_list_item_t *item = list->last_item;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(!item->nalu, OMS_UNKNOWN_FAILURE);
    copied_nalu = malloc(sizeof(nalu_info_t));
    OMS_THROW_IF(!copied_nalu, OMS_MEMORY);
    if (item->nalu->tlv_data) {
      nalu_wo_epb = malloc(item->nalu->tlv_size);
      OMS_THROW_IF(!nalu_wo_epb, OMS_MEMORY);
      memcpy(nalu_wo_epb, item->nalu->tlv_data, item->nalu->tlv_size);
    }
    // If the library does not know which hash algo to use, store the |hashable_data| for
    // later.
    if (!hash_algo_known && item->nalu->is_hashable) {
      hashable_data = malloc(item->nalu->hashable_data_size);
      OMS_THROW_IF(!hashable_data, OMS_MEMORY);
      memcpy(hashable_data, item->nalu->hashable_data, item->nalu->hashable_data_size);
    }
    copy_nalu_except_pointers(copied_nalu, item->nalu);
    copied_nalu->nalu_wo_epb = nalu_wo_epb;
    copied_nalu->tlv_data = copied_nalu->nalu_wo_epb;
    copied_nalu->pending_hashable_data = hashable_data;
    copied_nalu->hashable_data = copied_nalu->pending_hashable_data;
  OMS_CATCH()
  {
    free(nalu_wo_epb);  // At this point, nalu_wo_epb is actually NULL.
    free(copied_nalu);
    copied_nalu = NULL;
  }
  OMS_DONE(status)

  // if (item->taken_ownership_of_nalu) {
  //   // We have taken ownership of the existing |nalu|, hence we need to free it when
  //   releasing it.
  //   // NOTE: This should not happen if the list is used properly.
  //   if (item->nalu) free(item->nalu->nalu_wo_epb);
  //   free(item->nalu);
  // }
  item->nalu = copied_nalu;
  // item->taken_ownership_of_nalu = true;

  return status;
}

#if 0
/* Append or prepend the |item| of the |list| with |num_missing| NALUs. */
oms_rc
h26x_nalu_list_add_missing(nalu_list_t *list,
    int num_missing,
    bool append,
    nalu_list_item_t *item)
{
  if (!list || !item || !is_in_list(list, item) || num_missing < 0) return OMS_INVALID_PARAMETER;
  if (num_missing == 0) return SV_OK;

  int added_items = 0;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    for (added_items = 0; added_items < num_missing; added_items++) {
      nalu_list_item_t *missing_nalu = nalu_list_item_create(NULL);
      OMS_THROW_IF(!missing_nalu, OMS_MEMORY);

      missing_nalu->validation_status = 'M';
      if (append) {
        nalu_list_item_append_item(item, missing_nalu);
      } else {
        h26x_nalu_list_item_prepend_item(item, missing_nalu);
      }
      nalu_list_refresh(list);
    }

  OMS_CATCH()
  OMS_DONE(status)

  if (added_items > 0) DEBUG_LOG("Added %d missing NAL Unit items to list", added_items);

  return status;
}

/* Removes 'M' items present at the beginning of the |list|. The |first_verification_not_authentic|
 * flag is reset on all items until we find the first pending item, inclusive. Further, a decoded
 * SEI is marked as 'U' since it is not associated with this recording. The screening keeps going
 * until we find the decoded SEI. */
void
h26x_nalu_list_remove_missing_items(nalu_list_t *list)
{
  if (!list) return;

  bool found_first_pending_nalu = false;
  bool found_decoded_sei = false;
  nalu_list_item_t *item = list->first_item;
  while (item && !(found_first_pending_nalu && found_decoded_sei)) {
    // Reset the invalid verification failure if we have not past the first pending item.

    if (!found_first_pending_nalu) item->first_verification_not_authentic = false;
    // Remove the missing NAL Unit in the front.
    if (item->validation_status == 'M' && (item == list->first_item)) {
      const nalu_list_item_t *item_to_remove = item;
      item = item->next;
      nalu_list_remove_and_free_item(list, item_to_remove);
      continue;
    }
    if (item->has_been_decoded && item->validation_status != 'U') {
      // Usually, these items were added because we verified hashes with a SEI not associated with
      // this recording. This can happen if we export to file or fast forward in a recording. The
      // SEI used to generate these missing items is set to 'U'.
      item->validation_status = 'U';
      found_decoded_sei = true;
    }
    if (item->validation_status == 'P') found_first_pending_nalu = true;
    item = item->next;
  }
}

/* Searches for, and returns, the next pending SEI item. */
nalu_list_item_t *
h26x_nalu_list_get_next_sei_item(const nalu_list_t *list)
{
  if (!list) return NULL;

  nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item->nalu && item->nalu->is_gop_sei && item->validation_status == 'P') break;
    item = item->next;
  }
  return item;
}

/* Loops through the |list| and collects statistics.
 * The stats collected are
 *   - number of invalid NALUs
 *   - number of missing NALUs
 * and return true if any valid NALUs, including those pending a second verification, are present.
 */
bool
h26x_nalu_list_get_stats(const nalu_list_t *list,
    int *num_invalid_nalus,
    int *num_missing_nalus)
{
  if (!list) return false;

  int local_num_invalid_nalus = 0;
  int local_num_missing_nalus = 0;
  bool has_valid_nalus = false;

  // From the list, get number of invalid NALUs and number of missing NALUs.
  nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item->validation_status == 'M') local_num_missing_nalus++;
    if (item->validation_status == 'N' || item->validation_status == 'E') local_num_invalid_nalus++;
    if (item->validation_status == '.') {
      // Do not count SEIs, since they are marked valid if the signature could be verified, which
      // happens for out-of-sync SEIs for example.
      has_valid_nalus |= !(item->nalu && item->nalu->is_gop_sei);
    }
    if (item->validation_status == 'P') {
      // Count NALUs that were verified successfully the first time and waiting for a second
      // verification.
      has_valid_nalus |= item->need_second_verification && !item->first_verification_not_authentic;
    }
    item = item->next;
  }

  if (num_invalid_nalus) *num_invalid_nalus = local_num_invalid_nalus;
  if (num_missing_nalus) *num_missing_nalus = local_num_missing_nalus;

  return has_valid_nalus;
}

/* Counts and returns number of items pending validation. */
int
h26x_nalu_list_num_pending_items(const nalu_list_t *list)
{
  if (!list) return 0;

  int num_pending_nalus = 0;
  nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item->validation_status == 'P') num_pending_nalus++;
    item = item->next;
  }

  return num_pending_nalus;
}
#endif

/* Transforms all |validation_status| characters of the items in the |list| into a char
 * string and returns that string if VALIDATION_STR is set. Transforms all |nalu_type|
 * characters of the items in the |list| into a char string and returns that string if
 * NALU_STR is set. */
char *
nalu_list_get_str(const nalu_list_t *list, NaluListStringType str_type)
{
  if (!list)
    return NULL;
  // Allocate memory for all items + a null terminated character.
  char *dst_str = calloc(1, list->num_items + 1);
  if (!dst_str)
    return NULL;

  nalu_list_item_t *item = list->first_item;
  int idx = 0;
  while (item) {
    char src = 'U';
    switch (str_type) {
      case NALU_STR:
        src = nalu_type_to_char(item->nalu);
        break;
      default:
      case VALIDATION_STR:
        src = item->validation_status;
        break;
    }
    dst_str[idx] = src;
    item = item->next;
    idx++;
  }

  return dst_str;
}

/* Cleans up the list by removing the validated items. */
unsigned int
nalu_list_clean_up(nalu_list_t *list)
{
  if (!list)
    return 0;

  // Remove validated items.
  unsigned int removed_items = 0;
  nalu_list_item_t *item = list->first_item;
  // while (item && item->validation_status != 'P' && !item->need_second_verification) {
  while (item && item->validation_status != 'P') {
    if (item->validation_status != 'M') {
      removed_items++;
    }
    nalu_list_remove_and_free_item(list, list->first_item);
    item = list->first_item;
  }

  return removed_items;
}

#if 0
/* Prints all items in the list. */
void
h26x_nalu_list_print(const nalu_list_t *list)
{
  if (!list) return;
#ifdef SIGNED_VIDEO_DEBUG
  const nalu_list_item_t *item = list->first_item;
  printf("\n");
  while (item) {
    h26x_nalu_list_item_print(item);
    item = item->next;
  }
  printf("\n");
#endif
}
#endif
