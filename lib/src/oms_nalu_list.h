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

#ifndef __OMS_NALU_LIST_H__
#define __OMS_NALU_LIST_H__

#include <stdbool.h>

#include "oms_defines.h"  // oms_rc
#include "oms_internal.h"  // nalu_list_t, nalu_list_item_t, nalu_info_t

typedef enum {
  VALIDATION_STR = 0,
  NALU_STR = 1,
} NaluListStringType;

/* Function declarations needed to handle the linked list of NAL Units used to validate
 * the authenticity of a ONIVF Media Signing. */

/**
 * @brief Creates a nalu list
 *
 * @return A pointer to the created object, or NULL upon failure.
 */
nalu_list_t*
nalu_list_create();

/**
 * @brief Frees all the items in the list and the list itself
 *
 * @param list The nalu_list_t object to free.
 */
void
nalu_list_free(nalu_list_t* list);

/**
 * @brief Removes and frees all the items in a nalu_list_t
 *
 * @param list The list to empty. All items in the list are freed.
 */
void
nalu_list_free_items(nalu_list_t* list);

/**
 * @brief Appends a list with a new item
 *
 * From the |nalu| a nalu_list_item_t is created. The new item is the added to the |list|
 * by appending the last item. @note that the ownership of |nalu| is not transferred. The
 * list item only holds a pointer to the |nalu| memory. To store |nalu| for the future use
 * nalu_list_copy_last_item(...) before releasing the |nalu| memory.
 *
 * @param list The list to which the NAL Unit should be added.
 * @param nalu The nalu_info_t to add to the list through a new item.
 *
 * @return Media Signing Return Code
 */
oms_rc
nalu_list_append(nalu_list_t* list, const nalu_info_t* nalu);

/**
 * @brief Makes a copy of the last item in a list
 *
 * A copy of the |nalu| in the last nalu_list_item_t of the |list| is made, but only the
 * necessary information is kept. For example, most of the pointers are not needed and
 * therefore set to NULL. The ownership of |nalu| is handed over and the user can now
 * safely free the memory. If the |nalu| could not be copied it will be a NULL pointer and
 * an error is returned.
 *
 * @param list The list of which the last item is to be copied.
 * @param hash_algo_known If true, the hash of the NAL Unit is copied, otherwise the
 *                        hashable data of the NAL Unit is copied.
 *
 * @return Media Signing Return Code
 */
oms_rc
nalu_list_copy_last_item(nalu_list_t* list, bool hash_algo_known);

/**
 * @brief Appends or prepends a certain item of a list with a new item marked as missing
 *
 * Searches through the |list| for the |item| and if found appends/prepends it with a new
 * item that is marked as missing (|validation_status| = 'M'). The |nalu| of this missing
 * item is a NULL pointer.
 *
 * @param list The |list| including the |item|.
 * @param num_missing Number of missing items to append/prepend.
 * @param append Appends |item| if true and prepends |item| if false.
 * @param item The |item| of which the 'missing' items are append/prepend.
 * @param associated_sei A pointer to the SEI which the missing items are associated with.
 *
 * @return Media Signing Return Code
 */
oms_rc
nalu_list_add_missing_items(nalu_list_t* list,
    int num_missing,
    bool append,
    nalu_list_item_t* item,
    const nalu_list_item_t* associated_sei);

/**
 * @brief Appends last associated item with new items marked as missing
 *
 * Searches through the |list| for the last |item| associated with |associated_sei| and if
 * found appends it with |num_missing| new items that are marked as missing
 * (|validation_status| = 'M'). The |nalu| of the missing items is a NULL pointer.
 *
 * @param list The |list| including the |item|.
 * @param num_missing Number of missing items to append/prepend.
 * @param associated_sei A pointer to the SEI which the missing items are associated with.
 *
 * @return Media Signing Return Code
 */
void
nalu_list_add_missing_items_at_end_of_partial_gop(nalu_list_t* list,
    int num_missing,
    const nalu_list_item_t* associated_sei);

/**
 * @brief Removes a specific item from the |list| and frees the memory
 *
 * @param list The |list| to remove items from.
 * @param item_to_remove The item to remove from |list|.
 */
void
nalu_list_remove_and_free_item(nalu_list_t* list, const nalu_list_item_t* item_to_remove);

/**
 * @brief Searches for, and returns, the next pending SEI item
 *
 * @param list The |list| to search for the next SEI.
 *
 * @return The next nalu_list_item_t that holds a SEI, which also is 'pending'
 * validation. If no pending SEI item is found a NULL pointer is returned.
 */
nalu_list_item_t*
nalu_list_get_next_sei_item(const nalu_list_t* list);

/**
 * @brief Updates or resets validation status of all items in a list
 *
 * @param list The |list| to count pending items.
 * @param update Updates |validation_status| with |tmp_validation_status| if 'true',
 *   otherwise resets |tmp_validation_status| with |validation_status|.
 *
 * @return An appropriate ONVIF Media Signing Return Code.
 */
oms_rc
nalu_list_update_status(nalu_list_t* list, bool update);

/**
 * @brief Collects statistics from a list
 *
 * Loops through the |list| and collects statistics.
 * The stats collected are
 *   - number of invalid NAL Units
 *   - number of missing NAL Units
 *
 * @param list The |list| to collect statistics from.
 * @param sei The SEI that the current GOP has been validated with. A NULL pointer means
 *   that no SEI was used, e.g., when missing a SEI.
 * @param num_invalid_nalus A pointer to which the number of NAL Units, that could not be
 *   validated as authentic, is written.
 * @param num_missing_nalus A pointer to which the number of missing NAL Units, detected
 *   by the validation, is written.
 *
 * @return True if at least one item is validated as authentic.
 */
bool
nalu_list_get_stats(const nalu_list_t* list,
    const nalu_list_item_t* sei,
    int* num_invalid_nalus,
    int* num_missing_nalus);

/**
 * @brief Counts and returns number of items pending validation
 *
 * @param list The |list| to count pending items.
 * @param stop_item Stop counting here. A NULL pointer counts all.
 *
 * @return Number of items pending validation. Returns zero upon failure.
 */
int
nalu_list_num_pending_items(const nalu_list_t* list, nalu_list_item_t* stop_item);

/**
 * @brief Returns a string with all authentication statuses of the items
 *
 * Transforms all |validation_status| characters, or NAL Unit character, of the items in
 * the |list| into a char string.
 *
 * @param list The list to get string from.
 * @param str_type The type of string data to get (validation or nalu).
 *
 * @return The validation string, and "" upon failure.
 */
char*
nalu_list_get_str(const nalu_list_t* list, NaluListStringType str_type);

/**
 * @brief Cleans up among validated NAL Units
 *
 * To avoid the list from growing uncontrolled in size outdated, already validated, NAL
 * Units are removed. This is done by removing the first_item from the list one-by-one
 * until the first 'pending' one is detected.
 *
 * @note that calling this function before nalu_list_get_str() can remove information that
 * was supposed to be presented to the end user.
 *
 * @param list The list to clean from validated items.
 *
 * @return Number of removed items, excluding previously added 'missing' NAL Units.
 */
unsigned int
nalu_list_clean_up(nalu_list_t* list);

/**
 * @brief Prints all items in the list
 *
 * The |validation_status| as well as flags and hashes are printed for all items in the
 * |list|.
 *
 * @param list The |list| to print items.
 */
void
nalu_list_print(const nalu_list_t* list);

/**
 * @brief Searches for, and returns, the next hashable item
 *
 * @param start_item The list item to start the search for the next hashable item.
 *
 * @return The next item that is hashable. NULL if no hashable item is found.
 */
nalu_list_item_t*
nalu_list_item_get_next_hashable(const nalu_list_item_t* start_item);

#endif  // __OMS_NALU_LIST_H__
