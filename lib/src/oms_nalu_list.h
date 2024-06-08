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

#ifndef __OMS_NALU_LIST_H__
#define __OMS_NALU_LIST_H__

#include "oms_internal.h"  // nalu_list_t

typedef enum {
  VALIDATION_STR = 0,
  NALU_STR = 1,
} NaluListStringType;

/* Function declarations needed to handle the linked list of NALUs used to validate the
 * authenticity of a Signed Video. */

/**
 * @brief Creates a nalu list
 *
 * @returns A pointer to the created object, or NULL upon failure.
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
 * @returns Media Signing Return Code
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
 *
 * @returns Signed Video Internal Return Code
 */
oms_rc
nalu_list_copy_last_item(nalu_list_t* list, bool hash_algo_known);

#if 0
/**
 * @brief Appends or prepends a certain item of a list with a new item marked as missing
 *
 * Searches through the |list| for the |item| and if found appends/prepends it with a new item that
 * is marked as missing (|validation_status| = 'M'). The |nalu| of this missing item is a NULL
 * pointer.
 *
 * @param list The |list| including the |item|.
 * @param num_missing Number of missing items to append/prepend.
 * @param append Appends |item| if true and prepends |item| if false.
 * @param item The |item| of which the 'missing' items are append/prepend.
 *
 * @returns Signed Video Internal Return Code
 */
oms_rc
h26x_nalu_list_add_missing(nalu_list_t* list,
    int num_missing,
    bool append,
    nalu_list_item_t* item);

/**
 * @brief Removes 'M' items present at the beginning of a |list|
 *
 * There are scenarios when missing items are added to the front of the |list|, when the framework
 * actually could not verify the hashes. This function removes them and resets the flag
 * |first_verification_not_authentic| of non-pending items. Further, marks the decoded SEI as 'U',
 * even if it could be verified, because it is not associated with this recording.
 *
 * @param list The |list| to remove items from.
 */
void
h26x_nalu_list_remove_missing_items(nalu_list_t* list);
#endif

/**
 * @brief Searches for, and returns, the next pending SEI item
 *
 * @param list The |list| to search for the next SEI.
 *
 * @returns The nex nalu_list_item_t that holds a SEI NALU, which also is 'pending'
 * validation. If no pending SEI item is found a NULL pointer is returned.
 */
nalu_list_item_t*
nalu_list_get_next_sei_item(const nalu_list_t* list);

/**
 * @brief Collects statistics from a list
 *
 * Loops through the |list| and collects statistics.
 * The stats collected are
 *   - number of invalid NAL Units
 *   - number of missing NAL Units
 *
 * @param list The |list| to collect statistics from.
 * @param num_invalid_nalus A pointer to which the number of NAL Units, that could not be
 *   validated as authentic, is written.
 * @param num_missing_nalus A pointer to which the number of missing NAL Units, detected
 *   by the validation, is written.
 *
 * @returns True if at least one item is validated as authentic including those that are
 *   pending a second verification.
 */
bool
nalu_list_get_stats(const nalu_list_t* list,
    int* num_invalid_nalus,
    int* num_missing_nalus);

/**
 * @brief Counts and returns number of items pending validation
 *
 * @param list The |list| to count pending items.
 *
 * @returns Number of items pending validation. Returns zero upon failure.
 */
int
nalu_list_num_pending_items(const nalu_list_t* list);

/**
 * @brief Returns a string with all authentication statuses of the items
 *
 * Transforms all |validation_status| characters, or NAL Unit character, of the items in
 * the |list| into a char string.
 *
 * @param list The list to get string from.
 * @param str_type The type of string data to get (validation or nalu).
 *
 * @returns The validation string, and a '\0' upon failure.
 */
char*
nalu_list_get_str(const nalu_list_t* list, NaluListStringType str_type);

/**
 * @brief Cleans up among validated NALUs
 *
 * To avoid the list from growing uncontrolled in size outdated, already validated, NALUs
 * are removed. This is done by removing the first_item from the list one-by-one until the
 * first 'pending' one is detected.
 *
 * @note that calling this function before nalu_list_get_str() can remove information that
 * was supposed to be presented to the end user.
 *
 * @param list The list to clean from validated items.
 *
 * @returns Number of removed items, excluding previously added 'missing' NALUs.
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

#endif  // __OMS_NALU_LIST_H__
