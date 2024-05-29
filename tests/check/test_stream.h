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

#ifndef __TEST_STREAM_H__
#define __TEST_STREAM_H__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "lib/src/includes/onvif_media_signing_common.h"  // MediaSigningCodec

/* A struct representing a NAL Unit in a test stream, the test stream being represented as
 * a linked list. Each object holds the data as well as pointers to the previous and next
 * item in the list.
 */
typedef struct _test_stream_item_st {
  uint8_t *data;  // Pointer to NAL Unit data
  size_t data_size;  // Size of NAL Unit data
  char type;  // One character representation of NAL Unit
  struct _test_stream_item_st *prev;  // Previous item
  struct _test_stream_item_st *next;  // Next item
} test_stream_item_t;

#define MAX_NUM_ITEMS (100)

/* A struct representing the test stream of nal units. It holds the first and last item in
 * the linked list. In addition, it stores the number of items and a string representation
 * of all the NAL Unit types for easy identification.
 */
typedef struct _test_stream_st {
  test_stream_item_t *first_item;  // First NAL Unit in the stream
  test_stream_item_t *last_item;  // Last NAL Unit in the stream
  int num_items;  // Number of NAL Units in the stream
  char types[MAX_NUM_ITEMS + 1];  // One extra for null termination.
  MediaSigningCodec codec;  // H.264 or H.265
} test_stream_t;

/**
 * test_stream_t functions
 **/

/* Creates a test stream with test stream items based on the input string. The string is
 * converted to test stream items. */
test_stream_t *
test_stream_create(const char *str, MediaSigningCodec codec);

/* Frees all the items in the list and the list itself. */
void
test_stream_free(test_stream_t *list);

/* Pops number_of_items from a list and returns a new list with these items. If there are
 * not at least number_of_items in the list NULL is returned. */
test_stream_t *
test_stream_pop(test_stream_t *list, int number_of_items);

/* Appends a list to a list. The |list_to_append| is freed after the operation. */
void
test_stream_append(test_stream_t *list, test_stream_t *list_to_append);

/* Appends the list item with position |item_number_to_append| with a |new_item|. */
void
test_stream_append_item(test_stream_t *list,
    test_stream_item_t *new_item,
    int item_number_to_append);

/* Prepends the first_item of a list with a |new_item|. */
void
test_stream_prepend_first_item(test_stream_t *list, test_stream_item_t *new_item);

/* Makes a refresh on the |list|. This means restoring all struct members. Helpful if the
 * |list| is out of sync. Rewinds the |first_item| to the beginning and loops through all
 * items to get the size, the |last_item| and the |types|. Note that the |first_item| has
 * to be represented in the |list|. */
void
test_stream_refresh(test_stream_t *list);

/* Checks the sequence of NAL Units of |list| against the expected |types|. */
void
test_stream_check_types(const test_stream_t *list, const char *types);

/* Prints the members of the |list|. */
void
test_stream_print(test_stream_t *list);

/**
 * test_stream_item_t functions
 **/

/* Creates a test_stream_item_t from a |type| and |codec|. Then sets the |id|. */
test_stream_item_t *
test_stream_item_create_from_type(char type, uint8_t id, MediaSigningCodec codec);

/* Creates a new test stream item. Takes pointers to the NAL Unit data, the nalu data
 * size. Memory ownership is transferred. */
test_stream_item_t *
test_stream_item_create(const uint8_t *nalu, size_t nalu_size, MediaSigningCodec codec);

/* Frees the item. */
void
test_stream_item_free(test_stream_item_t *item);

/* Get the item with position |item_number| in the list. The item is not removed from the
 * list, so if any action is taken on the item, the list has to be refreshed. */
test_stream_item_t *
test_stream_item_get(test_stream_t *list, int item_number);

/* Returns the test stream item with position |item_number| in the list. The user takes
 * ownership of the item and is responsible to free the memory. The item is no longer part
 * of the list after this operation. */
test_stream_item_t *
test_stream_item_remove(test_stream_t *list, int item_number);

/* Returns the first item in the list. This item is no longer part of the list and the
 * user is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_first_item(test_stream_t *list);

/* Returns the last item in the list. This item is no longer part of the list and the user
 * is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_last_item(test_stream_t *list);

/* Prepends a |list_item| with a |new_item|. Assumes |list_item| exists. */
void
test_stream_item_prepend(test_stream_item_t *list_item, test_stream_item_t *new_item);

/* Checks the test stream |item| against the expected |type|. */
void
test_stream_item_check_type(const test_stream_item_t *item, char type);

/* Prints the members of the item. */
void
test_stream_item_print(test_stream_item_t *item);

#endif  // __TEST_STREAM_H__
