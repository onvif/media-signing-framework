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

#include "test_stream.h"

#include <check.h>  // ck_assert
#include <stdbool.h>
#include <stdio.h>  // printf
#include <stdlib.h>  // calloc, free
#include <string.h>  // memcpy, memset, strcmp

#include "oms_internal.h"  // parse_nalu_info()

#define START_CODE_SIZE 4
#define DUMMY_NALU_SIZE 5
#define DUMMY_SEI_SIZE 22

static const uint8_t start_code[START_CODE_SIZE] = {0x00, 0x00, 0x00, 0x01};
static const uint8_t no_start_code[START_CODE_SIZE] = {0xff, 0xff, 0xff, 0xff};
static const uint8_t invalid_nalu[DUMMY_NALU_SIZE] = {0xff, 0xff, 0xff, 0x00, 0xff};
/* Dummy NAL Unit data
 *
 * The valid H.264 and H.265 NAL Units share, for convenience, the same size even though
 * the NAL Unit headers are 1 vs. 2 bytes long. This adds a dummy byte to H.264.
 *
 * The H.264 pattern is as follows:
 *
 *  non-SEI
 * |-- 1 byte --|--  1 byte  --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   NALU header  slice header   dummy 0xff       id        stop bit
 *
 * SEI
 * |-- 1 byte --|-- 18 bytes --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   NALU header    sei data     dummy 0xff       id        stop bit
 *
 * All NAL Unit types have one byte to represent the id, which is modified from NAL Unit
 * to NAL Unit to generate unique data/hashes. Otherwise, e.g., switching two P-nalus will
 * have no impact, since the NAL Unit hashes will be identical. */
static const uint8_t I_nalu_h264[DUMMY_NALU_SIZE] = {0x65, 0x80, 0xff, 0x00, 0x80};
static const uint8_t i_nalu_h264[DUMMY_NALU_SIZE] = {0x65, 0x00, 0xff, 0x00, 0x80};
static const uint8_t P_nalu_h264[DUMMY_NALU_SIZE] = {0x01, 0x80, 0xff, 0x00, 0x80};
static const uint8_t p_nalu_h264[DUMMY_NALU_SIZE] = {0x01, 0x00, 0xff, 0x00, 0x80};
static const uint8_t pps_nalu_h264[DUMMY_NALU_SIZE] = {0x28, 0x00, 0xff, 0x00, 0x80};
static const uint8_t sei_nalu_h264[DUMMY_SEI_SIZE] = {0x06, 0x05, 0x12, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00,
    0x00, 0x80};
/* The H.265 pattern is as follows:
 *
 *  non-SEI
 * |-- 2 bytes --|--  1 byte  --|-- 1 byte --|-- 1 byte --|
 *   NALU header   slice header       id        stop bit
 *
 * SEI
 * |-- 2 bytes --|-- 18 bytes --|-- 1 byte --|-- 1 byte --|
 *   NALU header     sei data         id        stop bit
 *
 */
static const uint8_t I_nalu_h265[DUMMY_NALU_SIZE] = {0x26, 0x01, 0x80, 0x00, 0x80};
static const uint8_t i_nalu_h265[DUMMY_NALU_SIZE] = {0x26, 0x01, 0x00, 0x00, 0x80};
static const uint8_t P_nalu_h265[DUMMY_NALU_SIZE] = {0x02, 0x01, 0x80, 0x00, 0x80};
static const uint8_t p_nalu_h265[DUMMY_NALU_SIZE] = {0x02, 0x01, 0x00, 0x00, 0x80};
static const uint8_t pps_nalu_h265[DUMMY_NALU_SIZE] = {0x44, 0x01, 0x00, 0x00, 0x80};
static const uint8_t sei_nalu_h265[DUMMY_SEI_SIZE] = {0x4e, 0x01, 0x05, 0x11, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0x00, 0x80};

// Function declarations.
static void
test_stream_append_last_item(test_stream_t *list, test_stream_item_t *new_item);

/* Helper that parses information from the NAL Unit |data| and returns a character
 * representing the NAL Unit type. */
static char
get_type_char(const uint8_t *data, size_t data_size, MediaSigningCodec codec)
{
  nalu_info_t nalu_info = parse_nalu_info(data, data_size, codec, false, true);

  char type;
  switch (nalu_info.nalu_type) {
    case NALU_TYPE_UNDEFINED:
      type = nalu_info.is_valid == 0 ? 'X' : '\0';
      break;
    case NALU_TYPE_I:
      type = nalu_info.is_primary_slice == true ? 'I' : 'i';
      break;
    case NALU_TYPE_P:
      type = nalu_info.is_primary_slice == true ? 'P' : 'p';
      break;
    case NALU_TYPE_PS:
      type = 'V';
      break;
    case NALU_TYPE_SEI: {
      if (!nalu_info.is_oms_sei)
        type = 'z';
      else if (nalu_info.is_certificate_sei)
        type = 'C';
      else if (nalu_info.is_signed)
        type = 'S';
      else
        type = 's';
      break;
    }
    default:
      type = '\0';
      break;
  }

  free(nalu_info.nalu_wo_epb);

  return type;
}

/* Helper to allocate memory and generate a NAL Unit w/wo correct start code, followed by
 * some |nalu_data|. The |nalu_data| should end with a stop byte preceeded with a byte to
 * fill in the |id|. */
static uint8_t *
generate_nalu(bool valid_start_code,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    uint8_t id,
    size_t *final_nalu_size)
{
  // Sanity checks.
  ck_assert(nalu_data);
  ck_assert(nalu_data_size > 0);
  ck_assert(final_nalu_size);

  *final_nalu_size = START_CODE_SIZE + nalu_data_size;  // Add start_code
  // Allocate memory, copy |start_code| and |nalu_data| and set the |id|.
  uint8_t *nalu = (uint8_t *)malloc(*final_nalu_size);
  memcpy(nalu, valid_start_code ? start_code : no_start_code, START_CODE_SIZE);
  memcpy(nalu + START_CODE_SIZE, nalu_data, nalu_data_size);
  nalu[*final_nalu_size - 2] = id;  // Set ID to make it unique.

  return nalu;
}

/**
 * test_stream_item_t functions.
 */

/* Creates a test_stream_item_t from |type| for |codec|, then sets the |id|. */
test_stream_item_t *
test_stream_item_create_from_type(char type, uint8_t id, MediaSigningCodec codec)
{
  uint8_t *nalu = NULL;  // Final NAL Unit with start code and id.
  const uint8_t *nalu_data = NULL;
  size_t nalu_data_size = DUMMY_NALU_SIZE;  // Change if we have a SEI.
  bool start_code = true;  // Use a valid start code by default.

  // Find out which type of NAL Unit the character is and point |nalu_data| to it.
  switch (type) {
    case 'I':
      nalu_data = codec == OMS_CODEC_H264 ? I_nalu_h264 : I_nalu_h265;
      break;
    case 'i':
      nalu_data = codec == OMS_CODEC_H264 ? i_nalu_h264 : i_nalu_h265;
      break;
    case 'P':
      nalu_data = codec == OMS_CODEC_H264 ? P_nalu_h264 : P_nalu_h265;
      break;
    case 'p':
      nalu_data = codec == OMS_CODEC_H264 ? p_nalu_h264 : p_nalu_h265;
      break;
    case 'z':
      nalu_data = codec == OMS_CODEC_H264 ? sei_nalu_h264 : sei_nalu_h265;
      nalu_data_size = DUMMY_SEI_SIZE;
      break;
    case 'V':
      nalu_data = codec == OMS_CODEC_H264 ? pps_nalu_h264 : pps_nalu_h265;
      break;
    case 'X':
    default:
      nalu_data = invalid_nalu;
      start_code = false;
      break;
  }

  size_t nalu_size = 0;
  nalu = generate_nalu(start_code, nalu_data, nalu_data_size, id, &nalu_size);
  ck_assert(nalu);
  ck_assert(nalu_size > 0);
  ck_assert_int_eq(nalu[nalu_size - 2], id);  // Check id.
  return test_stream_item_create(nalu, nalu_size, codec);
}

/* Creates a new test stream item. Takes pointer to the NAL Unit |data| and the nalu
 * |data_size|. The ownership of |data| is transferred to the item. */
test_stream_item_t *
test_stream_item_create(const uint8_t *data, size_t data_size, MediaSigningCodec codec)
{
  // Sanity check on input parameters.
  if (!data || data_size <= 0)
    return NULL;

  test_stream_item_t *item = (test_stream_item_t *)calloc(1, sizeof(test_stream_item_t));
  ck_assert(item);

  item->data = (uint8_t *)data;
  item->data_size = data_size;
  item->type = get_type_char(data, data_size, codec);

  return item;
}

void
test_stream_item_free(test_stream_item_t *item)
{
  if (!item)
    return;

  free(item->data);
  free(item);
}

/* This function detaches an |item|, that is, removes the links to all neighboring items.
 */
static void
nalu_list_detach_item(test_stream_item_t *item)
{
  if (!item)
    return;
  item->prev = NULL;
  item->next = NULL;
}

/* Get the item with positioned at |item_number| in the |list|. The item is not removed
 * from the |list|, so if any action is taken on the item, the |list| has to be refreshed.
 */
test_stream_item_t *
test_stream_item_get(test_stream_t *list, int item_number)
{
  // Sanity check on input parameters. List items start from 1.
  if (!list || item_number <= 0)
    return NULL;

  // Check for invalid list.
  if (list->num_items < item_number)
    return NULL;
  if (list->first_item == NULL || list->num_items == 0)
    return NULL;

  test_stream_item_t *item_to_get = list->first_item;
  // Find the correct item.
  while (--item_number)
    item_to_get = item_to_get->next;

  return item_to_get;
}

/* Returns the test stream item with position |item_number| in the |list|. The user takes
 * ownership of the item and is responsible to free the memory. The item is no longer part
 * of the |list| after this operation. */
test_stream_item_t *
test_stream_item_remove(test_stream_t *list, int item_number)
{
  // Sanity check on input parameters. List items start from 1.
  if (!list || item_number <= 0)
    return NULL;

  test_stream_item_t *item_to_remove = test_stream_item_get(list, item_number);
  if (!item_to_remove)
    return NULL;

  // Connect the previous and next items in the list.
  if (item_to_remove->prev)
    item_to_remove->prev->next = item_to_remove->next;
  if (item_to_remove->next)
    item_to_remove->next->prev = item_to_remove->prev;

  // Fix the broken list. To use test_stream_refresh(), first_item needs to be part of the
  // list. If item_to_get was that first_item, we need to set a new one.
  if (list->first_item == item_to_remove)
    list->first_item = item_to_remove->next;
  if (list->last_item == item_to_remove)
    list->last_item = item_to_remove->prev;
  test_stream_refresh(list);

  nalu_list_detach_item(item_to_remove);
  return item_to_remove;
}

/* Returns the first item in the |list|. This item is no longer part of the |list| and the
 * user is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_first_item(test_stream_t *list)
{
  return test_stream_item_remove(list, 1);
}

/* Returns the last item in the |list|. This item is no longer part of the |list| and the
 * user is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_last_item(test_stream_t *list)
{
  return test_stream_item_remove(list, list->num_items);
}

/* Appends a |list_item| with a |new_item|, assuming the |list_item| exists. */
static void
test_stream_item_append(test_stream_item_t *list_item, test_stream_item_t *new_item)
{
  if (!list_item || !new_item)
    return;

  test_stream_item_t *next_item = list_item->next;
  if (next_item != NULL) {
    next_item->prev = new_item;
    new_item->next = next_item;
  }
  list_item->next = new_item;
  new_item->prev = list_item;
}

/* Prepends a |list_item| with a |new_item|, assuming the |list_item| exists. */
void
test_stream_item_prepend(test_stream_item_t *list_item, test_stream_item_t *new_item)
{
  if (!list_item || !new_item)
    return;

  test_stream_item_t *prev_item = list_item->prev;
  if (prev_item != NULL) {
    prev_item->next = new_item;
    new_item->prev = prev_item;
  }
  list_item->prev = new_item;
  new_item->next = list_item;
}

/* Checks the test stream |item| against the expected |type|. */
void
test_stream_item_check_type(const test_stream_item_t *item, char type)
{
  if (!item)
    return;
  ck_assert_int_eq(item->type, type);
}

/* Helper function to print test_stream_item_t members. */
void
test_stream_item_print(test_stream_item_t *item)
{
  printf("\n-- PRINT LIST ITEM: %p --\n", item);
  if (item) {
    printf("  data = %p\n", item->data);
    printf("  data_size = %zu\n", item->data_size);
    printf("  type = %c\n", item->type);
    printf("  prev = %p\n", item->prev);
    printf("  next = %p\n", item->next);
  }
  printf("-- END PRINT LIST ITEM --\n");
}

/**
 * test_stream_t functions
 */

/* Creates a test stream with items based on the input string for a given |codec|. The
 * string is converted to test stream items. */
test_stream_t *
test_stream_create(const char *str, MediaSigningCodec codec)
{
  test_stream_t *list = (test_stream_t *)calloc(1, sizeof(test_stream_t));
  ck_assert(list);
  list->codec = codec;
  uint8_t i = 0;

  while (str[i]) {
    test_stream_item_t *new_item = test_stream_item_create_from_type(str[i], i, codec);
    if (!new_item) {
      // No character could be identified. Continue without adding.
      i++;
      continue;
    }
    test_stream_append_last_item(list, new_item);
    i++;
  }

  return list;
}

/* Frees all the items in the |list| and the |list| itself. */
void
test_stream_free(test_stream_t *list)
{
  if (!list)
    return;

  // Pop all items and free them.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  while (item) {
    test_stream_item_free(item);
    item = test_stream_pop_first_item(list);
  }
  free(list);
}

/* Makes a refresh on the |list|. This means restoring all struct members. Helpful if the
 * |list| is out of sync. Rewinds the |first_item| to the beginning and loops through all
 * items to get the size, the |last_item| and the |types|. Note that the |first_item| has
 * to be represented in the |list|. */
void
test_stream_refresh(test_stream_t *list)
{
  if (!list)
    return;

  // Start from scratch, that is, reset |num_items| and |types|.
  list->num_items = 0;
  memset(list->types, 0, sizeof(list->types));
  // Rewind first_item to get the true first list item.
  while (list->first_item && (list->first_item)->prev) {
    list->first_item = (list->first_item)->prev;
  }
  // Start from the |first_item| and count, as well as updating, the types.
  test_stream_item_t *item = list->first_item;
  while (item) {
    list->types[list->num_items] = item->type;
    list->num_items++;

    if (!item->next || list->num_items > MAX_NUM_ITEMS)
      break;
    item = item->next;
  }
  list->last_item = item;
}

/* Pops |number_of_items| from a |list| and returns a new list with these items. If there
 * is not at least |number_of_items| in the list NULL is returned. */
test_stream_t *
test_stream_pop(test_stream_t *list, int number_of_items)
{
  if (!list || number_of_items > list->num_items)
    return NULL;

  // Create an empty list.
  test_stream_t *new_list = test_stream_create("", list->codec);
  ck_assert(new_list);
  // Pop items from list and append to the new_list.
  while (number_of_items--) {
    test_stream_item_t *item = test_stream_pop_first_item(list);
    test_stream_append_last_item(new_list, item);
  }

  return new_list;
}

/* Pops |number_of_gops| from a |list| and returns a new list with these items. If there
 * is not at least |number_of_gops| in the list NULL is returned. */
test_stream_t *
test_stream_pop_gops(test_stream_t *list, int number_of_gops)
{
  if (!list) {
    return NULL;
  }

  // Count number of I-frames, which equals number of GOPs.
  int num_gops_in_list = 0;
  test_stream_item_t *item = list->first_item;
  while (item) {
    num_gops_in_list += item->type == 'I';
    item = item->next;
  }

  if (num_gops_in_list < number_of_gops) {
    return NULL;
  }

  // Create an empty list.
  test_stream_t *new_list = test_stream_create("", list->codec);
  ck_assert(new_list);
  // Pop items from list and append to the new_list.
  while (number_of_gops) {
    test_stream_item_t *item = test_stream_pop_first_item(list);
    test_stream_append_last_item(new_list, item);
    number_of_gops -= list->first_item->type == 'I';  // Reached end of GOP
  }

  return new_list;
}

/* Appends a test stream to a |list|. The |list_to_append| is freed after the operation.
 */
void
test_stream_append(test_stream_t *list, test_stream_t *list_to_append)
{
  if (!list || !list_to_append)
    return;
  if (list->num_items + list_to_append->num_items > MAX_NUM_ITEMS)
    return;

  // Link the last and the first items together.
  list->last_item->next = list_to_append->first_item;
  list_to_append->first_item->prev = list->last_item;
  // Update the types.
  memcpy(&list->types[list->num_items], list_to_append->types,
      sizeof(char) * list_to_append->num_items);
  // Update the number of items.
  list->num_items += list_to_append->num_items;
  // Detach the |first_item| and the |last_item| from the |list_to_append|.
  list_to_append->first_item = NULL;
  list_to_append->last_item = NULL;
  test_stream_free(list_to_append);
}

/* Appends the list item with position |item_number| with a |new_item|. */
void
test_stream_append_item(test_stream_t *list,
    test_stream_item_t *new_item,
    int item_number)
{
  if (!list || !new_item)
    return;

  test_stream_item_t *item_to_append = test_stream_item_get(list, item_number);
  if (!item_to_append)
    return;

  test_stream_item_append(item_to_append, new_item);
  test_stream_refresh(list);
}

/* Appends the |last_item| of a |list| with a |new_item|. */
static void
test_stream_append_last_item(test_stream_t *list, test_stream_item_t *new_item)
{
  if (!list || !new_item)
    return;

  // If list is empty set |new_item| as |first_item|.
  if (!list->first_item)
    list->first_item = new_item;
  if (list->last_item)
    test_stream_item_append(list->last_item, new_item);

  test_stream_refresh(list);
}

/* Prepends the |first_item| of a |list| with a |new_item|. */
void
test_stream_prepend_first_item(test_stream_t *list, test_stream_item_t *new_item)
{
  if (!list || !new_item)
    return;

  if (list->first_item)
    test_stream_item_prepend(list->first_item, new_item);
  else
    list->first_item = new_item;

  test_stream_refresh(list);
}

/* Checks the sequence of NAL Units in |list| against their expected |types|. */
void
test_stream_check_types(const test_stream_t *list, const char *types)
{
  if (!list) {
    ck_assert(false);
  } else {
    ck_assert_int_eq(strcmp(list->types, types), 0);
  }
}

/* Helper function to print test_stream_t members. */
void
test_stream_print(test_stream_t *list)
{
  printf("\nPRINT LIST: %p\n", list);
  if (list) {
    printf("  first_item = %p\n", list->first_item);
    printf("  last_item = %p\n", list->last_item);
    printf("  num_items = %d\n", list->num_items);
    printf("  types = %s\n", list->types);
    printf("  codec = %s\n", list->codec == OMS_CODEC_H264 ? "H.264" : "H.265");
    printf("END PRINT LIST\n");
  }
}
