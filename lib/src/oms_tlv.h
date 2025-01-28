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

#ifndef __OMS_TLV_H__
#define __OMS_TLV_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t, uint16_t, uint32_t, uint64_t, int64_t
#include <stdlib.h>  // size_t

#include "includes/onvif_media_signing_common.h"  // onvif_media_signing_t
#include "oms_defines.h"  // oms_rc

/**
 * Definition of available TLV tags.
 *
 * NOTE: When a new tag is added simply append the sub-list of valid tags. Changing the
 * number of existing tags will break backwards compatibility!
 */
typedef enum {
  UNDEFINED_TAG = 0,  // Should always be zero
  GENERAL_TAG = 1,
  HASH_LIST_TAG = 2,
  SIGNATURE_TAG = 3,
  CRYPTO_INFO_TAG = 4,
  VENDOR_INFO_TAG = 5,
  CERTIFICATES_TAG = 6,
  ARBITRARY_DATA_TAG = 7,
  NUMBER_OF_TLV_TAGS = 8,
} oms_tlv_tag_t;

/**
 * @brief Helper to get only the optional tags as an array
 *
 * @param num_optional_tags A pointer to a location where the number of optional tags
 *   will be written.
 *
 * @return Array that contains all optional tags.
 */
const oms_tlv_tag_t *
get_optional_tags(size_t *num_optional_tags);

/**
 * @brief Helper to get only the mandatory tags as an array
 *
 * @param num_mandatory_tags A pointer to a location where number of mandatory tags
 *   will be written.
 *
 * @return Array that contains all mandatory tags.
 */
const oms_tlv_tag_t *
get_mandatory_tags(size_t *num_mandatory_tags);

/**
 * @brief Gets the signature tag
 */
oms_tlv_tag_t
get_signature_tag();

/**
 * @brief Encodes a SEI payload defined by a list of tags.
 *
 * The tags are written to data in a TLV structure. The tags define a TLV tuple
 * associating encoders and decoders with the tag.
 *
 * @param self Pointer to the onvif_media_signing_t object.
 * @param tags Array of tags to be encoded.
 * @param num_tags Number of tags in the array.
 * @param data Pointer to the memory to write to, or a NULL pointer to only get the size.
 *
 * @return The size of the data encoded.
 */
size_t
tlv_list_encode_or_get_size(onvif_media_signing_t *self,
    const oms_tlv_tag_t *tags,
    size_t num_tags,
    uint8_t *data);

/**
 * @brief Decodes a SEI payload into the onvif_media_signing_t object.
 *
 * The data is assumed to have been written in a TLV format. This function parses data as
 * long as there are more tags.
 *
 * @param self Pointer to the onvif_media_signing_t object.
 * @param data Pointer to the data to read from.
 * @param data_size Size of the data.
 *
 * @returns OMS_OK if decoding was successful, otherwise an error code.
 */
oms_rc
tlv_decode(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

/**
 * @brief Scans the TLV part of a SEI payload and decodes all recurrent tags
 *
 * The data is assumed to have been written in a TLV format. This function parses data and
 * finds all tags dependent on recurrency (marked not |mandatory|) and decodes
 * them.
 *
 * @param self Pointer to the onvif_media_signing_t session.
 * @param tlv_data Pointer to the TLV data to scan.
 * @param tlv_data_size Size of the TLV data.
 *
 * @returns True if find and decoding tag was successful.
 */
bool
tlv_find_and_decode_optional_tags(onvif_media_signing_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size);
bool
tlv_find_and_decode_signature_tag(onvif_media_signing_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size);

/**
 * @brief Scans the TLV part of a SEI payload and stops when a given tag is detected.
 *
 * The data is assumed to have been written in a TLV format. This function parses data as
 * long as there are more tags, but never decodes it. The function can handle data both
 * with and without emulation prevention bytes.
 *
 * @param tlv_data Pointer to the TLV data to scan.
 * @param tlv_data_size Size of the TLV data.
 * @param tag The tag to search for and when detected returns its location.
 * @param with_ep Flag to indicate if emulation prevention bytes is on.
 *
 * @return A pointer to the location of the tag to scan for. Returns NULL if the tag was
 *   not found.
 */
const uint8_t *
tlv_find_tag(const uint8_t *tlv_data,
    size_t tlv_data_size,
    oms_tlv_tag_t tag,
    bool with_ep);

/**
 * @brief Reads bits from p into val.
 *
 * @param p The pointer location to start reading from.
 * @param val A pointer to where the result should be written.
 *
 * @return Number of bytes read.
 */
size_t
read_64bits_signed(const uint8_t *p, int64_t *val);
size_t
read_64bits(const uint8_t *p, uint64_t *val);
size_t
read_32bits(const uint8_t *p, uint32_t *val);
size_t
read_16bits(const uint8_t *p, uint16_t *val);
size_t
read_8bits(const uint8_t *p, uint8_t *val);

/**
 * @brief Writes many bytes to dst w/wo emulation prevention
 *
 * @param dst Location to write
 * @param src Location from where to read data
 * @param size Number of bytes to write to |dst|, usually size of |src|
 * @param last_two_bytes For emulation prevention
 */
void
write_byte_many(uint8_t **dst,
    uint8_t *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention);

/**
 * @brief Writes a byte to dst w/wo emulation prevention
 *
 * @param last_two_bytes For emulation prevention
 * @param dst Location write byte
 * @param byte Byte to write
 * @param do_emulation_prevention If emulation prevention
 */
void
write_byte(uint16_t *last_two_bytes,
    uint8_t **dst,
    uint8_t byte,
    bool do_emulation_prevention);

/**
 * @brief Reads a byte from dst w/wo emulation prevention
 *
 * @param last_two_bytes For emulation prevention
 * @param dst Location read byte
 * @param do_emulation_prevention If emulation prevention
 *
 * @return The byte read.
 */
uint8_t
read_byte(uint16_t *last_two_bytes, const uint8_t **dst, bool do_emulation_prevention);

/**
 * @brief Reads many bytes to dst w/wo emulation prevention
 *
 * @param dst Location to write (NULL pointer is allowed for which the read value is
 *   ignored)
 * @param src Location from where to read data
 * @param size Number of bytes to write to |dst|, usually size of |src|
 * @param last_two_bytes For emulation prevention
 * @param do_emulation_prevention If emulation prevention
 */
void
read_byte_many(uint8_t *dst,
    const uint8_t **src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention);

#endif  // __OMS_TLV_H__
