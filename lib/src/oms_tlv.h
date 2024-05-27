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

#ifndef __OMS_TLV_H__
#define __OMS_TLV_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
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
 * @returns Array that contains all optional tags.
 */
const oms_tlv_tag_t *
get_optional_tags(size_t *num_optional_tags);

/**
 * @brief Helper to get only the mandatory tags as an array
 *
 * @param num_mandatory_tags A pointer to a location where number of mandatory tags
 *   will be written.
 *
 * @returns Array that contains all mandatory tags.
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
 * @returns The size of the data encoded.
 */
size_t
tlv_list_encode_or_get_size(onvif_media_signing_t *self,
    const oms_tlv_tag_t *tags,
    size_t num_tags,
    uint8_t *data);

#if 0
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
 * @returns A pointer to the location of the tag to scan for. Returns NULL if the tag was
 *   not found.
 */
const uint8_t *
tlv_find_tag(const uint8_t *tlv_data, size_t tlv_data_size, oms_tlv_tag_t tag, bool with_ep);

#endif
/**
 * @brief Reads bits from p into val.
 *
 * @returns Number of bytes read.
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

#if 0
/**
 * @brief Writes many bytes to payload w/wo emulation prevention
 *
 * @param dst Location to write
 * @param src Location from where to read data
 * @param size Number of bytes to write to |dst|, usually size of |src|
 * @param last_two_bytes For emulation prevention
 */
void
write_byte_many(uint8_t **dst,
    char *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention);
#endif

/**
 * @brief Writes a byte to payload w/wo emulation prevention
 *
 * @param last_two_bytes For emulation prevention
 * @param payload Location write byte
 * @param byte Byte to write
 * @param do_emulation_prevention If emulation prevention
 */
void
write_byte(uint16_t *last_two_bytes,
    uint8_t **payload,
    uint8_t byte,
    bool do_emulation_prevention);

/**
 * @brief Reads a byte from payload w/wo emulation prevention
 *
 * @returns The byte read.
 */
uint8_t
read_byte(uint16_t *last_two_bytes,
    const uint8_t **payload,
    bool do_emulation_prevention);

#endif  // __OMS_TLV_H__
