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

#include "oms_tlv.h"

// #include "includes/signed_video_auth.h"  // signed_video_product_info_t
// #include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
// #include "signed_video_authenticity.h"  // transfer_product_info()
// #include "signed_video_openssl_internal.h"  // openssl_public_key_malloc()
#include "oms_internal.h"  // gop_info_t

/**
 * Encoder and decoder interfaces
 */

/**
 * @brief TLV encoder interface
 *
 * @param onvif_media_signing_t The Media Signing object to encode.
 * @param data Pointer to the data to write to. If NULL only returns the data size of the
 * data.
 *
 * @returns The size of the data written.
 */
typedef size_t (*oms_tlv_encoder_t)(onvif_media_signing_t *, uint8_t *);

/**
 * @brief TLV decoder interface
 *
 * @param data Pointer to the data to decode.
 * @param data_size Size of the data.
 * @param onvif_media_signing_t The Signed Video object to write to.
 *
 * @returns OMS_OK if successful otherwise an error code.
 */
typedef oms_rc (*oms_tlv_decoder_t)(onvif_media_signing_t *, const uint8_t *, size_t);

/**
 * Declarations of encoder and decoder implementations.
 */
static size_t
encode_general(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_general(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_hash_list(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_hash_list(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_signature(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_signature(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_crypto_info(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_crypto_info(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_vendor_info(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_vendor_info(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_certificates(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_certificates(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_arbitrary_data(onvif_media_signing_t *self, uint8_t *data);
static oms_rc
decode_arbitrary_data(onvif_media_signing_t *self, const uint8_t *data, size_t data_size);

/**
 * Definition of a TLV tuple associating the TLV Tag with an encoder, a decoder and
 * whether it is mandatory in an ordinary SEI or not.
 */
typedef struct {
  oms_tlv_tag_t tag;
  oms_tlv_encoder_t encoder;
  oms_tlv_decoder_t decoder;
  bool mandatory;
} oms_tlv_tuple_t;

/**
 * This is an array of all available TLV tuples. The first and last tuples, which are
 * invalid tags, have dummy values to avoid the risk of reading outside memory.
 *
 * NOTE: They HAVE TO be in the same order as the available tags!
 *
 * When you add a new tag you have to add the tuple to this array as well.
 */
static const oms_tlv_tuple_t tlv_tuples[] = {
    {UNDEFINED_TAG, NULL, NULL, true},
    {GENERAL_TAG, encode_general, decode_general, true},
    {HASH_LIST_TAG, encode_hash_list, decode_hash_list, true},
    {SIGNATURE_TAG, encode_signature, decode_signature, true},
    {CRYPTO_INFO_TAG, encode_crypto_info, decode_crypto_info, false},
    {VENDOR_INFO_TAG, encode_vendor_info, decode_vendor_info, false},
    {CERTIFICATES_TAG, encode_certificates, decode_certificates, false},
    {ARBITRARY_DATA_TAG, encode_arbitrary_data, decode_arbitrary_data, true},
    {NUMBER_OF_TLV_TAGS, NULL, NULL, true},
};

/*
 * This is an array that contains only optional tags (not |mandatory|).
 */
static const oms_tlv_tag_t optional_tags[] = {
    CRYPTO_INFO_TAG,
    VENDOR_INFO_TAG,
    CERTIFICATES_TAG,
};

/*
 * This is an array that contains only mandatory tags (|mandatory|).
 * Array excludes the SIGNATURE_TAG since it has to be treated separately.
 */
static const oms_tlv_tag_t mandatory_tags[] = {
    GENERAL_TAG,
    HASH_LIST_TAG,
    ARBITRARY_DATA_TAG,
};

/**
 * Declarations of STATIC functions.
 */
static oms_tlv_decoder_t
get_decoder(oms_tlv_tag_t tag);
static oms_tlv_tuple_t
get_tlv_tuple(oms_tlv_tag_t tag);
static oms_rc
decode_tlv_header(const uint8_t *data,
    size_t *data_bytes_read,
    oms_tlv_tag_t *tag,
    size_t *length);

/* Selects and returns the correct decoder from either |tlv_tuples|. */
static oms_tlv_decoder_t
get_decoder(oms_tlv_tag_t tag)
{
  return tlv_tuples[tag].decoder;
}

/* Selects and returns the correct tlv_tuple from either |tlv_tuples|. */
static oms_tlv_tuple_t
get_tlv_tuple(oms_tlv_tag_t tag)
{
  if ((tag > UNDEFINED_TAG) && (tag < NUMBER_OF_TLV_TAGS)) {
    // Library tag.
    return tlv_tuples[tag];
  } else {
    // Unknown tag.
    return tlv_tuples[UNDEFINED_TAG];
  }
}

/**
 * @brief Encodes the GENERAL_TAG into data
 */
static size_t
encode_general(onvif_media_signing_t *self, uint8_t *data)
{
  gop_info_t *gop_info = self->gop_info;
  size_t data_size = 0;
  uint32_t gop_counter = gop_info->current_gop;
  uint16_t num_nalus_in_partial_gop = gop_info->num_nalus_in_partial_gop;
  const uint8_t version = 1;
  int64_t timestamp = gop_info->timestamp;
  size_t hash_size = openssl_get_hash_size(self->crypto_handle);

  // Value fields:
  //  - version (1 byte)
  //  - media signing version (OMS_VERSION_BYTES bytes)
  //  - timestamp (8 bytes)
  //  - gop_counter (4 bytes)
  //  - num_nalus_in_partial_gop (2 bytes)
  //  - partial_gop_hash (hash_size bytes)
  //  - linked_hash (hash_size bytes)

  // Get size of data
  data_size += sizeof(version);
  data_size += OMS_VERSION_BYTES;
  data_size += sizeof(timestamp);
  data_size += sizeof(gop_counter);
  data_size += sizeof(num_nalus_in_partial_gop);
  data_size += hash_size;  // partial_gop_hash
  data_size += hash_size;  // linked_hash

  if (!data) {
    DEBUG_LOG("General tag has size %zu", data_size);
    return data_size;
  }

  DEBUG_LOG("Encoding GOP counter = %u", gop_counter);

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Media Signing version
  for (int i = 0; i < OMS_VERSION_BYTES; i++) {
    write_byte(last_two_bytes, &data_ptr, (uint8_t)self->code_version[i], epb);
  }
  // Write timestamp; 8 bytes
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 56) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 48) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 40) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 32) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 24) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 16) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 8) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp)&0x000000ff), epb);
  // GOP counter; 4 bytes
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 24) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 16) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 8) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter)&0x000000ff), epb);
  // Write num_nalus_in_partial_gop; 2 bytes
  write_byte(last_two_bytes, &data_ptr,
      (uint8_t)((num_nalus_in_partial_gop >> 8) & 0x00ff), epb);
  write_byte(
      last_two_bytes, &data_ptr, (uint8_t)((num_nalus_in_partial_gop)&0x00ff), epb);
  // Write the partial_gop_hash; hash_size bytes
  write_byte_many(&data_ptr, gop_info->partial_gop_hash, hash_size, last_two_bytes, epb);
  // Write the linked_hash; hash_size bytes
  write_byte_many(&data_ptr, gop_info->linked_hash, hash_size, last_two_bytes, epb);

  return (data_ptr - data);
}

/**
 * @brief Decodes the GENERAL_TAG from data
 */
static oms_rc
decode_general(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  if (!self || !data)
    return OMS_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  uint8_t version = *data_ptr++;
  oms_rc status = OMS_UNKNOWN_FAILURE;

  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);

    // Read Media Signing version
    for (int i = 0; i < OMS_VERSION_BYTES; i++) {
      self->code_version[i] = *data_ptr++;
    }
    bytes_to_version_str(self->code_version, self->authenticity->version_on_signing_side);
    // Read timestamp
    data_ptr += read_64bits_signed(data_ptr, &gop_info->timestamp);
    // self->latest_validation->timestamp = gop_info->timestamp;
    // Read current GOP
    data_ptr += read_32bits(data_ptr, &gop_info->current_gop);
    DEBUG_LOG("Found GOP counter = %u", gop_info->current_gop);
    // Read number of NAL Units part of the (partial) GOP
    data_ptr += read_16bits(data_ptr, &gop_info->num_sent_nalus);
    DEBUG_LOG("Number of sent NAL Units = %u", gop_info->num_sent_nalus);
    // Read (partial) GOP hash. Remaining data is split into two hashes of equal size.
    size_t hash_size = (data_size - (data_ptr - data)) / 2;
    uint16_t last_two_bytes = 0xffff;  // Not needed
    read_byte_many(
        gop_info->partial_gop_hash, &data_ptr, hash_size, &last_two_bytes, false);
    // Read linked hash.
    read_byte_many(gop_info->linked_hash, &data_ptr, hash_size, &last_two_bytes, false);

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
  OMS_CATCH()
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

/**
 * @brief Encodes the PRODUCT_INFO_TAG into data
 */
static size_t
encode_vendor_info(onvif_media_signing_t *self, uint8_t *data)
{
#if 0
  signed_video_product_info_t *product_info = &self->product_info;
  size_t data_size = 0;
  const uint8_t version = 2;

  // Value fields:
  //  - version (1 byte)
  //  - hardware_id_size (1 byte)
  //  - hardware_id
  //  - firmware_version
  //  - firmware_version_size (1 byte)
  //  - serial_number
  //  - serial_number_size (1 byte)
  //  - manufacturer
  //  - manufacturer_size (1 byte)
  //  - address
  //  - address_size (1 byte)

  data_size += sizeof(version);

  // Determine sizes excluding null-terminated character
  data_size += 1;
  size_t hardware_id_size = strlen(product_info->hardware_id);
  data_size += hardware_id_size;

  data_size += 1;
  size_t firmware_version_size = strlen(product_info->firmware_version);
  data_size += firmware_version_size;

  data_size += 1;
  size_t serial_number_size = strlen(product_info->serial_number);
  data_size += serial_number_size;

  data_size += 1;
  size_t manufacturer_size = strlen(product_info->manufacturer);
  data_size += manufacturer_size;

  data_size += 1;
  size_t address_size = strlen(product_info->address);
  data_size += address_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  // Write |hardware_id|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, hardware_id_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, product_info->hardware_id, hardware_id_size, last_two_bytes, epb);

  // Write |firmware_version|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, firmware_version_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(
      &data_ptr, product_info->firmware_version, firmware_version_size, last_two_bytes, epb);

  // Write |serial_number|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, serial_number_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, product_info->serial_number, serial_number_size, last_two_bytes, epb);

  // Write |manufacturer|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, manufacturer_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, product_info->manufacturer, manufacturer_size, last_two_bytes, epb);

  // Write |address|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, address_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, product_info->address, address_size, last_two_bytes, epb);

  return (data_ptr - data);
#else
  return !self ? 0 : (data ? 1 : 0);
#endif
}

/**
 * @brief Decodes the PRODUCT_INFO_TAG from data
 */
static oms_rc
decode_vendor_info(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  oms_rc status = OMS_UNKNOWN_FAILURE;

  if (!self)
    return OMS_INVALID_PARAMETER;

  OMS_TRY()
    OMS_THROW_IF(version == 0, OMS_INCOMPATIBLE_VERSION);

    signed_video_product_info_t *product_info = &self->product_info;

    product_info_reset_members(product_info);

    uint8_t hardware_id_size = *data_ptr++;
    strncpy(product_info->hardware_id, (const char *)data_ptr, hardware_id_size);
    data_ptr += hardware_id_size;

    uint8_t firmware_version_size = *data_ptr++;
    strncpy(
        product_info->firmware_version, (const char *)data_ptr, firmware_version_size);
    data_ptr += firmware_version_size;

    uint8_t serial_number_size = *data_ptr++;
    strncpy(product_info->serial_number, (const char *)data_ptr, serial_number_size);
    data_ptr += serial_number_size;

    uint8_t manufacturer_size = *data_ptr++;
    strncpy(product_info->manufacturer, (const char *)data_ptr, manufacturer_size);
    data_ptr += manufacturer_size;

    uint8_t address_size = *data_ptr++;
    strncpy(product_info->address, (const char *)data_ptr, address_size);
    data_ptr += address_size;

    // Transfer the decoded |product_info| to the authenticity report.
    OMS_THROW(transfer_product_info(&self->authenticity->product_info, product_info));

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);

  OMS_CATCH()
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

/**
 * @brief Encodes the ARBITRARY_DATA_TAG into data
 */
static size_t
encode_arbitrary_data(onvif_media_signing_t *self, uint8_t *data)
{
#if 0
  size_t data_size = 0;
  const uint8_t version = 1;

  if (!self->arbitrary_data || self->arbitrary_data_size == 0) return 0;

  data_size += sizeof(version);

  // Size of arbitrary_data
  data_size += self->arbitrary_data_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  for (size_t ii = 0; ii < self->arbitrary_data_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, self->arbitrary_data[ii], epb);
  }

  return (data_ptr - data);
#else
  return !self ? 0 : (data ? 1 : 0);
#endif
}

/**
 * @brief Decodes the ARBITRARY_DATA_TAG from data
 */
static oms_rc
decode_arbitrary_data(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  uint16_t arbdata_size = (uint16_t)(data_size - 1);
  oms_rc status = OMS_UNKNOWN_FAILURE;

  OMS_TRY()
    OMS_THROW_IF(version == 0, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(arbdata_size == 0, OMS_AUTHENTICATION_ERROR);
    uint8_t *arbdata = realloc(self->arbitrary_data, arbdata_size);
    OMS_THROW_IF(!arbdata, OMS_MEMORY);
    memcpy(arbdata, data_ptr, arbdata_size);
    self->arbitrary_data = arbdata;
    self->arbitrary_data_size = arbdata_size;
    data_ptr += arbdata_size;
    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
  OMS_CATCH()
  {
    free(self->arbitrary_data);
    self->arbitrary_data = NULL;
    self->arbitrary_data_size = 0;
  }
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

/**
 * @brief Encodes the PUBLIC_KEY_TAG into data
 */
static size_t
encode_certificates(onvif_media_signing_t *self, uint8_t *data)
{
#if 0
  pem_pkey_t *pem_public_key = &self->pem_public_key;
  size_t data_size = 0;
  const uint8_t version = 2;

  // If there is no |key| present, or if it should not be added to the SEI, skip encoding,
  // that is, return 0.
  if (!pem_public_key->key || !self->add_public_key_to_sei) return 0;

  // Value fields:
  //  - version (1 byte)
  //  - public_key (key_size bytes)
  //  - num_nalus_in_partial_gop (2 bytes)
  //  - signed video version (SV_VERSION_BYTES bytes)
  //  - flags (1 byte)
  //  - timestamp (8 bytes) requires version 2+

  // Version 1:
  //  - version (1 byte)
  //  - public_key
  //
  // Note that we do not have to store the size of the public. We already know it from the TLV
  // length.

  data_size += sizeof(version);

  // Size of pubkey
  data_size += pem_public_key->key_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint8_t *public_key = (uint8_t *)pem_public_key->key;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  // public_key; public_key_size bytes
  for (size_t ii = 0; ii < pem_public_key->key_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, public_key[ii], epb);
  }

  return (data_ptr - data);
#else
  return !self ? 0 : (data ? 1 : 0);
#endif
}

/**
 * @brief Decodes the PUBLIC_KEY_TAG from data
 *
 */
static oms_rc
decode_certificates(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  const uint8_t *data_ptr = data;
  pem_pkey_t *pem_public_key = &self->pem_public_key;
  uint8_t version = *data_ptr++;
  uint16_t pubkey_size = (uint16_t)(data_size - 1);  // We only store version and the key.

  // The algo was removed in version 2 since it is not needed. Simply move to next byte if
  // older version.
  if (version < 2) {
    data_ptr++;
    pubkey_size -= 1;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version == 0, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(pubkey_size == 0, OMS_AUTHENTICATION_ERROR);

    if (pem_public_key->key_size != pubkey_size) {
      free(pem_public_key->key);
      pem_public_key->key = calloc(1, pubkey_size);
      OMS_THROW_IF(!pem_public_key->key, OMS_MEMORY);
      pem_public_key->key_size = pubkey_size;
    }

    int key_diff = memcmp(data_ptr, pem_public_key->key, pubkey_size);
    if (self->has_public_key && key_diff) {
      self->latest_validation->public_key_has_changed = true;
    }
    memcpy(pem_public_key->key, data_ptr, pubkey_size);
    self->has_public_key = true;
    data_ptr += pubkey_size;

    // Convert to EVP_PKEY_CTX
    OMS_THROW(openssl_public_key_malloc(self->verify_data, &self->pem_public_key));

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // If "Axis Communications AB" can be identified from the |product_info|, set
    // |public_key| to |vendor_handle|.
    if (strcmp(self->product_info.manufacturer, "Axis Communications AB") == 0) {
      // Set public key.
      SV_THROW(set_axis_communications_public_key(self->vendor_handle,
          self->verify_data->key, self->latest_validation->public_key_has_changed));
    }
#endif

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
  OMS_CATCH()
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

/**
 * @brief Encodes the HASH_LIST_TAG into data
 *
 */
static size_t
encode_hash_list(onvif_media_signing_t *self, uint8_t *data)
{
#if 0
  gop_info_t *gop_info = self->gop_info;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // If the |hash_list| is empty, or invalid, skip encoding, that is, return 0. Also, if we do not
  // use OMS_AUTHENTICITY_LEVEL_FRAME skip encoding.
  if (gop_info->list_idx <= 0 || self->authenticity_level != OMS_AUTHENTICITY_LEVEL_FRAME) return 0;

  // Value fields:
  //  - version (1 byte)
  //  - hash_list (list_idx bytes)

  data_size += sizeof(version);
  data_size += gop_info->list_idx * sizeof(gop_info->hash_list[0]);

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write hash_list data
  for (int i = 0; i < gop_info->list_idx; i++) {
    write_byte(last_two_bytes, &data_ptr, gop_info->hash_list[i], epb);
  }

  // Having successfully encoded the hash_list means we should sign the document_hash and not the
  // gop_hash.
  self->gop_info->signature_hash_type = DOCUMENT_HASH;

  return (data_ptr - data);
#else
  return !self ? 0 : (data ? 1 : 0);
#endif
}

/**
 * @brief Decodes the HASH_LIST_TAG from data
 */
static oms_rc
decode_hash_list(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_list_size = data_size - (data_ptr - data);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version == 0, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF_WITH_MSG(hash_list_size > HASH_LIST_SIZE, OMS_MEMORY,
        "Found more hashes than fit in hash_list");
    memcpy(self->gop_info->hash_list, data_ptr, hash_list_size);
    self->gop_info->list_idx = (int)hash_list_size;

    data_ptr += hash_list_size;

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);

  OMS_CATCH()
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

/**
 * @brief Encodes the SIGNATURE_TAG into data
 */
static size_t
encode_signature(onvif_media_signing_t *self, uint8_t *data)
{
#if 0
  gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *sign_data = self->sign_data;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // Value fields:
  //  - version (1 byte)
  //  - info field (1 byte)
  //  - hash type (1 byte)
  //  - signature size (2 bytes)
  //  - signature (max_signature_size bytes)

  data_size += sizeof(version);

  // Info field. This field holds information on whether the GOP info was correctly created or if
  // there were errors. This means that the validator is informed what can be verified and what
  // cannot.
  data_size += sizeof(gop_info->encoding_status);  // Info field
  data_size += 1;  // hash type
  data_size += 2;  // 2 bytes to store the actual size of the signature.
  data_size += sign_data->max_signature_size;  // Allocated size of the signature

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint16_t signature_size = (uint16_t)sign_data->signature_size;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write info field
  write_byte(last_two_bytes, &data_ptr, gop_info->encoding_status, epb);
  // Write hash type
  write_byte(last_two_bytes, &data_ptr, (uint8_t)gop_info->signature_hash_type, epb);
  // Write actual signature size (2 bytes)
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size >> 8) & 0x00ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size)&0x00ff), epb);
  // Write signature
  size_t i = 0;
  for (; i < signature_size; i++) {
    write_byte(last_two_bytes, &data_ptr, sign_data->signature[i], epb);
  }
  for (; i < sign_data->max_signature_size; i++) {
    // Write 1's in the unused bytes to avoid emulation prevention bytes.
    write_byte(last_two_bytes, &data_ptr, 1, epb);
  }

  return (data_ptr - data);
#else
  return !self ? 0 : (data ? 1 : 0);
#endif
}

/**
 * @brief Decodes the SIGNATURE_TAG from data
 */
static oms_rc
decode_signature(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *verify_data = self->verify_data;
  uint8_t **signature_ptr = &verify_data->signature;
  uint8_t version = *data_ptr++;
  uint8_t encoding_status = *data_ptr++;
  hash_type_t hash_type = *data_ptr++;
  uint16_t signature_size = 0;
  size_t max_signature_size = 0;

  // Read true size of the signature.
  data_ptr += read_16bits(data_ptr, &signature_size);
  // The rest of the value bytes should now be the allocated size for the signature.
  max_signature_size = data_size - (data_ptr - data);

  oms_rc status = OMS_UNKNOWN_FAILURE;

  OMS_TRY()
    OMS_THROW_IF(version == 0, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(hash_type < 0 || hash_type >= NUM_HASH_TYPES, OMS_AUTHENTICATION_ERROR);
    OMS_THROW_IF(max_signature_size < signature_size, OMS_AUTHENTICATION_ERROR);
    if (!*signature_ptr) {
      verify_data->max_signature_size = 0;
      verify_data->signature_size = 0;
      // Allocate enough space for future signatures as well, that is, max_signature_size.
      *signature_ptr = malloc(max_signature_size);
      OMS_THROW_IF(!*signature_ptr, OMS_MEMORY);
      // Set memory size.
      verify_data->max_signature_size = max_signature_size;
    }
    OMS_THROW_IF(verify_data->max_signature_size != max_signature_size, OMS_MEMORY);
    memcpy(*signature_ptr, data_ptr, max_signature_size);
    data_ptr += max_signature_size;

    // Set true signature size.
    verify_data->signature_size = signature_size;
    gop_info->encoding_status = encoding_status;
    gop_info->signature_hash_type = hash_type;
    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
  OMS_CATCH()
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

/**
 * @brief Encodes the CRYPTO_INFO_TAG into data
 */
static size_t
encode_crypto_info(onvif_media_signing_t *self, uint8_t *data)
{
#if 0
  size_t hash_algo_encoded_oid_size = 0;
  const unsigned char *hash_algo_encoded_oid =
      openssl_get_hash_algo_encoded_oid(self->crypto_handle, &hash_algo_encoded_oid_size);
  size_t data_size = 0;
  const uint8_t version = 1;

  // If there is no hash algorithm present skip encoding, that is, return 0.
  if (!hash_algo_encoded_oid || !hash_algo_encoded_oid_size) return 0;

  // Value fields:
  //  - version (1 byte)
  //  - size of hash algo OID (serialized form) (1 byte)
  //  - hash algo (hash_algo_encoded_oid_size bytes)

  data_size += sizeof(version);
  data_size += sizeof(uint8_t);
  // Size of hash algorithm in OID serialized form
  data_size += hash_algo_encoded_oid_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // OID size
  write_byte(last_two_bytes, &data_ptr, (uint8_t)hash_algo_encoded_oid_size, epb);

  // OID data; hash_algo_encoded_oid_size bytes
  for (size_t ii = 0; ii < hash_algo_encoded_oid_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, hash_algo_encoded_oid[ii], epb);
  }

  return (data_ptr - data);
#else
  return !self ? 0 : (data ? 1 : 0);
#endif
}

/**
 * @brief Decodes the CRYPTO_INFO_TAG from data
 */
static oms_rc
decode_crypto_info(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
#ifdef VALIDATION_SIDE
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_algo_encoded_oid_size = *data_ptr++;
  const unsigned char *hash_algo_encoded_oid = (const unsigned char *)data_ptr;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version == 0, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(hash_algo_encoded_oid_size == 0, OMS_AUTHENTICATION_ERROR);
    OMS_THROW(openssl_set_hash_algo_by_encoded_oid(
        self->crypto_handle, hash_algo_encoded_oid, hash_algo_encoded_oid_size));
    self->validation_flags.hash_algo_known = true;
    self->verify_data->hash_size = openssl_get_hash_size(self->crypto_handle);
    data_ptr += hash_algo_encoded_oid_size;

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
  OMS_CATCH()
  OMS_DONE(status)

  return status;
#else
  return (self && data && data_size > 0) ? OMS_OK : OMS_AUTHENTICATION_ERROR;
#endif
}

static size_t
tlv_encode_or_get_size_generic(onvif_media_signing_t *self,
    const oms_tlv_tuple_t tlv,
    uint8_t *data)
{
  const size_t tl_size = 3;  // Fixed size of 1 + 2 bytes
  size_t v_size = 0;

  // TLV:
  //  - tag (1 byte)
  //  - length (2 bytes)
  //  - value (variable, dependent on encoder/decoder)

  v_size = tlv.encoder(self, NULL);

  if (v_size == 0) {
    // If there is no data to encode, there is no point in transmitting an empty tag.
    DEBUG_LOG("Tag %u is without payload", tlv.tag);
    return 0;
  }

  if (!data) {
    DEBUG_LOG("Tag %u is of total size %zu", tlv.tag, tl_size + v_size);
    return tl_size + v_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Write Tag
  write_byte(last_two_bytes, &data_ptr, (uint8_t)tlv.tag, epb);
  // Write length
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((v_size >> 8) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)(v_size & 0x000000ff), epb);

  // Write value, i.e., the actual data of the TLV
  size_t v_size_written = tlv.encoder(self, data_ptr);

  if (v_size_written != v_size) {
    DEBUG_LOG("Written size %zu != %zu computed size", v_size_written, v_size);
    return 0;
  }
  data_ptr += v_size_written;

  return data_ptr - data;
}

size_t
tlv_list_encode_or_get_size(onvif_media_signing_t *self,
    const oms_tlv_tag_t *tags,
    size_t num_tags,
    uint8_t *data)
{
  if (!self || !tags || !num_tags)
    return OMS_INVALID_PARAMETER;

  size_t tlv_list_size = 0;
  uint8_t *data_ptr = data;

  for (size_t ii = 0; ii < num_tags; ++ii) {
    oms_tlv_tag_t tag = tags[ii];
    oms_tlv_tuple_t tlv = get_tlv_tuple(tag);
    if (tlv.tag != tag) {
      DEBUG_LOG("Did not find TLV tuple from tag (%d)", tag);
      continue;
    }

    // TODO: Update this part when golden SEI is supported.
    if (tlv.mandatory || true) {
      size_t tlv_size = tlv_encode_or_get_size_generic(self, tlv, data_ptr);
      tlv_list_size += tlv_size;
      // Increment data_ptr if data is written
      if (data)
        data_ptr += tlv_size;
    }
  }
  return tlv_list_size;
}

static oms_rc
decode_tlv_header(const uint8_t *data,
    size_t *data_bytes_read,
    oms_tlv_tag_t *tag,
    size_t *length)
{
  // Sanity checks on input parameters.
  if (!data || !data_bytes_read || !tag || !length)
    return OMS_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  oms_tlv_tag_t tag_from_data = (oms_tlv_tag_t)(*data_ptr++);
  *data_bytes_read = 0;
  oms_tlv_tuple_t tlv = get_tlv_tuple(tag_from_data);
  if (tlv.tag != tag_from_data) {
    DEBUG_LOG("Parsed an invalid tag (%d) in the data", tag_from_data);
    return OMS_INVALID_PARAMETER;
  }
  *tag = tag_from_data;

  data_ptr += read_16bits(data_ptr, (uint16_t *)length);

  *data_bytes_read = (data_ptr - data);

  return OMS_OK;
}

oms_rc
tlv_decode(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  oms_rc status = OMS_INVALID_PARAMETER;
  const uint8_t *data_ptr = data;

  if (!self || !data || data_size == 0)
    return OMS_INVALID_PARAMETER;

  while (data_ptr < data + data_size) {
    oms_tlv_tag_t tag = 0;
    size_t tlv_header_size = 0;
    size_t length = 0;
    status = decode_tlv_header(data_ptr, &tlv_header_size, &tag, &length);
    if (status != OMS_OK) {
      DEBUG_LOG("Could not decode TLV header (error %d)", status);
      break;
    }
    data_ptr += tlv_header_size;

    oms_tlv_decoder_t decoder = get_decoder(tag);
    status = decoder(self, data_ptr, length);
    if (status != OMS_OK) {
      DEBUG_LOG("Could not decode data (error %d)", status);
      break;
    }
    data_ptr += length;
  }

  return status;
}

const uint8_t *
tlv_find_tag(const uint8_t *tlv_data,
    size_t tlv_data_size,
    oms_tlv_tag_t tag,
    bool with_ep)
{
  const uint8_t *tlv_data_ptr = tlv_data;
  const uint8_t *latest_tag_location = NULL;

  if (!tlv_data || tlv_data_size == 0)
    return 0;

  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  while (tlv_data_ptr < tlv_data + tlv_data_size) {
    latest_tag_location = tlv_data_ptr;
    // Read the tag
    oms_tlv_tag_t this_tag = read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    if (this_tag == tag) {
      return latest_tag_location;
    }

    // Read the length
    uint16_t length = read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    length <<= 8;
    length |= read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    // Scan past the data
    read_byte_many(NULL, &tlv_data_ptr, length, &last_two_bytes, with_ep);
  }
  DEBUG_LOG("Never found the tag %d", tag);

  return NULL;
}

bool
tlv_find_and_decode_optional_tags(onvif_media_signing_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size)
{
  const uint8_t *tlv_data_ptr = tlv_data;

  if (!self || !tlv_data || tlv_data_size == 0)
    return false;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  bool optional_tags_decoded = false;
  while (tlv_data_ptr < tlv_data + tlv_data_size) {
    size_t tlv_header_size = 0;
    size_t length = 0;
    oms_tlv_tag_t this_tag = UNDEFINED_TAG;
    status = decode_tlv_header(tlv_data_ptr, &tlv_header_size, &this_tag, &length);
    if (status != OMS_OK) {
      DEBUG_LOG("Could not decode tlv header");
      break;
    }
    tlv_data_ptr += tlv_header_size;
    if (!tlv_tuples[this_tag].mandatory) {
      oms_tlv_decoder_t decoder = get_decoder(this_tag);
      status = decoder(self, tlv_data_ptr, length);
      if (status != OMS_OK) {
        DEBUG_LOG("Could not decode tlv values");
        break;
      }
      optional_tags_decoded = true;
    }
    tlv_data_ptr += length;
  }

  return optional_tags_decoded;
}

const oms_tlv_tag_t *
get_optional_tags(size_t *num_of_optional_tags)
{
  *num_of_optional_tags = ARRAY_SIZE(optional_tags);
  return optional_tags;
}

const oms_tlv_tag_t *
get_mandatory_tags(size_t *num_of_mandatory_tags)
{
  *num_of_mandatory_tags = ARRAY_SIZE(mandatory_tags);
  return mandatory_tags;
}

oms_tlv_tag_t
get_signature_tag()
{
  return SIGNATURE_TAG;
}

size_t
read_64bits(const uint8_t *p, uint64_t *val)
{
  if (!p || !val)
    return 0;
  *val = ((uint64_t)p[0]) << 56;
  *val += ((uint64_t)p[1]) << 48;
  *val += ((uint64_t)p[2]) << 40;
  *val += ((uint64_t)p[3]) << 32;
  *val += ((uint64_t)p[4]) << 24;
  *val += ((uint64_t)p[5]) << 16;
  *val += ((uint64_t)p[6]) << 8;
  *val += (uint64_t)p[7];

  return 8;
}

size_t
read_64bits_signed(const uint8_t *p, int64_t *val)
{
  uint64_t tmp_val = 0;
  size_t bytes_read = read_64bits(p, &tmp_val);
  *val = (int64_t)tmp_val;
  return bytes_read;
}

size_t
read_32bits(const uint8_t *p, uint32_t *val)
{
  if (!p || !val)
    return 0;
  *val = ((uint32_t)p[0]) << 24;
  *val += ((uint32_t)p[1]) << 16;
  *val += ((uint32_t)p[2]) << 8;
  *val += (uint32_t)p[3];

  return 4;
}

size_t
read_16bits(const uint8_t *p, uint16_t *val)
{
  if (!p || !val)
    return 0;
  *val = ((uint16_t)p[0]) << 8;
  *val += (uint16_t)p[1];

  return 2;
}

size_t
read_8bits(const uint8_t *p, uint8_t *val)
{
  if (!p || !val)
    return 0;
  *val = *p;

  return 1;
}

uint8_t
read_byte(uint16_t *last_two_bytes, const uint8_t **data, bool do_emulation_prevention)
{
  uint8_t curr_byte = **data;
  if (do_emulation_prevention && curr_byte == 0x03 && *last_two_bytes == 0) {
    // Emulation prevention byte (0x03) detected. Move to next byte and return.
    *last_two_bytes <<= 8;
    *last_two_bytes |= (uint16_t)curr_byte;
    (*data)++;
    curr_byte = **data;
  }

  *last_two_bytes <<= 8;
  *last_two_bytes |= (uint16_t)curr_byte;
  (*data)++;

  return curr_byte;
}

void
read_byte_many(uint8_t *dst,
    const uint8_t **src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention)
{
  if (!src || !last_two_bytes) {
    return;
  }

  const uint8_t *src_ptr = *src;
  for (size_t ii = 0; ii < size; ++ii) {
    uint8_t value = read_byte(last_two_bytes, &src_ptr, do_emulation_prevention);
    if (dst) {
      dst[ii] = value;
    }
  }
}

void
write_byte(uint16_t *last_two_bytes,
    uint8_t **data,
    uint8_t curr_byte,
    bool do_emulation_prevention)
{
  if (do_emulation_prevention && (curr_byte & (~0x03)) == 0 && *last_two_bytes == 0) {
    // Emulation prevention adds 0x03
    **data = 0x03;
    (*data)++;
    *last_two_bytes <<= 8;
    *last_two_bytes |= 0x0003;
  }

  **data = curr_byte;
  (*data)++;
  *last_two_bytes <<= 8;
  *last_two_bytes |= (uint16_t)curr_byte;
}

void
write_byte_many(uint8_t **dst,
    uint8_t *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention)
{
  if (!src) {
    return;
  }

  for (size_t ii = 0; ii < size; ++ii) {
    uint8_t ch = src[ii];
    write_byte(last_two_bytes, dst, ch, do_emulation_prevention);
  }
}
