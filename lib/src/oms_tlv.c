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

#include <string.h>  // memcpy

#include "oms_authenticity_report.h"  // transfer_vendor_info()
#include "oms_internal.h"  // gop_info_t
#include "oms_openssl_internal.h"  // pem_pkey_t, sign_or_verify_data_t

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

// #define PRINT_DECODED_SEI
/**
 * @brief Decodes the GENERAL_TAG from data
 */
static oms_rc
decode_general(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  if (!self || !data) {
    return OMS_INVALID_PARAMETER;
  }

  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  uint8_t version = *data_ptr++;
  char sw_version_str[OMS_VERSION_MAX_STRLEN] = {0};
  char *code_version_str = sw_version_str;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);

    // Read Media Signing version
    for (int i = 0; i < OMS_VERSION_BYTES; i++) {
      self->code_version[i] = *data_ptr++;
    }
    if (self->authenticity) {
      code_version_str = self->authenticity->version_on_signing_side;
    }
    bytes_to_version_str(self->code_version, code_version_str);
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
#ifdef PRINT_DECODED_SEI
    printf("\nGeneral Information Tag\n");
    printf("       tag version: %u\n", version);
    printf("        SW version: %s\n", code_version_str);
    printf("         timestamp: %ld\n", gop_info->timestamp);
    printf("       current GOP: %u\n", gop_info->current_gop);
    printf("  hashed NAL Units: %u\n", gop_info->num_sent_nalus);
    printf("(partial) GOP hash: ");
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", gop_info->partial_gop_hash[i]);
    }
    printf("\n");
    printf("       linked hash: ");
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", gop_info->linked_hash[i]);
    }
    printf("\n");
#endif
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * @brief Encodes the HASH_LIST_TAG into data
 *
 */
static size_t
encode_hash_list(onvif_media_signing_t *self, uint8_t *data)
{
  gop_info_t *gop_info = self->gop_info;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // If the |hash_list| is empty, or invalid, skip encoding, that is, return 0. Also,
  // |low_bitrate_mode| will skip encoding.
  if (gop_info->hash_list_idx <= 0 || self->low_bitrate_mode) {
    return 0;
  }

  // Value fields:
  //  - version (1 byte)
  //  - hash_list (list_idx bytes)

  data_size += sizeof(version);
  data_size += gop_info->hash_list_idx * sizeof(gop_info->hash_list[0]);

  if (!data) {
    DEBUG_LOG("Hash list tag has size %zu", data_size);
    return data_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write hash_list data
  for (int i = 0; i < gop_info->hash_list_idx; i++) {
    write_byte(last_two_bytes, &data_ptr, gop_info->hash_list[i], epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the HASH_LIST_TAG from data
 */
static oms_rc
decode_hash_list(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_list_size = data_size - (data_ptr - data);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF_WITH_MSG(hash_list_size > HASH_LIST_SIZE, OMS_MEMORY,
        "Found more hashes than fit in hash_list");
    memcpy(self->gop_info->hash_list, data_ptr, hash_list_size);
    self->gop_info->hash_list_idx = (int)hash_list_size;

    data_ptr += hash_list_size;

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nHash list Tag\n");
    printf("tag version: %u\n", version);
    printf("  hash list: ");
    size_t hash_size = openssl_get_hash_size(self->crypto_handle);
    for (size_t i = 0; i < hash_list_size; i++) {
      if (i % hash_size == 0) {
        printf("\n");
      }
      printf("%02x", self->gop_info->hash_list[i]);
    }
    printf("\n");
#endif
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * @brief Encodes the SIGNATURE_TAG into data
 */
static size_t
encode_signature(onvif_media_signing_t *self, uint8_t *data)
{
  sign_or_verify_data_t *sign_data = self->sign_data;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // Value fields:
  //  - version (1 byte)
  //  - signature size (2 bytes)
  //  - signature (max_signature_size bytes)

  data_size += sizeof(version);
  data_size += 2;  // 2 bytes to store the actual size of the signature.
  data_size += sign_data->max_signature_size;  // Allocated size of the signature

  if (!data) {
    DEBUG_LOG("Signature tag has size %zu", data_size);
    return data_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint16_t signature_size = (uint16_t)sign_data->signature_size;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, epb);
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
    write_byte(last_two_bytes, &data_ptr, 0x01, epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the SIGNATURE_TAG from data
 */
static oms_rc
decode_signature(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  sign_or_verify_data_t *verify_data = self->verify_data;
  uint8_t version = *data_ptr++;
  uint16_t signature_size = 0;
  size_t max_signature_size = 0;

  // Read true size of the signature.
  data_ptr += read_16bits(data_ptr, &signature_size);
  // The rest of the value bytes should now be the allocated size for the signature.
  max_signature_size = data_size - (data_ptr - data);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(max_signature_size < signature_size, OMS_AUTHENTICATION_ERROR);
    if (!verify_data->signature) {
      verify_data->max_signature_size = 0;
      verify_data->signature_size = 0;
      // Allocate enough space for future signatures as well, that is, max_signature_size.
      verify_data->signature = malloc(max_signature_size);
      OMS_THROW_IF(!verify_data->signature, OMS_MEMORY);
      // Set memory size.
      verify_data->max_signature_size = max_signature_size;
    }
    OMS_THROW_IF(verify_data->max_signature_size != max_signature_size, OMS_MEMORY);
    memcpy(verify_data->signature, data_ptr, max_signature_size);
    data_ptr += max_signature_size;

    // Set true signature size.
    verify_data->signature_size = signature_size;

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);

#ifdef PRINT_DECODED_SEI
    printf("\nSignature Tag\n");
    printf("                tag version: %u\n", version);
    printf("             signature size: %u\n", signature_size);
    printf("signature (allocated %zu B): ", max_signature_size);
    for (size_t i = 0; i < max_signature_size; i++) {
      printf("%02x", verify_data->signature[i]);
    }
    printf("\n");
#endif
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * @brief Encodes the CRYPTO_INFO_TAG into data
 */
static size_t
encode_crypto_info(onvif_media_signing_t *self, uint8_t *data)
{
  size_t hash_algo_encoded_oid_size = 0;
  const unsigned char *hash_algo_encoded_oid =
      openssl_get_hash_algo_encoded_oid(self->crypto_handle, &hash_algo_encoded_oid_size);
  // TODO: EC signing keys do not need this information. For now send zeros and activate
  // when supporting RSA.
  size_t sign_algo_encoded_oid_size = 0;
  const unsigned char *sign_algo_encoded_oid = NULL;
  uint16_t rsa_size = 0;
  size_t data_size = 0;
  const uint8_t version = 1;

  // If there is no hash algorithm present skip encoding, that is, return 0.
  if (!hash_algo_encoded_oid || !hash_algo_encoded_oid_size) {
    return 0;
  }

  // Value fields:
  //  - version (1 byte)
  //  - size of hash algorithm OID (serialized form) (1 byte)
  //  - hash algorithm (hash_algo_encoded_oid_size bytes)
  //  - size of signing algorithm OID (serialized form) (1 byte)
  //  - signing algorithm (sign_algo_encoded_oid_size bytes)
  //  - size of RSA encryption (2 byte)

  data_size += sizeof(version);
  // Size of hash algorithm in OID serialized form
  data_size += sizeof(uint8_t);
  data_size += hash_algo_encoded_oid_size;
  // Size of sign algorithm in OID serialized form
  data_size += sizeof(uint8_t);
  data_size += sign_algo_encoded_oid_size;
  data_size += 2;  // RSA size

  if (!data) {
    DEBUG_LOG("Crypto tag has size %zu", data_size);
    return data_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Hash OID size
  write_byte(last_two_bytes, &data_ptr, (uint8_t)hash_algo_encoded_oid_size, epb);
  // OID data; hash_algo_encoded_oid_size bytes
  for (size_t ii = 0; ii < hash_algo_encoded_oid_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, hash_algo_encoded_oid[ii], epb);
  }
  // Sign OID size
  write_byte(last_two_bytes, &data_ptr, sign_algo_encoded_oid_size, epb);
  // OID data; sign_algo_encoded_oid_size bytes
  for (size_t ii = 0; ii < sign_algo_encoded_oid_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, sign_algo_encoded_oid[ii], epb);
  }
  // RSA encryption size (2 bytes)
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((rsa_size >> 8) & 0x00ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((rsa_size)&0x00ff), epb);

  return (data_ptr - data);
}

/**
 * @brief Decodes the CRYPTO_INFO_TAG from data
 */
static oms_rc
decode_crypto_info(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_algo_encoded_oid_size = *data_ptr++;
  const unsigned char *hash_algo_encoded_oid = (const unsigned char *)data_ptr;
  char *hash_algo_name =
      openssl_encoded_oid_to_str(hash_algo_encoded_oid, hash_algo_encoded_oid_size);
  size_t sign_algo_encoded_oid_size = 0;
  const unsigned char *sign_algo_encoded_oid = NULL;
  char *sign_algo_name = NULL;
  uint16_t rsa_size = 0;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(hash_algo_encoded_oid_size == 0, OMS_AUTHENTICATION_ERROR);
    OMS_THROW(openssl_set_hash_algo_by_encoded_oid(
        self->crypto_handle, hash_algo_encoded_oid, hash_algo_encoded_oid_size));
    self->validation_flags.hash_algo_known = true;
    self->verify_data->hash_size = openssl_get_hash_size(self->crypto_handle);
    data_ptr += hash_algo_encoded_oid_size;

    sign_algo_encoded_oid_size = *data_ptr++;
    sign_algo_encoded_oid = (const unsigned char *)data_ptr;
    // TODO: Enable when RSA signing algo is supported. For EC sign algo is empty.
    // OMS_THROW(openssl_set_sign_algo_by_encoded_oid(
    //     self->crypto_handle, sign_algo_encoded_oid, sign_algo_encoded_oid_size));
    sign_algo_name =
        openssl_encoded_oid_to_str(sign_algo_encoded_oid, sign_algo_encoded_oid_size);

    data_ptr += sign_algo_encoded_oid_size;
    data_ptr += read_16bits(data_ptr, &rsa_size);

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nCrypto Information Tag\n");
    printf("                  tag version: %u\n", version);
    printf("hashing algorithm (ASN.1/DER): ");
    for (size_t i = 0; i < hash_algo_encoded_oid_size; i++) {
      printf("%02x", hash_algo_encoded_oid[i]);
    }
    printf(" -> %s\n", hash_algo_name);
    printf("signing algorithm (ASN.1/DER): ");
    for (size_t i = 0; i < sign_algo_encoded_oid_size; i++) {
      printf("%02x", sign_algo_encoded_oid[i]);
    }
    if (sign_algo_name) {
      printf(" -> %s", sign_algo_name);
    }
    printf("\n");
    printf("                     RSA size: %u\n", rsa_size);
#endif
  OMS_CATCH()
  OMS_DONE(status)

  free(hash_algo_name);
  free(sign_algo_name);

  return status;
}

/**
 * @brief Encodes the VENDOR_INFO_TAG into data
 */
static size_t
encode_vendor_info(onvif_media_signing_t *self, uint8_t *data)
{
  onvif_media_signing_vendor_info_t *vendor_info = &self->vendor_info;
  size_t data_size = 0;
  const uint8_t version = 1;

  // Value fields:
  //  - version (1 byte)
  //  - firmware_version_size (1 byte)
  //  - firmware_version
  //  - serial_number_size (1 byte)
  //  - serial_number
  //  - manufacturer_size (1 byte)
  //  - manufacturer

  data_size += sizeof(version);

  // Determine sizes excluding null-terminated character
  data_size += 1;
  size_t firmware_version_size = strlen(vendor_info->firmware_version);
  data_size += firmware_version_size;

  data_size += 1;
  size_t serial_number_size = strlen(vendor_info->serial_number);
  data_size += serial_number_size;

  data_size += 1;
  size_t manufacturer_size = strlen(vendor_info->manufacturer);
  data_size += manufacturer_size;

  if (!data) {
    DEBUG_LOG("Vendor info tag has size %zu", data_size);
    return data_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  // Write |firmware_version|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, firmware_version_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, (uint8_t *)vendor_info->firmware_version,
      firmware_version_size, last_two_bytes, epb);

  // Write |serial_number|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, serial_number_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, (uint8_t *)vendor_info->serial_number, serial_number_size,
      last_two_bytes, epb);

  // Write |manufacturer|, i.e., size + string.
  write_byte(last_two_bytes, &data_ptr, manufacturer_size, epb);
  // Write all but the null-terminated character.
  write_byte_many(&data_ptr, (uint8_t *)vendor_info->manufacturer, manufacturer_size,
      last_two_bytes, epb);

  return (data_ptr - data);
}

/**
 * @brief Decodes the VENDOR_INFO_TAG from data
 */
static oms_rc
decode_vendor_info(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;

  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  onvif_media_signing_vendor_info_t *vendor_info = &self->vendor_info;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);
    memset(vendor_info, 0, sizeof(onvif_media_signing_vendor_info_t));

    uint8_t firmware_version_size = *data_ptr++;
    strncpy(vendor_info->firmware_version, (const char *)data_ptr, firmware_version_size);
    data_ptr += firmware_version_size;

    uint8_t serial_number_size = *data_ptr++;
    strncpy(vendor_info->serial_number, (const char *)data_ptr, serial_number_size);
    data_ptr += serial_number_size;

    uint8_t manufacturer_size = *data_ptr++;
    strncpy(vendor_info->manufacturer, (const char *)data_ptr, manufacturer_size);
    data_ptr += manufacturer_size;

    // Transfer the decoded |vendor_info| to the authenticity report.
    if (self->authenticity) {
      transfer_vendor_info(&self->authenticity->vendor_info, vendor_info);
    }

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nVendor Information Tag\n");
    printf("     tag version: %u\n", version);
    printf("firmware version: %s\n", vendor_info->firmware_version);
    printf("   serial number: %s\n", vendor_info->serial_number);
    printf("    manufacturer: %s\n", vendor_info->manufacturer);
#endif
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * @brief Encodes the CERTIFICATES_TAG into data
 */
static size_t
encode_certificates(onvif_media_signing_t *self, uint8_t *data)
{
  size_t data_size = 0;
  const uint8_t version = 1;

  // Value fields:
  //  - version (1 byte)
  //  - user provisioned (1 byte)
  //  - certificate_chain (variable bytes)
  //
  // Note that we do not have to store the size of the certificate_chain. It is known from
  // the TLV length.

  data_size += sizeof(version);
  data_size += 1;  // user provisioned flag
  // Size of certificate_chain
  data_size += self->certificate_chain.key_size;

  if (!data) {
    DEBUG_LOG("Certificate chain tag has size %zu", data_size);
    return data_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint8_t *certificate_chain = (uint8_t *)self->certificate_chain.key;
  // TODO: User provisioned signing not yet supported
  const bool user_provisioned = self->certificate_chain.user_provisioned;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // User provisioned
  write_byte(last_two_bytes, &data_ptr, user_provisioned, epb);

  // certificate_chain
  for (size_t ii = 0; ii < self->certificate_chain.key_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, certificate_chain[ii], epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the CERTIFICATES_TAG from data
 *
 */
static oms_rc
decode_certificates(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  bool user_provisioned = (bool)(*data_ptr++);
  uint16_t certificate_chain_size = (uint16_t)(data_size - 2);

  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  pem_pkey_t *certificate_chain = &self->certificate_chain;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(certificate_chain_size == 0, OMS_AUTHENTICATION_ERROR);

    if (certificate_chain->key_size != certificate_chain_size) {
      free(certificate_chain->key);
      certificate_chain->key = calloc(1, certificate_chain_size);
      OMS_THROW_IF(!certificate_chain->key, OMS_MEMORY);
      certificate_chain->key_size = certificate_chain_size;
    }

    int cert_diff = memcmp(data_ptr, certificate_chain->key, certificate_chain_size);
    if (self->has_public_key && cert_diff) {
      self->latest_validation->public_key_has_changed = true;
    }
    memcpy(certificate_chain->key, data_ptr, certificate_chain_size);
    self->has_public_key = true;
    data_ptr += certificate_chain_size;

    certificate_chain->user_provisioned = user_provisioned;
    // Convert to EVP_PKEY_CTX
    OMS_THROW(openssl_public_key_malloc(self->verify_data, &self->certificate_chain));

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    char *certificate_chain_str = calloc(1, certificate_chain_size + 1);
    OMS_THROW_IF(!certificate_chain_str, OMS_MEMORY);
    memcpy(certificate_chain_str, certificate_chain->key, certificate_chain_size);
    printf("\nCertificates Tag\n");
    printf("           tag version: %u\n", version);
    printf("      user provisioned: %u\n", user_provisioned);
    printf("certificate chain size: %u\n", certificate_chain_size);
    printf("     certificate chain:\n%s\n", certificate_chain_str);
    free(certificate_chain_str);
#endif
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * @brief Encodes the ARBITRARY_DATA_TAG into data
 */
static size_t
encode_arbitrary_data(onvif_media_signing_t *self, uint8_t *data)
{
  size_t data_size = 0;
  const uint8_t version = 1;

  if (!self->arbitrary_data || self->arbitrary_data_size == 0) {
    return 0;
  }

  // Value fields:
  //  - version (1 byte)
  //  - arbitrary_data (arbitrary_data_size bytes)

  data_size += sizeof(version);
  data_size += self->arbitrary_data_size;

  if (!data) {
    DEBUG_LOG("Arbitrary data tag has size %zu", data_size);
    return data_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  for (size_t ii = 0; ii < self->arbitrary_data_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, self->arbitrary_data[ii], epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the ARBITRARY_DATA_TAG from data
 */
static oms_rc
decode_arbitrary_data(onvif_media_signing_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  uint16_t arbitrary_data_size = (uint16_t)(data_size - 1);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(version != 1, OMS_INCOMPATIBLE_VERSION);
    OMS_THROW_IF(arbitrary_data_size == 0, OMS_AUTHENTICATION_ERROR);
    uint8_t *arbitrary_data = realloc(self->arbitrary_data, arbitrary_data_size);
    OMS_THROW_IF(!arbitrary_data, OMS_MEMORY);
    memcpy(arbitrary_data, data_ptr, arbitrary_data_size);
    self->arbitrary_data = arbitrary_data;
    self->arbitrary_data_size = arbitrary_data_size;
    data_ptr += arbitrary_data_size;

    OMS_THROW_IF(data_ptr != data + data_size, OMS_AUTHENTICATION_ERROR);
  OMS_CATCH()
  {
    free(self->arbitrary_data);
    self->arbitrary_data = NULL;
    self->arbitrary_data_size = 0;
  }
  OMS_DONE(status)

#ifdef PRINT_DECODED_SEI
  printf("\nArbitrary Data Tag\n");
  printf("        tag version: %u\n", version);
  printf("arbitrary data size: %u\n", arbitrary_data_size);
  printf("     arbitrary data: ");
  for (size_t i = 0; i < arbitrary_data_size; i++) {
    printf("%02x", self->arbitrary_data[i]);
  }
  printf("\n");
#endif

  return status;
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

  if (v_size_written < v_size) {
    DEBUG_LOG("Written size %zu < %zu computed size", v_size_written, v_size);
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
    return NULL;

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

bool
tlv_find_and_decode_signature_tag(onvif_media_signing_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size)
{
  const uint8_t *tlv_data_ptr = tlv_data;

  if (!self || !tlv_data || tlv_data_size == 0)
    return false;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  bool signature_tag_decoded = false;
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
    if (this_tag == SIGNATURE_TAG) {
      oms_tlv_decoder_t decoder = get_decoder(this_tag);
      status = decoder(self, tlv_data_ptr, length);
      if (status != OMS_OK) {
        DEBUG_LOG("Could not decode tlv values");
        break;
      }
      signature_tag_decoded = true;
    }
    tlv_data_ptr += length;
  }

  return signature_tag_decoded;
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

  // const uint8_t *src_ptr = *src;
  for (size_t ii = 0; ii < size; ++ii) {
    uint8_t value = read_byte(last_two_bytes, src, do_emulation_prevention);
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
