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

// #include <assert.h>  // assert
// #include <stdint.h>  // uint8_t
// #include <stdlib.h>  // free, malloc
// #include <string.h>  // size_t, strncpy

// #include "includes/onvif_media_signing_openssl.h"  // pem_pkey_t
// #include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_plugin.h"
#include "includes/onvif_media_signing_signer.h"
// #include "onvif_media_signing_authenticity.h"  // allocate_memory_and_copy_string
#include "oms_defines.h"  // oms_rc
// #include "onvif_media_signing_h26x_internal.h"  // parse_nalu_info()
#include "oms_internal.h"
#include "oms_openssl_internal.h"
// #include "onvif_media_signing_tlv.h"  // tlv_list_encode_or_get_size()

// #define ENABLE_CODE
#ifdef ENABLE_CODE
static void
set_nal_uuid_type(onvif_media_signing_t *self,
    uint8_t **payload,
    MediaSigningUUIDType uuid_type);
static size_t
get_sign_and_complete_sei_nalu(onvif_media_signing_t *self,
    uint8_t **payload,
    uint8_t *write_position);

/* Functions for payload_buffer. */
static void
add_payload_to_buffer(onvif_media_signing_t *self,
    uint8_t *payload_ptr,
    uint8_t *write_position);
static oms_rc
complete_sei_nalu_and_add_to_prepend(onvif_media_signing_t *self);

/* Functions related to the list of NALUs to prepend. */
static oms_rc
generate_sei_nalu(onvif_media_signing_t *self,
    uint8_t **payload,
    uint8_t **write_position);
static oms_rc
prepare_for_nalus_to_prepend(onvif_media_signing_t *self);
static void
shift_sei_buffer_at_index(onvif_media_signing_t *self, int index);

static void
set_nal_uuid_type(onvif_media_signing_t *self,
    uint8_t **payload,
    MediaSigningUUIDType uuid_type)
{
  const uint8_t *uuid;
  switch (uuid_type) {
    case UUID_TYPE_MEDIA_SIGNING:
      uuid = kUuidMediaSigning;
      break;
    default:
      DEBUG_LOG("UUID type %d not recognized", uuid_type);
      return;
  }
  for (int i = 0; i < UUID_LEN; i++) {
    write_byte(&self->last_two_bytes, payload, uuid[i], true);
  }
}

/* Frees all payloads in the |sei_data_buffer|. Declared in oms_internal.h */
void
free_sei_data_buffer(sei_data_t sei_data_buffer[])
{
  for (int i = 0; i < MAX_SEI_DATA_BUFFER; i++) {
    free(sei_data_buffer[i].sei);
    sei_data_buffer[i].sei = NULL;
    sei_data_buffer[i].write_position = NULL;
  }
}

/* Adds the |payload| to the next available slot in |payload_buffer| and |last_two_bytes|
 * to the next available slot in |last_two_bytes_buffer|. */
static void
add_payload_to_buffer(onvif_media_signing_t *self,
    uint8_t *payload,
    uint8_t *write_position)
{
  assert(self);

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this payload. Free the memory and return.
    free(payload);
    return;
  }

  self->sei_data_buffer[self->sei_data_buffer_idx].sei = payload;
  self->sei_data_buffer[self->sei_data_buffer_idx].write_position = write_position;
  self->sei_data_buffer[self->sei_data_buffer_idx].last_two_bytes = self->last_two_bytes;
  self->sei_data_buffer[self->sei_data_buffer_idx].completed_sei_size = 0;
  self->sei_data_buffer_idx += 1;
}

/* Picks the oldest payload from the |sei_data_buffer| and completes it with the generated
 * signature and the stop byte. If we have no signature the SEI payload is freed and not
 * added to the video session. */
static oms_rc
complete_sei_nalu_and_add_to_prepend(onvif_media_signing_t *self)
{
  assert(self);
  if (self->sei_data_buffer_idx < 1)
    return OMS_NOT_SUPPORTED;

  // Get the oldest sei data
  assert(self->sei_data_buffer_idx <= MAX_SEI_DATA_BUFFER);
  oms_rc status = OMS_UNKNOWN_FAILURE;
  sei_data_t *sei_data = &(self->sei_data_buffer[self->num_of_completed_seis]);
  // Transfer oldest pointer in |payload_buffer| to local |payload|
  uint8_t *payload = sei_data->sei;
  uint8_t *write_position = sei_data->write_position;
  self->last_two_bytes = sei_data->last_two_bytes;

  // If the signature could not be generated |signature_size| equals zero. Free the
  // started SEI and move on. This is a valid operation. What will happen is that the
  // video will have an unsigned GOP.
  if (self->sign_data->signature_size == 0) {
    free(payload);
    status = OMS_OK;
    goto done;
  } else if (!payload) {
    // No more pending payloads. Already freed due to too many unsigned SEIs.
    status = OMS_OK;
    goto done;
  }

  // Add the signature to the SEI payload.
  sei_data->completed_sei_size =
      get_sign_and_complete_sei_nalu(self, &payload, write_position);
  if (!sei_data->completed_sei_size) {
    status = OMS_UNKNOWN_FAILURE;
    goto done;
  }
  self->num_of_completed_seis++;

  // Unset flag when SEI is completed and prepended.
  // Note: If signature could not be generated then nalu data is freed. See
  // |onvif_media_signing_nalu_data_free| above in this function. In this case the flag is
  // still set and a SEI with all metatdata is created next time.
  self->has_recurrent_data = false;
  return OMS_OK;

done:

  return status;
}

/* Removes the specified index element from the SEI buffer of a `onvif_media_signing_t`
 * structure by shifting remaining elements left and clearing the last slot.
 */
static void
shift_sei_buffer_at_index(onvif_media_signing_t *self, int index)
{
  const int sei_data_buffer_end = self->sei_data_buffer_idx;
  for (int j = index; j < sei_data_buffer_end - 1; j++) {
    self->sei_data_buffer[j] = self->sei_data_buffer[j + 1];
  }
  self->sei_data_buffer[sei_data_buffer_end - 1].sei = NULL;
  self->sei_data_buffer[sei_data_buffer_end - 1].write_position = NULL;
  self->sei_data_buffer[sei_data_buffer_end - 1].last_two_bytes =
      LAST_TWO_BYTES_INIT_VALUE;
  self->sei_data_buffer[sei_data_buffer_end - 1].completed_sei_size = 0;
  self->sei_data_buffer_idx -= 1;
}

/* This function generates a SEI NALU of type "user data unregistered". The payload
 * encoded in this SEI is constructed using a set of TLVs. The TLVs are organized as
 * follows; | metadata | maybe hash_list | signature |
 *
 * The hash_list is only present if we use OMS_AUTHENTICITY_LEVEL_FRAME. The metadata +
 * the hash_list form a document. This document is hashed. For OMS_AUTHENTICITY_LEVEL_GOP,
 * this hash is treated as any NALU hash and added to the gop_hash. For
 * OMS_AUTHENTICITY_LEVEL_FRAME we sign this hash instead of the gop_hash, which is the
 * traditional principle of signing. */
static oms_rc
generate_sei_nalu(onvif_media_signing_t *self,
    uint8_t **payload,
    uint8_t **write_position)
{
  sign_or_verify_data_t *sign_data = self->sign_data;
  const size_t hash_size = sign_data->hash_size;
  size_t num_optional_tags = 0;
  size_t num_mandatory_tags = 0;

  const sv_tlv_tag_t *optional_tags = get_optional_tags(&num_optional_tags);
  const sv_tlv_tag_t *mandatory_tags = get_mandatory_tags(&num_mandatory_tags);
  const sv_tlv_tag_t gop_info_encoders[] = {
      SIGNATURE_TAG,
  };

  size_t payload_size = 0;
  size_t optional_tags_size = 0;
  size_t mandatory_tags_size = 0;
  size_t gop_info_size = 0;
  size_t sei_buffer_size = 0;
  const size_t num_gop_encoders = ARRAY_SIZE(gop_info_encoders);

  if (*payload) {
    DEBUG_LOG("Payload is not empty, *payload must be NULL");
    return OMS_OK;
  }

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this payload.
    return OMS_NOT_SUPPORTED;
  }

  // Reset |signature_hash_type| to |GOP_HASH|. If the |hash_list| is successfully added,
  // |signature_hash_type| is changed to |DOCUMENT_HASH|.
  self->gop_info->signature_hash_type = GOP_HASH;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Get the total payload size of all TLVs. Then compute the total size of the SEI NALU
    // to be generated. Add extra space for potential emulation prevention bytes.
    optional_tags_size =
        tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, NULL);
    mandatory_tags_size =
        tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
    if (self->is_golden_sei)
      mandatory_tags_size = 0;
    gop_info_size =
        tlv_list_encode_or_get_size(self, gop_info_encoders, num_gop_encoders, NULL);

    payload_size = gop_info_size + optional_tags_size + mandatory_tags_size;
    payload_size += UUID_LEN;  // UUID
    payload_size += 1;  // One byte for reserved data.
    if ((self->max_sei_payload_size > 0) && (payload_size > self->max_sei_payload_size) &&
        (mandatory_tags_size > 0)) {
      // Fallback to GOP-level signing
      payload_size -= mandatory_tags_size;
      self->gop_info->list_idx = -1;  // Reset hash list size to exclude it from TLV
      mandatory_tags_size =
          tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
      payload_size += mandatory_tags_size;
    }
    // Compute total SEI NALU data size.
    sei_buffer_size += self->codec == OMS_CODEC_H264 ? 6 : 7;  // NALU header
    sei_buffer_size += payload_size / 256 + 1;  // Size field
    sei_buffer_size += payload_size;
    sei_buffer_size += 1;  // Stop bit in a separate byte

    // Secure enough memory for emulation prevention. Worst case will add 1 extra byte per
    // 3 bytes.
    sei_buffer_size = sei_buffer_size * 4 / 3;

    // Allocate memory for payload + SEI header to return
    *payload = (uint8_t *)malloc(sei_buffer_size);
    OMS_THROW_IF(!(*payload), OMS_MEMORY);

    // Track the payload position with |payload_ptr|.
    uint8_t *payload_ptr = *payload;

    // Start writing bytes.
    // Reset last_two_bytes before writing bytes
    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
    uint16_t *last_two_bytes = &self->last_two_bytes;
    // Start code prefix
    *payload_ptr++ = 0x00;
    *payload_ptr++ = 0x00;
    *payload_ptr++ = 0x00;
    *payload_ptr++ = 0x01;

    if (self->codec == OMS_CODEC_H264) {
      write_byte(last_two_bytes, &payload_ptr, 0x06, false);  // SEI NAL type
    } else if (self->codec == OMS_CODEC_H265) {
      write_byte(last_two_bytes, &payload_ptr, 0x4E, false);  // SEI NAL type
      // nuh_layer_id and nuh_temporal_id_plus1
      write_byte(last_two_bytes, &payload_ptr, 0x01, false);
    }
    // last_payload_type_byte : user_data_unregistered
    write_byte(last_two_bytes, &payload_ptr, 0x05, false);

    // Payload size
    size_t size_left = payload_size;
    while (size_left >= 0xFF) {
      write_byte(last_two_bytes, &payload_ptr, 0xFF, false);
      size_left -= 0xFF;
    }
    // last_payload_size_byte - u(8)
    write_byte(last_two_bytes, &payload_ptr, (uint8_t)size_left, false);

    // User data unregistered UUID field
    set_nal_uuid_type(self, &payload_ptr, UUID_TYPE_MEDIA_SIGNING);

    // Add reserved byte(s).
    // The bit stream is illustrated below.
    // reserved_byte = |epb|golden sei|0|0|0|0|0|0|
    uint8_t reserved_byte = self->sei_epb << 7;
    reserved_byte |= self->is_golden_sei << 6;
    *payload_ptr++ = reserved_byte;

    size_t written_size =
        tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, payload_ptr);
    OMS_THROW_IF(written_size == 0, OMS_MEMORY);
    payload_ptr += written_size;
    if (mandatory_tags_size > 0) {
      written_size = tlv_list_encode_or_get_size(
          self, mandatory_tags, num_mandatory_tags, payload_ptr);
      payload_ptr += written_size;
      OMS_THROW_IF(written_size == 0, OMS_MEMORY);
    }

    // Up till now we have all the hashable data available. Before writing the signature
    // TLV to the payload we need to hash the NALU as it is so far and update the
    // |gop_hash|. Parse a fake NALU with the data so far and we will automatically get
    // the pointers to the |hashable_data| and the size of it. Then we can use the
    // hash_and_add() function.
    {
      size_t fake_payload_size = (payload_ptr - *payload);
      // Force SEI to be hashable.
      h26x_nalu_t nalu_without_signature_data =
          parse_nalu_info(*payload, fake_payload_size, self->codec, false, true);
      // Create a document hash.
      OMS_THROW(hash_and_add(self, &nalu_without_signature_data));
      // Note that the "add" part of the hash_and_add() operation above is actually only
      // necessary for OMS_AUTHENTICITY_LEVEL_GOP where we need to update the |gop_hash|.
      // For OMS_AUTHENTICITY_LEVEL_FRAME adding this hash to the |hash_list| is
      // pointless, since we have already encoded the |hash_list|. There is no harm done
      // though, since the list will be reset after generating the SEI NALU. So, for
      // simplicity, we use the same function for both authenticity levels.

      // The current |nalu_hash| is the document hash. Copy to |document_hash|. In
      // principle we only need to do this for OMS_AUTHENTICITY_LEVEL_FRAME, but for
      // simplicity we always copy it.
      memcpy(self->gop_info->document_hash, self->gop_info->nalu_hash, hash_size);
      // Free the memory allocated when parsing the NALU.
      free(nalu_without_signature_data.nalu_data_wo_epb);
    }

    gop_info_t *gop_info = self->gop_info;
    if (gop_info->signature_hash_type == DOCUMENT_HASH) {
      memcpy(sign_data->hash, gop_info->document_hash, hash_size);
    } else {
      memcpy(sign_data->hash, gop_info->gop_hash, hash_size);
    }

    // Reset the gop_hash since we start a new GOP.
    OMS_THROW(reset_gop_hash(self));
    // Reset the |hash_list| by rewinding the |list_idx| since we start a new GOP.
    gop_info->list_idx = 0;

    // End of GOP. Reset flag to get new reference.
    self->gop_info->has_reference_hash = false;
    // Reset the timestamp to avoid including a duplicate in the next SEI.
    gop_info->has_timestamp = false;

    OMS_THROW(onvif_media_signing_plugin_sign(
        self->plugin_handle, sign_data->hash, sign_data->hash_size));

  OMS_CATCH()
  {
    DEBUG_LOG("Failed generating the SEI");
    free(*payload);
    *payload = NULL;
    payload_ptr = NULL;
  }
  OMS_DONE(status)

  // Store offset so that we can append the signature once it has been generated.
  *write_position = payload_ptr;

  return status;
}

static size_t
get_sign_and_complete_sei_nalu(onvif_media_signing_t *self,
    uint8_t **payload,
    uint8_t *write_position)
{
  const sv_tlv_tag_t gop_info_encoders[] = {
      SIGNATURE_TAG,
  };
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint8_t *payload_ptr = write_position;
  if (!payload_ptr) {
    DEBUG_LOG("No SEI to finalize");
    return 0;
  }
  // TODO: Do we need to check if a signature is present before encoding it? Can it happen
  // that we encode an old signature?

  const size_t num_gop_encoders = ARRAY_SIZE(gop_info_encoders);
  size_t written_size =
      tlv_list_encode_or_get_size(self, gop_info_encoders, num_gop_encoders, payload_ptr);
  payload_ptr += written_size;

  // Stop bit
  write_byte(last_two_bytes, &payload_ptr, 0x80, false);

#ifdef MEDIA_SIGNING_DEBUG
  size_t data_filled_size = payload_ptr - *payload;
  size_t i = 0;
  printf("\n SEI (%zu bytes):  ", data_filled_size);
  for (i = 0; i < data_filled_size; ++i) {
    printf(" %02x", (*payload)[i]);
  }
  printf("\n");
#endif

  // Return payload size + extra space for emulation prevention
  return payload_ptr - *payload;
}

static oms_rc
prepare_for_nalus_to_prepend(onvif_media_signing_t *self)
{
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(!self, OMS_INVALID_PARAMETER);

    // Without a private key we cannot sign, which is equivalent with the existence of a
    // signin plugin.
    OMS_THROW_IF_WITH_MSG(
        !self->plugin_handle, OMS_NOT_SUPPORTED, "The private key has not been set");
    // Mark the start of signing when the first NAL Unit is passed in and a signing key
    // has been set.
    self->signing_started = true;
    // Check if we have NALUs to prepend waiting to be pulled. If we have one item only,
    // this is an empty list item, the pull action has no impact. We can therefore
    // silently remove it and proceed. But if there are vital SEI-nalus waiting to be
    // pulled we return an error message (OMS_NOT_SUPPORTED).
    if (!self->sv_test_on) {
      OMS_THROW_IF_WITH_MSG(self->num_of_completed_seis > 0, OMS_NOT_SUPPORTED,
          "There are remaining SEIs.");
    }
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/**
 * @brief Public onvif_media_signing_signer.h APIs
 */

MediaSigningReturnCode
onvif_media_signing_add_nalu_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size)
{
  return onvif_media_signing_add_nalu_for_signing_with_timestamp(
      self, nalu_data, nalu_data_size, NULL);
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_for_signing_with_timestamp(onvif_media_signing_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    const int64_t *timestamp)
{
  return onvif_media_signing_add_nalu_part_for_signing_with_timestamp(
      self, nalu_data, nalu_data_size, timestamp, true);
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_part_for_signing_with_timestamp(onvif_media_signing_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    const int64_t *timestamp,
    bool is_last_part)
{
  if (!self || !nalu_data || !nalu_data_size) {
    DEBUG_LOG("Invalid input parameters: (%p, %p, %zu)", self, nalu_data, nalu_data_size);
    return OMS_INVALID_PARAMETER;
  }

  h26x_nalu_t nalu = {0};
  // TODO: Consider moving this into parse_nalu_info().
  if (self->last_nalu->is_last_nalu_part) {
    // Only check for trailing zeros if this is the last part.
    nalu = parse_nalu_info(nalu_data, nalu_data_size, self->codec, is_last_part, false);
    nalu.is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(self->last_nalu, &nalu);
  } else {
    self->last_nalu->is_first_nalu_part = false;
    self->last_nalu->is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(&nalu, self->last_nalu);
    nalu.nalu_data = nalu_data;
    nalu.hashable_data = nalu_data;
    // Remove any trailing 0x00 bytes at the end of a NALU.
    while (is_last_part && (nalu_data[nalu_data_size - 1] == 0x00)) {
      nalu_data_size--;
    }
    nalu.hashable_data_size = nalu_data_size;
  }

  sign_or_verify_data_t *sign_data = self->sign_data;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(prepare_for_nalus_to_prepend(self));

    OMS_THROW_IF(nalu.is_valid < 0, OMS_INVALID_PARAMETER);

    // Note that |recurrence| is counted in frames and not in NALUs, hence we only
    // increment the counter for primary slices.
    if (nalu.is_primary_slice && nalu.is_last_nalu_part) {
      if ((self->frame_count % self->recurrence) == 0) {
        self->has_recurrent_data = true;
      }
      self->frame_count++;  // It is ok for this variable to wrap around
    }

    OMS_THROW(hash_and_add(self, &nalu));
    // Depending on the input NALU, we need to take different actions. If the input is an
    // I-NALU we have a transition to a new GOP. Then we need to generate the necessary
    // SEI-NALU(s) and put in prepend_list. For all other valid NALUs, simply hash and
    // proceed.
    if (nalu.is_first_nalu_in_gop && nalu.is_last_nalu_part) {
      // An I-NALU indicates the start of a new GOP, hence prepend with SEI-NALUs. This
      // also means that the signing feature is present.

      // Store the timestamp for the first nalu in gop.
      if (timestamp) {
        self->gop_info->timestamp = *timestamp;
        self->gop_info->has_timestamp = true;
      }

      uint8_t *payload = NULL;
      uint8_t *write_position = NULL;

      OMS_THROW(generate_sei_nalu(self, &payload, &write_position));
      // Add |payload| to buffer. Will be picked up again when the signature has been
      // generated.
      add_payload_to_buffer(self, payload, write_position);
      // Now we are done with the previous GOP. The gop_hash was reset right after signing
      // and adding it to the SEI NALU. Now it is time to start a new GOP, that is, hash
      // and add this first NALU of the GOP.
      OMS_THROW(hash_and_add(self, &nalu));
    }

    // Only add a SEI if the current NALU is the primary picture NALU and of course if
    // signing is completed.
    if ((nalu.nalu_type == NALU_TYPE_I || nalu.nalu_type == NALU_TYPE_P) &&
        nalu.is_primary_slice && sign_data->signature) {
      MediaSigningReturnCode signature_error = OMS_UNKNOWN_FAILURE;
      while (sv_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
          sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
        OMS_THROW(signature_error);
#ifdef MEDIA_SIGNING_DEBUG
        // TODO: This might not work for blocked signatures, that is if the hash in
        // |sign_data| does not correspond to the copied |signature|.
        // Borrow hash and signature from |sign_data|.
        sign_or_verify_data_t verify_data = {
            .hash = sign_data->hash,
            .hash_size = sign_data->hash_size,
            .key = NULL,
            .signature = sign_data->signature,
            .signature_size = sign_data->signature_size,
            .max_signature_size = sign_data->max_signature_size,
        };
        // Convert the public key to EVP_PKEY for verification. Normally done upon
        // validation.
        OMS_THROW(openssl_public_key_malloc(&verify_data, &self->pem_public_key));
        // Verify the just signed hash.
        int verified = -1;
        OMS_THROW_WITH_MSG(
            openssl_verify_hash(&verify_data, &verified), "Verification test had errors");
        openssl_free_key(verify_data.key);
        OMS_THROW_IF_WITH_MSG(
            verified != 1, OMS_EXTERNAL_ERROR, "Verification test failed");
#endif
        OMS_THROW(complete_sei_nalu_and_add_to_prepend(self));
      }
    }

  OMS_CATCH()
  OMS_DONE(status)

  free(nalu.nalu_data_wo_epb);

  return status;
}

static oms_rc
get_latest_sei(onvif_media_signing_t *self, uint8_t *sei, size_t *sei_size)
{
  if (!self || !sei_size)
    return OMS_INVALID_PARAMETER;
  *sei_size = 0;
  if (self->num_of_completed_seis < 1) {
    DEBUG_LOG("There are no completed seis.");
    return OMS_OK;
  }
  *sei_size = self->sei_data_buffer[self->num_of_completed_seis - 1].completed_sei_size;
  if (!sei)
    return OMS_OK;
  // Copy SEI data to the provided pointer.
  memcpy(sei, self->sei_data_buffer[self->num_of_completed_seis - 1].sei, *sei_size);

  // Reset the fetched SEI information from the sei buffer.
  free(self->sei_data_buffer[self->num_of_completed_seis - 1].sei);
  --(self->num_of_completed_seis);
  shift_sei_buffer_at_index(self, self->num_of_completed_seis);
  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t *self, uint8_t *sei, size_t *sei_size)
{

  if (!self || !sei_size)
    return OMS_INVALID_PARAMETER;
  *sei_size = 0;
  if (self->num_of_completed_seis < 1) {
    DEBUG_LOG("There are no completed seis.");
    return OMS_OK;
  }
  *sei_size = self->sei_data_buffer[0].completed_sei_size;
  if (!sei)
    return OMS_OK;
  // Copy the SEI data to the provided pointer.
  memcpy(sei, self->sei_data_buffer[0].sei, *sei_size);

  // Reset the fetched SEI information from the sei buffer.
  free(self->sei_data_buffer[0].sei);
  --(self->num_of_completed_seis);
  shift_sei_buffer_at_index(self, 0);
  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_get_nalu_to_prepend(onvif_media_signing_t *self,
    onvif_media_signing_nalu_to_prepend_t *nalu_to_prepend)
{
  if (!self || !nalu_to_prepend)
    return OMS_INVALID_PARAMETER;
  // Reset nalu_to_prepend.
  nalu_to_prepend->nalu_data = NULL;
  nalu_to_prepend->nalu_data_size = 0;
  nalu_to_prepend->prepend_instruction = SIGNED_VIDEO_PREPEND_NOTHING;
  // Directly pass the members of nalu_to_prepend as arguments to get_latest_sei().
  size_t *sei_size = &nalu_to_prepend->nalu_data_size;
  // Get the size from get_latest_sei() and check if its success.
  oms_rc status = get_latest_sei(self, NULL, sei_size);
  if (OMS_OK == status && *sei_size != 0) {
    nalu_to_prepend->nalu_data = malloc(*sei_size);
    nalu_to_prepend->prepend_instruction = SIGNED_VIDEO_PREPEND_NALU;
    status = get_latest_sei(
        self, nalu_to_prepend->nalu_data, &nalu_to_prepend->nalu_data_size);
  }
  return status;
}

void
onvif_media_signing_nalu_data_free(uint8_t *nalu_data)
{
  if (nalu_data)
    free(nalu_data);
}

// Note that this API only works for a plugin that blocks the worker thread.
MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t *self)
{
  if (!self)
    return OMS_INVALID_PARAMETER;

  uint8_t *payload = NULL;
  uint8_t *write_position = NULL;
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(prepare_for_nalus_to_prepend(self));
    OMS_THROW(generate_sei_nalu(self, &payload, &write_position));
    add_payload_to_buffer(self, payload, write_position);
    // Fetch the signature. If it is not ready we exit without generating the SEI.
    sign_or_verify_data_t *sign_data = self->sign_data;
    MediaSigningReturnCode signature_error = OMS_UNKNOWN_FAILURE;
    while (sv_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
        sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
      OMS_THROW(signature_error);
      OMS_THROW(complete_sei_nalu_and_add_to_prepend(self));
    }

  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

MediaSigningReturnCode
onvif_media_signing_generate_golden_sei(onvif_media_signing_t *self)
{
  if (!self)
    return OMS_INVALID_PARAMETER;

  uint8_t *payload = NULL;
  uint8_t *write_position = NULL;
  // The flag |is_golden_sei| will mark the next SEI as golden and should include
  // recurrent data, hence |has_recurrent_data| is set to true.
  self->is_golden_sei = true;
  self->has_recurrent_data = true;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(prepare_for_nalus_to_prepend(self));
    OMS_THROW(generate_sei_nalu(self, &payload, &write_position));
    add_payload_to_buffer(self, payload, write_position);

    // Note: From here, this is a temporary solution. It will only work unthreaded.
    // Fetch the signature. If it is not ready we exit without generating the SEI.
    MediaSigningReturnCode signature_error = OMS_UNKNOWN_FAILURE;
    sign_or_verify_data_t *sign_data = self->sign_data;
    while (sv_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
        sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
      OMS_THROW(signature_error);
      OMS_THROW(complete_sei_nalu_and_add_to_prepend(self));
    }

  OMS_CATCH()
  OMS_DONE(status)
  // Reset the |is_golden_sei| flag, ensuring that a golden SEI is not
  // generated outside of this API.
  self->is_golden_sei = false;
  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_product_info(onvif_media_signing_t *self,
    const char *hardware_id,
    const char *firmware_version,
    const char *serial_number,
    const char *manufacturer,
    const char *address)
{
  if (!self)
    return OMS_INVALID_PARAMETER;

  onvif_media_signing_product_info_t *product_info = &self->product_info;

  product_info_reset_members(product_info);

  if (hardware_id)
    strncpy(product_info->hardware_id, hardware_id, 256);
  if (firmware_version)
    strncpy(product_info->firmware_version, firmware_version, 256);
  if (serial_number)
    strncpy(product_info->serial_number, serial_number, 256);
  if (manufacturer)
    strncpy(product_info->manufacturer, manufacturer, 256);
  if (address)
    strncpy(product_info->address, address, 256);

  return OMS_OK;
}
#endif

MediaSigningReturnCode
onvif_media_signing_set_signing_key_pair(onvif_media_signing_t *self,
    const char *private_key,
    size_t private_key_size,
    const char *certificate_chain,
    size_t certificate_chain_size,
    bool user_provisioned)
{
  if (!self || !private_key || private_key_size == 0 || !certificate_chain ||
      certificate_chain_size == 0) {
    return OMS_INVALID_PARAMETER;
  }
  if (user_provisioned)
    return OMS_NOT_SUPPORTED;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    self->plugin_handle =
        onvif_media_signing_plugin_session_setup(private_key, private_key_size);
    OMS_THROW_IF(!self->plugin_handle, OMS_EXTERNAL_ERROR);

    self->certificate_chain.key = malloc(certificate_chain_size);
    OMS_THROW_IF(!self->certificate_chain.key, OMS_MEMORY);
    self->certificate_chain.key_size = certificate_chain_size;
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

#ifdef ENABLE_CODE
MediaSigningReturnCode
onvif_media_signing_set_authenticity_level(onvif_media_signing_t *self,
    SignedVideoAuthenticityLevel authenticity_level)
{
  if (!self)
    return OMS_INVALID_PARAMETER;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(authenticity_level >= OMS_AUTHENTICITY_LEVEL_NUM, OMS_NOT_SUPPORTED);
    OMS_THROW_IF(authenticity_level < OMS_AUTHENTICITY_LEVEL_GOP, OMS_NOT_SUPPORTED);

    self->authenticity_level = authenticity_level;

  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_recurrence_interval_frames(onvif_media_signing_t *self,
    unsigned recurrence)
{
  if (!self)
    return OMS_INVALID_PARAMETER;
  if (recurrence < RECURRENCE_ALWAYS)
    return OMS_NOT_SUPPORTED;

  self->recurrence = recurrence;

  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_sei_epb(onvif_media_signing_t *self, bool sei_epb)
{
  if (!self)
    return OMS_INVALID_PARAMETER;

  self->sei_epb = sei_epb;
  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_max_sei_payload_size(onvif_media_signing_t *self,
    size_t max_sei_payload_size)
{
  if (!self)
    return OMS_INVALID_PARAMETER;

  self->max_sei_payload_size = max_sei_payload_size;
  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_hash_algo(onvif_media_signing_t *self, const char *name_or_oid)
{
  if (!self)
    return OMS_INVALID_PARAMETER;
  if (self->signing_started)
    return OMS_NOT_SUPPORTED;

  size_t hash_size = 0;
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(openssl_set_hash_algo(self->crypto_handle, name_or_oid));
    hash_size = openssl_get_hash_size(self->crypto_handle);
    OMS_THROW_IF(hash_size == 0 || hash_size > MAX_HASH_SIZE, OMS_NOT_SUPPORTED);

    self->sign_data->hash_size = hash_size;
    // Point |nalu_hash| to the correct location in the |hashes| buffer.
    self->gop_info->nalu_hash = self->gop_info->hashes + hash_size;
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}
#endif
