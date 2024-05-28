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

#include "includes/onvif_media_signing_plugin.h"
#include "includes/onvif_media_signing_signer.h"
#include "oms_defines.h"  // oms_rc
#include "oms_internal.h"
#include "oms_openssl_internal.h"
#include "oms_tlv.h"

static void
add_sei_to_buffer(onvif_media_signing_t *self, uint8_t *sei, uint8_t *write_position);
static void
shift_sei_buffer_at_index(onvif_media_signing_t *self, int index);

static void
set_uuid(onvif_media_signing_t *self, uint8_t **payload);
static oms_rc
generate_sei(onvif_media_signing_t *self, uint8_t **sei, uint8_t **write_position);
static oms_rc
complete_sei(onvif_media_signing_t *self);

// #define ENABLE_CODE
#ifdef ENABLE_CODE
static size_t
add_signature_to_sei(onvif_media_signing_t *self, uint8_t **sei, uint8_t *write_position);

/* Functions for payload_buffer. */

/* Functions related to the list of NALUs to prepend. */
static oms_rc
prepare_for_nalus_to_prepend(onvif_media_signing_t *self);

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
#endif

/* Adds the |sei| and |last_two_bytes| to the next available slot in |sei_data_buffer|. */
static void
add_sei_to_buffer(onvif_media_signing_t *self, uint8_t *sei, uint8_t *write_position)
{
  assert(self);

  if (!sei) {
    return;
  }
  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this sei. Free the memory and return.
    free(sei);
    return;
  }

  self->sei_data_buffer[self->sei_data_buffer_idx].sei = sei;
  self->sei_data_buffer[self->sei_data_buffer_idx].write_position = write_position;
  self->sei_data_buffer[self->sei_data_buffer_idx].last_two_bytes = self->last_two_bytes;
  self->sei_data_buffer[self->sei_data_buffer_idx].completed_sei_size = 0;
  self->sei_data_buffer_idx += 1;
}

/* Picks the oldest sei from the |sei_data_buffer| and completes it with the generated
 * signature + the stop byte. If we have no signature the SEI payload is freed and not
 * added to the video session. */
static oms_rc
complete_sei(onvif_media_signing_t *self)
{
  assert(self);
  if (self->sei_data_buffer_idx < 1) {
    return OMS_NOT_SUPPORTED;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  // Get the oldest sei data
  assert(self->sei_data_buffer_idx <= MAX_SEI_DATA_BUFFER);
  sei_data_t *sei_data = &(self->sei_data_buffer[self->num_of_completed_seis]);
  // Transfer oldest pointer in |payload_buffer| to local |sei|
  uint8_t *sei = sei_data->sei;
  // uint8_t *write_position = sei_data->write_position;
  self->last_two_bytes = sei_data->last_two_bytes;

  // If the signature could not be generated |signature_size| equals zero. Free the
  // pending SEI and move on. This is a valid operation. What will happen is that the
  // video will have an unsigned GOP.
  if (self->sign_data->signature_size == 0) {
    free(sei);
    status = OMS_OK;
    goto done;
  } else if (!sei) {
    // No more pending payloads. Already freed due to too many unsigned SEIs.
    status = OMS_OK;
    goto done;
  }

  // Add the signature to the SEI payload.
  // TODO: Enable when TLV is in place.
  // sei_data->completed_sei_size = add_signature_to_sei(self, &sei, write_position);
  sei_data->completed_sei_size = 0;
  if (!sei_data->completed_sei_size) {
    status = OMS_UNKNOWN_FAILURE;
    goto done;
  }
  self->num_of_completed_seis++;
  status = OMS_OK;

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
  self->sei_data_buffer[sei_data_buffer_end - 1].sei = NULL;  // Memory is already freed
  self->sei_data_buffer[sei_data_buffer_end - 1].write_position = NULL;
  self->sei_data_buffer[sei_data_buffer_end - 1].last_two_bytes =
      LAST_TWO_BYTES_INIT_VALUE;
  self->sei_data_buffer[sei_data_buffer_end - 1].completed_sei_size = 0;
  self->sei_data_buffer_idx -= 1;
}

static void
set_uuid(onvif_media_signing_t *self, uint8_t **payload)
{
  const uint8_t *uuid = kUuidMediaSigning;
  for (int i = 0; i < UUID_LEN; i++) {
    write_byte(&self->last_two_bytes, payload, uuid[i], true);
  }
}

/* This function generates a SEI of type "user data unregistered". The payload encoded in
 * this SEI is constructed using a set of TLVs. The TLVs are organized as
 * follows; | optional metadata | mandatory metadata | maybe hash_list | signature |
 *
 * The hash_list is only present if not |low_bitrate_mode| is activated, or if the maximum
 * payload size is reached. The metadata + the hash_list form a document. This document is
 * hashed and signed */
static oms_rc
generate_sei(onvif_media_signing_t *self, uint8_t **sei, uint8_t **write_position)
{
  gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *sign_data = self->sign_data;
  const size_t hash_size = sign_data->hash_size;
  size_t num_optional_tags = 0;
  size_t num_mandatory_tags = 0;

  const oms_tlv_tag_t *optional_tags = get_optional_tags(&num_optional_tags);
  const oms_tlv_tag_t *mandatory_tags = get_mandatory_tags(&num_mandatory_tags);
  const oms_tlv_tag_t signature_tag = get_signature_tag();

  size_t payload_size = 0;
  size_t optional_tags_size = 0;
  size_t mandatory_tags_size = 0;
  size_t signature_size = 0;
  size_t sei_size = 0;

  if (*sei) {
    DEBUG_LOG("SEI data is not empty, *sei must be NULL");
    return OMS_OK;
  }

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this payload.
    return OMS_NOT_SUPPORTED;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Get the total payload size of all TLVs. Then compute the total size of the SEI NALU
    // to be generated. Add extra space for potential emulation prevention bytes.
    optional_tags_size =
        tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, NULL);
    mandatory_tags_size =
        tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
    if (self->is_golden_sei) {
      mandatory_tags_size = 0;
    }
    signature_size = tlv_list_encode_or_get_size(self, &signature_tag, 1, NULL);

    payload_size = optional_tags_size + mandatory_tags_size + signature_size;
    payload_size += UUID_LEN;  // UUID
    payload_size += 1;  // One byte for reserved data.
    if ((self->max_sei_payload_size > 0) && (payload_size > self->max_sei_payload_size) &&
        (mandatory_tags_size > 0)) {
      // Fallback to low_bitrate_mode, that is, exclude the hash list
      payload_size -= mandatory_tags_size;
      gop_info->hash_list_idx = -1;  // Reset hash list size to exclude it from TLV
      mandatory_tags_size =
          tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
      payload_size += mandatory_tags_size;
    }
    // Compute total SEI data size.
    sei_size += self->codec == OMS_CODEC_H264 ? 6 : 7;  // NALU header
    sei_size += payload_size / 256 + 1;  // Size field
    sei_size += payload_size;
    sei_size += 1;  // Stop bit in a separate byte

    // Secure enough memory for emulation prevention. Worst case will add 1 extra byte per
    // 3 bytes.
    sei_size = sei_size * 4 / 3;

    // Allocate memory for payload + SEI header to return
    *sei = (uint8_t *)malloc(sei_size);
    OMS_THROW_IF(!(*sei), OMS_MEMORY);

    // Track the payload position with |sei_ptr|.
    uint8_t *sei_ptr = *sei;

    // Start writing bytes.
    // Reset last_two_bytes before writing bytes
    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
    uint16_t *last_two_bytes = &self->last_two_bytes;
    // Start code prefix
    *sei_ptr++ = 0x00;
    *sei_ptr++ = 0x00;
    *sei_ptr++ = 0x00;
    *sei_ptr++ = 0x01;

    if (self->codec == OMS_CODEC_H264) {
      write_byte(last_two_bytes, &sei_ptr, 0x06, false);  // SEI NAL Unit type
    } else if (self->codec == OMS_CODEC_H265) {
      write_byte(last_two_bytes, &sei_ptr, 0x4E, false);  // SEI NAL Unit type
      // nuh_layer_id and nuh_temporal_id_plus1
      write_byte(last_two_bytes, &sei_ptr, 0x01, false);
    }
    // SEI type : user_data_unregistered
    write_byte(last_two_bytes, &sei_ptr, USER_DATA_UNREGISTERED, false);

    // Payload size
    size_t size_left = payload_size;
    while (size_left >= 0xFF) {
      write_byte(last_two_bytes, &sei_ptr, 0xFF, false);
      size_left -= 0xFF;
    }
    // last_payload_size_byte - u(8)
    write_byte(last_two_bytes, &sei_ptr, (uint8_t)size_left, false);

    // User data unregistered UUID field
    set_uuid(self, &sei_ptr);

    // Add reserved byte(s).
    // The bit stream is illustrated below.
    // reserved_byte = |golden sei|epb|0|0|0|0|0|0|
    uint8_t reserved_byte = 0;
    reserved_byte |= self->is_golden_sei << 7;
    reserved_byte |= self->sei_epb << 6;
    *sei_ptr++ = reserved_byte;

    size_t written_size = 0;
    if (optional_tags_size > 0) {
      written_size =
          tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, sei_ptr);
      OMS_THROW_IF(written_size == 0, OMS_MEMORY);
      sei_ptr += written_size;
    }
    if (mandatory_tags_size > 0) {
      written_size =
          tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, sei_ptr);
      OMS_THROW_IF(written_size == 0, OMS_MEMORY);
      sei_ptr += written_size;
    }

    // Up till now all the hashable data is available. Before writing the signature TLV to
    // the payload the hashable data needs to be hashed. Parse a fake NAL Unit with the
    // data so far and we will automatically get the pointers to the |hashable_data| and
    // the size of it. Then use the hash_and_add() function.
    {
      size_t fake_payload_size = (sei_ptr - *sei);
      // Force SEI to be hashable.
      nalu_info_t nalu_info_without_signature_data =
          parse_nalu_info(*sei, fake_payload_size, self->codec, false, true);
      // Create a document hash.
      OMS_THROW(hash_and_add(self, &nalu_info_without_signature_data));
      // Note that the "add" part of the hash_and_add() operation above will add this hash
      // to the |hash_list|. There is no harm done though, since the list will be reset
      // after generating the SEI.

      // TODO: Fix this
      // The current |nalu_hash| is the |hash_to_sign|.
      memcpy(gop_info->hash_to_sign, gop_info->nalu_hash, hash_size);
      // Free the memory allocated when parsing the NAL Unit.
      free(nalu_info_without_signature_data.nalu_wo_epb);
    }

    memcpy(sign_data->hash, gop_info->hash_to_sign, hash_size);

    // Reset the |hash_list| by rewinding the |hash_list_idx| since a new GOP is
    // triggered.
    gop_info->hash_list_idx = 0;

    // End of GOP. Reset flag to get new reference.
    self->gop_info->has_anchor_hash = false;

    OMS_THROW(onvif_media_signing_plugin_sign(
        self->plugin_handle, sign_data->hash, sign_data->hash_size));

  OMS_CATCH()
  {
    DEBUG_LOG("Failed generating the SEI");
    free(*sei);
    *sei = NULL;
    sei_ptr = NULL;
  }
  OMS_DONE(status)

  // Store offset so that we can append the signature once it has been generated.
  *write_position = sei_ptr;

  return status;
}

#ifdef ENABLE_CODE
static size_t
add_signature_to_sei(onvif_media_signing_t *self, uint8_t **sei, uint8_t *write_position)
{
  const oms_tlv_tag_t signature_tag[] = {
      SIGNATURE_TAG,
  };
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint8_t *sei_ptr = write_position;
  if (!sei_ptr) {
    DEBUG_LOG("No SEI to finalize");
    return 0;
  }
  // TODO: Do we need to check if a signature is present before encoding it? Can it happen
  // that we encode an old signature?

  const size_t num_gop_encoders = ARRAY_SIZE(signature_tag);
  size_t written_size =
      tlv_list_encode_or_get_size(self, signature_tag, num_gop_encoders, sei_ptr);
  sei_ptr += written_size;

  // Stop bit
  write_byte(last_two_bytes, &sei_ptr, 0x80, false);

#ifdef MEDIA_SIGNING_DEBUG
  size_t data_filled_size = sei_ptr - *payload;
  size_t i = 0;
  printf("\n SEI (%zu bytes):  ", data_filled_size);
  for (i = 0; i < data_filled_size; ++i) {
    printf(" %02x", (*payload)[i]);
  }
  printf("\n");
#endif

  // Return payload size + extra space for emulation prevention
  return sei_ptr - *payload;
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
#endif

/**
 * @brief Public onvif_media_signing_signer.h APIs
 */

MediaSigningReturnCode
onvif_media_signing_add_nalu_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    const int64_t timestamp)
{
  return onvif_media_signing_add_nalu_part_for_signing(
      self, nalu, nalu_size, timestamp, true);
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_part_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    const int64_t timestamp,
    bool is_last_part)
{
  if (!self || !nalu || !nalu_size) {
    return OMS_INVALID_PARAMETER;
  }

  nalu_info_t nalu_info = {0};
  // TODO: Consider moving this into parse_nalu_info().
  if (self->last_nalu->is_last_nalu_part) {
    // Only check for trailing zeros if this is the last part.
    nalu_info = parse_nalu_info(nalu, nalu_size, self->codec, is_last_part, false);
    nalu_info.is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(self->last_nalu, &nalu_info);
  } else {
    self->last_nalu->is_first_nalu_part = false;
    self->last_nalu->is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(&nalu_info, self->last_nalu);
    nalu_info.nalu_data = nalu;
    nalu_info.hashable_data = nalu;
    // Remove any trailing 0x00 bytes at the end of a NALU.
    while (is_last_part && (nalu[nalu_size - 1] == 0x00)) {
      nalu_size--;
    }
    nalu_info.hashable_data_size = nalu_size;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Without a private key (signing plugin) it is not possible to sign.
    OMS_THROW_IF_WITH_MSG(!self->plugin_handle, OMS_NOT_SUPPORTED, "No private key set");
    OMS_THROW_IF(nalu_info.is_valid < 0, OMS_INVALID_PARAMETER);
    // Mark the start of signing when the first NAL Unit is passed in and a signing key
    // has been set.
    self->signing_started = true;

    // Depending on the input NAL Unit, different actions are taken. If the input is an
    // I-frame there is a transition to a new GOP. That triggers generating a SEI. While
    // being signed it is put in a buffer. For all other valid NALUs, simply hash and
    // proceed.
    if (nalu_info.is_first_nalu_in_gop && nalu_info.is_last_nalu_part) {
      // An I-frame indicates the start of a new GOP, hence trigger generating a SEI. This
      // also means that the signing feature is present.

      // Store the timestamp for the first NAL Unit in gop.
      self->gop_info->timestamp = timestamp;

      uint8_t *sei = NULL;
      uint8_t *write_position = NULL;
      // TODO: Enable generating SEIs when implemented.
      OMS_THROW(generate_sei(self, &sei, &write_position));
      // Add |sei| to buffer. Will be picked up again when the signature has been
      // generated.
      add_sei_to_buffer(self, sei, write_position);
      // Now we are done with the previous GOP. The gop_hash was reset right after signing
      // and adding it to the SEI NALU. Now it is time to start a new GOP, that is, hash
      // and add this first NALU of the GOP.
      // OMS_THROW(hash_and_add(self, &nalu_info));
    }
    OMS_THROW(hash_and_add(self, &nalu_info));
  OMS_CATCH()
  OMS_DONE(status)

  free(nalu_info.nalu_wo_epb);

  return status;
}

#ifdef ENABLE_CODE
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
#endif

MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t *self,
    uint8_t *sei,
    size_t *sei_size,
    const uint8_t *nal_to_prepend,
    size_t nal_to_prepend_size,
    unsigned *num_pending_seis)
{
  if (!self || !sei_size) {
    return OMS_INVALID_PARAMETER;
  }

  // Ask the signing plugin for signatures.
  sign_or_verify_data_t *sign_data = self->sign_data;
  *sei_size = 0;
  if (num_pending_seis) {
    *num_pending_seis = self->sei_data_buffer_idx - 1;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    MediaSigningReturnCode signature_error = OMS_UNKNOWN_FAILURE;
    while (onvif_media_signing_plugin_get_signature(self->plugin_handle,
        sign_data->signature, sign_data->max_signature_size, &sign_data->signature_size,
        &signature_error)) {
      OMS_THROW(signature_error);
#ifdef MEDIA_SIGNING_DEBUG
#ifdef VALIDATION_SIDE
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
#endif
      OMS_THROW(complete_sei(self));
    }
  OMS_CATCH()
  OMS_DONE(status)

  if (status != OMS_OK) {
    return status;
  }

  if (self->num_of_completed_seis < 1) {
    DEBUG_LOG("There are no completed seis.");
    return OMS_OK;
  }
  if (nal_to_prepend && nal_to_prepend_size > 0) {
    nalu_info_t nalu_info =
        parse_nalu_info(nal_to_prepend, nal_to_prepend_size, self->codec, false, false);
    free(nalu_info.nalu_wo_epb);
    // Only display a SEI if the |nal_to_prepend| is a primary picture NAL Unit.
    if (!((nalu_info.nalu_type == NALU_TYPE_I || nalu_info.nalu_type == NALU_TYPE_P) &&
            nalu_info.is_primary_slice)) {
      return OMS_OK;
    }
  }

  *sei_size = self->sei_data_buffer[0].completed_sei_size;
  if (!sei) {
    return OMS_OK;
  }

  // Copy the SEI data to the provided pointer.
  memcpy(sei, self->sei_data_buffer[0].sei, *sei_size);
  // Reset the fetched SEI information from the sei buffer.
  free(self->sei_data_buffer[0].sei);
  --(self->num_of_completed_seis);
  shift_sei_buffer_at_index(self, 0);

  // Set again in case SEIs were copied.
  if (num_pending_seis) {
    *num_pending_seis = self->sei_data_buffer_idx - 1;
  }

  return OMS_OK;
}

#ifdef ENABLE_CODE
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
#endif

// Note that this API only works for a plugin that blocks the worker thread.
MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t *self)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  if (!self->signing_started) {
    return OMS_NOT_SUPPORTED;
  }

  oms_rc status = OMS_OK;
  // TODO: Enable when implemented.
  // oms_rc status = OMS_UNKNOWN_FAILURE;
  // OMS_TRY()
  //   uint8_t *sei = NULL;
  //   uint8_t *write_position = NULL;
  //   OMS_THROW(generate_sei(self, &sei, &write_position));
  //   add_sei_to_buffer(self, sei, write_position);
  // OMS_CATCH()
  // OMS_DONE(status)

  return status;
}

MediaSigningReturnCode
onvif_media_signing_generate_golden_sei(onvif_media_signing_t *self)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  uint8_t *sei = NULL;
  uint8_t *write_position = NULL;
  // The flag |is_golden_sei| will mark the next SEI as golden.
  self->is_golden_sei = true;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Without a private key (signing plugin) it is not possible to sign.
    OMS_THROW_IF_WITH_MSG(!self->plugin_handle, OMS_NOT_SUPPORTED, "No private key set");
    // TODO: Enable the SEI generator when it has been omplemented
    OMS_THROW(generate_sei(self, &sei, &write_position));
    add_sei_to_buffer(self, sei, write_position);
  OMS_CATCH()
  OMS_DONE(status)

  // Disable the golden SEI for future.
  self->is_golden_sei = false;

  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_use_golden_sei(onvif_media_signing_t *self, bool enable)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  if (self->signing_started) {
    return OMS_NOT_SUPPORTED;
  }
  self->use_golden_sei = enable;

  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_low_bitrate_mode(onvif_media_signing_t *self, bool enable)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  self->low_bitrate_mode = enable;

  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_vendor_info(onvif_media_signing_t *self,
    const onvif_media_signing_vendor_info_t *vendor_info)
{
  if (!self || !vendor_info) {
    return OMS_INVALID_PARAMETER;
  }

  memcpy(&self->vendor_info, vendor_info, sizeof(onvif_media_signing_vendor_info_t));

  return OMS_OK;
}

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
    // Temporally turn the PEM |private_key| into an EVP_PKEY and allocate memory for
    // signatures.
    OMS_THROW(openssl_private_key_malloc(self->sign_data, private_key, private_key_size));
    self->plugin_handle =
        onvif_media_signing_plugin_session_setup(private_key, private_key_size);
    OMS_THROW_IF(!self->plugin_handle, OMS_EXTERNAL_ERROR);

    self->certificate_chain.key = malloc(certificate_chain_size);
    OMS_THROW_IF(!self->certificate_chain.key, OMS_MEMORY);
    memcpy(self->certificate_chain.key, certificate_chain, certificate_chain_size);
    self->certificate_chain.key_size = certificate_chain_size;
  OMS_CATCH()
  OMS_DONE(status)

  // Free the EVP_PKEY since it is no longer needed. It is handled by the signing plugin.
  openssl_free_key(self->sign_data->key);
  self->sign_data->key = NULL;

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
#endif

MediaSigningReturnCode
onvif_media_signing_set_emulation_prevention_before_signing(onvif_media_signing_t *self,
    bool enable)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  self->sei_epb = enable;
  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_max_sei_payload_size(onvif_media_signing_t *self,
    size_t max_sei_payload_size)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  self->max_sei_payload_size = max_sei_payload_size;
  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_hash_algo(onvif_media_signing_t *self, const char *name_or_oid)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  if (self->signing_started) {
    return OMS_NOT_SUPPORTED;
  }

  size_t hash_size = 0;
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(openssl_set_hash_algo(self->crypto_handle, name_or_oid));
    hash_size = openssl_get_hash_size(self->crypto_handle);
    OMS_THROW_IF(hash_size == 0 || hash_size > MAX_HASH_SIZE, OMS_NOT_SUPPORTED);

    self->sign_data->hash_size = hash_size;
    // Point |nalu_hash| to the correct location in the |hash_to_sign| buffer.
    self->gop_info->nalu_hash = self->gop_info->hash_to_sign + hash_size;
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_signing_frequency(onvif_media_signing_t *self,
    unsigned signing_frequency)
{
  if (!self || signing_frequency == 0) {
    return OMS_INVALID_PARAMETER;
  }
  self->signing_frequency = signing_frequency;

  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_max_signing_nalus(onvif_media_signing_t *self,
    unsigned max_signing_nalus)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  self->max_signing_nalus = max_signing_nalus;

  return OMS_OK;
}
