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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // free, malloc, size_t
#include <string.h>  // memset

#include "includes/onvif_media_signing_plugin.h"
#include "includes/onvif_media_signing_signer.h"
#include "oms_defines.h"  // oms_rc
#include "oms_internal.h"
#include "oms_openssl_internal.h"
#include "oms_tlv.h"

static void
add_sei_to_buffer(onvif_media_signing_t *self,
    uint8_t *sei,
    uint8_t *write_position,
    bool is_complete);
static void
shift_sei_buffer_at_index(onvif_media_signing_t *self, int index);

static oms_rc
complete_sei(onvif_media_signing_t *self);
static void
set_uuid(onvif_media_signing_t *self, uint8_t **payload);
static oms_rc
generate_sei_and_add_to_buffer(onvif_media_signing_t *self, bool force_signature);
static size_t
add_stopbit_to_sei(onvif_media_signing_t *self, uint8_t *write_position);
static size_t
add_signature_to_sei(onvif_media_signing_t *self,
    const uint8_t *sei,
    uint8_t *write_position);
static oms_rc
process_signature(onvif_media_signing_t *self, oms_rc signature_error);

/* Adds the |sei| with current |write_position| to the next available slot in
 * |sei_data_buffer|. */
static void
add_sei_to_buffer(onvif_media_signing_t *self,
    uint8_t *sei,
    uint8_t *write_position,
    bool is_complete)
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

  size_t sei_size = 0;
  if (is_complete) {
    sei_size = write_position - sei;
  }
  self->sei_data_buffer[self->sei_data_buffer_idx].sei = sei;
  self->sei_data_buffer[self->sei_data_buffer_idx].write_position = write_position;
  self->sei_data_buffer[self->sei_data_buffer_idx].last_two_bytes = self->last_two_bytes;
  self->sei_data_buffer[self->sei_data_buffer_idx].completed_sei_size = sei_size;
  self->sei_data_buffer_idx += 1;
}

/* Removes the specified |index| element from |sei_data_buffer| by shifting remaining
 * elements left and clearing the last slot. */
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

/* Takes the oldest SEI from the |sei_data_buffer| and completes it with the generated
 * signature + the stop byte. If there is no signature the SEI payload is freed and not
 * added to the video session. */
static oms_rc
complete_sei(onvif_media_signing_t *self)
{
  assert(self);
  // Sanity check the buffer index.
  if (self->sei_data_buffer_idx < 1) {
    return OMS_NOT_SUPPORTED;
  }
  assert(self->sei_data_buffer_idx <= MAX_SEI_DATA_BUFFER);

  oms_rc status = OMS_UNKNOWN_FAILURE;
  // Find the oldest non-completed SEI (has size = 0).
  int idx = 0;
  sei_data_t *sei_data = &(self->sei_data_buffer[idx]);
  while (sei_data->completed_sei_size > 0 && idx < self->sei_data_buffer_idx) {
    idx++;
    sei_data = &(self->sei_data_buffer[idx]);
  }
  assert(sei_data->completed_sei_size == 0);
  // Transfer oldest pointer in |sei_data_buffer| to local |sei|.
  uint8_t *sei = sei_data->sei;
  uint8_t *write_position = sei_data->write_position;
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
  sei_data->completed_sei_size = add_signature_to_sei(self, sei, write_position);
  if (!sei_data->completed_sei_size) {
    status = OMS_UNKNOWN_FAILURE;
    goto done;
  }
  status = OMS_OK;
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
  OMS_TRY()
    // Hash the SEI
    uint8_t test_hash[MAX_HASH_SIZE];
    nalu_info_t test_nalu_info =
        parse_nalu_info(sei, sei_data->completed_sei_size, self->codec, false, true);
    OMS_THROW(simply_hash(self, &test_nalu_info, test_hash, self->sign_data->hash_size));
    free(test_nalu_info.nalu_wo_epb);
    // Borrow hash and signature from |sign_data|.
    sign_or_verify_data_t verify_data = {
        .hash = test_hash,
        .hash_size = self->sign_data->hash_size,
        .key = NULL,
        .signature = self->sign_data->signature,
        .signature_size = self->sign_data->signature_size,
        .max_signature_size = self->sign_data->max_signature_size,
    };
    // Extract the Public key from the leaf certificate for verification. Normally done
    // upon validation.
    OMS_THROW(openssl_store_public_key(&verify_data, &self->certificate_chain));
    // Verify the just signed hash.
    int verified = -1;
    OMS_THROW_WITH_MSG(
        openssl_verify_hash(&verify_data, &verified), "Verification test had errors");
    openssl_free_key(verify_data.key);
    OMS_THROW_IF_WITH_MSG(verified != 1, OMS_EXTERNAL_ERROR, "Verification test failed");
  OMS_CATCH()
  OMS_DONE(status)
#endif

done:

  return status;
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
 * hashed and signed.
 * Signing is performed by a signing plugin and, while "waiting" for the signature, the
 * ongoing SEI is stored in a buffer. */
static oms_rc
generate_sei_and_add_to_buffer(onvif_media_signing_t *self, bool force_signature)
{
  gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *sign_data = self->sign_data;
  const size_t hash_size = sign_data->hash_size;
  size_t num_optional_tags = 0;
  size_t num_mandatory_tags = 0;
  uint8_t *sei = NULL;
  bool sign_this_sei = (self->num_gops_until_signing == 0) || force_signature;

  const oms_tlv_tag_t *optional_tags = get_optional_tags(&num_optional_tags);
  const oms_tlv_tag_t *mandatory_tags = get_mandatory_tags(&num_mandatory_tags);
  const oms_tlv_tag_t signature_tag = get_signature_tag();

  size_t payload_size = 0;
  size_t optional_tags_size = 0;
  size_t mandatory_tags_size = 0;
  size_t signature_size = 0;
  size_t sei_size = 0;

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space to store the, to be generated, SEI.
    return OMS_NOT_SUPPORTED;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Get the total payload size of all TLVs. Then compute the total size of the SEI to
    // be generated. Add extra space for potential emulation prevention bytes.
    optional_tags_size =
        tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, NULL);
    mandatory_tags_size =
        tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
    // Turn off optional tags if they are sent in a certificate SEI.
    if (self->use_certificate_sei && !self->is_certificate_sei) {
      optional_tags_size = 0;
    }
    // Certificate SEIs only transmit optional tags.
    if (self->is_certificate_sei) {
      mandatory_tags_size = 0;
    }
    signature_size = tlv_list_encode_or_get_size(self, &signature_tag, 1, NULL);
    if (!sign_this_sei) {
      signature_size = 0;
    }

    payload_size = optional_tags_size + mandatory_tags_size + signature_size;
    payload_size += UUID_LEN;  // UUID
    payload_size += 1;  // One byte for reserved data.
    // Take action if |max_sei_payload_size| is reached.
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
    sei_size += self->codec == OMS_CODEC_H264 ? 6 : 7;  // NAL Unit header
    sei_size += payload_size / 255 + 1;  // Size field
    sei_size += payload_size;
    sei_size += 1;  // Stop bit in a separate byte

    // Secure enough memory for emulation prevention. Worst case will add 1 extra byte per
    // 3 bytes.
    sei_size = sei_size * 4 / 3;

    // Allocate memory for payload + SEI header to return
    sei = malloc(sei_size);
    OMS_THROW_IF(!sei, OMS_MEMORY);

    // Track the write position with |sei_ptr|.
    uint8_t *sei_ptr = sei;

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
    // reserved_byte = |certificate sei|epb|0|0|0|0|0|0|
    uint8_t reserved_byte = 0;
    reserved_byte |= self->is_certificate_sei << 7;
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
    // data so far and the pointers to the |hashable_data| and the size of it will
    // automatically be set. Then use the hash_and_add() function.
    if (sign_this_sei) {
      size_t fake_payload_size = (sei_ptr - sei);
      // Force SEI to be hashable by flagging this as being the validation side.
      nalu_info_t nalu_info_without_signature_data =
          parse_nalu_info(sei, fake_payload_size, self->codec, false, true);
      // Create a document hash.
      OMS_THROW(hash_and_add(self, &nalu_info_without_signature_data));
      // Note that the "add" part of the hash_and_add() operation above will add this hash
      // to the |hash_list|. There is no harm done though, since the list will be reset
      // after generating the SEI.

      // The current |nalu_hash| is the hash to sign.
      memcpy(sign_data->hash, gop_info->nalu_hash, hash_size);
      // Free the memory allocated when parsing the NAL Unit.
      free(nalu_info_without_signature_data.nalu_wo_epb);
    }

    // Reset the |num_frames_in_partial_gop| since a new partial GOP is started.
    gop_info->num_frames_in_partial_gop = 0;
    // Reset the |hash_list| by rewinding the |hash_list_idx| since a new (partial) GOP is
    // triggered.
    gop_info->hash_list_idx = 0;
    // Initialize the gop_hash by resetting it.
    OMS_THROW(openssl_init_hash(self->crypto_handle, true));
    // End of (partial) GOP. Reset flag to get new reference.
    gop_info->has_anchor_hash = false;

    if (sign_this_sei) {
      OMS_THROW(onvif_media_signing_plugin_sign(
          self->plugin_handle, sign_data->hash, sign_data->hash_size));
    } else {
      written_size = add_stopbit_to_sei(self, sei_ptr);
      OMS_THROW_IF(written_size == 0, OMS_MEMORY);
      sei_ptr += written_size;
    }
  OMS_CATCH()
  {
    DEBUG_LOG("Failed generating the SEI");
    free(sei);
    sei = NULL;
    sei_ptr = NULL;
  }
  OMS_DONE(status)

  // Add |sei| to buffer. Will be picked up again when the signature has been generated.
  // If the SEI is not signed mark it as complete at once.
  add_sei_to_buffer(self, sei, sei_ptr, !sign_this_sei);

  return status;
}

static size_t
add_stopbit_to_sei(onvif_media_signing_t *self, uint8_t *write_position)
{
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint8_t *sei_ptr = write_position;

  // Stop bit
  write_byte(last_two_bytes, &sei_ptr, 0x80, false);

  // Return number of written bytes
  return sei_ptr - write_position;
}

static size_t
add_signature_to_sei(onvif_media_signing_t *self,
    const uint8_t *sei,
    uint8_t *write_position)
{
  const oms_tlv_tag_t signature_tag = get_signature_tag();
  uint8_t *sei_ptr = write_position;
  if (!sei_ptr) {
    // No SEI to finalize
    return 0;
  }
  // TODO: Investigate if it can happen that an older signature could be added by
  // accident.

  size_t written_size = tlv_list_encode_or_get_size(self, &signature_tag, 1, sei_ptr);
  if (written_size == 0) {
    DEBUG_LOG("Failed to write signature");
    return 0;
  }
  sei_ptr += written_size;
  sei_ptr += add_stopbit_to_sei(self, sei_ptr);

  // Return the total size of the completed SEI
  return sei_ptr - sei;
}

static oms_rc
process_signature(onvif_media_signing_t *self, oms_rc signature_error)
{
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW(signature_error);
    OMS_THROW(complete_sei(self));
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

/* This function finds the beginning of the last certificate, which is the trusted anchor
 * certificate. The size of the other certificates is returned.
 *
 * Note that the returned size excludes any null-terminated characters.
 */
// TODO: Let OpenSSL do this for us.
size_t
get_untrusted_certificates_size(const char *certificate_chain,
    size_t certificate_chain_size)
{
  size_t cert_chain_size_without_anchor = 0;
  // Turn the input data into a character string
  char *cert_chain_str = calloc(1, certificate_chain_size + 1);
  if (!cert_chain_str) {
    return 0;
  }
  memcpy(cert_chain_str, certificate_chain, certificate_chain_size);
  if (strlen(cert_chain_str) == 0) {
    return 0;
  }

  // Find the start of the last certificate in |certificate_chain|, which should be the
  // anchor certificate.
  const char *cert_chain_ptr = cert_chain_str;
  const char *cert_ptr = strstr(cert_chain_ptr, "-----BEGIN CERTIFICATE-----");
  const char *last_cert = cert_chain_str;
  int num_certs = 0;
  int size_left = (int)certificate_chain_size;
  while (cert_ptr && size_left > 27) {
    num_certs++;
    last_cert = cert_ptr;
    cert_chain_ptr = cert_ptr + 1;
    cert_ptr = strstr(cert_chain_ptr, "-----BEGIN CERTIFICATE-----");
    if (cert_ptr) {
      size_left -= (cert_ptr - last_cert);
    }
  }
  // Check if there are at least two certificates in the chain. The chain should at least
  // include a leaf certificate with the public key and a self-signed trusted anchor
  // certificate. It is not allowed to have one single self-signed certificate with the
  // public key.
  if ((num_certs > 1) && last_cert) {
    cert_chain_size_without_anchor = last_cert - cert_chain_str;
  }

  free(cert_chain_str);
  return cert_chain_size_without_anchor;
}

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
  gop_info_t *gop_info = self->gop_info;
  // TODO: Consider moving this into parse_nalu_info().
  if (self->last_nalu->is_last_nalu_part) {
    // Only parse the |nalu| for information if this is the first part of a NAL Unit,
    // hence includes the header.
    nalu_info = parse_nalu_info(nalu, nalu_size, self->codec, is_last_part, false);
    nalu_info.is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(self->last_nalu, &nalu_info);
  } else {
    self->last_nalu->is_first_nalu_part = false;
    self->last_nalu->is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(&nalu_info, self->last_nalu);
    nalu_info.nalu_data = nalu;
    nalu_info.hashable_data = nalu;
    // Remove any trailing 0x00 bytes at the end of a NAL Unit.
    while (is_last_part && (nalu[nalu_size - 1] == 0x00)) {
      nalu_size--;
    }
    nalu_info.hashable_data_size = nalu_size;
  }
  // Only completed primary slices can trigger actions.
  bool is_actionable = nalu_info.is_primary_slice && nalu_info.is_last_nalu_part;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Without a private key (signing plugin) it is not possible to sign.
    OMS_THROW_IF_WITH_MSG(!self->plugin_handle, OMS_NOT_SUPPORTED, "No private key set");
    OMS_THROW_IF(nalu_info.is_valid < 0, OMS_INVALID_PARAMETER);

    unsigned hashed_nalus = gop_info->hash_list_idx / self->sign_data->hash_size;
    // Determine if a SEI should be generated.
    bool new_gop = nalu_info.is_first_nalu_in_gop && is_actionable;
    // Trigger signing if number of frames exceeds the limit for a partial GOP.
    bool trigger_signing = ((self->max_signing_frames > 0) &&
        (gop_info->num_frames_in_partial_gop >= self->max_signing_frames));
    // Only trigger if this NAL Unit is hashable, hence will be added to the hash list.
    trigger_signing &= nalu_info.is_hashable && is_actionable;
    gop_info->triggered_partial_gop = false;
    // Depending on the input NAL Unit, different actions are taken. If the input is an
    // I-frame there is a transition to a new GOP. That triggers generating a SEI. While
    // being signed it is put in a buffer. For all other valid NAL Units, simply hash and
    // proceed.
    if (new_gop || trigger_signing) {
      gop_info->triggered_partial_gop = !new_gop;
      // An I-frame indicates the start of a new GOP, hence trigger generating a SEI. This
      // also means that the signing feature is present.

      // Update the timestamp for the partial GOP.
      gop_info->start_timestamp = gop_info->end_timestamp;
      gop_info->end_timestamp = timestamp;
      // Generate a GOP hash
      gop_info->num_nalus_in_partial_gop = hashed_nalus;
      if (gop_info->hash_list_idx == 0) {
        // If the |hash_list| is empty make sure the |partial_gop_hash| has all zeros.
        memset(gop_info->partial_gop_hash, 0, MAX_HASH_SIZE);
      } else {
        OMS_THROW(finalize_gop_hash(self->crypto_handle, gop_info->partial_gop_hash));
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
        oms_print_hex_data(gop_info->partial_gop_hash, self->sign_data->hash_size,
            "Current (partial) GOP hash: ");
#endif
      }
      if (self->signing_started && (gop_info->current_partial_gop > 0)) {
        OMS_THROW(generate_sei_and_add_to_buffer(self, trigger_signing));
        if (new_gop && (self->num_gops_until_signing == 0)) {
          // Reset signing counter only upon new GOPs
          self->num_gops_until_signing = self->signing_frequency;
        }
      }
      // Increment GOP counter since a new (partial) GOP is detected.
      if (gop_info->current_partial_gop < 0) {
        gop_info->current_partial_gop = 0;
      }
      gop_info->current_partial_gop++;
      if (new_gop) {
        self->num_gops_until_signing--;
      }
    }
    OMS_THROW(hash_and_add(self, &nalu_info));
    // Mark the start of signing when the first NAL Unit is passed in and successfully
    // been hashed (all parts).
    if (nalu_info.is_last_nalu_part) {
      self->signing_started = true;
      // Increment frame counter after the incoming NAL Unit has been processed.
      gop_info->num_frames_in_partial_gop += nalu_info.is_primary_slice;
    }
  OMS_CATCH()
  OMS_DONE(status)

  free(nalu_info.nalu_wo_epb);

  return status;
}

MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t *self,
    uint8_t **sei,
    size_t *sei_size,
    unsigned *payload_offset,
    const uint8_t *peek_nalu,
    size_t peek_nalu_size,
    unsigned *num_pending_seis)
{
  if (!self || !sei || !sei_size) {
    return OMS_INVALID_PARAMETER;
  }

  // Ask the signing plugin for signatures.
  sign_or_verify_data_t *sign_data = self->sign_data;
  *sei_size = 0;
  if (payload_offset) {
    *payload_offset = 0;
  }
  if (num_pending_seis) {
    *num_pending_seis = self->sei_data_buffer_idx;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  MediaSigningReturnCode signature_error = OMS_UNKNOWN_FAILURE;
  while (
      onvif_media_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
          sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
    status = process_signature(self, signature_error);
    if (status != OMS_OK) {
      return status;
    }
  }

  if (peek_nalu && peek_nalu_size > 0) {
    nalu_info_t nalu_info =
        parse_nalu_info(peek_nalu, peek_nalu_size, self->codec, false, false);
    free(nalu_info.nalu_wo_epb);
    // Only display a SEI if the |peek_nalu| is a primary picture NAL Unit.
    if (!((nalu_info.nalu_type == NALU_TYPE_I || nalu_info.nalu_type == NALU_TYPE_P) &&
            nalu_info.is_primary_slice)) {
      return OMS_OK;
    }
  }

  *sei_size = self->sei_data_buffer[0].completed_sei_size;
  if (*sei_size == 0) {
    return OMS_OK;
  }

  // Transfer the SEI data to the user through the provided pointer.
  *sei = self->sei_data_buffer[0].sei;
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
  size_t i = 0;
  printf("\n SEI (%zu bytes):  ", *sei_size);
  for (i = 0; i < *sei_size; ++i) {
    printf(" %02x", (*sei)[i]);
  }
  printf("\n");
#endif
  // Reset the fetched SEI information from the sei buffer.
  shift_sei_buffer_at_index(self, 0);

  // Get the offset to the start of the SEI payload if requested.
  if (payload_offset) {
    nalu_info_t nalu_info = parse_nalu_info(*sei, *sei_size, self->codec, false, false);
    free(nalu_info.nalu_wo_epb);
    *payload_offset = (unsigned)(nalu_info.payload - *sei);
  }

  // Set again in case SEIs were copied.
  if (num_pending_seis) {
    *num_pending_seis = self->sei_data_buffer_idx;
  }

  return OMS_OK;
}

// Note that the user has to fetch all the remaining SEIs before closing the stream.
MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t *self)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  if (!self->signing_started) {
    return OMS_NOT_SUPPORTED;
  }

  return generate_sei_and_add_to_buffer(self, true);
}

MediaSigningReturnCode
onvif_media_signing_generate_certificate_sei(onvif_media_signing_t *self)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }

  // The flag |is_certificate_sei| will mark the next SEI as certificate.
  self->is_certificate_sei = true;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Without a private key (signing plugin) it is not possible to sign.
    OMS_THROW_IF_WITH_MSG(!self->plugin_handle, OMS_NOT_SUPPORTED, "No private key set");
    OMS_THROW(generate_sei_and_add_to_buffer(self, true));
  OMS_CATCH()
  OMS_DONE(status)

  // Disable the certificate SEI for future.
  self->is_certificate_sei = false;

  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_use_certificate_sei(onvif_media_signing_t *self, bool enable)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  if (self->signing_started) {
    return OMS_NOT_SUPPORTED;
  }
  self->use_certificate_sei = enable;

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
  if (self->signing_started) {
    return OMS_NOT_SUPPORTED;
  }
  if (user_provisioned) {
    return OMS_NOT_SUPPORTED;
  }

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    size_t stripped_size =
        get_untrusted_certificates_size(certificate_chain, certificate_chain_size);
    OMS_THROW_IF_WITH_MSG(stripped_size == 0, OMS_INVALID_PARAMETER,
        "To few certificates in certificate_chain");
    self->certificate_chain.key = malloc(stripped_size);
    OMS_THROW_IF(!self->certificate_chain.key, OMS_MEMORY);
    memcpy(self->certificate_chain.key, certificate_chain, stripped_size);
    self->certificate_chain.key_size = stripped_size;
    // Verify that the certificate chain is complete and feasible to verify.
    OMS_THROW(openssl_set_trusted_certificate(self->crypto_handle,
        &certificate_chain[stripped_size], certificate_chain_size - stripped_size,
        user_provisioned));
    OMS_THROW(openssl_verify_certificate_chain(self->crypto_handle,
        self->certificate_chain.key, self->certificate_chain.key_size, user_provisioned));

    // Temporally store the PEM |private_key| and allocate memory for signatures.
    OMS_THROW(openssl_store_private_key(self->sign_data, private_key, private_key_size));
    self->plugin_handle =
        onvif_media_signing_plugin_session_setup(private_key, private_key_size);
    OMS_THROW_IF(!self->plugin_handle, OMS_EXTERNAL_ERROR);
  OMS_CATCH()
  OMS_DONE(status)

  // Free the temporally stored key since it is no longer needed. It is handled by the
  // signing plugin.
  openssl_free_key(self->sign_data->key);
  self->sign_data->key = NULL;

  return status;
}

MediaSigningReturnCode
onvif_media_signing_set_emulation_prevention_before_signing(onvif_media_signing_t *self,
    bool enable)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  if (self->signing_started) {
    return OMS_NOT_SUPPORTED;
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
  if (!self->signing_started) {
    self->num_gops_until_signing = signing_frequency;
  }

  return OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_max_signing_frames(onvif_media_signing_t *self,
    unsigned max_signing_frames)
{
  if (!self) {
    return OMS_INVALID_PARAMETER;
  }
  self->max_signing_frames = max_signing_frames;

  return OMS_OK;
}
