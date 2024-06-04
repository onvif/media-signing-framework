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

#include <assert.h>  // assert
#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <stdio.h>  // sscanf
#include <stdlib.h>  // free, calloc, malloc, size_t, memcmp

#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_plugin.h"
#include "oms_defines.h"
#include "oms_internal.h"
#include "oms_openssl_internal.h"
#include "oms_tlv.h"

#define H264_NALU_HEADER_LEN 1  // length of forbidden_zero_bit, nal_ref_idc and
// nal_unit_type
#define H265_NALU_HEADER_LEN 2  // length of nal_unit_header as per
// ISO/ITU spec

static bool
version_str_to_bytes(int *arr, const char *str);

static gop_info_t *
gop_info_create(void);
static void
gop_info_free(gop_info_t *gop_info);
static void
gop_info_reset(gop_info_t *gop_info);

static sign_or_verify_data_t *
sign_or_verify_data_create();
static void
sign_or_verify_data_free(sign_or_verify_data_t *self);

static oms_rc
set_hash_list_size(gop_info_t *gop_info, size_t hash_list_size);

static size_t
get_payload_size(const uint8_t *data, size_t *payload_size);
static bool
is_media_signing_uuid(const uint8_t *uuid);
static void
remove_epb_from_sei_payload(nalu_info_t *nalu_info);

// /* Hash wrapper functions */
typedef oms_rc (
    *hash_wrapper_t)(onvif_media_signing_t *, const nalu_info_t *, uint8_t *, size_t);
static hash_wrapper_t
get_hash_wrapper(onvif_media_signing_t *self, const nalu_info_t *nalu_info);
static oms_rc
update_hash(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size);
static oms_rc
simply_hash(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size);
static oms_rc
hash_and_copy_to_anchor(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size);
static oms_rc
hash_with_anchor(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *buddy_hash,
    size_t hash_size);
static void
check_and_copy_hash_to_hash_list(onvif_media_signing_t *self,
    const uint8_t *hash,
    size_t hash_size);

/* Reads the version string and puts the Major.Minor.Patch in the first, second and third
 * element of the array, respectively */
static bool
version_str_to_bytes(int *arr, const char *str)
{
  bool status = false;
  int ret = sscanf(str, "v%d.%d.%d", &arr[0], &arr[1], &arr[2]);
  if (ret == 3) {
    status = true;  // All three elements read
  }

  return status;
}

/* Puts Major, Minor and Patch from a version array to a version string */
#ifdef PRINT_DECODED_SEI
void
bytes_to_version_str(const int *arr, char *str)
{
  if (!arr || !str) {
    return;
  }
  sprintf(str, "v%d.%d.%d", arr[0], arr[1], arr[2]);
}
#endif

#ifdef ONVIF_MEDIA_SIGNING_DEBUG
char *
nalu_type_to_str(const nalu_info_t *nalu_info)
{
  switch (nalu_info->nalu_type) {
    case NALU_TYPE_SEI:
      return "SEI";
    case NALU_TYPE_I:
      return nalu_info->is_primary_slice == true ? "I (primary)" : "i (not primary)";
    case NALU_TYPE_P:
      return nalu_info->is_primary_slice == true ? "P (primary)" : "p (not primary)";
    case NALU_TYPE_PS:
      return "PPS/SPS/VPS";
    case NALU_TYPE_AUD:
      return "AUD";
    case NALU_TYPE_OTHER:
      return "valid other NAL Unit";
    case NALU_TYPE_UNDEFINED:
    default:
      return "unknown NAL Unit";
  }
}

#if 0
char
nalu_type_to_char(const nalu_info_t *nalu_info)
{
  // If no NALU is present, mark as missing, i.e., empty ' '.
  if (!nalu_info) return ' ';

  switch (nalu_info->nalu_type) {
    case NALU_TYPE_SEI:
      return nalu_info->is_gop_sei ? 'S' : 'z';
    case NALU_TYPE_I:
      return nalu_info->is_primary_slice == true ? 'I' : 'i';
    case NALU_TYPE_P:
      return nalu_info->is_primary_slice == true ? 'P' : 'p';
    case NALU_TYPE_PS:
      return 'v';
    case NALU_TYPE_AUD:
      return '_';
    case NALU_TYPE_OTHER:
      return 'o';
    case NALU_TYPE_UNDEFINED:
    default:
      return 'U';
  }
}
#endif
#endif

/* Declared in oms_internal.h */
const uint8_t kUuidMediaSigning[UUID_LEN] = {0x00, 0x5b, 0xc9, 0x3f, 0x2d, 0x71, 0x5e,
    0x95, 0xad, 0xa4, 0x79, 0x6f, 0x90, 0x87, 0x7a, 0x6f};

static sign_or_verify_data_t *
sign_or_verify_data_create()
{
  sign_or_verify_data_t *self = calloc(1, sizeof(sign_or_verify_data_t));
  if (self) {
    self->hash = calloc(1, MAX_HASH_SIZE);
    if (!self->hash) {
      free(self);
      self = NULL;
    } else {
      self->hash_size = DEFAULT_HASH_SIZE;
    }
  }
  return self;
}

static void
sign_or_verify_data_free(sign_or_verify_data_t *self)
{
  if (!self) {
    return;
  }

  openssl_free_key(self->key);
  free(self->hash);
  free(self->signature);
  free(self);
}

static oms_rc
set_hash_list_size(gop_info_t *gop_info, size_t hash_list_size)
{
  if (!gop_info) {
    return OMS_INVALID_PARAMETER;
  }
  if (hash_list_size > HASH_LIST_SIZE) {
    return OMS_NOT_SUPPORTED;
  }

  gop_info->hash_list_size = hash_list_size;
  return OMS_OK;
}

/**
 * @brief Helper function to create a gop_info_t struct
 *
 * Allocate gop_info struct and initialize
 */
static gop_info_t *
gop_info_create(void)
{
  gop_info_t *gop_info = calloc(1, sizeof(gop_info_t));
  if (!gop_info) {
    return NULL;
  }

  gop_info->current_gop = 0;
  // Initialize |verified_signature_hash| as 'error', since we lack data.
  gop_info->verified_signature = -1;

  // Set shortcut pointers to the NAL Unit hash parts of the memory.
  gop_info->nalu_hash = gop_info->hash_to_sign + DEFAULT_HASH_SIZE;

  // Set hash_list_size to same as what is allocated.
  if (set_hash_list_size(gop_info, HASH_LIST_SIZE) != OMS_OK) {
    gop_info_free(gop_info);
    gop_info = NULL;
  }

  return gop_info;
}

static void
gop_info_free(gop_info_t *gop_info)
{
  free(gop_info);
}

static void
gop_info_reset(gop_info_t *gop_info)
{
  gop_info->verified_signature = -1;
  // If a reset is forced, the stored hashes in |hash_list| have no meaning anymore.
  gop_info->hash_list_idx = 0;
  gop_info->has_anchor_hash = false;
  gop_info->global_gop_counter_is_synced = false;
}

#if 0
oms_rc
reset_gop_hash(onvif_media_signing_t *self)
{
  if (!self) return OMS_INVALID_PARAMETER;

  gop_info_t *gop_info = self->gop_info;
  assert(gop_info);

  gop_info->num_nalus_in_partial_gop = 0;
  return openssl_hash_data(self->crypto_handle, &gop_info->gop_hash_init, 1, gop_info->gop_hash);
}

/**
 * Checks a pointer to member in struct if it's allocated, and correct size, then copies over the
 * data to that member.
 *
 * If new_data_ptr is the empty string then the member will be freed. If it's null then this
 * function will do nothing. Member pointers must not be null, i.e. member_ptr and member_size_ptr.
 *
 * Assumptions:
 *  - if the new_data_pointer is null then new_data_size is zero.
 *  - new_data_size should include the null-terminator.
 *  - if member_ptr points to some memory then member_size_ptr should point to a value of that size.
 *    Otherwise, if member_ptr points to null, then member_size_ptr should point to zero.
 *
 * Restrictions:
 *  - member_ptr can't be set to the empty string
 */
oms_rc
struct_member_memory_allocated_and_copy(void **member_ptr,
    uint8_t *member_size_ptr,
    const void *new_data_ptr,
    const uint8_t new_data_size)
{
  if (!member_size_ptr || !member_ptr) {
    return OMS_INVALID_PARAMETER;
  } else if (!new_data_size) {
    // New size is zero, doing nothing
    return OMS_OK;
  } else if (new_data_size == 1 && *(char *)new_data_ptr == '\0') {
    // Reset member on empty string, i.e. ""
    free(*member_ptr);
    *member_ptr = NULL;
    *member_size_ptr = 0;
    return OMS_OK;
  }
  // The allocated size must be exact or reset on empty string, i.e., ""
  if (*member_size_ptr != new_data_size) {
    DEBUG_LOG("Member size diff, re-allocating");
    *member_ptr = realloc(*member_ptr, new_data_size);
    if (*member_ptr == NULL) return OMS_MEMORY;
  }
  memcpy(*member_ptr, new_data_ptr, new_data_size);
  *member_size_ptr = new_data_size;
  return OMS_OK;
}
#endif

static size_t
get_payload_size(const uint8_t *data, size_t *payload_size)
{
  const uint8_t *data_ptr = data;
  // Get payload size (including UUID), assuming that |data| points to the size bytes.
  while (*data_ptr == 0xFF) {
    *payload_size += *data_ptr++;
  }
  *payload_size += *data_ptr++;

  return (data_ptr - data);
}

static bool
is_media_signing_uuid(const uint8_t *uuid)
{
  if (!uuid) {
    return false;
  }
  return (memcmp(uuid, kUuidMediaSigning, UUID_LEN) == 0);
}

static bool
parse_h264_nalu_header(nalu_info_t *nalu_info)
{
  // Parse the H264 NAL Unit Header
  uint8_t nalu_header = *(nalu_info->hashable_data);
  bool forbidden_zero_bit = (bool)(nalu_header & 0x80);  // First bit
  uint8_t nal_ref_idc = nalu_header & 0x60;  // Two bits
  uint8_t nalu_type = nalu_header & 0x1f;
  bool nalu_header_is_valid = false;

  // First slice in the current NALU or not
  nalu_info->is_primary_slice = *(nalu_info->hashable_data + H264_NALU_HEADER_LEN) & 0x80;

  // Verify that NALU type and nal_ref_idc follow standard.
  switch (nalu_type) {
    // nal_ref_idc can be zero for types 1-4.
    case 1:  // Coded slice of a non-IDR picture, hence P-nalu or B-nalu
      nalu_info->nalu_type = NALU_TYPE_P;
      nalu_header_is_valid = true;
      break;
    case 2:  // Coded slice data partition A
    case 3:  // Coded slice data partition B
    case 4:  // Coded slice data partition C
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = true;
      break;
    case 5:  // Coded slice of an IDR picture, hence I-nalu
      nalu_info->nalu_type = NALU_TYPE_I;
      nalu_header_is_valid = (nal_ref_idc > 0);
      break;
    case 6:  // SEI-nalu
      nalu_info->nalu_type = NALU_TYPE_SEI;
      nalu_header_is_valid = (nal_ref_idc == 0);
      break;
    case 7:  // SPS
    case 8:  // PPS
    case 13:  // SPS extension
    case 15:  // Subset SPS
      nalu_info->nalu_type = NALU_TYPE_PS;
      nalu_header_is_valid = (nal_ref_idc > 0);
      break;
    case 9:  // AU delimiter
      // Do not hash because these will be removed if you switch from bytestream to NALU
      // stream format
      nalu_info->nalu_type = NALU_TYPE_AUD;
      nalu_header_is_valid = true;
      break;
    case 10:  // End of sequence
    case 11:  // End of stream
    case 12:  // Filter data
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (nal_ref_idc == 0);
      break;
    default:
      nalu_info->nalu_type = NALU_TYPE_UNDEFINED;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct NALU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

static bool
parse_h265_nalu_header(nalu_info_t *nalu_info)
{
  // Parse the H265 NAL Unit Header
  uint8_t nalu_header = *(nalu_info->hashable_data);
  bool forbidden_zero_bit = (bool)(nalu_header & 0x80);  // First bit
  uint8_t nalu_type = (nalu_header & 0x7E) >> 1;  // Six bits
  uint8_t nuh_layer_id = ((nalu_header & 0x01) << 5) |
      ((*(nalu_info->hashable_data + 1) & 0xF8) >> 3);  // Six bits
  uint8_t nuh_temporal_id_plus1 = (*(nalu_info->hashable_data + 1) & 0x07);  // Three bits
  uint8_t temporalId = nuh_temporal_id_plus1 - 1;
  bool nalu_header_is_valid = false;

  if ((nuh_temporal_id_plus1 == 0) || (nuh_layer_id > 63)) {
    DEBUG_LOG("H.265 NALU header %02x%02x is invalid", nalu_header,
        *(nalu_info->hashable_data + 1));
    return false;
  }

  // First slice in the current NALU or not
  nalu_info->is_primary_slice =
      (*(nalu_info->hashable_data + H265_NALU_HEADER_LEN) & 0x80);

  // Verify that NALU type and nal_ref_idc follow standard.
  switch (nalu_type) {
      // 0 to 5. Trailing non-IRAP pictures
    case 0:  // 0 TRAIL_N Coded slice segment of a non-TSA, non-STSA trailing picture VCL

    case 1:  // 1 TRAIL_R Coded slice segment of a non-TSA, non-STSA trailing picture VCL

      nalu_info->nalu_type = NALU_TYPE_P;
      nalu_header_is_valid = true;
      break;
    case 2:  // 2 TSA_N Coded slice segment of a TSA picture VCL
    case 3:  // 3 TSA_R Coded slice segment of a TSA picture VCL
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId != 0);
      break;
    case 4:  // 4 STSA_N Coded slice segment of an STSA picture VCL
    case 5:  // 5 STSA_R Coded slice segment of an STSA picture VCL
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (nuh_layer_id == 0) ? (temporalId != 0) : true;
      break;

    // 6 to 9. Leading picture*/
    case 6:  // 6 RADL_N Coded slice segment of a RADL picture VCL
    case 7:  // 7 RADL_R Coded slice segment of a RADL picture VCL
    case 8:  // 8 RASL_N Coded slice segment of a RASL picture VCL
    case 9:  // 9 RASL_R Coded slice segment of a RASL picture VCL
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId != 0);
      break;

    // 16 to 21. Intra random access point (IRAP) pictures
    case 16:  // 16 BLA_W_LP Coded slice segment of a BLA picture VCL
    case 17:  // 17 BLA_W_RADL Coded slice segment of a BLA picture VCL
    case 18:  // 18 BLA_N_LP Coded slice segment of a BLA picture VCL
    case 19:  // 19 IDR_W_RADL Coded slice segment of an IDR picture VCL
    case 20:  // 20 IDR_N_LP Coded slice segment of an IDR picture VCL
    case 21:  // 21 CRA_NUTCoded slice segment of a CRA picture VCL
      nalu_info->nalu_type = NALU_TYPE_I;
      nalu_header_is_valid = (temporalId == 0);
      break;

    case 32:  // 32 VPS_NUT Video parameter non-VCL
    case 33:  // 33 SPS_NUT Sequence parameter non-VCL
      nalu_info->nalu_type = NALU_TYPE_PS;
      nalu_header_is_valid = (temporalId == 0);
      break;
    case 34:  // 34 PPS_NUT Picture parameter non-VCL
      nalu_info->nalu_type = NALU_TYPE_PS;
      nalu_header_is_valid = true;
      break;
    case 35:  // 35 AUD_NUT Access unit non-VCL
      // Do not hash because these will be removed if you switch
      // from bytestream to NALU stream format
      nalu_info->nalu_type = NALU_TYPE_AUD;
      nalu_header_is_valid = true;
      break;
    case 36:  // 36 EOS_NUT End non-VCL
    case 37:  // 37 EOB_NUT End of non-VCL
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId == 0) && (nuh_layer_id == 0);
      break;
    case 38:  // 38 FD_NUTFiller datafiller_data_rbsp() non-VCL
      nalu_info->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = true;
      break;
    case 39:  // 39 PREFIX_SEI_NUTSUFFIX_SEI_NUT non-VCL
    case 40:  // 40 SUFFIX_SEI_NUTSUFFIX_SEI_NUT non-VCL
      nalu_info->nalu_type = NALU_TYPE_SEI;
      nalu_header_is_valid = true;
      break;

    default:
      // Reserved and non valid
      // 10 RSV_VCL_N Reserved non-IRAP SLNR VCL NAL unit types VCL
      // 12 RSV_VCL_N Reserved non-IRAP SLNR VCL NAL unit types VCL
      // 14 RSV_VCL_N Reserved non-IRAP SLNR VCL NAL unit types VCL
      // 11 RSV_VCL_R Reserved non-IRAP sub-layer reference VCL NAL unit types VCL
      // 13 RSV_VCL_R Reserved non-IRAP sub-layer reference VCL NAL unit types VCL
      // 15 RSV_VCL_R Reserved non-IRAP sub-layer reference VCL NAL unit types VCL
      // 22 RSV_IRAP_VCL22 Reserved IRAP VCL NAL unit types VCL
      // 23 RSV_IRAP_VCL23 Reserved IRAP VCL NAL unit types VCL
      // 41..47 RSV_NVCL41..RSV_NVCL47 Reserved non-VCL
      // 24..31 RSV_VCL24.. RSV_VCL31 Reserved non-IRAP VCL NAL unit types VCL
      // 48..63 UNSPEC48..UNSPEC63Unspecified  non-VCL
      nalu_info->nalu_type = NALU_TYPE_UNDEFINED;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct NALU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

/**
 * @brief Removes emulation prevention bytes from a, by ONVIF Media Signing, generated SEI
 *
 * If emulation prevention bytes are present, temporary memory is allocated to hold the
 * new tlv data. Once emulation prevention bytes have been removed the new tlv data can be
 * decoded. */
static void
remove_epb_from_sei_payload(nalu_info_t *nalu_info)
{
  assert(nalu_info);
  if (!nalu_info->is_hashable || !nalu_info->is_oms_sei || (nalu_info->is_valid <= 0)) {
    return;
  }

  // The UUID (16 bytes) has by definition no emulation prevention bytes. Hence, read the
  // |reserved_byte| and point to the start of the TLV part.
  nalu_info->tlv_start_in_nalu_data = nalu_info->payload + UUID_LEN;
  nalu_info->tlv_size = nalu_info->payload_size - UUID_LEN;
  nalu_info->reserved_byte = *nalu_info->tlv_start_in_nalu_data;
  nalu_info->tlv_start_in_nalu_data++;  // Move past the |reserved_byte|.
  nalu_info->tlv_size -= 1;  // Exclude the |reserved_byte| from TLV size.
  nalu_info->tlv_data = nalu_info->tlv_start_in_nalu_data;
  // Read flags from |reserved_byte|
  nalu_info->is_golden_sei =
      (nalu_info->reserved_byte & 0x80);  // The NAL Unit is a golden SEI.
  nalu_info->with_epb =
      (nalu_info->reserved_byte & 0x40);  // Hash with emulation prevention bytes

  if (nalu_info->emulation_prevention_bytes <= 0) {
    return;
  }

  // We need to read byte by byte to a new memory and remove any emulation prevention
  // bytes.
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  // Complete data size including stop bit (byte). Note that |payload_size| excludes the
  // final byte with the stop bit.
  const size_t data_size =
      (nalu_info->payload - nalu_info->hashable_data) + nalu_info->payload_size + 1;
  assert(!nalu_info->nalu_wo_epb);
  nalu_info->nalu_wo_epb = malloc(data_size);
  if (!nalu_info->nalu_wo_epb) {
    DEBUG_LOG("Failed allocating |nalu_wo_epb|, marking NAL Unit with error");
    nalu_info->is_valid = -1;
  } else {
    // Copy everything from the NALU header to stop bit (byte) inclusive, but with the
    // emulation prevention bytes removed.
    const uint8_t *hashable_data_ptr = nalu_info->hashable_data;
    for (size_t i = 0; i < data_size; i++) {
      nalu_info->nalu_wo_epb[i] = read_byte(&last_two_bytes, &hashable_data_ptr, true);
    }
    // Point |tlv_data| to the first byte of the TLV part in |nalu_wo_epb|.
    nalu_info->tlv_data =
        &nalu_info->nalu_wo_epb[data_size - nalu_info->payload_size + UUID_LEN];
    if (!nalu_info->with_epb) {
      // If the SEI was hashed before applying emulation prevention, update
      // |hashable_data|.
      nalu_info->hashable_data = nalu_info->nalu_wo_epb;
      nalu_info->hashable_data_size = data_size;
      nalu_info->tlv_start_in_nalu_data = nalu_info->tlv_data;
    }
  }
}

/**
 * @brief Parses a H.26X NAL Unit data
 *
 * Tries to parse general information about the NAL Unit. Checks if the NAL Unit is valid
 * for signing, i.e., is I, P, or SEI. Convenient information in the NAL Unit info struct
 * such as NAL Unit type, payload size, UUID in case of SEI.
 *
 * Emulation prevention bytes may have been removed and if so, memory has been allocated.
 * The user is responsible for freeing |nalu_wo_epb|.
 */
nalu_info_t
parse_nalu_info(const uint8_t *nalu,
    size_t nalu_size,
    MediaSigningCodec codec,
    bool check_trailing_bytes,
    bool is_validation_side)
{
  uint32_t nalu_header_len = 0;
  nalu_info_t nalu_info = {0};
  // Initialize NALU
  nalu_info.nalu_data = nalu;
  nalu_info.nalu_data_size = nalu_size;
  nalu_info.is_valid = -1;
  nalu_info.is_hashable = false;
  nalu_info.nalu_type = NALU_TYPE_UNDEFINED;
  nalu_info.is_oms_sei = false;
  nalu_info.is_first_nalu_part = true;
  nalu_info.is_last_nalu_part = true;

  if (!nalu || (nalu_size == 0) || codec < 0 || codec >= OMS_CODEC_NUM) {
    return nalu_info;
  }

  // For a Bytestream the nalu_data begins with a Start Code, which is either 3 or 4
  // bytes. That is, look for a 0x000001 or 0x00000001 pattern. For a NAL Unit stream a
  // start code is not necessary. We need to support all three cases.
  const uint32_t kStartCode = 0x00000001;
  uint32_t start_code = 0;
  start_code |= nalu[0] << 24;
  start_code |= nalu[1] << 16;
  start_code |= nalu[2] << 8;
  start_code |= nalu[3] << 0;
  size_t read_bytes = 4;
  // size_t read_bytes = read_32bits(nalu, &start_code);
  bool nalu_header_is_valid = false;

  if (start_code != kStartCode) {
    // Check if this is a 3 byte Start Code.
    read_bytes = 3;
    start_code >>= 8;
    if (start_code != kStartCode) {
      // No Start Code found.
      start_code = 0;
      read_bytes = 0;
    }
  }
  nalu_info.hashable_data = &nalu[read_bytes];
  nalu_info.start_code = start_code;

  if (codec == OMS_CODEC_H264) {
    nalu_header_is_valid = parse_h264_nalu_header(&nalu_info);
    nalu_header_len = H264_NALU_HEADER_LEN;
  } else {
    nalu_header_is_valid = parse_h265_nalu_header(&nalu_info);
    nalu_header_len = H265_NALU_HEADER_LEN;
  }
  // If a correct NALU header could not be parsed, mark as invalid.
  nalu_info.is_valid = nalu_header_is_valid;

  // Only picture NALUs are hashed.
  if (nalu_info.nalu_type == NALU_TYPE_I || nalu_info.nalu_type == NALU_TYPE_P) {
    nalu_info.is_hashable = true;
  }
  nalu_info.is_first_nalu_in_gop =
      (nalu_info.nalu_type == NALU_TYPE_I) && nalu_info.is_primary_slice;

  // It has been noticed that, at least, ffmpeg can add a trailing 0x00 byte at the end of
  // a NAL Unit when exporting to an mp4 container file. This has so far only been
  // observed for H.265. Therefore the hashable part ends at the byte including the stop
  // bit.
  while (check_trailing_bytes && (nalu[nalu_size - 1] == 0x00)) {
    DEBUG_LOG("Found trailing 0x00");
    nalu_size--;
  }
  nalu_info.hashable_data_size = nalu_size - read_bytes;

  // For SEIs the payload and the UUID information is parsed.
  if (nalu_info.nalu_type == NALU_TYPE_SEI) {
    // SEI payload starts after the NAL Unit header.
    const uint8_t *payload = nalu_info.hashable_data + nalu_header_len;
    // Check user_data_unregistered
    uint8_t user_data_unregistered = *payload;
    payload++;
    if (user_data_unregistered == USER_DATA_UNREGISTERED) {
      // Decode payload size and compute emulation prevention bytes
      size_t payload_size = 0;
      size_t read_bytes = get_payload_size(payload, &payload_size);
      payload += read_bytes;
      nalu_info.payload = payload;
      nalu_info.payload_size = payload_size;
      // The payload size, including UUID (16 bytes) and excluding stop bit, is now known.
      // This means that it is possible to determine if any emulation prevention bytes has
      // been added.
      int epb = (int)nalu_info.hashable_data_size;
      epb -= (int)(payload - nalu_info.hashable_data);  // Read bytes so far
      epb -= (int)payload_size;  // The true encoded payload size, excluding stop byte.
      // If the stop bit is in a byte of its own it is not included in the payload size.
      // This is actually always the case for the Media Signing generated SEI data.

      epb -= nalu[nalu_size - 1] == STOP_BYTE_VALUE ? 1 : 0;
      nalu_info.emulation_prevention_bytes = epb;
      DEBUG_LOG("Computed %d emulation prevention byte(s)",
          nalu_info.emulation_prevention_bytes);

      // Decode UUID type and identify Media Signing SEI
      nalu_info.is_oms_sei = is_media_signing_uuid(payload);
    }

    // Only Media Signing generated SEIs are valid and hashable.
    nalu_info.is_hashable = nalu_info.is_oms_sei && is_validation_side;

    remove_epb_from_sei_payload(&nalu_info);
    if (nalu_info.emulation_prevention_bytes >= 0) {
      // Check if a signature TLV tag exists. If number of computed emulation prevention
      // bytes is negative, either the SEI is currupt or incomplete.
      const uint8_t *signature_ptr =
          tlv_find_tag(nalu_info.tlv_data, nalu_info.tlv_size, SIGNATURE_TAG, false);
      nalu_info.is_signed = (signature_ptr != NULL);
      // Update hashable w.r.t. signed or not.
      nalu_info.is_hashable |= !nalu_info.is_signed;
    }
  }

  return nalu_info;
}

/**
 * @brief Copy a H.26X NAL Unit info struct
 *
 * Copies all members, except the pointers from |src_nalu| to |dst_nalu|. All pointers and
 * set to NULL.
 */
void
copy_nalu_except_pointers(nalu_info_t *dst_nalu, const nalu_info_t *src_nalu)
{
  if (!dst_nalu || !src_nalu) {
    return;
  }

  memcpy(dst_nalu, src_nalu, sizeof(nalu_info_t));
  // Set pointers to NULL, since memory is not transfered to next NAL Unit.
  dst_nalu->nalu_data = NULL;
  dst_nalu->hashable_data = NULL;
  dst_nalu->payload = NULL;
  dst_nalu->tlv_start_in_nalu_data = NULL;
  dst_nalu->tlv_data = NULL;
  dst_nalu->nalu_wo_epb = NULL;
}

#if 0
/* Helper function to public APIs */

/* Internal APIs for validation_flags_t functions */

/* Prints the |validation_flags| */
void
validation_flags_print(const validation_flags_t *validation_flags)
{
  if (!validation_flags) return;

  DEBUG_LOG("         has_auth_result: %u", validation_flags->has_auth_result);
  DEBUG_LOG("     is_first_validation: %u", validation_flags->is_first_validation);
  DEBUG_LOG("         signing_present: %u", validation_flags->signing_present);
  DEBUG_LOG("            is_first_sei: %u", validation_flags->is_first_sei);
  DEBUG_LOG("         hash_algo_known: %u", validation_flags->hash_algo_known);
  DEBUG_LOG("");
}

void
validation_flags_init(validation_flags_t *validation_flags)
{
  if (!validation_flags) return;

  memset(validation_flags, 0, sizeof(validation_flags_t));
  validation_flags->is_first_validation = true;
}

void
update_validation_flags(validation_flags_t *validation_flags, nalu_info_t *nalu_info)
{
  if (!validation_flags || !nalu_info) return;

  validation_flags->is_first_sei = !validation_flags->signing_present && nalu_info->is_gop_sei;
  // As soon as we receive a SEI, Signed Video is present.
  validation_flags->signing_present |= nalu_info->is_gop_sei;
}

/* Internal APIs for gop_state_t functions */

/* Prints the |gop_state| */
void
gop_state_print(const gop_state_t *gop_state)
{
  if (!gop_state) return;

  DEBUG_LOG("                 has_sei: %u", gop_state->has_sei);
  DEBUG_LOG("validate_after_next_nalu: %u", gop_state->validate_after_next_nalu);
  DEBUG_LOG("   no_gop_end_before_sei: %u", gop_state->no_gop_end_before_sei);
  DEBUG_LOG("            has_lost_sei: %u", gop_state->has_lost_sei);
  DEBUG_LOG("  gop_transition_is_lost: %u", gop_state->gop_transition_is_lost);
  DEBUG_LOG("");
}

/* Updates the |gop_state| w.r.t. a |nalu_info|.
 *
 * Since auth_state is updated along the way, the only thing we need to update is |has_sei| to
 * know if we have received a signature for this GOP. */
void
gop_state_update(gop_state_t *gop_state, nalu_info_t *nalu_info)
{
  if (!gop_state || !nalu_info) return;

  // If the NALU is not valid nor hashable no action should be taken.
  if (nalu_info->is_valid <= 0 || !nalu_info->is_hashable) return;

  gop_state->has_sei |= nalu_info->is_gop_sei;
}

/* Resets the |gop_state| after validating a GOP. */
void
gop_state_reset(gop_state_t *gop_state)
{
  if (!gop_state) return;

  gop_state->has_lost_sei = false;
  gop_state->gop_transition_is_lost = false;
  gop_state->has_sei = false;
  gop_state->no_gop_end_before_sei = false;
  gop_state->validate_after_next_nalu = false;
}

/* Others */

void
update_num_nalus_in_gop_hash(onvif_media_signing_t *self, const nalu_info_t *nalu_info)
{
  if (!self || !nalu_info) return;

  if (!nalu_info->is_gop_sei) {
    self->gop_info->num_nalus_in_partial_gop++;
    if (self->gop_info->num_nalus_in_partial_gop == 0) {
      DEBUG_LOG("Wraparound in |num_nalus_in_partial_gop|");
      // This will not fail validation, but may produce incorrect statistics.
    }
  }
}

oms_rc
update_gop_hash(void *crypto_handle, gop_info_t *gop_info)
{
  if (!gop_info) return OMS_INVALID_PARAMETER;

  size_t hash_size = openssl_get_hash_size(crypto_handle);
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Update the gop_hash, that is, hash the memory (both hashes) in hash_to_sign = [gop_hash, latest
    // nalu_hash] and replace the gop_hash part with the new hash.
    OMS_THROW(openssl_hash_data(crypto_handle, gop_info->hash_to_sign, 2 * hash_size, gop_info->gop_hash));

#ifdef ONVIF_MEDIA_SIGNING_DEBUG
    printf("Latest NALU hash ");
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", gop_info->nalu_hash[i]);
    }
    printf("\nCurrent gop_hash ");
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", gop_info->gop_hash[i]);
    }
    printf("\n");
#endif
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}
#endif

/* Checks if there is enough room to copy the hash. If so, copies the |nalu_hash| and
 * updates the |list_idx|. Otherwise, sets the |list_idx| to -1 and proceeds. */
static void
check_and_copy_hash_to_hash_list(onvif_media_signing_t *self,
    const uint8_t *hash,
    size_t hash_size)
{
  if (!self || !hash) {
    return;
  }

  uint8_t *hash_list = &self->gop_info->hash_list[0];
  int *list_idx = &self->gop_info->hash_list_idx;
  // Check if there is room for another hash in the |hash_list|.
  if (*list_idx + hash_size > self->gop_info->hash_list_size)
    *list_idx = -1;
  if (*list_idx >= 0) {
    // Copy the |nalu_hash| to |hash_list|.
    memcpy(&hash_list[*list_idx], hash, hash_size);
    *list_idx += hash_size;
  }
}

/* A getter that determines which hash wrapper to use and returns it. */
static hash_wrapper_t
get_hash_wrapper(onvif_media_signing_t *self, const nalu_info_t *nalu_info)
{
  assert(self && nalu_info);

  if (!nalu_info->is_last_nalu_part) {
    // If this is not the last part of a NAL Unit, update the ongoing hash.
    return update_hash;
  } else if (nalu_info->is_oms_sei) {
    // A SEI is hashed without anchor, since that one should be verified separately.
    return simply_hash;
  } else if (nalu_info->is_first_nalu_in_gop && !self->gop_info->has_anchor_hash) {
    // If the current NAL Unit |is_first_nalu_in_gop| and there is not already an anchor,
    // use it as anchor after a |simply_hash|.
    return hash_and_copy_to_anchor;
  } else {
    // All other NAL Units should be hashed together with the anchor.
    return hash_with_anchor;
  }
}

/* Hash wrapper functions */

/* update_hash()
 *
 * takes the |hashable_data| from the NAL Unit, and updates the hash in |crypto_handle|.
 */
static oms_rc
update_hash(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t ATTR_UNUSED *hash,
    size_t ATTR_UNUSED hash_size)
{
  assert(nalu_info);
  const uint8_t *hashable_data = nalu_info->hashable_data;
  size_t hashable_data_size = nalu_info->hashable_data_size;

  return openssl_update_hash(self->crypto_handle, hashable_data, hashable_data_size);
}

/* simply_hash()
 *
 * takes the |hashable_data| from the NAL Unit, hash it and stores the hash in
 * |nalu_hash|. */
static oms_rc
simply_hash(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size)
{
  // It should not be possible to end up here unless the NAL Unit data includes the last
  // part.
  assert(nalu_info && nalu_info->is_last_nalu_part && hash);
  const uint8_t *hashable_data = nalu_info->hashable_data;
  size_t hashable_data_size = nalu_info->hashable_data_size;

  if (nalu_info->is_first_nalu_part) {
    // Entire NAL Unit can be hashed in one part.
    return openssl_hash_data(
        self->crypto_handle, hashable_data, hashable_data_size, hash);
  } else {
    oms_rc status = update_hash(self, nalu_info, hash, hash_size);
    if (status == OMS_OK) {
      // Finalize the ongoing hash of NAL Unit parts.
      status = openssl_finalize_hash(self->crypto_handle, hash);
      // For the first NAL Unit in a GOP, the hash is used twice. Once for linking and
      // once as anchor for the future. Store the |nalu_hash| in |tmp_hash| to be copied
      // for its second use, since it is not possible to recompute the hash from partial
      // NAL Unit data.
      if (status == OMS_OK && nalu_info->is_first_nalu_in_gop &&
          !nalu_info->is_first_nalu_part) {
        memcpy(self->gop_info->tmp_hash, hash, hash_size);
        self->gop_info->tmp_hash_ptr = self->gop_info->tmp_hash;
      }
    }
    return status;
  }
}

/* hash_and_copy_to_anchor()
 *
 * extends simply_hash() by also copying the |hash| to the anchor hash used to
 * hash_with_anchor().
 *
 * This is needed for the first NALU of a GOP, which serves as a anchor. The member
 * variable |has_anchor_hash| is set to true after a successful operation. */
static oms_rc
hash_and_copy_to_anchor(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size)
{
  assert(self && nalu_info && hash);

  gop_info_t *gop_info = self->gop_info;
  // First hash in |hash_buddies| is the |anchor_hash|.
  uint8_t *anchor_hash = &gop_info->hash_buddies[0];

  oms_rc status = OMS_UNKNOWN_FAILURE;
  if (nalu_info->is_first_nalu_in_gop && !nalu_info->is_first_nalu_part &&
      gop_info->tmp_hash_ptr) {
    // If the NAL Unit is split in parts and a hash has already been computed and stored
    // in |tmp_hash|, copy from |tmp_hash| since it is not possible to recompute the hash.
    memcpy(hash, gop_info->tmp_hash_ptr, hash_size);
    status = OMS_OK;
  } else {
    // Hash NAL Unit data and store as |nalu_hash|.
    status = simply_hash(self, nalu_info, hash, hash_size);
  }
  // Copy |anchor_hash| to |linked_hash|.
  memcpy(gop_info->linked_hash, anchor_hash, hash_size);
  // Copy the |nalu_hash| to |anchor_hash| to be used in hash_with_anchor().
  memcpy(anchor_hash, hash, hash_size);
  // Flag a new anchor hash.
  gop_info->has_anchor_hash = true;

  return status;
}

/* hash_with_anchor()
 *
 * Hashes a NAL Units together with an anchor hash. The |hash_buddies| memory is organized
 * to have room for two hashes:
 *   hash_buddies = [anchor_hash, nalu_hash]
 * The output |buddy_hash| is then the hash of this memory
 *   buddy_hash = hash(hash_buddies)
 *
 * This hash wrapper should be used for all NAL Units except the initial one (the anchor).
 */
static oms_rc
hash_with_anchor(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *buddy_hash,
    size_t hash_size)
{
  assert(self && nalu_info && buddy_hash);

  gop_info_t *gop_info = self->gop_info;
  // Second hash in |hash_buddies| is the |nalu_hash|.
  uint8_t *nalu_hash = &gop_info->hash_buddies[hash_size];

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Hash NAL Unit data and store as |nalu_hash|.
    OMS_THROW(simply_hash(self, nalu_info, nalu_hash, hash_size));
    // Hash anchor hash together with the |nalu_hash| and store in |buddy_hash|.
    OMS_THROW(openssl_hash_data(
        self->crypto_handle, gop_info->hash_buddies, hash_size * 2, buddy_hash));
    // Copy |buddy_hash| to |linked_hash| if signing is triggered.
    if (nalu_info->triggered_signing) {
      memcpy(gop_info->linked_hash, buddy_hash, hash_size);
    }
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

oms_rc
hash_and_add(onvif_media_signing_t *self, const nalu_info_t *nalu_info)
{
  if (!self || !nalu_info)
    return OMS_INVALID_PARAMETER;

  if (!nalu_info->is_hashable) {
    DEBUG_LOG("This NAL Unit (type %d) was not hashed", nalu_info->nalu_type);
    return OMS_OK;
  }

  gop_info_t *gop_info = self->gop_info;
  uint8_t *nalu_hash = gop_info->nalu_hash;
  assert(nalu_hash);
  size_t hash_size = self->sign_data->hash_size;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    if (nalu_info->is_first_nalu_part && !nalu_info->is_last_nalu_part) {
      // If this is the first part of a non-complete NAL Unit, initialize the
      // |crypto_handle| to enable sequential update of the hash with more parts.
      OMS_THROW(openssl_init_hash(self->crypto_handle));
    }
    // Select hash function, hash the NAL Unit and store as 'latest hash'
    hash_wrapper_t hash_wrapper = get_hash_wrapper(self, nalu_info);
    OMS_THROW(hash_wrapper(self, nalu_info, nalu_hash, hash_size));
    if (nalu_info->is_last_nalu_part) {
      // The end of the NAL Unit has been reached. Update the hash list.
      check_and_copy_hash_to_hash_list(self, nalu_hash, hash_size);
    }
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
    printf("Hash of %s: ", nalu_type_to_str(nalu_info));
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", nalu_hash[i]);
    }
    printf("\n");
#endif

  OMS_CATCH()
  {
    // If we fail, the |hash_list| is not trustworthy.
    gop_info->hash_list_idx = -1;
  }
  OMS_DONE(status)

  return status;
}

#if 0
oms_rc
hash_and_add_for_auth(onvif_media_signing_t *self, h26x_nalu_list_item_t *item)
{
  if (!self || !item) return OMS_INVALID_PARAMETER;

  const nalu_info_t *nalu_info = item->nalu_info;
  if (!nalu_info) return OMS_INVALID_PARAMETER;

  if (!nalu_info->is_hashable) {
    DEBUG_LOG("This NALU (type %d) was not hashed.", nalu_info->nalu_type);
    return OMS_OK;
  }
  if (!self->validation_flags.hash_algo_known) {
    DEBUG_LOG("NALU will be hashed when hash algo is known.");
    return OMS_OK;
  }

  gop_info_t *gop_info = self->gop_info;
  gop_state_t *gop_state = &self->gop_state;

  uint8_t *nalu_hash = NULL;
  nalu_hash = item->hash;
  assert(nalu_hash);
  size_t hash_size = self->verify_data->hash_size;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    // Select hash wrapper, hash the NALU and store as |nalu_hash|.
    hash_wrapper_t hash_wrapper = get_hash_wrapper(self, nalu_info);
    OMS_THROW(hash_wrapper(self, nalu_info, nalu_hash, hash_size));
    // Check if we have a potential transition to a new GOP. This happens if the current NALU
    // |is_first_nalu_in_gop|. If we have lost the first NALU of a GOP we can still make a guess by
    // checking if |has_sei| flag is set. It is set if the previous hashable NALU was SEI.
    if (nalu_info->is_first_nalu_in_gop || (gop_state->validate_after_next_nalu && !nalu_info->is_gop_sei)) {
      // Updates counters and reset flags.
      gop_info->has_anchor_hash = false;

      // Hash the NALU again, but this time store the hash as a |second_hash|. This is needed since
      // the current NALU belongs to both the ended and the started GOP. Note that we need to get
      // the hash wrapper again since conditions may have changed.
      hash_wrapper = get_hash_wrapper(self, nalu_info);
      free(item->second_hash);
      item->second_hash = malloc(MAX_HASH_SIZE);
      SV_THROW_IF(!item->second_hash, OMS_MEMORY);
      OMS_THROW(hash_wrapper(self, nalu_info, item->second_hash, hash_size));
    }

  OMS_CATCH()
  OMS_DONE(status)

  return status;
}
#endif

/* Public onvif_media_signing_common.h APIs */
onvif_media_signing_t *
onvif_media_signing_create(MediaSigningCodec codec)
{
  DEBUG_LOG("Creating media signing from code version %s", ONVIF_MEDIA_SIGNING_VERSION);
  onvif_media_signing_t *self = NULL;

  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF((codec < 0) || (codec >= OMS_CODEC_NUM), OMS_INVALID_PARAMETER);

    self = calloc(1, sizeof(onvif_media_signing_t));
    OMS_THROW_IF(!self, OMS_MEMORY);

    // Initialize common members
    version_str_to_bytes(self->code_version, ONVIF_MEDIA_SIGNING_VERSION);
    self->codec = codec;

    // Setup crypto handle.
    self->crypto_handle = openssl_create_handle();
    OMS_THROW_IF(!self->crypto_handle, OMS_EXTERNAL_ERROR);

    self->gop_info = gop_info_create();
    OMS_THROW_IF(!self->gop_info, OMS_MEMORY);

    // Initialize signing members
    // Signing plugin is setup when the private key is set.
    self->signing_frequency = 1;
    self->num_gops_until_signing = self->signing_frequency;
    self->sei_epb = false;
    self->signing_started = false;
    self->sign_data = sign_or_verify_data_create();
    self->sign_data->hash_size = openssl_get_hash_size(self->crypto_handle);
    // Make sure the hash size matches the default hash size.
    OMS_THROW_IF(self->sign_data->hash_size != DEFAULT_HASH_SIZE, OMS_EXTERNAL_ERROR);

    self->last_nalu = calloc(1, sizeof(nalu_info_t));
    OMS_THROW_IF(!self->last_nalu, OMS_MEMORY);
    // Mark the last NAL Unit as complete, hence, no ongoing hashing is present.
    self->last_nalu->is_last_nalu_part = true;

    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;

#ifdef VALIDATION_SIDE
    // Initialize validation members
    self->nalu_list = nalu_list_create();
    // No need to check if |nalu_list| is a nullptr, since it is only of importance on the
    // authentication side. The check is done there instead.
    self->authentication_started = false;

    validation_flags_init(&(self->validation_flags));
    gop_state_reset(&(self->gop_state));
    self->has_public_key = false;

    self->verify_data = sign_or_verify_data_create();
    self->verify_data->hash_size = openssl_get_hash_size(self->crypto_handle);
#endif
  OMS_CATCH()
  {
    onvif_media_signing_free(self);
    self = NULL;
  }
  OMS_DONE(status)
  assert(status != OMS_OK ? self == NULL : self != NULL);

  return self;
}

// TODO: Move to oms_signer.c.
/* Frees all payloads in the |sei_data_buffer|. Declared in signed_video_internal.h */
static void
free_sei_data_buffer(sei_data_t sei_data_buffer[])
{
  for (int i = 0; i < MAX_SEI_DATA_BUFFER; i++) {
    free(sei_data_buffer[i].sei);
    sei_data_buffer[i].sei = NULL;
    sei_data_buffer[i].write_position = NULL;
  }
}

void
onvif_media_signing_free(onvif_media_signing_t *self)
{
  DEBUG_LOG("Free media signing %p", self);
  if (!self)
    return;

  // Teardown the plugin before closing.
  onvif_media_signing_plugin_session_teardown(self->plugin_handle);
  // Teardown the crypto handle.
  openssl_free_handle(self->crypto_handle);

  // Free any pending SEIs
  free_sei_data_buffer(self->sei_data_buffer);

  free(self->last_nalu);
#ifdef VALIDATION_SIDE
  h26x_nalu_list_free(self->nalu_list);

  signed_video_authenticity_report_free(self->authenticity);
  sign_or_verify_data_free(self->verify_data);
#endif
  gop_info_free(self->gop_info);
  sign_or_verify_data_free(self->sign_data);
  free(self->certificate_chain.key);

  free(self);
}

MediaSigningReturnCode
onvif_media_signing_reset(onvif_media_signing_t *self)
{
  oms_rc status = OMS_UNKNOWN_FAILURE;
  OMS_TRY()
    OMS_THROW_IF(!self, OMS_INVALID_PARAMETER);
    DEBUG_LOG("Resetting signed session");
    // Reset session states
    self->num_gops_until_signing = self->signing_frequency;
    self->use_golden_sei = false;
    self->signing_started = false;
    gop_info_reset(self->gop_info);
#ifdef VALIDATION_SIDE
    gop_state_reset(&(self->gop_state));
    validation_flags_init(&(self->validation_flags));
    latest_validation_init(self->latest_validation);
    accumulated_validation_init(self->accumulated_validation);
    // Empty the |nalu_list|.
    nalu_list_free_items(self->nalu_list);
#endif
    memset(self->last_nalu, 0, sizeof(nalu_info_t));
    self->last_nalu->is_last_nalu_part = true;
    OMS_THROW(openssl_init_hash(self->crypto_handle));
  OMS_CATCH()
  OMS_DONE(status)

  return status;
}

const char *
onvif_media_signing_get_version()
{
  return ONVIF_MEDIA_SIGNING_VERSION;
}

int
onvif_media_signing_compare_versions(const char *version1, const char *version2)
{
  int status = -1;
  if (!version1 || !version2)
    return status;

  int arr1[OMS_VERSION_BYTES] = {0};
  int arr2[OMS_VERSION_BYTES] = {0};
  if (!version_str_to_bytes(arr1, version1))
    goto error;
  if (!version_str_to_bytes(arr2, version2))
    goto error;

  int result = 0;
  int j = 0;
  while (result == 0 && j < OMS_VERSION_BYTES) {
    result = arr1[j] - arr2[j];
    j++;
  }
  if (result == 0)
    status = 0;  // |version1| equals to |version2|
  if (result > 0)
    status = 1;  // |version1| newer than |version2|
  if (result < 0)
    status = 2;  // |version2| newer than |version1|

error:
  return status;
}

#ifdef PRINT_DECODED_SEI
void
onvif_media_signing_parse_sei(uint8_t *nalu, size_t nalu_size, MediaSigningCodec codec)
{
  if (!nalu || nalu_size == 0) {
    return;
  }
  nalu_info_t nalu_info = parse_nalu_info(nalu, nalu_size, codec, true, true);
  if (nalu_info.is_oms_sei) {
    printf("\nSEI (%zu bytes):\n", nalu_size);
    for (size_t i = 0; i < nalu_size; ++i) {
      printf(" %02x", nalu[i]);
    }
    printf("\n");
    printf("Reserved byte: ");
    for (int i = 7; i >= 0; i--) {
      printf("%u", (nalu_info.reserved_byte & (1 << i)) ? 1 : 0);
    }
    printf("\n");
    onvif_media_signing_t *self = onvif_media_signing_create(codec);
    tlv_decode(self, nalu_info.tlv_data, nalu_info.tlv_size);
    onvif_media_signing_free(self);
  }

  free(nalu_info.nalu_wo_epb);
}
#endif
