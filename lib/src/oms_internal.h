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

#ifndef __OMS_INTERNAL_H__
#define __OMS_INTERNAL_H__

#include <stdbool.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "includes/onvif_media_signing_common.h"  // MediaSigningReturnCode, onvif_media_signing_product_info_t
#include "includes/onvif_media_signing_validator.h"
#include "oms_defines.h"  // oms_rc
#include "oms_openssl_internal.h"  // pem_pkey_t, sign_or_verify_data_t

typedef struct _gop_info_t gop_info_t;
typedef struct _sei_data_t sei_data_t;
typedef struct _nalu_list_item_t nalu_list_item_t;
// typedef struct _validation_flags_t validation_flags_t;
#ifdef VALIDATION_SIDE
typedef struct _gop_state_t gop_state_t;
#endif
// Forward declare nalu_list_t here for onvif_media_signing_t.
// typedef struct _nalu_list_t nalu_list_t;

#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif

#define OMS_VERSION_BYTES 3
#define ONVIF_MEDIA_SIGNING_VERSION "v0.0.4"
#define OMS_VERSION_MAX_STRLEN 13  // Longest possible string

#define DEFAULT_MAX_GOP_LENGTH 300

// Maximum number of ongoing and completed SEIs to hold until the user fetches them
#define MAX_SEI_DATA_BUFFER 60
#define UUID_LEN 16
#define LAST_TWO_BYTES_INIT_VALUE 0x0101  // Anything but 0x00 are proper init values
#define STOP_BYTE_VALUE 0x80
extern const uint8_t kUuidMediaSigning[UUID_LEN];

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/* Compile time defined, otherwise set default value */
#ifndef MAX_GOP_LENGTH
#define MAX_GOP_LENGTH DEFAULT_MAX_GOP_LENGTH
#endif

// Currently the largest supported hash is SHA-512.
#define MAX_HASH_SIZE (512 / 8)
// Size of the default hash (SHA-256).
#define DEFAULT_HASH_SIZE (256 / 8)
#define HASH_LIST_SIZE (MAX_HASH_SIZE * MAX_GOP_LENGTH)

typedef enum {
  NALU_TYPE_UNDEFINED = 0,
  NALU_TYPE_SEI = 1,
  NALU_TYPE_I = 2,
  NALU_TYPE_P = 3,  // P- & B-frames
  NALU_TYPE_PS = 4,  // Parameter Set: PPS/SPS/VPS
  NALU_TYPE_AUD = 5,
  NALU_TYPE_OTHER = 6,
} MediaSigningFrameType;

/**
 * Information of a H.26X NAL Unit.
 * This struct stores all necessary information of the H.26X NAL Unit, such as, pointer to
 * the NAL Unit data, NAL Unit data size, pointer to the hashable data and size. Further,
 * includes information on NAL Unit type, UUID type (if any) and if the NAL Unit is valid
 * for use/hashing. Also short-cuts to the TLV part of a SEI and parsed flags are also
 * present.
 */
typedef struct _nalu_t {
  const uint8_t *nalu_data;  // The actual NAL Unit data
  size_t nalu_data_size;  // The total size of the NAL Unit data
  const uint8_t *hashable_data;  // The part of the NAL Unit data hashing
  size_t hashable_data_size;  // Size of the data to hash, excluding stop bit
  uint8_t *pending_hashable_data;  // The NAL Unit data for later hashing
  MediaSigningFrameType nalu_type;  // Frame type: I, P, SPS, PPS, VPS or SEI
  int is_valid;  // Is a valid H.26X NAL Unit (1), invalid (0) or has errors (-1)
  bool is_hashable;  // Should be hashed
  const uint8_t *payload;  // Points to the payload (including UUID for SEIs)
  size_t payload_size;  // Parsed payload size
  uint8_t reserved_byte;  // First byte of SEI payload
  const uint8_t
      *tlv_start_in_nalu_data;  // Points to beginning of the TLV data in the |nalu_data|
  const uint8_t
      *tlv_data;  // Points to the TLV data after removing emulation prevention bytes
  size_t tlv_size;  // Total size of the |tlv_data|
  uint8_t *nalu_wo_epb;  // Temporary memory used if there are emulation prevention
                         // bytes. Note this memory has to be freed after usage.
  uint32_t start_code;  // Start code or replaced by NAL Unit data size
  int emulation_prevention_bytes;  // Computed emulation prevention bytes
  bool is_primary_slice;  // The first slice in the NAL Unit or not
  bool is_first_nalu_in_gop;  // True for the first slice of an I-frame
  bool is_oms_sei;  // True if this is an ONVIF Media Signing generated SEI
  bool is_first_nalu_part;  // True if the |nalu_data| includes the first part
  bool is_last_nalu_part;  // True if the |nalu_data| includes the last part
  bool with_epb;  // Hashable data may include emulation prevention bytes
  bool is_golden_sei;
  bool triggered_signing;  // True if GOP is long enough to trigger an intermediate SEI
  bool is_signed;  // True if the SEI is signed, i.e., has a signature
} nalu_info_t;

/**
 * A struct representing the stream of NAL Units, added to Media Signing for validating
 * authenticity. It is a linked list of nalu_list_item_t and holds the first and last
 * items. The list is linear, that is, one parent and one child only.
 */
typedef struct _nalu_list_t {
  nalu_list_item_t *first_item;  // Points to the first item in the linked list, that is,
                                 // the oldest NAL Unit added for validation.
  nalu_list_item_t *last_item;  // Points to the last item in the linked list, that is,
                                // the latest NAL Unit added for validation.
  int num_items;  // The number of items linked together in the list.
} nalu_list_t;

/**
 * A struct representing a NAL Unit in a stream. The stream being a linked list. Each item
 * holds the NAL Unit data as well as pointers to the previous and next items in the list.
 */
struct _nalu_list_item_t {
  nalu_info_t *nalu_info;  // The parsed NAL Unit information.
  char validation_status;  // The authentication status which can take on the following
  // characters:
  // 'P' : Pending validation. This is the initial value. The NALU has been registered and
  //       waiting for validating the authenticity.
  // 'U' : The NAL Unit has an unknown authenticity. This occurs if the NAL Unit could not
  //       be parsed, or ifthe SEI is associated with NAL Units not part of the validating
  //       segment.
  // '_' : The NAL Unit is ignored and therefore not part of the signature. The NAL Unit
  //       has no impact on the video and can be considered authentic.
  // '.' : The NAL Unit has been validated authentic.
  // 'N' : The NAL Unit has been validated not authentic.
  // 'M' : The validation has detected one or more missing NAL Units at this position.
  //       Note that changing the order of NAL Units will detect a missing NAL Unit and an
  //       invalid NAL Unit.
  // 'E' : An error occurred and validation could not be performed. This should be treated
  //       as an invalid NAL Unit.
  char validation_status_if_sei_ok;
  uint8_t hash[MAX_HASH_SIZE];  // The hash of the NAL Unit is stored in this memory slot,
  // if it is hashable that is.
#if 0
  size_t hash_size;
  // Flags
  bool taken_ownership_of_nalu;  // Flag to indicate if the item has taken ownership of the |nalu|
  // memory, hence need to free the memory if the item is released.
  bool need_second_verification;  // This NALU need another verification, either due to failures or
  // because it is a chained hash, that is, used in two GOPs. The second verification is done with
  // |second_hash|.
  bool first_verification_not_authentic;  // Marks the NALU as not authentic so the second one does
  // not overwrite with an acceptable status.
#endif
  const nalu_list_item_t *associated_sei;  // Which SEI this item is associated with.
  bool has_been_decoded;  // Marks a SEI as decoded. Decoding it twice might overwrite
  // vital information.
  int verified_signature;

  // Linked list
  nalu_list_item_t *prev;  // Points to the previously added NAL Unit. Is NULL if this is
  // the first item.
  nalu_list_item_t *next;  // Points to the next added NAL Unit. Is NULL if this is the
  // last item.
};

typedef struct _validation_flags_t {
  bool has_auth_result;  // Indicates that an authenticity result is available for the
                         // user.
  bool is_first_validation;  // Indicates if this is the first validation. If so, a
                             // failing validation result is not necessarily true, since
                             // the framework may be out of sync, e.g., after exporting to
                             // a file.
  bool reset_first_validation;  // Indicates if this a second attempt of a first
                                // validation should be performed. Hence, flag a reset.
  bool signing_present;  // Indicates if ONVIF Media Signing is present or not. It is only
                         // possible to move from false to true unless a reset is
                         // performed.
  bool is_first_sei;  // Indicates that this is the first received SEI.
  bool hash_algo_known;  // Information on what hash algorithm to use has been received.
  bool validate_golden_sei;  // Golden SEIs should be validated stand alone.
  bool waiting_for_signature;  // Validating a GOP with a SEI without signature.
} validation_flags_t;

#ifdef VALIDATION_SIDE
struct _gop_state_t {
  bool has_sei;  // The GOP includes a SEI.
  bool has_lost_sei;  // Has detected a lost SEI since last validation.
  bool no_gop_end_before_sei;  // No GOP end (I-frame) has been found before the SEI.
  bool gop_transition_is_lost;  // The transition between GOPs has been lost. This can be
                                // detected if a lost SEI is detected, and at the same
                                // time waiting for an 'I'. An example when this happens
                                // is if an entire AU is lost including both the SEI and
                                // the 'I'.
};
#endif

// Buffer of |last_two_bytes| and pointers to |sei| memory and current |write_position|.
// Writing of the SEI is split in time and it is therefore necessary to pick up the value
// of |last_two_bytes| when we continue writing with emulation prevention turned on. As
// soon as a SEI is completed, the |completed_sei_size| is filled in.
struct _sei_data_t {
  uint8_t *sei;  // Pointer to the allocated SEI data
  uint8_t *write_position;
  uint16_t last_two_bytes;
  size_t completed_sei_size;  // The final SEI size, set when it is completed
};

struct _onvif_media_signing_t {
  // Members common to both signing and validation
  int code_version[OMS_VERSION_BYTES];
  MediaSigningCodec codec;  // Codec used in this session.
  onvif_media_signing_vendor_info_t vendor_info;

  // For cryptographic functions, like OpenSSL
  void *crypto_handle;
  pem_pkey_t certificate_chain;  // Using the pem_pkey_t struct to store certificate chain
  gop_info_t *gop_info;

  // Arbitrary data
  uint8_t *arbitrary_data;  // Enables the user to transmit user specific data and is
                            // automatically
  // sent through the ARBITRARY_DATA_TAG.
  size_t arbitrary_data_size;  // Size of |arbitrary_data|.

  // Members only used for signing

  // Configuration members
  size_t max_sei_payload_size;  // Default 0 = unlimited
  unsigned signing_frequency;  // Number of GOPs per signature (default 1)
  unsigned num_gops_until_signing;  // Counter to track |signing_frequency|
  unsigned max_signing_nalus;  // Max number of NAL Units per signature (default 0, i.e.,
                               // no limit)

  // Flags
  bool sei_epb;  // Flag that tells whether to generate SEI frames w/wo emulation
                 // prevention bytes
  bool is_golden_sei;  // Flag that tells if a SEI is a golden SEI
  bool use_golden_sei;  // If enabled, the session uses the golden SEI concept
  bool low_bitrate_mode;  // If enabled, the session will not send the hash list
  bool signing_started;

  // For signing plugin
  void *plugin_handle;
  sign_or_verify_data_t *sign_data;  // All necessary information to sign in a plugin.

  nalu_info_t *last_nalu;  // Track last parsed nalu_info_t to pass on to next part

  // Members associated with SEI writing
  uint16_t last_two_bytes;
  sei_data_t sei_data_buffer[MAX_SEI_DATA_BUFFER];
  int sei_data_buffer_idx;

  // Members only used for validation

  // TODO: Collect everything needed by the authentication part only in one struct/object,
  // which then is not needed to be created on the signing side, saving some memory.

  // Shortcuts to authenticity information.
  // If no authenticity report has been set by the user the memory is allocated and used
  // locally. Otherwise, these members point to the corresponding members in
  // |authenticity| below.
  onvif_media_signing_latest_validation_t *latest_validation;
  onvif_media_signing_accumulated_validation_t *accumulated_validation;
  onvif_media_signing_authenticity_t *authenticity;  // Pointer to the authenticity report
                                                     // of which results will be written.
  // Status and authentication
  // Linked list to track the validation status of each added NAL Unit. Items are appended
  // to the list when added, that is, in onvif_media_signing_add_nalu_and_authenticate().
  // Items are removed when reported through the authenticity_report.
  nalu_list_t *nalu_list;
  bool authentication_started;
  validation_flags_t validation_flags;
  sign_or_verify_data_t *verify_data;  // All necessary information to verify a signature.
  int verified_pubkey;  // Result after verification of the certificate chain.
  bool has_public_key;  // State to indicate if public key is received/added
  uint8_t
      tmp_partial_gop_hash[MAX_HASH_SIZE];  // Memory for storing a (partial) GOP hash.
  uint8_t tmp_linked_hash[MAX_HASH_SIZE];  // Memory for storing a linked hash.
  uint16_t tmp_num_nalus_in_partial_gop;  // Counted number of NAL Units in the currently
                                          // recursively updated |gop_hash|.

#ifdef VALIDATION_SIDE
  // Members only used for validation
  // TODO: Collect everything needed by the authentication part only in one struct/object,
  // which then is not needed to be created on the signing side, saving some memory.

  gop_state_t gop_state;
  // For signature verification
  pem_pkey_t pem_public_key;  // Public key in PEM form for writing/reading to/from SEIs

#endif
};

/**
 * Information related to the GOP signature.
 * The |gop_hash| is a recursive hash. It is the hash of the memory [gop_hash, latest
 * hash] and then replaces the gop_hash location. This is used for signing, as it
 * incorporates all information of the nalus that has been added.
 */
struct _gop_info_t {
  uint8_t hash_buddies[2 *
      MAX_HASH_SIZE];  // Memory for two hashes organized as [anchor_hash, nalu_hash].
  bool has_anchor_hash;  // Flags if the anchor hash in |hash_buddies| is valid.
  uint8_t hash_list[HASH_LIST_SIZE];  // Pointer to the list of hashes
  size_t hash_list_size;  // The allowed size of the |hash_list|. This can be less than
                          // allocated.
  int hash_list_idx;  // Pointing to next available slot in the |hash_list|. If something
                      // has gone wrong, like exceeding available memory, |list_idx| = -1.
  uint8_t *nalu_hash;  // Pointing to the NAL Unit hash in |hash_to_sign|.
  uint8_t hash_to_sign[MAX_HASH_SIZE];  // Memory for storing the hash to be signed
  uint8_t tmp_hash[MAX_HASH_SIZE];  // Memory for storing a temporary hash needed when a
                                    // NAL Unit split in parts.
  uint8_t partial_gop_hash[MAX_HASH_SIZE];  // Memory for storing a (partial) GOP hash.
  uint8_t linked_hash[2 * MAX_HASH_SIZE];  // Memory for storing a linked hash and pending
                                           // linked hash.
  uint8_t encoding_status;  // Stores potential errors when encoding, to transmit to the
                            // client (authentication part).
  uint16_t num_sent_nalus;  // The number of NAL Units used to generate the gop_hash on
                            // the signing side.
  uint16_t num_nalus_in_partial_gop;  // Counted number of NAL Units in the currently
                                      // recursively updated |gop_hash|.
  uint32_t current_partial_gop;  // The index of the current partial GOP (current SEI).

  bool global_gop_counter_is_synced;  // Turns true when a SEI corresponding to the
                                      // segment is detected.
  int verified_signature;  // Status of last hash-signature-pair verification. Has 1 for
                           // success, 0 for fail, and -1 for error.
  int64_t timestamp;  // Unix epoch UTC timestamp of the first nalu in GOP
};

nalu_info_t
parse_nalu_info(const uint8_t *nalu,
    size_t nalu_size,
    MediaSigningCodec codec,
    bool check_trailing_bytes,
    bool is_validation_side);

void
copy_nalu_except_pointers(nalu_info_t *dst_nalu, const nalu_info_t *src_nalu);

oms_rc
hash_and_add(onvif_media_signing_t *self, const nalu_info_t *nalu_info);

oms_rc
hash_and_add_for_validation(onvif_media_signing_t *self, nalu_list_item_t *item);

oms_rc
reset_gop_hash(onvif_media_signing_t *self);
oms_rc
update_gop_hash(void *crypto_handle, const uint8_t *nalu_hash);
oms_rc
finalize_gop_hash(void *crypto_handle, uint8_t *gop_hash);

void
update_linked_hash(onvif_media_signing_t *self,
    const uint8_t *nalu_hash,
    size_t hash_size);

void
update_validation_flags(validation_flags_t *validation_flags, nalu_info_t *nalu_info);

void
bytes_to_version_str(const int *arr, char *str);
char *
nalu_type_to_str(const nalu_info_t *nalu);
char
nalu_type_to_char(const nalu_info_t *nalu_info);

#ifdef ONVIF_MEDIA_SIGNING_DEBUG
oms_rc
simply_hash(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size);
void
update_hashable_data(nalu_info_t *nalu_info);
#endif

#if 0
/* Sets the allowed size of |hash_list|.
 * Note that this can be different from what is allocated. */
oms_rc
set_hash_list_size(gop_info_t *gop_info, size_t hash_list_size);

/* Defined in oms_signer.c */
/* Frees all allocated memory of payload pointers in the SEI data buffer. */
void
free_sei_data_buffer(sei_data_t sei_data_buffer[]);
#endif

#endif  // __OMS_INTERNAL_H__
