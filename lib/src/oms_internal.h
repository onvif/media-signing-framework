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

#ifndef __OMS_INTERNAL_H__
#define __OMS_INTERNAL_H__

#include <stdbool.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "includes/onvif_media_signing_common.h"  // MediaSigningReturnCode, onvif_media_signing_product_info_t
#include "includes/onvif_media_signing_validator.h"
#include "oms_defines.h"
#include "oms_openssl_internal.h"  // pem_cert_t, sign_or_verify_data_t

extern const uint8_t kUuidMediaSigning[UUID_LEN];

typedef struct _nalu_list_item_t nalu_list_item_t;

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
  bool is_certificate_sei;
  bool is_signed;  // True if the SEI is signed, i.e., has a signature
} nalu_info_t;

/**
 * A struct representing a NAL Unit in a stream. The stream being a linked list. Each item
 * holds the NAL Unit data as well as pointers to the previous and next items in the list.
 */
struct _nalu_list_item_t {
  nalu_info_t *nalu_info;  // The parsed NAL Unit information.
  char validation_status;  // The authentication status which can take on the following
  // characters:
  // 'P' : Pending validation. This is the initial value. The NAL Unit has been registered
  //       and waiting for validating the authenticity.
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
  bool validate_certificate_sei;  // Certificate SEIs should be validated stand alone.
  bool waiting_for_signature;  // Validating a GOP with a SEI without signature.
  bool sei_in_sync;  // The SEIs are correctly associated with a (partial) GOP
  int num_lost_seis;  // Detected lost SEIs, based on partial GOP counter.
  int num_invalid_nalus;  // Tracks invalid GOPs across multiple GOP validation
  int num_gop_starts;  // Counts I-frames for use when validating unsigned streams, or
                       // when the first SEI arrives late. This prevents storage of NAL
                       // Unit data to grow indefinitely.
  bool lost_start_of_gop;  // Tracks if a an I-frame has been lost, which needs to be
                           // handled as a special case if it happens for the first
                           // validation.
} validation_flags_t;

// Buffer of |last_two_bytes| and pointers to |sei| memory and current |write_position|.
// Writing of the SEI is split in time and it is therefore necessary to pick up the value
// of |last_two_bytes| when we continue writing with emulation prevention turned on. As
// soon as a SEI is completed, the |completed_sei_size| is filled in.
typedef struct _sei_data_t {
  uint8_t *sei;  // Pointer to the allocated SEI data
  uint8_t *write_position;
  uint16_t last_two_bytes;
  size_t completed_sei_size;  // The final SEI size, set when it is completed
} sei_data_t;

/**
 * Information related to the GOP signature.
 */
typedef struct _gop_info_t {
  uint8_t hash_buddies[2 * MAX_HASH_SIZE];  // Two hashes: [anchor_hash, nalu_hash].
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
  uint16_t num_frames_in_partial_gop;  // Counted number of frames in the current partial
                                       // GOP.
  int64_t current_partial_gop;  // The index of the current partial GOP (current SEI).
  uint32_t next_partial_gop;  // The index of the next partial GOP (when decoding SEI).
  uint32_t num_partial_gop_wraparounds;  // Tracks number of times the |next_partial_gop|
                                         // has been wrapped around.

  bool triggered_partial_gop;  // Marks if the signing was triggered by an intermediate
                               // partial GOP, compared to normal I-frame triggered.
  bool global_gop_counter_is_synced;  // Turns true when a SEI corresponding to the
                                      // segment is detected.
  int verified_signature;  // Status of last hash-signature-pair verification. Has 1 for
                           // success, 0 for fail, and -1 for error.
  int64_t timestamp;  // Unix epoch UTC timestamp of the first nalu in GOP
} gop_info_t;

struct _onvif_media_signing_t {
  // Members common to both signing and validation
  int code_version[OMS_VERSION_BYTES];
  MediaSigningCodec codec;  // Codec used in this session.
  onvif_media_signing_vendor_info_t vendor_info;

  // For cryptographic functions, like OpenSSL
  void *crypto_handle;
  pem_cert_t certificate_chain;  // Using the pem_cert_t struct to store certificate chain
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
  unsigned max_signing_frames;  // Max number of NAL Units per signature (default 0, i.e.,
                                // no limit)

  // Flags
  bool sei_epb;  // Flag that tells whether to generate SEI frames w/wo emulation
                 // prevention bytes
  bool is_certificate_sei;  // Flag that tells if a SEI is a certificate SEI
  bool use_certificate_sei;  // If enabled, the session uses the certificate SEI concept
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
};

/* Definitions in oms_common.c. */
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

nalu_info_t
parse_nalu_info(const uint8_t *nalu,
    size_t nalu_size,
    MediaSigningCodec codec,
    bool check_trailing_bytes,
    bool is_validation_side);
void
copy_nalu_except_pointers(nalu_info_t *dst_nalu, const nalu_info_t *src_nalu);

void
bytes_to_version_str(const int *arr, char *str);

size_t
get_untrusted_certificates_size(const char *certificate_chain,
    size_t certificate_chain_size);

#ifdef ONVIF_MEDIA_SIGNING_DEBUG
char *
nalu_type_to_str(const nalu_info_t *nalu);
oms_rc
simply_hash(onvif_media_signing_t *self,
    const nalu_info_t *nalu_info,
    uint8_t *hash,
    size_t hash_size);
#endif
#if defined(ONVIF_MEDIA_SIGNING_DEBUG) || defined(PRINT_DECODED_SEI)
void
oms_print_hex_data(const uint8_t *data, size_t data_size, const char *fmt, ...);
#endif

/* Definitions in oms_validator.c. */
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
void
update_hashable_data(nalu_info_t *nalu_info);
#endif

#endif  // __OMS_INTERNAL_H__
