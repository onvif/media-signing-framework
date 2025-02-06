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

#ifndef __TEST_HELPERS_H__
#define __TEST_HELPERS_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>  // size_t

#include "lib/src/includes/onvif_media_signing_common.h"  // onvif_media_signing_t, MediaSigningCodec
#include "lib/src/includes/onvif_media_signing_signer.h"
#include "test_stream.h"  // test_stream_t, test_stream_item_t

#define FW_VER "firmware_version"
#define SER_NO "serial_no"
#define MANUFACT "manufacturer"

struct oms_setting {
  MediaSigningCodec codec;
  bool ec_key;
  const char* hash_algo;
  bool low_bitrate_mode;
  bool ep_before_signing;
  size_t max_sei_payload_size;
  bool with_certificate_sei;
  unsigned max_signing_frames;
  unsigned signing_frequency;
  int delay;
  bool get_seis_at_end;
  bool force_no_ep;
};

#define NUM_SETTINGS 10
extern struct oms_setting settings[NUM_SETTINGS];

extern const int64_t g_testTimestamp;

/* Creates a onvif_media_signing_t session and initialize it by setting
 * 1. a private key
 * 2. product info strings
 *
 * new_private_key = Generate a new private key, otherwise read from an existing file.
 * This is useful for testing the signing part and generating a signed stream of NAL
 * Units. */
onvif_media_signing_t*
get_initialized_media_signing(MediaSigningCodec codec, bool ec_key, bool new_private_key);
onvif_media_signing_t*
get_initialized_media_signing_by_setting(struct oms_setting setting,
    bool new_private_key);

/* See function create_signed_nalus_int */
test_stream_t*
create_signed_nalus(const char* str, struct oms_setting setting);

/* See function create_signed_nalus_int, with the diffrence that each NAL Unit is split in
 * two parts. */
test_stream_t*
create_signed_splitted_nalus(const char* str, struct oms_setting setting);

/* Creates a test_stream_t with all the NAL Units produced after signing. This mimic what
 * leaves the camera.
 *
 * The input is a string of characters representing the type of NAL Units passed into the
 * signing session.
 * Example-1: 'IPPIPP' will push two identical GOPs
 *   I-nalu, P-nalu, P-nalu.
 * Example-2: for multi slice, 'IiPpPpIiPpPp' will push two identical GOPs
 *   I-nalu, i-nalu, P-nalu, p-nalu, P-nalu, p-nalu.
 * Valid characters are:
 *   I: I-nalu Indicates first slice in the current I nalu
 *   i: i-nalu Indicates other than first slice. Example: second and third slice
 *   P: P-nalu Indicates first slice in the current P nalu
 *   p: p-nalu Indicates other than first slice. Example: second and third slice
 *   S: Non signed-video-framework SEI
 *   X: Invalid nalu, i.e., not a H.26x nalu.
 *
 * settings = the session setup for this test.
 * new_private_key = Generate a new private key or not.
 */
test_stream_t*
create_signed_nalus_int(const char* str,
    struct oms_setting settings,
    bool new_private_key);

/* Removes the NAL Unit item with position |item_number| from the test stream |list|. The
 * item is, after a check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t* list, int item_number, char type);

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t* list, int item_number, char type);

/* Checks the TLV data for optional tags. Returns true if any optional tag is present. */
bool
tlv_has_optional_tags(const uint8_t* tlv_data, size_t tlv_data_size);

/* Checks the TLV data for mandatory tags. Returns true if any mandatory tag is
 * present. */
bool
tlv_has_mandatory_tags(const uint8_t* tlv_data, size_t tlv_data_size);

/* Reads and sets a trusted certificate. */
bool
test_helper_set_trusted_certificate(onvif_media_signing_t* oms);

#endif  // __TEST_HELPERS_H__
