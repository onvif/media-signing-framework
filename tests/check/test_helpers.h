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

#ifndef __TEST_HELPERS_H__
#define __TEST_HELPERS_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>  // size_t

#include "lib/src/includes/onvif_media_signing_common.h"  // onvif_media_signing_t, MediaSigningCodec
#include "lib/src/includes/onvif_media_signing_signer.h"
#include "test_stream.h"  // test_stream_t, test_stream_item_t

/* Function pointer typedef for generating private key. */
typedef MediaSigningReturnCode (
    *generate_key_fcn_t)(const char*, char**, size_t*, char**, size_t*);

struct oms_setting {
  MediaSigningCodec codec;
  generate_key_fcn_t generate_key;
};

#define NUM_SETTINGS 2
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
get_initialized_media_signing(MediaSigningCodec codec,
    generate_key_fcn_t generate_key,
    bool new_private_key);

/* See function create_signed_nalus_int */
test_stream_t*
create_signed_nalus(const char* str, struct oms_setting settings);

/* See function create_signed_nalus_int, with the diffrence that each NAL Unit is split in
 * two parts. */
test_stream_t*
create_signed_splitted_nalus(const char* str, struct oms_setting settings);

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

/* Generates a media signing stream of NAL Units for a user-owned onvif_media_signing_t
 * session.
 *
 * Takes a string of NAL Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates NAL Unit data for these. Then adds these NAL Units to the input session. The
 * generated seis are added to the stream. */
test_stream_t*
create_signed_nalus_with_oms(onvif_media_signing_t* oms,
    const char* str,
    bool split_nalus);

/* Removes the NAL Unit item with position |item_number| from the test stream |list|. The
 * item is, after a check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t* list, int item_number, char type);

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t* list, int item_number, char type);

#endif  // __TEST_HELPERS_H__
