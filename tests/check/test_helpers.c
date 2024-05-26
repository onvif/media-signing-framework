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

#include "test_helpers.h"

#include <assert.h>  // assert
#include <check.h>

#include "lib/src/includes/onvif_media_signing_helpers.h"

#define RSA_PRIVATE_KEY_ALLOC_BYTES 2000
#define ECDSA_PRIVATE_KEY_ALLOC_BYTES 1000

const int64_t g_testTimestamp = 42;

struct oms_setting settings[NUM_SETTINGS] = {
    {OMS_CODEC_H264, oms_generate_ecdsa_private_key, NULL},
    {OMS_CODEC_H265, oms_generate_ecdsa_private_key, NULL},
    // Special cases
    {OMS_CODEC_H264, oms_generate_ecdsa_private_key, "sha512"},
};

onvif_media_signing_t*
get_initialized_media_signing(MediaSigningCodec __attribute__((unused)) codec,
    generate_key_fcn_t __attribute__((unused)) generate_key,
    bool __attribute__((unused)) new_private_key)
{
  return NULL;
}

/* See function create_signed_nalus_int */
test_stream_t*
create_signed_nalus(const char __attribute__((unused)) * str,
    struct oms_setting __attribute__((unused)) settings)
{
  return NULL;
}

/* See function create_signed_nalus_int, with the diffrence that each NAL Unit is split in
 * two parts. */
test_stream_t*
create_signed_splitted_nalus(const char __attribute__((unused)) * str,
    struct oms_setting __attribute__((unused)) settings)
{
  return NULL;
}

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
create_signed_nalus_int(const char __attribute__((unused)) * str,
    struct oms_setting __attribute__((unused)) settings,
    bool __attribute__((unused)) new_private_key)
{
  return NULL;
}

/* Generates a media signing stream of NAL Units for a user-owned onvif_media_signing_t
 * session.
 *
 * Takes a string of NAL Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates NAL Unit data for these. Then adds these NAL Units to the input session. The
 * generated seis are added to the stream. */
test_stream_t*
create_signed_nalus_with_oms(onvif_media_signing_t __attribute__((unused)) * oms,
    const char __attribute__((unused)) * str,
    bool __attribute__((unused)) split_nalus)
{
  return NULL;
}

/* Removes the NAL Unit item with position |item_number| from the test stream |list|. The
 * item is, after a check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t __attribute__((unused)) * list,
    int __attribute__((unused)) item_number,
    char __attribute__((unused)) type)
{
}

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t __attribute__((unused)) * list,
    int __attribute__((unused)) item_number,
    char __attribute__((unused)) type)
{
}
