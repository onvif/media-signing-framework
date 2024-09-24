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

#ifndef __ONVIF_MEDIA_SIGNING_HELPERS_H__
#define __ONVIF_MEDIA_SIGNING_HELPERS_H__

#include <stdbool.h>
#ifdef PRINT_DECODED_SEI
#include <stdint.h>  // uint8_t
#endif
#include <stdlib.h>  // size_t

#ifdef PRINT_DECODED_SEI
#include "onvif_media_signing_common.h"
#endif

/**
 * @brief Helper function to read test key and certificate
 *
 * Reads either the pre-generated EC, or RSA, private key and certificate. The user can
 * then pass the content to ONVIF Media Signing through
 * onvif_media_signing_set_signing_key_pair().
 * Memory is allocated for |private_key| and the content of |private_key_size| bytes is
 * written. Note that the ownership is transferred. The same holds for the
 * |certificate_chain|.
 * It is feasible to read only the private key or the certificate chain, by setting the
 * other part to NULL.
 *
 * @param ec_key Selects the EC key if true, otherwise the RSA key.
 * @param private_key Memory is allocated and the content of the private key PEM file is
 *   copied to this output. Ownership is transferred.
 * @param private_key_size Outputs the size of the |private_key|.
 * @param certificate_chain Memory is allocated and the content of the public key, wrapped
 *   in a certificate, is copied to this output. Ownership is transferred.
 * @param certificate_chain_size Outputs the size of the |certificate_chain|.
 *
 * @return true upon success, otherwise false.
 */
bool
oms_read_test_private_key_and_certificate(bool ec_key,
    char **private_key,
    size_t *private_key_size,
    char **certificate_chain,
    size_t *certificate_chain_size);

/**
 * @brief Helper function to read trusted test certificate
 *
 * Reads the pre-generated CA certificate. The user can then pass the content to ONVIF
 * Media Signing through onvif_media_signing_set_trusted_certificate().
 * Memory is allocated for |private_key| and the content of |private_key_size| bytes is
 * written. Note that the ownership is transferred.
 * It is feasible to read only the private key or the certificate chain, by setting the
 * other part to NULL.
 *
 * @param certificate Memory is allocated and the content of the trusted certificate is
 *   copied to this output. Ownership is transferred.
 * @param certificate_size Outputs the size of the |certificate|.
 *
 * @return true upon success, otherwise false.
 */
bool
oms_read_test_trusted_certificate(char **certificate, size_t *certificate_size);

#ifdef PRINT_DECODED_SEI
void
onvif_media_signing_parse_sei(uint8_t *nalu, size_t nalu_size, MediaSigningCodec codec);
#endif

#endif  // __ONVIF_MEDIA_SIGNING_HELPERS_H__
