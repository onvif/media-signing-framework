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
