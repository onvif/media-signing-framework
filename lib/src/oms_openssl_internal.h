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

#ifndef __OMS_OPENSSL_INTERNAL_H__
#define __OMS_OPENSSL_INTERNAL_H__

#include <assert.h>
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "includes/onvif_media_signing_common.h"

/**
 * Struct for storing necessary information to sign a hash and generate a signature.
 * It is used primarily by the signing plugins.
 */
typedef struct _sign_or_verify_data {
  uint8_t *hash;  // The hash to be signed or to use when verifying the signature.
  size_t hash_size;  // The size of the |hash|.
  void *key;  // The private key used for signing or public key used for verifying.
  uint8_t *signature;  // The signature of the |hash|.
  size_t signature_size;  // The size of the |signature|.
  size_t max_signature_size;  // The allocated size of the |signature|.
} sign_or_verify_data_t;

/**
 * Struct to store a private key in PEM format. Useful to bundle the data in a single
 * object.
 */
typedef struct _pem_pkey_t {
  void *key;  // The private/public key used for signing/verification
  size_t key_size;  // The size of the |key|.
} pem_pkey_t;

/**
 * @brief Signs a hash
 *
 * The function generates a signature of the |hash| in |sign_data| and stores the result
 * in |signature| of |sign_data|.
 *
 * @param sign_data A pointer to the struct that holds all necessary information for
 *   signing.
 *
 * @returns OMS_OK Successfully generated |signature|,
 *          OMS_INVALID_PARAMETER Errors in |sign_data|,
 *          OMS_NOT_SUPPORTED No private key present,
 *          OMS_MEMORY Not enough memory allocated for the |signature|,
 *          OMS_EXTERNAL_ERROR Failure in OpenSSL.
 */
MediaSigningReturnCode
openssl_sign_hash(sign_or_verify_data_t *sign_data);

/**
 * @brief Turns a private key on PEM form to EVP_PKEY form
 *
 * and allocates memory for a signature
 *
 * The function allocates enough memory for a signature given the |private_key|.
 * Use openssl_free_key() to free the key context.
 *
 * @param sign_data A pointer to the struct that holds all necessary information for
 *   signing.
 * @param private_key The content of the private key PEM file.
 * @param private_key_size The size of the |private_key|.
 *
 * @returns OMS_OK Successfully generated |signature|,
 *          OMS_INVALID_PARAMETER Missing inputs,
 *          OMS_MEMORY Failed allocating memory for the |signature|,
 *          OMS_EXTERNAL_ERROR Failure in OpenSSL.
 */
MediaSigningReturnCode
openssl_private_key_malloc(sign_or_verify_data_t *sign_data,
    const char *private_key,
    size_t private_key_size);

/**
 * @brief Frees the memory of a private/public key context
 *
 * The |key| is assumed to be a key on context form.
 *
 * @param key A pointer to the key context which memory to free
 */
void
openssl_free_key(void *key);

#endif  // __OMS_OPENSSL_INTERNAL_H__
