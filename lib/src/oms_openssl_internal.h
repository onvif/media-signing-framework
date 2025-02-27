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

#ifndef __OMS_OPENSSL_INTERNAL_H__
#define __OMS_OPENSSL_INTERNAL_H__

#include <assert.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "includes/onvif_media_signing_common.h"  // MediaSigningReturnCode
#include "oms_defines.h"  // oms_rc

/**
 * Struct for storing necessary information to sign a hash and generate a signature.
 * It is used primarily by the signing plugins.
 */
typedef struct _sign_or_verify_data {
  uint8_t *hash;  // The hash to be signed or to use when verifying the signature.
  size_t hash_size;  // The size of the |hash|.
  void *key;  // The private key used for signing or public key used for verification.
  uint8_t *signature;  // The signature of the |hash|.
  size_t signature_size;  // The size of the |signature|.
  size_t max_signature_size;  // The allocated size of the |signature|.
} sign_or_verify_data_t;

/**
 * Struct to store certificate data, primarily in PEM format.
 */
typedef struct _pem_cert_t {
  void *key;  // The private/public key used for signing/verification
  size_t key_size;  // The size of the |key|.
  bool user_provisioned;
} pem_cert_t;

/**
 * @brief Creates a cryptographic handle
 *
 * Allocates the memory for a crypthographic |handle| holding specific OpenSSL
 * information. This handle should be created when starting the session and freed at
 * teardown with openssl_free_handle().
 *
 * @return Pointer to the OpenSSL cryptographic handle.
 */
void *
openssl_create_handle(void);

/**
 * @brief Frees a cryptographic handle
 *
 * Frees a crypthographic |handle| created with openssl_create_handle().
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 */
void
openssl_free_handle(void *handle);

/**
 * @brief Signs a hash
 *
 * The function generates a signature of the |hash| in |sign_data| and stores the result
 * in |signature| of |sign_data|.
 *
 * @param sign_data A pointer to the struct that holds all necessary information for
 *   signing.
 *
 * @return OMS_OK Successfully generated |signature|,
 *         OMS_INVALID_PARAMETER Errors in |sign_data|,
 *         OMS_MEMORY Not enough memory allocated for the |signature|,
 *         OMS_EXTERNAL_ERROR Failure in OpenSSL.
 */
MediaSigningReturnCode
openssl_sign_hash(sign_or_verify_data_t *sign_data);

/**
 * @brief Verifies a signature against a hash
 *
 * The |hash| is verified against the |signature| using the public |key|, all being
 * members of the input parameter |verify_data|.
 *
 * @param verify_data Pointer to the sign_or_verify_data_t object in use.
 * @param verified_result Pointer to the place where the verification result is written.
 *   The |verified_result| can either be 1 (success), 0 (failure), or < 0 (error).
 *
 * @return OMS_OK Successful with verifying operations.
 *         OMS_INVALID_PARAMETER Errors in |verify_data|, or null pointer inputs,
 */
oms_rc
openssl_verify_hash(const sign_or_verify_data_t *verify_data, int *verified_result);

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
 * @return OMS_OK Successfully stored the private key,
 *         OMS_INVALID_PARAMETER Missing inputs,
 *         OMS_MEMORY Failed allocating memory for the |signature|,
 *         OMS_EXTERNAL_ERROR Failure in OpenSSL.
 */
MediaSigningReturnCode
openssl_store_private_key(sign_or_verify_data_t *sign_data,
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

/**
 * @brief Sets hashing algorithm given by its |name_or_oid|
 *
 * Assigns a hashing algorithm to the |handle|, identified by its |name_or_oid|.
 * If a nullptr is passed in as |name_or_oid|, the default SHA256 is used.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param name_or_oid A null-terminated string defining the hashing algorithm.
 *
 * @return OMS_OK Successfully set hash algorithm,
 *         OMS_INVALID_PARAMETER Null pointer |handle| or invalid |name_or_oid|.
 */
oms_rc
openssl_set_hash_algo(void *handle, const char *name_or_oid);

/**
 * @brief Sets the hashing algorithm given by its OID on ASN.1/DER form
 *
 * Stores the OID of the hashing algorithm on serialized form and determines its type.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param encoded_oid A pointer to the encoded OID of the hashing algorithm.
 * @param encoded_oid_size The size of the encoded OID data.
 *
 * @return OMS_OK Successfully set hash algorithm,
 *         Other appropriate error.
 */
oms_rc
openssl_set_hash_algo_by_encoded_oid(void *handle,
    const unsigned char *encoded_oid,
    size_t encoded_oid_size);

/**
 * @brief Gets hashing algorithm on ASN.1/DER form
 *
 * Returns the hashing algorithm OID on serialized form, that is encoded as ASN.1/DER.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param encoded_oid_size A Pointer to where the size of the encoded OID is written.
 *
 * @return A pointer to the encoded OID of the hashing algorithm,
 *         and a NULL pointer upon failure.
 */
const unsigned char *
openssl_get_hash_algo_encoded_oid(void *handle, size_t *encoded_oid_size);

/**
 * @brief Gets the hash size of the hashing algorithm
 *
 * Returns the hash size of the hashing algorithm and 0 upon failure.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 *
 * @return The size of the hash.
 */
size_t
openssl_get_hash_size(void *handle);

/**
 * @brief Hashes data
 *
 * Uses the hash algorithm set through openssl_set_hash_algo() to hash data. The memory
 * for the |hash| has to be pre-allocated by the user. Use openssl_get_hash_size() to get
 * the hash size.
 *
 * This is a simplification for calling openssl_init_hash(), openssl_update_hash() and
 * openssl_finalize_hash() done in one go.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param data Pointer to the data to hash.
 * @param data_size Size of the |data| to hash.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 *
 * @returns OMS_OK Successfully hashed |data|,
 *          OMS_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *          OMS_EXTERNAL_FAILURE Failed to hash.
 */
oms_rc
openssl_hash_data(void *handle, const uint8_t *data, size_t data_size, uint8_t *hash);

/**
 * @brief Initiates the cryptographic handle for hashing data
 *
 * Uses the OpenSSL API EVP_DigestInit_ex() to initiate an EVP_MD_CTX object in |handle|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param is_primary Select between primary and secondary hash contexts.
 *
 * @returns OMS_OK Successfully initialized EVP_MD_CTX object in |handle|,
 *          OMS_INVALID_PARAMETER Null pointer input,
 *          OMS_EXTERNAL_FAILURE Failed to initialize.
 */
oms_rc
openssl_init_hash(void *handle, bool is_primary);

/**
 * @brief Updates the cryptographic handle with |data| for hashing
 *
 * Uses the OpenSSL API EVP_DigestUpdate() to update the EVP_MD_CTX object in |handle|
 * with |data|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param is_primary Select between primary and secondary hash contexts.
 * @param data Pointer to the data to update an ongoing hash.
 * @param data_size Size of the |data|.
 *
 * @returns OMS_OK Successfully updated EVP_MD_CTX object in |handle|,
 *          OMS_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *          OMS_EXTERNAL_FAILURE Failed to update.
 */
oms_rc
openssl_update_hash(void *handle, bool is_primary, const uint8_t *data, size_t data_size);

/**
 * @brief Finalizes the cryptographic handle and outputs the hash
 *
 * Uses the OpenSSL API EVP_DigestFinal_ex() to finalize the EVP_MD_CTX object in |handle|
 * and get the |hash|. The EVP_MD_CTX object in |handle| is reset afterwards.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param is_primary Select between primary and secondary hash contexts.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 *
 * @return OMS_OK Successfully wrote the final result o |hash|,
 *         OMS_INVALID_PARAMETER Null pointer inputs,
 *         OMS_EXTERNAL_FAILURE Failed to finalize.
 */
oms_rc
openssl_finalize_hash(void *handle, bool is_primary, uint8_t *hash);

/**
 * @brief Helper to turn an encoded OID (in ASN.1/DER form) to a numeric string
 *
 * @param handle
 * @param encoded_oid
 * @param encoded_oid_size
 *
 * @return name as a string
 */
char *
openssl_encoded_oid_to_str(const unsigned char *encoded_oid, size_t encoded_oid_size);

/**
 * @brief Reads the public key from a certificate
 *
 * The function reads the public key from a |certificate| and stores it as |key| in
 * |verify_data| on the EVP_PKEY_CTX form.
 * Use openssl_free_key() to free the key context.
 *
 * @param verify_data A pointer to the struct that holds all necessary information for
 * verifying a signature.
 * @param certificate A pointer to the PEM format struct.
 *
 * @returns OMS_OK Successfully stored |key|,
 *          OMS_INVALID_PARAMETER Missing inputs,
 *          OMS_EXTERNAL_FAILURE Failure in OpenSSL.
 */
oms_rc
openssl_store_public_key(sign_or_verify_data_t *verify_data, pem_cert_t *certificate);

/**
 * @brief Stores a trusted certificate
 *
 * The function reads a trusted certificate and stores it as a X509_STORE object.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param trusted_certificate A pointer to the trusted certificate in PEM format.
 * @param trusted_certificate_size The size of |trusted_certificate|.
 * @param user_provisioned Selects between manufacturer (false) and user (true)
 * provisioned.
 *
 * @return OMS_OK Successfully stored |trusted_certificate|,
 *         OMS_INVALID_PARAMETER Missing inputs,
 *         OMS_NOT_SUPPORTED |trusted_certificate| already set,
 *         OMS_EXTERNAL_FAILURE Failure in OpenSSL.
 */
oms_rc
openssl_set_trusted_certificate(void *handle,
    const char *trusted_certificate,
    size_t trusted_certificate_size,
    bool user_provisioned);

/**
 * @brief Stores a certificate chain
 *
 * The function reads a certificate chain, adds a trusted certificate and verifies the
 * leaf certificate.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param certificate_chain A pointer to the certificate chain in PEM format.
 * @param certificate_chain_size The size of |certificate_chain|.
 * @param user_provisioned Selects between manufacturer (false) and user (true)
 * provisioned.
 *
 * @return OMS_OK Successfully stored |certificate_chain|,
 *         OMS_INVALID_PARAMETER Missing inputs,
 *         OMS_EXTERNAL_FAILURE Failure in OpenSSL.
 */
oms_rc
openssl_verify_certificate_chain(void *handle,
    const char *certificate_chain,
    size_t certificate_chain_size,
    bool user_provisioned);

/**
 * @brief Gets the latest leaf certificate verification
 *
 * The leaf certificate includes the public key needed for validating the authenticity of
 * the stream. This leaf certificate needs to be verified against a root (trusted)
 * certificate to prove provenance.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param user_provisioned Selects between manufacturer (false) and user (true)
 * provisioned.
 *
 * @return Success (1), unsuccessful (0), error (-1).
 */
int
openssl_get_pubkey_verification(void *handle, bool user_provisioned);

/**
 * @brief Checks if a trusted certificate has been set
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param user_provisioned Selects between manufacturer (false) and user (true)
 * provisioned.
 *
 * @return Trusted certificate exists (true), otherwise (false).
 */
bool
openssl_has_trusted_certificate(void *handle, bool user_provisioned);

#endif  // __OMS_OPENSSL_INTERNAL_H__
