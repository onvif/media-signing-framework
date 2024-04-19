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

#ifndef __ONVIF_MEDIA_SIGNING_PLUGIN_H__
#define __ONVIF_MEDIA_SIGNING_PLUGIN_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "onvif_media_signing_common.h"  // MediaSigningReturnCode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interfaces that need implemented definitions, since these functions are called by the
 * ONVIF Media Signing library for every session.
 */

/**
 * @brief Signs data with a private key
 *
 * This function takes |hash| data and adds it for signing using the private_key provided
 * through onvif_media_signing_plugin_session_setup(...). The ONVIF Media Signing library
 * will call this function when signing a hash.
 *
 * @param handle    A pointer to the handle for the plugin, generated by
 *                  onvif_media_signing_plugin_session_setup(...).
 * @param hash      A pointer to the hash data to be signed.
 * @param hash_size The size of the |hash| to be signed.
 *
 * @returns Should return OMS_OK upon success and an adequate value upon failure.
 */
MediaSigningReturnCode
onvif_media_signing_plugin_sign(void *handle, const uint8_t *hash, size_t hash_size);

/**
 * @brief Gets a signature
 *
 * If there is signed data available, this function should write the signed data to
 * |signature|, and return 'true' when the output has been updated. The ONVIF Media
 * Signing library calls this function repeatedly to collect all available signatures.
 *
 * @param handle                 A pointer to the handle for the plugin, generated by
 *                               onvif_media_signing_plugin_session_setup(...).
 * @param signature              The memory slot to which the signature may be copied. The
 *                               ONVIF Media Signing library is responsible for allocating
 *                               enough space. This should be known a priori since the
 *                               signing algorithm is known when setting the private key.
 * @param max_signature_size     The maximum amount of data that can be written to
 *                               |signature|. If the plugin cannot write all the data to
 *                               |signature|, no data should be written and
 *                               |written_signature_size| should be set to 0. Further, an
 *                               appropriate error code, e.g., OMS_INVALID_PARAMETER
 *                               should be provided.
 * @param written_signature_size The actual size of the data written to |signature|.
 * @param error                  Pointer to catch an error that occured when signing. A
 *                               NULL pointer should be allowed to skip collecting an
 *                               error.
 *
 * @returns 'true' if signature is updated, else 'false'
 */
bool
onvif_media_signing_plugin_get_signature(void *handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    MediaSigningReturnCode *error);

/**
 * @brief Sets up the signing plugin for the current session
 *
 * This function is called by the ONVIF Media Signing session when the user sets the
 * signing key through onvif_media_signing_set_signing_key_pair(...).
 *
 * @param private_key      The content of the private key PEM file.
 * @param private_key_size The size of the |private_key|.
 *
 * @returns A plugin handle needed for further operations.
 */
void *
onvif_media_signing_plugin_session_setup(const void *private_key,
    size_t private_key_size);

/**
 * @brief Tears down the signing plugin for this session
 *
 * This function is called when the ONVIF Media Signing session is terminated.
 *
 * @param handle A pointer to the handle for the plugin, generated by
 *               onvif_media_signing_plugin_session_setup(...).
 */
void
onvif_media_signing_plugin_session_teardown(void *handle);

/**
 * Interfaces that can be used to initialize and close down a plugin. These functions are
 * not called by the ONVIF Media Signing library. They can be used to apply operations
 * prior to starting sessions, e.g., if the same signin plugin is used for all sessions.
 */

/**
 * @brief Plugin initialization
 *
 * This function can/should be called to initialize the signing plugin. Compared to
 * onvif_media_signing_plugin_session_setup(...) this function is not called by the
 * library when creating a session. Therefore, it can be used to handle session
 * independent operations, like setting up a thread, before any session has been created.
 *
 * @param user_data Generic data to provide if needed.
 *
 * @returns 0 upon success
 */
int
onvif_media_signing_plugin_init(void *user_data);

/**
 * @brief Plugin termination
 *
 * This function can/should be called when terminating the plugin. Compared to
 * onvif_media_signing_plugin_session_teardown() this function is not called by the
 * library when closing a session. Therefore, it can be used to handle session independent
 * operations, like terminating a thread, after all sessions have been closed.
 *
 * @param user_data Generic data to provide if needed.
 */
void
onvif_media_signing_plugin_exit(void *user_data);

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_MEDIA_SIGNING_PLUGIN_H__
