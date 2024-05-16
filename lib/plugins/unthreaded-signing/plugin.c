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

/**
 * This signing plugin calls openssl_sign_hash() and stores the generated signature before
 * return. This signature is then copied to the user when
 * onvif_media_signing_plugin_get_signature().
 */
#include <stdlib.h>  // calloc, memcpy

#include "includes/onvif_media_signing_plugin.h"
#include "oms_openssl_internal.h"

#ifndef ATTR_UNUSED
#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
#endif

// Plugin handle to store the signature, etc.
typedef struct _oms_unthreaded_plugin_t {
  bool signature_generated;
  sign_or_verify_data_t sign_data;
} oms_unthreaded_plugin_t;

static MediaSigningReturnCode
unthreaded_sign_hash(oms_unthreaded_plugin_t *self, const uint8_t *hash, size_t hash_size)
{
  // If the generated signature has not been pulled a new signature cannot be generated
  // without being overwritten.
  if (self->signature_generated) return OMS_NOT_SUPPORTED;

  MediaSigningReturnCode status = OMS_UNKNOWN_FAILURE;
  // Borrow the |hash| by passing the pointer to |sign_data| for signing.
  self->sign_data.hash = (uint8_t *)hash;
  self->sign_data.hash_size = hash_size;

  status = openssl_sign_hash(&self->sign_data);
  self->signature_generated = (status == OMS_OK) && (self->sign_data.signature_size > 0);

  return status;
}

static bool
unthreaded_has_signature(oms_unthreaded_plugin_t *self)
{
  if (self->signature_generated) {
    self->signature_generated = false;
    return true;
  }
  return false;
}

/**
 * Definitions of declared interfaces according to onvif_media_signing_plugin.h.
 */

MediaSigningReturnCode
onvif_media_signing_plugin_sign(void *handle, const uint8_t *hash, size_t hash_size)
{
  oms_unthreaded_plugin_t *self = (oms_unthreaded_plugin_t *)handle;
  if (!self || !hash || hash_size == 0) return OMS_INVALID_PARAMETER;

  return unthreaded_sign_hash(self, hash, hash_size);
}

/* The |signature| is copied from the local |sign_data| if the |signature_generated|
 * flag is set. */
bool
onvif_media_signing_plugin_get_signature(void *handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    MediaSigningReturnCode *error)
{
  oms_unthreaded_plugin_t *self = (oms_unthreaded_plugin_t *)handle;

  if (!self || !signature || !written_signature_size) return false;

  bool has_signature = unthreaded_has_signature(self);
  if (has_signature) {
    // Copy signature if there is room for it.
    if (max_signature_size < self->sign_data.signature_size) {
      *written_signature_size = 0;
    } else {
      memcpy(signature, self->sign_data.signature, self->sign_data.signature_size);
      *written_signature_size = self->sign_data.signature_size;
    }
  }
  if (error) *error = OMS_OK;

  return has_signature;
}

void *
onvif_media_signing_plugin_session_setup(const void *private_key, size_t private_key_size)
{
  if (!private_key || private_key_size == 0) return NULL;

  oms_unthreaded_plugin_t *self = calloc(1, sizeof(oms_unthreaded_plugin_t));
  if (!self) return NULL;

  // Turn the PEM |private_key| into an EVP_PKEY and allocate memory for signatures.
  if (openssl_private_key_malloc(&self->sign_data, private_key, private_key_size) !=
      OMS_OK) {
    onvif_media_signing_plugin_session_teardown((void *)self);
    self = NULL;
  }

  return self;
}

void
onvif_media_signing_plugin_session_teardown(void *handle)
{
  oms_unthreaded_plugin_t *self = (oms_unthreaded_plugin_t *)handle;
  if (!self) return;

  openssl_free_key(self->sign_data.key);
  free(self->sign_data.signature);
  free(self);
}

int
onvif_media_signing_plugin_init(void ATTR_UNUSED *user_data)
{
  return 0;
}

void
onvif_media_signing_plugin_exit(void ATTR_UNUSED *user_data)
{
}
