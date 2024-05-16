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

#include <stdlib.h>  // size_t

#include "onvif_media_signing_common.h"

/**
 * @brief Helper functions to generate a private key
 *
 * Two different APIs for RSA and ECDSA. By specifying a location a PEM file is generated
 * and stored as private_rsa_key.pem or private_ecdsa_key.pem. The user can then read this
 * file and pass the content to ONVIF Media Signing through
 * onvif_media_signing_set_signing_key_pair().
 * In addition to storing as file the content can be written to buffers at once. Memory is
 * allocated for |private_key| and the content of |private_key_size| Bytes is written.
 * Note that the ownership is transferred.
 *
 * Writing to file currently only works on Linux.
 *
 * @param dir_to_key If not NULL, the location where the PEM file will be written.
 *   Null-terminated string.
 * @param private_key If not NULL the content of the private key PEM file is copied to
 *   this output. Ownership is transferred.
 * @param private_key_size If not NULL outputs the size of the |private_key|.
 * @param certificate_chain If not NULL the content of the public key, wrapped in a
 *   certificate, is copied to this output. Ownership is transferred.
 * @param certificate_chain_size If not NULL outputs the size of the |certificate_chain|.
 *
 * @returns OMS_OK Successfully written PEM-file or to buffers,
 *          OMS_NOT_SUPPORTED Algorithm is not supported,
 *          OMS_INVALID_PARAMETER Invalid input parameter,
 *          OMS_EXTERNAL_ERROR PEM-file could not be written.
 */
MediaSigningReturnCode
oms_generate_ecdsa_private_key(const char *dir_to_key,
    char **private_key,
    size_t *private_key_size,
    char **certificate_chain,
    size_t *certificate_chain_size)
{
  return (dir_to_key || (private_key && private_key_size) ||
             (certificate_chain && certificate_chain_size))
      ? OMS_OK
      : OMS_INVALID_PARAMETER;
}
MediaSigningReturnCode
oms_generate_rsa_private_key(const char *dir_to_key,
    char **private_key,
    size_t *private_key_size,
    char **certificate_chain,
    size_t *certificate_chain_size)
{
  return (dir_to_key || (private_key && private_key_size) ||
             (certificate_chain && certificate_chain_size))
      ? OMS_OK
      : OMS_INVALID_PARAMETER;
}

#endif  // __ONVIF_MEDIA_SIGNING_HELPERS_H__
