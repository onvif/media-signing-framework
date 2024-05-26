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

#include <stdint.h>
#include <stdlib.h>  // free
#include <string.h>  // strcmp

#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_signer.h"
#include "includes/onvif_media_signing_validator.h"
#include "oms_openssl_internal.h"

/* onvif_media_signing_signer APIs */
MediaSigningReturnCode
onvif_media_signing_add_nalu_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    int64_t timestamp)
{
  return (!self || !nalu || nalu_size == 0 || timestamp == 0) ? OMS_INVALID_PARAMETER
                                                              : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_part_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu_part,
    size_t nalu_part_size,
    int64_t timestamp,
    bool is_last_part)
{
  return (!self || !nalu_part || nalu_part_size == 0 || timestamp == 0)
      ? OMS_INVALID_PARAMETER
      : (is_last_part ? OMS_OK : OMS_NOT_SUPPORTED);
}

MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t *self, oms_sei_to_add_t *sei)
{
  return (!self || !sei) ? OMS_INVALID_PARAMETER : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_hash_algo(onvif_media_signing_t *self, const char *hash_algo_oid)
{
  return (!self || !hash_algo_oid) ? OMS_INVALID_PARAMETER : OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_product_info(onvif_media_signing_t *self,
    const onvif_media_signing_product_info_t *product_info)
{
  return (!self || !product_info) ? OMS_INVALID_PARAMETER : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_sei_epb(onvif_media_signing_t *self, bool sei_epb)
{
  return (!self) ? OMS_INVALID_PARAMETER : (sei_epb ? OMS_OK : OMS_NOT_SUPPORTED);
}

MediaSigningReturnCode
onvif_media_signing_set_signing_frequency(onvif_media_signing_t *self,
    unsigned signing_frequency)
{
  return (!self || signing_frequency == 0) ? OMS_INVALID_PARAMETER : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_max_signing_nalus(onvif_media_signing_t *self,
    unsigned max_signing_nalus)
{
  return (!self || max_signing_nalus == 1) ? OMS_INVALID_PARAMETER : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_max_sei_payload_size(onvif_media_signing_t *self,
    size_t max_sei_payload_size)
{
  return (!self || max_sei_payload_size == 1) ? OMS_INVALID_PARAMETER : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t *self)
{
  return !self ? OMS_INVALID_PARAMETER : OMS_OK;
}

/* onvif_media_signing_validator APIs */
void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t *authenticity_report)
{
  free(authenticity_report);
}

onvif_media_signing_authenticity_t *
onvif_media_signing_get_authenticity_report(onvif_media_signing_t *self)
{
  return !self ? NULL : NULL;
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_and_authenticate(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    onvif_media_signing_authenticity_t **authenticity)
{
  return (!self || !nalu || nalu_size == 0 || authenticity) ? OMS_INVALID_PARAMETER
                                                            : OMS_OK;
}

MediaSigningReturnCode
onvif_media_signing_set_root_certificate(onvif_media_signing_t *self,
    const char *root_cert,
    size_t root_cert_size)
{
  return (!self || !root_cert || root_cert_size == 0) ? OMS_INVALID_PARAMETER : OMS_OK;
}

bool
onvif_media_signing_is_start_of_stream_sei(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size)
{
  return (!self || !nalu || nalu_size == 0) ? false : true;
}
