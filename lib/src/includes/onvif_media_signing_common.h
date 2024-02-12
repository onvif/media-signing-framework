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

#ifndef __ONVIF_MEDIA_SIGNING_COMMON_H__
#define __ONVIF_MEDIA_SIGNING_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _onvif_media_signing_t onvif_media_signing_t;

/**
 * Struct for holding strings to vendor product information
 *
 * This is used both by the device to set product information, and by the client to store
 * the sent information in the bundled authenticity report.
 */
typedef struct {
  char* firmware_version;
  char* serial_number;
  char* manufacturer;
} onvif_media_signing_product_info_t;

/**
 * @brief ONVIF Media Signing Return Code
 *
 * The error codes are categorized as
 * -(01-09): hardware issues like memory failure
 * -(10-19): user input errors like invalid parameters
 * -(20-29): internal or external signing errors
 * -(30-39): internal authentication errors
 *     -100: unknown failure
 */
typedef enum
{
  OMS_OK = 0,  // No error
  OMS_MEMORY = -1,  // Memory related failure
  OMS_INVALID_PARAMETER = -10,  // Invalid input parameter to function
  OMS_NOT_SUPPORTED = -12,  // The operation is not supported
  OMS_INCOMPATIBLE_VERSION = -15,  // Incompatible software version
  OMS_EXTERNAL_ERROR = -20,  // Failure in external code, e.g., plugin or OpenSSL
  OMS_AUTHENTICATION_ERROR = -30,  // Failure related to validating the authenticity
  OMS_UNKNOWN_FAILURE = -100,  // Unknown failure
} MediaSigningReturnCode;

/**
 * ONVIF Media Signing Codec
 *
 * Codecs supported by ONVIF Media Signing. This is necessary to provide when creating a
 * media signing session.
 */
typedef enum
{
  OMS_CODEC_H264 = 0,
  OMS_CODEC_H265 = 1,
  OMS_CODEC_NUM
} MediaSigningCodec;

/**
 * @brief Creates a new media signing session
 *
 * Creates an onvif_media_signing_t object which the user should keep across the entire
 * streaming session.
 * The user is responsible to free the memory when closing the session by calling the
 * onvif_media_signing_free() function. The returned struct can be used for either signing
 * a video, or validating the authenticity and provenance of a video. Signing specific
 * APIs can be found in onvif_media_signing_signer.h and validation specific APIs can be
 * found in onvif_media_signing_validator.h
 *
 * @param codec The codec format used in this session.
 *
 * @returns A pointer to onvif_media_signing_t struct, allocated and initialized. A null
 *          pointer is returned if memory could not be allocated or if initialization
 *          failed.
 */
onvif_media_signing_t*
onvif_media_signing_create(MediaSigningCodec codec);

/**
 * @brief Frees the memory of the onvif_media_signing_t object
 *
 * All memory allocated to and by the onvif_media_signing_t object is freed. This will
 * affectivly end the media signing session.
 *
 * @param self Pointer to the object which memory to free.
 */
void
onvif_media_signing_free(onvif_media_signing_t* self);

/**
 * @brief Resets the session to allow for, e.g., scrubbing a signed media
 *
 * Resets the session and puts it in a pre-stream state, that is, waiting for a new GOP.
 * Once a new GOP is found the operations start over.
 *
 * For the signing part, this means for example resetting linking GOPs which will affect
 * validation if done across the reset point. So resetting on the signing side should only
 * be done if something has gone really wrong with the stream.
 * For the validation part, this should be used when scrubbing the video. Otherwise, the
 * lib will fail authentication due to skipped NAL Units.
 *
 * @param self The ONVIF Media Signing session in use
 *
 * @returns An ONVIF Media Signing Return Code
 */
MediaSigningReturnCode
onvif_media_signing_reset(onvif_media_signing_t* self);

/**
 * @brief Returns the current software version as a null-terminated string.
 *
 * @returns A string with the current software version
 */
const char*
onvif_media_signing_get_version();

/**
 * @brief Compares two ONVIF Media Signing versions
 *
 * This function is meant to identify mismatches in implementations between the signing
 * part and the validation part. The code is backward compatible, but if signing has been
 * done with a newer version of this library than what is used in the validation firmware
 * there is no guarantee that validation can be performed correctly.
 *
 * @param version1 First version string for comparison
 * @param version2 Second version string for comparison
 *
 * @returns 0 if |version1| is equal to |version2|
 *          1 if |version1| is newer than |version2|
 *          2 if |version1| is older than |version2|
 *          -1 Failure
 */
int
onvif_media_signing_compare_versions(const char* version1, const char* version2);

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_MEDIA_SIGNING_COMMON_H__
