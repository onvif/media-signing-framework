/**
 * MIT License
 *
 * Copyright (c) 2024 ONVIF. All rights reserved.
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
 * the sent information in the bundled authenticity report. ONVIF Media Signing only
 * supports names at most 255 bytes long in SEIs.
 */
typedef struct {
  char firmware_version[256];
  char serial_number[256];
  char manufacturer[256];
} onvif_media_signing_vendor_info_t;

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
typedef enum {
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
typedef enum {
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
 * All memory allocated for the onvif_media_signing_t object is freed. This will
 * effectivly end the media signing session.
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
