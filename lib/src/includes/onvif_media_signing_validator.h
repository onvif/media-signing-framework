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

#ifndef __ONVIF_MEDIA_SIGNING_VALIDATOR_H__
#define __ONVIF_MEDIA_SIGNING_VALIDATOR_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "onvif_media_signing_common.h"  // onvif_media_signing_t, MediaSigningReturnCode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Authenticity and provenance status since last result
 *
 * The authenticity (correctness of received video NAL Units) is validated using the
 * public cryptographic key present in the stream.
 * The provenance (correctness of the received public cryptographic key) is validated
 * using a trusted top certificate.
 * The authenticity and provenance result can take one of the states below.
 */
typedef enum
{
  // The consumed NAL Units so far contain no media signing information.
  OMS_AUTHENTICITY_NOT_SIGNED = 0,
  // Presence of Media Signing has been detected, but there is not enough information to
  // complete a validation. This state is only shown before the first validation. This can
  // happen if Media Signing SEIs have been detected, but no signature has yet been
  // received. It can also happen if no public key has been received or if no top
  // certificate has been set.
  OMS_AUTHENTICITY_NOT_FEASIBLE = 1,
  // The public cryptographic key could not successfully be validated.
  OMS_PROVENANCE_NOT_OK = 2,
  // At least one NAL Unit failed verification.
  OMS_AUTHENTICITY_NOT_OK = 3,
  // Successfully verified all NAL Units that could be verified, but missing NAL Units
  // were detected. Further judgements need to be made to complete the authenticity
  // validation.
  OMS_AUTHENTICITY_OK_WITH_MISSING_INFO = 4,
  // Successfully verified all NAL Units that could be verified, and all expected NAL
  // Units are present.
  OMS_AUTHENTICITY_OK = 5,
  // Video has been signed with a version newer than that used by the validation part.
  // Correct validation cannot be guaranteed. The user is encouraged to update the
  // validation code with a newer version.
  OMS_AUTHENTICITY_VERSION_MISMATCH = 6,
  // Marking the number of authenticity states that can be returned.
  OMS_AUTHENTICITY_NUM_STATES
} MediaSigningAuthenticityResult;

/**
 * Struct storing the latest validation result, that is, holds for NAL Units added since
 * the previous validation result. In general, the result spans an entire GOP. For long
 * GOP lengths the result may span a subset of the GOP if the signer has added
 * intermediate signatures.
 */
typedef struct {
  // The result of the latest authenticity and provenance validation.
  MediaSigningAuthenticityResult authenticity;
  // A new public cryptographic key has been detected. Signing an ongoing stream with a
  // new key is not allowed.
  bool public_key_has_changed;
  // Indicates how many hashable NAL Units (i.e., excluding SEI, PPS/SPS/VPS, AUD) were
  // expected, and part of the signature, since last validation. A negative value
  // indicates that such information is lacking due to a missing, or tampered, SEI.
  int number_of_expected_hashable_nalus;
  // Indicates how many hashable NAL Units (i.e., excluding SEI, PPS/SPS/VPS, AUD) have
  // been received since last validation, and used to verify the signature. If the Media
  // Signing feature is disabled, or an error occurred during validation, a negative value
  // is set.
  int number_of_received_hashable_nalus;
  // Indicates how many hashable NAL Units (i.e., excluding SEI, PPS/SPS/VPS, AUD) are
  // pending validation.
  int number_of_pending_hashable_nalus;
  // A null terminated string displaying the validation status of all the latest NAL
  // Units. The validated NAL Units are removed after fetching the authenticity_report.
  // This means that the user can count backwards from the latest/current NAL Unit and
  // verify each NAL Unit's authenticity individually. Each NAL Unit is marked by one of
  // these characters:
  // 'P' : Pending validation. This is the initial value. The NAL Unit has been registered
  //       and waiting for authenticity validation.
  // 'U' : The NAL Unit has an unknown authenticity. This occurs if the NAL Unit could not
  //       be parsed, or if the SEI is associated with NAL Units not part of the
  //       validating segment.
  // '_' : The NAL Unit is ignored and therefore not part of the signature. The NAL Unit
  //       has no impact on the video and is validated as authentic.
  // '.' : The NAL Unit has been validated as authentic.
  // 'N' : The NAL Unit has been validated as not authentic.
  // 'M' : The validation has detected one or more missing NAL Units at this position.
  // 'E' : An error occurred and validation could not be performed. This should be treated
  //       as an invalid NAL Unit.

  // Example:
  // Two consecutive |validation_str|. After 10 NAL Units an authentication result was
  // received which generated the first string. Left for next validation are the three
  // pending NAL Units (P's) and the ignored NAL Unit ('_'). Five new NAL Units were added
  // before the authentication result was updated. A new string has been generated (second
  // line) and now the pending NAL Units have been validated successfully (the P's have
  // been turned into '.'). Note that the ignored NAL Unit ('_') is still ignored.
  //   __....P_P.
  //         ._....PP.
  char *validation_str;
  // As a complement to the validation_str above, this null terminated string displays the
  // type of all the latest NAL Units. The string ends with a null terminated character.
  // Each NAL Unit is marked by one of these characters:
  // 'I' : I-frame (primary slice)
  // 'i' : I-frame (not primary slice)
  // 'P' : {P,B}-frame (primary slice)
  // 'p' : {P,B}-frame (not primary slice)
  // 'S' : SEI, generated by Media Signing including a signature
  // 's' : SEI, generated by Media Signing not including a signature
  // 'z' : SEI, other type than Media Signing generated
  // 'v' : Parameter Set NAL Unit, i.e., SPS/PPS/VPS
  // '_' : AUD
  // 'o' : Other valid type of NAL Unit
  // 'U' : Undefined NAL Unit
  // ' ' : No NAL Unit present, e.g., when missing NAL Units are detected

  // Example:
  // Complementing the example above.
  //         nalu_str:  vvIPPPIzPS
  //   validation_str:  __....P_P.
  //
  //         nalu_str:        IzPSPPIPS
  //   validation_str:        ._....PP.
  char *nalu_str;
  // The UTC (8 bytes) based time represented by the number of 100-nanosecond intervals
  // since January 1, 1601 of the I-frame leading the GOP.
  int64_t timestamp;
} onvif_media_signing_latest_validation_t;

/**
 * A struct holding information of the overall authenticity and provenance of the session.
 * Typically, this information is useful after screening an entire file, or when closing a
 * session.
 */
typedef struct {
  // The overall authenticity and provenance of the session.
  MediaSigningAuthenticityResult authenticity;
  // A new public cryptographic key has been detected. Signing an ongoing stream with a
  // new key is not allowed. If this flag is set the |authenticity| is automatically set
  // to OMS_AUTHENTICITY_NOT_OK.
  bool public_key_has_changed;
  // Total number of received NAL Units, that is all NAL Units added for validation. It
  // includes both hashable and non-hashable NAL Units.
  unsigned int number_of_received_nalus;
  // Total number of validated NAL Units, that is, how many of the received NAL Units that
  // so far have been validated.
  unsigned int number_of_validated_nalus;
  // The number of NAL Units that currently are pending validation.
  unsigned int number_of_pending_nalus;
  // The UTC (8 bytes) based time represented by the number of 100-nanosecond intervals
  // since January 1, 1601 of the first signed I-frame.
  int64_t first_timestamp;
  // The UTC (8 bytes) based time represented by the number of 100-nanosecond intervals
  // since January 1, 1601 of the last signed I-frame.
  int64_t last_timestamp;
} onvif_media_signing_accumulated_validation_t;

/**
 * Struct for holding strings to vendor product information
 */
typedef struct {
  char *firmware_version;  // Firmware version
  char *serial_number;  // Serial number
  char *manufacturer;  // Manufacturer
} onvif_media_signing_product_info_t;

/**
 * Authenticity Report
 *
 * This struct includes statistics and information of the authenticity and provenance
 * validation process. This should provide all necessary means to make a correct decision
 * on the authenticity and provenance of the video.
 */
typedef struct {
  // Code version used when signing the video.
  char *version_on_signing_side;
  // Code version used when validating the authenticity.
  char *this_version;
  // Information about the product provided in a struct.
  onvif_media_signing_product_info_t product_info;
  // Holds the information of the latest validation.
  onvif_media_signing_latest_validation_t latest_validation;
  // Holds the information of the total validation since the first added NALU.
  onvif_media_signing_accumulated_validation_t accumulated_validation;
} onvif_media_signing_authenticity_t;

/**
 * @brief Frees the onvif_media_signing_authenticity_t report.
 *
 * Frees all memory used in the |authenticity_report|.
 *
 * @param authenticity_report Pointer to current Authenticity Report
 */
void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t *authenticity_report);

/**
 * @brief Returns a copy of the onvif_media_signing_authenticity_t report from the Media
 * Signing session.
 *
 * The returned onvif_media_signing_authenticity_t report is a snapshot of the current
 * validation status. Hence, the returned report is not updated further with new
 * statistics if the Media Signing session proceeds. Note that also
 * onvif_media_signing_add_nalu_and_authenticate(...) can report the current validation
 * status, hence use this function with care.
 *
 * Memory is transfered and the user is responsibe to free it using
 * onvif_media_signing_authenticity_report_free(...)
 *
 * @param self Pointer to the current Media Signing session.
 *
 * @returns A copy of the latest authenticity report
 */
onvif_media_signing_authenticity_t *
onvif_media_signing_get_authenticity_report(onvif_media_signing_t *self);

/* Example code
 *
 * Use case: Live monitoring
 *   onvif_media_signing_t *oms = onvif_media_signing_create(OMS_CODEC_H264);
 *   onvif_media_signing_authenticity_t *auth_report = NULL;
 *
 *   // For every H26x NAL Unit received do
 *   while (still_nalus_remaining) {
 *     MediaSigningReturnCode status = onvif_media_signing_add_nalu_and_authenticate(oms,
 *         nalu, nalu_size, &auth_report);
 *     if (status != OMS_OK) {
 *       printf("Authentication encountered error (%d)\n", status);
 *     } else if (auth_report) {
 *       switch (auth_report->latest_validation.authenticity) {
 *         case OMS_AUTHENTICITY_OK:
 *           printf("The video since last signature is authentic\n");
 *           // Perform your action
 *           break;
 *         case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
 *           printf("The video since last signature has missing information, but the \
 *               last  gop is authentic\n");
 *           // Perform your action
 *           break;
 *         case OMS_AUTHENTICITY_NOT_SIGNED:
 *           printf("The Media Signing feature is not present in this video\n");
 *           // Perform your action
 *           break;
 *         case OMS_AUTHENTICITY_VERSION_MISMATCH:
 *           printf("The video was signed with a newer version than this validation\n");
 *           // Perform your action
 *           break;
 *         case OMS_AUTHENTICITY_NOT_FEASIBLE:
 *           printf("The Media Signing feature has been detected and waiting for the \
 *               first signature, or for a public cryptographic key\n");
 *           // Perform your action
 *           break;
 *         case OMS_PROVENANCE_NOT_OK:
 *           printf("The provenance of the video since last signature is not correct\n");
 *           // Perform your action
 *           break;
 *         case OMS_AUTHENTICITY_NOT_OK:
 *           printf("The video since last signature is not authentic\n");
 *           // Perform your action
 *           break;
 *         default:
 *           printf("Unexpected authentication result\n")
 *           break;
 *       }
 *       // Free |auth_report| if you are done with it
 *       onvif_media_signing_authenticity_report_free(auth_report);
 *     } else {
 *       printf("Waiting for next signature\n")
 *     }
 *   }
 *
 *   // Free the memory when session ends
 *   onvif_media_signing_free(oms);
 */

/**
 * @brief Add NAL Unit data to the session and get an authentication report
 *
 * This function should be called for each H26x NAL Unit the user receives. It is assumed
 * that |nalu| consists of one single NAL Unit including Start Code and NAL Unit, so
 * that NAL Unit type can be parsed. That is, the format should look like this:
 *
 * |------------|----------|
 * | Start Code | NAL Unit |
 * |------------|----------|
 *  3 or 4 bytes           ^
 *                         Including stop bit
 *
 * NOTE: NAL Units sent into the API cannot be in packetized format (access units)!
 * The access unit has to be split into separate NAL Units if so.
 *
 * The input |nalu| is not changed by this call. Note that it is assumed that ALL H26x NAL
 * Units are passed to this function. Otherwise, they will be treated as missing/lost
 * which may affect the validation.
 *
 * Signatures are sent on regular basis. Commonly this is done at the end of each GOP
 * (Group Of Pictures). For every input |nalu| with a signature, or when a signature is
 * expected, validation is performed and a copy of the |authenticity| result is provided.
 * If a NAL Unit does not trigger a validation, |authenticity| is a NULL pointer.
 *
 * The user should continuously check the return value for errors and upon success check
 * |authenticity| for a new report.
 * Two typical use cases are; 1) live monitoring which could be screening the video until
 * authenticity can no longer be validated OK, and 2) screening a recording and get a full
 * report at the end. In the first case further operations can simply be aborted as soon
 * as a validation fails, whereas in the latter case all the NAL Units need to be
 * screened.
 *
 * Example code of usage; See example code above.
 *
 * @param self Pointer to the onvif_media_signing_t object to update
 * @param nalu Pointer to the H26x NAL Unit data to be added
 * @param nalu_size Size of the |nalu|
 * @param authenticity Pointer to the autenticity report. Passing in a NULL pointer will
 *     not provide latest validation results. The user is then responsible to get a report
 *     using onvif_media_signing_get_authenticity_report(...).
 *
 * @returns A Media Signing Return Code (MediaSigningReturnCode)
 */
MediaSigningReturnCode
onvif_media_signing_add_nalu_and_authenticate(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    onvif_media_signing_authenticity_t **authenticity);

/**
 * @brief Sets the root certificate used to validate the public key
 *
 * The public key, necessary to verify the signatures, is at least once added to the
 * stream through its leaf certificate. The stream also includes potential intermediate
 * certificates creating a chain of certifcates. To be able to validate the public key as
 * authentic the root (CA) certificate is needed.
 *
 * This root certificate should never be present in the media stream and has to be added
 * for complete validation.
 * This function allows the user to add the root certificate to the current Media Signing
 * session. The operation has to be performed before the session starts. It is not allowed
 * to change the root certificate on the fly, for which OMS_NOT_SUPPORTED is returned.
 *
 * The root certificate is expected to be in PEM format.
 *
 * @param self Pointer to the current Media Signing session
 * @param root_cert Pointer to the root certificate in PEM format
 * @param root_cert_size Size of the root certificate
 *
 * @returns A Media Signing Return Code (MediaSigningReturnCode)
 */
MediaSigningReturnCode
onvif_media_signing_set_root_certificate(onvif_media_signing_t *self,
    const char *root_cert,
    size_t root_cert_size);

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_MEDIA_SIGNING_VALIDATOR_H__
