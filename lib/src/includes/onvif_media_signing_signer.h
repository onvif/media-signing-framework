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

#ifndef __ONVIF_MEDIA_SIGNING_SIGNER_H__
#define __ONVIF_MEDIA_SIGNING_SIGNER_H__

#include <stdbool.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "onvif_media_signing_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief General description on how to integrate the signing part of ONVIF Media Signing
 *
 * Each NAL Unit in a video has to be processed for signing. The ONVIF Media Signing
 * library makes the decision whether a NAL Unit should be hashed and included in the
 * signature or not.
 *
 * ONVIF Media Signing adds SEIs of type "user data unregistered" to communicate data for
 * authentication. These SEIs are generated by the ONVIF Media Signing library and are
 * complete NAL Units + 4 start code bytes. The user is responsible for pulling these
 * generated NAL Units from the session.
 * Hence, upon a successful onvif_media_signing_add_nalu_for_signing(...) call, the user
 * should always call onvif_media_signing_get_sei(...) to fetch potentilally generated
 * SEIs.
 *
 * These generated SEIs are, by default, written with emulation prevention bytes. If
 * emulation prevention bytes will be added afterwards by the device, the user can change
 * this with the setter onvif_media_signing_set_emulation_prevention_before_signing(...).
 *
 * To follow the H.26x standard, SEIs should be added right before the NAL Unit primary
 * slice. If the library provides multiple SEIs through the pulling procedure, they are
 * provided in the same order that they should appear in the stream. Further, these SEIs
 * can then be added to the same AU or in a later AUs.
 * For example, assume one AU with SPS, PPS and a frame consisting of two NAL Unit slices;
 * A primary slice (F0p) and a secondary slice (F0s). That is, the memory looks like
 *
 * | AUD | SPS | PPS | F0p | F0s |
 *
 * Now, assume that two SEIs are pulled from the library; F1, F2 in order. Then, if added
 * to the same AU, the memory afterwards should look like this
 *
 * | AUD | SPS | PPS | F1 | F2 | F0p | F0s |
 *
 *
 * There are a set of configuration APIs that can/should be used before the first NAL Unit
 * is added for signing:
 *   Mandatory
 *     onvif_media_signing_set_signing_key_pair(...)
 *   Optional
 *     onvif_media_signing_set_hash_algo(...)
 *     onvif_media_signing_set_vendor_info(...)
 *     onvif_media_signing_set_emulation_prevention_before_signing(...)
 *     onvif_media_signing_set_signing_frequency(...)
 *     onvif_media_signing_set_max_signing_nalus(...)
 *     onvif_media_signing_set_use_golden_sei(...)
 *     onvif_media_signing_set_low_bitrate_mode(...)
 *     onvif_media_signing_set_max_sei_payload_size(...)
 *
 * For descriptions of the configuration APIs; See respective function below.
 *
 * To lower the bitrate increase, introduced by the SEIs, the user has two options to
 * reduce it. One is to activate the low bitrate mode (see optional calls above). The
 * other is to transmit the certificate chain, and other information only needed once, in
 * a golden SEI. The golden SEI is self-signed and should be the first SEI of the stream.
 * If the golden SEI is pre-generated it is the responsibility of the user to add it to
 * the stream. There is a helper function to get the golden SEI
 *   onvif_media_signing_generate_golden_sei(...)
 *
 * Another helper function that can be used if a video stream is closed gracefully. If
 * there is time to wait for a final SEI when closing a stream
 *   onvif_media_signing_set_end_of_stream(...)
 * will force a final signing request.
 *
 *
 * Here is an example pseudo code of usage:
 *
 *   onvif_media_signing_t *oms = onvif_media_signing_create(OMS_CODEC_H264);
 *   if (!oms) {
 *     // Handle error
 *   }
 *   // Set manufacturer provisioned signing key pair (should always be done)
 *   if (onvif_media_signing_set_signing_key_pair(oms, private_key, private_key_size,
 *           certificate_chain, certificate_chain_size, false) != OMS_OK) {
 *     // Handle error
 *   }
 *   if (user_provisioned_signing) {
 *     if (onvif_media_signing_set_signing_key_pair(oms, user_private_key,
 *             user_private_key_size, user_certificate_chain, user_certificate_chain_size,
 *             true) != OMS_OK) {
 *       // Handle error
 *     }
 *   }
 *   // Configure session by using configuration APIs, for example
 *   if (onvif_media_signing_set_use_golden_sei(oms, use_stream_start_sei) !=
 *       OMS_OK) {
 *     // Handle error
 *   }
 *   if (use_stream_start_sei && stream_start_sei_not_loaded) {
 *     if (onvif_media_signing_generate_golden_sei(oms) != OMS_OK) {
 *       // Handle error
 *     }
 *     // Use onvif_media_signing_get_sei() to get the golden SEI
 *     // Add stream_start_sei to the first AU
 *   }
 *
 *   // Start session and add NAL Units repeatedly
 *   MediaSigningReturnCode status;
 *   status = onvif_media_signing_add_nalu_for_signing(oms, nalu, nalu_size, NULL);
 *   if (status != OMS_OK) {
 *     // Handle error
 *   } else {
 *     size_t sei_size = 0;
 *     status = onvif_media_signing_get_sei(sv, NULL, &sei_size);
 *     while (status == OMS_OK && sei_size > 0) {
 *       uint8_t *sei = malloc(sei_size);
 *       status = onvif_media_signing_get_sei(sv, sei, &sei_size);
 *       if (status != OMS_OK)
 *         break;
 *       // Prepend the latest NAL Unit in the current AU with this SEI.
 *       status = onvif_media_signing_get_sei(sv, NULL, &sei_size);
 *     }
 *     // Handle return code
 *     if (status != SV_OK) {
 *       // True error. Handle it properly.
 *     }
 *   }
 *
 */

/**
 * @brief Updates ONVIF Media Signing, with a H26x NAL Unit, for signing
 *
 * Each NAL Unit in a video has to be processed for signing. The ONVIF Media Signing
 * library makes the decision whether a NAL Unit should be hashed and included in the
 * signature or not.
 *
 * The timestamp format is the UTC based time represented by the number of 100-nanosecond
 * intervals since January 1, 1601 (8 bytes).
 *
 * @param self      Pointer to the ONVIF Media Signing session.
 * @param nalu      A pointer to the NAL Unit data
 * @param nalu_size The size of the NAL Unit data.
 * @param timestamp The UTC based time represented by the number of 100-nanosecond
 *                  intervals since January 1, 1601 (8 bytes).
 *
 * @returns OMS_OK            - the NAL Unit was processed successfully.
 *          OMS_NOT_SUPPORTED - onvif_media_signing_set_private_key(...) has not been set
 *          otherwise a different error code.
 */
MediaSigningReturnCode
onvif_media_signing_add_nalu_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    int64_t timestamp);

/**
 * @brief Updates ONVIF Media Signing, with a part of a H.26X NAL Unit, for signing
 *
 * For description see onvif_media_signing_add_nalu_for_signing(...) above.
 *
 * This API allows the user to add parts of a NAL Unit for signing. For complete, NAL
 * Units use onvif_media_signing_add_nalu_for_signing(...) or always set |is_last_part| to
 * 'true'.
 *
 * It is very important that the video NAL Units are fed to this API in the same order as
 * they would have concatenated into one complete NAL Unit. Otherwise, the authentication
 * will fail.
 *
 * @param self           Pointer to the ONVIF Media Signing session.
 * @param nalu_part      A pointer to the partial NAL Unit data
 * @param nalu_part_size The size of the partial NAL Unit data.
 * @param timestamp      The UTC based time represented by the number of 100-nanosecond
 *                       intervals since January 1, 1601 (8 bytes).
 * @param is_last_part   Flag to mark the last part of the current NAL Unit.
 */
MediaSigningReturnCode
onvif_media_signing_add_nalu_part_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu_part,
    size_t nalu_part_size,
    int64_t timestamp,
    bool is_last_part);

/** NOTE: This function will most likely change before published. */
/**
 * @brief Gets a generated SEI to be added to the stream
 *
 * This function should always be called after a successful
 * onvif_media_signing_add_nalu_for_signing(...) or
 * onvif_media_signing_add_nalu_part_for_signing(...). Otherwise, the functionality of
 * ONVIF Media Signing is jeopardized, since vital SEIs may not be added to the video
 * stream.
 *
 * These SEIs are generated by the ONVIF Media Signing library and are complete NAL Units
 * + 4 start code bytes. Hence, this API allows the user to pull the existing SEIs one by
 * one until no further SEIs exist. When no more SEI exists the |sei_size| is 0.
 *
 * The user is responsible for allocating memory for the SEI to get. The library will copy
 * the SEI into that memory. To know the seize of the SEI, the user can pass in a NULL
 * pointer as |sei|.
 * NOTE: to make life a little bit easier for the user, the library provide generated SEIs
 * only in conjunction with primary slice NAL Units, like F0p in the example description
 * at the top of this file.
 *
 * @param self                Pointer to the ONVIF Media Signing session.
 * @param sei                 A pointer to the memory of which the library will copy the
 *   SEI. A NULL pointer means that only the |sei_size| is written.
 * @param sei_size            A pointer to where the size of the SEI will be written. If
 *   zero, no SEI is available
 * @param peek_nalu           A pointer to the NAL Unit of which the SEI will be prepended
 *   as a header. SEIs can only be fetched if the NAL is a primary slice. Note that the
 *   |peek_nalu| must NOT been added for signing. A NULL pointer means that the user is
 *   responsible to add the SEI according to standard.
 * @param peek_nalu_size      The size of the peek NAL Unit.
 * @param num_pending_seis    A pointer to where the number of pending SEIs is written.
 *
 * @returns OMS_OK            - SEI was pulled successfully, or no SEI was available,
 *          otherwise         - an error code.
 */
MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t *self,
    uint8_t *sei,
    size_t *sei_size,
    const uint8_t *peek_nalu,
    size_t peek_nalu_size,
    unsigned *num_pending_seis);

/**
 * @brief Sets the content of the signing key pair
 *
 * This function sets a private key used for signing. The private key should be in PEM
 * format. ONVIF Media Signing allows both manufacturer provisioned and user provisioned
 * signing keys. This function is used for both alternatives and the flag
 * |user_provisioned| indicates which one of them to set.
 *
 * It is mandatory to set a manufacturer provisioned signing key even if the video should
 * be signed with a user provisioned signing key. The manufacturer provisioned signing key
 * is used to sign the start-of-stream SEI, including the certificates etc. of the user
 * provisioned signing key, otherwise the provenance is lost.
 *
 * NOTE: Private keys cannot be changed after the stream start. If this API is called
 * after the first NAL Unit has been added, OMS_NOT_SUPPORTED is returned.
 *
 * The validation side requires the corresponding public key to verify signatures. The
 * public key is included in the leaf certificate of the certificate chain, which is added
 * to at least one SEI. The root certificate will be removed by the library before added
 * to the stream.
 * Further, the certificate chain is expected to be in PEM format.
 *
 * @param self                   Pointer to the ONVIF Media Signing session.
 * @param private_key            The content of the private key PEM file.
 * @param private_key_size       The size of the |private_key|.
 * @param certificate_chain      The content of the certificate chain in PEM format
 *                               excluding the root certificate.
 * @param certificate_chain_size The size of the |certificate_chain|.
 * @param user_provisioned       A flag to signal that the |private_key| is user
 *                               provisioned instead of manufactuerer provisioned.
 *
 * @returns OMS_OK             - upon success,
 *          OMS_NOT_SUPPORTED  - if a key pair has already been set,
 *          OMS_EXTERNAL_ERROR - for OpenSSL-related issues
 *          other error code   - otherwise.
 */
MediaSigningReturnCode
onvif_media_signing_set_signing_key_pair(onvif_media_signing_t *self,
    const char *private_key,
    size_t private_key_size,
    const char *certificate_chain,
    size_t certificate_chain_size,
    bool user_provisioned);

/**
 * @brief Sets the hash algorithm
 *
 * This function sets the algorithm used for hashing NAL Units. The hash algorithm has to
 * be supported by OpenSSL and represented by the OID as a null-terminated string.
 * If no hash algorithm is set, SHA256 (OID '2.16.840.1.101.3.4.2.1') is used.
 *
 *
 * @param self        Pointer to the ONVIF Media Signing session.
 * @param name_or_oid The hash algorithm represented by name or OID
 *
 * @returns OMS_OK             - upon success,
 *          OMS_NOT_SUPPORTED  - if the algorithm is not supported by OpenSSL,
 *          OMS_EXTERNAL_ERROR - for OpenSSL-related issues
 *          other error code   - otherwise.
 */
MediaSigningReturnCode
onvif_media_signing_set_hash_algo(onvif_media_signing_t *self, const char *name_or_oid);

/**
 * @brief Sets product information for the ONVIF Media Signing session
 *
 * This API will set the firmware version, serial number and manufacturer of the
 * onvif_media_signing_t session.
 * NOTE: The members of |vendor_info| should be null-terminated strings and empty strings
 * for information that should be excluded.
 *
 * @param self        Pointer to the ONVIF Media Signing session.
 * @param vendor_info Pointer to an onvif_media_signing_vendor_info_t object holding
 *                    null-terminated strings of firmware version, serial number and
 *                    manufacturer.
 *
 * @returns OMS_OK           - Product info was successfully set,
 *          other error code - otherwise.
 */
MediaSigningReturnCode
onvif_media_signing_set_vendor_info(onvif_media_signing_t *self,
    const onvif_media_signing_vendor_info_t *vendor_info);

/**
 * @brief Configures ONVIF Media Signing to generate the SEIs w/wo emulation prevention
 *
 * Emulation prevention bytes (EPB) are used to prevent the decoder from detecting a start
 * code sequence in the middle of a NAL Unit. By default, the framework generates SEIs
 * without EPB written to the payload at once. With this API, the user can select to have
 * ONVIF Media Signing generate SEIs with or without EPBs.
 *
 * Typically a device that adds SEIs at once on a stream where emulation prevention is
 * applied will configure Media Signing to apply EPB before signing (set to true). A
 * device that lets the encoder add SEIs will configure Media Signing to not apply EPB
 * before signing (set to false).
 *
 * If this API is not used, SEI payload is written without EPBs, hence equivalent with
 * setting |enable| to 'false'.
 *
 * @param self   Pointer to the ONVIF Media Signing session.
 * @param enable SEI payload written with EPB (default False)
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_emulation_prevention_before_signing(onvif_media_signing_t *self,
    bool enable);

/**
 * @brief Sets the signing frequency for this ONVIF Media Signing session
 *
 * The default behavior of the ONVIF Media Signing library is to sign and generate a SEI
 * every GOP (Group Of Pictures). Due to hardware resource limitations and GOP length
 * settings, signing every GOP can become infeasible in real-time. For example, when
 * multiple streams are signed or if the GOP length is very short.
 *
 * This API allows the user to change the signing frequency at anytime during a session.
 * The signing frequency is measured in number of GOPs.
 *
 * @param self              Pointer to the ONVIF Media Signing session.
 * @param signing_frequency Number of GOPs between signatures
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_signing_frequency(onvif_media_signing_t *self,
    unsigned signing_frequency);

/**
 * @brief Sets an upper limit on number of NAL Units before signing
 *
 * The default behavior of the ONVIF Media Signing library is to sign and generate a SEI
 * every GOP (Group Of Pictures). When very long GOPs are used, the duration between
 * signatures can become impractically long, or even makes a file export on the validation
 * side infeasible to validate because the segment lacks a SEI.
 *
 * This API allows the user to set an upper limit on how many NAL Units that can be added
 * before sending a signing request. If this limit is reached, an intermediate SEI is
 * generated. This limit will not affect the normal behavior of signing when reaching the
 * end of a GOP (or when the signing frequency set with
 * onvif_media_signing_set_signing_frequency(...)).
 * If |max_signing_nalus| = 0, no limit is used. This is the default behavior.
 *
 * @param self              Pointer to the ONVIF Media Signing session.
 * @param max_signing_nalus Maximum number of NAL Units covered by a signatures
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_max_signing_nalus(onvif_media_signing_t *self,
    unsigned max_signing_nalus);

/**
 * @brief Configures the ONVIF Media Signing session to use the golden SEI concept
 *
 * ONVIF Media Signing allows the signing part to transmit information needed by the
 * validation side only once, such as the public key embedded in a certificate chain.

 * The default behavior is to continuously transmit everything necessary to verify a
 * signature, that is, not to use the golden SEI concept.
 * NOTE: This function has to be called before the session starts.
 *
 * @param self    Pointer to the ONVIF Media Signing session.
 * @param enable 'true' enables the golden SEI concept, and
 *               'false' (default) disables it.
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_use_golden_sei(onvif_media_signing_t *self, bool enable);

/**
 * @brief Puts the ONVIF Media Signing session in a low bitrate mode
 *
 * ONVIF Media Signing supports a low bitrate mode, for which hashes of individual NAL
 * Units are not included in the SEIs. This lowers the bitrate to a cost in
 * identifiability. When the NAL Unit hashes are left out, individual errors like missing
 * or incorrect NAL Units cannot be identified. Hence, all NAL Units part of the signature
 * become invalid.
 *
 * This function can be called at anytime and several times during a session.
 *
 * @param self        Pointer to the ONVIF Media Signing session.
 * @param low_bitrate 'true' turns on, and 'false' (default) turns off, the low bitrate
 *                    mode.
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_low_bitrate_mode(onvif_media_signing_t *self, bool low_bitrate);

/**
 * @brief Configures the ONVIF Media Signing session to limit the SEI payload
 *
 * As a helper function to onvif_media_signing_set_low_bitrate_mode(...) it can be easier
 * to provide an upper limit of the size of the generated SEIs before falling back to the
 * low bitrate mode.
 * This API sets an upper limit on the payload size of the generated SEI. If the, to be
 * generated, SEI exceeds the |max_sei_payload_size| ONVIF Media Signing falls back to low
 * bitrate.
 *
 * Note that it is a soft limit. If the payload size is still too large even in low
 * bitrate mode the SEI is generated anyhow. Further, note that the API sets the maximum
 * SEI payload size. The final SEI size can become larger since it includes headers, size
 * bytes and potentional emulation prevention.
 *
 * If this API is not used, an unlimited SEI payload size is used
 * (|max_sei_payload_size| = 0).
 *
 * @param self                 Pointer to the ONVIF Media Signing session.
 * @param max_sei_payload_size The maximum size of a SEI payload before falling back to
 *                             low bitrate mode.
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_max_sei_payload_size(onvif_media_signing_t *self,
    size_t max_sei_payload_size);

/**
 * @brief Generates a golden SEI from the ONVIF Media Signing session
 *
 * ONVIF Media Signing allows the signing part to transmit information needed by the
 * validation side only once, such as the public key embedded in a certificate chain.
 *
 * If this feature has been turned on, by using
 * onvif_media_signing_set_use_golden_sei(...), this API generates this
 * golden SEI. It can then be fetched like all other SEIs with
 * onvif_media_signing_get_sei().
 *
 * NOTE: All configurations need to have been completed and the session should not have
 * been started.
 *
 * @param self Pointer to the ONVIF Media Signing session.
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_generate_golden_sei(onvif_media_signing_t *self);

/**
 * @brief Marks the end of an ONVIF Media Signing session
 *
 * If a video stream can be stopped gracefully and allows the system to wait for some
 * actions to be completed, the session can force a final signing to avoid a dangling end.
 *
 * Use this API to mark the end of a stream. The session will then force a final signing.
 * All generated SEIs should be pulled as normal using onvif_media_signing_get_sei(...).
 * Further, after this call any use of onvif_media_signing_add_nalu_for_signing(...) will
 * return OMS_NOT_SUPPORTED.
 *
 * @param self Pointer to the ONVIF Media Signing session.
 *
 * @returns An ONVIF Media Signing Return Code.
 */
MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t *self);

#ifdef __cplusplus
}
#endif

#endif  // __ONVIF_MEDIA_SIGNING_SIGNER_H__
