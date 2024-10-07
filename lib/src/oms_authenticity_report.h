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

#ifndef __OMS_AUTHENTICITY_REPORT_H__
#define __OMS_AUTHENTICITY_REPORT_H__

#include "includes/onvif_media_signing_common.h"  // onvif_media_signing_vendor_info_t
#include "includes/onvif_media_signing_validator.h"
#include "oms_defines.h"  // oms_rc

/**
 * @brief Transfers all members in onvif_media_signing_vendor_info_t from |src| to |dst|
 *
 * @param dst The onvif_media_signing_vendor_info_t struct of which to write to
 * @param src The onvif_media_signing_vendor_info_t struct of which to read from
 */
void
transfer_vendor_info(onvif_media_signing_vendor_info_t *dst,
    const onvif_media_signing_vendor_info_t *src);

/**
 * @brief Initializes a onvif_media_signing_latest_validation_t struct
 *
 * Counters are initialized to -1 and lists are NULL pointers.
 *
 * @param self The struct to initialize.
 */
void
latest_validation_init(onvif_media_signing_latest_validation_t *self);

/**
 * @brief Initializes a onvif_media_signing_accumulated_validation_t struct
 *
 * Counters are initialized to -1, etc.
 *
 * @param self The struct to initialize.
 */
void
accumulated_validation_init(onvif_media_signing_accumulated_validation_t *self);

/**
 * @brief Updates the local onvif_media_signing_accumulated_validation_t struct
 *
 * Updates the local authenticity report w.r.t. the Media Signing NAL Unit list and latest
 * validation.
 *
 * @param self The current Media Signing session
 */
void
update_authenticity_report(onvif_media_signing_t *self);

/**
 * @brief Creates a local authenticity report unless already present
 *
 * @param self The current Media Signing session
 *
 * @return A Media Signing Return Code
 */
oms_rc
create_local_authenticity_report_if_needed(onvif_media_signing_t *self);

#endif  // __OMS_AUTHENTICITY_REPORT_H__
