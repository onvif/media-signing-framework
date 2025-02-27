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
