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

// #include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_validator.h"
#include "oms_defines.h"  // oms_rc
// #include "signed_video_internal.h"

#if 0
/**
 * @brief Transfers all members in signed_video_product_info_t from |src| to |dst|
 *
 * @param dst The signed_video_product_info_t struct of which to write to
 * @param src The signed_video_product_info_t struct of which to read from
 *
 * @returns A Signed Video Return Code
 */
svrc_t
transfer_product_info(signed_video_product_info_t *dst, const signed_video_product_info_t *src);
#endif

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
 * @brief Maybe creates a local authenticity report
 *
 * If an authenticity report has not been set by the user, a local one is created to
 * populate for later use.
 *
 * @param self The current Media Signing session
 *
 * @returns A Media Signing Return Code
 */
oms_rc
create_local_authenticity_report_if_needed(onvif_media_signing_t *self);

#if 0
/**
 * @brief Copies a null-terminated string
 *
 * Memory is (re-)allocated if needed to match the new string. A NULL pointer in as |src_str| will
 * copy an empty "" string.
 *
 * @param dst_str A pointer holding a pointer to the copied string. Memory is allocated if needed.
 * @param src_str The null-terminated string to copy. A NULL pointer copies "".
 *
 * @returns A Signed Video Return Code
 */
svrc_t
allocate_memory_and_copy_string(char **dst_str, const char *src_str);
#endif

void
update_authenticity_report(onvif_media_signing_t *self);

#endif  // __OMS_AUTHENTICITY_REPORT_H__
