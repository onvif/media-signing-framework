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

#ifndef __OMS_DEFINES_H__
#define __OMS_DEFINES_H__

#include <stdbool.h>  // bool

#include "includes/onvif_media_signing_common.h"

typedef MediaSigningReturnCode oms_rc;  // Short Name for ONVIF Media Signing Return Code

// Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42);
#ifdef ONVIF_MEDIA_SIGNING_DEBUG
#include <stdio.h>
#define DEBUG_LOG(str, ...) printf("[DEBUG](%s): " str "\n", __func__, ##__VA_ARGS__)
#else
#define DEBUG_LOG(str, ...) ((void)0)
#endif

// Helpers for the try/catch macros below
#define OMS_MAYBE_GOTO_CATCH_ERROR() \
  if (status_ != OMS_OK) goto catch_error;
#define OMS_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(msg, ...) \
  if (status_ != OMS_OK) { \
    DEBUG_LOG(msg, ##__VA_ARGS__); \
    goto catch_error; \
  }

/* Macros for writing uniform try/catch code.
 *
 * OMS_TRY()
 *     initiates the scope.
 * OMS_CATCH()
 *     initiates a scope for catching and handling errors. Note that if this point is
 * reached without errors, this section is not executed. OMS_DONE(status) completes the
 * scope and everything afterwards (error or not) will be executed. The variable |status|
 * is set accordingly.
 *
 * OMS_THROW_IF(fail_condition, fail_status)
 *     checks |fail_condition| and throws a |fail_status| error.
 * OMS_THROW(my_status)
 *     same as OMS_THROW_IF(), but with the difference that a oms_rc check is assumed,
 * that is, simplification of OMS_THROW_IF(my_status != OMS_OK, my_status)
 *
 * The THROW macros has a version to print a specific error message |fail_msg| upon
 * failure.
 *
 * OMS_THROW_IF_WITH_MSG(fail_condition, fail_status, fail_msg)
 * OMS_THROW_WITH_MSG(my_status, fail_msg)
 *
 * Limitation : The above try/catch macros comes with limitation as given below,
 * 1. Macros need to be called in the particularly defined order as explained in the below
 * example.
 * 2. Macros "OMS_TRY, OMS_CATCH and OMS_DONE" should only be called once per function.
 * The macro order is "OMS_TRY, OMS_CATCH and OMS_DONE".
 * 3. The macros "OMS_TRY, OMS_CATCH and OMS_DONE" cannot be used standalone. Using
 * OMS_TRY means that OMS_CATCH and OMS_DONE must be used as well.
 * 4. OMS_THROW_IF, OMS_THROW, OMS_THROW_IF_WITH_MSG and OMS_THROW_WITH_MSG can be called
 * (single or multiple times) in between OMS_TRY and OMS_CATCH.
 *
 * Example code:
 *
 * oms_rc
 * example_function(my_struct_t **output_parameter)
 * {
 *   if (!output_parameter) return OMS_INVALID_PARAMETER;
 *
 *   my_struct_t *a = NULL;
 *   oms_rc status = OMS_UNKNOWN_FAILURE;  // Initiate to something that fails
 *   OMS_TRY()
 *     a = malloc(sizeof(my_struct_t));
 *     OMS_THROW_IF(!a, OMS_MEMORY);  // Throw without message
 *
 *     int b = -1;
 *     // get_b_value() returns oms_rc
 *     OMS_THROW_WITH_MSG(get_b_value(&b), "Could not get b");
 *
 *     a->b = b;
 *   OMS_CATCH()
 *   {
 *     free(a);
 *     a = NULL;
 *   }
 *   OMS_DONE(status)
 *
 *   // Assign output parameter
 *   *output_parameter = a;
 *
 *   return status;
 * }
 */
#define OMS_TRY() \
  oms_rc status_; \
  bool status_set_ = false;
#define OMS_CATCH() \
  catch_error: \
  if (!status_set_) { \
    DEBUG_LOG("status_ was never set, which means no THROW call was used"); \
    status_ = OMS_OK; \
  } \
  if (status_ != OMS_OK) { \
    DEBUG_LOG("Caught error %d", status_);
#define OMS_DONE(status) \
  } \
  status = status_;

#define OMS_THROW_IF(fail_condition, fail_status) \
  do { \
    status_ = (fail_condition) ? (fail_status) : OMS_OK; \
    status_set_ = true; \
    OMS_MAYBE_GOTO_CATCH_ERROR() \
  } while (0)
#define OMS_THROW(status) \
  do { \
    status_ = (status); \
    status_set_ = true; \
    OMS_MAYBE_GOTO_CATCH_ERROR() \
  } while (0)

#define OMS_THROW_IF_WITH_MSG(fail_condition, fail_status, fail_msg, ...) \
  do { \
    status_ = (fail_condition) ? (fail_status) : OMS_OK; \
    status_set_ = true; \
    OMS_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(fail_msg, ##__VA_ARGS__) \
  } while (0)
#define OMS_THROW_WITH_MSG(status, fail_msg, ...) \
  do { \
    status_ = status; \
    status_set_ = true; \
    OMS_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(fail_msg, ##__VA_ARGS__) \
  } while (0)

#endif  // __OMS_DEFINES_H__
