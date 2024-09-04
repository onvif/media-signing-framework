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

#include <stdio.h>  // FILE, fseek, ftell, rewind, fread, fclose
#include <stdlib.h>  // malloc, free
#include <string.h>  // memset, strcat, strstr
#if defined(_WIN32) || defined(_WIN64)
#include <direct.h>
#define getcwd _getcwd  // "deprecation" warning
#else
#include <unistd.h>  // getcwd
#endif

#include "includes/onvif_media_signing_helpers.h"

#define MAX_PATH_LENGTH 500
#define EC_PRIVATE_KEY_ALLOC_BYTES 1000
#define RSA_PRIVATE_KEY_ALLOC_BYTES 2000
#define EC_PRIVATE_KEY_FILE "signing_key_ec.key"
#define EC_CERTIFICATE_FILE "signing_cert_ec.crt"
#define RSA_PRIVATE_KEY_FILE "signing_key_rsa.key"
#define RSA_CERTIFICATE_FILE "signing_cert_rsa.crt"

bool
oms_read_private_key_and_certificate(bool ec_key,
    char **private_key,
    size_t *private_key_size,
    char **certificate_chain,
    size_t *certificate_chain_size)
{
  bool success = false;
  FILE *fp_key = NULL;
  FILE *fp_cert = NULL;
  const char *private_key_name = ec_key ? EC_PRIVATE_KEY_FILE : RSA_PRIVATE_KEY_FILE;
  const char *certificate_name = ec_key ? EC_CERTIFICATE_FILE : RSA_CERTIFICATE_FILE;
  char full_path_to_private_key[MAX_PATH_LENGTH] = {0};
  char full_path_to_cert[MAX_PATH_LENGTH] = {0};
  char cwd[MAX_PATH_LENGTH] = {0};

  // At least one of private key and certificate has to be possible to set.
  if ((!private_key || !private_key_size) &&
      (!certificate_chain || !certificate_chain_size)) {
    goto done;
  }
  // Either both are NULL pointers or none.
  if (!private_key ^ !private_key_size) {
    goto done;
  }
  // Either both are NULL pointers or none.
  if (!certificate_chain ^ !certificate_chain_size) {
    goto done;
  }

  if (private_key)
    *private_key = NULL;
  if (private_key_size)
    *private_key_size = 0;
  if (certificate_chain)
    *certificate_chain = NULL;
  if (certificate_chain_size)
    *certificate_chain_size = 0;

  if (!getcwd(cwd, sizeof(cwd))) {
    goto done;
  }

  // Find the root location of the library.
  char *lib_root = NULL;
  char *next_lib_root = strstr(cwd, "signed-media-framework");
  while (next_lib_root) {
    lib_root = next_lib_root;
    next_lib_root = strstr(next_lib_root + 1, "signed-media-framework");
  }
  if (!lib_root) {
    goto done;
  }
  // Terminate string after lib root.
  memset(lib_root + strlen("signed-media-framework"), '\0', 1);

  if (private_key) {
    // Get private signing key from folder tests/.
    strcat(full_path_to_private_key, cwd);
    strcat(full_path_to_private_key, "/tests/");
    strcat(full_path_to_private_key, private_key_name);

    fp_key = fopen(full_path_to_private_key, "rb");
    if (!fp_key) {
      goto done;
    }

    fseek(fp_key, 0L, SEEK_END);
    size_t key_size = ftell(fp_key);
    rewind(fp_key);
    *private_key = malloc(key_size);
    if (!(*private_key)) {
      goto done;
    }
    fread(*private_key, sizeof(char), key_size / sizeof(char), fp_key);
    *private_key_size = key_size;
  }

  if (certificate_chain) {
    // Get certificate chain from folder tests/.
    strcat(full_path_to_cert, cwd);
    strcat(full_path_to_cert, "/tests/");
    strcat(full_path_to_cert, certificate_name);

    fp_cert = fopen(full_path_to_cert, "rb");
    if (!fp_cert) {
      goto done;
    }

    fseek(fp_cert, 0L, SEEK_END);
    size_t cert_size = ftell(fp_cert);
    rewind(fp_cert);
    *certificate_chain = malloc(cert_size);
    if (!(*certificate_chain)) {
      goto done;
    }
    fread(*certificate_chain, sizeof(char), cert_size / sizeof(char), fp_cert);
    *certificate_chain_size = cert_size;
  }

  success = true;

done:
  if (fp_key) {
    fclose(fp_key);
  }
  if (fp_cert) {
    fclose(fp_cert);
  }
  if (!success) {
    free(*private_key);
    free(*certificate_chain);
  }

  return success;
}
