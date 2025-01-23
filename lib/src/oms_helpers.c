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
#define EC_PRIVATE_KEY_FILE "ec_signing.key"
#define EC_CERTIFICATE_FILE "ec_cert_chain.pem"
#define RSA_PRIVATE_KEY_FILE "rsa_signing.key"
#define RSA_CERTIFICATE_FILE "rsa_cert_chain.pem"
#define TRUSTED_CERTIFICATE_FILE "ca_ec.pem"

static bool
read_file_content(const char *filename, char **content, size_t *content_size)
{
  bool success = false;
  FILE *fp = NULL;
  char full_path[MAX_PATH_LENGTH] = {0};
  char cwd[MAX_PATH_LENGTH] = {0};

  *content = NULL;
  *content_size = 0;

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

  // Get certificate chain from folder tests/.
  strcat(full_path, cwd);
  strcat(full_path, "/tests/");
  strcat(full_path, filename);

  fp = fopen(full_path, "rb");
  if (!fp) {
    goto done;
  }

  fseek(fp, 0L, SEEK_END);
  size_t file_size = ftell(fp);
  rewind(fp);
  *content = malloc(file_size);
  if (!(*content)) {
    goto done;
  }
  if (fread(*content, sizeof(char), file_size / sizeof(char), fp) == 0) {
    goto done;
  }
  *content_size = file_size;

  success = true;

done:
  if (fp) {
    fclose(fp);
  }
  if (!success) {
    free(*content);
  }

  return success;
}

bool
oms_read_test_private_key_and_certificate(bool ec_key,
    char **private_key,
    size_t *private_key_size,
    char **certificate_chain,
    size_t *certificate_chain_size)
{
  bool success = false;
  const char *private_key_name = ec_key ? EC_PRIVATE_KEY_FILE : RSA_PRIVATE_KEY_FILE;
  const char *certificate_name = ec_key ? EC_CERTIFICATE_FILE : RSA_CERTIFICATE_FILE;

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

  if (private_key) {
    if (!read_file_content(private_key_name, private_key, private_key_size)) {
      goto done;
    }
  }

  if (certificate_chain) {
    if (!read_file_content(certificate_name, certificate_chain, certificate_chain_size)) {
      goto done;
    }
  }

  success = true;

done:
  if (!success) {
    if (private_key) {
      free(*private_key);
    }
    if (certificate_chain) {
      free(*certificate_chain);
    }
  }

  return success;
}

bool
oms_read_test_trusted_certificate(char **certificate, size_t *certificate_size)
{
  if (!certificate || !certificate_size) {
    return false;
  }

  return read_file_content(TRUSTED_CERTIFICATE_FILE, certificate, certificate_size);
}
