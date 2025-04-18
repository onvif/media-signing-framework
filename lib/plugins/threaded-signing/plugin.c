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

/**
 * This signing plugin sets up a worker thread and calls openssl_sign_hash(), from the
 * worker thread, when there is a new hash to sign. To handle several signatures at the
 * same time, the plugin has two buffers. One for incomming hashes and another one for
 * outgoing signatures. The thread is stopped if 1) the out buffer is full, 2) there was a
 * failure in the memory allocation for a new signature or 3)
 * onvif_media_signing_plugin_session_teardown() is called.
 *
 * If the plugin is initialized, onvif_media_signing_plugin_init(), one single central
 * thread is spawned. Each ONVIF Media Signing session will then get an id to distiguish
 * between them since they use common input and output buffers. The thread is stopped if
 * 1) the out buffer is full, 2) there was a failure in the memory allocation for a new
 * signature or 3) onvif_media_signing_plugin_exit() is called.
 */

#include <assert.h>
#include <glib.h>
#include <stdbool.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // calloc, malloc, free
#include <string.h>  // memcpy

#include "includes/onvif_media_signing_plugin.h"
#include "oms_openssl_internal.h"

// This means that the signing plugin can handle a blocked signing hardware up to, for
// example, 60 seconds if the GOP length is 1 second
#define MAX_BUFFER_LENGTH 60

// Structure for the input buffer of hashes
typedef struct _oms_hash_data_t {
  uint8_t *hash;
  size_t size;
  unsigned id;
} oms_hash_data_t;

// Structure for the output buffer of signatures
typedef struct _oms_signature_data_t {
  uint8_t *signature;
  size_t size;
  bool signing_error;
  unsigned id;
} oms_signature_data_t;

/* A data handle maintaining the thread, lock and buffers. It stores the hashes to sign
 * and the written signatures in two separate buffers. This structure is used for both
 * local and central signing. */
typedef struct _oms_threaded_data {
  GThread *thread;
  GMutex mutex;
  GCond cond;

  // Variables that have to be r/w under mutex lock.
  bool is_running;
  bool is_in_signing;
  // Buffer of hashes to sign
  oms_hash_data_t in[MAX_BUFFER_LENGTH];
  int in_idx;
  // Buffer of written signatures
  oms_signature_data_t out[MAX_BUFFER_LENGTH];
  int out_idx;
  // Variables that can operate without mutex lock.
  // A local copy of the sign_data is used for signing. The hash to be signed is copied to
  // it when it is time to sign.
  sign_or_verify_data_t *sign_data;
} oms_threaded_data_t;

/* A structure for keeping ONVIF Media Signing session dependent data when signing is
 * central. */
typedef struct _oms_central_threaded_data {
  unsigned id;
} oms_central_threaded_data_t;

/* Threaded plugin handle containing data for either a local signing or a central signing.
 */
typedef struct _oms_threaded_plugin {
  oms_central_threaded_data_t *central;
  oms_threaded_data_t *local;
} oms_threaded_plugin_t;

typedef struct _oms_id_node oms_id_node_t;
struct _oms_id_node {
  unsigned id;
  oms_id_node_t *prev;
  oms_id_node_t *next;
};

// Static members for a central thread
static oms_threaded_data_t central = {0};
// Session related variables
static unsigned last_added_id = 0;
static unsigned id_in_signing = 0;
static oms_id_node_t *id_list = NULL;

/*
 * Helper functions common to both a local and a central thread.
 */

/* Frees the memory of |sign_data|. */
static void
sign_data_free(sign_or_verify_data_t *sign_data)
{
  if (!sign_data)
    return;

  openssl_free_key(sign_data->key);
  free(sign_data->signature);
  free(sign_data->hash);
  free(sign_data);
}

/* Resets a hash_data_t element. */
static void
reset_hash_buffer(oms_hash_data_t *buf)
{
  buf->id = 0;
}

/* Resets a signature_data_t element. */
static void
reset_signature_buffer(oms_signature_data_t *buf)
{
  buf->size = 0;  // Note: the size of the allocated signature is handled by |sign_data|
  buf->id = 0;
  buf->signing_error = false;
}

/* Reset and free memory in a hash_data_t element. */
static void
free_hash_buffer(oms_hash_data_t *buf)
{
  reset_hash_buffer(buf);
  free(buf->hash);
  buf->hash = NULL;
  buf->size = 0;
}

/* Reset and free memory in a signature_data_t element. */
static void
free_signature_buffer(oms_signature_data_t *buf)
{
  reset_signature_buffer(buf);
  free(buf->signature);
  buf->signature = NULL;
}

/* Free all memory of input and ourput buffers. */
static void
free_buffers(oms_threaded_data_t *self)
{
  for (int i = 0; i < MAX_BUFFER_LENGTH; i++) {
    free_signature_buffer(&self->out[i]);
    free_hash_buffer(&self->in[i]);
  }
  self->in_idx = 0;
  self->out_idx = 0;
}

/* Frees all allocated memory and resets members. Excluded are the worker thread members
 * |thread|, |mutex|, |cond| and |is_running|. */
static void
free_plugin(oms_threaded_data_t *self)
{
  sign_data_free(self->sign_data);
  self->sign_data = NULL;

  free_buffers(self);
}

/* This function is, via onvif_media_signing_plugin_sign(), called from the library upon
 * signing.
 *
 * If this is the first time of signing, memory for |self->sign_data->hash| is allocated.
 * The |hash| is copied to |in|. If memory for the |in| hash has not been allocated it
 * will be allocated. */
static MediaSigningReturnCode
sign_hash(oms_threaded_data_t *self, unsigned id, const uint8_t *hash, size_t hash_size)
{
  assert(self && hash);
  MediaSigningReturnCode status = OMS_UNKNOWN_FAILURE;
  g_mutex_lock(&self->mutex);
  int idx = self->in_idx;

  if (idx >= MAX_BUFFER_LENGTH) {
    // |in| is full. Buffers this long are not supported.
    status = OMS_NOT_SUPPORTED;
    goto done;
  }

  if (!self->is_running) {
    // Thread is not running. Go to catch_error and return status.
    status = OMS_EXTERNAL_ERROR;
    goto done;
  }

  // Signing from a central thread. The |sign_data| should have been allocated when
  // the plugin was initialized.
  assert(self->sign_data);
  // Allocate memory for the hash slot in |sign_data| if this is the first time,
  // since it is now known to the signing plugin and cannot be changed.
  if (!self->sign_data->hash) {
    self->sign_data->hash = calloc(1, hash_size);
    if (!self->sign_data->hash) {
      // Failed in memory allocation.
      status = OMS_MEMORY;
      goto done;
    }
    self->sign_data->hash_size = hash_size;
  }

  if (!self->in[idx].hash) {
    self->in[idx].hash = calloc(1, hash_size);
    if (!self->in[idx].hash) {
      // Failed in memory allocation.
      status = OMS_MEMORY;
      goto done;
    }
    self->in[idx].size = hash_size;
  }

  // The |hash_size| has to be fixed throughout the session.
  if (self->in[idx].size != hash_size) {
    status = OMS_NOT_SUPPORTED;
    goto done;
  }

  // Copy the |hash| ready for signing.
  memcpy(self->in[idx].hash, hash, hash_size);
  self->in[idx].id = id;
  self->in_idx++;

  status = OMS_OK;

done:

  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  return status;
}

/* If
 *   1. the |id| matches the oldest |out|, and
 *   2. the signature in |out| has been copied to |signature|
 * then returns true, otherwise false.
 * Moves the signatures in |out| forward when the copy is done. */
static bool
get_signature(oms_threaded_data_t *self,
    unsigned id,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    MediaSigningReturnCode *error)
{
  assert(self && signature && written_signature_size);

  bool has_copied_signature = false;
  MediaSigningReturnCode status = OMS_OK;

  g_mutex_lock(&self->mutex);

  if (!self->is_running) {
    // Thread is not running. Go to done and return error.
    status = OMS_EXTERNAL_ERROR;
    goto done;
  }

  // Return if there are no signatures in the buffer
  if (self->out_idx == 0)
    goto done;

  // Return if next signature belongs to a different session.
  if (self->out[0].id != id)
    goto done;

  *written_signature_size = 0;
  if (self->out[0].signing_error) {
    // Propagate OMS_EXTERNAL_ERROR when signing failed.
    status = OMS_EXTERNAL_ERROR;
  } else if (self->out[0].size > max_signature_size) {
    // There is no room to copy the signature, set status to invalid parameter.
    status = OMS_INVALID_PARAMETER;
  } else {
    // Copy the oldest signature
    memcpy(signature, self->out[0].signature, self->out[0].size);
    *written_signature_size = self->out[0].size;
    // Mark as copied.
    has_copied_signature = true;
  }
  // Move buffer
  oms_signature_data_t tmp = self->out[0];
  reset_signature_buffer(&tmp);
  int i = 1;
  while (i < MAX_BUFFER_LENGTH) {
    self->out[i - 1] = self->out[i];
    i++;
  }
  self->out[MAX_BUFFER_LENGTH - 1] = tmp;
  self->out_idx--;

done:
  g_mutex_unlock(&self->mutex);

  if (error)
    *error = status;

  return has_copied_signature;
}

/*
 * Helper functions for a central thread.
 */

/* Goes through the list of active sessions and returns true if id exists. This function
 * has to be called under a lock. */
static bool
is_active(unsigned id)
{
  bool found_id = false;
  oms_id_node_t *item = id_list;
  while (item && !found_id) {
    if (item->id == id) {
      found_id = true;
    }
    item = item->next;
  }
  return found_id;
}

/* Appends the |item| to the |id_list| of active sessions. This function has to be called
 * under a lock. */
static void
append_item(oms_id_node_t *item)
{
  oms_id_node_t *cur = id_list;
  while (cur->next)
    cur = cur->next;
  item->prev = cur;
  cur->next = item;
}

/* Delete the item of the |id_list| corresponding to the active session with |id|. This
 * function has to be called under a lock. */
static void
delete_item(unsigned id)
{
  oms_id_node_t *item = id_list;
  while (item && (item->id != id))
    item = item->next;
  if (item) {
    (item->prev)->next = item->next;
    if (item->next)
      (item->next)->prev = item->prev;
    free(item);
  }
}

/* Resets all elements of input and output buffers with correct |id|. */
static void
buffer_reset(unsigned id)
{
  int i = 0;
  while (i < MAX_BUFFER_LENGTH) {
    if (central.out[i].id == id) {
      // Found an element with correct id. Reset element and move to the back of buffer.
      oms_signature_data_t tmp = central.out[i];
      reset_signature_buffer(&tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.out[j - 1] = central.out[j];
        j++;
      }
      central.out[j - 1] = tmp;
      if (i < central.out_idx)
        central.out_idx--;
    } else {
      i++;
    }
  }

  i = 0;
  while (i < MAX_BUFFER_LENGTH) {
    if (central.in[i].id == id) {
      // Found an element with correct id. Reset element and move to the back of buffer.
      oms_hash_data_t tmp = central.in[i];
      reset_hash_buffer(&tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.in[j - 1] = central.in[j];
        j++;
      }
      central.in[j - 1] = tmp;
      if (i < central.in_idx)
        central.in_idx--;
    } else {
      i++;
    }
  }
}

/* The worker thread waits for a condition signal, triggered when there is a hash to sign.
 */
static void *
central_worker_thread(void *user_data)
{
  if (user_data != NULL)
    return NULL;

  g_mutex_lock(&(central.mutex));
  if (central.is_running)
    goto done;

  central.is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&(central.cond));

  while (central.is_running) {
    if (central.in_idx > 0) {
      MediaSigningReturnCode status = OMS_UNKNOWN_FAILURE;
      // Get the oldest hash from the input buffer
      // Copy the hash to |sign_data| and start signing.
      assert(central.in[0].size == central.sign_data->hash_size);
      assert(central.sign_data->hash);
      memcpy(central.sign_data->hash, central.in[0].hash, central.in[0].size);
      id_in_signing = central.in[0].id;

      // Move the oldest input buffer to end of queue for reuse at a later stage.
      oms_hash_data_t tmp = central.in[0];
      reset_hash_buffer(&tmp);
      int j = 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.in[j - 1] = central.in[j];
        j++;
      }
      central.in[MAX_BUFFER_LENGTH - 1] = tmp;
      central.in_idx--;

      // Let the signing operate outside a lock. Otherwise
      // onvif_media_signing_plugin_get_signature() is blocked, since variables need to be
      // read under a lock.
      central.is_in_signing = true;
      g_mutex_unlock(&(central.mutex));
      status = openssl_sign_hash(central.sign_data);
      g_mutex_lock(&(central.mutex));
      central.is_in_signing = false;

      if (!is_active(id_in_signing)) {
        // If the current |id| is no longer active, discard the generated signature and
        // move on.
        continue;
      }

      int idx = central.out_idx;
      if (idx >= MAX_BUFFER_LENGTH) {
        // |out| is full. Buffers this long are not supported.
        // There are no means to signal an error to the signing session. Flush all buffers
        // for this id and move on.
        status = OMS_NOT_SUPPORTED;
        buffer_reset(id_in_signing);
        continue;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      central.out[idx].signing_error = (status != OMS_OK);
      central.out[idx].id = id_in_signing;

      // Allocate memory for the |signature| if necessary.
      if (!central.out[idx].signature) {
        central.out[idx].signature = calloc(1, central.sign_data->max_signature_size);
        if (!central.out[idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          status = OMS_MEMORY;
          central.is_running = false;
          free_buffers(&central);
          continue;
        }
      }

      if (status == OMS_OK) {
        // Copy the |signature| to the output buffer
        memcpy(central.out[idx].signature, central.sign_data->signature,
            central.sign_data->signature_size);
        central.out[idx].size = central.sign_data->signature_size;
      }
      central.out_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&(central.cond), &(central.mutex));
    }
  }

done:
  // Send a signal that thread has stopped.
  g_cond_signal(&(central.cond));
  g_mutex_unlock(&(central.mutex));

  return NULL;
}

/* This function creates an id for the session to identify hashes and signatures.
 *
 * returns central_threaded_data_t upon success, and NULL upon failure. */
static oms_central_threaded_data_t *
central_setup()
{
  oms_central_threaded_data_t *self = calloc(1, sizeof(oms_central_threaded_data_t));

  if (!self)
    return NULL;

  g_mutex_lock(&(central.mutex));

  // Make sure that the thread is running.
  if (!central.is_running)
    goto catch_error;

  // Find first available id after the last added one and add to list of active sessions.
  unsigned id = ((last_added_id + 1) == 0) ? 1 : (last_added_id + 1);
  // Pick the first inactive id.
  while (is_active(id) && (id != last_added_id)) {
    id++;
    if (id == 0) {
      // The |id| wrapped around and zero |id| is not allowed
      id++;
    }
  }
  if (id == last_added_id) {
    goto catch_error;
  }
  last_added_id = id;

  oms_id_node_t *item = (oms_id_node_t *)calloc(1, sizeof(oms_id_node_t));
  if (!item)
    goto catch_error;

  item->id = id;
  append_item(item);
  self->id = id;

  g_mutex_unlock(&(central.mutex));

  return self;

catch_error:
  g_mutex_unlock(&(central.mutex));
  free(self);
  return NULL;
}

static void
central_teardown(oms_central_threaded_data_t *self)
{
  g_mutex_lock(&(central.mutex));
  buffer_reset(self->id);
  delete_item(self->id);
  g_mutex_unlock(&(central.mutex));

  free(self);
}

/*
 * Helper functions for a local thread.
 */

/* The worker thread waits for a condition signal, triggered when there is a hash to sign.
 */
static void *
local_worker_thread(void *user_data)
{
  oms_threaded_data_t *self = (oms_threaded_data_t *)user_data;

  g_mutex_lock(&self->mutex);
  if (self->is_running)
    goto done;

  self->is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&self->cond);

  while (self->is_running) {
    if (self->in_idx > 0) {
      // Get the oldest hash from the input buffer
      // Copy the hash to |sign_data| and start signing.
      assert(self->in[0].size == self->sign_data->hash_size);
      assert(self->sign_data->hash);
      memcpy(self->sign_data->hash, self->in[0].hash, self->in[0].size);

      // Move the oldest input buffer to end of queue for reuse at a later stage.
      oms_hash_data_t tmp = self->in[0];
      int j = 0;
      while (self->in[j + 1].hash != NULL && j < MAX_BUFFER_LENGTH - 1) {
        self->in[j] = self->in[j + 1];
        j++;
      }
      self->in[j] = tmp;
      self->in_idx--;

      // Let the signing operate outside a lock. Otherwise
      // onvif_media_signing_plugin_get_signature() is blocked, since variables need to be
      // read under a lock.
      self->is_in_signing = true;
      g_mutex_unlock(&self->mutex);
      MediaSigningReturnCode status = openssl_sign_hash(self->sign_data);
      g_mutex_lock(&self->mutex);
      self->is_in_signing = false;

      int idx = self->out_idx;
      if (idx >= MAX_BUFFER_LENGTH) {
        // |out| is full. Buffers this long are not supported.
        self->is_running = false;
        free_plugin(self);
        goto done;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      self->out[idx].signing_error = (status != OMS_OK);

      // Allocate memory for the |signature| if necessary.
      if (!self->out[idx].signature) {
        self->out[idx].signature = calloc(1, self->sign_data->max_signature_size);
        if (!self->out[idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          self->is_running = false;
          free_plugin(self);
          goto done;
        }
      }

      if (status == OMS_OK) {
        // Copy the |signature| to the output buffer
        memcpy(self->out[idx].signature, self->sign_data->signature,
            self->sign_data->signature_size);
        self->out[idx].size = self->sign_data->signature_size;
      }
      self->out_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&self->cond, &self->mutex);
    }
  }

done:
  // Send a signal that thread has stopped.
  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  return NULL;
}

/* This function starts a local worker thread for signing.
 *
 * returns oms_threaded_data_t upon success, and NULL upon failure. */
static oms_threaded_data_t *
local_setup(const void *private_key, size_t private_key_size)
{
  oms_threaded_data_t *self = calloc(1, sizeof(oms_threaded_data_t));

  if (!self)
    return NULL;

  // Setup |sign_data| with |private_key| if there is one
  if (private_key && private_key_size > 0 && !self->sign_data) {
    self->sign_data = calloc(1, sizeof(sign_or_verify_data_t));
    if (!self->sign_data)
      goto catch_error;
    // Turn the PEM |private_key| into an EVP_PKEY and allocate memory for signatures.
    if (openssl_store_private_key(self->sign_data, private_key, private_key_size) !=
        OMS_OK) {
      goto catch_error;
    }
  }

  // Initialize |self|.
  g_mutex_init(&(self->mutex));
  g_cond_init(&(self->cond));

  self->thread =
      g_thread_try_new("local-signing", local_worker_thread, (void *)self, NULL);

  if (!self->thread)
    goto catch_error;

  // Wait for the thread to start before returning.
  g_mutex_lock(&self->mutex);
  // TODO: Consider using g_cond_wait_until() instead, to avoid potential deadlock.
  while (!self->is_running)
    g_cond_wait(&self->cond, &self->mutex);

  g_mutex_unlock(&self->mutex);

  return self;

catch_error:
  free_plugin(self);
  return NULL;
}

static void
local_teardown_locked(oms_threaded_data_t *self)
{
  if (!self->thread) {
    g_mutex_unlock(&self->mutex);
    goto done;
  }

  GThread *thread = self->thread;

  self->is_running = false;
  self->thread = NULL;

  // Wait (at most 2 seconds) for an ongoing signing to complete
  int64_t end_time = g_get_monotonic_time() + 2 * G_TIME_SPAN_SECOND;
  while (self->is_in_signing) {
    if (!g_cond_wait_until(&self->cond, &self->mutex, end_time)) {
      // timeout has passed.
      break;
    }
  }
  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  g_thread_join(thread);

done:
  free_plugin(self);
}

/**
 * Definitions of declared interfaces. For declarations see onvif_media_signing_plugin.h.
 */

MediaSigningReturnCode
onvif_media_signing_plugin_sign(void *handle, const uint8_t *hash, size_t hash_size)
{
  oms_threaded_plugin_t *self = (oms_threaded_plugin_t *)handle;

  if (!self || !hash || hash_size == 0)
    return OMS_INVALID_PARAMETER;

  if (self->local) {
    return sign_hash(self->local, 0, hash, hash_size);
  } else if (self->central) {
    return sign_hash(&central, self->central->id, hash, hash_size);
  } else {
    return OMS_NOT_SUPPORTED;
  }
}

bool
onvif_media_signing_plugin_get_signature(void *handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    MediaSigningReturnCode *error)
{
  oms_threaded_plugin_t *self = (oms_threaded_plugin_t *)handle;

  if (!self || !signature || !written_signature_size)
    return false;

  if (self->local) {
    return get_signature(
        self->local, 0, signature, max_signature_size, written_signature_size, error);
  } else if (self->central) {
    return get_signature(&central, self->central->id, signature, max_signature_size,
        written_signature_size, error);
  } else {
    *error = OMS_NOT_SUPPORTED;
    return false;
  }
}

void *
onvif_media_signing_plugin_session_setup(const void *private_key, size_t private_key_size)
{
  oms_threaded_plugin_t *self = calloc(1, sizeof(oms_threaded_plugin_t));

  if (!self)
    return NULL;

  if (central.thread) {
    assert(id_list);
    self->central = central_setup();
    if (!self->central)
      goto catch_error;
  } else {
    // Setting a |private_key| is only necessary if setup to use separate threads for each
    // session.
    if (!private_key || private_key_size == 0)
      goto catch_error;

    self->local = local_setup(private_key, private_key_size);
    if (!self->local)
      goto catch_error;
  }

  return (void *)self;

catch_error:
  free(self);
  return NULL;
}

void
onvif_media_signing_plugin_session_teardown(void *handle)
{
  oms_threaded_plugin_t *self = (oms_threaded_plugin_t *)handle;
  if (!self)
    return;

  if (self->local) {
    g_mutex_lock(&(self->local)->mutex);
    local_teardown_locked(self->local);
    free(self->local);
    self->local = NULL;
  }
  if (self->central) {
    central_teardown(self->central);
    self->central = NULL;
  }
  free(self);
}

/* This plugin initializer expects the |user_data| to be a key_data_t struct. The
 * |private_key| will be used through all added sessions.
 *
 * A central thread is set up and a list, containing the IDs of the active sessions, is
 * initialized with an empty list head.
 */
int
onvif_media_signing_plugin_init(void *user_data)
{
  key_data_t *pem_private_key = (key_data_t *)user_data;

  if (central.thread || id_list || central.sign_data || !user_data) {
    // Central thread, id list or sign_data already exists. Or no |user_data| is set.
    return -1;
  }

  id_list = (oms_id_node_t *)calloc(1, sizeof(oms_id_node_t));
  if (!id_list)
    goto catch_error;

  central.sign_data = calloc(1, sizeof(sign_or_verify_data_t));
  if (!central.sign_data)
    goto catch_error;

  // Turn the PEM key into an EVP_PKEY and allocate memory for signatures.
  if (openssl_store_private_key(central.sign_data, (const char *)pem_private_key->key,
          pem_private_key->key_size) != OMS_OK) {
    goto catch_error;
  }

  g_mutex_init(&(central.mutex));
  g_cond_init(&(central.cond));

  central.thread = g_thread_try_new("central-signing", central_worker_thread, NULL, NULL);
  if (!central.thread)
    goto catch_error;

  // Wait for the thread to start before returning.
  g_mutex_lock(&(central.mutex));
  // TODO: Consider using g_cond_wait_until() instead, to avoid deadlock.
  while (!central.is_running)
    g_cond_wait(&(central.cond), &(central.mutex));

  g_mutex_unlock(&(central.mutex));
  return 0;

catch_error:
  sign_data_free(central.sign_data);
  central.sign_data = NULL;
  free(id_list);
  id_list = NULL;
  return -1;
}

/* This function closes down the plugin. No |user_data| is expected and aborts the action
 * if present.
 *
 * The thread is terminated and all allocated memory is freed.
 */
void
onvif_media_signing_plugin_exit(void *user_data)
{
  // User is not expected to pass in any data. Aborting.
  if (user_data)
    return;

  g_mutex_lock(&(central.mutex));

  if (id_list) {
    oms_id_node_t *item = id_list;
    while (item) {
      oms_id_node_t *next_item = item->next;
      free(item);
      item = next_item;
    }
    id_list = NULL;
  }

  local_teardown_locked(&central);
}
