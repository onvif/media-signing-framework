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

#ifndef __GST_SIGNING_H__
#define __GST_SIGNING_H__

#include <gst/base/gstbasetransform.h>
#include <gst/gst.h>

G_BEGIN_DECLS

#define GST_TYPE_SIGNING (gst_signing_get_type())
#define GST_SIGNING(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), GST_TYPE_SIGNING, GstSigning))
#define GST_SIGNING_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), GST_TYPE_SIGNING, GstSigningClass))
#define GST_IS_SIGNING(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), GST_TYPE_SIGNING))
#define GST_IS_SIGNING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), GST_TYPE_SIGNING))

typedef struct _GstSigning GstSigning;
typedef struct _GstSigningClass GstSigningClass;
typedef struct _GstSigningPrivate GstSigningPrivate;

struct _GstSigning {
  GstBaseTransform parent;
  GstSigningPrivate *priv;
};

struct _GstSigningClass {
  GstBaseTransformClass parent_class;
};

GType
gst_signing_get_type(void);

G_END_DECLS

#endif  // __GST_SIGNING_H__
