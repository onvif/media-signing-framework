*Copyright (C) 2024, ????*

# Using the ONVIF Signed Media Framework library
The ONVIF Signed Media Framework handles both the signing part as well as the validation
part. All public APIs needed are located in [includes/](./includes/).

## Making your own validation application
The APIs needed are
[onvif_media_signing_common.h](./includes/onvif_media_signing_common.h) and
[onvif_media_signing_validator.h](./includes/onvif_media_signing_validator.h).
To validate an H.264 or an H.265 video you need to split the video into NAL Units. For a
detailed description and example code see
[onvif_media_signing_validator.h](./includes/onvif_media_signing_validator.h) or look at
the validator application in the
[examples/apps/validator](../../examples/apps/validator/).

## Making your own signing application
The APIs needed are
[onvif_media_signing_common.h](./includes/onvif_media_signing_common.h),
[onvif_media_signing_signer.h](./includes/onvif_media_signing_signer.h) and
[onvif_media_signing_signer.h](./includes/onvif_media_signing_plugin.h).
To sign an H.264 or an H.265 video you need to split the video into NAL Units. Before
signing can begin you need to configure the ONVIF Media Signing session. Setting a private
key is mandatory, but there are also possibilities to add some product information etc. to
use. The public key, needed for validation, is automatically added to the stream through
its certificate chain.

The ONVIF Signed Media Framework generates SEI frames including signatures and other
information. Getting them and instructions on how to add them to the current stream are
handled through the API `onvif_media_signing_get_sei()`. Note that the framework follows
the Access Unit format of H.264, hence SEI frames must prepend the NAL Unit slices.

For a detailed description and example code see
[onvif_media_signing_signer.h](./includes/onvif_media_signing_signer.h) or look at the
signer application in the
[examples/apps/signer](../../examples/apps/signer/) where signing is implemented as a
gStreamer element.

## Making your own signing plugin
There is no signing plugin management in the ONVIF Signed Media Framework. It currently
builds with the [unthreaded-signing/plugin.c](../plugins/unthreaded-signing/plugin.c) by
default. For more information see [lib/plugins/](../plugins/).
