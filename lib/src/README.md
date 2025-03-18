*Copyright (c) 2025 ONVIF. All rights reserved.*

# Using the ONVIF Media Signing Framework library
The ONVIF Media Signing Framework handles both the signing part as well as the validation
part. All public APIs needed are located in [includes/](./includes/).

## Making your own validation application
The APIs needed are
[onvif_media_signing_common.h](./includes/onvif_media_signing_common.h) and
[onvif_media_signing_validator.h](./includes/onvif_media_signing_validator.h).
To validate an H.264 or an H.265 video you need to split the video into NAL Units. For a
detailed description and example code see
[onvif_media_signing_validator.h](./includes/onvif_media_signing_validator.h) or look at
the validator application in [examples/apps/validator](../../examples/apps/validator/).

## Making your own signing application
The APIs needed are
[onvif_media_signing_common.h](./includes/onvif_media_signing_common.h) and
[onvif_media_signing_signer.h](./includes/onvif_media_signing_signer.h).
To sign an H.264 or an H.265 video you need to split the video into NAL Units. Before
signing can begin you need to configure the ONVIF Media Signing session. Setting a private
key and a certificate chain is mandatory, but there are also possibilities to add some
product information etc. to use. The public key, needed for validation, is automatically
added to the stream through its certificate chain. The library removes the anchor
certificate from the certificate chain before put in a generated SEI.

The ONVIF Media Signing Framework generates SEI frames including signatures and other
information. Getting them and instructions on how to add them to the current stream are
handled through the API `onvif_media_signing_get_sei()`. Note that the framework follows
the Access Unit format of H.264, hence SEI frames must prepend the NAL Unit slices.

For a detailed description and example code see
[onvif_media_signing_signer.h](./includes/onvif_media_signing_signer.h) or look at the
signer application in the
[examples/apps/signer](../../examples/apps/signer/) where signing is implemented as a
GStreamer element.

## Making your own signing plugin
There is no signing plugin management in the ONVIF Media Signing Framework. It builds with
the plugin specified by the meson option `signingplugin`. If no signing plugin is
specified [unthreaded-signing/plugin.c](../plugins/unthreaded-signing/plugin.c) is used.
For more information see [lib/plugins/](../plugins/).
