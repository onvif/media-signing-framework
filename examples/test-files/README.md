*Copyright (c) 2025 ONVIF. All rights reserved.*

# Media Signing Framework example test files

These files can be used to test the signer and/or validator applications, or verify
integrations in devices and clients.

- *ca.pem*: The trusted anchor certificate of the public key certificate chain for the
signed test files.
- *test_h264.mp4*: Unsigned H.264 recording in an mp4 container.
- *test_h265.mp4*: Unsigned H.265 recording in an mp4 container.
- *test_signed_h264.mp4*: Signed H.264 recording in an mp4 container following the ONVIF
Media Signing specification with deafult settings. Certificate-SEIs are not applied.
- *test_signed_h265.mp4*: Signed H.265 recording in an mp4 container following the ONVIF
Media Signing specification with deafult settings. Certificate-SEIs are not applied.
