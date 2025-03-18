*Copyright (c) 2025 ONVIF. All rights reserved.*

# Media Signing Framework examples

## Getting started with the example applications
This folder contains a set of application examples which aims to enrich the developers
implementation experience. All examples are using the [library](../lib/) code.

This repository uses meson + ninja as default build method. Further, all application
examples uses GStreamer APIs. Hence, the prerequisites for building any application are
- [meson](https://mesonbuild.com/Getting-meson.html) Getting meson and ninja. Meson
version 0.49.0 or newer is required.
- [GStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)
All applications are built around the GStreamer framework to handle encoded video.

## Example applications
Below is a list of example applications available in the repository.
- [signer](./apps/signer/)
  - The example code implements video signing.
- [validator](./apps/validator/)
  - The example code implements video authenticity validation by validating the
  authenticity and provenance of a video file.

### Building applications
The applications in this repository all have meson options for easy usage. These options
are by default disabled and the user can enable an arbitrary number of them.

Multiple applications can be built by adding multiple `-D` options, and for convenience,
the option `-Dbuild_all_apps=true` builds all available applications.
Note that some applications require additional environment variables set, for example,
`GST_PLUGIN_PATH`; See, individual application README.md.

#### Example meson commands on Linux
These example commands assume the current directory is `media-signing-framework`.
Build and install the `<application>` as
```
meson setup --prefix $PWD/my_installs -D<application>=true . build_apps
meson install -C build_apps
```
The executable is now located at `./my_installs/bin/<application>`

## Example files
Shorter MP4 recordings for testing can be found in [test-files/](./test-files/).
