*Copyright (c) 2025 ONVIF. All rights reserved.*

# Media Signing Framework examples

## Getting started with the example applications
This folder contains a set of application examples which aims to enrich the developers
implementation experience. All examples are using the [library](../lib/) code.

This repository uses meson + ninja as default build method. Further, all application
examples uses GStreamer APIs. Hence, the prerequisites for building any application are
- [meson](https://mesonbuild.com/Getting-meson.html) Getting meson and ninja. Meson
version 0.56.0 or newer is required.
- [GStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)
All applications are built around the GStreamer framework to handle encoded video.
- [OpenSSL](https://openssl-library.org/) version 3.0.0 or newer. The library is built
together with the applications, so the mandatory library dependency applies here as well.

The `pkg-config` modules that have to be available are `gstreamer-1.0` and
`gstreamer-base-1.0` for the signer, `gstreamer-app-1.0` in addition for the validator,
and `openssl` for the library, so the GStreamer development files are required and not
only the runtime. As a worked example, on Debian and Ubuntu
```
sudo apt-get install build-essential pkg-config meson ninja-build libssl-dev \
    libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev
```

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

Enable every application you want in the same `meson setup` call, or give each one its own
build folder. Adding a `-D` option to a build folder that is already configured is not
reliable; meson answers `Directory already configured.` and exits 0, and up to and
including meson 0.53 the option is silently discarded, so the second application is never
built. To change an existing build folder use `meson setup --reconfigure`.

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
