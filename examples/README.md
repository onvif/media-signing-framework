*Copyright (C) 2024, ????*

# Signed Media Framework examples

## Getting started with the example applications
This folder contains a set of application examples which aims to enrich the developers
implementation experience. All examples are using the
[signed-media-framework](https://github.com/onvif/signed-media-framework); See the main
README on how to build and install it.

The repository uses meson + ninja as default build method. Further, all application
examples uses gStreamer APIs.
- [meson](https://mesonbuild.com/Getting-meson.html) Getting meson and ninja. Meson
version 0.49.0 or newer is required.
- [gStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)
All applications are built around the gStreamer framework to handle encoded video.

## Example applications
Below is a list of example applications available in the repository.
- [signer](./apps/signer/)
  - The example code implements video signing.
- [validator](./apps/validator/)
  - The example code implements video authenticity validation.

### Building applications
The applications in this repository all have meson options for easy usage. These options
are by default disabled and the user can enable an arbitrary number of them.

First you need to have the signed-media-framework library installed. Installing the shared
library and applications locally is in many cases preferably.

Assuming the signed-media-framework library is installed and accessible, build the
application with meson as
```
meson -D<application>=true path/to/signed-media-framework/examples path/to/build/folder
meson install -C path/to/build/folder
```
Multiple applications can be built by adding multiple `-D` options, and for convenience,
the option `-Dbuild_all_apps=true` builds all available applications.
Note that some applications require additional environment variables set, for example,
`GST_PLUGIN_PATH`; See, individual application README.md.

#### Example meson commands on Linux
These example commands assume the current directory is the parent directory of
`signed-media-framework`.
```
meson --prefix $PWD/my_installs signed-media-framework build_lib
meson install -C build_lib
```
Then build and install the `<application>` as
```
meson --prefix $PWD/my_installs -D<application>=true signed-media-framework/examples build_apps
meson install -C build_apps
```
The executable is now located at `./my_installs/bin/<application>`

## Example files
Shorter MP4 recordings for testing can be found in [test-files/](./test-files/).
