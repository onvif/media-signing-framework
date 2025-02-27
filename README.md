*Copyright (c) 2025 ONVIF. All rights reserved.*

# ONVIF Media Signing Framework
This repository holds the framework code of the feature ONVIF Media Signing. The ONVIF
Media Signing feature secures the video from tampering after signing by adding
cryptographic signatures to the video. Each video frame is hashed and signatures are
generated repeatedly based on these hashes, using a private key set by the signer. The
signature data added to the video does not affect the video rendering. The data is added
in a Supplemental Enhancement Information (SEI) NAL Unit of type "user data unregistered".
This SEI has a UUID of `005bc93f-2d71-5e95-ada4-796f90877a6f`.

For a more detailed description of the ONVIF Media Signing feature see the Media Signing
specification at
[onvif.org/profiles/specifications/](https://www.onvif.org/specs/stream/ONVIF-MediaSigning-Spec.pdf).

## File structure
```
media-signing-framework
├── examples
├── lib
|   ├── plugins
|   |   ├── threaded-signing
|   |   |   └── plugin.c
|   |   └── unthreaded-signing
|   |       └── plugin.c
|   └── src
|       ├── includes
|       |   └── public header files
|       └── source files
└── tests
```

The repository is split into three parts; a library accompanied by tests and examples. The
library is further organized in [source code](./lib/src/) and [plugins](./lib/plugins/).
The source code includes all necessary source files for both signing and validation, and
there is no conceptual difference in building the library for signing or for validation
(device or client).

The signing part is in general device specific, in particular in how the private key is
accessed and used for signing. Therefore, the framework uses the concept of signing
plugins which implements a set of
[interfaces](./lib/src/includes/onvif_media_signing_plugin.h). The framework comes with
both a threaded and an unthreaded signing plugin.

For instructions on how to use the APIs to integrate the ONVIF Media Signing Framework in
either a signing or a validation application, see [lib/](./lib/). Example applications are
available in [examples](./examples/).

# Releases
There are no pre-built releases. The user is encouraged to build the library from a
[release tag](https://github.com/onvif/media-signing-framework/tags).

# Getting started
The build instructions in this repository is mainly targeted a Linux environment which
uses meson + ninja as default build method. OpenSSL is used for cryptographic operations
and to run unittests you need libcheck. The automatic tests through github workflow
actions run in Linux. For Windows build instructions with Visual Studio see
[VS2022](./VS2022/).

## Prerequisites
To use the included meson build structure
- [meson](https://mesonbuild.com/Getting-meson.html) Getting meson and ninja. Meson
version 0.49.0 or newer is required.

Mandatory third party libraries
- [OpenSSL](https://openssl-library.org/) The default library to handle keys, hashes,
certificates and signatures. OpenSSL version 3.0.0 or newer is required.
Optional third party libraries
- [libcheck](https://libcheck.github.io/check/) The framework for unittests.
- [glib-2.0](https://docs.gtk.org/glib/) To build the library with signing in a separate
thread.
- [gStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)
To build the example applications in this repository.

# Build Instructions
Below are meson instructions on how to build for either signing or validation. For help on
meson usage see [mesonbuild.com](https://mesonbuild.com/). The meson instructions in this
repository will create a shared library named `libmedia-signing-framework`.

This repository comes with some additional [meson options](./meson_options.txt) to assist
in configuration.
Library related options
- _debugprints_: Runs with debug prints (default off).
- _signingplugin_: Selects one of the available signing plugins. Three alternatives;
unthreaded (default), threaded or threaded_unless_check_dep. The last setting will use the
threaded plugin unless a dependency on libcheck is detected, for which it falls back to
the unthreaded plugin.
Example application related options
- _signer_: Builds the signer example application (default off).
- _validator_: Builds the validator example application (default off).
- _build_all_apps_: Builds all applications above (default off).
- _parsesei_: Builds an application that will make the application (primarily the validator)
to parse and display the information of incoming SEIs. Default off.

## Configure with meson
```
meson setup path/to/media-signing-framework path/to/build/folder
```
will generate compile instructions for ninja and put them in a folder located at
`path/to/build/folder`. To turn on debug prints use the `debugprints` option
```
meson setup -Ddebugprints=true path/to/media-signing-framework path/to/build/folder
```
With the `--prefix` meson option it is possible to specify an arbitrary location to where
the shared library is installed.
```
meson setup --prefix /absolute/path/to/your/local/installs path/to/media-signing-framework path/to/build/folder
```

## Compile and install the shared library
To compile media-signing-framework using ninja
```
ninja -C path/to/build/folder
```
and the object file is located at
`path/to/build/folder/lib/src/libmedia-signing-framework.so`. To install the shared library
run
```
meson install -C build
```
The library, named `libmedia-signing-framework`, will be installed where libraries are
installed, or at `path/to/your/local/installs` if you configured meson with `--prefix`.
The header files will be located in a sub-folder of `includes` named
`media-signing-framework`.

## Example build commands on Linux
1. Configure and compile into `./build` without installing from the top level of
`media-signing-framework/`
```
meson setup . build
ninja -C build
```
2. Configure, compile and install in `./my_installs/` from the parent folder of
`media-signing-framework/`
```
meson setup --prefix $PWD/my_installs media-signing-framework build
meson install -C build
```

## Configure, build and run unittests
Nothing extra part from having libcheck installed is needed. Hence, to build and run the
unittests do
```
meson setup . build
ninja -C build test
```
Alternatively, you can run the script
[tests/run_check_tests.sh](./tests/run_check_tests.sh) and the unittests will run both
with and without debug prints.

# License
[MIT License](./LICENSE).
