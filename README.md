*Copyright (C) 2024, ????*

# ONVIF Signed Media Framework
This repository holds the framework code of the feature ONVIF Media Signing. The ONVIF
Media Signing feature secures the video from tampering after signing by adding
cryptographic signatures to the video. Each video frame is hashed and signatures are
generated repeatedly based on these hashes, using a private key set by the signer. The
signature data added to the video does not affect the video rendering. The data is added
in a Supplemental Enhancement Information (SEI) NAL Unit of type "user data unregistered".
This SEI has a UUID of `005bc93f-2d71-5e95-ada4-796f90877a6f` in hexadecimal.

For a more detailed description of the ONVIF Media Signing feature see the specification
TODO: ADD REFERENCE TO SPECIFICATION.

## File structure
```
signed-media-framework
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

The repository is split into a library and tests. The library is further organized in
[source code](./lib/src/) and [plugins](./lib/plugins/). The source code includes all
necessary source files for both signing and validation, and there is no conceptual
difference in building the library for signing or for validation (device or client).

The signing part is in general device specific. Therefore, the framework uses the concept
of signing plugins which implements a set of
[interfaces](./lib/src/includes/onvif_media_signing_plugin.h). The framework comes with
both a threaded and an unthreaded signing plugin.

For instructions on how to use the APIs to integrate the ONVIF Media Signing Framework in
either a signing or a validation application, see [lib/](./lib/). Example applications are
available in [plugins](./lib/examples/).

# Releases
There are no pre-built releases. The user is encouraged to build the library from a
[release tag](https://github.com/onvif/signed-media-framework/tags).

The check tests here in Github run on a Linux platform.

# Getting started
The repository uses meson + ninja as default build method. Further, OpenSSL is used for
cryptographic operations and to run unittests you need libcheck.
- [meson](https://mesonbuild.com/Getting-meson.html) Getting meson and ninja. Meson
version 0.47.0 or newer is required.
- [OpenSSL](https://www.openssl.org/) The default library to handle keys, hashes and
signatures. OpenSSL version 1.1.1 or newer is required.
- [libcheck](https://libcheck.github.io/check/) The framework for unittests

# Build Instructions
Below are meson instructions on how to build for either signing or validation. For help on
meson usage see [mesonbuild.com](https://mesonbuild.com/). The meson instructions in this
repository will create a shared library named `libsigned-media-framework`.

## Configure with meson
```
meson setup path/to/signed-media-framework path/to/build/folder
```
will generate compile instructions for ninja and put them in a folder located at
`path/to/build/folder`. The framework comes with an option to build with debug prints
```
meson setup -Ddebugprints=true path/to/signed-media-framework path/to/build/folder
```
With the `--prefix` meson option it is possible to specify an arbitrary location to where
the shared library is installed.
```
meson setup --prefix /absolute/path/to/your/local/installs path/to/signed-media-framework path/to/build/folder
```

## Compile and install the shared library
To compile signed-media-framework using ninja
```
ninja -C path/to/build/folder
```
and the object file is located at
`path/to/build/folder/lib/src/libsigned-media-framework.so`. To install the shared library
run
```
meson install -C build
```
The library, named `libsigned-media-framework`, will be installed where libraries are
installed, or at `path/to/your/local/installs` if you configured meson with `--prefix`.
The header files will be located in a sub-folder of `includes` named
`signed-media-framework`.

## Example build commands on Linux
1. Configure and compile into `./build` without installing from the top level
```
meson setup . build
ninja -C build
```
2. Configure, compile and install in `./my_installs/` from the parent folder of
`signed-media-framework/`
```
meson setup --prefix $PWD/my_installs signed-media-framework build
meson install -C build
```

## Configure, build and run unittests
Nothing extra is needed. Hence, to build and run the unittests call
```
meson setup . build
ninja -C build test
```
Alternatively, you can run the script
[tests/test_checks.sh](./tests/test_checks.sh) and the unittests will run both with and
without debug prints. Note that you need libcheck installed as well.
TODO: ADD TEST SCRIPT

# License
[MIT License](./LICENSE)
TODO: ADD LICENSE FILE OR REFERENCE TO ONE
