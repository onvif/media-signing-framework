*Copyright (c) 2025 ONVIF. All rights reserved.*

# Application to sign a video file
Note: This example application code also serves as example code for how to implement the
signing side of the *Media Signing Framework*.

## Prerequisites
This application relies on GStreamer.
- [GStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)

## Description
The application processes a file NAL by NAL and adds signatures in SEIs, provided by the
*Media Signing Framework*. A successfully signed GOP prints it on the screen.

It is implemented as a GStreamer element that processes every NAL Unit and adds SEI NALs
to the stream repeatedly. The signed video is written to a new file, prepending the
filenamne with `signed_`. That is, `test_h264.mp4` becomes `signed_test_h264.mp4`.

## Building the signer application
Below are meson commands to build the signer application. The library is built at the same
time as the signer application.

Build the signer application with meson as
```
meson setup --prefix path/to/your/local/installs -Dsigner=true . path/to/build/folder
meson install -C path/to/build/folder
```
The application has to be installed to be usable, since it finds the shared library
through the install prefix. Without `--prefix` it is installed system wide, which
typically requires root privileges.

`libgstsigning.so` is installed in the library folder of the prefix, which is not part of
the plugin folders GStreamer searches by default. Therefore `GST_PLUGIN_PATH` has to point
at the install prefix, both to build the example below and to run the signer afterwards.

### Example meson commands on Linux
These example commands assume the current directory is media-signing-framework.

Build and install the `signer` in the same place as the library. Since this application is
implemented as a GStreamer element set `GST_PLUGIN_PATH` for GStreamer to find it.
```
export GST_PLUGIN_PATH=$PWD/my_installs
meson setup --prefix $PWD/my_installs -Dsigner=true . build_signer
meson install -C build_signer
```
The executable is now located at `./my_installs/bin/signer`

## Running
Note that `GST_PLUGIN_PATH` has to be set in the shell that runs the signer as well, see
above. Without it the signer exits with
*The gstsigning element could not be found*.

The signing keys and the certificate chain are written to the current working directory.

Sign an MP4 file of an H.264 video using the app
```
./path/to/your/installed/signer -c h264 test_h264.mp4
```
With the example Linux commands above sign `test_h264.mp4` in
[test-files/](../../test-files/).
```
./my_installs/bin/signer -c h264 examples/test-files/test_h264.mp4
```

There are unsigned test files in [test-files/](../../test-files/) for both H.264 and H.265.

## Known issues
There are known valgrind errors produced when running the signer application. These
*leaks* are produced by GLib and GStreamer. Any help to solve these is appreciated.
