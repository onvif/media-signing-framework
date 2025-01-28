*Copyright (c) 2024 ONVIF. All rights reserved.*

# Application to sign a video file
Note: This example application code also serves as example code for how to implement the
signing side of the *Signed Media Framework*.

## Prerequisites
This application relies on gStreamer.
- [gStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)

## Description
The application processes a file NAL by NAL and adds signatures in SEIs, provided by the
*Signed Media Framework*. A successfully signed GOP prints it on the screen.

It is implemented as a gStreamer element that processes every NAL Unit and adds SEI NALs
to the stream repeatedly. The signed video is written to a new file, prepending the
filenamne with `signed_`. That is, `test_h264.mp4` becomes `signed_test_h264.mp4`.

## Building the signer application
Below are meson commands to build the signer application. The library is built at the same
time as the signer application.

Build the signer application with meson as
```
meson setup -Dsigner=true . path/to/build/folder
meson install -C path/to/build/folder
```

### Example meson commands on Linux
These example commands assume the current directory is media-signing-framework.

Build and install the `signer` in the same place as the library. Since this application is
implemented as a gStreamer element set `GST_PLUGIN_PATH` for gStreamer to find it.
```
export GST_PLUGIN_PATH=$PWD/my_installs
meson setup --prefix $PWD/my_installs -Dsigner=true . build_apps
meson install -C build_apps
```
The executable is now located at `./my_installs/bin/signer`

## Running
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
*leaks* are produced by glib and gStreamer. Any help to solve these is appreciated.
