*Copyright (C) 2024, ????*

# Application to sign a video file
Note: This example application code also serves as example code for how to implement the
signing side of the *Signed Media Framework*.

## Prerequisites
This application relies on gStreamer and signed-media-framework.
- [gStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)

## Description
The application processes a file NAL by NAL and adds signatures in SEIs, provided by the
*Signed Media Framework*. A successfully signed GOP prints it on the screen.

It is implemented as a gStreamer element that process every NAL Unit and adds SEI NALs to
the stream repeatedly. The signed video is written to a new file, prepending the filenamne
with `signed_`. That is, `test_h264.mp4` becomes `signed_test_h264.mp4`. The application
requires the file to process to be in the current directory.

## Building the signer application
Below are meson commands to build the signer application. The library is built at the same
time as the signer application.

Build the signer application with meson as
```
meson setup -Dsigner=true . path/to/build/folder
meson install -C path/to/build/folder
```

### Example meson commands on Linux
These example commands assume the current directory is signed-media-framework.

Build and install the `signer` in the same place as the library. Since this application is
implemented as a gStreamer element set `GST_PLUGIN_PATH` for gStreamer to find it.
```
export GST_PLUGIN_PATH=$PWD/my_installs
meson --prefix $PWD/my_installs -Dsigner=true build_apps
meson install -C build_apps
```
The executable is now located at `./my_installs/bin/signer`

## Running
Sign an MP4 file of an H.264 video using the app
```
./path/to/your/installed/signer -c h264 test_h264.mp4
```
Note that the recording to sign must be present in the current directory, so copy it
before signing. With the example Linux commands above sign `test_h264.mp4` in
[test-files/](../../test-files/).
```
cp signed-media-framework/test-files/test_h264.mp4 .
./my_installs/bin/signer -c h264 test_h264.mp4
```

There are unsigned test files in [test-files/](../../test-files/) for both H.264 and H.265.
