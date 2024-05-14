*Copyright (C) 2024, ????*

# Application to validate video authenticity
Note: This example application code also serves as example code for how to implement the
validation side of the *Signed Media Framework*.

## Prerequisites
This application relies on GstAppSink (part of dev pack of gStreamer).
- [gStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)

## Description
The application process NAL by NAL and validates the authenticity continuously. The result
is written on screen and in addition, a summary is written to the file
*validation_results.txt*.

It is implemented as a GstAppSink that process every NAL and validates the authenticity
on-the-fly.

## Building the validator application
Below are meson commands to build and install the validator application.

Build the validator application with meson as
```
meson setup -Dvalidator=true . path/to/build/folder
meson install -C path/to/build/folder
```

### Example meson commands on Linux
These example commands assume the current directory is signed-media-framework.

Build and install the `validator`
```
meson setup --prefix $PWD/my_installs -Dvalidator=true . build_apps
meson install -C build_apps
```
The executable is now located at `./my_installs/bin/validator`

## Running
Validate an MP4 file of an H264 video using the app
```
./path/to/your/installed/validator -c h264 signed_test_h264.mp4
```
With the example Linux commands above testing `signed_test_h264.mp4` in
[test-files/](../../test-files/)
```
./my_installs/bin/validator -c h264 signed-media-framework/examples/test-files/signed_test_h264.mp4
```

There are both signed and unsigned test files in [test-files/](../../test-files/) for both
H.264 and H.265.
