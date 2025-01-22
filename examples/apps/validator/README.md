*Copyright (C) 2024, ????*

# Application to validate video authenticity
Note: This example application code also serves as example code for how to implement the
validation side of the *Signed Media Framework*.

## Prerequisites
This application relies on GstAppSink (part of dev pack of gStreamer).
- [gStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)

## Description
The application processes NAL by NAL. A summary is written to the file
*validation_results.txt*. The application implements both continuous validation, as well
as batch validation. When running continuous validation (default) the validation results
are printed on the screen for every SEI received. When running in batch mode (option `-b`)
a final authenticity report is analyzed after processing all NAL Units.

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
./path/to/your/installed/validator -c h264 test_signed_h264.mp4
```
With the example Linux commands above testing `test_signed_h264.mp4` in
[test-files/](../../test-files/)
```
./my_installs/bin/validator -C examples/test-files/ca.pem -c h264 examples/test-files/test_signed_h264.mp4
```
and in batch mode
```
./my_installs/bin/validator -b -C examples/test-files/ca.pem -c h264 examples/test-files/test_signed_h264.mp4
```

There are both signed and unsigned test files in [test-files/](../../test-files/) for both
H.264 and H.265.

## Known issues
There are known valgrind errors produced when running the validator application. These
*leaks* are produced by glib and gStreamer. Any help to solve these is appreciated.
