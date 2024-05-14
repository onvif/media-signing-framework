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

It is implemented as a gStreamer element that process every NAL Unit and adds SEI NALs to the stream repeatedly.
The signed video is written to a new file, prepending the filenamne with `signed_`. That is, `test_h264.mp4` becomes `signed_test_h264.mp4`. The application requires the file to process to be in the current directory.

## Building the signer application
Below are meson commands to build the signer application. First you need to have the signed-video-framework library installed. Installing the share library and applications locally is in many cases preferably.

Then build the signer application with meson as
```
meson -Dsigner=true path/to/signed-video-framework-examples path/to/build/folder
meson install -C path/to/build/folder
```

### Example meson commands on Linux
These example commands assume the current directory is the parent directory of both signed-video-framework and signed-video-framework-examples.

Build and install the library locally in `./my_installs/`.
```
meson --prefix $PWD/my_installs signed-video-framework build_lib
meson install -C build_lib
```
Then build and install the `signer` in the same place. Since this application is implemented as a gStreamer element set `GST_PLUGIN_PATH` for gStreamer to find it.
```
export GST_PLUGIN_PATH=$PWD/my_installs
meson --prefix $PWD/my_installs -Dsigner=true signed-video-framework-examples build_apps
meson install -C build_apps
```
The executable is now located at `./my_installs/bin/signer`

## Running
Sign an MP4 file of an H264 video using the app
```
./path/to/your/installed/signer -c h264 test_h264.mp4
```
Note that the recording to sign must be present in the current directory, so copy it before signing. With the example Linux commands above sign `test_h264.mp4` in [test-files/](../../test-files/).
```
cp signed-video-framework-examples/test-files/test_h264.mp4 .
./my_installs/bin/signer -c h264 test_h264.mp4
```

There are unsigned test files in [test-files/](../../test-files/) for both H264 and H265.

Note: There is currently a known flaw when signing H265. The timestamps of the first NALs are not
set correctly. This affects the validation of the first GOP, which then may not properly parse the
NALs.
