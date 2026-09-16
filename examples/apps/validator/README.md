*Copyright (c) 2025 ONVIF. All rights reserved.*

# Application to validate video authenticity
Note: This example application code also serves as example code for how to implement the
validation side of the *Media Signing Framework*.

## Prerequisites
This application relies on GstAppSink and GstDiscoverer from the GStreamer development
package. JSON output requires JSON-GLib 1.6 or later.

- [GStreamer](https://gstreamer.freedesktop.org/documentation/installing/index.html?gi-language=c)
- [JSON-GLib](https://gnome.pages.gitlab.gnome.org/json-glib/)

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
meson setup --prefix path/to/your/local/installs -Dvalidator=true . path/to/build/folder
meson install -C path/to/build/folder
```
The application has to be installed to be usable, since it finds the shared library
through the install prefix. Without `--prefix` it is installed system wide, which
typically requires root privileges.

### Example meson commands on Linux
These example commands assume the current directory is media-signing-framework.

Build and install the `validator`
```
meson setup --prefix $PWD/my_installs -Dvalidator=true . build_validator
meson install -C build_validator
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

### JSON output

Use `--json` for machine-readable validation:

```sh
./my_installs/bin/validator --json -C examples/test-files/ca.pem \
	examples/test-files/test_signed_h264.mp4
```

When `-c` is omitted in JSON mode, the application detects H.264 or H.265 from the
media stream. An explicit `-c h264` or `-c h265` overrides detection. Codec behavior in
the existing text mode is unchanged.

JSON mode writes exactly one object to stdout, writes diagnostics to stderr, and does
not create `validation_results.txt`. A completed validation returns exit code `0`
regardless of its authenticity result. Invalid arguments, unreadable inputs, pipeline
failures, and failures to produce a report return a nonzero exit code and this shape:

```json
{
	"status": "validation_error",
	"is_authentic": false,
	"error": "error description"
}
```

Successful reports contain:

- normalized `status` and `is_authentic` fields describing media authenticity;
- readable and numeric authenticity, provenance, and combined framework results;
- signing and validator versions plus vendor information;
- accumulated NAL-unit and frame statistics;
- accumulated first/last timestamps and final partial-GOP timestamps;
- the complete final `latest_validation` snapshot, including NAL-unit type and
	validation strings.

Available timestamps contain the exact framework value as a decimal string under
`ticks_100ns_since_1601` and an ISO 8601 rendering under `utc`. The exact value is a
string to avoid precision loss in JSON consumers. Unavailable timestamps are `null`.
Media authenticity and signing-key provenance remain separate results.

There are both signed and unsigned test files in [test-files/](../../test-files/) for both
H.264 and H.265.

## Known issues
There are known valgrind errors produced when running the validator application. These
*leaks* are produced by GLib and GStreamer. Any help to solve these is appreciated.
