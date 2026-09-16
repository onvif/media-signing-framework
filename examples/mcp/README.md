# Media Signing MCP Demo

An unofficial, local MCP demonstration that wraps ONVIF Media Signing Framework
validation in two tools: `validate_media_file` and `log_case_event`. It supports
stdio for MCP host integration and loopback HTTP for a visible two-terminal demo.

## Quick Start

From this directory, run the bundled MCP client against a local media file:

```sh
npm run demo:stdio -- ../test-files/test_signed_h264.mp4 demo-case
```

That command verifies the required tools, installs local Node packages when
needed, and builds the framework and JSON bridge. Meson reports missing native
libraries. It then validates the file and records a case event when the result
is not `authentic`. Subsequent runs reuse `.demo/`.

For a visible server/client demonstration in two terminals, see
[Run over loopback HTTP](docs/tutorial.md#run-over-loopback-http).

To expose the stdio server to Copilot or another MCP host instead, configure that
host to run `npm --prefix /absolute/path/to/examples/mcp run start:stdio`. Then ask:

> Validate `/absolute/path/to/video.mp4`. Explain the result in plain language.
> If it is not authentic, record the complete report under case `demo-case`.

The JSON validation bridge is a small C executable between Node and the existing
C framework. It is needed because the existing example validator writes a
human-readable report, while MCP needs one stable machine-readable JSON result.

## Documentation

- [Tutorial](docs/tutorial.md): build and run the end-to-end demo.
- [How-to guides](docs/how-to.md): change or extend the demo.
- [Reference](docs/reference.md): tool contracts and configuration.
- [Explanation](docs/explanation.md): architecture, flow, and result semantics.
- [Future work](docs/future-work.md): deferred hardening and production topics.
- [Phase 0 design](spec.md): scope and implementation decisions.

The primary path is a native Meson build on macOS or Linux. All generated
artifacts and local dependencies remain in `.demo/` or `node_modules/`.
