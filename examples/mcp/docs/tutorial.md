# Tutorial: Validate Media Through MCP

The demo supports stdio and loopback Streamable HTTP. Use stdio for MCP host
integration or a one-command end-to-end run. Use HTTP when presenting the server
and client as visibly separate processes in two terminals.

## Prerequisites

Install Node.js 22.13+, Meson, Ninja, a C compiler, `pkg-config`, OpenSSL 3+, and
GStreamer development/runtime packages that provide MP4 demuxing and H.264/H.265
parsing. The bridge also requires JSON-GLib 1.6+. Package names differ between
macOS and Linux.

On macOS with Homebrew:

```sh
xcode-select --install
brew install node meson ninja pkg-config openssl@3 gstreamer json-glib
```

On Debian or Ubuntu, install Node.js 22.13+ separately if the distribution does
not provide it, then install the native dependencies:

```sh
sudo apt-get install build-essential meson ninja-build pkg-config libssl-dev \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libjson-glib-dev \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad
```

No global npm packages are required. Node dependencies, builds, installed local
binaries, and case logs stay below `examples/mcp`.

## Run over stdio

From `examples/mcp`, provide a media path and an optional case ID:

```sh
npm run demo:stdio -- ../test-files/test_signed_h264.mp4 demo-case
```

The demo command accepts absolute paths or paths relative to the current
directory. Direct MCP tool calls require absolute paths.

On the first run, the command:

1. Builds and locally installs the Media Signing Framework with Meson.
2. Builds the C JSON validation bridge.
3. Installs project-local Node dependencies.
4. Starts the MCP server as a child process and calls `validate_media_file`.
5. Prints a plain-language explanation and the structured report.
6. Calls `log_case_event` when a case ID is supplied and the status is not
   `authentic`.

Later runs reuse the local setup. The demo defaults to the repository test CA.
Set `MEDIA_SIGNING_MCP_CA` to an absolute PEM path to use another trust anchor.

## Run over loopback HTTP

Start the server from `examples/mcp` in the first terminal:

```sh
npm run start:http
```

After it reports `Media Signing MCP demo server ready`, leave it running. In a
second terminal, run:

```sh
npm run demo:http -- ../test-files/test_signed_h264.mp4 demo-case
```

The client prints the result while the server terminal shows each received MCP
method. The HTTP server listens only on `127.0.0.1`; stop it with `Ctrl+C`.
To use another port, set matching values in the two terminals:

```sh
MEDIA_SIGNING_MCP_PORT=3010 npm run start:http
MEDIA_SIGNING_MCP_URL=http://127.0.0.1:3010/mcp \
  npm run demo:http -- ../test-files/test_signed_h264.mp4 demo-case
```

## Connect Copilot or Another MCP Client

Configure the MCP host to launch this stdio command:

```text
command: npm
arguments: --prefix /absolute/path/to/media-signing-framework/examples/mcp run start:stdio
```

This is a long-running server command. After the build completes, it prints
`Media Signing MCP server ready; waiting for a client on stdio.` to stderr and
waits until the MCP client disconnects; prompts are entered in the MCP client,
not in this terminal.

For clients that use JSON server configuration, the equivalent shape is:

```json
{
  "servers": {
    "media-signing": {
      "type": "stdio",
      "command": "npm",
      "args": [
        "--prefix",
        "/absolute/path/to/media-signing-framework/examples/mcp",
        "run",
        "start:stdio"
      ]
    }
  }
}
```

The exact configuration filename or add-server command is client-specific. The
server command itself is the same for Copilot CLI, VS Code, and other stdio MCP
clients.

Once connected, use this natural-language request:

> Validate `/absolute/path/to/video.mp4`. Explain what the Media Signing
> Framework established in plain language. If the result is not authentic,
> record the complete report under case `demo-case`.

Clients that expose MCP prompts can select `investigate_media` and supply
`media_path` plus an optional `case_id`. The prompt directs the client to call
the same two tools in the correct order.

For an exact Copilot CLI registration and interactive agent walkthrough, see
[Test through a Copilot agent](how-to.md#test-through-a-copilot-agent).

## Expected Result

The committed signed fixture should return `status: "authentic"`. A separately
prepared signed stream with missing validation information can return
`status: "integrity_warning"`; a reproducible warning fixture is future work.
This status is not a claim of cryptographic forgery. Case records are written
under `.demo/cases/case_<id>.jsonl` by default.

See the [explanation](explanation.md) for why the JSON bridge exists and
[future work](future-work.md) for limitations that are intentionally outside
this demo.
