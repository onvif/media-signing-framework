# Reference

## Runtime

- Node.js 22.13 or later
- Meson, Ninja, a C compiler, `pkg-config`, and OpenSSL 3+
- JSON-GLib 1.6 or later
- GStreamer with `qtdemux`, `h264parse`, `h265parse`, and `appsink`
- Supported input: lowercase `.mp4` containing H.264 or H.265 video

| Command | Transport | Purpose |
| --- | --- | --- |
| `npm run start:stdio` | stdio | Start a server for an MCP host that owns its process. |
| `npm run demo:stdio -- MEDIA [CASE]` | stdio | Bootstrap and run the bundled end-to-end client. |
| `npm run start:http` | HTTP | Start the visible server on `127.0.0.1:3000`. |
| `npm run demo:http -- MEDIA [CASE]` | HTTP | Connect the bundled client to that waiting server. |

`npm start` and `npm run demo` remain aliases for their stdio counterparts. All
start/demo commands except `demo:http` bootstrap as needed. The bootstrap builds
the framework and its native validator into `.demo/`; users do not run Meson
directly.

## `validate_media_file`

```json
{
  "path": "/absolute/path/to/video.mp4",
  "ca_cert_ref": "/absolute/path/to/ca.pem"
}
```

`path` is required. `ca_cert_ref` is optional and defaults to
`examples/test-files/ca.pem` for the local demo.

A successful tool result passes through the complete native validator JSON
object as MCP `structuredContent`. For example:

```json
{
  "status": "authentic",
  "is_authentic": true,
  "raw_authenticity": "authentic",
  "raw_provenance": "trusted",
  "raw_authenticity_and_provenance": "authentic_and_trusted",
  "raw_authenticity_and_provenance_code": 2,
  "timestamps": {
    "first": {
      "ticks_100ns_since_1601": "string",
      "utc": "YYYY-MM-DDTHH:mm:ss.sssssssZ"
    }
  }
}
```

The MCP layer does not add, remove, or rename native report fields. See the
[validator JSON output](../../apps/validator/README.md#json-output) for the
authoritative schema and result semantics.

## `log_case_event`

```json
{
  "case_id": "case-42",
  "event_type": "integrity_warning",
  "details": { "status": "integrity_warning" }
}
```

`case_id` matches `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`. Events are appended to
`case_<case_id>.jsonl` in `MEDIA_SIGNING_MCP_CASE_DIRECTORY` or `.demo/cases`.

## Configuration

| Variable | Purpose |
| --- | --- |
| `MEDIA_SIGNING_MCP_VALIDATOR` | Absolute path to a compatible native validator. |
| `MEDIA_SIGNING_MCP_CA` | Absolute path to the CA used by the bundled client. |
| `MEDIA_SIGNING_MCP_CASE_DIRECTORY` | Local directory for case JSONL files. |
| `MEDIA_SIGNING_MCP_PORT` | Loopback HTTP server port; defaults to `3000`. |
| `MEDIA_SIGNING_MCP_URL` | Streamable HTTP URL used by the bundled client. |

The server invokes `validator --json -C ABSOLUTE_CA_PATH ABSOLUTE_MEDIA_PATH`.
The command writes one JSON object to stdout and diagnostics to stderr.

## MCP Prompt

`investigate_media` accepts `media_path` and optional `case_id`. It directs an
LLM-backed MCP client to validate the file, explain only what the framework
established, and record non-authentic results when a case ID is supplied.
