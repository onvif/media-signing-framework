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
the framework and C JSON validation bridge into `.demo/`; users do not run Meson
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

A successful adapter response includes:

```json
{
  "status": "authentic",
  "is_authentic": true,
  "raw_authenticity": "authentic",
  "raw_provenance": "trusted",
  "raw_authenticity_and_provenance_code": 2,
  "raw_authenticity_code": 4,
  "raw_provenance_code": 3,
  "public_key_has_changed": false,
  "validator_version": "string",
  "signing_version": "string",
  "vendor": {
    "manufacturer": "string",
    "serial_number": "string",
    "firmware_version": "string"
  },
  "statistics": {
    "received_nalus": 0,
    "validated_nalus": 0,
    "pending_nalus": 0,
    "received_frames": 0,
    "validated_frames": 0,
    "pending_frames": 0
  },
  "timestamps": {
    "first": {
      "ticks_100ns_since_1601": "string",
      "utc": "YYYY-MM-DDTHH:mm:ss.sssssssZ"
    },
    "last": {
      "ticks_100ns_since_1601": "string",
      "utc": "YYYY-MM-DDTHH:mm:ss.sssssssZ"
    }
  },
  "latest_validation": {
    "raw_authenticity": "authentic",
    "raw_provenance": "trusted",
    "raw_authenticity_and_provenance_code": 2,
    "raw_authenticity_code": 4,
    "raw_provenance_code": 3,
    "public_key_has_changed": false,
    "expected_hashable_nalus": 0,
    "received_hashable_nalus": 0,
    "pending_hashable_nalus": 0,
    "validation": "string",
    "nalu_types": "string",
    "timestamps": {
      "start": null,
      "end": null
    }
  }
}
```

The normalized `status` and `is_authentic` fields describe media authenticity.
The other status values are `integrity_warning`, `not_authentic`, `not_signed`,
and `validation_error`. Provenance is reported separately as `raw_provenance`:
`trusted`, `verifiable_without_trusted_ca`, `not_trusted`, or `not_feasible`.
The combined framework result remains available in
`raw_authenticity_and_provenance_code`.

The top-level statistics and timestamps represent the accumulated whole-file
result. `latest_validation` preserves the framework's final partial-GOP snapshot,
including its NAL-unit status strings. Each available timestamp contains both an
exact decimal string in the framework's 100-nanosecond-since-1601 format and an
ISO 8601 UTC rendering. An unavailable timestamp is `null`; using a string for
the raw value avoids loss of precision in JavaScript clients.

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
| `MEDIA_SIGNING_MCP_ADAPTER` | Absolute path to the installed C JSON validation bridge. |
| `MEDIA_SIGNING_MCP_CA` | Absolute path to the CA used by the bundled client. |
| `MEDIA_SIGNING_MCP_CASE_DIRECTORY` | Local directory for case JSONL files. |
| `MEDIA_SIGNING_MCP_PORT` | Loopback HTTP server port; defaults to `3000`. |
| `MEDIA_SIGNING_MCP_URL` | Streamable HTTP URL used by the bundled client. |

The validation bridge takes `ABSOLUTE_MEDIA_PATH [ABSOLUTE_CA_PATH]`. It writes
one JSON object to stdout and diagnostics to stderr.

## MCP Prompt

`investigate_media` accepts `media_path` and optional `case_id`. It directs an
LLM-backed MCP client to validate the file, explain only what the framework
established, and record non-authentic results when a case ID is supplied.
