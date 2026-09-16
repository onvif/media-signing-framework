# Media Signing MCP Demo: Phase 0 Design

- **Status:** Implemented
- **Last updated:** 2026-09-16
- **Relationship to upstream:** An unofficial community demonstration built
  with the ONVIF Media Signing Framework. It is not affiliated with or endorsed
  by ONVIF.

## Goal

Expose Media Signing Framework validation to local MCP clients without adding
new authenticity logic or changing the core framework API. The demo may report
what the framework established, but it must not claim general forensic proof or
legal chain of custody.

## Decisions

### Use the native JSON validator

The validator application's `--json` mode owns the machine-readable report
schema. MCP invokes that command with an argument array, parses its single JSON
object, and returns it without reimplementing authenticity rules or translating
report fields.

GStreamer demuxing, codec detection, framework parsing, and report serialization
remain in the native validator process.

### Share one server across transports

The stdio and loopback Streamable HTTP entry points both instantiate the same
MCP server. Tool and prompt contracts therefore have one implementation and the
same behavior in both modes.

Stdio is the primary MCP-host integration. HTTP exists only to make requests and
responses visible during a local demonstration; it binds to loopback and has no
authentication or remote-deployment role.

### Keep effects explicit and local

Validation reads one caller-selected local media file and trust anchor. It does
not write a case record automatically. The separate case-log tool appends only
to its configured local directory and restricts case IDs to a safe filename
grammar.

Generated dependencies, builds, installed binaries, and default case logs stay
under `examples/mcp/.demo/` or `node_modules/`. No tool accepts private-key
material.

### Preserve framework semantics

The native report preserves raw authenticity, provenance, and their combined
result. Its normalized status describes media authenticity; provenance remains
a separate trust result because valid signatures and a trusted signing-key chain
answer different questions. Missing validation information is an integrity
warning, not proof of forgery.

## Phase 0 Boundary

- Validate local H.264 or H.265 video in a lowercase `.mp4` container.
- Detect the codec from demuxed stream capabilities rather than caller input.
- Use the committed signed H.264 fixture and repository test CA as the required
  demonstration path.
- Support macOS and Linux through a native Meson build and project-local Node
  dependencies.
- Remain fully offline and avoid changes to the upstream framework API.

Deferred production and hardening concerns are tracked in
[Future work](docs/future-work.md).

## Maintained Documentation

- [Tutorial](docs/tutorial.md): prerequisites and end-to-end operation
- [How-to guides](docs/how-to.md): focused extension and integration tasks
- [Reference](docs/reference.md): commands, schemas, statuses, and configuration
- [Explanation](docs/explanation.md): architecture, flow, and trust boundaries
- [Future work](docs/future-work.md): deliberately deferred capabilities
