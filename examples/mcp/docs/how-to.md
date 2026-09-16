# How-To Guides

## Test through a Copilot agent

The bundled `demo:stdio` and `demo:http` clients are deterministic protocol
checks; they do not contain an LLM. To test conversational tool selection and
response generation, register the server with Copilot CLI and chat with the
Copilot agent.

For the normal stdio lifecycle, run this once from `examples/mcp`:

```sh
copilot mcp add media-signing -- npm --prefix "$PWD" run start:stdio
copilot mcp get media-signing
```

Then start an interactive session:

```sh
copilot -C "$PWD"
```

Ask the agent:

> Resolve `../test-files/test_signed_h264.mp4` to an absolute path, then check it
> with the media-signing tools. Explain what the framework established in plain
> language. If it is not authentic, record the full report under case
> `agent-demo`.

Copilot should propose or request permission for `validate_media_file`, call it,
interpret the structured result, and conditionally call `log_case_event`. This
reasoning and narration come from Copilot; the MCP server only exposes tools and
the `investigate_media` prompt template.

To see the waiting server at the same time, use HTTP instead. Start
`npm run start:http` in the first terminal, then register and launch Copilot from
a second terminal:

```sh
copilot mcp remove media-signing
copilot mcp add --transport http media-signing http://127.0.0.1:3000/mcp
copilot -C "$PWD"
```

Use the same natural-language request. The first terminal will show the
direction of each request and response, and names such as
`tools/call [validate_media_file]`, while Copilot responds in the second.

`copilot mcp remove media-signing` only removes Copilot's saved registration. It
does not own or stop the independent process started by `npm run start:http`.
Stop that HTTP server with `Ctrl+C` in its terminal. Return to stdio afterward
with:

```sh
copilot mcp remove media-signing
copilot mcp add media-signing -- npm --prefix "$PWD" run start:stdio
```

## Test a custom validation bridge

Most users should skip this: the setup script builds and uses the bridge under
`.demo/adapter-prefix/bin/` automatically.

Set `MEDIA_SIGNING_MCP_ADAPTER` only when developing or debugging a separately
built bridge executable without replacing the default build:

```sh
MEDIA_SIGNING_MCP_ADAPTER=/absolute/path/to/media-signing-mcp-validator \
  npm run demo:stdio -- ../test-files/test_h264.mp4 demo-case
```

The custom executable must accept an absolute media path and CA path as
arguments and write one JSON report to stdout. For HTTP mode, set the variable
on `npm run start:http`, because the server process launches the bridge.

## Store case logs elsewhere

Set `MEDIA_SIGNING_MCP_CASE_DIRECTORY` to an absolute local directory. The
server creates it when the first event is appended.

## Add an MCP tool

Both stdio and HTTP use the shared `createServer()` function in
`src/server.mjs`. Register the tool there once to expose it through both
transports. Give it a Zod input schema, keep its side effects inside a
configured local directory, and add a Node test in `test/`. Change
`src/http-server.mjs` only when the HTTP transport behavior itself must change.

## Change report mapping

Update `authenticity_name()` and `normalized_status()` in `main.c`, then run
`npm run check`. Preserve the raw framework code in JSON so callers can
distinguish framework semantics from demo-level presentation.

## Run quality checks

Run the complete local gate before submitting changes:

```sh
npm run check
```

This requires `clang-format` on `PATH`, as does the repository pre-commit hook.
The command bootstraps dependencies, then checks Prettier formatting, ESLint,
Markdown, repository clang-format, Node tests, and the Meson build with the
framework's warning-as-error settings. Use `npm run format` to format
JavaScript, JSON, and `main.c`; review the resulting diff before committing.
