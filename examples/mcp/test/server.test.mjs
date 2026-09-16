import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  createClientTransport,
  formatReport,
  resolveMediaPath,
} from "../src/client.mjs";
import { describeMcpRequest } from "../src/http-server.mjs";
import {
  appendCaseEvent,
  createServer,
  mcpDirectory,
  resolveAdapterPath,
  runValidator,
} from "../src/server.mjs";

test("exposes the demo tools and investigation prompt over stdio", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(mcpDirectory, "src", "server.mjs")],
    cwd: mcpDirectory,
    stderr: "pipe",
  });
  const client = new Client({
    name: "media-signing-test-client",
    version: "0.1.0",
  });

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    const prompts = await client.listPrompts();
    assert.deepEqual(tools.tools.map(({ name }) => name).sort(), [
      "log_case_event",
      "validate_media_file",
    ]);
    assert.deepEqual(
      prompts.prompts.map(({ name }) => name),
      ["investigate_media"],
    );
  } finally {
    await transport.close();
  }
});

test("explains validation results in plain language", () => {
  assert.equal(
    formatReport({ status: "integrity_warning" }),
    "The media has an integrity warning because validation information or NAL units are missing.",
  );
});

test("reports provenance separately from media authenticity", () => {
  assert.equal(
    formatReport({ status: "authentic", raw_provenance: "not_trusted" }),
    "The framework validated this media as authentic. Signing-key provenance: not_trusted.",
  );
});

test("resolves demo media paths from the current directory", () => {
  assert.equal(
    resolveMediaPath("../test-files/test_h264.mp4", "/repo/examples/mcp"),
    "/repo/examples/test-files/test_h264.mp4",
  );
  assert.equal(
    resolveMediaPath("/tmp/video.mp4", "/repo/examples/mcp"),
    "/tmp/video.mp4",
  );
});

test("rejects missing demo arguments before setup", () => {
  const result = spawnSync("sh", [join(mcpDirectory, "scripts", "demo.sh")], {
    encoding: "utf8",
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /npm run demo:stdio/);
  assert.doesNotMatch(result.stderr, /Meson build system/);
});

test("uses Streamable HTTP for a separately started demo server", () => {
  const transport = createClientTransport("http://127.0.0.1:3000/mcp");
  assert.equal(transport.constructor.name, "StreamableHTTPClientTransport");
});

test("describes HTTP MCP tool calls by name", () => {
  assert.equal(
    describeMcpRequest({
      method: "tools/call",
      params: { name: "validate_media_file" },
    }),
    "tools/call [validate_media_file]",
  );
  assert.equal(describeMcpRequest({ method: "initialize" }), "initialize");
});

test("resolves an explicitly configured adapter", () => {
  assert.equal(
    resolveAdapterPath({ MEDIA_SIGNING_MCP_ADAPTER: "/tmp/validator" }),
    "/tmp/validator",
  );
});

test("accepts a configured case-log directory", () => {
  assert.ok(
    createServer({
      environment: { MEDIA_SIGNING_MCP_CASE_DIRECTORY: "/tmp/mcp-cases" },
    }),
  );
});

test("runs the adapter with individual arguments and parses its report", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-validator-"));
  const mediaPath = join(directory, "input.mp4");
  const caPath = join(directory, "ca.pem");
  await writeFile(mediaPath, "media");
  await writeFile(caPath, "certificate");
  let invocation;

  const report = await runValidator({
    mediaPath,
    caPath,
    adapterPath: "/tmp/validator",
    execute: async (file, argumentsList, options) => {
      invocation = { file, argumentsList, options };
      return { stdout: '{"status":"authentic","is_authentic":true}' };
    },
  });

  assert.deepEqual(report, { status: "authentic", is_authentic: true });
  assert.equal(invocation.file, "/tmp/validator");
  assert.deepEqual(invocation.argumentsList, [mediaPath, caPath]);
  assert.equal(invocation.options.shell, false);
});

test("rejects a relative media path", async () => {
  await assert.rejects(
    runValidator({
      mediaPath: "input.mp4",
      caPath: "/tmp/ca.pem",
      adapterPath: "/tmp/validator",
    }),
    /path must be an absolute path/,
  );
});

test("reports an unreadable media path clearly", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-missing-media-"));

  await assert.rejects(
    runValidator({
      mediaPath: join(directory, "missing-media"),
      caPath: "/tmp/ca.pem",
      adapterPath: "/tmp/validator",
    }),
    /Media file is not readable/,
  );
});

test("appends a JSONL case event", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-cases-"));
  const result = await appendCaseEvent({
    caseId: "case-42",
    eventType: "integrity_warning",
    details: { status: "integrity_warning" },
    caseDirectory: directory,
  });
  const event = JSON.parse(await readFile(result.path, "utf8"));

  assert.equal(event.case_id, "case-42");
  assert.equal(event.event_type, "integrity_warning");
  assert.deepEqual(event.details, { status: "integrity_warning" });
});

test("rejects an unsafe case identifier", async () => {
  await assert.rejects(
    appendCaseEvent({
      caseId: "../outside",
      eventType: "integrity_warning",
      details: {},
      caseDirectory: "/tmp/cases",
    }),
    /case_id/,
  );
});
