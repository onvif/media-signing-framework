import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { mcpDirectory } from "./server.mjs";

export function formatReport(report) {
  const summaries = {
    authentic: "The framework validated this media as authentic.",
    integrity_warning:
      "The media has an integrity warning because validation information or NAL units are missing.",
    not_authentic: "The framework determined that this media is not authentic.",
    not_signed: "The media does not contain a supported media-signing record.",
    validation_error: "Validation could not be completed.",
  };
  const authenticitySummary =
    summaries[report.status] || `Validation returned status: ${report.status}`;
  if (report.raw_provenance && report.raw_provenance !== "trusted") {
    return `${authenticitySummary} Signing-key provenance: ${report.raw_provenance}.`;
  }
  return authenticitySummary;
}

export function resolveMediaPath(mediaPath, currentDirectory = process.cwd()) {
  return mediaPath ? resolve(currentDirectory, mediaPath) : undefined;
}

export function createClientTransport(
  serverUrl = process.env.MEDIA_SIGNING_MCP_URL,
) {
  if (serverUrl) return new StreamableHTTPClientTransport(new URL(serverUrl));
  return new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("./server.mjs", import.meta.url))],
    cwd: mcpDirectory,
    stderr: "inherit",
  });
}

export async function runDemo({ mediaPath, caseId, caPath }) {
  const absoluteMediaPath = resolveMediaPath(mediaPath);
  if (!absoluteMediaPath) {
    throw new Error(
      "Usage: npm run demo:stdio -- <path-to-video.mp4> [case-id]",
    );
  }

  const transport = createClientTransport();
  const client = new Client({
    name: "media-signing-demo-client",
    version: "0.1.0",
  });

  try {
    await client.connect(transport);
    const validation = await client.callTool({
      name: "validate_media_file",
      arguments: {
        path: absoluteMediaPath,
        ...(caPath ? { ca_cert_ref: caPath } : {}),
      },
    });
    if (validation.isError)
      throw new Error(validation.content?.[0]?.text || "Validation failed");

    const report = validation.structuredContent;
    console.log(formatReport(report));
    console.log(JSON.stringify(report, null, 2));

    if (caseId && report.status !== "authentic") {
      const logged = await client.callTool({
        name: "log_case_event",
        arguments: {
          case_id: caseId,
          event_type: report.status,
          details: report,
        },
      });
      if (logged.isError)
        throw new Error(
          logged.content?.[0]?.text || "Could not write the case event",
        );
      console.log(logged.content?.[0]?.text);
    }
    return report;
  } finally {
    await transport.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo({
    mediaPath: process.argv[2],
    caseId: process.argv[3],
    caPath: process.env.MEDIA_SIGNING_MCP_CA,
  }).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
