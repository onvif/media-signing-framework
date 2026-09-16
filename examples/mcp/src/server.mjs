import { execFile as execFileCallback } from "node:child_process";
import { access, appendFile, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const execFile = promisify(execFileCallback);
const moduleDirectory = dirname(fileURLToPath(import.meta.url));
export const mcpDirectory = resolve(moduleDirectory, "..");
export const defaultAdapterPath = join(
  mcpDirectory,
  ".demo",
  "adapter-prefix",
  "bin",
  "media-signing-mcp-validator",
);
export const defaultCaPath = resolve(
  mcpDirectory,
  "..",
  "test-files",
  "ca.pem",
);
export const defaultCaseDirectory = join(mcpDirectory, ".demo", "cases");
const caseIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function resolveAdapterPath(environment = process.env) {
  return environment.MEDIA_SIGNING_MCP_ADAPTER || defaultAdapterPath;
}

export function validateAbsolutePath(value, fieldName) {
  if (!isAbsolute(value)) {
    throw new Error(`${fieldName} must be an absolute path`);
  }
}

async function requireReadableFile(path, description) {
  try {
    await access(path);
  } catch (error) {
    throw new Error(`${description} is not readable: ${path}`, {
      cause: error,
    });
  }
}

export async function runValidator({
  mediaPath,
  caPath,
  adapterPath,
  execute = execFile,
}) {
  validateAbsolutePath(mediaPath, "path");
  validateAbsolutePath(caPath, "ca_cert_ref");
  await requireReadableFile(mediaPath, "Media file");
  await requireReadableFile(caPath, "CA certificate");

  let result;
  try {
    result = await execute(adapterPath, [mediaPath, caPath], {
      encoding: "utf8",
      shell: false,
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    const stderr = error.stderr?.trim();
    throw new Error(
      stderr ? `Validator failed: ${stderr}` : "Validator process failed",
      {
        cause: error,
      },
    );
  }

  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("Validator returned malformed JSON");
  }
}

export async function appendCaseEvent({
  caseId,
  eventType,
  details,
  caseDirectory,
}) {
  if (!caseIdPattern.test(caseId)) {
    throw new Error(
      "case_id must contain 1-64 letters, numbers, underscores, or hyphens",
    );
  }
  if (!eventType.trim()) {
    throw new Error("event_type must not be empty");
  }

  await mkdir(caseDirectory, { recursive: true });
  const casePath = join(caseDirectory, `case_${caseId}.jsonl`);
  const event = {
    timestamp: new Date().toISOString(),
    case_id: caseId,
    event_type: eventType,
    details,
  };
  await appendFile(casePath, `${JSON.stringify(event)}\n`, "utf8");
  return { record_id: `${caseId}:${event.timestamp}`, path: casePath };
}

export function createServer(options = {}) {
  const environment = options.environment || process.env;
  const adapterPath = options.adapterPath || resolveAdapterPath(environment);
  const caPath = options.caPath || defaultCaPath;
  const caseDirectory =
    options.caseDirectory ||
    environment.MEDIA_SIGNING_MCP_CASE_DIRECTORY ||
    defaultCaseDirectory;
  const execute = options.execute || execFile;
  const server = new McpServer({
    name: "media-signing-mcp-demo",
    version: "0.1.0",
  });

  server.registerPrompt(
    "investigate_media",
    {
      description:
        "Validate signed media, explain the result, and optionally record a case event.",
      argsSchema: {
        media_path: z.string().describe("Absolute path to the local MP4 file"),
        case_id: z
          .string()
          .optional()
          .describe("Case ID used when recording warnings or failures"),
      },
    },
    async ({ media_path: mediaPath, case_id: caseId }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text:
              `Validate ${mediaPath} with validate_media_file. Explain the framework result ` +
              "without claiming legal chain of custody or general forensic proof. " +
              (caseId
                ? `If the status is not authentic, record the complete report with log_case_event using case ID ${caseId}.`
                : "Do not create a case event unless I provide a case ID."),
          },
        },
      ],
    }),
  );

  server.registerTool(
    "validate_media_file",
    {
      description: "Validate a local signed H.264/H.265 MP4 media file.",
      inputSchema: {
        path: z.string(),
        ca_cert_ref: z.string().optional(),
      },
    },
    async ({ path, ca_cert_ref: caCertRef }) => {
      try {
        const report = await runValidator({
          mediaPath: path,
          caPath: caCertRef || caPath,
          adapterPath,
          execute,
        });
        return {
          content: [{ type: "text", text: report.status }],
          structuredContent: report,
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: error.message }],
          isError: true,
        };
      }
    },
  );

  server.registerTool(
    "log_case_event",
    {
      description: "Append a structured event to a local case JSONL log.",
      inputSchema: {
        case_id: z.string(),
        event_type: z.string(),
        details: z.record(z.unknown()),
      },
    },
    async ({ case_id: caseId, event_type: eventType, details }) => {
      try {
        const record = await appendCaseEvent({
          caseId,
          eventType,
          details,
          caseDirectory,
        });
        return {
          content: [{ type: "text", text: `Recorded ${record.record_id}` }],
          structuredContent: record,
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: error.message }],
          isError: true,
        };
      }
    },
  );

  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  console.error(
    "Media Signing MCP server ready; waiting for a client on stdio.",
  );
}
