import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";

import { createServer } from "./server.mjs";

const host = "127.0.0.1";
const port = Number.parseInt(process.env.MEDIA_SIGNING_MCP_PORT || "3000", 10);
const app = createMcpExpressApp({ host });

export function describeMcpRequest(body = {}) {
  const method = body.method || "request";
  const detail =
    method === "tools/call" && body.params?.name
      ? ` [${body.params.name}]`
      : "";
  return `${method}${detail}`;
}

app.post("/mcp", async (request, response) => {
  const server = createServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  const requestDescription = describeMcpRequest(request.body);

  console.error(`client -> server: ${requestDescription}`);
  try {
    await server.connect(transport);
    await transport.handleRequest(request, response, request.body);
    console.error(
      `server -> client: ${requestDescription} result (${response.statusCode})`,
    );
  } catch (error) {
    console.error(
      `server -> client: ${requestDescription} failed: ${error.message}`,
    );
    if (!response.headersSent)
      response.status(500).end("Internal server error");
  } finally {
    await transport.close();
    await server.close();
  }
});

app.get("/mcp", (_request, response) =>
  response.status(405).end("Method not allowed"),
);
app.delete("/mcp", (_request, response) =>
  response.status(405).end("Method not allowed"),
);

if (import.meta.url === `file://${process.argv[1]}`) {
  app.listen(port, host, () => {
    console.error(
      `Media Signing MCP demo server ready at http://${host}:${port}/mcp`,
    );
  });
}
