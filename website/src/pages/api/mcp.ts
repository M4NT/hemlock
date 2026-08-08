export const prerender = false;

import type { APIRoute } from "astro";
import { TOOL_DEFINITIONS, handleTool, type ToolName } from "@hemlock/mcp/tools";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

function ok(id: string | number | undefined, result: unknown) {
  return Response.json({ jsonrpc: "2.0", id: id ?? null, result });
}

function err(id: string | number | undefined, code: number, message: string) {
  return Response.json(
    { jsonrpc: "2.0", id: id ?? null, error: { code, message } },
    { status: 400 }
  );
}

export const POST: APIRoute = async ({ request }) => {
  let body: JsonRpcRequest;
  try {
    body = await request.json();
  } catch {
    return err(undefined, -32700, "Parse error");
  }

  const { id, method, params = {} } = body;

  if (method === "tools/list") {
    return ok(id, { tools: TOOL_DEFINITIONS });
  }

  if (method === "tools/call") {
    const name = (params as { name?: string }).name;
    const args = ((params as { arguments?: Record<string, unknown> }).arguments) ?? {};

    if (!name || !TOOL_DEFINITIONS.some((t) => t.name === name)) {
      return err(id, -32602, `Unknown tool: ${name}`);
    }

    const text = handleTool(name as ToolName, args);
    return ok(id, { content: [{ type: "text", text }] });
  }

  return err(id, -32601, `Method not found: ${method}`);
};

// CORS pre-flight — allow any agent to call this endpoint
export const OPTIONS: APIRoute = () =>
  new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
