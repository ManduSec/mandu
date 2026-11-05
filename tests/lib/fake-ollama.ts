/**
 * fake-ollama — a scripted model provider on Ollama's native API
 * (`POST /api/chat`, NDJSON; docs/design/agents/model-wires.md, "The Ollama
 * wire") for the Ollama tests of the model proxy and the OpenClaw plugin's
 * Route 1: it records every request (method, path, headers, body), answers
 * each chat with the NDJSON a script picks, in the shape Ollama sends (one
 * JSON object per line, a final `done: true` line), and answers OpenClaw's
 * model discovery (`GET /api/tags`, `POST /api/show`, `GET /api/version`)
 * with one tool-capable model. No key, no network, no Ollama install.
 */
import { createServer } from "node:http";

/** One request the stand-in received. */
export interface OllamaRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface ScriptedOllama {
  origin: string;
  requests: OllamaRequest[];
  close(): Promise<void>;
}

/** The model the stand-in lists. */
export const FAKE_OLLAMA_MODEL = "qwen3:8b";

/** Start the stand-in; `respond` returns the NDJSON text for one chat's parsed body. */
export async function startScriptedOllama(respond: (body: Record<string, unknown>, req: OllamaRequest) => string): Promise<ScriptedOllama> {
  const requests: OllamaRequest[] = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const r: OllamaRequest = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body };
      requests.push(r);
      const path = (req.url ?? "").split("?")[0];
      const json = (status: number, v: unknown): void => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(v));
      };
      if (req.method === "GET" && path === "/api/tags") {
        json(200, { models: [{ name: FAKE_OLLAMA_MODEL, model: FAKE_OLLAMA_MODEL, modified_at: "2026-10-01T00:00:00Z", size: 1, digest: "0".repeat(64), details: { family: "qwen3", parameter_size: "8B" } }] });
        return;
      }
      if (req.method === "GET" && path === "/api/version") { json(200, { version: "0.12.6" }); return; }
      if (req.method === "POST" && path === "/api/show") {
        json(200, { capabilities: ["completion", "tools"], model_info: { "qwen3.context_length": 32768 }, parameters: "", template: "" });
        return;
      }
      if (req.method !== "POST" || path !== "/api/chat") { json(404, { error: `stand-in: no ${req.method} ${path}` }); return; }
      let parsed: Record<string, unknown> = {};
      try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { /* answered as an empty body */ }
      res.writeHead(200, { "content-type": "application/x-ndjson" });
      res.end(respond(parsed, r));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  return {
    origin: `http://127.0.0.1:${(srv.address() as { port: number }).port}`,
    requests,
    close: () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()); }),
  };
}

function line(message: Record<string, unknown>, done: boolean): string {
  return `${JSON.stringify({
    model: FAKE_OLLAMA_MODEL, created_at: "2026-10-26T00:00:00Z",
    message: { role: "assistant", content: "", ...message }, done,
    ...(done ? { done_reason: "stop", total_duration: 1, prompt_eval_count: 10, eval_count: 5 } : {}),
  })}\n`;
}

/** A turn that answers in text. */
export function ollamaTextNdjson(text: string): string {
  return line({ content: text }, false) + line({}, true);
}

/** A turn that calls one tool (no `id` unless given: Ollama's own answers
 *  often carry none, and the proxy gives one). */
export function ollamaCallNdjson(name: string, args: Record<string, unknown>, id?: string): string {
  return line({ tool_calls: [{ ...(id ? { id } : {}), function: { name, arguments: args } }] }, false) + line({}, true);
}

/** Every tool message a chat request carried. */
export function ollamaToolMessages(body: string): Array<{ toolCallId?: string; toolName?: string; text: string }> {
  let req: { messages?: Array<Record<string, unknown>> };
  try { req = JSON.parse(body) as typeof req; } catch { return []; }
  return (req.messages ?? []).filter((m) => m["role"] === "tool").map((m) => ({
    ...(typeof m["tool_call_id"] === "string" ? { toolCallId: m["tool_call_id"] } : {}),
    ...(typeof m["tool_name"] === "string" ? { toolName: m["tool_name"] } : {}),
    text: typeof m["content"] === "string" ? m["content"] : "",
  }));
}
