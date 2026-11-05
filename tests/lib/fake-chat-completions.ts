/**
 * fake-chat-completions — a scripted model provider on the OpenAI Chat
 * Completions wire (an OpenRouter / LiteLLM / vLLM / Ollama stand-in) for
 * the Route 1 tests of the OpenClaw plugin (docs/design/agents/
 * openclaw-plugin.md §8.1): it records every request (path, headers, body)
 * and answers each with the SSE a script picks. No key, no network.
 */
import { createServer } from "node:http";

/** One request the stand-in received. */
export interface ChatRequest {
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface ScriptedChat {
  origin: string;
  requests: ChatRequest[];
  close(): Promise<void>;
}

/** Start the stand-in; `respond` returns the SSE text for one request's parsed body. */
export async function startScriptedChat(respond: (body: Record<string, unknown>, req: ChatRequest) => string): Promise<ScriptedChat> {
  const requests: ChatRequest[] = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const r: ChatRequest = { path: req.url ?? "", headers: req.headers, body };
      requests.push(r);
      if (req.method !== "POST") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: [] }));
        return;
      }
      let parsed: Record<string, unknown> = {};
      try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { /* answered as an empty body */ }
      res.writeHead(200, { "content-type": "text/event-stream" });
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

const CHUNK = { id: "chatcmpl-mdu", object: "chat.completion.chunk", created: 1, model: "stand-in" };

function sse(events: unknown[]): string {
  return events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join("") + "data: [DONE]\n\n";
}

/** A turn that calls one tool. */
export function chatToolCallSse(id: string, name: string, args: Record<string, unknown>): string {
  return sse([
    { ...CHUNK, choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id, type: "function", function: { name, arguments: "" } }] }, finish_reason: null }] },
    { ...CHUNK, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: JSON.stringify(args) } }] }, finish_reason: null }] },
    { ...CHUNK, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } },
  ]);
}

/** A turn that answers in text. */
export function chatTextSse(text: string): string {
  return sse([
    { ...CHUNK, choices: [{ index: 0, delta: { role: "assistant", content: text }, finish_reason: null }] },
    { ...CHUNK, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } },
  ]);
}

/** The content of the tool message answering `callId` in a request body
 *  (null: none). An id the agent rewrote (OpenClaw 2026.3.x keeps letters
 *  and digits only) is matched the same way. */
export function chatToolMessage(body: string, callId: string): string | null {
  const norm = (s: string): string => s.replace(/[^A-Za-z0-9]/g, "");
  try {
    const req = JSON.parse(body) as { messages?: Array<{ role?: string; tool_call_id?: string; content?: unknown }> };
    const m = (req.messages ?? []).find((x) => x.role === "tool" && typeof x.tool_call_id === "string" && norm(x.tool_call_id) === norm(callId));
    if (!m) return null;
    if (typeof m.content === "string") return m.content;
    if (Array.isArray(m.content)) return (m.content as Array<{ text?: string }>).map((b) => b.text ?? "").join("");
    return JSON.stringify(m.content);
  } catch { return null; }
}

/** The tool calls an SSE answer hands the agent (what the proxy relayed). */
export function chatSseCalls(text: string): Array<{ id: string; name: string; args: Record<string, unknown> }> {
  const calls = new Map<number, { id: string; name: string; args: string }>();
  for (const ev of text.split("\n\n")) {
    const d = ev.startsWith("data: ") ? ev.slice(6) : "";
    if (!d || d === "[DONE]") continue;
    let o: { choices?: Array<{ delta?: { tool_calls?: Array<{ index: number; id?: string; function?: { name?: string; arguments?: string } }> } }> };
    try { o = JSON.parse(d); } catch { continue; }
    for (const ch of o.choices ?? []) {
      for (const tc of ch.delta?.tool_calls ?? []) {
        const c = calls.get(tc.index) ?? { id: "", name: "", args: "" };
        if (tc.id) c.id = tc.id;
        if (tc.function?.name) c.name = tc.function.name;
        c.args += tc.function?.arguments ?? "";
        calls.set(tc.index, c);
      }
    }
  }
  return [...calls.values()].map((c) => ({ id: c.id, name: c.name, args: c.args ? JSON.parse(c.args) as Record<string, unknown> : {} }));
}
