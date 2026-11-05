/**
 * fake-gemini — a scripted model provider on the Google Gemini wire
 * (`…/models/{model}:streamGenerateContent?alt=sse`; docs/design/agents/
 * model-wires.md §4) for the Gemini tests of the model proxy and the OpenClaw
 * plugin's Route 1: it records every request (path, headers, body) and
 * answers each with the SSE a script picks, in the shape the API sends
 * (CRLF-framed `data:` events, one answer object each). No key, no network.
 */
import { createServer } from "node:http";

/** One request the stand-in received. */
export interface GeminiRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface ScriptedGemini {
  origin: string;
  requests: GeminiRequest[];
  close(): Promise<void>;
}

/** Start the stand-in; `respond` returns the SSE text for one POST's parsed body. */
export async function startScriptedGemini(respond: (body: Record<string, unknown>, req: GeminiRequest) => string): Promise<ScriptedGemini> {
  const requests: GeminiRequest[] = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const r: GeminiRequest = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body };
      requests.push(r);
      if (req.method !== "POST") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ models: [] }));
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

function chunk(parts: unknown[], finish?: string): string {
  return `data: ${JSON.stringify({
    candidates: [{ content: { role: "model", parts }, index: 0, ...(finish ? { finishReason: finish } : {}) }],
    modelVersion: "stand-in", responseId: "resp-mdu-gemini",
    ...(finish ? { usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, totalTokenCount: 15 } } : {}),
  })}\r\n\r\n`;
}

/** A turn that answers in text. */
export function geminiTextSse(text: string): string {
  return chunk([{ text }]) + chunk([{ text: "" }], "STOP");
}

/** A turn that calls one tool (no `id` unless given: Gemini's own answers
 *  carry none, and the proxy gives one). */
export function geminiCallSse(name: string, args: Record<string, unknown>, id?: string): string {
  return chunk([{ functionCall: { ...(id ? { id } : {}), name, args } }], "STOP");
}

/** Every function response a request carried, with the text it carries (its
 *  one string leaf, else its JSON). */
export function geminiFunctionResponses(body: string): Array<{ id?: string; name: string; text: string }> {
  const out: Array<{ id?: string; name: string; text: string }> = [];
  let req: { contents?: Array<{ parts?: Array<Record<string, unknown>> }> };
  try { req = JSON.parse(body) as typeof req; } catch { return out; }
  for (const c of req.contents ?? []) {
    for (const p of c.parts ?? []) {
      const fr = (p["functionResponse"] ?? p["function_response"]) as { id?: string; name?: string; response?: unknown } | undefined;
      if (!fr) continue;
      const leaves: string[] = [];
      const walk = (v: unknown): void => {
        if (typeof v === "string") leaves.push(v);
        else if (Array.isArray(v)) v.forEach(walk);
        else if (v !== null && typeof v === "object") for (const [k, x] of Object.entries(v)) { if (k !== "name") walk(x); }
      };
      walk(fr.response);
      out.push({ ...(fr.id ? { id: fr.id } : {}), name: fr.name ?? "", text: leaves.length === 1 ? leaves[0]! : JSON.stringify(fr.response) });
    }
  }
  return out;
}

/** The function calls an SSE answer hands the agent (what the proxy relayed). */
export function geminiSseCalls(text: string): Array<{ id: string; name: string; args: Record<string, unknown> }> {
  const out: Array<{ id: string; name: string; args: Record<string, unknown> }> = [];
  for (const ev of text.split(/\r?\n\r?\n/)) {
    if (!ev.startsWith("data: ")) continue;
    let o: { candidates?: Array<{ content?: { parts?: Array<{ functionCall?: { id?: string; name?: string; args?: Record<string, unknown> } }> } }> };
    try { o = JSON.parse(ev.slice(6)); } catch { continue; }
    for (const c of o.candidates ?? []) {
      for (const p of c.content?.parts ?? []) {
        if (p.functionCall) out.push({ id: p.functionCall.id ?? "", name: p.functionCall.name ?? "", args: p.functionCall.args ?? {} });
      }
    }
  }
  return out;
}
