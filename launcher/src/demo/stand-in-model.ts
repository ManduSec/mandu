/**
 * demo/stand-in-model — the offline model `mandu demo` talks to
 * (mandu-demo.md §4).
 *
 * A capture server on 127.0.0.1 that speaks both agents' model APIs: the
 * Anthropic Messages API (`/v1/messages`, Claude Code) and the OpenAI
 * Responses API (`/v1/responses`, Codex). It records the exact request body
 * each model proxy forwarded (the demo's evidence of what the AI received)
 * and plays a fixed script, scene by scene:
 *
 *   - a request whose last turn is one of the demo's prompts gets that
 *     scene's tool call: Read `.env` (Claude Code) or `cat .env` (Codex),
 *     then the curl to the bound host, then the curl to the unbound one;
 *   - a request whose last turn is a tool result gets a short text reply.
 *     Scene 1's reply repeats the file as the request showed it, which is
 *     the only way a model can refer to a value it was shown as a
 *     placeholder.
 *
 * It never contacts anything and never sees a key: the demo sends no
 * credentials, and the proxies reach it over plain HTTP only because it is a
 * loopback address (each proxy's `upstreamTransport`).
 *
 * Mandu-new (no reference origin).
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { CMD_READ, codexCell, lastToolResultText, PROMPTS, sceneCommand, withoutNotes, type SceneId } from "./fixture.js";

export type Wire = "anthropic" | "openai";

/** Where the request stands: which scene, and whether the tool ran. Pure. */
export function conversationState(body: string): { scene: SceneId; afterTool: boolean } | null {
  let req: { messages?: Array<{ role?: string; content?: unknown }>; input?: Array<Record<string, unknown>> };
  try { req = JSON.parse(body) as typeof req; } catch { return null; }
  const sceneOf = (t: string): SceneId | null => {
    for (const k of [1, 2, 3] as SceneId[]) if (t.trim() === PROMPTS[k]) return k;
    return null;
  };
  let scene: SceneId | null = null;
  let afterTool = false;
  for (const m of req.messages ?? []) {
    if (m.role !== "user") continue;
    const blocks = typeof m.content === "string" ? [{ type: "text", text: m.content }] : Array.isArray(m.content) ? m.content as Array<Record<string, unknown>> : [];
    for (const b of blocks) {
      const s = b["type"] === "text" && typeof b["text"] === "string" ? sceneOf(b["text"]) : null;
      if (s !== null) { scene = s; afterTool = false; }
      if (b["type"] === "tool_result") afterTool = true;
    }
  }
  for (const it of req.input ?? []) {
    if (it["type"] === "message" && it["role"] === "user" && Array.isArray(it["content"])) {
      for (const c of it["content"] as Array<Record<string, unknown>>) {
        const s = typeof c["text"] === "string" ? sceneOf(c["text"]) : null;
        if (s !== null) { scene = s; afterTool = false; }
      }
    }
    if (it["type"] === "custom_tool_call_output") afterTool = true;
  }
  return scene === null ? null : { scene, afterTool };
}

/** The text reply after a scene's tool ran. Pure. */
export function replyText(scene: SceneId, body: string): string {
  if (scene === 1) {
    // What the request showed, minus Mandu's own notes to the model.
    const seen = withoutNotes(lastToolResultText(body) ?? "").replace(/\n+$/, "");
    return `Your .env sets:\n${seen}`;
  }
  if (scene === 2) return "Done: the request went to Stripe with your key.";
  return "That send was stopped, so the key did not go to paste.example.";
}

function sse(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

const MSG_START = (): string => sse("message_start", {
  type: "message_start",
  message: { id: "msg_demo", type: "message", role: "assistant", content: [], model: "mandu-demo-stand-in", stop_reason: null, usage: { input_tokens: 1, output_tokens: 1 } },
});

/** A complete streamed Messages response carrying one text block. Pure. */
export function anthropicTextSse(text: string): string {
  return [
    MSG_START(),
    sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }),
    sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }),
    sse("content_block_stop", { type: "content_block_stop", index: 0 }),
    sse("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }),
    sse("message_stop", { type: "message_stop" }),
  ].join("");
}

/** A complete streamed Messages response carrying one tool_use. Pure. */
export function anthropicToolSse(id: string, name: string, input: Record<string, unknown>): string {
  return [
    MSG_START(),
    sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id, name, input: {} } }),
    sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } }),
    sse("content_block_stop", { type: "content_block_stop", index: 0 }),
    sse("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }),
    sse("message_stop", { type: "message_stop" }),
  ].join("");
}

/** A complete streamed Responses answer carrying one text message. Pure. */
export function openaiTextSse(text: string): string {
  const m = { type: "message", id: "msg_demo", status: "completed", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] };
  return [
    sse("response.created", { type: "response.created", response: { id: "resp_demo", status: "in_progress", output: [] } }),
    sse("response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { ...m, status: "in_progress", content: [] } }),
    sse("response.output_text.delta", { type: "response.output_text.delta", item_id: "msg_demo", output_index: 0, content_index: 0, delta: text }),
    sse("response.output_text.done", { type: "response.output_text.done", item_id: "msg_demo", output_index: 0, content_index: 0, text }),
    sse("response.output_item.done", { type: "response.output_item.done", output_index: 0, item: m }),
    sse("response.completed", { type: "response.completed", response: { id: "resp_demo", status: "completed", output: [m], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } }),
  ].join("");
}

/** A complete streamed Responses answer carrying one `exec` script cell
 *  (codex-cli ≥ 0.154). Pure. */
export function openaiCellSse(callId: string, input: string): string {
  const item = { type: "custom_tool_call", id: `ctc_${callId}`, call_id: callId, name: "exec", input, status: "completed" };
  return [
    sse("response.created", { type: "response.created", response: { id: "resp_demo", status: "in_progress", output: [] } }),
    sse("response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { ...item, input: "", status: "in_progress" } }),
    sse("response.custom_tool_call_input.delta", { type: "response.custom_tool_call_input.delta", item_id: item.id, output_index: 0, delta: input }),
    sse("response.custom_tool_call_input.done", { type: "response.custom_tool_call_input.done", item_id: item.id, output_index: 0, input }),
    sse("response.output_item.done", { type: "response.output_item.done", output_index: 0, item }),
    sse("response.completed", { type: "response.completed", response: { id: "resp_demo", status: "completed", output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } }),
  ].join("");
}

/**
 * The scripted answer to one forwarded request. `project` is the folder the
 * agent works in (Claude Code's Read names `<project>/.env`; Codex's cell
 * runs there). Pure.
 */
export function scriptedAnswer(wire: Wire, body: string, project: string): string {
  const st = conversationState(body);
  if (st === null) {
    const t = "I am the demo's stand-in model; I only answer the demo's own questions.";
    return wire === "anthropic" ? anthropicTextSse(t) : openaiTextSse(t);
  }
  if (st.afterTool) {
    const t = replyText(st.scene, body);
    return wire === "anthropic" ? anthropicTextSse(t) : openaiTextSse(t);
  }
  const callId = `call_demo_${st.scene}`;
  const cmd = sceneCommand(st.scene);
  if (wire === "openai") return openaiCellSse(callId, codexCell(cmd, project));
  if (cmd === CMD_READ) return anthropicToolSse(`toolu_demo_${st.scene}`, "Read", { file_path: join(project, ".env") });
  return anthropicToolSse(`toolu_demo_${st.scene}`, "Bash", { command: cmd, description: st.scene === 2 ? "List Stripe customers" : "Paste the key" });
}

export interface Captured { wire: Wire; body: string }

export interface StandInModel {
  /** `http://127.0.0.1:<port>`: what each proxy's MANDU_UPSTREAM points at. */
  origin: string;
  /** Every request body a proxy forwarded, in arrival order. */
  bodies: Captured[];
  close: () => Promise<void>;
}

export async function startStandInModel(project: string): Promise<StandInModel> {
  const bodies: Captured[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const path = (req.url ?? "").split("?")[0]!;
      const wire: Wire | null = req.method !== "POST" ? null
        : path === "/v1/messages" ? "anthropic"
          : path === "/v1/responses" ? "openai" : null;
      if (wire === null) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ type: "error", error: { type: "not_found_error", message: "the demo's stand-in model answers only /v1/messages and /v1/responses" } }));
        return;
      }
      const body = Buffer.concat(chunks).toString("utf8");
      bodies.push({ wire, body });
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      res.end(scriptedAnswer(wire, body, project));
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `http://127.0.0.1:${port}`,
    bodies,
    close: () => new Promise<void>((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}
