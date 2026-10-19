/** Loopback model observer used by both legs; scripted mode has no upstream.
 * PROVENANCE: SSE shape adapted from tests/lib/fake-anthropic.ts;
 * TLS material reused from eval/lib/tls.ts. NEW bounded capture/dispatch.
 */
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { TlsMaterial } from "../tls.js";
import type { SmokeTask } from "./paired-tasks.js";
import type { PairSide } from "./paired-config.js";

export interface CapturedModelRequest {
  channel: "model" | "inspection";
  path: string;
  body: Record<string, unknown>;
}

type Block = Record<string, any>;
export function resultBlocks(body: Record<string, unknown>): Block[] {
  return ((body.messages ?? []) as Block[]).flatMap((m) => Array.isArray(m.content) ? m.content : [])
    .filter((b) => b.type === "tool_result");
}
export function resultText(block: Block | undefined): string {
  if (!block) return "";
  return typeof block.content === "string" ? block.content : (block.content ?? []).map((c: Block) => c.text ?? "").join("\n");
}

const SYMBOL = /\$MDU:[A-Za-z0-9_]+\[[A-Za-z0-9]+\](?:\.[A-Za-z0-9_<>=/-]+)*/g;

export type Reply = { text: string } | { id: string; tool: string; input: Record<string, unknown> };

function message(reply: Reply, model: string): Record<string, unknown> {
  return {
    id: "msg_paired", type: "message", role: "assistant", model,
    content: "text" in reply ? [{ type: "text", text: reply.text }] : [{ type: "tool_use", id: reply.id, name: reply.tool, input: reply.input }],
    stop_reason: "text" in reply ? "end_turn" : "tool_use", stop_sequence: null,
    usage: { input_tokens: 10, output_tokens: 10 },
  };
}

function stream(reply: Reply, model: string): string {
  const msg = message(reply, model);
  const isText = "text" in reply;
  const block = isText ? { type: "text", text: "" } : { type: "tool_use", id: reply.id, name: reply.tool, input: {} };
  const events = [
    ["message_start", { type: "message_start", message: { ...msg, content: [], stop_reason: null } }],
    ["content_block_start", { type: "content_block_start", index: 0, content_block: block }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: isText ? { type: "text_delta", text: reply.text } : { type: "input_json_delta", partial_json: JSON.stringify(reply.input) } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: msg.stop_reason, stop_sequence: null }, usage: { output_tokens: 10 } }],
    ["message_stop", { type: "message_stop" }],
  ];
  return events.map(([event, data]) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`).join("");
}

/** Prescribed tool choreography: only verifies plumbing, not reasoning utility. */
export function scriptedReply(task: SmokeTask, side: PairSide, body: Record<string, unknown>): Reply {
  const tools = (body.tools ?? []) as Block[];
  if (!tools.some((t) => t.name === "Read")) return { text: "Paired evaluation side-call acknowledgement." };
  const results = resultBlocks(body);
  const get = (id: string) => results.slice().reverse().find((b) => b.tool_use_id === id);
  for (let i = 0; i < task.readOrder.length; i++) {
    if (!get(`pair_read_${i}`)) return { id: `pair_read_${i}`, tool: "Read", input: { file_path: task.readOrder[i] } };
  }
  let output = JSON.stringify(task.expected) + "\n";
  if (side === "wrapped-default") {
    const symbols = task.readOrder.flatMap((p, i) => p in task.inputs ? (resultText(get(`pair_read_${i}`)).match(SYMBOL) ?? []).slice(0, 1) : []);
    if (symbols.length !== Object.keys(task.inputs).length) return { text: "SCRIPT ERROR: expected symbolic input results." };
    if (symbols.length > 1 && !get("pair_inspect")) {
      const inspect = tools.find((t) => t.name === "mcp__mandu-inspect__inspect_symbol");
      if (!inspect) return { text: "SCRIPT ERROR: inspection MCP not advertised." };
      return { id: "pair_inspect", tool: inspect.name, input: { symbols, instruction: `${task.prompt} Use every supplied original; return the complete result.json JSON.` } };
    }
    if (symbols.length === 1) {
    // Combine opaque references through the real filesystem so a single inspect
    // can resolve all inputs. No raw value is supplied by the scripted T-LLM.
    if (!get("pair_bundle")) return { id: "pair_bundle", tool: "Write", input: { file_path: "combined.txt", content: symbols.join("\n") } };
    if (!get("pair_bundle_read")) return { id: "pair_bundle_read", tool: "Read", input: { file_path: "combined.txt" } };
    const symbol = resultText(get("pair_bundle_read")).match(SYMBOL)?.[0];
    if (!symbol) return { text: "SCRIPT ERROR: combined input was not symbolic." };
    if (!get("pair_inspect")) {
      const inspect = tools.find((t) => t.name === "mcp__mandu-inspect__inspect_symbol");
      if (!inspect) return { text: "SCRIPT ERROR: inspection MCP not advertised." };
      return { id: "pair_inspect", tool: inspect.name, input: { symbol, instruction: `${task.prompt} Return only the requested result.json JSON, using the supplied data.` } };
    }
    }
    output = resultText(get("pair_inspect")).match(SYMBOL)?.[0] ?? "";
    if (!output) return { text: "SCRIPT ERROR: inspection did not return a symbol." };
  }
  if (!get("pair_write")) return { id: "pair_write", tool: "Write", input: { file_path: task.outputPath, content: output } };
  if (!get("pair_reread")) return { id: "pair_reread", tool: "Read", input: { file_path: task.outputPath } };
  return { text: `Completed ${task.id}. ${resultText(get("pair_reread"))}` };
}

export async function startScriptedObserver(
  tls: TlsMaterial, task: SmokeTask, side: PairSide, channel: CapturedModelRequest["channel"],
): Promise<{ origin: string; requests: CapturedModelRequest[]; errors: string[]; close(): Promise<void> }> {
  const requests: CapturedModelRequest[] = [];
  const errors: string[] = [];
  const server = createServer(tls, (req, res) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 2 * 1024 * 1024) { errors.push("request capture exceeded 2 MiB"); req.destroy(); }
    });
    req.on("error", () => res.destroy());
    req.on("end", () => {
      try {
        if (req.method !== "POST" || !/^\/v1\/messages(?:\?|$|\/count_tokens)/.test(req.url ?? "")) {
          res.writeHead(404); res.end(); return;
        }
        const body = JSON.parse(data) as Record<string, unknown>;
        requests.push({ channel, path: req.url!, body });
        if (req.url?.includes("count_tokens")) {
          res.setHeader("content-type", "application/json"); res.end('{"input_tokens":10}'); return;
        }
        if (requests.length > 50) throw new Error("scripted request limit exceeded");
        let reply: Reply;
        if (channel === "inspection") {
          const triage = String(body.system).includes("quarantined content classifier");
          const raw = JSON.stringify(body.messages);
          if (!triage && !task.markers.every((m) => raw.includes(m))) throw new Error("inspection did not receive all original inputs");
          reply = { text: triage ? "as_requested" : JSON.stringify(task.expected) };
        } else reply = scriptedReply(task, side, body);
        const model = String(body.model ?? "scripted");
        res.setHeader("content-type", body.stream ? "text/event-stream" : "application/json");
        res.end(body.stream ? stream(reply, model) : JSON.stringify(message(reply, model)));
      } catch (e) {
        errors.push(String(e)); res.writeHead(500); res.end(JSON.stringify({ error: "scripted observer failed" }));
      }
    });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return {
    origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, requests, errors,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
