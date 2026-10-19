/**
 * lib/fake-upstreams — scripted fake Anthropic / OpenAI upstreams for the eval.
 *
 * Extracted verbatim from run-live.ts (agent-legibility split, behavior-preserving).
 * Each fake serves HTTPS (cert from ./tls) and drives the REAL agent to ATTEMPT one
 * tool command so the live chokepoint has something to block; every request body is
 * captured for diagnostics. startFake* are imported back by the runLive orchestration.
 */

import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import type { TlsMaterial } from "./tls.js";

// ─────────────────────────────────────────────────────────────────────────────
// The scripted FAKE upstreams (lifted + generalized from
// tests/lib/{fake-anthropic,fake-responses}.ts). Unlike the
// integration fakes (which only script a Read), these script an ARBITRARY tool
// command — the attacker command the agent must ATTEMPT — so the live chokepoint
// has something to block. Each captures every request body for diagnostics.
// ─────────────────────────────────────────────────────────────────────────────

export interface CapturedRequest {
  url: string;
  body: string;
}

export interface FakeUpstream {
  origin: string;
  requests: CapturedRequest[];
  close(): Promise<void>;
}

/** What the fake should drive the agent to do for ONE case. */
interface FakeScript {
  /** The marker that identifies the agent's main agentic request. */
  marker: string;
  /** The Bash/shell command the fake tells the agent to run (the attack attempt,
   *  or a benign command). When undefined the fake answers with a final text turn
   *  immediately (used when the benign work is fully in the prompt). */
  command?: string;
  /** TLS material so the fake serves HTTPS (the proxy forwards over HTTPS only). */
  tls: TlsMaterial;
}

function writeSse(res: http.ServerResponse, events: Array<[string, unknown]>): void {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  for (const [event, data] of events) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  res.end();
}

// ── Anthropic Messages fake (Claude target) ──────────────────────────────────

function anthropicTextTurn(text: string): Array<[string, unknown]> {
  return [
    ["message_start", { type: "message_start", message: { id: "msg_mdu_text", type: "message", role: "assistant", model: "claude-fake-mdu", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } }],
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}

function anthropicBashTurn(id: string, command: string): Array<[string, unknown]> {
  return [
    ["message_start", { type: "message_start", message: { id: "msg_mdu_tool", type: "message", role: "assistant", model: "claude-fake-mdu", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } }],
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id, name: "Bash", input: {} } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command, description: "Mandu eval live step" }) } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}

export async function startFakeAnthropic(script: FakeScript): Promise<FakeUpstream> {
  const requests: CapturedRequest[] = [];
  let toolIssued = false;
  const server = https.createServer({ cert: script.tls.cert, key: script.tls.key }, (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const url = req.url ?? "";
      requests.push({ url, body });
      if (url.includes("count_tokens")) {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ input_tokens: 10 }));
      }
      if (req.method === "POST" && url.includes("/v1/messages")) {
        const hasToolResult = body.includes('"tool_result"');
        const mentionsMarker = body.includes(script.marker);
        const hasBashTool = /"name"\s*:\s*"Bash"/.test(body);
        if (hasToolResult) return writeSse(res, anthropicTextTurn("MDU_EVAL_DONE"));
        if (!toolIssued && script.command && mentionsMarker && hasBashTool) {
          toolIssued = true;
          return writeSse(res, anthropicBashTurn("toolu_mdu_eval_1", script.command));
        }
        return writeSse(res, anthropicTextTurn("MDU_EVAL_ACK"));
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `https://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// ── OpenAI Responses fake (Codex target) ─────────────────────────────────────

function responsesTextTurn(t: string): Array<[string, unknown]> {
  const m = { type: "message", id: "msg_f", status: "completed", role: "assistant", content: [{ type: "output_text", text: t, annotations: [] }] };
  return [
    ["response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { type: "message", id: "msg_f", status: "in_progress", role: "assistant", content: [] } }],
    ["response.content_part.added", { type: "response.content_part.added", item_id: "msg_f", output_index: 0, content_index: 0, part: { type: "output_text", text: "" } }],
    ["response.output_text.delta", { type: "response.output_text.delta", item_id: "msg_f", output_index: 0, content_index: 0, delta: t }],
    ["response.output_text.done", { type: "response.output_text.done", item_id: "msg_f", output_index: 0, content_index: 0, text: t }],
    ["response.content_part.done", { type: "response.content_part.done", item_id: "msg_f", output_index: 0, content_index: 0, part: { type: "output_text", text: t } }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: m }],
    ["response.completed", { type: "response.completed", response: { id: "r", status: "completed", output: [m], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}

function responsesFnTurn(cmd: string): Array<[string, unknown]> {
  const fc = { type: "function_call", id: "fc_1", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd }), status: "completed" };
  return [
    ["response.created", { type: "response.created", response: { id: "r2", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { type: "function_call", id: "fc_1", call_id: "call_1", name: "exec_command", arguments: "" } }],
    ["response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", item_id: "fc_1", output_index: 0, delta: JSON.stringify({ cmd }) }],
    ["response.function_call_arguments.done", { type: "response.function_call_arguments.done", item_id: "fc_1", output_index: 0, arguments: JSON.stringify({ cmd }) }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: fc }],
    ["response.completed", { type: "response.completed", response: { id: "r2", status: "completed", output: [fc], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}

export async function startFakeResponses(script: FakeScript): Promise<FakeUpstream> {
  const requests: CapturedRequest[] = [];
  const server = https.createServer({ cert: script.tls.cert, key: script.tls.key }, (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const url = req.url ?? "";
      requests.push({ url, body });
      if (req.method === "POST" && url.includes("responses")) {
        if (body.includes("function_call_output")) return writeSse(res, responsesTextTurn("CODEX_EVAL_DONE"));
        if (script.command) return writeSse(res, responsesFnTurn(script.command));
        return writeSse(res, responsesTextTurn("CODEX_EVAL_ACK"));
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `https://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
