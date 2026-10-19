/**
 * fake-responses.ts — a scripted, in-process fake OpenAI Responses API for the
 * LIVE Codex CLI e2e (codex-prompt-filter.test.ts and the codex replay suites).
 *
 * Mandu-new test helper. It impersonates `api.openai.com` (the Responses API,
 * `wire_api="responses"`) so a REAL `codex exec` process can be driven through
 * the REAL openai-proxy with NO API key and NO network. The proxy sits between
 * codex and this server:
 *
 *     codex  ──►  openai-proxy (symbolizes function_call_output)  ──►  fake-responses
 *
 * The script drives one agentic turn: codex's first real request (no
 * function_call_output yet) is answered with a `function_call` telling codex to
 * run its shell tool `exec_command` with `cmd = "cat <notesfile>"`. codex
 * executes that locally and sends the command output back as a
 * `function_call_output` item; the proxy symbolizes that output before it reaches
 * us. We then answer with a final text turn so codex prints and exits. Every
 * request body is captured so the test can assert what the model actually saw.
 *
 * Provenance: the SSE event sequences below are ported VERBATIM from the verified
 * spike (`/tmp/fake-responses2.mjs`) — the exact event shapes codex 0.136 accepts
 * for (a) a function_call turn (exec_command with a `cmd`) and (b) a final text
 * turn.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeResponsesConfig {
  /** Absolute path the model "decides" to read (the poisoned file). The fake
   * returns a function_call running `cat <readFilePath>`. */
  readFilePath: string;
  /** Unique substring identifying codex's main agentic request (informational;
   * codex's first turn is detected by the ABSENCE of a function_call_output). */
  promptMarker?: string;
  /** Text returned after the function_call_output turn. */
  finalText?: string;
}

export interface CapturedRequest {
  method: string;
  url: string;
  body: string;
  /** The request headers (the scripted engine records them; codex-chatgpt.test.ts checks the sign-in relay). */
  headers?: http.IncomingHttpHeaders;
  /** When it arrived: epoch ms (Date.now()), as fake-anthropic.ts records it. */
  at: number;
}

export interface FakeResponses {
  origin: string; // http://127.0.0.1:<port>
  requests: CapturedRequest[];
  /** Requests that carry a function_call_output item (the post-exec follow-up). */
  functionCallOutputRequests(): CapturedRequest[];
  close(): Promise<void>;
}

/** Write an SSE event sequence and end the response. */
function send(res: http.ServerResponse, events: Array<[string, unknown]>): void {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  for (const [e, d] of events) {
    res.write(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`);
  }
  res.end();
}

/**
 * The final assistant text turn. Ported verbatim from the spike's `textTurn`.
 */
function textTurn(t: string): Array<[string, unknown]> {
  const m = {
    type: "message",
    id: "msg_f",
    status: "completed",
    role: "assistant",
    content: [{ type: "output_text", text: t, annotations: [] }],
  };
  return [
    ["response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } }],
    [
      "response.output_item.added",
      {
        type: "response.output_item.added",
        output_index: 0,
        item: { type: "message", id: "msg_f", status: "in_progress", role: "assistant", content: [] },
      },
    ],
    [
      "response.content_part.added",
      {
        type: "response.content_part.added",
        item_id: "msg_f",
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      },
    ],
    [
      "response.output_text.delta",
      { type: "response.output_text.delta", item_id: "msg_f", output_index: 0, content_index: 0, delta: t },
    ],
    [
      "response.output_text.done",
      { type: "response.output_text.done", item_id: "msg_f", output_index: 0, content_index: 0, text: t },
    ],
    [
      "response.content_part.done",
      {
        type: "response.content_part.done",
        item_id: "msg_f",
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: t },
      },
    ],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: m }],
    [
      "response.completed",
      {
        type: "response.completed",
        response: { id: "r", status: "completed", output: [m], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } },
      },
    ],
  ];
}

/**
 * A function_call turn invoking codex's shell tool `exec_command` with a `cmd`.
 * Ported verbatim from the spike's `fnTurn`.
 */
function fnTurn(cmd: string): Array<[string, unknown]> {
  const fc = {
    type: "function_call",
    id: "fc_1",
    call_id: "call_1",
    name: "exec_command",
    arguments: JSON.stringify({ cmd }),
    status: "completed",
  };
  return [
    ["response.created", { type: "response.created", response: { id: "r2", status: "in_progress", output: [] } }],
    [
      "response.output_item.added",
      {
        type: "response.output_item.added",
        output_index: 0,
        item: { type: "function_call", id: "fc_1", call_id: "call_1", name: "exec_command", arguments: "" },
      },
    ],
    [
      "response.function_call_arguments.delta",
      { type: "response.function_call_arguments.delta", item_id: "fc_1", output_index: 0, delta: JSON.stringify({ cmd }) },
    ],
    [
      "response.function_call_arguments.done",
      { type: "response.function_call_arguments.done", item_id: "fc_1", output_index: 0, arguments: JSON.stringify({ cmd }) },
    ],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: fc }],
    [
      "response.completed",
      {
        type: "response.completed",
        response: { id: "r2", status: "completed", output: [fc], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } },
      },
    ],
  ];
}

export async function startFakeResponses(cfg: FakeResponsesConfig): Promise<FakeResponses> {
  const requests: CapturedRequest[] = [];
  const finalText = cfg.finalText ?? "CODEX_DONE";

  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const url = req.url ?? "";
      requests.push({ method: req.method ?? "GET", url, body, at: Date.now() });

      if (req.method === "POST" && url.includes("responses")) {
        // Turn 2: codex has sent the command output back as a
        // function_call_output → end the turn with a final text response.
        if (body.includes("function_call_output")) {
          return send(res, textTurn(finalText));
        }
        // Turn 1: instruct codex to run `cat <notesfile>` via exec_command.
        return send(res, fnTurn(`cat ${cfg.readFilePath}`));
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    functionCallOutputRequests: () => requests.filter((r) => r.body.includes("function_call_output")),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// ── The scripted engine (2026-09-05, the codex differential lane) ───────────
// Mirrors fake-anthropic.ts startScriptedAnthropic for the Responses wire so
// the differential harness's agent seam can script codex the same way it
// scripts claude: marker-matched ScriptedExchange[] (never content-matched —
// wrapped function_call_outputs arrive SYMBOLIZED), paced SSE, an ACK
// fallback for anything unmatched.

import type { ScriptedExchange, ScriptedFakeConfig } from "./fake-anthropic.js";
import {
  extractFunctionCallOutputText, lastUserText, responsesFnTurn, responsesTextTurn, writeSse, type ParsedRequest,
} from "./model-wire.js";

// The Responses encoders and extractors live in model-wire.ts since step 5
// WP-A (shared with the drill scripts' engine, replay-engine.ts); re-exported
// so every legacy import keeps working unchanged.
export { extractFunctionCallOutputText, lastUserText, responsesFnTurn, responsesTextTurn };

/** What the differential driver needs from ANY scripted fake, whichever wire. */
export interface ScriptedFake {
  origin: string;
  requests: CapturedRequest[];
  close(): Promise<void>;
}

export async function startScriptedResponses(cfg: ScriptedFakeConfig): Promise<ScriptedFake> {
  const requests: CapturedRequest[] = [];
  const consumed = new Set<ScriptedExchange>();
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      void (async () => {
        const url = req.url ?? "";
        requests.push({ method: req.method ?? "", url, body, headers: req.headers, at: Date.now() });
        if (req.method === "POST" && url.includes("/responses")) {
          const parsed: ParsedRequest = { url, body, hasToolResult: body.includes('"function_call_output"') };
          for (const ex of cfg.script) {
            if (consumed.has(ex)) continue;
            if (!ex.match(parsed)) continue;
            if (ex.once) consumed.add(ex);
            return writeSse(res, ex.respond(parsed), cfg.paceMs ?? 0);
          }
          return writeSse(res, responsesTextTurn(cfg.fallbackText ?? "MDU_LIVE_ACK"), 0);
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{}");
      })();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
