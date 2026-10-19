/**
 * fake-anthropic.ts — a scripted, in-process fake Anthropic Messages API for the
 * LIVE Claude Code e2e (claude-prompt-filter.test.ts, the golden path) and the
 * differential-interactive harness (differential.test.ts).
 *
 * Mandu-new test helper. It impersonates `api.anthropic.com` so a REAL
 * `claude` process can be driven through the REAL anthropic-proxy with NO API key
 * and NO network. The proxy sits between claude and this server:
 *
 *     claude  ──►  anthropic-proxy (symbolizes tool_result)  ──►  fake-anthropic
 *
 * Two layers:
 *
 * 1. `startScriptedAnthropic` — the general engine. A `ScriptedExchange[]`
 *    script is matched IN ORDER against each /v1/messages request (marker-based
 *    matching only — on the wrapped side tool_result content arrives
 *    SYMBOLIZED, so content matching would diverge between the differential
 *    harness's two sides). Responders receive the parsed request and may echo
 *    content out of it (the sharpest fidelity probe: the wrapped reply carries
 *    a `$MDU:` symbol the reply-filter must resolve on the human screen).
 *    `paceMs` spaces the SSE events out — REQUIRED for the differential
 *    harness (differential-interactive.md §5): the reply-filter's eager-hold
 *    bugs (A2/A3/A4) were timing-triggered, and a burst-write fake never
 *    enters those hold windows. Unmatched agentic requests get a short ACK —
 *    this is what absorbs Claude Code's interactive side calls (startup quota
 *    probe, title generation, typeahead).
 *
 * 2. `startFakeAnthropic` — the original one-Read-turn config, now a canned
 *    script over the engine. Behavior is UNCHANGED (claude-code.live and
 *    launcher-golden-path.live depend on it): tool_result → final text;
 *    first marker+Read request → the Read tool_use; anything else → ACK.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";

import {
  extractEchoedContent, extractToolResultText, readToolUseTurn, textTurn, toolUseTurn, writeSse,
  type ParsedRequest, type SseEvent,
} from "./model-wire.js";

// The encoders and extractors live in model-wire.ts since step 5 WP-A (shared
// with the drill scripts' engine, replay-engine.ts); re-exported so every
// legacy import keeps working unchanged.
export { extractEchoedContent, extractToolResultText, readToolUseTurn, textTurn, toolUseTurn };
export type { ParsedRequest, SseEvent };

export interface FakeAnthropicConfig {
  /** Absolute path the model "decides" to Read (the poisoned file). */
  readFilePath: string;
  /** Unique substring identifying claude's main agentic request. */
  promptMarker: string;
  /** Text returned after the tool_result turn. */
  finalText?: string;
}

export interface CapturedRequest {
  url: string;
  body: string;
  /** When it arrived: epoch ms (Date.now()). The replay record puts it on the
   *  side's cast clock (differential-driver.ts SideResult.startedAtMs). */
  at: number;
}

export interface FakeAnthropic {
  origin: string; // http://127.0.0.1:<port>
  requests: CapturedRequest[];
  /** Requests that carry a tool_result block (i.e. the post-Read follow-up). */
  toolResultRequests(): CapturedRequest[];
  close(): Promise<void>;
}

export interface ScriptedExchange {
  /** Marker-based predicate — match on prompt sentinels / structural facts
   *  (hasToolResult), NEVER on tool_result content (symbolized on the wrapped
   *  side of a differential run). */
  match: (req: ParsedRequest) => boolean;
  respond: (req: ParsedRequest) => SseEvent[];
  /** Consume this exchange after its first match. */
  once?: boolean;
}

export interface ScriptedFakeConfig {
  script: ScriptedExchange[];
  /** Reply for unmatched agentic requests (side calls: quota probe, title
   *  generation, typeahead). Default "MDU_LIVE_ACK". */
  fallbackText?: string;
  /** Delay between SSE events when writing a response. 0 (default) = burst.
   *  The differential harness sets this — see the file header. */
  paceMs?: number;
}

export async function startScriptedAnthropic(cfg: ScriptedFakeConfig): Promise<FakeAnthropic> {
  const requests: CapturedRequest[] = [];
  const consumed = new Set<ScriptedExchange>();

  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      void (async () => {
        const url = req.url ?? "";
        requests.push({ url, body, at: Date.now() });

        if (url.includes("count_tokens")) {
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify({ input_tokens: 10 }));
        }

        if (req.method === "POST" && url.includes("/v1/messages")) {
          const parsed: ParsedRequest = { url, body, hasToolResult: body.includes('"tool_result"') };
          for (const ex of cfg.script) {
            if (consumed.has(ex)) continue;
            if (!ex.match(parsed)) continue;
            if (ex.once) consumed.add(ex);
            return writeSse(res, ex.respond(parsed), cfg.paceMs ?? 0);
          }
          // Warmup / title-generation / typeahead / any other turn.
          return writeSse(res, textTurn(cfg.fallbackText ?? "MDU_LIVE_ACK"), 0);
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
    toolResultRequests: () => requests.filter((r) => r.body.includes('"tool_result"')),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export async function startFakeAnthropic(cfg: FakeAnthropicConfig): Promise<FakeAnthropic> {
  return startScriptedAnthropic({
    script: [
      {
        // The post-Read follow-up: the (symbolized) file content is in this
        // request. End the turn. Checked FIRST — same precedence the original
        // hand-rolled handler had.
        match: (r) => r.hasToolResult,
        respond: () => textTurn(cfg.finalText ?? "MDU_LIVE_DONE"),
      },
      {
        // claude's main agentic request: advertises Read, carries our marker,
        // no tool_result yet. Issue the Read tool_use, once.
        match: (r) => !r.hasToolResult && r.body.includes(cfg.promptMarker) && /"name"\s*:\s*"Read"/.test(r.body),
        respond: () => readToolUseTurn("toolu_mdu_live_1", cfg.readFilePath),
        once: true,
      },
    ],
  });
}
