/**
 * quota-probe-429.test.ts — deterministic reproduction of the live-found
 * "429'd quota probe steals the delivery zone" bug (session 1783733223-3201158,
 * fixed in dashboard commit 08ce27e), pinned across the REAL components so it
 * can never regress silently.
 *
 * Mandu (tests/). Claude Code fires a background startup quota probe —
 * a stateless request with ONE user message "quota", max_tokens=1, NO tools.
 * Live, the upstream 429'd that probe, so the anthropic-proxy emitted a
 * tllm_call whose output is its synthesized explainer ("⚠ no model response —
 * upstream HTTP 429 (rate-limited): …", proxy.ts emitTllmCall). Before the fix,
 * the dashboard's dual-lanes builder no longer recognized the probe as a side
 * call (the explainer escapes the ≤8-char one-token check), rendered the
 * explainer as the LAST response card, and stole `final` — the delivery zone —
 * from the reply the human actually received.
 *
 * The dashboard's own unit tests pin this over hand-built events; THIS test
 * pins the CROSS-PACKAGE contract with the real producer in the loop:
 *   1. A real ArbiterServer on a temp socket (temp event store + symbol DB) and
 *      the REAL AnthropicProxy over its ArbiterClientAdapter — the full-stack /
 *      replay-e2e harness. NO network, NO agent, NO key: the injectable
 *      UpstreamFetcher stub answers the conversation request with a canned SSE
 *      text reply and the probe request with the HTTP 429 error body
 *      api.anthropic.com sends ({"type":"error","error":{"type":
 *      "rate_limit_error",…}}). retry.maxAttempts=1 so the 429 relays
 *      immediately instead of burning the default ~1-2 min backoff budget.
 *   2. Two POSTs under one session id: the conversation turn (system + user
 *      prompt + a non-empty `tools` array — the agent loop always carries the
 *      tool battery), then the errored probe, so the explainer tllm_call lands
 *      LAST — the exact event order that stole the delivery zone live.
 *   3. The events are read back via the arbiter `events()` op (the dashboard's
 *      data source) and pushed through the dashboard's PURE toDualLanes:
 *      exactly one response card (the real reply) holding `final`, no "quota"
 *      input card, and no no-model-response explainer card carrying `final`.
 *   4. The proxy side of the contract is pinned too: the probe's tllm_call
 *      event exists and its output.symbolized starts with the 429 explainer —
 *      if the proxy ever stops emitting that shape, this goes red HERE, not in
 *      a live session.
 *
 * Deliberately NOT asserted: the tllm_call `callShape` field (structural
 * side-call detection) — it is landing in a parallel change; this test must
 * hold with or without it (the string-shape detector alone already passes it).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── REAL components under test (imported across package boundaries) ───────────
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { toDualLanes } from "../../dashboard/src/view-model.js";
import type { ManduEvent } from "../../dashboard/src/event-model.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** Static-type bridge real-arbiter-client → proxy adapter (see proxy-replay.test.ts). */
function bridge(client: ArbiterClient): ConstructorParameters<typeof AnthropicProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    recordToolCall: (args) => client.recordToolCall(args),
    // Phase-0 exec gate (exec-routing.md §3): absent = the adapter fails CLOSED
    // and every model-emitted Bash command becomes the block sentinel.
    execGate: (req) => client.execGate(req as never) as never,
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    // the value backstop (a side call's text, the exec legs), as the real client has it
    scanSecretValues: (text) => client.scanSecretValues(text),
    // the prompt filter (confidentiality-plan-15 §3.2), as the real client has it
    filterPrompt: (args: Parameters<ArbiterClient["filterPrompt"]>[0]) => client.filterPrompt(args),
    close: () => client.close(),
  };
}

/** POST a Messages request to the proxy; collect the full (streamed) response. */
function postMessages(
  port: number,
  headers: Record<string, string>,
  body: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path: "/v1/messages",
        headers: { "content-type": "application/json", ...headers },
      },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Poll the arbiter `events()` op until `predicate` is satisfied or we time out
 * (mirrors full-stack.test.ts): proxy emission is best-effort + async, off the
 * security path, so events may land a tick after the HTTP response completes.
 */
async function waitForEvents(
  client: ArbiterClient,
  sessionId: string,
  predicate: (events: ManduEvent[]) => boolean,
  timeoutMs = 5000,
): Promise<ManduEvent[]> {
  const deadline = Date.now() + timeoutMs;
  let last: ManduEvent[] = [];
  while (Date.now() < deadline) {
    last = (await client.events(sessionId)) as unknown as ManduEvent[];
    if (predicate(last)) return last;
    await new Promise((r) => setTimeout(r, 25));
  }
  return last;
}

// ── The two request shapes, verbatim from the live session ────────────────────

/** The reply the human actually received — must keep the delivery zone. */
const REPLY_TEXT = 'The word "security" appears 12 times in the document.';

/** A conversation-shaped turn: system + user prompt + a non-empty tool battery
 *  (the agent loop always sends one — what separates it from harness side calls). */
function conversationRequest(): string {
  return JSON.stringify({
    model: "claude-opus-4",
    stream: true,
    max_tokens: 4096,
    system: "You are Claude Code.",
    tools: [
      {
        name: "Read",
        description: "Read a file from the filesystem.",
        input_schema: { type: "object", properties: { file_path: { type: "string" } } },
      },
    ],
    messages: [{ role: "user", content: "count the word security in docs/design/architecture/mandu.md" }],
  });
}

/** The startup quota probe: a lone "quota" user message, max_tokens=1, NO tools. */
function quotaProbeRequest(): string {
  return JSON.stringify({
    model: "claude-opus-4",
    max_tokens: 1,
    messages: [{ role: "user", content: "quota" }],
  });
}

/** The rate-limit error body api.anthropic.com relays on a 429. */
const RATE_LIMIT_BODY = {
  type: "error",
  error: {
    type: "rate_limit_error",
    message: "Number of requests has exceeded your per-minute rate limit.",
  },
};

test(
  "quota-probe-429: an upstream-429'd quota probe emits the proxy explainer and never steals the dashboard delivery zone",
  { timeout: 30_000 },
  async () => {
    // ── 1. Real arbiter on a temp socket; real proxy over a dispatching stub ──
    const tmp = mkdtempSync(join(tmpdir(), "mandu-quota-429-"));
    const socketPath = join(tmp, "arbiter.sock");
    const arbiter = new ArbiterServer({
      socketPath,
      humanSocketPath: humanSockIn(tmp),
      dbPath: join(tmp, "symbols.sqlite"),
      eventDir: join(tmp, "events"),
      log: () => {},
    });
    await arbiter.listen();

    const proxyClient = new ArbiterClient(socketPath);
    await proxyClient.connect();
    // The test's event reads ride the human plane (arbiter-human-plane.md).
    const readClient = new ArbiterClient(humanSockIn(tmp));
    await readClient.connect();

    // The stub upstream: the conversation turn gets a normal SSE text reply;
    // the probe (lone "quota" user message) gets the 429 error body. Dispatch
    // on the FORWARDED body so the test proves the real proxy routed each.
    const convoUpstream = new MockUpstream({ sse: buildTextSse(REPLY_TEXT) });
    const probeUpstream = new MockUpstream({ status: 429, json: RATE_LIMIT_BODY });
    const upstream: UpstreamFetcher = async (req) => {
      const parsed = JSON.parse(req.body.toString("utf8")) as {
        messages?: Array<{ role?: string; content?: unknown }>;
      };
      const users = (parsed.messages ?? []).filter((m) => m.role === "user");
      const isProbe = users.length === 1 && users[0]!.content === "quota";
      return isProbe ? probeUpstream.fetcher(req) : convoUpstream.fetcher(req);
    };

    const proxy = new AnthropicProxy({
      arbiter: new AnthropicProxyArbiterAdapter(bridge(proxyClient)),
      upstream,
      // One attempt: relay the 429 immediately (the default policy retries
      // 429s with backoff for a ~1-2 min budget — pointless against a stub).
      retry: { maxAttempts: 1 },
      log: () => {},
    });
    const port = await proxy.listen(0);

    const sessionId = `quota-probe-429-${Date.now()}`;
    const headers = { "x-mandu-session-id": sessionId };

    try {
      // ── 2. The conversation turn, then the errored probe (explainer lands LAST) ─
      const convoRes = await postMessages(port, headers, conversationRequest());
      assert.equal(convoRes.status, 200, "conversation turn relayed 200");
      // Reassemble the relayed SSE text deltas (the fixture splits the reply
      // across chunks, so a raw substring match would straddle a boundary).
      const streamed = convoRes.body
        .split("\n")
        .filter((l) => l.startsWith("data: "))
        .map((l) => JSON.parse(l.slice(6)) as { type?: string; delta?: { type?: string; text?: string } })
        .filter((d) => d.type === "content_block_delta" && d.delta?.type === "text_delta")
        .map((d) => d.delta!.text ?? "")
        .join("");
      assert.equal(streamed, REPLY_TEXT, "the real reply reached the client");

      const probeRes = await postMessages(port, headers, quotaProbeRequest());
      assert.equal(probeRes.status, 429, "the probe's 429 is relayed unmasked");
      assert.ok(probeRes.body.includes("rate_limit_error"), "the error body is relayed unchanged");

      // The stub dispatch actually exercised both paths (guards the fixture).
      assert.equal(convoUpstream.requests.length, 1, "conversation turn forwarded upstream once");
      assert.equal(probeUpstream.requests.length, 1, "probe forwarded upstream once (no retry storm)");

      // ── 3. The proxy side of the contract: the probe's tllm_call explains the 429 ─
      const events = await waitForEvents(
        readClient,
        sessionId,
        (evs) => evs.filter((e) => e.kind === "tllm_call").length >= 2,
      );
      const tllmCalls = events.filter((e) => e.kind === "tllm_call");
      assert.equal(tllmCalls.length, 2, "one tllm_call per exchange");

      const probeCall = tllmCalls.find((e) => /\n▸ user\nquota$/.test(e.input?.symbolized ?? ""));
      assert.ok(probeCall, "the probe's tllm_call event was emitted");
      assert.ok(
        (probeCall!.output?.symbolized ?? "").startsWith("⚠ no model response — upstream HTTP 429"),
        `the probe's output is the proxy's 429 explainer (got: ${JSON.stringify(probeCall!.output?.symbolized)})`,
      );

      const convoCall = tllmCalls.find((e) => e !== probeCall);
      assert.ok(convoCall, "the conversation turn's tllm_call event was emitted");
      assert.equal(convoCall!.output?.symbolized, REPLY_TEXT, "the conversation turn recorded the real reply");

      // ── 4. The dashboard side: the explainer never takes the delivery zone ──────
      const dv = toDualLanes(events);

      const responses = dv.steps.filter((s) => s.step === "response");
      assert.equal(responses.length, 1, "the errored probe mints no response card");
      const reply = responses[0]!;
      if (reply.step !== "response") throw new Error("unreachable: filtered to response steps");
      assert.equal(reply.text, REPLY_TEXT, "the one response card is the reply the human received");
      assert.equal(reply.final, true, "the delivered reply keeps the delivery zone");

      // The probe seeds no input endpoint; the real prompt still renders one.
      assert.ok(
        !dv.steps.some((s) => s.step === "input" && s.text === "quota"),
        'the probe minted no "quota" input card',
      );
      assert.ok(
        dv.steps.some((s) => s.step === "input" && s.text.includes("count the word security")),
        "the real prompt renders as the entry endpoint",
      );

      // Defense in depth: however future dual-lanes changes render the
      // explainer (no card today; an explanatory non-final card is also
      // acceptable), it must NEVER carry `final` — nothing was delivered.
      for (const s of dv.steps) {
        if (s.step === "response" && s.text.trimStart().startsWith("⚠ no model response")) {
          assert.equal(s.final, false, "a no-model-response explainer card must never be the delivered reply");
        }
      }
    } finally {
      await proxy.close();
      proxyClient.close();
      readClient.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);
