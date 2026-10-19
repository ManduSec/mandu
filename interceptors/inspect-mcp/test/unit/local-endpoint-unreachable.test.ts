/**
 * local-endpoint-unreachable.test — a declared `local: true` endpoint that
 * fails REFUSES the call, and nothing ever moves to the default U-LLM
 * (confidentiality-plan-11 §8 item 4).
 *
 * The default U-LLM is external: it must never see a `local-model` datum,
 * whatever the local endpoint does (connection refused, timeout, 5xx, a
 * garbage reply), and whichever call fails (the main call, the concurrent
 * content_kind triage, or the contradiction retry). Every case below hands
 * inspect_symbol a recording mock as the default U-LLM and asserts it
 * recorded ZERO calls. The shipped routers the survey found default to the
 * opposite (`on_error: allow`); this suite is the contrast, pinned.
 *
 * The second half drives the PRODUCTION endpoint clients (the ones
 * `buildEndpointUllmClient` builds) against stub transports: their errors
 * name the failure and never quote a response body (a local server may echo
 * the request, and the error string reaches T-LLM).
 *
 * Axes: this package never reads the protection axes; the arbiter does. The
 * mock arbiter plays the confidentiality axis ON (`secrets` / `full`), the
 * only state in which `local-model` symbols exist.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectSymbol, REFUSAL_SHAPE_RE, type InspectSymbolDeps } from "../../src/inspect-symbol.js";
import type { ModelEndpoint, SymbolizeArgs } from "../../src/arbiter-client.js";
import {
  AnthropicUllmClient,
  OpenAiChatUllmClient,
  transportError,
  type UllmCall,
  type UllmClient,
  type UllmResult,
} from "../../src/ullm-client.js";
import { buildEndpointUllmClient, endpointTimeoutMs } from "../../src/ullm-config.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUllm } from "../helpers/mock-ullm.js";
import { TRIAGE_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT_REQUEST } from "../../src/inspect-symbol.js";

const LOCAL = "$MDU:localmodel_Read[5c01]";
const NOTES = "Private notes: the Q4 layoff list is Kim, Park, Lee.";
const OLLAMA: ModelEndpoint = {
  name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true,
};

const isTriage = (c: UllmCall): boolean => c.system === TRIAGE_SYSTEM_PROMPT || c.system === TRIAGE_SYSTEM_PROMPT_REQUEST;

/** A scripted endpoint client: `main` / `triage` / `retry` each either
 *  answer with text or throw the given error. Records every call. */
class ScriptedEndpoint implements UllmClient {
  readonly calls: UllmCall[] = [];
  private mains = 0;
  constructor(private readonly script: {
    main: string | Error;
    triage?: string | Error;
    retry?: string | Error;
  }) {}
  async complete(call: UllmCall): Promise<UllmResult> {
    this.calls.push(call);
    let step: string | Error;
    if (isTriage(call)) step = this.script.triage ?? "substantive";
    else step = this.mains++ === 0 ? this.script.main : this.script.retry ?? this.script.main;
    if (step instanceof Error) throw step;
    return { text: step, model: "llama-local" };
  }
}

class DerivingArbiter extends MockArbiter {
  async symbolizeDerived(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
    return this.symbolize(args);
  }
}

function rig(endpoint: UllmClient) {
  const arbiter = new DerivingArbiter().seed(LOCAL, NOTES).declareEndpoints([OLLAMA]);
  const def = new MockUllm({ reply: "THE DEFAULT MUST NOT RUN", model: "claude-haiku-4-5" });
  const deps: InspectSymbolDeps = {
    arbiter,
    ullm: def,
    sessionId: "test-session",
    now: () => new Date("2026-09-27T00:00:00.000Z"),
    genId: () => "evt-1",
    endpointUllm: () => endpoint,
  };
  return { arbiter, def, deps };
}

// A body a local server could echo back: the request, local-model bytes included.
const ECHO = `{"echo":"${NOTES}"}`;

const FAILURES: Array<[string, Error]> = [
  ["connection refused", transportError(Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } }), new AbortController().signal, 1000)],
  ["timeout", new Error("U-LLM request timed out after 300ms")],
  ["5xx", new Error("U-LLM request failed: 500 Internal Server Error")],
  ["garbage body", new Error("U-LLM response was not valid JSON")],
  ["no content", new Error("U-LLM response carried no choices[0].message.content")],
];

for (const [label, err] of FAILURES) {
  test(`declared endpoint fails (${label}): refused with the by-design text, ZERO default U-LLM calls`, async () => {
    const endpoint = new ScriptedEndpoint({ main: err });
    const { arbiter, def, deps } = rig(endpoint);

    const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize my notes" });
    assert.equal(res.ok, false);
    const text = (res as { error: string }).error;
    assert.match(text, /your declared model 'ollama' did not answer/);
    assert.ok(text.includes(err.message), "the failure is named");
    assert.match(text, /only your own model may read it, so it was not sent to any other model/);
    assert.match(text, /This is by design/);
    assert.match(text, /route the symbol instead; do not retry until they say it is running/);
    assert.ok(!text.includes(NOTES), "no datum byte in the error");
    assert.ok(!text.includes("—"), "no em-dash in user-facing text");

    assert.equal(def.calls.length, 0, "the external default U-LLM is NEVER the fallback");
    assert.ok(endpoint.calls.length >= 1 && endpoint.calls.every((c) => c.user.includes(NOTES)), "every call went to the declared endpoint");
    assert.equal(arbiter.symbolizeCalls.length, 0, "nothing re-symbolized: there is no result");
    assert.equal(arbiter.emitted.length, 0, "no ullm_call event for a call that produced nothing");
  });
}

test("an injected client's error is bounded to one line of 160 characters", async () => {
  const long = new Error(`line one\nline two ${"x".repeat(400)}`);
  const { def, deps } = rig(new ScriptedEndpoint({ main: long }));
  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize" });
  const text = (res as { error: string }).error;
  assert.ok(!/[\r\n]/.test(text));
  assert.ok(!text.includes("x".repeat(200)), "bounded");
  assert.equal(def.calls.length, 0);
});

test("no triage and so no contradiction retry at the declared endpoint (plan 11 §8 row 1); the default is never asked", async () => {
  // A small local model's triage labeled real documents wrong_content live
  // (4 of 4), steering the main model off correct answers: at a user's own
  // model the verdict is the neutral "unknown", and the endpoint gets one call.
  for (const main of ["a summary", "I cannot help with that request."]) {
    const endpoint = new ScriptedEndpoint({ main, triage: "wrong_content", retry: "a retried answer" });
    const { arbiter, def, deps } = rig(endpoint);
    const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize" });
    assert.equal(res.ok, true);
    assert.equal((res as { contentKind: string }).contentKind, "unknown");
    assert.equal(endpoint.calls.length, 1, "the main call only: no triage, no retry");
    assert.equal(endpoint.calls.filter(isTriage).length, 0);
    assert.equal(def.calls.length, 0);
    assert.equal(arbiter.symbolizeCalls[0]?.value, main, "the endpoint's own answer is what is sealed");
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// The production endpoint clients: failures named, bodies never quoted.
// ─────────────────────────────────────────────────────────────────────────────

const GUARD = { forwarderUrl: undefined, proxyUrls: [] as string[] };
const CALL: UllmCall = { system: "s", user: `summarize: ${NOTES}` };

function fetchStub(behavior: "refused" | "500-echo" | "200-garbage" | "200-shapeless" | "hang"): typeof fetch {
  return (async (_url: unknown, init?: { signal?: AbortSignal }) => {
    switch (behavior) {
      case "refused":
        throw Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:11434"), { code: "ECONNREFUSED" }) });
      case "500-echo":
        return new Response(ECHO, { status: 500, statusText: "Internal Server Error" });
      case "200-garbage":
        return new Response(`not json at all ${NOTES}`, { status: 200 });
      case "200-shapeless":
        return new Response(ECHO, { status: 200, headers: { "content-type": "application/json" } });
      case "hang":
        return await new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("This operation was aborted"), { name: "AbortError" })));
        });
    }
  }) as typeof fetch;
}

for (const wire of ["openai-chat", "anthropic"] as const) {
  const client = (behavior: Parameters<typeof fetchStub>[0]): UllmClient =>
    wire === "openai-chat"
      ? new OpenAiChatUllmClient({ baseUrl: OLLAMA.url, model: "llama3.2", sanctionedOrigins: [new URL(OLLAMA.url).origin], timeoutMs: 50, fetchImpl: fetchStub(behavior) })
      : new AnthropicUllmClient({ apiKey: "", requireApiKey: false, errorDetail: false, requireContent: true, baseUrl: OLLAMA.url, sanctionedOrigins: [new URL(OLLAMA.url).origin], timeoutMs: 50, fetchImpl: fetchStub(behavior) });

  const cases: Array<[Parameters<typeof fetchStub>[0], RegExp]> = [
    ["refused", /could not reach the endpoint \(ECONNREFUSED\)/],
    ["500-echo", /500 Internal Server Error/],
    ["200-garbage", /not valid JSON/],
    ["200-shapeless", wire === "openai-chat" ? /no choices\[0\]\.message\.content/ : /no content array/],
    ["hang", /timed out after 50ms/],
  ];
  for (const [behavior, expected] of cases) {
    test(`${wire} endpoint client, ${behavior}: throws a named error that quotes no body`, async () => {
      await assert.rejects(client(behavior).complete(CALL), (err: Error) => {
        assert.match(err.message, expected);
        assert.ok(!err.message.includes(NOTES), `no echoed bytes in: ${err.message}`);
        assert.ok(!err.message.includes("echo"), "no body fragment either");
        return true;
      });
    });
  }
}

test("buildEndpointUllmClient: an anthropic-wire endpoint refuses a shapeless 2xx (it is not an empty answer)", async () => {
  // Through the production builder: requireContent + errorDetail:false are set there.
  const c = buildEndpointUllmClient({ ...OLLAMA, wire: "anthropic" }, [OLLAMA], GUARD, {});
  assert.ok(c instanceof AnthropicUllmClient);
  const inner = c as unknown as { requireContent: boolean; errorDetail: boolean };
  assert.equal(inner.requireContent, true);
  assert.equal(inner.errorDetail, false);
});

test("endpointTimeoutMs: MANDU_ULLM_ENDPOINT_TIMEOUT_MS, a positive integer up to ten minutes; anything else is the default", () => {
  assert.equal(endpointTimeoutMs({}), undefined);
  assert.equal(endpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "300" }), 300);
  assert.equal(endpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: " 120000 " }), 120_000);
  assert.equal(endpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "600000" }), 600_000);
  for (const bad of ["0", "-5", "1.5", "abc", "600001", "99999999", ""]) {
    assert.equal(endpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: bad }), undefined, bad);
  }
  const c = buildEndpointUllmClient(OLLAMA, [OLLAMA], GUARD, { MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "250" });
  assert.equal((c as unknown as { timeoutMs: number }).timeoutMs, 250, "the builder passes it to the client");
});

test("transportError: an abort is a timeout; a coded cause names the code; anything else passes through", () => {
  const aborted = new AbortController();
  aborted.abort();
  assert.match(transportError(new Error("x"), aborted.signal, 42).message, /timed out after 42ms/);
  const live = new AbortController().signal;
  assert.match(transportError(Object.assign(new TypeError("fetch failed"), { cause: { code: "EACCES" } }), live, 1).message, /\(EACCES\)/);
  assert.equal(transportError(new Error("plain"), live, 1).message, "plain");
  // A cause code that is not an errno-shaped token is not echoed.
  assert.equal(transportError(Object.assign(new TypeError("fetch failed"), { cause: { code: "<body bytes>" } }), live, 1).message, "fetch failed");
});
