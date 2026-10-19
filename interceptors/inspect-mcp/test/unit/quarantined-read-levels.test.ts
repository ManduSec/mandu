/**
 * quarantined-read-levels.test — inspect_symbol per confidentiality level (Plan 7).
 *
 * §3.3 rung 2: `any-model` is READABLE inside the quarantine (the provider
 * is a cleared reader for that datum, and the quarantine shares no T-LLM
 * context), while `no-model` is not (the U-LLM *is* the provider).
 *
 * The arbiter enforces both — it refuses a strict symbol into `resolve(deep)`
 * (returning null) and admits a model-ok one. What THIS suite pins is the
 * inspect-mcp half: that the refusal is REPORTED as a refusal rather than as
 * "unknown symbol", and that a model-ok inspection still returns an opaque,
 * re-symbolized result (never raw content) — the property that makes admitting
 * it safe in the first place.
 *
 * Plan 11 (D3/D5) adds `local-model` (`$MDU:localmodel_`): readable only at a
 * model endpoint policy.yaml `models:` declares `local: true`. inspect-mcp
 * ROUTES such a call to that endpoint (naming it on every resolve, the triage
 * included) and refuses, before any resolve, when none is declared.
 *
 * Axes: this package never reads the protection axes; the arbiter does. The
 * mock arbiter here plays the confidentiality axis ON (`secrets` / `full`),
 * the only state in which leveled symbols exist.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  helperEndpoint,
  inspectSymbol,
  isLocalModelSymbolName,
  isStrictSymbolName,
  type InspectSymbolDeps,
} from "../../src/inspect-symbol.js";
import type { ModelEndpoint, SymbolizeArgs } from "../../src/arbiter-client.js";
import type { UllmClient } from "../../src/ullm-client.js";
import { createEndpointUllmFactory } from "../../src/ullm-config.js";
import { endpointRecord } from "../../src/inspect-symbol.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUllm } from "../helpers/mock-ullm.js";

const STRICT = "$MDU:nomodel_Read[3fa9]";
const MODEL_OK = "$MDU:anymodel_Read[7b21]";
const CONTRACT = "Acme agrees to pay $4,200,000 on 2026-09-30.";
const SUMMARY = "A $4.2M payment agreement due at end of Q3.";

function makeDeps(arbiter: MockArbiter, ullm: MockUllm): InspectSymbolDeps {
  return {
    arbiter,
    ullm,
    sessionId: "test-session",
    now: () => new Date("2026-07-12T00:00:00.000Z"),
    genId: () => "evt-1",
  };
}

test("the strict marker is recognized, and `anymodel_` does NOT match it", () => {
  // The whole level split turns on this prefix not over-matching. `anymodel_` shares
  // three characters with `nomodel_`; an unanchored test would refuse the very level
  // Plan 7 exists to admit, and rung 2 would be dead on arrival.
  assert.equal(isStrictSymbolName(STRICT), true);
  assert.equal(isStrictSymbolName(MODEL_OK), false);
  assert.equal(isStrictSymbolName("$MDU:Read[1234]"), false);
});

test("no-model: the arbiter refuses (null), and inspect_symbol says WHY", async () => {
  // The arbiter's resolve(deep) returns null for a strict symbol — the same
  // shape as "unknown". Reporting it as unknown teaches the model to retry and
  // then improvise a workaround; reporting it as by-design gets the behavior the
  // handling prompt asks for.
  const arbiter = new MockArbiter(); // strict ⇒ the arbiter yields nothing
  const ullm = new MockUllm({ reply: "should never run", model: "m" });
  const res = await inspectSymbol(makeDeps(arbiter, ullm), { symbol: STRICT, instruction: "summarize" });

  assert.equal(res.ok, false);
  assert.match(res.error!, /no-model/);
  assert.match(res.error!, /by design/i);
  assert.match(res.error!, /do not retry/i);
  assert.ok(!/unknown symbol/i.test(res.error!), "a refusal is not an unknown symbol");
  assert.equal(ullm.calls.length, 0, "no vendor model saw the strict datum — the residency claim");
});

test("any-model: the quarantine READS it and returns a re-symbolized answer", async () => {
  const arbiter = new MockArbiter().seed(MODEL_OK, CONTRACT);
  const ullm = new MockUllm({ reply: SUMMARY, model: "claude-haiku-4-5" });
  const res = await inspectSymbol(makeDeps(arbiter, ullm), {
    symbol: MODEL_OK,
    instruction: "summarize this contract",
  });

  assert.equal(res.ok, true);

  // The U-LLM DID see the content — that is exactly what `model-ok` grants.
  // (Two quarantined calls: the inspection itself plus the concurrent
  // content-kind triage, symbol-quality.md §4.2. Both are inside the quarantine.)
  assert.ok(ullm.calls.length >= 1);
  assert.ok(
    ullm.calls.some((c) => c.user.includes(CONTRACT)),
    "the quarantined model read the real contract",
  );

  // ...and what comes BACK is a symbol, not the answer. This is what makes
  // admitting the datum safe: the quarantine's only egress is a labeled symbol.
  const text = JSON.stringify(res);
  assert.ok(!text.includes(CONTRACT), "the contract never returns to T-LLM");
  assert.ok(!text.includes(SUMMARY), "nor does the SUMMARY — it is derived from a secret, so it is a secret");
  assert.match(
    (res as { resultSymbol: string }).resultSymbol, /^\$MDU:/,
    "the result is an opaque symbol",
  );
});

test("the re-symbolized result carries the SOURCE SYMBOL as its origin — the inheritance hook", async () => {
  // inspect-mcp does not send a level, and does not need to: the arbiter derives
  // the inherited label from this `origin` server-side (Plan 7,
  // ArbiterServer.originSymbolLabel). Passing the origin is the ONE thing this
  // side must get right, so pin it — if it ever stopped, the arbiter would mint
  // the summary of a secret as `public` and launder it.
  const arbiter = new MockArbiter().seed(MODEL_OK, CONTRACT);
  const ullm = new MockUllm({ reply: SUMMARY, model: "m" });
  await inspectSymbol(makeDeps(arbiter, ullm), { symbol: MODEL_OK, instruction: "summarize" });

  assert.equal(arbiter.symbolizeCalls.length, 1);
  assert.equal(
    arbiter.symbolizeCalls[0].origin, MODEL_OK,
    "the origin IS the inheritance channel — the arbiter reads the level off this symbol's row",
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Plan 11: local-model routing (D5)
// ─────────────────────────────────────────────────────────────────────────────

const LOCAL = "$MDU:localmodel_Read[5c01]";
const NOTES = "Private notes: the Q4 layoff list is Kim, Park, Lee.";
const OLLAMA: ModelEndpoint = {
  name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true,
};
const CLOUD: ModelEndpoint = {
  name: "litellm", url: "https://llm.example.com", wire: "anthropic", local: false,
};

class DerivingArbiter extends MockArbiter {
  async symbolizeDerived(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
    return this.symbolize(args);
  }
}

/** A deps rig whose endpoint factory hands out one recording mock per
 *  declared endpoint name, so a test can see exactly which wire saw what. */
function routedDeps(arbiter: MockArbiter, def: MockUllm) {
  const perEndpoint = new Map<string, MockUllm>();
  const built: string[] = [];
  const deps: InspectSymbolDeps = {
    ...makeDeps(arbiter, def),
    endpointUllm: (ep: ModelEndpoint): UllmClient => {
      built.push(ep.name);
      let m = perEndpoint.get(ep.name);
      if (!m) { m = new MockUllm({ reply: SUMMARY, model: `${ep.name}-model` }); perEndpoint.set(ep.name, m); }
      return m;
    },
  };
  return { deps, perEndpoint, built };
}

test("the local-model marker is recognized, and neither sibling marker matches it", () => {
  assert.equal(isLocalModelSymbolName(LOCAL), true);
  assert.equal(isLocalModelSymbolName(MODEL_OK), false);
  assert.equal(isLocalModelSymbolName(STRICT), false);
  assert.equal(isLocalModelSymbolName("$MDU:Read_localmodel_x[1234]"), false, "anchored at the prefix");
  assert.equal(isStrictSymbolName(LOCAL), false, "local-model is not the no-model refusal");
});

test("local-model: routed to the declared local endpoint, named on every resolve, no triage there", async () => {
  const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints([CLOUD, OLLAMA]);
  const def = new MockUllm({ reply: "the default must not run", model: "claude-haiku-4-5" });
  const { deps, perEndpoint, built } = routedDeps(arbiter, def);

  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize my notes" });
  assert.equal(res.ok, true);

  assert.equal(def.calls.length, 0, "the external default U-LLM saw nothing");
  assert.deepEqual(built, ["ollama"], "the first local: true entry, not the external one");
  const local = perEndpoint.get("ollama")!;
  assert.equal(local.mainCalls.length, 1);
  assert.ok(local.mainCalls[0].user.includes(NOTES), "the user's own model read the notes");
  // No triage at a user's own model (plan 11 §8 row 1): a small model's
  // verdict steered the main model off correct answers; "unknown" instead.
  assert.equal(local.triageCalls.length, 0, "no triage at a declared local endpoint");
  assert.equal((res as { contentKind: string }).contentKind, "unknown");

  assert.deepEqual(arbiter.resolveRequests, [{ symbol: LOCAL, opts: { endpoint: "ollama" } }]);

  // The answer is still an opaque symbol, and the events name the endpoint.
  const ok = res as { resultSymbol: string; endpoint: { name: string; location: string } };
  assert.match(ok.resultSymbol, /^\$MDU:/);
  assert.ok(!JSON.stringify(res).includes(NOTES));
  assert.deepEqual(ok.endpoint, { name: "ollama", location: "local", placement: "host" });
  assert.equal(arbiter.emitted.length, 1, "the main ullm_call event only");
  for (const e of arbiter.emitted) assert.deepEqual(e.endpoint, { name: "ollama", location: "local", placement: "host" });
});

test("helper: true routes to the marked local entry; without a mark, the first local one; a mark on an outside entry never counts", async () => {
  const lab: ModelEndpoint = { name: "lab", url: "http://10.0.0.5:8000", wire: "openai-chat", model: "qwen", local: true };
  assert.equal(helperEndpoint([CLOUD, OLLAMA, { ...lab, helper: true }])?.name, "lab");
  assert.equal(helperEndpoint([CLOUD, OLLAMA, lab])?.name, "ollama");
  assert.equal(helperEndpoint([{ ...CLOUD, helper: true }, lab])?.name, "lab", "the helper only uses your own models");
  assert.equal(helperEndpoint([{ ...CLOUD, helper: true }]), undefined);

  const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints([CLOUD, OLLAMA, { ...lab, helper: true }]);
  const def = new MockUllm({ reply: "the default must not run", model: "claude-haiku-4-5" });
  const { deps, perEndpoint, built } = routedDeps(arbiter, def);
  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize my notes" });
  assert.equal(res.ok, true);
  assert.deepEqual(built, ["lab"]);
  assert.equal(perEndpoint.get("ollama"), undefined, "the first local entry saw nothing");
  assert.deepEqual(arbiter.resolveRequests, [{ symbol: LOCAL, opts: { endpoint: "lab" } }], "the resolve names the helper's entry");
  assert.equal(def.calls.length, 0);
});

test("local-model with NO local endpoint declared: refused by design BEFORE any resolve, zero model calls", async () => {
  for (const declared of [[], [CLOUD]]) {
    const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints(declared);
    const def = new MockUllm({ reply: "must not run" });
    const { deps, built } = routedDeps(arbiter, def);

    const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize" });
    assert.equal(res.ok, false);
    const err = (res as { error: string }).error;
    assert.match(err, /local-model/);
    assert.match(err, /readable only by your own model and none is declared in policy\.yaml `models:`/);
    assert.match(err, /by design/i);
    assert.match(err, /route the symbol instead, and do not retry/);
    assert.ok(!err.includes(NOTES));
    assert.equal(arbiter.resolveCalls.length, 0, "no resolve: no raw byte ever entered this process");
    assert.equal(def.calls.length, 0, "the default U-LLM is never the fallback");
    assert.deepEqual(built, [], "no endpoint client was built");
    assert.equal(arbiter.emitted.length, 0);
  }
});

test("local-model on an arbiter without the modelEndpoints op, or with a failing one: refused, no fallback", async () => {
  const old = new MockArbiter().seed(LOCAL, NOTES); // op undefined, like an older arbiter
  const def1 = new MockUllm();
  const r1 = await inspectSymbol(routedDeps(old, def1).deps, { symbol: LOCAL, instruction: "summarize" });
  assert.equal(r1.ok, false);
  assert.match((r1 as { error: string }).error, /modelEndpoints/);
  assert.equal(old.resolveCalls.length, 0);
  assert.equal(def1.calls.length, 0);

  const failing = new MockArbiter({ failModelEndpoints: true }).seed(LOCAL, NOTES).declareEndpoints([OLLAMA]);
  const def2 = new MockUllm();
  const r2 = await inspectSymbol(routedDeps(failing, def2).deps, { symbol: LOCAL, instruction: "summarize" });
  assert.equal(r2.ok, false);
  assert.match((r2 as { error: string }).error, /modelEndpoints failed/);
  assert.equal(failing.resolveCalls.length, 0);
  assert.equal(def2.calls.length, 0);
});

test("an endpoint client that cannot be built (e.g. the proxy's address) refuses before any resolve", async () => {
  const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints([OLLAMA]);
  const def = new MockUllm();
  const deps: InspectSymbolDeps = {
    ...makeDeps(arbiter, def),
    endpointUllm: () => { throw new Error("declared model endpoint 'ollama' is the model proxy's address"); },
  };
  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize" });
  assert.equal(res.ok, false);
  assert.match((res as { error: string }).error, /your declared model 'ollama' is unusable/);
  assert.equal(arbiter.resolveCalls.length, 0);
  assert.equal(def.calls.length, 0);
});

test("the arbiter refusing a local-model datum at the named endpoint is reported as a refusal", async () => {
  // The arbiter decides from ITS registry; if it disagrees (say the entry
  // was removed between the list and the resolve) it returns null.
  const arbiter = new MockArbiter().declareEndpoints([OLLAMA]); // LOCAL unseeded ⇒ null
  const { deps, perEndpoint } = routedDeps(arbiter, new MockUllm());
  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize" });
  assert.equal(res.ok, false);
  const err = (res as { error: string }).error;
  assert.match(err, /local-model and the arbiter refused it at your declared model 'ollama'/);
  assert.match(err, /do not retry/);
  assert.equal(perEndpoint.get("ollama")?.calls.length ?? 0, 0, "nothing to send, nothing sent");
});

test("multi-input mixing local-model and any-model routes the WHOLE call to the local endpoint", async () => {
  const arbiter = new DerivingArbiter().seed(MODEL_OK, CONTRACT).seed(LOCAL, NOTES).declareEndpoints([OLLAMA]);
  const def = new MockUllm({ reply: "must not run" });
  const { deps, perEndpoint } = routedDeps(arbiter, def);

  const res = await inspectSymbol(deps, { symbols: [MODEL_OK, LOCAL], instruction: "merge both" });
  assert.equal(res.ok, true);
  assert.equal(def.calls.length, 0, "no input went to the external default, not even the any-model one");
  const local = perEndpoint.get("ollama")!;
  assert.equal(local.mainCalls.length, 1);
  assert.ok(local.mainCalls[0].user.includes(CONTRACT));
  assert.ok(local.mainCalls[0].user.includes(NOTES));
  assert.deepEqual(arbiter.resolveRequests, [
    { symbol: MODEL_OK, opts: { endpoint: "ollama" } },
    { symbol: LOCAL, opts: { endpoint: "ollama" } },
  ]);
});

test("any-model-only inputs still go to the default U-LLM, with today's resolve request and no endpoint lookup", async () => {
  const arbiter = new MockArbiter().seed(MODEL_OK, CONTRACT).declareEndpoints([OLLAMA]);
  const def = new MockUllm({ reply: SUMMARY, model: "claude-haiku-4-5" });
  const { deps, built } = routedDeps(arbiter, def);

  const res = await inspectSymbol(deps, { symbol: MODEL_OK, instruction: "summarize" });
  assert.equal(res.ok, true);
  assert.equal(def.mainCalls.length, 1);
  assert.equal(def.triageCalls.length, 1, "triage on the same (default) endpoint");
  assert.deepEqual(built, []);
  assert.equal(arbiter.modelEndpointsCalls, 0, "the endpoint list is not even consulted");
  assert.deepEqual(arbiter.resolveRequests, [{ symbol: MODEL_OK }], "no endpoint field: byte-for-byte today");
  for (const e of arbiter.emitted) assert.deepEqual(e.endpoint, { name: "default", location: "external" });
});

test("a local-model datum never resolves on the default path (the mock mirrors the arbiter's admission)", async () => {
  // Belt check on the rig itself: without an endpoint the arbiter treats the
  // resolve as external and refuses a local-model symbol.
  const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints([OLLAMA]);
  assert.equal(await arbiter.resolve(LOCAL), null);
  assert.equal(await arbiter.resolve(LOCAL, { endpoint: "litellm" }), null);
  assert.equal(await arbiter.resolve(LOCAL, { endpoint: "ollama" }), NOTES);
});

test("plan 12 D2: a local-model read bound for plain http on another machine is refused BEFORE any resolve, zero model calls", async () => {
  const lab: ModelEndpoint = { name: "lab", url: "http://10.0.3.7:8000", wire: "openai-chat", model: "qwen", local: true };
  const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints([lab]);
  const def = new MockUllm({ reply: "must not run" });
  const deps: InspectSymbolDeps = { ...makeDeps(arbiter, def), endpointUllm: createEndpointUllmFactory({}) };
  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "summarize my notes" });
  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.match(res.error, /your declared model 'lab' is unusable: .*plain http on another machine/);
    assert.ok(!res.error.includes(NOTES), "no raw byte in the error");
  }
  assert.deepEqual(arbiter.resolveRequests, [], "nothing was resolved");
  assert.equal(def.calls.length, 0);
});

test("plan 12 D6: the event record names the placement, and plainHttp only for an opted-in plain-http call to another machine", () => {
  const base: ModelEndpoint = { name: "m", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "q", local: true };
  assert.deepEqual(endpointRecord(base), { name: "m", location: "local", placement: "host" });
  assert.deepEqual(endpointRecord({ ...base, url: "https://llm.corp.example/v1" }), { name: "m", location: "local", placement: "network" });
  assert.deepEqual(endpointRecord({ ...base, url: "http://10.0.3.7:8000", allowPlainHttp: true }), { name: "m", location: "local", placement: "network", plainHttp: true });
  assert.deepEqual(endpointRecord({ ...base, url: "http://localhost:18000" }), { name: "m", location: "local", placement: "host" }, "a tunnel is on this computer");
});
