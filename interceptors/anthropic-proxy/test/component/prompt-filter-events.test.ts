/**
 * prompt-filter-events (proxy e2e) — the REAL AnthropicProxy over HTTP, a fake
 * upstream and the mock arbiter's `filterPrompt` (confidentiality-plan-15 §3,
 * §8, phase 1).
 *
 * Proves: the model receives a registered key from the human's prompt only as
 * its symbol, `postgres` stays in the human's text and is masked in a
 * `<system-reminder>`; one `prompt_filter` event per segment with a finding
 * (or a skipped value), not one per resend; the events carry symbols and
 * counts, never the value; a failing filter refuses the request with nothing
 * sent upstream. Plan 15 §13.7: a resend whose earlier finding no longer
 * applies (an exception) records ONE event with no findings and the
 * message's remembered turn, so the note under it clears; later resends
 * record nothing, and the finding coming back records it again; a
 * restarted proxy (a fresh one on the same arbiter) records the same
 * clearing when the arbiter names the noted message's turn, and nothing
 * when it names none (§13.7 item 10). Plan 15 §12
 * (2026-10-04): the arbiter's `onceOnly` (a locked administrator's `ask`
 * row) is copied onto the event's finding, and its lifting is recorded.
 *
 * Axes: secrets (the mock answers as the arbiter does with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";

import { AnthropicProxy, type UpstreamFetcher } from "../../src/proxy.js";
import { CLAUDE_CODE_GATE_SURFACE } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { policyFilter, registeredValueFilter } from "../helpers/mock-prompt-filter.js";
import type { FilterPromptRequest, FilterPromptResult } from "../../src/arbiter-client.js";
import { sseEvent } from "../helpers/mock-upstream.js";

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";
const KEY_SYM = "$MDU:nomodel_env[9c1d]";
const PG_SYM = "$MDU:nomodel_env[5e5e]";

function send(port: number, body: unknown): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": "pf-1" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

const SSE = sseEvent("message_start", { type: "message_start", message: { id: "m1", role: "assistant", content: [] } })
  + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })
  + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "ok" } })
  + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
  + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" } })
  + sseEvent("message_stop", { type: "message_stop" });

async function harness(arb: MockArbiter) {
  const forwarded: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    forwarded.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(SSE)]) };
  };
  const proxy = new AnthropicProxy({ arbiter: arb, sessionKey: "s-pf", log: () => {}, upstream: fetcher });
  const port = await proxy.listen(0);
  return { proxy, port, forwarded };
}

const TURN = {
  model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: {} }],
  messages: [{ role: "user", content: [
    { type: "text", text: "<system-reminder>DB_PASSWORD=postgres</system-reminder>" },
    { type: "text", text: `my key is ${KEY}; log in as postgres` },
  ] }],
};

test("the model reads the key as its symbol, postgres only where the harness wrote it; one event per finding", async () => {
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: registeredValueFilter({ [KEY]: KEY_SYM, postgres: PG_SYM }) });
  const h = await harness(arb);
  try {
    const r1 = await send(h.port, TURN);
    assert.equal(r1.status, 200, r1.body);
    const r2 = await send(h.port, TURN); // the resend of the same turn
    assert.equal(r2.status, 200, r2.body);
    for (const sent of h.forwarded) {
      assert.ok(!sent.includes(KEY), "CONFIDENTIALITY VIOLATION: the registered key reached the model raw");
      assert.ok(sent.includes(KEY_SYM));
      assert.ok(sent.includes(`DB_PASSWORD=${PG_SYM}`), "postgres is masked in the reminder");
      assert.ok(sent.includes("log in as postgres"), "postgres in the human's text passes (prompt floor)");
    }
  } finally {
    await h.proxy.close();
  }
  const events = arb.eventsOfKind("prompt_filter");
  assert.equal(events.length, 2, "one per segment with a finding, not one per resend");
  const detail = events.map((e) => (e as unknown as { promptFilter: { origin: string; skipped: number; findings: Array<{ symbol?: string; action: string }> } }).promptFilter);
  const harnessEv = detail.find((d) => d.origin === "harness")!;
  const humanEv = detail.find((d) => d.origin === "human")!;
  assert.deepEqual(harnessEv.findings.map((f) => [f.action, f.symbol]), [["mask", PG_SYM]]);
  assert.deepEqual(humanEv.findings.map((f) => [f.action, f.symbol]), [["mask", KEY_SYM]]);
  assert.equal(humanEv.skipped, 1);
  for (const e of events) {
    assert.equal(e.emitter, "anthropic-proxy");
    assert.ok(!JSON.stringify(e).includes(KEY), "an event never carries the value");
    assert.ok(!JSON.stringify(e).includes("postgres"), "nor a skipped one");
  }
});

test("FAIL CLOSED: a filter that throws refuses the request and sends nothing upstream", async () => {
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: () => { throw new Error("arbiter down"); } });
  const h = await harness(arb);
  try {
    const r = await send(h.port, TURN);
    assert.equal(r.status, 502);
    assert.equal(h.forwarded.length, 0);
  } finally {
    await h.proxy.close();
  }
});

/** Plan 15 §13.7: a ticket the policy redacts until an exception lets it
 *  through. With a finding the human segment carries its message's turn
 *  reference, as the arbiter's hold layer sets it; with none, no turn. */
const TICKET = "ACME-20417";
const TURN_REF = "7".repeat(32);
function exceptable() {
  const state = { excepted: false };
  const redact = policyFilter([{ needle: TICKET, category: "acme.ticket", action: "redact" }]);
  const fn = (req: FilterPromptRequest): FilterPromptResult => {
    if (state.excepted) {
      return { enforcing: true, dryRun: false, digest: { policy: "p3", packs: "k2", values: "v" }, segments: req.segments.map((s) => ({ id: s.id, origin: s.origin, action: "pass" as const, findings: [], skipped: 0, cached: false })) };
    }
    const r = redact(req);
    return { ...r, segments: r.segments.map((s) => (s.origin === "human" && s.findings.length > 0 ? { ...s, turn: TURN_REF } : s)) };
  };
  return { state, fn };
}

type Detail = { origin: string; action: string; findings: unknown[]; skipped: number; turn?: string; enforcing: boolean };
const detailOf = (e: unknown): Detail => (e as { promptFilter: Detail }).promptFilter;

test("a resend the filter now finds nothing in records one event with no findings and the message's turn; then nothing more (plan 15 §13.7)", async () => {
  const f = exceptable();
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: f.fn });
  const h = await harness(arb);
  const turn = { ...TURN, messages: [{ role: "user", content: [{ type: "text", text: `see ${TICKET} today` }] }] };
  try {
    assert.equal((await send(h.port, turn)).status, 200);
    assert.equal((await send(h.port, turn)).status, 200); // an unchanged resend
    assert.ok(h.forwarded.every((b) => !b.includes(TICKET)), "redacted while no exception lets it through");
    assert.equal(arb.eventsOfKind("prompt_filter").length, 1, "one event for the finding, none for the unchanged resend");
    f.state.excepted = true;
    assert.equal((await send(h.port, turn)).status, 200);
    assert.ok(h.forwarded.at(-1)!.includes(`see ${TICKET} today`), "the exception lets it through");
    const after = arb.eventsOfKind("prompt_filter");
    assert.equal(after.length, 2, "the resend with nothing found records that it has none");
    const cleared = detailOf(after[1]);
    assert.deepEqual([cleared.origin, cleared.action, cleared.findings, cleared.skipped, cleared.turn, cleared.enforcing], ["human", "pass", [], 0, TURN_REF, true],
      "no findings, under the message's remembered turn");
    assert.equal((await send(h.port, turn)).status, 200);
    assert.equal(arb.eventsOfKind("prompt_filter").length, 2, "a further resend records nothing more");
    f.state.excepted = false;
    assert.equal((await send(h.port, turn)).status, 200);
    const back = arb.eventsOfKind("prompt_filter");
    assert.equal(back.length, 3, "the finding coming back is recorded again");
    assert.equal(detailOf(back[2]).findings.length, 1);
    for (const e of back) assert.ok(!JSON.stringify(e).includes(TICKET), "an event never carries the value");
  } finally {
    await h.proxy.close();
  }
});

test("the arbiter's lock rides the event: a finding it says onceOnly is recorded with onceOnly, and the lock going away records the message again without it (plan 15 §12, 2026-10-04)", async () => {
  const state = { locked: true };
  const redact = policyFilter([{ needle: TICKET, category: "acme.ticket", action: "redact" }]);
  const REF = "c".repeat(32);
  const fn = (req: FilterPromptRequest): FilterPromptResult => {
    const r = redact(req);
    return { ...r, segments: r.segments.map((s) => (s.origin === "human" && s.findings.length > 0
      ? { ...s, turn: TURN_REF, findings: s.findings.map((x) => ({ ...x, ref: REF, ...(state.locked ? { onceOnly: true as const } : {}) })) }
      : s)) };
  };
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: fn });
  const h = await harness(arb);
  const turn = { ...TURN, messages: [{ role: "user", content: [{ type: "text", text: `see ${TICKET} today` }] }] };
  type F = { ref?: string; onceOnly?: boolean };
  try {
    assert.equal((await send(h.port, turn)).status, 200);
    assert.equal((await send(h.port, turn)).status, 200); // an unchanged resend
    const first = arb.eventsOfKind("prompt_filter");
    assert.equal(first.length, 1);
    assert.deepEqual((detailOf(first[0]).findings as F[]).map((x) => [x.ref, x.onceOnly]), [[REF, true]], "copied from the arbiter's answer");
    state.locked = false;
    assert.equal((await send(h.port, turn)).status, 200);
    const after = arb.eventsOfKind("prompt_filter");
    assert.equal(after.length, 2, "the lock lifted is a changed outcome: recorded again");
    assert.deepEqual((detailOf(after[1]).findings as F[]).map((x) => [x.ref, x.onceOnly]), [[REF, undefined]], "no lock, no flag");
  } finally {
    await h.proxy.close();
  }
});

test("a message never recorded with a finding records nothing when the filter finds nothing", async () => {
  const f = exceptable();
  f.state.excepted = true;
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: f.fn });
  const h = await harness(arb);
  try {
    assert.equal((await send(h.port, { ...TURN, messages: [{ role: "user", content: [{ type: "text", text: "nothing to find here" }] }] })).status, 200);
    assert.equal(arb.eventsOfKind("prompt_filter").length, 0);
  } finally {
    await h.proxy.close();
  }
});

/** Plan 15 §13.7 item 10: the arbiter names the turn on a NOTED message's
 *  answer with nothing found (holds.ts, noted messages); `noted: false` is
 *  an arbiter that does not (an older one, or a mark it lost). */
function exceptableNoted(noted: { on: boolean }) {
  const f = exceptable();
  const fn = (req: FilterPromptRequest): FilterPromptResult => {
    const r = f.fn(req);
    if (!f.state.excepted || !noted.on) return r;
    return { ...r, segments: r.segments.map((s) => (s.origin === "human" && req.segments.find((x) => x.id === s.id)?.text.includes(TICKET) ? { ...s, turn: TURN_REF } : s)) };
  };
  return { state: f.state, fn };
}

test("a RESTARTED proxy clears a note it never recorded: the arbiter names the noted message's turn on its answer with nothing found (plan 15 §13.7 item 10)", async () => {
  const noted = { on: true };
  const f = exceptableNoted(noted);
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: f.fn });
  const turn = { ...TURN, messages: [{ role: "user", content: [{ type: "text", text: `see ${TICKET} today` }] }] };
  const a = await harness(arb);
  try {
    assert.equal((await send(a.port, turn)).status, 200);
    assert.ok(!a.forwarded.at(-1)!.includes(TICKET), "redacted through proxy A");
  } finally {
    await a.proxy.close();
  }
  assert.equal(arb.eventsOfKind("prompt_filter").length, 1, "proxy A recorded the finding");
  // Proxy B: a fresh process on the same arbiter, an empty ledger.
  f.state.excepted = true;
  const b = await harness(arb);
  try {
    assert.equal((await send(b.port, turn)).status, 200);
    assert.ok(b.forwarded.at(-1)!.includes(`see ${TICKET} today`), "the exception lets it through");
    const after = arb.eventsOfKind("prompt_filter");
    assert.equal(after.length, 2, "B records the cleared outcome");
    const cleared = detailOf(after[1]);
    assert.deepEqual([cleared.origin, cleared.action, cleared.findings, cleared.skipped, cleared.turn], ["human", "pass", [], 0, TURN_REF], "under the arbiter's turn");
    assert.equal((await send(b.port, turn)).status, 200);
    assert.equal(arb.eventsOfKind("prompt_filter").length, 2, "a further resend records nothing more");
  } finally {
    await b.proxy.close();
  }
  // FAIL-CLOSED: an arbiter that names no turn leaves the note standing.
  noted.on = false;
  const c = await harness(arb);
  try {
    assert.equal((await send(c.port, turn)).status, 200);
    assert.equal(arb.eventsOfKind("prompt_filter").length, 2, "no turn named: nothing recorded, the note is kept");
  } finally {
    await c.proxy.close();
  }
});
