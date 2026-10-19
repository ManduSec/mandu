/**
 * prompt-filter-events (proxy e2e) — the REAL OpenAiProxy over HTTP, a mock
 * provider and the mock arbiter's `filterPrompt` (confidentiality-plan-15 §3,
 * §8, phase 1), for Codex's Responses wire.
 *
 * Proves: a registered key in the human's message reaches the provider only
 * as its symbol, `postgres` stays in the typed text and is masked in the
 * AGENTS.md message; one `prompt_filter` event per segment with a finding,
 * not one per resend, never carrying the value; a failing filter is a 502
 * with nothing sent. Plan 15 §13.7: a resend whose earlier finding no longer
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

import { OpenAiProxy } from "../../src/proxy.js";
import { MockArbiter, type MockArbiterOptions } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";
import { policyFilter, registeredValueFilter } from "../helpers/mock-prompt-filter.js";
import type { FilterPromptRequest, FilterPromptResult } from "../../src/arbiter-client.js";

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";
const KEY_SYM = "$MDU:nomodel_env[9c1d]";
const PG_SYM = "$MDU:nomodel_env[5e5e]";

function send(port: number, body: unknown): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": "pf-codex", authorization: "Bearer sk-test-not-real" } },
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

async function withProxy(opts: MockArbiterOptions, fn: (port: number, upstream: MockUpstream, arbiter: MockArbiter) => Promise<void>): Promise<void> {
  const arbiter = new MockArbiter(opts);
  const upstream = new MockUpstream({ json: { id: "r1", object: "response", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "ok" }] }] } });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try { await fn(port, upstream, arbiter); } finally { await proxy.close(); }
}

const TURN = {
  model: "gpt-5", stream: false, tools: [{ type: "function", name: "exec_command", parameters: {} }],
  input: [
    { type: "message", role: "user", content: [{ type: "input_text", text: "# AGENTS.md instructions for /w\n\nDB_PASSWORD=postgres" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: `my key is ${KEY}; log in as postgres` }] },
  ],
};

test("the provider reads the key as its symbol, postgres only where the harness wrote it; one event per finding", async () => {
  await withProxy({ filterPromptFn: registeredValueFilter({ [KEY]: KEY_SYM, postgres: PG_SYM }) }, async (port, upstream, arbiter) => {
    for (let i = 0; i < 2; i++) {
      const r = await send(port, TURN);
      assert.equal(r.status, 200, r.body);
    }
    assert.equal(upstream.requests.length, 2);
    for (const sent of upstream.requests) {
      assert.ok(!sent.bodyText.includes(KEY), "CONFIDENTIALITY VIOLATION: the registered key reached the provider raw");
      assert.ok(sent.bodyText.includes(KEY_SYM));
      assert.ok(sent.bodyText.includes(`DB_PASSWORD=${PG_SYM}`));
      assert.ok(sent.bodyText.includes("log in as postgres"), "postgres in the human's text passes (prompt floor)");
    }
    const events = arbiter.eventsOfKind("prompt_filter");
    assert.equal(events.length, 2, "one per segment with a finding, not one per resend");
    for (const e of events) {
      assert.equal(e.emitter, "openai-proxy");
      assert.ok(!JSON.stringify(e).includes(KEY) && !JSON.stringify(e).includes("postgres"), "never the value");
    }
    const human = events.map((e) => (e as unknown as { promptFilter: { origin: string; skipped: number; agent: string } }).promptFilter).find((d) => d.origin === "human")!;
    assert.equal(human.skipped, 1);
    assert.equal(human.agent, "codex");
  });
});

test("FAIL CLOSED: a filter that throws is a 502 and the provider receives nothing", async () => {
  await withProxy({ filterPromptFn: () => { throw new Error("arbiter down"); } }, async (port, upstream) => {
    const r = await send(port, TURN);
    assert.equal(r.status, 502);
    assert.equal(upstream.requests.length, 0);
  });
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
  await withProxy({ filterPromptFn: f.fn }, async (port, upstream, arbiter) => {
    const turn = { ...TURN, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: `see ${TICKET} today` }] }] };
    assert.equal((await send(port, turn)).status, 200);
    assert.equal((await send(port, turn)).status, 200); // an unchanged resend
    assert.ok(upstream.requests.every((q) => !q.bodyText.includes(TICKET)), "redacted while no exception lets it through");
    assert.equal(arbiter.eventsOfKind("prompt_filter").length, 1, "one event for the finding, none for the unchanged resend");
    f.state.excepted = true;
    assert.equal((await send(port, turn)).status, 200);
    assert.ok(upstream.requests.at(-1)!.bodyText.includes(`see ${TICKET} today`), "the exception lets it through");
    const after = arbiter.eventsOfKind("prompt_filter");
    assert.equal(after.length, 2, "the resend with nothing found records that it has none");
    const cleared = detailOf(after[1]);
    assert.deepEqual([cleared.origin, cleared.action, cleared.findings, cleared.skipped, cleared.turn, cleared.enforcing], ["human", "pass", [], 0, TURN_REF, true],
      "no findings, under the message's remembered turn");
    assert.equal((await send(port, turn)).status, 200);
    assert.equal(arbiter.eventsOfKind("prompt_filter").length, 2, "a further resend records nothing more");
    f.state.excepted = false;
    assert.equal((await send(port, turn)).status, 200);
    const back = arbiter.eventsOfKind("prompt_filter");
    assert.equal(back.length, 3, "the finding coming back is recorded again");
    assert.equal(detailOf(back[2]).findings.length, 1);
    for (const e of back) assert.ok(!JSON.stringify(e).includes(TICKET), "an event never carries the value");
  });
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
  type F = { ref?: string; onceOnly?: boolean };
  await withProxy({ filterPromptFn: fn }, async (port, _upstream, arbiter) => {
    const turn = { ...TURN, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: `see ${TICKET} today` }] }] };
    assert.equal((await send(port, turn)).status, 200);
    assert.equal((await send(port, turn)).status, 200); // an unchanged resend
    const first = arbiter.eventsOfKind("prompt_filter");
    assert.equal(first.length, 1);
    assert.deepEqual((detailOf(first[0]).findings as F[]).map((x) => [x.ref, x.onceOnly]), [[REF, true]], "copied from the arbiter's answer");
    state.locked = false;
    assert.equal((await send(port, turn)).status, 200);
    const after = arbiter.eventsOfKind("prompt_filter");
    assert.equal(after.length, 2, "the lock lifted is a changed outcome: recorded again");
    assert.deepEqual((detailOf(after[1]).findings as F[]).map((x) => [x.ref, x.onceOnly]), [[REF, undefined]], "no lock, no flag");
  });
});

test("a message never recorded with a finding records nothing when the filter finds nothing", async () => {
  const f = exceptable();
  f.state.excepted = true;
  await withProxy({ filterPromptFn: f.fn }, async (port, _upstream, arbiter) => {
    assert.equal((await send(port, { ...TURN, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "nothing to find here" }] }] })).status, 200);
    assert.equal(arbiter.eventsOfKind("prompt_filter").length, 0);
  });
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
  const arbiter = new MockArbiter({ filterPromptFn: f.fn });
  const upstream = new MockUpstream({ json: { id: "r1", object: "response", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "ok" }] }] } });
  const turn = { ...TURN, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: `see ${TICKET} today` }] }] };
  const run = async (fn: (port: number) => Promise<void>) => {
    const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
    const port = await proxy.listen(0);
    try { await fn(port); } finally { await proxy.close(); }
  };
  await run(async (port) => {
    assert.equal((await send(port, turn)).status, 200);
    assert.ok(!upstream.requests.at(-1)!.bodyText.includes(TICKET), "redacted through proxy A");
  });
  assert.equal(arbiter.eventsOfKind("prompt_filter").length, 1, "proxy A recorded the finding");
  // Proxy B: a fresh process on the same arbiter, an empty ledger.
  f.state.excepted = true;
  await run(async (port) => {
    assert.equal((await send(port, turn)).status, 200);
    assert.ok(upstream.requests.at(-1)!.bodyText.includes(`see ${TICKET} today`), "the exception lets it through");
    const after = arbiter.eventsOfKind("prompt_filter");
    assert.equal(after.length, 2, "B records the cleared outcome");
    const cleared = detailOf(after[1]);
    assert.deepEqual([cleared.origin, cleared.action, cleared.findings, cleared.skipped, cleared.turn], ["human", "pass", [], 0, TURN_REF], "under the arbiter's turn");
    assert.equal((await send(port, turn)).status, 200);
    assert.equal(arbiter.eventsOfKind("prompt_filter").length, 2, "a further resend records nothing more");
  });
  // FAIL-CLOSED: an arbiter that names no turn leaves the note standing.
  noted.on = false;
  await run(async (port) => {
    assert.equal((await send(port, turn)).status, 200);
    assert.equal(arbiter.eventsOfKind("prompt_filter").length, 2, "no turn named: nothing recorded, the note is kept");
  });
});
