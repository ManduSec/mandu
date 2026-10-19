/**
 * prompt-filter-hold — the anthropic-proxy waits out a prompt filter `hold`
 * (src/prompt-filter.ts `waitOutHolds`, `applyPromptFilter`;
 * confidentiality-plan-15-prompt-filter.md §7, phase 3; §13.5).
 *
 * Proves, with a scripted `filterPrompt` and a fake clock:
 *   - a `hold` is asked again until the arbiter answers otherwise; the
 *     request carries `holds: true` and the human's answer is what is applied
 *     (as written, or the default);
 *   - at the deadline (the arbiter's `timeoutMs` plus slack, capped) ONE last
 *     ask carries `heldMs`; a hold still standing after it refuses
 *     (PromptFilterRefusal), never forwards;
 *   - a token count never says `holds` and never waits; a `hold` answer to it
 *     refuses;
 *   - a cancel (`block` with the arbiter's reason) refuses the request with
 *     that reason (PromptBlocked → the 400);
 *   - an arbiter error while waiting refuses;
 *   - the agent disconnecting while held (the proxy's `signal`, `clientGone`)
 *     ends the wait at once: no further ask (not even the last one), the
 *     answer of an ask in flight dropped, the poll's timer cleared, nothing
 *     rewritten or forwarded (PromptHoldAbandoned, a PromptFilterRefusal);
 *     a request that is not held is not affected;
 *   - the production adapter sends `filterPrompt` on the HUMAN client when it
 *     has one (only there is a hold filed, plan 13 D9), forwarding `holds`
 *     and `heldMs`.
 *
 * Axes: secrets (the scripted answers are the arbiter's with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { EventEmitter } from "node:events";

import { applyPromptFilter, clientGone, PromptBlocked, PromptFilterRefusal, PromptHoldAbandoned, waitOutHolds } from "../../src/prompt-filter.js";
import { ArbiterClientAdapter, type Arbiter, type FilterPromptRequest, type FilterPromptResult, type RealArbiterClient } from "../../src/arbiter-client.js";
import type { MessagesRequest } from "../../src/messages-types.js";

const TYPED = "deploy falcon today";
const SYM = "$MDU:localmodel_prompt_filter[cb13]";

type Seg = FilterPromptResult["segments"][number];
const answer = (seg: Partial<Seg>): FilterPromptResult => ({
  segments: [{ id: "m0.b0.p0", origin: "human", action: "pass", findings: [], skipped: 0, cached: false, ...seg } as Seg],
  enforcing: true, dryRun: false, digest: { policy: "p", packs: "k", values: "v" },
});
const finding = (hold: string) => ({ start: 7, end: 13, category: "acme.codename", filterId: "acme-dlp", action: "ask" as const, symbol: SYM, ref: "a".repeat(32), hold: { state: hold as "pending", approvalId: "egr-1" } });
const HELD = answer({ action: "hold", hold: { approvalId: "egr-1", timeoutMs: 3_000 }, findings: [finding("pending")] });
const SENT = answer({ action: "pass", findings: [{ ...finding("sent"), let: "once" }], turn: "b".repeat(32) });
const MASKED = answer({ action: "rewrite", text: `deploy ${SYM} today`, findings: [finding("timed-out")] });

function scripted(answers: Array<FilterPromptResult | Error>) {
  const calls: FilterPromptRequest[] = [];
  const arb = {
    async filterPrompt(req: FilterPromptRequest) {
      calls.push(req);
      const a = answers.length > 1 ? answers.shift()! : answers[0]!;
      if (a instanceof Error) throw a;
      return structuredClone(a);
    },
  } as unknown as Arbiter;
  return { arb, calls };
}

function clock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => { t += ms; } };
}

const req = (): MessagesRequest => ({
  model: "claude-sonnet-4-5", max_tokens: 64,
  tools: [{ name: "Read", input_schema: { type: "object" } }],
  messages: [{ role: "user", content: [{ type: "text", text: TYPED }] }],
} as unknown as MessagesRequest);

const textOf = (r: MessagesRequest): string => ((r.messages[0]!.content as Array<{ text: string }>)[0]!.text);

test("a hold is asked again until the human answers; the answer is applied", async () => {
  const { arb, calls } = scripted([HELD, HELD, SENT]);
  const c = clock();
  const r = req();
  const report = await applyPromptFilter(r, arb, { agent: "claude-code", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep } });
  assert.equal(calls.length, 3);
  assert.ok(calls.every((q) => q.holds === true && q.heldMs === undefined), "every ask says it can wait; none is the last ask");
  assert.equal(textOf(r), TYPED, "sent as written: the human's answer");
  assert.equal(report!.segments[0]!.findings[0]!.let, "once");
  assert.equal(report!.segments[0]!.turn, "b".repeat(32));
  assert.deepEqual(report!.replaced, [], "a span sent as written is not a replaced symbol");
});

test("the deadline: one last ask with heldMs; the default goes; a hold after it refuses", async () => {
  const { arb, calls } = scripted([HELD, HELD, HELD, HELD, HELD, HELD, HELD, HELD, HELD, MASKED]);
  const c = clock();
  const r = req();
  await applyPromptFilter(r, arb, { agent: "claude-code", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep, pollMs: 500 } });
  const last = calls.at(-1)!;
  assert.equal(typeof last.heldMs, "number", "the last ask says the hold is over");
  assert.ok(c.now() >= 3_000 && c.now() <= 4_000, `waited the arbiter's deadline plus slack (${c.now()} ms)`);
  assert.equal(textOf(r), `deploy ${SYM} today`, "the default (masked)");

  const stuck = scripted([HELD]);
  const c2 = clock();
  const r2 = req();
  await assert.rejects(() => applyPromptFilter(r2, stuck.arb, { agent: "claude-code", sessionKey: "s1", holdWait: { now: c2.now, sleep: c2.sleep } }), PromptFilterRefusal);
  assert.equal(textOf(r2), TYPED, "nothing rewritten, nothing forwarded (the caller refuses)");
  assert.equal(typeof stuck.calls.at(-1)!.heldMs, "number");
  // The proxy's own cap holds whatever deadline the arbiter claims.
  const long = scripted([answer({ action: "hold", hold: { approvalId: "egr-1", timeoutMs: 10_000_000 }, findings: [finding("pending")] })]);
  const c3 = clock();
  await assert.rejects(() => applyPromptFilter(req(), long.arb, { agent: "claude-code", sessionKey: "s1", holdWait: { now: c3.now, sleep: c3.sleep, maxMs: 5_000 } }), PromptFilterRefusal);
  assert.ok(c3.now() <= 5_000, "capped by maxMs");
});

test("a token count never waits; a hold answer to it refuses", async () => {
  const { arb, calls } = scripted([HELD]);
  await assert.rejects(() => applyPromptFilter(req(), arb, { agent: "claude-code", sessionKey: "s1", countOnly: true }), PromptFilterRefusal);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.holds, undefined, "a token count does not say it can wait (the arbiter answers the default)");
});

test("a cancel refuses with the arbiter's reason; an arbiter error while waiting refuses", async () => {
  const CANCEL = answer({ action: "block", text: `deploy ${SYM} today`, reason: "You cancelled this message in Mandu's Inbox, so nothing was sent to the model.", findings: [finding("cancelled")] });
  const { arb } = scripted([HELD, CANCEL]);
  const c = clock();
  await assert.rejects(
    () => applyPromptFilter(req(), arb, { agent: "claude-code", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep } }),
    (e: unknown) => e instanceof PromptBlocked && /You cancelled this message/.test(e.message),
  );
  const broken = scripted([HELD, new Error("arbiter gone")]);
  await assert.rejects(() => applyPromptFilter(req(), broken.arb, { agent: "claude-code", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep } }), PromptFilterRefusal);
});

test("waitOutHolds: no hold, one ask", async () => {
  let n = 0;
  const out = await waitOutHolds(async () => { n++; return MASKED; }, { canWait: true });
  assert.equal(n, 1);
  assert.equal(out.segments[0]!.action, "rewrite");
});

test("the production adapter asks on the human client, forwarding holds and heldMs", async () => {
  const seen: Array<{ via: string; args: unknown }> = [];
  const mk = (via: string) => ({ filterPrompt: async (args: unknown) => { seen.push({ via, args }); return MASKED; } });
  const adapter = new ArbiterClientAdapter(mk("data") as unknown as RealArbiterClient, { ...mk("human"), symbolShape: async () => null, sessionRelay: async () => null, noteReserveBlock: async () => {} } as never);
  await adapter.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text: TYPED }], holds: true, heldMs: 31_000 });
  assert.deepEqual(seen, [{ via: "human", args: { session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text: TYPED }], holds: true, heldMs: 31_000 } }]);
  const dataOnly = new ArbiterClientAdapter(mk("data") as unknown as RealArbiterClient);
  await dataOnly.filterPrompt({ agent: "claude-code", segments: [] });
  assert.equal(seen.at(-1)!.via, "data", "without a human client: the data socket, where an ask takes its default");
});

// ── the agent disconnects while held (plan 15 §13.6 item 13) ──────────────────

const timers = (): number => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;

test("a disconnect while held stops the poll at once: no further ask, nothing forwarded, no timer left", async () => {
  const { arb, calls } = scripted([HELD]);
  const ac = new AbortController();
  const before = timers();
  const r = req();
  const logs: string[] = [];
  // Real timers and a long poll: only the abort can end this wait early.
  const p = applyPromptFilter(r, arb, { agent: "claude-code", sessionKey: "s1", signal: ac.signal, holdWait: { pollMs: 60_000 }, log: (m) => logs.push(m) });
  await new Promise((res) => setImmediate(res));
  assert.equal(calls.length, 1, "the first ask filed the hold");
  assert.equal(timers(), before + 1, "the poll's timer is armed");
  const t0 = Date.now();
  ac.abort();
  await assert.rejects(p, (e: unknown) => e instanceof PromptHoldAbandoned && e instanceof PromptFilterRefusal);
  assert.ok(Date.now() - t0 < 1_000, "the wait ended with the client, not at the poll");
  assert.equal(calls.length, 1, "no ask after the disconnect");
  assert.equal(timers(), before, "the poll's timer was cleared");
  assert.equal(textOf(r), TYPED, "nothing rewritten (the caller forwards nothing)");
  assert.ok(logs.some((m) => /disconnected while its prompt was held/.test(m)), logs.join("\n"));
});

test("a disconnect during an ask: the answer that comes back is dropped, even the human's send", async () => {
  const ac = new AbortController();
  const calls: FilterPromptRequest[] = [];
  const arb = {
    async filterPrompt(q: FilterPromptRequest) {
      calls.push(q);
      if (calls.length === 1) return structuredClone(HELD);
      ac.abort(); // the agent goes away while this ask is on the wire
      return structuredClone(SENT);
    },
  } as unknown as Arbiter;
  const c = clock();
  const r = req();
  await assert.rejects(
    () => applyPromptFilter(r, arb, { agent: "claude-code", sessionKey: "s1", signal: ac.signal, holdWait: { now: c.now, sleep: c.sleep } }),
    PromptHoldAbandoned,
  );
  assert.equal(calls.length, 2, "no third ask, and no last ask with heldMs");
  assert.ok(calls.every((q) => q.heldMs === undefined));
  assert.equal(textOf(r), TYPED);
});

test("a disconnect before the last ask: it is not made", async () => {
  const ac = new AbortController();
  const { arb, calls } = scripted([HELD]);
  let t = 0;
  const handed: Array<AbortSignal | undefined> = [];
  // The deadline (3 s + slack) passes in one sleep, during which the agent goes.
  const sleep = async (ms: number, signal?: AbortSignal) => { t += ms; handed.push(signal); ac.abort(); };
  await assert.rejects(
    () => applyPromptFilter(req(), arb, { agent: "claude-code", sessionKey: "s1", signal: ac.signal, holdWait: { now: () => t, sleep, pollMs: 10_000 } }),
    PromptHoldAbandoned,
  );
  assert.equal(calls.length, 1);
  assert.deepEqual(handed, [ac.signal], "the sleep is handed the client's signal");
});

test("the signal only ends a wait: a request that is not held goes on", async () => {
  const ac = new AbortController();
  ac.abort();
  const { arb, calls } = scripted([MASKED]);
  const r = req();
  await applyPromptFilter(r, arb, { agent: "claude-code", sessionKey: "s1", signal: ac.signal });
  assert.equal(calls.length, 1);
  assert.equal(textOf(r), `deploy ${SYM} today`);
});

test("clientGone: a connection closed before the answer aborts; a finished response does not", () => {
  const mk = (finished: boolean) => Object.assign(new EventEmitter(), { writableFinished: finished });
  const gone = mk(false);
  const s1 = clientGone(gone);
  assert.equal(s1.aborted, false);
  gone.emit("close");
  assert.equal(s1.aborted, true, "the agent went away mid-request");
  const done = mk(true);
  const s2 = clientGone(done);
  done.emit("close");
  assert.equal(s2.aborted, false, "a response that finished also closes");
});
