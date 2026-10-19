/**
 * prompt-filter-hold — the openai-proxy waits out a prompt filter `hold`
 * (src/prompt-filter.ts `waitOutHolds`, `applyPromptFilter`; the
 * anthropic-proxy's twin; confidentiality-plan-15-prompt-filter.md §7,
 * phase 3; §13.5).
 *
 * Proves, on Codex's Responses wire with a scripted `filterPrompt` and a fake
 * clock: a `hold` is asked again (`holds: true`) until the human's answer,
 * which is applied; the deadline's one last ask carries `heldMs` and a hold
 * after it refuses (PromptFilterRefusal); a token count never waits; a
 * cancel refuses with the arbiter's reason (PromptBlocked); the production
 * adapter asks on the HUMAN client, forwarding `holds` and `heldMs`; the
 * agent disconnecting while held (`signal`, `clientGone`) ends the wait at
 * once, no further ask, the poll's timer cleared, nothing forwarded
 * (PromptHoldAbandoned, a PromptFilterRefusal).
 *
 * Axes: secrets (the scripted answers are the arbiter's with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { EventEmitter } from "node:events";

import { applyPromptFilter, clientGone, PromptBlocked, PromptFilterRefusal, PromptHoldAbandoned } from "../../src/prompt-filter.js";
import { ArbiterClientAdapter, type Arbiter, type FilterPromptRequest, type FilterPromptResult, type RealArbiterClient } from "../../src/arbiter-client.js";
import type { ResponsesRequest } from "../../src/responses-types.js";

const TYPED = "deploy falcon today";
const SYM = "$MDU:localmodel_prompt_filter[cb13]";

type Seg = FilterPromptResult["segments"][number];
const finding = (hold: string) => ({ start: 7, end: 13, category: "acme.codename", filterId: "acme-dlp", action: "ask" as const, symbol: SYM, ref: "a".repeat(32), hold: { state: hold as "pending", approvalId: "egr-1" } });
type Shape = Omit<Partial<Seg>, "id" | "origin">;
const HELD: Shape = { action: "hold", hold: { approvalId: "egr-1", timeoutMs: 3_000 }, findings: [finding("pending")] };
const SENT: Shape = { action: "pass", findings: [{ ...finding("sent"), let: "once" }], turn: "b".repeat(32) };
const MASKED: Shape = { action: "rewrite", text: `deploy ${SYM} today`, findings: [finding("timed-out")] };
const CANCEL: Shape = { action: "block", text: `deploy ${SYM} today`, reason: "You cancelled this message in Mandu's Inbox, so nothing was sent to the model.", findings: [finding("cancelled")] };

/** Answers every human segment with the next shape (the last repeats). */
function scripted(shapes: Shape[]) {
  const calls: FilterPromptRequest[] = [];
  const arb = {
    async filterPrompt(req: FilterPromptRequest): Promise<FilterPromptResult> {
      calls.push(req);
      const shape = shapes.length > 1 ? shapes.shift()! : shapes[0]!;
      return {
        segments: req.segments.map((s) => (s.origin === "human"
          ? { id: s.id, origin: s.origin, skipped: 0, cached: false, findings: [], action: "pass", ...structuredClone(shape) } as Seg
          : { id: s.id, origin: s.origin, action: "pass", findings: [], skipped: 0, cached: false })),
        enforcing: true, dryRun: false, digest: { policy: "p", packs: "k", values: "v" },
      };
    },
  } as unknown as Arbiter;
  return { arb, calls };
}

function clock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => { t += ms; } };
}

const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });
const req = (): ResponsesRequest => ({
  model: "gpt-5", tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
  input: [msg("<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), msg(TYPED)],
} as unknown as ResponsesRequest);
const textOf = (r: ResponsesRequest): string => ((r.input as Array<{ content: Array<{ text: string }> }>)[1]!.content[0]!.text);

test("a hold is asked again until the human answers; the answer is applied", async () => {
  const { arb, calls } = scripted([HELD, HELD, SENT]);
  const c = clock();
  const r = req();
  const report = await applyPromptFilter(r, arb, { agent: "codex", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep } });
  assert.equal(calls.length, 3);
  assert.ok(calls.every((q) => q.holds === true && q.heldMs === undefined));
  assert.equal(textOf(r), TYPED, "sent as written: the human's answer");
  assert.equal(report!.segments.find((s) => s.origin === "human")!.turn, "b".repeat(32));
});

test("the deadline: one last ask with heldMs; the default goes; a hold after it refuses", async () => {
  const { arb, calls } = scripted([HELD, HELD, HELD, HELD, HELD, HELD, HELD, HELD, HELD, MASKED]);
  const c = clock();
  const r = req();
  await applyPromptFilter(r, arb, { agent: "codex", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep, pollMs: 500 } });
  assert.equal(typeof calls.at(-1)!.heldMs, "number");
  assert.equal(textOf(r), `deploy ${SYM} today`);
  const stuck = scripted([HELD]);
  const r2 = req();
  await assert.rejects(() => applyPromptFilter(r2, stuck.arb, { agent: "codex", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep } }), PromptFilterRefusal);
  assert.equal(textOf(r2), TYPED);
});

test("a token count never waits; a cancel refuses with the arbiter's reason", async () => {
  const t = scripted([HELD]);
  await assert.rejects(() => applyPromptFilter(req(), t.arb, { agent: "codex", sessionKey: "s1", countOnly: true }), PromptFilterRefusal);
  assert.equal(t.calls[0]!.holds, undefined);
  const k = scripted([HELD, CANCEL]);
  const c = clock();
  await assert.rejects(
    () => applyPromptFilter(req(), k.arb, { agent: "codex", sessionKey: "s1", holdWait: { now: c.now, sleep: c.sleep } }),
    (e: unknown) => e instanceof PromptBlocked && /You cancelled this message/.test(e.message),
  );
});

test("the production adapter asks on the human client, forwarding holds and heldMs", async () => {
  const seen: Array<{ via: string; args: unknown }> = [];
  const mk = (via: string) => ({ filterPrompt: async (args: unknown) => { seen.push({ via, args }); return { segments: [], enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" } }; } });
  const adapter = new ArbiterClientAdapter(mk("data") as unknown as RealArbiterClient, { ...mk("human"), symbolShape: async () => null, sessionRelay: async () => null, noteReserveBlock: async () => {} } as never);
  await adapter.filterPrompt({ session: "s1", agent: "codex", segments: [{ id: "h", origin: "human", text: TYPED }], holds: true, heldMs: 31_000 });
  assert.deepEqual(seen, [{ via: "human", args: { session: "s1", agent: "codex", segments: [{ id: "h", origin: "human", text: TYPED }], holds: true, heldMs: 31_000 } }]);
  await new ArbiterClientAdapter(mk("data") as unknown as RealArbiterClient).filterPrompt({ agent: "codex", segments: [] });
  assert.equal(seen.at(-1)!.via, "data");
});

// ── the agent disconnects while held (plan 15 §13.6 item 13) ──────────────────

const timers = (): number => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;

test("a disconnect while held stops the poll at once: no further ask, nothing forwarded, no timer left", async () => {
  const { arb, calls } = scripted([HELD]);
  const ac = new AbortController();
  const before = timers();
  const r = req();
  // Real timers and a long poll: only the abort can end this wait early.
  const p = applyPromptFilter(r, arb, { agent: "codex", sessionKey: "s1", signal: ac.signal, holdWait: { pollMs: 60_000 } });
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
});

test("a disconnect during an ask: the answer that comes back is dropped, even the human's send; no last ask", async () => {
  const ac = new AbortController();
  const inner = scripted([HELD, SENT]);
  const arb = {
    async filterPrompt(q: FilterPromptRequest) {
      const out = await inner.arb.filterPrompt!(q);
      if (inner.calls.length === 2) ac.abort(); // the agent goes away while this ask is on the wire
      return out;
    },
  } as unknown as Arbiter;
  const c = clock();
  const r = req();
  await assert.rejects(
    () => applyPromptFilter(r, arb, { agent: "codex", sessionKey: "s1", signal: ac.signal, holdWait: { now: c.now, sleep: c.sleep } }),
    PromptHoldAbandoned,
  );
  assert.equal(inner.calls.length, 2);
  assert.ok(inner.calls.every((q) => q.heldMs === undefined));
  assert.equal(textOf(r), TYPED);
});

test("clientGone: a connection closed before the answer aborts; a finished response does not", () => {
  const mk = (finished: boolean) => Object.assign(new EventEmitter(), { writableFinished: finished });
  const gone = mk(false);
  const s1 = clientGone(gone);
  gone.emit("close");
  assert.equal(s1.aborted, true);
  const done = mk(true);
  const s2 = clientGone(done);
  done.emit("close");
  assert.equal(s2.aborted, false);
});
