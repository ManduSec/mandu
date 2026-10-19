/**
 * coalescer.test — unit matrix for EmitCoalescer (arbiter/events/coalescer.ts).
 *
 * Defense-in-depth backstop (a DIFFERENT layer than net-proxy's self-loop guard):
 * the arbiter collapses a runaway burst of identical-consecutive observability
 * events into the first `burst` verbatim + periodic/run-end `coalesced` summaries,
 * so no single emitter can balloon a session log (the 35,723-event incident). It
 * must NEVER coalesce distinct events or invariant-violating (security) events.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { EmitCoalescer } from "../../events/coalescer.js";
import type { ArbiterEvent } from "../../events/event-store.js";

let n = 0;
function ev(over: Partial<ArbiterEvent> = {}): ArbiterEvent {
  return {
    kind: "net_action",
    sessionId: "s1",
    id: `in-${n++}`,
    ts: "2026-06-21T00:00:00.000Z",
    view: "AgentView",
    boundary: "network",
    emitter: "net-supervisor",
    action: "forwarded",
    method: "GET",
    destination: "127.0.0.1:8790",
    status: 502,
    invariant: { violatedInvariant: false },
    ...over,
  };
}
const fixedNow = (): string => "2026-06-21T12:00:00.000Z";
const suppressedOf = (e: ArbiterEvent): number => (e.coalesced as { suppressed: number }).suppressed;

test("distinct events pass through unchanged (no coalescing)", () => {
  const c = new EmitCoalescer({ burst: 3, now: fixedNow });
  for (let i = 0; i < 6; i++) {
    const out = c.consider(ev({ destination: `host-${i}:80` }));
    assert.equal(out.length, 1);
    assert.equal(out[0]!.action, "forwarded");
  }
});

test("appends the first `burst` identical events, then suppresses the rest", () => {
  const c = new EmitCoalescer({ burst: 3, discloseEvery: 10_000, now: fixedNow });
  let kept = 0;
  for (let i = 0; i < 500; i++) kept += c.consider(ev()).length;
  assert.equal(kept, 3, "a 500-event runaway shrinks to the burst of 3");
});

test("discloses a coalesced summary every `discloseEvery` suppressed events", () => {
  const c = new EmitCoalescer({ burst: 2, discloseEvery: 10, now: fixedNow });
  const out: ArbiterEvent[] = [];
  for (let i = 0; i < 2 + 10 + 10 + 3; i++) out.push(...c.consider(ev()));
  const summaries = out.filter((e) => e.action === "coalesced");
  assert.equal(summaries.length, 2, "two disclosures for 20 suppressed at every-10");
  assert.equal(suppressedOf(summaries[0]!), 10, "running total at first disclosure");
  assert.equal(suppressedOf(summaries[1]!), 20, "running total at second disclosure");
  // A summary is a valid, renderable net_action (canonical ManduEvent shape).
  assert.equal(summaries[0]!.kind, "net_action");
  assert.equal((summaries[0]!.invariant as { violatedInvariant: boolean }).violatedInvariant, false);
  assert.equal(typeof summaries[0]!.id, "string");
  assert.equal(summaries[0]!.ts, fixedNow());
});

test("emits a run-end summary when the run changes after suppression", () => {
  const c = new EmitCoalescer({ burst: 2, discloseEvery: 10_000, now: fixedNow });
  for (let i = 0; i < 7; i++) c.consider(ev()); // 2 kept, 5 suppressed
  const out = c.consider(ev({ destination: "elsewhere.example:443", status: 200 }));
  assert.equal(out.length, 2, "the run-end summary precedes the new (distinct) event");
  assert.equal(out[0]!.action, "coalesced");
  assert.equal(suppressedOf(out[0]!), 5);
  assert.equal(out[1]!.action, "forwarded");
  assert.equal(out[1]!.destination, "elsewhere.example:443");
});

test("a violatedInvariant (security) event is NEVER suppressed", () => {
  const c = new EmitCoalescer({ burst: 1, discloseEvery: 10_000, now: fixedNow });
  c.consider(ev()); // kept (burst=1)
  c.consider(ev()); // suppressed
  // Even a long run of identical *violated* events must all pass through.
  for (let i = 0; i < 20; i++) {
    const out = c.consider(ev({ invariant: { violatedInvariant: true } }));
    assert.ok(
      out.some((e) => (e.invariant as { violatedInvariant: boolean }).violatedInvariant === true),
      "each violated event is emitted, never dropped",
    );
  }
});

test("a run of CLAIMED events never folds a believed one (arbiter-human-plane.md §10.2)", () => {
  const c = new EmitCoalescer({ burst: 2, discloseEvery: 10_000, now: fixedNow });
  // the agent's program floods the session with claimed copies of a real event's shape
  for (let i = 0; i < 50; i++) c.consider(ev({ claimed: true }));
  // MASTER: suppressed into the claimed run (the signature ignored the mark)
  const real = c.consider(ev());
  assert.ok(real.some((e) => e.claimed === undefined && e.kind === "net_action"), "the believed event is stored");
});

test("coalescing is per-session (one session's runaway doesn't suppress another)", () => {
  const c = new EmitCoalescer({ burst: 2, discloseEvery: 10_000, now: fixedNow });
  for (let i = 0; i < 50; i++) c.consider(ev({ sessionId: "noisy" }));
  // A different session's identical-looking events are unaffected by 'noisy'.
  let kept = 0;
  for (let i = 0; i < 2; i++) kept += c.consider(ev({ sessionId: "quiet" })).length;
  assert.equal(kept, 2, "the quiet session keeps its own burst");
});

test("summary ids are unique across disclosures (append requires a unique id)", () => {
  const c = new EmitCoalescer({ burst: 1, discloseEvery: 5, now: fixedNow });
  const ids = new Set<string>();
  for (let i = 0; i < 100; i++) {
    for (const e of c.consider(ev())) if (e.action === "coalesced") ids.add(e.id);
  }
  // 1 kept + 99 suppressed → floor(99/5) = 19 disclosures, all unique ids.
  assert.equal(ids.size, 19);
});
