/**
 * eager-sync.test — the coalescing sync driver in isolation (no git, no
 * arbiter): the fs-sync.md §2.3 coalescing rule, the tool_result →
 * WriteProvenance mapping (§4), and the §5 fail-safe degradation contract
 * (a failing sync warns and the driver keeps consuming — never throws, never
 * leaves an unhandled rejection).
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { EagerSync, type EagerSyncTarget } from "../../src/eager-sync.js";
import type { Logger, WriteProvenance } from "../../src/view-sync.js";

/** A controllable sync target: records provenance; resolves when told to
 * (deferred), so tests can hold a sync "in flight" while triggers arrive. */
class MockTarget implements EagerSyncTarget {
  readonly calls: WriteProvenance[] = [];
  /** When set, syncToHuman rejects with this error instead of parking. */
  failWith?: Error;
  /** When true, syncToHuman resolves immediately (no deferred gate). */
  auto = false;
  private gates: Array<() => void> = [];

  async syncToHuman(prov: WriteProvenance): Promise<string[]> {
    this.calls.push(prov);
    if (this.failWith) throw this.failWith;
    if (!this.auto) await new Promise<void>((r) => this.gates.push(r));
    return [];
  }

  /** Release the oldest in-flight sync. */
  release(): void {
    const gate = this.gates.shift();
    assert.ok(gate, "release() called with no sync in flight");
    gate();
  }
}

function capturingLog(): { log: Logger; warns: string[] } {
  const warns: string[] = [];
  return {
    warns,
    log: { info: () => {}, warn: (m) => warns.push(m), error: () => {} },
  };
}

/** A minimal tool_result event as the anthropic-proxy emits it (verified
 * against real session NDJSON): the tool name rides output.symbols[].tool. */
function toolResult(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "ev_x",
    sessionId: "sess-1",
    kind: "tool_result",
    callId: "toolu_1",
    output: {
      symbolized: "$MDU:Bash[abcd]",
      original: "raw",
      differs: true,
      symbols: [{ name: "$MDU:Bash[abcd]", tool: "Bash", field: null, origin: null, value: "raw" }],
    },
    ...over,
  };
}

/** Let queued microtasks run (the driver hands off between syncs on await). */
const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

test("coalescing: a burst of N triggers during one in-flight sync → exactly 2 syncs, the second with the LATEST provenance", async () => {
  const target = new MockTarget();
  const driver = new EagerSync({ target });

  // Trigger 1 starts a sync; it parks in-flight on the mock's gate.
  driver.handleEvent(toolResult({ callId: "toolu_1" }));
  await tick();
  assert.equal(target.calls.length, 1, "first trigger started a sync");
  assert.equal(target.calls[0]!.callId, "toolu_1");

  // A rapid burst while in flight: all coalesce into ONE pending slot.
  for (let i = 2; i <= 6; i++) {
    driver.handleEvent(toolResult({ callId: `toolu_${i}` }));
  }
  await tick();
  assert.equal(target.calls.length, 1, "burst did not start extra syncs while one is in flight");

  target.release(); // finish sync 1 → the pending run starts
  await tick();
  assert.equal(target.calls.length, 2, "one pending sync ran after the in-flight one");
  assert.equal(target.calls[1]!.callId, "toolu_6", "the pending run carries the LATEST provenance");

  target.release(); // finish sync 2
  await driver.idle();
  assert.equal(target.calls.length, 2, "no further syncs after the queue drained");
});

test("mapping: symbols[].tool wins; tool_use correlation covers a trusted (symbol-less) result; else the fallback", async () => {
  const target = new MockTarget();
  target.auto = true;
  const driver = new EagerSync({ target });

  // (a) UNTRUSTED result → tool from output.symbols[0].tool.
  driver.handleEvent(toolResult({ callId: "toolu_a", sessionId: "sess-42" }));
  await driver.idle();
  assert.deepEqual(target.calls[0], { toolName: "Bash", callId: "toolu_a", runId: "sess-42" });

  // (b) TRUSTED result (no symbols) whose tool_use we saw → learned name.
  driver.handleEvent({
    kind: "tool_use",
    callId: "toolu_b",
    input: { symbolized: 'Write({"file_path":"/x","content":"$MDU:Bash[abcd]"})' },
  });
  driver.handleEvent(
    toolResult({
      callId: "toolu_b",
      output: { symbolized: "File created", original: "File created", differs: false, symbols: [] },
    }),
  );
  await driver.idle();
  assert.equal(target.calls[1]!.toolName, "Write");
  assert.equal(target.calls[1]!.callId, "toolu_b");

  // (c) no symbols, no correlated tool_use → honest fallback.
  driver.handleEvent(
    toolResult({ callId: "toolu_c", output: { symbolized: "ok", original: "ok", differs: false, symbols: [] } }),
  );
  await driver.idle();
  assert.equal(target.calls[2]!.toolName, "tool_result");
});

test("non-tool_result kinds and malformed events never trigger (and never throw)", async () => {
  const target = new MockTarget();
  target.auto = true;
  const { log, warns } = capturingLog();
  const driver = new EagerSync({ target, log });

  driver.handleEvent(toolResult({ kind: "tllm_call" }));
  driver.handleEvent(toolResult({ kind: "symbolize" }));
  driver.handleEvent({ kind: "tool_use", callId: "toolu_x", input: { symbolized: "Read({...})" } });
  driver.handleEvent(null);
  driver.handleEvent("not an event");
  driver.handleEvent(42);
  driver.handleEvent({}); // no kind at all
  driver.handleEvent({ kind: "tool_result", callId: 7, output: "garbage", sessionId: null });
  await driver.idle();

  // Only the garbage tool_result triggers (it IS a tool_result — the driver is
  // tolerant and degrades its provenance rather than dropping the trigger).
  assert.equal(target.calls.length, 1);
  assert.deepEqual(target.calls[0], { toolName: "tool_result", callId: undefined, runId: undefined });
  assert.equal(warns.length, 0, "tolerant mapping needs no warning");
});

test("FAIL-SAFE: a throwing sync warns and the driver keeps consuming (no unhandled rejection)", async () => {
  const target = new MockTarget();
  target.auto = true;
  target.failWith = new Error("git exploded");
  const { log, warns } = capturingLog();
  const driver = new EagerSync({ target, log });

  driver.handleEvent(toolResult({ callId: "toolu_fail" }));
  await driver.idle();
  assert.equal(target.calls.length, 1);
  assert.equal(driver.syncsFailed, 1);
  assert.equal(warns.length, 1, "the failure was warned about");
  assert.match(warns[0]!, /post-exit sweep/, "the warn names the catch-all");
  assert.match(warns[0]!, /toolu_fail/, "the warn carries the provenance");

  // The driver is still alive: the next trigger syncs normally.
  target.failWith = undefined;
  driver.handleEvent(toolResult({ callId: "toolu_ok" }));
  await driver.idle();
  assert.equal(target.calls.length, 2, "the driver kept consuming after the failure");
  assert.equal(target.calls[1]!.callId, "toolu_ok");
  assert.equal(driver.syncsRun, 2);
});

test("session scoping: only a POSITIVE mismatch skips; unknown and throwing filters degrade to sync-on-any", async () => {
  const target = new MockTarget();
  target.auto = true;
  const verdicts = new Map<string, boolean | undefined>([
    ["sess-ours", true],
    ["sess-other", false],
    ["sess-unknown", undefined],
  ]);
  const driver = new EagerSync({
    target,
    sessionMatches: (sessionId) => {
      if (sessionId === "sess-throws") throw new Error("matcher exploded");
      return verdicts.get(sessionId);
    },
  });

  driver.handleEvent(toolResult({ callId: "t1", sessionId: "sess-ours" }));
  await driver.idle();
  driver.handleEvent(toolResult({ callId: "t2", sessionId: "sess-other" }));
  await driver.idle();
  driver.handleEvent(toolResult({ callId: "t3", sessionId: "sess-unknown" }));
  await driver.idle();
  driver.handleEvent(toolResult({ callId: "t4", sessionId: "sess-throws" }));
  await driver.idle();

  assert.deepEqual(
    target.calls.map((c) => c.callId),
    ["t1", "t3", "t4"],
    "matched, unknown, and throwing-filter events sync; only the proven mismatch is skipped",
  );
});

test("idle() resolves immediately when nothing is running", async () => {
  const driver = new EagerSync({ target: new MockTarget() });
  await driver.idle(); // must not hang
});

// ── HumanView → AgentView: reconcile rides the same slot (cadence §5a) ───────
// Live (watch U27): nothing called reconcileHumanEdits at runtime, so a file
// the human edited mid-session kept its pre-edit twin.

class TwoWayTarget extends MockTarget {
  readonly order: string[] = [];
  reconcileFailWith?: Error;
  async reconcileHumanEdits(): Promise<unknown> {
    this.order.push("reconcile");
    if (this.reconcileFailWith) throw this.reconcileFailWith;
    return null;
  }
  override async syncToHuman(prov: WriteProvenance): Promise<string[]> {
    this.order.push(`sync:${prov.toolName}`);
    return super.syncToHuman(prov);
  }
}

test("every sync run reconciles FIRST, in the same slot", async () => {
  const target = new TwoWayTarget();
  target.auto = true;
  const driver = new EagerSync({ target });
  driver.handleEvent(toolResult());
  await driver.idle();
  assert.deepEqual(target.order, ["reconcile", "sync:Bash"]);
});

test("the human-edit clock's run is RECONCILE-ONLY: it never commits the agent's pending writes under no callId", async () => {
  const target = new TwoWayTarget();
  target.auto = true;
  const driver = new EagerSync({ target });
  driver.triggerReconcile();
  await driver.idle();
  assert.deepEqual(target.order, ["reconcile"]);
  assert.equal(target.calls.length, 0);
  assert.equal(driver.syncsRun, 0);
});

test("a clock tick during an in-flight sync parks ONE reconcile; it never replaces a parked sync", async () => {
  const target = new TwoWayTarget();
  const driver = new EagerSync({ target });
  driver.handleEvent(toolResult({ callId: "toolu_a" }));
  await new Promise((r) => setImmediate(r)); // reconcile done, sync A parked on its gate
  driver.triggerReconcile();
  driver.triggerReconcile();
  driver.handleEvent(toolResult({ callId: "toolu_b" })); // a real sync takes the slot
  driver.triggerReconcile(); // …and keeps it
  target.release();
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  target.release();
  await driver.idle();
  assert.deepEqual(target.order, ["reconcile", "sync:Bash", "reconcile", "sync:Bash"]);
  assert.deepEqual(target.calls.map((c) => c.callId), ["toolu_a", "toolu_b"]);
});

test("FAIL-SAFE: a throwing reconcile warns, the sync still runs, nothing rejects out of the driver", async () => {
  const target = new TwoWayTarget();
  target.auto = true;
  target.reconcileFailWith = new Error("provenance unavailable");
  const { log, warns } = capturingLog();
  const driver = new EagerSync({ target, log });
  driver.handleEvent(toolResult());
  driver.triggerReconcile();
  await driver.idle();
  assert.equal(target.calls.length, 1, "the sync ran despite the failed reconcile");
  assert.ok(driver.reconcilesFailed >= 1);
  assert.ok(warns.some((w) => /human-edit reconcile failed/.test(w)));
});
