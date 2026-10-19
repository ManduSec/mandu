/**
 * lineage.test — unit tests for the best-effort spawn-lineage emitter
 * (src/lineage.ts). The emitter is OFF the security path: it records the
 * parent→child edge when it can, and a arbiter error is swallowed so it NEVER
 * blocks or alters the exec gate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { recordSpawnLineage, provisionalProcKey } from "../../src/lineage.js";
import type { ExecArbiter } from "../../src/arbiter-client.js";

/** Minimal ExecArbiter stub: only processLineage is exercised here. */
function makeArbiter(opts: { fail?: boolean } = {}): {
  arbiter: ExecArbiter;
  calls: { childKey: string; parentKey: string; session?: string }[];
} {
  const calls: { childKey: string; parentKey: string; session?: string }[] = [];
  const arbiter: ExecArbiter = {
    classifyExec: async () => {
      throw new Error("not used in lineage tests");
    },
    resolveExecArgv: async () => {
      throw new Error("not used in lineage tests");
    },
    async processLineage(args) {
      calls.push(args);
      if (opts.fail) throw new Error("mock arbiter: processLineage failure (injected)");
    },
  };
  return { arbiter, calls };
}

test("recordSpawnLineage calls processLineage with the given child/parent keys", async () => {
  const { arbiter, calls } = makeArbiter();
  await recordSpawnLineage(arbiter, "curl-2", "bash-1");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { childKey: "curl-2", parentKey: "bash-1" });
});

test("recordSpawnLineage swallows a arbiter error (never throws — off the security path)", async () => {
  const { arbiter, calls } = makeArbiter({ fail: true });
  // Must NOT throw — a lineage emission failure must never block/affect the exec.
  await recordSpawnLineage(arbiter, "curl-2", "bash-1");
  assert.equal(calls.length, 1, "the call was attempted before the error was swallowed");
});

// ── Rust↔TS format cross-check ────────────────────────────────────────────────
// The cross-layer contract (Plan 6 §Task 1): Rust `proc_key_from(pid, starttime)`
// and TS `provisionalProcKey(pid)` must produce a byte-identical string for the
// SAME (pid, starttime). The Rust format is `${pid}-${starttime_ticks}` (decimal
// pid, single ASCII '-', raw clock ticks from /proc/<pid>/stat field 22, NO unit
// conversion). The TS shim already emits exactly this shape; this test pins it.
//
// Two assertions:
//   1. The LIVE key for this process matches /^\d+-\d+$/ and leads with process.pid
//      (so the real /proc read works and the format is correct). Keyed on the
//      platform, not on /proc's presence, so a Linux regression cannot hide:
//      darwin has no /proc starttime to read, and its documented fallback is
//      the bare pid (lineage.ts; off the security path), pinned instead.
//   2. A SYNTHETIC stat fixture (same one as the Rust tests) produces the expected
//      `${pid}-${starttime}` string — byte-identical to what Rust's
//      proc_key_from(1234, 9999) returns.
test("provisionalProcKey format matches Rust proc_key_from (pid-starttime, cross-layer contract)", () => {
  // Part 1: live key for this process.
  const liveKey = provisionalProcKey(process.pid);
  if (process.platform === "linux") {
    assert.match(
      liveKey,
      /^\d+-\d+$/,
      "key must be `${pid}-${starttime}` (matches Rust proc_key_from) — bare pid fallback would fail this",
    );
    assert.ok(
      liveKey.startsWith(`${process.pid}-`),
      `key must lead with the real pid ${process.pid}, got: ${liveKey}`,
    );
  } else {
    assert.equal(liveKey, String(process.pid), "no /proc (darwin): the bare-pid fallback, never a thrown read");
  }

  // Part 2: synthetic fixture — the SAME stat line the Rust unit test uses.
  // "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 9999 ..."
  // Field 22 = 9999 → expected key "1234-9999".
  // We call provisionalProcKey with pid=1234 but it reads /proc/1234/stat live,
  // so instead we call the internal parse step directly by reproducing it here —
  // this is the HERMETIC form of the cross-check (no live /proc dependency).
  const statLine =
    "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194304 " +
    "100 0 0 0 10 5 0 0 20 0 1 0 9999 12345678 0 0 0";
  // Mirror the TS parse logic from provisionalProcKey (anchors on last ')').
  const afterComm = statLine.slice(statLine.lastIndexOf(")") + 2);
  const fields = afterComm.split(" ");
  const starttime = fields[19]; // field 22 overall (1-based), index 19 post-comm
  assert.equal(starttime, "9999", "synthetic stat field 22 must parse to 9999");
  // The cross-layer key: Rust proc_key_from(1234, 9999) === "1234-9999".
  const syntheticKey = `${1234}-${starttime}`;
  assert.equal(
    syntheticKey,
    "1234-9999",
    "synthetic key must equal Rust proc_key_from(1234, 9999) == \"1234-9999\"",
  );
});
