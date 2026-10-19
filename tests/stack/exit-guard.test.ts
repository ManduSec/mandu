/**
 * exit-guard.test — e2e proof that the hung-runner backstop
 * (tests/lib/exit-guard.ts) turns a leaked-handle zombie runner into a loud
 * diagnostic + clean exit, WITHOUT touching healthy runners.
 *
 * Each case spawns a tiny fixture suite (test/fixtures/*.fixture.ts — named
 * so the normal `stack/*.test.ts` glob can NEVER pick them up) under the
 * package-local tsx, exactly how the real suites run, and inspects the
 * child's exit code + captured output:
 *   1. leaky-pass: a PASSING suite leaking a ref'd net.Server. Without the
 *      guard this runner never exits; with it, it must exit 0 (green stays
 *      green), print the TAP epilogue, and emit the per-handle diagnostic in
 *      ~graceMs — far under the 30s safety timeout.
 *   2. leaky-fail: same leak, FAILING test — the run must stay red (exit 1)
 *      through the guard's forced exit.
 *   3. clean (negative control): guard installed, no leak — exits 0 quickly
 *      with NO `[exit-guard:` output at all.
 *
 * EMPIRICAL notes (node v22.22.1 / tsx 4.22.4, verified 2026-07-11), baked
 * into the assertions below:
 *   - `tsx --test <file>` runs the file in a CHILD runner (process
 *     isolation); the guard fires there, and its console.error lines are
 *     forwarded by the orchestrator as TAP `# ` comment lines on STDOUT.
 *   - The TAP epilogue (`# pass 1`) is printed by the ORCHESTRATOR after the
 *     child exits, so it reliably appears in stdout AFTER the guard lines.
 *   - On a red run the child runner does NOT set process.exitCode=1 (the
 *     guard's footer reads `code=0` inside the child); the overall exit code
 *     1 comes from the orchestrator's failure tally — red stays red, but via
 *     the parent, so the footer's code= value is child-local and NOT
 *     asserted to be 1 here.
 *
 * Mandu (tests/). NEW code, no reference origin. Deterministic: no
 * agent CLI, no arbiter, no network beyond the fixtures' loopback listen.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runChildToExit } from "../lib/child-run.js";

const HERE = dirname(fileURLToPath(import.meta.url)); // …/tests/stack/
const PKG_ROOT = join(HERE, ".."); //       …/tests (the package root)
const TSX = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const FIXTURES = join(PKG_ROOT, "fixtures");

/** Hard safety net: runChildToExit SIGKILLs the fixture's whole process
 *  group and REJECTS at this deadline — so a guard that fails to fire shows
 *  up as a rejection here, never as a hung suite. Resolution = the child
 *  really EXITED on its own. */
const SAFETY_MS = 30_000;

const ENV = { PATH: process.env["PATH"], HOME: process.env["HOME"] };

async function runFixture(
  name: string,
): Promise<{ code: number; stdout: string; stderr: string; combined: string; elapsedMs: number }> {
  const started = Date.now();
  const r = await runChildToExit(TSX, ["--test", join(FIXTURES, name)], {
    cwd: PKG_ROOT,
    env: ENV,
    timeoutMs: SAFETY_MS,
    label: `fixture ${name}`,
  });
  return { ...r, combined: r.stdout + r.stderr, elapsedMs: Date.now() - started };
}

test("leaky PASSING suite: guard diagnoses the leak and force-exits 0 in ~grace time", async () => {
  const r = await runFixture("exit-guard-leaky-pass.fixture.ts");
  assert.equal(r.code, 0, `green stays green through the guard (output: ${r.combined.slice(0, 600)})`);
  assert.match(r.stdout, /# pass 1\b/, "the TAP epilogue reached stdout despite the forced exit");
  assert.match(r.combined, /\[exit-guard:fixture\]/, "the guard announced itself");
  assert.match(r.combined, /leaked handle/, "the header names the leak");
  assert.match(r.combined, /\[exit-guard:fixture\]\s+Server /, "the leaked net.Server got its per-handle line");
  assert.match(r.combined, /forcing exit code=0/, "the footer carries the preserved (green) exit code");
  assert.ok(
    r.elapsedMs < 15_000,
    `exited in ~grace time (${r.elapsedMs}ms), well under the ${SAFETY_MS / 1000}s safety net`,
  );
});

test("leaky FAILING suite: a red run stays red (exit 1) through the guard", async () => {
  const r = await runFixture("exit-guard-leaky-fail.fixture.ts");
  // The 1 comes from the node:test ORCHESTRATOR's failure tally (the child
  // runner never sets process.exitCode — see the header notes), so the
  // property that matters holds: the guard cannot launder a red run green.
  assert.equal(r.code, 1, `red stays red through the guard (output: ${r.combined.slice(0, 600)})`);
  assert.match(r.stdout, /# fail 1\b/, "the TAP epilogue records the failure");
  assert.match(r.combined, /\[exit-guard:fixture\]/, "the guard still fired on the red run");
  assert.match(r.combined, /leaked handle/, "the header names the leak");
  assert.match(r.combined, /forcing exit code=/, "the footer printed before the forced exit");
  assert.ok(
    r.elapsedMs < 15_000,
    `exited in ~grace time (${r.elapsedMs}ms), well under the ${SAFETY_MS / 1000}s safety net`,
  );
});

test("clean suite (negative control): guard stays silent and the runner exits 0 naturally", async () => {
  const r = await runFixture("exit-guard-clean.fixture.ts");
  assert.equal(r.code, 0, `healthy run exits green (output: ${r.combined.slice(0, 600)})`);
  assert.match(r.stdout, /# pass 1\b/, "the TAP epilogue printed");
  assert.doesNotMatch(r.combined, /\[exit-guard:/, "NO guard output on a healthy runner (unref'd timer never fired)");
  assert.ok(
    r.elapsedMs < 15_000,
    `exited promptly (${r.elapsedMs}ms) without waiting out the grace timer`,
  );
});
