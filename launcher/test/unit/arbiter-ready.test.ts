/**
 * arbiter-ready.test — the test readiness budget and wait
 * (test/lib/arbiter-ready.ts; docs/design/architecture/runtime-instances.md §14.6).
 * scripts/test/ready-deadline.test.sh pins the same numbers for the shell rule.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { onCi, readyOverridden, sourceArbiterArgs, testReadyBudgetMs, waitForPaths } from "../lib/arbiter-ready.js";

const idle = { load1: 0.5, ncpu: 4 };

test("onCi: set the way GitHub and GitLab set it; false, 0, no and empty are off", () => {
  assert.equal(onCi({ CI: "true" }), true);
  assert.equal(onCi({ CI: "1" }), true);
  for (const v of [undefined, "", "false", "FALSE", "0", "no", " "]) assert.equal(onCi({ CI: v }), false, `CI=${JSON.stringify(v)}`);
});

test("testReadyBudgetMs: the launcher's deadline off CI, twice it on CI", () => {
  assert.equal(testReadyBudgetMs({}, idle), 30_000, "idle, not CI: the 30 s base");
  assert.equal(testReadyBudgetMs({ CI: "true" }, idle), 60_000, "idle CI runner: doubled");
  assert.equal(testReadyBudgetMs({}, { load1: 8, ncpu: 4 }), 60_000, "twice the CPU count in load: twice the time");
  assert.equal(testReadyBudgetMs({ CI: "true" }, { load1: 8, ncpu: 4 }), 120_000, "load scaling and CI compose");
  assert.equal(testReadyBudgetMs({}, { load1: 400, ncpu: 2 }), 120_000, "the load-scaled part is capped at 120 s");
  assert.equal(testReadyBudgetMs({ CI: "true" }, { load1: 400, ncpu: 2 }), 240_000, "so a CI wait is at most 240 s");
  assert.equal(testReadyBudgetMs({}, { load1: Number.NaN, ncpu: 0 }), 30_000, "nonsense host figures: the base");
});

test("testReadyBudgetMs: MANDU_SERVICE_READY_TIMEOUT_MS is taken exactly, on CI too; a garbled one is ignored", () => {
  assert.equal(testReadyBudgetMs({ MANDU_SERVICE_READY_TIMEOUT_MS: "5000" }, idle), 5000);
  assert.equal(testReadyBudgetMs({ MANDU_SERVICE_READY_TIMEOUT_MS: "5000", CI: "true" }, idle), 5000);
  assert.equal(testReadyBudgetMs({ MANDU_SERVICE_READY_TIMEOUT_MS: "500000" }, idle), 500_000, "uncapped: the operator asked");
  assert.equal(readyOverridden({ MANDU_SERVICE_READY_TIMEOUT_MS: "5000" }), true);
  for (const v of ["0", "-5", "5s", "abc", ""]) {
    assert.equal(readyOverridden({ MANDU_SERVICE_READY_TIMEOUT_MS: v }), false, v);
    assert.equal(testReadyBudgetMs({ MANDU_SERVICE_READY_TIMEOUT_MS: v, CI: "true" }, idle), 60_000, v);
  }
});

test("waitForPaths: resolves once every path exists", async () => {
  const d = mkdtempSync(join(tmpdir(), "mdu-ar-"));
  try {
    const a = join(d, "a"), b = join(d, "b");
    setTimeout(() => writeFileSync(a, ""), 30);
    setTimeout(() => writeFileSync(b, ""), 60);
    await waitForPaths([a, b], { budgetMs: 5000, pollMs: 10 });
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("waitForPaths: at the budget it says what is missing, the time spent against the budget, and the log's tail", async () => {
  const d = mkdtempSync(join(tmpdir(), "mdu-ar-"));
  try {
    const log = join(d, "arbiter.log");
    writeFileSync(log, "line one\n[arbiter] still starting\n");
    await assert.rejects(
      waitForPaths(join(d, "arbiter.sock"), { what: "the arbiter", budgetMs: 150, pollMs: 20, logPath: log }),
      (e: Error) => {
        assert.match(e.message, /^the arbiter did not come up: .*arbiter\.sock not there after 0\.\d s \(budget 0\.1 s; MANDU_SERVICE_READY_TIMEOUT_MS sets it\)/);
        assert.match(e.message, /\[arbiter\] still starting/, "the log's tail rides along");
        return true;
      },
    );
    await assert.rejects(waitForPaths(join(d, "x"), { budgetMs: 10, logPath: join(d, "none.log") }), /none\.log is empty or missing/);
    await assert.rejects(waitForPaths(join(d, "x"), { budgetMs: 10, output: () => "boot noise\n" }), /its output \(last lines\) ---\nboot noise/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("waitForPaths: a started process that exits ends the wait at once, not at the budget", async () => {
  const d = mkdtempSync(join(tmpdir(), "mdu-ar-"));
  try {
    const child = spawn(process.execPath, ["-e", "process.exit(3)"], { stdio: "ignore" });
    await once(child, "exit");
    const t0 = Date.now();
    await assert.rejects(
      waitForPaths(join(d, "arbiter.sock"), { what: "the arbiter", child, budgetMs: 60_000, pollMs: 10 }),
      /the arbiter did not come up: it exited with code 3 before .*arbiter\.sock appeared after/,
    );
    assert.ok(Date.now() - t0 < 5000, "well before the 60 s budget");
    const killed = spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { stdio: "ignore" });
    killed.kill("SIGKILL");
    await once(killed, "exit");
    await assert.rejects(waitForPaths(join(d, "y"), { child: killed, budgetMs: 60_000 }), /killed by SIGKILL/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("sourceArbiterArgs: one node process through the arbiter package's own tsx, the socket last", () => {
  const a = sourceArbiterArgs("/tmp/x.sock");
  assert.equal(a[0], "--import");
  assert.match(a[1]!, /arbiter\/node_modules\/tsx\/dist\/esm\/index\.mjs$/);
  assert.match(a[2]!, /arbiter\/ipc\/server-main\.ts$/);
  assert.equal(a[3], "/tmp/x.sock");
  assert.equal(a.length, 4);
});
