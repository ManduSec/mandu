// run-suites-timeout.test.mjs — end to end, a suite that hangs
// (scripts/run-suites.mjs, docs/design/testing/test-organization.md §5): a real
// `node --test` over three files, the middle one stuck with a child process of
// its own, run through main() to its timeout. The log's report and the
// verdict's reason name the hung file and its child, not only "timed out"; a
// shell suite with no test file still gets the process list. Pure node, no
// network, no privilege.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { main } from "../run-suites.mjs";

const E = (id, o = {}) => ({ id, kind: "unit", axis: "off", cwd: ".", cmd: ["true"], needs: [], timeout: 5, parallel: true, flaky: null, internet: false, platforms: ["linux"], env: {}, ...o });

function sink() {
  const s = { text: "", isTTY: false, write(c) { s.text += c; return true; } };
  return s;
}

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function fixture(entries) {
  const root = mkdtempSync(join(tmpdir(), "run-suites-timeout-"));
  mkdirSync(join(root, "tests"), { recursive: true });
  mkdirSync(join(root, "pkg", "test"), { recursive: true });
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(entries, null, 2)};\nexport default entries;\n`);
  return root;
}

test("a hung node:test file: the report names it and its child; the reason carries it; the group is killed", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "run-suites-timeout-pid-"));
  const pidFile = join(scratch, "child.pid");
  const root = fixture([E("pkg.hangs", {
    cwd: "pkg", timeout: 10, // room for three node starts on a loaded CI host
    // env -u: this test itself runs under node:test, whose context a nested runner would inherit.
    cmd: ["env", "-u", "NODE_TEST_CONTEXT", "node", "--test", "test/a.test.mjs", "test/b-hangs.test.mjs", "test/c.test.mjs"],
  })]);
  const t = (body) => `import { test } from "node:test";\n${body}\n`;
  writeFileSync(join(root, "pkg", "test", "a.test.mjs"), t(`test("a is quick", () => {});`));
  writeFileSync(join(root, "pkg", "test", "c.test.mjs"), t(`test("c is quick", () => {});`));
  // The stuck file starts a child named by a marker argument, records its pid, then never settles.
  writeFileSync(join(root, "pkg", "test", "b-hangs.test.mjs"), t([
    `import { spawn } from "node:child_process";`,
    `import { writeFileSync } from "node:fs";`,
    `test("b waits forever", async () => {`,
    `  const c = spawn("sleep", ["300"], { stdio: "ignore" });`,
    `  writeFileSync(${JSON.stringify(pidFile)}, String(c.pid));`,
    `  await new Promise(() => { setInterval(() => {}, 1000); });`,
    `});`,
  ].join("\n")));
  const out = join(root, "out");
  const stdout = sink();
  try {
    const rc = await main(["--only", "pkg.hangs", "--out", out, "--run-id", "t-1", "--commit", "b814495e", "--ref", "t"],
      { root, stdout, stderr: sink() });
    assert.equal(rc, 1, stdout.text);
    const summary = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
    assert.equal(summary.entries[0].result, "timeout");

    const log = readFileSync(join(out, "logs", "pkg.hangs.log"), "utf8");
    const childPid = Number(readFileSync(pidFile, "utf8"));
    assert.match(log, /\[run-suites\] timeout after 10s: the suite's processes at the deadline, before the SIGTERM/);
    assert.match(log, /^\[run-suites\] still running: pkg\/test\/b-hangs\.test\.mjs$/m, log);
    assert.doesNotMatch(log, /still running: .*(a|c)\.test\.mjs/, "the files that finished are not named");
    // The hung file's process, and its child indented under it.
    const row = (re) => log.split("\n").find((l) => re.test(l));
    const fileRow = row(/^\[run-suites\] {3}\d+ .*node test\/b-hangs\.test\.mjs$/);
    const childRow = row(new RegExp(`^\\[run-suites\\] {3}${childPid} +\\d+s +sleep 300$`));
    assert.ok(fileRow, log);
    assert.ok(childRow, `the hung file's child ${childPid} is listed:\n${log}`);
    const indent = (l) => /^\[run-suites\] {3}\d+ +\d+s( +)\S/.exec(l)[1].length;
    assert.ok(indent(childRow) > indent(fileRow), "the child sits under the file's process");
    // The report came before the kill, so the TAP the runner flushed on SIGTERM follows it.
    assert.ok(log.indexOf("still running:") < log.lastIndexOf("[run-suites] timeout: "));
    assert.match(log, /^\[run-suites\] timeout: timed out after 10s; still running: pkg\/test\/b-hangs\.test\.mjs$/m);
    assert.match(stdout.text, /timeout: timed out after 10s; still running: pkg\/test\/b-hangs\.test\.mjs/);

    for (let i = 0; i < 50 && alive(childPid); i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(alive(childPid), false, "the hung file's child was killed with the group");
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("a hung shell suite: no test file to name, the process list still says what was running", async () => {
  const root = fixture([E("sh.hangs", { timeout: 1, cmd: ["bash", "-c", "sleep 300 & wait"] })]);
  const out = join(root, "out");
  const stdout = sink();
  try {
    const rc = await main(["--only", "sh.hangs", "--out", out, "--run-id", "t-2", "--commit", "b814495e", "--ref", "t"],
      { root, stdout, stderr: sink() });
    assert.equal(rc, 1);
    const log = readFileSync(join(out, "logs", "sh.hangs.log"), "utf8");
    assert.match(log, /^\[run-suites\] {3}\d+ +\d+s  bash -c sleep 300 & wait$/m, log);
    assert.match(log, /^\[run-suites\] {3}\d+ +\d+s {4}sleep 300$/m, log);
    assert.match(log, /still running: \(no test file named by a process\)/);
    assert.match(log, /^\[run-suites\] timeout: timed out after 1s$/m, "the reason is the bare limit");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// --deadline (the CI guest's, continuous-integration.md §3): a hung entry
// whose own timeout is past the run's deadline (rust.kernel's 3600 s against a
// 2700 s guest, pipelines 10978, 11050 and 11099) is stopped AT the deadline,
// with the timeout report, and the run still writes its summary and logs.
test("--deadline: the hung entry is stopped as a timeout at the deadline, the queue is not started, the summary is written", async () => {
  const root = fixture([
    E("sh.quick", { timeout: 60, cmd: ["bash", "-c", "echo '1 passed, 0 failed'"] }),
    E("sh.hangs-long", { timeout: 3600, cmd: ["bash", "-c", "sleep 300 & wait"] }),
    E("sh.later", { timeout: 60, parallel: false, cmd: ["bash", "-c", "echo '1 passed, 0 failed'"] }),
  ]);
  const out = join(root, "out");
  const stdout = sink();
  const t0 = Date.now();
  try {
    const deadline = String((Date.now() + 3000) / 1000);
    const rc = await main(["--only", "sh.quick,sh.hangs-long,sh.later", "--jobs", "2", "--deadline", deadline, "--heartbeat", "1",
      "--out", out, "--run-id", "t-3", "--commit", "b814495e", "--ref", "t"], { root, stdout, stderr: sink() });
    assert.equal(rc, 1, stdout.text);
    assert.ok(Date.now() - t0 < 30_000, "stopped at the deadline, not at the entry's own 3600 s");
    const summary = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
    assert.equal(summary.result, "error");
    assert.match(summary.reason, /^deadline: the run's time was up at /);
    const byId = Object.fromEntries(summary.entries.map((e) => [e.id, e]));
    assert.equal(byId["sh.quick"].result, "pass");
    assert.equal(byId["sh.hangs-long"].result, "timeout");
    assert.equal(byId["sh.later"], undefined, "the serial entry after the stage never started");
    const log = readFileSync(join(out, "logs", "sh.hangs-long.log"), "utf8");
    assert.match(log, /^\[run-suites\] the run's deadline \(--deadline\) came after \d+s, before this entry's own timeout of 3600s$/m, log);
    assert.match(log, /^\[run-suites\] {3}\d+ +\d+s {4}sleep 300$/m, "the process list, as at a timeout");
    assert.match(log, /^\[run-suites\] timeout: stopped by the run's deadline \(--deadline\) after \d+s, before its own timeout of 3600s$/m, log);
    assert.match(stdout.text, /⏰ deadline reached \(--deadline\): stopping sh\.hangs-long; no other entry starts/);
    assert.match(stdout.text, /… \d+s into the run, still running: sh\.hangs-long \(\d+s of 3600s\)/, "the heartbeat names the running entry");
    assert.match(stdout.text, /- +sh\.later +not run \(deadline: /);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("--deadline already past: nothing starts, the run is an error with every entry not run", async () => {
  const root = fixture([E("sh.quick", { cmd: ["bash", "-c", "echo '1 passed, 0 failed'"] })]);
  const out = join(root, "out");
  const stdout = sink();
  try {
    const rc = await main(["--only", "sh.quick", "--deadline", String(Math.floor(Date.now() / 1000) - 5),
      "--out", out, "--run-id", "t-4", "--commit", "b814495e", "--ref", "t"], { root, stdout, stderr: sink() });
    assert.equal(rc, 1);
    const summary = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
    assert.equal(summary.result, "error");
    assert.deepEqual(summary.entries, []);
    assert.match(stdout.text, /⏰ deadline reached \(--deadline\): stopping nothing running/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("--deadline and --heartbeat refuse what is not a number", async () => {
  for (const args of [["--deadline", "soon"], ["--deadline", ""], ["--deadline=-1"], ["--deadline", "0"], ["--heartbeat", "1.5"], ["--heartbeat", "x"]]) {
    const stderr = sink();
    const rc = await main(["--kind", "unit", ...args], { stdout: sink(), stderr });
    assert.equal(rc, 2, args.join(" "));
    assert.match(stderr.text, /--(deadline|heartbeat) must be/);
  }
});
