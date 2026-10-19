/**
 * primitives.test — the injectable service low-level ops.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { closeSync, existsSync, linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, writeSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import {
  probePort, waitFor, waitForFile, startDetachedCmd, runOnce, openAppendLog,
  serviceReadyDeadlineMs, readinessBudget, SERVICE_READY_BASE_MS, SERVICE_READY_MAX_MS,
} from "../../src/services/primitives.js";

test("probePort true when something listens, false when nothing does", async () => {
  const srv = createServer();
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  const port = (srv.address() as { port: number }).port;
  assert.equal(await probePort("127.0.0.1", port), true);
  srv.close();
  await once(srv, "close");
  assert.equal(await probePort("127.0.0.1", port), false);
});

test("waitFor resolves true when the check passes within the budget", async () => {
  let n = 0;
  assert.equal(await waitFor(() => ++n >= 3, { tries: 10, delayMs: 1 }), true);
  assert.equal(await waitFor(() => false, { tries: 3, delayMs: 1 }), false);
});

test("waitFor giveUp: an unready wait ends at once when giveUp says so (the child exited), not after every try", async () => {
  let checks = 0;
  const t0 = Date.now();
  assert.equal(await waitFor(() => { checks++; return false; }, { tries: 1000, delayMs: 50, giveUp: () => checks >= 2 }), false);
  assert.equal(checks, 2);
  assert.ok(Date.now() - t0 < 1000, "gave up early");
  // A check that passes wins over giveUp on the same probe.
  assert.equal(await waitFor(() => true, { tries: 3, delayMs: 1, giveUp: () => true }), true);
});

test("serviceReadyDeadlineMs: the base on an idle host, stretched by load per CPU, capped; an env override replaces it", () => {
  const idle = { load1: 0.5, ncpu: 8 };
  assert.equal(serviceReadyDeadlineMs({}, idle), SERVICE_READY_BASE_MS);
  // The old fixed deadline was about 10 s; the idle base is longer.
  assert.ok(SERVICE_READY_BASE_MS >= 30_000);
  // Load at the CPU count: still the base (the ratio only ever stretches).
  assert.equal(serviceReadyDeadlineMs({}, { load1: 8, ncpu: 8 }), SERVICE_READY_BASE_MS);
  // Twice the CPU count: twice the base.
  assert.equal(serviceReadyDeadlineMs({}, { load1: 16, ncpu: 8 }), 2 * SERVICE_READY_BASE_MS);
  // The CI incident's shape (a 48-way host at load ~46), then over it.
  assert.equal(serviceReadyDeadlineMs({}, { load1: 46, ncpu: 48 }), SERVICE_READY_BASE_MS);
  assert.equal(serviceReadyDeadlineMs({}, { load1: 72, ncpu: 48 }), 1.5 * SERVICE_READY_BASE_MS);
  // Capped.
  assert.equal(serviceReadyDeadlineMs({}, { load1: 1000, ncpu: 4 }), SERVICE_READY_MAX_MS);
  // Nonsense host figures fall back to the base, never to 0 or NaN.
  assert.equal(serviceReadyDeadlineMs({}, { load1: NaN, ncpu: 8 }), SERVICE_READY_BASE_MS);
  assert.equal(serviceReadyDeadlineMs({}, { load1: 5, ncpu: 0 }), SERVICE_READY_BASE_MS);
  // The override, in milliseconds: used as given (no cap, no load scaling).
  assert.equal(serviceReadyDeadlineMs({ MANDU_SERVICE_READY_TIMEOUT_MS: "1500" }, { load1: 1000, ncpu: 4 }), 1500);
  assert.equal(serviceReadyDeadlineMs({ MANDU_SERVICE_READY_TIMEOUT_MS: " 300000 " }, idle), 300_000);
  // A garbled or non-positive override is ignored (the computed deadline).
  for (const bad of ["", "0", "-5", "abc", "1.5", "10s"]) {
    assert.equal(serviceReadyDeadlineMs({ MANDU_SERVICE_READY_TIMEOUT_MS: bad }, idle), SERVICE_READY_BASE_MS, `override '${bad}'`);
  }
  // With no arguments it reads the real host and env: a finite positive number.
  const real = serviceReadyDeadlineMs();
  assert.ok(Number.isFinite(real) && real > 0);
});

test("readinessBudget: one deadline across successive waits; the note says timeout or exit", () => {
  let now = 1_000;
  let exited: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  const b = readinessBudget({ exited: () => exited }, 30_000, () => now);
  assert.equal(b.opts(100).tries, 300);
  assert.equal(b.opts(100).delayMs, 100);
  now += 12_000; // the port-file wait spent 12 s: the listen wait gets the rest
  assert.equal(b.opts(100).tries, 180);
  now += 60_000; // past the deadline: still one probe, never zero
  assert.equal(b.opts(100).tries, 1);
  assert.equal(b.opts(100).giveUp!(), false);
  assert.match(b.note(), /not ready within 30 s; MANDU_SERVICE_READY_TIMEOUT_MS \(milliseconds\) sets a longer deadline/);
  exited = { code: 1, signal: null };
  assert.equal(b.opts(100).giveUp!(), true);
  assert.equal(b.note(), "it exited with code 1 before becoming ready");
  exited = { code: null, signal: "SIGKILL" };
  assert.equal(b.note(), "it was killed by SIGKILL before becoming ready");
  // A handle without exit tracking (a test double) never gives up early.
  assert.equal(readinessBudget({}, 1000).opts(100).giveUp!(), false);
});

test("startDetachedCmd: exited() is null while the service runs and its status once it exits", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sdx-"));
  const quick = startDetachedCmd("bash", ["-c", "exit 7"], { cwd: dir, env: process.env }, join(dir, "q.log"));
  const slow = startDetachedCmd("bash", ["-c", "sleep 30"], { cwd: dir, env: process.env }, join(dir, "s.log"));
  try {
    assert.equal(await waitFor(() => quick.exited!() !== null, { tries: 100, delayMs: 20 }), true);
    assert.deepEqual(quick.exited!(), { code: 7, signal: null });
    assert.equal(slow.exited!(), null);
  } finally {
    quick.stop();
    slow.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("waitForFile waits for a non-empty file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wf-"));
  const f = join(dir, "ca.pem");
  setTimeout(() => writeFileSync(f, "CERT"), 5);
  assert.equal(await waitForFile(f, { tries: 50, delayMs: 2 }), true);
  assert.equal(await waitForFile(join(dir, "absent"), { tries: 3, delayMs: 1 }), false);
  rmSync(dir, { recursive: true, force: true });
});

test("startDetachedCmd creates the log dir (no ENOENT when scope run dir is absent)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sd-"));
  const logPath = join(dir, "scope", "sid", "svc.log"); // parent dirs do NOT exist
  // Point at a bogus entry so the spawned node just fails async; the assertion
  // is that startDetachedCmd itself does not throw and the log dir gets created.
  const h = startDetachedCmd("node", [join(dir, "no-such-entry.mjs")], { cwd: dir, env: { ...process.env } }, logPath);
  assert.ok(existsSync(join(dir, "scope", "sid")), "log dir created");
  h.stop();
  rmSync(dir, { recursive: true, force: true });
});

test("openAppendLog: appends to a log of its own, and refuses a link, a hard link to someone's file, or a FIFO at the name (runtime-instances.md §2)", () => {
  const dir = mkdtempSync(join(tmpdir(), "oal-"));
  try {
    // An ordinary log: created, then appended to (never truncated).
    const log = join(dir, "svc.log");
    for (const line of ["one\n", "two\n"]) {
      const fd = openAppendLog(log);
      writeSync(fd, line);
      closeSync(fd);
    }
    assert.equal(readFileSync(log, "utf8"), "one\ntwo\n");
    // What an agent may leave at a log's name in the runtime dir.
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "keep me\n");
    symlinkSync(victim, join(dir, "linked.log"));
    assert.throws(() => openAppendLog(join(dir, "linked.log")), /is a symbolic link; refusing to write through it/);
    symlinkSync(join(dir, "absent-target"), join(dir, "dangling.log"));
    assert.throws(() => openAppendLog(join(dir, "dangling.log")), /symbolic link/);
    assert.equal(existsSync(join(dir, "absent-target")), false, "a dangling link's target is not created");
    linkSync(victim, join(dir, "hard.log"));
    assert.throws(() => openAppendLog(join(dir, "hard.log")), /not a regular file of its own \(2 links to it\)/);
    assert.equal(readFileSync(victim, "utf8"), "keep me\n", "the linked file is untouched");
    execFileSync("mkfifo", [join(dir, "fifo.log")]);
    assert.throws(() => openAppendLog(join(dir, "fifo.log")), /FIFO/, "no reader: refused at once, never a hang");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("startDetachedCmd opens its log with openAppendLog: a link planted at the log's name refuses the start, nothing is written through it", () => {
  const dir = mkdtempSync(join(tmpdir(), "sdl-"));
  try {
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "keep me\n");
    symlinkSync(victim, join(dir, "dashboard.log"));
    assert.throws(() => startDetachedCmd("bash", ["-c", "echo appended"], { cwd: dir, env: process.env }, join(dir, "dashboard.log")), /symbolic link/);
    assert.equal(readFileSync(victim, "utf8"), "keep me\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runOnce captures stdout, stderr and exit status of a one-shot command", () => {
  const ok = runOnce("bash", ["-c", "echo OUT; echo ERR >&2"], { cwd: "/tmp", env: process.env });
  assert.equal(ok.status, 0);
  assert.equal(ok.stdout.trim(), "OUT");
  assert.equal(ok.stderr.trim(), "ERR");
  const bad = runOnce("bash", ["-c", "exit 3"], { cwd: "/tmp", env: process.env });
  assert.equal(bad.status, 3);
  const missing = runOnce("no-such-binary-xyz", [], { cwd: "/tmp", env: process.env });
  assert.equal(missing.status, null);
  assert.match(missing.stderr, /ENOENT/);
  const slow = runOnce("bash", ["-c", "sleep 5"], { cwd: "/tmp", env: process.env, timeoutMs: 200 });
  assert.equal(slow.status, null);
  assert.notEqual(slow.stderr, "");
});

test("runOnce ownSession: the command runs as the leader of a new session, outside the caller's", () => {
  // macOS ps has no session id column (`sess` prints 0): a new session's
  // leader also leads a new process group, so the process group stands in.
  const col = process.platform === "darwin" ? "pgid=" : "sid=";
  const sid = (pid: string | number) => runOnce("ps", ["-o", col, "-p", String(pid)], { cwd: "/tmp", env: process.env }).stdout.trim();
  const mine = sid(process.pid);
  assert.notEqual(mine, "");
  const own = runOnce("sh", ["-c", `echo $$; ps -o ${col} -p $$`], { cwd: "/tmp", env: process.env, ownSession: true });
  assert.equal(own.status, 0);
  const [pid, childSid] = own.stdout.trim().split(/\s+/);
  assert.equal(childSid, pid, "the child leads its own session");
  assert.notEqual(childSid, mine);
  const same = runOnce("sh", ["-c", `ps -o ${col} -p $$`], { cwd: "/tmp", env: process.env });
  assert.equal(same.stdout.trim(), mine, "without it, the caller's session");
});
