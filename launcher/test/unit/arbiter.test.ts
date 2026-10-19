/**
 * arbiter.test — ensureArbiter attaches to an existing socket, refuses when none
 * and autostart is disabled, and honors the injected clock/waiter.
 */
import { Layout } from "../../src/services/layout.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { once } from "node:events";
import {
  ensureArbiter as ensureArbiterIn, startArbiter, assertSockPathFits, lastArbiterFatal, lastStartFailure,
  pollSocket, pollArbiterSocket, defaultSupervisorGraceMs, type EnsureArbiterOpts,
} from "../../src/arbiter.js";
import { SERVICE_READY_BASE_MS, SERVICE_READY_MAX_MS } from "../../src/services/primitives.js";
import { withTestRuntime } from "../lib/test-runtime.js";

/** ensureArbiter with this file's own runtime dir when the env names none:
 *  it checks the runtime base, and the default env (process.env, without
 *  XDG_RUNTIME_DIR on a bare host) would make that the shared /tmp/mandu
 *  (test-runtime.ts). */
const ensureArbiter = (o: EnsureArbiterOpts): ReturnType<typeof ensureArbiterIn> =>
  ensureArbiterIn({ ...o, env: withTestRuntime(o.env ?? {}) });

test("attaches when the socket already answers (no start)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "brk-"));
  const sock = join(dir, "b.sock");
  const srv = createServer();
  srv.listen(sock);
  await once(srv, "listening");
  let started = false;
  const r = await ensureArbiter({ sock, noAutostart: false, start: async () => { started = true; }, waitForSocket: async () => true });
  assert.equal(r.attached, true);
  assert.equal(started, false, "must not start when already up");
  srv.close(); rmSync(dir, { recursive: true, force: true });
});

test("refuses (throws) when down and autostart disabled", async () => {
  await assert.rejects(
    ensureArbiter({ sock: "/nonexistent/x.sock", noAutostart: true, start: async () => {}, waitForSocket: async () => false }),
    /arbiter/i,
  );
});

test("starts then waits when down and autostart enabled; refuses if it never comes up", async () => {
  let started = false;
  await assert.rejects(
    ensureArbiter({ sock: "/nonexistent/x.sock", noAutostart: false, start: async () => { started = true; }, waitForSocket: async () => false }),
    /arbiter.*did not/i,
  );
  assert.equal(started, true);
});

// ── load-aware autostart deadlines (runtime-instances.md §14.6; runtime-instances.md §10) ──

test("the socket wait ends at once when the STARTED daemon exits (no full deadline), and still refuses", async () => {
  let giveUpSeen: (() => boolean) | undefined;
  await assert.rejects(
    ensureArbiter({
      sock: "/nonexistent/x.sock", noAutostart: false,
      start: async () => ({ pid: 7, running: () => false }),
      waitForSocket: async (_s, giveUp) => { giveUpSeen = giveUp; return false; },
    }),
    /arbiter did not come up/,
  );
  assert.ok(giveUpSeen, "the wait was handed the daemon's liveness");
  assert.equal(giveUpSeen!(), true);
  // A start that reports no daemon (attach race, a test double): no early exit.
  let none: (() => boolean) | undefined = () => true;
  await assert.rejects(ensureArbiter({
    sock: "/nonexistent/x.sock", noAutostart: false, start: async () => {},
    waitForSocket: async (_s, giveUp) => { none = giveUp; return false; },
  }));
  assert.equal(none, undefined);
});

test("pollSocket: giveUp ends the poll early; a socket that exists still wins", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pollg-"));
  try {
    const t0 = Date.now();
    assert.equal(await pollSocket(join(dir, "absent.sock"), 1000, 50, () => true), false);
    assert.ok(Date.now() - t0 < 1000, "gave up at once");
    writeFileSync(join(dir, "there.sock"), "");
    assert.equal(await pollSocket(join(dir, "there.sock"), 1000, 50, () => true), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pollArbiterSocket: probes 100 ms apart for the given deadline (was a fixed ~5 s)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "polla-"));
  try {
    const t0 = Date.now();
    assert.equal(await pollArbiterSocket(join(dir, "absent.sock"), undefined, 300), false);
    const took = Date.now() - t0;
    assert.ok(took >= 250 && took < 3000, `waited about the 300 ms deadline, took ${took} ms`);
    const sock = join(dir, "late.sock");
    setTimeout(() => writeFileSync(sock, ""), 200);
    assert.equal(await pollArbiterSocket(sock, undefined, 5_000), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("defaultSupervisorGraceMs: two readiness deadlines (the supervisor's own start, then its arbiter's) less the first 6 s wait, never under 14 s", () => {
  assert.equal(defaultSupervisorGraceMs(SERVICE_READY_BASE_MS), 2 * SERVICE_READY_BASE_MS - 6_000);
  assert.equal(defaultSupervisorGraceMs(SERVICE_READY_MAX_MS), 2 * SERVICE_READY_MAX_MS - 6_000);
  assert.equal(defaultSupervisorGraceMs(1_000), 14_000, "the floor: never shorter than before");
});

test("startArbiter returns the spawned daemon for the socket wait (and nothing for a spawner that reports none)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-"));
  try {
    const d = { pid: 9, running: () => true };
    const got = await startArbiter(Layout.dev("/repo"), join(dir, "b.sock"), join(dir, "ev"), join(dir, "a.log"), {}, { spawnDaemon: () => d })();
    assert.equal(got, d);
    assert.equal(await startArbiter(Layout.dev("/repo"), join(dir, "b.sock"), join(dir, "ev"), join(dir, "a.log"), {}, { spawnDaemon: () => undefined })(), undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a refused arbiter boot reaches the terminal: the log's last `[arbiter] fatal:` line is quoted in the refusal", async () => {
  const log =
    "[arbiter] protection mode: secrets\n" +
    "[arbiter] fatal: mandu.db at /home/u/.mandu/mandu.db was written by a different Mandu version (schema v3; this build needs v1). delete it and relaunch\n";
  await assert.rejects(
    ensureArbiter({
      sock: "/nonexistent/x.sock", noAutostart: false, start: async () => {}, waitForSocket: async () => false,
      logPath: "/var/log/arbiter.log", readLog: () => log,
    }),
    (e: unknown) =>
      e instanceof Error &&
      /did not come up/.test(e.message) &&
      /The arbiter refused to start: mandu\.db at .*schema v3; this build needs v1/.test(e.message) &&
      /\(log: \/var\/log\/arbiter\.log\)/.test(e.message),
  );
  // no fatal line → the log path alone
  await assert.rejects(
    ensureArbiter({
      sock: "/nonexistent/x.sock", noAutostart: false, start: async () => {}, waitForSocket: async () => false,
      logPath: "/var/log/arbiter.log", readLog: () => "[arbiter] up\n",
    }),
    (e: unknown) => e instanceof Error && !/refused to start/.test(e.message) && /\(log: \/var\/log\/arbiter\.log\)/.test(e.message),
  );
  assert.equal(lastArbiterFatal(null), null);
});

test("assertSockPathFits: an over-108-byte sock path is refused with a clear message (not a silent truncation)", () => {
  const longPath = "/tmp/" + "x".repeat(120) + "/arbiter.sock"; // well over sun_path
  assert.throws(() => assertSockPathFits(longPath), /over the .*byte OS limit.*sun_path|Unix socket/i);
  // A short, normal path passes.
  assert.doesNotThrow(() => assertSockPathFits("/run/user/1000/mandu/arbiter.sock"));
});

test("ensureArbiter preflights the sock-path length BEFORE attach/start", async () => {
  let started = false;
  await assert.rejects(
    ensureArbiter({
      sock: "/tmp/" + "y".repeat(130) + "/b.sock",
      noAutostart: false,
      start: async () => { started = true; },
      waitForSocket: async () => true,
    }),
    /byte OS limit|sun_path/i,
  );
  assert.equal(started, false, "must refuse before starting the arbiter");
});

test("startArbiter creates the log/event/socket dirs (fresh-host, no ENOENT)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "brk-fresh-"));
  const scopeRun = join(dir, "mandu", "sid-1"); // does NOT exist yet
  const sock = join(dir, "mandu", "arbiter.sock");
  const eventDir = join(scopeRun, "events");
  const logPath = join(scopeRun, "arbiter.log");
  // Point at a repoRoot with no arbiter/ so the spawned npm just fails async —
  // the assertion is that start() itself does not throw (dirs get created).
  const start = startArbiter(Layout.dev(join(dir, "no-such-repo")), sock, eventDir, logPath);
  await start();
  assert.ok(existsSync(scopeRun), "scope run dir created");
  assert.ok(existsSync(eventDir), "event dir created");
  assert.ok(existsSync(join(dir, "mandu")), "socket dir created");
  rmSync(dir, { recursive: true, force: true });
});

// ── store paths reach the arbiter as flags (on-disk-layout.md §5) ──────────

import { daemonArgv } from "../../src/arbiter.js";
import type { DaemonSpec } from "../../src/services/layout.js";

/** The args without the prompt filter plugins' confinement flags
 *  (`arbiterPluginArgs`: present wherever the native bins are built, which
 *  these tests do not control; their own test is policy-suggest-model's). */
function withoutPluginArgs(args: readonly unknown[] | undefined): unknown[] {
  const out: unknown[] = [];
  const a = [...(args ?? [])];
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--net-guard" || a[i] === "--landlock-apply") { i++; continue; }
    out.push(a[i]);
  }
  return out;
}

test("startArbiter (pinned, per launch): the scope's event dir rides as --event-dir, never as MANDU_EVENT_DIR", async () => {
  const dir = mkdtempSync(join(tmpdir(), "brk-flag-"));
  const saved = process.env["MANDU_EVENT_DIR"];
  process.env["MANDU_EVENT_DIR"] = "/must/not/reach/the/arbiter";
  try {
    const eventDir = join(dir, "sid-1", "events");
    const calls: Array<{ spec: DaemonSpec; env: NodeJS.ProcessEnv; args: string[] }> = [];
    await startArbiter(Layout.dev("/repo"), join(dir, "a.sock"), eventDir, join(dir, "sid-1", "arbiter.log"), { MANDU_CONFIDENTIALITY: "1" },
      { spawnDaemon: (spec, env, _out, args) => { calls.push({ spec, env, args }); } })();
    assert.equal(calls.length, 1);
    const c = calls[0]!;
    assert.deepEqual(withoutPluginArgs(c.args), ["--event-dir", eventDir]);
    assert.deepEqual(daemonArgv(c.spec, withoutPluginArgs(c.args) as string[]), {
      cmd: "node",
      argv: ["--import", "file:///repo/arbiter/node_modules/tsx/dist/esm/index.mjs", "/repo/arbiter/ipc/server-main.ts", "--event-dir", eventDir],
    }, "one node process loading the source through tsx: no npm, no tsx binary");
    assert.equal(c.env["MANDU_ARBITER_SOCK"], join(dir, "a.sock"));
    assert.equal(c.env["MANDU_CONFIDENTIALITY"], "1");
    // The inherited value is the caller's, not one the launcher set: the
    // arbiter no longer reads the variable, and the launcher never writes it.
    assert.equal(c.env["MANDU_EVENT_DIR"], "/must/not/reach/the/arbiter");
    assert.ok(!Object.entries(c.env).some(([k, v]) => k !== "MANDU_EVENT_DIR" && v === eventDir), "the event dir is in no env var");
  } finally {
    if (saved === undefined) delete process.env["MANDU_EVENT_DIR"]; else process.env["MANDU_EVENT_DIR"] = saved;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("daemonArgv: flags follow the spec's own args (bundle or tsx-loaded entry), with no `--` separator", () => {
  const src: DaemonSpec = { cmd: "node", args: ["--import", "file:///repo/arbiter/node_modules/tsx/dist/esm/index.mjs", "/repo/arbiter/ipc/server-main.ts"], cwd: "/repo/arbiter", env: {} };
  const cmd: DaemonSpec = { cmd: "node", args: ["--no-warnings", "/pkg/dist/arbiter.mjs"], cwd: "/pkg", env: {} };
  assert.deepEqual(daemonArgv(src, ["--event-dir", "/e"]), { cmd: "node", argv: [...src.args, "--event-dir", "/e"] });
  assert.deepEqual(daemonArgv(cmd), { cmd: "node", argv: ["--no-warnings", "/pkg/dist/arbiter.mjs"] });
  assert.deepEqual(daemonArgv(cmd, ["--event-dir", "/e"]), { cmd: "node", argv: ["--no-warnings", "/pkg/dist/arbiter.mjs", "--event-dir", "/e"] });
});

// ── stage 0b (policy-surface.md §2.6): the instance autostart starts the SUPERVISOR ──

import { startArbiterInstance, promotedSockPath } from "../../src/arbiter.js";

/** A SHORT scratch dir: startArbiterInstance refuses a base an instance
 *  socket might not fit under (104-byte sun_path on macOS, whose per-user
 *  TMPDIR alone is 49 bytes; runtime-instances.md §3b), so the harness lives
 *  under /tmp, realpath'd (/private/tmp on macOS), like demo.test.ts. */
function shortTmp(prefix: string): string {
  return realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), prefix)));
}

function instanceHarness() {
  const dir = shortTmp("brk-");
  const base = join(dir, "runtime");
  const spawned: { spec: DaemonSpec; env: NodeJS.ProcessEnv }[] = [];
  const logs: string[] = [];
  return {
    dir, base, spawned, logs,
    layout: Layout.dev(join(dir, "repo")),
    deps: (up: boolean, env: NodeJS.ProcessEnv = {}) => ({
      spawnDaemon: (spec: DaemonSpec, e: NodeJS.ProcessEnv) => { spawned.push({ spec, env: e }); },
      waitForSocket: async (sock: string) => { assert.equal(sock, promotedSockPath(base)); return up; },
      log: (m: string) => { logs.push(m); },
      env,
    }),
    close: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("startArbiterInstance: the SUPERVISOR (dashboard, arbiter only) is started first, in instance+promote mode, with no pinned sock", async () => {
  const h = instanceHarness();
  try {
    await startArbiterInstance(h.layout, h.base, join(h.dir, "logs", "a.log"), { MANDU_INTEGRITY: "1" }, h.deps(true, { MANDU_ARBITER_SOCK: "/pinned.sock", HOME: "/h" }))();
    assert.equal(h.spawned.length, 1, "the supervisor came up → no bare arbiter");
    const s = h.spawned[0]!;
    assert.equal(s.spec.cmd, "node", "the source form: one node process, no npm");
    assert.match(String(s.spec.args.at(-1)), /\/dashboard\/src\/server-main\.ts$/);
    assert.match(String(s.spec.cwd), /\/dashboard$/, "the dashboard package is the supervisor");
    assert.equal(s.env.DASHBOARD_AUTOSTART, "arbiter", "only the arbiter — the proxies are this launch's own services");
    assert.equal(s.env.MANDU_RUNTIME_DIR, h.base);
    assert.equal(s.env.MANDU_PROMOTE, "1");
    assert.equal(s.env.MANDU_INTEGRITY, "1", "the axis env rides along");
    assert.equal(s.env.MANDU_ARBITER_SOCK, undefined, "a pinned sock would flip server-main back to pinned mode");
    assert.equal(s.env.MANDU_LIFELINE, undefined, "the stack outlives the launcher");
    assert.equal(s.env.MANDU_OWNER_PID, "none", "resident: no owner, so reap never stops it once the launcher exits (d4)");
    assert.ok(h.logs.some((l) => /starting the Mandu stack \(dashboard \+ arbiter\)/.test(l)));
    assert.ok(existsSync(join(h.dir, "logs")), "log dir created");
  } finally {
    h.close();
  }
});

test("startArbiterInstance: FAIL-SOFT — when the promoted socket never appears, the bare arbiter is started and the adoption consequence is said", async () => {
  const h = instanceHarness();
  try {
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, h.deps(false, { HOME: "/h" }))();
    assert.equal(h.spawned.length, 2);
    assert.match(String(h.spawned[0]!.spec.cwd), /\/dashboard$/);
    assert.match(String(h.spawned[1]!.spec.cwd), /\/arbiter$/, "the bare arbiter is the fallback");
    assert.equal(h.spawned[1]!.env.DASHBOARD_AUTOSTART, undefined);
    assert.equal(h.spawned[1]!.env.MANDU_PROMOTE, "1", "the fallback still promotes `current`");
    assert.equal(h.spawned[1]!.env.MANDU_OWNER_PID, "none", "the fallback arbiter is resident too");
    assert.ok(h.logs.some((l) =>
      /the dashboard did not start \(it did not answer within 6 s, and its log shows no error\)/.test(l) &&
      /protection runs without it/.test(l) && /read-only until you restart/.test(l)), JSON.stringify(h.logs));
  } finally {
    h.close();
  }
});

test("startArbiterInstance: MANDU_AUTOSTART_SUPERVISOR=0 opts back into the bare-arbiter start (no supervisor attempt, no wait)", async () => {
  const h = instanceHarness();
  try {
    const deps = h.deps(true, { MANDU_AUTOSTART_SUPERVISOR: "0", HOME: "/h" });
    deps.waitForSocket = async () => { throw new Error("must not wait for the supervisor"); };
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, deps)();
    assert.equal(h.spawned.length, 1);
    assert.match(String(h.spawned[0]!.spec.cwd), /\/arbiter$/);
    assert.equal(h.logs.length, 0);
  } finally {
    h.close();
  }
});

test("startArbiterInstance: the supervisor gets the launcher's readiness deadline for its own arbiter start (MANDU_SERVICE_READY_TIMEOUT_MS)", async () => {
  const h = instanceHarness();
  try {
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, h.deps(true, { HOME: "/h", MANDU_SERVICE_READY_TIMEOUT_MS: "45000" }))();
    assert.equal(h.spawned[0]!.env["MANDU_SERVICE_READY_TIMEOUT_MS"], "45000");
  } finally {
    h.close();
  }
  const computed = instanceHarness();
  try {
    await startArbiterInstance(computed.layout, computed.base, join(computed.dir, "a.log"), {}, computed.deps(true, { HOME: "/h" }))();
    const ms = Number(computed.spawned[0]!.env["MANDU_SERVICE_READY_TIMEOUT_MS"]);
    assert.ok(ms >= SERVICE_READY_BASE_MS && ms <= SERVICE_READY_MAX_MS, `the load-aware deadline, got ${ms}`);
  } finally {
    computed.close();
  }
});

test("startArbiterInstance: the autostarted dashboard takes a FREE port unless the user pinned one (release checklist a1)", async () => {
  const h = instanceHarness();
  try {
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, h.deps(true, { HOME: "/h" }))();
    assert.equal(h.spawned[0]!.env.DASHBOARD_PORT, "0", "kernel-assigned: a dashboard already on 4500 (another user, a resident deployment) never costs this launch its supervisor");
  } finally {
    h.close();
  }
  const pinned = instanceHarness();
  try {
    await startArbiterInstance(pinned.layout, pinned.base, join(pinned.dir, "a.log"), {}, pinned.deps(true, { HOME: "/h", DASHBOARD_PORT: "4600" }))();
    assert.equal(pinned.spawned[0]!.env.DASHBOARD_PORT, "4600", "an env/config-pinned DASHBOARD_PORT still wins");
  } finally {
    pinned.close();
  }
});

test("startArbiterInstance: the all-is-well 'starting the stack' note goes to `info` (verbose-only at the launcher); the fallback stays on `log`", async () => {
  const h = instanceHarness();
  try {
    const infos: string[] = [];
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, { ...h.deps(false, { HOME: "/h" }), info: (m: string) => { infos.push(m); } })();
    assert.equal(infos.length, 1);
    assert.match(infos[0]!, /starting the Mandu stack/);
    assert.ok(!h.logs.some((l) => /starting the Mandu stack/.test(l)), "not on the always-printed channel");
    assert.ok(h.logs.some((l) => /the dashboard did not start/.test(l)), "the fallback is a real problem: always printed");
  } finally {
    h.close();
  }
});

test("startArbiterInstance: the fallback names the REAL reason from this start's part of the log (d6)", async () => {
  const h = instanceHarness();
  try {
    const logPath = join(h.dir, "a.log");
    writeFileSync(logPath, "old run: Error: something from yesterday\n");
    const deps = {
      ...h.deps(false, { HOME: "/h" }),
      // What the dashboard appended during THIS start.
      spawnDaemon: (spec: DaemonSpec, e: NodeJS.ProcessEnv) => {
        h.spawned.push({ spec, env: e });
        if (/dashboard$/.test(String(spec.cwd))) {
          appendFileSync(logPath, "[dashboard] starting\nError: listen EADDRINUSE: address already in use 127.0.0.1:4500\n    at Server.setupListenHandle\n");
        }
      },
    };
    await startArbiterInstance(h.layout, h.base, logPath, {}, deps)();
    const line = h.logs.find((l) => /the dashboard did not start/.test(l)) ?? "";
    assert.match(line, /port 4500 is already in use \(unset DASHBOARD_PORT/, line);
    assert.doesNotMatch(line, /yesterday/, "only this start's log lines count");
  } finally {
    h.close();
  }
});

// ── one resident arbiter (2026-09-29): a SLOW supervisor is not a failed one ──
//
// Found live: a 3-hour orphan `npm run serve` → tsx → mandu-arbiter from
// instance-autostart.test.ts. On a loaded host the supervisor missed the 6 s
// wait, the bare fallback started BESIDE it, and nobody owned the second
// resident arbiter.

/** A supervisor handle whose liveness the test drives. */
function fakeDaemon(running: () => boolean) {
  return { pid: 4242, running };
}

test("startArbiterInstance: a supervisor still RUNNING at 6 s gets the grace window; when it promotes, no bare arbiter starts", async () => {
  const h = instanceHarness();
  try {
    let polls = 0;
    const stops: unknown[] = [];
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, {
      ...h.deps(false, { HOME: "/h" }),
      spawnDaemon: (spec: DaemonSpec, e: NodeJS.ProcessEnv) => { h.spawned.push({ spec, env: e }); return fakeDaemon(() => true); },
      // The first (6 s) wait and one grace poll miss; the next one sees the socket.
      waitForSocket: async () => ++polls >= 3,
      supervisorGraceMs: 10_000,
      stopDaemon: async (d) => { stops.push(d); },
    })();
    assert.equal(h.spawned.length, 1, "only the supervisor: a slow one is waited for, never doubled");
    assert.match(String(h.spawned[0]!.spec.cwd), /\/dashboard$/);
    assert.equal(stops.length, 0, "a supervisor that promoted is never stopped");
    assert.ok(!h.logs.some((l) => /did not start/.test(l)), JSON.stringify(h.logs));
  } finally {
    h.close();
  }
});

test("startArbiterInstance: a supervisor that never promotes is STOPPED before the bare arbiter starts (never two residents)", async () => {
  const h = instanceHarness();
  try {
    let alive = true;
    const order: string[] = [];
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, {
      ...h.deps(false, { HOME: "/h" }),
      spawnDaemon: (spec: DaemonSpec, e: NodeJS.ProcessEnv) => {
        h.spawned.push({ spec, env: e });
        order.push(`spawn:${String(spec.cwd).split("/").pop()}`);
        return fakeDaemon(() => alive);
      },
      supervisorGraceMs: 50,
      stopDaemon: async (d) => { assert.equal(d.pid, 4242); order.push("stop:dashboard"); alive = false; },
    })();
    assert.deepEqual(order, ["spawn:dashboard", "stop:dashboard", "spawn:arbiter"], "the fallback starts only once the supervisor is gone");
    assert.ok(h.logs.some((l) => /the dashboard did not start \(it was still starting after 6 s, so it was stopped\)/.test(l)), JSON.stringify(h.logs));
  } finally {
    h.close();
  }
});

test("startArbiterInstance: a supervisor that already EXITED falls back at once (no grace wait, nothing to stop)", async () => {
  const h = instanceHarness();
  try {
    let polls = 0;
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, {
      ...h.deps(false, { HOME: "/h" }),
      spawnDaemon: (spec: DaemonSpec, e: NodeJS.ProcessEnv) => { h.spawned.push({ spec, env: e }); return fakeDaemon(() => false); },
      waitForSocket: async () => { polls++; return false; },
      stopDaemon: async () => { throw new Error("an exited supervisor has nothing to stop"); },
    })();
    assert.equal(polls, 1, "only the first wait");
    assert.equal(h.spawned.length, 2);
    assert.match(String(h.spawned[1]!.spec.cwd), /\/arbiter$/);
  } finally {
    h.close();
  }
});

test("lastStartFailure: EADDRINUSE names the port; else the last error-looking line; nothing → null", () => {
  assert.equal(lastStartFailure(null), null);
  assert.equal(lastStartFailure("[dashboard] up on http://127.0.0.1:4500/\n"), null);
  assert.match(lastStartFailure("Error: listen EADDRINUSE: address already in use :::8123\n")!, /^port 8123 is already in use/);
  assert.equal(
    lastStartFailure("[dashboard] refusing to bind 0.0.0.0: a non-loopback bind needs authentication\n"),
    "refusing to bind 0.0.0.0: a non-loopback bind needs authentication",
  );
  assert.equal(
    lastStartFailure("Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/x/dist/dashboard.mjs'\n    at resolve (node:internal)\n"),
    "Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/x/dist/dashboard.mjs'",
  );
});

// ── runtime-instances.md §13: the shared stack starts as the ACCOUNT (2026-09-28) ──
//
// Found live: `HOME=<scratch> mandu --target shell …` with no stack up
// autostarted one under the scratch HOME; its promoted arbiter kept the
// account's symbol DB, policy and events there for 20 hours.

import { sharedStackHomeEnv } from "../../src/arbiter.js";

test("sharedStackHomeEnv: a foreign HOME at the account's rendezvous starts the stack under the real home", () => {
  const account = { home: "/home/u", rendezvous: "/run/user/1001/mandu" };
  const env = {
    HOME: "/tmp/scratch/home",
    XDG_STATE_HOME: "/tmp/scratch/home/.local/state", // points into the scratch HOME: dropped
    XDG_CONFIG_HOME: "/etc/elsewhere", // set on purpose, elsewhere: kept
  };
  assert.deepEqual(sharedStackHomeEnv(env, "/run/user/1001/mandu", account), {
    set: { HOME: "/home/u" },
    unset: ["XDG_STATE_HOME"],
  });
  // The real home (trailing slash and all) needs nothing.
  assert.equal(sharedStackHomeEnv({ HOME: "/home/u/" }, "/run/user/1001/mandu", account), null);
  // An isolated run (its own runtime base) keeps its HOME.
  assert.equal(sharedStackHomeEnv(env, "/tmp/scratch/run/mandu", account), null);
  // A MANDU_HOME inside the scratch HOME goes too; one elsewhere was set on purpose.
  assert.deepEqual(sharedStackHomeEnv({ ...env, MANDU_HOME: "/tmp/scratch/home/.mandu" }, "/run/user/1001/mandu", account)?.unset, ["MANDU_HOME", "XDG_STATE_HOME"]);
  assert.deepEqual(sharedStackHomeEnv({ ...env, MANDU_HOME: "/data/mandu" }, "/run/user/1001/mandu", account)?.unset, ["XDG_STATE_HOME"]);
  // Unknown account or no HOME: no guess.
  assert.equal(sharedStackHomeEnv(env, "/run/user/1001/mandu", null), null);
  assert.equal(sharedStackHomeEnv({}, "/run/user/1001/mandu", account), null);
});

import { accountRendezvous } from "../../src/arbiter.js";

test("accountRendezvous: the path table's runtime-dir under the account's logind dir", () => {
  assert.equal(accountRendezvous(1001, "/home/u"), "/run/user/1001/mandu");
  assert.equal(accountRendezvous(0, "/root"), "/run/user/0/mandu");
});

test("startArbiterInstance: under a foreign HOME the supervisor and the bare fallback both get the account's home", async () => {
  const h = instanceHarness();
  try {
    const account = { home: join(h.dir, "realhome"), rendezvous: h.base };
    const scratch = join(h.dir, "scratch");
    const infos: string[] = [];
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, {
      ...h.deps(false, { HOME: scratch, XDG_STATE_HOME: join(scratch, ".local", "state") }),
      account,
      info: (m: string) => { infos.push(m); },
    })();
    assert.equal(h.spawned.length, 2, "supervisor attempt + bare fallback");
    for (const s of h.spawned) {
      assert.equal(s.env["HOME"], account.home);
      assert.equal(s.env["XDG_STATE_HOME"], undefined);
      assert.equal(s.env["MANDU_PROMOTE"], "1");
    }
    assert.ok(infos.some((m) => m.includes("not your account's home")), infos.join("\n"));
  } finally {
    h.close();
  }
});

test("startArbiterInstance: the account's own HOME passes through untouched", async () => {
  const h = instanceHarness();
  try {
    const account = { home: join(h.dir, "realhome"), rendezvous: h.base };
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, {
      ...h.deps(true, { HOME: account.home, XDG_STATE_HOME: "/x/state" }),
      account,
    })();
    assert.equal(h.spawned[0]!.env["HOME"], account.home);
    assert.equal(h.spawned[0]!.env["XDG_STATE_HOME"], "/x/state");
  } finally {
    h.close();
  }
});

test("startArbiterInstance (resident): neither the supervisor nor the bare arbiter gets a store flag; they keep the home's own", async () => {
  const h = instanceHarness();
  try {
    const argsSeen: unknown[][] = [];
    const deps = {
      ...h.deps(false, { HOME: "/h" }),
      spawnDaemon: (...a: unknown[]) => { argsSeen.push(a.slice(3)); },
    };
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, deps)();
    assert.equal(argsSeen.length, 2, "supervisor, then the bare fallback");
    assert.deepEqual(argsSeen.map((a) => withoutPluginArgs(a[0] as unknown[] | undefined)), [[], []], "no extra argv: no --event-dir / --symbol-db");
  } finally {
    h.close();
  }
});

// ── runtime-instances.md §3b: the short, private darwin runtime base (2026-09-29) ──
//
// Found live: on macOS the arbiter bound $TMPDIR/mandu/instances/<id>/arbiter.sock
// = 107 bytes > 103 and refused; the launcher waited 11 s, then refused too; the
// dashboard it had spawned stayed up with no owner.

import { chmodSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { accountOf, guardRuntimePath } from "../../src/arbiter.js";

const UID = process.getuid?.() ?? 0;

test("accountOf: the rendezvous is /tmp/mandu-<uid> on macOS (the §13 guard is live there) and /run/user/<uid>/mandu on Linux", () => {
  assert.deepEqual(accountOf({
    platform: "darwin", getuid: () => 501, homedir: () => "/Users/u",
    darwinTempDir: () => "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/",
  }), { home: "/Users/u", rendezvous: "/tmp/mandu-501" });
  assert.deepEqual(accountOf({ platform: "linux", getuid: () => 1001, homedir: () => "/home/u" }), { home: "/home/u", rendezvous: "/run/user/1001/mandu" });
  assert.equal(accountOf({ getuid: null }), null);
  // The HOME rewrite now fires at the darwin rendezvous.
  const account = accountOf({
    platform: "darwin", getuid: () => 501, homedir: () => "/Users/u",
    darwinTempDir: () => "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/",
  });
  assert.deepEqual(sharedStackHomeEnv({ HOME: "/tmp/scratch" }, "/tmp/mandu-501", account), { set: { HOME: "/Users/u" }, unset: [] });
});

test("startArbiterInstance PREFLIGHT: a base the arbiter's instance socket cannot fit under fails at once naming MANDU_RUNTIME_DIR (no spawn, no 11 s wait)", async () => {
  const h = instanceHarness();
  try {
    // darwin, no git rev (the harness layout is no checkout): the REAL socket
    // adds 50 bytes (nogit, a 5-digit pid), so 54 + 50 ≥ 104.
    const base = "/" + "b".repeat(53);
    const deps = { ...h.deps(true, { HOME: "/h", MANDU_RUNTIME_DIR: base }), platform: "darwin" };
    deps.waitForSocket = async () => { throw new Error("must not wait"); };
    await assert.rejects(
      startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, deps)(),
      (e: Error) => /refusing to launch: the runtime dir \/b+ is 54 bytes: .*can reach 104 bytes/.test(e.message) &&
        /103-byte limit/.test(e.message) && /MANDU_RUNTIME_DIR at a directory of at most 40 bytes/.test(e.message),
    );
    assert.equal(h.spawned.length, 0);
    assert.equal(existsSync(join(h.dir, "a.log")), false, "nothing created");
    // XDG_RUNTIME_DIR as the source is named too.
    const xdg = { ...h.deps(true, { HOME: "/h", XDG_RUNTIME_DIR: "/" + "x".repeat(60) }), platform: "darwin" };
    await assert.rejects(startArbiterInstance(h.layout, "/" + "x".repeat(60) + "/mandu", join(h.dir, "a.log"), {}, xdg)(),
      /comes from XDG_RUNTIME_DIR; MANDU_RUNTIME_DIR overrides it/);
    // The Linux budget (108): a base that fits there starts.
    const linux = { ...h.deps(true, { HOME: "/h" }), platform: "linux" };
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, linux)();
    assert.equal(h.spawned.length, 1);
  } finally {
    h.close();
  }
});

test("startArbiterInstance: the runtime-dir checks read `runtimeEnv` (the env the launch resolved its base from) over the spawn env", async () => {
  const h = instanceHarness();
  try {
    const xdg = "/" + "x".repeat(60);
    const base = xdg + "/mandu";
    // The spawn env (process.env at the launcher) names a MANDU_RUNTIME_DIR;
    // the launch's own env names only XDG_RUNTIME_DIR, so the advice names it.
    const deps = {
      ...h.deps(true, { HOME: "/h", MANDU_RUNTIME_DIR: "/elsewhere" }), platform: "darwin",
      runtimeEnv: { HOME: "/h", XDG_RUNTIME_DIR: xdg },
    };
    await assert.rejects(startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, deps)(),
      /comes from XDG_RUNTIME_DIR; MANDU_RUNTIME_DIR overrides it/);
    // Without runtimeEnv the spawn env is judged: it names MANDU_RUNTIME_DIR, no advice.
    const { runtimeEnv: _unused, ...spawnOnly } = deps;
    await assert.rejects(startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, spawnOnly)(),
      (e: Error) => /refusing to launch/.test(e.message) && !/comes from XDG_RUNTIME_DIR/.test(e.message));
    // The fallback's private-dir rule too: a shared fallback named only by runtimeEnv refuses.
    const fb = join(h.dir, `mandu-${UID}`);
    mkdirSync(fb, { mode: 0o755 });
    chmodSync(fb, 0o755);
    await assert.rejects(
      startArbiterInstance(h.layout, fb, join(fb, "logs", "a.log"), {}, {
        ...h.deps(true, { HOME: "/h" }), platform: "linux", runtimeEnv: { HOME: "/h", MANDU_RUNTIME_FALLBACK_ROOT: h.dir },
      })(),
      /refusing to launch: the Mandu runtime dir .* is shared \(mode 0755/,
    );
    assert.equal(h.spawned.length, 0);
  } finally {
    h.close();
  }
});

test("startArbiter (pinned socket): the runtime-dir checks read `runtimeEnv` (main()'s env), never process.env (2026-10-10)", async () => {
  const dir = realpathSync(shortTmp("brk-legacy-"));
  // A shared (0755) fallback base under a root only `runtimeEnv` names: the
  // private-dir rule refuses the log, event dir and socket under it. This
  // process's env names another fallback root, under which the same paths are
  // no fallback at all, so a check that read process.env would start.
  const fb = join(dir, `mandu-${UID}`);
  mkdirSync(fb, { mode: 0o755 });
  chmodSync(fb, 0o755);
  const saved = process.env["MANDU_RUNTIME_FALLBACK_ROOT"];
  process.env["MANDU_RUNTIME_FALLBACK_ROOT"] = join(dir, "process-env-root");
  const spawned: DaemonSpec[] = [];
  const spawnDaemon = (spec: DaemonSpec) => { spawned.push(spec); };
  const paths = [join(fb, "arbiter.sock"), join(fb, "sid-1", "events"), join(fb, "sid-1", "arbiter.log")] as const;
  try {
    await assert.rejects(
      startArbiter(Layout.dev("/repo"), ...paths, {}, { spawnDaemon, runtimeEnv: { HOME: "/h", MANDU_RUNTIME_FALLBACK_ROOT: dir } })(),
      /refusing to launch: the Mandu runtime dir .* is shared \(mode 0755/,
    );
    assert.equal(spawned.length, 0, "nothing spawned");
    assert.equal(existsSync(join(fb, "sid-1")), false, "nothing created");
    assert.equal(statSync(fb).mode & 0o777, 0o755, "the base is left as it was");
    // Without runtimeEnv the default is process.env: its root is elsewhere,
    // so the same paths start (the control: the refusal above is runtimeEnv's).
    await startArbiter(Layout.dev("/repo"), ...paths, {}, { spawnDaemon })();
    assert.equal(spawned.length, 1);
  } finally {
    if (saved === undefined) delete process.env["MANDU_RUNTIME_FALLBACK_ROOT"]; else process.env["MANDU_RUNTIME_FALLBACK_ROOT"] = saved;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ensureArbiter over an autostart with a too-long base refuses FAST: the preflight error, never the poll", async () => {
  const h = instanceHarness();
  try {
    let waited = false;
    const base = "/" + "c".repeat(60); // over the budget on every platform
    await assert.rejects(
      ensureArbiter({
        sock: `${base}/current/arbiter.sock`,
        noAutostart: false,
        start: startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, { ...h.deps(false, { HOME: "/h" }) }),
        waitForSocket: async () => { waited = true; return false; },
      }),
      /refusing to launch: the runtime dir .* over the \d+-byte limit/,
    );
    assert.equal(waited, false);
    assert.equal(h.spawned.length, 0);
  } finally {
    h.close();
  }
});

test("startArbiterInstance at the /tmp fallback: the base is CREATED 0700 before anything spawns", async () => {
  const h = instanceHarness();
  try {
    const root = h.dir;
    const base = join(root, `mandu-${UID}`);
    const env = { HOME: "/h", MANDU_RUNTIME_FALLBACK_ROOT: root };
    await startArbiterInstance(h.layout, base, join(base, "logs", "arbiter-autostart.log"), {}, {
      ...h.deps(true, env),
      waitForSocket: async () => true,
    })();
    assert.equal(statSync(base).mode & 0o777, 0o700);
    assert.equal(h.spawned.length, 1);
    assert.equal(h.spawned[0]!.env["MANDU_RUNTIME_DIR"], base, "the arbiter/dashboard get the base verbatim (and re-check it)");
  } finally {
    h.close();
  }
});

test("startArbiterInstance at a SHARED (0755) fallback: refused, nothing spawned, nothing created in it", async () => {
  const h = instanceHarness();
  try {
    const root = h.dir;
    const base = join(root, `mandu-${UID}`);
    mkdirSync(base);
    chmodSync(base, 0o755);
    const env = { HOME: "/h", MANDU_RUNTIME_FALLBACK_ROOT: root };
    await assert.rejects(
      startArbiterInstance(h.layout, base, join(base, "logs", "a.log"), {}, h.deps(true, env))(),
      (e: Error) => e.message.startsWith("mandu: refusing to launch: the Mandu runtime dir") && /is shared \(mode 0755/.test(e.message),
    );
    assert.equal(h.spawned.length, 0);
    assert.equal(existsSync(join(base, "logs")), false);
  } finally {
    h.close();
  }
});

/** A TMPDIR too long for an instance socket: the base resolves to the
 *  /tmp/mandu-<uid> fallback (its root the test hook), never rule 3's shared
 *  /tmp/mandu, which an env with no TMPDIR would give (test-runtime.ts). */
const LONG_TMPDIR = "/" + "t".repeat(60);

test("ensureArbiter refuses a socket under a fallback that is not private — BEFORE attaching to it", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "brk-fb-")));
  const dir2 = realpathSync(mkdtempSync(join(tmpdir(), "brk-fb2-")));
  try {
    const base = join(dir, `mandu-${UID}`);
    mkdirSync(join(base, "current"), { recursive: true });
    chmodSync(base, 0o777);
    const sock = join(base, "current", "arbiter.sock");
    writeFileSync(sock, ""); // an "impostor" socket that exists
    let started = false;
    await assert.rejects(
      ensureArbiter({
        sock, noAutostart: false, start: async () => { started = true; }, waitForSocket: async () => true,
        env: { TMPDIR: LONG_TMPDIR, MANDU_RUNTIME_FALLBACK_ROOT: dir },
      }),
      /refusing to launch: .* is shared \(mode 0777/,
    );
    assert.equal(started, false);
    // A foreign owner, simulated through the injected lstat, is refused the same way.
    chmodSync(base, 0o700);
    await assert.rejects(
      ensureArbiter({
        sock, noAutostart: false, start: async () => {}, waitForSocket: async () => true,
        env: { TMPDIR: LONG_TMPDIR, MANDU_RUNTIME_FALLBACK_ROOT: dir },
        privateDirDeps: { uid: UID, lstat: () => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: UID + 1, mode: 0o40700 }) },
      }),
      /owned by uid/,
    );
    // Its owner's private dir: attached.
    assert.deepEqual(await ensureArbiter({
      sock, noAutostart: false, start: async () => {}, waitForSocket: async () => true, env: { TMPDIR: LONG_TMPDIR, MANDU_RUNTIME_FALLBACK_ROOT: dir },
    }), { attached: true });
    // runtimeDirs: a scope dir under an ABSENT fallback gets the base made 0700 first.
    await assert.rejects(ensureArbiter({
      sock: join(dir2, "elsewhere.sock"), noAutostart: true, start: async () => {}, waitForSocket: async () => true,
      env: { TMPDIR: LONG_TMPDIR, MANDU_RUNTIME_FALLBACK_ROOT: dir2 }, runtimeDirs: [join(dir2, `mandu-${UID}`, "123-4")],
    }), /MANDU_NO_ARBITER_AUTOSTART=1/, "the refusal comes AFTER the base was prepared");
    assert.equal(statSync(join(dir2, `mandu-${UID}`)).mode & 0o777, 0o700);
    // Default runtimeDirs: the runtime base of env (the scope-dir root) —
    // here a long TMPDIR makes it the fallback although the pinned arbiter
    // socket lives elsewhere.
    rmSync(join(dir2, `mandu-${UID}`), { recursive: true });
    await assert.rejects(ensureArbiter({
      sock: join(dir2, "elsewhere.sock"), noAutostart: true, start: async () => {}, waitForSocket: async () => true,
      env: { TMPDIR: "/" + "t".repeat(60), MANDU_RUNTIME_FALLBACK_ROOT: dir2 },
    }), /MANDU_NO_ARBITER_AUTOSTART=1/);
    assert.equal(statSync(join(dir2, `mandu-${UID}`)).mode & 0o777, 0o700, "made private before run.ts mkdirs a scope dir in it");
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(dir2, { recursive: true, force: true });
  }
});

test("guardRuntimePath: a no-op off the fallback (never creates); the launcher's voice on a refusal", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "brk-guard-")));
  try {
    guardRuntimePath(join(dir, "x", "y"), { MANDU_RUNTIME_FALLBACK_ROOT: join(dir, "fb") });
    assert.equal(existsSync(join(dir, "x")), false);
    mkdirSync(join(dir, "fb", `mandu-${UID}`), { recursive: true });
    chmodSync(join(dir, "fb", `mandu-${UID}`), 0o750);
    assert.throws(() => guardRuntimePath(join(dir, "fb", `mandu-${UID}`, "s"), { MANDU_RUNTIME_FALLBACK_ROOT: join(dir, "fb") }),
      /^Error: mandu: refusing to launch: the Mandu runtime dir .* is shared \(mode 0750/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("guardRuntimePath on $XDG_RUNTIME_DIR/mandu (2026-10-17): created 0700 under a 002 umask; createOther:false (ensureArbiter) creates nothing but still tightens a present 0775 one", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "brk-guard-")));
  try {
    const env = { XDG_RUNTIME_DIR: dir };
    const base = join(dir, "mandu");
    guardRuntimePath(join(base, "current", "arbiter.sock"), env, {}, {}, { createOther: false });
    assert.equal(existsSync(base), false, "the preflight creates no base of the third rule");
    const old = process.umask(0o002);
    try {
      guardRuntimePath(join(base, "x.log"), env);
    } finally {
      process.umask(old);
    }
    assert.equal(statSync(base).mode & 0o777, 0o700, "a creator makes it 0700, never the umask's 0775");
    chmodSync(base, 0o775);
    guardRuntimePath(join(base, "current", "arbiter.sock"), env, {}, {}, { createOther: false });
    assert.equal(statSync(base).mode & 0o777, 0o700, "a present 0775 base in a sealed dir is tightened by the preflight too");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── finding linux-2: the preflight sizes the REAL socket, not the worst case ──

import { arbiterRevDir, arbiterRevOf, type InstanceStartDeps } from "../../src/arbiter.js";
import { execFileSync } from "node:child_process";
import { symlinkSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** A real, creatable base of exactly `bytes` bytes under the harness dir. */
function baseOfBytes(dir: string, bytes: number): string {
  const b = join(dir, "r".repeat(bytes - Buffer.byteLength(dir) - 1));
  assert.equal(Buffer.byteLength(b), bytes);
  return b;
}

test("startArbiterInstance PREFLIGHT (Linux): a 46-byte base — over the 63-byte worst case, but the real socket is 101 bytes — STARTS", async () => {
  const h = instanceHarness();
  try {
    const base = baseOfBytes(h.dir, 46);
    let revReads = 0;
    await startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, {
      ...h.deps(true, { HOME: "/h", MANDU_RUNTIME_DIR: base }),
      platform: "linux",
      arbiterRev: () => { revReads++; return "335883df"; }, // git rev-parse --short: 8 chars
      waitForSocket: async (sock: string) => { assert.equal(sock, promotedSockPath(base)); return true; },
    })();
    assert.equal(h.spawned.length, 1, "the supervisor was started");
    assert.equal(h.spawned[0]!.env["MANDU_RUNTIME_DIR"], base);
    assert.equal(revReads, 1);
    // A short base never reads the rev (no git on the common path).
    await startArbiterInstance(h.layout, h.base, join(h.dir, "a.log"), {}, {
      ...h.deps(true, { HOME: "/h" }), platform: "linux", arbiterRev: () => { revReads++; return "x"; },
    })();
    assert.equal(revReads, 1);
  } finally {
    h.close();
  }
});

test("startArbiterInstance PREFLIGHT (Linux): a base the real socket does not fit (53 + 55 = 108) refuses at once, advising the safe 44 bytes", async () => {
  const h = instanceHarness();
  try {
    const base = baseOfBytes(h.dir, 53);
    await assert.rejects(
      startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, {
        ...h.deps(true, { HOME: "/h", MANDU_RUNTIME_DIR: base }),
        platform: "linux",
        arbiterRev: () => "335883df",
        waitForSocket: async () => { throw new Error("must not wait"); },
      })(),
      (e: Error) => /refusing to launch: the runtime dir .* is 53 bytes: .*can reach 108 bytes, over the 107-byte limit/.test(e.message) &&
        /at most 44 bytes/.test(e.message),
    );
    assert.equal(h.spawned.length, 0);
    assert.equal(existsSync(base), false, "nothing created");
    // With no rev (an installed layout outside any git work tree) the same
    // 53-byte base fits: 53 + 52 = 105 < 108.
    await startArbiterInstance(h.layout, base, join(h.dir, "a.log"), {}, {
      ...h.deps(true, { HOME: "/h", MANDU_RUNTIME_DIR: base }),
      platform: "linux",
      arbiterRev: () => "nogit",
      waitForSocket: async () => true,
    })();
    assert.equal(h.spawned.length, 1);
  } finally {
    h.close();
  }
});

test("arbiterRevDir / arbiterRevOf: the dir and the rev the spawned arbiter's server-main reads (REPO_DIR = <entry>/../..)", () => {
  assert.equal(arbiterRevDir(Layout.dev("/src/mandu")), "/src/mandu", "dev: <repoRoot>/arbiter/ipc/server-main.ts → the checkout");
  assert.equal(arbiterRevDir(Layout.installed("/opt/homebrew/lib/node_modules/@mandusec/mandu")), "/opt/homebrew/lib/node_modules/@mandusec",
    "installed: <pkgRoot>/dist/arbiter.mjs → the dir holding the package");
  const dir = shortTmp("brk-rev-");
  try {
    assert.equal(arbiterRevOf(join(dir, "absent")), "nogit");
    assert.equal(arbiterRevOf(dir), "nogit", "not a git work tree");
    // This checkout: the same answer `git rev-parse --short HEAD` gives.
    const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    let want = "nogit";
    try {
      want = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || "nogit";
    } catch { /* an exported tree without .git */ }
    assert.equal(arbiterRevOf(repo), want);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("arbiterRevOf is hardened like gitRevOf: a GIT_DIR or GIT_CONFIG_PARAMETERS in the launcher's environment never redirects the read", () => {
  const dir = shortTmp("brk-revh-");
  const env = {
    PATH: process.env["PATH"] ?? "/usr/bin:/bin", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  };
  // The answer an unpoisoned git gives (the user's own config read, as the
  // hardened call reads it).
  const plain = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")));
  const saved = { GIT_DIR: process.env["GIT_DIR"], GIT_CONFIG_PARAMETERS: process.env["GIT_CONFIG_PARAMETERS"] };
  try {
    const revOf = (name: string): string => {
      const root = join(dir, name);
      mkdirSync(root);
      execFileSync("git", ["init", "-q"], { cwd: root, env });
      execFileSync("git", ["commit", "-q", "--allow-empty", "-m", name], { cwd: root, env });
      return execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: root, env: plain, encoding: "utf8" }).trim();
    };
    const mine = revOf("mine");
    const other = revOf("other");
    assert.notEqual(mine, other);
    process.env["GIT_DIR"] = join(dir, "other", ".git");
    process.env["GIT_CONFIG_PARAMETERS"] = "'core.abbrev'='20'";
    assert.equal(arbiterRevOf(join(dir, "mine")), mine, "the dir's own HEAD, at the default abbreviation");
    assert.equal(arbiterRevOf(join(dir, "absent")), "nogit", "no inherited GIT_DIR stands in for a missing repository");
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── finding linux-3: the one-line hint when the base moved off $TMPDIR/mandu ──

test("startArbiterInstance at the fallback while a stack still answers at the old $TMPDIR/mandu: one hint line on `log`, then the start goes on", async () => {
  const h = instanceHarness();
  try {
    const uid = process.getuid?.() ?? 0;
    const longTmp = join(h.dir, "t".repeat(40));
    const old = join(longTmp, "mandu");
    mkdirSync(join(old, "instances", "i1"), { recursive: true });
    writeFileSync(join(old, "instances", "i1", "arbiter.sock"), "");
    symlinkSync(join("instances", "i1"), join(old, "current"));
    const opts = { platform: "linux", uid, fallbackRoot: h.dir };
    const base = join(h.dir, `mandu-${uid}`);
    await startArbiterInstance(h.layout, base, join(base, "logs", "a.log"), {}, {
      ...h.deps(true, { HOME: "/h", TMPDIR: longTmp }),
      platform: "linux",
      runtimeBaseOpts: opts,
      waitForSocket: async () => true,
    })();
    const hints = h.logs.filter((m) => m.includes("still running under"));
    assert.deepEqual(hints, [
      `mandu: a Mandu stack is still running under ${old}, where older versions kept it; this launch uses ${base}. ` +
        `Stop the old one: MANDU_RUNTIME_DIR=${old} mandu stop --all`,
    ]);
    assert.equal(h.spawned.length, 1, "the hint does not stop the start");
    // No live stack at the old base: no hint.
    h.logs.length = 0;
    rmSync(join(old, "instances"), { recursive: true });
    await startArbiterInstance(h.layout, base, join(base, "logs", "a.log"), {}, {
      ...h.deps(true, { HOME: "/h", TMPDIR: longTmp }), platform: "linux", runtimeBaseOpts: opts, waitForSocket: async () => true,
    })();
    assert.deepEqual(h.logs.filter((m) => m.includes("still running under")), []);
  } finally {
    h.close();
  }
});

// ── finding linux-4: a base directly in a shared sticky dir must be ours ─────

test("startArbiterInstance on a base in a shared sticky dir: created 0700 when absent; group-writable or foreign → refused, nothing spawned", async () => {
  const h = instanceHarness();
  const sticky = join(h.dir, "tmp");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777); // stands in for /tmp
  try {
    const base = join(sticky, "mandu");
    const run = (d: Partial<InstanceStartDeps> = {}) => startArbiterInstance(h.layout, base, join(base, "logs", "a.log"), {}, {
      ...h.deps(true, { HOME: "/h", MANDU_RUNTIME_DIR: base }), platform: "linux",
      waitForSocket: async () => true, ...d,
    })();
    await run();
    assert.equal(statSync(base).mode & 0o777, 0o700, "created private (an earlier arbiter's mkdir -p made it 0755)");
    assert.equal(h.spawned.length, 1);
    chmodSync(base, 0o755);
    await run();
    assert.equal(h.spawned.length, 2, "a self-made 0755 dir still starts");
    chmodSync(base, 0o775);
    await assert.rejects(run(), (e: Error) =>
      e.message.startsWith("mandu: refusing to launch: the Mandu runtime dir") && /writable by other accounts \(mode 0775/.test(e.message));
    chmodSync(base, 0o755);
    await assert.rejects(run({
      privateDirDeps: { uid: UID, lstat: () => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: UID + 1, mode: 0o40755 }) },
    }), /owned by uid/);
    assert.equal(h.spawned.length, 2, "nothing spawned on a refusal");
  } finally {
    chmodSync(sticky, 0o755);
    h.close();
  }
});
