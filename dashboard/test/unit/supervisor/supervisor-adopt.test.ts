/**
 * supervisor-adopt.test — adoption (never spawn over / reap an arbiter we did
 * not start), runtime-instances mode env wiring, and the adopted daemon's hello
 * identity + staleness flag. Split from supervisor.test.ts (agent-legibility);
 * shared fixtures live in supervisor-harness.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import os from "node:os";
import { join } from "node:path";
import { existsSync, rmSync } from "node:fs";

import { type ServiceDefinition } from "../../../src/supervisor/supervisor.js";
import {
  NEVER_READY_SCRIPT,
  tmpdir,
  nodeArgs,
  mkSup,
  registerTmpHooks,
} from "./supervisor-harness.js";
import { tmpDir } from "../tmp-dir.js";

registerTmpHooks();

// ── adoption: don't start (or reap) a arbiter that's already running ────────────

/** Resolve true if something accepts a connection on the unix socket `path`. */
function listening(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ path });
    let settled = false;
    const done = (v: boolean): void => {
      if (settled) return;
      settled = true;
      try { s.destroy(); } catch { /* ignore */ }
      resolve(v);
    };
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
    s.setTimeout(1000, () => done(false));
  });
}

test("start() ADOPTS an already-running instance instead of spawning a duplicate", async () => {
  const workdir = tmpDir("mandu-adopt-");
  const sock = join(workdir, "arbiter.sock");
  // An EXTERNAL arbiter already listening on the socket (e.g. a live-e2e run or
  // another dashboard process).
  const external = net.createServer(() => {});
  await new Promise<void>((r) => external.listen(sock, () => r()));

  // The supervised def points at that socket, but its command would CRASH if it
  // were ever spawned — so a "running" state proves we ADOPTED (never spawned).
  const def: ServiceDefinition = {
    label: "Arbiter",
    command: process.execPath,
    args: ["-e", "process.exit(3)"],
    cwd: workdir,
    env: {},
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running", "an already-live arbiter is adopted as running");
    assert.equal(st.pid, null, "an adopted service has no child pid (it was not spawned)");
    assert.equal(st.adopted, true, "status() flags it ADOPTED so the control panel can badge it");

    // The decisive property: stopping the supervisor must NOT kill a arbiter it
    // did not start — so a dashboard restart can't take down a shared arbiter.
    // It must also not PRETEND it did: reporting "stopped" while the daemon keeps
    // serving is the stale-daemon trap. So stop() REFUSES, loudly, naming what the
    // operator has to kill — and leaves the state as it truthfully is.
    await assert.rejects(
      () => sup.stop("arbiter"),
      /ADOPTED/,
      "stop() on an adopted service refuses instead of silently claiming success",
    );
    assert.ok(await listening(sock), "the external arbiter survives stop() (we only reap what we start)");
    const after = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(after.state, "running", "the refused stop leaves the row RUNNING — because it is");

    // restart() refuses through the same door: it would only re-adopt the very
    // same daemon (the silent no-op that lets a STALE arbiter outlive its banner).
    await assert.rejects(() => sup.restart("arbiter"), /ADOPTED/, "restart() refuses too — it would be a no-op");
    assert.ok(await listening(sock), "…and the external arbiter is still there");

    // shutdownAll() (dashboard exit / self-restart) allSettles: the refusal must
    // NOT break it, and the adopted daemon survives it by design.
    await sup.shutdownAll();
    assert.ok(await listening(sock), "shutdownAll swallows the refusal; the adopted arbiter lives on");
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => external.close(() => r()));
    rmSync(workdir, { recursive: true, force: true });
  }
});

// ── runtime-instances mode (runtime-instances.md) ─────────────────────────────

test("instance mode: the arbiter spawns UN-pinned (promotes itself); logs stay off the current symlink", () => {
  const base = tmpdir();
  const currentSock = join(base, "current", "arbiter.sock");
  const sup = mkSup({}, { arbiterSock: currentSock, arbiterInstanceBase: base });

  const d = sup.definition("arbiter");
  assert.equal(d.env.MANDU_RUNTIME_DIR, base, "the spawned arbiter gets the runtime base");
  assert.equal(d.env.MANDU_PROMOTE, "1", "the supervised arbiter IS the deployment → promotes");
  assert.equal(d.env.MANDU_ARBITER_SOCK, "", "the inherited explicit socket is cleared (instance mode)");
  assert.deepEqual(d.ready, { kind: "socket", path: currentSock }, "readiness = the promotion rendezvous");
  // Deriving logDir from dirname(current/arbiter.sock) would mkdir -p a REAL
  // `current` directory and break the promotion symlink — logs live at the base.
  assert.equal(sup.logFilePath("arbiter"), join(base, "logs", "arbiter.log"));

  // Legacy explicit-path mode is unchanged.
  const pinned = join(base, "pinned.sock");
  const legacy = mkSup({}, { arbiterSock: pinned });
  assert.equal(legacy.definition("arbiter").env.MANDU_ARBITER_SOCK, pinned);
  assert.equal(legacy.definition("arbiter").env.MANDU_RUNTIME_DIR, undefined);
});

// Needs this repo's git history to call "deadbee" unresolvable; the OS test
// matrix copies the tree into its VM guests without .git.
const NO_GIT = !existsSync(join(__dirnameOfThisFile(), "..", "..", "..", "..", ".git"))
  && "no git checkout here (the OS test matrix copies the tree without .git)";
test("adopting an arbiter fetches its hello identity and flags an unresolvable rev STALE", { skip: NO_GIT }, async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  // A fake arbiter speaking just enough NDJSON to answer the hello handshake.
  const identity = {
    pid: 4242, startedAt: "2026-07-07T00:00:00.000Z", instanceId: "20260707-0000-deadbee-p4242",
    gitRev: "deadbee", gitDirty: false, sockPath: sock, eventDir: "/e", symbolDb: "/s",
  };
  const fake = net.createServer((c) => {
    c.on("data", (b) => {
      const line = b.toString();
      if (line.includes('"hello"')) {
        c.write(JSON.stringify({ id: 1, ok: true, result: identity }) + "\n");
      }
    });
  });
  await new Promise<void>((r) => fake.listen(sock, r));

  // repoRoot = THIS repo → a real HEAD rev; "deadbee" resolves to nothing here,
  // so the scoped diff FAILS → stale, fail-loud (an unresolvable foreign rev is
  // the masquerading-daemon trap, not noise — supervisor-defs arbiterStaleness).
  const repoRoot = join(__dirnameOfThisFile(), "..", "..", "..", "..");
  const sup = mkSup(
    { arbiter: { label: "Arbiter", command: process.execPath, args: nodeArgs(NEVER_READY_SCRIPT),
      cwd: dir, env: {}, ready: { kind: "socket", path: sock }, endpoint: sock } },
    { arbiterSock: sock, repoRoot },
  );
  try {
    await sup.start("arbiter"); // endpoint already live → ADOPT (no spawn)
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running");
    assert.ok(st.identity, "the adopt path records the listener's hello identity");
    assert.equal(st.identity!.pid, 4242);
    assert.equal(st.identity!.gitRev, "deadbee");
    assert.equal(st.identity!.instanceId, "20260707-0000-deadbee-p4242");
    assert.equal(st.stale, true, "an unresolvable foreign rev flags the daemon STALE (fail-loud)");
    assert.match(st.staleReason!, /not in this repo's history/, "the reason names the unresolvable rev");
    assert.match(st.staleReason!, /deadbee/);
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => fake.close(() => r()));
  }
});

function __dirnameOfThisFile(): string {
  return new URL(".", import.meta.url).pathname;
}

// ── a FOREIGN arbiter at `current` is displaced, not adopted (2026-09-28) ────
//
// Found live: a test launch under a scratch HOME autostarted the host stack,
// its promoted arbiter kept events in that scratch dir, and the systemd
// dashboard ADOPTED it — the sidebar showed that dir's sessions, no drills and
// no tests. The adopt check now compares the listener's event dir with ours.

/** A fake arbiter: listens at `<base>/instances/<name>/arbiter.sock`, answers
 *  hello with its own pid + `eventDir`, and (promote) swaps `<base>/current`
 *  onto its instance dir, as the real arbiter's promotion does. */
const FAKE_INSTANCE_SCRIPT = `
const net = require("node:net"), fs = require("node:fs"), path = require("node:path");
const base = process.env.FAKE_BASE, name = process.env.FAKE_NAME;
const dir = path.join(base, "instances", name);
fs.mkdirSync(dir, { recursive: true });
const sock = path.join(dir, "arbiter.sock");
net.createServer((c) => c.on("data", (b) => {
  if (b.toString().includes('"hello"')) c.write(JSON.stringify({ id: 1, ok: true, result: {
    pid: process.pid, startedAt: "2026-09-28T00:00:00.000Z", instanceId: name, gitRev: "0000000",
    gitDirty: false, sockPath: sock, eventDir: process.env.FAKE_EVENT_DIR, symbolDb: "x" } }) + "\\n");
})).listen(sock, () => {
  const tmp = path.join(base, "current.tmp-" + name);
  fs.symlinkSync(path.join("instances", name), tmp);
  fs.renameSync(tmp, path.join(base, "current"));
  process.stdout.write("promoted\\n");
});
setInterval(() => {}, 1000);
`;

async function spawnForeign(base: string, eventDir: string): Promise<import("node:child_process").ChildProcess> {
  const { spawn } = await import("node:child_process");
  const child = spawn(process.execPath, nodeArgs(FAKE_INSTANCE_SCRIPT), {
    env: { ...process.env, FAKE_BASE: base, FAKE_NAME: "foreign", FAKE_EVENT_DIR: eventDir },
    stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise<void>((r) => child.stdout!.once("data", () => r()));
  return child;
}

function instanceDef(base: string, eventDir: string): ServiceDefinition {
  const sock = join(base, "current", "arbiter.sock");
  return {
    label: "Arbiter", command: process.execPath, args: nodeArgs(FAKE_INSTANCE_SCRIPT), cwd: base,
    env: { FAKE_BASE: base, FAKE_NAME: "ours", FAKE_EVENT_DIR: eventDir },
    ready: { kind: "socket", path: sock }, endpoint: sock,
  };
}

test("instance mode: an arbiter whose event dir is not ours is DISPLACED — ours starts and takes over 'current'", async () => {
  const base = tmpdir();
  const ours = join(base, "home", ".local", "state", "mandu", "events");
  const foreign = await spawnForeign(base, join(base, "scratch", "home", ".local", "state", "mandu", "events"));
  const logs: string[] = [];
  const sock = join(base, "current", "arbiter.sock");
  const sup = mkSup({ arbiter: instanceDef(base, ours) }, {
    arbiterSock: sock, arbiterInstanceBase: base, eventDir: ours, log: (l: string) => logs.push(l),
  });
  try {
    await sup.start("arbiter");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running");
    assert.equal(st.adopted, false, "the foreign arbiter is not adopted");
    assert.ok(st.pid !== null && st.pid !== foreign.pid, "a child of ours was spawned");
    assert.equal(st.identity?.pid, st.pid, "readiness waited for OUR instance, not the foreign one still answering");
    assert.equal(st.identity?.eventDir, ours);
    assert.ok(logs.some((l) => /NOT adopting .*its event dir is .*scratch/.test(l)), logs.join("\n"));
    assert.equal(foreign.exitCode, null, "the foreign arbiter is left running for whoever joined it");
  } finally {
    await sup.shutdownAll();
    foreign.kill("SIGKILL");
  }
});

test("instance mode: an arbiter with OUR event dir is adopted as before", async () => {
  const base = tmpdir();
  const ours = join(base, "home", ".local", "state", "mandu", "events");
  const peer = await spawnForeign(base, ours);
  const sock = join(base, "current", "arbiter.sock");
  const sup = mkSup({ arbiter: instanceDef(base, ours) }, { arbiterSock: sock, arbiterInstanceBase: base, eventDir: ours });
  try {
    await sup.start("arbiter");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.adopted, true);
    assert.equal(st.identity?.pid, peer.pid);
  } finally {
    await sup.shutdownAll();
    peer.kill("SIGKILL");
  }
});

test("pinned socket: a foreign arbiter cannot be displaced — adopted, with a FOREIGN warning", async () => {
  const base = tmpdir();
  const ours = join(base, "home", ".local", "state", "mandu", "events");
  const foreign = await spawnForeign(base, join(base, "elsewhere"));
  const logs: string[] = [];
  const sock = join(base, "current", "arbiter.sock");
  const sup = mkSup({ arbiter: instanceDef(base, ours) }, { arbiterSock: sock, eventDir: ours, log: (l: string) => logs.push(l) });
  try {
    await sup.start("arbiter");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.adopted, true);
    assert.ok(logs.some((l) => /FOREIGN — its event dir is .*elsewhere/.test(l)), logs.join("\n"));
  } finally {
    await sup.shutdownAll();
    foreign.kill("SIGKILL");
  }
});
