/**
 * event-store-durability.test — the event store's ON-DISK default, live
 * (docs/design/architecture/runtime-instances.md §12): spawns the REAL daemon entrypoint
 * with a fake per-boot runtime dir and a fake state dir and asserts that
 *   - a defaulted event dir lands in the one home, ~/.mandu/events (the
 *     manifest says so), never under $XDG_RUNTIME_DIR nor $XDG_STATE_HOME;
 *   - nothing is read from anywhere else: session files in the older
 *     layouts' dirs (the runtime tmpfs, $XDG_STATE_HOME/mandu/events) stay
 *     where they are and unseen (a clean start, on-disk-layout.md §6);
 *   - $MANDU_EVENT_RETENTION_DAYS prunes what is idle past the window at
 *     boot and `0` disables it;
 *   - an explicit --event-dir is used verbatim, and a set MANDU_EVENT_DIR
 *     (retired) moves nothing.
 *
 * The behavior under test is the fix for a live incident: three host reboots
 * on 2026-09-04 erased every session trace and the dashboard's CI-run
 * history, because the default sat on the reboot-wiped runtime tmpfs.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const DAY = 86_400_000;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface Host {
  root: string;
  runtimeDir: string;  // the fake $XDG_RUNTIME_DIR (a "tmpfs")
  stateHome: string;   // the fake $XDG_STATE_HOME (an older layout's root, never read)
  home: string;        // the fake $HOME (holds the one home, ~/.mandu)
  base: string;        // $MANDU_RUNTIME_DIR — the instance registry
  cleanup: () => void;
}

function fakeHost(): Host {
  // A short prefix: the instance socket must fit the 103-byte macOS / 107-byte Linux sun_path under a
  // suite's TMPDIR, longer than /tmp (test-organization.md §8.5).
  // With no prefix, the Darwin runner's 22-byte TMPDIR plus the random
  // directory and /run/mandu stays within the 40-byte instance-base budget.
  const root = mkdtempSync(`${tmpdir()}/`);
  const h: Host = {
    root,
    runtimeDir: join(root, "run"),
    stateHome: join(root, "state"),
    home: join(root, "home"),
    base: join(root, "run", "mandu"),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
  mkdirSync(h.runtimeDir, { recursive: true });
  mkdirSync(h.home, { recursive: true });
  return h;
}

function seed(dir: string, id: string, ageMs: number): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, `${id}.ndjson`);
  writeFileSync(p, JSON.stringify({ sessionId: id, id: `${id}-1`, seq: 1, ts: new Date().toISOString() }) + "\n");
  const t = new Date(Date.now() - ageMs);
  utimesSync(p, t, t);
  return p;
}

interface Daemon { child: ChildProcess; stderr: () => string }

/** Spawn server-main promoted, with the event dir DEFAULTED unless `eventDir`
 *  is given (as --event-dir). MANDU_HOME is deleted from the inherited env
 *  (the npm script's /dev/null guard) so the default is the fake HOME's
 *  ~/.mandu. `node --import tsx`, NOT the
 *  tsx CLI: the CLI relays a SIGTERM and SIGKILLs its child unless the child
 *  reports it back within 30 ms (tsx 4 `relaySignals`), and the second boot
 *  below reads what the first one's graceful close left
 *  (runtime-instances.md §10). Here the signalled process IS the daemon. */
function spawnDaemon(h: Host, extra: Record<string, string> = {}, eventDir?: string): Daemon {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.MANDU_HOME;
  delete env.MANDU_EVENT_RETENTION_DAYS;
  Object.assign(env, {
    HOME: h.home,
    XDG_RUNTIME_DIR: h.runtimeDir,
    XDG_STATE_HOME: h.stateHome,
    MANDU_RUNTIME_DIR: h.base,
    MANDU_ARBITER_SOCK: "",
    MANDU_PROMOTE: "1",
    ...extra,
  });
  const args = eventDir ? ["--event-dir", eventDir] : [];
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN, ...args], { cwd: ARBITER_DIR, env, stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (c: string) => { err += c; });
  return { child, stderr: () => err };
}

/** Deadlines, not delays: every wait returns as soon as its condition holds
 *  (about a second when idle). tsx's cold start of the daemon is the long
 *  pole, and in the per-push CI guest (16 suites plus the kernel lane side by
 *  side, continuous-integration.md §5) it passed 20 s with nothing printed yet, so
 *  the deadline is 90 s, as in lifeline.test.ts and instance-mode.test.ts. */
const START_DEADLINE_MS = 90_000;

async function waitFor(pred: () => boolean, what: string, ms = START_DEADLINE_MS): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (pred()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** SIGTERM, then SIGKILL only after a 60 s grace (a deadline: it returns on
 *  exit); a second boot reads what the graceful close left, and under CI load
 *  that close passed the old 5 s grace (instance-mode.test.ts, 2026-09-29). */
async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => { child.kill("SIGKILL"); }, 60_000);
    kill.unref();
    child.once("exit", () => { clearTimeout(kill); resolve(); });
    child.kill("SIGTERM");
  });
}

/** The daemon's human-plane client (arbiter-human-plane.md): `sessions` is a
 *  human-plane op, refused on the data socket. Discovered the way a
 *  supervisor does — `hello` on the data socket names the human socket. */
async function humanClientOf(sock: string): Promise<ArbiterClient> {
  const data = new ArbiterClient(sock);
  try {
    const humanSock = (await data.hello()).humanSock;
    assert.ok(humanSock, "the daemon serves a human-plane socket");
    return new ArbiterClient(humanSock);
  } finally {
    data.close();
  }
}

function manifestOf(h: Host): { eventDir: string; pid: number } {
  return JSON.parse(readFileSync(join(h.base, "current", "manifest.json"), "utf8")) as { eventDir: string; pid: number };
}

test("defaulted event dir lands in the one home; the older layouts' dirs are never read; stale sessions pruned at boot", async () => {
  const h = fakeHost();
  const expectDir = join(h.home, ".mandu", "events");
  const oldRuntime = join(h.runtimeDir, "events");
  const oldState = join(h.stateHome, "mandu", "events");
  const recent = seed(expectDir, "recent-session", 2 * DAY);
  seed(expectDir, "stale-session", 10 * DAY);
  const inRuntime = seed(oldRuntime, "tmpfs-session", 1 * DAY);
  const inState = seed(oldState, "old-layout-session", 1 * DAY);
  const d = spawnDaemon(h, { MANDU_EVENT_RETENTION_DAYS: "7" });
  try {
    const sock = join(h.base, "current", "arbiter.sock");
    await waitFor(() => existsSync(sock), `promoted socket (stderr: ${d.stderr()})`);
    assert.equal(manifestOf(h).eventDir, expectDir, "manifest names the on-disk default");
    assert.equal(manifestOf(h).pid, d.child.pid, "the spawned process is the daemon itself (no tsx CLI shim)");
    assert.ok(!manifestOf(h).eventDir.startsWith(h.runtimeDir), "never under the runtime tmpfs");

    // The stale session was pruned by the boot sweep; nothing came over from
    // the older layouts' dirs, and they are left as they were.
    await waitFor(() => /retention: removed/.test(d.stderr()), "boot sweep");
    assert.deepEqual(readdirSync(expectDir).sort(), ["recent-session.ndjson"]);
    assert.ok(existsSync(recent) && existsSync(inRuntime) && existsSync(inState));

    const client = await humanClientOf(sock);
    try {
      assert.deepEqual((await client.sessions()).map((s) => s.sessionId), ["recent-session"]);
      // New events land on disk, in the one home.
      await client.emit({ sessionId: "born-on-disk", id: "e1" });
      assert.ok(existsSync(join(expectDir, "born-on-disk.ndjson")));
      assert.ok(!existsSync(join(oldRuntime, "born-on-disk.ndjson")), "nothing new is written to the tmpfs");
    } finally {
      await client.close();
    }
    const err = d.stderr();
    assert.doesNotMatch(err, /carried \d+ session file/);
    assert.match(err, new RegExp(`event store: ${expectDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\(retention: 7d\\)`));
    assert.match(err, /retention: removed 1 session\(s\) idle > 7d: stale-session/);
  } finally {
    await stop(d.child);
    h.cleanup();
  }
});

test("MANDU_EVENT_RETENTION_DAYS=0 disables pruning", async () => {
  const h = fakeHost();
  const expectDir = join(h.home, ".mandu", "events");
  seed(expectDir, "ancient", 400 * DAY);
  const d = spawnDaemon(h, { MANDU_EVENT_RETENTION_DAYS: "0" });
  try {
    const sock = join(h.base, "current", "arbiter.sock");
    await waitFor(() => existsSync(sock), `promoted socket (stderr: ${d.stderr()})`);
    const client = await humanClientOf(sock);
    try {
      assert.deepEqual((await client.sessions()).map((s) => s.sessionId), ["ancient"], "kept: retention off");
    } finally {
      await client.close();
    }
    assert.match(d.stderr(), /\(retention: off\)/);
    assert.doesNotMatch(d.stderr(), /retention: removed/);
  } finally {
    await stop(d.child);
    h.cleanup();
  }
});

test("explicit --event-dir is used verbatim; a set MANDU_EVENT_DIR moves nothing", async () => {
  const h = fakeHost();
  seed(join(h.home, ".mandu", "events"), "default-only", 1 * DAY);
  const pinned = join(h.root, "pinned-events");
  const retired = join(h.root, "retired-env-events");
  const d = spawnDaemon(h, { MANDU_EVENT_DIR: retired }, pinned);
  try {
    const sock = join(h.base, "current", "arbiter.sock");
    await waitFor(() => existsSync(sock), `promoted socket (stderr: ${d.stderr()})`);
    assert.equal(manifestOf(h).eventDir, pinned);
    const client = await humanClientOf(sock);
    try {
      assert.deepEqual(await client.sessions(), [], "the default dir's sessions are not the pinned dir's");
      await client.emit({ sessionId: "s", id: "e1" });
      assert.ok(existsSync(join(pinned, "s.ndjson")));
    } finally {
      await client.close();
    }
    assert.deepEqual(readdirSync(join(h.home, ".mandu", "events")), ["default-only.ndjson"], "the default dir is untouched when pinned");
    assert.ok(!existsSync(retired), "the retired MANDU_EVENT_DIR is not read");
    assert.match(d.stderr(), /\(retention: 90d\)/, "the default window applies without the env knob");
  } finally {
    await stop(d.child);
    h.cleanup();
  }
});
