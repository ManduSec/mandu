/**
 * instance-mode.test — server-main's per-deployment runtime identity, live
 * (docs/design/architecture/runtime-instances.md): spawns the REAL daemon entrypoint and
 * asserts the instance-dir layout, the MANDU_PROMOTE gate on the `current`
 * rendezvous, the hello handshake identity, dead-instance sweeping, and
 * graceful-shutdown tidy-up.
 *
 * The behavior under test is the fix for three live incidents: hand-started
 * arbiters silently stealing the shared socket (2026-07-05), weeks-stale
 * daemons masquerading as current, and mixed-generation stacks.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../ipc/client.js";
import {
  CURRENT_LINK,
  INSTANCES_DIR,
  readManifest,
  createInstanceDir,
  writeManifest,
} from "../../ipc/instance.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface Stack {
  base: string;
  home: string;
  eventDir: string;
  symbolDb: string;
  cleanup: () => void;
}

function tmpStack(): Stack {
  // A short prefix: <root>/mandu/instances/<id>/arbiter.sock must fit the 103-byte macOS / 107-byte Linux
  // sun_path under a suite's TMPDIR, longer than /tmp (test-organization.md §8.5).
  const root = mkdtempSync(join(tmpdir(), "mdu-"));
  return {
    base: join(root, "mandu"),
    home: join(root, "home"),
    eventDir: join(root, "events"),
    symbolDb: join(root, "symbols.db"),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

/** Spawn server-main in instance mode against an isolated runtime base, its
 *  stores named by --symbol-db / --event-dir (a temp MANDU_HOME besides, so
 *  nothing defaults into a real home).
 *  `node --import tsx`, NOT the tsx CLI: the CLI relays a SIGTERM to its
 *  child and SIGKILLs it unless the child reports the signal back over tsx's
 *  IPC within 30 ms (tsx 4 `relaySignals`), which CI load exceeds, so the
 *  daemon died before its graceful shutdown tidied the registry (the "pinned
 *  socket" flake, CI run gl-7359). Here the signalled process IS the daemon. */
function spawnArbiter(s: Stack, extraEnv: Record<string, string> = {}, symbolDb = s.symbolDb): ChildProcess {
  return spawn(process.execPath, ["--import", "tsx", SERVER_MAIN, "--symbol-db", symbolDb, "--event-dir", s.eventDir], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env,
      MANDU_RUNTIME_DIR: s.base,
      MANDU_HOME: s.home,
      MANDU_ARBITER_SOCK: "", // ensure DEFAULT (instance) mode
      ...extraEnv,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
}

/** Wait until `pred` holds. A deadline, not a delay: it returns as soon as the
 *  condition does (about a second when idle). tsx's cold start of the daemon is
 *  the long pole, and under CI load (16 suites side by side,
 *  continuous-integration.md §5) it passed 15 s, so the deadline is 90 s. */
async function waitFor(pred: () => boolean | Promise<boolean>, what: string, ms = 90_000): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (await pred()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}`);
}

function instanceIds(base: string): string[] {
  try {
    return readdirSync(join(base, INSTANCES_DIR));
  } catch {
    return [];
  }
}

/** Signal, then SIGKILL only after a 60 s grace (a deadline: it returns on
 *  exit). A graceful close is what tidies the registry, and under CI load it
 *  passed the old 5 s grace, so the SIGKILL left the entry for the test to
 *  wait on in vain (as lifeline.test.ts's EXIT_DEADLINE_MS). */
async function stop(child: ChildProcess, sig: NodeJS.Signals = "SIGTERM"): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => { child.kill("SIGKILL"); }, 60_000);
    kill.unref();
    child.once("exit", () => { clearTimeout(kill); resolve(); });
    child.kill(sig);
  });
}

test("un-promoted instance: socket + manifest under instances/, current NOT touched", async () => {
  const s = tmpStack();
  const child = spawnArbiter(s);
  try {
    await waitFor(() => instanceIds(s.base).length === 1, "the instance dir");
    const id = instanceIds(s.base)[0]!;
    const dir = join(s.base, INSTANCES_DIR, id);
    await waitFor(() => existsSync(join(dir, "arbiter.sock")), "the bound socket");
    await waitFor(() => readManifest(dir) !== null, "the manifest");

    const m = readManifest(dir)!;
    assert.equal(m.role, "arbiter");
    assert.equal(m.instanceId, id);
    assert.match(id, /^\d{8}-\d{4}-[a-zA-Z0-9._-]+-p\d+$/, "id = <utc>-<rev>-p<pid>");
    // The manifest/hello/dir-name agree with each other, and (no tsx CLI
    // shim in between, see spawnArbiter) with the process the test spawned.
    assert.ok(id.endsWith(`-p${m.pid}`), "the pid is readable from the dir name");
    assert.equal(m.pid, child.pid, "the spawned process is the daemon itself");
    assert.equal(m.eventDir, s.eventDir);
    assert.equal(m.symbolDb, s.symbolDb);

    // THE promotion gate: a hand-started arbiter must NOT become the rendezvous.
    assert.ok(!existsSync(join(s.base, CURRENT_LINK)), "current is untouched without MANDU_PROMOTE");

    // The socket answers hello with the same identity.
    const client = new ArbiterClient(join(dir, "arbiter.sock"));
    await client.connect();
    const hello = await client.hello();
    client.close();
    assert.equal(hello.pid, m.pid, "hello and manifest agree on the daemon pid");
    assert.equal(hello.instanceId, id);
    assert.equal(hello.gitRev, m.gitRev, "hello and manifest agree on the code rev");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("MANDU_PROMOTE=1: current resolves to the instance; a newer promoted instance takes over", async () => {
  const s = tmpStack();
  const currentSock = join(s.base, CURRENT_LINK, "arbiter.sock");
  const a = spawnArbiter(s, { MANDU_PROMOTE: "1" });
  let b: ChildProcess | null = null;
  try {
    await waitFor(() => existsSync(currentSock), "promotion of instance A");
    const helloA = await helloVia(currentSock);
    assert.ok(helloA.instanceId, "current answers with a promoted instance id");
    assert.ok(instanceIds(s.base).includes(helloA.instanceId!), "instance A's dir exists");

    // A SECOND promoted instance atomically takes over the rendezvous...
    // (it gets its OWN symbol DB: side-by-side live instances are only legal
    // with separate DBs — the symbol table is single-writer, db-owner.ts; the
    // same-DB overlap is the REFUSAL test below).
    b = spawnArbiter(s, { MANDU_PROMOTE: "1" }, `${s.symbolDb}.b`);
    await waitFor(async () =>
      existsSync(currentSock) && (await helloVia(currentSock)).instanceId !== helloA.instanceId,
      "promotion swap to instance B");
    const helloB = await helloVia(currentSock);
    assert.notEqual(helloB.pid, helloA.pid, "current now answers with a different daemon");
    // ...while instance A keeps serving ITS OWN socket (no theft, both live).
    const dirA = join(s.base, INSTANCES_DIR, helloA.instanceId!);
    const helloAgain = await helloVia(join(dirA, "arbiter.sock"));
    assert.equal(helloAgain.pid, helloA.pid, "the demoted instance still serves its own socket");
    assert.equal(instanceIds(s.base).length, 2, "both instance dirs coexist");
  } finally {
    await stop(a);
    if (b) await stop(b);
    s.cleanup();
  }
});

test("same symbol DB: a live second arbiter REFUSES (single-writer); a sequential successor starts", async () => {
  const s = tmpStack();
  const currentSock = join(s.base, CURRENT_LINK, "arbiter.sock");
  const a = spawnArbiter(s, { MANDU_PROMOTE: "1" });
  let c: ChildProcess | null = null;
  try {
    await waitFor(() => existsSync(currentSock), "promotion of instance A");
    const helloA = await helloVia(currentSock);

    // Overlapping writer on the SAME symbol DB: loud refusal, nonzero exit —
    // never silent write interleaving (each arbiter full-rewrites the table
    // from its in-memory map, so overlap means lost updates).
    const b = spawnArbiter(s, { MANDU_PROMOTE: "1" });
    let stderrB = "";
    b.stderr!.on("data", (d: Buffer) => { stderrB += d.toString(); });
    await new Promise<void>((resolve) => b.once("exit", () => resolve()));
    assert.equal(b.exitCode, 1, "the second writer exits nonzero");
    assert.match(stderrB, /single-writer/, "the refusal names the invariant");

    // The refused start left NOTHING behind: A's dir only, current still A.
    assert.equal(instanceIds(s.base).length, 1, "no half-created instance dir from the refusal");
    assert.equal((await helloVia(currentSock)).pid, helloA.pid, "A is undisturbed");

    // Sequential handover works: A stops gracefully (releases ownership),
    // then a same-DB successor claims it and takes the rendezvous.
    await stop(a, "SIGTERM");
    c = spawnArbiter(s, { MANDU_PROMOTE: "1" });
    await waitFor(async () => {
      if (!existsSync(currentSock)) return false;
      try { return (await helloVia(currentSock)).pid !== helloA.pid; } catch { return false; }
    }, "the sequential successor to take over");
  } finally {
    await stop(a);
    if (c) await stop(c);
    s.cleanup();
  }
});

test("pinned socket: STILL registers a registry-only instance (mode/ownerPid), never promotes", async () => {
  const s = tmpStack();
  const pinnedSock = join(s.base, "pinned.sock");
  // MANDU_PROMOTE=1 deliberately: promotion must be REFUSED for a pinned
  // path (current/<sock> would not resolve inside a registry-only dir).
  const child = spawnArbiter(s, {
    MANDU_ARBITER_SOCK: pinnedSock,
    MANDU_PROMOTE: "1",
    MANDU_OWNER_PID: String(process.pid),
  });
  try {
    await waitFor(() => existsSync(pinnedSock), "the pinned socket");
    // The dir exists before its manifest is written (readManifest: null for a
    // dir mid-creation), a window CI load made wide enough to land in.
    await waitFor(() => instanceIds(s.base).length === 1 && readManifest(join(s.base, INSTANCES_DIR, instanceIds(s.base)[0]!)) !== null,
      "the registry-only instance dir and its manifest");
    const id = instanceIds(s.base)[0]!;
    const m = readManifest(join(s.base, INSTANCES_DIR, id))!;
    assert.equal(m.mode, "pinned");
    assert.equal(m.sockPath, pinnedSock, "manifest names the CALLER's socket path");
    assert.equal(m.ownerPid, process.pid, "MANDU_OWNER_PID is recorded");
    assert.ok(!existsSync(join(s.base, CURRENT_LINK)), "a pinned arbiter never takes the rendezvous");

    // Graceful shutdown tidies the registry entry like any instance.
    await stop(child, "SIGTERM");
    await waitFor(() => instanceIds(s.base).length === 0, "registry entry tidied on SIGTERM");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("graceful shutdown removes the instance dir; startup sweeps dead instances", async () => {
  const s = tmpStack();
  // Seed a fake DEAD instance (manifest pid can't exist) — the next start reaps it.
  const dead = createInstanceDir(s.base, "20260101-0000-deadbeef-p9");
  writeManifest(dead, {
    instanceId: "20260101-0000-deadbeef-p9", role: "arbiter", pid: 2 ** 30,
    startedAt: new Date().toISOString(), gitRev: "deadbeef", gitDirty: false,
    sockPath: dead.sockPath, eventDir: s.eventDir, symbolDb: s.symbolDb,
  });

  const child = spawnArbiter(s);
  try {
    await waitFor(
      () => instanceIds(s.base).length === 1 && !existsSync(dead.dir),
      "the dead instance to be swept and the live one to appear",
    );
    const id = instanceIds(s.base)[0]!;
    await waitFor(() => existsSync(join(s.base, INSTANCES_DIR, id, "arbiter.sock")), "the live socket");

    await stop(child, "SIGTERM");
    await waitFor(() => instanceIds(s.base).length === 0, "the instance dir to be tidied on SIGTERM");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("a SIGTERM before the socket is up still exits gracefully and tidies the instance dir", async () => {
  // The window between creating the instance dir and binding the socket (the
  // policy load, the SQLite open, the server's construction) once had no
  // handler: SIGTERM took the default action, the daemon died by signal and
  // left its dir for the next sweep (the CI flake of the test above). Signal
  // the moment the dir appears, polled tightly so the socket is not up yet.
  const s = tmpStack();
  const child = spawnArbiter(s);
  try {
    const t0 = Date.now();
    while (instanceIds(s.base).length === 0 && Date.now() - t0 < 90_000) {
      await new Promise((r) => setTimeout(r, 2));
    }
    const id = instanceIds(s.base)[0];
    assert.ok(id, "the instance dir appeared");
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
      child.once("exit", (code, signal) => resolve({ code, signal })),
    );
    child.kill("SIGTERM");
    const { code, signal } = await exited;
    assert.equal(signal, null, "the daemon handled SIGTERM instead of dying by it");
    assert.equal(code, 0, "graceful exit");
    assert.deepEqual(instanceIds(s.base), [], "the instance dir is tidied");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

async function helloVia(sock: string): Promise<{ pid: number; instanceId: string | null }> {
  const c = new ArbiterClient(sock);
  await c.connect();
  try {
    return await c.hello();
  } finally {
    c.close();
  }
}
