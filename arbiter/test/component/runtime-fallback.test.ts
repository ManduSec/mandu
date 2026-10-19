/**
 * runtime-fallback (e2e) — the REAL arbiter daemon started the way a macOS
 * launch starts it: no MANDU_RUNTIME_DIR, no XDG_RUNTIME_DIR, and a TMPDIR too
 * long for `mandu/instances/<id>/arbiter.sock` to fit sun_path (the per-user
 * /var/folders/…/T/ shape). It must bind under the private /tmp/mandu-<uid>
 * fallback, created 0700, and promote `current` there; and it must REFUSE to
 * start — binding nothing, creating nothing — when that dir already exists but
 * is not a private dir of this uid (runtime-instances.md §3b).
 *
 * The fallback root is the test hook MANDU_RUNTIME_FALLBACK_ROOT (a short
 * scratch dir), so the host's real /tmp/mandu-<uid> is never touched.
 *
 * The same daemon started the way a Linux session WITHOUT XDG_RUNTIME_DIR
 * starts it (a short TMPDIR that is world-writable and sticky, standing in
 * for /tmp, so the base is <TMPDIR>/mandu): that base must be ours — created
 * 0700 when absent, a self-made 0755 dir accepted — and a group-writable one
 * is refused before anything is read or created in it.
 *
 * And under a 002 umask with the base in a private runtime dir (the
 * dashboard service unit's MANDU_RUNTIME_DIR=%t/mandu): the base is created
 * 0700, and an earlier version's 0775 one is tightened to 0700.
 *
 * Mandu-new test (no reference origin). Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../ipc/client.js";
import { readManifest } from "../../ipc/instance.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the path logic is axis-independent

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const UID = process.getuid?.() ?? 0;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface Scratch {
  /** The fallback root (short, canonical). */
  root: string;
  /** Where the fallback base lands: <root>/mandu-<uid>. */
  base: string;
  /** A TMPDIR too long for an instance socket on any platform. */
  longTmp: string;
  cleanup: () => void;
}

function scratch(): Scratch {
  // A SHORT root: /tmp when present (demo.test.ts does the same), realpath'd
  // so the macOS /tmp → /private/tmp alias cannot make the test poll one
  // spelling while the daemon uses the other.
  const root = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-fb-")));
  const longTmp = join(root, "t".repeat(70));
  mkdirSync(longTmp); // tsx keeps its cache under os.tmpdir(): it must exist
  return {
    root, base: join(root, `mandu-${UID}`), longTmp,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function spawnArbiter(s: Scratch, extra: Record<string, string> = {}): { child: ChildProcess; stderr: () => string } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    TMPDIR: s.longTmp,
    MANDU_RUNTIME_FALLBACK_ROOT: s.root,
    // Its stores in a scratch Mandu home (the per-path overrides are
    // retired, on-disk-layout.md §5): never the host's.
    MANDU_HOME: join(s.root, "mandu-home"),
    MANDU_ARBITER_SOCK: "", // instance mode
    MANDU_LIFELINE: "",
  };
  delete env["MANDU_RUNTIME_DIR"];
  delete env["XDG_RUNTIME_DIR"];
  Object.assign(env, extra);
  let err = "";
  // `node --import tsx` (instance-mode.test.ts): the signalled process IS the daemon.
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN], {
    cwd: ARBITER_DIR, env, stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr!.on("data", (d) => { err += String(d); });
  return { child, stderr: () => err };
}

async function waitFor(pred: () => boolean, what: string, ms = 90_000): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (pred()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => { child.kill("SIGKILL"); }, 60_000);
    kill.unref();
    child.once("exit", () => { clearTimeout(kill); resolve(); });
    child.kill("SIGTERM");
  });
}

async function exitCode(child: ChildProcess, ms = 90_000): Promise<number | null> {
  if (child.exitCode !== null) return child.exitCode;
  return await new Promise<number | null>((resolve) => {
    const t = setTimeout(() => { child.kill("SIGKILL"); resolve(null); }, ms);
    child.once("exit", (c) => { clearTimeout(t); resolve(c); });
  });
}

test("a long TMPDIR and no runtime dir: the arbiter binds and promotes under the private fallback, created 0700", { timeout: 120_000 }, async () => {
  const s = scratch();
  const { child, stderr } = spawnArbiter(s, { MANDU_PROMOTE: "1" });
  try {
    const current = join(s.base, "current", "arbiter.sock");
    await waitFor(() => existsSync(current) || child.exitCode !== null, "the promoted socket under the fallback");
    assert.ok(existsSync(current), `promoted under ${s.base}; stderr:\n${stderr()}`);
    const st = lstatSync(s.base);
    assert.ok(st.isDirectory() && !st.isSymbolicLink());
    assert.equal(statSync(s.base).mode & 0o777, 0o700, "created private");
    assert.equal(st.uid, UID);

    const ids = readdirSync(join(s.base, "instances"));
    assert.equal(ids.length, 1);
    const m = readManifest(join(s.base, "instances", ids[0]!));
    assert.ok(m && m.sockPath.startsWith(`${s.base}/instances/`), JSON.stringify(m));
    assert.ok(Buffer.byteLength(m!.sockPath) < (process.platform === "darwin" ? 104 : 108));
    assert.equal(existsSync(join(s.longTmp, "mandu")), false, "nothing under the long TMPDIR");

    const client = new ArbiterClient(current);
    await client.connect();
    const hello = await client.hello();
    client.close();
    assert.equal(hello.pid, m!.pid, "the promoted rendezvous answers as that instance");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("a pre-existing SHARED (0755) fallback dir: the arbiter refuses to start and creates nothing in it", { timeout: 120_000 }, async () => {
  const s = scratch();
  mkdirSync(s.base);
  chmodSync(s.base, 0o755);
  const { child, stderr } = spawnArbiter(s, { MANDU_PROMOTE: "1" });
  try {
    assert.equal(await exitCode(child), 1, `must refuse; stderr:\n${stderr()}`);
    assert.match(stderr(), /\[arbiter\] fatal: the Mandu runtime dir .*mandu-\d+ is shared \(mode 0755/);
    assert.match(stderr(), /MANDU_RUNTIME_DIR/, "names the way out");
    assert.deepEqual(readdirSync(s.base), [], "no instance dir, no current link");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("a fallback that is a SYMLINK (to a private dir) is refused too, and its target stays untouched", { timeout: 120_000 }, async () => {
  const s = scratch();
  const target = join(s.root, "elsewhere");
  mkdirSync(target, { mode: 0o700 });
  symlinkSync(target, s.base);
  const { child, stderr } = spawnArbiter(s);
  try {
    assert.equal(await exitCode(child), 1, `must refuse; stderr:\n${stderr()}`);
    assert.match(stderr(), /\[arbiter\] fatal: the Mandu runtime dir .* is a symlink/);
    assert.deepEqual(readdirSync(target), []);
  } finally {
    await stop(child);
    s.cleanup();
  }
});

/** A short scratch dir standing in for /tmp: world-writable with the sticky bit. */
function stickyTmp(s: Scratch): string {
  const sticky = join(s.root, "st");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777);
  return sticky;
}

test("Linux without XDG_RUNTIME_DIR, TMPDIR a shared sticky dir: the per-user base <TMPDIR>/mandu-<uid> is created 0700 and served; a self-made 0755 one is served too", { timeout: 180_000 }, async () => {
  const s = scratch();
  const sticky = stickyTmp(s);
  const base = join(sticky, `mandu-${UID}`); // per-user since 2026-10-09 (runtime-instances.md §3b)
  try {
    for (const [round, before] of [["absent", null], ["our 0755 dir", 0o755]] as const) {
      if (before !== null) chmodSync(base, before);
      const { child, stderr } = spawnArbiter(s, { TMPDIR: sticky, MANDU_PROMOTE: "1" });
      try {
        const current = join(base, "current", "arbiter.sock");
        await waitFor(() => existsSync(current) || child.exitCode !== null, `the promoted socket (${round})`);
        assert.ok(existsSync(current), `${round}: promoted under ${base}; stderr:\n${stderr()}`);
        const st = lstatSync(base);
        assert.ok(st.isDirectory() && !st.isSymbolicLink());
        assert.equal(st.uid, UID);
        assert.equal(statSync(base).mode & 0o777, before ?? 0o700, `${round}: mode kept (never chmod-repaired, never widened)`);
      } finally {
        await stop(child);
      }
    }
  } finally {
    s.cleanup();
  }
});

test("a base in a shared sticky dir that other accounts can WRITE (0775): the arbiter refuses to start and creates nothing in it", { timeout: 120_000 }, async () => {
  const s = scratch();
  const sticky = stickyTmp(s);
  const base = join(sticky, "mandu");
  mkdirSync(base);
  chmodSync(base, 0o775);
  // The launcher hands its base over as MANDU_RUNTIME_DIR: the rule keys on the
  // parent's mode, so an explicit base there is checked the same way.
  const { child, stderr } = spawnArbiter(s, { TMPDIR: sticky, MANDU_RUNTIME_DIR: base, MANDU_PROMOTE: "1" });
  try {
    assert.equal(await exitCode(child), 1, `must refuse; stderr:\n${stderr()}`);
    assert.match(stderr(), /\[arbiter\] fatal: the Mandu runtime dir .*mandu is writable by other accounts \(mode 0775/);
    assert.match(stderr(), /rm -rf .*MANDU_RUNTIME_DIR/, "names the way out");
    assert.deepEqual(readdirSync(base), [], "no instance dir, no current link");
    assert.equal(statSync(base).mode & 0o777, 0o775, "never chmod-repaired");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("umask 002, the base under a private runtime dir (the service unit's MANDU_RUNTIME_DIR=%t/mandu): created 0700, and an earlier 0775 one tightened to 0700", { timeout: 180_000 }, async () => {
  const s = scratch();
  const xdg = join(s.root, "run"); // stands in for logind's 0700 /run/user/<uid>
  mkdirSync(xdg, { mode: 0o700 });
  const base = join(xdg, "mandu");
  try {
    for (const [round, before] of [["absent", null], ["an earlier version's 0775 dir", 0o775]] as const) {
      if (before !== null) chmodSync(base, before);
      const old = process.umask(0o002); // the daemon inherits it
      let spawned: ReturnType<typeof spawnArbiter>;
      try {
        spawned = spawnArbiter(s, { XDG_RUNTIME_DIR: xdg, MANDU_RUNTIME_DIR: base, MANDU_PROMOTE: "1" });
      } finally {
        process.umask(old);
      }
      const { child, stderr } = spawned;
      try {
        const current = join(base, "current", "arbiter.sock");
        await waitFor(() => existsSync(current) || child.exitCode !== null, `the promoted socket (${round})`);
        assert.ok(existsSync(current), `${round}: promoted under ${base}; stderr:\n${stderr()}`);
        assert.equal(statSync(base).mode & 0o777, 0o700, `${round}: the runtime base is 0700 (was the umask's 0775)`);
      } finally {
        await stop(child);
      }
    }
  } finally {
    s.cleanup();
  }
});
