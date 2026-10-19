/**
 * runtime-dir-mode.test — E2E: the mode of the runtime base a Linux launch
 * makes and keeps (runtime-instances.md §3b, "Any other base is made 0700"),
 * through the real launcher main() and the real autostarted stack:
 *
 *   1. under a 002 umask, with XDG_RUNTIME_DIR set (a mkdtemp dir standing in
 *      for logind's 0700 /run/user/<uid>) and no `mandu` in it yet → the
 *      stack autostarts under `<xdg>/mandu`, created 0700 (it was 0775: a
 *      `mkdir -p` with the umask's mode), and no shared `$TMPDIR/mandu` or
 *      `/tmp/mandu` is created or touched;
 *   2. a 0775 `<xdg>/mandu` an earlier version made → the launch tightens it
 *      to 0700 (only this uid could have set the bits, and nobody else could
 *      reach inside the 0700 parent) and starts;
 *   3. an explicit MANDU_RUNTIME_DIR that other accounts could reach and WRITE
 *      (0775, every ancestor searchable) → the launch refuses before anything
 *      is spawned or created in it; it is never chmod-repaired, since a
 *      socket or link may already have been planted.
 *
 * The autostarted stack has no lifeline (it is the shared daemon): this test
 * is its owner and stops it in finally, as runtime-fallback.test.ts does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import "../lib/private-home.js"; // the daemons' npm cache and the agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); the runtime-dir mode it proves is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "fixtures", "fake-agent.sh");

/** A short canonical scratch root, 0700 (mkdtemp): stands in for /run/user/<uid>. */
function scratch(): { root: string; cleanup: () => void } {
  const root = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-rm-")));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** What the shared `/tmp/mandu` looks like now (absent, or its inode, owner,
 *  mode and change time): a launch must leave it exactly so. */
function sharedTmpMandu(): string {
  try {
    const st = lstatSync("/tmp/mandu");
    return `${st.ino}:${st.uid}:${st.mode}:${st.ctimeMs}`;
  } catch {
    return "absent";
  }
}

async function withProcessEnv<T>(patch: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(patch)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

/** Run `fn` under umask `mask` (the spawned stack inherits it). */
async function withUmask<T>(mask: number, fn: () => Promise<T>): Promise<T> {
  const old = process.umask(mask);
  try {
    return await fn();
  } finally {
    process.umask(old);
  }
}

function pidsIn(dir: string): number[] {
  if (!existsSync(dir)) return [];
  const out: number[] = [];
  for (const n of readdirSync(dir)) {
    const f = n.endsWith(".json") ? join(dir, n) : join(dir, n, "manifest.json");
    try {
      const m = JSON.parse(readFileSync(f, "utf8")) as { pid?: unknown };
      if (typeof m.pid === "number") out.push(m.pid);
    } catch { /* torn / not a manifest */ }
  }
  return out;
}

async function stopStack(base: string): Promise<void> {
  for (let i = 0; i < 50 && pidsIn(join(base, "dashboards")).length === 0 && existsSync(join(base, "instances")); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  for (const pid of pidsIn(join(base, "dashboards"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
  for (const pid of pidsIn(join(base, "instances"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
  await new Promise((r) => setTimeout(r, 500));
}

/** One real launch with XDG_RUNTIME_DIR = `xdg` under a 002 umask; returns
 *  the socket the agent was handed. */
async function launchUnderXdg(root: string, xdg: string): Promise<string> {
  const tmp = join(root, "t"); // the launch's TMPDIR: its legacy shared name would be <tmp>/mandu
  mkdirSync(tmp, { recursive: true });
  const outFile = join(root, "out.json");
  const base = join(xdg, "mandu");
  return withUmask(0o002, () => withProcessEnv({
    XDG_RUNTIME_DIR: xdg,
    TMPDIR: tmp,
    MANDU_RUNTIME_DIR: undefined,
    MANDU_ARBITER_SOCK: undefined,
    MANDU_HOME: join(root, "mandu-home"), // never the host's durable stores
  }, async () => {
    try {
      const code = await main(["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`], {
        HOME: process.env["HOME"], PWD: root, PATH: process.env["PATH"],
        MANDU_CONFIG: "/dev/null", // hermetic: never the developer's config.toml
        MANDU_NO_CONTEXT_PROXY: "1",
        XDG_RUNTIME_DIR: xdg,
        TMPDIR: tmp,
      });
      assert.equal(code, 0);
      const got = JSON.parse(readFileSync(outFile, "utf8")) as { arbiter: string };
      assert.equal(existsSync(join(tmp, "mandu")), false, "no shared $TMPDIR/mandu was made");
      return got.arbiter;
    } finally {
      await stopStack(base);
    }
  }));
}

test("umask 002, XDG_RUNTIME_DIR set: the stack autostarts under <xdg>/mandu created 0700; no shared /tmp/mandu is touched", { timeout: 120_000 }, async () => {
  chmodSync(FAKE, 0o755);
  const s = scratch();
  const xdg = join(s.root, "run");
  mkdirSync(xdg, { mode: 0o700 });
  const base = join(xdg, "mandu");
  const shared = sharedTmpMandu();
  try {
    const sock = await launchUnderXdg(s.root, xdg);
    assert.equal(sock, join(base, "current", "arbiter.sock"), "the agent gets the XDG base");
    const st = lstatSync(base);
    assert.ok(st.isDirectory() && !st.isSymbolicLink());
    assert.equal(st.mode & 0o777, 0o700, "the runtime base was created 0700 under a 002 umask");
    assert.equal(sharedTmpMandu(), shared, "the shared /tmp/mandu was neither created nor changed");
  } finally {
    s.cleanup();
  }
});

test("a 0775 <xdg>/mandu an earlier version made is tightened to 0700, and the launch starts", { timeout: 120_000 }, async () => {
  chmodSync(FAKE, 0o755);
  const s = scratch();
  const xdg = join(s.root, "run");
  mkdirSync(xdg, { mode: 0o700 });
  const base = join(xdg, "mandu");
  mkdirSync(base);
  chmodSync(base, 0o775);
  try {
    const sock = await launchUnderXdg(s.root, xdg);
    assert.equal(sock, join(base, "current", "arbiter.sock"));
    assert.equal(statSync(base).mode & 0o777, 0o700, "tightened: the parent kept everyone else out, so the bits were ours");
  } finally {
    s.cleanup();
  }
});

test("an explicit MANDU_RUNTIME_DIR other accounts can reach and WRITE (0775): the launch refuses before anything is spawned", { timeout: 60_000 }, async () => {
  const s = scratch();
  // Every ancestor searchable by others: the scratch root opened to 0755
  // (under /tmp, 1777, and /, 0755), so nothing seals the base.
  chmodSync(s.root, 0o755);
  const base = join(s.root, "rt");
  mkdirSync(base);
  chmodSync(base, 0o775);
  try {
    await withProcessEnv({ MANDU_RUNTIME_DIR: base, MANDU_ARBITER_SOCK: undefined }, async () => {
      await assert.rejects(
        main(["--target", "claude", "--no-scope", "--", "/usr/bin/true"], {
          HOME: process.env["HOME"], PWD: s.root, PATH: process.env["PATH"],
          MANDU_CONFIG: "/dev/null", MANDU_NO_CONTEXT_PROXY: "1",
          MANDU_RUNTIME_DIR: base, TMPDIR: s.root,
        }),
        (e: Error) => /^mandu: the Mandu runtime dir .*\/rt is writable by other accounts \(mode 0775/.test(e.message) &&
          /MANDU_RUNTIME_DIR/.test(e.message),
      );
    });
    assert.deepEqual(readdirSync(base), [], "no instance, no logs, no scope dir");
    assert.equal(statSync(base).mode & 0o777, 0o775, "never chmod-repaired");
  } finally {
    s.cleanup();
  }
});
