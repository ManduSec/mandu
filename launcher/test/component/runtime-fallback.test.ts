/**
 * runtime-fallback.test — E2E: the runtime base a macOS launch actually gets
 * (runtime-instances.md §3b), through the real launcher main():
 *
 *   1. no MANDU_RUNTIME_DIR, no XDG_RUNTIME_DIR, a TMPDIR too long for an
 *      instance socket (the per-user /var/folders/…/T/ shape) → the stack is
 *      autostarted under the PRIVATE fallback <root>/mandu-<uid>: created 0700,
 *      the REAL arbiter binds and promotes there, the agent gets the `current`
 *      spelling, and nothing lands under the long TMPDIR;
 *   2. that fallback already exists but is shared (0755) → the launch refuses
 *      before anything is spawned or created in it;
 *   3. an explicit MANDU_RUNTIME_DIR too long for an instance socket → the
 *      launch refuses AT ONCE naming MANDU_RUNTIME_DIR (it used to wait 11 s
 *      for an arbiter that could not bind, then say only "did not come up");
 *   4. an explicit 46-byte MANDU_RUNTIME_DIR — over the 63-byte worst case,
 *      but the arbiter's REAL socket fits — autostarts (the preflight sizes
 *      the socket the arbiter will bind; before it existed such dirs worked
 *      on Linux, and the worst-case preflight refused them);
 *   5. a base directly in a shared sticky dir (a short TMPDIR standing in for
 *      /tmp, no XDG_RUNTIME_DIR: Linux's /tmp/mandu-<uid>) that other accounts
 *      can write → the launch refuses before anything is spawned or created;
 *   6. a squatted shared `$TMPDIR/mandu` (the name every account resolved
 *      before 2026-10-09; others can write it, and it holds a planted
 *      `current` link to an impostor arbiter) → the launch no longer looks
 *      there: it autostarts under its own `$TMPDIR/mandu-<uid>` (0700), the
 *      agent gets that socket, the impostor gets no connection, and nothing
 *      is created in the squatted dir.
 *
 * The fallback root is the test hook MANDU_RUNTIME_FALLBACK_ROOT, so the
 * host's real /tmp/mandu-<uid> is never created or bound. The autostarted
 * stack has no lifeline (it is the shared daemon): this test is its owner and
 * stops it in finally, as instance-autostart.test.ts does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import "../lib/private-home.js"; // the daemons' npm cache and the agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { probeCacheFile } from "../../src/probe-cache.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); the runtime-dir wiring it proves is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "fixtures", "fake-agent.sh");
const UID = process.getuid?.() ?? 0;

interface Scratch {
  root: string;
  base: string;
  longTmp: string;
  cleanup: () => void;
}

function scratch(): Scratch {
  // SHORT and canonical (see instance-autostart.test.ts).
  const root = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-rf-")));
  const longTmp = join(root, "T".repeat(70)); // over the budget on every platform
  mkdirSync(longTmp);
  return { root, base: join(root, `mandu-${UID}`), longTmp, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** Run `fn` with process.env patched (the autostarted daemons inherit it). */
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

function launchEnv(s: Scratch, extra: Record<string, string> = {}): Record<string, string | undefined> {
  return {
    HOME: process.env["HOME"], PWD: s.root, PATH: process.env["PATH"],
    MANDU_CONFIG: "/dev/null", // hermetic: never the developer's config.toml
    MANDU_NO_CONTEXT_PROXY: "1",
    TMPDIR: s.longTmp,
    MANDU_RUNTIME_FALLBACK_ROOT: s.root,
    ...extra,
  };
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

test("long TMPDIR, no runtime dir: the stack autostarts under the PRIVATE /tmp-style fallback (0700), the agent gets its current spelling", { timeout: 120_000 }, async () => {
  chmodSync(FAKE, 0o755);
  const s = scratch();
  const outFile = join(s.root, "out.json");
  try {
    await withProcessEnv({
      MANDU_RUNTIME_FALLBACK_ROOT: s.root, // the spawned dashboard/arbiter recognize the fallback by it
      MANDU_RUNTIME_DIR: undefined,
      MANDU_ARBITER_SOCK: undefined,
      MANDU_HOME: join(s.root, "mandu-home"), // never the host's durable stores
    }, async () => {
      try {
        const code = await main(["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`], launchEnv(s));
        assert.equal(code, 0);
        const got = JSON.parse(readFileSync(outFile, "utf8")) as { arbiter: string };
        assert.equal(got.arbiter, join(s.base, "current", "arbiter.sock"));
        assert.ok(existsSync(got.arbiter), "the promoted socket resolves");

        const st = lstatSync(s.base);
        assert.ok(st.isDirectory() && !st.isSymbolicLink());
        assert.equal(statSync(s.base).mode & 0o777, 0o700, "the fallback base was created private");
        const ids = readdirSync(join(s.base, "instances"));
        assert.equal(ids.length, 1);
        const m = JSON.parse(readFileSync(join(s.base, "instances", ids[0]!, "manifest.json"), "utf8")) as { sockPath: string };
        assert.ok(m.sockPath.startsWith(`${s.base}/instances/`), m.sockPath);
        assert.ok(Buffer.byteLength(m.sockPath) < (process.platform === "darwin" ? 104 : 108));
        assert.equal(probeCacheFile(launchEnv(s)), join(s.base, "probe-cache", "kernel-probes.json"), "kernel probes use the stack's short base too");
        assert.equal(existsSync(join(s.longTmp, "mandu")), false, "no runtime registry or kept kernel probe under the long TMPDIR");
      } finally {
        // Stop the supervisor dashboard (it stops its arbiter), then the arbiter.
        for (let i = 0; i < 50 && pidsIn(join(s.base, "dashboards")).length === 0 && existsSync(join(s.base, "instances")); i++) {
          await new Promise((r) => setTimeout(r, 100));
        }
        for (const pid of pidsIn(join(s.base, "dashboards"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
        for (const pid of pidsIn(join(s.base, "instances"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
        await new Promise((r) => setTimeout(r, 500));
      }
    });
  } finally {
    s.cleanup();
  }
});

test("a pre-existing SHARED (0755) fallback: the launch refuses before anything is spawned or created in it", { timeout: 60_000 }, async () => {
  const s = scratch();
  try {
    mkdirSync(s.base);
    chmodSync(s.base, 0o755);
    await withProcessEnv({ MANDU_RUNTIME_FALLBACK_ROOT: s.root, MANDU_RUNTIME_DIR: undefined, MANDU_ARBITER_SOCK: undefined }, async () => {
      await assert.rejects(
        main(["--target", "claude", "--no-scope", "--", "/usr/bin/true"], launchEnv(s)),
        (e: Error) => /^mandu: the Mandu runtime dir .*mandu-\d+ is shared \(mode 0755/.test(e.message) &&
          /rm -rf/.test(e.message) && /MANDU_RUNTIME_DIR/.test(e.message),
      );
    });
    assert.deepEqual(readdirSync(s.base), [], "no instance, no logs, no scope dir");
    assert.equal(statSync(s.base).mode & 0o777, 0o755, "never chmod-repaired");
  } finally {
    s.cleanup();
  }
});

test("an explicit MANDU_RUNTIME_DIR too long for an instance socket refuses AT ONCE, naming MANDU_RUNTIME_DIR", { timeout: 60_000 }, async () => {
  const s = scratch();
  try {
    const base = join(s.root, "r".repeat(50)); // ≥ 67 bytes: even the real socket does not fit
    const t0 = Date.now();
    await withProcessEnv({ MANDU_RUNTIME_DIR: undefined, MANDU_ARBITER_SOCK: undefined }, async () => {
      await assert.rejects(
        main(["--target", "claude", "--no-scope", "--", "/usr/bin/true"], launchEnv(s, { TMPDIR: s.root, MANDU_RUNTIME_DIR: base })),
        (e: Error) => /^mandu: refusing to launch: the runtime dir .* is \d+ bytes/.test(e.message) &&
          /Point MANDU_RUNTIME_DIR at a directory of at most \d+ bytes/.test(e.message),
      );
    });
    assert.ok(Date.now() - t0 < 5_000, `fail fast, not after the socket wait (${Date.now() - t0} ms)`);
    assert.equal(existsSync(base), false, "nothing spawned, nothing created");
  } finally {
    s.cleanup();
  }
});

test("an explicit 46-byte MANDU_RUNTIME_DIR (over the worst case, under the real socket) AUTOSTARTS: the arbiter binds and promotes there", { timeout: 120_000 }, async () => {
  chmodSync(FAKE, 0o755);
  const s = scratch();
  const base = join(s.root, "r".repeat(46 - Buffer.byteLength(s.root) - 1));
  assert.equal(Buffer.byteLength(base), 46);
  const outFile = join(s.root, "out.json");
  try {
    await withProcessEnv({
      MANDU_RUNTIME_DIR: base,
      MANDU_ARBITER_SOCK: undefined,
      MANDU_HOME: join(s.root, "mandu-home"),
    }, async () => {
      try {
        const code = await main(["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`],
          launchEnv(s, { TMPDIR: s.root, MANDU_RUNTIME_DIR: base }));
        assert.equal(code, 0);
        const got = JSON.parse(readFileSync(outFile, "utf8")) as { arbiter: string };
        assert.equal(got.arbiter, join(base, "current", "arbiter.sock"));
        assert.ok(existsSync(got.arbiter), "the promoted socket resolves");
        const ids = readdirSync(join(base, "instances"));
        assert.equal(ids.length, 1);
        const m = JSON.parse(readFileSync(join(base, "instances", ids[0]!, "manifest.json"), "utf8")) as { sockPath: string };
        const limit = process.platform === "darwin" ? 104 : 108;
        assert.ok(Buffer.byteLength(m.sockPath) < limit, `${m.sockPath} fits`);
        assert.ok(46 + 63 >= limit, "the worst case alone would have refused this base");
      } finally {
        for (let i = 0; i < 50 && pidsIn(join(base, "dashboards")).length === 0 && existsSync(join(base, "instances")); i++) {
          await new Promise((r) => setTimeout(r, 100));
        }
        for (const pid of pidsIn(join(base, "dashboards"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
        for (const pid of pidsIn(join(base, "instances"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
        await new Promise((r) => setTimeout(r, 500));
      }
    });
  } finally {
    s.cleanup();
  }
});

test("a base in a shared sticky dir (Linux's /tmp/mandu-<uid> without XDG_RUNTIME_DIR) that others can WRITE: the launch refuses before anything is spawned", { timeout: 60_000 }, async () => {
  const s = scratch();
  const sticky = join(s.root, "st");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777); // stands in for /tmp
  const base = join(sticky, `mandu-${UID}`);
  mkdirSync(base);
  chmodSync(base, 0o775);
  try {
    await withProcessEnv({ MANDU_RUNTIME_DIR: undefined, MANDU_ARBITER_SOCK: undefined, XDG_RUNTIME_DIR: undefined }, async () => {
      await assert.rejects(
        main(["--target", "claude", "--no-scope", "--", "/usr/bin/true"], launchEnv(s, { TMPDIR: sticky })),
        (e: Error) => /^mandu: the Mandu runtime dir .*\/st\/mandu-\d+ is writable by other accounts \(mode 0775/.test(e.message) &&
          /rm -rf/.test(e.message) && /MANDU_RUNTIME_DIR/.test(e.message),
      );
    });
    assert.deepEqual(readdirSync(base), [], "no instance, no logs, no scope dir");
    assert.equal(statSync(base).mode & 0o777, 0o775, "never chmod-repaired");
  } finally {
    s.cleanup();
  }
});

test("a squatted shared $TMPDIR/mandu (others can write it; a planted current link to an impostor) no longer blocks or diverts the launch: it autostarts under its own $TMPDIR/mandu-<uid>", { timeout: 120_000 }, async () => {
  chmodSync(FAKE, 0o755);
  const s = scratch();
  const sticky = join(s.root, "st");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777); // stands in for /tmp
  // The squat: the shared name every account resolved before 2026-10-09,
  // writable by all, with a `current` an impostor arbiter answers on.
  const squat = join(sticky, "mandu");
  mkdirSync(join(squat, "current"), { recursive: true });
  chmodSync(squat, 0o777);
  const impostorSock = join(squat, "current", "arbiter.sock");
  let impostorHits = 0;
  const impostor = createServer((c) => { impostorHits++; c.destroy(); });
  await new Promise<void>((r) => impostor.listen(impostorSock, r));
  const before = readdirSync(squat).sort();
  const own = join(sticky, `mandu-${UID}`);
  const outFile = join(s.root, "out.json");
  try {
    await withProcessEnv({
      MANDU_RUNTIME_FALLBACK_ROOT: s.root,
      MANDU_RUNTIME_DIR: undefined, MANDU_ARBITER_SOCK: undefined, XDG_RUNTIME_DIR: undefined,
      // A real launch resolves in its own process env: the stack start checks
      // and creates the base under the same TMPDIR the launch env names.
      TMPDIR: sticky,
      MANDU_HOME: join(s.root, "mandu-home"),
    }, async () => {
      try {
        const code = await main(["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`], launchEnv(s, { TMPDIR: sticky }));
        assert.equal(code, 0, "the squat does not block the launch");
        const got = JSON.parse(readFileSync(outFile, "utf8")) as { arbiter: string };
        assert.equal(got.arbiter, join(own, "current", "arbiter.sock"), "the agent gets this account's own base");
        assert.ok(existsSync(got.arbiter), "the promoted socket resolves");
        assert.equal(statSync(own).mode & 0o777, 0o700, "the per-user base was created private");
        assert.equal(impostorHits, 0, "nothing connected to the impostor");
        assert.deepEqual(readdirSync(squat).sort(), before, "nothing created in the squatted dir");
      } finally {
        for (let i = 0; i < 50 && pidsIn(join(own, "dashboards")).length === 0 && existsSync(join(own, "instances")); i++) {
          await new Promise((r) => setTimeout(r, 100));
        }
        for (const pid of pidsIn(join(own, "dashboards"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
        for (const pid of pidsIn(join(own, "instances"))) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
        await new Promise((r) => setTimeout(r, 500));
      }
    });
  } finally {
    await new Promise<void>((r) => impostor.close(() => r()));
    s.cleanup();
  }
});
