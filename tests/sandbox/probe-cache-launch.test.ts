/**
 * The per-boot kernel probe cache through the REAL launch (launcher
 * src/probe-cache.ts; packaging.md §5.4, rootless-confinement-ubuntu-2404.md
 * §12.6): the launcher's main() in `secrets` mode with the guard off (so the
 * bind wrap is the confinement step a userns answer decides), a REAL
 * ArbiterServer, and a `bwrap` first on PATH that logs every call and either
 * refuses every namespace (`deny`, a host whose userns broke) or runs the
 * host's real bubblewrap (`real`). The "agent" is /bin/sh reading a catalog
 * credential file.
 *
 *   C1 a POISONED "available": a kept userns pass for this exact host while
 *      bwrap can make no namespace. The launch still enacts the bind wrap,
 *      bwrap fails, the agent NEVER runs (no raw read, no unconfined run), the
 *      launch fails, and it drops the cache file.
 *   C2 the next launch probes afresh (the probe's argv is in the log),
 *      resolves the honest `gated` posture with a userns gap, and keeps
 *      nothing: a failure is never cached.
 *   C3 `mandu setup` (the real deps' clear) drops the file; the host is
 *      "fixed" (the real bwrap): the next launch probes, passes, binds, and the
 *      agent reads the placeholder; the pass is kept.
 *   C4 the launch after that asks no userns probe (kept), and the kept pass
 *      is ENACTED: the agent still reads the placeholder, never the raw bytes.
 *
 * Self-SKIPs where the host's bwrap cannot create a user namespace, or where
 * Mandu's own bubblewrap is in force (the launch then runs that copy by its
 * absolute path, and no stand-in on PATH can stand between).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { manduBwrapInForceHere } from "../../launcher/src/bwrap-grant.js";
import { BWRAP_PROBE_ARGV, usernsProbeInputs } from "../../launcher/src/userns.js";
import { cachedProbe, disableProbeCache, enableProbeCache, parseCacheFile } from "../../launcher/src/probe-cache.js";
import { realSetupDeps, runSetup, type SetupFacts } from "../../launcher/src/setup.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the bind wrap is the confidentiality axis's

const REAL_BWRAP = (spawnSync("bash", ["-c", "command -v bwrap"], { encoding: "utf8" }).stdout ?? "").trim();
const BWRAP_RUNS = process.platform === "linux" && REAL_BWRAP !== "" &&
  spawnSync(REAL_BWRAP, ["--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const skip = !BWRAP_RUNS
  ? "bwrap cannot create a user namespace on this host"
  : manduBwrapInForceHere() ? "Mandu's own bubblewrap is in force (the launch runs it by path)" : false;
const RAW = "AKIA_PROBE_CACHE_4471_RAW_MUST_NOT_BE_READ";

interface World { dir: string; rt: string; bin: string; log: string; cache: string; home: string; secret: string; path: string }

function world(): World {
  const dir = mkdtempSync(join(tmpdir(), "mandu-probe-cache-"));
  const rt = join(dir, "rt");
  mkdirSync(rt, { mode: 0o700 });
  const bin = join(dir, "bin");
  mkdirSync(bin);
  const log = join(dir, "bwrap.log");
  // The stand-in: logs its argv, then refuses (deny) or runs the real one.
  writeFileSync(join(bin, "bwrap"), `#!/bin/sh
printf '%s\\n' "$*" >> '${log}'
if [ "$(cat '${join(dir, "mode")}')" = deny ]; then
  echo "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces." >&2
  exit 1
fi
exec '${REAL_BWRAP}' "$@"
`);
  chmodSync(join(bin, "bwrap"), 0o755);
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  const secret = join(home, ".aws", "credentials");
  writeFileSync(secret, `[default]\naws_secret_access_key=${RAW}\n`);
  return { dir, rt, bin, log, home, secret, cache: join(rt, "probe-cache", "kernel-probes.json"), path: `${bin}:${process.env["PATH"] ?? ""}` };
}

const setMode = (w: World, m: "deny" | "real"): void => writeFileSync(join(w.dir, "mode"), m);
const logLines = (w: World): string[] => (existsSync(w.log) ? readFileSync(w.log, "utf8").split("\n").filter(Boolean) : []);
const USERNS_PROBE = BWRAP_PROBE_ARGV.join(" ");

/** Run `f` with process.env's PATH (what every probe's spawn sees) and the
 *  runtime dir pointed at the world. */
async function withEnv<T>(w: World, f: () => Promise<T> | T): Promise<T> {
  const saved = { PATH: process.env["PATH"], HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"], MANDU_RUNTIME_DIR: process.env["MANDU_RUNTIME_DIR"] };
  process.env["PATH"] = w.path;
  process.env["HOME"] = w.home;
  process.env["MANDU_HOME"] = join(w.home, ".mandu");
  process.env["MANDU_RUNTIME_DIR"] = w.rt;
  try {
    return await f();
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
}

interface Launch { code: number | null; err: Error | null; lines: string[]; out: string; posture: Record<string, unknown> | null }

async function launch(w: World): Promise<Launch> {
  const out = join(w.dir, `out-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const sock = join(w.dir, "arbiter.sock");
  const events = join(w.dir, "events");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(w.dir, "sym.db"), eventDir: events, log: () => {} });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  let code: number | null = null;
  let err: Error | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    await withEnv(w, async () => {
      try {
        code = await main(
          ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--no-net-guard",
            "--", "/bin/sh", "-c", `echo CHILD_RAN > ${out}; cat ${w.secret} >> ${out}`],
          {
            HOME: w.home, PWD: w.dir, MANDU_ARBITER_SOCK: sock, PATH: w.path,
            MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(w.home, ".mandu"), MANDU_MODE: "secrets",
            MANDU_RUNTIME_DIR: w.rt, XDG_RUNTIME_DIR: w.dir, MANDU_VERBOSE: "1",
          },
        );
      } catch (e) {
        err = e as Error;
      }
    });
  } finally {
    console.error = orig;
    await server.close();
  }
  let posture: Record<string, unknown> | null = null;
  if (existsSync(events)) {
    for (const f of readdirSync(events, { recursive: true }) as string[]) {
      if (!f.endsWith(".ndjson")) continue;
      for (const l of readFileSync(join(events, f), "utf8").split("\n")) {
        if (l.includes('"launch_posture"')) posture = (JSON.parse(l) as Record<string, unknown>)["secrets"] as Record<string, unknown>;
      }
      rmSync(join(events, f), { force: true });
    }
  }
  return { code, err, lines, out: existsSync(out) ? readFileSync(out, "utf8") : "", posture };
}

/** Plant a kept userns pass for this exact host (the launch's own key). */
async function plantUsernsPass(w: World): Promise<void> {
  await withEnv(w, () => {
    enableProbeCache({ MANDU_RUNTIME_DIR: w.rt });
    try {
      assert.equal(cachedProbe("userns", usernsProbeInputs, () => true), true);
    } finally {
      disableProbeCache();
    }
  });
  assert.ok(parseCacheFile(readFileSync(w.cache, "utf8"))!.entries["userns"], "planted");
}

test("C1-C4: a poisoned pass fails closed and is dropped; a failure is re-probed; setup clears; a real pass is kept and enacted", { skip, timeout: 240_000 }, async () => {
  const w = world();
  try {
    // ── C1: poisoned "available" on a host whose bwrap makes no namespace ──
    setMode(w, "deny");
    await plantUsernsPass(w);
    const c1 = await launch(w);
    const log1 = c1.lines.join("\n");
    assert.ok(c1.err !== null || (c1.code ?? 0) !== 0, `the launch must fail closed:\n${log1}`);
    assert.doesNotMatch(c1.out, /CHILD_RAN/, "the agent never runs without the step the kept answer promised");
    assert.ok(!c1.out.includes(RAW));
    assert.ok(!logLines(w).includes(USERNS_PROBE), "the kept answer was used: no userns probe ran");
    assert.ok(logLines(w).some((l) => l.includes("--dev-bind / /") && l.includes("/bin/sh")), `the bind wrap was enacted:\n${logLines(w).join("\n")}`);
    assert.match(log1, /kernel probe userns: passed earlier this boot/);
    assert.equal(existsSync(w.cache), false, "a failed launch that used a kept pass drops the file");

    // ── C2: the next launch probes afresh and keeps no failure ──
    writeFileSync(w.log, "");
    const c2 = await launch(w);
    const log2 = c2.lines.join("\n");
    assert.equal(c2.err, null, `${c2.err?.message}\n${log2}`);
    assert.equal(c2.code, 0, log2);
    assert.ok(logLines(w).includes(USERNS_PROBE), "the userns probe ran");
    assert.ok(c2.posture !== null && c2.posture["posture"] === "gated", JSON.stringify(c2.posture));
    assert.ok(["apparmor-userns", "userns-off"].includes(String(c2.posture!["gap"])), JSON.stringify(c2.posture));
    assert.match(log2, /secrets are GATED, not confined/);
    const kept2 = existsSync(w.cache) ? parseCacheFile(readFileSync(w.cache, "utf8"))!.entries : {};
    assert.equal(kept2["userns"], undefined, "a failed probe is never kept");

    // ── C3: setup clears the file; the fixed host is seen at once ──
    await plantUsernsPass(w);
    await withEnv(w, async () => {
      const nothing: SetupFacts = {
        platform: "linux", systemBwrap: null, usernsOk: false, nestingOk: false, apparmorRestricted: false, apparmorParser: false,
        copy: "absent", profileFile: null, legacy: { bwrap: null, unshare: null }, sameName: { bwrap: [], unshare: [] }, usernsHint: "",
      };
      const deps = { ...realSetupDeps(Layout.dev(resolve(import.meta.dirname, "..", ".."))), facts: () => nothing, sudo: () => 1, out: () => {}, err: () => {} };
      assert.equal(await runSetup(["--uninstall"], deps), 0);
    });
    assert.equal(existsSync(w.cache), false, "`mandu setup` drops the cache (the real deps)");
    setMode(w, "real");
    writeFileSync(w.log, "");
    const c3 = await launch(w);
    const log3 = c3.lines.join("\n");
    assert.equal(c3.err, null, `${c3.err?.message}\n${log3}`);
    assert.equal(c3.code, 0, log3);
    assert.ok(logLines(w).includes(USERNS_PROBE), "probed afresh after setup");
    assert.match(c3.out, /CHILD_RAN/);
    assert.ok(!c3.out.includes(RAW), `the bind covers the file:\n${c3.out}`);
    assert.match(c3.out, /\$MDU:/);
    assert.ok(parseCacheFile(readFileSync(w.cache, "utf8"))!.entries["userns"], "the pass is kept");

    // ── C4: kept and still enacted ──
    writeFileSync(w.log, "");
    const c4 = await launch(w);
    const log4 = c4.lines.join("\n");
    assert.equal(c4.err, null, `${c4.err?.message}\n${log4}`);
    assert.equal(c4.code, 0, log4);
    assert.ok(!logLines(w).includes(USERNS_PROBE), `no userns probe this time:\n${logLines(w).join("\n")}`);
    assert.match(log4, /kernel probe userns: passed earlier this boot/);
    assert.match(c4.out, /CHILD_RAN/);
    assert.ok(!c4.out.includes(RAW), `the kept pass was enacted (the bind is up):\n${c4.out}`);
    assert.match(c4.out, /\$MDU:/);
  } finally {
    rmSync(w.dir, { recursive: true, force: true });
  }
});
