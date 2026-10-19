/**
 * The voided-caches notice and the worktree launch's bins, across the REAL
 * launcher (confidentiality-plan-14 §11.2.1; packaging.md §5.2):
 *
 *   U1 a confined launch builds and seals the sanitized git history; while an
 *      unconfined launch is live (recorded on the human socket the way run.ts
 *      records one: `--mode off`, its workspace and session), the next
 *      launch keeps ONE notice naming it (pid, workspace, why) and how to end
 *      it (counted on its default banner, in full in its log), and the key
 *      stays hidden (the rule is unchanged: the cache is rebuilt); once it
 *      ends, the notice is gone, the next launch says in ONE line, above the
 *      banner, that it
 *      re-checks the git history because that session ended (the rebuild
 *      notice), and the one after is silent: the cache serves again;
 *   W1 the launcher run from a git worktree with no native bins of its own
 *      (its own launcher/dist bundle, as launcher/mandu-run.sh runs a
 *      checkout) uses its main checkout's bins when their provenance record
 *      (scripts/native-provenance.mjs, as scripts/build-native.sh writes it)
 *      matches the worktree's native sources: the launch is CONFINED (the
 *      mode line masks, no GATED notice, and its end leaves the seals'
 *      epoch alone, which only a confined launch does). One source byte
 *      changed in the worktree: the bins are refused, the launch runs gated,
 *      says why and names scripts/build-native.sh, and its end voids the
 *      seals (it was unconfined).
 *
 * A private in-process ArbiterServer with a human socket, throwaway HOMEs.
 * Self-SKIPs where bwrap cannot create a user namespace or the guard is not
 * built fresh (scripts/build-native.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { launchLogs } from "../../launcher/test/lib/launch-log-read.js";
import { compactNotice } from "../../launcher/src/launch-banner.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { beginLaunchRecord, endLaunchRecord, type CacheEpochDeps } from "../../launcher/src/cache-epoch.js";
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { resolveNativeBin, type NativeBinName } from "../../launcher/src/services/native-bins.js";
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // the product default: the seals and the confinement serve the confidentiality axis

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");
const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const PICK = pickGuard(join(REPO, "interceptors", "target"));
const GUARD = PICK.path !== undefined && PICK.stale === null ? PICK.path : undefined;
const skip = !BWRAP_RUNS ? "bwrap cannot create a user namespace on this host (the confined launch cannot start)"
  : !GUARD ? "no fresh mandu-net-guard (scripts/build-native.sh)" : false;

const DEPLOY_KEY = ["VOIDED", "NOTICE", "KEY", "4471", "Hk".repeat(16)].join("_");
const AWS_KEY = ["wJalr", "VOIDED", "NOTICE", "CRED", "x".repeat(20)].join("");

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: GIT_ENV });

interface Stack { dir: string; home: string; ws: string; sock: string; humanSock: string; admin: ArbiterClient; close: () => Promise<void> }

async function stack(prefix: string): Promise<Stack> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_access_key_id = AKIAVOIDEDNOTICE0001\naws_secret_access_key = ${AWS_KEY}\n`);
  git(dir, "init", "-q", ws);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  return {
    dir, home, ws, sock, humanSock, admin,
    close: async () => { admin.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

/** A repository whose history holds a deploy key that is locked now (the
 *  git-history twins then build, cache and seal a sanitized pack). */
async function lockedHistory(s: Stack): Promise<string> {
  writeFileSync(join(s.ws, "README.md"), "project readme\n");
  git(s.ws, "add", ".");
  git(s.ws, "commit", "-qm", "init");
  mkdirSync(join(s.ws, "deploy"));
  writeFileSync(join(s.ws, "deploy", "id_rsa"), `${DEPLOY_KEY}\n`);
  git(s.ws, "add", ".");
  git(s.ws, "commit", "-qm", "add deploy key");
  const added = git(s.ws, "rev-parse", "HEAD").trim();
  git(s.ws, "rm", "-rq", "deploy");
  git(s.ws, "commit", "-qm", "oops, remove it");
  git(s.ws, "repack", "-adq");
  const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: join(s.ws, "deploy", "id_rsa"), level: "no-model" }], reason: "U1", requestedBy: "dashboard" });
  assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
  return added;
}

/** One launch through the real main(), in the default display, running
 *  `cmd` in the workspace; what it printed, its own log's lines (launch-log.ts:
 *  every note in full, packaging.md §5) and what `cmd` wrote. */
async function launchInProcess(s: Stack, cmd: string): Promise<{ log: string; full: string[]; out: string }> {
  const out = join(s.dir, `out-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const lines: string[] = [];
  const orig = console.error;
  const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"], MANDU_NET_GUARD_BIN: process.env["MANDU_NET_GUARD_BIN"] };
  const cwd = process.cwd();
  let code: number | null = null;
  let err: Error | null = null;
  const logs = launchLogs({ HOME: s.home, MANDU_HOME: join(s.home, ".mandu") });
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = s.home;
    process.env["MANDU_HOME"] = join(s.home, ".mandu");
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.chdir(s.ws);
    try {
      code = await main(
        ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "/bin/sh", "-c",
          `export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_PAGER=cat; (${cmd}) > '${out}' 2>&1; true`],
        {
          HOME: s.home, PWD: s.ws, MANDU_ARBITER_SOCK: s.sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1",
          MANDU_HOME: join(s.home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: s.dir,
        },
      );
    } catch (e) { err = e as Error; }
  } finally {
    console.error = orig;
    process.chdir(cwd);
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  const log = lines.join("\n");
  assert.equal(err, null, `${err?.message}\n${log}`);
  assert.equal(code, 0, log);
  return { log, full: logs.newLines(), out: existsSync(out) ? readFileSync(out, "utf8") : "" };
}

/** The voided-caches notice (cache-seals.ts voidedCachesLine) a launch kept:
 *  counted on the default banner, in full in its log. */
const noticeLines = (full: string[]): string[] => full.filter((l) => l.startsWith("mandu: the git-history caches are not trusted this launch"));

test("U1 (plan 14 §11.2.1): while an unconfined launch runs, the next launch keeps one notice naming it (pid, workspace, why, how to end it), counted on its banner; the key stays hidden; once it ends, the next launch says in one line, above the banner, that it re-checks the git history, and the cache serves again", { skip, timeout: 300_000 }, async () => {
  const s = await stack("mandu-voided-notice-");
  const other = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  try {
    const added = await lockedHistory(s);
    const show = `git show ${added}:deploy/id_rsa`;
    const first = await launchInProcess(s, show);
    assert.match(first.out, /bad object/, first.log);
    assert.deepEqual(noticeLines(first.full), [], "no other launch: no notice");
    assert.ok(!first.log.includes("re-checking the git history"), "a first build is not a re-check");

    // An unconfined launch, recorded the way run.ts records one.
    const deps: CacheEpochDeps = { call: (sk, op, a) => ndjsonCall(sk, op, a, 5000), log: () => {}, purge: () => {} };
    const otherWs = join(s.dir, "elsewhere", "my-worktree");
    const rec = await beginLaunchRecord(s.humanSock, { pid: other.pid!, mode: "off", posture: "off", writeProtect: false, sessionId: "claude-off-u1", workspace: otherWs }, deps);
    assert.equal(rec.confined, false);

    const during = await launchInProcess(s, show);
    assert.match(during.out, /bad object/, "the rule is unchanged: the history stays hidden");
    assert.ok(!during.out.includes(DEPLOY_KEY));
    const notice = noticeLines(during.full);
    assert.equal(notice.length, 1, during.full.join("\n"));
    assert.equal(compactNotice(notice[0]!),
      `mandu: ! git history rebuilt (slower) while a Mandu launch runs without protection (pid ${other.pid} in ${otherWs} (session claude-off-u1): protection off); ` +
      `to end it: quit its agent, or \`kill ${other.pid}\``,
      "it names the launch (pid, workspace, why) and how to end it");
    // The default display counts it on the banner (packaging.md §5, 2026-10-18).
    assert.match(during.log, /^mandu: secrets mode · .* · \d+ notices?: `mandu log`$/m, during.log);
    assert.ok(!during.log.includes("mandu: the git-history caches are not trusted"), "the long form is not on the terminal");

    // It ends (its launcher dies): the next launch is told nothing, and the
    // cache serves again from the one after.
    const exited = new Promise((ok) => other.once("exit", ok));
    other.kill("SIGKILL");
    await exited;
    const after = await launchInProcess(s, show);
    assert.deepEqual(noticeLines(after.full), [], after.full.join("\n"));
    assert.match(after.out, /bad object/);
    // Plan 14 §11.2.1 "The rebuild notice": that launch rebuilds what the
    // ended period voided, and says so in ONE plain line printed at once,
    // above the banner (so before the agent starts), not counted with the
    // banner's notices.
    const lines = after.log.split("\n");
    const said = lines.filter((l) => l.startsWith("mandu: ! ") && l.includes("re-checking the git history"));
    assert.deepEqual(said, ["mandu: ! an earlier Mandu session without protection has ended, so Mandu is re-checking the git history of 1 repository (slower this once)"], after.log);
    assert.ok(lines.indexOf(said[0]!) < lines.findIndex((l) => /^mandu: secrets mode · /.test(l)), after.log);
    const again = await launchInProcess(s, show);
    assert.ok(!again.log.includes("re-checking the git history"), `warm again: silent\n${again.log}`);
    assert.match(again.out, /bad object/);
    await endLaunchRecord(s.humanSock, rec, deps);
  } finally {
    other.kill("SIGKILL");
    await s.close();
  }
});

// ── W1: a worktree launch with matching bins is confined ────────────────────

const BINS: NativeBinName[] = ["mandu-net-guard", "mandu-exec-box", "mandu-landlock-apply"];
const REAL_BINS = BINS.map((b) => resolveNativeBin(b, { shared: false }));
const ESBUILD = existsSync(join(REPO, "launcher", "node_modules", "esbuild"));
const skipW = skip || (REAL_BINS.some((b) => b === null) ? "the native bins are not all built (scripts/build-native.sh)" : !ESBUILD ? "launcher/node_modules has no esbuild" : false);
const SOURCES = ["net-supervisor/src/lib.rs", "exec-supervisor/src/lib.rs", "mandu-paths/src/lib.rs"];

/** A main checkout whose interceptors/target/release holds this checkout's
 *  real bins with provenance records over stand-in sources, and a git
 *  worktree of it whose launcher/dist is a bundle of this launcher (the
 *  launcher then lives in the worktree: its own target/ is empty). */
function worktreeRig(dir: string): { main: string; wt: string } {
  const main = join(dir, "main");
  mkdirSync(main);
  git(main, "init", "-q");
  const ic = join(main, "interceptors");
  for (const rel of SOURCES) {
    mkdirSync(dirname(join(ic, rel)), { recursive: true });
    writeFileSync(join(ic, rel), `// ${rel}\n`);
  }
  writeFileSync(join(ic, "Cargo.toml"), "[workspace]\n");
  writeFileSync(join(ic, "Cargo.lock"), "version = 3\n");
  mkdirSync(join(main, "launcher", "src"), { recursive: true });
  writeFileSync(join(main, "launcher", "src", "run.ts"), "// the checkout marker (layout.ts isCheckoutBuild)\n");
  // The assets a checkout launch reads from its sources: the `claude` shim's
  // preload and its rule (agent-sdks.md §3.5). Without them a launch with a
  // `claude` on PATH refuses (fail closed).
  for (const f of ["sdk-route-preload.cjs", "claude-permission-rule.cjs"]) {
    copyFileSync(join(REPO, "launcher", "src", f), join(main, "launcher", "src", f));
  }
  writeFileSync(join(main, ".gitignore"), "target/\ndist/\n");
  git(main, "add", ".");
  git(main, "commit", "-qm", "sources");
  const out = join(ic, "target", "release");
  mkdirSync(out, { recursive: true });
  const later = new Date(Date.now() + 5000);
  BINS.forEach((b, i) => {
    copyFileSync(REAL_BINS[i]!, join(out, b));
    utimesSync(join(out, b), later, later);
    writeFileSync(join(out, `${b}.d`), `${join(out, b)}: ${SOURCES.map((s) => join(ic, s)).join(" ")}\n`);
  });
  execFileSync(process.execPath, [join(REPO, "scripts", "native-provenance.mjs"), "record", ic, out, ...BINS], { encoding: "utf8" });
  const wt = join(dir, "wt");
  git(main, "worktree", "add", "-q", "--detach", wt);
  execFileSync(process.execPath, [join(REPO, "launcher", "scripts", "build-bundle.mjs"), `--outdir=${join(wt, "launcher", "dist")}`, "--no-native", "--quiet"], { cwd: join(REPO, "launcher"), stdio: "pipe" });
  return { main, wt };
}

/** One launch of the worktree's own launcher bundle (a child process, as the
 *  checkout shim runs it), the default display; exit code, and stderr then
 *  the launch's own log. Async:
 *  the arbiter answering it runs in this process. */
async function launchFromWorktree(s: Stack, wt: string): Promise<{ code: number | null; err: string }> {
  const logs = launchLogs({ HOME: s.home, MANDU_HOME: join(s.home, ".mandu") });
  const env: Record<string, string> = {
    HOME: s.home, PWD: s.ws, PATH: process.env["PATH"] ?? "/usr/bin:/bin", MANDU_ARBITER_SOCK: s.sock, MANDU_NO_CONTEXT_PROXY: "1",
    MANDU_HOME: join(s.home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: s.dir,
    MANDU_AXES_STRICT: "1", MANDU_POLICY_FILE: "/dev/null/mandu-test-no-policy.yaml",
  };
  const child = spawn(process.execPath, [join(wt, "launcher", "dist", "mandu.mjs"),
    "--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "/bin/sh", "-c", "true"],
  { cwd: s.ws, env, stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  child.stderr!.on("data", (b: Buffer) => { err += b.toString("utf8"); });
  const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
  const code = await new Promise<number | null>((ok) => child.once("close", (c) => ok(c)));
  clearTimeout(timer);
  // The launch's own log after its terminal lines: the default display prints
  // one banner line and a short line per warning, the log every note in full.
  return { code, err: [err, ...logs.newLinesIfAny()].join("\n") };
}

test("W1 (packaging.md §5.2): a launch from a git worktree with no bins of its own uses the main checkout's bins built from the same sources and is CONFINED; one source byte different, it is refused them, runs gated, says why and names scripts/build-native.sh", { skip: skipW, timeout: 300_000 }, async () => {
  const s = await stack("mandu-wt-bins-");
  try {
    const { main, wt } = worktreeRig(s.dir);
    assert.ok(!existsSync(join(wt, "interceptors", "target")), "the worktree has no bins of its own");

    const epoch0 = (await s.admin.cacheSeals("object-twin", [])).epoch;
    const ok = await launchFromWorktree(s, wt);
    assert.equal(ok.code, 0, ok.err);
    assert.match(ok.err, /^mandu: mode secrets \(\d+ credential files? masked/m, ok.err);
    assert.ok(!/GATED|not built|were not used/.test(ok.err), `confined, with the main checkout's bins: ${ok.err}`);
    assert.equal((await s.admin.cacheSeals("object-twin", [])).epoch, epoch0, "a confined launch's end leaves the seals' epoch alone");

    // One byte of a native source differs in the worktree: refused.
    appendFileSync(join(wt, "interceptors", SOURCES[0]!), " ");
    const refused = await launchFromWorktree(s, wt);
    assert.equal(refused.code, 0, refused.err);
    assert.match(refused.err, /GATED/, refused.err);
    assert.match(refused.err, /The main checkout's bins were not used \(.*interceptors\/net-supervisor\/src\/lib\.rs differs from the source it was built from/, refused.err);
    assert.match(refused.err, /run scripts\/build-native\.sh in this worktree to launch confined/);
    assert.ok(refused.err.includes(join(main, "interceptors", "target", "release", "mandu-net-guard")), "names the bin it refused");
    assert.notEqual((await s.admin.cacheSeals("object-twin", [])).epoch, epoch0, "the gated launch was unconfined: its end voided the seals");
  } finally {
    await s.close();
  }
});
