/**
 * Unit: hardened-git — the forced config, the scrubbed environment and the
 * git sandbox's command line (docs/design/architecture/write-protection.md §8), and the
 * launcher's driver-free working-copy hash (git-object-twins.ts
 * `worktreeBlobNames`), which replaced a `git hash-object` that ran the
 * repository's clean filter.
 *
 * hardened-git.ts is copied byte-identical into the arbiter, the dashboard
 * and fs-sync; tests/stack/hardened-git-parity.test.ts holds
 * the copies equal and runs a hostile repository through each.
 *
 * The git sandbox is off in this file (MANDU_GIT_SANDBOX=0): a marker
 * program inside it could not write its marker. Its probe is tested with
 * injected runners and an injected platform (both the Linux bubblewrap and
 * the macOS Seatbelt branch, on every host), the macOS profile byte for
 * byte, and the per-process answer (gitSandboxCache) with an injected probe
 * and clock; its confinement is launcher/test/kernel/git-sandbox.test.ts
 * (bubblewrap) and launcher/test/darwin/git-sandbox-live.test.ts (Seatbelt).
 */
process.env["MANDU_GIT_SANDBOX"] = "0";

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GIT_HOOK_EVENTS, GIT_NO_PROGRAM_CONFIG, GIT_SANDBOX_FLAG_SETS, GIT_SANDBOX_RETRY_MS, GIT_SEATBELT_MACH_ALLOW, HARDENED_GIT_ENV, HARDENED_GIT_GLOBAL_ARGS, MANDU_OWN_BWRAP,
  SANDBOX_EXEC, canonicalSpelling, gitCommand, gitSandboxCache, gitSeatbeltProfile, hardenedGitArgs, hardenedGitEnv, isSeatbeltGitSandbox,
  probeGitSandbox, probeGitSandboxOutcome, probeRunVerdict, resolveGitBinary, type GitSandboxProbe, type SeatbeltGitSandbox,
} from "../../src/hardened-git.js";
import { canonicalPath, SANDBOX_EXEC as PROFILE_SANDBOX_EXEC } from "../../src/seatbelt-profile.js";
import { eolConfigArgs, scratchGitConfig, worktreeBlobNames, defaultGitRunner, prepareGitObjectTwins } from "../../src/git-object-twins.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; the working-copy hash serves the confidentiality axis

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

test("the forced config names every program-starting key and is passed as -c pairs behind --no-pager", () => {
  const keys = GIT_NO_PROGRAM_CONFIG.map((kv) => kv.slice(0, kv.indexOf("=")));
  for (const k of [
    "core.fsmonitor", "core.hooksPath", "log.showSignature", "commit.gpgSign", "tag.gpgSign", "merge.verifySignatures",
    "credential.helper", "protocol.allow", "gc.auto", "maintenance.auto", "submodule.recurse",
  ]) assert.ok(keys.includes(k), `${k} is forced`);
  assert.equal(HARDENED_GIT_GLOBAL_ARGS[0], "--no-pager");
  assert.deepEqual(HARDENED_GIT_GLOBAL_ARGS.slice(1), GIT_NO_PROGRAM_CONFIG.flatMap((kv) => ["-c", kv]));
  assert.ok(!HARDENED_GIT_GLOBAL_ARGS.includes("--no-lazy-fetch"), "no global option an older git refuses (the env carries it)");
  assert.deepEqual(hardenedGitArgs(["log", "-1"]), [...HARDENED_GIT_GLOBAL_ARGS, "log", "-1"]);
  assert.deepEqual(hardenedGitArgs(["ls-files"], { literalPathspecs: true }), [...HARDENED_GIT_GLOBAL_ARGS, "--literal-pathspecs", "ls-files"]);
});

test("config-based hooks (git 2.54+): every hook event git documents is switched off by event, so no hook name has to be known", () => {
  // githooks(5) of git 2.54, 2.55 and 2.56: the same 28 events.
  const documented = [
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg",
    "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
    "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
    "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-index-change",
  ];
  assert.deepEqual([...GIT_HOOK_EVENTS].sort(), [...documented].sort());
  assert.equal(new Set(GIT_HOOK_EVENTS).size, GIT_HOOK_EVENTS.length, "no event twice");
  for (const e of GIT_HOOK_EVENTS) assert.ok(GIT_NO_PROGRAM_CONFIG.includes(`hook.${e}.enabled=false`), `hook.${e}.enabled forced false`);
  // Only `hook.<event>.enabled` keys: a forced `.command` or `.event` under a
  // known event's name is a fatal error from git 2.55 on.
  for (const kv of GIT_NO_PROGRAM_CONFIG.filter((x) => x.startsWith("hook."))) {
    assert.match(kv, /^hook\.([a-z0-9-]+)\.enabled=false$/, kv);
    assert.ok(GIT_HOOK_EVENTS.includes(/^hook\.([a-z0-9-]+)\./.exec(kv)![1]!), kv);
  }
  // The host's git takes every key quietly (an older git ignores keys it
  // does not know; none is a global option it could refuse).
  const r = spawnSync("git", [...HARDENED_GIT_GLOBAL_ARGS, "version"], { encoding: "utf8", env: hardenedGitEnv(process.env) });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, "", "no warning about the forced keys");
});

test("config-based hooks: a hardened commit in a repository whose config names one for every event runs none (git 2.55+; git 2.54 is §8.6's residual)", (t) => {
  const m = /(\d+)\.(\d+)/.exec(execFileSync("git", ["--version"], { encoding: "utf8" }));
  const [maj, min] = m ? [Number(m[1]), Number(m[2])] : [0, 0];
  const runsThem = maj > 2 || (maj === 2 && min >= 54);
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-cfghook-")));
  dirs.push(dir);
  const root = join(dir, "repo");
  const marker = join(dir, "fired");
  const env = { ...process.env, HOME: dir, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" };
  const git = (...a: string[]): void => { execFileSync("git", a, { cwd: root, env, stdio: "ignore" }); };
  mkdirSync(root);
  git("init", "-q");
  git("commit", "-q", "--allow-empty", "-m", "one");
  for (const e of GIT_HOOK_EVENTS) {
    git("config", `hook.trap-${e}.command`, `echo ${e} >> '${marker}'`);
    git("config", `hook.trap-${e}.event`, e);
  }
  // The control: a stock commit runs the config hooks where this git has them.
  git("commit", "-q", "--allow-empty", "-m", "two");
  assert.equal(existsSync(marker), runsThem, `git ${maj}.${min}: a stock commit runs config hooks exactly from 2.54 on`);
  rmSync(marker, { force: true });
  if (!runsThem) { t.diagnostic(`git ${maj}.${min} runs no config-based hooks: the control is the whole proof here`); return; }
  if (maj === 2 && min === 54) { t.diagnostic("git 2.54: no hook.<event>.enabled switch (write-protection.md §8.6)"); return; }
  execFileSync("git", hardenedGitArgs(["commit", "-q", "--allow-empty", "-m", "three"]), {
    cwd: root, stdio: "ignore",
    env: hardenedGitEnv(env, { GIT_CONFIG_GLOBAL: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" }),
  });
  assert.equal(existsSync(marker), false, "the hardened commit ran no config hook");
});

test("the environment drops every inherited GIT_* and sets the hardened values; the caller's extra goes on top", () => {
  const base = {
    PATH: "/usr/bin", HOME: "/home/u", LANG: "C.UTF-8", UNSET: undefined,
    GIT_DIR: "/elsewhere/.git", GIT_WORK_TREE: "/", GIT_CONFIG_PARAMETERS: "'core.fsmonitor'='/x'", GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "core.pager", GIT_CONFIG_VALUE_0: "/x", GIT_EXTERNAL_DIFF: "/x", GIT_SSH_COMMAND: "/x",
    GIT_EXEC_PATH: "/x", GIT_PAGER: "/x", GIT_EDITOR: "/x", GIT_ASKPASS: "/x", GIT_TRACE: "/tmp/t",
  };
  const env = hardenedGitEnv(base, { GIT_DIR: "/mine/.git", LC_ALL: "C" });
  assert.equal(env["PATH"], "/usr/bin");
  assert.equal(env["HOME"], "/home/u");
  assert.equal("UNSET" in env, false);
  for (const k of ["GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
    "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_PAGER", "GIT_TRACE"]) {
    assert.equal(k in env, false, `${k} is not inherited`);
  }
  for (const [k, v] of Object.entries(HARDENED_GIT_ENV)) assert.equal(env[k], v);
  assert.equal(env["GIT_ASKPASS"], "", "empty, so git does not fall back to core.askPass");
  assert.equal(env["GIT_EDITOR"], ":");
  assert.equal(env["xcrun_nocache"], "1", "macOS: the xcrun shim ignores its per-user cache");
  assert.equal(env["GIT_DIR"], "/mine/.git", "the caller's own GIT_DIR");
  assert.equal(env["LC_ALL"], "C");
});

test("gitCommand: git itself without a sandbox; bubblewrap with its flags, each writable dir bound once, then git", () => {
  assert.deepEqual(gitCommand(["log"], null, ["/w"]), { file: "git", args: ["log"] });
  const sb = { bwrap: "/usr/bin/bwrap", flags: ["--unshare-net", "--ro-bind", "/", "/"] };
  assert.deepEqual(gitCommand(["pack-objects", "p"], sb, ["/cache", "/cache", "/b"]), {
    file: "/usr/bin/bwrap",
    args: ["--unshare-net", "--ro-bind", "/", "/", "--bind", "/cache", "/cache", "--bind", "/b", "/b", "--", "git", "pack-objects", "p"],
  });
});

test("the sandbox's flag sets: no network, a read-only root, no capabilities, new namespaces and session", () => {
  for (const flags of GIT_SANDBOX_FLAG_SETS) {
    for (const f of ["--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session"]) {
      assert.ok(flags.includes(f), `${f} in every set`);
    }
    assert.deepEqual(flags.slice(flags.indexOf("--ro-bind"), flags.indexOf("--ro-bind") + 3), ["--ro-bind", "/", "/"]);
    assert.deepEqual(flags.slice(flags.indexOf("--cap-drop"), flags.indexOf("--cap-drop") + 2), ["--cap-drop", "ALL"]);
    assert.ok(!flags.includes("--bind") && !flags.includes("--dev-bind") && !flags.includes("--share-net"), "nothing writable, no host network");
  }
  assert.ok(GIT_SANDBOX_FLAG_SETS[0]!.includes("--disable-userns"), "the most hardened set first");
});

test("probeGitSandbox (linux): off by MANDU_GIT_SANDBOX=0; Mandu's own root-owned bwrap first; the first flag set that runs git; null when none does", () => {
  const calls: string[] = [];
  const runOk = (ok: (file: string, args: readonly string[]) => boolean) => (file: string, args: readonly string[]) => {
    calls.push(`${file} ${args.includes("--disable-userns") ? "full" : "lite"}`);
    return ok(file, args);
  };
  const linux = { platform: "linux", systemBwrap: () => "bwrap" } as const;
  assert.equal(probeGitSandbox({ ...linux, env: { MANDU_GIT_SANDBOX: "0" }, runOk: () => true }), null);
  const own = probeGitSandbox({ ...linux, env: {}, rootOwned: () => true, runOk: runOk(() => true) });
  assert.deepEqual(own, { bwrap: MANDU_OWN_BWRAP, flags: GIT_SANDBOX_FLAG_SETS[0] });
  calls.length = 0;
  const lite = probeGitSandbox({ ...linux, env: {}, rootOwned: () => false, runOk: runOk((_f, a) => !a.includes("--disable-userns")) });
  assert.deepEqual(lite, { bwrap: "bwrap", flags: GIT_SANDBOX_FLAG_SETS[1] });
  assert.deepEqual(calls, ["bwrap full", "bwrap lite"]);
  const probe = gitCommand(["--version"], lite);
  assert.deepEqual(probe.args.slice(-3), ["--", "git", "--version"], "the probe runs git inside, not just bwrap");
  assert.equal(probeGitSandbox({ ...linux, env: {}, rootOwned: () => true, runOk: () => false }), null, "no working bwrap: none (the hardened git runs as is)");
  assert.deepEqual(probeGitSandboxOutcome({ ...linux, env: {}, rootOwned: () => true, runOk: () => false }), { sandbox: null, transient: false }, "a final none");
  assert.deepEqual(probeGitSandboxOutcome({ ...linux, env: {}, rootOwned: () => false, systemBwrap: () => null,
    run: () => { throw new Error("no candidate: no process to run"); } }), { sandbox: null, transient: false },
  "an absent distribution bwrap is a final none without invoking the runner");
  assert.equal(probeGitSandbox({ platform: "win32", env: {}, runOk: () => true, executable: () => true, resolveGit: () => "/git" }), null, "another platform: none");
  // A run that could not be judged (a timeout, no free process) makes a none
  // that is not final; one that worked still wins.
  assert.deepEqual(probeGitSandboxOutcome({ ...linux, env: {}, rootOwned: () => false, runOk: (_f, a) => (a.includes("--disable-userns") ? "transient" : false) }),
    { sandbox: null, transient: true });
  assert.deepEqual(probeGitSandboxOutcome({ ...linux, env: {}, rootOwned: () => false, runOk: (_f, a) => (a.includes("--disable-userns") ? "transient" : true) }),
    { sandbox: { bwrap: "bwrap", flags: GIT_SANDBOX_FLAG_SETS[1] }, transient: false });
});

test("probe runners retain the sandboxed git version and transient verdict on Linux and macOS", () => {
  for (const platform of ["linux", "darwin"]) {
    const deps = { platform, env: {}, rootOwned: () => false, systemBwrap: () => "/mock/bwrap",
      executable: () => true, resolveGit: () => "/resolved/git" };
    let clock = 0;
    let runs = 0;
    const get = gitSandboxCache({
      env: {}, now: () => clock, executable: () => true,
      probe: () => probeGitSandboxOutcome({ ...deps, run: () => {
        runs++;
        return clock === 0 ? { ok: "transient", stdout: "git version 0.0.0\n" } : { ok: true, stdout: "git version 2.50.0\n" };
      } }),
    });
    assert.equal(get(), null, `${platform}: an inconclusive run never counts as success`);
    const attempts = runs;
    assert.ok(attempts > 0, `${platform}: the candidate was actually probed`);
    assert.equal(get(), null);
    assert.equal(runs, attempts, "retry waits for backoff");
    clock += GIT_SANDBOX_RETRY_MS.first;
    const sandbox = get();
    assert.equal(sandbox?.gitVersion, "git version 2.50.0\n", `${platform}: captured from the sandboxed binary`);
    assert.equal(get(), sandbox, "the successful sandbox and version are cached together");
    assert.equal(runs, attempts + 1, "no second process just to obtain its version");
    assert.equal(probeGitSandbox({ ...deps, run: () => ({ ok: true, stdout: "unrelated output" }) })?.gitVersion,
      undefined, "a successful probe without a version leaves callers free to ask");
    assert.equal(probeGitSandbox({ ...deps, runOk: () => false, run: () => { throw new Error("runOk takes precedence"); } }),
      null, "verdict-only injection takes precedence on both platforms");
  }
});

test("probeRunVerdict: exit 0 runs; a missing program or a failing exit is an answer; a spawn error like EAGAIN, a kill or the timeout is transient", () => {
  const err = (code: string): Error => Object.assign(new Error(code), { code });
  assert.equal(probeRunVerdict({ status: 0, signal: null }), true);
  assert.equal(probeRunVerdict({ status: 1, signal: null }), false);
  assert.equal(probeRunVerdict({ status: 71, signal: null }), false, "inside another profile: a final none");
  for (const code of ["ENOENT", "EACCES", "ENOEXEC", "ENOTDIR"]) assert.equal(probeRunVerdict({ status: null, signal: null, error: err(code) }), false, code);
  for (const code of ["EAGAIN", "ENOMEM", "EMFILE", "ETIMEDOUT"]) assert.equal(probeRunVerdict({ status: null, signal: null, error: err(code) }), "transient", code);
  assert.equal(probeRunVerdict({ status: null, signal: "SIGKILL" }), "transient");
  // The real thing: spawnSync's own timeout, and a program that is not there.
  assert.equal(probeRunVerdict(spawnSync("/bin/sleep", ["5"], { stdio: "ignore", timeout: 100 })), "transient");
  assert.equal(probeRunVerdict(spawnSync("/nonexistent-mandu/bwrap", [], { stdio: "ignore" })), false);
});

test("gitSandboxCache: a final answer is kept; a transient none is not (null for that call, probed again after a doubling backoff); a Seatbelt sandbox whose git is gone is probed again", () => {
  const bwrap = { bwrap: "bwrap", flags: ["--unshare-net"] };
  let clock = 0;
  const outcomes: GitSandboxProbe[] = [];
  let probes = 0;
  const cache = (exec: (p: string) => boolean = () => true) => gitSandboxCache({
    probe: () => { probes++; return outcomes.shift() ?? { sandbox: null, transient: false }; },
    now: () => clock, executable: exec, env: {},
  });
  // Found at once: kept, never probed again.
  outcomes.push({ sandbox: bwrap, transient: false });
  let get = cache();
  assert.equal(get(), bwrap);
  assert.equal(get(), bwrap);
  assert.equal(probes, 1);
  // A final none: kept.
  probes = 0;
  get = cache();
  assert.equal(get(), null);
  clock += GIT_SANDBOX_RETRY_MS.max * 10;
  assert.equal(get(), null);
  assert.equal(probes, 1, "a final none is final");
  // Transient: null now, no probe until the backoff passes, then again; the
  // backoff doubles; the first real answer ends it.
  probes = 0;
  clock = 0;
  outcomes.push({ sandbox: null, transient: true }, { sandbox: null, transient: true }, { sandbox: bwrap, transient: false });
  get = cache();
  assert.equal(get(), null, "the transient call runs as it would with none");
  assert.equal(probes, 1);
  clock += GIT_SANDBOX_RETRY_MS.first - 1;
  assert.equal(get(), null);
  assert.equal(probes, 1, "not before the backoff");
  clock += 1;
  assert.equal(get(), null);
  assert.equal(probes, 2, "probed again, transient again");
  clock += GIT_SANDBOX_RETRY_MS.first;
  assert.equal(get(), null);
  assert.equal(probes, 2, "the backoff doubled");
  clock += GIT_SANDBOX_RETRY_MS.first;
  assert.equal(get(), bwrap, "a later probe finds the sandbox and keeps it");
  assert.equal(probes, 3);
  // A Seatbelt sandbox whose git went away (a `brew upgrade`): probed again,
  // and the new git is used.
  const oldGit: SeatbeltGitSandbox = { sandboxExec: SANDBOX_EXEC, git: "/opt/homebrew/Cellar/git/2.50.0/bin/git" };
  const newGit: SeatbeltGitSandbox = { sandboxExec: SANDBOX_EXEC, git: "/opt/homebrew/Cellar/git/2.51.0/bin/git" };
  const there = new Set([oldGit.git]);
  probes = 0;
  outcomes.push({ sandbox: oldGit, transient: false }, { sandbox: newGit, transient: false });
  get = cache((p) => there.has(p));
  assert.equal(get(), oldGit);
  assert.equal(get(), oldGit);
  assert.equal(probes, 1);
  there.delete(oldGit.git);
  there.add(newGit.git);
  assert.equal(get(), newGit);
  assert.equal(probes, 2);
});

test("gitSandboxCache: once git ran under Seatbelt, no probe turns it off (a swapped git, a transient failure): the last sandbox stays, its gone git fails each call, until a probe finds a working one; MANDU_GIT_SANDBOX=0 still does", () => {
  let clock = 0;
  const outcomes: GitSandboxProbe[] = [];
  let probes = 0;
  const env: Record<string, string | undefined> = {};
  const sb: SeatbeltGitSandbox = { sandboxExec: SANDBOX_EXEC, git: "/opt/homebrew/Cellar/git/2.51.0/bin/git" };
  const there = new Set([sb.git]);
  const get = gitSandboxCache({
    probe: () => { probes++; return outcomes.shift() ?? { sandbox: null, transient: false }; },
    now: () => clock, executable: (p) => there.has(p), env,
  });
  outcomes.push({ sandbox: sb, transient: false });
  assert.equal(get(), sb);
  // The agent moves the git away and points PATH's git at a program that
  // fails the probe: a FINAL none from the probe, and still no downgrade.
  there.delete(sb.git);
  outcomes.push({ sandbox: null, transient: false });
  assert.equal(get(), sb, "fail closed: the sandbox stays (its git is gone, so the call fails)");
  assert.equal(probes, 2);
  const cmd = gitCommand(["rev-parse", "HEAD"], get());
  assert.deepEqual([cmd.file, cmd.args[2]], [SANDBOX_EXEC, sb.git], "never plain git");
  assert.equal(get(), sb, "within the backoff: no probe, still the sandbox");
  assert.equal(probes, 2);
  // A transient probe after that: still the sandbox.
  clock += GIT_SANDBOX_RETRY_MS.first;
  outcomes.push({ sandbox: null, transient: true });
  assert.equal(get(), sb);
  assert.equal(probes, 3);
  // The real git is back: the next probe after the backoff finds it.
  there.add(sb.git);
  clock += GIT_SANDBOX_RETRY_MS.first * 2;
  outcomes.push({ sandbox: sb, transient: false });
  assert.equal(get(), sb);
  assert.equal(probes, 4);
  assert.equal(get(), sb);
  assert.equal(probes, 4, "settled again");
  // The backoff is capped.
  there.delete(sb.git);
  for (let i = 0; i < 20; i++) { clock += GIT_SANDBOX_RETRY_MS.max; outcomes.push({ sandbox: null, transient: false }); get(); }
  const before = probes;
  clock += GIT_SANDBOX_RETRY_MS.max;
  outcomes.push({ sandbox: null, transient: false });
  get();
  assert.equal(probes, before + 1, "a probe at least every GIT_SANDBOX_RETRY_MS.max");
  // The operator's own opt-out is honoured: the probe says none, and so does
  // the cache.
  env["MANDU_GIT_SANDBOX"] = "0";
  clock += GIT_SANDBOX_RETRY_MS.max;
  outcomes.push({ sandbox: null, transient: false });
  assert.equal(get(), null);
});

// ── macOS: the Seatbelt git sandbox (write-protection.md §8) ─────────────────

/** /tmp and /var are links on macOS: their canonical spelling, as the host
 *  resolves it there (injected, so every host renders the same bytes). */
const macCanonical = (p: string): string => p.replace(/^\/(tmp|var)(\/|$)/, "/private/$1$2");

test("gitSeatbeltProfile: byte for byte; the writable paths in both spellings, sorted and deduped; nothing else writable; no fork, no exec but git, no network", () => {
  const got = gitSeatbeltProfile("/Library/Developer/CommandLineTools/usr/bin/git", ["/tmp/cache", "/private/tmp/cache", "/var/folders/x/T/work/", "/tmp/cache"], macCanonical);
  assert.equal(got, [
    "(version 1)",
    "(allow default)",
    "(deny process-fork)",
    "(deny process-exec)",
    "(allow process-exec (literal \"/Library/Developer/CommandLineTools/usr/bin/git\"))",
    "(deny file-write*)",
    "(allow file-write* (literal \"/dev/null\") (subpath \"/private/tmp/cache\") (subpath \"/private/var/folders/x/T/work\") (subpath \"/tmp/cache\") (subpath \"/var/folders/x/T/work\"))",
    "(deny file-read* file-write* (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\"))",
    "(deny network*)",
    "(deny mach-lookup)",
    "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))",
    "(deny appleevent-send)",
    "(deny signal)",
    "(allow signal (target same-sandbox))",
    "(deny ipc-posix-shm*)",
    "(deny ipc-posix-sem* ipc-sysv*)",
    "(deny iokit-open)",
    "",
  ].join("\n"));
  assert.equal(GIT_SEATBELT_MACH_ALLOW, "com.apple.system.opendirectoryd.libinfo");
  // A read binds nothing: /dev/null is the one writable file.
  assert.match(gitSeatbeltProfile("/g", [], macCanonical), /^\(allow file-write\* \(literal "\/dev\/null"\)\)$/m);
  // Relative, `..`-holding and root paths are dropped (the write then fails):
  // a lexical `..` is not what the kernel resolves through a link, and `/`
  // would make everything writable.
  assert.match(gitSeatbeltProfile("/g", ["rel/dir", "/a/../etc", "/", "//", "/./"], macCanonical), /^\(allow file-write\* \(literal "\/dev\/null"\)\)$/m);
  // A canonical spelling that is itself relative or `/` adds nothing.
  assert.match(gitSeatbeltProfile("/g", ["/w"], () => "/"), /^\(allow file-write\* \(literal "\/dev\/null"\) \(subpath "\/w"\)\)$/m);
  // SBPL string literals: backslash and double quote escaped.
  const odd = gitSeatbeltProfile("/o\"dd\\git", ["/w\"q\\x"], (p) => p);
  assert.match(odd, /\(allow process-exec \(literal "\/o\\"dd\\\\git"\)\)/);
  assert.match(odd, /\(subpath "\/w\\"q\\\\x"\)/);
});

test("gitCommand (seatbelt): sandbox-exec and git by absolute path, the rendered profile inline (-p), then git's own arguments", () => {
  const sb = { sandboxExec: SANDBOX_EXEC, git: "/opt/homebrew/Cellar/git/2.51.0/bin/git" };
  assert.equal(isSeatbeltGitSandbox(sb), true);
  assert.equal(isSeatbeltGitSandbox({ bwrap: "/usr/bin/bwrap", flags: [] }), false);
  const cmd = gitCommand(["pack-objects", "-q", "/tmp/c/p"], sb, ["/tmp/c"], macCanonical);
  assert.deepEqual(cmd, {
    file: "/usr/bin/sandbox-exec",
    args: ["-p", gitSeatbeltProfile(sb.git, ["/tmp/c"], macCanonical), "/opt/homebrew/Cellar/git/2.51.0/bin/git", "pack-objects", "-q", "/tmp/c/p"],
  });
  assert.match(cmd.args[1]!, /\(subpath "\/private\/tmp\/c"\) \(subpath "\/tmp\/c"\)/, "the profile carries the bind, in both spellings");
  // The default spelling is the host's realpath of the longest existing
  // prefix: a link to a directory, and a path not made yet below it.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hg-canon-")));
  dirs.push(dir);
  mkdirSync(join(dir, "real"));
  symlinkSync(join(dir, "real"), join(dir, "link"));
  const host = gitCommand(["init"], sb, [join(dir, "link", "not-yet")]);
  assert.match(host.args[1]!, new RegExp(`\\(subpath "${join(dir, "link", "not-yet")}"\\)`));
  assert.match(host.args[1]!, new RegExp(`\\(subpath "${join(dir, "real", "not-yet")}"\\)`));
});

test("canonicalSpelling and SANDBOX_EXEC agree with the launch profile's (seatbelt-profile.ts canonicalPath, SANDBOX_EXEC)", () => {
  assert.equal(SANDBOX_EXEC, PROFILE_SANDBOX_EXEC);
  const realpath = (p: string): string | null => { try { return realpathSync(p); } catch { return null; } };
  const dir = mkdtempSync(join(tmpdir(), "mdu-hg-canon-"));
  dirs.push(dir);
  for (const p of [dir, join(dir, "a", "b"), tmpdir(), "/tmp", "/tmp/mandu-none/x", "/var/folders", "/", "/nonexistent-mandu/x/y", "/etc/hosts"]) {
    assert.equal(canonicalSpelling(p), canonicalPath(p, realpath), p);
  }
  // Injected: the longest existing prefix resolves, the rest is kept.
  const fake = (p: string): string | null => (p === "/tmp" ? "/private/tmp" : p === "/" ? "/" : null);
  assert.equal(canonicalSpelling("/tmp/a/b", fake), "/private/tmp/a/b");
  assert.equal(canonicalSpelling("/x/y", fake), "/x/y");
  assert.equal(canonicalSpelling("rel", fake), "rel");
});

test("probeGitSandbox (darwin): off by MANDU_GIT_SANDBOX=0; no sandbox-exec, no git, or git not running under it (inside another profile: exit 71) → none; else sandbox-exec with the resolved git", () => {
  const darwin = { platform: "darwin" } as const;
  const git = "/Library/Developer/CommandLineTools/usr/bin/git";
  const calls: Array<{ file: string; args: readonly string[] }> = [];
  const runOk = (ok: boolean | "transient") => (file: string, args: readonly string[]): boolean | "transient" => { calls.push({ file, args }); return ok; };
  const executable = (p: string): boolean => p === SANDBOX_EXEC;
  assert.equal(probeGitSandbox({ ...darwin, env: { MANDU_GIT_SANDBOX: "0" }, runOk: runOk(true), executable, resolveGit: () => git }), null);
  assert.equal(calls.length, 0, "off: nothing probed");
  assert.equal(probeGitSandbox({ ...darwin, env: {}, runOk: runOk(true), executable: () => false, resolveGit: () => git }), null, "no /usr/bin/sandbox-exec");
  assert.equal(probeGitSandbox({ ...darwin, env: {}, runOk: runOk(true), executable, resolveGit: () => null }), null, "no git");
  assert.deepEqual(probeGitSandboxOutcome({ ...darwin, env: {}, runOk: runOk(true), executable, resolveGit: () => "transient" }), { sandbox: null, transient: true },
    "git's --exec-path could not be judged: a none that is not final");
  assert.equal(calls.length, 0, "nothing to run");
  assert.deepEqual(probeGitSandboxOutcome({ ...darwin, env: {}, runOk: runOk(false), executable, resolveGit: () => git }), { sandbox: null, transient: false },
    "git did not run under it (exit 71 inside another profile): a final none (the hardened git runs as is)");
  assert.deepEqual(probeGitSandboxOutcome({ ...darwin, env: {}, runOk: runOk("transient"), executable, resolveGit: () => git }), { sandbox: null, transient: true },
    "the run could not be judged (a timeout, no free process): not final");
  const ok = probeGitSandbox({ ...darwin, env: {}, runOk: runOk(true), executable, resolveGit: () => git });
  assert.deepEqual(ok, { sandboxExec: "/usr/bin/sandbox-exec", git });
  // The probe runs git itself under the very profile a read gets.
  assert.deepEqual(calls.at(-1), { file: "/usr/bin/sandbox-exec", args: ["-p", gitSeatbeltProfile(git, []), git, "--version"] });
  // The bubblewrap candidates are never tried on macOS.
  assert.ok(calls.every((c) => c.file === SANDBOX_EXEC));
});

test("resolveGitBinary: PATH's first executable git (absolute entries only), resolved; then the real binary its --exec-path names (the Apple shim's developer-directory git); --exec-path runs sandboxed, as is only for a root-only system binary", () => {
  const files: Record<string, string> = {
    "/usr/bin/git": "/usr/bin/git", // the xcrun shim: a real file
    "/Library/Developer/CommandLineTools/usr/libexec/git-core/git": "/Library/Developer/CommandLineTools/usr/bin/git",
    "/Library/Developer/CommandLineTools/usr/bin/git": "/Library/Developer/CommandLineTools/usr/bin/git",
    "/opt/homebrew/bin/git": "/opt/homebrew/Cellar/git/2.51.0/bin/git",
    "/opt/homebrew/Cellar/git/2.51.0/bin/git": "/opt/homebrew/Cellar/git/2.51.0/bin/git",
    "/opt/homebrew/Cellar/git/2.51.0/libexec/git-core/git": "/opt/homebrew/Cellar/git/2.51.0/libexec/git-core/git",
    "/Users/u/.local/bin/git": "/Users/u/.local/bin/git", // planted by the agent
    "/opt/evil/bin/git": "/bin/sh", // a link the agent points at a root-owned binary
    "/bin/sh": "/bin/sh",
    "./git": "./git",
  };
  const executable = (p: string): boolean => p in files;
  const realpath = (p: string): string | null => files[p] ?? null;
  const systemOwned = (p: string): boolean => p === "/usr/bin/git" || p === "/bin/sh" || p.startsWith("/Library/Developer/");
  const asked: string[] = [];
  // The shim must exec xcrun's pick, which the git profile refuses: its
  // sandboxed run fails; a real git answers inside the sandbox.
  const execPath = (g: string, boxed: boolean): string | null => {
    asked.push(`${g} ${boxed ? "boxed" : "PLAIN"}`);
    if (g === "/usr/bin/git") return boxed ? null : "/Library/Developer/CommandLineTools/usr/libexec/git-core";
    if (g.startsWith("/opt/homebrew/Cellar/")) return "/opt/homebrew/Cellar/git/2.51.0/libexec/git-core/";
    return null;
  };
  const deps = { executable, realpath, execPath, systemOwned };
  assert.equal(resolveGitBinary({ ...deps, path: ".:relative/bin:/nowhere:/usr/bin:/bin" }), "/Library/Developer/CommandLineTools/usr/bin/git",
    "a relative entry is skipped; the shim becomes the Command Line Tools' git");
  assert.deepEqual(asked, ["/usr/bin/git boxed", "/usr/bin/git PLAIN"], "the root-only shim is asked as is only after its sandboxed run failed");
  asked.length = 0;
  assert.equal(resolveGitBinary({ ...deps, path: "/opt/homebrew/bin:/usr/bin" }), "/opt/homebrew/Cellar/git/2.51.0/libexec/git-core/git",
    "Homebrew's git: the one in its exec path (a real file there)");
  assert.deepEqual(asked, ["/opt/homebrew/Cellar/git/2.51.0/bin/git boxed"], "a git the user can write answers inside the sandbox");
  asked.length = 0;
  assert.equal(resolveGitBinary({ ...deps, path: "/Users/u/.local/bin:/usr/bin" }), "/Users/u/.local/bin/git", "a planted git: PATH's first, as found");
  assert.deepEqual(asked, ["/Users/u/.local/bin/git boxed"], "a planted git never runs outside the sandbox, not even to answer --exec-path");
  asked.length = 0;
  assert.equal(resolveGitBinary({ ...deps, path: "/opt/evil/bin:/usr/bin" }), "/bin/sh");
  assert.deepEqual(asked, ["/bin/sh boxed"], "a root-owned binary that is not the Apple shim is never asked as is either");
  asked.length = 0;
  assert.equal(resolveGitBinary({ ...deps, systemOwned: () => false, path: "/usr/bin" }), "/usr/bin/git");
  assert.deepEqual(asked, ["/usr/bin/git boxed"], "the shim is asked as is only while it is root's alone");
  assert.equal(resolveGitBinary({ ...deps, execPath: () => null, path: "/opt/homebrew/bin" }), "/opt/homebrew/Cellar/git/2.51.0/bin/git",
    "no answer from --exec-path: PATH's git, resolved");
  assert.equal(resolveGitBinary({ ...deps, execPath: () => null, path: "/usr/bin" }), "/usr/bin/git",
    "the shim with no developer directory (no Command Line Tools): the shim itself, which the probe then cannot run");
  assert.equal(resolveGitBinary({ ...deps, execPath: () => "relative/git-core", path: "/usr/bin" }), "/usr/bin/git", "a relative exec path is not used");
  assert.equal(resolveGitBinary({ ...deps, execPath: () => "transient", path: "/usr/bin" }), "transient", "an --exec-path that could not be judged");
  assert.equal(resolveGitBinary({ ...deps, execPath: (_g, boxed) => (boxed ? null : "transient"), path: "/usr/bin" }), "transient");
  assert.equal(resolveGitBinary({ ...deps, path: "/nowhere:rel" }), null, "no git on PATH");
  assert.equal(resolveGitBinary({ ...deps, path: "" }), null);
});

test("eolConfigArgs / scratchGitConfig: the end-of-line settings, last value wins, a bare key is true; the scratch config per object format", () => {
  assert.deepEqual(eolConfigArgs(""), []);
  assert.deepEqual(eolConfigArgs("core.autocrlf\ninput\0core.eol\ncrlf\0core.autocrlf\nfalse\0"), ["-c", "core.autocrlf=false", "-c", "core.eol=crlf"]);
  assert.deepEqual(eolConfigArgs("core.autocrlf\0"), ["-c", "core.autocrlf=true"]);
  assert.deepEqual(eolConfigArgs("core.fsmonitor\n/x\0"), [], "only the end-of-line keys");
  assert.match(scratchGitConfig("sha1"), /repositoryformatversion = 0/);
  assert.doesNotMatch(scratchGitConfig("sha1"), /objectFormat/);
  assert.match(scratchGitConfig("sha256"), /repositoryformatversion = 1[\s\S]*objectFormat = sha256/);
});

const CLEAN_ENV = {
  PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
};

/** A repository with CRLF files under `text eol=lf`, one of them also under
 *  a planted clean filter (a marker program) and the other under an
 *  `ident` attribute; the control twin has the same attributes and no
 *  filter config, so `git add` there stores what a driver-free add would. */
function eolRepos(format: "sha1" | "sha256"): { root: string; control: string; marker: string } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hg-unit-")));
  dirs.push(dir);
  const marker = join(dir, "fired");
  const prog = join(dir, "clean.sh");
  writeFileSync(prog, `#!/bin/sh\necho ran >> '${marker}'\ncat\n`);
  chmodSync(prog, 0o755);
  const make = (name: string, hostile: boolean): string => {
    const root = join(dir, name);
    mkdirSync(root);
    execFileSync("git", ["init", "-q", `--object-format=${format}`], { cwd: root, env: CLEAN_ENV });
    writeFileSync(join(root, ".gitattributes"), "crlf.txt text eol=lf filter=evil\nid.txt text ident\n");
    writeFileSync(join(root, "crlf.txt"), "a\r\nb\r\n");
    writeFileSync(join(root, "id.txt"), "v $Id: stale $\r\n");
    writeFileSync(join(root, "raw.bin"), "\0\x01binary\r\n");
    if (hostile) {
      execFileSync("git", ["config", "filter.evil.clean", prog], { cwd: root, env: CLEAN_ENV });
      execFileSync("git", ["config", "filter.evil.required", "true"], { cwd: root, env: CLEAN_ENV });
      execFileSync("git", ["config", "core.fsmonitor", prog], { cwd: root, env: CLEAN_ENV });
    }
    return root;
  };
  return { root: make("hostile", true), control: make("control", false), marker };
}

for (const format of ["sha1", "sha256"] as const) {
  test(`worktreeBlobNames (${format}): the name git add gives a CRLF / ident file without a driver, and the raw bytes' name; the planted clean filter never runs`, async () => {
    const { root, control, marker } = eolRepos(format);
    const rels = ["crlf.txt", "id.txt", "raw.bin"];
    const got = await worktreeBlobNames(defaultGitRunner, root, rels);
    assert.equal(existsSync(marker), false, "the repository's clean filter (and fsmonitor) did not run");
    execFileSync("git", ["add", "--", ...rels], { cwd: control, env: CLEAN_ENV });
    const added = execFileSync("git", ["ls-files", "-s", "--", ...rels], { cwd: control, env: CLEAN_ENV, encoding: "utf8" })
      .trim().split("\n").map((l) => l.split(/\s+/)[1]!);
    for (const b of added) assert.ok(got.includes(b), `git add's blob ${b} is among the names`);
    const raw = execFileSync("git", ["hash-object", "--no-filters", "--", ...rels], { cwd: control, env: CLEAN_ENV, encoding: "utf8" }).trim().split("\n");
    for (const b of raw) assert.ok(got.includes(b), `the raw bytes' blob ${b} is among the names`);
    assert.ok(got.every((b) => b.length === (format === "sha256" ? 64 : 40)));
  });
}

test("the pack rebuild's writers (pack-objects, and index-pack rebuilding the index from the content) bind the pack cache; no other call binds anything", async () => {
  // In the git sandbox a call writes only where it binds: index-pack writes
  // the rebuilt .idx and .rev beside the new pack, in the cache (without the
  // bind it failed EROFS on every cache miss where bubblewrap works).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hgit-binds-")));
  dirs.push(dir);
  const ws = join(dir, "ws");
  mkdirSync(ws);
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" };
  const g = (...a: string[]): string => execFileSync("git", a, { cwd: ws, env, encoding: "utf8" });
  g("init", "-q");
  writeFileSync(join(ws, "secret.env"), "TOKEN=one\n");
  writeFileSync(join(ws, "README"), "readme\n");
  g("add", "."); g("commit", "-qm", "one");
  writeFileSync(join(ws, "secret.env"), "TOKEN=two\n");
  g("commit", "-qam", "two");
  g("repack", "-adq");
  const cacheDir = join(dir, "cache");
  mkdirSync(cacheDir);
  const denyFile = join(dir, "deny");
  writeFileSync(denyFile, "", { mode: 0o000 });
  const calls: Array<{ args: string[]; writable: readonly string[] }> = [];
  const got = await prepareGitObjectTwins([join(ws, "secret.env")], {
    cacheDir, denyFile,
    git: (args, opts) => { calls.push({ args, writable: opts.writable ?? [] }); return defaultGitRunner(args, opts); },
  });
  assert.equal(got.packsRebuilt, 1);
  const writes = (c: { args: string[] }): boolean => c.args.includes("pack-objects") || c.args.includes("index-pack");
  assert.deepEqual(calls.filter(writes).map((c) => c.args.find((a) => a === "pack-objects" || a === "index-pack")), ["pack-objects", "index-pack"]);
  for (const c of calls.filter(writes)) assert.deepEqual(c.writable, [cacheDir], `${c.args.join(" ")}: binds the pack cache`);
  for (const c of calls.filter((x) => !writes(x))) assert.deepEqual(c.writable, [], `${c.args.join(" ")}: a read binds nothing`);
});

test("worktreeBlobNames: no path, no git", async () => {
  let calls = 0;
  const got = await worktreeBlobNames(async () => { calls++; return { code: 0, stdout: "", stderr: "" }; }, "/nowhere", []);
  assert.deepEqual(got, []);
  assert.equal(calls, 0);
});
