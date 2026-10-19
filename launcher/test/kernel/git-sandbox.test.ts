/**
 * kernel — the git sandbox (hardened-git.ts `gitSandbox`, docs/design/
 * write-protection.md §8.5): defense in depth for the hardened git calls the
 * launcher and the arbiter run on repositories an agent can write.
 *
 * The hardening keeps every program a repository names from starting; this
 * file proves what the sandbox adds should one start anyway (a vector not
 * known today): a program git runs inside it (here a clean filter, run on
 * purpose, with none of the hardening) cannot write outside the directories
 * the call binds, cannot reach the host's network (a TCP server on the
 * host's loopback sees no connection) and runs with no capabilities; the
 * launcher's production runner, sandboxed, still builds a sanitized pack
 * (the pack cache is its one writable directory), and a deadline landing
 * in bubblewrap's start-up still settles the call and leaves no sandbox
 * child behind (§5.1). A git SESSION (git-session.ts, §8.5.3) runs all its
 * calls in ONE such sandbox (one pid and net namespace, no capability,
 * read-only), answers byte for byte as the per-call runner, and fails closed
 * (a deadline, a straggler, the runner killed) with nothing left behind.
 *
 * Self-SKIPs where bubblewrap cannot make the sandbox (no bwrap, no
 * unprivileged user namespaces, an AppArmor restriction). The macOS
 * (Seatbelt) sandbox refuses with EPERM and has no /proc: its counterpart is
 * test/darwin/git-sandbox-live.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gitCommand, gitSandbox, hardenedGitEnv, isSeatbeltGitSandbox, probeGitSandbox } from "../../src/hardened-git.js";
import { defaultGitRunner, prepareGitObjectTwins } from "../../src/git-object-twins.js";
import { openGitSession, perCallGitRunner, type GitSession } from "../../src/git-session.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the sandbox wraps the git the confidentiality axis's launch prep runs

const probed = probeGitSandbox({ env: {} });
const sandbox = probed !== null && !isSeatbeltGitSandbox(probed) ? probed : null;
const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const ENV = {
  PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
};

test("a program git starts inside the sandbox writes only where the call binds, reaches no network, holds no capability", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-git-sandbox-")));
  dirs.push(dir);
  const repo = join(dir, "repo");
  const inside = join(dir, "writable");
  const outside = join(dir, "outside-marker");
  mkdirSync(repo);
  mkdirSync(inside);
  execFileSync("git", ["init", "-q"], { cwd: repo, env: ENV });
  writeFileSync(join(repo, "f.txt"), "content\n");

  let connections = 0;
  const server = createServer((s) => { connections++; s.destroy(); });
  await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
  const port = (server.address() as { port: number }).port;

  const prog = join(dir, "filter.cjs");
  writeFileSync(prog, `#!/usr/bin/env node
const fs = require("fs"), net = require("net");
const report = (k, v) => fs.appendFileSync(${JSON.stringify(join(inside, "report"))}, k + "=" + v + "\\n");
try { fs.writeFileSync(${JSON.stringify(outside)}, "escaped\\n"); report("outside", "written"); } catch (e) { report("outside", e.code); }
try { fs.writeFileSync(${JSON.stringify(join(dir, "repo", "planted"))}, "x"); report("repo", "written"); } catch (e) { report("repo", e.code); }
const caps = fs.readFileSync("/proc/self/status", "utf8").match(/^CapEff:\\s*(\\S+)/m);
report("capeff", caps ? caps[1] : "?");
const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const s = net.connect(${port}, "127.0.0.1");
  const done = (v) => { report("net", v); process.stdout.write(Buffer.concat(chunks)); };
  s.setTimeout(3000, () => { s.destroy(); done("timeout"); });
  s.on("connect", () => { s.destroy(); done("connected"); });
  s.on("error", (e) => done(e.code));
});
`);
  chmodSync(prog, 0o755);

  // The program runs on purpose: the filter is passed on the command line and
  // none of the hardening applies. Only the sandbox stands in its way.
  const cmd = gitCommand(["-c", `filter.x.clean=${prog}`, "-c", "filter.x.required=true", "hash-object", "--", "f.txt"], sandbox, [inside]);
  writeFileSync(join(repo, ".gitattributes"), "f.txt filter=x\n");
  const child = spawn(cmd.file, cmd.args, { cwd: repo, env: hardenedGitEnv(process.env), stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", (c) => { err += c; });
  const code = await new Promise<number | null>((res) => child.on("close", res));
  server.close();
  assert.equal(code, 0, `git ran in the sandbox: ${err}`);
  assert.match(out.trim(), /^[0-9a-f]{40}$/);

  const report = Object.fromEntries(readFileSync(join(inside, "report"), "utf8").trim().split("\n").map((l) => l.split("=")));
  assert.equal(existsSync(outside), false, "nothing written outside the bound directory");
  assert.equal(report["outside"], "EROFS");
  assert.equal(existsSync(join(repo, "planted")), false, "the repository itself is read-only");
  assert.equal(report["repo"], "EROFS");
  assert.equal(report["capeff"], "0000000000000000", "no capability");
  assert.notEqual(report["net"], "connected");
  assert.equal(connections, 0, "the host's loopback saw no connection");
});

test("the launcher's production runner, sandboxed, still rebuilds a sanitized pack into its cache", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-git-sandbox-")));
  dirs.push(dir);
  const ws = join(dir, "ws");
  mkdirSync(ws);
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: ws, env: ENV, encoding: "utf8" });
  git("init", "-q");
  writeFileSync(join(ws, "secret.env"), "TOKEN=one\n");
  writeFileSync(join(ws, "README"), "readme\n");
  git("add", "."); git("commit", "-qm", "one");
  writeFileSync(join(ws, "secret.env"), "TOKEN=two\n");
  git("commit", "-qam", "two");
  git("repack", "-adq");
  const cacheDir = join(dir, "cache");
  mkdirSync(cacheDir);
  const denyFile = join(dir, "deny");
  closeSync(openSync(denyFile, "w", 0o000));
  const saved = process.env["MANDU_GIT_SANDBOX"];
  delete process.env["MANDU_GIT_SANDBOX"];
  try {
    assert.notEqual(gitSandbox(), null, "the production runner runs git sandboxed here");
    const got = await prepareGitObjectTwins([join(ws, "secret.env")], { cacheDir, denyFile });
    assert.equal(got.repos, 1);
    assert.equal(got.packsRebuilt, 1, "pack-objects wrote the sanitized pack into the cache from inside the sandbox");
  } finally {
    if (saved !== undefined) process.env["MANDU_GIT_SANDBOX"] = saved;
  }
});

// write-protection.md §8.5.1: bubblewrap's sandbox child blocks on an eventfd
// until its parent has set it up and binds its life to that parent only
// later. A deadline that killed bubblewrap alone in that window (node's own
// execFile kill) left the child reparented to init, blocked forever, holding
// the pipes: the call never settled. The runner kills the whole process
// group, so every call settles and no sandbox child outlives it. Deadlines
// of 1 to 8 ms land in bubblewrap's start-up; each call carries a marker in
// its arguments so a leftover is found in /proc.
test("the launcher's production runner, its deadline landing in bubblewrap's start-up: every call settles, no sandbox child is left", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  const saved = process.env["MANDU_GIT_SANDBOX"];
  delete process.env["MANDU_GIT_SANDBOX"];
  try {
    assert.notEqual(gitSandbox(), null, "the production runner runs git sandboxed here");
    const marker = `mandu.orphan-probe=${process.pid}-${Date.now()}`;
    const runs = 256;
    let next = 0;
    const unsettled: number[] = [];
    const lane = async (): Promise<void> => {
      while (next < runs) {
        const i = next++;
        let timer: NodeJS.Timeout | undefined;
        const settled = await Promise.race([
          defaultGitRunner(["-c", marker, "--version"], { cwd: tmpdir(), timeoutMs: 1 + Math.floor(Math.random() * 8) }).then(() => true),
          new Promise<boolean>((res) => { timer = setTimeout(() => res(false), 15_000); }),
        ]);
        clearTimeout(timer);
        if (!settled) unsettled.push(i);
      }
    };
    await Promise.all(Array.from({ length: 16 }, lane));
    // A killed process takes a moment to go: a leftover is one still there
    // after three seconds (a zombie is gone: its cmdline reads empty).
    const leftovers = (): string[] => readdirSync("/proc").filter((p) => /^\d+$/.test(p)).flatMap((pid) => {
      let cmd = "";
      try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8"); } catch { return []; }
      return cmd.includes(marker) ? [`${pid}: ${cmd.split("\0").slice(0, 3).join(" ")}`] : [];
    });
    let left = leftovers();
    for (let end = Date.now() + 3000; left.length > 0 && Date.now() < end; left = leftovers()) await new Promise((r) => setTimeout(r, 50));
    for (const l of left) { try { process.kill(Number(l.split(":")[0]), "SIGKILL"); } catch { /* gone */ } }
    assert.deepEqual(unsettled, [], "a call never settled (its sandbox child held the output)");
    assert.deepEqual(left, [], "a sandbox child outlived its call");
  } finally {
    if (saved !== undefined) process.env["MANDU_GIT_SANDBOX"] = saved;
  }
});

// ── One sandbox for a launch's calls (git-session.ts, write-protection.md §8.5.3) ──

const sessions: GitSession[] = [];
after(() => { for (const x of sessions) x.close(); });
const sandboxed = () => sandbox;
/** A session over the probed sandbox (the real bubblewrap, the real flags). */
function realSession(extra: { closeGraceMs?: number } = {}): GitSession {
  // Yama pinned on: the session mechanism under test (the host rule has its unit test).
  const x = openGitSession({ sandbox: sandboxed, ptraceScope: () => 1, ...extra });
  sessions.push(x);
  return x;
}
/** A stand-in `git` (sh) first on PATH for `fn`; PATH restored after. */
async function withFakeGit<T>(body: string, fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-git-session-")));
  dirs.push(dir);
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin", "git"), `#!/bin/sh\nfor a; do last=$a; done\n${body}\n`);
  chmodSync(join(dir, "bin", "git"), 0o755);
  const saved = process.env["PATH"];
  process.env["PATH"] = `${join(dir, "bin")}:${saved ?? "/usr/bin:/bin"}`;
  try { return await fn(dir); } finally { process.env["PATH"] = saved; }
}
/** Host processes whose command line holds `marker` (pid: cmdline). */
const withMarker = (marker: string): string[] => readdirSync("/proc").filter((p) => /^\d+$/.test(p)).flatMap((pid) => {
  let cmd = "";
  try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8"); } catch { return []; }
  return cmd.includes(marker) ? [`${pid}: ${cmd.split("\0").join(" ")}`] : [];
});
/** Wait up to three seconds for every process holding `marker` to go; the
 *  ones still there (killed now). */
async function noneLeft(marker: string): Promise<string[]> {
  let left = withMarker(marker);
  for (const end = Date.now() + 3000; left.length > 0 && Date.now() < end; left = withMarker(marker)) await new Promise((r) => setTimeout(r, 50));
  for (const l of left) { try { process.kill(Number(l.split(":")[0]), "SIGKILL"); } catch { /* gone */ } }
  return left;
}

/** The namespaces and effective capabilities of each host process whose
 *  command line holds `marker`, once `n` of them run (read from the host's
 *  /proc: the session's own /proc is empty). */
async function hostViewOf(marker: string, n: number): Promise<string[]> {
  const end = Date.now() + 10_000;
  let pids: string[] = [];
  while (Date.now() < end) {
    pids = withMarker(marker).map((l) => l.split(":")[0]!).filter((pid) => {
      try { return readFileSync(`/proc/${pid}/comm`, "utf8").trim() === "sh"; } catch { return false; }
    });
    if (pids.length >= n) break;
    await new Promise((r) => setTimeout(r, 20));
  }
  return pids.map((pid) => {
    const cap = /^CapEff:\s*(\S+)/m.exec(readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? "?";
    return `pid=${readlinkSync(`/proc/${pid}/ns/pid`)} net=${readlinkSync(`/proc/${pid}/ns/net`)} cap=${cap}`;
  });
}

const HOLD = `echo "procs=$(ls -A /proc | wc -l)"; if (: > "$OUT/escaped") 2>/dev/null; then echo wrote; else echo read-only; fi; if [ "$last" = hold ]; then sh -c 'sleep 2; :' "$MARK"; fi`;

test("a git session runs every call in ONE sandbox (one pid and net namespace, no capability, read-only, an empty /proc); the per-call runner makes one per call", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  await withFakeGit(HOLD, async (dir) => {
    const mark = `mandu.ns-probe-${process.pid}-${Date.now()}`;
    const x = realSession();
    const run = x.runner();
    const sessionCalls = Promise.all(Array.from({ length: 6 }, () => run(["hold"], { cwd: dir, env: { OUT: dir, MARK: `${mark}-s` } })));
    const inSession = await hostViewOf(`${mark}-s`, 6);
    const viaSession = await sessionCalls;
    const perCall = perCallGitRunner(undefined, sandboxed);
    const perCallCalls = Promise.all(Array.from({ length: 3 }, () => perCall(["hold"], { cwd: dir, env: { OUT: dir, MARK: `${mark}-p` } })));
    const inPerCall = await hostViewOf(`${mark}-p`, 3);
    const viaPerCall = await perCallCalls;
    const host = `pid=${readlinkSync("/proc/self/ns/pid")}`;
    const hostNet = `net=${readlinkSync("/proc/self/ns/net")}`;
    assert.equal(inSession.length, 6);
    assert.equal(inPerCall.length, 3);
    for (const v of [...inSession, ...inPerCall]) {
      assert.match(v, / cap=0000000000000000$/, "no capability");
      assert.ok(!v.includes(host) && !v.includes(hostNet), "not the host's pid or net namespace");
    }
    assert.equal(new Set(inSession).size, 1, "every session call in the same sandbox");
    assert.equal(new Set(inPerCall.map((v) => v.split(" ")[0])).size, 3, "one sandbox per call");
    for (const r of viaSession) assert.deepEqual([r.code, r.stdout], [0, "procs=0\nread-only\n"], "an empty /proc, nothing written");
    for (const r of viaPerCall) assert.match(r.stdout, /^procs=[1-9]\d*\nread-only\n$/, "the per-call sandbox keeps its own procfs");
    assert.equal(existsSync(join(dir, "escaped")), false);
    assert.deepEqual([x.stats.sandboxes, x.stats.inSession, x.stats.perCall], [1, 6, 0]);
  });
});

test("a git session's /proc shows no sibling call and not the host's: no /proc/<pid>/fd, environ or mem to open; git still works", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  await withFakeGit([
    `case "$last" in`,
    `  hold) sh -c 'sleep 3; :' "$MARK";;`,
    `  probe) for p in 1 2 3 4 5 6 7 8 9 self thread-self "$HOSTPID"; do`,
    `      for f in fd environ mem status; do if (cat "/proc/$p/$f" >/dev/null) 2>/dev/null || (ls "/proc/$p/$f" >/dev/null) 2>/dev/null; then echo "OPENED /proc/$p/$f"; fi; done`,
    `    done; echo "entries=$(ls -A /proc | wc -l)"; if (: > /proc/planted) 2>/dev/null; then echo "WROTE /proc"; fi; echo done;;`,
    `esac`,
  ].join("\n"), async (dir) => {
    const mark = `mandu.proc-probe-${process.pid}-${Date.now()}`;
    const run = realSession().runner();
    const holding = run(["hold"], { cwd: dir, env: { MARK: mark } });
    assert.equal((await hostViewOf(mark, 1)).length, 1, "a sibling call is running");
    const probe = await run(["probe"], { cwd: dir, env: { HOSTPID: String(process.pid) } });
    assert.equal(probe.code, 0, probe.stderr);
    assert.equal(probe.stdout, "entries=0\ndone\n", "nothing under /proc: no sibling, no runner, no host process, not itself; read-only");
    assert.equal((await holding).code, 0);
    // The probe is not vacuous: with a procfs (the per-call sandbox) it opens.
    const control = await perCallGitRunner(undefined, sandboxed)(["probe"], { cwd: dir, env: { HOSTPID: String(process.pid) } });
    assert.match(control.stdout, /OPENED \/proc\/self\/status/);
  });
  // Real git, in that /proc-less sandbox.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-git-session-")));
  dirs.push(dir);
  execFileSync("git", ["init", "-q"], { cwd: dir, env: ENV });
  writeFileSync(join(dir, "f.txt"), "one\n");
  execFileSync("git", ["add", "."], { cwd: dir, env: ENV });
  execFileSync("git", ["commit", "-qm", "one"], { cwd: dir, env: ENV });
  const run = realSession().runner();
  for (const args of [["rev-parse", "HEAD"], ["log", "--format=%s"], ["rev-list", "--all"], ["ls-files", "-s"], ["cat-file", "-p", "HEAD:f.txt"], ["for-each-ref"], ["config", "-z", "--get-regexp", "^core\\."]]) {
    const r = await run(args, { cwd: dir });
    assert.equal(r.code, 0, `${args.join(" ")}: ${r.stderr}`);
    assert.notEqual(r.stdout, "");
  }
});

test("a git session in the real sandbox answers byte for byte as the per-call sandboxed runner, a death by signal included", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-git-session-")));
  dirs.push(dir);
  const repo = join(dir, "repo");
  mkdirSync(repo);
  const g = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: ENV, encoding: "utf8" });
  g("init", "-q");
  writeFileSync(join(repo, "f.txt"), "one\n");
  writeFileSync(join(repo, "bin.dat"), Buffer.concat([Buffer.from([0xff, 0xc3]), Buffer.alloc(150_000, "x")]));
  g("add", ".");
  g("commit", "-qm", "one");
  const calls: Array<[string[], { cwd: string; input?: string }]> = [
    [["rev-parse", "--show-object-format", "--git-common-dir"], { cwd: repo }],
    [["config", "--get", "no.such"], { cwd: repo }],
    [["rev-list", "--all", "--no-walk"], { cwd: repo }],
    [["ls-files", "-z", "-s"], { cwd: repo }],
    [["cat-file", "-p", "HEAD:bin.dat"], { cwd: repo }],
    [["hash-object", "--stdin"], { cwd: repo, input: "hello\n" }],
    [["show", "no-such-ref"], { cwd: repo }],
  ];
  const run = realSession().runner();
  const perCall = perCallGitRunner(undefined, sandboxed);
  const got = await Promise.all(calls.map(([a, o]) => run(a, o)));
  for (let i = 0; i < calls.length; i++) assert.deepEqual(got[i], await perCall(calls[i]![0], calls[i]![1]), calls[i]![0].join(" "));
  await withFakeGit(`kill -TERM $$`, async (fake) => {
    const a = await realSession().runner()(["x"], { cwd: fake });
    const b = await perCall(["x"], { cwd: fake });
    assert.deepEqual([a.code, b.code], [143, 143], "bubblewrap's 128 + SIGTERM, in both");
  });
});

test("a git session fails closed and leaves nothing behind: a deadline kills just its call, a straggler or a killed runner ends the sandbox and fails the calls in flight", { skip: sandbox === null ? "bubblewrap cannot make the git sandbox here" : false }, async () => {
  const mark = `mandu.session-probe-${process.pid}-${Date.now()}`;
  await withFakeGit([
    `case "$last" in`,
    `  hang) sh -c 'sleep 30; :' ${mark}-hang & sleep 30;;`,
    `  escape) perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV' sh -c 'sleep 30; :' ${mark}-escape & sleep 0.5; exit 0;;`,
    `  slow) sh -c 'sleep 30; :' ${mark}-slow; exit 0;;`,
    `  *) echo "ok $last";;`,
    `esac`,
  ].join("\n"), async (dir) => {
    const x = realSession({ closeGraceMs: 500 });
    const run = x.runner();
    const [hung, ok] = await Promise.all([run(["hang"], { cwd: dir, timeoutMs: 1500 }), run(["a"], { cwd: dir })]);
    assert.equal(hung.code, 1);
    assert.match(hung.stderr, /killed at its 1500 ms deadline/);
    assert.deepEqual([ok.code, ok.stdout], [0, "ok a\n"], "the other call ran on");
    assert.deepEqual(await noneLeft(`${mark}-hang`), [], "the deadline killed the call's whole group inside the sandbox");
    assert.equal(x.stats.sandboxes, 1);

    // A process outside the call's group holding its output: the call fails
    // and the whole sandbox goes, the straggler and the calls in flight with it.
    const [esc, slow] = await Promise.all([run(["escape"], { cwd: dir }), run(["slow"], { cwd: dir })]);
    assert.equal(esc.code, 1);
    assert.match(esc.stderr, /kept its output open/);
    assert.equal(slow.code, 1);
    assert.deepEqual(await noneLeft(`${mark}-escape`), [], "the straggler died with the sandbox");
    assert.deepEqual(await noneLeft(`${mark}-slow`), []);
    assert.equal((await run(["later"], { cwd: dir })).stdout, "ok later\n", "later calls run per call");

    // The runner killed under a call in flight: it fails, nothing is left.
    const y = realSession();
    const inFlight = y.runner()(["slow"], { cwd: dir });
    for (const end = Date.now() + 5000; withMarker(`${mark}-slow`).length === 0 && Date.now() < end;) await new Promise((r) => setTimeout(r, 20));
    process.kill(-y.runnerPid!, "SIGKILL");
    const r = await inFlight;
    assert.equal(r.code, 1);
    assert.match(r.stderr, /the git sandbox ended/);
    assert.deepEqual(await noneLeft(`${mark}-slow`), [], "the call's git died with the sandbox (--die-with-parent, its pid namespace)");
    y.close();
  });
});
