/**
 * A protected file git tracks: git in the agent's world reads its twin, so
 * the agent's `git commit -a` after an edit of the twin records the
 * PLACEHOLDER in the user's repository (an unedited twin of a tracked file
 * looks clean to git there since 2026-10-17, twin-index-stat.ts, so each
 * case below edits the twins first: EDIT_TWINS). The launcher says so after
 * the agent exits, and a session that crashed is checked by the next launch
 * (launcher/src/placeholder-commits.ts; confidentiality.md §7.2a "A
 * placeholder in your repository"; docs/guarantees.md §3).
 *
 * The REAL components: the launcher's main() in `secrets` mode, a REAL
 * ArbiterServer (a tracked `.env`, a catalog file, and a tracked
 * `settings.ini` labelled `no-model`), the host's REAL bwrap, real git. The
 * "agent" is /bin/sh running git as an agent would.
 *
 *   W1 `git commit -a` after editing README.md and both twins commits them; the
 *      launch ends with ONE WARNING block naming the commit and both files,
 *      the remove-only repair (`git rm --cached -f`, then amend), that the
 *      user adds back a file that belongs in git, and what not to run, and
 *      never a secret, a command that puts a version back, nor a claim it
 *      did not check. The repair it prints, run outside, takes both
 *      placeholders out of HEAD and puts nothing back: the real values are
 *      in no tip that moved, not in the index (the leak oracle).
 *   W2 `git add <other file>` and commit: no warning.
 *   W3 a launch whose launcher is killed after the agent's commit (before
 *      its own check) leaves its record; the NEXT launch names the commit,
 *      and clears the record; the launch after that says nothing.
 *   W4 `git commit -a`, then `git add -A` (an untracked `.env.local`) and
 *      `git add -f` (a `.gitignore`d `prod.env`), never committed: the
 *      warning names the commit and both staged files, and its repair,
 *      run as printed, unstages those two FIRST, so the amend takes
 *      neither placeholder along (it did when the unstaging came last),
 *      and leaks nothing.
 *   W5 the walk cache swapped for a symlink to a folder outside the home,
 *      holding a pending record and a broken one: the launch is refused by
 *      the store-link check before the pending check runs, which reads,
 *      checks and removes nothing through the link (it ran first, and
 *      cleaned there, before).
 *   W6 TWO SESSIONS (the blocker of 2026-10-10): a launch whose agent runs
 *      `git add -A` (a never-tracked `.env.local`'s placeholder staged) is
 *      killed; the next launch, before any repair, says so, and its agent
 *      runs `git commit -a`. Every command the warnings print after that
 *      agent, run as printed, leaks nothing: no real value in a tip that
 *      moved, in the index, or reachable from a ref that did not hold it
 *      (an early build printed `git add -- .env.local` and an amend, which
 *      committed it).
 *   W7 THE BRANCH SWITCH (the blocker of the 2026-10-10 second review): the
 *      launch is on the branch that holds the real `.env` and
 *      `settings.ini`; the agent moves HEAD to `public`, a branch that
 *      never held them, and commits everything there. The printed repair,
 *      run as printed, takes both placeholders out of `public` and puts
 *      nothing back: `public` never reaches either real value (the second
 *      build's `git restore --staged --source=<launch commit>` put both
 *      there).
 *
 * Self-SKIPs where bwrap cannot create a user namespace (no twins there:
 * the files stay readable, posture `gated`, and git commits the real bytes).
 * Where bwrap runs but the twins do NOT engage (the launch says NONE
 * confined), the "twins engaged" assertion FAILS on purpose instead of
 * skipping: a host that can run bwrap is expected to confine, and a pass
 * without twins would prove nothing about the warning.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // the twins exist only with the confidentiality axis on

const HERE = dirname(fileURLToPath(import.meta.url));
const LAUNCHER = resolve(HERE, "..", "..", "launcher");
const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const GIT = spawnSync("git", ["--version"], { stdio: "ignore" }).status === 0;
const skip = !BWRAP_RUNS ? "bwrap cannot create a user namespace on this host (no twins: the bind layer cannot mount)"
  : !GIT ? "git is not installed" : false;

const ENV_KEY = "sk_live_PLACEHOLDERCOMMIT_9f8e7d6c5b4a";
const INI_PW = "dbPw_PLACEHOLDERCOMMIT_0a1b2c3d";
const LOCAL_KEY = "sk_live_PLACEHOLDERLOCAL_77aa66bb55cc";
const PROD_KEY = "sk_live_PLACEHOLDERPROD_1122334455ff";
const REAL_ENV = `API_TOKEN=${ENV_KEY}\nDEBUG=1\n`;
const REAL_INI = `[db]\nhost=db.local\nDB_PASSWORD=${INI_PW}\n`;
const GIT_ENV = {
  ...process.env, GIT_AUTHOR_NAME: "u", GIT_AUTHOR_EMAIL: "u@x", GIT_COMMITTER_NAME: "u", GIT_COMMITTER_EMAIL: "u@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: GIT_ENV });
/** git as the agent runs it: an identity of its own, no hooks. */
const AGENT_GIT = "git -c user.name=agent -c user.email=agent@x -c core.hooksPath=/dev/null";
/** The agent edits both tracked twins. An UNEDITED twin of a tracked file is
 *  clean to git in the agent's world (launcher/src/twin-index-stat.ts), so a
 *  `commit -a` leaves it out; an edited one shows modified and goes in. */
const EDIT_TWINS = "echo '# edited by the agent' >> .env && echo '; edited by the agent' >> settings.ini";

interface Rig { dir: string; home: string; ws: string; out: string; manduHome: string; sock: string; checks: string; server: ArbiterServer }

/** `untracked`: also a protected `.env.local` git does not track and a
 *  `prod.env` that `.gitignore` names (W4). */
async function rig(opts: { untracked?: boolean } = {}): Promise<Rig> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-ph-commit-")));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  const out = join(dir, "out");
  for (const d of [home, ws, out]) mkdirSync(d, { recursive: true });
  writeFileSync(join(ws, ".env"), REAL_ENV);
  writeFileSync(join(ws, "settings.ini"), REAL_INI);
  writeFileSync(join(ws, "README.md"), "# project\n");
  if (opts.untracked === true) writeFileSync(join(ws, ".gitignore"), "prod.env\n");
  git(ws, "init", "-q");
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "init");
  if (opts.untracked === true) {
    writeFileSync(join(ws, ".env.local"), `LOCAL_TOKEN=${LOCAL_KEY}\n`);
    writeFileSync(join(ws, "prod.env"), `PROD_TOKEN=${PROD_KEY}\n`);
  }
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {},
    // The human plane: the launch is recorded with the arbiter, so its end
    // keeps the git-history cache folder (and the records in it).
    humanSocketPath: humanSockIn(dir),
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "settings.ini"), level: "no-model" }] } as never,
  });
  await server.listen();
  const manduHome = join(dir, "mandu-home");
  // Where the launch keeps its record (on-disk-layout.md §3): named here
  // rather than imported, so this suite runs (and fails) on a tree without it.
  return { dir, home, ws, out, manduHome, sock, checks: join(manduHome, "state", "object-walks", "placeholder-checks"), server };
}

const FLAGS = ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box"];

function launchEnv(r: Rig): Record<string, string> {
  return {
    HOME: r.home, PWD: r.ws, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"] ?? "",
    MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: r.manduHome, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: r.dir, MANDU_VERBOSE: "1",
    // The launch-time scan for unprotected keys is not under test here, and
    // its first run in a fresh repository costs about ten seconds a launch.
    MANDU_SUGGEST_AT_LAUNCH: "0",
  };
}

/** One in-process launch of `/bin/sh -c script`; its stderr lines. */
async function launch(r: Rig, script: string): Promise<{ code: number | null; err: Error | null; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"] };
  let code: number | null = null;
  let err: Error | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = r.home;
    process.env["MANDU_HOME"] = r.manduHome;
    try {
      code = await main([...FLAGS, "--", "/bin/sh", "-c", script], launchEnv(r));
    } catch (e) {
      err = e as Error;
    }
  } finally {
    console.error = orig;
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  return { code, err, lines };
}

/** The lines of the placeholder WARNING blocks in a launch's output. */
function warningOf(lines: readonly string[]): string[] {
  const at = lines.findIndex((l) => /^WARNING: mandu: git in the agent's session recorded Mandu's placeholder/.test(l));
  if (at < 0) return [];
  const end = lines.findIndex((l, i) => i > at && /do NOT run git checkout/.test(l));
  return lines.slice(at, end < 0 ? undefined : end + 1);
}

/** The records left in the launch's record folder (absent until a launch
 *  writes one). */
function records(r: Rig): string[] {
  return existsSync(r.checks) ? readdirSync(r.checks) : [];
}

function noSecret(text: string, what: string): void {
  for (const s of [ENV_KEY, INI_PW, LOCAL_KEY, PROD_KEY]) assert.ok(!text.includes(s), `${what} holds a secret (${s})`);
}

/** Every printed repair command: only git's record, and nothing put back
 *  (no add, no --source, no commit with -a or a pathspec). */
const SAFE_REPAIR = /^git (restore --staged -- |rm --cached -f -- |commit (--amend --no-edit --allow-empty|-m '[^']*')$)/;

/** The printed repair commands in a block's lines. */
const printed = (lines: readonly string[]): string[] => lines.filter((l) => /^ {4}git /.test(l)).map((l) => l.trim());

// ── The leak oracle (as in launcher/test/unit/placeholder-commits.test.ts) ──

/** Every ref and HEAD, with the commit each names. */
function refTips(ws: string): Map<string, string> {
  const tips = new Map<string, string>();
  for (const l of git(ws, "for-each-ref", "--format=%(refname) %(objectname)").split("\n")) {
    const [ref, sha] = l.split(" ");
    if (ref && sha) tips.set(ref, sha);
  }
  const head = spawnSync("git", ["rev-parse", "-q", "--verify", "HEAD"], { cwd: ws, env: GIT_ENV, encoding: "utf8" }).stdout.trim();
  if (head !== "") tips.set("HEAD", head);
  return tips;
}

/** Whether a commit `revs` reach holds `secret` anywhere in its tree. */
function holds(ws: string, secret: string, ...revs: string[]): boolean {
  const commits = git(ws, "rev-list", ...revs).split("\n").filter((l) => l !== "");
  if (commits.length === 0) return false;
  const r = spawnSync("git", ["grep", "-l", "-F", "-e", secret, ...commits], { cwd: ws, env: GIT_ENV, encoding: "utf8" });
  assert.ok(r.status === 0 || r.status === 1, r.stderr);
  return r.status === 0;
}

interface Before { secret: string; tips: Map<string, string>; held: Set<string> }

/** Each ref's tip before the session, and the refs from which a commit
 *  holding `secret` was reachable. */
function before(ws: string, secret: string): Before {
  const tips = refTips(ws);
  return { secret, tips, held: new Set([...tips].filter(([, sha]) => holds(ws, secret, sha)).map(([ref]) => ref)) };
}

/** After the printed commands ran: the real value is in no ref's tip (but
 *  one that held it before and did not move), not in the index, and in no
 *  commit reachable from a ref that did not hold it before. */
function assertNoLeak(ws: string, b: Before, what: string): void {
  const idx = spawnSync("git", ["grep", "-l", "-F", "-e", b.secret, "--cached"], { cwd: ws, env: GIT_ENV, encoding: "utf8" });
  assert.equal(idx.status, 1, `${what}: the real value is in the index: ${idx.stdout}${idx.stderr}`);
  for (const [ref, tip] of refTips(ws)) {
    if (!(b.held.has(ref) && b.tips.get(ref) === tip)) assert.equal(holds(ws, b.secret, tip, "--max-count=1"), false, `${what}: the real value is in ${ref}'s tip`);
    if (!b.held.has(ref)) assert.equal(holds(ws, b.secret, tip), false, `${what}: the real value is reachable from ${ref}, which did not hold it before`);
  }
}

/** Each WARNING block in a launch's output, with the line before it (an
 *  earlier session's block opens with `…; checked now:` at launch, `…;
 *  checked again now:` after the agent). */
function warningBlocks(lines: readonly string[]): Array<{ prev: string; lines: string[] }> {
  const out: Array<{ prev: string; lines: string[] }> = [];
  lines.forEach((l, i) => {
    if (/^WARNING: mandu: git in the agent's session recorded/.test(l)) out.push({ prev: lines[i - 1] ?? "", lines: warningOf(lines.slice(i)) });
  });
  return out;
}

/** The launcher as its own process, SIGKILLed (no exit path runs) once
 *  `marker` exists; its output. `script` ends by touching `marker`; the
 *  agent then waits until the launcher is dead: the sandbox outlives the
 *  launcher's process group and holds its output pipes open, so it waits on
 *  a release file the test writes after the kill (at most 120 s, the old
 *  `sleep 120`, which every such launch waited out in full). */
async function killedLaunch(r: Rig, script: string, marker: string): Promise<string> {
  const release = `${marker}.release`;
  const hold = `i=0; while [ ! -e '${release}' ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done`;
  const child = spawn(join(LAUNCHER, "node_modules", ".bin", "tsx"), [join(LAUNCHER, "src", "run.ts"), ...FLAGS, "--", "/bin/sh", "-c", `${script}; ${hold}`], {
    cwd: r.ws, env: launchEnv(r), stdio: ["ignore", "pipe", "pipe"], detached: true,
  });
  let childOut = "";
  child.stdout!.setEncoding("utf8").on("data", (c: string) => { childOut += c; });
  child.stderr!.setEncoding("utf8").on("data", (c: string) => { childOut += c; });
  const closed = new Promise<void>((res) => child.on("close", () => res()));
  const exited = new Promise<void>((res) => child.on("exit", () => res()));
  const deadline = Date.now() + 150_000;
  while (!existsSync(marker) && Date.now() < deadline && child.exitCode === null) await new Promise((res) => setTimeout(res, 100));
  assert.ok(existsSync(marker), `the agent never got there:\n${childOut}`);
  process.kill(-child.pid!, "SIGKILL");
  await exited; // the launcher is gone: no exit path of its ran
  writeFileSync(release, "");
  await closed;
  return childOut;
}

test("W1+W2: the agent's commit -a of the twins is named after the session, with a remove-only repair that works and leaks nothing; a commit of another file is not", { skip, timeout: 240_000 }, async () => {
  const r = await rig();
  try {
    // W2 first: git add of another file only.
    const w2 = await launch(r, `cd '${r.ws}' && echo x > other.txt && ${AGENT_GIT} add other.txt && ${AGENT_GIT} commit -q -m other; echo "RC=$?" > '${r.out}/w2'`);
    const log2 = w2.lines.join("\n");
    assert.equal(w2.err, null, `${w2.err?.message}\n${log2}`);
    assert.equal(w2.code, 0, log2);
    assert.match(readFileSync(join(r.out, "w2"), "utf8"), /RC=0/);
    // Fails (never skips) when bwrap runs but nothing is confined: see the
    // header.
    assert.match(log2, /secret\(s\) (confined|behind placeholder)/, `the twins engaged:\n${log2}`);
    assert.deepEqual(warningOf(w2.lines), [], `no warning for a commit of another file:\n${log2}`);
    assert.equal(git(r.ws, "show", "HEAD:.env"), REAL_ENV);

    // W1: an unrelated edit, then `git commit -a` (the twins ride along).
    const was = [before(r.ws, ENV_KEY), before(r.ws, INI_PW)];
    const atStart = git(r.ws, "rev-parse", "HEAD").trim();
    const w1 = await launch(r, [
      `cd '${r.ws}'`,
      `cat .env settings.ini > '${r.out}/seen'`,
      "echo 'more' >> README.md",
      // The twins edited first: an unedited twin of a tracked file is clean
      // to git in the agent's world (twin-index-stat.ts), so commit -a would
      // leave it out.
      EDIT_TWINS,
      `${AGENT_GIT} commit -q -a -m agent-commit; echo "RC=$?" >> '${r.out}/seen'`,
    ].join("; "));
    const log1 = w1.lines.join("\n");
    assert.equal(w1.err, null, `${w1.err?.message}\n${log1}`);
    assert.equal(w1.code, 0, log1);
    const seen = readFileSync(join(r.out, "seen"), "utf8");
    assert.match(seen, /\$MDU:/, `the agent read the twins:\n${seen}`);
    noSecret(seen, "the agent's world");
    const head = git(r.ws, "rev-parse", "HEAD").trim();
    assert.match(git(r.ws, "show", "HEAD:.env"), /\$MDU:/, "precondition: the agent's commit recorded the placeholder of .env");
    assert.match(git(r.ws, "show", "HEAD:settings.ini"), /\$MDU:/, "and of the labelled settings.ini");
    assert.equal(readFileSync(join(r.ws, ".env"), "utf8"), REAL_ENV, "the real file on disk is untouched");

    const warn = warningOf(w1.lines);
    const text = warn.join("\n");
    assert.ok(warn.length > 0, `the launch must warn after the agent's commit:\n${log1}`);
    assert.ok(text.includes(`commit ${head.slice(0, 10)}`), `the warning names the commit ${head}:\n${text}`);
    assert.match(text, /\.env, settings\.ini/);
    assert.match(text, /not pushed/);
    const cmds = printed(warn);
    assert.deepEqual(cmds, ["git rm --cached -f -- .env settings.ini", "git commit --amend --no-edit --allow-empty"], `the placeholders out, nothing put back:\n${text}`);
    assert.match(text, /After this, git no longer tracks \.env, settings\.ini\. If one of them belongs in git, check what the file on disk holds and add it back yourself: what you add is your real file\. Mandu prints no command that puts it back\./);
    assert.match(text, /do NOT run git checkout, git restore without --staged, git reset --hard/);
    assert.doesNotMatch(text, /no secret was written|git add --|--source/, "never a claim it did not check, never a version put back");
    noSecret(log1, "the launch output");
    assert.equal(warningOf(w1.lines.slice(w1.lines.indexOf(warn.at(-1)!) + 1)).length, 0, "said once");
    assert.deepEqual(records(r), [], "the record is cleared once checked");

    // The repair as printed, run outside: both placeholders out of HEAD,
    // nothing put back in their place.
    for (const c of cmds) {
      assert.match(c, SAFE_REPAIR, c);
      execFileSync("sh", ["-c", c], { cwd: r.ws, env: GIT_ENV });
    }
    for (const p of [".env", "settings.ini"]) {
      assert.notEqual(spawnSync("git", ["cat-file", "-e", `HEAD:${p}`], { cwd: r.ws, env: GIT_ENV }).status, 0, `${p}: out of HEAD`);
    }
    assert.equal(git(r.ws, "rev-parse", "HEAD^").trim(), atStart, "the amend replaced the agent's commit");
    assert.match(git(r.ws, "show", "HEAD:README.md"), /more/, "the agent's own change is kept");
    assert.equal(git(r.ws, "status", "--porcelain"), "?? .env\n?? settings.ini\n", "untracked now, for the user to add back or ignore");
    assert.equal(readFileSync(join(r.ws, ".env"), "utf8"), REAL_ENV, "the real file on disk is untouched");
    for (const b of was) assertNoLeak(r.ws, b, "W1");
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("W3: a session killed before its check is checked by the next launch, once", { skip, timeout: 240_000 }, async () => {
  const r = await rig();
  try {
    // The launcher as its own process, killed (SIGKILL: no exit path runs)
    // once the agent has committed.
    const marker = join(r.out, "committed");
    const childOut = await killedLaunch(r, `cd '${r.ws}'; echo edit >> README.md; ${EDIT_TWINS}; ${AGENT_GIT} commit -q -a -m crashed; touch '${marker}'`, marker);
    const head = git(r.ws, "rev-parse", "HEAD").trim();
    assert.match(git(r.ws, "show", "HEAD:.env"), /\$MDU:/, "precondition: the crashed session committed the placeholder");
    assert.equal(records(r).length, 1, `the killed launch left its record:\n${childOut}`);
    assert.doesNotMatch(childOut, /git in the agent's session recorded/, "the killed launch never checked");

    // The next launch: names the commit before its agent runs, checks it
    // again after (and says it again), and clears the record.
    const next = await launch(r, "true");
    const log = next.lines.join("\n");
    assert.equal(next.code, 0, log);
    assert.ok(log.includes(`ended before Mandu could check ${r.ws}; checked now:`), log);
    const warn = warningOf(next.lines).join("\n");
    assert.ok(warn.includes(`commit ${head.slice(0, 10)}`), `the next launch names the crashed session's commit:\n${log}`);
    noSecret(log, "the next launch's output");
    assert.deepEqual(records(r), [], "cleared once checked");

    // And the launch after that says nothing more.
    const after = await launch(r, "true");
    assert.equal(after.code, 0, after.lines.join("\n"));
    assert.deepEqual(warningOf(after.lines), [], after.lines.join("\n"));
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("W4: a commit -a, then an untracked and an ignored protected file staged: the repair unstages those first, and run as printed leaves no placeholder anywhere", { skip, timeout: 240_000 }, async () => {
  const r = await rig({ untracked: true });
  try {
    const was = [ENV_KEY, INI_PW, LOCAL_KEY, PROD_KEY].map((k) => before(r.ws, k));
    const w4 = await launch(r, [
      `cd '${r.ws}'`,
      `cat .env.local prod.env > '${r.out}/seen'`,
      "echo 'more' >> README.md",
      EDIT_TWINS,
      `${AGENT_GIT} commit -q -a -m agent-commit`,
      `${AGENT_GIT} add -A`,
      `${AGENT_GIT} add -f prod.env; echo "RC=$?" >> '${r.out}/seen'`,
    ].join("; "));
    const log = w4.lines.join("\n");
    assert.equal(w4.err, null, `${w4.err?.message}\n${log}`);
    assert.equal(w4.code, 0, log);
    // Fails (never skips) when bwrap runs but nothing is confined: see the
    // header.
    assert.match(log, /secret\(s\) (confined|behind placeholder)/, `the twins engaged:\n${log}`);
    const seen = readFileSync(join(r.out, "seen"), "utf8");
    assert.match(seen, /LOCAL_TOKEN=.*\$MDU:[\s\S]*PROD_TOKEN=.*\$MDU:/, `the agent read both untracked files' twins:\n${seen}`);
    assert.match(seen, /RC=0/);
    noSecret(seen, "the agent's world");
    const head = git(r.ws, "rev-parse", "HEAD").trim();
    assert.match(git(r.ws, "show", "HEAD:.env"), /\$MDU:/, "precondition: the commit holds the placeholder of .env");
    assert.match(git(r.ws, "show", ":.env.local"), /\$MDU:/, "precondition: the untracked file's placeholder is staged");
    assert.match(git(r.ws, "show", ":prod.env"), /\$MDU:/, "precondition: the ignored file's placeholder is staged");

    const warn = warningOf(w4.lines);
    const text = warn.join("\n");
    assert.ok(warn.length > 0, `the launch must warn:\n${log}`);
    assert.ok(text.includes(`commit ${head.slice(0, 10)}`), text);
    assert.match(text, /staged for your next commit: \.env\.local, prod\.env/);
    noSecret(log, "the launch output");
    const cmds = printed(warn);
    assert.deepEqual(cmds, [
      "git restore --staged -- .env.local prod.env",
      "git rm --cached -f -- .env settings.ini",
      "git commit --amend --no-edit --allow-empty",
    ], `unstaged first:\n${text}`);
    assert.match(text, /After this, git no longer tracks \.env, \.env\.local, prod\.env, settings\.ini\./);
    assert.match(text, /If not, list them in \.gitignore/, "the files leaving git: keep them out");
    for (const c of cmds) {
      assert.match(c, SAFE_REPAIR, c);
      execFileSync("sh", ["-c", c], { cwd: r.ws, env: GIT_ENV });
    }
    for (const p of [".env", "settings.ini", ".env.local", "prod.env"]) {
      assert.notEqual(spawnSync("git", ["cat-file", "-e", `HEAD:${p}`], { cwd: r.ws, env: GIT_ENV }).status, 0, `${p}: neither its placeholder nor its value in HEAD`);
    }
    assert.equal(git(r.ws, "diff", "--cached", "--name-only"), "", "nothing staged");
    assert.equal(git(r.ws, "status", "--porcelain"), "?? .env\n?? .env.local\n?? settings.ini\n", "untracked (prod.env ignored), for the user to add back or ignore");
    assert.equal(readFileSync(join(r.ws, ".env.local"), "utf8"), `LOCAL_TOKEN=${LOCAL_KEY}\n`, "the real files on disk are untouched");
    for (const b of was) assertNoLeak(r.ws, b, "W4");
    assert.deepEqual(records(r), [], "the record is cleared once checked");
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("W5: the walk cache swapped for a link outside the home: refused before the pending check, and nothing is read or removed through the link", { skip, timeout: 240_000 }, async () => {
  const r = await rig();
  try {
    // A crashed session's record (its launcher long gone: no such pid
    // alive, no start time or boot to compare) and a broken one, in a
    // folder outside the home the walk cache now points at.
    const planted = join(r.dir, "planted");
    mkdirSync(join(planted, "placeholder-checks"), { recursive: true, mode: 0o700 });
    const ids = ["a".repeat(40)];
    const pending = join(planted, "placeholder-checks", "1-4194301-crashed.json");
    const broken = join(planted, "placeholder-checks", "2-4194302-broken.json");
    writeFileSync(pending, JSON.stringify({
      v: 1, pid: 4194301, startTicks: null, bootId: null, scopeId: "crashed", at: 1,
      repos: [{ root: r.ws, tips: [git(r.ws, "rev-parse", "HEAD").trim()], paths: [{ rel: ".env", tracked: true, ids }] }],
    }));
    writeFileSync(broken, "{");
    mkdirSync(join(r.manduHome, "state"), { recursive: true, mode: 0o700 });
    symlinkSync(planted, join(r.manduHome, "state", "object-walks"));
    const ran = join(r.out, "ran");
    const w5 = await launch(r, `touch '${ran}'`);
    const log = `${w5.err?.message ?? ""}\n${w5.lines.join("\n")}`;
    assert.ok(w5.err !== null || w5.code !== 0, `refused:\n${log}`);
    assert.match(log, /Mandu's stores must lie inside its home/);
    assert.ok(!existsSync(ran), "the agent never started");
    assert.doesNotMatch(log, /ended before Mandu could check/, "the record behind the link was never checked");
    assert.ok(existsSync(pending) && existsSync(broken), "nothing removed through the link");
    assert.deepEqual(readdirSync(join(planted, "placeholder-checks")).sort(), ["1-4194301-crashed.json", "2-4194302-broken.json"]);
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("W6: TWO SESSIONS, the first killed after its agent's `git add -A`, the second's agent commits before any repair: every command printed after it, run as printed, leaks nothing", { skip, timeout: 300_000 }, async () => {
  const r = await rig({ untracked: true });
  try {
    const was = [ENV_KEY, INI_PW, LOCAL_KEY].map((k) => before(r.ws, k));
    // Session 1: the agent stages everything, the never-tracked .env.local's
    // placeholder included; then the launcher is killed (no check).
    const marker = join(r.out, "staged");
    const out1 = await killedLaunch(r, `cd '${r.ws}'; ${AGENT_GIT} add -A; touch '${marker}'`, marker);
    assert.match(git(r.ws, "show", ":.env.local"), /\$MDU:/, `precondition: the placeholder is staged:\n${out1}`);
    assert.equal(records(r).length, 1, `the killed launch left its record:\n${out1}`);

    // Session 2, before any repair: its agent's `git commit -a` takes the
    // staged placeholder along.
    const w6 = await launch(r, `cd '${r.ws}' && echo more >> README.md && ${EDIT_TWINS} && ${AGENT_GIT} commit -q -a -m second; echo "RC=$?" > '${r.out}/w6'`);
    const log = w6.lines.join("\n");
    assert.equal(w6.err, null, `${w6.err?.message}\n${log}`);
    assert.equal(w6.code, 0, log);
    assert.match(readFileSync(join(r.out, "w6"), "utf8"), /RC=0/);
    assert.match(log, /secret\(s\) (confined|behind placeholder)/, `the twins engaged:\n${log}`);
    assert.match(git(r.ws, "show", "HEAD:.env.local"), /\$MDU:/, "precondition: the second session committed the placeholder");

    const blocks = warningBlocks(w6.lines);
    const atLaunch = blocks.filter((b) => /; checked now:$/.test(b.prev));
    const after = blocks.filter((b) => !/; checked now:$/.test(b.prev));
    assert.equal(atLaunch.length, 1, `the earlier session is said at launch:\n${log}`);
    assert.match(atLaunch[0]!.lines.join("\n"), /staged for your next commit: .*\.env\.local/);
    assert.ok(after.length >= 1, `and the commit after the agent:\n${log}`);
    const text = after.map((b) => b.lines.join("\n")).join("\n");
    const cmds = after.flatMap((b) => printed(b.lines));
    assert.ok(cmds.some((c) => /^git rm --cached -f -- .*\.env\.local/.test(c)), `the never-tracked file leaves git:\n${text}`);
    assert.match(text, /After this, git no longer tracks .*\.env\.local/);
    assert.match(text, /If (it|one of them) belongs in git, check what the file on disk holds and add it back yourself/);
    for (const c of [...atLaunch.flatMap((b) => printed(b.lines)), ...cmds]) assert.match(c, SAFE_REPAIR, c);
    assert.doesNotMatch(log, /no secret was written|git add --|--source/);
    noSecret(log, "the launch output");

    // Every block's commands, in order. The earlier session's block and this
    // session's differ (this agent edited the tracked twins, which the
    // earlier record does not know), so both are said, and the later block's
    // `git rm --cached` of a file the earlier one already took out finds
    // nothing: git refuses that one ("did not match"), which removes
    // nothing and puts nothing back.
    for (const c of cmds) {
      const run = spawnSync("sh", ["-c", c], { cwd: r.ws, env: GIT_ENV, encoding: "utf8" });
      if (run.status !== 0) assert.match(`${c}\n${run.stderr}`, /^git rm --cached -f -- [\s\S]*did not match any files/, `${c}: ${run.stderr}`);
    }
    assert.notEqual(spawnSync("git", ["cat-file", "-e", "HEAD:.env.local"], { cwd: r.ws, env: GIT_ENV }).status, 0, ".env.local out of HEAD");
    assert.equal(git(r.ws, "ls-files", "-s", "--", ".env.local"), "", "and out of the index");
    for (const b of was) assertNoLeak(r.ws, b, "W6");
    assert.match(git(r.ws, "show", "HEAD:README.md"), /more/, "the agent's own change is kept");
    assert.equal(readFileSync(join(r.ws, ".env.local"), "utf8"), `LOCAL_TOKEN=${LOCAL_KEY}\n`, "the real file on disk is untouched");
    assert.deepEqual(records(r), [], "every record checked and cleared");
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("W7: THE BRANCH SWITCH: the launch on the branch holding the real files, the agent's commit on a branch that never held them: the printed repair, run as printed, leaves that branch without either real value", { skip, timeout: 240_000 }, async () => {
  const r = await rig();
  try {
    // `public`: a root commit of its own with README.md only (made with a
    // scratch index, so HEAD, the index and the files stay as they are).
    const scratch = { ...GIT_ENV, GIT_INDEX_FILE: join(r.dir, "scratch-index") };
    execFileSync("git", ["read-tree", "HEAD"], { cwd: r.ws, env: scratch });
    execFileSync("git", ["rm", "--cached", "-q", "--", ".env", "settings.ini"], { cwd: r.ws, env: scratch });
    const tree = execFileSync("git", ["write-tree"], { cwd: r.ws, env: scratch, encoding: "utf8" }).trim();
    const pub = execFileSync("git", ["commit-tree", tree, "-m", "public"], { cwd: r.ws, env: GIT_ENV, encoding: "utf8" }).trim();
    git(r.ws, "update-ref", "refs/heads/public", pub);
    const was = [before(r.ws, ENV_KEY), before(r.ws, INI_PW)];
    for (const b of was) assert.equal(b.held.has("refs/heads/public"), false, "precondition: public never held the real files");
    const home = git(r.ws, "symbolic-ref", "HEAD").trim();

    // The agent: HEAD to public (the work tree kept), an edit, everything
    // staged and committed there.
    const w7 = await launch(r, [
      `cd '${r.ws}'`,
      "git symbolic-ref HEAD refs/heads/public",
      "git reset -q --mixed public",
      "echo 'more' >> README.md",
      `${AGENT_GIT} add -A`,
      `${AGENT_GIT} commit -q -m agent-on-public; echo "RC=$?" > '${r.out}/w7'`,
    ].join(" && "));
    const log = w7.lines.join("\n");
    assert.equal(w7.err, null, `${w7.err?.message}\n${log}`);
    assert.equal(w7.code, 0, log);
    assert.match(readFileSync(join(r.out, "w7"), "utf8"), /RC=0/);
    assert.match(log, /secret\(s\) (confined|behind placeholder)/, `the twins engaged:\n${log}`);
    assert.equal(git(r.ws, "symbolic-ref", "HEAD").trim(), "refs/heads/public");
    assert.match(git(r.ws, "show", "public:.env"), /\$MDU:/, "precondition: public holds the placeholder");

    const warn = warningOf(w7.lines);
    const text = warn.join("\n");
    const cmds = printed(warn);
    assert.deepEqual(cmds, ["git rm --cached -f -- .env settings.ini", "git commit --amend --no-edit --allow-empty"], `nothing put back:\n${log}`);
    assert.doesNotMatch(log, /--source|git add --/);
    noSecret(log, "the launch output");
    for (const c of cmds) {
      assert.match(c, SAFE_REPAIR, c);
      execFileSync("sh", ["-c", c], { cwd: r.ws, env: GIT_ENV });
    }
    for (const p of [".env", "settings.ini"]) {
      assert.notEqual(spawnSync("git", ["cat-file", "-e", `public:${p}`], { cwd: r.ws, env: GIT_ENV }).status, 0, `public: no ${p} at all`);
    }
    for (const b of was) assertNoLeak(r.ws, b, "W7");
    assert.equal(git(r.ws, "show", `${home}:.env`), REAL_ENV, "the branch that held it is untouched");
    assert.equal(readFileSync(join(r.ws, ".env"), "utf8"), REAL_ENV, "the real file on disk is untouched");
    assert.match(text, /commit [0-9a-f]{10} \(public; not pushed\) holds the placeholder of \.env, settings\.ini/);
    assert.match(text, /After this, git no longer tracks \.env, settings\.ini\./);
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});
