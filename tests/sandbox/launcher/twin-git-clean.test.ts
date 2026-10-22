/**
 * A protected file git tracks looks CLEAN to git in the agent's world
 * (launcher/src/twin-index-stat.ts; confidentiality.md §7.2a "A twinned file
 * git tracks looks clean"). Found by the demo battery, 2026-10-16 (demo-c4,
 * "scrub a committed key from git history"): the tracked `storefront/.env`
 * was its twin, so git saw the work tree modified, and the model's natural
 * `git filter-branch --index-filter 'git rm --cached …' -- --all` (without
 * untracking first) refused with "You have unstaged changes"; nothing was
 * rewritten.
 *
 * The REAL launcher in `secrets` (withStack: a private arbiter, the guard
 * where built), a shell agent running git, in both postures: the mount layer
 * (the default) and the guard alone (`--no-secret-bind`).
 *
 *   T1 the demo-c4 flow without untracking first: `git status` lists
 *      nothing; filter-branch runs (exit 0) and drops `.env` from every
 *      commit of `main`; the key never reaches the agent's world; the
 *      human's `.env` keeps its key.
 *   T2 a `git commit -a` after an unrelated edit leaves `.env` out (before
 *      the fix it recorded the placeholder); an edit of the twin shows
 *      modified, and the `git commit -a` after it records the placeholder,
 *      which the launcher names after the session (the existing guarantee,
 *      placeholder-commits.ts).
 *   T3 THE TRADE-OFF, pinned: while the session runs, the human's own git
 *      shows `.env` ` M` with no content diff; after it, clean (the launch
 *      stat put back).
 *   T4 a launcher SIGKILLed mid-session leaves the twin's stat in the index
 *      (` M` outside) and its crash record; the next launch puts it back
 *      before its own patch, and says so.
 *   T6 THE 2026-10-21 INCIDENT: two launches overlap on one repository,
 *      each with its own Mandu home (the demo battery's sides), and the
 *      first ends first: after both, the human's git is clean (before the
 *      fix the second put back its launch stat, the first's twin stat, and
 *      ` M .env` stayed with no crash record anywhere).
 *   T7 the scope: a repository under HOME the launch is not in (its .env
 *      tracked and twinned) keeps its index as is, so the human's git there
 *      is clean while the session runs and the agent's git there sees the
 *      twin modified (as before the patch); the launch's own repository is
 *      patched (clean in the agent's world).
 *   T8 a launcher SIGKILLed while its MANDU_HOME is a scratch home that is
 *      then removed (the demo battery's sides): the crash record is in the
 *      HOME's own store, so `mandu reap`, and separately the next launch,
 *      each with yet another MANDU_HOME, put the real stat back.
 *   T5 bind-only (`--no-net-guard`, posture gated): nothing is patched (a
 *      human's `git stash` would replace the real file and detach the bind,
 *      review of !1642 M1); the twin shows modified there, as before.
 *   T1 also: the exit notice names `.env`, untracked by the rewrite and not
 *      in .gitignore (a later `git add -A` would commit the real file).
 *
 * Self-SKIPs off Linux, without bwrap or user namespaces, and (guard-only)
 * without the built guard.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier, LAUNCHER_MAIN, LAUNCHER_TSX } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("twin-git-clean");

// This suite STATES its axes (protection-modes.md §4): `secrets`.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : false;
const GUARD_GATE = GATE !== false ? GATE : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

const KEY = "sk_test_TWINGITCLEAN_7c1e5a90d2b4";
const REAL_ENV = `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`;
const GIT_ENV = {
  ...process.env, GIT_AUTHOR_NAME: "u", GIT_AUTHOR_EMAIL: "u@x", GIT_COMMITTER_NAME: "u", GIT_COMMITTER_EMAIL: "u@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: GIT_ENV });

/** The workspace's history: `.env` committed "months ago", then app work. */
function seed(workspace: string): void {
  writeFileSync(join(workspace, ".env"), REAL_ENV, { mode: 0o600 });
  writeFileSync(join(workspace, "app.js"), "console.log(1);\n");
}
function moreHistory(workspace: string): void {
  writeFileSync(join(workspace, "app.js"), "console.log(2);\n");
  git(workspace, "commit", "-qam", "app work");
  // The real file untouched since long before the index was written.
  const old = Date.now() / 1000 - 3600;
  utimesSync(join(workspace, ".env"), old, old);
  git(workspace, "update-index", "-q", "--refresh");
}

const AGENT_GIT = "git -c user.name=agent -c user.email=agent@x -c core.hooksPath=/dev/null";

const T1_SCRIPT = String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
FILTER_BRANCH_SQUELCH_WARNING=1 ${AGENT_GIT} filter-branch -f --index-filter 'git rm --cached --ignore-unmatch -q -- .env' --prune-empty -- --all > "$OUT/fb" 2>&1
echo "FB_RC=$?"
echo "TRACKED<$(${AGENT_GIT} ls-files .env)>"
echo "SEEN<$(/bin/cat .env 2>&1 | tr '\n' '|')>"
echo "AGENT_DONE"
`;

const T2_SCRIPT = String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
echo 'console.log(3);' > app.js
${AGENT_GIT} commit -q -a -m unrelated; echo "C1_RC=$?"
echo "C1_FILES<$(${AGENT_GIT} show --name-only --format= HEAD | tr '\n' '|')>"
echo "EDITED=1" >> .env
echo "STATUS1<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
${AGENT_GIT} commit -q -a -m edited; echo "C2_RC=$?"
echo "AGENT_DONE"
`;

async function run(posture: "bind" | "guard", script: string, check: (out: string, workspace: string, diag: string) => void): Promise<void> {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    const sh = join(tmp, "agent.sh");
    writeFileSync(join(tmp, "work.sh"), script);
    writeFileSync(sh, `WS='${workspace}' OUT='${tmp}' exec bash ${join(tmp, "work.sh")}\n`);
    const argv = ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", ...(posture === "guard" ? ["--no-secret-bind"] : []), "--", "/bin/sh", sh];
    const r = await runLauncher(argv, { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home }, workspace, 240_000);
    const out = r.out;
    const diag = `\n--- launch output (tail) ---\n${out.slice(-6000)}`;
    assert.equal(r.code, 0, `the launch failed${diag}`);
    assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
    assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(out), `the twins engaged${diag}`);
    if (posture === "guard") assert.ok(/bind mount SKIPPED|by the guard, no bind/.test(out), `guard-only posture${diag}`);
    // THE LEAK ORACLE first: the key never reached the agent's world.
    assert.ok(!out.includes(KEY), `CONFIDENTIALITY VIOLATION: the key reached the agent's world${diag}`);
    let fb = "";
    try { fb = readFileSync(join(tmp, "fb"), "utf8"); } catch { /* T2 */ }
    assert.ok(!fb.includes(KEY), `CONFIDENTIALITY VIOLATION: the key in filter-branch's output\n${fb}`);
    check(out, workspace, `${diag}\n--- filter-branch ---\n${fb}`);
  }, { mode: "secrets", seed });
}

for (const posture of ["bind", "guard"] as const) {
  const skip = posture === "bind" ? GATE : GUARD_GATE;

  test(`T1 (${posture}) demo-c4 without untracking first: the tree is clean, filter-branch rewrites every commit, the key never reaches the agent, the human's .env keeps it`, { skip, timeout: 300_000 }, async () => {
    await run(posture, T1_SCRIPT, (out, ws, diag) => {
      assert.match(out, /STATUS0<>/, `git status in the agent's world lists nothing${diag}`);
      assert.match(out, /FB_RC=0/, `filter-branch ran${diag}`);
      assert.match(out, /SEEN<STRIPE_SECRET_KEY='?\$MDU:/, `the agent reads the twin${diag}`);
      assert.match(out, /TRACKED<>/, `the agent's index no longer tracks .env${diag}`);
      assert.equal(git(ws, "log", "main", "--format=%H", "--", ".env"), "", "main no longer holds .env");
      assert.equal(readFileSync(join(ws, ".env"), "utf8"), REAL_ENV, "the human's .env keeps its key");
      assert.match(out, /\.env is no longer tracked by git \(the session untracked it\) and \.gitignore does not name it/, `the exit notice says a later add would commit it${diag}`);
    });
  });

  test(`T2 (${posture}) commit -a after an unrelated edit leaves .env out; an edit of the twin shows modified and its commit is named after the session`, { skip, timeout: 300_000 }, async () => {
    await run(posture, T2_SCRIPT, (out, ws, diag) => {
      assert.match(out, /STATUS0<>/, `clean at the start${diag}`);
      assert.match(out, /C1_RC=0/, diag);
      assert.match(out, /C1_FILES<app\.js\|>/, `the unrelated commit -a took app.js alone${diag}`);
      assert.match(out, /STATUS1< M \.env\|>/, `the edited twin shows modified${diag}`);
      assert.match(out, /C2_RC=0/, diag);
      assert.match(git(ws, "show", "HEAD:.env"), /\$MDU:/, "the edited twin's commit holds the placeholder");
      assert.equal(git(ws, "show", "HEAD~1:.env"), REAL_ENV, "the unrelated commit kept the real blob");
      assert.match(out, /WARNING: mandu: git in the agent's session recorded Mandu's placeholder/, `the launcher names it${diag}`);
      assert.equal(readFileSync(join(ws, ".env"), "utf8"), REAL_ENV, "the real file on disk is untouched");
    });
  });
}

/** The agent's half of a pause: touch `$OUT/mid`, then wait (at most 120 s)
 *  for the test to write `$OUT/release`. */
const PAUSE = String.raw`touch "$OUT/mid"; i=0; while [ ! -e "$OUT/release" ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done`;

async function waitFor(path: string, ms = 150_000): Promise<void> {
  const end = Date.now() + ms;
  while (!existsSync(path) && Date.now() < end) await new Promise((res) => setTimeout(res, 100));
  assert.ok(existsSync(path), `never got ${path}`);
}

const humanStatus = (ws: string): string => spawnSync("git", ["status", "--porcelain"], { cwd: ws, env: GIT_ENV, encoding: "utf8" }).stdout;

test("T3 (bind) THE TRADE-OFF, pinned: while the session runs, the human's own git shows .env ` M` with no content diff; after it, clean (the launch stat restored)", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    writeFileSync(join(tmp, "work.sh"), String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
${PAUSE}
echo "AGENT_DONE"
`);
    const sh = join(tmp, "agent.sh");
    writeFileSync(sh, `WS='${workspace}' OUT='${tmp}' exec bash ${join(tmp, "work.sh")}\n`);
    const launched = runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", sh],
      { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home }, workspace, 240_000);
    await waitFor(join(tmp, "mid"));
    const during = humanStatus(workspace);
    const diffStat = spawnSync("git", ["diff", "--stat"], { cwd: workspace, env: GIT_ENV, encoding: "utf8" }).stdout;
    writeFileSync(join(tmp, "release"), "");
    const r = await launched;
    const diag = `\n--- launch output (tail) ---\n${r.out.slice(-6000)}`;
    assert.equal(r.code, 0, diag);
    assert.ok(!r.out.includes(KEY), `CONFIDENTIALITY VIOLATION${diag}`);
    assert.match(r.out, /STATUS0<>/, `clean in the agent's world${diag}`);
    assert.equal(during, " M .env\n", "outside, during the session: shown modified (the cached size is the twin's)");
    assert.equal(diffStat, "", "with no content change");
    assert.equal(humanStatus(workspace), "", "outside, clean after the session");
  }, { mode: "secrets", seed });
});

test("T6 (bind) THE 2026-10-21 INCIDENT: two overlapping launches in two Mandu homes (the demo battery's sides), the first ends first: the human's git is clean after both", { skip: GATE, timeout: 400_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    writeFileSync(join(tmp, "work.sh"), String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
${PAUSE}
echo "AGENT_DONE"
`);
    // Each side its own Mandu home (neither sees the other's crash record)
    // and its own pause.
    const launch = (side: "a" | "b"): ReturnType<typeof runLauncher> => {
      const out = join(tmp, side);
      mkdirSync(out, { recursive: true });
      const sh = join(tmp, `agent-${side}.sh`);
      writeFileSync(sh, `WS='${workspace}' OUT='${out}' exec bash ${join(tmp, "work.sh")}\n`);
      const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home, ...(side === "b" ? { MANDU_HOME: join(tmp, "mandu-home-b") } : {}) };
      return runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", sh], env, workspace, 300_000);
    };
    const a = launch("a");
    await waitFor(join(tmp, "a", "mid"));
    const b = launch("b");
    await waitFor(join(tmp, "b", "mid"));
    writeFileSync(join(tmp, "a", "release"), "");
    const ra = await a;
    const between = humanStatus(workspace);
    writeFileSync(join(tmp, "b", "release"), "");
    const rb = await b;
    const diag = `\n--- side a (tail) ---\n${ra.out.slice(-3000)}\n--- side b (tail) ---\n${rb.out.slice(-3000)}`;
    assert.equal(ra.code, 0, diag);
    assert.equal(rb.code, 0, diag);
    assert.ok(!ra.out.includes(KEY) && !rb.out.includes(KEY), `CONFIDENTIALITY VIOLATION${diag}`);
    assert.match(ra.out, /STATUS0<>/, `side a: clean in its world${diag}`);
    assert.match(rb.out, /STATUS0<>/, `side b: clean in its world${diag}`);
    assert.equal(between, " M .env\n", "side b still holds the entry after side a ended");
    // Before the fix side b put back its launch stat, side a's twin stat:
    // ` M .env` with no diff for good, and no crash record in either home.
    assert.equal(humanStatus(workspace), "", `outside, clean after both${diag}`);
  }, { mode: "secrets", seed });
});

test("T7 (bind) only the launch's own repositories are patched: another repository's index under HOME is never written, so the human's git there stays clean while the session runs", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    // A repository the session never touches, its .env tracked and twinned
    // (the walk covers HOME), as the main checkout is on a dev host.
    const other = join(home, "other");
    mkdirSync(other, { recursive: true });
    seed(other);
    git(other, "init", "-q");
    git(other, "add", "-A");
    git(other, "commit", "-qm", "other");
    moreHistory(other);
    const otherIndex = readFileSync(join(other, ".git", "index"));
    writeFileSync(join(tmp, "work.sh"), String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
cd "$OTHER"
echo "OTHER<$(GIT_OPTIONAL_LOCKS=0 ${AGENT_GIT} status --porcelain | tr '\n' '|')>"
echo "OTHERSEEN<$(/bin/cat .env 2>&1 | tr '\n' '|')>"
${PAUSE}
echo "AGENT_DONE"
`);
    const sh = join(tmp, "agent.sh");
    writeFileSync(sh, `WS='${workspace}' OTHER='${other}' OUT='${tmp}' exec bash ${join(tmp, "work.sh")}\n`);
    const launched = runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", sh],
      { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home }, workspace, 240_000);
    await waitFor(join(tmp, "mid"));
    const duringOther = humanStatus(other);
    const duringOwn = humanStatus(workspace);
    const otherIndexDuring = readFileSync(join(other, ".git", "index"));
    writeFileSync(join(tmp, "release"), "");
    const r = await launched;
    const diag = `\n--- launch output (tail) ---\n${r.out.slice(-6000)}`;
    assert.equal(r.code, 0, diag);
    assert.ok(!r.out.includes(KEY), `CONFIDENTIALITY VIOLATION${diag}`);
    assert.match(r.out, /OTHERSEEN<STRIPE_SECRET_KEY='?\$MDU:/, `the other repository's .env is twinned too (the test is not vacuous)${diag}`);
    assert.match(r.out, /STATUS0<>/, `the launch's own repository: clean in the agent's world${diag}`);
    assert.match(r.out, /OTHER< M \.env\|>/, `another repository: the twin shows modified in the agent's world, as before the patch${diag}`);
    assert.equal(duringOwn, " M .env\n", "the launch's own repository: patched (the trade-off, T3)");
    assert.equal(duringOther, "", "another repository: the human's git is clean while the session runs");
    assert.ok(otherIndexDuring.equals(otherIndex), "another repository's index never written");
    assert.equal(humanStatus(other), "", "and clean after");
    assert.equal(humanStatus(workspace), "", "the launch's own repository clean after");
  }, { mode: "secrets", seed });
});

test("T5 (bind-only: no guard, posture gated) the index is NOT patched: a human's git stash there would replace the real file and detach the bind (review of !1642 M1)", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    const indexBefore = readFileSync(join(workspace, ".git", "index"));
    writeFileSync(join(tmp, "work.sh"), String.raw`
set -u
cd "$WS"
echo "STATUS0<$(GIT_OPTIONAL_LOCKS=0 ${AGENT_GIT} status --porcelain | tr '\n' '|')>"
echo "AGENT_DONE"
`);
    const sh = join(tmp, "agent.sh");
    writeFileSync(sh, `WS='${workspace}' OUT='${tmp}' exec bash ${join(tmp, "work.sh")}\n`);
    const r = await runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--no-net-guard", "--target", "claude", "--", "/bin/sh", sh],
      { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home }, workspace, 240_000);
    const diag = `\n--- launch output (tail) ---\n${r.out.slice(-6000)}`;
    assert.equal(r.code, 0, diag);
    assert.ok(!r.out.includes(KEY), `CONFIDENTIALITY VIOLATION${diag}`);
    assert.match(r.out, /behind placeholder copies by the mount layer only|posture: gated/, `the bind-only posture${diag}`);
    assert.match(r.out, /STATUS0< M \.env\|>/, `unpatched: the twin shows modified to the agent's git, as before${diag}`);
    assert.ok(readFileSync(join(workspace, ".git", "index")).equals(indexBefore), "the human's index never written");
    assert.equal(humanStatus(workspace), "", "clean outside throughout");
  }, { mode: "secrets", seed });
});

test("T4 (bind) a launcher killed mid-session leaves its crash record; the next launch puts the index stat back before its own", { skip: GATE, timeout: 400_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    writeFileSync(join(tmp, "work.sh"), String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
${PAUSE}
`);
    const sh = join(tmp, "agent.sh");
    writeFileSync(sh, `WS='${workspace}' OUT='${tmp}' exec bash ${join(tmp, "work.sh")}\n`);
    const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home };
    const child = spawn(LAUNCHER_TSX, [LAUNCHER_MAIN, "--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", sh], {
      cwd: workspace, env: env as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"], detached: true,
    });
    let out1 = "";
    child.stdout!.setEncoding("utf8").on("data", (c: string) => { out1 += c; });
    child.stderr!.setEncoding("utf8").on("data", (c: string) => { out1 += c; });
    const closed = new Promise<void>((res) => child.on("close", () => res()));
    const exited = new Promise<void>((res) => child.on("exit", () => res()));
    await waitFor(join(tmp, "mid"));
    process.kill(-child.pid!, "SIGKILL");
    await exited; // no exit path of the launcher ran
    writeFileSync(join(tmp, "release"), "");
    await closed;
    assert.ok(!out1.includes(KEY), "CONFIDENTIALITY VIOLATION in the killed session");
    assert.match(out1, /STATUS0<>/, `the killed session's agent saw a clean tree\n${out1.slice(-4000)}`);
    assert.equal(humanStatus(workspace), " M .env\n", "after the crash, the twin's stat is still in the index");

    // The next launch: its agent does nothing.
    writeFileSync(sh, "exit 0\n");
    const r = await runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", sh], env, workspace, 240_000);
    const diag = `\n--- launch output (tail) ---\n${r.out.slice(-6000)}`;
    assert.equal(r.code, 0, diag);
    assert.match(r.out, /put back the index stat of a protected file an earlier session left/, `the next launch says it repaired it${diag}`);
    assert.equal(humanStatus(workspace), "", `clean again outside${diag}`);
  }, { mode: "secrets", seed });
});

/** Launch with `env`, wait for the agent's pause, SIGKILL the launcher's
 *  whole group (no exit path of it runs), then release the paused agent.
 *  Returns what the killed launch printed. */
async function killedLaunch(tmp: string, workspace: string, env: Record<string, string | undefined>, tag: string): Promise<string> {
  const out = join(tmp, tag);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(tmp, `work-${tag}.sh`), String.raw`
set -u
cd "$WS"
echo "STATUS0<$(${AGENT_GIT} status --porcelain | tr '\n' '|')>"
${PAUSE}
`);
  const sh = join(tmp, `agent-${tag}.sh`);
  writeFileSync(sh, `WS='${workspace}' OUT='${out}' exec bash ${join(tmp, `work-${tag}.sh`)}\n`);
  const child = spawn(LAUNCHER_TSX, [LAUNCHER_MAIN, "--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", sh], {
    cwd: workspace, env: env as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"], detached: true,
  });
  let printed = "";
  child.stdout!.setEncoding("utf8").on("data", (c: string) => { printed += c; });
  child.stderr!.setEncoding("utf8").on("data", (c: string) => { printed += c; });
  const closed = new Promise<void>((res) => child.on("close", () => res()));
  const exited = new Promise<void>((res) => child.on("exit", () => res()));
  await waitFor(join(out, "mid"));
  process.kill(-child.pid!, "SIGKILL");
  await exited;
  writeFileSync(join(out, "release"), "");
  await closed;
  return printed;
}

test("T8 (bind) a launcher killed in a Mandu home that is then removed (the demo battery's sides): its crash record survives in the HOME's store, and `mandu reap` or the next launch from another Mandu home puts the real stat back", { skip: GATE, timeout: 600_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    moreHistory(workspace);
    const base = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home };
    for (const healer of ["reap", "next-launch"] as const) {
      const scratch = join(tmp, `scratch-home-${healer}`);
      const killed = await killedLaunch(tmp, workspace, { ...base, MANDU_HOME: scratch }, `k-${healer}`);
      assert.ok(!killed.includes(KEY), "CONFIDENTIALITY VIOLATION in the killed session");
      assert.match(killed, /STATUS0<>/, `${healer}: the killed session's agent saw a clean tree\n${killed.slice(-4000)}`);
      rmSync(scratch, { recursive: true, force: true }); // the side's home goes with it
      assert.equal(humanStatus(workspace), " M .env\n", `${healer}: the dead session's twin stat is still in the index`);
      const other = { ...base, MANDU_HOME: join(tmp, `other-home-${healer}`) };
      if (healer === "reap") {
        const r = await runLauncher(["reap"], other, workspace, 120_000);
        assert.match(r.out, /restored the index stat of a protected file in /, `reap from another Mandu home restores it\n${r.out.slice(-3000)}`);
      } else {
        writeFileSync(join(tmp, "noop.sh"), "exit 0\n");
        const r = await runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", join(tmp, "noop.sh")], other, workspace, 240_000);
        assert.equal(r.code, 0, r.out.slice(-4000));
        assert.match(r.out, /put back the index stat of a protected file an earlier session left/, `the next launch from another Mandu home restores it first\n${r.out.slice(-3000)}`);
      }
      assert.equal(humanStatus(workspace), "", `${healer}: clean outside again`);
    }
  }, { mode: "secrets", seed });
});
