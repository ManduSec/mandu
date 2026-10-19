// tmp-gc.test.mjs — scripts/tmp-gc.mjs, the pruner of this user's stale temp
// files (docs/design/testing/test-organization.md §8.5.1): the names it may
// take, the ages, the owner and filesystem rules, the live-process holds (an
// injected process table, then the real /proc: a cwd, an open file, an
// environment path, a bound socket), each class over a temp tree, the throttle,
// the inode warning and the CLI. Every tree is the test's own; nothing outside
// it is touched (the CLI runs get --root).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

import { tmpDir } from "./lib/tmp-dir.mjs";
import {
  DEFAULTS, applyGc, claudeSlug, holdIndex, inodeWarning, isClaudeProcess, leftoverName, main, planGc, readProcs,
  socketPid, stampPath, throttled, touchStamp, treeState,
} from "../tmp-gc.mjs";

const UID = process.getuid();
const H = 3600e3;
const LINUX = process.platform === "linux";
// "now" for the plan: 100 h after the tree was made, so whatever the test
// made is old; a fresh entry gets its mtime (or atime) set to NOW.
const NOW = Date.now() + 100 * H;
const fresh = (p, { atimeOnly = false } = {}) => {
  const st = fs.lstatSync(p);
  fs.utimesSync(p, atimeOnly ? NOW / 1000 : st.atimeMs / 1000, atimeOnly ? st.mtimeMs / 1000 : NOW / 1000);
};
const root = () => fs.realpathSync(tmpDir("tmp-gc-"));
const put = (p, body = "x") => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); return p; };
const noProcs = (o = {}) => ({ ok: true, held: new Set(), claudeCwds: new Set(), alive: () => false, ...o });
const paths = (plan) => plan.remove.map((r) => r.path).sort();
const SID = (n) => `${String(n).padStart(8, "0")}-1111-2222-3333-444455556666`;

/** A bound Unix socket at `p` that outlives its server: a child binds it and
 *  is SIGKILLed, so nothing unlinks it. */
async function deadSocket(p) {
  const child = spawn(process.execPath, ["-e", `require("net").createServer().listen(${JSON.stringify(p)}, () => console.log("up"))`], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((res) => child.stdout.once("data", res));
  child.kill("SIGKILL");
  await new Promise((res) => child.once("exit", res));
  assert.ok(fs.lstatSync(p).isSocket());
}

// ── names ──────────────────────────────────────────────────────────────────────

test("leftoverName: the test leftovers' prefixes and the extracted .so files; never a cache or the runtime base", () => {
  for (const n of ["mandu-suites-AbC123", "mdu-w-x", "org.chromium.Chromium.abc", "shot-1", "q-chrome-x", "aio-stock-1", "qemu_run_1", "v-abc",
    ".9adf7ffdf3e2efb7-00000000.so", `.bun-${UID}-89812e6e6a68aaeb.so`]) assert.equal(leftoverName(n, UID), true, n);
  for (const n of ["mandu-kernel-vm-cache", "mandu-vm-cache", `mandu-${UID}`, "mandu", "tsx-0", "node-compile-cache", "claude-1",
    "systemd-private-x", ".X11-unix", `.bun-${UID + 1}-89812e6e6a68aaeb.so`, ".9adf.so", "my-mandu-x", "zshAbc"]) assert.equal(leftoverName(n, UID), false, n);
  assert.equal(leftoverName("twin-index-x", UID), false);
  assert.equal(leftoverName("twin-index-x", UID, ["twin-index-"]), true, "--prefix adds a prefix");
});

test("claudeSlug, socketPid, isClaudeProcess", () => {
  assert.equal(claudeSlug("/home/u/project/mandu/.claude/worktrees/a-b"), "-home-u-project-mandu--claude-worktrees-a-b");
  assert.equal(socketPid("12345.pipe"), 12345);
  assert.equal(socketPid("srt-mux-25233-0.sock"), 25233);
  assert.equal(socketPid("x.pipe"), null);
  assert.equal(socketPid("srt-mux-1.sock"), null);
  assert.equal(isClaudeProcess("claude", ["claude", "-w"]), true);
  assert.equal(isClaudeProcess("node", ["/usr/bin/node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"]), true);
  assert.equal(isClaudeProcess("MainThread", ["/home/u/.local/bin/claude"]), true);
  assert.equal(isClaudeProcess("node", ["node", "claude-helper.js"]), false);
});

test("holdIndex: a held path holds every dir above it, not its siblings", () => {
  const idx = holdIndex(new Set(["/t/a/b/c.txt"]));
  for (const p of ["/t/a/b/c.txt", "/t/a/b", "/t/a", "/t"]) assert.ok(idx.has(p), p);
  for (const p of ["/t/a/b/d", "/t/b", "/t/a/b/c.txt/x"]) assert.ok(!idx.has(p), p);
});

// ── the tree's state ───────────────────────────────────────────────────────────

test("treeState: the newest mtime or ctime of the whole tree, its inodes, and what makes it foreign", () => {
  const r = root();
  put(path.join(r, "e/a/b/f"));
  const s = treeState(path.join(r, "e"), { uid: UID });
  assert.equal(s.inodes, 4);
  assert.equal(s.foreign, null);
  fresh(path.join(r, "e/a/b/f"));
  assert.ok(treeState(path.join(r, "e"), { uid: UID }).newest >= NOW - 1000, "a deep fresh file makes the whole tree fresh");
  assert.match(treeState(path.join(r, "e"), { uid: UID + 1 }).foreign, /owned by uid/);
  assert.match(treeState(path.join(r, "e"), { uid: UID, dev: -1 }).foreign, /another filesystem/);
});

// ── the plan, class by class ───────────────────────────────────────────────────

test("leftovers: an old one goes, a fresh one (anywhere in its tree) stays, an unknown name stays, a cache name stays", () => {
  const r = root();
  put(path.join(r, "mandu-old-1/deep/f"));
  put(path.join(r, "mdu-fresh/deep/f")); fresh(path.join(r, "mdu-fresh/deep/f"));
  put(path.join(r, "unrelated-x/f"));
  put(path.join(r, "mandu-kernel-vm-cache/f"));
  put(path.join(r, ".abc123-00000001.so"));
  fs.symlinkSync("/etc", path.join(r, "mandu-link"));
  const plan = planGc({ root: r, now: NOW, procs: noProcs() });
  assert.deepEqual(paths(plan), [path.join(r, ".abc123-00000001.so"), path.join(r, "mandu-link"), path.join(r, "mandu-old-1")].sort());
  assert.equal(plan.remove.find((x) => x.path.endsWith("mandu-old-1")).inodes, 3);
  assert.equal(plan.kept.recent, 1);
  // a younger "now" keeps the old one too (the age is the threshold's)
  assert.deepEqual(paths(planGc({ root: r, now: Date.now() + 2 * H, procs: noProcs(), opts: { leftoverHours: 24 } })), []);
  assert.deepEqual(paths(planGc({ root: r, now: Date.now() + 2 * H, procs: noProcs(), opts: { leftoverHours: 1 } })).length, 3);
  // applying removes exactly the plan; the symlink's target is untouched
  const { removed, failed } = applyGc(plan);
  assert.equal(removed.length, 3); assert.deepEqual(failed, []);
  assert.ok(!fs.existsSync(path.join(r, "mandu-old-1")) && !fs.existsSync(path.join(r, "mandu-link")));
  assert.ok(fs.existsSync("/etc") && fs.existsSync(path.join(r, "mdu-fresh")) && fs.existsSync(path.join(r, "unrelated-x")) && fs.existsSync(path.join(r, "mandu-kernel-vm-cache")));
});

test("owner: nothing another uid owns is ever planned", () => {
  const r = root();
  put(path.join(r, "mandu-old/f"));
  put(path.join(r, `tsx-${UID + 1}/abc`));
  fs.mkdirSync(path.join(r, `claude-${UID + 1}/-x/${SID(1)}`), { recursive: true });
  // the same tree, read as another uid's: every entry is someone else's
  const plan = planGc({ root: r, uid: UID + 1, now: NOW, procs: noProcs() });
  assert.deepEqual(paths(plan), []);
});

test("holds: an entry a live process holds at or under it stays; a held path elsewhere does not keep it", () => {
  const r = root();
  for (const n of ["mandu-cwd", "mandu-file", "mandu-other"]) put(path.join(r, n, "sub/f"));
  const held = new Set([path.join(r, "mandu-cwd"), path.join(r, "mandu-file/sub/f"), path.join(r, "unrelated/x")]);
  const plan = planGc({ root: r, now: NOW, procs: noProcs({ held }) });
  assert.deepEqual(paths(plan), [path.join(r, "mandu-other")]);
  assert.equal(plan.kept.held, 2);
});

test("tsx cache: old files and dead pids' pipes go; a file read lately (atime), a live pid's pipe and the dir itself stay", async () => {
  const r = root();
  const d = path.join(r, `tsx-${UID}`);
  put(path.join(d, "17922-old"));
  put(path.join(d, "17922-read")); fresh(path.join(d, "17922-read"), { atimeOnly: true });
  await deadSocket(path.join(d, "999991.pipe"));
  await deadSocket(path.join(d, "999992.pipe"));
  const plan = planGc({ root: r, now: NOW, procs: noProcs({ alive: (pid) => pid === 999992 }) });
  assert.deepEqual(paths(plan), [path.join(d, "17922-old"), path.join(d, "999991.pipe")].sort());
  assert.ok(plan.remove.every((x) => x.cls === "tsx-cache"));
  applyGc(plan);
  assert.ok(fs.existsSync(d) && fs.existsSync(path.join(d, "17922-read")) && fs.existsSync(path.join(d, "999992.pipe")));
  // a bound socket (in /proc/net/unix, so in `held`) stays whatever its pid
  const plan2 = planGc({ root: r, now: NOW, procs: noProcs({ held: new Set([path.join(d, "999992.pipe")]) }) });
  assert.deepEqual(paths(plan2), []);
});

test("node compile cache: old files go, then the dirs they leave empty; the cache dir itself stays", () => {
  const r = root();
  const d = path.join(r, "node-compile-cache");
  put(path.join(d, "v22-x/a")); put(path.join(d, "v22-x/b"));
  put(path.join(d, "v24-y/a")); put(path.join(d, "v24-y/fresh")); fresh(path.join(d, "v24-y/fresh"));
  const plan = planGc({ root: r, now: NOW, procs: noProcs() });
  assert.deepEqual(paths(plan), [path.join(d, "v22-x"), path.join(d, "v22-x/a"), path.join(d, "v22-x/b"), path.join(d, "v24-y/a")].sort());
  const { removed, failed } = applyGc(plan);
  assert.equal(removed.length, 4); assert.deepEqual(failed, []);
  assert.deepEqual(fs.readdirSync(d), ["v24-y"]);
});

test("dead sockets: a top-level srt-mux-<pid>-<n>.sock of a gone pid goes; a live pid's, and a plain file of that name, stay", async () => {
  const r = root();
  await deadSocket(path.join(r, "srt-mux-999993-0.sock"));
  await deadSocket(path.join(r, "srt-mux-999994-0.sock"));
  put(path.join(r, "srt-mux-999995-0.sock"));
  const plan = planGc({ root: r, now: Date.now(), procs: noProcs({ alive: (pid) => pid === 999994 }) });
  assert.deepEqual(paths(plan), [path.join(r, "srt-mux-999993-0.sock")]);
  assert.equal(plan.remove[0].cls, "dead-socket");
});

test("Claude Code scratch: an ended session's old dir goes, then its cwd's empty dir; a live cwd's sessions get the longer age; a live session id stays everywhere", () => {
  const r = root();
  const c = path.join(r, `claude-${UID}`);
  const ended = "-home-u-ended", live = "-home-u-live", moved = "-home-u-moved";
  put(path.join(c, ended, SID(1), "scratchpad/big/f"));
  put(path.join(c, live, SID(2), "scratchpad/f"));                         // old by 48 h, not by 168 h
  put(path.join(c, live, SID(3), "tasks/x.output")); fresh(path.join(c, live, SID(3), "tasks/x.output"));
  put(path.join(c, moved, SID(4), "scratchpad/f"));                        // the session moved: held in another slug
  put(path.join(c, "-home-u-other", SID(4), "tasks/y.output"));
  put(path.join(c, "bash-edit-diff/abc"));                                 // not a cwd's dir: never touched
  put(path.join(c, ended, "not-a-session/f"));
  fs.mkdirSync(path.join(c, "-home-u-empty"));
  const procs = noProcs({
    claudeCwds: new Set(["/home/u/live"]),
    held: new Set([path.join(c, "-home-u-other", SID(4), "tasks/y.output")]),
  });
  const p48 = planGc({ root: r, now: Date.now() + 100 * H, procs });
  assert.deepEqual(paths(p48), [path.join(c, ended, SID(1)), path.join(c, "-home-u-empty")].sort(),
    "the ended session goes; its cwd's dir keeps a non-session entry; the empty cwd dir goes");
  assert.ok(p48.remove.every((x) => x.cls === "claude-session"));
  const p200 = planGc({ root: r, now: Date.now() + 200 * H, procs });
  assert.ok(paths(p200).includes(path.join(c, live, SID(2))), "a live cwd's idle session goes past --live-session-hours");
  assert.ok(!paths(p200).includes(path.join(c, live, SID(3))), "the fresh one stays");
  assert.ok(!paths(p200).some((p) => p.includes(SID(4))), "a session id held under any cwd stays under every cwd");
  assert.ok(!paths(p200).includes(path.join(c, live)), "a live cwd's dir stays");
  // apply: rm the session tree, then rmdir the emptied cwd dir
  fs.rmSync(path.join(c, ended, "not-a-session"), { recursive: true });
  const p = planGc({ root: r, now: Date.now() + 100 * H, procs });
  assert.deepEqual(paths(p), [path.join(c, ended), path.join(c, ended, SID(1)), path.join(c, "-home-u-empty")].sort());
  const { failed } = applyGc(p);
  assert.deepEqual(failed, []);
  assert.ok(!fs.existsSync(path.join(c, ended)) && fs.existsSync(path.join(c, "bash-edit-diff/abc")));
});

// ── the real /proc ─────────────────────────────────────────────────────────────

test("readProcs on the real /proc: a child's cwd, open file, environment path and bound socket hold their entries", { skip: !LINUX && "Linux /proc" }, async (t) => {
  const r = root();
  for (const n of ["mandu-cwd", "mandu-fd", "mandu-env", "mandu-sock", "mandu-free"]) fs.mkdirSync(path.join(r, n, "sub"), { recursive: true });
  const file = put(path.join(r, "mandu-fd/sub/open.txt"));
  const sock = path.join(r, "mandu-sock/s.sock");
  const code = `const fs=require("fs");fs.openSync(${JSON.stringify(file)},"r");` +
    `require("net").createServer().listen(${JSON.stringify(sock)},()=>console.log("up"));setInterval(()=>{},1e3);`;
  const child = spawn(process.execPath, ["-e", code], {
    cwd: path.join(r, "mandu-cwd/sub"), env: { ...process.env, MANDU_TEST_PATH: path.join(r, "mandu-env/sub") }, stdio: ["ignore", "pipe", "inherit"],
  });
  t.after(() => child.kill("SIGKILL"));
  await new Promise((res) => child.stdout.once("data", res));
  const procs = readProcs({ root: r });
  assert.equal(procs.ok, true);
  assert.equal(procs.alive(child.pid), true);
  assert.equal(procs.alive(2 ** 22 + 1), false);
  for (const p of [path.join(r, "mandu-cwd/sub"), file, path.join(r, "mandu-env/sub"), sock]) assert.ok(procs.held.has(p), `held: ${p}`);
  const plan = planGc({ root: r, now: NOW, procs });
  assert.deepEqual(paths(plan), [path.join(r, "mandu-free")]);
  assert.equal(plan.kept.held, 4);
  // with no proc to read, nothing may be removed (the CLI's rule)
  assert.equal(readProcs({ root: r, proc: path.join(r, "no-proc") }).ok, false);
});

// ── throttle, warning, CLI ─────────────────────────────────────────────────────

test("throttled / touchStamp: under the minutes since the stamp; never for 0 minutes or no stamp", () => {
  const r = root();
  const s = stampPath(r);
  assert.equal(path.basename(s), `.mandu-tmp-gc-${UID}.stamp`);
  assert.equal(throttled(s, 60), false, "no stamp");
  touchStamp(s, Date.now());
  assert.equal(throttled(s, 60), true);
  assert.equal(throttled(s, 0), false);
  assert.equal(throttled(s, 60, Date.now() + 61 * 60e3), false);
  assert.equal(leftoverName(path.basename(s), UID), false, "the stamp is never a leftover");
});

test("inodeWarning: none under the percent; over it, the usage, this user's biggest entries and the owners", () => {
  const usage = { files: 1000, used: 850, percent: 85 };
  const users = { mine: [{ name: "claude-1007", inodes: 600 }, { name: "tsx-1007", inodes: 100 }], owners: [[1007, 40], [1000, 12]], partial: false };
  assert.equal(inodeWarning("/t", { percent: 90, usage, users }), null);
  const w = inodeWarning("/t", { percent: 80, usage, users });
  assert.match(w, /^WARNING: \/t has used 85% of its inodes \(850 of 1,000\)/);
  assert.match(w, /claude-1007 600, tsx-1007 100/);
  assert.match(w, /uid 1007 40, uid 1000 12/);
  assert.match(w, /node scripts\/tmp-gc\.mjs/);
  // the real call over a real root, forced over by percent 0
  const r = root();
  put(path.join(r, "mandu-x/a/b"));
  assert.match(inodeWarning(r, { percent: 0 }), /mandu-x 3/);
});

test("CLI: a dry run reports and removes nothing; --apply removes; --throttle-minutes skips a second run; --json; --hook; usage errors", { skip: !LINUX && "Linux /proc" }, () => {
  const r = root();
  put(path.join(r, "mandu-stale/f"));
  // `now` a second ahead: with --leftover-hours 0 the cutoff is `now`, and a
  // file made in the same millisecond has a fractional mtime past Date.now().
  const run = (...args) => { const o = [], e = []; const rc = main([...args, "--root", r, "--leftover-hours", "0", "--warn-percent", "101"], { out: (s) => o.push(s), err: (s) => e.push(s), now: Date.now() + 1000 }); return { rc, out: o.join("\n"), err: e.join("\n") }; };
  let x = run();
  assert.equal(x.rc, 0);
  assert.match(x.out, /\(dry run; --apply removes\): would remove 1 entries, 2 inodes/);
  assert.match(x.out, /leftover\s+1 entries\s+2 inodes/);
  assert.ok(fs.existsSync(path.join(r, "mandu-stale")));
  x = run("--list");
  assert.match(x.out, new RegExp(`leftover\\t2\\t${path.join(r, "mandu-stale")}`));
  x = run("--json");
  assert.equal(JSON.parse(x.out).total.inodes, 2);
  x = run("--hook");
  assert.equal(x.out, "", "under --hook-min-inodes (1000) the hook says nothing");
  x = run("--hook", "--hook-min-inodes", "1");
  assert.match(x.out, /holds 1 stale entries of this user's \(2 inodes.*node scripts\/tmp-gc\.mjs --apply/);
  x = run("--apply", "--throttle-minutes", "60");
  assert.match(x.out, /: removed 1 entries, 2 inodes/);
  assert.ok(!fs.existsSync(path.join(r, "mandu-stale")));
  put(path.join(r, "mandu-stale2/f"));
  x = run("--apply", "--throttle-minutes", "60");
  assert.match(x.out, /under 60 minute\(s\) ago.*nothing done/);
  assert.ok(fs.existsSync(path.join(r, "mandu-stale2")));
  x = run("--apply", "--quiet");
  assert.match(x.out, /^tmp-gc: removed 1 stale entries of this user's from /);
  for (const bad of [["--cache-hours", "-1"], ["--nope"], ["--session-hours", "x"]]) assert.equal(run(...bad).rc, 2, bad.join(" "));
  assert.equal(main(["--root", path.join(r, "nowhere")], { out: () => {}, err: () => {} }), 2);
});

test("the defaults are the documented ones", () => {
  assert.deepEqual({ ...DEFAULTS }, { leftoverHours: 24, cacheHours: 24, sessionHours: 48, liveSessionHours: 168, warnPercent: 80, throttleMinutes: 0 });
});
