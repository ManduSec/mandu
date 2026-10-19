#!/usr/bin/env node
// scripts/tmp-gc.mjs — remove this user's own stale entries from the host's
// temp dir (docs/design/testing/test-organization.md §8.5.1). A dry run unless
// --apply. Node builtins only; Linux (it needs /proc for the live-process
// check, and removes nothing where /proc is absent).
//
//   node scripts/tmp-gc.mjs [--apply] [--root DIR] [--leftover-hours 24]
//       [--cache-hours 24] [--session-hours 48] [--live-session-hours 168]
//       [--prefix P]... [--throttle-minutes N] [--warn-percent 80]
//       [--quiet | --hook [--hook-min-inodes 1000]] [--list] [--json]
//
// Why: /tmp on a shared dev and CI host is a tmpfs with a fixed inode count.
// Tests run by hand (outside run-suites, which gives each suite its own
// TMPDIR), tsx's compile cache, Node's compile cache and Claude Code's
// per-session scratch dirs all grow without bound there, and at 100% of the
// inodes every write of every process fails (2026-10-18).
//
// What it may remove (each class with its own age; "old" means nothing in the
// entry's whole tree was modified or changed, mtime and ctime, for that long):
//   leftover        a top-level entry whose name is a test leftover's prefix
//                   (LEFTOVER_PREFIXES, plus --prefix), a `.<hex>-<hex>.so`
//                   (a bun-compiled CLI's extracted native module) or a
//                   `.bun-<uid>-<hex>.so`, old by --leftover-hours. Never a
//                   name that says cache, nor `mandu-<digits>` (the runtime
//                   base dir fallback, scripts/lib/runtime-base.sh).
//   tsx-cache       a file in `tsx-<uid>/` (tsx's content-hash compile cache)
//                   neither read nor written for --cache-hours (its atime
//                   counts too: a cache file is written once and read often;
//                   relatime moves atime at most daily, hence 24 h); a
//                   `<pid>.pipe` socket there whose pid is gone and that no
//                   process has bound.
//   node-cache      a file under `node-compile-cache/` (Node's
//                   module.enableCompileCache), by the same age, and the
//                   empty dirs it leaves.
//   dead-socket     a top-level `srt-mux-<pid>-<n>.sock` whose pid is gone and
//                   that no process has bound.
//   claude-session  Claude Code's per-session scratch, `claude-<uid>/<cwd
//                   slug>/<session uuid>/`, old by --session-hours when no
//                   live `claude` process has that cwd, else old by
//                   --live-session-hours (a long-lived process's earlier
//                   sessions, after /clear); then the cwd's dir once empty.
// What it never removes:
//   - anything another uid owns, or any tree with an inode another uid owns
//     or on another filesystem (a mount inside it) — the whole entry stays;
//   - anything a live process of this user holds: its cwd or root, an open
//     file or a mapped one (/proc/<pid>/fd, /proc/<pid>/maps), a path in its
//     environment (TMPDIR, a socket path), or a Unix socket bound in this net
//     namespace (/proc/net/unix) — at or under the entry;
//   - an unreadable directory's tree;
//   - anything at all where /proc is not there to check (macOS): a report only.
// --throttle-minutes N does nothing more when the last run that got past the
// throttle was under N minutes ago (the stamp `.mandu-tmp-gc-<uid>.stamp` in
// the root, its mtime); the inode check still runs. --warn-percent P (default
// 80) prints a warning when the root's filesystem has used P% of its inodes,
// naming this user's biggest entries and every owner's count of top-level
// entries. --quiet prints only that warning and one line when something was
// removed. --hook is --quiet plus, in a dry run, one line naming the stale
// count and the command that removes it when it is --hook-min-inodes (1000)
// or more (the agent sessions' SessionStart hook's form). --list prints every
// path it would remove. Exit 0 (a failure to remove one path is reported, not
// fatal), 2 on a usage error.

import {
  existsSync, lstatSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, rmdirSync, statfsSync,
  unlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const DEFAULTS = Object.freeze({
  leftoverHours: 24, cacheHours: 24, sessionHours: 48, liveSessionHours: 168, warnPercent: 80, throttleMinutes: 0,
});

/** Top-level names this repository's tests and tools make in the temp dir
 *  (mkdtemp prefixes), and the browser and VM tools' own. */
export const LEFTOVER_PREFIXES = Object.freeze([
  "mandu-", "mdu-", "org.chromium.Chromium", "shot", "q-chrome", "aio-stock", "qemu_run_", "v-",
]);

const HEX_SO = /^\.[0-9a-f]+-[0-9a-f]+\.so$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEEP_NAME = [/cache/i, /^mandu-\d+$/];

/** Is `name` (a top-level entry of the root) a leftover's name? */
export function leftoverName(name, uid, prefixes = LEFTOVER_PREFIXES) {
  if (KEEP_NAME.some((re) => re.test(name))) return false;
  if (HEX_SO.test(name)) return true;
  if (new RegExp(`^\\.bun-${uid}-[0-9a-f]+\\.so$`).test(name)) return true;
  return prefixes.some((p) => name.startsWith(p));
}

/** Claude Code's name for a cwd's dir under `claude-<uid>/`: every character
 *  but a letter or digit becomes `-`. */
export function claudeSlug(cwd) {
  return cwd.replace(/[^A-Za-z0-9]/g, "-");
}

/** The pid a dead-pid socket's name carries (`<pid>.pipe`,
 *  `srt-mux-<pid>-<n>.sock`), or null. */
export function socketPid(name) {
  const m = /^(\d+)\.pipe$/.exec(name) ?? /^srt-mux-(\d+)-\d+\.sock$/.exec(name);
  return m ? Number(m[1]) : null;
}

// ── the live processes ─────────────────────────────────────────────────────────

/** Is a process the `claude` CLI? Its comm, its argv[0]'s basename, or a
 *  node running Claude Code's cli.js. */
export function isClaudeProcess(comm, argv) {
  if (comm === "claude") return true;
  if (argv.length && basename(argv[0]) === "claude") return true;
  return argv.slice(0, 3).some((a) => /@anthropic-ai\/claude-code\/cli\.m?js$/.test(a));
}

/**
 * What this user's live processes hold, read from `proc`: `held`, the paths
 * under `root` they hold (cwd, root, open fds, mapped files, absolute paths
 * in their environment, bound Unix sockets of this net namespace); `claudeCwds`,
 * the cwds of the live `claude` processes; `alive(pid)`; `ok`, false where
 * there is no proc to read (then nothing may be removed).
 */
export function readProcs({ proc = "/proc", uid = process.getuid(), root }) {
  const held = new Set();
  const claudeCwds = new Set();
  const ok = existsSync(join(proc, "self"));
  const under = (p) => p.startsWith(root + "/");
  const add = (p) => { if (typeof p === "string") { p = p.replace(/ \(deleted\)$/, ""); if (under(p)) held.add(p); } };
  if (ok) {
    let pids = [];
    try { pids = readdirSync(proc).filter((n) => /^\d+$/.test(n)); } catch { /* none */ }
    for (const pid of pids) {
      const dir = join(proc, pid);
      try { if (lstatSync(dir).uid !== uid) continue; } catch { continue; }
      let cwd = null;
      try { cwd = readlinkSync(join(dir, "cwd")); add(cwd); } catch { /* gone or denied */ }
      try { add(readlinkSync(join(dir, "root"))); } catch { /* gone */ }
      try { for (const fd of readdirSync(join(dir, "fd"))) { try { add(readlinkSync(join(dir, "fd", fd))); } catch { /* closed */ } } } catch { /* gone */ }
      try {
        for (const line of readFileSync(join(dir, "maps"), "utf8").split("\n")) {
          const i = line.indexOf(" /");
          if (i >= 0) add(line.slice(i + 1).trim());
        }
      } catch { /* gone */ }
      try {
        for (const kv of readFileSync(join(dir, "environ"), "utf8").split("\0")) {
          const eq = kv.indexOf("=");
          if (eq > 0) for (const v of kv.slice(eq + 1).split(":")) add(v);
        }
      } catch { /* gone */ }
      if (cwd !== null) {
        let comm = "", argv = [];
        try { comm = readFileSync(join(dir, "comm"), "utf8").trim(); } catch { /* gone */ }
        try { argv = readFileSync(join(dir, "cmdline"), "utf8").split("\0").filter(Boolean); } catch { /* gone */ }
        if (isClaudeProcess(comm, argv)) claudeCwds.add(cwd);
      }
    }
    try {
      for (const line of readFileSync(join(proc, "net/unix"), "utf8").split("\n").slice(1)) {
        const f = line.trim().split(/\s+/);
        if (f.length >= 8) add(f.slice(7).join(" "));
      }
    } catch { /* no net/unix */ }
  }
  const alive = (pid) => existsSync(join(proc, String(pid)));
  return { ok, held, claudeCwds, alive };
}

/** A lookup that answers "does a live process hold `p` or anything under it":
 *  every held path and each of its ancestors. */
export function holdIndex(held) {
  const idx = new Set();
  for (let p of held) {
    while (p.length > 1 && !idx.has(p)) { idx.add(p); p = p.slice(0, p.lastIndexOf("/")) || "/"; }
  }
  return idx;
}

// ── a tree's state ─────────────────────────────────────────────────────────────

/**
 * Walk `p` (never following a link): `newest`, the latest mtime or ctime in
 * the tree (ms); `inodes`; `bytes` (allocated); `foreign`, a reason to keep
 * it whatever its age (another uid's inode, another filesystem, an unreadable
 * dir). Stops early once `newest` passes `cutoff` or `foreign` is set.
 */
export function treeState(p, { uid, dev, cutoff = Infinity }) {
  const s = { newest: 0, inodes: 0, bytes: 0, foreign: null };
  const stack = [p];
  while (stack.length) {
    const q = stack.pop();
    let st;
    try { st = lstatSync(q); } catch { continue; } // gone meanwhile
    s.inodes++;
    s.bytes += (st.blocks ?? 0) * 512;
    s.newest = Math.max(s.newest, st.mtimeMs, st.ctimeMs);
    if (st.uid !== uid) { s.foreign = `${q} is owned by uid ${st.uid}`; return s; }
    if (dev !== undefined && st.dev !== dev) { s.foreign = `${q} is on another filesystem`; return s; }
    if (s.newest > cutoff) return s;
    if (st.isDirectory()) {
      try { for (const k of readdirSync(q)) stack.push(join(q, k)); } catch { s.foreign = `${q} is unreadable`; return s; }
    }
  }
  return s;
}

// ── the plan ───────────────────────────────────────────────────────────────────

/**
 * What to remove under `root`. Pure but for the reads of the tree: `procs`
 * (readProcs' answer) and `now` are inputs. Returns `remove` ({path, cls,
 * inodes, bytes}, the deepest first where one holds another) and `kept`
 * (counts by reason: recent, held, foreign).
 */
export function planGc({ root, uid = process.getuid(), now = Date.now(), procs, opts = {} }) {
  const o = { ...DEFAULTS, ...opts };
  const prefixes = [...LEFTOVER_PREFIXES, ...(o.prefixes ?? [])];
  const H = 3600e3;
  const held = holdIndex(procs.held);
  const remove = [];
  const kept = { recent: 0, held: 0, foreign: 0 };
  let dev;
  try { dev = lstatSync(root).dev; } catch { return { remove, kept }; }
  const consider = (path, cls, hours) => {
    if (held.has(path)) { kept.held++; return false; }
    const cutoff = now - hours * H;
    const s = treeState(path, { uid, dev, cutoff });
    if (s.foreign) { kept.foreign++; return false; }
    if (s.newest > cutoff) { kept.recent++; return false; }
    remove.push({ path, cls, inodes: s.inodes, bytes: s.bytes });
    return true;
  };
  const owned = (p) => { try { const st = lstatSync(p); return st.uid === uid && st.dev === dev ? st : null; } catch { return null; } };

  let names = [];
  try { names = readdirSync(root); } catch { return { remove, kept }; }
  for (const name of names) {
    const p = join(root, name);
    if (name === `tsx-${uid}` || name === "node-compile-cache") {
      const st = owned(p);
      if (st?.isDirectory()) cacheDir(p, name === "node-compile-cache" ? "node-cache" : "tsx-cache");
      else if (name === "node-compile-cache") { try { if (lstatSync(p).isDirectory()) cacheDir(p, "node-cache"); } catch { /* gone */ } }
      continue;
    }
    if (name === `claude-${uid}`) { if (owned(p)?.isDirectory()) claudeDir(p); continue; }
    const pid = socketPid(name);
    if (pid !== null && name.startsWith("srt-mux-")) {
      const st = owned(p);
      if (st?.isSocket() && !procs.alive(pid)) consider(p, "dead-socket", 0);
      continue;
    }
    if (!leftoverName(name, uid, prefixes)) continue;
    if (!owned(p)) continue;
    consider(p, "leftover", o.leftoverHours);
  }
  return { remove, kept };

  // A cache dir: its old files go (and the dead pids' pipes), then the dirs
  // that are left empty and old; the cache dir itself stays.
  function cacheDir(dir, cls) {
    const cutoff = now - o.cacheHours * H;
    const walk = (d) => {
      let kids;
      try { kids = readdirSync(d); } catch { kept.foreign++; return false; }
      let empty = true;
      for (const k of kids) {
        const p = join(d, k);
        let st;
        try { st = lstatSync(p); } catch { continue; }
        if (st.uid !== uid || st.dev !== dev) { kept.foreign++; empty = false; continue; }
        if (st.isDirectory()) {
          const gone = walk(p);
          if (gone && !held.has(p) && Math.max(st.mtimeMs, st.ctimeMs) <= cutoff) remove.push({ path: p, cls, inodes: 1, bytes: 0, dir: true });
          else empty = false;
          continue;
        }
        const pid = cls === "tsx-cache" ? socketPid(k) : null;
        if (held.has(p)) { kept.held++; empty = false; continue; }
        if (pid !== null && st.isSocket()) {
          if (procs.alive(pid)) { kept.held++; empty = false; continue; }
        } else if (Math.max(st.atimeMs, st.mtimeMs, st.ctimeMs) > cutoff) { kept.recent++; empty = false; continue; }
        remove.push({ path: p, cls, inodes: 1, bytes: (st.blocks ?? 0) * 512 });
      }
      return empty;
    };
    walk(dir);
  }

  // Claude Code's scratch: claude-<uid>/<cwd slug>/<session uuid>/.
  function claudeDir(dir) {
    const liveSlugs = new Set([...procs.claudeCwds].map(claudeSlug));
    // A session's id is live wherever a process holds a path in one of its
    // dirs: a session that began in one cwd and moved (EnterWorktree) has a
    // dir under each, and its process's cwd names only the second.
    const liveSessions = new Set();
    for (const h of procs.held) {
      if (!h.startsWith(dir + "/")) continue;
      const s = h.slice(dir.length + 1).split("/")[1];
      if (s && UUID.test(s)) liveSessions.add(s);
    }
    let slugs = [];
    try { slugs = readdirSync(dir); } catch { return; }
    for (const slug of slugs) {
      const sd = join(dir, slug);
      const st = owned(sd);
      if (!st?.isDirectory() || !slug.startsWith("-")) continue;
      const live = liveSlugs.has(slug);
      let sessions = [];
      try { sessions = readdirSync(sd); } catch { continue; }
      let left = 0;
      for (const s of sessions) {
        const p = join(sd, s);
        if (!UUID.test(s) || !owned(p)?.isDirectory()) { left++; continue; }
        if (liveSessions.has(s)) { kept.held++; left++; continue; }
        if (!consider(p, "claude-session", live ? o.liveSessionHours : o.sessionHours)) left++;
      }
      // The cwd's dir once nothing is left in it (its own mtime moves when a
      // session goes, so its age is the age it had before this run).
      if (left === 0 && !live && !held.has(sd) && Math.max(st.mtimeMs, st.ctimeMs) <= now - o.sessionHours * H) {
        remove.push({ path: sd, cls: "claude-session", inodes: 1, bytes: 0, dir: true });
      }
    }
  }
}

/** Remove what the plan names, in order (a cache dir after its files).
 *  Returns {removed: [...], failed: [{path, error}]}. */
export function applyGc(plan) {
  const removed = [], failed = [];
  for (const r of plan.remove) {
    try {
      if (r.dir) rmdirSync(r.path);
      else if (r.cls === "leftover" || r.cls === "claude-session") rmSync(r.path, { recursive: true, force: true });
      else unlinkSync(r.path);
      removed.push(r);
    } catch (e) {
      if (e.code === "ENOENT") removed.push(r);
      else failed.push({ path: r.path, error: e.code ?? e.message });
    }
  }
  return { removed, failed };
}

// ── the inode check ────────────────────────────────────────────────────────────

/** The root's filesystem: inodes used and total, and the percent used. */
export function inodeUsage(root) {
  const s = statfsSync(root);
  const used = s.files - s.ffree;
  return { files: s.files, used, percent: s.files > 0 ? Math.round((used / s.files) * 100) : 0 };
}

/** Who fills the root: this user's top-level entries by inodes (the first
 *  `top`; the walk stops after `budgetMs`, `partial` then) and every owner's
 *  count of top-level entries. */
export function biggestUsers(root, { uid = process.getuid(), top = 5, budgetMs = 5000 } = {}) {
  const t0 = Date.now();
  const mine = [];
  const owners = new Map();
  let partial = false;
  let names = [];
  try { names = readdirSync(root); } catch { /* none */ }
  for (const name of names) {
    const p = join(root, name);
    let st;
    try { st = lstatSync(p); } catch { continue; }
    owners.set(st.uid, (owners.get(st.uid) ?? 0) + 1);
    if (st.uid !== uid) continue;
    if (Date.now() - t0 > budgetMs) { partial = true; continue; }
    mine.push({ name, inodes: treeState(p, { uid: st.uid }).inodes });
  }
  mine.sort((a, b) => b.inodes - a.inodes);
  return { mine: mine.slice(0, top), owners: [...owners].sort((a, b) => b[1] - a[1]), partial };
}

const n = (x) => x.toLocaleString("en-US");
const human = (b) => (b >= 2 ** 30 ? `${(b / 2 ** 30).toFixed(1)} GiB` : b >= 2 ** 20 ? `${(b / 2 ** 20).toFixed(1)} MiB` : `${Math.round(b / 1024)} KiB`);

/** The warning line, or null under `percent`. */
export function inodeWarning(root, { percent = DEFAULTS.warnPercent, uid = process.getuid(), usage, users } = {}) {
  let u = usage;
  try { u ??= inodeUsage(root); } catch { return null; }
  if (u.percent < percent) return null;
  const b = users ?? biggestUsers(root, { uid });
  const mine = b.mine.map((m) => `${m.name} ${n(m.inodes)}`).join(", ");
  const owners = b.owners.map(([o, c]) => `uid ${o} ${n(c)}`).join(", ");
  return `WARNING: ${root} has used ${u.percent}% of its inodes (${n(u.used)} of ${n(u.files)}); this user's biggest entries (inodes): ${mine || "none"}${b.partial ? " (partial)" : ""}; top-level entries by owner: ${owners}. node scripts/tmp-gc.mjs lists what is stale.`;
}

// ── the throttle ───────────────────────────────────────────────────────────────

export const stampPath = (root, uid = process.getuid()) => join(root, `.mandu-tmp-gc-${uid}.stamp`);

/** Is the last run under `minutes` ago? Never true for 0 minutes or no stamp. */
export function throttled(stamp, minutes, now = Date.now()) {
  if (!(minutes > 0)) return false;
  try { return now - lstatSync(stamp).mtimeMs < minutes * 60e3; } catch { return false; }
}

/** Mark a run (best effort: a full filesystem cannot take the stamp, and then
 *  the next run is not throttled, which is what a full one needs). */
export function touchStamp(stamp, now = Date.now()) {
  try { writeFileSync(stamp, ""); utimesSync(stamp, now / 1000, now / 1000); } catch { /* full or read-only */ }
}

// ── the CLI ────────────────────────────────────────────────────────────────────

const CLASSES = ["leftover", "tsx-cache", "node-cache", "dead-socket", "claude-session"];

export function summarize(list) {
  const by = Object.fromEntries(CLASSES.map((c) => [c, { entries: 0, inodes: 0, bytes: 0 }]));
  for (const r of list) { const c = by[r.cls]; c.entries++; c.inodes += r.inodes; c.bytes += r.bytes; }
  const total = Object.values(by).reduce((a, c) => ({ entries: a.entries + c.entries, inodes: a.inodes + c.inodes, bytes: a.bytes + c.bytes }), { entries: 0, inodes: 0, bytes: 0 });
  return { by, total };
}

export function main(argv = process.argv.slice(2), { out = console.log, err = console.error, proc = "/proc", now = Date.now() } = {}) {
  let a;
  try {
    a = parseArgs({
      args: argv, allowPositionals: false, options: {
        apply: { type: "boolean" }, root: { type: "string" }, quiet: { type: "boolean" }, hook: { type: "boolean" },
        list: { type: "boolean" }, json: { type: "boolean" }, "hook-min-inodes": { type: "string" },
        "leftover-hours": { type: "string" }, "cache-hours": { type: "string" }, "session-hours": { type: "string" },
        "live-session-hours": { type: "string" }, "throttle-minutes": { type: "string" }, "warn-percent": { type: "string" },
        prefix: { type: "string", multiple: true }, help: { type: "boolean", short: "h" },
      },
    }).values;
  } catch (e) { err(`tmp-gc: ${e.message}`); return 2; }
  if (a.help) { out("usage: node scripts/tmp-gc.mjs [--apply] [--root DIR] [--leftover-hours H] [--cache-hours H] [--session-hours H] [--live-session-hours H] [--prefix P]... [--throttle-minutes M] [--warn-percent P] [--quiet | --hook [--hook-min-inodes N]] [--list] [--json]"); return 0; }
  const num = (k, d) => {
    if (a[k] === undefined) return d;
    const v = Number(a[k]);
    if (!Number.isFinite(v) || v < 0) throw new Error(`--${k} wants a number >= 0, not ${a[k]}`);
    return v;
  };
  let opts;
  try {
    opts = {
      leftoverHours: num("leftover-hours", DEFAULTS.leftoverHours), cacheHours: num("cache-hours", DEFAULTS.cacheHours),
      sessionHours: num("session-hours", DEFAULTS.sessionHours), liveSessionHours: num("live-session-hours", DEFAULTS.liveSessionHours),
      throttleMinutes: num("throttle-minutes", DEFAULTS.throttleMinutes), warnPercent: num("warn-percent", DEFAULTS.warnPercent),
      hookMinInodes: num("hook-min-inodes", 1000),
      prefixes: (a.prefix ?? []).filter((p) => p.length >= 2),
    };
  } catch (e) { err(`tmp-gc: ${e.message}`); return 2; }
  let root;
  try { root = realpathSync(a.root ?? tmpdir()); } catch (e) { err(`tmp-gc: no root ${a.root ?? tmpdir()}: ${e.message}`); return 2; }
  const uid = process.getuid();
  const quiet = a.quiet || a.hook;
  const say = quiet ? () => {} : out;

  const warning = inodeWarning(root, { percent: opts.warnPercent, uid });
  if (warning) out(`tmp-gc: ${warning}`);

  const stamp = stampPath(root, uid);
  if (throttled(stamp, opts.throttleMinutes, now)) {
    say(`tmp-gc: ${root}: the last run was under ${opts.throttleMinutes} minute(s) ago (${stamp}); nothing done`);
    return 0;
  }
  if (opts.throttleMinutes > 0) touchStamp(stamp, now);

  const procs = readProcs({ proc, uid, root });
  if (!procs.ok) {
    say(`tmp-gc: ${root}: no ${proc} to check live processes against; nothing removed`);
    return 0;
  }
  const plan = planGc({ root, uid, now, procs, opts });
  const { removed, failed } = a.apply ? applyGc(plan) : { removed: plan.remove, failed: [] };
  const sum = summarize(removed);
  if (a.json) {
    out(JSON.stringify({ root, apply: !!a.apply, ...sum, kept: plan.kept, failed, paths: a.list ? removed.map((r) => r.path) : undefined }, null, 2));
    return 0;
  }
  const verb = a.apply ? "removed" : "would remove";
  if (a.list) for (const r of removed) say(`  ${r.cls}\t${r.inodes}\t${r.path}`);
  if (!quiet) {
    out(`tmp-gc: ${root}${a.apply ? "" : " (dry run; --apply removes)"}: ${verb} ${n(sum.total.entries)} entries, ${n(sum.total.inodes)} inodes, ${human(sum.total.bytes)}`);
    for (const c of CLASSES) {
      const x = sum.by[c];
      if (x.entries) out(`  ${c.padEnd(15)} ${n(x.entries).padStart(8)} entries ${n(x.inodes).padStart(9)} inodes ${human(x.bytes).padStart(10)}`);
    }
    out(`  kept: ${n(plan.kept.recent)} recent, ${n(plan.kept.held)} held by a live process, ${n(plan.kept.foreign)} with another owner's, another filesystem's or an unreadable inode`);
    try { const u = inodeUsage(root); out(`  ${root} inodes: ${u.percent}% used (${n(u.used)} of ${n(u.files)})`); } catch { /* no statfs */ }
  } else if (a.apply && sum.total.inodes > 0) {
    out(`tmp-gc: removed ${n(sum.total.entries)} stale entries of this user's from ${root} (${n(sum.total.inodes)} inodes, ${human(sum.total.bytes)}; scripts/tmp-gc.mjs)`);
  } else if (a.hook && !a.apply && sum.total.inodes >= opts.hookMinInodes) {
    out(`tmp-gc: ${root} holds ${n(sum.total.entries)} stale entries of this user's (${n(sum.total.inodes)} inodes, ${human(sum.total.bytes)}): \`node scripts/tmp-gc.mjs\` lists them by rule, and \`node scripts/tmp-gc.mjs --apply\` removes them (only this user's, nothing a live process holds).`);
  }
  for (const f of failed) err(`tmp-gc: could not remove ${f.path}: ${f.error}`);
  return 0;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
