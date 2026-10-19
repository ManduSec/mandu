/**
 * probe-cache — the launch's kernel probes, remembered for the rest of the
 * boot (docs/design/distribution/packaging.md §5.4;
 * rootless-confinement-ubuntu-2404.md §12.6; privilege-model.md §0).
 *
 * WHY. Every launch asked the kernel the same questions again: can bwrap make
 * a user namespace (userns.ts), is Mandu's own bubblewrap's grant loaded
 * (bwrap-grant.ts), does Landlock confine TCP (inspect-net-confine.ts), can a
 * sandbox start inside the secret wrap (secret-setup.ts), does the git
 * sandbox run (hardened-git.ts), does Codex's own sandbox start
 * (codex-sandbox.ts), does the command box's bubblewrap take
 * `--disable-userns` (exec-box-setup.ts). Each is a process or two, 0.15-0.3 s in all on the dev
 * host, and the answers change only when the host does. One launch probe
 * that is not the kernel's rides the same file under the same rules: the
 * exec-wrap shim's load probe ("exec-shim", services/exec-shims.ts;
 * portable-wrapper.md §5), a node start (0.18-0.24 s) whose answer changes
 * only with the files and environment it loads from.
 *
 * THE RULES (security first):
 *   - ONLY THE BEST ANSWER IS KEPT. An entry means "this probe passed, with
 *     the strongest answer it can give" (`true`; for the git sandbox, the
 *     first bubblewrap with the most hardened flag set). A failed or weaker
 *     answer is never written, so it is probed again on every launch: a fixed
 *     host is noticed at once (no stale "unavailable" to outlive `mandu
 *     setup`), and no entry, whoever wrote it, can make a launch weaker than
 *     a fresh probe would.
 *   - A KEPT ANSWER IS STILL ENACTED. A launch that read "available" runs the
 *     step exactly as after a fresh probe, and each step fails closed when the
 *     answer was wrong: the secret wrap and the exec box die (the agent or the
 *     command never runs), a sandboxed git call fails (the object twins
 *     refuse the launch), the inspect_symbol Landlock wrap runs WITHOUT
 *     `--skip-unsupported` (the applier exits 71 instead of running inspect-mcp
 *     unconfined). So a wrong entry costs a failed launch, never a missing
 *     confinement step; and a launch that read any entry and then failed drops
 *     the file (`forgetAfterFailure`), so the next one probes afresh.
 *   - THE KEY IS EVERY INPUT A PROBE READS: the boot (`boot_id`), the user,
 *     the kernel release, the knobs that gate unprivileged user namespaces,
 *     the namespaces, seccomp, no_new_privs, capabilities and AppArmor label
 *     the launcher itself runs in (a launch from inside a sandbox asks
 *     different questions), the LSM list, the AppArmor profile files Mandu and
 *     the distro install, PATH, this code's own identity (its file, so any
 *     rebuild or upgrade), and per probe the identity (real path, device,
 *     inode, size, mtime, ctime) of every binary it runs, plus its argv.
 *   - THE FILE IS THE USER'S OWN: `probe-cache/kernel-probes.json` in the
 *     per-boot runtime dir (the path table's `runtime-dir`; its own directory,
 *     made 0700, since the runtime dir itself may be looser), written 0600 by
 *     rename, never world-writable /tmp's (the runtime dir's /tmp fallback is
 *     under the same rule), read
 *     through O_NOFOLLOW, and refused (a miss) unless it and its directory are
 *     owned by the caller and closed to group and others. A parse error, an
 *     unknown version or an entry older than PROBE_CACHE_MAX_AGE_MS is a miss.
 *   - ONLY THE LAUNCH READS IT. `enableProbeCache` is called on the launch
 *     path; `mandu doctor`, `mandu setup` and every other caller probe fresh.
 *     `mandu setup` deletes the file. MANDU_PROBE_CACHE=0 bypasses it for one
 *     launch (fresh probes, nothing read; the fresh answers are still kept).
 *
 * Mandu-new (no reference origin).
 */
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants as fsc, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readlinkSync, readSync, realpathSync, renameSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { arch, homedir, release } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ManduPathEnv } from "./generated/mandu-paths.js";
import { resolveRuntimeBase } from "./runtime-base.js";
import { GIT_SANDBOX_FLAG_SETS, MANDU_OWN_BWRAP, gitSandbox, probeGitSandbox, isSeatbeltGitSandbox, type BwrapGitSandbox, type GitSandbox } from "./hardened-git.js";
import { systemBwrapBin } from "./bwrap-path.js";

/** Bump when a probe's argv, its meaning or the file format changes. */
export const PROBE_CACHE_VERSION = 1;
/** A kept answer is trusted at most this long (a backstop for an AppArmor
 *  policy loaded or unloaded outside /etc/apparmor.d within a boot). */
export const PROBE_CACHE_MAX_AGE_MS = 6 * 60 * 60 * 1000;
/** A file larger than this is not Mandu's: a miss. */
export const PROBE_CACHE_MAX_BYTES = 64 * 1024;
/** `MANDU_PROBE_CACHE=0`: read nothing, probe fresh. */
export const PROBE_CACHE_ENV = "MANDU_PROBE_CACHE";
export const PROBE_CACHE_FILE = "kernel-probes.json";
/** Its own directory, created 0700: the runtime dir itself may be looser
 *  (one was found 0775), and a directory others could write would let them
 *  swap the file. */
export const PROBE_CACHE_DIR = "probe-cache";

/** The probes the launch keeps. */
export type ProbeName = "userns" | "mandu-bwrap" | "landlock-net" | "nesting" | "git-sandbox" | "codex-bwrap" | "bwrap-help" | "exec-shim";
const PROBE_NAMES: ReadonlySet<string> = new Set<ProbeName>(["userns", "mandu-bwrap", "landlock-net", "nesting", "git-sandbox", "codex-bwrap", "bwrap-help", "exec-shim"]);

/** What one probe depends on beyond the shared context. */
export interface ProbeInputs {
  /** Every binary the probe runs: a name (resolved on PATH, as exec would)
   *  or an absolute path. */
  bins: readonly string[];
  /** The probe's argv (a changed flag is a different question). */
  argv?: readonly string[];
  /** Anything else it reads. */
  extra?: Readonly<Record<string, string | boolean | number | null>>;
}

/** The host reads the key is built from; injectable for the unit tests. */
export interface ProbeCacheIo {
  readText: (path: string) => string | null;
  readLink: (path: string) => string | null;
  /** A file's identity, or null when absent. */
  identity: (path: string) => string | null;
  /** The first executable regular file named `name` on `pathVar`. */
  which: (name: string, pathVar: string) => string | null;
}

export const realProbeCacheIo: ProbeCacheIo = {
  readText: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
  readLink: (p) => { try { return readlinkSync(p); } catch { return null; } },
  identity: (p) => {
    try {
      const s = statSync(p);
      let real = p;
      try { real = realpathSync(p); } catch { /* keep p */ }
      return `${real}|${s.dev}|${s.ino}|${s.size}|${s.mtimeMs}|${s.ctimeMs}|${s.mode}|${s.uid}`;
    } catch {
      return null;
    }
  },
  which: (name, pathVar) => {
    for (const dir of pathVar.split(delimiter)) {
      if (dir === "") continue;
      const p = join(dir, name);
      try {
        const s = statSync(p);
        if (s.isFile() && (s.mode & 0o111) !== 0) return p;
      } catch { /* next */ }
    }
    return null;
  },
};

/** Files whose content is part of the key. Never a blocking one: the
 *  AppArmor `revision` file waits for the next policy change on read. */
const CONTEXT_FILES = [
  "/proc/sys/kernel/random/boot_id",
  "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
  "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
  "/proc/sys/kernel/unprivileged_userns_clone",
  "/proc/sys/kernel/unprivileged_userns_apparmor_policy",
  "/proc/sys/user/max_user_namespaces",
  "/proc/sys/user/max_mnt_namespaces",
  "/proc/sys/user/max_pid_namespaces",
  "/proc/sys/user/max_net_namespaces",
  "/proc/sys/user/max_ipc_namespaces",
  "/proc/sys/user/max_uts_namespaces",
  "/proc/sys/user/max_cgroup_namespaces",
  "/sys/kernel/security/lsm",
  "/proc/self/attr/current",
];
/** The lines of /proc/self/status that change what the launcher may create. */
const STATUS_FIELDS = ["Uid", "Gid", "NoNewPrivs", "Seccomp", "Seccomp_filters", "CapEff", "CapBnd", "CapAmb"];
/** The namespaces the launcher runs in. */
const NAMESPACES = ["user", "mnt", "pid", "net", "ipc", "uts", "cgroup"];
/** The AppArmor profile files that grant or restrict bubblewrap, and their
 *  directory (a profile added or removed changes its mtime). */
const PROFILE_FILES = [
  "/etc/apparmor.d",
  "/etc/apparmor.d/mandu-bwrap",
  "/etc/apparmor.d/bwrap-userns-restrict",
  "/etc/apparmor.d/bwrap",
  "/etc/apparmor.d/unshare",
  "/usr/lib/mandu/bin/bwrap",
];

/** This code's own file (src or the bundle): a rebuild changes the key. */
function selfIdentity(io: ProbeCacheIo): string {
  try { return io.identity(fileURLToPath(import.meta.url)) ?? "unknown"; } catch { return "unknown"; }
}

/** The shared part of every key. `procEnv` is what the probes' spawns see. */
export function probeContext(procEnv: ManduPathEnv, io: ProbeCacheIo = realProbeCacheIo): Record<string, string | null> {
  const ctx: Record<string, string | null> = {
    v: String(PROBE_CACHE_VERSION),
    self: selfIdentity(io),
    uid: String(process.getuid?.() ?? -1),
    euid: String(process.geteuid?.() ?? -1),
    platform: process.platform,
    arch: arch(),
    release: release(),
    path: procEnv["PATH"] ?? "",
    gitSandboxEnv: procEnv["MANDU_GIT_SANDBOX"] ?? "",
  };
  for (const f of CONTEXT_FILES) ctx[`file:${f}`] = io.readText(f)?.trim() ?? null;
  const status = io.readText("/proc/self/status") ?? "";
  for (const k of STATUS_FIELDS) ctx[`status:${k}`] = new RegExp(`^${k}:\\s*(.*)$`, "m").exec(status)?.[1]?.trim() ?? null;
  for (const n of NAMESPACES) ctx[`ns:${n}`] = io.readLink(`/proc/self/ns/${n}`);
  for (const f of PROFILE_FILES) ctx[`id:${f}`] = io.identity(f);
  return ctx;
}

/** The key for one probe: sha256 over the context and its own inputs. */
export function probeKey(name: ProbeName, inputs: ProbeInputs, ctx: Record<string, string | null>, procEnv: ManduPathEnv, io: ProbeCacheIo = realProbeCacheIo): string {
  const pathVar = procEnv["PATH"] ?? "";
  const bins = inputs.bins.map((b) => {
    const p = isAbsolute(b) ? b : io.which(b, pathVar);
    return [b, p === null ? null : io.identity(p)];
  });
  const body = JSON.stringify({ name, ctx: Object.entries(ctx).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)), bins, argv: inputs.argv ?? null, extra: inputs.extra ? Object.entries(inputs.extra).sort() : null });
  return createHash("sha256").update(body).digest("hex");
}

interface Entry { key: string; at: number }
interface CacheFile { v: number; entries: Record<string, Entry> }

/** Why a file was not read (diagnostics, `--verbose`). */
export type RefusalReason = "absent" | "symlink" | "not-a-file" | "foreign-owner" | "loose-mode" | "too-large" | "unparsable" | "bad-dir";

/** The directory holds Mandu's per-user files only when it is the caller's
 *  own and closed to group and others (and not a symlink). */
function dirIsOwn(dir: string, uid: number): boolean {
  try {
    const s = lstatSync(dir);
    return s.isDirectory() && s.uid === uid && (s.mode & 0o077) === 0;
  } catch {
    return false;
  }
}

/**
 * Read the cache file safely: O_NOFOLLOW, owned by `uid`, mode 0600 or
 * tighter, small, well-formed. Anything else is a miss (`refused`). Pure but
 * for the one read.
 */
export function readProbeCacheFile(file: string, uid: number): { entries: Record<string, Entry>; refused?: RefusalReason } {
  const dir = file.slice(0, file.lastIndexOf("/")) || "/";
  let fd: number;
  try {
    fd = openSync(file, fsc.O_RDONLY | fsc.O_NOFOLLOW | fsc.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return { entries: {}, refused: code === "ELOOP" ? "symlink" : "absent" };
  }
  try {
    const s = fstatSync(fd);
    if (!s.isFile()) return { entries: {}, refused: "not-a-file" };
    if (s.uid !== uid) return { entries: {}, refused: "foreign-owner" };
    if ((s.mode & 0o077) !== 0) return { entries: {}, refused: "loose-mode" };
    if (!dirIsOwn(dir, uid)) return { entries: {}, refused: "bad-dir" };
    if (s.size > PROBE_CACHE_MAX_BYTES) return { entries: {}, refused: "too-large" };
    const buf = Buffer.alloc(s.size);
    let off = 0;
    while (off < s.size) {
      const n = readSync(fd, buf, off, s.size - off, off);
      if (n === 0) break;
      off += n;
    }
    const parsed = parseCacheFile(buf.subarray(0, off).toString("utf8"));
    return parsed === null ? { entries: {}, refused: "unparsable" } : { entries: parsed.entries };
  } catch {
    return { entries: {}, refused: "unparsable" };
  } finally {
    closeSync(fd);
  }
}

/** Parse and validate; null on anything unexpected. Pure. Unknown probe
 *  names and malformed entries are dropped, never trusted. */
export function parseCacheFile(text: string): CacheFile | null {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { return null; }
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as { v?: unknown; entries?: unknown };
  if (o.v !== PROBE_CACHE_VERSION || typeof o.entries !== "object" || o.entries === null || Array.isArray(o.entries)) return null;
  const entries: Record<string, Entry> = {};
  for (const [name, e] of Object.entries(o.entries as Record<string, unknown>)) {
    if (!PROBE_NAMES.has(name) || typeof e !== "object" || e === null) continue;
    const { key, at } = e as { key?: unknown; at?: unknown };
    if (typeof key !== "string" || !/^[0-9a-f]{64}$/.test(key) || typeof at !== "number" || !Number.isFinite(at)) continue;
    entries[name] = { key, at };
  }
  return { v: PROBE_CACHE_VERSION, entries };
}

/** Write the file 0600 by rename; never follows a planted link. Best-effort:
 *  a launch never fails for its cache. */
export function writeProbeCacheFile(file: string, entries: Record<string, Entry>, uid: number): boolean {
  const dir = file.slice(0, file.lastIndexOf("/")) || "/";
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (!dirIsOwn(dir, uid)) return false;
    const tmp = `${file}.${process.pid}.${randomBytes(6).toString("hex")}`;
    writeFileSync(tmp, JSON.stringify({ v: PROBE_CACHE_VERSION, entries } satisfies CacheFile), { mode: 0o600, flag: "wx" });
    try {
      renameSync(tmp, file);
    } catch (e) {
      rmSync(tmp, { force: true });
      throw e;
    }
    return true;
  } catch {
    return false;
  }
}

/** Where the cache lives: the same runtime base as the launch and stack,
 *  including the private short-path fallback when TMPDIR cannot fit sockets.
 *  The legacy home argument is retained for callers; runtime paths never use it. */
export function probeCacheFile(env: ManduPathEnv, _home: string = homedir()): string {
  return join(resolveRuntimeBase(env).base, PROBE_CACHE_DIR, PROBE_CACHE_FILE);
}

/** Delete the cache (`mandu setup`; a failed launch that read it) — only out
 *  of a cache dir that is this uid's own private directory (dirIsOwn, links
 *  not followed), as the writer requires: a `probe-cache` link planted in a
 *  runtime base another account controls (a `/tmp/mandu` made first) must
 *  not aim the delete at a file elsewhere. */
export function clearProbeCacheFile(env: ManduPathEnv, home: string = homedir()): void {
  const file = probeCacheFile(env, home);
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid !== null && !dirIsOwn(file.slice(0, file.lastIndexOf("/")) || "/", uid)) return;
  try { rmSync(file, { force: true }); } catch { /* best-effort */ }
}

// ── The launch's one cache ──────────────────────────────────────────────────

export interface ProbeCacheOpts {
  /** Where the file is (default: probeCacheFile(env)). */
  file?: string;
  /** What the probes' spawns see (PATH, MANDU_GIT_SANDBOX). Default process.env. */
  procEnv?: ManduPathEnv;
  io?: ProbeCacheIo;
  now?: () => number;
  uid?: number;
  /** A diagnostic line (`--verbose`). */
  log?: (m: string) => void;
}

interface Active {
  file: string;
  procEnv: ManduPathEnv;
  io: ProbeCacheIo;
  now: () => number;
  uid: number;
  read: boolean;
  entries: Record<string, Entry>;
  ctx: Record<string, string | null> | null;
  hits: ProbeName[];
  /** This launch's answers by name + key: each question is asked once. */
  memo: Map<string, boolean>;
  /** This launch's git sandbox (launchGitSandbox), once resolved. */
  git?: { sandbox: GitSandbox | null };
  log: (m: string) => void;
}

let active: Active | null = null;

/**
 * Turn the cache on for this process: the launch path only (run.ts). Reads
 * the file once. `env` is the launch's environment (the runtime dir, the
 * bypass); MANDU_PROBE_CACHE=0 reads nothing.
 */
export function enableProbeCache(env: ManduPathEnv, opts: ProbeCacheOpts = {}): void {
  const uid = opts.uid ?? process.getuid?.() ?? -1;
  const file = opts.file ?? probeCacheFile(env);
  const read = env[PROBE_CACHE_ENV] !== "0";
  const log = opts.log ?? (() => {});
  let entries: Record<string, Entry> = {};
  if (read && uid >= 0) {
    const r = readProbeCacheFile(file, uid);
    entries = r.entries;
    if (r.refused !== undefined && r.refused !== "absent") log(`mandu: the kernel probe cache ${file} is not used (${r.refused}); probing afresh`);
  }
  active = {
    file, uid, read, entries, log,
    procEnv: opts.procEnv ?? process.env,
    io: opts.io ?? realProbeCacheIo,
    now: opts.now ?? Date.now,
    ctx: null,
    hits: [],
    memo: new Map(),
  };
}

/** Turn it off again (tests; a launch that is done). */
export function disableProbeCache(): void {
  active = null;
}

/** Is the cache on in this process (a launch)? */
export function probeCacheEnabled(): boolean {
  return active !== null;
}

/** The probes this launch answered from the cache. */
export function probeCacheHits(): readonly ProbeName[] {
  return active?.hits ?? [];
}

/**
 * Answer a probe: from the cache when the launch enabled it and an entry
 * matches every input, else `fresh()`. A fresh `true` is kept; anything else
 * is not (the next launch asks again). Without an enabled cache (doctor,
 * setup, tests) this is `fresh()`.
 */
export function cachedProbe(name: ProbeName, inputs: () => ProbeInputs, fresh: () => boolean): boolean {
  const a = active;
  if (a === null || a.uid < 0) return fresh();
  const l = lookup(a, name, inputs);
  if (l === null) return fresh();
  if (l.answer !== undefined) return l.answer;
  const v = fresh();
  record(a, name, l, v);
  return v;
}

/**
 * {@link cachedProbe} for a probe the launch awaits (the exec-wrap shim's
 * load probe, services/exec-shims.ts; portable-wrapper.md §5). The same
 * rules: only a pass is kept; `fresh()` resolving false, or rejecting, is a
 * failure that is never kept (and drops a kept entry for the probe); a
 * rejection is rethrown unchanged, so the caller fails exactly as it would
 * without the cache.
 */
export async function cachedProbeAsync(name: ProbeName, inputs: () => ProbeInputs, fresh: () => Promise<boolean>): Promise<boolean> {
  const a = active;
  if (a === null || a.uid < 0) return fresh();
  const l = lookup(a, name, inputs);
  if (l === null) return fresh();
  if (l.answer !== undefined) return l.answer;
  let v: boolean;
  try {
    v = await fresh();
  } catch (e) {
    // Nothing is recorded once the launch has turned the cache off.
    if (active === a) record(a, name, l, false);
    throw e;
  }
  if (active === a) record(a, name, l, v);
  return v;
}

/** The kernel probes' label in a log line; the one kept probe that is not a
 *  kernel question (the exec-wrap shim's load probe) says so. */
const probeLabel = (name: ProbeName): string => (name === "exec-shim" ? "launch probe" : "kernel probe");

/** The lookup half of a cached probe: the key, and the answer when a kept
 *  entry (or this launch's own earlier ask) settles it. `null` = no key
 *  (probe fresh, keep nothing). */
function lookup(a: Active, name: ProbeName, inputs: () => ProbeInputs): { key: string; memoKey: string; entry: Entry | undefined; answer: boolean | undefined } | null {
  let key: string;
  try {
    a.ctx ??= probeContext(a.procEnv, a.io);
    key = probeKey(name, inputs(), a.ctx, a.procEnv, a.io);
  } catch {
    return null;
  }
  const memoKey = `${name}:${key}`;
  const e = a.read ? a.entries[name] : undefined;
  const asked = a.memo.get(memoKey);
  if (asked !== undefined) return { key, memoKey, entry: e, answer: asked };
  const age = e === undefined ? Infinity : a.now() - e.at;
  if (e !== undefined && e.key === key && age >= 0 && age <= PROBE_CACHE_MAX_AGE_MS) {
    if (!a.hits.includes(name)) a.hits.push(name);
    a.memo.set(memoKey, true);
    a.log(`mandu: ${probeLabel(name)} ${name}: passed earlier this boot, not asked again (${PROBE_CACHE_ENV}=0 asks afresh)`);
    return { key, memoKey, entry: e, answer: true };
  }
  return { key, memoKey, entry: e, answer: undefined };
}

/** The record half: a fresh pass is kept; a fresh failure is never written,
 *  and drops a kept entry for the probe (the host changed under it) — also
 *  under MANDU_PROBE_CACHE=0, which read nothing, so it looks in the file. */
function record(a: Active, name: ProbeName, l: { key: string; memoKey: string; entry: Entry | undefined }, v: boolean): void {
  a.memo.set(l.memoKey, v);
  if (v === true) {
    // Merge with what another launch may have written since we read.
    const now = readProbeCacheFile(a.file, a.uid).entries;
    a.entries = { ...now, ...a.entries, [name]: { key: l.key, at: a.now() } };
    writeProbeCacheFile(a.file, a.entries, a.uid);
    return;
  }
  const onFile = a.read ? undefined : readProbeCacheFile(a.file, a.uid).entries;
  if (l.entry === undefined && onFile?.[name] === undefined) return;
  if (onFile !== undefined) a.entries = { ...onFile, ...a.entries };
  delete a.entries[name];
  writeProbeCacheFile(a.file, a.entries, a.uid);
}

/**
 * The launch failed after it used a kept answer: drop the file, so the next
 * launch probes afresh (a wrong "available" costs one failed launch). Returns
 * whether anything was dropped.
 */
export function forgetAfterFailure(): boolean {
  const a = active;
  if (a === null || a.hits.length === 0) return false;
  try { rmSync(a.file, { force: true }); } catch { /* best-effort */ }
  a.entries = {};
  return true;
}

// ── The git sandbox (hardened-git.ts) ───────────────────────────────────────

/** Mandu's own bubblewrap counts only root-owned and closed to writers
 *  (hardened-git.ts `defaultRootOwned`). */
function rootOwnedFile(p: string): boolean {
  try {
    const s = statSync(p);
    return s.isFile() && s.uid === 0 && (s.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

/** The best sandbox `probeGitSandbox` can find here: its first candidate
 *  with the most hardened flag set. Only this answer is kept. */
export function bestGitSandbox(
  rootOwned: (p: string) => boolean = rootOwnedFile,
  system: () => string | null = systemBwrapBin,
): BwrapGitSandbox | null {
  // Mandu's own copy, else the distribution's by absolute path (bwrap-path.ts);
  // none: no sandbox can be best, and nothing is kept.
  const bwrap = rootOwned(MANDU_OWN_BWRAP) ? MANDU_OWN_BWRAP : system();
  return bwrap === null ? null : { bwrap, flags: GIT_SANDBOX_FLAG_SETS[0]! };
}

const sameFlags = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The git sandbox the launcher's git runner uses (git-object-twins.ts). With
 * the cache on: a kept answer gives the best sandbox WITHOUT a probe (and
 * without its `git --version`: the runner then asks `git version` itself, in
 * the sandbox, so a wrong answer fails that first call); a weaker or no
 * sandbox is probed on every launch. Without the cache: hardened-git's own
 * per-process probe, as before.
 */
export function launchGitSandbox(
  deps: { probe?: (env: ManduPathEnv) => GitSandbox | null; rootOwned?: (p: string) => boolean; systemBwrap?: () => string | null; platform?: string } = {},
): GitSandbox | null {
  const a = active;
  if (a === null) return gitSandbox();
  if (a.git !== undefined) return a.git.sandbox;
  if (a.procEnv["MANDU_GIT_SANDBOX"] === "0") {
    a.git = { sandbox: null };
    return null;
  }
  // The persistent cache is Linux-only. macOS still uses hardened-git's
  // process-local Seatbelt probe, including its transient retry behavior.
  if ((deps.platform ?? process.platform) !== "linux") {
    return deps.probe ? deps.probe(a.procEnv) : gitSandbox();
  }
  const best = bestGitSandbox(deps.rootOwned, deps.systemBwrap);
  if (best === null) {
    // No bubblewrap the probe could find either: nothing to keep.
    const probedNone = (deps.probe ?? ((env) => probeGitSandbox({ env })))(a.procEnv);
    a.git = { sandbox: probedNone };
    return probedNone;
  }
  let probed: GitSandbox | null | undefined;
  const ok = cachedProbe(
    "git-sandbox",
    () => ({ bins: [best.bwrap, "git"], argv: best.flags, extra: { ownCopy: best.bwrap === MANDU_OWN_BWRAP } }),
    () => {
      probed = (deps.probe ?? ((env) => probeGitSandbox({ env })))(a.procEnv);
      return probed !== null && !isSeatbeltGitSandbox(probed) && probed.bwrap === best.bwrap && sameFlags(probed.flags, best.flags);
    },
  );
  const sandbox = probed !== undefined ? probed : ok ? best : null;
  a.git = { sandbox };
  return sandbox;
}
