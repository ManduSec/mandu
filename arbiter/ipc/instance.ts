/**
 * instance — per-deployment runtime identity for the Mandu stack
 * (Mandu-new, no reference origin; docs/design/architecture/runtime-instances.md).
 *
 * THE PROBLEM (three real incidents, 2026-06/07): every arbiter start —
 * dashboard-supervised, launcher autostart, hand-check one-off — targeted the
 * SAME well-known socket path. Unix sockets are last-binder-wins
 * (unlink-before-bind), the path carries no version/owner marker, and daemons
 * outlive the code they were compiled from (tsx loads source at process
 * start). Result: silent socket theft, weeks-stale daemons masquerading as
 * current, and mixed-generation stacks that are only diagnosable via
 * `ss -xlp` + `/proc/<pid>/environ` forensics.
 *
 * THE SCHEME:
 *
 *   <runtime base>/        runtime-base.ts: $MANDU_RUNTIME_DIR, else
 *                          $XDG_RUNTIME_DIR/mandu, else $TMPDIR/mandu when an
 *                          instance socket fits sun_path under it, else the
 *                          private /tmp/mandu-<uid> (runtime-instances.md §3b)
 *     current -> instances/20260707-1139-91dca36-p402360   (atomic swap)
 *     instances/                         a real directory, never a link
 *       20260707-1139-91dca36-p402360/   <utc-time>-<git-rev>-p<pid>, 0700,
 *                                        made exclusively (never adopted)
 *         arbiter.sock                   bound HERE — never at a shared path
 *         manifest.json                  identity: pid/rev/startedAt/paths
 *                                        (temp file O_EXCL, then rename)
 *         logs/
 *
 *  - A daemon binds only inside ITS OWN instance dir, so binding can never
 *    steal another instance's socket (squatting is impossible by construction).
 *  - The well-known rendezvous is `current/arbiter.sock` — a symlink one level
 *    up. Promotion is an ATOMIC symlink swap (symlink at temp name + rename),
 *    so readers always resolve a complete path, never a half-written one.
 *  - The instance id answers the recurring diagnostic questions from `ls`
 *    alone: when it started (sortable), which code it runs (git rev), what to
 *    kill (pid).
 *  - Durable state is deliberately NOT per-instance: the event dir and symbol
 *    DB stay shared across instances (sessions and symbols survive restarts);
 *    only the RUNTIME identity (socket/pid/rev) is instance-scoped.
 *
 * THE HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): the ops that return
 * originals (desymbolize, shallow resolve, events/subscribe/sessions/
 * verifyEvents) are served on a SECOND socket,
 *
 *   ${base}/human/<instanceId>.sock      dir `human/` is 0700, owned by us
 *
 * deliberately OUTSIDE the instance dir: the launcher walls the agent world
 * off from `${base}/human` as a whole (net-guard's always-deny entry, the
 * secret-twins tmpfs, Seatbelt), and no scope dir or allow-list entry may
 * contain it. It is published with `current` (resolveArbiterHumanSock keys it
 * on the promoted instance id) and removed on shutdown like the data socket.
 *
 * Consumers resolve the socket in this order (resolveArbiterSock):
 *   1. $MANDU_ARBITER_SOCK (explicit deployments/tests — verbatim, as today)
 *   2. ${base}/current/arbiter.sock   (a live promoted instance)
 *   3. ${base}/arbiter.sock           (legacy fixed path, one release of compat)
 */

import { execFileSync } from "node:child_process";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync,
  renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import { userInfo } from "node:os";
import { basename, join, resolve } from "node:path";
import { manduPath } from "../src/generated/mandu-paths.js";
import { hardenedGitArgs, hardenedGitEnv } from "../src/hardened-git.js";

import { accountRendezvous, resolveRuntimeBase } from "./runtime-base.js";

/** Directory (under the runtime base) that holds one dir per instance. */
export const INSTANCES_DIR = "instances";
/** Symlink (under the runtime base) naming the promoted instance. */
export const CURRENT_LINK = "current";
/** The name prefix of promoteInstance's temporary link,
 *  `${base}/.current.tmp-<pid>`. Exported for the macOS Seatbelt profile,
 *  which write-denies it (launcher runtime-registry.ts `RUNTIME_REGISTRY`,
 *  held to this by tests/integration runtime-registry-parity.test.ts): the
 *  agent may write the base, and a link it swapped in at this name between
 *  the symlink and the rename would become `current`. */
export const CURRENT_TMP_PREFIX = `.${CURRENT_LINK}.tmp-`;
/** Socket filename inside an instance dir (and at the legacy fixed path). */
export const ARBITER_SOCK = "arbiter.sock";
/** Identity manifest filename inside an instance dir. */
export const MANIFEST = "manifest.json";
/** Directory (under the runtime base) that holds the human-plane sockets,
 *  one `<instanceId>.sock` per instance (arbiter-human-plane.md §3). */
export const HUMAN_DIR = "human";
/** The env var naming the human-plane socket to the HUMAN-FACING consumers
 *  (reply filter, fs-sync, net-proxy, net-supervisor, the dashboard). Never
 *  set in the agent's own environment. */
export const HUMAN_SOCK_ENV = "MANDU_ARBITER_HUMAN_SOCK";

/** `${base}/human` — the directory the agent world is walled off from. */
export function humanSockDir(base: string): string {
  return join(base, HUMAN_DIR);
}

/** `${base}/human/<id>.sock` — an instance's human-plane socket. */
export function humanSockPath(base: string, id: string): string {
  return join(humanSockDir(base), `${id}.sock`);
}

/**
 * Create `dir` (mode 0700) when absent, then VERIFY it: a real directory (not
 * a symlink), owned by this uid, with no group/other permission bits. Any
 * other state throws — the human plane refuses to start in a directory
 * someone else controls or can read (fail closed). A directory we own with
 * wider bits is NOT silently tightened: something else set them, and the
 * start says so instead of guessing.
 */
export function ensurePrivateDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // mkdir honours the umask; state the mode we asked for explicitly.
    try { chmodSync(dir, 0o700); } catch { /* verified below */ }
  }
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error(`human-plane directory ${dir} is not a real directory (a symlink or a file) — refusing to start`);
  }
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new Error(`human-plane directory ${dir} is owned by uid ${st.uid}, not ${process.getuid()} — refusing to start`);
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error(
      `human-plane directory ${dir} has mode ${(st.mode & 0o777).toString(8)}, not 700 — refusing to start ` +
        `(fix: chmod 700 ${dir})`,
    );
  }
}

/** The runtime base (runtime-base.ts resolveRuntimeBase, runtime-instances.md
 *  §3b): `$MANDU_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/mandu`, else
 *  `$TMPDIR/mandu` when an instance socket fits under it, else the private
 *  `/tmp/mandu-<uid>`. */
export function runtimeBase(env: NodeJS.ProcessEnv = process.env): string {
  return resolveRuntimeBase(env).base;
}

/** Injectable facts for accountIdentity (tests pin darwin on any host). */
export interface AccountIdentityDeps {
  platform?: string;
  getuid?: (() => number) | null;
  homedir?: () => string;
  darwinTempDir?: () => string;
}

/** The account this process runs as: its passwd home and its host
 *  rendezvous base — `/run/user/<uid>/mandu` on Linux, the default base of
 *  DARWIN_USER_TEMP_DIR on macOS (in practice `/tmp/mandu-<uid>`,
 *  runtime-base.ts accountRendezvous). Null when the platform cannot say (no
 *  getuid, no passwd entry) — callers then skip the foreign-HOME guard rather
 *  than guess. */
export function accountIdentity(deps: AccountIdentityDeps = {}): { home: string; rendezvous: string } | null {
  try {
    const getuid = deps.getuid !== undefined
      ? deps.getuid
      : (typeof process.getuid === "function" ? () => process.getuid!() : null);
    if (typeof getuid !== "function") return null;
    const uid = getuid();
    const home = (deps.homedir ?? (() => userInfo().homedir))();
    return {
      home,
      rendezvous: accountRendezvous(uid, {
        ...(deps.platform !== undefined ? { platform: deps.platform } : {}),
        ...(deps.darwinTempDir ? { darwinTempDir: deps.darwinTempDir } : {}),
      }),
    };
  } catch {
    return null;
  }
}

/**
 * Why promoting an instance at `base` would hand the account's shared
 * rendezvous to a FOREIGN HOME, or null when it would not (runtime-instances.md
 * §13, 2026-09-28). The host rendezvous is the account's default runtime base
 * (`/run/user/<uid>/mandu` on Linux, `/tmp/mandu-<uid>` on macOS) — what every
 * launcher and the account's dashboard resolve by default. An arbiter keeps its
 * symbol DB, policy file and event dir under $HOME, so one started with a
 * scratch HOME (a test launch that autostarted the stack) and promoted there
 * makes every later client of the account join a throwaway store: found live,
 * it held `current` for 20 hours and the dashboard showed its scratch
 * sessions. A fully isolated run (its own MANDU_RUNTIME_DIR or
 * XDG_RUNTIME_DIR) is never refused: its `base` is not the account's.
 *
 * MANDU_HOME follows the launcher's rule (launcher/src/arbiter.ts
 * sharedStackHomeEnv, which drops a MANDU_HOME inside the foreign HOME and
 * keeps one set elsewhere): the refusal is keyed on HOME and a MANDU_HOME
 * never lifts it. Where the stores are is only part of it: HOME is also the
 * `~` of the policy's labels and of the secret catalog (path-labels.ts,
 * secret-catalog.ts), so an arbiter under a scratch HOME would guard the
 * scratch dir's keys and not the account's even with its stores in the
 * account's own home. The reason names where the Mandu home resolves, so a
 * relocated one is not misreported as "under that HOME". Every env the
 * launcher's rewrite produces passes here (the rewrite sets HOME to the
 * account's), which tests/stack/foreign-home-parity.test.ts
 * pins across both packages.
 */
export function foreignHomePromotion(
  base: string,
  env: NodeJS.ProcessEnv = process.env,
  account: { home: string; rendezvous: string } | null = accountIdentity(),
): string | null {
  if (!account || !env.HOME) return null;
  if (resolve(base) !== resolve(account.rendezvous)) return null;
  const foreign = resolve(env.HOME);
  if (foreign === resolve(account.home)) return null;
  const manduHome = resolve(manduPath("mandu-home", env, env.HOME));
  const stores =
    manduHome === foreign || manduHome.startsWith(foreign + "/")
      ? `its symbol DB, policy and events under that HOME (${manduHome})`
      : `its policy's ~ (the secret catalog and path labels) under that HOME and its stores in MANDU_HOME ${manduHome}`;
  return (
    `HOME is ${env.HOME}, not this account's home ${account.home}; an arbiter promoted at ${base} ` +
    `becomes the rendezvous every launch and the dashboard of this account joins, with ${stores}`
  );
}

/** Identity manifest written next to the instance's socket. All fields are
 *  informational (diagnosis + staleness detection); the socket is authoritative. */
export interface InstanceManifest {
  instanceId: string;
  role: "arbiter";
  pid: number;
  /** ISO 8601 start time. */
  startedAt: string;
  /** `git rev-parse --short HEAD` of the repo the daemon was started from,
   *  or "nogit" when unavailable. */
  gitRev: string;
  /** True when the working tree had uncommitted changes at start. */
  gitDirty: boolean;
  /** Absolute path of the socket this instance bound. */
  sockPath: string;
  /** Absolute path of this instance's human-plane socket (absent in manifests
   *  written before 2026-09-30, or when the instance serves none). */
  humanSockPath?: string;
  /** Shared durable state this instance reads/writes. */
  eventDir: string;
  symbolDb: string;
  /** How the socket was chosen: "instance" (bound in this dir) or "pinned"
   *  (caller-owned path — registered here so NO arbiter process is invisible
   *  to `mandu status`/`reap`). Absent in pre-2026-07-15 manifests ⇒
   *  "instance". */
  mode?: "instance" | "pinned";
  /** The pid whose death makes this daemon garbage (`mandu reap` kills the
   *  arbiter once ownerPid is gone, unless it is the promoted `current`).
   *  Spawners declare it via MANDU_OWNER_PID; defaults to the parent pid.
   *  null ⇒ no owner (stopped only explicitly). */
  ownerPid?: number | null;
}

/** The owner pid for this daemon: $MANDU_OWNER_PID (a spawner's explicit
 *  claim — the blessed dev spawn passes the invoking SHELL so an orphaned
 *  setsid chain still has a real owner), "0"/"none" for ownerless, else the
 *  parent pid. */
export function resolveOwnerPid(
  env: NodeJS.ProcessEnv = process.env,
  ppid: number = process.ppid,
): number | null {
  const raw = env.MANDU_OWNER_PID;
  if (raw === undefined || raw === "") return ppid;
  if (raw === "0" || raw === "none") return null;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : ppid;
}

/** `<utc yyyymmdd-hhmm>-<gitrev>-p<pid>`: sortable by start time, code rev
 *  readable at a glance, pid says what to signal. */
export function instanceId(now: Date, gitRev: string, pid: number): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, "0");
  const t =
    `${now.getUTCFullYear()}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}` +
    `-${p(now.getUTCHours())}${p(now.getUTCMinutes())}`;
  const rev = gitRev.replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 16) || "nogit";
  return `${t}-${rev}-p${pid}`;
}

/** One index entry's stat fields as `git ls-files --debug` prints them. */
export interface IndexStat {
  path: string;
  mtimeSec: number;
  mtimeNsec: number;
  size: number;
}

/** `git ls-files --debug` output → the entries' stat fields. A quoted path
 *  (a name git had to escape) is left out. Pure. */
export function parseLsFilesDebug(out: string): IndexStat[] {
  const entries: IndexStat[] = [];
  let cur: IndexStat | null = null;
  for (const line of out.split("\n")) {
    if (line === "") continue;
    if (!line.startsWith("  ")) {
      if (cur) entries.push(cur);
      cur = line.startsWith("\"") ? null : { path: line, mtimeSec: -1, mtimeNsec: 0, size: -1 };
      continue;
    }
    if (!cur) continue;
    const m = /^\s+mtime:\s*(\d+):(\d+)/.exec(line);
    if (m) { cur.mtimeSec = Number(m[1]); cur.mtimeNsec = Number(m[2]); continue; }
    const s = /^\s+size:\s*(\d+)/.exec(line);
    if (s) cur.size = Number(s[1]);
  }
  if (cur) entries.push(cur);
  return entries;
}

/** Does a working file's lstat differ from its index entry (git's own first
 *  test: size and mtime; an index without nanoseconds compares seconds)?
 *  A missing file differs; a directory (a submodule) is skipped. Pure. */
export function statDiffers(e: IndexStat, st: { isDir: boolean; size: number; mtimeNs: bigint } | null): boolean {
  if (st === null) return true;
  if (st.isDir) return false;
  if (e.size !== st.size % 2 ** 32) return true;
  const sec = Number(st.mtimeNs / 1_000_000_000n);
  const nsec = Number(st.mtimeNs % 1_000_000_000n);
  return e.mtimeSec !== sec || (e.mtimeNsec !== 0 && e.mtimeNsec !== nsec);
}

/**
 * Best-effort short git rev + dirty flag for `repoDir`. Never throws: a
 * non-repo / missing git yields { rev: "nogit", dirty: false }.
 *
 * `repoDir` is Mandu's own checkout, which may be an agent's workspace, so
 * git runs HARDENED (../src/hardened-git.ts, docs/design/architecture/write-protection.md §8)
 * and no command here reads a working file's CONTENT: `git status` would
 * pass a stat-changed file through the clean filter the repository's
 * attributes name, a program the agent could plant. So dirty is: staged
 * changes (`diff-index --cached`, index against HEAD), untracked files
 * (`ls-files -o`), or a tracked file whose size or mtime differs from its
 * index entry (a touched file counts as dirty; git would re-hash it).
 */
export function gitRevOf(repoDir: string): { rev: string; dirty: boolean } {
  const git = (args: string[], timeout: number): string => execFileSync("git", hardenedGitArgs(args), {
    cwd: repoDir, encoding: "utf8", timeout, stdio: ["ignore", "pipe", "ignore"], env: hardenedGitEnv(process.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" }),
  });
  let rev: string;
  try {
    rev = git(["rev-parse", "--short", "HEAD"], 3000).trim();
  } catch {
    return { rev: "nogit", dirty: false };
  }
  let dirty = false;
  try {
    try { git(["diff-index", "--cached", "--quiet", "HEAD", "--"], 5000); } catch { dirty = true; }
    if (!dirty) dirty = git(["ls-files", "-o", "--exclude-standard", "-z"], 5000).length > 0;
    if (!dirty) {
      // ls-files names each entry relative to the directory it runs in.
      dirty = parseLsFilesDebug(git(["-c", "core.quotepath=off", "ls-files", "--debug"], 5000)).some((e) => {
        let st: { isDir: boolean; size: number; mtimeNs: bigint } | null = null;
        try {
          const s = lstatSync(join(repoDir, e.path), { bigint: true });
          st = { isDir: s.isDirectory(), size: Number(s.size), mtimeNs: s.mtimeNs };
        } catch { st = null; }
        return statDiffers(e, st);
      });
    }
  } catch {
    // The flag is informational: unknown reads as clean.
  }
  return { rev: rev || "nogit", dirty };
}

export interface InstancePaths {
  /** instances/<id> */
  dir: string;
  /** instances/<id>/arbiter.sock */
  sockPath: string;
  /** instances/<id>/manifest.json */
  manifestPath: string;
  /** instances/<id>/logs */
  logsDir: string;
}

/** Paths of an instance dir (no filesystem access). */
export function instancePaths(base: string, id: string): InstancePaths {
  const dir = join(base, INSTANCES_DIR, id);
  return {
    dir,
    sockPath: join(dir, ARBITER_SOCK),
    manifestPath: join(dir, MANIFEST),
    logsDir: join(dir, "logs"),
  };
}

/** Is `p` a real directory (lstat: a symlink is NOT one)? */
function isRealDir(p: string): boolean {
  try {
    const st = lstatSync(p);
    return st.isDirectory() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Create `instances/<id>` (+ logs/) under the base and return its paths.
 *
 * Never in a place someone else prepared (runtime-instances.md §2, planted
 * paths, 2026-09-30). Whoever can write the runtime base (on macOS the
 * agent's Seatbelt profile keeps the base writable and denies only these
 * entries; on Linux nothing stops a same-uid process) could otherwise
 * pre-create the dir of a predictable id (`<utc-minute>-<rev>-p<pid>`) with
 * a link planted inside, or make `instances` itself a link:
 *
 *   - `instances/` must be a real directory: through a link, the socket, the
 *     manifest and the sweep's removals would land wherever it points;
 *   - `<id>` is made non-recursively, mode 0700: one that already exists
 *     (planted, or left by an earlier process that had this pid in the same
 *     minute) is REFUSED, never adopted, and left alone. A later start gets a
 *     new id (the minute, or the pid, changes).
 */
export function createInstanceDir(base: string, id: string): InstancePaths {
  const paths = instancePaths(base, id);
  const root = join(base, INSTANCES_DIR);
  mkdirSync(root, { recursive: true });
  if (!isRealDir(root)) {
    throw new Error(`the instance registry ${root} is not a real directory (a symlink or a file) — refusing to start (remove it and retry)`);
  }
  try {
    mkdirSync(paths.dir, { mode: 0o700 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `the instance dir ${paths.dir} already exists (left by an earlier process with this pid, or planted) — ` +
          "refusing to start in a directory this start did not create (remove it, or start again: a new start gets a new id)",
      );
    }
    throw e;
  }
  // No chmod after it: the umask can only take bits away from 0700, never add
  // any, and a chmod by path would follow a link swapped in after the mkdir.
  mkdirSync(paths.logsDir);
  return paths;
}

/**
 * Write the instance manifest ATOMICALLY: the JSON goes to a temp file in the
 * same dir, then rename(2) puts it at `manifest.json`. A plain write to the
 * final path creates the file empty before its bytes land, and every reader
 * that polls the registry (`mandu reap`/`status`, the dashboard, the sweeper,
 * tests) could catch it empty or half-written (CI gl-7778-12995: a poll read
 * an empty manifest, `Unexpected end of JSON input`). With the rename a
 * reader sees no manifest or the whole one, never a prefix.
 *
 * The temp file is created EXCLUSIVELY (`wx`: O_CREAT|O_EXCL, 2026-09-30).
 * Its name is predictable, so a link planted there would have this unconfined
 * process write the manifest through it, into whatever file it names. A
 * leftover entry at the name is unlinked first (unlink never follows a
 * link), then open(2) with O_EXCL refuses ANY entry at the name, a symlink
 * included, so the bytes only ever land in a file this call created. One
 * re-planted between the two makes the write fail, never follow.
 */
export function writeManifest(paths: InstancePaths, manifest: InstanceManifest): void {
  const tmp = join(paths.dir, `.${MANIFEST}.${process.pid}.tmp`);
  try { unlinkSync(tmp); } catch { /* none left over */ }
  try {
    writeFileSync(tmp, JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
    renameSync(tmp, paths.manifestPath);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* never created, or already renamed */ }
    throw e;
  }
}

/** Read an instance manifest; null when missing/corrupt (a dir mid-creation
 *  or hand-tampered — callers treat it as unknown, not fatal). */
export function readManifest(dir: string): InstanceManifest | null {
  try {
    const m = JSON.parse(readFileSync(join(dir, MANIFEST), "utf8")) as InstanceManifest;
    return typeof m === "object" && m !== null && typeof m.pid === "number" ? m : null;
  } catch {
    return null;
  }
}

/**
 * Point `${base}/current` at instance dir `id` ATOMICALLY: create the symlink
 * under a temp name, then rename(2) over `current`. Readers resolving
 * `current/arbiter.sock` see either the old target or the new one, never a
 * missing/partial link. A plain directory squatting the `current` name (e.g. a
 * stray `mkdir -p .../current`) is removed first — only if it is NOT a symlink.
 */
export function promoteInstance(base: string, id: string): void {
  const link = join(base, CURRENT_LINK);
  const tmp = join(base, `${CURRENT_TMP_PREFIX}${process.pid}`);
  try { unlinkSync(tmp); } catch { /* no stale tmp */ }
  // Relative target keeps the link valid if the base dir is bind-mounted/moved.
  symlinkSync(join(INSTANCES_DIR, id), tmp);
  try {
    if (existsSync(link) && !lstatSync(link).isSymbolicLink()) {
      rmSync(link, { recursive: true, force: true });
    }
  } catch { /* race: someone else fixed it */ }
  renameSync(tmp, link);
}

/** The instance id `current` points to, or null (no promotion yet / dangling). */
export function currentInstanceId(base: string): string | null {
  try {
    const link = join(base, CURRENT_LINK);
    if (!lstatSync(link).isSymbolicLink()) return null;
    const sock = join(link, ARBITER_SOCK);
    if (!existsSync(sock)) return null; // dangling promotion (dead + GC'd)
    return basename(readlinkSync(link));
  } catch {
    return null;
  }
}

/**
 * Resolve the arbiter socket a CLIENT should use:
 *   1. `$MANDU_ARBITER_SOCK` (legacy alias `MANDU_ARBITER_SOCKET`) verbatim;
 *   2. `${base}/current/arbiter.sock` when the promoted instance's socket exists;
 *   3. `${base}/arbiter.sock` — the legacy fixed path (pre-instance stacks).
 * Pure path logic + existence checks; liveness is the caller's concern.
 */
export function resolveArbiterSock(env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env.MANDU_ARBITER_SOCK ?? env.MANDU_ARBITER_SOCKET;
  if (explicit) return explicit;
  const base = runtimeBase(env);
  const current = join(base, CURRENT_LINK, ARBITER_SOCK);
  if (existsSync(current)) return current;
  return join(base, ARBITER_SOCK);
}

/**
 * Resolve the HUMAN-PLANE socket a human-facing consumer should use
 * (arbiter-human-plane.md §3):
 *   1. `$MANDU_ARBITER_HUMAN_SOCK` verbatim (what the launcher and the
 *      dashboard supervisor pass their human-facing children);
 *   2. `${base}/human/<current instance id>.sock` when it exists.
 * Null when neither names a socket. There is deliberately NO fallback to the
 * data socket: a consumer that cannot reach the human plane degrades by its
 * own fail-closed rule (the reply filter passes tokens through, fs-sync and
 * the egress paths refuse), it never asks the data socket for originals.
 */
export function resolveArbiterHumanSock(env: NodeJS.ProcessEnv = process.env): string | null {
  const explicit = env[HUMAN_SOCK_ENV];
  if (explicit) return explicit;
  const base = runtimeBase(env);
  const id = currentInstanceId(base);
  if (id === null) return null;
  const p = humanSockPath(base, id);
  return existsSync(p) ? p : null;
}

/** True iff a process with this pid exists (signal 0 probe). */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM"; // alive, not ours
  }
}

/**
 * Garbage-collect instance dirs whose manifest pid is DEAD. Keeps: live pids,
 * dirs with no readable manifest younger than `graceMs` (mid-creation), and
 * never follows `current` — a dangling `current` simply stops resolving.
 * Returns the removed instance ids. Best-effort: any per-dir error skips that
 * dir (GC must never take the arbiter down).
 *
 * Nor does it follow `instances` itself (2026-09-30): swapped for a link to
 * some other directory, every entry there would read as a manifest-less dir
 * past its grace and be removed, by a process that runs outside the agent's
 * confinement. A registry that is not a real directory is not swept (the
 * start then refuses it in createInstanceDir). A check, not a lock: the
 * macOS Seatbelt profile keeps the agent from replacing it at all.
 */
export function sweepDeadInstances(base: string, graceMs = 60_000): string[] {
  const removed: string[] = [];
  const root = join(base, INSTANCES_DIR);
  if (!isRealDir(root)) return removed; // no instances dir yet, or not one to trust
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return removed;
  }
  for (const id of entries) {
    const dir = join(root, id);
    try {
      const manifest = readManifest(dir);
      if (manifest === null) {
        // Unreadable manifest: only reap once clearly abandoned (older than grace).
        const age = Date.now() - lstatSync(dir).mtimeMs;
        if (age < graceMs) continue;
      } else if (pidAlive(manifest.pid)) {
        continue;
      }
      rmSync(dir, { recursive: true, force: true });
      // Its human-plane socket lives outside the instance dir (§3 above).
      try { unlinkSync(humanSockPath(base, id)); } catch { /* none, or already gone */ }
      removed.push(id);
    } catch {
      /* skip this dir; never fail the sweep */
    }
  }
  return removed;
}
