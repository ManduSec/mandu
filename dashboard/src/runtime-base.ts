/**
 * runtime-base — where the Mandu runtime state lives (the arbiter's instance
 * sockets, `current`, the registry, per-launch scope dirs), the private-dir
 * check for its /tmp fallback and the ownership check for a base in a shared
 * sticky dir (docs/design/architecture/runtime-instances.md §3b).
 *
 * THE RULE (identical in every mirror, 2026-09-29; rule 3 per-user since 2026-10-09):
 *
 *   1. $MANDU_RUNTIME_DIR verbatim (one trailing `/` stripped);
 *   2. else $XDG_RUNTIME_DIR/mandu;
 *   3. else cand = ($TMPDIR || /tmp)/mandu-<uid>, used when
 *        byteLength(cand) + INSTANCE_SOCK_SUFFIX_MAX < SUN_PATH_MAX
 *      (sun_path: 104 on darwin/BSD, 108 elsewhere);
 *   4. otherwise the FALLBACK /tmp/mandu-<uid>.
 *
 * Rule 3 was `($TMPDIR || /tmp)/mandu` until 2026-10-09: on a host with no
 * XDG_RUNTIME_DIR every account shared the one name `/tmp/mandu`, so the
 * first account to make it owned it and every other account's Mandu refused
 * to start (the check below). Per-user, the name an account resolves is its
 * own, and on Linux without TMPDIR rule 3 IS the fallback's form. An unknown
 * uid (no process.getuid) keeps the shared name.
 *
 * Why: macOS has no XDG_RUNTIME_DIR, and its per-user TMPDIR
 * (/var/folders/xx/…/T/, 49 bytes) left no room for
 * `mandu/instances/<id>/arbiter.sock` under the 103 usable sun_path bytes —
 * the arbiter refused to bind (§3a) and every `mandu claude` refused. The
 * fallback is short by construction (≤ 22 bytes + 63 fits everywhere).
 *
 * Rules 1–2 ARE the path table's `runtime-dir` (manduPath, generated from
 * scripts/paths/mandu-paths.mjs; on-disk-layout.md §5), and rule 3 is the
 * table's `runtime-dir` under TMPDIR with `-<uid>` appended: only env counts,
 * so an env without TMPDIR gives `/tmp/mandu-<uid>`, never os.tmpdir(). This
 * module adds the uid, the fit check and rule 4, which the table (a function
 * of the environment alone) cannot express.
 *
 * THE FALLBACK IS PRIVATE OR NOTHING. /tmp is shared by every account: a
 * `/tmp/mandu-<uid>` another user created first could hold a `current` link to
 * an impostor arbiter. So wherever Mandu is about to use it, the dir is created
 * with mode 0700 when absent, and otherwise must be a real directory (not a
 * symlink), owned by this uid, with no group/other permission bits — else the
 * start REFUSES (fail closed) and says how to fix it. /tmp's sticky bit keeps a
 * verified dir ours: nobody else can rename or remove it afterwards.
 *
 * A BASE DIRECTLY IN A SHARED STICKY DIR IS OURS OR NOTHING. The same attack
 * works on any base whose PARENT is world-writable and sticky (/tmp, /var/tmp):
 * `$TMPDIR/mandu-<uid>` with TMPDIR=/var/tmp (or `/tmp/mandu`, the shared name
 * before 2026-10-09), an explicit MANDU_RUNTIME_DIR=/tmp/<x>. Such a base gets the
 * RELAXED check (ownedDirProblem): created 0700 when absent, else a real
 * directory owned by this uid that no other account can WRITE. Group/other
 * read and search stay allowed, so the 0755 dir an earlier arbiter made with
 * the umask passes. The fallback keeps the strict check.
 *
 * ANY OTHER BASE IS MADE 0700 (2026-10-17): `$XDG_RUNTIME_DIR/mandu`, an
 * explicit MANDU_RUNTIME_DIR elsewhere. It was made by a `mkdir -p` with the
 * umask's mode (0775 under a 002 umask), and it holds the sockets: a
 * group-writable base lets a group member plant or replace one. Now it is
 * created 0700 (ensureRuntimeBaseDir); an existing one with group/other bits is
 * tightened to 0700 when an ancestor keeps every other account out
 * (sealedFromOthers: /run/user/<uid> is 0700), else refused when others can
 * write it (the relaxed rule); a symlink or another uid's dir is refused.
 *
 * `MANDU_RUNTIME_FALLBACK_ROOT` (a TEST HOOK, not a product knob) replaces the
 * `/tmp` root of the fallback so a suite can exercise the fallback without
 * touching the host's real `/tmp/mandu-<uid>`. It grants nothing
 * MANDU_RUNTIME_DIR does not already: whoever sets env picks the base anyway.
 * The account's rendezvous (the arbiter's and launcher's accountRendezvous)
 * never reads it.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): a MIRROR of arbiter/ipc/runtime-base.ts
 * — the dashboard is an arbiter CLIENT and does not import the arbiter
 * package, so the rule is copied; the parity oracle
 * tests/stack/runtime-base-parity.test.ts proves the copies
 * (arbiter, launcher, dashboard) agree. Keep them in sync. The account
 * rendezvous half is not mirrored here (the dashboard has no foreign-HOME
 * guard of its own; dashboard.md §3.3a checks the adopted arbiter's event dir).
 *
 * Dashboard user: server-main.ts (RUNTIME_BASE, and the private-fallback
 * check before it connects to or creates anything under the base).
 */

import { chmodSync, lstatSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { manduPath } from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

/** Where the base came from. "fallback" is the only one the private-dir rule
 *  is about; a base that merely EQUALS the fallback path (the launcher hands
 *  its resolved base to the arbiter as MANDU_RUNTIME_DIR) is recognized by
 *  path, see fallbackBaseContaining. */
export type RuntimeBaseSource = "explicit" | "xdg" | "tmpdir" | "fallback";

export interface ResolvedRuntimeBase {
  base: string;
  source: RuntimeBaseSource;
}

/** Injectable facts for the pure rule (tests; the account rendezvous). */
export interface RuntimeBaseOptions {
  /** Default process.platform — picks the sun_path size. */
  platform?: string;
  /** Default process.getuid(); null = unknown (no fallback is possible). */
  uid?: number | null;
  /** Default $MANDU_RUNTIME_FALLBACK_ROOT, else "/tmp". */
  fallbackRoot?: string;
}

/** The env var of the fallback-root test hook (module doc). */
export const FALLBACK_ROOT_ENV = "MANDU_RUNTIME_FALLBACK_ROOT";
/** The real root of the fallback. */
export const DEFAULT_FALLBACK_ROOT = "/tmp";

/** The longest instance id arbiter/ipc/instance.ts instanceId() can produce:
 *  `yyyymmdd-hhmm` (13) + `-` + the git rev sliced to 16 + `-p` + a 7-digit
 *  pid (Linux pid_max tops out at 4194304). */
export const INSTANCE_ID_MAX = 13 + 1 + 16 + 2 + 7;
/** Bytes an arbiter instance socket adds to its base:
 *  `/instances/` + the longest instance id + `/arbiter.sock` = 63. Pinned
 *  against the arbiter's instanceId() by the parity oracle. */
export const INSTANCE_SOCK_SUFFIX_MAX = "/instances/".length + INSTANCE_ID_MAX + "/arbiter.sock".length;

/** `sockaddr_un.sun_path` capacity, NUL included, for a platform. */
export function sunPathMaxFor(platform: string): number {
  return platform === "darwin" || platform.endsWith("bsd") ? 104 : 108;
}

/** The most digits a pid can have: 5 on darwin (PID_MAX 99999), else 7
 *  (Linux pid_max tops out at 4194304). */
export function maxPidDigitsFor(platform: string): number {
  return platform === "darwin" ? 5 : 7;
}

/** Bytes the instance socket of an arbiter running code rev `gitRev` adds to
 *  its base, for a pid of `pidDigits` digits: the REAL suffix, where
 *  INSTANCE_SOCK_SUFFIX_MAX is the worst case. The rev is sanitised and
 *  sliced exactly as arbiter/ipc/instance.ts instanceId() does ("nogit" when
 *  nothing is left); pinned against it by the arbiter's unit test. */
export function instanceSockSuffix(gitRev: string, pidDigits: number): number {
  const rev = gitRev.replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 16) || "nogit";
  return "/instances/".length + 13 + 1 + rev.length + 2 + pidDigits + "/arbiter.sock".length;
}

function stripSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/$/, "") : p;
}

function currentUid(): number | null {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

/** `<root>/mandu-<uid>`, or null when the uid is unknown. */
export function fallbackBase(env: Env = process.env, opts: RuntimeBaseOptions = {}): string | null {
  const uid = opts.uid !== undefined ? opts.uid : currentUid();
  if (uid === null) return null;
  const root = stripSlash(opts.fallbackRoot ?? (env[FALLBACK_ROOT_ENV] || DEFAULT_FALLBACK_ROOT));
  return `${root === "/" ? "" : root}/mandu-${uid}`;
}

/** The path table's `runtime-dir` under TMPDIR (`$TMPDIR/mandu`, `/tmp/mandu`
 *  when TMPDIR is unset or empty): rule 3's base before 2026-10-09, shared
 *  by every account. On Linux without XDG_RUNTIME_DIR every version before
 *  then put the base there (the moved-base hint in the launcher's
 *  arbiter-sock.ts looks there). */
export function legacyTmpdirBase(env: Env = process.env): string {
  return stripSlash(manduPath("runtime-dir", { TMPDIR: env["TMPDIR"] }, ""));
}

/** Rule 3's candidate, `<legacyTmpdirBase>-<uid>` (`/tmp/mandu-<uid>` when
 *  TMPDIR is unset or empty), whether or not an instance socket fits under
 *  it; the legacy shared name when the uid is unknown. */
export function tmpdirCandidate(env: Env = process.env, opts: RuntimeBaseOptions = {}): string {
  const uid = opts.uid !== undefined ? opts.uid : currentUid();
  const legacy = legacyTmpdirBase(env);
  return uid === null ? legacy : `${legacy}-${uid}`;
}

/** Rules 2–4: the base when MANDU_RUNTIME_DIR is not set. Pure over opts. */
export function defaultRuntimeBaseOf(env: Env = process.env, opts: RuntimeBaseOptions = {}): ResolvedRuntimeBase {
  const xdg = env["XDG_RUNTIME_DIR"];
  if (xdg) return { base: stripSlash(manduPath("runtime-dir", { XDG_RUNTIME_DIR: xdg }, "")), source: "xdg" };
  const cand = tmpdirCandidate(env, opts);
  const platform = opts.platform ?? process.platform;
  if (Buffer.byteLength(cand, "utf8") + INSTANCE_SOCK_SUFFIX_MAX < sunPathMaxFor(platform)) {
    return { base: cand, source: "tmpdir" };
  }
  const fb = fallbackBase(env, opts);
  return fb === null ? { base: cand, source: "tmpdir" } : { base: fb, source: "fallback" };
}

/** The whole rule (1–4). */
export function resolveRuntimeBase(env: Env = process.env, opts: RuntimeBaseOptions = {}): ResolvedRuntimeBase {
  const explicit = env["MANDU_RUNTIME_DIR"];
  if (explicit) return { base: stripSlash(explicit), source: "explicit" };
  return defaultRuntimeBaseOf(env, opts);
}

/** Why an arbiter instance socket under `base` might not fit sun_path, or null.
 *  `suffixBytes` is what the socket adds to the base: by default the worst
 *  case (any rev, any pid); the launcher's autostart preflight passes the
 *  real suffix of the arbiter it is about to start (instanceSockSuffix), so
 *  it refuses only a base that arbiter cannot bind under. The advice names
 *  the worst-case budget either way: a dir that size always fits. */
export function instanceBaseProblem(
  base: string,
  platform: string = process.platform,
  suffixBytes: number = INSTANCE_SOCK_SUFFIX_MAX,
): string | null {
  const bytes = Buffer.byteLength(base, "utf8");
  const max = sunPathMaxFor(platform);
  if (bytes + suffixBytes < max) return null;
  return (
    `the runtime dir ${base} is ${bytes} bytes: an arbiter socket under it ` +
    `(<dir>/instances/<id>/arbiter.sock) can reach ${bytes + suffixBytes} bytes, over the ` +
    `${max - 1}-byte limit for a Unix socket (sun_path). Point MANDU_RUNTIME_DIR at a directory of at most ` +
    `${max - 1 - INSTANCE_SOCK_SUFFIX_MAX} bytes, e.g. MANDU_RUNTIME_DIR=/tmp/mdu-$USER`
  );
}

// ── the private fallback, and a base in a shared sticky dir ─────────────────

/** What the private-dir check reads (fs.lstatSync's shape). */
export interface DirStat {
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
  uid: number;
  mode: number;
}

/** Injectable filesystem for the private-dir check (tests simulate a foreign
 *  owner through `lstat`; nothing else can). */
export interface PrivateDirDeps {
  lstat?: (p: string) => DirStat;
  /** Non-recursive mkdir with a mode (throws EEXIST when present). */
  mkdir?: (p: string, mode: number) => void;
  chmod?: (p: string, mode: number) => void;
  /** Default process.getuid(). */
  uid?: number | null;
  /** The mode of a base's PARENT, links followed (fs.statSync(p).mode): is
   *  it a shared sticky dir? Tests stand a scratch dir in for /tmp. */
  statMode?: (p: string) => number;
  /** The owner and mode of an ANCESTOR of a base, links followed
   *  (fs.statSync): does it keep every other account out? Tests simulate
   *  a sealing or an open ancestor. */
  statDir?: (p: string) => { uid: number; mode: number };
  /** Recursive mkdir with a mode, for the missing ancestors of a base that is
   *  neither the fallback nor directly in a shared sticky dir. */
  mkdirp?: (p: string, mode: number) => void;
}

function modeString(mode: number): string {
  return (mode & 0o777).toString(8).padStart(4, "0");
}

/** Why `dir` is not a private directory of `uid`, or null when it is. Pure
 *  over the stat. */
export function privateDirProblem(st: DirStat, uid: number | null): string | null {
  if (st.isSymbolicLink()) return "is a symlink";
  if (!st.isDirectory()) return "is not a directory";
  if (uid !== null && st.uid !== uid) return `is owned by uid ${st.uid}, not by you (uid ${uid})`;
  if ((st.mode & 0o077) !== 0) {
    return `is shared (mode ${modeString(st.mode)}: group/other permission bits are set)`;
  }
  return null;
}

/** Why `dir` is not a directory `uid` alone controls — a real directory it
 *  owns that no other account can write — or null. The RELAXED rule for a
 *  base directly in a shared sticky dir: group/other read and search are
 *  allowed (a self-made 0755 dir passes), group/other WRITE is not (anyone
 *  who can write the base can plant a `current` link in it). Pure. */
export function ownedDirProblem(st: DirStat, uid: number | null): string | null {
  if (st.isSymbolicLink()) return "is a symlink";
  if (!st.isDirectory()) return "is not a directory";
  if (uid !== null && st.uid !== uid) return `is owned by uid ${st.uid}, not by you (uid ${uid})`;
  if ((st.mode & 0o022) !== 0) {
    return `is writable by other accounts (mode ${modeString(st.mode)}: group/other write bits are set)`;
  }
  return null;
}

/** A world-writable directory with the sticky bit (/tmp, /var/tmp, macOS
 *  /private/tmp): anyone may create an entry in it, and only that entry's
 *  owner (or the dir's) may rename or remove it. */
export function isSharedStickyMode(mode: number): boolean {
  return (mode & 0o1002) === 0o1002;
}

function refusal(dir: string, problem: string): Error {
  return new Error(
    `the Mandu runtime dir ${dir} ${problem}. Mandu keeps its sockets there and will not use a directory ` +
      `another user could control. If it is yours, remove it (rm -rf ${dir}) and retry; or point ` +
      "MANDU_RUNTIME_DIR at a private directory (mkdir -m 700 <dir>).",
  );
}

type DirCheck = (st: DirStat, uid: number | null) => string | null;

/** Create `dir` 0700 when absent, else verify it with `check`. */
function ensureDirWith(dir: string, deps: PrivateDirDeps, check: DirCheck): void {
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p));
  const mkdir = deps.mkdir ?? ((p: string, mode: number) => { mkdirSync(p, { mode }); });
  const chmod = deps.chmod ?? ((p: string, mode: number) => { chmodSync(p, mode); });
  const uid = deps.uid !== undefined ? deps.uid : currentUid();
  try {
    mkdir(dir, 0o700);
    // Ours from this instant (/tmp is sticky): pin the mode the umask may have
    // narrowed (it can only remove bits; an owner-less 0000 would lock us out).
    chmod(dir, 0o700);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "EEXIST") throw refusal(dir, `could not be created (${(err as Error).message})`);
  }
  let st: DirStat;
  try {
    st = lstat(dir);
  } catch (err) {
    throw refusal(dir, `could not be checked (${(err as Error).message})`);
  }
  const problem = check(st, uid);
  if (problem !== null) throw refusal(dir, problem);
}

/** Verify `dir` with `check` when present; an ABSENT dir passes. */
function assertDirIfPresentWith(dir: string, deps: PrivateDirDeps, check: DirCheck): void {
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p));
  const uid = deps.uid !== undefined ? deps.uid : currentUid();
  let st: DirStat;
  try {
    st = lstat(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw refusal(dir, `could not be checked (${(err as Error).message})`);
  }
  const problem = check(st, uid);
  if (problem !== null) throw refusal(dir, problem);
}

/**
 * Create `dir` with mode 0700 when absent, else verify it is a private
 * directory of this uid; throw an actionable refusal otherwise. Non-recursive
 * on purpose: the fallback's parent is /tmp, and a missing parent is a
 * misconfiguration to report, not to paper over.
 */
export function ensurePrivateDir(dir: string, deps: PrivateDirDeps = {}): void {
  ensureDirWith(dir, deps, privateDirProblem);
}

/** Verify-only form: an ABSENT dir passes (there is nothing to trust yet);
 *  a present one must be private. For readers that must not create. */
export function assertPrivateDirIfPresent(dir: string, deps: PrivateDirDeps = {}): void {
  assertDirIfPresentWith(dir, deps, privateDirProblem);
}

/** ensurePrivateDir with the RELAXED rule (ownedDirProblem): created 0700
 *  when absent (non-recursive, so a dir someone else made first is caught
 *  by the check, never adopted by a `mkdir -p`), else it must be ours and
 *  writable by nobody else. */
export function ensureOwnedDir(dir: string, deps: PrivateDirDeps = {}): void {
  ensureDirWith(dir, deps, ownedDirProblem);
}

/** Verify-only form of ensureOwnedDir: an ABSENT dir passes. */
export function assertOwnedDirIfPresent(dir: string, deps: PrivateDirDeps = {}): void {
  assertDirIfPresentWith(dir, deps, ownedDirProblem);
}

/** `dir` as given, plus its spelling with the PARENT canonicalised when that
 *  differs (macOS `/tmp/x` → `/private/tmp/x`). */
function spellingsOf(dir: string): string[] {
  const spellings = [dir];
  try {
    const i = dir.lastIndexOf("/");
    const parentReal = realpathSync(dir.slice(0, i) || "/");
    const canon = `${parentReal === "/" ? "" : parentReal}${dir.slice(i)}`;
    if (canon !== dir) spellings.push(canon);
  } catch { /* the parent does not resolve: only the literal spelling */ }
  return spellings;
}

/** Is `p` (already resolved) `dir` or inside it? */
function within(p: string, dir: string): boolean {
  return p === dir || p.startsWith(dir === "/" ? "/" : dir + "/");
}

/**
 * The fallback base (either spelling: `/tmp/mandu-<uid>` and its canonical
 * `/private/tmp/mandu-<uid>` on macOS) that `path` is, or lies inside; null
 * otherwise. This is how a process that received the base as
 * MANDU_RUNTIME_DIR (the arbiter and dashboard the launcher spawns) still
 * recognizes the fallback.
 */
export function fallbackBaseContaining(
  path: string,
  env: Env = process.env,
  opts: RuntimeBaseOptions = {},
): string | null {
  const fb = fallbackBase(env, opts);
  if (fb === null) return null;
  const p = resolve(path);
  for (const s of spellingsOf(fb)) {
    if (within(p, s)) return s;
  }
  return null;
}

/**
 * The runtime base — the resolved one (rules 1–4) or the default one (2–4,
 * the scope-dir root) — that `path` is or lies inside, when that base sits
 * DIRECTLY in a shared sticky dir (isSharedStickyMode of its parent); null
 * otherwise. Either spelling, as fallbackBaseContaining. Keyed on the parent's
 * mode, not on where the base came from, because the arbiter and dashboard
 * the launcher spawns receive every base as MANDU_RUNTIME_DIR.
 */
export function sharedParentBaseContaining(
  path: string,
  env: Env = process.env,
  opts: RuntimeBaseOptions = {},
  deps: PrivateDirDeps = {},
): string | null {
  const statMode = deps.statMode ?? ((p: string) => statSync(p).mode);
  const p = resolve(path);
  for (const base of [resolveRuntimeBase(env, opts).base, defaultRuntimeBaseOf(env, opts).base]) {
    for (const s of spellingsOf(resolve(base))) {
      if (!within(p, s)) continue;
      const parent = dirname(s);
      if (parent === s) continue; // the root has no parent to share
      let mode: number;
      try {
        mode = statMode(parent);
      } catch {
        continue; // no parent yet: nothing shared to guard against
      }
      if (isSharedStickyMode(mode)) return s;
    }
  }
  return null;
}

// ── any other base: made 0700, tightened when sealed (2026-10-17) ───────────

/**
 * The runtime base — the resolved one (rules 1–4) or the default one (2–4) —
 * that `path` is or lies inside, whatever its parent; null otherwise. Either
 * spelling, as fallbackBaseContaining.
 */
export function runtimeBaseContaining(
  path: string,
  env: Env = process.env,
  opts: RuntimeBaseOptions = {},
): string | null {
  const p = resolve(path);
  for (const base of [resolveRuntimeBase(env, opts).base, defaultRuntimeBaseOf(env, opts).base]) {
    for (const s of spellingsOf(resolve(base))) {
      if (within(p, s)) return s;
    }
  }
  return null;
}

/**
 * Does no account but this uid (and root) reach inside `dir`? True when an
 * ANCESTOR of it (its parent or higher), owned by this uid or by root, grants
 * group and other no search permission: `/run/user/<uid>` (logind makes it
 * 0700), a mkdtemp dir, macOS's per-user `T/`. Then a group/other bit on
 * `dir` itself was set by this uid (only an owner chmods) and no other
 * account could have used it, so tightening it loses nothing. An ancestor
 * that cannot be stat'ed ends the walk unsealed (fail closed).
 */
export function sealedFromOthers(dir: string, deps: PrivateDirDeps = {}): boolean {
  const statDir = deps.statDir ?? ((p: string) => statSync(p));
  const uid = deps.uid !== undefined ? deps.uid : currentUid();
  let p = dirname(resolve(dir));
  for (;;) {
    let st: { uid: number; mode: number };
    try {
      st = statDir(p);
    } catch {
      return false;
    }
    if ((st.uid === uid || st.uid === 0) && (st.mode & 0o011) === 0) return true;
    const up = dirname(p);
    if (up === p) return false;
    p = up;
  }
}

/** What to do with an EXISTING runtime base that is neither the fallback nor
 *  directly in a shared sticky dir. */
export type RuntimeBaseVerdict =
  | { kind: "ok" }
  | { kind: "tighten" }
  | { kind: "refuse"; problem: string };

/**
 * The rule for any other base (`$XDG_RUNTIME_DIR/mandu`, an explicit
 * `MANDU_RUNTIME_DIR` outside a shared sticky dir). Pure over the stat:
 *   - a symlink, a non-directory or another uid's directory: refuse;
 *   - no group/other bit: ok;
 *   - group/other bits and `sealed` (sealedFromOthers): tighten to 0700, since
 *     only this uid could have set them and only it could have reached in;
 *   - else the relaxed rule (ownedDirProblem): a dir others can WRITE is
 *     refused (someone may already have planted a link or a socket in it,
 *     which a chmod would not undo); a 0755 one passes.
 */
export function runtimeBaseVerdict(st: DirStat, uid: number | null, sealed: boolean): RuntimeBaseVerdict {
  if (st.isSymbolicLink()) return { kind: "refuse", problem: "is a symlink" };
  if (!st.isDirectory()) return { kind: "refuse", problem: "is not a directory" };
  if (uid !== null && st.uid !== uid) {
    return { kind: "refuse", problem: `is owned by uid ${st.uid}, not by you (uid ${uid})` };
  }
  if ((st.mode & 0o077) === 0) return { kind: "ok" };
  if (sealed) return { kind: "tighten" };
  const problem = ownedDirProblem(st, uid);
  return problem === null ? { kind: "ok" } : { kind: "refuse", problem };
}

/**
 * Create the runtime base `dir` (neither the fallback nor directly in a
 * shared sticky dir) with mode 0700 when absent — its missing ancestors too,
 * 0700 — and `chmod` it, since the umask can narrow the mode; else apply
 * runtimeBaseVerdict: tighten a sealed one to 0700, refuse what it refuses.
 * Before 2026-10-17 such a base was made by a `mkdir -p` with the umask's
 * mode: 0775 under a 002 umask.
 */
export function ensureRuntimeBaseDir(dir: string, deps: PrivateDirDeps = {}): void {
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p));
  const mkdir = deps.mkdir ?? ((p: string, mode: number) => { mkdirSync(p, { mode }); });
  const mkdirp = deps.mkdirp ?? ((p: string, mode: number) => { mkdirSync(p, { recursive: true, mode }); });
  const chmod = deps.chmod ?? ((p: string, mode: number) => { chmodSync(p, mode); });
  const uid = deps.uid !== undefined ? deps.uid : currentUid();
  try {
    mkdirp(dirname(dir), 0o700);
    mkdir(dir, 0o700);
    chmod(dir, 0o700);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "EEXIST") throw refusal(dir, `could not be created (${(err as Error).message})`);
  }
  let st: DirStat;
  try {
    st = lstat(dir);
  } catch (err) {
    throw refusal(dir, `could not be checked (${(err as Error).message})`);
  }
  const verdict = runtimeBaseVerdict(st, uid, (st.mode & 0o077) !== 0 && sealedFromOthers(dir, deps));
  if (verdict.kind === "refuse") throw refusal(dir, verdict.problem);
  if (verdict.kind === "tighten") {
    try {
      chmod(dir, 0o700);
    } catch (err) {
      throw refusal(dir, `is shared (mode ${modeString(st.mode)}) and could not be made 0700 (${(err as Error).message})`);
    }
  }
}

/** Verify-only form of ensureRuntimeBaseDir: an ABSENT dir passes, and so
 *  does a sealed one with group/other bits (a reader does not chmod; nobody
 *  else could have reached in). */
export function assertRuntimeBaseIfPresent(dir: string, deps: PrivateDirDeps = {}): void {
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p));
  const uid = deps.uid !== undefined ? deps.uid : currentUid();
  let st: DirStat;
  try {
    st = lstat(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw refusal(dir, `could not be checked (${(err as Error).message})`);
  }
  const verdict = runtimeBaseVerdict(st, uid, (st.mode & 0o077) !== 0 && sealedFromOthers(dir, deps));
  if (verdict.kind === "refuse") throw refusal(dir, verdict.problem);
}

/** When `path` is (under) the fallback base: create-or-verify that base as a
 *  private dir. Else, when it is (under) a runtime base directly in a shared
 *  sticky dir: create-or-verify that base with the relaxed rule
 *  (ensureOwnedDir). Else, when it is (under) any other runtime base
 *  (`$XDG_RUNTIME_DIR/mandu`, an explicit one): create it 0700, tighten or
 *  refuse it (ensureRuntimeBaseDir). No-op for a path under no base. The one
 *  call every creator uses. */
export function ensurePrivateIfFallback(
  path: string,
  env: Env = process.env,
  opts: RuntimeBaseOptions = {},
  deps: PrivateDirDeps = {},
): void {
  const fb = fallbackBaseContaining(path, env, opts);
  if (fb !== null) {
    ensurePrivateDir(fb, deps);
    return;
  }
  const shared = sharedParentBaseContaining(path, env, opts, deps);
  if (shared !== null) {
    ensureOwnedDir(shared, deps);
    return;
  }
  const base = runtimeBaseContaining(path, env, opts);
  if (base !== null) ensureRuntimeBaseDir(base, deps);
}

/** The verify-only twin of ensurePrivateIfFallback, for readers that must not
 *  create: the same three rules, an ABSENT base passes. */
export function assertTrustedIfPresent(
  path: string,
  env: Env = process.env,
  opts: RuntimeBaseOptions = {},
  deps: PrivateDirDeps = {},
): void {
  const fb = fallbackBaseContaining(path, env, opts);
  if (fb !== null) {
    assertPrivateDirIfPresent(fb, deps);
    return;
  }
  const shared = sharedParentBaseContaining(path, env, opts, deps);
  if (shared !== null) {
    assertOwnedDirIfPresent(shared, deps);
    return;
  }
  const base = runtimeBaseContaining(path, env, opts);
  if (base !== null) assertRuntimeBaseIfPresent(base, deps);
}
