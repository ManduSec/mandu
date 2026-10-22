/**
 * reap — `mandu reap`: garbage-collect the runtime registry
 * (runtime-instances.md §10).
 *
 * What accumulates on a shared dev+CI host and what this collects:
 *   - instances/<id>/ whose manifest pid is DEAD (SIGKILLed daemons — the
 *     startup sweep only runs at the NEXT arbiter start, which may be never);
 *   - live arbiters whose OWNER pid is dead (ad-hoc session spawns orphaned by
 *     a closed shell/session — the 17h-straggler class), unless promoted as
 *     `current`; killed via SIGTERM only after the process proves it is THIS
 *     record's arbiter (arbiterIdentity: the canonical title read from /proc
 *     on Linux or `ps` on darwin, and, where readable, a start time that fits
 *     the manifest's startedAt). A pid that fails either was recycled: its
 *     record is removed and nothing is signalled;
 *   - a dangling `current` symlink (dead + swept promotion target);
 *   - scope-run dirs `<epochSec>-<pid>` whose pid is dead (exec-shims/events
 *     litter from finished launches). Before one goes, reap names each
 *     registered secret file whose placeholder copy that session changed,
 *     when its launcher died before it could say so itself
 *     (twin-writes.ts `staleScopeDiscardedWrites`; plan 10 §4.1);
 *   - a DEAD legacy `${base}/arbiter.sock` file (it would win the
 *     resolution order in arbiter-sock.ts and break the next launch);
 *   - qemu guests the VM test harnesses registered (`vm-guests/<id>.json`,
 *     scripts/lib/guest-registry.sh) whose OWNER harness is gone: a live one
 *     is stopped only after its pid's start time and cmdline CONFIRM it is
 *     the registered qemu; then its scratch dir is removed (kept under
 *     --keep, except what `alsoRemove` names).
 *
 * Deliberately conservative: anything ambiguous is SKIPPED and reported.
 * Container-scoped pids never appear here — the registry lives in the host's
 * runtime base; containers have their own.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; manifest layout
 * mirrors arbiter/ipc/instance.ts (each package stays standalone).
 */
import { execFileSync } from "node:child_process";
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readlinkSync, readSync } from "node:fs";
import { basename, isAbsolute, join, normalize, relative } from "node:path";
import { connect } from "node:net";
import { homedir, tmpdir } from "node:os";
import { runtimeBase } from "./arbiter-sock.js";
import { manduPath } from "./generated/mandu-paths.js";
import { PS_ENV } from "./platform/proc-tree.js";
import { closeDir, listDir, lstatIn, openDir, openDirIn, readJsonIn, removeIn, removePath, type DirHandle, type EntryKind } from "./safe-remove.js";
import { reapDiscardedWriteNotice, staleScopeDiscardedWrites } from "./twin-writes.js";
import { restorePendingFromStores, twinIndexReadStores } from "./twin-index-stat.js";
import { findAbandonedDaemons, procFactsOf, realAbandonedDeps, stillAbandoned, type AbandonedDeps, type ProcFacts } from "./abandoned-stacks.js";

type Env = Record<string, string | undefined>;

/** Mirror of the arbiter's InstanceManifest fields reap consumes. */
export interface ManifestLite {
  pid: number;
  ownerPid?: number | null;
  mode?: "instance" | "pinned";
  sockPath?: string;
  /** ISO 8601, written by the arbiter itself once its socket listens, so
   *  always AFTER its process started (arbiter/ipc/server-main.ts). */
  startedAt?: string;
}

/** Mirror of the dashboard's DashboardManifest fields reap/status consume
 *  (dashboard/src/registry.ts — flat `dashboards/<id>.json` entries). */
export interface DashManifestLite {
  pid: number;
  ownerPid?: number | null;
  port?: number;
  host?: string;
  gitRev?: string;
  /** URL prefix the dashboard serves under ("" = none; absent in old entries). */
  basePath?: string;
  /** Its sign-in socket in the human-plane directory (dashboard sign-in.ts;
   *  absent before 2026-10-05). */
  signInSock?: string;
  /** How a person signs in (dashboard registry.ts; absent before 2026-10-22). */
  signInMode?: string;
}

export interface ReapDeps {
  pidAlive(pid: number): boolean;
  cmdlineOf(pid: number): string | null;
  kill(pid: number, sig: NodeJS.Signals): void;
  /** true when a connect() to the unix socket is accepted. */
  socketLive(path: string): Promise<boolean>;
  now(): number;
  /** The process's start time (/proc/<pid>/stat field 22, clock ticks since
   *  boot); null when the pid is gone or a zombie. Absent or null ⇒ a
   *  guest's identity is unverifiable, and reap never signals it. */
  procStart?(pid: number): number | null;
  /** /proc/sys/kernel/random/boot_id; null when unreadable. */
  bootId?(): string | null;
  sleep?(ms: number): Promise<void>;
  /** When `pid` started (epoch ms, whole seconds), or null when it cannot be
   *  read. Absent = never readable: the identity check is then title-only. */
  startMsOf?(pid: number): number | null;
  /** The processes `mandu reap` reads for abandoned daemons of OTHER stacks
   *  (abandoned-stacks.ts). Absent = none are looked for (a test's deps). */
  abandoned?: AbandonedDeps;
  /** Re-read one process's facts right before stopping it (defaults to /proc). */
  procFacts?(pid: number): ProcFacts | null;
}

/** Where a command line is read from — injectable for tests. */
export interface CmdlineSource {
  platform: NodeJS.Platform;
  /** Raw `/proc/<pid>/cmdline` (NUL-separated); throws when unreadable. */
  readProcCmdline(pid: number): string;
  /** `ps -ww -o args= -p <pid>`; throws when ps fails (no such pid) or hangs. */
  psArgs(pid: number): string;
}

export const realCmdlineSource: CmdlineSource = {
  platform: process.platform,
  readProcCmdline: (pid) => readFileSync(`/proc/${pid}/cmdline`, "utf8"),
  psArgs: (pid) =>
    execFileSync("/bin/ps", ["-ww", "-o", "args=", "-p", String(pid)], {
      encoding: "utf8",
      timeout: 2_000,
      stdio: ["ignore", "pipe", "ignore"],
    }),
};

/**
 * The command line of `pid` with NULs as spaces, trimmed, or null when it
 * cannot be read. Linux reads /proc/<pid>/cmdline; a host without /proc
 * (darwin) asks `ps -ww -o args=` (same user, unprivileged) — the same argv
 * area, so the canonical `process.title`s (runtime-instances.md §7) read the
 * same on both. Without the ps rung darwin read null for every pid: reap
 * deleted a LIVE dashboard's registry entry as "recycled" and never stopped
 * an orphaned arbiter. Mirror of arbiter/symbol-table/db-owner.ts
 * processCmdline (each package stays standalone).
 */
export function processCmdline(pid: number, src: CmdlineSource = realCmdlineSource): string | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const raw = src.platform === "linux" ? src.readProcCmdline(pid).replaceAll("\0", " ") : src.psArgs(pid);
    return raw.trim() || null;
  } catch {
    return null;
  }
}

/** Where a start time is read from — injectable for tests. */
export interface StartTimeSource {
  /** Runs `/bin/ps` with `args` under exactly `env`; throws when ps fails
   *  (no such pid, no procps on a busybox host) or hangs. */
  ps(args: string[], env: Readonly<Record<string, string>>): string;
}

export const realStartTimeSource: StartTimeSource = {
  ps: (args, env) =>
    execFileSync("/bin/ps", args, {
      encoding: "utf8",
      env: { ...env },
      timeout: 2_000,
      stdio: ["ignore", "pipe", "ignore"],
    }),
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** `ps -o lstart=` under the C locale and UTC (`Tue Sep 29 04:17:03 2026`,
 *  the day space-padded) → epoch ms; null when it is not that shape. */
export function parseLstartUtc(text: string): number | null {
  const m = /^\s*[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})\s*$/.exec(text);
  if (!m) return null;
  const month = MONTHS.indexOf(m[1]!);
  if (month < 0) return null;
  return Date.UTC(Number(m[6]), month, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
}

/**
 * When `pid` started, in epoch ms (whole seconds, rounded down), or null when
 * it cannot be read. One source on both platforms: `ps -o lstart=` (procps on
 * Linux, BSD ps on darwin) under PS_ENV, i.e. the C locale and TZ=UTC0, so the
 * answer does not move with the system time zone. A host whose ps has no
 * lstart (busybox) answers null, and the caller falls back to the title.
 */
export function processStartMs(pid: number, src: StartTimeSource = realStartTimeSource): number | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    return parseLstartUtc(src.ps(["-o", "lstart=", "-p", String(pid)], PS_ENV));
  } catch {
    return null;
  }
}

/** Start time of a live, non-zombie pid, from /proc/<pid>/stat. */
function readProcStart(pid: number): number | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // comm (field 2) may hold spaces and parens: split after the LAST ") ".
    const rest = stat.slice(stat.lastIndexOf(") ") + 2).trim().split(/\s+/);
    if (rest[0] === "Z" || rest[0] === "X") return null;
    const start = Number(rest[19]);
    return Number.isSafeInteger(start) ? start : null;
  } catch {
    return null;
  }
}

export const realReapDeps: ReapDeps = {
  pidAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === "EPERM";
    }
  },
  cmdlineOf: (pid: number): string | null => processCmdline(pid),
  kill(pid: number, sig: NodeJS.Signals): void {
    process.kill(pid, sig);
  },
  socketLive(path: string): Promise<boolean> {
    return new Promise((resolve) => {
      const s = connect(path);
      let settled = false;
      const done = (v: boolean): void => {
        if (settled) return;
        settled = true;
        try { s.destroy(); } catch { /* ignore */ }
        resolve(v);
      };
      s.once("connect", () => done(true));
      s.once("error", () => done(false));
      s.setTimeout(1000, () => done(false));
    });
  },
  now: () => Date.now(),
  procStart: readProcStart,
  bootId(): string | null {
    try {
      return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() || null;
    } catch {
      return null;
    }
  },
  sleep: (ms: number) => new Promise((r) => setTimeout(r, ms)),
  startMsOf: (pid: number): number | null => processStartMs(pid),
  abandoned: realAbandonedDeps,
  procFacts: procFactsOf,
};

export interface ReapAction {
  kind:
    | "rm-dead-instance"
    | "kill-orphan-arbiter"
    | "rm-dead-dashboard-entry"
    | "kill-orphan-dashboard"
    | "rm-dangling-current"
    | "rm-stale-scope-dir"
    | "rm-dead-legacy-sock"
    | "kill-orphan-guest"
    | "rm-dead-guest";
  /** What to remove (dirs/links/socket files) or the instance dir of a kill.
   *  For the guest kinds: the registry entry. */
  path: string;
  pid?: number;
  /** Guest kinds: the registered start time a kill re-checks just before it signals. */
  pidStart?: number;
  /** Guest kinds: the scratch paths removed once the guest is gone. */
  remove?: string[];
  detail: string;
}

/** Mirror of the entry scripts/lib/guest-registry.sh writes
 *  (`vm-guests/<harness>-<pid>.json`). */
export interface GuestEntryLite {
  pid: number;
  pidStart?: number;
  bootId?: string;
  ownerPid?: number | null;
  ownerStart?: number;
  harness?: string;
  workDir?: string;
  keep?: boolean;
  alsoRemove?: string[];
}

/** A parsed guest entry, or null = unreadable/corrupt. */
function guestEntryOf(m: unknown): GuestEntryLite | null {
  const g = m as Partial<GuestEntryLite> | null;
  if (g === null || typeof g !== "object" || typeof g.pid !== "number" || !Number.isSafeInteger(g.pid) || g.pid <= 0) return null;
  return g as GuestEntryLite;
}

/** Read a guest entry; null = unreadable/corrupt (or not a regular file:
 *  never through a link or a FIFO, `readJsonNoFollow`). */
export function readGuestEntryLite(path: string): GuestEntryLite | null {
  return guestEntryOf(readJsonNoFollow(path));
}

/** The JSON in the regular file `path`, opened O_NOFOLLOW|O_NONBLOCK (a link
 *  or a FIFO planted at the name is never read through or waited on); null
 *  when it is missing, not a regular file, over 1 MiB or not JSON. */
function readJsonNoFollow(path: string): unknown {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > 1 << 20) return null;
    const buf = Buffer.alloc(st.size);
    let off = 0;
    for (let n = -1; off < buf.length && n !== 0; off += n) n = readSync(fd, buf, off, buf.length - off, off);
    return JSON.parse(buf.subarray(0, off).toString("utf8"));
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** Open the registry directory `name` under the open base: null when it is
 *  absent; a refusal (a link, not a directory, not this user's) is noted and
 *  the directory is not walked. */
function openRegistry(baseH: DirHandle, name: string, notes: string[]): DirHandle | null {
  if (lstatIn(baseH, name) === null) return null;
  try {
    return openDirIn(baseH, name);
  } catch (e) {
    notes.push(`${name}/ not walked: ${(e as Error).message}`);
    return null;
  }
}

/** A live pid registered as a guest must BE qemu before reap signals it: its
 *  argv[0] (the /proc cmdline's first word) names a qemu system emulator. */
const QEMU_CMDLINE = /^(\S*\/)?qemu-(system-[\w.-]+|kvm)(\s|$)/;

/** Where a VM harness keeps a guest's scratch (the callers of
 *  scripts/lib/guest-registry.sh): the temp dirs (`mktemp -d
 *  "${TMPDIR:-/tmp}/…"`), the user's cache dir, Mandu's cache root
 *  (vm-run.sh's runs live under the CI cache), and the two overrides the
 *  harnesses read (MANDU_CI_WORK, MANDU_VM_CACHE). */
export function scratchRoots(env: Record<string, string | undefined> = process.env, home: string = homedir()): string[] {
  const out = [
    "/tmp", "/var/tmp", "/dev/shm", tmpdir(), env["TMPDIR"],
    env["XDG_CACHE_HOME"] || join(home, ".cache"),
    manduPath("cache-root", env, home),
    env["MANDU_CI_WORK"], env["MANDU_VM_CACHE"],
  ];
  return [...new Set(out.filter((r): r is string => !!r && isAbsolute(r)).map((r) => normalize(r).replace(/(.)\/+$/, "$1")))];
}

/** A scratch path from a guest entry reap may delete: absolute, normalized,
 *  at least two levels deep, not the runtime base, the home dir or an
 *  ancestor of either, and strictly below one of `roots` (`scratchRoots`):
 *  an entry is same-uid data, and a typo'd or forged one must never turn
 *  reap into `rm -rf ~` or `rm -rf ~/Documents`. The removal itself refuses
 *  a link on the way and an entry that is not this user's (safe-remove.ts). */
export function safeScratchPath(p: unknown, base: string, home: string = homedir(), roots: readonly string[] = scratchRoots(process.env, home)): p is string {
  if (typeof p !== "string" || !isAbsolute(p) || normalize(p) !== p || p.endsWith("/")) return false;
  if (p.split("/").filter(Boolean).length < 2) return false;
  for (const keep of [base, home].filter(Boolean)) {
    if (p === keep || keep.startsWith(p + "/")) return false;
  }
  return roots.some((r) => r !== "/" && p.startsWith(`${r}/`));
}

type Liveness = "alive" | "gone" | "unknown";

/** Is the process `pid` still the one that started at `start`? "unknown"
 *  when that cannot be proved (no start time recorded or readable). */
function sameProcess(pid: number, start: number | undefined, bootId: string | undefined, deps: ReapDeps): Liveness {
  const nowBoot = deps.bootId?.() ?? null;
  if (bootId && nowBoot && bootId !== nowBoot) return "gone"; // an earlier boot's pid
  if (!deps.pidAlive(pid)) return "gone";
  // A live pid is only "gone" when its start time PROVES it is another
  // process (a reused pid). Unreadable (a zombie not yet collected, no
  // procStart dep) or nothing recorded to compare: unknown, so nothing is done.
  const now = deps.procStart?.(pid) ?? null;
  if (now === null || typeof start !== "number") return "unknown";
  return now === start ? "alive" : "gone";
}

/** Plan the `vm-guests/` entries (planReap step 1c). */
function planGuests(baseH: DirHandle, base: string, deps: ReapDeps, actions: ReapAction[], notes: string[]): void {
  const root = join(base, "vm-guests");
  const h = openRegistry(baseH, "vm-guests", notes);
  if (h === null) return;
  try {
    planGuestsIn(h, root, base, deps, actions, notes);
  } finally {
    closeDir(h);
  }
}

function planGuestsIn(h: DirHandle, root: string, base: string, deps: ReapDeps, actions: ReapAction[], notes: string[]): void {
  for (const name of listDir(h).sort()) {
    if (!name.endsWith(".json")) continue; // .tmp mid-write files are not entries
    const path = join(root, name);
    const id = name.replace(/\.json$/, "");
    if (!lstatIn(h, name)?.isFile()) {
      notes.push(`vm-guests/${name} skipped: not a regular file`);
      continue;
    }
    const g = guestEntryOf(readJsonIn(h, name));
    if (g === null) {
      // Written tmp+rename: an unparsable .json is garbage, and names no dir.
      actions.push({ kind: "rm-dead-guest", path, remove: [], detail: `${id}: unreadable entry` });
      continue;
    }
    // Only a guest whose OWNER is gone is ever touched: a running harness
    // tidies its own guest (guest_release), whatever state it is in.
    const owner = g.ownerPid;
    const hasOwner = typeof owner === "number" && owner > 0;
    if (hasOwner && sameProcess(owner, g.ownerStart, g.bootId, deps) !== "gone") continue;

    const guest = sameProcess(g.pid, g.pidStart, g.bootId, deps);
    if (guest === "unknown") continue; // unprovable either way: skip
    const cmd = guest === "alive" ? deps.cmdlineOf(g.pid) ?? "" : "";
    if (guest === "alive" && !QEMU_CMDLINE.test(cmd)) continue; // same start time, not qemu: ambiguous, skip
    if (guest === "alive" && !hasOwner) continue; // ownerless live guest: nobody's garbage

    const remove: string[] = [];
    const refused: string[] = [];
    const want = [...(g.keep === true ? [] : [g.workDir]), ...(Array.isArray(g.alsoRemove) ? g.alsoRemove : [])];
    for (const p of want) {
      if (p === undefined) continue;
      if (safeScratchPath(p, base)) remove.push(p);
      else refused.push(String(p));
    }
    const what = [
      remove.length > 0 ? `remove ${remove.join(", ")}` : null,
      g.keep === true && g.workDir ? `keep ${g.workDir} (--keep)` : null,
      refused.length > 0 ? `refuse to remove ${refused.join(", ")} (not a scratch path)` : null,
    ].filter(Boolean).join("; ");
    const who = `${g.harness ?? "guest"} ${id}`;
    const ownerWord = hasOwner ? `owner ${owner} is gone` : "no owner";
    if (guest === "alive") {
      actions.push({
        kind: "kill-orphan-guest", path, pid: g.pid, pidStart: g.pidStart, remove,
        detail: `${who}: ${ownerWord}; stop qemu pid ${g.pid}${what ? `; ${what}` : ""}`,
      });
    } else {
      actions.push({
        kind: "rm-dead-guest", path, pid: g.pid, remove,
        detail: `${who}: ${ownerWord}, guest pid ${g.pid} stopped${what ? `; ${what}` : ""}`,
      });
    }
  }
}

/** Stop a registered orphan guest: SIGTERM (qemu shuts down on it), then
 *  SIGKILL after 5 s; every signal is preceded by the identity re-check, so a
 *  pid reused between plan and execute is never signalled. Throws when the
 *  guest outlives SIGKILL (its entry and dir then stay for the next reap). */
async function stopGuest(action: ReapAction, deps: ReapDeps): Promise<void> {
  const pid = action.pid!;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const same = (): boolean => {
    const s = deps.procStart?.(pid) ?? null;
    return deps.pidAlive(pid) && s !== null && s === action.pidStart && QEMU_CMDLINE.test(deps.cmdlineOf(pid) ?? "");
  };
  const waitGone = async (ms: number): Promise<boolean> => {
    for (let t = 0; t < ms; t += 100) {
      if (!same()) return true;
      await sleep(100);
    }
    return !same();
  };
  if (!same()) return;
  deps.kill(pid, "SIGTERM");
  if (await waitGone(5000)) return;
  if (!same()) return;
  deps.kill(pid, "SIGKILL");
  if (!(await waitGone(2000))) throw new Error(`qemu pid ${pid} survived SIGKILL; entry kept`);
}

/** Read the pieces of a manifest reap needs; null = missing/corrupt. */
export function readManifestLite(dir: string): ManifestLite | null {
  return manifestOf(readJsonNoFollow(join(dir, "manifest.json"))) as ManifestLite | null;
}

/** Read a flat dashboard entry (`dashboards/<id>.json`); null = corrupt. */
export function readDashManifestLite(path: string): DashManifestLite | null {
  return manifestOf(readJsonNoFollow(path)) as DashManifestLite | null;
}

function manifestOf(m: unknown): { pid: number } | null {
  const x = m as { pid?: unknown } | null;
  return x !== null && typeof x === "object" && typeof x.pid === "number" ? (x as { pid: number }) : null;
}

/** A live pid registered as a dashboard must LOOK like one before reap ever
 *  signals it: the canonical process title (runtime-instances.md §7,
 *  process.title = "mandu-dashboard" rewrites the argv area both /proc cmdline
 *  and darwin's `ps -o args=` read). Deliberately NOT a loose /dashboard/ —
 *  an editor open on dashboard.md must never match. */
const DASHBOARD_CMDLINE = /mandu-dashboard/;

/** The arbiter's canonical title (arbiter/ipc/server-main.ts: process.title =
 *  "mandu-arbiter"), which replaces argv[0] and empties the other arguments:
 *  /proc cmdline reads it followed by NULs, darwin's `ps -ww -o args=` followed
 *  by padding spaces, and processCmdline trims both to exactly this. Anchored
 *  to the start: an editor on arbiter/ipc/server-main.ts, a test runner, or a
 *  `grep mandu-arbiter` never matches (the old /arbiter|server-main/ did). */
const ARBITER_CMDLINE = /^mandu-arbiter(\s|$)/;

/** The manifest's startedAt is written once the socket listens, after module
 *  load, the policy and the symbol DB: the process started up to this long
 *  BEFORE it (generous, for a loaded CI host). */
export const ARBITER_START_BEFORE_MS = 10 * 60_000;
/** …and at most this long AFTER it: `lstart` has one-second resolution
 *  (rounded down) and two clocks were read. A recycled pid started after the
 *  arbiter it replaces had died, so after startedAt by at least its lifetime. */
export const ARBITER_START_AFTER_MS = 5_000;

/** What reap knows about the process behind an instance record's pid. */
export type ArbiterIdentity =
  | { kind: "arbiter"; checked: "title" | "title+start" }
  | { kind: "recycled"; why: string }
  | { kind: "unknown" };

/**
 * Is the live process behind `m.pid` the arbiter this record describes? Only
 * "arbiter" may be signalled. "recycled" (the title is not the arbiter's, or
 * its start time does not fit the record's startedAt) means that arbiter is
 * gone and the pid names another process. "unknown" (no command line could be
 * read) is left alone. A start time that cannot be read, or a record without
 * startedAt, keeps the title-only check: it never widens what is signalled.
 */
export function arbiterIdentity(m: ManifestLite, deps: Pick<ReapDeps, "cmdlineOf" | "startMsOf">): ArbiterIdentity {
  const cmd = deps.cmdlineOf(m.pid);
  if (cmd === null) return { kind: "unknown" };
  if (!ARBITER_CMDLINE.test(cmd)) return { kind: "recycled", why: `pid ${m.pid} is not an arbiter any more` };
  const declared = typeof m.startedAt === "string" ? Date.parse(m.startedAt) : NaN;
  const actual = Number.isFinite(declared) ? deps.startMsOf?.(m.pid) ?? null : null;
  if (actual === null || !Number.isFinite(actual)) return { kind: "arbiter", checked: "title" };
  if (actual > declared + ARBITER_START_AFTER_MS || actual < declared - ARBITER_START_BEFORE_MS) {
    return {
      kind: "recycled",
      why: `pid ${m.pid} is a different arbiter (started ${new Date(actual).toISOString()}; the record says ${m.startedAt})`,
    };
  }
  return { kind: "arbiter", checked: "title+start" };
}

/** Grace for manifest-less instance dirs (mid-creation) — mirror of the
 *  arbiter's sweepDeadInstances grace, but reap runs by hand so use a wider
 *  window before declaring a dir abandoned. */
const MANIFESTLESS_GRACE_MS = 10 * 60_000;

/** The promoted instance id: `current`'s LINK TARGET basename (not liveness). */
function promotedTargetId(base: string): string | null {
  try {
    const link = join(base, "current");
    if (!lstatSync(link).isSymbolicLink()) return null;
    return readlinkSync(link).split("/").filter(Boolean).pop() ?? null;
  } catch {
    return null;
  }
}

/**
 * Compute everything reap WOULD do. Pure given deps (unit-tested), and never
 * through a link (runtime-instances.md §2, "planted paths"; safe-remove.ts):
 * the base and each registry directory are opened as real directories of
 * this user's and walked through their descriptors; an entry that is a link
 * (or not the kind its registry holds) is skipped, never followed, and
 * `notes` says so. A base that cannot be opened that way plans nothing.
 */
export async function planReap(base: string, deps: ReapDeps, notes: string[] = []): Promise<ReapAction[]> {
  let baseH: DirHandle;
  try {
    baseH = openDir(normalize(base));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") notes.push(`${base} not walked: ${(e as Error).message}`);
    return [];
  }
  try {
    return await planReapIn(baseH, normalize(base), deps, notes);
  } finally {
    closeDir(baseH);
  }
}

async function planReapIn(baseH: DirHandle, base: string, deps: ReapDeps, notes: string[]): Promise<ReapAction[]> {
  const actions: ReapAction[] = [];
  const promotedId = promotedTargetId(base);

  // 1. Instance dirs.
  const instRoot = join(base, "instances");
  const instH = openRegistry(baseH, "instances", notes);
  const ids = instH === null ? [] : listDir(instH);
  for (const id of ids) {
    const dir = join(instRoot, id);
    const st = lstatIn(instH!, id);
    if (st === null) continue;
    if (!st.isDirectory()) {
      notes.push(`instances/${id} skipped: ${st.isSymbolicLink() ? "a symbolic link" : "not a directory"}`);
      continue;
    }
    let m: ManifestLite | null = null;
    try {
      const h = openDirIn(instH!, id);
      try { m = manifestOf(readJsonIn(h, "manifest.json")) as ManifestLite | null; } finally { closeDir(h); }
    } catch (e) {
      notes.push(`instances/${id} skipped: ${(e as Error).message}`);
      continue;
    }
    if (m === null) {
      const age = deps.now() - st.mtimeMs;
      if (age >= MANIFESTLESS_GRACE_MS) {
        actions.push({ kind: "rm-dead-instance", path: dir, detail: `${id}: manifest-less and abandoned` });
      }
      continue;
    }
    if (!deps.pidAlive(m.pid)) {
      actions.push({ kind: "rm-dead-instance", path: dir, pid: m.pid, detail: `${id}: pid ${m.pid} is dead` });
      continue;
    }
    if (id === promotedId) continue; // the resident rendezvous — never reap
    const owner = m.ownerPid;
    if (typeof owner === "number" && owner > 0 && !deps.pidAlive(owner)) {
      // Kill only what the process CONFIRMS is this record's arbiter — a
      // recycled pid must never be signalled, only its stale record removed.
      const who = arbiterIdentity(m, deps);
      if (who.kind === "arbiter") {
        actions.push({
          kind: "kill-orphan-arbiter", path: dir, pid: m.pid,
          detail: `${id}: owner ${owner} is dead; SIGTERM arbiter pid ${m.pid}`,
        });
      } else if (who.kind === "recycled") {
        actions.push({
          kind: "rm-dead-instance", path: dir, pid: m.pid,
          detail: `${id}: ${who.why} (recycled) — record removed, nothing signalled`,
        });
      }
    }
  }
  if (instH !== null) closeDir(instH);

  // 1b. Dashboard entries (`dashboards/<id>.json` — dashboard/src/registry.ts;
  // flat files, a dashboard owns no socket dir). Same conservatism contract as
  // the instance rules: a dead pid or a recycled pid (cmdline fails the
  // canonical-title check) loses its ENTRY only; a signal is sent solely to a
  // live, title-confirmed dashboard whose owner is dead. SIGTERM → the
  // dashboard's own exit path removes its entry; if it ignores the signal, the
  // entry survives until the pid actually dies (never rm a live pid's entry —
  // that would just make the daemon invisible again, the incident this
  // registry exists to prevent).
  const dashRoot = join(base, "dashboards");
  const dashH = openRegistry(baseH, "dashboards", notes);
  const dashNames = dashH === null ? [] : listDir(dashH);
  for (const name of dashNames) {
    if (!name.endsWith(".json")) continue; // .tmp mid-write files are not entries
    const path = join(dashRoot, name);
    const id = name.replace(/\.json$/, "");
    if (!lstatIn(dashH!, name)?.isFile()) {
      notes.push(`dashboards/${name} skipped: not a regular file`);
      continue;
    }
    const m = manifestOf(readJsonIn(dashH!, name)) as DashManifestLite | null;
    if (m === null) {
      // Atomic tmp+rename means a complete-but-unparsable .json is garbage,
      // not a write in flight (contrast the instance dirs' creation grace).
      actions.push({ kind: "rm-dead-dashboard-entry", path, detail: `${id}: unreadable entry` });
      continue;
    }
    if (!deps.pidAlive(m.pid)) {
      actions.push({ kind: "rm-dead-dashboard-entry", path, pid: m.pid, detail: `${id}: pid ${m.pid} is dead` });
      continue;
    }
    const cmd = deps.cmdlineOf(m.pid) ?? "";
    if (!DASHBOARD_CMDLINE.test(cmd)) {
      actions.push({
        kind: "rm-dead-dashboard-entry", path, pid: m.pid,
        detail: `${id}: pid ${m.pid} is not a dashboard any more (recycled) — entry removed, nothing signalled`,
      });
      continue;
    }
    const owner = m.ownerPid;
    if (typeof owner === "number" && owner > 0 && !deps.pidAlive(owner)) {
      actions.push({
        kind: "kill-orphan-dashboard", path, pid: m.pid,
        detail: `${id}: owner ${owner} is dead; SIGTERM dashboard pid ${m.pid}` +
          (typeof m.port === "number" ? ` (port ${m.port})` : ""),
      });
    }
  }
  if (dashH !== null) closeDir(dashH);

  // 1c. qemu guests of the VM test harnesses (`vm-guests/<id>.json` —
  // scripts/lib/guest-registry.sh). Nothing is touched while the owner
  // harness lives (same pid AND start time); once it is gone, a guest whose
  // pid, start time and qemu cmdline all still match is stopped, one that is
  // gone (or whose pid was reused) loses its entry only, and either way its
  // scratch dir goes. An unregistered qemu is never seen here at all.
  planGuests(baseH, base, deps, actions, notes);

  // 2. Dangling `current` (existsSync follows the link; false = dangling).
  const link = join(base, "current");
  if (lstatIn(baseH, "current")?.isSymbolicLink() && !existsSync(link)) {
    actions.push({ kind: "rm-dangling-current", path: link, detail: "current → swept instance" });
  }

  // 3. Scope-run dirs `<epochSec>-<pid>` with a dead pid: real directories
  // only (a link there is not a scope dir, and is never followed).
  for (const name of listDir(baseH)) {
    const m = name.match(/^\d+-(\d+)$/);
    if (!m) continue;
    const pid = Number(m[1]);
    if (!deps.pidAlive(pid)) {
      const st = lstatIn(baseH, name);
      if (st === null) continue;
      if (!st.isDirectory()) {
        notes.push(`${name} skipped: ${st.isSymbolicLink() ? "a symbolic link" : "not a directory"}`);
        continue;
      }
      actions.push({
        kind: "rm-stale-scope-dir", path: join(base, name), pid,
        detail: `scope ${name}: launcher pid ${pid} is dead`,
      });
    }
  }

  // 4. A dead legacy fixed-path socket file (would win resolution + break launches).
  const legacy = join(base, "arbiter.sock");
  const legacySt = lstatIn(baseH, "arbiter.sock");
  if ((legacySt?.isSocket() || legacySt?.isFile()) && !(await deps.socketLive(legacy))) {
    actions.push({ kind: "rm-dead-legacy-sock", path: legacy, detail: "legacy socket file, nothing listening" });
  }

  return actions;
}

/**
 * Remove the entry `path` names under the runtime base `base`, re-checked
 * now (the plan is not trusted to still hold): the base and every directory
 * on the way are opened as real directories of this user's, and the entry
 * must be this user's and of `kind` (safe-remove.ts). A link swapped in
 * since the plan refuses the removal; nothing is followed. A path outside
 * the base is refused.
 */
function removeUnderBase(base: string, path: string, kind: EntryKind | readonly EntryKind[]): void {
  const rel = relative(normalize(base), path);
  const parts = rel.split("/");
  if (rel === "" || isAbsolute(rel) || parts.some((p) => p === "" || p === "." || p === "..")) throw new Error(`${path} is not under ${base}`);
  const opened: DirHandle[] = [openDir(normalize(base))];
  try {
    for (const p of parts.slice(0, -1)) opened.push(openDirIn(opened[opened.length - 1]!, p));
    removeIn(opened[opened.length - 1]!, parts[parts.length - 1]!, { kind });
  } finally {
    for (const h of opened) closeDir(h);
  }
}

/** Execute one action (split from planning so --dry-run is exact), never
 *  through a link: every removal is re-checked at this moment
 *  (`removeUnderBase`, safe-remove.ts `removePath`). */
export async function executeReapAction(action: ReapAction, base: string, deps: ReapDeps): Promise<void> {
  switch (action.kind) {
    case "kill-orphan-guest":
    case "rm-dead-guest":
      // The guest first (a live one is stopped; stopGuest throws if it
      // survives, keeping entry and dir), then its scratch, then the entry.
      // A scratch path already gone is fine; one refused (a link on the
      // way, not this user's) fails the action and keeps the entry.
      if (action.kind === "kill-orphan-guest") await stopGuest(action, deps);
      for (const p of action.remove ?? []) {
        try {
          removePath(p, { kind: "any" });
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
        }
      }
      removeUnderBase(base, action.path, "file");
      break;
    case "kill-orphan-arbiter":
    case "kill-orphan-dashboard":
      // SIGTERM → the daemon's graceful shutdown removes its own dir/entry;
      // if it ignores the signal, the NEXT reap sees a dead owner again (and
      // its record survives until the pid actually dies — never rm a live pid's).
      deps.kill(action.pid!, "SIGTERM");
      break;
    case "rm-dangling-current":
      removeUnderBase(base, action.path, "link");
      break;
    case "rm-dead-legacy-sock":
      removeUnderBase(base, action.path, ["socket", "file"]);
      break;
    case "rm-dead-dashboard-entry":
      removeUnderBase(base, action.path, "file");
      break;
    case "rm-dead-instance":
    case "rm-stale-scope-dir":
      removeUnderBase(base, action.path, "dir");
      break;
  }
}

/** `mandu reap [--dry-run]` — plan, print, (maybe) execute. */
export async function runReap(rest: string[], env: Env, deps: ReapDeps = realReapDeps): Promise<number> {
  const dry = rest.includes("--dry-run") || rest.includes("-n");
  const otherStacks = rest.includes("--other-stacks");
  const base = runtimeBase(env);
  const notes: string[] = [];
  const actions = await planReap(base, deps, notes);
  // Daemons of other stacks whose code folder is gone and that nobody owns
  // or uses (abandoned-stacks.ts, runtime-instances.md §10.5): listed by a
  // dry run, stopped only when asked (`--other-stacks`), since they are not
  // this stack's registry's to judge.
  const abandoned = deps.abandoned ? findAbandonedDaemons(base, deps.abandoned) : [];
  let abandonedFailed = 0;
  for (const d of abandoned) {
    const what = `pid ${d.pid} ${d.title} of the stack at ${d.stack}: its code folder ${d.cwd} is gone, nobody owns it and no mandu session uses it`;
    if (dry) {
      process.stdout.write(`  would stop (with --other-stacks) ${what}\n`);
    } else if (otherStacks) {
      if (!stillAbandoned(d, deps.procFacts ?? procFactsOf)) {
        process.stdout.write(`  (skipped) ${what} — it changed since (its pid was reused, or its folder is back)\n`);
        continue;
      }
      try {
        deps.kill(d.pid, "SIGTERM");
        process.stdout.write(`  stopped ${what}\n`);
      } catch (e) {
        abandonedFailed++;
        process.stdout.write(`  (failed) stop ${what} — ${(e as Error).message}\n`);
      }
    }
  }
  if (abandoned.length > 0 && !dry && !otherStacks) {
    process.stdout.write(
      `  ${abandoned.length} daemon${abandoned.length === 1 ? "" : "s"} of other stacks ${abandoned.length === 1 ? "is" : "are"} abandoned ` +
        "(their code folder is gone): `mandu reap --dry-run` lists them, `mandu reap --other-stacks` stops them\n",
    );
  }
  // A session that died with a protected file's twin stat in a git index
  // (twin-index-stat.ts, confidentiality.md §7.2a): put back, so git outside
  // stops showing the file modified. Only a record whose launcher is gone.
  if (!dry && process.platform === "linux") {
    const home = homedir();
    for (const root of restorePendingFromStores(twinIndexReadStores(env, home))) {
      process.stdout.write(`  restored the index stat of a protected file in ${root} (a session that ended without it)\n`);
    }
  }
  // What reap would not walk or touch (a link, a stranger's entry): said,
  // never followed (runtime-instances.md §2, "planted paths").
  for (const n of notes) process.stdout.write(`  refused: ${n}\n`);
  if (actions.length === 0) {
    process.stdout.write(`nothing to reap under ${base}\n`);
    return abandonedFailed === 0 ? 0 : 1;
  }
  let failed = 0;
  for (const a of actions) {
    // A session whose launcher died (a signal it does not catch, a crash)
    // never said which protected files its agent changed: the changes are in
    // the placeholder copies this removal discards. Say it first, by path
    // only (twin-writes.ts; confidentiality-plan-10-flow-taint.md §4.1).
    if (a.kind === "rm-stale-scope-dir") {
      const scope = basename(a.path);
      for (const line of reapDiscardedWriteNotice(scope, staleScopeDiscardedWrites(normalize(base), scope))) process.stdout.write(`${line}\n`);
    }
    if (dry) {
      process.stdout.write(`  would ${a.kind}: ${a.detail}\n`);
      continue;
    }
    try {
      await executeReapAction(a, base, deps);
      process.stdout.write(`  ${a.kind}: ${a.detail}\n`);
    } catch (e) {
      failed++;
      process.stdout.write(`  (failed) ${a.kind}: ${a.detail} — ${(e as Error).message}\n`);
    }
  }
  process.stdout.write(
    dry
      ? `dry-run: ${actions.length} action(s) planned under ${base}\n`
      : `reaped ${actions.length - failed}/${actions.length} action(s) under ${base}\n`,
  );
  return failed === 0 && abandonedFailed === 0 ? 0 : 1;
}

/** The names in `dir` when it is a real directory (lstat: not a link);
 *  throws otherwise. `mandu status` lists a registry only then. */
function listRealDir(dir: string): string[] {
  if (!lstatSync(dir).isDirectory()) throw new Error(`${dir} is not a real directory`);
  return readdirSync(dir);
}

/** Registry listing for `mandu status`: one line per registered instance. */
export function listInstances(env: Env, deps: ReapDeps = realReapDeps): string[] {
  const base = runtimeBase(env);
  const promotedId = promotedTargetId(base);
  let ids: string[] = [];
  try { ids = listRealDir(join(base, "instances")); } catch { return []; }
  const lines: string[] = [];
  for (const id of ids.sort()) {
    const m = readManifestLite(join(base, "instances", id));
    if (!m) {
      lines.push(`  ${id}  (no manifest)`);
      continue;
    }
    const alive = deps.pidAlive(m.pid);
    const promoted = id === promotedId;
    // Worded as what `mandu reap` does with it (planReap's rules): a dead
    // pid loses its record; a live one whose owner exited is stopped, unless
    // it is the promoted (resident) arbiter.
    const owner =
      typeof m.ownerPid === "number" && m.ownerPid > 0
        ? `owner ${m.ownerPid}${deps.pidAlive(m.ownerPid) ? "" : promoted || !alive ? " (exited)" : " (exited; `mandu reap` stops it)"}`
        : "no owner (resident)";
    const tags = [
      m.mode ?? "instance",
      promoted ? "PROMOTED" : null,
      alive ? null : "not running; `mandu reap` removes the record",
    ].filter(Boolean).join(", ");
    lines.push(`  ${id}  [${tags}] ${owner}`);
  }
  return lines;
}

/** Registry listing for `mandu status`: one line per registered dashboard
 *  (dashboard/src/registry.ts entries — id encodes start time + git rev; the
 *  manifest carries the bound port, so a forgotten dashboard is FINDABLE, not
 *  just known to exist). */
export function listDashboards(env: Env, deps: ReapDeps = realReapDeps): string[] {
  const base = runtimeBase(env);
  let names: string[] = [];
  try { names = listRealDir(join(base, "dashboards")); } catch { return []; }
  const lines: string[] = [];
  for (const name of names.filter((n) => n.endsWith(".json")).sort()) {
    const id = name.replace(/\.json$/, "");
    const m = readDashManifestLite(join(base, "dashboards", name));
    if (!m) {
      lines.push(`  ${id}  (unreadable entry)`);
      continue;
    }
    const alive = deps.pidAlive(m.pid);
    const owner =
      typeof m.ownerPid === "number" && m.ownerPid > 0
        ? `owner ${m.ownerPid}${deps.pidAlive(m.ownerPid) ? "" : alive ? " (exited; `mandu reap` stops it)" : " (exited)"}`
        : "no owner (resident)";
    const where = typeof m.port === "number" ? `http://${m.host ?? "127.0.0.1"}:${m.port}` : "port unknown";
    lines.push(`  ${id}  [${alive ? "" : "not running; `mandu reap` removes the record, "}${where}] ${owner}`);
  }
  return lines;
}
