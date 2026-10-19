/**
 * cache-seals — seals and epochs for the enforcement caches
 * (confidentiality-plan-14-policy-suggestions.md §11.2).
 *
 * Three caches under the Mandu home decide what the git-object twins strip:
 * the sanitized packs (`cache/object-twins/`), the history walks
 * (`state/object-walks/`) and the history scan
 * (`state/object-walks/history-scan/`). None of them was authenticated: a
 * pack holding the real bytes under a clean `.idx`, a walk entry with a
 * version left out, or a scan entry marking a finding's blob clean was used
 * as if Mandu had written it. In `secrets` mode the agent can neither read
 * nor write the home, so the writer is something unconfined: an `off`
 * session, a `gated` launch, an agent run outside Mandu. This module is the
 * arbiter's half of the answer:
 *
 *   - S1 SEALS. Whoever writes a cache entry (the launcher, the arbiter's own
 *     scan) records `(kind, key, sha256, size)` here, stamped with the
 *     current EPOCH. On use the entry's bytes are hashed and must match a
 *     seal of the current epoch; anything else is rebuilt.
 *   - S2 EPOCHS. A random epoch id, persisted in mandu.db. A new one starts,
 *     and every older seal is deleted, when an UNCONFINED PERIOD ends: an
 *     unconfined launch ends (`endLaunch`, or its launcher's pid is gone),
 *     or the arbiter starts and its last shutdown was not recorded as clean
 *     with no unconfined launch live and the confidentiality axis on. While
 *     an unconfined launch is live, or while this arbiter runs with the
 *     confidentiality axis OFF, no seal is honoured (every entry is rebuilt;
 *     what is recorded meanwhile dies at the rotation that ends the period).
 *   - CLASSIFICATION (fail closed). A launch is confined only when it says it
 *     runs `secrets` or `full`, with the Mandu home write-protected, AND this
 *     arbiter's confidentiality axis is on, at the `confined` posture (Linux:
 *     the guard) or at the `read-blocked` posture (macOS) with `homeSealed`
 *     (the launcher found every part of the home's seal in the one Seatbelt
 *     profile it applied: seatbelt-setup.ts `homeSealed`; it denies every
 *     direct read and write of the home, and leaves the confidentiality.md
 *     §7.3 residual, code a system service runs outside the profile, to S3
 *     below). Anything else, an unknown mode or posture, or `read-blocked`
 *     without the seal, is unconfined.
 *
 * WHO MAY RECORD (the design question of §11.2): the seal and launch ops are
 * HUMAN PLANE (arbiter-human-plane.md), not data plane. On the data socket an
 * agent in `secrets` mode could not write a cache file, but it could still
 * seal one written EARLIER: a file planted during an `off` session survives
 * the rotation that ends the session (rotation voids seals, not files), and
 * the agent that planted it knows its hash. Re-sealing it in the new epoch
 * over the data socket would make the next launch serve it. The human plane
 * is walled off from a confined agent by the same layers that deny it the
 * home, so in a confined period only the launcher and this arbiter record;
 * in an unconfined one anybody may, and the rotation at its end voids it.
 * The arbiter's own history-scan cache uses this store in-process.
 *
 * THE HUMAN PLANE'S EXPOSURE (confidentiality plan 13 D9 leftovers,
 * arbiter-human-plane.md §8). The same launch rows say whether each
 * unconfined launch's agent world is walled off from the human-plane socket
 * (`humanPlaneWalled`: the guard's `unixDeny` or the wrap's tmpfs). While
 * an UNWALLED one is live, its agent's programs reach the human socket, so
 * the server believes no guard or proxy record there
 * (`humanPlaneExposure`). An unwalled launch is also kept in memory, so a
 * program of its agent that deletes the row from mandu.db (nothing hides
 * the home from it) does not end the exposure while this arbiter runs. A
 * launcher that does not say (an older one) counts as unwalled.
 *
 * Each launch may also name its session (the launcher's scope id, display
 * only): the arbiter answers the exposure with it (`humanPlaneStatus`), so a
 * confined launch's launcher, the dashboard and the inspector can name the
 * launch that holds its guard's reports unbelieved
 * (arbiter-human-plane.md §10.1.1). It decides nothing.
 *
 * OUT OF SCOPE (S3): a same-uid process outside Mandu that forges Mandu's
 * own records (this table, the clean-shutdown flag, the launch rows). No
 * file on disk can stop it without root, and such a process can read the
 * secret file directly anyway: the line policy.yaml already draws for an
 * edit made while the arbiter is down (policy-surface.md §8.4.6). An
 * agent process that outlives its launcher is such a process, and so is
 * code a system service runs for a confined agent outside its sandbox (the
 * X11 display on Linux; launchd through a copied `launchctl` or a direct
 * XPC client on macOS): it is not bound to the session, so the rotation at
 * the session's end never voided what it writes.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import Database from "../db/sqlite.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS cache_seals (
  epoch      TEXT NOT NULL,
  kind       TEXT NOT NULL,
  key        TEXT NOT NULL,
  sha256     TEXT NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (epoch, kind, key, sha256, size)
);
CREATE TABLE IF NOT EXISTS cache_seal_state (
  name  TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS unconfined_launches (
  token     TEXT PRIMARY KEY,
  pid       INTEGER NOT NULL,
  pid_start TEXT,
  mode      TEXT NOT NULL,
  posture   TEXT NOT NULL,
  begun_at  INTEGER NOT NULL
);
`;
/** Added 2026-10-02 (plan 13 D9 leftovers): 1 when the launch's agent world
 *  is walled off from the human plane. NULL (an older row) is unwalled. */
const WALLED_COLUMN_SQL = "ALTER TABLE unconfined_launches ADD COLUMN walled INTEGER";
/** Added 2026-10-03 (the exposure made visible, §10.1.1): the launch's
 *  session (scope id), display only. NULL: an older launcher, or none said. */
const SESSION_COLUMN_SQL = "ALTER TABLE unconfined_launches ADD COLUMN session TEXT";
/** Added 2026-10-04 (the voided caches made visible, plan 14 §11.2.1): the
 *  launch's workspace and why it is unconfined, display only. NULL: an older
 *  launcher (workspace) or an older arbiter (why). */
const WORKSPACE_COLUMN_SQL = "ALTER TABLE unconfined_launches ADD COLUMN workspace TEXT";
const WHY_COLUMN_SQL = "ALTER TABLE unconfined_launches ADD COLUMN why TEXT";
/** A session name as the launcher spells a scope id; anything else is not
 *  stored (it is display only, and the human socket may carry a claim). */
const SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** The session a claim names, or null when absent or not of the shape. */
export function claimSession(v: unknown): string | null {
  return typeof v === "string" && SESSION_RE.test(v) ? v : null;
}

/** The workspace a claim names (display only, printed on another launch's
 *  terminal): an absolute path of at most 512 characters with no control
 *  character, else null. */
export function claimWorkspace(v: unknown): string | null {
  // eslint-disable-next-line no-control-regex
  return typeof v === "string" && v.startsWith("/") && v.length <= 512 && !/[\u0000-\u001f\u007f-\u009f]/.test(v) ? v : null;
}

/**
 * Why a launch is unconfined, for the caches' purpose, in a few plain words
 * (the first rule of {@link launchConfinedForCaches} it fails), or null when
 * it is confined. Display only: a launch that finds the caches void names
 * the launch that voids them by it (plan 14 §11.2.1). Pure.
 */
export function unconfinedWhy(claim: Partial<LaunchClaim>, axisOn: boolean): string | null {
  if (!axisOn) return "the protection service runs with secret protection off";
  if (claim.mode === "off") return "protection off";
  if (claim.mode !== "secrets" && claim.mode !== "full") return `mode ${String(claim.mode ?? "unknown").slice(0, 40)}`;
  if (claim.posture === "gated") return "no file guard";
  if (claim.posture !== "confined" && !(claim.posture === "read-blocked" && claim.homeSealed === true)) return `posture ${String(claim.posture ?? "unknown").slice(0, 40)}`;
  if (claim.writeProtect !== true) return "Mandu's home not write-protected";
  return null;
}

/** The kinds the launcher and the arbiter record today. The store accepts
 *  any kind of the {@link KIND_RE} shape, so a new cache (plan 14 §11.1's
 *  registry walks) needs no change here. */
export const CACHE_SEAL_KINDS = {
  /** A sanitized pack's `.pack`, `.idx` or `.rev`; key `<cache key>/<file name>`. */
  objectTwin: "object-twin",
  /** One repository's history-walk entry; key = the file's name without `.json`. */
  historyWalk: "history-walk",
  /** One repository's history-scan entry; key = the file's name without `.json`. */
  historyScan: "history-scan",
  /** One repository's lock resolution (mandu.db `lock_resolutions`, plan 14
   *  §11.1 R2); key = 32 hex of sha256(root). */
  lockResolution: "lock-resolution",
} as const;

const KIND_RE = /^[a-z][a-z0-9-]{0,40}$/;
const KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const SHA_RE = /^[0-9a-f]{64}$/;

/** One seal as recorded and answered. */
export interface CacheSeal {
  kind: string;
  key: string;
  sha256: string;
  size: number;
}

/** An entry a reader did not use, and why (an event names it; no content). */
export interface CacheSealRejection {
  kind: string;
  key: string;
  /** `unsealed`: no seal of the current epoch; `mismatch`: seals exist, none
   *  match the bytes. */
  reason: "unsealed" | "mismatch";
}

/** Why the current epoch began, as a code a launcher can say in plain words
 *  (plan 14 §11.2.1 "The rebuild notice"): `unprotected-ended` an unconfined
 *  launch ended (its `endLaunch`, or its launcher gone); `unclean-stop` the
 *  arbiter's previous run did not record a clean shutdown (a crash, a
 *  SIGKILL, an unconfined period live at it, or an axis-off run);
 *  `first-start` no epoch was recorded yet. Display only: no decision reads
 *  it. */
export type EpochCause = "unprotected-ended" | "unclean-stop" | "first-start";
const EPOCH_CAUSES: readonly string[] = ["unprotected-ended", "unclean-stop", "first-start"];

/** What a reader may trust now. */
export interface CacheSealStatus {
  epoch: string;
  /** false: no seal is honoured now (an unconfined period is live). */
  honoured: boolean;
  reason?: string;
  /** Why the current epoch began ({@link EpochCause}), when honoured and
   *  recorded (absent for an epoch an older arbiter started). Display only:
   *  a launch that finds a cache entry with no seal of this epoch says why
   *  it rebuilds (plan 14 §11.2.1). */
  epochCause?: EpochCause;
  /** The unconfined launches that hold the seals void now, oldest first (at
   *  most 5), when they are the reason: a launch that finds the caches void
   *  names them (plan 14 §11.2.1). Display only. */
  live?: LiveLaunch[];
}

/** A check of one entry's bytes. */
export type CacheSealVerdict = "ok" | "unsealed" | "mismatch" | "not-honoured";

/** What a launch says about itself (`beginLaunch`). */
export interface LaunchClaim {
  pid: number;
  mode: string;
  posture: string;
  /** The Mandu home is write-denied to the agent's tree (write-protect). */
  writeProtect: boolean;
  /** macOS only (posture `read-blocked`): the one whole-agent Seatbelt
   *  profile the launch applied denies every direct read and write of the
   *  Mandu home to everything that runs under it (every home a launch hides,
   *  no carve-out reaching an enforcement store), write-protects it, walls
   *  off the human plane, and has the Unix-socket list and the six-program
   *  host-service deny on (launcher seatbelt-setup.ts `homeSealed`). Sent
   *  only when all of that holds; the Linux launch never sends it. It does
   *  NOT cover code a system service runs for the agent outside the profile
   *  (confidentiality.md §7.3: a copied `launchctl`, a direct XPC client):
   *  that is S3's same-uid process outside Mandu, accepted on macOS as the
   *  Linux classification accepts its own such channels (plan 14 §11.2
   *  "Residuals" (e), §12). */
  homeSealed?: boolean;
  /** The agent's world cannot reach the human-plane socket (the guard's
   *  `unixDeny`, or the wrap's tmpfs over the directory). Absent (an older
   *  launcher) counts as false. */
  humanPlaneWalled?: boolean;
  /** The launch's session (the launcher's scope id), display only. */
  sessionId?: string;
  /** The launch's workspace (its working directory), display only. */
  workspace?: string;
}

/** Another unconfined launch live when one begins (`beginLaunch`'s `others`). */
export interface LiveLaunch {
  pid: number;
  mode: string;
  posture: string;
  /** Its agent world is walled off from the human plane. */
  walled: boolean;
  /** Its session, when its launcher named one (display only). */
  session?: string;
  /** When it began (ms since the epoch). */
  begunAt?: number;
  /** Its workspace, when its launcher named one (display only). */
  workspace?: string;
  /** Why it is unconfined ({@link unconfinedWhy}), when this arbiter recorded it. */
  why?: string;
}

/** Is this launch confined, for the caches' purpose? Pure. Fail closed:
 *  anything not exactly a `secrets`/`full` launch with the home
 *  write-protected, under an arbiter whose confidentiality axis is on, at
 *  the `confined` posture, or at the `read-blocked` posture with the home
 *  sealed (`homeSealed`, macOS). `homeSealed` is read only beside
 *  `read-blocked`: it neither adds to nor takes from any other posture. */
export function launchConfinedForCaches(claim: Partial<LaunchClaim>, axisOn: boolean): boolean {
  return axisOn
    && (claim.mode === "secrets" || claim.mode === "full")
    && claim.writeProtect === true
    && (claim.posture === "confined" || (claim.posture === "read-blocked" && claim.homeSealed === true));
}

/** The environment a `ps` read of a start time runs under: the C locale (a
 *  fixed `lstart` shape) and UTC (`lstart` is rendered in the local zone, so
 *  a zone change would rewrite the token). Mirror of launcher
 *  src/platform/proc-tree.ts `PS_ENV` (each package stays standalone). */
export const PS_ENV: Readonly<Record<string, string>> = { LC_ALL: "C", TZ: "UTC0", PATH: "/usr/bin:/bin" };

/** Where a process's start time is read from — injectable for tests. */
export interface ProcStartSource {
  platform: NodeJS.Platform;
  /** Raw `/proc/<pid>/stat`; throws when unreadable. */
  readProcStat(pid: number): string;
  /** `/bin/ps -o lstart= -p <pid>` under {@link PS_ENV}; throws when ps
   *  fails (no such pid: exit 1) or hangs. */
  psLstart(pid: number): string;
}

export const realProcStartSource: ProcStartSource = {
  platform: process.platform,
  readProcStat: (pid) => readFileSync(`/proc/${pid}/stat`, "utf8"),
  psLstart: (pid) =>
    execFileSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8",
      env: { ...PS_ENV },
      // ps answers in a few ms; a hung one must not stall an answer.
      timeout: 2_000,
      stdio: ["ignore", "pipe", "ignore"],
    }),
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** `ps -o lstart=` under the C locale and UTC (`Wed Sep 30 20:01:39 2026`,
 *  the day space-padded) → epoch ms; null when it is not that shape. Pure.
 *  Mirror of launcher src/reap.ts `parseLstartUtc`. */
export function parseLstartUtc(text: string): number | null {
  const m = /^\s*[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})\s*$/.exec(text);
  if (!m) return null;
  const month = MONTHS.indexOf(m[1]!);
  if (month < 0) return null;
  return Date.UTC(Number(m[6]), month, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
}

/** When `pid` started, as an opaque token compared for equality, or null
 *  where it cannot be read. Guards a liveness check against pid reuse.
 *  Linux (and any host but darwin): the field-22 start time from /proc
 *  (clock ticks since boot). darwin has no /proc: `ps -o lstart=` under the
 *  C locale and UTC, as epoch ms (one-second resolution; the rung the
 *  launcher's reap uses there, reap.ts `processStartMs`; like the DB-owner
 *  check's `ps -o args=`, /bin/ps by path). Without it darwin answered
 *  null, and a launcher pid reused by another process kept an ended
 *  unconfined period open (seals void, never a wrong answer). One read
 *  spawns ps: the store memoizes it for a liveness check
 *  ({@link DARWIN_START_MEMO_MS}). */
export function procStartTime(pid: number, src: ProcStartSource = realProcStartSource): string | null {
  if (src.platform === "darwin") {
    if (!Number.isSafeInteger(pid) || pid <= 0) return null;
    try {
      const ms = parseLstartUtc(src.psLstart(pid));
      return ms === null ? null : String(ms);
    } catch {
      return null;
    }
  }
  try {
    const stat = src.readProcStat(pid);
    // The command name (field 2) is parenthesized and may hold spaces.
    const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    const start = rest[19];
    return start !== undefined && /^\d+$/.test(start) ? start : null;
  } catch {
    return null;
  }
}

/** Does `pid` exist (a signal 0 reaches it or is refused for permission)? */
export function pidExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** A launcher whose pid this arbiter cannot see (another pid namespace)
 *  counts as live until its `endLaunch`, at most this long. */
export const INVISIBLE_LAUNCH_MAX_MS = 24 * 3600_000;
/** darwin: how long a liveness check reuses a launcher's start token (one
 *  `ps` spawn, synchronous, up to its 2 s timeout, in the arbiter's event
 *  loop). Every answer reaps first, and the history-scan gate checks once
 *  per cache file, so without it each check of a live unconfined launch
 *  spawned `ps`. A memoized token is always a real earlier read of that
 *  pid, so it can only make a check see the pid as it was up to this long
 *  ago: an ended launcher whose pid was just reused counts as live a little
 *  longer (seals void a little longer, never honoured wrongly).
 *  `beginLaunch` never uses the memo: the token it records is read fresh.
 *  Linux reads /proc every time (no memo). */
export const DARWIN_START_MEMO_MS = 1_000;
/** Pids whose start token the memo keeps (past it, the oldest go). */
const START_MEMO_MAX = 256;
/** Seals kept per epoch; past it the oldest tenth goes (a rebuild, never a
 *  wrong answer). */
export const MAX_SEALS_PER_EPOCH = 100_000;
/** Entries one `record` call may carry. */
export const MAX_SEALS_PER_CALL = 10_000;

export interface CacheSealStoreOptions {
  /** mandu.db (default: the path table's `symbol-db`). */
  dbPath?: string;
  /** This arbiter's confidentiality axis: OFF makes its whole run an
   *  unconfined period. */
  confidentiality: boolean;
  now?: () => number;
  newEpoch?: () => string;
  newToken?: () => string;
  /** Liveness seams (tests). `procStartTime` replaces the start-time read
   *  whole; `procStartSource` feeds the real one (`procStartTime` over it). */
  pidExists?: (pid: number) => boolean;
  procStartTime?: (pid: number) => string | null;
  procStartSource?: ProcStartSource;
  /** How long a liveness check reuses a pid's start token (default
   *  {@link DARWIN_START_MEMO_MS} for the darwin source, 0 otherwise and
   *  with an injected `procStartTime`). */
  startMemoMs?: number;
  /** Called after every rotation (the arbiter emits an event). */
  onRotate?: (e: { from: string | null; to: string; reason: string }) => void;
  /** Seals kept per epoch (default {@link MAX_SEALS_PER_EPOCH}). */
  maxSealsPerEpoch?: number;
}

const INVISIBLE = "invisible";

/**
 * The seal table, the epoch and the unconfined launches, in mandu.db (the
 * arbiter is its single writer). Every public method opens the store first
 * (`open` is idempotent), so an in-process server that never listens still
 * gets the start-time rules.
 */
export class CacheSealStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly axisOn: boolean;
  private readonly now: () => number;
  private readonly newEpoch: () => string;
  private readonly newToken: () => string;
  private readonly exists: (pid: number) => boolean;
  private readonly startOf: (pid: number) => string | null;
  private readonly startMemoMs: number;
  /** pid → the last start token read for it, and when (a liveness check's
   *  memo; darwin). */
  private readonly startMemo = new Map<number, { at: number; start: string | null }>();
  private readonly onRotate?: CacheSealStoreOptions["onRotate"];
  private readonly maxSeals: number;
  private opened = false;
  private closed = false;
  /** The unwalled launches, by token, also held in memory (see the header). */
  private readonly unwalled = new Map<string, { pid: number; start: string | null; begunAt: number; mode: string; posture: string; session: string | null; workspace: string | null; why: string }>();

  constructor(opts: CacheSealStoreOptions) {
    const dbPath = opts.dbPath ?? getSymbolDbPath();
    const dir = dirname(dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    const cols = this.db.prepare("PRAGMA table_info(unconfined_launches)").all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === "walled")) this.db.exec(WALLED_COLUMN_SQL);
    if (!cols.some((c) => c.name === "session")) this.db.exec(SESSION_COLUMN_SQL);
    if (!cols.some((c) => c.name === "workspace")) this.db.exec(WORKSPACE_COLUMN_SQL);
    if (!cols.some((c) => c.name === "why")) this.db.exec(WHY_COLUMN_SQL);
    this.axisOn = opts.confidentiality;
    this.now = opts.now ?? Date.now;
    this.newEpoch = opts.newEpoch ?? (() => randomBytes(16).toString("hex"));
    this.newToken = opts.newToken ?? (() => randomBytes(24).toString("hex"));
    this.exists = opts.pidExists ?? pidExists;
    const src = opts.procStartSource ?? realProcStartSource;
    this.startOf = opts.procStartTime ?? ((pid) => procStartTime(pid, src));
    this.startMemoMs = opts.startMemoMs
      ?? (opts.procStartTime === undefined && src.platform === "darwin" ? DARWIN_START_MEMO_MS : 0);
    this.onRotate = opts.onRotate;
    this.maxSeals = opts.maxSealsPerEpoch ?? MAX_SEALS_PER_EPOCH;
  }

  /**
   * The start-time rules (S2): no epoch yet, or a last shutdown not recorded
   * as clean, starts a new epoch; then this run is marked unclean until
   * `markShutdown` says otherwise, and the launches a previous run left live
   * are checked (a gone launcher ends its period). Idempotent.
   */
  open(): void {
    if (this.opened || this.closed) return;
    this.opened = true;
    const epoch = this.getState("epoch");
    if (epoch === null) this.rotate("first start", "first-start");
    else if (this.getState("clean") !== "1") this.rotate("the arbiter's last shutdown was not clean, or an unconfined period was live at it", "unclean-stop");
    this.setState("clean", "0");
    this.reap();
  }

  /** The current epoch id. */
  epoch(): string {
    this.open();
    return this.getState("epoch") ?? this.rotate("no epoch", "first-start");
  }

  /** Whether seals are honoured now, and the epoch. Reaps ended launches
   *  first, so a launch whose launcher is gone rotates before any answer. */
  status(): CacheSealStatus {
    this.open();
    this.reap();
    const epoch = this.epoch();
    if (!this.axisOn) return { epoch, honoured: false, reason: "the confidentiality axis is off: this arbiter's whole run is an unconfined period" };
    const live = this.liveCount();
    if (live > 0) return { epoch, honoured: false, reason: `${live} unconfined launch${live === 1 ? " is" : "es are"} live`, live: this.liveNamed().slice(0, 5) };
    const cause = this.getState("rotation_cause");
    return { epoch, honoured: true, ...(cause !== null && EPOCH_CAUSES.includes(cause) ? { epochCause: cause as EpochCause } : {}) };
  }

  /** The current epoch's seals for `keys` of `kind` (none while not
   *  honoured). Throws on a malformed request. */
  seals(kind: string, keys: readonly string[]): CacheSealStatus & { seals: Array<{ key: string; sha256: string; size: number }> } {
    if (!KIND_RE.test(kind)) throw new Error(`cacheSeals: kind must match ${KIND_RE}`);
    if (!Array.isArray(keys) || keys.length > MAX_SEALS_PER_CALL || !keys.every((k) => typeof k === "string" && KEY_RE.test(k))) {
      throw new Error(`cacheSeals: keys must be at most ${MAX_SEALS_PER_CALL} strings matching ${KEY_RE}`);
    }
    const st = this.status();
    if (!st.honoured || keys.length === 0) return { ...st, seals: [] };
    const want = new Set(keys);
    const rows = this.db.prepare("SELECT key, sha256, size FROM cache_seals WHERE epoch = ? AND kind = ?")
      .all(st.epoch, kind) as Array<{ key: string; sha256: string; size: number }>;
    return { ...st, seals: rows.filter((r) => want.has(r.key)).map((r) => ({ key: r.key, sha256: r.sha256, size: Number(r.size) })) };
  }

  /** Record seals in the current epoch (add-only; an existing one is
   *  refreshed so a used entry is not pruned). Throws on a malformed entry. */
  record(entries: readonly CacheSeal[]): { epoch: string; recorded: number } {
    if (!Array.isArray(entries) || entries.length > MAX_SEALS_PER_CALL) throw new Error(`sealCacheEntries: at most ${MAX_SEALS_PER_CALL} entries`);
    for (const e of entries) {
      if (e === null || typeof e !== "object" || typeof e.kind !== "string" || !KIND_RE.test(e.kind) || typeof e.key !== "string" || !KEY_RE.test(e.key)
        || typeof e.sha256 !== "string" || !SHA_RE.test(e.sha256) || !Number.isSafeInteger(e.size) || e.size < 0) {
        throw new Error("sealCacheEntries: every entry is {kind, key, sha256 (64 lowercase hex), size (a non-negative integer)}");
      }
    }
    const epoch = this.epoch();
    const now = this.now();
    const ins = this.db.prepare(
      "INSERT INTO cache_seals (epoch, kind, key, sha256, size, created_at) VALUES (?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT(epoch, kind, key, sha256, size) DO UPDATE SET created_at = excluded.created_at",
    );
    for (const e of entries) ins.run(epoch, e.kind, e.key, e.sha256, e.size, now);
    this.prune(epoch);
    return { epoch, recorded: entries.length };
  }

  /** Check `bytes` read from a cache entry against the current epoch. */
  check(kind: string, key: string, bytes: Buffer): CacheSealVerdict {
    const got = this.seals(kind, [key]);
    if (!got.honoured) return "not-honoured";
    if (got.seals.length === 0) return "unsealed";
    const sha = sha256Hex(bytes);
    return got.seals.some((s) => s.sha256 === sha && s.size === bytes.length) ? "ok" : "mismatch";
  }

  /** Seal `bytes` just written to a cache entry. Never throws. */
  sealBytes(kind: string, key: string, bytes: Buffer): boolean {
    try {
      this.record([{ kind, key, sha256: sha256Hex(bytes), size: bytes.length }]);
      return true;
    } catch {
      return false;
    }
  }

  /** A launch starts (before its agent does). Confined launches are not
   *  stored; an unconfined one is live until `endLaunch` with its token or
   *  until its launcher's pid is gone. */
  beginLaunch(claim: Partial<LaunchClaim>): { token: string; confined: boolean; epoch: string; others: LiveLaunch[] } {
    this.open();
    const pid = claim.pid;
    if (!Number.isSafeInteger(pid) || (pid as number) <= 0) throw new Error("beginLaunch: pid must be a positive integer");
    // The launches live before this one (reaped first): a confined launch
    // warns of them (a concurrent unconfined launch is plan 14 §11.2's
    // residual (a)).
    this.reap();
    const others = this.liveLaunchRows();
    const token = this.newToken();
    const confined = launchConfinedForCaches(claim, this.axisOn);
    if (!confined) {
      const visible = this.exists(pid as number);
      // Read fresh, never from the memo: a token memoized for an earlier
      // process on this pid, recorded here, would end this live launch's
      // period at the next fresh check (seals honoured while it runs).
      const start = visible ? this.freshStart(pid as number) : INVISIBLE;
      const walled = claim.humanPlaneWalled === true;
      const mode = String(claim.mode ?? "unknown").slice(0, 40);
      const posture = String(claim.posture ?? "unknown").slice(0, 40);
      const begunAt = this.now();
      const session = claimSession(claim.sessionId);
      const workspace = claimWorkspace(claim.workspace);
      const why = unconfinedWhy(claim, this.axisOn) ?? "unknown";
      this.db.prepare("INSERT INTO unconfined_launches (token, pid, pid_start, mode, posture, begun_at, walled, session, workspace, why) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(token, pid as number, start, mode, posture, begunAt, walled ? 1 : 0, session, workspace, why);
      if (!walled) this.unwalled.set(token, { pid: pid as number, start, begunAt, mode, posture, session, workspace, why });
    }
    return { token, confined, epoch: this.epoch(), others };
  }

  /**
   * The unwalled launches live now: while any is, its agent's programs reach
   * the human-plane socket, and the server believes no guard or proxy record
   * there (plan 13 D9 leftovers). The rows and the in-memory copy both
   * count; a launch whose launcher is gone is reaped first.
   */
  humanPlaneExposure(): LiveLaunch[] {
    this.open();
    this.reap();
    const out = new Map<string, LiveLaunch>();
    for (const r of this.db.prepare("SELECT token, pid, mode, posture, session, begun_at FROM unconfined_launches WHERE walled IS NULL OR walled = 0").all() as Array<{ token: string; pid: number; mode: string; posture: string; session: string | null; begun_at: number }>) {
      out.set(r.token, liveLaunch(Number(r.pid), r.mode, r.posture, false, claimSession(r.session), Number(r.begun_at)));
    }
    // The in-memory copy wins: a row a program rewrote does not rename it.
    for (const [token, l] of this.unwalled) out.set(token, liveLaunch(l.pid, l.mode, l.posture, false, l.session, l.begunAt));
    return [...out.values()].sort((a, b) => (a.begunAt ?? 0) - (b.begunAt ?? 0) || a.pid - b.pid);
  }

  /** A launch ended. An unconfined one's end starts a new epoch. An unknown
   *  token (a confined launch, or one already reaped) changes nothing. */
  endLaunch(token: string): { ended: boolean; rotated: boolean; epoch: string } {
    this.open();
    if (typeof token !== "string" || token === "") throw new Error("endLaunch: token must be a non-empty string");
    const r = this.db.prepare("DELETE FROM unconfined_launches WHERE token = ?").run(token);
    const inMemory = this.unwalled.delete(token);
    if (r.changes > 0 || inMemory) {
      const epoch = this.rotate("an unconfined launch ended", "unprotected-ended");
      return { ended: true, rotated: true, epoch };
    }
    return { ended: false, rotated: false, epoch: this.epoch() };
  }

  /** Start a new epoch now: every older seal is deleted. Returns it.
   *  `cause`: what a launch may say about it ({@link EpochCause}); none
   *  (a test, a by-hand rotation) is said as an unknown cause. */
  rotate(reason: string, cause?: EpochCause): string {
    const from = this.getState("epoch");
    const to = this.newEpoch();
    this.setState("epoch", to);
    this.setState("epoch_started_at", String(this.now()));
    this.setState("rotation_reason", reason);
    this.setState("rotation_cause", cause ?? "");
    this.db.prepare("DELETE FROM cache_seals WHERE epoch != ?").run(to);
    try { this.onRotate?.({ from, to, reason }); } catch { /* observability only */ }
    return to;
  }

  /** The arbiter stops: the shutdown is clean only with the axis on and no
   *  unconfined launch live. `record` false (an arbiter that never owned the
   *  DB: its start was refused) writes nothing, so it cannot mark the owner's
   *  run clean. Idempotent; the store is closed after. */
  markShutdown(record = true): void {
    if (this.closed) return;
    try {
      if (this.opened && record) {
        this.reap();
        this.setState("clean", this.axisOn && this.liveCount() === 0 ? "1" : "0");
      }
    } finally {
      this.closed = true;
      try { this.db.close(); } catch { /* double-close */ }
    }
  }

  /** The unconfined launches live now (a test and doctor aid). */
  liveLaunches(): Array<{ pid: number; mode: string; posture: string; begunAt: number }> {
    this.open();
    return (this.db.prepare("SELECT pid, mode, posture, begun_at FROM unconfined_launches").all() as Array<{ pid: number; mode: string; posture: string; begun_at: number }>)
      .map((r) => ({ pid: Number(r.pid), mode: r.mode, posture: r.posture, begunAt: Number(r.begun_at) }));
  }

  private liveLaunchRows(): LiveLaunch[] {
    return (this.db.prepare("SELECT pid, mode, posture, walled, session, begun_at, workspace, why FROM unconfined_launches").all() as Array<{ pid: number; mode: string; posture: string; walled: number | null; session: string | null; begun_at: number; workspace: string | null; why: string | null }>)
      .map((r) => liveLaunch(Number(r.pid), r.mode, r.posture, Number(r.walled) === 1, claimSession(r.session), Number(r.begun_at), claimWorkspace(r.workspace), r.why));
  }

  /** Every live unconfined launch, oldest first: the rows, and an unwalled
   *  launch whose row a program deleted (its in-memory copy, which also wins
   *  over a rewritten row, as in {@link humanPlaneExposure}). */
  private liveNamed(): LiveLaunch[] {
    const out = new Map<string, LiveLaunch>();
    const rows = this.db.prepare("SELECT token, pid, mode, posture, walled, session, begun_at, workspace, why FROM unconfined_launches").all() as Array<{
      token: string; pid: number; mode: string; posture: string; walled: number | null; session: string | null; begun_at: number; workspace: string | null; why: string | null;
    }>;
    for (const r of rows) {
      out.set(r.token, liveLaunch(Number(r.pid), r.mode, r.posture, Number(r.walled) === 1, claimSession(r.session), Number(r.begun_at), claimWorkspace(r.workspace), r.why));
    }
    for (const [token, l] of this.unwalled) out.set(token, liveLaunch(l.pid, l.mode, l.posture, false, l.session, l.begunAt, l.workspace, l.why));
    return [...out.values()].sort((a, b) => (a.begunAt ?? 0) - (b.begunAt ?? 0) || a.pid - b.pid);
  }

  /** End every unconfined launch whose launcher is gone; one rotation for
   *  all of them. */
  private reap(): void {
    // The in-memory unwalled launches count too: one whose row was deleted
    // by hand ends here like any other. One rotation for all of them.
    const gone = new Set<string>();
    for (const [token, l] of this.unwalled) {
      if (!this.alive(l.pid, l.start, l.begunAt)) gone.add(token);
    }
    const rows = this.db.prepare("SELECT token, pid, pid_start, begun_at FROM unconfined_launches").all() as Array<{
      token: string; pid: number; pid_start: string | null; begun_at: number;
    }>;
    for (const r of rows) if (!this.alive(Number(r.pid), r.pid_start, Number(r.begun_at))) gone.add(r.token);
    if (gone.size === 0) return;
    const del = this.db.prepare("DELETE FROM unconfined_launches WHERE token = ?");
    for (const t of gone) { del.run(t); this.unwalled.delete(t); }
    this.rotate(`${gone.size} unconfined launch${gone.size === 1 ? "" : "es"} ended (launcher gone)`, "unprotected-ended");
  }


  private alive(pid: number, start: string | null, begunAt: number): boolean {
    if (start === INVISIBLE) return this.now() - begunAt < INVISIBLE_LAUNCH_MAX_MS;
    if (!this.exists(pid)) return false;
    if (start === null) return true;
    const now = this.checkStart(pid);
    return now === null || now === start;
  }

  /** A liveness check's start token: memoized per pid for `startMemoMs`
   *  (darwin: one `ps` spawn per pid per second at most, however many
   *  answers reap). A clock that went back reads fresh. */
  private checkStart(pid: number): string | null {
    if (this.startMemoMs <= 0) return this.startOf(pid);
    const hit = this.startMemo.get(pid);
    const t = this.now();
    if (hit !== undefined && t >= hit.at && t - hit.at < this.startMemoMs) return hit.start;
    return this.freshStart(pid);
  }

  /** Read `pid`'s start token now; with a memo, remember it. */
  private freshStart(pid: number): string | null {
    const start = this.startOf(pid);
    if (this.startMemoMs > 0) {
      this.startMemo.delete(pid);
      this.startMemo.set(pid, { at: this.now(), start });
      while (this.startMemo.size > START_MEMO_MAX) this.startMemo.delete(this.startMemo.keys().next().value!);
    }
    return start;
  }

  private liveCount(): number {
    const tokens = new Set((this.db.prepare("SELECT token FROM unconfined_launches").all() as Array<{ token: string }>).map((r) => r.token));
    for (const t of this.unwalled.keys()) tokens.add(t);
    return tokens.size;
  }

  private prune(epoch: string): void {
    const r = this.db.prepare("SELECT COUNT(*) AS n FROM cache_seals WHERE epoch = ?").get(epoch) as { n: number | bigint };
    const n = Number(r.n);
    if (n <= this.maxSeals) return;
    const drop = n - Math.floor(this.maxSeals * 0.9);
    this.db.prepare(
      "DELETE FROM cache_seals WHERE rowid IN (SELECT rowid FROM cache_seals WHERE epoch = ? ORDER BY created_at ASC LIMIT ?)",
    ).run(epoch, drop);
  }

  private getState(name: string): string | null {
    const r = this.db.prepare("SELECT value FROM cache_seal_state WHERE name = ?").get(name) as { value: string } | undefined;
    return r?.value ?? null;
  }

  private setState(name: string, value: string): void {
    this.db.prepare("INSERT INTO cache_seal_state (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value").run(name, value);
  }
}

/** sha256 of `bytes`, lowercase hex. */
export function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** The narrow surface an arbiter-internal cache uses (the history scan
 *  here; plan 14 §11.1's registry walks). `check` answers `ok` only for
 *  bytes a current-epoch seal vouches for; `seal` records bytes just
 *  written; `rejected` is told of an entry not used (an event, no
 *  content). */
export interface CacheSealGate {
  check(kind: string, key: string, bytes: Buffer): CacheSealVerdict;
  seal(kind: string, key: string, bytes: Buffer): void;
  rejected?(r: CacheSealRejection): void;
}

/** A gate over the store. */
export function sealGate(store: CacheSealStore, onRejected?: (r: CacheSealRejection) => void): CacheSealGate {
  return {
    check: (kind, key, bytes) => {
      try { return store.check(kind, key, bytes); } catch { return "not-honoured"; }
    },
    seal: (kind, key, bytes) => { store.sealBytes(kind, key, bytes); },
    ...(onRejected ? { rejected: onRejected } : {}),
  };
}

/** One live launch as answered; `session`, `workspace` and `why` only when
 *  known (`why` as this arbiter recorded it, at most 80 characters). */
function liveLaunch(
  pid: number, mode: string, posture: string, walled: boolean, session: string | null, begunAt: number,
  workspace: string | null = null, why: string | null = null,
): LiveLaunch {
  return {
    pid, mode, posture, walled, ...(session !== null ? { session } : {}), ...(Number.isFinite(begunAt) ? { begunAt } : {}),
    ...(workspace !== null ? { workspace } : {}), ...(typeof why === "string" && why !== "" ? { why: why.slice(0, 80) } : {}),
  };
}
