/**
 * secret-workspace-scan — S2 of confidentiality plan 14 (§3, §13): find FILES
 * ON DISK that hold a credential the catalog and the labels miss (a token in
 * `deploy/staging.conf`, a key pasted into `notes/deploy.md`). Each finding
 * becomes a `lock-path` suggestion (policy-suggestions.ts
 * `suggestWorkspaceEdits`), reviewed and applied like a history one. This
 * module FINDS; it enforces nothing and writes nothing.
 *
 * WHY THE ARBITER READS THE FILES (the rule of secret-registry.ts,
 * secret-discovery.ts and secret-history-scan.ts): the arbiter runs outside
 * every agent's sandbox and is the one component that may hold secret bytes.
 * A file's bytes live in this process's memory while it is matched and
 * nowhere else. A finding carries the path, the detector's kind, the line
 * and the detector's fixed mask (secret-detectors.ts): never a character of
 * a value's body, its length or a hash of it. The in-memory cache holds the
 * same masked hits, keyed by the file's identity, and is never written to
 * disk (so there is no file to plant and plan 14 §11.2's seals do not
 * apply).
 *
 * TWO TIERS (§13.1), both walked with DISCOVERY'S PRUNES, imported from
 * secret-discovery.ts so the two walks cannot drift: SKIP_DIRS (`.git`
 * included, so history stays S1's job), the agent's own auth
 * (`isAgentAuthPath`), Mandu's home and state (`discoveryPrunes`), Mandu's
 * install trees, and symlinked directories, which are never descended (the
 * walk decides on `lstat`). The kernel's pseudo-filesystems (`/proc`, `/sys`,
 * `/dev`) are pruned too: a root of `/` must not read another process's
 * environment.
 *
 * ON MACOS (2026-09-30), two more prunes, both keyed on the platform
 * (`platform`, default this process's), Linux unchanged:
 *   - HOME's app-data and media folders (`Library`, `.Trash`, `Pictures`,
 *     `Music`, `Movies`, direct children of HOME: discovery's
 *     `homeSkip`, secret-discovery.ts DARWIN_HOME_SKIP). Unlike discovery,
 *     with NO label or catalog re-entry: a file a label or the catalog
 *     already calls a secret is `covered` and never opened wherever it
 *     lies, so pruning its folder loses no key finding (this scan reports
 *     only files nothing protects yet), while walking them can cost TCC
 *     prompts ("access data from other apps") and tens of thousands of
 *     entries. It does lose sensitivity labels (S4) and model candidates
 *     (T1, T2) under `~/Library/CloudStorage` and `~/Library/Mobile
 *     Documents` (OneDrive, Google Drive, iCloud Drive): plan 14 §11.3.
 *   - the mount points a walk from above never enters
 *     (`systemPrunes`): `/System/Volumes` (the firmlinked Data volume, a
 *     second path to `/Users`), `/.vol` (volfs), `/Volumes` (other disks,
 *     TCC-protected), `/net` and `/home` (the automounter). A root inside
 *     `/System/Volumes` or `/.vol` is refused like a pseudo-filesystem; a
 *     root inside the other three is walked when named (a project on an
 *     external disk).
 *
 *   workspace  each root that is neither HOME nor above it; depth 8; every
 *              regular file up to the size cap that is not binary
 *   home       HOME when asked (`includeHome`), and any root equal to HOME
 *              or above it (`/` included); discovery's depth 4; only files
 *              whose NAME hints at configuration or keys (`nameHints`)
 *
 * HOSTILE INPUT (the op is on the data plane: the agent may build the
 * workspace and name the roots):
 *   - a file the catalog or a label already calls a secret is counted
 *     `covered` and NEVER OPENED (it is confined already);
 *   - only regular files are read, decided on `lstat`; a symlinked file is
 *     counted, never followed; the open is `O_NOFOLLOW | O_NONBLOCK |
 *     O_NOCTTY` (a symlink swapped in after the lstat fails the open; a FIFO
 *     swapped in opens without blocking), and `fstat` on the descriptor
 *     checks again that it is a regular file within the caps before a byte
 *     is read; at most cap + 1 bytes are read;
 *   - budgets (per file, in all, files examined, one deadline) with every
 *     cap counted in `capped` and one plain line per cap: nothing is
 *     skipped silently;
 *   - reads are asynchronous and matching yields to the event loop every
 *     SLICE_MS, so a scan does not hold the arbiter's other clients;
 *   - no path is logged or evented by this module; names with control
 *     characters travel only inside JSON strings.
 *
 * S4 IN THE SAME WALK (plan 14 §14.1, §14.9): an Office file (`.docx`,
 * `.xlsx`, `.pptx` and their macro and template forms) is never text-read.
 * With `sensitivityLabels` in mode `mapped` or `count` it is label-read, in
 * both tiers: covered first (never opened), then its own cache, then
 * `readOfficeFileLabels` (the same safe open, then a bounded range read of
 * the zip: sensitivity-labels.ts) under its own budgets. The finding keeps
 * the enabled labels' GUIDs only.
 *
 * THE MODEL'S WALK (plan 14 §14.10, §14.11): `list: true` answers the names
 * of the files examined (never their bytes), each marked `scanned` when the
 * detectors ran over the whole file; `documents` makes the home tier read
 * the contents model's documents too, so the detectors have run over every
 * candidate. `readFileHead` is the contents model's read: the same safe
 * open, at most the first 16 KiB. `readOfficeFileText` is its read of an
 * Office document (§14.13): the same safe open, then office-text.ts over a
 * bounded range reader; the walk itself still never text-reads one.
 *
 * Pure over its seams (the filesystem, the coverage check, the clock, the
 * yield); the name hints and the limits are pure and unit-tested.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { constants, promises as fsp, type BigIntStats } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import { manduPath } from "../src/generated/mandu-paths.js";
import { detectSecretShapes, historyDetectorFingerprint, isBinaryBlob, type ShapeHit } from "./secret-detectors.js";
import { MAX_DEPTH, SKIP_DIRS, discoveryPrunes, isAgentAuthPath, type DiscoveryOptions } from "./secret-discovery.js";
import { HISTORY_ROOTS_MAX, type SecretHistoryDetector } from "./secret-history-scan.js";
import {
  DEFAULT_LABEL_LIMITS, SENSITIVITY_LABEL_READER_VERSION, UNMAPPED_LABELS_MAX, emptyLabelSummary, isOfficeName, readOfficeLabels,
  type LabelScanLimits, type OfficeByteReader, type OfficeLabelRead, type SensitivityLabelFinding, type SensitivityLabelScanSummary,
} from "./sensitivity-labels.js";
import { officeFamily, readOfficeText, type OfficeTextRead } from "./office-text.js";

// ── The findings type (plan 14 §13.3) ────────────────────────────────────────

export type WorkspaceTier = "workspace" | "home";

/** A content hit on a file: the history scan's detector shape, masked. */
export type WorkspaceDetector = Extract<SecretHistoryDetector, { kind: "content-shape" }>;

/** One file whose current content is secret-shaped. No field carries a
 *  value, its length or its hash. */
export interface SecretWorkspaceFinding {
  /** The scan root it was found under. */
  root: string;
  tier: WorkspaceTier;
  /** The nearest work tree above it (a directory with a `.git` entry, found
   *  without running git), up to and including the scan root; else null. */
  repoRoot: string | null;
  /** Absolute. */
  path: string;
  detectors: WorkspaceDetector[];
}

/** What a cap or a failure left unread. Every count is complete. */
export interface SecretWorkspaceCapped {
  /** Files over the per-file cap, not read. */
  tooBig: number;
  /** Files not read: the total byte cap. */
  overTotal: number;
  /** Entries (files, or folders not yet listed in a listed one) not
   *  examined: the deadline. */
  overTime: number;
  /** Files not examined: the file cap. */
  overFiles: number;
  /** Read but skipped as binary (a NUL in the first 8000 bytes). */
  binary: number;
  /** Symbolic links to files, counted and never followed. */
  symlinks: number;
  /** Files or folders that could not be read (permissions, a race). */
  unreadable: number;
  /** A pipe, a socket or a device: never read (as built, §13.3 has no
   *  field for them). */
  special: number;
  /** Folders below the tier's depth, not walked. */
  depth: number;
  /** Folders below a root that are linked work trees (a `.git` FILE naming
   *  `…/worktrees/<name>`): a second checkout of a repository, not walked
   *  (§13.9 "Nested linked work trees"). */
  worktrees: number;
  /** One human line per cap or failure. */
  lines: string[];
}

export interface SecretWorkspaceLimits {
  /** A file larger than this is counted, not read. */
  fileMaxBytes: number;
  /** Bytes read in all. */
  totalMaxBytes: number;
  /** Files examined in all. */
  maxFiles: number;
  /** One deadline for the whole scan. */
  timeoutMs: number;
}

export interface SecretWorkspaceScan {
  /** One per requested root (HOME too when asked): its tier, or why it was
   *  not walked. */
  roots: Array<{ root: string; tier: WorkspaceTier; reason?: string }>;
  counts: {
    /** Candidate files looked at (every file in a workspace root, the
     *  name-hinted ones in a home root). */
    examined: number;
    /** Files whose content was read and matched this call. */
    read: number;
    /** Files answered from the in-memory cache (unchanged since read). */
    cached: number;
    /** Bytes read this call. */
    bytes: number;
    /** Files the catalog or a label already protects: never opened. */
    covered: number;
  };
  capped: SecretWorkspaceCapped;
  findings: SecretWorkspaceFinding[];
  /** S4 (plan 14 §14.1): the labelled Office files (enabled labels only). */
  labelFindings?: SensitivityLabelFinding[];
  /** S4's summary; null when the label read was not asked for. */
  labels?: SensitivityLabelScanSummary | null;
  /** With `list: true`: every regular file examined (covered ones
   *  included), names only, bounded by the file cap. Absent otherwise. */
  listed?: WorkspaceListedFile[];
  limits: SecretWorkspaceLimits;
  ms: number;
}

/** The scan without its findings (and its listing): what `suggestPolicy`
 *  answers. */
export type SecretWorkspaceScanSummary = Omit<SecretWorkspaceScan, "findings" | "labelFindings" | "listed">;

/**
 * One file the walk examined, NAMES ONLY (plan 14 §14.2, the T1 model's
 * view): only with `list: true`, and never answered by `suggestPolicy`. It
 * carries no byte of the file: its path, its size from `lstat`, whether the
 * law already covers it (a covered file is never opened), and the kinds of
 * the detectors that hit it (`github-token`, never a mask or a line).
 */
export interface WorkspaceListedFile {
  root: string;
  tier: WorkspaceTier;
  repoRoot: string | null;
  /** Absolute. */
  path: string;
  /** Bytes, from `lstat`. */
  size: number;
  /** The catalog or a label already protects it (it was not opened). */
  covered: boolean;
  /** The shapes the detectors found in it, sorted, each once. */
  kinds: string[];
  /** The detectors ran over the WHOLE file (read now or from the cache, not
   *  binary). Unset: over the size cap, binary, unreadable, a link, or not
   *  read at all. The contents tier (plan 14 §14.2) reads only such a file. */
  scanned?: true;
}

export const DEFAULT_WORKSPACE_LIMITS: SecretWorkspaceLimits = {
  fileMaxBytes: 256 * 1024,
  totalMaxBytes: 64 * 1024 * 1024,
  maxFiles: 20_000,
  timeoutMs: 30_000,
};

/** MANDU_WORKSPACE_SCAN_FILE_MAX_KB / _MAX_MB / _FILES / _TIMEOUT_S → limits
 *  (unset or invalid: the default). Pure. */
export function workspaceLimitsFromEnv(env: Record<string, string | undefined>): SecretWorkspaceLimits {
  const num = (k: string): number | null => {
    const n = Number(env[k]);
    return Number.isFinite(n) && n > 0 ? n : null;
  };
  const kb = num("MANDU_WORKSPACE_SCAN_FILE_MAX_KB");
  const mb = num("MANDU_WORKSPACE_SCAN_MAX_MB");
  const files = num("MANDU_WORKSPACE_SCAN_FILES");
  const s = num("MANDU_WORKSPACE_SCAN_TIMEOUT_S");
  return {
    ...DEFAULT_WORKSPACE_LIMITS,
    ...(kb !== null ? { fileMaxBytes: Math.floor(kb * 1024) } : {}),
    ...(mb !== null ? { totalMaxBytes: Math.floor(mb * 1024 * 1024) } : {}),
    ...(files !== null ? { maxFiles: Math.floor(files) } : {}),
    ...(s !== null ? { timeoutMs: Math.floor(s * 1000) } : {}),
  };
}

/** The workspace tier's depth (§13.1). */
export const WORKSPACE_MAX_DEPTH = 8;
/** The home tier's depth: discovery's. */
export const HOME_MAX_DEPTH = MAX_DEPTH;
/** Matching yields to the event loop after this much work (S1's). */
const SLICE_MS = 15;
/** The in-memory cache's size. */
export const WORKSPACE_CACHE_MAX = 50_000;

/** The kernel's pseudo-filesystems at their usual mount points: never
 *  walked, so a root of `/` does not read `/proc/<pid>/environ`. */
export const PSEUDO_FS_DIRS: ReadonlySet<string> = new Set(["/proc", "/sys", "/dev"]);

/**
 * macOS (2026-09-30): the mount points no walk enters from above, beside
 * PSEUDO_FS_DIRS (Linux-shaped: on a Mac `/dev` is devfs, and `/proc` and
 * `/sys` do not exist). A root of `/` reached every one of them:
 *
 *   /System/Volumes  the system's volumes: the firmlinked Data volume holds
 *                    `/Users`, `/Applications`, `/Library` and `/private` a
 *                    second time (`/System/Volumes/Data/Users/<you>`), so a
 *                    walk read HOME again under a spelling no HOME prune
 *                    (the agent's auth, Mandu's state, `Library`) matches
 *   /.vol            volfs: files by volume and inode number
 *   /Volumes         every other mounted volume: external and network disks
 *                    and disk images (TCC asks before a "removable" or
 *                    "network volume" is read; a network one can hang)
 *   /net, /home      the automounter (autofs `-hosts`, `auto_home`): listing
 *                    one mounts network file systems
 *
 * A root inside `/System/Volumes` or `/.vol` is refused (`DARWIN_REFUSED_ROOTS`),
 * as a root inside a pseudo-filesystem is: both only reach files under
 * another spelling. A root inside `/Volumes`, `/net` or `/home` is walked
 * when named: a project on an external disk is a workspace.
 */
export const DARWIN_UNWALKED_DIRS: ReadonlySet<string> = new Set(["/System/Volumes", "/.vol", "/Volumes", "/net", "/home"]);

/** macOS: the roots refused, with why (see DARWIN_UNWALKED_DIRS). */
export const DARWIN_REFUSED_ROOTS: ReadonlyMap<string, string> = new Map([
  ["/System/Volumes", "the system's volumes, a second path to this Mac's folders, not scanned"],
  ["/.vol", "a kernel pseudo-filesystem, not scanned"],
]);

/** The system directories a scan on `platform` never walks (`walk`, by
 *  exact path) and those a root inside is refused (`roots`, with why).
 *  Linux (and any host but macOS): the kernel's pseudo-filesystems, as
 *  before; macOS adds DARWIN_UNWALKED_DIRS. Pure. */
export function systemPrunes(platform: NodeJS.Platform = process.platform): {
  walk: ReadonlySet<string>;
  roots: ReadonlyArray<{ dir: string; why: string }>;
} {
  const pseudo = [...PSEUDO_FS_DIRS].map((dir) => ({ dir, why: "a kernel pseudo-filesystem, not scanned" }));
  if (platform !== "darwin") return { walk: PSEUDO_FS_DIRS, roots: pseudo };
  return {
    walk: new Set([...PSEUDO_FS_DIRS, ...DARWIN_UNWALKED_DIRS]),
    roots: [...pseudo, ...[...DARWIN_REFUSED_ROOTS].map(([dir, why]) => ({ dir, why }))],
  };
}

// ── Pure: the home tier's name hints ─────────────────────────────────────────

const HINT_EXT_RE = /\.(pem|key|json|ya?ml|toml|ini|cfg|conf|properties|tfvars)$/i;
const HINT_WORD_RE = /secret|token|credential|passw|auth|config|settings/i;

/** Does a file NAME hint at configuration or keys (`NAME_HINTS`, §13.1)?
 *  `.env*`, `*.env`, `*.pem`, `*.key`, `*rc`, the configuration
 *  extensions, and names with a credential or configuration word. Pure. */
export function nameHints(name: string): boolean {
  const n = name.toLowerCase();
  return n.startsWith(".env") || n.endsWith(".env") || n.endsWith("rc")
    || HINT_EXT_RE.test(n) || HINT_WORD_RE.test(n);
}

/** A root's tier: HOME itself or any folder above it is walked as a home
 *  (name hints, depth 4), so a launch from `~` never reads every text file
 *  in a home. Pure over normalized absolute paths. */
export function rootTier(root: string, home: string): WorkspaceTier {
  if (root === home || root === "/") return "home";
  return home.startsWith(root.endsWith("/") ? root : root + "/") ? "home" : "workspace";
}

/** `p` normalized without a trailing slash (`/` stays `/`). Pure. */
function norm(p: string): string {
  const n = path.posix.normalize(p);
  return n.length > 1 && n.endsWith("/") ? n.slice(0, -1) : n;
}

/** Is `p` equal to or under `dir`? Pure. */
function within(p: string, dir: string): boolean {
  return p === dir || p.startsWith(dir === "/" ? "/" : dir + "/");
}

// ── The cache (in memory only) ───────────────────────────────────────────────

/** A file's identity as the cache keys it: a change of content moves the
 *  size, the mtime or (unforgeably, on any write or `utimes`) the ctime. */
export interface WorkspaceFileId {
  dev: bigint;
  ino: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
}

interface CacheEntry {
  binary: boolean;
  hits: ShapeHit[];
}

/**
 * What earlier workspace scans read, keyed by the file's identity plus the
 * detector's fingerprint, holding the MASKED hits (or "binary"). One arbiter
 * process, at most `max` entries (the least recently used goes first). Never
 * written to disk.
 */
export class WorkspaceScanCache<V = CacheEntry> {
  private readonly map = new Map<string, V>();

  constructor(private readonly max: number = WORKSPACE_CACHE_MAX) {}

  static key(id: WorkspaceFileId, fingerprint: string = historyDetectorFingerprint()): string {
    return `${fingerprint}|${id.dev}:${id.ino}:${id.size}:${id.mtimeNs}:${id.ctimeNs}`;
  }

  get(key: string): V | undefined {
    const v = this.map.get(key);
    if (v !== undefined) {
      this.map.delete(key);
      this.map.set(key, v);
    }
    return v;
  }

  set(key: string, v: V): void {
    this.map.delete(key);
    this.map.set(key, v);
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }

  get size(): number {
    return this.map.size;
  }
}

// ── The seams ────────────────────────────────────────────────────────────────

/** The outcome of one safe read. */
export type WorkspaceRead =
  | { kind: "read"; content: Buffer; id: WorkspaceFileId }
  | { kind: "too-big" }
  | { kind: "over-total" }
  | { kind: "not-regular" }
  | { kind: "symlink" }
  | { kind: "unreadable" };

/** The outcome of one safe label read (S4, plan 14 §14.1). */
export type WorkspaceLabelRead =
  | { kind: "read"; result: OfficeLabelRead; id: WorkspaceFileId }
  | { kind: "not-regular" }
  | { kind: "symlink" }
  | { kind: "unreadable" };

export interface WorkspaceScanFs {
  lstat(p: string): Promise<BigIntStats>;
  /** Follows links: used on a ROOT only (the caller named it). */
  stat(p: string): Promise<BigIntStats>;
  readdir(p: string): Promise<string[]>;
  /** Open without following a link or blocking, re-check on the descriptor
   *  that it is a regular file within the caps, read at most cap + 1 bytes. */
  readRegular(p: string, caps: { fileMax: number; totalLeft: number }): Promise<WorkspaceRead>;
  /** S4: open the same safe way, then read an Office file's labels through
   *  a bounded range reader (at most `totalLeft` bytes). Unset: the
   *  production `readOfficeFileLabels`. */
  readLabels?(p: string, caps: { totalLeft: number }): Promise<WorkspaceLabelRead>;
}

/** The detector kinds of a file's hits, sorted, each once (no mask). */
const kindsOf = (hits: readonly ShapeHit[]): string[] => [...new Set(hits.map((h) => h.shape as string))].sort();

const idOf = (st: BigIntStats): WorkspaceFileId => ({ dev: st.dev, ino: st.ino, size: st.size, mtimeNs: st.mtimeNs, ctimeNs: st.ctimeNs });

/** The production safe read (§13.1 "Only regular files, opened safely"). */
async function openSafely(p: string): Promise<fsp.FileHandle | { kind: "symlink" } | { kind: "unreadable" }> {
  try {
    return await fsp.open(p, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
  } catch (e) {
    // O_NOFOLLOW on a symlink: ELOOP (EMLINK on some BSDs).
    const code = (e as NodeJS.ErrnoException).code;
    return code === "ELOOP" || code === "EMLINK" ? { kind: "symlink" } : { kind: "unreadable" };
  }
}

export async function readRegularFile(p: string, caps: { fileMax: number; totalLeft: number }): Promise<WorkspaceRead> {
  const opened = await openSafely(p);
  if ("kind" in opened) return opened;
  const fh = opened;
  try {
    const st = await fh.stat({ bigint: true });
    if (!st.isFile()) return { kind: "not-regular" };
    const size = Number(st.size);
    if (size > caps.fileMax) return { kind: "too-big" };
    if (size > caps.totalLeft) return { kind: "over-total" };
    if (size === 0) return { kind: "read", content: Buffer.alloc(0), id: idOf(st) };
    // One byte past the size fstat gave: a file that grew past the cap
    // since is caught, and never more than cap + 1 bytes are read.
    const buf = Buffer.alloc(Math.min(size, caps.fileMax) + 1);
    let n = 0;
    while (n < buf.length) {
      const { bytesRead } = await fh.read(buf, n, buf.length - n, n);
      if (bytesRead === 0) break;
      n += bytesRead;
    }
    if (n > caps.fileMax) return { kind: "too-big" };
    return { kind: "read", content: buf.subarray(0, Math.min(n, caps.totalLeft)), id: idOf(st) };
  } catch {
    return { kind: "unreadable" };
  } finally {
    await fh.close().catch(() => { /* already gone */ });
  }
}

/**
 * The production label read (S4, plan 14 §14.1): the same safe open as the
 * text read (`O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`, then `fstat` on the
 * descriptor: a regular file or nothing), then `readOfficeLabels` over
 * positional reads of that descriptor, at most `totalLeft` bytes in all.
 * The file is never read whole: its head, its tail, the central directory
 * and two entries at most.
 */
export async function readOfficeFileLabels(p: string, caps: { totalLeft: number }): Promise<WorkspaceLabelRead> {
  const opened = await openSafely(p);
  if ("kind" in opened) return opened;
  const fh = opened;
  try {
    const st = await fh.stat({ bigint: true });
    if (!st.isFile()) return { kind: "not-regular" };
    const result = await readOfficeLabels(descriptorReader(fh, Number(st.size)), { maxBytes: caps.totalLeft });
    return { kind: "read", result, id: idOf(st) };
  } catch {
    return { kind: "unreadable" };
  } finally {
    await fh.close().catch(() => { /* already gone */ });
  }
}

/** The outcome of one head read (plan 14 §14.2, T2). */
export type WorkspaceHeadRead =
  | { kind: "read"; head: Buffer; size: number }
  | { kind: "not-regular" }
  | { kind: "symlink" }
  | { kind: "unreadable" };

/**
 * The contents tier's read (plan 14 §14.2): the first `max` bytes of a
 * document, with the text read's safe open (`O_NOFOLLOW | O_NONBLOCK |
 * O_NOCTTY`, then `fstat` on the descriptor: a regular file or nothing) and
 * the file's size at the read. Never more than `max` bytes are read. The
 * bytes are what the request carries after the gate re-runs the detectors
 * over them (a file changed since the walk is checked as it is now).
 */
export async function readFileHead(p: string, max: number): Promise<WorkspaceHeadRead> {
  const opened = await openSafely(p);
  if ("kind" in opened) return opened;
  const fh = opened;
  try {
    const st = await fh.stat({ bigint: true });
    if (!st.isFile()) return { kind: "not-regular" };
    const size = Number(st.size);
    const buf = Buffer.alloc(Math.max(0, Math.min(size, max)));
    let n = 0;
    while (n < buf.length) {
      const { bytesRead } = await fh.read(buf, n, buf.length - n, n);
      if (bytesRead === 0) break;
      n += bytesRead;
    }
    return { kind: "read", head: buf.subarray(0, n), size };
  } catch {
    return { kind: "unreadable" };
  } finally {
    await fh.close().catch(() => { /* already gone */ });
  }
}

/** The outcome of one Office text read (plan 14 §14.13, T2). */
export type WorkspaceOfficeTextRead =
  | { kind: "read"; result: OfficeTextRead }
  | { kind: "not-regular" }
  | { kind: "symlink" }
  | { kind: "unreadable" };

/**
 * The contents tier's read of an Office document (plan 14 §14.13): the text
 * read's safe open (`O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`, then `fstat` on
 * the descriptor: a regular file or nothing), then `readOfficeText` (4a's
 * bounded zip reader, the visible text of a bounded set of parts) over
 * positional reads of that descriptor, at most `totalLeft` bytes. Separate
 * from the walk: the walk never text-reads an Office file (§14.9), so the
 * key detectors of S2 never see this text; the contents gate does
 * (`officeTextHead`).
 */
export async function readOfficeFileText(p: string, caps: { totalLeft: number }): Promise<WorkspaceOfficeTextRead> {
  const family = officeFamily(p);
  if (family === null) return { kind: "unreadable" };
  const opened = await openSafely(p);
  if ("kind" in opened) return opened;
  const fh = opened;
  try {
    const st = await fh.stat({ bigint: true });
    if (!st.isFile()) return { kind: "not-regular" };
    const result = await readOfficeText(descriptorReader(fh, Number(st.size)), family, { maxBytes: caps.totalLeft });
    return { kind: "read", result };
  } catch {
    return { kind: "unreadable" };
  } finally {
    await fh.close().catch(() => { /* already gone */ });
  }
}

/** A range reader over an open descriptor (positional reads). */
function descriptorReader(fh: fsp.FileHandle, size: number): OfficeByteReader {
  return {
    size,
    read: async (offset, length) => {
      const buf = Buffer.alloc(length);
      let n = 0;
      while (n < length) {
        const { bytesRead } = await fh.read(buf, n, length - n, offset + n);
        if (bytesRead === 0) break;
        n += bytesRead;
      }
      return buf.subarray(0, n);
    },
  };
}

/** A linked work tree's gitfile: `gitdir: <common dir>/worktrees/<name>`. */
const LINKED_GITDIR_RE = /^gitdir: .*[\\/]worktrees[\\/][^\\/\n]+[\\/]?\s*$/;

/**
 * Is `gitPath` (a `.git` entry) the gitfile of a linked work tree? A `.git`
 * folder (a clone of its own) or a submodule's gitfile (`…/modules/<name>`)
 * is not. Read with the scan's safe read, a few bytes at most. The agent
 * can plant one to keep a folder out of this scan; that hides nothing it
 * could not delete, and enforcement never reads this (§13.9).
 */
export async function isLinkedWorktree(fs: WorkspaceScanFs, gitPath: string): Promise<boolean> {
  let st: BigIntStats;
  try {
    st = await fs.lstat(gitPath);
  } catch {
    return false;
  }
  if (!st.isFile()) return false;
  const r = await fs.readRegular(gitPath, { fileMax: 4096, totalLeft: 4096 });
  return r.kind === "read" && LINKED_GITDIR_RE.test(r.content.toString("utf8").split("\n")[0] ?? "");
}

export const defaultWorkspaceFs: WorkspaceScanFs = {
  lstat: (p) => fsp.lstat(p, { bigint: true }),
  stat: (p) => fsp.stat(p, { bigint: true }),
  readdir: (p) => fsp.readdir(p),
  readRegular: readRegularFile,
  readLabels: readOfficeFileLabels,
};

/** What the label cache holds per file identity: the read's outcome (label
 *  ids and tenants, or why it was not read), never file text. */
export type LabelCacheEntry = Exclude<OfficeLabelRead, { kind: "over-budget" }>;

export interface WorkspaceScanOptions {
  /** The user's HOME (tiers, the agent's auth, Mandu's home). Default: this
   *  process's. */
  home?: string;
  /** Add HOME as a home-tier root. */
  includeHome?: boolean;
  /** Is this absolute path a secret the catalog or a label already covers
   *  (the arbiter: `pathConfidentiality` with its label lookup)? A covered
   *  file is never opened. Unset: nothing is covered. */
  isCovered?: (absPath: string) => boolean;
  /** Discovery's prune knobs (the state base, the install trees). Default:
   *  the state base of the environment's Mandu home. */
  discovery?: DiscoveryOptions;
  /** The host platform the macOS prunes key on (HOME's app-data and media
   *  folders, `systemPrunes`); also the discovery prunes' platform.
   *  Default `discovery.platform`, else this process's. A test knob. */
  platform?: NodeJS.Platform;
  /** The environment the Mandu home is read from (MANDU_HOME); default
   *  `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
  fs?: WorkspaceScanFs;
  cache?: WorkspaceScanCache;
  limits?: Partial<SecretWorkspaceLimits>;
  now?: () => number;
  /** Yield to the event loop (default: setImmediate); a test passes a no-op. */
  yieldNow?: () => Promise<void>;
  /** Read the text files for credentials (S2). Default true; false when
   *  `suggestPolicy` asked for the sensitivity labels only. */
  readText?: boolean;
  /**
   * S4 (plan 14 §14.1): read Office files' sensitivity labels. Unset: no
   * label summary; mode `off`: a summary of zeros and no Office file opened.
   * Office files never go to the text read, whatever this says: they are
   * not text.
   */
  sensitivityLabels?: {
    mode: "mapped" | "count" | "off";
    /** Does the mapping in force map this label (at any level)? */
    isMapped: (label: { id: string; site: string | null }) => boolean;
    limits?: Partial<LabelScanLimits>;
    cache?: WorkspaceScanCache<LabelCacheEntry>;
  };
  /** Also answer `listed`: the names of the regular files examined (plan 14
   *  §14.2, the names-only model's candidates). Off by default. */
  list?: boolean;
  /** Plan 14 §14.4 (T2): in the home tier, also read the files a name hint
   *  would skip when this says they are documents (the contents model's
   *  candidates: `documentExtension`), so the detectors run over them before
   *  any is considered. Unset: the home tier reads name-hinted files only. */
  documents?: (name: string) => boolean;
}

const kib = (n: number): string => `${Math.round(n / 1024)} KiB`;
const mib = (n: number): string => `${Math.round((n / 1048576) * 10) / 10} MiB`;

/**
 * Scan the files under each root (§13.1). Never throws for a filesystem
 * failure: what could not be read is in `capped`. The result carries no
 * file content.
 */
export async function scanSecretWorkspace(roots: readonly string[], opts: WorkspaceScanOptions = {}): Promise<SecretWorkspaceScan> {
  const home = norm(opts.home && opts.home.startsWith("/") ? opts.home : homedir());
  const fs = opts.fs ?? defaultWorkspaceFs;
  const now = opts.now ?? Date.now;
  const yieldNow = opts.yieldNow ?? (() => new Promise<void>((r) => setImmediate(r)));
  const limits: SecretWorkspaceLimits = { ...DEFAULT_WORKSPACE_LIMITS, ...(opts.limits ?? {}) };
  const isCovered = opts.isCovered ?? (() => false);
  const cache = opts.cache;
  const fingerprint = historyDetectorFingerprint();
  const t0 = now();
  const deadline = t0 + limits.timeoutMs;
  const late = (): boolean => now() >= deadline;

  // Discovery's prunes, for this home, with the state base of the Mandu
  // home this arbiter runs under (MANDU_HOME), so a moved home is pruned too.
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? opts.discovery?.platform ?? process.platform;
  const prunes = discoveryPrunes(home, { stateBase: manduPath("view-state", env, home), ...(opts.discovery ?? {}), platform });
  const system = systemPrunes(platform);
  // macOS: HOME's app-data and media folders are pruned outright here (the
  // header says why this scan needs no label or catalog re-entry).
  const pruned = (full: string): boolean =>
    prunes.stateDirs.has(full) || isAgentAuthPath(full, home) || system.walk.has(full) || prunes.homeSkip.has(full);
  const insidePruned = (p: string): string | null => {
    for (const d of prunes.stateDirs) if (within(p, d)) return "Mandu's own state, not scanned";
    if (isAgentAuthPath(p, home)) return "the agent's own credentials, not scanned";
    for (const { dir, why } of system.roots) if (within(p, dir)) return why;
    return null;
  };

  const labelFindings: SensitivityLabelFinding[] = [];
  const scan: SecretWorkspaceScan = {
    roots: [],
    counts: { examined: 0, read: 0, cached: 0, bytes: 0, covered: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, special: 0, depth: 0, worktrees: 0, lines: [] },
    findings: [], labelFindings, labels: null, limits, ms: 0,
    ...(opts.list === true ? { listed: [] } : {}),
  };
  const listed = scan.listed;
  const readText = opts.readText ?? true;
  const lab = opts.sensitivityLabels;
  const labMode = lab?.mode ?? "off";
  const labLimits: LabelScanLimits = { ...DEFAULT_LABEL_LIMITS, ...(lab?.limits ?? {}) };
  const L: SensitivityLabelScanSummary | null = lab ? emptyLabelSummary(labMode, labLimits) : null;
  scan.labels = L;
  const unmappedIds = new Map<string, { id: string; site: string | null; files: number }>();

  // The roots and their tiers. A root inside another workspace root is
  // walked by that one; a home-tier walk prunes every other root (each is
  // walked by its own plan, workspace roots in full).
  const plans: Array<{ root: string; tier: WorkspaceTier }> = [];
  const requested: string[] = roots.slice(0, HISTORY_ROOTS_MAX).map(String);
  if (opts.includeHome && !requested.some((r) => r.startsWith("/") && norm(r) === home)) requested.push(home);
  for (const raw of requested) {
    if (!path.posix.isAbsolute(raw)) { scan.roots.push({ root: raw, tier: "workspace", reason: "not an absolute path" }); continue; }
    const root = norm(raw);
    const tier = rootTier(root, home);
    const rec: SecretWorkspaceScan["roots"][number] = { root, tier };
    scan.roots.push(rec);
    const why = insidePruned(root);
    if (why !== null) { rec.reason = why; continue; }
    if (plans.some((p) => p.root === root)) { rec.reason = "the same as another root"; continue; }
    if (tier === "workspace" && plans.some((p) => p.tier === "workspace" && within(root, p.root))) { rec.reason = "inside another root"; continue; }
    let st: BigIntStats | null = null;
    try { st = await fs.lstat(root); } catch { st = null; }
    // A root named by a symlink is followed (the caller named it); only
    // what is found below it is decided on lstat.
    if (st?.isSymbolicLink()) {
      try { st = await fs.stat(root); } catch { st = null; }
    }
    if (st === null) { rec.reason = "does not exist or cannot be read"; continue; }
    if (!st.isDirectory()) { rec.reason = "not a directory"; continue; }
    plans.push({ root, tier });
  }
  // A workspace root that sits inside a later one: drop the inner plan.
  for (let i = plans.length - 1; i >= 0; i--) {
    const p = plans[i]!;
    if (p.tier !== "workspace") continue;
    if (plans.some((q, j) => j !== i && q.tier === "workspace" && q.root !== p.root && within(p.root, q.root))) {
      const rec = scan.roots.find((r) => r.root === p.root && r.reason === undefined);
      if (rec) rec.reason = "inside another root";
      plans.splice(i, 1);
    }
  }
  plans.sort((a, b) => Number(a.tier === "home") - Number(b.tier === "home"));
  const planRoots = new Set(plans.map((p) => p.root));

  let slice = now();
  let dirsLeftTime = 0;
  let dirsLeftFiles = 0;
  const seen = new Set<string>();
  for (const plan of plans) {
    const maxDepth = plan.tier === "workspace" ? WORKSPACE_MAX_DEPTH : HOME_MAX_DEPTH;
    const queue: Array<{ dir: string; depth: number; repo: string | null }> = [{ dir: plan.root, depth: 0, repo: null }];
    while (queue.length > 0) {
      if (late()) { dirsLeftTime += queue.length; break; }
      if (scan.counts.examined >= limits.maxFiles) { dirsLeftFiles += queue.length; break; }
      const { dir, depth, repo: parentRepo } = queue.shift()!;
      let names: string[];
      try {
        names = (await fs.readdir(dir)).sort();
      } catch {
        scan.capped.unreadable++;
        continue;
      }
      // A linked work tree below the root is a second checkout of a
      // repository (an agent's `.claude/worktrees/<name>`, `git worktree
      // add` inside a project): its files are the main checkout's again,
      // test fixtures included, and one launch filed 131 suggestions from
      // 39 of them (§13.9). Not walked; the root itself may be one.
      if (depth > 0 && names.includes(".git") && (await isLinkedWorktree(fs, `${dir}/.git`))) {
        scan.capped.worktrees++;
        continue;
      }
      const repo = names.includes(".git") ? dir : parentRepo;
      for (let k = 0; k < names.length; k++) {
        // The deadline bounds a huge directory too (past the file cap its
        // entries are still lstat'ed to be counted).
        if (late()) { scan.capped.overTime += names.length - k; break; }
        const name = names[k]!;
        // `.git` (a folder, or a linked work tree's gitfile) is history,
        // S1's job.
        if (name === ".git") continue;
        const full = dir === "/" ? `/${name}` : `${dir}/${name}`;
        if (pruned(full)) continue;
        let st: BigIntStats;
        try {
          st = await fs.lstat(full);
        } catch {
          scan.capped.unreadable++;
          continue;
        }
        if (st.isDirectory()) {
          if (SKIP_DIRS.has(name) || prunes.isInstallTree(full, name) || planRoots.has(full)) continue;
          if (depth + 1 > maxDepth) { scan.capped.depth++; continue; }
          queue.push({ dir: full, depth: depth + 1, repo });
          continue;
        }
        // S4: an Office file is never text-read (it is not text); its
        // labels are read only while a mapping is in force or a count was
        // asked for, in both tiers.
        if (isOfficeName(name)) {
          if (L !== null && labMode !== "off") await labelFile(plan, repo, full, st);
          // The names-only listing (plan 14 §14.2): an Office file is a name
          // like any other, in both tiers (the documents T1 is for). The
          // listing never opens it; the coverage check is a path lookup.
          if (listed && st.isFile() && !seen.has(full) && listed.length < limits.maxFiles) {
            seen.add(full);
            listed.push({ root: plan.root, tier: plan.tier, repoRoot: repo, path: full, size: Number(st.size), covered: isCovered(full), kinds: [] });
          }
          continue;
        }
        if (!readText) continue;
        if (plan.tier === "home" && !nameHints(name) && !(opts.documents?.(name) ?? false)) continue;
        if (seen.has(full)) continue;
        seen.add(full);
        if (scan.counts.examined >= limits.maxFiles) { scan.capped.overFiles++; continue; }
        if (late()) { scan.capped.overTime++; continue; }
        scan.counts.examined++;
        // Covered first: a file the law confines already is never opened.
        if (isCovered(full)) {
          scan.counts.covered++;
          if (listed && st.isFile()) listed.push({ root: plan.root, tier: plan.tier, repoRoot: repo, path: full, size: Number(st.size), covered: true, kinds: [] });
          continue;
        }
        if (st.isSymbolicLink()) { scan.capped.symlinks++; continue; }
        if (!st.isFile()) { scan.capped.special++; continue; }
        const size = Number(st.size);
        const entry: WorkspaceListedFile | null = listed ? { root: plan.root, tier: plan.tier, repoRoot: repo, path: full, size, covered: false, kinds: [] } : null;
        if (entry && listed) listed.push(entry);
        if (size > limits.fileMaxBytes) { scan.capped.tooBig++; continue; }
        const known = cache?.get(WorkspaceScanCache.key(idOf(st), fingerprint));
        if (known !== undefined) {
          scan.counts.cached++;
          if (known.binary) scan.capped.binary++;
          else { record(plan, repo, full, known.hits); if (entry) { entry.kinds = kindsOf(known.hits); entry.scanned = true; } }
          continue;
        }
        const totalLeft = limits.totalMaxBytes - scan.counts.bytes;
        if (size > totalLeft) { scan.capped.overTotal++; continue; }
        const r = await fs.readRegular(full, { fileMax: limits.fileMaxBytes, totalLeft });
        if (r.kind === "symlink") { scan.capped.symlinks++; continue; }
        if (r.kind === "not-regular") { scan.capped.special++; continue; }
        if (r.kind === "too-big") { scan.capped.tooBig++; continue; }
        if (r.kind === "over-total") { scan.capped.overTotal++; continue; }
        if (r.kind === "unreadable") { scan.capped.unreadable++; continue; }
        scan.counts.read++;
        scan.counts.bytes += r.content.length;
        const key = WorkspaceScanCache.key(r.id, fingerprint);
        if (isBinaryBlob(r.content)) {
          scan.capped.binary++;
          cache?.set(key, { binary: true, hits: [] });
        } else {
          const hits = detectSecretShapes(r.content.toString("utf8"));
          cache?.set(key, { binary: false, hits });
          record(plan, repo, full, hits);
          if (entry) { entry.kinds = kindsOf(hits); entry.scanned = true; }
        }
        if (now() - slice >= SLICE_MS) { await yieldNow(); slice = now(); }
      }
    }
  }

  const c = scan.capped;
  if (roots.length > HISTORY_ROOTS_MAX) c.lines.push(`${roots.length - HISTORY_ROOTS_MAX} root(s) over ${HISTORY_ROOTS_MAX} not scanned`);
  if (c.tooBig > 0) c.lines.push(`${c.tooBig} file(s) over ${kib(limits.fileMaxBytes)} not read (MANDU_WORKSPACE_SCAN_FILE_MAX_KB)`);
  if (c.overTotal > 0) c.lines.push(`${c.overTotal} file(s) not read: over the ${mib(limits.totalMaxBytes)} total (MANDU_WORKSPACE_SCAN_MAX_MB)`);
  if (c.overFiles > 0 || dirsLeftFiles > 0) {
    c.lines.push(`${c.overFiles} file(s) and ${dirsLeftFiles} folder(s) not examined: over the ${limits.maxFiles} file cap (MANDU_WORKSPACE_SCAN_FILES)`);
  }
  if (c.overTime > 0 || dirsLeftTime > 0) {
    c.lines.push(`${c.overTime} entr(ies) and ${dirsLeftTime} more folder(s) not examined: the ${Math.round(limits.timeoutMs / 1000)} s time budget ran out (MANDU_WORKSPACE_SCAN_TIMEOUT_S)`);
  }
  if (c.binary > 0) c.lines.push(`${c.binary} binary file(s) skipped`);
  if (c.symlinks > 0) c.lines.push(`${c.symlinks} symbolic link(s) to files not followed`);
  if (c.special > 0) c.lines.push(`${c.special} special file(s) (a pipe, a socket or a device) not read`);
  if (c.unreadable > 0) c.lines.push(`${c.unreadable} file(s) or folder(s) could not be read`);
  if (c.worktrees > 0) c.lines.push(`${c.worktrees} linked git work tree(s) inside a root not walked (a second checkout of a repository)`);
  if (c.depth > 0) c.lines.push(`${c.depth} folder(s) below the depth limit not walked (${WORKSPACE_MAX_DEPTH} in a project, ${HOME_MAX_DEPTH} in the home folder)`);
  if (L !== null) {
    if (L.capped.overFiles > 0) c.lines.push(`${L.capped.overFiles} Office file(s) not examined for a sensitivity label: over the ${labLimits.maxFiles} file cap`);
    if (L.capped.overBytes > 0) c.lines.push(`${L.capped.overBytes} Office file(s) not read for a sensitivity label: over the ${mib(labLimits.totalMaxBytes)} total`);
    if (L.encrypted > 0) c.lines.push(`${L.encrypted} encrypted Office file(s) not read (the sensitivity label is inside the encryption)`);
    if (L.unreadable > 0) c.lines.push(`${L.unreadable} Office file(s) whose sensitivity label could not be read`);
    const ids = [...unmappedIds.values()].sort((a, b) => b.files - a.files || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0) || (a.site ?? "").localeCompare(b.site ?? ""));
    L.unmapped = ids.slice(0, UNMAPPED_LABELS_MAX);
    L.unmappedMore = Math.max(0, ids.length - UNMAPPED_LABELS_MAX);
    labelFindings.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }
  scan.findings.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  listed?.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  scan.ms = now() - t0;
  return scan;

  /** S4: one Office file's labels (§14.1 "The read"): covered first (never
   *  opened), then the cache, then the bounded read under the label
   *  budgets. Keeps the enabled labels' ids and tenants only. */
  async function labelFile(plan: { root: string; tier: WorkspaceTier }, repo: string | null, full: string, st: BigIntStats): Promise<void> {
    const l = L!;
    if (seen.has(full)) return;
    seen.add(full);
    if (l.examined >= labLimits.maxFiles) { l.capped.overFiles++; return; }
    if (late()) { scan.capped.overTime++; return; }
    l.examined++;
    // Covered first: a file the law confines already is never opened.
    if (isCovered(full)) { l.covered++; return; }
    if (st.isSymbolicLink()) { scan.capped.symlinks++; return; }
    if (!st.isFile()) { scan.capped.special++; return; }
    const cacheKey = (id: WorkspaceFileId): string => WorkspaceScanCache.key(id, SENSITIVITY_LABEL_READER_VERSION);
    const known = lab!.cache?.get(cacheKey(idOf(st)));
    let outcome: LabelCacheEntry;
    if (known !== undefined) {
      l.cached++;
      outcome = known;
    } else {
      const totalLeft = labLimits.totalMaxBytes - l.bytes;
      if (totalLeft <= 0) { l.capped.overBytes++; return; }
      const r = await (fs.readLabels ?? readOfficeFileLabels)(full, { totalLeft });
      if (r.kind === "symlink") { scan.capped.symlinks++; return; }
      if (r.kind === "not-regular") { scan.capped.special++; return; }
      if (r.kind === "unreadable") { l.unreadable++; return; }
      l.read++;
      l.bytes += r.result.bytes;
      if (r.result.kind === "over-budget") { l.capped.overBytes++; return; }
      outcome = r.result;
      // Stored under the descriptor's identity: a file swapped since the
      // lstat is read again next time.
      lab!.cache?.set(cacheKey(r.id), outcome);
    }
    if (outcome.kind === "encrypted") l.encrypted++;
    else if (outcome.kind === "unreadable") l.unreadable++;
    else {
      const enabled = outcome.labels.filter((x) => x.enabled).map((x) => ({ id: x.id, site: x.site }));
      if (enabled.length > 0) {
        l.files++;
        let anyMapped = false;
        let anyUnmapped = false;
        for (const x of enabled) {
          if (lab!.isMapped(x)) { anyMapped = true; continue; }
          anyUnmapped = true;
          const k = `${x.id}|${x.site ?? ""}`;
          const u = unmappedIds.get(k) ?? { id: x.id, site: x.site, files: 0 };
          u.files++;
          unmappedIds.set(k, u);
        }
        if (anyMapped) l.mapped++;
        if (anyUnmapped) l.unmappedFiles++;
        labelFindings.push({ path: full, repoRoot: repo ?? plan.root, labels: enabled });
      }
    }
    if (now() - slice >= SLICE_MS) { await yieldNow(); slice = now(); }
  }

  function record(plan: { root: string; tier: WorkspaceTier }, repo: string | null, full: string, hits: readonly ShapeHit[]): void {
    if (hits.length === 0) return;
    scan.findings.push({
      root: plan.root,
      tier: plan.tier,
      repoRoot: repo,
      path: full,
      detectors: hits.map((h) => ({ kind: "content-shape" as const, rule: h.shape, line: h.line, preview: h.preview })),
    });
  }
}
