/**
 * secret-history-scan — find secret-shaped blobs in a repository's reachable
 * git history (docs/design/confidentiality/secret-discovery.md §3; the C17 boundary of
 * `secrets` mode, test-organization.md §7.2).
 *
 * A key committed and later deleted lives only in git history: in no file on
 * disk, no catalog path, no label, so no launch protects it and `git log -p`
 * hands it to the model raw. This module FINDS such blobs; it enforces
 * nothing and writes nothing. The arbiter answers it as the data-plane op
 * `scanSecretHistory`; `mandu doctor --secrets` renders the answer (phase
 * 1), and the policy generator of confidentiality-plan-14 consumes
 * {@link SecretHistoryFinding} as its input, so that type is kept stable.
 *
 * WHY THE ARBITER READS THE BLOBS (the rule of secret-registry.ts and
 * secret-discovery.ts): the arbiter runs outside every agent's sandbox and
 * is the one component that may hold secret bytes. The raw bytes of a blob
 * live in this process's memory while it is matched and nowhere else: a
 * finding carries the detector's kind, the line and a fixed mask (the
 * format's public prefix at most, `sk-ant-…`; an assignment's name,
 * `DB_PASSWORD=…`; a key block's header), never a character of a value's
 * body, and no length or hash of it.
 *
 * What it reads: every blob reachable from any ref, the reflog and the stash
 * (what `git rev-list --all --reflog --objects` lists, with the reflogs read
 * from their files once and handed to git on stdin, history-tips.ts; never
 * fewer commits, git's own `--reflog` on any doubt), plus the index's stages, each
 * read once by name (`git cat-file --batch`). Bounded by a blob size cap, a
 * total byte cap and one deadline shared by every git call; whatever a cap
 * left unread is in `capped`, never silent. Matching yields to the event
 * loop every few milliseconds, so a scan does not hold the arbiter's other
 * clients.
 *
 * git runs HARDENED (../src/hardened-git.ts, docs/design/architecture/write-protection.md §8):
 * the op is on the data plane, so the repository may be one the agent
 * built. None of the commands used runs a hook, a diff driver or a filter;
 * every key that starts a program by a name git knows (`core.fsmonitor`,
 * hooks, `log.showSignature` and its `gpg.program`, transports and the lazy
 * fetch of a partial clone, …) is forced off on every call, the
 * environment carries no inherited `GIT_*`, and where a git sandbox can be made
 * (bubblewrap on Linux, Seatbelt on macOS) git runs in the read-only,
 * no-network git sandbox. The pager is off and
 * pathspecs are literal.
 *
 * Pure over its seams: the git runner, the blob batch reader, the path
 * classifier (the arbiter's catalog and labels), `exists` and the clock are
 * injected; the parsers and the detector are pure and unit-tested.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 * The git runner mirrors launcher/src/git-object-twins.ts `defaultGitRunner`
 * (the packages ship standalone and do not import each other).
 */
import { runChild } from "../src/child-run.js";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { gitCommand, gitSandbox, hardenedGitArgs, hardenedGitEnv } from "../src/hardened-git.js";
import { historyTipsOf, reflogNamesOf, reflogRevArgs, type ReflogNames, type TipsGit } from "./history-tips.js";
import { IGNORE_SHALLOW_ARGS, walkShallowRule } from "./history-labels.js";
import {
  historyCacheBase,
  planHistoryScan,
  type HistoryScanCache,
  type HistoryScanCacheEntry,
  type HistoryScanPlan,
  type HistoryScanTrace,
} from "./secret-history-cache.js";
import {
  detectSecretShapes,
  historyDetectorFingerprint,
  isBinaryBlob,
  type SecretShape,
  type ShapeHit,
} from "./secret-detectors.js";

// The detectors live in their own module since plan 14 phase 3 (§13.2), so
// the workspace scan shares them; every name is re-exported here, so no
// import of this module broke.
export {
  detectSecretShapes,
  entropy,
  HISTORY_DETECTOR_VERSION,
  historyDetectorFingerprint,
  isBinaryBlob,
  isPlaceholder,
  looksLikeSecretValue,
  type SecretShape,
  type ShapeHit,
} from "./secret-detectors.js";

// ── The findings type (stable: confidentiality-plan-14 consumes it) ─────────

/** Why a blob is a finding. */
export type SecretHistoryDetector =
  | {
      kind: "content-shape";
      /** The {@link SecretShape}. */
      rule: SecretShape;
      line: number;
      preview: string;
    }
  | {
      /** A path the blob had that no longer exists in the work tree, which
       *  the catalog or a label calls a secret (a deleted `.env`, `id_rsa`). */
      kind: "catalog-path";
      /** The deciding rule (`catalog:…` or `label:…`). */
      rule: string;
      /** That path, repo-relative. */
      path: string;
      level: string;
    };

/** One secret-shaped blob in a repository's reachable history. */
export interface SecretHistoryFinding {
  /** The work tree root (absolute). */
  repoRoot: string;
  /** The blob's object name (full). */
  blob: string;
  /** Every path the blob had that the scan saw, repo-relative, sorted. */
  paths: string[];
  /** The oldest commit that added it; null when not traced (the index only,
   *  or over the attribution cap). */
  firstCommit: string | null;
  /** The newest commit that added or removed it (its deletion, or the
   *  addition when it was never removed); null when not traced. */
  lastCommit: string | null;
  /** The blob is a file of HEAD's tree. */
  inHead: boolean;
  /** The blob is staged in the index. */
  inIndex: boolean;
  /** One of its paths exists in the work tree now. */
  stillPresent: boolean;
  /** The law covers this version now, so a launch's object twins hide it
   *  (covered): one of its paths that exists now is a secret by the catalog
   *  or a label (the file is confined and every committed version of that
   *  path hidden); or, since plan 14 §8.1/§8.2, a path of it that no longer
   *  exists has a human label above `public`, or the blob itself is locked
   *  above `public` (`blobs:`). The name predates the last two. */
  pathStillSecretByCatalog: boolean;
  /** The strongest reason (a content shape before a catalog name). */
  detector: SecretHistoryDetector;
  /** Every reason. */
  detectors: SecretHistoryDetector[];
}

/** What a cap or a failure left unread. Every count is complete. */
export interface SecretHistoryCapped {
  /** Blobs over the size cap, not read. */
  tooBig: number;
  /** Blobs not read: the total byte cap. */
  overTotal: number;
  /** Blobs not read: the deadline. */
  overTime: number;
  /** Blobs not read before the deadline: git failed to hand them over (the
   *  reader failed or came back short). Never counted as `overTime`. */
  readFailed: number;
  /** Read but skipped as binary (a NUL in the first 8000 bytes). */
  binary: number;
  /** Deleted paths not asked of the catalog (over the cap). */
  pathsUnchecked: number;
  /** Findings not traced to their commits (over the cap or the deadline). */
  untraced: number;
  /** The history could not be listed at all (nothing scanned). */
  unlisted: boolean;
  /** One human line per cap or failure, in the order they happened. */
  lines: string[];
}

export interface SecretHistoryLimits {
  /** A blob larger than this is counted, not read. */
  blobMaxBytes: number;
  /** Bytes of blob content read in all. */
  totalMaxBytes: number;
  /** One deadline for the whole scan, shared by every git call. */
  timeoutMs: number;
  /** Findings traced to commits (one `git log --find-object` each). */
  traceMax: number;
  /** Deleted paths asked of the classifier. */
  classifyMax: number;
}

/** How the cache served one repository (secret-discovery.md §3.2 item 8). */
export interface SecretHistoryCacheUse {
  /** `fresh`: nothing usable was cached; `hit`: the same tips; `incremental`:
   *  new tips, only their objects listed; `relist`: a tip went away, the
   *  history listed again; `off`: this repository was not cacheable (a
   *  shallow clone, grafts, a git failure while keying it). */
  plan: HistoryScanPlan["kind"] | "off";
  /** Blobs this call read (the rest came from the cache). */
  read: number;
  /** The entry was written back. */
  stored: boolean;
}

export interface SecretHistoryScan {
  /** One per requested root: its work tree, or why it has none; `cache`
   *  when the scan ran with a cache. */
  repos: Array<{ root: string; repoRoot: string | null; reason?: string; cache?: SecretHistoryCacheUse }>;
  counts: {
    /** Distinct blobs reachable (history and index), over every repository. */
    blobs: number;
    /** Blobs whose content was read and matched. */
    scanned: number;
    /** Deleted paths asked of the classifier. */
    classified: number;
  };
  capped: SecretHistoryCapped;
  findings: SecretHistoryFinding[];
  limits: SecretHistoryLimits;
  ms: number;
}

export const DEFAULT_HISTORY_LIMITS: SecretHistoryLimits = {
  blobMaxBytes: 1024 * 1024,
  totalMaxBytes: 256 * 1024 * 1024,
  timeoutMs: 60_000,
  traceMax: 1000,
  classifyMax: 5000,
};

/** MANDU_HISTORY_SCAN_BLOB_MAX_KB / _MAX_MB / _TIMEOUT_S → limits (unset or
 *  invalid: the default). Pure. */
export function historyLimitsFromEnv(env: Record<string, string | undefined>): SecretHistoryLimits {
  const num = (k: string): number | null => {
    const n = Number(env[k]);
    return Number.isFinite(n) && n > 0 ? n : null;
  };
  const kb = num("MANDU_HISTORY_SCAN_BLOB_MAX_KB");
  const mb = num("MANDU_HISTORY_SCAN_MAX_MB");
  const s = num("MANDU_HISTORY_SCAN_TIMEOUT_S");
  return {
    ...DEFAULT_HISTORY_LIMITS,
    ...(kb !== null ? { blobMaxBytes: Math.floor(kb * 1024) } : {}),
    ...(mb !== null ? { totalMaxBytes: Math.floor(mb * 1024 * 1024) } : {}),
    ...(s !== null ? { timeoutMs: Math.floor(s * 1000) } : {}),
  };
}

// ── Pure: the git output parsers ────────────────────────────────────────────

const HEX_OID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

/** `git rev-list --objects` output: object name → the path it was reached
 *  by (null for commits and root trees). Pure. */
export function parseRevListObjects(out: string): Map<string, string | null> {
  const found = new Map<string, string | null>();
  for (const line of out.split("\n")) {
    if (line === "") continue;
    const sp = line.indexOf(" ");
    const oid = sp < 0 ? line : line.slice(0, sp);
    if (!HEX_OID.test(oid)) continue;
    const path = sp < 0 ? "" : line.slice(sp + 1);
    if (!found.has(oid)) found.set(oid, path === "" ? null : path);
  }
  return found;
}

/** `git cat-file --batch-check` output: name → {type, size}; a missing
 *  object is left out. Pure. */
export function parseBatchCheck(out: string): Map<string, { type: string; size: number }> {
  const found = new Map<string, { type: string; size: number }>();
  for (const line of out.split("\n")) {
    const [oid, type, size] = line.trim().split(" ");
    if (oid === undefined || !HEX_OID.test(oid) || type === undefined || type === "missing" || size === undefined) continue;
    const n = Number(size);
    if (Number.isFinite(n)) found.set(oid, { type, size: n });
  }
  return found;
}

/** `git ls-files -s -z` or `git ls-tree -r -z` records: blob name → paths.
 *  Gitlinks (mode 160000) are left out. Pure. */
export function parseIndexOrTree(out: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const rec of out.split("\0")) {
    // ls-files -s: "<mode> <oid> <stage>\t<path>"; ls-tree: "<mode> blob <oid>\t<path>"
    const m = /^(\d{6}) (?:blob )?([0-9a-f]{40}(?:[0-9a-f]{24})?)(?: \d)?\t([\s\S]+)$/.exec(rec);
    if (!m || m[1] === "160000") continue;
    const list = found.get(m[2]!) ?? [];
    if (!list.includes(m[3]!)) list.push(m[3]!);
    found.set(m[2]!, list);
  }
  return found;
}

/** One object of `git cat-file --batch` output. */
export interface BatchObject {
  oid: string;
  type: string;
  content: Buffer;
}

/** `git cat-file --batch` output: `<oid> <type> <size>\n<content>\n` per
 *  object, `<oid> missing\n` for a missing one. A torn tail (the reader was
 *  stopped at the deadline) is dropped. Pure. */
export function parseBatchOutput(buf: Buffer): BatchObject[] {
  const out: BatchObject[] = [];
  let i = 0;
  while (i < buf.length) {
    const nl = buf.indexOf(0x0a, i);
    if (nl < 0) break;
    const header = buf.subarray(i, nl).toString("latin1").split(" ");
    i = nl + 1;
    if (header[1] === "missing" || header.length < 3) continue;
    const size = Number(header[2]);
    if (!Number.isFinite(size) || i + size > buf.length) break;
    out.push({ oid: header[0]!, type: header[1]!, content: buf.subarray(i, i + size) });
    i += size + 1;
  }
  return out;
}

/** git's C-style quoting of an unusual path (`"a\tb"`), undone. Pure. */
export function unquoteGitPath(p: string): string {
  if (!(p.length >= 2 && p.startsWith('"') && p.endsWith('"'))) return p;
  const bytes: number[] = [];
  const s = p.slice(1, -1);
  const esc: Record<string, number> = { n: 10, t: 9, r: 13, '"': 34, "\\": 92, a: 7, b: 8, f: 12, v: 11 };
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c !== "\\") { for (const b of Buffer.from(c, "utf8")) bytes.push(b); continue; }
    const n = s[++i];
    if (n === undefined) break;
    if (/[0-7]/.test(n)) {
      bytes.push(parseInt(s.slice(i, i + 3), 8));
      i += 2;
      continue;
    }
    bytes.push(esc[n] ?? n.charCodeAt(0));
  }
  return Buffer.from(bytes).toString("utf8");
}

/** `git log --format='commit %H' --raw --no-abbrev --find-object=<oid>`
 *  output: the commits (newest first, unique) and the paths `oid` had on
 *  either side of a change record. Pure. */
export function parseFindObjectLog(out: string, oid: string): { commits: string[]; paths: string[] } {
  const commits: string[] = [];
  const paths = new Set<string>();
  for (const line of out.split("\n")) {
    const c = /^commit ([0-9a-f]{40}(?:[0-9a-f]{24})?)/.exec(line);
    if (c) {
      if (!commits.includes(c[1]!)) commits.push(c[1]!);
      continue;
    }
    if (!line.startsWith(":")) continue;
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    const [, , src, dst] = line.slice(1, tab).split(" ");
    if (src === oid || dst === oid) paths.add(unquoteGitPath(line.slice(tab + 1)));
  }
  return { commits, paths: [...paths].sort() };
}

// ── The seams ───────────────────────────────────────────────────────────────

export interface GitRun {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs one git command (the hardening flags are the scan's, prepended). */
export type HistoryGitRunner = (args: string[], opts: { cwd: string; input?: string; timeoutMs: number }) => Promise<GitRun>;

/** Every call's global options: hardened-git.ts (no pager, no program a
 *  repository names: `core.fsmonitor`, hooks, the signature verifier
 *  `log.showSignature` hands a signed commit to — plan 14 §11.1, found
 *  2026-09-30: the scan's trace walk ran it —, transports and the lazy
 *  fetch of a partial clone, docs/design/architecture/write-protection.md §8), literal
 *  pathspecs and unquoted paths. */
export const HARDENED_GIT_ARGS: readonly string[] = hardenedGitArgs(
  ["-c", "core.quotepath=off", "-c", "core.untrackedCache=false"],
  { literalPathspecs: true },
);

/** Every call's environment: scrubbed of `GIT_*` (hardened-git.ts), no
 *  optional locks, the C locale. */
export const historyGitEnv = (): NodeJS.ProcessEnv => hardenedGitEnv(process.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" });

/** The command for one hardened call: `git` behind HARDENED_GIT_ARGS, in the
 *  git sandbox where one can be made (bubblewrap on Linux, Seatbelt on
 *  macOS: read-only, no network; on macOS no program but git starts). */
export function historyGitCommand(args: readonly string[]): { file: string; args: string[] } {
  return gitCommand([...HARDENED_GIT_ARGS, ...args], gitSandbox());
}

/** The production runner (mirrors launcher git-object-twins.ts
 *  `defaultGitRunner`), run by ../src/child-run.ts `runChild`: killed at
 *  the deadline with its whole process group, and settled even when a
 *  sandbox child orphaned in its start-up holds the pipes
 *  (write-protection.md §8.5.1). Output over 512 MiB fails the call. */
export const defaultHistoryGitRunner: HistoryGitRunner = async (args, opts) => {
  const cmd = historyGitCommand(args);
  const r = await runChild(cmd.file, cmd.args, {
    cwd: opts.cwd, env: historyGitEnv(), timeoutMs: opts.timeoutMs, maxStdout: 512 * 1024 * 1024, maxStderr: 1 << 16,
    ...(opts.input !== undefined ? { input: opts.input } : {}),
  });
  return { code: r.code, stdout: r.stdout, stderr: r.stderr };
};

/** Reads blobs by name: the raw `git cat-file --batch` output. */
export type BlobBatchReader = (root: string, oids: readonly string[], opts: { timeoutMs: number }) => Promise<Buffer>;

/** The production reader: `git cat-file --batch` in `root`, killed at the
 *  deadline (what arrived by then is parsed; a torn tail is dropped); run
 *  by `runChild`, so it settles whatever holds the pipes. A call that could
 *  not start or FAILED on its own (the git sandbox did not come up, git
 *  exited non-zero) throws with git's last line: the scan counts that chunk
 *  as `readFailed`, never as the deadline. */
export const defaultBlobReader: BlobBatchReader = async (root, oids, opts) => {
  const cmd = historyGitCommand(["cat-file", "--batch"]);
  const chunks: Buffer[] = [];
  const r = await runChild(cmd.file, cmd.args, {
    cwd: root, env: historyGitEnv(), timeoutMs: opts.timeoutMs, input: oids.join("\n") + "\n",
    onStdoutBytes: (c) => { chunks.push(c); },
  });
  if (r.error !== undefined) throw new Error(r.error);
  if (!r.complete && !r.killed) throw new Error(`git cat-file failed: ${lastLine(r.stderr)}`);
  return Buffer.concat(chunks);
};

/** Runs one git command (the hardening flags prepended) and hands its
 *  stdout to `onLine` a line at a time, so a long log is never held whole.
 *  `complete` is false when it failed or was killed at the deadline. */
export type HistoryGitLines = (
  args: string[],
  opts: { cwd: string; input?: string; timeoutMs: number; onLine: (line: string) => void },
) => Promise<{ code: number; complete: boolean }>;

/** The production line runner: run by `runChild`, killed at the deadline. */
export const defaultHistoryGitLines: HistoryGitLines = async (args, opts) => {
  const cmd = historyGitCommand(args);
  let rest = "";
  const r = await runChild(cmd.file, cmd.args, {
    cwd: opts.cwd, env: historyGitEnv(), timeoutMs: opts.timeoutMs,
    ...(opts.input !== undefined ? { input: opts.input } : {}),
    onStdout: (c) => {
      const parts = (rest + c).split("\n");
      rest = parts.pop()!;
      for (const l of parts) opts.onLine(l);
    },
  });
  if (r.error !== undefined) return { code: 1, complete: false };
  if (rest !== "") opts.onLine(rest);
  return { code: r.code, complete: r.complete };
};

/** One change record of `git log --raw --no-abbrev` (`:<modes> <src> <dst>
 *  <status>\t<path>`): the two object names and the path, or null for any
 *  other line. Pure. */
export function parseRawRecord(line: string): { src: string; dst: string; path: string } | null {
  if (!line.startsWith(":")) return null;
  const tab = line.indexOf("\t");
  if (tab < 0) return null;
  const [, , src, dst] = line.slice(1, tab).split(" ");
  if (src === undefined || dst === undefined) return null;
  return { src, dst, path: unquoteGitPath(line.slice(tab + 1)) };
}

/** Each absolute path's level and deciding rule (the arbiter's catalog and
 *  labels). */
export type PathClassifier = (absPaths: string[]) => Array<{ level: string; rule: string | null }>;

export interface HistoryScanOptions {
  git?: HistoryGitRunner;
  /** The streaming runner for the logs that trace findings. */
  gitLines?: HistoryGitLines;
  readBlobs?: BlobBatchReader;
  /** Unset: no `catalog-path` detector and no coverage answer. */
  classifyPaths?: PathClassifier;
  /** Plan 14 §8.1: which of these absolute paths (gone from the work tree) a
   *  HUMAN label holds above `public`, the rule the launcher's object twins
   *  apply to history paths. Unset: a gone path never counts as covered. */
  labelledAbovePublic?: (absPaths: string[]) => boolean[];
  /** Plan 14 §8.2: the law's blob locks above `public`, as `sha1:<hex>` /
   *  `sha256:<hex>`. A locked blob is covered. */
  lockedBlobs?: ReadonlySet<string>;
  exists?: (p: string) => boolean;
  /** What earlier scans already know (secret-history-cache.ts). Unset:
   *  every call lists and reads the whole history. */
  cache?: HistoryScanCache;
  limits?: Partial<SecretHistoryLimits>;
  now?: () => number;
  /** Yield to the event loop (default: setImmediate); a test passes a no-op. */
  yieldNow?: () => Promise<void>;
}

/** Blobs read per `cat-file --batch` call, so memory holds one chunk. */
const CHUNK_BYTES = 32 * 1024 * 1024;
/** Matching yields to the event loop after this much work. */
const SLICE_MS = 15;
/** Roots one request may name. */
export const HISTORY_ROOTS_MAX = 8;

const mib = (n: number): string => `${Math.round((n / 1048576) * 10) / 10} MiB`;
const lastLine = (s: string): string => s.trim().split("\n").slice(-1)[0] || "git failed";

/**
 * Scan the reachable history of the repository holding each root. Never
 * throws for a git failure: what could not be read is in `capped`. The
 * result carries no blob content.
 */
export async function scanSecretHistory(roots: readonly string[], opts: HistoryScanOptions = {}): Promise<SecretHistoryScan> {
  const git = opts.git ?? defaultHistoryGitRunner;
  const gitLines = opts.gitLines ?? defaultHistoryGitLines;
  const readBlobs = opts.readBlobs ?? defaultBlobReader;
  const exists = opts.exists ?? existsSync;
  const now = opts.now ?? Date.now;
  const yieldNow = opts.yieldNow ?? (() => new Promise<void>((r) => setImmediate(r)));
  const limits: SecretHistoryLimits = { ...DEFAULT_HISTORY_LIMITS, ...(opts.limits ?? {}) };
  const t0 = now();
  const deadline = t0 + limits.timeoutMs;
  const left = (): number => Math.max(1, deadline - now());
  const late = (): boolean => now() >= deadline;
  const budget = `the ${Math.round(limits.timeoutMs / 1000)} s time budget (MANDU_HISTORY_SCAN_TIMEOUT_S)`;
  const scan: SecretHistoryScan = {
    repos: [],
    counts: { blobs: 0, scanned: 0, classified: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, readFailed: 0, binary: 0, pathsUnchecked: 0, untraced: 0, unlisted: false, lines: [] },
    findings: [], limits, ms: 0,
  };
  let totalRead = 0;
  // The reflogs' names, read from their files once per repository
  // (history-tips.ts): every call below that started from `--all --reflog`
  // starts from `--all` and these names on git's stdin, never fewer
  // commits; on any doubt git's own `--reflog` answers.
  const tipsGit = (root: string): TipsGit => (args, input) =>
    git(args, { cwd: root, timeoutMs: left(), ...(input !== undefined ? { input } : {}) });
  const reflogNames = new Map<string, Promise<ReflogNames>>();
  const namesOf = (root: string): Promise<ReflogNames> => {
    let p = reflogNames.get(root);
    if (p === undefined) { p = reflogNamesOf(tipsGit(root), root); reflogNames.set(root, p); }
    return p;
  };
  const seenRepos = new Set<string>();
  for (const root of roots.slice(0, HISTORY_ROOTS_MAX)) {
    if (!isAbsolute(root)) { scan.repos.push({ root, repoRoot: null, reason: "not an absolute path" }); continue; }
    const top = await git(["rev-parse", "--show-toplevel"], { cwd: root, timeoutMs: left() });
    const repoRoot = top.stdout.trim();
    if (top.code !== 0 || repoRoot === "") { scan.repos.push({ root, repoRoot: null, reason: "not in a git work tree" }); continue; }
    const rec: SecretHistoryScan["repos"][number] = { root, repoRoot };
    scan.repos.push(rec);
    if (seenRepos.has(repoRoot)) continue;
    seenRepos.add(repoRoot);
    await scanRepo(repoRoot, rec);
  }
  if (roots.length > HISTORY_ROOTS_MAX) scan.capped.lines.push(`${roots.length - HISTORY_ROOTS_MAX} root(s) over ${HISTORY_ROOTS_MAX} not scanned`);
  const c = scan.capped;
  if (c.tooBig > 0) c.lines.push(`${c.tooBig} blob(s) over ${mib(limits.blobMaxBytes)} not read (MANDU_HISTORY_SCAN_BLOB_MAX_KB)`);
  if (c.overTotal > 0) c.lines.push(`${c.overTotal} blob(s) not read: over the ${mib(limits.totalMaxBytes)} total (MANDU_HISTORY_SCAN_MAX_MB)`);
  if (c.overTime > 0) c.lines.push(`${c.overTime} blob(s) not read: ${budget} ran out`);
  if (c.readFailed > 0) c.lines.push(`${c.readFailed} blob(s) not read: git failed to hand them over`);
  if (c.binary > 0) c.lines.push(`${c.binary} binary blob(s) skipped`);
  if (c.pathsUnchecked > 0) c.lines.push(`${c.pathsUnchecked} deleted path(s) not checked against the catalog (over ${limits.classifyMax})`);
  if (c.untraced > 0) c.lines.push(`${c.untraced} finding(s) not traced to their commits (over ${limits.traceMax}, or the time budget ran out)`);
  scan.ms = now() - t0;
  return scan;

  /** The cache key of a repository (secret-history-cache.ts), or null when
   *  it is not cacheable: a shallow clone (its file rewrites what is
   *  reachable without moving a tip), or a git call that failed. Grafts no
   *  longer count: every hardened call reads an empty graft file
   *  (hardened-git.ts, GIT_GRAFT_FILE=/dev/null, which `--git-path
   *  info/grafts` now names), so a repository's `info/grafts` rewrites
   *  nothing the scan lists. */
  async function cacheKeyOf(root: string): Promise<{ base: string; tips: string[] } | null> {
    const rp = await git(["rev-parse", "--show-object-format", "--is-shallow-repository"], { cwd: root, timeoutMs: left() });
    const [format, shallow] = rp.stdout.split("\n").map((l) => l.trim());
    if (rp.code !== 0 || !format || shallow !== "false") return null;
    const ver = await git(["version"], { cwd: root, timeoutMs: left() });
    // What `rev-list --all --reflog --no-walk` names, the reflogs read once.
    const revs = await historyTipsOf(tipsGit(root), await namesOf(root));
    const refs = await git(["for-each-ref", "--format=%(objectname) %(refname)"], { cwd: root, timeoutMs: left() });
    if (ver.code !== 0 || "error" in revs || refs.code !== 0) return null;
    // Every ref's own object too: a tag of a tree or a blob is a tip no
    // commit walk names.
    const tips = new Set<string>(revs.tips);
    const replace: string[] = [];
    for (const l of refs.stdout.split("\n")) {
      const [oid, ref] = l.split(" ");
      if (oid === undefined || !HEX_OID.test(oid)) continue;
      tips.add(oid);
      if (ref?.startsWith("refs/replace/")) replace.push(l);
    }
    return {
      base: historyCacheBase({ detector: historyDetectorFingerprint(), objectFormat: format, gitVersion: ver.stdout, replaceRefs: replace.sort().join("\n") }),
      tips: [...tips].sort(),
    };
  }

  /** The global options the scan's listing and walks run with: the history
   *  walk's shallow rule (history-labels.ts walkShallowRule), so what the
   *  scan reads is what the object twins walk (a shallow file is honoured
   *  only where it is true). A failure to tell ignores the shallow file. */
  async function shallowArgsOf(root: string): Promise<string[]> {
    const rp = await git(["rev-parse", "--show-object-format", "--git-path", "shallow"], { cwd: root, timeoutMs: left() });
    const [fmt, path] = rp.stdout.split("\n").map((l) => l.trim());
    if (rp.code !== 0 || (fmt !== "sha1" && fmt !== "sha256") || !path) return [...IGNORE_SHALLOW_ARGS];
    let text = "";
    try { text = readFileSync(isAbsolute(path) ? path : join(root, path), "utf8"); } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") return [...IGNORE_SHALLOW_ARGS];
    }
    const rule = await walkShallowRule(
      async (args, input) => { const r = await git(args, { cwd: root, input, timeoutMs: left() }); return { code: r.code, stdout: r.stdout }; },
      text, fmt === "sha256" ? 64 : 40,
    );
    return rule.args;
  }

  async function scanRepo(root: string, rec: SecretHistoryScan["repos"][number]): Promise<void> {
    const cache = opts.cache;
    const sh = await shallowArgsOf(root);
    const keyed = cache ? await cacheKeyOf(root) : null;
    const entry = cache && keyed ? cache.load(root) : null;
    let plan: HistoryScanPlan = keyed ? planHistoryScan(entry, root, keyed.base, keyed.tips) : { kind: "fresh" };
    const prior: HistoryScanCacheEntry | null = plan.kind === "fresh" ? null : entry;
    const use: SecretHistoryCacheUse | undefined = cache ? { plan: keyed ? plan.kind : "off", read: 0, stored: false } : undefined;
    if (use) rec.cache = use;

    // Every object reachable from a ref, the reflog or the stash, with the
    // path it was reached by: from the cache where it is current, else
    // listed (only the new tips' objects when the old tips are all still
    // there). A history too large to list in the budget scans nothing rather
    // than a biased part.
    const priorBlobs = new Map<string, { size: number; path: string | null }>();
    for (const [o, size, path] of prior?.blobs ?? []) priorBlobs.set(o, { size, path });
    let listed = new Map<string, string | null>();
    let rangeInput: string | null = null;
    if (plan.kind === "incremental") {
      rangeInput = `${plan.include.join("\n")}\n${plan.exclude.map((t) => `^${t}`).join("\n")}\n`;
      const r = await git([...sh, "rev-list", "--objects", "--stdin"], { cwd: root, input: rangeInput, timeoutMs: left() });
      if (r.code === 0) listed = parseRevListObjects(r.stdout);
      else { plan = { kind: "relist" }; rangeInput = null; if (use) use.plan = "relist"; }
    }
    if (plan.kind === "fresh" || plan.kind === "relist") {
      const from = reflogRevArgs(await namesOf(root));
      const rl = await git([...sh, "rev-list", ...from.args, "--objects"], {
        cwd: root, timeoutMs: left(), ...(from.input !== undefined ? { input: from.input } : {}),
      });
      if (rl.code !== 0) {
        scan.capped.unlisted = true;
        scan.capped.lines.push(late()
          ? `${root}: the history could not be listed within ${budget}; nothing was scanned`
          : `${root}: the history could not be listed (${lastLine(rl.stderr)}); nothing was scanned`);
        return;
      }
      listed = parseRevListObjects(rl.stdout);
    }
    const idx = await git(["ls-files", "-s", "-z"], { cwd: root, timeoutMs: left() });
    const index = idx.code === 0 ? parseIndexOrTree(idx.stdout) : new Map<string, string[]>();
    if (idx.code !== 0) scan.capped.lines.push(`${root}: the index could not be read (${lastLine(idx.stderr)})`);
    const ht = await git(["ls-tree", "-r", "-z", "--full-tree", "HEAD"], { cwd: root, timeoutMs: left() });
    const head = ht.code === 0 ? parseIndexOrTree(ht.stdout) : new Map<string, string[]>();

    // Which named objects are blobs, and how large: asked only of what the
    // cache does not already know (a blob's name fixes its type and size).
    const reach = new Map<string, { size: number; path: string | null }>();
    if (plan.kind === "hit" || plan.kind === "incremental") for (const [o, v] of priorBlobs) reach.set(o, v);
    const unknown = new Set<string>();
    const ask = (o: string): void => { if (!reach.has(o) && !priorBlobs.has(o)) unknown.add(o); };
    for (const o of listed.keys()) ask(o);
    for (const o of index.keys()) ask(o);
    for (const o of head.keys()) ask(o);
    const bc = unknown.size === 0
      ? { code: 0, stdout: "", stderr: "" }
      : await git(["cat-file", "--batch-check"], { cwd: root, input: [...unknown].join("\n") + "\n", timeoutMs: left() });
    if (bc.code !== 0) {
      scan.capped.unlisted = true;
      scan.capped.lines.push(late()
        ? `${root}: the objects could not be sized within ${budget}; nothing was scanned`
        : `${root}: the objects could not be sized (${lastLine(bc.stderr)}); nothing was scanned`);
      return;
    }
    const kinds = parseBatchCheck(bc.stdout);
    const sizeOf = (o: string): number | null => {
      const k = kinds.get(o);
      if (k !== undefined) return k.type === "blob" ? k.size : null;
      return reach.get(o)?.size ?? priorBlobs.get(o)?.size ?? null;
    };
    for (const [o, p] of listed) {
      const size = sizeOf(o);
      if (size !== null && !reach.has(o)) reach.set(o, { size, path: p });
    }

    const paths = new Map<string, Set<string>>();
    const addPath = (oid: string, p: string): void => {
      const s = paths.get(oid) ?? new Set<string>();
      s.add(p);
      paths.set(oid, s);
    };
    for (const [oid, { path }] of reach) if (path !== null) addPath(oid, path);
    for (const [oid, ps] of index) for (const p of ps) addPath(oid, p);
    for (const [oid, ps] of head) for (const p of ps) addPath(oid, p);

    const blobs = [...paths.keys()].filter((o) => sizeOf(o) !== null);
    scan.counts.blobs += blobs.length;

    // What earlier scans read is not read again: a blob's name is its
    // content. Only the blobs actually read are recorded, so what a cap
    // leaves unread here is read by the next call.
    const scanned = new Set(prior?.scanned ?? []);
    const binary = new Set(prior?.binary ?? []);
    const hits = new Map<string, ShapeHit[]>(Object.entries(prior?.hits ?? {}));

    // History-only blobs first (in no file of HEAD, not staged): a cap cuts
    // what the working tree already shows before it cuts history.
    const historyOnly = (o: string): boolean => !head.has(o) && !index.has(o);
    const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
    const order = blobs.filter((o) => !scanned.has(o) && !binary.has(o))
      .sort((a, b) => Number(historyOnly(b)) - Number(historyOnly(a)) || cmp(a, b));
    const toRead: string[] = [];
    for (const o of order) {
      const size = sizeOf(o)!;
      if (size > limits.blobMaxBytes) { scan.capped.tooBig++; continue; }
      if (totalRead + size > limits.totalMaxBytes) { scan.capped.overTotal++; continue; }
      totalRead += size;
      toRead.push(o);
    }

    // A chunk that comes back short before the deadline is git failing (the
    // sandbox did not start, an object is missing), not the time budget: it
    // is counted apart, named, and the next chunk is still read.
    let read = 0;
    let failed = 0;
    let i = 0;
    let slice = now();
    reading: while (i < toRead.length && !late()) {
      const chunk: string[] = [];
      let bytes = 0;
      while (i < toRead.length && (chunk.length === 0 || bytes + sizeOf(toRead[i]!)! <= CHUNK_BYTES)) {
        bytes += sizeOf(toRead[i]!)!;
        chunk.push(toRead[i++]!);
      }
      let objs: BatchObject[];
      try {
        objs = parseBatchOutput(await readBlobs(root, chunk, { timeoutMs: left() }));
      } catch (e) {
        if (late()) break reading;
        failed += chunk.length;
        scan.capped.lines.push(`${root}: blob contents could not be read (${(e as Error).message})`);
        continue;
      }
      let got = 0;
      for (const o of objs) {
        if (o.type !== "blob") continue;
        got++;
        read++;
        if (isBinaryBlob(o.content)) { binary.add(o.oid); continue; }
        scanned.add(o.oid);
        const h = detectSecretShapes(o.content.toString("utf8"));
        if (h.length > 0) hits.set(o.oid, h);
        if (now() - slice >= SLICE_MS) { await yieldNow(); slice = now(); }
      }
      if (got < chunk.length) {
        if (late()) break reading; // the reader was stopped at the deadline
        failed += chunk.length - got;
        scan.capped.lines.push(`${root}: ${chunk.length - got} of ${chunk.length} blob(s) asked of git did not come back`);
      }
    }
    scan.capped.readFailed += failed;
    if (read + failed < toRead.length) scan.capped.overTime += toRead.length - read - failed;
    if (use) use.read = read;
    for (const o of blobs) {
      if (scanned.has(o)) scan.counts.scanned++;
      else if (binary.has(o)) scan.capped.binary++;
    }

    // The catalog detector: paths a blob had that no longer exist in the
    // work tree, asked of the arbiter's catalog and labels (never cached:
    // the work tree and the law move without history moving).
    const byName = new Map<string, Array<{ path: string; rule: string; level: string }>>();
    if (opts.classifyPaths) {
      const gone = new Map<string, string[]>(); // path → blobs
      for (const o of blobs) {
        for (const p of paths.get(o) ?? []) {
          if (exists(join(root, p))) continue;
          const l = gone.get(p) ?? [];
          l.push(o);
          gone.set(p, l);
        }
      }
      const asked = [...gone.keys()].sort().slice(0, limits.classifyMax);
      scan.capped.pathsUnchecked += gone.size - asked.length;
      scan.counts.classified += asked.length;
      const levels = asked.length > 0 ? opts.classifyPaths(asked.map((p) => join(root, p))) : [];
      levels.forEach((l, k) => {
        if (l.level === "public" || l.rule === null) return;
        const rel = asked[k]!;
        for (const o of gone.get(rel) ?? []) {
          const list = byName.get(o) ?? [];
          list.push({ path: rel, rule: l.rule, level: l.level });
          byName.set(o, list);
        }
      });
    }

    // The traces the cache holds are current at its tips: all of them on a
    // hit; on new tips, those of blobs no new commit adds or removes (one
    // log over only the new commits); none after a rewrite.
    const traces = new Map<string, HistoryScanTrace>();
    if (prior !== null && (plan.kind === "hit" || plan.kind === "incremental")) {
      const known = Object.keys(prior.traces);
      let touched: Set<string> | null = new Set();
      if (plan.kind === "incremental" && known.length > 0) {
        const t = new Set<string>();
        const lg = await gitLines([...sh, "log", "--stdin", "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H"], {
          cwd: root, input: rangeInput ?? "", timeoutMs: left(),
          onLine: (line) => {
            const rec = parseRawRecord(line);
            if (rec !== null) { t.add(rec.src); t.add(rec.dst); }
          },
        });
        touched = lg.complete ? t : null;
      }
      if (touched !== null) for (const o of known) if (!touched.has(o)) traces.set(o, prior.traces[o]!);
    }

    const inBlobs = new Set(blobs);
    const firstPath = (o: string): string => [...(paths.get(o) ?? [])].sort()[0] ?? "";
    const found = [...new Set([...[...hits.keys()].filter((o) => inBlobs.has(o)), ...byName.keys()])]
      .sort((a, b) => Number(historyOnly(b)) - Number(historyOnly(a)) || cmp(firstPath(a), firstPath(b)) || cmp(a, b));

    // Trace what the cache does not: one finding by its own `--find-object`
    // walk; more in ONE pass over the whole history (a walk costs the same
    // for one object as for all of them), streamed, killed at the deadline.
    const need = found.filter((o) => !traces.has(o)).slice(0, limits.traceMax);
    const whole: { args: string[]; input?: string } = need.length > 0 && !late() ? reflogRevArgs(await namesOf(root)) : { args: [] };
    const wholeInput = whole.input !== undefined ? { input: whole.input } : {};
    if (need.length === 1 && !late()) {
      const oid = need[0]!;
      const lg = await git(
        [...sh, "log", ...whole.args, "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H", `--find-object=${oid}`],
        { cwd: root, timeoutMs: left(), ...wholeInput },
      );
      if (lg.code === 0) {
        const parsed = parseFindObjectLog(lg.stdout, oid);
        traces.set(oid, { first: parsed.commits.at(-1) ?? null, last: parsed.commits[0] ?? null, paths: parsed.paths });
      }
    } else if (need.length > 1 && !late()) {
      const want = new Set(need);
      const acc = new Map<string, { commits: string[]; paths: Set<string> }>();
      let commit: string | null = null;
      const lg = await gitLines([...sh, "log", ...whole.args, "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H"], {
        cwd: root, timeoutMs: left(), ...wholeInput,
        onLine: (line) => {
          if (line.startsWith("commit ")) { commit = line.slice(7).trim(); return; }
          const rec = parseRawRecord(line);
          // A mode change (the same object on both sides) is not a change
          // of where the blob lives, as `--find-object` also reads it.
          if (rec === null || rec.src === rec.dst) return;
          for (const o of [rec.src, rec.dst]) {
            if (!want.has(o)) continue;
            const a = acc.get(o) ?? { commits: [], paths: new Set<string>() };
            if (commit !== null && !a.commits.includes(commit)) a.commits.push(commit);
            a.paths.add(rec.path);
            acc.set(o, a);
          }
        },
      });
      if (lg.complete) {
        for (const o of need) {
          const a = acc.get(o);
          traces.set(o, { first: a?.commits.at(-1) ?? null, last: a?.commits[0] ?? null, paths: a ? [...a.paths].sort() : [] });
        }
      }
    }

    const foundTraces: Record<string, HistoryScanTrace> = {};
    for (const oid of found) {
      let firstCommit: string | null = null;
      let lastCommit: string | null = null;
      const t = traces.get(oid);
      if (t !== undefined) {
        firstCommit = t.first;
        lastCommit = t.last;
        for (const p of t.paths) addPath(oid, p);
        foundTraces[oid] = t;
      }
      const ps = [...(paths.get(oid) ?? [])].sort();
      const present = ps.filter((p) => exists(join(root, p)));
      const gonePaths = ps.filter((p) => !present.includes(p));
      const covered = (present.length > 0 && opts.classifyPaths !== undefined
        && opts.classifyPaths(present.map((p) => join(root, p))).some((l) => l.level !== "public" && l.rule !== null))
        || (opts.lockedBlobs?.has(`${oid.length === 64 ? "sha256" : "sha1"}:${oid}`) ?? false)
        || (gonePaths.length > 0 && opts.labelledAbovePublic !== undefined && opts.labelledAbovePublic(gonePaths.map((p) => join(root, p))).some(Boolean));
      const detectors: SecretHistoryDetector[] = [
        ...(inBlobs.has(oid) ? hits.get(oid) ?? [] : []).map((h) => ({ kind: "content-shape" as const, rule: h.shape, line: h.line, preview: h.preview })),
        ...(byName.get(oid) ?? []).map((n) => ({ kind: "catalog-path" as const, rule: n.rule, path: n.path, level: n.level })),
      ];
      if (firstCommit === null && !index.has(oid)) scan.capped.untraced++;
      scan.findings.push({
        repoRoot: root,
        blob: oid,
        paths: ps,
        firstCommit,
        lastCommit,
        inHead: head.has(oid),
        inIndex: index.has(oid),
        stillPresent: present.length > 0,
        pathStillSecretByCatalog: covered,
        detector: detectors[0]!,
        detectors,
      });
    }

    // Write back what is known now, pruned to what is still reachable or
    // staged. Nothing listed failed above, so `reach` is the whole reachable
    // set at the keyed tips.
    if (cache && keyed && use) {
      const keep = (o: string): boolean => reach.has(o) || index.has(o);
      const next: HistoryScanCacheEntry = {
        v: 1,
        repoRoot: root,
        base: keyed.base,
        tips: keyed.tips,
        blobs: [...reach].map(([o, v]) => [o, v.size, v.path]),
        scanned: [...scanned].filter(keep).sort(),
        binary: [...binary].filter(keep).sort(),
        hits: Object.fromEntries([...hits].filter(([o]) => keep(o)).sort(([a], [b]) => cmp(a, b))),
        traces: foundTraces,
      };
      const same = plan.kind === "hit" && read === 0 && prior !== null
        && next.scanned.length === prior.scanned.length && next.binary.length === prior.binary.length
        && Object.keys(next.hits).length === Object.keys(prior.hits).length
        && Object.keys(next.traces).length === Object.keys(prior.traces).length
        && Object.keys(next.traces).every((o) => prior.traces[o] !== undefined);
      if (same) cache.touch(root);
      else use.stored = cache.save(next);
    }
  }
}
