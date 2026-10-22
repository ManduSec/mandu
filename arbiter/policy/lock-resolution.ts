/**
 * lock-resolution — every path label resolved to the blob ids of its
 * versions, in every known repository, in the background
 * (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md §11.1 R2).
 *
 * A lock is a label on a path (policy.yaml `paths:`, the dashboard's "Lock
 * it") or on an object (`blobs:`). The launcher's object twins turn a path
 * label into the versions it must hide by walking a repository's history
 * at launch, and only for the repositories that launch prepares. This
 * module does the same walk in the arbiter, for every repository the
 * registry knows (known-repos.ts, R1), ahead of any launch:
 *
 *   - per repository: the history blobs of every path a human label puts
 *     above `public` (gone paths and patterns included), plus the index's,
 *     decided by the launcher's own rule (history-labels.ts, a pinned copy);
 *   - the GLOBAL LOCKED SET: the union over every repository, with the
 *     `blobs:` locks above `public`, per object format. An object id is its
 *     content's hash, so a clone or a fork holding the same blob is covered
 *     with no work of its own.
 *
 * The walk is the launcher's (the same arguments, the same bound by the
 * labels' literal prefixes, the same keep rule), cached per repository by
 * (root, labels + pathspecs, base, tips): an unchanged repository is not
 * walked again, new commits walk only themselves. The tips are every ref
 * and every reflog entry, the reflogs read from their files once
 * (history-tips.ts over ../src/reflog-tips.ts, the launcher's reader;
 * git's own `--reflog` on any doubt), never fewer than `git rev-list --all
 * --reflog --no-walk` names. Each resolution carries
 * its `resolutionKey`; the launcher skips its own label walk for a
 * repository only when it computes the SAME key (so a stale answer costs
 * a walk, never a version).
 *
 * git runs HARDENED (secret-history-scan.ts `historyGitCommand`, over
 * ../src/hardened-git.ts: no pager, literal pathspecs, every program a
 * repository can name by a key git knows forced off, no inherited `GIT_*`,
 * the git sandbox where one can be made, bubblewrap on Linux or Seatbelt on
 * macOS; docs/design/architecture/write-protection.md §8):
 * the registry holds repositories the agent can create and configure, and
 * none of the commands used runs a hook, a filter or a diff driver.
 * Nothing here reads a blob's content: only names and paths.
 *
 * THE CACHE IS AN ENFORCEMENT CACHE (§11.2): an entry that listed fewer
 * versions would leave a locked blob out of the set. It lives in this
 * process's memory and in mandu.db (`lock_resolutions`, the arbiter's
 * single-writer DB), never in a plain file under `state/`. Its rows are
 * SEALED (§11.2, cache-seals.ts, kind `lock-resolution`, key the first 32
 * hex of sha256(root)): a row is loaded at start only when a seal of the
 * current epoch vouches for its bytes, so a row an unconfined same-uid
 * writer of mandu.db changed is void once its unconfined period ends (the
 * epoch rotates); memory is never re-read from the DB while running.
 *
 * Bounds: one cycle at a time, two repositories at once, 120 s a
 * repository (a repository that fails is retried after an hour unless
 * asked for by name), 50 000 labelled versions a repository and 200 000 in
 * the set (over either, the repository is left PENDING: the launcher walks
 * it itself and a consumer of the set is told it is incomplete).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. The walk, its cache
 * plan and the index read are ported from launcher/src/git-object-twins.ts
 * (`historyBlobsOf`, `planWalk`, `labelledBlobsOf`, `parseRawLogBlobPaths`,
 * `parseLsFilesStagePaths`); tests/stack/
 * lock-resolution-parity.test.ts runs both over one corpus.
 */
import { runChild, type RunningChild } from "../src/child-run.js";
import { existsSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import Database from "../db/sqlite.js";
import {
  compileHistoryLabels, HISTORY_WALK_ARGS, historyPathspecs, labelFilterKey, labelledAbovePublic, labelWalkKey, realSpellingOf,
  resolutionKey, walkBaseKey, walkShallowRule, withRealSpellings, type CompiledHistoryLabels, type HistoryLabel,
} from "./history-labels.js";
import {
  findRepositories, isUnderAny, isWorkTreeRoot, KnownRepoStore, manduOwnDirs, workTreeRootAt, type RegistryLimits, type RepoSource, type RepoWalkLimits,
  type RepoWalkResult,
} from "./known-repos.js";
import { historyGitCommand, historyGitEnv } from "./secret-history-scan.js";
import { CACHE_SEAL_KINDS, sha256Hex, type CacheSealGate } from "./cache-seals.js";
import { historyTipsOf, reflogNamesOf, type TipsGit } from "./history-tips.js";

// ── Pure: git output ────────────────────────────────────────────────────────

const ZERO = /^0+$/;
const HEX = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

/**
 * `git log --raw -z --no-abbrev --format=` output, fed in chunks: every
 * (blob, path) of both sides of every change record, gitlinks (mode 160000)
 * and the all-zero name of a missing side left out. The streaming form of
 * the launcher's `parseRawLogBlobPaths` (the same tokens, the same rule), so
 * a whole history is never held as one string.
 */
export class RawLogBlobPaths {
  private rest = "";
  private header: string | null = null;
  constructor(private readonly emit: (blob: string, path: string) => void) {}

  feed(chunk: string): void {
    const parts = (this.rest + chunk).split("\0");
    this.rest = parts.pop()!;
    for (const tok of parts) this.token(tok);
  }

  /** The end of the output: a header with no path after it is dropped (as
   *  the launcher's parser drops it). */
  end(): void {
    this.rest = "";
    this.header = null;
  }

  private token(tok: string): void {
    if (this.header !== null) {
      const [srcMode, dstMode, src, dst] = this.header.slice(1).split(" ");
      this.header = null;
      if (src !== undefined && HEX.test(src) && !ZERO.test(src) && srcMode !== "160000") this.emit(src, tok);
      if (dst !== undefined && HEX.test(dst) && !ZERO.test(dst) && dstMode !== "160000") this.emit(dst, tok);
      return;
    }
    const t = tok.replace(/^\n+/, "");
    if (t.startsWith(":")) this.header = t;
  }
}

/** Every (blob, path) of `git ls-files -s -z` output (every stage). Pure. */
export function parseLsFilesStagePaths(out: string): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  for (const rec of out.split("\0")) {
    const m = /^(\d{6}) ([0-9a-f]+) \d\t(.*)$/s.exec(rec);
    if (m && m[1] !== "160000" && HEX.test(m[2]!)) found.push([m[2]!, m[3]!]);
  }
  return found;
}

// ── Pure: the resolution and its plan ───────────────────────────────────────

/** One repository resolved (memory + mandu.db `lock_resolutions`). */
export interface RepoResolution {
  v: 1;
  /** The real work-tree root. */
  root: string;
  format: "sha1" | "sha256";
  /** labelFilterKey: the labels (real spellings included) + the pathspecs. */
  filter: string;
  /** The pathspecs that bounded the walk ([] = the whole history). */
  specs: string[];
  /** walkBaseKey. */
  base: string;
  /** Every ref, every reflog entry, at resolution. */
  tips: string[];
  /** The labelled versions the history holds. */
  history: string[];
  /** The labelled versions the index held at resolution. */
  index: string[];
  /** resolutionKey(root, filter, base, tips). */
  key: string;
  at: number;
}

export type ResolutionPlan =
  | { kind: "hit" }
  | { kind: "incremental"; include: string[]; exclude: string[] }
  | { kind: "full" };

/** How to bring a cached resolution up to date (the launcher's `planWalk`):
 *  the same root, filter, base and pathspecs, and no new tip is a hit (a tip
 *  gone away leaves the cached names a superset, which only hides more);
 *  new tips walk only what the old tips cannot reach. Anything else walks
 *  the whole history. Pure. */
export function planResolution(
  prior: RepoResolution | null, root: string, filter: string, specs: readonly string[], base: string, tips: readonly string[],
): ResolutionPlan {
  if (prior === null || prior.v !== 1 || prior.root !== root || prior.base !== base || prior.filter !== filter) return { kind: "full" };
  const want = [...specs].sort();
  if (prior.specs.length !== want.length || prior.specs.some((s, i) => s !== want[i])) return { kind: "full" };
  const old = new Set(prior.tips);
  const include = tips.filter((t) => !old.has(t));
  if (include.length === 0) return { kind: "hit" };
  return { kind: "incremental", include, exclude: [...prior.tips] };
}

/** A resolution as read back from mandu.db, or null when it is not a
 *  well-formed one (the repository is walked whole). Pure. */
export function parseResolution(text: string): RepoResolution | null {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return null; }
  if (typeof j !== "object" || j === null) return null;
  const e = j as Record<string, unknown>;
  const strs = (v: unknown, re?: RegExp): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string" && (re === undefined || re.test(x)));
  if (e["v"] !== 1 || typeof e["root"] !== "string" || typeof e["filter"] !== "string" || typeof e["base"] !== "string" || typeof e["key"] !== "string") return null;
  if (e["format"] !== "sha1" && e["format"] !== "sha256") return null;
  const name = e["format"] === "sha256" ? /^[0-9a-f]{64}$/ : /^[0-9a-f]{40}$/;
  if (!strs(e["specs"]) || !strs(e["tips"], HEX) || !strs(e["history"], name) || !strs(e["index"], name) || typeof e["at"] !== "number") return null;
  return {
    v: 1, root: e["root"], format: e["format"], filter: e["filter"], specs: e["specs"], base: e["base"], tips: e["tips"],
    history: e["history"], index: e["index"], key: e["key"], at: e["at"],
  };
}

/** The work trees the labels above `public` name (a literal path, or a
 *  pattern's literal prefix, through its nearest existing folder): the
 *  registry's `label` source. Pure given `rootAt`. */
export function labelRepoRoots(c: CompiledHistoryLabels, rootAt: (p: string) => string | null): string[] {
  const out = new Set<string>();
  for (const l of c.labels) {
    if (l.level === "public") continue;
    const base = l.glob ? (l.compiled?.literalPrefix ?? "") : l.path;
    if (base === "") continue;
    const root = rootAt(base);
    if (root !== null) out.add(root);
  }
  return [...out].sort();
}

/** The locked ids of `blobs:` (`sha1:<hex>` / `sha256:<hex>`) split by
 *  object format, bare. Pure. */
export function splitBlobLocks(ids: readonly string[]): { sha1: string[]; sha256: string[] } {
  const sha1 = new Set<string>();
  const sha256 = new Set<string>();
  for (const id of ids) {
    const m = /^(sha1|sha256):([0-9a-f]+)$/.exec(id);
    if (m === null) continue;
    if (m[1] === "sha1" && m[2]!.length === 40) sha1.add(m[2]!);
    if (m[1] === "sha256" && m[2]!.length === 64) sha256.add(m[2]!);
  }
  return { sha1: [...sha1].sort(), sha256: [...sha256].sort() };
}

// ── The answer (`gitHistoryLocks`, plan 14 §11.1) ────────────────────────────

export interface LockedSetAnswer {
  /** The GLOBAL LOCKED SET: every repository's labelled versions and the
   *  `blobs:` locks above `public`, per object format, bare hex names. */
  lockedSet: { sha1: string[]; sha256: string[] };
  /** The repositories resolved under the labels in force that hold a
   *  labelled version (and each root the caller named, resolved, even with
   *  none): the key the launcher compares and the versions. */
  repos: Array<{ root: string; format: "sha1" | "sha256"; key: string; blobs: string[] }>;
  /** Every known repository is resolved under the labels in force. */
  complete: boolean;
  /** The known repositories that are not: not resolved yet, the last
   *  attempt failed, or over a cap. Their earlier versions stay in
   *  `lockedSet` (a superset only hides more). */
  pending: string[];
}

// ── The git seam ────────────────────────────────────────────────────────────

export interface ResolverGitRun {
  code: number;
  stdout: string;
  stderr: string;
  /** False when killed at the deadline or stopped. */
  complete: boolean;
}

/** Runs one hardened git command. With `onChunk`, stdout is handed over as
 *  it arrives and not kept. */
export type ResolverGit = (
  args: string[],
  opts: { cwd: string; input?: string; timeoutMs: number; onChunk?: (s: string) => void },
) => Promise<ResolverGitRun>;

/** The production runner: `git` with HARDENED_GIT_ARGS and the scrubbed
 *  environment (secret-history-scan.ts `historyGitCommand`, in the git
 *  sandbox where one can be made), run by ../src/child-run.ts `runChild`
 *  (its own process group, SIGKILL to the group at the deadline, settled
 *  even when a sandbox child orphaned in its start-up holds the pipes:
 *  write-protection.md §8.5.1); `children` tracks what runs so `stop` can kill
 *  it. */
export function hardenedResolverGit(children: Set<RunningChild>): ResolverGit {
  return async (args, opts) => {
    let cmd: { file: string; args: string[] };
    try {
      cmd = historyGitCommand(args);
    } catch (e) {
      return { code: 1, stdout: "", stderr: (e as Error).message, complete: false };
    }
    const r = await runChild(cmd.file, cmd.args, {
      cwd: opts.cwd, env: historyGitEnv(), timeoutMs: opts.timeoutMs,
      ...(opts.input !== undefined ? { input: opts.input } : {}),
      ...(opts.onChunk ? { onStdout: opts.onChunk } : {}),
    }, children);
    return { code: r.code, stdout: r.stdout, stderr: r.stderr, complete: r.complete };
  };
}

// ── The resolver ────────────────────────────────────────────────────────────

export interface ResolverLimits {
  /** Repositories resolved at once. */
  concurrency: number;
  /** One repository's git calls, together. */
  repoTimeoutMs: number;
  /** Labelled versions one repository may hold before it is left pending. */
  maxRepoBlobs: number;
  /** Ids the global locked set may hold. */
  maxLockedSet: number;
  /** A repository whose resolution failed waits this long before it is
   *  tried again (unless it is asked for by name). */
  retryFailedMs: number;
}

export const DEFAULT_RESOLVER_LIMITS: ResolverLimits = {
  concurrency: 2,
  repoTimeoutMs: 120_000,
  maxRepoBlobs: 50_000,
  maxLockedSet: 200_000,
  retryFailedMs: 3600_000,
};

/** When the background work runs (the daemon's; an embedder or a test gets
 *  only what it asks for). */
export interface ResolverSchedule {
  /** Walk HOME for repositories at start and every `homeWalkMs`. */
  walkHome: boolean;
  /** First cycle (and walk) this long after `start`. */
  startDelayMs: number;
  /** A cycle (new commits, labels) every this long. */
  cycleMs: number;
  homeWalkMs: number;
  /** How often the labels are compared with the last cycle's. */
  labelPollMs: number;
}

export const DAEMON_SCHEDULE: ResolverSchedule = {
  walkHome: true,
  startDelayMs: 5_000,
  cycleMs: 15 * 60_000,
  homeWalkMs: 6 * 3600_000,
  labelPollMs: 10_000,
};

export interface LockResolverOptions {
  /** The human labels, wire form (`gitHistoryLocks` `labels`). */
  labels: () => HistoryLabel[];
  /** The `blobs:` locks above `public` (`sha1:<hex>` / `sha256:<hex>`). */
  blobLocks: () => string[];
  /** mandu.db; omit for memory only (tests). */
  dbPath?: string;
  /** The HOME the walk starts at and the Mandu home is found under. */
  home: string;
  /** fs-sync's view state base (pruned). */
  stateBase?: string;
  env?: Readonly<Record<string, string | undefined>>;
  git?: ResolverGit;
  realpath?: (p: string) => string | null;
  isRoot?: (dir: string) => boolean;
  log?: (m: string) => void;
  now?: () => number;
  limits?: Partial<ResolverLimits>;
  walkLimits?: Partial<RepoWalkLimits>;
  /** The registry's caps (known-repos.ts DEFAULT_REGISTRY_LIMITS). */
  registryLimits?: Partial<RegistryLimits>;
  /** Set: the background schedule runs after `start`. Unset: nothing runs
   *  until asked (`kick`, a registration, `runCycle`). */
  schedule?: ResolverSchedule;
  /** Plan 14 §11.2: the seals the DB rows are loaded by (the server passes
   *  its store). Unset: every well-formed row is loaded (a test knob). */
  seals?: CacheSealGate;
  /** Mandu's own code directory (install-tree prune); a test knob. */
  selfDir?: string | null;
  /** The host platform the HOME walk's macOS prune keys on
   *  (known-repos.ts `findRepositories`, which re-enters a pruned folder
   *  for the labels this resolver locks by); default this process's. A
   *  test knob. */
  platform?: NodeJS.Platform;
  /** Called after every cycle (plan 14 §11.1 R3: the prepared copies follow
   *  the locked set). */
  onCycle?: () => void;
}

const CACHE_SQL = `
CREATE TABLE IF NOT EXISTS lock_resolutions (
  root  TEXT PRIMARY KEY,
  entry TEXT NOT NULL
);
`;

/** The labels as the resolver uses them, recomputed per cycle. */
interface LabelView {
  labels: HistoryLabel[];
  compiled: CompiledHistoryLabels;
  labelKey: string;
}

/** A resolution row's seal key (plan 14 §11.2): 32 hex of sha256(root). */
export function resolutionSealKey(root: string): string {
  return sha256Hex(Buffer.from(root, "utf8")).slice(0, 32);
}

/** Roots one `gitHistoryLocks` request may name. */
export const LAUNCH_ROOTS_MAX = 16;

export class LockResolver {
  readonly registry: KnownRepoStore;
  private readonly cache = new Map<string, RepoResolution>();
  private readonly failures = new Map<string, { at: number; reason: string }>();
  private readonly db?: InstanceType<typeof Database>;
  private readonly children = new Set<RunningChild>();
  private readonly git: ResolverGit;
  private readonly realpath: (p: string) => string | null;
  private readonly isRoot: (dir: string) => boolean;
  private readonly log: (m: string) => void;
  private readonly now: () => number;
  private readonly limits: ResolverLimits;
  private readonly ownDirs: string[];
  private readonly timers: NodeJS.Timeout[] = [];
  private readonly priority = new Set<string>();
  private running: Promise<void> | null = null;
  private again = false;
  private stopped = false;
  private lastLabelKey: string | null = null;
  private gitVersion: string | null = null;
  /** Repositories whose reflogs git's own `--reflog` answered last cycle,
   *  with why (history-tips.ts; a test and log aid). */
  readonly reflogFallbacks = new Map<string, string>();
  /** Cycles finished (a test aid). */
  cycles = 0;
  /** The last HOME walk (a test and log aid). */
  lastWalk: RepoWalkResult | null = null;

  constructor(private readonly opts: LockResolverOptions) {
    this.registry = new KnownRepoStore({
      ...(opts.dbPath !== undefined ? { dbPath: opts.dbPath } : {}),
      ...(opts.now ? { now: opts.now } : {}),
      ...(opts.registryLimits ? { limits: opts.registryLimits } : {}),
    });
    // Once stopped, no new call starts (one started after `stop` killed the
    // running ones would be waited for to its deadline).
    const run = opts.git ?? hardenedResolverGit(this.children);
    this.git = (args, o) => (this.stopped ? Promise.resolve({ code: 1, stdout: "", stderr: "the resolver stopped", complete: false }) : run(args, o));
    this.realpath = opts.realpath ?? ((p) => { try { return realpathSync(p); } catch { return null; } });
    this.isRoot = opts.isRoot ?? isWorkTreeRoot;
    this.log = opts.log ?? (() => {});
    this.now = opts.now ?? Date.now;
    this.limits = { ...DEFAULT_RESOLVER_LIMITS, ...(opts.limits ?? {}) };
    this.ownDirs = manduOwnDirs(opts.home, opts.env ?? process.env, opts.stateBase);
    if (opts.dbPath !== undefined) {
      const dir = dirname(opts.dbPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      this.db = new Database(opts.dbPath);
      this.db.pragma("journal_mode = WAL");
      this.db.exec(CACHE_SQL);
      for (const r of this.db.prepare("SELECT root, entry FROM lock_resolutions").all() as Array<{ root: string; entry: string }>) {
        const e = parseResolution(r.entry);
        if (e !== null && e.root === r.root && this.registry.has(r.root) && this.sealed(r.root, r.entry)) this.cache.set(r.root, e);
        else this.db.prepare("DELETE FROM lock_resolutions WHERE root = ?").run(r.root);
      }
    }
  }

  /** Plan 14 §11.2: may a row read back from mandu.db be used? Only when a
   *  seal of the current epoch vouches for its bytes (no seal gate: yes). A
   *  mismatch is reported; an unsealed row (every row after a rotation) is
   *  dropped quietly and resolved again. */
  private sealed(root: string, entry: string): boolean {
    const gate = this.opts.seals;
    if (gate === undefined) return true;
    const key = resolutionSealKey(root);
    const verdict = gate.check(CACHE_SEAL_KINDS.lockResolution, key, Buffer.from(entry, "utf8"));
    if (verdict === "mismatch") gate.rejected?.({ kind: CACHE_SEAL_KINDS.lockResolution, key, reason: "mismatch" });
    return verdict === "ok";
  }

  /** Start the background schedule (when one was given). */
  start(): void {
    const s = this.opts.schedule;
    if (s === undefined || this.stopped) return;
    const at = (ms: number, fn: () => void): void => { const t = setTimeout(fn, ms); t.unref(); this.timers.push(t); };
    const every = (ms: number, fn: () => void): void => { if (ms > 0) { const t = setInterval(fn, ms); t.unref(); this.timers.push(t); } };
    at(s.startDelayMs, () => { void (s.walkHome ? this.walkHome().then(() => this.kick()) : Promise.resolve(this.kick())); });
    every(s.cycleMs, () => this.kick());
    if (s.walkHome) every(s.homeWalkMs, () => { void this.walkHome().then(() => this.kick()); });
    every(s.labelPollMs, () => {
      if (this.lastLabelKey !== null && this.labelView().labelKey !== this.lastLabelKey) this.kick();
    });
  }

  /** Stop: no new work, running git killed, the current cycle awaited. */
  async stop(): Promise<void> {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    this.timers.length = 0;
    for (const c of this.children) { try { c.kill("the resolver stopped"); } catch { /* gone */ } }
    try { await this.running; } catch { /* reported */ }
    this.registry.close();
    try { this.db?.close(); } catch { /* closed */ }
  }

  /** Resolve soon: `roots` first (and tried again even after a failure). */
  kick(roots: readonly string[] = []): void {
    if (this.stopped) return;
    for (const r of roots) this.priority.add(r);
    if (this.running !== null) { this.again = true; return; }
    const t = setTimeout(() => { void this.runCycle(); }, 0);
    t.unref();
  }

  /** One cycle, or join the running one; resolves when no cycle runs. */
  runCycle(): Promise<void> {
    if (this.running !== null) { this.again = true; return this.running; }
    this.running = (async () => {
      try {
        do {
          this.again = false;
          await this.cycleOnce();
        } while (this.again && !this.stopped);
      } catch (e) {
        this.log(`lock resolution: a cycle failed: ${(e as Error).message}`);
      }
    })().finally(() => { this.running = null; });
    return this.running;
  }

  /** Resolves when no cycle runs (a test aid). */
  async idle(): Promise<void> {
    while (this.running !== null) await this.running;
  }

  /** Walk HOME and replace the registry's `walk` source. */
  async walkHome(): Promise<RepoWalkResult> {
    const r = await findRepositories(this.opts.home, {
      ...(this.opts.walkLimits ? { limits: this.opts.walkLimits } : {}),
      ...(this.opts.stateBase ? { stateBase: this.opts.stateBase } : {}),
      env: this.opts.env ?? process.env,
      ...(this.opts.selfDir !== undefined ? { selfDir: this.opts.selfDir } : {}),
      ...(this.opts.platform !== undefined ? { platform: this.opts.platform } : {}),
      // macOS: the labels this resolver locks by (above `public`, real
      // spellings included, the walk's spelling) keep a pruned HOME folder
      // walked where one concerns it: the `label` source only walks UP from
      // a label, so it never reaches a repository below a labelled folder
      // or a pattern's prefix (known-repos.ts header). Unused elsewhere.
      labelPaths: this.labelView().labels.filter((l) => l.level !== "public").map((l) => l.path),
    });
    if (this.stopped) return r;
    const kept = this.registry.replaceSource("walk", r.roots.filter((x) => !isUnderAny(x, this.ownDirs)));
    this.lastWalk = r;
    this.log(`known repositories: the HOME walk found ${kept.length} (${r.dirs} folder(s) read in ${r.ms} ms${r.truncated ? `, stopped by the ${r.truncated} cap` : ""})`);
    return r;
  }

  /**
   * A caller-named root, validated on the filesystem alone (the
   * synchronous path of `gitHistoryLocks` `roots` and the scan ops): its
   * real path, the work tree it lies in, never inside Mandu's own home.
   * The resolver's git calls check it again before any walk.
   */
  rootOf(raw: unknown): string | null {
    if (typeof raw !== "string" || !raw.startsWith("/") || raw.length > 4096 || raw.includes("\0")) return null;
    // A path that does not exist (a deleted folder) is decided by its
    // nearest existing ancestor, by real path.
    const real = realSpellingOf(raw, this.realpath);
    const root = workTreeRootAt(real, this.isRoot);
    if (root === null || isUnderAny(root, this.ownDirs)) return null;
    return root;
  }

  /** Register data-plane roots (`launch` / `scan`), validated by
   *  `rootOf`, and resolve them first. Returns the work-tree roots named. */
  note(raws: readonly unknown[], source: Extract<RepoSource, "launch" | "scan">): string[] {
    const out: string[] = [];
    for (const raw of raws.slice(0, LAUNCH_ROOTS_MAX)) {
      const root = this.rootOf(raw);
      if (root === null || out.includes(root)) continue;
      const got = this.registry.add(root, source);
      if (got === "full") { this.log(`known repositories: the registry is full (${this.registry.limits.dataPlane} data-plane roots); ${root} not added`); continue; }
      out.push(root);
    }
    if (out.length > 0) this.kick(out);
    return out;
  }

  /** `registerRepository`: validated on the filesystem and by git (a work
   *  tree the arbiter can read, its top), added (source `register`), and
   *  resolved first. */
  async register(raw: unknown): Promise<{ ok: true; root: string; added: boolean; known: number } | { ok: false; error: string }> {
    if (typeof raw !== "string" || !raw.startsWith("/")) return { ok: false, error: "root must be an absolute path" };
    const root = this.rootOf(raw);
    if (root === null) return { ok: false, error: "not a git work tree the arbiter can read (or inside Mandu's own home)" };
    const top = await this.git(["rev-parse", "--show-toplevel"], { cwd: root, timeoutMs: 10_000 });
    const real = top.code === 0 ? this.realpath(top.stdout.trim()) : null;
    if (real !== root) return { ok: false, error: "not a git work tree the arbiter can read" };
    const got = this.registry.add(root, "register");
    if (got === "full") return { ok: false, error: `the repository registry is full (${this.registry.limits.dataPlane} registered roots)` };
    this.kick([root]);
    return { ok: true, root, added: got === "added", known: this.registry.size };
  }

  /** The labels in force, with their real spellings, compiled and keyed. */
  private labelView(): LabelView {
    const wire = this.opts.labels();
    const labels = wire.length > 0 ? withRealSpellings(wire, (p) => realSpellingOf(p, this.realpath)) : [];
    return { labels, compiled: compileHistoryLabels(labels), labelKey: labelWalkKey(labels, null) };
  }

  private async cycleOnce(): Promise<void> {
    if (this.stopped) return;
    const t0 = this.now();
    const view = this.labelView();
    this.lastLabelKey = view.labelKey;
    // Asked again each cycle: an upgraded git changes the base key (the
    // launcher asks its own git; a different version only costs its walk).
    this.gitVersion = null;
    // R1: the work trees the labels name; then drop what is gone.
    // By real path (a label written through a symlink names the same work
    // tree), never inside Mandu's own home.
    this.registry.replaceSource("label", labelRepoRoots(view.compiled, (p) => this.rootOf(p)));
    for (const gone of this.registry.prune((r) => this.isRoot(r) && !isUnderAny(r, this.ownDirs))) this.forget(gone);
    const listed = this.registry.list().map((r) => r.root);
    const first = [...this.priority].filter((r) => this.registry.has(r));
    this.priority.clear();
    const forced = new Set(first);
    const order = [...first, ...listed.filter((r) => !forced.has(r))];
    let walked = 0;
    let failed = 0;
    await mapLimit(order, this.limits.concurrency, async (root) => {
      if (this.stopped) return;
      const f = this.failures.get(root);
      if (f !== undefined && !forced.has(root) && this.now() - f.at < this.limits.retryFailedMs) return;
      try {
        if (await this.resolveOne(root, view)) walked++;
        this.failures.delete(root);
      } catch (e) {
        failed++;
        this.failures.set(root, { at: this.now(), reason: (e as Error).message });
      }
    });
    this.cycles++;
    try { this.opts.onCycle?.(); } catch { /* a follower's failure is its own */ }
    if (walked > 0 || failed > 0) {
      this.log(`lock resolution: ${order.length} known repositor${order.length === 1 ? "y" : "ies"}, ${walked} walked, ${failed} failed, in ${this.now() - t0} ms`);
    }
  }

  private forget(root: string): void {
    this.cache.delete(root);
    this.failures.delete(root);
    this.reflogFallbacks.delete(root);
    this.db?.prepare("DELETE FROM lock_resolutions WHERE root = ?").run(root);
  }

  /** Resolve one repository under `view`. True when git walked history
   *  (not a hit). Throws on a failure (the caller records it). */
  private async resolveOne(root: string, view: LabelView): Promise<boolean> {
    const specs = historyPathspecs(root, view.compiled);
    if (specs !== null && specs.length === 0) {
      // No label above public reaches inside: nothing to walk (the launcher
      // computes the same and walks nothing either).
      this.forget(root);
      return false;
    }
    const rels = specs ?? [];
    const deadline = this.now() + this.limits.repoTimeoutMs;
    const left = (): number => Math.max(1, deadline - this.now());
    const must = async (args: string[], what: string, input?: string): Promise<string> => {
      const r = await this.git(args, { cwd: root, timeoutMs: left(), ...(input !== undefined ? { input } : {}) });
      if (r.code !== 0 || !r.complete) throw new Error(`${what} failed in ${root}: ${r.stderr.trim().split("\n").slice(-1)[0] || `exit ${r.code}`}`);
      return r.stdout;
    };
    // Validated by git: the root is a work tree's top, by real path.
    const rp = (await must(["rev-parse", "--show-toplevel", "--show-object-format", "--git-path", "shallow"], "git rev-parse")).split("\n");
    if (this.realpath((rp[0] ?? "").trim()) !== root) throw new Error(`${root} is not a work tree's top`);
    const format: "sha1" | "sha256" = (rp[1] ?? "").trim() === "sha256" ? "sha256" : "sha1";
    if (this.gitVersion === null) this.gitVersion = await must(["version"], "git version");
    // Every ref and every reflog entry, the reflogs read from their files
    // once (history-tips.ts; git's own `--reflog` on any doubt): the tips
    // the launcher computes for this work tree, never fewer than `rev-list
    // --all --reflog --no-walk`.
    const tg: TipsGit = async (args, input) => {
      const r = await this.git(args, { cwd: root, timeoutMs: left(), ...(input !== undefined ? { input } : {}) });
      return r.complete || r.code !== 0 ? r : { ...r, code: 1, stderr: `${r.stderr}\nkilled at the deadline` };
    };
    const names = await reflogNamesOf(tg, root);
    if (names.fallback !== null) this.reflogFallbacks.set(root, names.fallback);
    else this.reflogFallbacks.delete(root);
    const got = await historyTipsOf(tg, names);
    if ("error" in got) throw new Error(`${got.error} in ${root}`);
    const tips = got.tips;
    // The launcher's base and walk (history-labels.ts walkShallowRule):
    // grafts and replace refs are off for every hardened call, and the
    // shallow file is honoured only where it is true.
    const shallow = await walkShallowRule(
      async (args, input) => this.git(args, { cwd: root, timeoutMs: left(), input }).then((r) => (r.complete ? r : { ...r, code: 1 })),
      rp[2] ? readOptional(resolve(root, rp[2].trim())) : "",
      format === "sha256" ? 64 : 40,
    );
    const base = walkBaseKey({ gitVersion: this.gitVersion, shallow: shallow.honoured });
    const filter = labelFilterKey(view.labelKey, specs);
    const key = resolutionKey(root, filter, base, tips);
    const memo = new Map<string, boolean>();
    const keep = (rel: string): boolean => {
      let v = memo.get(rel);
      if (v === undefined) { v = labelledAbovePublic(join(root, rel), view.compiled); memo.set(rel, v); }
      return v;
    };
    const walk = async (args: string[], input?: string): Promise<Set<string> | null> => {
      const found = new Set<string>();
      const p = new RawLogBlobPaths((blob, path) => { if (keep(path)) found.add(blob); });
      const r = await this.git(args, { cwd: root, timeoutMs: left(), onChunk: (c) => p.feed(c), ...(input !== undefined ? { input } : {}) });
      p.end();
      return r.code === 0 && r.complete ? found : null;
    };
    const prior = this.cache.get(root) ?? null;
    const plan = planResolution(prior, root, filter, rels, base, tips);
    let history: string[];
    let walked = false;
    if (plan.kind === "hit") {
      history = prior!.history;
    } else {
      let got: Set<string> | null = null;
      if (plan.kind === "incremental") {
        got = await walk([...shallow.args, "log", "--stdin", ...HISTORY_WALK_ARGS, "--", ...rels], `${plan.include.join("\n")}\n${plan.exclude.map((t) => `^${t}`).join("\n")}\n`);
        if (got !== null) for (const b of prior!.history) got.add(b);
      }
      // The whole history: from the tips (every ref and reflog entry), the
      // commits `git log --all --reflog` starts from, without git
      // enumerating the reflogs again. No tip (an empty repository) is no
      // history (`git log --stdin` with no input would walk HEAD).
      if (got === null) {
        got = tips.length === 0 ? new Set<string>() : await walk([...shallow.args, "log", "--stdin", ...HISTORY_WALK_ARGS, "--", ...rels], `${tips.join("\n")}\n`);
      }
      if (got === null) throw new Error(`git log failed or ran out of time in ${root}`);
      // A version once resolved stays resolved while the same labels decide
      // the same repository (the launcher's locked memory, locked-memory.ts,
      // confidentiality.md §7.2a "A version once locked stays locked"): a
      // walk anew (another base, a history an agent cut) never drops one.
      if (prior !== null && prior.root === root && prior.filter === filter) for (const b of prior.history) got.add(b);
      history = [...got].sort();
      walked = true;
    }
    const index = [...new Set(parseLsFilesStagePaths(await must(["ls-files", "-s", "-z", "--", ...rels], "git ls-files"))
      .filter(([, p]) => keep(p)).map(([b]) => b))].sort();
    if (history.length + index.length > this.limits.maxRepoBlobs) {
      throw new Error(`${root} holds ${history.length + index.length} labelled versions, over the ${this.limits.maxRepoBlobs} cap`);
    }
    const next: RepoResolution = { v: 1, root, format, filter, specs: [...rels].sort(), base, tips, history, index, key, at: this.now() };
    if (this.stopped) return walked;
    this.cache.set(root, next);
    const entry = JSON.stringify(next);
    this.db?.prepare("INSERT INTO lock_resolutions (root, entry) VALUES (?, ?) ON CONFLICT(root) DO UPDATE SET entry = excluded.entry").run(root, entry);
    if (this.db) this.opts.seals?.seal(CACHE_SEAL_KINDS.lockResolution, resolutionSealKey(root), Buffer.from(entry, "utf8"));
    return walked;
  }

  /**
   * The answer (`gitHistoryLocks`): the global locked set, the resolved
   * repositories, and what is pending. `requested`: roots the caller named
   * (their resolution is listed even when it holds no labelled version, so
   * a launcher can tell "resolved, none" from "unknown").
   */
  snapshot(requested: readonly string[] = []): LockedSetAnswer {
    const view = this.labelView();
    if (this.lastLabelKey !== null && view.labelKey !== this.lastLabelKey) this.kick();
    const locked = splitBlobLocks(this.opts.blobLocks());
    const sets = { sha1: new Set(locked.sha1), sha256: new Set(locked.sha256) };
    const want = new Set(requested);
    const repos: LockedSetAnswer["repos"] = [];
    const pending: string[] = [];
    for (const { root } of this.registry.list()) {
      const specs = historyPathspecs(root, view.compiled);
      const reaches = !(specs !== null && specs.length === 0);
      const e = this.cache.get(root);
      const blobs = e !== undefined ? [...new Set([...e.history, ...e.index])].sort() : [];
      const set = e?.format === "sha256" ? sets.sha256 : sets.sha1;
      // Over the set's cap, a repository's versions are left out and it is
      // pending: an incomplete set is said, never silent.
      const fits = sets.sha1.size + sets.sha256.size + blobs.length <= this.limits.maxLockedSet;
      if (fits) for (const b of blobs) set.add(b);
      if (!reaches) continue;
      const current = e !== undefined && fits && e.filter === labelFilterKey(view.labelKey, specs) && !this.failures.has(root);
      if (!current) { pending.push(root); continue; }
      if (blobs.length > 0 || want.has(root)) repos.push({ root, format: e.format, key: e.key, blobs });
    }
    return {
      lockedSet: { sha1: [...sets.sha1].sort(), sha256: [...sets.sha256].sort() },
      repos,
      complete: pending.length === 0,
      pending,
    };
  }
}

function readOptional(path: string): string {
  try { return readFileSync(path, "utf8"); } catch { return ""; }
}

/** `fn` over `items`, at most `limit` at once. */
async function mapLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) await fn(items[next++]!);
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}
