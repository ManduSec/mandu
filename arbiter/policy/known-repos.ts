/**
 * known-repos — the arbiter's registry of the git repositories a lock must
 * hold in (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md §11.1
 * R1).
 *
 * The object twins hide a locked version only in the repositories a launch
 * prepares: the workspace, a repository holding a confined file or a
 * literally labelled path. A lock on another repository, a clone or a fork
 * of it, is not enforced. The first step is knowing the repositories at
 * all. This registry names every work tree the arbiter has reason to care
 * about, each with the SOURCES that named it:
 *
 *   launch    a launch's workspace (`gitHistoryLocks` `roots`)
 *   scan      a root `scanSecretHistory` / `suggestPolicy` scanned
 *   register  `registerRepository` (the guard, a launcher)
 *   label     a work tree a human label above `public` lies in (a literal
 *             path, or a pattern's literal prefix, found through its
 *             nearest existing folder); recomputed from the law each cycle
 *   walk      the background walk of HOME for `.git` entries
 *
 * CAPS AND ORDERING (bounded, and the agent cannot crowd out the rest):
 *   - `launch`, `scan` and `register` arrive on the DATA socket, which the
 *     agent can reach; together they hold at most `dataPlane` (256) roots.
 *     Registration is ADD-ONLY: at the cap a new data-plane root is refused
 *     (never another one evicted), and a data-plane source not renewed for
 *     30 days lapses, so a full registry drains by itself.
 *   - `label` holds at most 256 roots, `walk` at most 256 (the walk is
 *     breadth-first, so the shallowest repositories are the ones kept).
 *     Each of the two is REPLACED wholesale when it is recomputed.
 *   - At most 768 distinct roots in all. A root named by several sources is
 *     one entry; it leaves when its last source does.
 *   - Order (the resolver's order, and the listing's): the best source
 *     (launch, label, scan, register, walk), then the most recently seen,
 *     then the path.
 *   - A root whose work tree is gone (no `.git` at it) is dropped at the
 *     next cycle, whatever named it.
 *
 * A root is a work tree's top: a directory holding `.git` (a directory with
 * a HEAD, or a `gitdir:` file: a linked worktree or a submodule), by real
 * path, and never inside Mandu's own home (its shadow repositories are not
 * the user's, and the agent can reach none of it). A bare repository is not
 * registered: a path label names a work-tree path, so it has nothing to
 * resolve; a blob lock (`blobs:`) covers it by id wherever it lies (§11.1 R4).
 *
 * The HOME walk (`findRepositories`) uses discovery's prunes
 * (secret-discovery.ts `SKIP_DIRS`, the agents' own files `isAgentAuthPath`,
 * the Mandu home and state base, Mandu's install trees), never descends a
 * directory link, and is capped by depth (a work tree at most 5 below HOME),
 * repositories (256), directories read (50 000) and time (10 s); it yields
 * to the event loop every 15 ms, so it never holds the arbiter's clients.
 * On macOS (2026-09-30) it also prunes HOME's app-data and media folders
 * (`Library`, `.Trash`, `Pictures`, `Music`, `Movies`, direct children of
 * HOME: discovery's `darwinHomeSkipDirs`, the one helper every HOME walk
 * uses): tens of thousands of folders, parts of them TCC-protected (a walk
 * there can raise "access data from other apps" prompts on the terminal's
 * behalf, at start and every 6 hours), and rarely a repository the user
 * works in. Like discovery's, the prune never hides what a label concerns
 * (discovery's rule, `darwinPrune`, over `RepoWalkOptions.labelPaths`: the
 * resolver's labels above `public`, real spellings included). A label on
 * the folder or above it, or a pattern whose literal prefix is empty, above
 * or inside it (an unrooted `*.pem` pattern; an `id_rsa` pattern rooted at
 * `~/Library`), keeps the whole folder walked. A label on a folder inside
 * it (the iCloud Drive folder, `~/Library/Mobile Documents/
 * com~apple~CloudDocs`) has that folder walked: the outermost one, when it
 * is a real directory at its own spelling within the depth cap, in the
 * pruned folder's turn. The re-entry is needed: the `label` source finds a
 * work tree only by walking UP from a literal label or a pattern's literal
 * prefix (`labelRepoRoots` → `LockResolver.rootOf` → `workTreeRootAt`,
 * lock-resolution.ts), so it reaches the repository holding a labelled
 * file or folder, never one BELOW a labelled folder or a prefix, nor any
 * for a pattern with no prefix. A labelled FILE lifts nothing (its
 * repository is the `label` source's). Left on macOS: a repository in a
 * pruned folder that no label concerns and no launch, scan or registration
 * names; and a label added after a walk is followed at the next one (at
 * start, then every 6 hours). On macOS the locked set is read only to warn
 * which repositories keep a locked version readable (the launcher's
 * `lockedHistoryRepos`); nothing enforces it there (`hideGitHistory` runs on
 * Linux only). Linux: no prune.
 *
 * Persistence: one table in mandu.db (`known_repos`), the arbiter's single
 * writer, which the agent can neither read nor write in `secrets` mode.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 * `workTreeRootAt` restates launcher/src/git-object-twins.ts `repoRootAt`.
 */
import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, realpathSync, type Dirent } from "node:fs";
import { dirname, join, posix } from "node:path";
import Database from "../db/sqlite.js";
import { manduPath } from "../src/generated/mandu-paths.js";
import { darwinHomeSkipDirs, darwinPrune, defaultStateBase, isAgentAuthPath, manduInstallTrees, SKIP_DIRS } from "./secret-discovery.js";

export type RepoSource = "launch" | "label" | "scan" | "register" | "walk";

/** Source rank: lower is resolved (and listed) first. */
export const SOURCE_RANK: Readonly<Record<RepoSource, number>> = { launch: 0, label: 1, scan: 2, register: 3, walk: 4 };

/** The sources a data-socket client (the agent included) can add. */
export const DATA_PLANE_SOURCES: ReadonlySet<RepoSource> = new Set<RepoSource>(["launch", "scan", "register"]);

export interface RegistryLimits {
  /** Roots the data-plane sources may hold together. */
  dataPlane: number;
  /** Roots the `label` source may hold. */
  label: number;
  /** Roots the `walk` source may hold. */
  walk: number;
  /** A data-plane source not renewed for this long lapses. */
  dataPlaneMaxAgeMs: number;
}

export const DEFAULT_REGISTRY_LIMITS: RegistryLimits = {
  dataPlane: 256,
  label: 256,
  walk: 256,
  dataPlaneMaxAgeMs: 30 * 24 * 3600_000,
};

/** One known repository: its real work-tree root, and when each source last
 *  named it (epoch ms). */
export interface KnownRepo {
  root: string;
  sources: Partial<Record<RepoSource, number>>;
  firstSeen: number;
}

/** The best (lowest) rank among a repository's sources. Pure. */
export function bestRank(r: KnownRepo): number {
  let best = 99;
  for (const s of Object.keys(r.sources) as RepoSource[]) best = Math.min(best, SOURCE_RANK[s] ?? 99);
  return best;
}

/** The latest time any source named it. Pure. */
export function lastSeen(r: KnownRepo): number {
  let t = 0;
  for (const v of Object.values(r.sources)) if (typeof v === "number" && v > t) t = v;
  return t;
}

/** The registry's order: best source, then most recently seen, then path.
 *  Pure. */
export function orderRepos(list: readonly KnownRepo[]): KnownRepo[] {
  return [...list].sort((a, b) => bestRank(a) - bestRank(b) || lastSeen(b) - lastSeen(a) || (a.root < b.root ? -1 : a.root > b.root ? 1 : 0));
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS known_repos (
  root       TEXT PRIMARY KEY,
  sources    TEXT NOT NULL,
  first_seen INTEGER NOT NULL
);
`;

export type AddOutcome = "added" | "renewed" | "full";

export interface KnownRepoStoreOptions {
  /** Omit for an in-memory store (tests). */
  dbPath?: string;
  now?: () => number;
  limits?: Partial<RegistryLimits>;
}

/** The registry: in memory, written through to mandu.db. */
export class KnownRepoStore {
  private readonly rows = new Map<string, KnownRepo>();
  private readonly db?: InstanceType<typeof Database>;
  private readonly now: () => number;
  readonly limits: RegistryLimits;

  constructor(opts: KnownRepoStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.limits = { ...DEFAULT_REGISTRY_LIMITS, ...(opts.limits ?? {}) };
    if (opts.dbPath !== undefined) {
      const dir = dirname(opts.dbPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      this.db = new Database(opts.dbPath);
      this.db.pragma("journal_mode = WAL");
      this.db.exec(SCHEMA_SQL);
      const rows = this.db.prepare("SELECT root, sources, first_seen FROM known_repos").all() as Array<{ root: string; sources: string; first_seen: number }>;
      for (const r of rows) {
        const sources = parseSources(r.sources);
        if (sources !== null && r.root.startsWith("/")) this.rows.set(r.root, { root: r.root, sources, firstSeen: r.first_seen });
      }
    }
  }

  get size(): number {
    return this.rows.size;
  }

  has(root: string): boolean {
    return this.rows.has(root);
  }

  get(root: string): KnownRepo | undefined {
    const r = this.rows.get(root);
    return r ? { root: r.root, sources: { ...r.sources }, firstSeen: r.firstSeen } : undefined;
  }

  /** Every entry, in the registry's order. */
  list(): KnownRepo[] {
    return orderRepos([...this.rows.values()].map((r) => ({ root: r.root, sources: { ...r.sources }, firstSeen: r.firstSeen })));
  }

  /** How many roots hold a data-plane source. */
  dataPlaneCount(): number {
    let n = 0;
    for (const r of this.rows.values()) if (hasDataPlane(r)) n++;
    return n;
  }

  /**
   * Name `root` by a data-plane source (`launch`, `scan`, `register`).
   * ADD-ONLY: a root already known is renewed; a new one is refused once
   * the data-plane sources hold `dataPlane` roots (a root that already has
   * a data-plane source is renewed even then). The caller validated `root`.
   */
  add(root: string, source: RepoSource): AddOutcome {
    if (!DATA_PLANE_SOURCES.has(source)) throw new Error(`known-repos: ${source} is recomputed, not added`);
    const now = this.now();
    const cur = this.rows.get(root);
    if (cur !== undefined && hasDataPlane(cur)) {
      cur.sources[source] = now;
      this.write(cur);
      return "renewed";
    }
    if (this.dataPlaneCount() >= this.limits.dataPlane) return "full";
    const next = cur ?? { root, sources: {}, firstSeen: now };
    next.sources[source] = now;
    this.rows.set(root, next);
    this.write(next);
    return cur === undefined ? "added" : "renewed";
  }

  /** Replace everything `source` (`label` or `walk`) names with `roots`, in
   *  the caller's order, the first `limits[source]` kept. Returns the roots
   *  kept. */
  replaceSource(source: "label" | "walk", roots: readonly string[]): string[] {
    const now = this.now();
    const keep = [...new Set(roots)].slice(0, this.limits[source]);
    const want = new Set(keep);
    for (const r of [...this.rows.values()]) {
      if (r.sources[source] !== undefined && !want.has(r.root)) {
        delete r.sources[source];
        if (Object.keys(r.sources).length === 0) this.remove(r.root);
        else this.write(r);
      }
    }
    for (const root of keep) {
      const cur = this.rows.get(root) ?? { root, sources: {}, firstSeen: now };
      cur.sources[source] = now;
      this.rows.set(root, cur);
      this.write(cur);
    }
    return keep;
  }

  /** Drop every root `isRepo` refuses (the work tree is gone), and every
   *  data-plane source older than `dataPlaneMaxAgeMs`. Returns the roots
   *  dropped. */
  prune(isRepo: (root: string) => boolean): string[] {
    const dropped: string[] = [];
    const cutoff = this.now() - this.limits.dataPlaneMaxAgeMs;
    for (const r of [...this.rows.values()]) {
      if (!isRepo(r.root)) {
        this.remove(r.root);
        dropped.push(r.root);
        continue;
      }
      let changed = false;
      for (const s of DATA_PLANE_SOURCES) {
        const t = r.sources[s];
        if (t !== undefined && t < cutoff) { delete r.sources[s]; changed = true; }
      }
      if (!changed) continue;
      if (Object.keys(r.sources).length === 0) { this.remove(r.root); dropped.push(r.root); } else this.write(r);
    }
    return dropped.sort();
  }

  /** Drop one root, whatever named it. */
  remove(root: string): void {
    this.rows.delete(root);
    this.db?.prepare("DELETE FROM known_repos WHERE root = ?").run(root);
  }

  close(): void {
    try { this.db?.close(); } catch { /* already closed */ }
  }

  private write(r: KnownRepo): void {
    this.db
      ?.prepare("INSERT INTO known_repos (root, sources, first_seen) VALUES (?, ?, ?) ON CONFLICT(root) DO UPDATE SET sources = excluded.sources")
      .run(r.root, JSON.stringify(r.sources), r.firstSeen);
  }
}

function hasDataPlane(r: KnownRepo): boolean {
  for (const s of DATA_PLANE_SOURCES) if (r.sources[s] !== undefined) return true;
  return false;
}

function parseSources(text: string): Partial<Record<RepoSource, number>> | null {
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    if (typeof j !== "object" || j === null) return null;
    const out: Partial<Record<RepoSource, number>> = {};
    for (const [k, v] of Object.entries(j)) if (k in SOURCE_RANK && typeof v === "number") out[k as RepoSource] = v;
    return Object.keys(out).length > 0 ? out : null;
  } catch {
    return null;
  }
}

// ── What a root is ──────────────────────────────────────────────────────────

/** Is `dir` a work tree's top: `.git` a directory holding HEAD, or a file
 *  that starts `gitdir: ` (a linked worktree, a submodule)? */
export function isWorkTreeRoot(dir: string): boolean {
  const dotgit = join(dir, ".git");
  let st: ReturnType<typeof lstatSync> | undefined;
  try { st = lstatSync(dotgit, { throwIfNoEntry: false }); } catch { st = undefined; }
  if (st === undefined) return false;
  if (st.isDirectory()) return existsSync(join(dotgit, "HEAD"));
  if (!st.isFile()) return false;
  try {
    const fd = openSync(dotgit, "r");
    try {
      const buf = Buffer.alloc(16);
      const n = readSync(fd, buf, 0, 16, 0);
      return buf.subarray(0, n).toString("utf8").startsWith("gitdir: ");
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
}

/** The work tree `p` is or lies in (the nearest ancestor holding `.git`),
 *  or null; a path inside a `.git` directory is none. `p` need not exist:
 *  its nearest existing folder decides. Pure given `isRoot`. */
export function workTreeRootAt(p: string, isRoot: (dir: string) => boolean = isWorkTreeRoot): string | null {
  const norm = posix.normalize(p);
  if (!norm.startsWith("/") || norm.split("/").includes(".git")) return null;
  let dir = norm;
  for (;;) {
    if (isRoot(dir)) return dir;
    const up = posix.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

/** The directories never walked and never registered because they are
 *  Mandu's own: the Mandu home (the configured and the default) and the
 *  view state base. */
export function manduOwnDirs(home: string, env: Readonly<Record<string, string | undefined>> = process.env, stateBase?: string): string[] {
  const dirs = new Set<string>();
  for (const p of [manduPath("mandu-home", env, home), manduPath("mandu-home", {}, home), stateBase ?? defaultStateBase(home)]) {
    if (typeof p === "string" && p.startsWith("/")) {
      dirs.add(posix.normalize(p));
      try { dirs.add(realpathSync(p)); } catch { /* not there */ }
    }
  }
  return [...dirs].sort();
}

/** Is `p` one of `dirs` or below one? Pure. */
export function isUnderAny(p: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => p === d || p.startsWith(d.endsWith("/") ? d : d + "/"));
}

// ── The HOME walk ───────────────────────────────────────────────────────────

export interface RepoWalkLimits {
  /** A work tree at most this far below HOME (HOME is 0). */
  maxDepth: number;
  /** Stop after this many repositories. */
  maxRepos: number;
  /** Stop after reading this many directories. */
  maxDirs: number;
  /** Stop after this long. */
  timeMs: number;
}

export const DEFAULT_REPO_WALK_LIMITS: RepoWalkLimits = { maxDepth: 5, maxRepos: 256, maxDirs: 50_000, timeMs: 10_000 };

export interface RepoWalkResult {
  /** Work-tree roots, in the order found (breadth-first, names sorted). */
  roots: string[];
  /** Directories read. */
  dirs: number;
  /** Which cap stopped the walk, or null when it finished. */
  truncated: null | "repos" | "dirs" | "time";
  ms: number;
}

export interface RepoWalkOptions {
  limits?: Partial<RepoWalkLimits>;
  /** fs-sync's view state base (pruned); default the home's. */
  stateBase?: string;
  /** The environment MANDU_HOME / MANDU_PREFIX are read from. */
  env?: Readonly<Record<string, string | undefined>>;
  /** Mandu's own code directory (install-tree prune); a test knob. */
  selfDir?: string | null;
  /** The host platform: on `darwin` HOME's app-data and media folders are
   *  pruned (`darwinHomeSkipDirs`). Default this process's. A test knob. */
  platform?: NodeJS.Platform;
  /** The label paths above `public` in force (absolute literals, or
   *  gitignore-style patterns; their real spellings included), so the macOS
   *  prune never hides a repository a label concerns (discovery's rule,
   *  `darwinPrune`; the header says how). Unused off macOS. Default none. */
  labelPaths?: readonly string[];
  now?: () => number;
  /** Yield to the event loop (default: setImmediate); a test passes a no-op. */
  yieldNow?: () => Promise<void>;
}

const SLICE_MS = 15;

/**
 * The work trees under `home`, breadth-first, with discovery's prunes (see
 * the header). A directory holding `.git` is recorded and still descended
 * (a nested clone is a repository of its own); `.git` itself is never
 * entered. Never throws for an unreadable directory (it is skipped).
 */
export async function findRepositories(home: string, opts: RepoWalkOptions = {}): Promise<RepoWalkResult> {
  const limits: RepoWalkLimits = { ...DEFAULT_REPO_WALK_LIMITS, ...(opts.limits ?? {}) };
  const now = opts.now ?? Date.now;
  const yieldNow = opts.yieldNow ?? (() => new Promise<void>((r) => setImmediate(r)));
  const env = opts.env ?? process.env;
  const t0 = now();
  const own = new Set(manduOwnDirs(home, env, opts.stateBase));
  const installTrees = new Set(manduInstallTrees(home, { env, ...(opts.selfDir !== undefined ? { selfDir: opts.selfDir } : {}) }));
  const installNames = new Set([...installTrees].map((t) => posix.basename(t)));
  const roots: string[] = [];
  let dirs = 0;
  let truncated: RepoWalkResult["truncated"] = null;
  let slice = now();
  // Walked by REAL path (the registry's spelling); the agent-auth prune is
  // then matched against the real home too.
  let root = posix.normalize(home);
  try { root = realpathSync(root); } catch { /* walked as spelled */ }
  // macOS: HOME's app-data and media folders, by their exact path under the
  // walk's (real) spelling of HOME, the only one its paths are built from.
  const homeSkip = darwinHomeSkipDirs(root, opts.platform ?? process.platform);
  // Discovery's prunes of one directory (besides SKIP_DIRS by name).
  const pruned = (full: string, name: string): boolean => {
    if (own.has(full) || isAgentAuthPath(full, root) || isAgentAuthPath(full, home)) return true;
    if (!installNames.has(name)) return false;
    let real: string | null = null;
    try { real = realpathSync(full); } catch { real = null; }
    return real !== null && installTrees.has(real);
  };
  // macOS: what of a pruned folder at depth `d` is walked all the same, by
  // discovery's rule over the labels (`darwinPrune`; the header says why):
  // the whole folder when a label covers it or a pattern could match inside
  // it; else each labelled folder inside it, the outermost only, when it is
  // a real directory at its own (real) spelling, within the depth cap, and
  // under no pruned name, queued in the pruned folder's turn. A labelled
  // file is left to the `label` source.
  const ownList = [...own];
  const darwinReentry = (full: string, d: number): Array<[string, number]> => {
    const mac = darwinPrune(full, opts.labelPaths);
    if (mac.walk) return [[full, d]];
    const out: Array<[string, number]> = [];
    for (const p of mac.visit) {
      if (mac.visit.some((q) => q !== p && p.startsWith(q + "/"))) continue; // walked from the outer one
      const rel = p.slice(full.length + 1).split("/");
      const pd = d + rel.length;
      if (pd > limits.maxDepth || rel.some((s) => SKIP_DIRS.has(s)) || isUnderAny(p, ownList) || pruned(p, posix.basename(p))) continue;
      let real: string | null = null;
      try { real = lstatSync(p).isDirectory() ? realpathSync(p) : null; } catch { real = null; }
      if (real === p) out.push([p, pd]); // not a file, a link, a path through one, or gone
    }
    return out;
  };
  const queue: Array<[string, number]> = [[root, 0]];
  let dropped = false;
  for (let qi = 0; qi < queue.length; qi++) {
    if (roots.length >= limits.maxRepos) { truncated = "repos"; break; }
    if (dirs >= limits.maxDirs) { truncated = "dirs"; break; }
    if (now() - t0 >= limits.timeMs) { truncated = "time"; break; }
    const [dir, depth] = queue[qi]!;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    dirs++;
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    if (entries.some((e) => e.name === ".git" && (e.isDirectory() || e.isFile())) && isWorkTreeRoot(dir)) roots.push(dir);
    if (depth >= limits.maxDepth) continue;
    for (const e of entries) {
      // A directory link is never followed (it points out of the tree);
      // Dirent reports the link itself, not its target.
      if (!e.isDirectory() || SKIP_DIRS.has(e.name)) continue;
      const full = posix.join(dir, e.name);
      if (pruned(full, e.name)) continue;
      // The queue is bounded like the reads: what lies past it could never
      // be read under the directory cap anyway.
      if (homeSkip.has(full)) {
        for (const next of darwinReentry(full, depth + 1)) {
          if (queue.length - qi >= limits.maxDirs) { dropped = true; continue; }
          queue.push(next);
        }
        continue;
      }
      if (queue.length - qi >= limits.maxDirs) { dropped = true; continue; }
      queue.push([full, depth + 1]);
    }
    if (now() - slice >= SLICE_MS) { await yieldNow(); slice = now(); }
  }
  if (truncated === null && dropped) truncated = "dirs";
  return { roots, dirs, truncated, ms: now() - t0 };
}
