/**
 * twin-prefetch — the git-object twins' reads started at launch start
 * (confidentiality.md §7.2a "Cost on a relaunch", "The prefetch").
 *
 * The twins need, per object store, the history state (every ref and
 * reflog tip, and the base) and, per cached sanitized pack, a full hash of
 * its files for the seal check. Both used to start only after the arbiter's
 * secret discovery answered, seconds into the launch. The launch hint
 * (launch-hint.ts) names what the last launch from this workspace read; this
 * module starts those same reads when the launch starts, while the services
 * come up, and hands them to prepareGitObjectTwins only where they are
 * provably what it would compute itself:
 *
 *   - a STATE is offered for exactly the work trees it was computed for (a
 *     store read with one more or one fewer work tree computes it anew), and
 *     only when (1) each work tree's rev-parse facts and the first one's
 *     config, read fresh by the launch, equal the ones it was computed from,
 *     and (2) a FINGERPRINT of everything the tips are read from is
 *     unchanged: the `.git` entry of each work tree; HEAD, packed-refs, the
 *     config files, the shallow and grafts files; every directory and file
 *     under refs/, logs/ and reftable/; each linked worktree's HEAD,
 *     commondir, gitdir, refs/ and logs/; and every object directory the
 *     store reads, its pack/ and info/ and each loose-object fan-out
 *     directory (whether a reflog's object exists decides whether it is a
 *     tip). Each entry is (type, device, inode, size, mtime, ctime in ns),
 *     taken BEFORE the prefetch's git calls and again at use. git changes a
 *     ref by renaming a new file into place (a new inode, its directory's
 *     times) and a reflog by appending (its size), so a commit made between
 *     the prefetch and the use changes the fingerprint and the state is
 *     discarded. A fingerprint taken when any entry is younger than
 *     RACY_WINDOW_NS is not used at all ("racily clean", as git's index
 *     says), so a change after it can never carry the same timestamp as
 *     the value it replaced. A symlink in those trees, an unreadable entry
 *     or more than FINGERPRINT_MAX_ENTRIES of them: no prefetch.
 *   - a HASH is used only for the same unchanged file (file-hashes.ts).
 *
 * Anything else is discarded and the launch computes it as before: a
 * prefetch failure never fails or weakens a launch. `close` kills every git
 * call still running (each is a process group of its own, child-run.ts) and
 * ends the hash workers; the launcher closes it on every path, and on exit.
 * The prefetch writes nothing (no temp file or directory).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, type BigIntStats } from "node:fs";
import { join } from "node:path";
import type { RunningChild } from "./child-run.js";
import { FileHashes } from "./file-hashes.js";
import type { GitSession } from "./git-session.js";
import {
  objectDirsOfFacts, RepoReads, trackedGitRunner,
  type AlternatesIo, type GitRunner, type HistoryState, type RepoConfig, type RepoFacts, type StatePrefetch,
} from "./git-object-twins.js";
import { manduPath } from "./generated/mandu-paths.js";
import { launchHintFile, readLaunchHint } from "./launch-hint.js";

/** An entry younger than this when the fingerprint is taken makes it
 *  unusable (2 s: over the coarsest timestamp granularity of a common
 *  Linux filesystem, one second, with room for its truncation). */
export const RACY_WINDOW_NS = 2_000_000_000n;
export const FINGERPRINT_MAX_ENTRIES = 200_000;
const FINGERPRINT_MAX_DEPTH = 64;
/** At most this many bytes of cached packs are hashed ahead. */
export const PREFETCH_MAX_HASH_BYTES = 2048 * 1048576;

class Doubt extends Error {}

interface Acc { lines: string[]; newest: bigint }

function lst(path: string): BigIntStats | null {
  try {
    return lstatSync(path, { bigint: true });
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw new Doubt(`${path}: ${code ?? (e as Error).message}`);
  }
}

function kindOf(st: BigIntStats): string {
  return st.isFile() ? "f" : st.isDirectory() ? "d" : st.isSymbolicLink() ? "l" : "o";
}

function add(acc: Acc, path: string, st: BigIntStats | null, extra = ""): void {
  if (acc.lines.length >= FINGERPRINT_MAX_ENTRIES) throw new Doubt(`more than ${FINGERPRINT_MAX_ENTRIES} entries`);
  if (st === null) { acc.lines.push(`${path}\0-`); return; }
  acc.lines.push([path, kindOf(st), st.dev, st.ino, st.size, st.mtimeNs, st.ctimeNs, extra].join("\0"));
  if (st.mtimeNs > acc.newest) acc.newest = st.mtimeNs;
  if (st.ctimeNs > acc.newest) acc.newest = st.ctimeNs;
}

/** One path; a symlink is a doubt (what it names could change unseen). */
function one(acc: Acc, path: string): BigIntStats | null {
  const st = lst(path);
  if (st !== null && st.isSymbolicLink()) throw new Doubt(`${path} is a symlink`);
  add(acc, path, st);
  return st;
}

/** A directory tree: every directory and every entry in it. */
function tree(acc: Acc, path: string, depth: number): void {
  const st = one(acc, path);
  if (st === null || !st.isDirectory()) return;
  if (depth > FINGERPRINT_MAX_DEPTH) throw new Doubt(`${path} is deeper than ${FINGERPRINT_MAX_DEPTH}`);
  let names: string[];
  try { names = readdirSync(path); } catch (e) { throw new Doubt(`${path}: ${(e as Error).message}`); }
  for (const n of names.sort()) tree(acc, join(path, n), depth + 1);
}

/**
 * The fingerprint of everything the history state of the work trees `roots`
 * (one object store, `facts` the first one's) is read from (the module
 * comment), and the newest timestamp in it; null on any doubt.
 */
export function stateFingerprint(
  roots: readonly string[], facts: RepoFacts, io?: AlternatesIo,
): { digest: string; newestNs: bigint } | null {
  const acc: Acc = { lines: [], newest: 0n };
  try {
    for (const r of roots) {
      const p = join(r, ".git");
      const st = lst(p);
      if (st !== null && st.isSymbolicLink()) throw new Doubt(`${p} is a symlink`);
      // A `.git` FILE names the work tree's git dir: its content counts.
      let extra = "";
      if (st !== null && st.isFile()) {
        if (st.size > 4096n) throw new Doubt(`${p} is over 4 KiB`);
        extra = createHash("sha256").update(readFileSync(p)).digest("hex");
      }
      add(acc, p, st, extra);
    }
    const c = facts.commonDir;
    for (const f of ["HEAD", "packed-refs", "config", "config.worktree"]) one(acc, join(c, f));
    one(acc, facts.shallow);
    one(acc, facts.grafts);
    for (const t of ["refs", "logs", "reftable"]) tree(acc, join(c, t), 0);
    const wt = join(c, "worktrees");
    const wst = one(acc, wt);
    if (wst !== null && wst.isDirectory()) {
      let ids: string[];
      try { ids = readdirSync(wt); } catch (e) { throw new Doubt(`${wt}: ${(e as Error).message}`); }
      for (const id of ids.sort()) {
        const d = join(wt, id);
        const dst = one(acc, d);
        if (dst === null || !dst.isDirectory()) continue;
        for (const f of ["HEAD", "commondir", "gitdir", "config.worktree"]) one(acc, join(d, f));
        for (const t of ["refs", "logs"]) tree(acc, join(d, t), 0);
      }
    }
    // Every object directory the store reads (its alternates followed, as
    // the twins read them): whether a reflog's object exists is part of
    // the tips (`rev-list --ignore-missing`).
    let dirs: string[];
    try { dirs = objectDirsOfFacts(facts, io).dirs; } catch (e) { throw new Doubt((e as Error).message); }
    for (const d of dirs) {
      const st = one(acc, d);
      if (st === null || !st.isDirectory()) continue;
      for (const f of ["pack", "info", join("info", "alternates")]) one(acc, join(d, f));
      let names: string[];
      try { names = readdirSync(d); } catch (e) { throw new Doubt(`${d}: ${(e as Error).message}`); }
      for (const n of names.sort()) if (/^[0-9a-f]{2}$/.test(n)) one(acc, join(d, n));
    }
  } catch (e) {
    if (e instanceof Doubt) return null;
    throw e;
  }
  return { digest: createHash("sha256").update(acc.lines.join("\n")).digest("hex"), newestNs: acc.newest };
}

/** The wall clock in nanoseconds (the file timestamps' clock). */
function nowNs(): bigint {
  return BigInt(Date.now()) * 1_000_000n;
}

interface Snapshot {
  facts: RepoFacts[];
  config: RepoConfig;
  digest: string;
  state: HistoryState;
}

export interface TwinPrefetchOpts {
  /** The launch hint (launch-hint.ts `launchHintFile`). */
  hintFile: string;
  /** The object-twin cache (`cache/object-twins`). */
  cacheDir: string;
  /** A test knob (default: the production runner, its calls tracked). */
  git?: GitRunner;
  /** The launch's git session (git-session.ts): the prefetch's calls run in
   *  its one sandbox, still tracked (`close` kills them). Unset: one sandbox
   *  per call. */
  gitSession?: GitSession;
  /** A test knob (default: the wall clock). */
  now?: () => bigint;
  alternatesIo?: AlternatesIo;
  /** The hashes to fill (default: new, on worker threads). */
  hashes?: FileHashes;
  maxHashBytes?: number;
}

/** What the prefetch did, for the tests and the debug log. */
export interface TwinPrefetchStats {
  stores: number;
  hashedFiles: number;
  used: number;
  /** Why an offered state was not used, one line each. */
  discarded: string[];
}

export class TwinPrefetch implements StatePrefetch {
  readonly hashes: FileHashes;
  readonly stats: TwinPrefetchStats = { stores: 0, hashedFiles: 0, used: 0, discarded: [] };
  private readonly children = new Set<RunningChild>();
  private readonly snaps = new Map<string, Promise<Snapshot | null>>();
  private readonly ownsHashes: boolean;
  private closed = false;
  private readonly onExit = (): void => this.kill();

  /** Start the reads the hint names, or null when there is no hint. Never
   *  throws. */
  static start(opts: TwinPrefetchOpts): TwinPrefetch | null {
    const hint = readLaunchHint(opts.hintFile);
    if (hint === null || (hint.stores.length === 0 && hint.packs.length === 0)) return null;
    return new TwinPrefetch(opts, hint.stores, hint.packs);
  }

  private constructor(private readonly opts: TwinPrefetchOpts, stores: string[][], packs: string[]) {
    this.ownsHashes = opts.hashes === undefined;
    this.hashes = opts.hashes ?? new FileHashes();
    process.once("exit", this.onExit);
    // The cached packs the last launch served: hashed now, on the workers.
    const files: string[] = [];
    let bytes = 0;
    const max = opts.maxHashBytes ?? PREFETCH_MAX_HASH_BYTES;
    for (const key of packs) {
      const dir = join(opts.cacheDir, key);
      let names: string[];
      try { names = readdirSync(dir); } catch { continue; }
      for (const n of names.sort()) {
        if (!/\.(pack|idx|rev)$/.test(n)) continue;
        const p = join(dir, n);
        const st = lst(p);
        if (st === null || !st.isFile() || bytes + Number(st.size) > max) continue;
        bytes += Number(st.size);
        files.push(p);
      }
    }
    if (files.length > 0) {
      this.hashes.warm();
      this.hashes.prefetch(files);
    }
    this.stats.hashedFiles = files.length;
    const git = opts.git ?? opts.gitSession?.runner(this.children) ?? trackedGitRunner(this.children);
    for (const roots of stores) {
      const snap = this.snapshot(git, roots).catch(() => null);
      this.snaps.set(roots.join("\0"), snap);
      this.stats.stores++;
    }
  }

  private async snapshot(git: GitRunner, roots: readonly string[]): Promise<Snapshot | null> {
    const reads = new RepoReads(git);
    const facts = await Promise.all(roots.map((r) => reads.factsOf(r)));
    if (facts.some((f) => f.commonDir !== facts[0]!.commonDir)) return null;
    const config = await reads.configOf(roots[0]!);
    if (this.closed) return null;
    // The fingerprint BEFORE the state's git calls: a change after it shows.
    const at = (this.opts.now ?? nowNs)();
    const fp = stateFingerprint(roots, facts[0]!, this.opts.alternatesIo);
    if (fp === null || fp.newestNs >= at - RACY_WINDOW_NS) return null;
    const state = await reads.stateOf(roots);
    if (this.closed) return null;
    return { facts, config, digest: fp.digest, state };
  }

  /** Settles when every prefetched state is computed or given up (a test
   *  aid: the launch never waits for it). */
  async ready(): Promise<void> {
    await Promise.all([...this.snaps.values()]);
  }

  /** StatePrefetch: the prefetched state of exactly `roots`, when its
   *  inputs are unchanged (the module comment); else null. Each is offered
   *  once. Never throws. */
  async take(roots: readonly string[], reads: RepoReads): Promise<HistoryState | null> {
    const key = roots.join("\0");
    const p = this.snaps.get(key);
    if (p === undefined) return null;
    this.snaps.delete(key);
    const discard = (why: string): null => { this.stats.discarded.push(`${roots[0]}: ${why}`); return null; };
    try {
      const snap = await p;
      if (snap === null) return discard("no prefetched state (failed, racy or in doubt)");
      const facts = await Promise.all(roots.map((r) => reads.factsOf(r)));
      const config = await reads.configOf(roots[0]!);
      if (JSON.stringify(facts) !== JSON.stringify(snap.facts) || JSON.stringify(config) !== JSON.stringify(snap.config)) {
        return discard("the repository's facts or config changed");
      }
      const fp = stateFingerprint(roots, facts[0]!, this.opts.alternatesIo);
      if (fp === null || fp.digest !== snap.digest) return discard("its refs, reflogs or objects changed");
      this.stats.used++;
      return snap.state;
    } catch (e) {
      return discard((e as Error).message);
    }
  }

  /** Kill every git call still running. */
  private kill(): void {
    for (const c of [...this.children]) c.kill("the launch's git prefetch was closed");
  }

  /** End the prefetch: no state is offered any more, every git call still
   *  running is killed, and the hashes (when its own) end. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.snaps.clear();
    this.kill();
    process.removeListener("exit", this.onExit);
    if (this.ownsHashes) this.hashes.close();
  }
}

/** The launch's prefetch from the hint of `workspaceRoots` under the Mandu
 *  home `env` and `home` name (the paths applySecretTwins uses), or null:
 *  no hint, or anything failed. Never throws. */
export function startTwinPrefetch(
  env: NodeJS.ProcessEnv, home: string, workspaceRoots: readonly string[], gitSession?: GitSession,
): TwinPrefetch | null {
  try {
    return TwinPrefetch.start({
      hintFile: launchHintFile(manduPath("object-walks", env, home), workspaceRoots),
      cacheDir: manduPath("object-twins", env, home),
      ...(gitSession !== undefined ? { gitSession } : {}),
    });
  } catch {
    return null;
  }
}
