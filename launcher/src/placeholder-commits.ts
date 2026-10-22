/**
 * placeholder-commits — say so when git in a session put a protected file's
 * PLACEHOLDER copy into the user's repository (docs/design/confidentiality/
 * confidentiality.md §7.2a "A placeholder in your repository").
 *
 * Inside the agent's world a protected file is its twin (secret-twins.ts):
 * the file's keys with each value a `$MDU:` placeholder, or one placeholder
 * for the whole file. git in that world hashes what it reads, so when a file
 * git tracks is protected, `git commit -a`, `git add -A` / `git add .` and
 * `git stash` after ANY change stage the twin's bytes: the user's real `.git`
 * then holds the placeholder (git there never reads the secret). The user's
 * file on disk is untouched, so outside the session `git status` shows it
 * modified, and a `git checkout -- <file>`, `git restore <file>` or `git
 * reset --hard` there would write the placeholder over the real file; a push
 * spreads it.
 *
 * Nothing in the agent's world stops it (a commit of the twin is git doing
 * what it was asked). So the launcher checks, OUTSIDE that world, by blob id:
 *
 *   - at launch, for each protected file inside a git work tree, tracked or
 *     not (an untracked one, ignored or not, can still be added: `git add
 *     -A`, `git add -f`, a `.gitignore` line removed), the ids git would
 *     store for the twin: its bytes as they are and with CRLF turned into LF
 *     (what `core.autocrlf` or a `text` attribute makes of them), each as
 *     SHA-1 and SHA-256 (`git hash-object --no-filters`, computed here: no
 *     git call); which of them the index holds (`ls-files -s`); and the
 *     repository's tips (`rev-list --all --no-walk`). A record of this is
 *     left in the Mandu home, which the agent can neither read nor write;
 *   - after the agent exits, the index entries of those paths (`ls-files
 *     -s`) and the commits added since the launch's tips (`log --raw
 *     --full-history` from the new tips, the old ones excluded: a side
 *     branch merged away is walked too) are looked up for those ids, and
 *     the twin's current bytes too (the agent may have edited the twin). A
 *     hit prints one WARNING block: which file, staged or in which commit
 *     (and whether that commit is already on a remote), the commands that
 *     take the placeholder out of git's record, and the commands NOT to run
 *     before. The repair is REMOVE-ONLY: no printed command puts any version
 *     of the file into git, neither the file on disk (`git add`, a commit
 *     with `-a` or a pathspec) nor a version from another commit or branch
 *     (`--source`, a checkout), so following it cannot put a secret into
 *     the history whatever the check got wrong. What is only staged is
 *     unstaged FIRST (`git restore --staged`: back to what the checked-out
 *     commit itself holds, or out of the index when it holds nothing there;
 *     `git rm --cached -f` on a branch with no commit), so the commit below
 *     cannot take it along; then a placeholder in the checked-out commit
 *     leaves the index (`git rm --cached -f`) and the commit is amended
 *     (not pushed) or a new one made. A file that belongs in git the user
 *     adds back, knowing what is on disk is the real file; an older commit
 *     that holds the placeholder is named, and rewriting it is the user's
 *     decision. No secret value is ever read or printed: only ids, paths
 *     and commit names. A placeholder already staged at launch is not said
 *     again. The record is cleared once checked;
 *   - a record whose launcher is gone (a crash, a kill) is checked by the
 *     next launch and printed there; it is checked AGAIN after that launch's
 *     agent exits, and said again unless that launch's own check said the
 *     same. A record whose check at launch did not complete (a git call
 *     failed or was cut off, or the time ran out before every repository)
 *     stays on disk until that second check, so a launch killed in turn
 *     loses nothing. Only from a record folder that is a real directory
 *     inside the Mandu home (never read through a swapped link, nor made
 *     through one), and a record of a version this launcher does not know
 *     is left alone.
 *
 * Every git call is the hardened, sandboxed runner of git-object-twins.ts
 * (write-protection.md §8): the agent can write these repositories' config
 * and attributes, and no call here hashes a working copy or starts a driver.
 * The cost is bounded: only repositories holding such a file, two calls
 * each at launch (`ls-files -s`, `rev-list`; each cut off after
 * WATCH_GIT_TIMEOUT_MS, since the watch is advisory and must not hold the
 * launch up), two or three at exit, a few more only on a hit.
 *
 * Not caught: a file a clean filter changes on its way into git (Git LFS,
 * git-crypt), an intermediate edit of the twin committed and then edited
 * again (only the launch's and the final bytes are known), and a commit no
 * ref holds when the check runs.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import {
  closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, rmSync, statSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { defaultGitRunner, repoRootOf, type GitRun, type GitRunner } from "./git-object-twins.js";
import { IGNORE_SHALLOW_ARGS, walkShallowRule } from "./history-labels.js";
import { publishFile } from "./safe-file.js";

/** The mark every placeholder carries (secret-twins.ts). */
const PLACEHOLDER_MARK = "$MDU:";

/** Each git call of the launch's watch, and of the launch's check of an
 *  earlier session's record, at most: both are advisory and must not hold
 *  the launch up (a call cut off leaves its answer unknown: never read as
 *  a "no", and a record so checked is kept for a second check). */
export const WATCH_GIT_TIMEOUT_MS = 5_000;

// ── Pure: the ids git would store ───────────────────────────────────────────

/** `git hash-object --no-filters` of `bytes`, in the object format of
 *  `algo` (sha1 for SHA-1 repositories, sha256 for SHA-256 ones). Pure. */
export function gitBlobId(bytes: Uint8Array, algo: "sha1" | "sha256"): string {
  return createHash(algo).update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

/** The blob ids `git add` can store for a twin's content: its bytes as they
 *  are, and with every CRLF turned into LF (core.autocrlf, a `text`
 *  attribute), each in both object formats (sorted, unique). Pure. */
export function placeholderBlobIds(content: string | Uint8Array): string[] {
  const raw = typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content);
  const variants = [raw];
  if (raw.includes("\r\n")) variants.push(Buffer.from(raw.toString("latin1").replace(/\r\n/g, "\n"), "latin1"));
  return [...new Set(variants.flatMap((v) => [gitBlobId(v, "sha1"), gitBlobId(v, "sha256")]))].sort();
}

// ── Pure: git output ────────────────────────────────────────────────────────

const HEX = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const ZERO = /^0+$/;

function hexLines(out: string): string[] {
  return out.split("\n").map((l) => l.trim()).filter((l) => HEX.test(l));
}

/** `git ls-files -z -s` output (with `-o`, the untracked paths it lists
 *  too): the paths in the index, each with its blobs (every stage). Pure. */
export function parseWatchList(out: string): { tracked: Map<string, string[]>; untracked: Set<string> } {
  const tracked = new Map<string, string[]>();
  const untracked = new Set<string>();
  for (const rec of out.split("\0")) {
    if (rec === "") continue;
    const m = /^(\d{6}) ([0-9a-f]+) \d\t(.*)$/s.exec(rec);
    if (m !== null) {
      if (m[1] === "160000" || !HEX.test(m[2]!)) continue;
      const l = tracked.get(m[3]!) ?? [];
      l.push(m[2]!);
      tracked.set(m[3]!, l);
    } else {
      untracked.add(rec);
    }
  }
  return { tracked, untracked };
}

/** `git ls-tree -r -z` output: path → blob. Pure. */
export function parseLsTree(out: string): Map<string, string> {
  const got = new Map<string, string>();
  for (const rec of out.split("\0")) {
    const m = /^(\d{6}) blob ([0-9a-f]+)\t(.*)$/s.exec(rec);
    if (m !== null && HEX.test(m[2]!)) got.set(m[3]!, m[2]!);
  }
  return got;
}

/** A call that answered "no" plainly: exit 1 with nothing printed
 *  (`rev-parse -q --verify` of no commit, `show-ref --verify -q` of no
 *  ref). A call cut off at its deadline also ends 1, but says so on
 *  stderr, so it is never taken for a "no". Pure. */
export function plainNo(r: GitRun): boolean {
  return r.code === 1 && r.stdout.trim() === "" && r.stderr.trim() === "";
}

/** One commit of `git log --raw -z --no-abbrev -m --format=%x01%H`: the
 *  (blob, path) of every path it changed, its own side (a merge lists its
 *  changes against each parent). */
export interface CommitChanges {
  sha: string;
  changes: Array<[string, string]>;
}

/** The commits of `git log --raw -z --no-abbrev --no-renames -m
 *  --format=%x01%H` output, in log order (newest first), each once. Pure. */
export function parseCommitChanges(out: string): CommitChanges[] {
  const order: CommitChanges[] = [];
  const bySha = new Map<string, CommitChanges>();
  let cur: CommitChanges | null = null;
  const toks = out.split("\0");
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!.replace(/^\n+/, "");
    if (t.startsWith("\x01")) {
      const sha = t.slice(1).trim();
      if (!HEX.test(sha)) { cur = null; continue; }
      cur = bySha.get(sha) ?? null;
      if (cur === null) { cur = { sha, changes: [] }; bySha.set(sha, cur); order.push(cur); }
      continue;
    }
    if (!t.startsWith(":")) continue;
    const path = toks[i + 1];
    i++;
    if (cur === null || path === undefined) continue;
    const [, dstMode, , dst] = t.slice(1).split(" ");
    if (dst !== undefined && HEX.test(dst) && !ZERO.test(dst) && dstMode !== "160000") cur.changes.push([dst, path]);
  }
  return order;
}

// ── The watch, the record and the findings ──────────────────────────────────

/** One protected file inside a repository's work tree, tracked or not (an
 *  untracked one, ignored or not, is watched too: `git add -A` takes an
 *  unignored one, `git add -f` an ignored one). */
export interface WatchedPath {
  /** Relative to the work tree. */
  rel: string;
  /** The ids `git add` can store for its twin (placeholderBlobIds). */
  ids: string[];
  /** Its blobs in the index at launch: a placeholder staged before the
   *  session (and said then) is not said again. */
  index?: string[];
  /** The twin file (its bytes are hashed again at the check, when it still
   *  exists and still holds a placeholder). */
  twin?: string;
}

export interface WatchedRepo {
  /** The work tree. */
  root: string;
  /** The commits every ref and HEAD named at launch (sorted); null when
   *  there were too many to keep (then only the index is checked). */
  tips: string[] | null;
  paths: WatchedPath[];
}

/** A protected file as the launch twinned it. */
export interface TwinSource {
  /** The real path the twin stands for. */
  targetPath: string;
  /** The twin's content (what the agent's git reads). */
  content: string;
  twinPath?: string;
}

/** The repositories one launch watches at most. */
export const WATCH_MAX_REPOS = 16;
/** The paths one repository's watch holds at most. */
export const WATCH_MAX_PATHS = 256;
/** The launch tips kept per repository at most. */
export const WATCH_MAX_TIPS = 65536;
/** The commits the check names refs for at most (one call each). */
const MAX_COMMITS_NAMED = 6;
/** The twin bytes the check hashes at most. */
const TWIN_MAX_BYTES = 4 * 1024 * 1024;

/** `fn` over `items`, at most `limit` at once; results in input order. */
async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export interface WatchOpts {
  git?: GitRunner;
  exists?: (p: string) => boolean;
  log?: (m: string) => void;
  /** Each git call at most (default WATCH_GIT_TIMEOUT_MS). */
  timeoutMs?: number;
}

/**
 * What to watch for this launch: each protected file inside a git work tree,
 * tracked or not (an ignored one too: `git add -f`, or a `.gitignore` line
 * the agent removes, adds it all the same), with the ids its twin would get
 * and the blobs the index holds for it, and each such repository's tips.
 * Two calls per repository, each cut off after `timeoutMs`. Never throws: a
 * repository git cannot read is left out (logged).
 */
export async function preparePlaceholderWatch(files: readonly TwinSource[], opts: WatchOpts = {}): Promise<WatchedRepo[]> {
  const git = opts.git ?? defaultGitRunner;
  const exists = opts.exists ?? existsSync;
  const byRoot = new Map<string, Map<string, TwinSource>>();
  for (const f of files) {
    const root = repoRootOf(f.targetPath, exists);
    if (root === null) continue;
    const rel = relative(root, f.targetPath);
    if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) continue;
    const m = byRoot.get(root) ?? new Map<string, TwinSource>();
    m.set(rel, f);
    byRoot.set(root, m);
  }
  const roots = [...byRoot.keys()].sort();
  if (roots.length > WATCH_MAX_REPOS) {
    opts.log?.(`mandu: ${roots.length - WATCH_MAX_REPOS} repositor${roots.length - WATCH_MAX_REPOS === 1 ? "y" : "ies"} holding a protected file are not checked for a placeholder commit this session (over ${WATCH_MAX_REPOS})`);
  }
  const got = await mapLimit(roots.slice(0, WATCH_MAX_REPOS), 8, async (root): Promise<WatchedRepo | null> => {
    const byRel = byRoot.get(root)!;
    const rels = [...byRel.keys()].sort().slice(0, WATCH_MAX_PATHS);
    const call = { cwd: root, timeoutMs: opts.timeoutMs ?? WATCH_GIT_TIMEOUT_MS };
    try {
      // Which of them the index holds (every other one is untracked, and
      // watched all the same, ignored or not), and the tips. Spelled as the
      // history step asks them (git-object-twins.ts protectedBlobsOf,
      // historyStateOfRoots), so the launch's shared runner asks each once
      // (git-shared-answers.ts).
      const [ls, t] = await Promise.all([
        git(["ls-files", "-s", "-z", "--", ...rels], call),
        git(["rev-list", "--all", "--no-walk"], call),
      ]);
      if (ls.code !== 0) throw new Error(ls.stderr.trim().split("\n").slice(-1)[0] || `exit ${ls.code}`);
      const { tracked } = parseWatchList(ls.stdout);
      const paths: WatchedPath[] = rels.map((rel) => {
        const f = byRel.get(rel)!;
        return {
          rel, ids: placeholderBlobIds(f.content), index: [...new Set(tracked.get(rel) ?? [])].sort().slice(0, 8),
          ...(f.twinPath !== undefined ? { twin: f.twinPath } : {}),
        };
      });
      if (paths.length === 0) return null;
      const tips = t.code === 0 ? [...new Set(hexLines(t.stdout))].sort() : null;
      return { root, tips: tips !== null && tips.length <= WATCH_MAX_TIPS ? tips : null, paths };
    } catch (e) {
      opts.log?.(`mandu: ${root} is not checked for a placeholder commit this session (git: ${(e as Error).message})`);
      return null;
    }
  });
  return got.filter((r): r is WatchedRepo => r !== null);
}

/** What git holds at the check, as checkPlaceholderRepo reads it. */
export interface RepoState {
  /** path → blobs in the index (every stage). */
  index: ReadonlyMap<string, readonly string[]>;
  /** The new commits (newest first) and their changes to the watched paths. */
  commits: readonly CommitChanges[];
  /** HEAD's commit; null when unborn or unread. */
  head: string | null;
  /** HEAD's branch (`refs/heads/…`); null when detached. */
  headRef: string | null;
  /** HEAD names a branch with no commit yet (no commit at all to restore
   *  the index from). */
  unborn?: boolean;
  /** path → blob in HEAD's tree (empty on a branch with no commit); null
   *  when HEAD's tree was not read. */
  headBlobs: ReadonlyMap<string, string> | null;
  /** commit → the refs that hold it (`for-each-ref --contains`). */
  refsOf: ReadonlyMap<string, readonly string[]>;
  /** What could not be checked, said in the warning. */
  partial?: string;
}

export interface RepoFinding {
  root: string;
  /** New commits holding a placeholder (newest first), each with the refs
   *  that hold it (`refsUnread`: they could not be read). */
  commits: Array<{ sha: string; rels: string[]; refs: string[]; refsUnread?: boolean }>;
  /** Files whose checked-out version (HEAD) is a placeholder: the repair
   *  takes each out of the index, and the commit out of HEAD. */
  inHead: string[];
  /** Files staged as a placeholder whose HEAD version is not one. */
  staged: string[];
  /** Files git no longer tracks once the repair has run (on disk only):
   *  every one in HEAD, and those staged that HEAD does not hold (or on a
   *  branch with no commit). The warning says that the user adds back one
   *  that belongs in git, and lists the others in `.gitignore`, so a later
   *  `git add -A` does not take the real file. */
  leaves: string[];
  head: string | null;
  headRef: string | null;
  /** HEAD's branch has no commit yet (RepoState `unborn`). */
  unborn?: boolean;
  /** HEAD's tree could not be read: nothing is said of what it holds. */
  headUnread?: boolean;
  /** HEAD is one of `commits` and no remote holds it: amend repairs it. */
  amend: boolean;
  partial?: string;
}

/** The ids of a watched path, with `extra` (the twin's bytes now). */
function idSet(p: WatchedPath, extra?: ReadonlyMap<string, readonly string[]>): Set<string> {
  return new Set([...p.ids, ...(extra?.get(p.rel) ?? [])]);
}

/** Which watched files git now holds as a placeholder, staged or in a new
 *  commit; null when none. Pure. */
export function findPlaceholders(repo: WatchedRepo, state: RepoState, extra?: ReadonlyMap<string, readonly string[]>): RepoFinding | null {
  const ids = new Map(repo.paths.map((p) => [p.rel, idSet(p, extra)]));
  const isPlaceholder = (rel: string, blob: string | undefined): boolean => blob !== undefined && ids.get(rel)?.has(blob) === true;
  const commits: RepoFinding["commits"] = [];
  for (const c of state.commits) {
    const rels = [...new Set(c.changes.filter(([b, p]) => isPlaceholder(p, b)).map(([, p]) => p))].sort();
    const refs = state.refsOf.get(c.sha);
    if (rels.length > 0) commits.push({ sha: c.sha, rels, refs: [...(refs ?? [])].sort(), ...(refs === undefined ? { refsUnread: true } : {}) });
  }
  const headBlobs = state.headBlobs;
  const inHead = repo.paths.filter((p) => headBlobs !== null && isPlaceholder(p.rel, headBlobs.get(p.rel))).map((p) => p.rel);
  // Staged in the session: a placeholder in the index now that was not
  // there at launch (one staged before was said by the session before).
  const staged = repo.paths
    .filter((p) => !inHead.includes(p.rel))
    .filter((p) => (state.index.get(p.rel) ?? []).some((b) => isPlaceholder(p.rel, b) && !(p.index ?? []).includes(b)))
    .map((p) => p.rel);
  if (commits.length === 0 && inHead.length === 0 && staged.length === 0) return null;
  const headHit = state.head !== null ? commits.find((c) => c.sha === state.head) : undefined;
  // Amend only a HEAD that is one of the session's commits and that no
  // remote holds, as far as Mandu could read (refs unread: a new commit).
  const amend = inHead.length > 0 && headHit !== undefined && headHit.refsUnread !== true && !headHit.refs.some((r) => r.startsWith("refs/remotes/"));
  const leaves = [...new Set([
    ...staged.filter((rel) => state.unborn === true || (headBlobs !== null && !headBlobs.has(rel))),
    ...inHead,
  ])].sort();
  return {
    root: repo.root, commits, inHead, staged, leaves, head: state.head, headRef: state.headRef, amend,
    ...(state.unborn === true ? { unborn: true } : {}),
    ...(headBlobs === null ? { headUnread: true } : {}),
    ...(state.partial !== undefined ? { partial: state.partial } : {}),
  };
}

// ── Pure: the warning ───────────────────────────────────────────────────────

/** A path for a terminal line: control characters shown as `?`. Pure. */
function shown(p: string): string {
  // eslint-disable-next-line no-control-regex
  return p.replace(/[\u0000-\u001f\u007f]/g, "?");
}

/** A path as one shell word. Pure. */
export function shellWord(p: string): string {
  const s = shown(p);
  return /^[A-Za-z0-9._/@%+=:,-]+$/.test(s) && !s.startsWith("-") ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

const short = (sha: string): string => sha.slice(0, 10);
const list = (rels: readonly string[]): string => rels.map(shown).join(", ");

/** Where a commit is, from the refs that hold it: its branches, and the
 *  remotes it already reached. Each name as shown(): the refs are the
 *  agent's to write. Pure. */
export function whereCommit(refs: readonly string[]): string {
  const under = (p: string): string[] => refs.filter((r) => r.startsWith(p)).map((r) => shown(r.slice(p.length)));
  const heads = under("refs/heads/");
  const tags = under("refs/tags/").map((t) => `tag ${t}`);
  const stash = refs.includes("refs/stash") ? ["the stash"] : [];
  const remotes = under("refs/remotes/");
  const local = [...heads, ...tags, ...stash];
  const at = local.length > 0 ? local.join(", ") : remotes.length > 0 ? "" : "on no branch";
  const pushed = remotes.length > 0 ? `already pushed: ${remotes.join(", ")}` : heads.length + tags.length > 0 ? "not pushed" : "";
  return [at, pushed].filter((x) => x !== "").join("; ");
}

/** The commands that take the placeholder out of git's record, run outside
 *  a Mandu session in its work tree, in this order. REMOVE-ONLY: each
 *  changes only git's record (the index, a commit), never the file on disk
 *  (never a checkout, a restore of the work tree, a reset or a stash), and
 *  none puts any version of the file into git: never `git add`, never a
 *  commit with `-a` or a pathspec (each takes the file on disk, the real
 *  one), never `--source` nor anything else that takes a version from
 *  another commit or branch (a local branch can hold the real one). So
 *  whatever the check or a record got wrong, following them cannot copy a
 *  protected file's content into the history. What the commit records is
 *  the index once the placeholder is out: other work staged there goes in
 *  too, which the warning says to check first. Pure. */
export function repairCommands(f: RepoFinding): string[] {
  const out: string[] = [];
  // FIRST what is only staged, so the commit below cannot take it along
  // (a `git commit -a` then a `git add -A` leaves one file's placeholder in
  // HEAD and another's staged). `git restore --staged` sets the index entry
  // back to what HEAD itself holds (content already in this branch's
  // history; `staged` holds no path whose HEAD version has one of the
  // twin's ids, that is `inHead`), or drops it where HEAD holds none. A branch with no commit has no HEAD to
  // restore from (`git restore --staged` fails): out of the index instead.
  // -f: that staged placeholder differs from both the file and the missing
  // HEAD, which plain `git rm --cached` refuses; --cached leaves the file on
  // disk alone.
  if (f.staged.length > 0) {
    const words = f.staged.map(shellWord).join(" ");
    out.push(f.unborn === true ? `git rm --cached -f -- ${words}` : `git restore --staged -- ${words}`);
  }
  // A placeholder in HEAD: out of the index (-f as above, should the index
  // hold yet another placeholder of it), and the commit records that.
  // Nothing comes back in its place: whether the file belongs in git, with
  // the content on disk, is the user's to decide (the warning says so).
  if (f.inHead.length > 0) {
    out.push(`git rm --cached -f -- ${f.inHead.map(shellWord).join(" ")}`);
    // --allow-empty: a commit that held nothing but a new file's placeholder
    // is empty once that is out, and git would refuse the amend. No
    // pathspec: `git commit -- <file>` commits the work tree's copy of each
    // path it names, the real content of the file just taken out.
    out.push(f.amend ? "git commit --amend --no-edit --allow-empty"
      : `git commit -m ${shellWord(`Take the placeholder copy of ${f.inHead.length === 1 ? "a protected file" : "protected files"} out of git`)}`);
  }
  return out;
}

/**
 * The WARNING block for one repository: the files and where git holds their
 * placeholder, the commands that take it out (repairCommands), what is left
 * to the user (adding a file back that belongs in git, `.gitignore`,
 * rewriting an older commit), and what not to run before. Names files,
 * commits and refs only: never a secret, which is never read. Says only
 * what the check verified: that what git recorded is the placeholder (by
 * its id), never that git holds no secret elsewhere. Pure.
 */
export function placeholderWarning(f: RepoFinding): string[] {
  const files = [...new Set([...f.commits.flatMap((c) => c.rels), ...f.inHead, ...f.staged])].sort();
  const one = files.length === 1;
  const lines: string[] = [
    `WARNING: mandu: git in the agent's session recorded Mandu's placeholder copy of ${one ? "a protected file" : `${files.length} protected files`} ` +
      `in place of your real ${one ? "file" : "files"}, in ${shown(f.root)}:`,
  ];
  for (const c of f.commits) {
    lines.push(`  - commit ${short(c.sha)} (${c.refsUnread === true ? "where it is could not be read" : whereCommit(c.refs)}) holds the placeholder of ${list(c.rels)}`);
  }
  const headOnly = f.inHead.filter((rel) => !f.commits.some((c) => c.rels.includes(rel)));
  if (headOnly.length > 0) lines.push(`  - your checked-out commit holds the placeholder of ${list(headOnly)}`);
  if (f.staged.length > 0) lines.push(`  - staged for your next commit: ${list(f.staged)}`);
  lines.push("  What git recorded there is the placeholder, not your secret.");
  const cmds = repairCommands(f);
  if (cmds.length > 0) {
    lines.push(
      `  Take the placeholder out of git's record outside a Mandu session, in ${shown(f.root)}${cmds.length > 1 ? ", in this order" : ""} ` +
        "(no command here adds your file on disk to git, or brings back a version of it from another commit or branch):",
    );
    for (const c of cmds) lines.push(`    ${c}`);
    // The commit takes the whole index: other work staged in (or before)
    // the session would go in with it.
    if (cmds.some((c) => c.startsWith("git commit"))) {
      lines.push("  Before the commit: it takes everything staged, so check `git status` and unstage what should not go in (git restore --staged -- <file>).");
    }
  } else if (f.headUnread !== true && f.commits.length > 0) {
    lines.push("  Your checked-out commit does not hold this placeholder.");
  }
  // Nothing comes back in a file's place: the user decides whether it
  // belongs in git, and what goes in then is the file on disk, the real
  // one. A protected file out of git and not ignored is one `git add -A`
  // away from going in with its real value.
  if (f.leaves.length > 0) {
    const several = f.leaves.length > 1;
    lines.push(
      `  After this, git no longer tracks ${list(f.leaves)}. If ${several ? "one of them" : "it"} belongs in git, check what the file on disk holds ` +
        "and add it back yourself: what you add is your real file. Mandu prints no command that puts it back.",
      `  If not, list ${several ? "them" : "it"} in .gitignore (if ${several ? "they are" : "it is"} not there yet): ` +
        `untracked, a later git add -A would take your real ${several ? "files" : "file"}.`,
    );
  }
  // A commit the commands above do not replace (an older one, one on
  // another branch or in the stash, HEAD once pushed): named, and taking
  // the placeholder out of it means rewriting history, the user's call.
  // Mandu prints no command for that.
  for (const c of f.commits) {
    if (f.amend && c.sha === f.head) continue; // the amend replaces it
    if (c.refs.length > 0 && c.refs.every((r) => r === "refs/stash")) {
      lines.push(`  Commit ${short(c.sha)} is in the stash: do not apply or pop that stash entry; once you have kept what you need from it, git stash drop removes it.`);
      continue;
    }
    const remotes = c.refs.filter((r) => r.startsWith("refs/remotes/")).map((r) => shown(r.slice("refs/remotes/".length)));
    const elsewhere = c.refs.filter((r) => r.startsWith("refs/heads/") && r !== f.headRef).map((r) => shown(r.slice("refs/heads/".length)));
    let note = `  Commit ${short(c.sha)} keeps the placeholder in your history${cmds.length > 0 ? " after this repair" : ""}` +
      `${remotes.length > 0 ? ` (it is already on ${remotes.join(", ")})` : ""}: taking it out of that commit means rewriting history, which is your decision.`;
    if (elsewhere.length > 0) {
      const a = elsewhere.length === 1;
      note += ` Do not merge ${elsewhere.join(", ")} as ${a ? "it is" : "they are"}; checking ${a ? "it" : "one"} out can write the placeholder over your real file.`;
    }
    lines.push(note);
  }
  lines.push(
    `  ${cmds.length > 0 ? "Until then" : "Meanwhile"}, do NOT run git checkout, git restore without --staged, git reset --hard or git stash (push or pop) on ${one ? "this file" : "these files"}: ` +
      "each can write the placeholder over your real file.",
  );
  if (f.partial !== undefined) lines.push(`  (Not fully checked: ${f.partial}.)`);
  return lines;
}

// ── The check (git calls) ───────────────────────────────────────────────────

/** The twin's current bytes, when it is still a regular file holding a
 *  placeholder (opened without following a link, bounded); else null. */
export function readTwinNow(path: string): Buffer | null {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > TWIN_MAX_BYTES) return null;
    const b = readFileSync(fd);
    return b.includes(PLACEHOLDER_MARK) ? b : null;
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

export interface CheckOpts {
  git?: GitRunner;
  /** How the twin's current bytes are read (default readTwinNow). */
  readTwin?: (path: string) => Buffer | null;
  /** Each git call at most, the commit walk included (default 30 s, and
   *  60 s for the walk). The launch's check of an earlier session's record
   *  passes WATCH_GIT_TIMEOUT_MS: that record is checked again after the
   *  agent exits, without the hurry. */
  timeoutMs?: number;
}

/** One repository checked: what git holds of the watched files (null:
 *  nothing), and why the check could not run in full when nothing was
 *  found (`error`). */
export interface RepoCheck {
  finding: RepoFinding | null;
  error?: string;
  /** A git call failed or was cut off: what was said may fall short (a
   *  record so checked at launch is kept for a second check). */
  failed?: boolean;
}

/** The global options a walk in the work tree `root` runs with under the
 *  shallow rule (history-labels.ts walkShallowRule), read now. A failure to
 *  tell ignores the shallow file (the walk then goes through every present
 *  parent, or fails and the check says so). */
export async function shallowArgsAt(git: GitRunner, root: string, timeoutMs: number): Promise<string[]> {
  const r = await git(["rev-parse", "--show-object-format", "--git-path", "shallow"], { cwd: root, timeoutMs });
  const [fmt, path] = r.stdout.split("\n").map((l) => l.trim());
  if (r.code !== 0 || (fmt !== "sha1" && fmt !== "sha256") || path === undefined || path === "") return [...IGNORE_SHALLOW_ARGS];
  let text = "";
  try { text = readFileSync(resolve(root, path), "utf8"); } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") return [...IGNORE_SHALLOW_ARGS];
  }
  const rule = await walkShallowRule((args, input) => git(args, { cwd: root, input, timeoutMs }), text, fmt === "sha256" ? 64 : 40);
  return rule.args;
}

/** One repository of a record, checked now. A git call that fails is named
 *  (in the finding, or as `error`), never thrown. */
export async function checkPlaceholderRepo(repo: WatchedRepo, opts: CheckOpts = {}): Promise<RepoCheck> {
  const git = opts.git ?? defaultGitRunner;
  const readTwin = opts.readTwin ?? readTwinNow;
  if (!existsSync(repo.root)) return { finding: null };
  const rels = repo.paths.map((p) => p.rel);
  const extra = new Map<string, string[]>();
  for (const p of repo.paths) {
    if (p.twin === undefined) continue;
    const now = readTwin(p.twin);
    if (now !== null) extra.set(p.rel, placeholderBlobIds(now));
  }
  const partial: string[] = [];
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const walkMs = opts.timeoutMs ?? 60_000;
  let anyFailed = false;
  const failed = (args: readonly string[], r: GitRun): void => {
    anyFailed = true;
    partial.push(`git ${args[0]} failed: ${r.stderr.trim().split("\n").slice(-1)[0] || `exit ${r.code}`}`);
  };
  const run = async (args: string[], input?: string): Promise<string | null> => {
    const r = await git(args, { cwd: repo.root, timeoutMs: walkMs, ...(input !== undefined ? { input } : {}) });
    if (r.code !== 0) { failed(args, r); return null; }
    return r.stdout;
  };
  const [idxOut, tipsOut] = await Promise.all([
    run(["ls-files", "-z", "-s", "--", ...rels]),
    repo.tips !== null ? run(["rev-list", "--all", "--no-walk"]) : Promise.resolve(null),
  ]);
  const index = new Map<string, string[]>();
  for (const [rel, blobs] of parseWatchList(idxOut ?? "").tracked) index.set(rel, blobs);
  let commits: CommitChanges[] = [];
  if (repo.tips === null) partial.push("the session's commits cannot be told: its branches and tags were too many, or unreadable, at launch");
  else if (tipsOut !== null) {
    const old = new Set(repo.tips);
    const fresh = [...new Set(hexLines(tipsOut))].filter((t) => !old.has(t));
    if (fresh.length > 0) {
      // --full-history: with a pathspec, git's default simplification
      // follows a merge through one parent the paths are the same in, and
      // prunes the other side: a placeholder commit on a branch merged with
      // `-s ours` (then deleted), or a stash's index commit, would be missed.
      // (Recent git's `-m` keeps that side as well; the documented switch
      // keeps the check from resting on it.) The walk is bounded to the new
      // commits anyway.
      // History as the objects record it: grafts and replace refs are off
      // for every hardened call, and a shallow file the session may have
      // written is honoured only where it is true (history-labels.ts
      // walkShallowRule), so neither can cut a placeholder commit out of
      // this walk.
      const walkArgs = await shallowArgsAt(git, repo.root, walkMs);
      const out = await run(
        [...walkArgs, "log", "--ignore-missing", "--stdin", "--full-history", "--raw", "-z", "--no-abbrev", "--no-renames", "-m", "--format=%x01%H", "--", ...rels],
        `${fresh.join("\n")}\n${repo.tips.map((t) => `^${t}`).join("\n")}\n`,
      );
      if (out !== null) commits = parseCommitChanges(out);
    }
  }
  const empty: RepoState = { index, commits, head: null, headRef: null, headBlobs: null, refsOf: new Map() };
  const first = findPlaceholders(repo, empty, extra);
  // Nothing staged and no new commit (a placeholder already in HEAD before
  // the session was said then): clean, or a check git could not run.
  if (first === null) return partial.length > 0 ? { finding: null, error: partial.join("; "), ...(anyFailed ? { failed: true } : {}) } : { finding: null };
  // A hit: where HEAD is, what it holds, and where each commit is.
  const call = { cwd: repo.root, timeoutMs };
  const treeArgs = ["ls-tree", "-r", "-z", "HEAD", "--", ...rels];
  const [headOut, refOut, treeOut] = await Promise.all([
    git(["rev-parse", "-q", "--verify", "HEAD"], call),
    git(["symbolic-ref", "-q", "HEAD"], call),
    git(treeArgs, call),
  ]);
  const head = headOut.code === 0 && HEX.test(headOut.stdout.trim()) ? headOut.stdout.trim() : null;
  const headRef = refOut.code === 0 && refOut.stdout.trim().startsWith("refs/") ? refOut.stdout.trim() : null;
  // Unborn: HEAD names a branch, `rev-parse -q --verify` says plainly (exit
  // 1, nothing printed, not cut off) that it resolves to no commit, and that
  // branch's ref does not exist (`show-ref --verify -q`: 1; a ref to a
  // missing commit is 128, and an empty, unreadable or garbled one already
  // fails `symbolic-ref`). Anything else is a HEAD not read, never taken
  // for an unborn one: its repair (out of the index) would untrack a file
  // HEAD may hold.
  let unborn = false;
  if (head === null && headRef !== null && plainNo(headOut)) {
    unborn = plainNo(await git(["show-ref", "--verify", "-q", headRef], call));
  }
  const headBlobs = unborn ? new Map<string, string>() : treeOut.code === 0 ? parseLsTree(treeOut.stdout) : null;
  if (headBlobs === null) failed(treeArgs, treeOut);
  const named = first.commits.slice(0, MAX_COMMITS_NAMED);
  // Where each commit is. A call that fails leaves it unknown (said so,
  // never "on no branch"), and a HEAD whose refs are unknown is never
  // amended: it may be on a remote already.
  const refsOf = new Map<string, string[]>();
  for (const [c, r] of await Promise.all(named.map(async (c) => [c, await git(["for-each-ref", "--contains", c.sha, "--format=%(refname)"], call)] as const))) {
    if (r.code === 0) refsOf.set(c.sha, r.stdout.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("refs/")));
    else failed(["for-each-ref"], r);
  }
  const found = findPlaceholders(repo, {
    index, commits: commits.filter((c) => named.some((n) => n.sha === c.sha)), head, headRef, unborn, headBlobs, refsOf,
    ...(partial.length > 0 ? { partial: partial.join("; ") } : {}),
  }, extra);
  if (found !== null && first.commits.length > named.length) {
    found.partial = [found.partial, `${first.commits.length - named.length} more commit(s) hold a placeholder`].filter((x) => x !== undefined).join("; ");
  }
  return { finding: found, ...(anyFailed ? { failed: true } : {}) };
}

/** The lines for one repository's check: its WARNING block, or one line
 *  when git could not check it. Pure. */
export function checkLines(root: string, c: RepoCheck): string[] {
  if (c.finding !== null) return placeholderWarning(c.finding);
  if (c.error !== undefined) return [`mandu: could not check ${shown(root)} for a placeholder copy of a protected file in git (${c.error})`];
  return [];
}

// ── The record, in the Mandu home ───────────────────────────────────────────

/** One launch's watch, left where the next launch finds it. */
export interface PlaceholderRecord {
  v: 1;
  /** The launcher that wrote it, and that process's start (procfs ticks)
   *  and the boot it ran in: a record is pending once that process is gone. */
  pid: number;
  startTicks: string | null;
  bootId: string | null;
  scopeId: string;
  /** When it was written (ms). */
  at: number;
  repos: WatchedRepo[];
}

/** The records' directory under the walk cache (the path table's
 *  `object-walks`, in the Mandu home's state: the agent can neither read
 *  nor write it). Pure. */
export function placeholderCheckDir(walkCacheDir: string): string {
  return join(walkCacheDir, "placeholder-checks");
}

export const RECORD_MAX_BYTES = 8 * 1024 * 1024;
/** Pending records one launch checks at most (oldest first). */
export const PENDING_MAX_RECORDS = 8;
/** How long the launch spends on pending records before its agent starts:
 *  once over, no further record, nor repository of a record, is started
 *  (the first of each always is). A record not started waits, on disk, for
 *  the next launch; one cut short stays on disk too and is checked in full
 *  after the agent exits. */
export const PENDING_LAUNCH_BUDGET_MS = 15_000;
/** The names writePlaceholderRecord gives: `<ms>-<pid>-<scope>.json`. Only
 *  such a file in the folder is ever read or removed. */
export const RECORD_NAME = /^\d{1,16}-\d{1,10}-[A-Za-z0-9._-]{0,64}\.json$/;

/**
 * May the records in `dir` be read, written and removed: `dir` and the walk
 * cache holding it are real directories (no symlink in their place), this
 * user's own, and `dir` resolves inside the Mandu home `home`. Mandu's
 * stores must lie inside its home (store-links.ts, on-disk-layout.md §4);
 * a store swapped for a link to somewhere else, planted while something ran
 * unconfined, is never followed, read from or cleaned. Never throws.
 */
export function recordDirSafe(dir: string, home: string): boolean {
  try {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    for (const d of [dirname(dir), dir]) {
      const st = lstatSync(d);
      if (st.isSymbolicLink() || !st.isDirectory()) return false;
      if (uid !== null && st.uid !== uid) return false;
    }
    const realHome = realpathSync(home);
    return realpathSync(dir).startsWith(realHome.endsWith("/") ? realHome : `${realHome}/`);
  } catch {
    return false;
  }
}

/** `/proc/<pid>/stat`'s start time (field 22), or null. */
export function processStartTicks(pid: number): string | null {
  try {
    const s = readFileSync(`/proc/${pid}/stat`, "utf8");
    const f = s.slice(s.lastIndexOf(")") + 2).split(" ");
    const v = f[19];
    return v !== undefined && /^\d+$/.test(v) ? v : null;
  } catch {
    return null;
  }
}

export function bootIdNow(): string | null {
  try { return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() || null; } catch { return null; }
}

/** This launch's record of `repos`. */
export function newPlaceholderRecord(scopeId: string, repos: readonly WatchedRepo[], now = Date.now()): PlaceholderRecord {
  return { v: 1, pid: process.pid, startTicks: processStartTicks(process.pid), bootId: bootIdNow(), scopeId, at: now, repos: [...repos] };
}

const okAbs = (p: unknown): p is string => typeof p === "string" && p.length > 1 && p.length <= 4096 && isAbsolute(p) && !p.includes("\0");
const okRel = (p: unknown): p is string =>
  typeof p === "string" && p.length > 0 && p.length <= 4096 && !isAbsolute(p) && !p.includes("\0") && !p.split("/").includes("..");

/** The record in `text`, or null when it is not one (an exact, bounded
 *  shape). Pure. */
export function parsePlaceholderRecord(text: string): PlaceholderRecord | null {
  if (text.length > RECORD_MAX_BYTES) return null;
  let o: unknown;
  try { o = JSON.parse(text); } catch { return null; }
  const r = o as Partial<PlaceholderRecord> | null;
  if (r === null || typeof r !== "object" || r.v !== 1) return null;
  if (!Number.isInteger(r.pid) || (r.pid as number) <= 0 || typeof r.scopeId !== "string" || r.scopeId.length > 512 || !Number.isFinite(r.at)) return null;
  if (r.startTicks !== null && (typeof r.startTicks !== "string" || !/^\d+$/.test(r.startTicks))) return null;
  if (r.bootId !== null && (typeof r.bootId !== "string" || r.bootId.length > 128)) return null;
  if (!Array.isArray(r.repos) || r.repos.length > WATCH_MAX_REPOS) return null;
  const repos: WatchedRepo[] = [];
  for (const x of r.repos as unknown[]) {
    const w = x as Partial<WatchedRepo> | null;
    if (w === null || typeof w !== "object" || !okAbs(w.root) || !Array.isArray(w.paths) || w.paths.length === 0 || w.paths.length > WATCH_MAX_PATHS) return null;
    if (w.tips !== null && (!Array.isArray(w.tips) || w.tips.length > WATCH_MAX_TIPS || !w.tips.every((t) => typeof t === "string" && HEX.test(t)))) return null;
    const paths: WatchedPath[] = [];
    for (const y of w.paths as unknown[]) {
      // A field this version does not know is ignored, whatever it holds: a
      // record of an earlier build of this check (a `tracked` flag; a
      // `source` commit and a `headPlaceholder` flag) reads as the same
      // file without them, and its repair is remove-only like any other
      // (no field of a record can make a command put a version back).
      const p = y as Partial<WatchedPath> | null;
      if (p === null || typeof p !== "object" || !okRel(p.rel)) return null;
      if (!Array.isArray(p.ids) || p.ids.length === 0 || p.ids.length > 8 || !p.ids.every((i) => typeof i === "string" && HEX.test(i))) return null;
      if (p.twin !== undefined && !okAbs(p.twin)) return null;
      if (p.index !== undefined && (!Array.isArray(p.index) || p.index.length > 8 || !p.index.every((i) => typeof i === "string" && HEX.test(i)))) return null;
      paths.push({
        rel: p.rel, ids: [...p.ids], ...(p.index !== undefined ? { index: [...p.index] } : {}),
        ...(p.twin !== undefined ? { twin: p.twin } : {}),
      });
    }
    repos.push({ root: w.root, tips: w.tips === null ? null : [...(w.tips as string[])], paths });
  }
  return {
    v: 1, pid: r.pid as number, startTicks: r.startTicks ?? null, bootId: r.bootId ?? null, scopeId: r.scopeId, at: r.at as number, repos,
  };
}

/**
 * Make `dir` inside the Mandu home `home`, one level at a time (0700): each
 * level is checked to be a real directory, this user's own, BEFORE the next
 * is made in it, so nothing is ever made through a store swapped for a link
 * (where `mkdir -p` would follow it out of the home). The home itself is
 * the anchor (made when absent; it may be a link the user set up, as
 * recordDirSafe allows). Then recordDirSafe. False when `dir` is not under
 * `home`, a level is a link or another user's, or a level cannot be made.
 * Never throws.
 */
export function ensureRecordDir(dir: string, home: string): boolean {
  const rel = relative(home, dir);
  if (rel === "" || rel === ".." || rel.startsWith("../") || isAbsolute(rel)) return false;
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  try {
    if (!existsSync(home)) mkdirSync(home, { recursive: true, mode: 0o700 });
    if (!statSync(home).isDirectory()) return false;
    let cur = home;
    for (const part of rel.split("/")) {
      if (part === "" || part === "." || part === "..") return false;
      cur = join(cur, part);
      let st;
      try { st = lstatSync(cur); } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") return false;
        try { mkdirSync(cur, { mode: 0o700 }); } catch (m) { if ((m as NodeJS.ErrnoException).code !== "EEXIST") return false; }
        st = lstatSync(cur);
      }
      if (st.isSymbolicLink() || !st.isDirectory()) return false;
      if (uid !== null && st.uid !== uid) return false;
    }
  } catch {
    return false;
  }
  return recordDirSafe(dir, home);
}

/** Leave `rec` in `dir` (made by ensureRecordDir when absent; the file
 *  0600, written through safe-file's temp-and-rename), when `dir` is a real
 *  directory inside the Mandu home `home` (recordDirSafe). Returns its path,
 *  or null when it could not be written (the check at exit still runs from
 *  memory). Never throws. */
export function writePlaceholderRecord(dir: string, home: string, rec: PlaceholderRecord): string | null {
  const text = JSON.stringify(rec);
  if (text.length > RECORD_MAX_BYTES) return null;
  const safeScope = rec.scopeId.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64);
  const file = join(dir, `${rec.at}-${rec.pid}-${safeScope}.json`);
  try {
    if (!ensureRecordDir(dir, home)) return null;
    publishFile(file, text, { mode: 0o600 });
    return file;
  } catch {
    return null;
  }
}

/** What a file in the records' folder is: a record; `foreign` (a regular
 *  file this launcher cannot read as one but must not drop: JSON whose `v`
 *  is not 1, a newer launcher's, or one too large to be its own); `bad` (a
 *  record of this version it cannot read, or no JSON at all: dropped); or
 *  `absent` (gone, or not a regular file: left alone). Never throws. */
type RecordFile = { kind: "record"; rec: PlaceholderRecord } | { kind: "foreign" } | { kind: "bad" } | { kind: "absent" };

function readRecordFile(file: string): RecordFile {
  let fd: number;
  try { fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return { kind: "absent" }; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { kind: "absent" };
    if (st.size > RECORD_MAX_BYTES) return { kind: "foreign" };
    const text = readFileSync(fd, "utf8");
    const rec = parsePlaceholderRecord(text);
    if (rec !== null) return { kind: "record", rec };
    let o: unknown;
    try { o = JSON.parse(text); } catch { return { kind: "bad" }; }
    return o !== null && typeof o === "object" && (o as { v?: unknown }).v !== 1 ? { kind: "foreign" } : { kind: "bad" };
  } catch {
    return { kind: "absent" };
  } finally {
    closeSync(fd);
  }
}

/** The record at `file`, or null (absent, not a regular file, not a
 *  record). Never throws. */
export function readPlaceholderRecord(file: string): PlaceholderRecord | null {
  const r = readRecordFile(file);
  return r.kind === "record" ? r.rec : null;
}

/** Remove a checked record: only a file named as a record, in a folder that
 *  is a real directory inside the Mandu home `home` (recordDirSafe). Never
 *  throws. */
export function removePlaceholderRecord(file: string | null, home: string): void {
  if (file === null || !RECORD_NAME.test(basename(file)) || !recordDirSafe(dirname(file), home)) return;
  try { rmSync(file, { force: true }); } catch { /* best effort */ }
}

/** Is the launcher that wrote `rec` still running? Its pid, the same start
 *  time and the same boot; where procfs cannot tell, a live pid counts. */
export function recordOwnerLive(rec: Pick<PlaceholderRecord, "pid" | "startTicks" | "bootId">): boolean {
  if (rec.pid === process.pid) return true;
  const boot = bootIdNow();
  if (rec.bootId !== null && boot !== null && rec.bootId !== boot) return false;
  const ticks = processStartTicks(rec.pid);
  if (ticks !== null) return rec.startTicks === null || ticks === rec.startTicks;
  if (existsSync("/proc/self/stat")) return false;
  try { process.kill(rec.pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

/** What one repository's check says (checkLines), by work tree. */
export interface CheckBlock {
  root: string;
  /** What is printed: an earlier session's block opens with a line naming
   *  that session. */
  lines: string[];
  /** The check's own lines, without that opening line: two blocks for one
   *  work tree with the same body say the same (unsaidBlocks). */
  body: string[];
}

/** `rec`'s repositories checked now, four at a time (only those with
 *  something to say). Once `over()` says the time is spent, no further
 *  repository is started (the first always is). `complete`: every
 *  repository was checked, and no git call failed or was cut off. Never
 *  throws. */
async function checkRecordRepos(
  rec: PlaceholderRecord, opts: CheckOpts, over?: () => boolean,
): Promise<{ blocks: CheckBlock[]; complete: boolean }> {
  let started = 0;
  let complete = true;
  const checks = await mapLimit(rec.repos, 4, async (r): Promise<RepoCheck | null> => {
    if (over !== undefined && started > 0 && over()) { complete = false; return null; }
    started++;
    const c = await checkPlaceholderRepo(r, opts).catch((e: unknown): RepoCheck => ({ finding: null, error: (e as Error).message, failed: true }));
    if (c.failed === true) complete = false;
    return c;
  });
  const blocks = checks.flatMap((c, i): CheckBlock[] => {
    const lines = c === null ? [] : checkLines(rec.repos[i]!.root, c);
    return lines.length > 0 ? [{ root: rec.repos[i]!.root, lines, body: lines }] : [];
  });
  return { blocks, complete };
}

/** The lines of every repository of `rec` checked now (only those with
 *  something to say). Never throws. */
export async function checkPlaceholderRecord(rec: PlaceholderRecord, opts: CheckOpts = {}): Promise<CheckBlock[]> {
  return (await checkRecordRepos(rec, opts)).blocks;
}

/** `blocks` of `rec`, each opened by a line naming the earlier session. */
function earlierBlocks(rec: PlaceholderRecord, when: string, blocks: readonly CheckBlock[]): CheckBlock[] {
  return blocks.map((b) => ({
    root: b.root,
    body: b.body,
    lines: [`mandu: an earlier session (${shown(rec.scopeId)}, started ${new Date(rec.at).toISOString()}) ended before Mandu could check ${shown(b.root)}; ${when}:`, ...b.body],
  }));
}

/** What checkPendingPlaceholderRecords found: each repository's block, the
 *  records it checked (for recheckEarlierRecords after the agent exits),
 *  and the files of those it left on disk because their check did not
 *  complete (`kept`: the caller removes each after that second check). */
export interface PendingCheck {
  blocks: CheckBlock[];
  records: PlaceholderRecord[];
  kept: string[];
}

/**
 * The records in `dir` whose launcher is gone (a session that crashed or
 * was killed before its own check), checked now, oldest first, at most
 * PENDING_MAX_RECORDS. Each is removed once its check is complete; one whose
 * check is not (a git call failed or was cut off, or the budget ran out
 * before each of its repositories was started) stays on disk, named in
 * `kept`, so that a launch killed in turn loses nothing. Only when `dir` is
 * a real directory inside the Mandu home `home` (recordDirSafe: never
 * through a store swapped for a link), and only files named as records: one
 * this version cannot read is dropped, one of another version (a newer
 * launcher's) left for it. With `budgetMs`, no record and no repository is
 * started once that much time has gone (the first of each always is): the
 * records not started wait for the next launch. Returns what each
 * repository's check says, each block opened by a line naming the earlier
 * session, and the records checked. Never throws.
 */
export async function checkPendingPlaceholderRecords(
  dir: string, home: string, opts: CheckOpts & { live?: (rec: PlaceholderRecord) => boolean; budgetMs?: number; now?: () => number } = {},
): Promise<PendingCheck> {
  if (!recordDirSafe(dir, home)) return { blocks: [], records: [], kept: [] };
  let names: string[];
  try { names = readdirSync(dir).filter((n) => RECORD_NAME.test(n)); } catch { return { blocks: [], records: [], kept: [] }; }
  const live = opts.live ?? recordOwnerLive;
  const pending: Array<{ file: string; rec: PlaceholderRecord }> = [];
  for (const n of names) {
    const file = join(dir, n);
    const r = readRecordFile(file);
    if (r.kind === "bad") { removePlaceholderRecord(file, home); continue; }
    if (r.kind !== "record" || live(r.rec)) continue;
    pending.push({ file, rec: r.rec });
  }
  pending.sort((a, b) => a.rec.at - b.rec.at);
  const out: PendingCheck = { blocks: [], records: [], kept: [] };
  const now = opts.now ?? Date.now;
  const start = now();
  const budget = opts.budgetMs;
  const over = budget !== undefined ? (): boolean => now() - start > budget : undefined;
  for (const { file, rec } of pending.slice(0, PENDING_MAX_RECORDS)) {
    // Over the budget: the rest stay on disk for the next launch.
    if (over !== undefined && out.records.length > 0 && over()) break;
    const { blocks, complete } = await checkRecordRepos(rec, opts, over);
    out.blocks.push(...earlierBlocks(rec, "checked now", blocks));
    out.records.push(rec);
    if (complete) removePlaceholderRecord(file, home);
    else out.kept.push(file);
  }
  return out;
}

/** The earlier sessions' records the launch checked
 *  (checkPendingPlaceholderRecords), checked again now that this launch's
 *  agent has exited: what they say then, not what they said before the
 *  agent ran (it may have committed on top, or the user repaired it
 *  meanwhile). Never throws. */
export async function recheckEarlierRecords(records: readonly PlaceholderRecord[], opts: CheckOpts = {}): Promise<CheckBlock[]> {
  const out: CheckBlock[] = [];
  for (const rec of records) out.push(...earlierBlocks(rec, "checked again now", await checkPlaceholderRecord(rec, opts)));
  return out;
}

/** `earlier` without each block that says what a block already said for
 *  the same work tree (the same body, in `own` or earlier in `earlier`): a
 *  block whose repair differs is always said. Pure. */
export function unsaidBlocks(own: readonly CheckBlock[], earlier: readonly CheckBlock[]): CheckBlock[] {
  const said = [...own];
  const out: CheckBlock[] = [];
  const same = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((l, i) => l === b[i]);
  for (const b of earlier) {
    if (said.some((s) => s.root === b.root && same(s.body, b.body))) continue;
    out.push(b);
    said.push(b);
  }
  return out;
}
