/**
 * git-lock-backstop — the launcher's half of the guard's backstop for locked
 * git objects (confidentiality-plan-14-policy-suggestions.md §11.1 R4).
 *
 * The object twins (git-object-twins.ts) hide a locked object only in the
 * repositories the launch prepares. The whole-agent guard is the backstop in
 * every other one: the launcher hands it the LOCKED SET (`gitLocks.ids` in
 * the guard policy file: the `blobs:` locks above `public`, the protected
 * versions the launch's history walks resolved, and, once the arbiter
 * answers it, the global set across every known repository), and the guard
 * refuses an open of a pack, an index or a loose object that holds one when
 * the launch has no sanitized copy of it (net-supervisor `git_lock`).
 *
 * The guard appends each refused repository once to a notice file in the
 * launch's scope directory and asks the arbiter to register it (R1's
 * `registerRepository`); at the end of the session the launcher prints one
 * notice per repository (`gitLockNoticeLines`), with how to fix it, and
 * registers each again, awaited (`registerRefusedRepositories`). An
 * agent's own git store (OpenCode's snapshot history, `agentGitStoreOf`) is
 * said apart, without the repository advice: it is not one of the person's
 * repositories, and nothing needs doing (2026-10-11, a live walk of the
 * first-session tour on OpenCode read "start mandu in it" for it).
 *
 * Pure except `readGitLockNotice`. `Mandu-new`.
 */
import { closeSync, constants, openSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** The notice file's name in the scope directory. */
export const GIT_LOCK_NOTICE_NAME = "git-lock-refusals";

/** A locked id: the arbiter's `BLOB_ID_RE`. */
export const LOCKED_ID_RE = /^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/;

/** At most this many repositories are named at the end of a session. */
export const NOTICE_MAX = 20;

/** The notice file of a launch. */
export function gitLockNoticeFile(scopeRunDir: string): string {
  return join(scopeRunDir, GIT_LOCK_NOTICE_NAME);
}

/** The empty blob, in both formats: it holds no byte to protect, and a
 *  protected file that was once empty would otherwise lock every repository
 *  with an empty file in it (`__init__.py`, `.gitkeep`). */
export const EMPTY_BLOB_IDS: ReadonlySet<string> = new Set([
  "sha1:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
  "sha256:473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
]);

/**
 * The locked set the guard gets: the blob locks above `public`, the ids the
 * launch's walks resolved, and the arbiter's global set when it has one
 * (the `lockedSet` seam of `gitHistoryLocks`). Only well-formed ids, never
 * the empty blob; sorted, unique. Pure.
 */
export function lockedIdsOf(parts: {
  blobs?: ReadonlyArray<{ id: string; level: string }>;
  resolved?: readonly string[];
  /** The arbiter's answer: bare hex per object format. */
  lockedSet?: { readonly sha1: readonly string[]; readonly sha256: readonly string[] };
}): string[] {
  const all = [
    ...(parts.blobs ?? []).filter((b) => b.level !== "public").map((b) => b.id),
    ...(parts.resolved ?? []),
    ...(parts.lockedSet?.sha1 ?? []).map((h) => `sha1:${h}`),
    ...(parts.lockedSet?.sha256 ?? []).map((h) => `sha256:${h}`),
  ];
  return [...new Set(all.filter((id) => LOCKED_ID_RE.test(id) && !EMPTY_BLOB_IDS.has(id)))].sort();
}

/** The `gitLocks` field of the guard policy file, or nothing when no object
 *  is locked (the guard then checks nothing). Pure. */
export function gitLocksField(ids: readonly string[], scopeRunDir: string): { gitLocks?: { ids: string[]; noticeFile: string } } {
  if (ids.length === 0) return {};
  return { gitLocks: { ids: [...ids], noticeFile: gitLockNoticeFile(scopeRunDir) } };
}

/** One refused repository, as the guard recorded it. */
export interface GitLockRefusal {
  repo: string;
  why: string;
}

/** Control characters out: the fields are printed to the person's terminal. */
function clean(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").trim();
}

/** The notice file's lines (`<repo>\t<why>`): absolute repositories only,
 *  each once, at most NOTICE_MAX. Pure. */
export function parseGitLockNotice(text: string): GitLockRefusal[] {
  const out: GitLockRefusal[] = [];
  const seen = new Set<string>();
  for (const line of text.split("\n")) {
    const tab = line.indexOf("\t");
    const repo = clean(tab < 0 ? line : line.slice(0, tab)).slice(0, 4096);
    const why = clean(tab < 0 ? "" : line.slice(tab + 1)).slice(0, 400);
    if (!repo.startsWith("/") || seen.has(repo)) continue;
    seen.add(repo);
    out.push({ repo, why });
    if (out.length >= NOTICE_MAX) break;
  }
  return out;
}

/** The agents that keep a git repository of the user's files in their own
 *  data folder, by the name a user reads. */
export type AgentGitStoreOwner = "opencode";

/** The shape of OpenCode's snapshot store under any data home (the
 *  catalog's OPENCODE_DATA_SHAPE_RE spelling: `…/share/opencode/…`). */
const OPENCODE_SNAPSHOT_SHAPE_RE = /\/share\/opencode\/snapshot(?:\/|$)/;

/**
 * Whose own git store `repo` is, or null for any other repository. Of the
 * supported agents only OpenCode keeps one (2026-10-11): its snapshot store,
 * `$XDG_DATA_HOME/opencode/snapshot` (`~/.local/share/opencode/snapshot`
 * by default; OpenCode 1 and 2), a git repository per project of the files
 * it works on, for its undo. A copy it took before the person labelled a
 * file holds that file, so the guard refuses it like any repository, and the
 * repository advice ("start mandu in it") does not fit. Pure over `env`.
 */
export function agentGitStoreOf(repo: string, env: Readonly<Record<string, string | undefined>>): AgentGitStoreOwner | null {
  const xdg = env["XDG_DATA_HOME"];
  const home = env["HOME"];
  const data = xdg !== undefined && xdg.startsWith("/") ? xdg : home !== undefined && home.startsWith("/") ? join(home, ".local", "share") : null;
  const dir = data === null ? null : join(data, "opencode", "snapshot");
  if (dir !== null && (repo === dir || repo.startsWith(dir + "/"))) return "opencode";
  return OPENCODE_SNAPSHOT_SHAPE_RE.test(repo) ? "opencode" : null;
}

/** `p` with the home directory spelled `~`. */
function tildeOf(p: string, home: string | undefined): string {
  return home !== undefined && home.length > 1 && p.startsWith(home + "/") ? `~${p.slice(home.length)}` : p;
}

/** What the person reads at the end of the session: the repositories git
 *  was refused in, with the two fixes, and, apart, an agent's own git store
 *  (`agentGitStoreOf`), which needs nothing done. Pure over `env` (HOME,
 *  XDG_DATA_HOME). */
export function gitLockNoticeLines(refusals: readonly GitLockRefusal[], env: Readonly<Record<string, string | undefined>> = {}): string[] {
  const stores = refusals.filter((r) => agentGitStoreOf(r.repo, env) !== null);
  const repos = refusals.filter((r) => agentGitStoreOf(r.repo, env) === null);
  return [...repositoryLines(repos), ...storeLines(stores, env["HOME"])];
}

/** OpenCode's snapshot store refused (the only agent git store): what it is,
 *  that nothing needs doing for the secret, that it comes back (the store is
 *  not a work tree, so the arbiter never registers it and nothing prepares
 *  its copy: K15 in tests/sandbox/git-history-locks.test.ts), and how to
 *  stop it. */
function storeLines(stores: readonly GitLockRefusal[], home: string | undefined): string[] {
  if (stores.length === 0) return [];
  return [
    "mandu: OpenCode's own snapshot history (the copy of your files it keeps for undo) holds a file you marked secret, " +
      "so Mandu kept OpenCode from reading it in this session (nothing was read):",
    ...stores.map((r) => `  ${tildeOf(r.repo, home)}`),
    "  Nothing needs doing: it is OpenCode's own store, not one of your repositories. While it holds the file, OpenCode's " +
      "undo and cleanup of that older history fail (once OpenCode has packed that history, its new snapshots too), and " +
      "this notice comes back in each session where OpenCode reads it " +
      "(Mandu prepares no copy of OpenCode's store). To stop it, remove that folder outside Mandu: OpenCode starts a new " +
      "history and loses only the undo of earlier changes.",
  ];
}

/** The person's repositories refused, with the two fixes. */
function repositoryLines(refusals: readonly GitLockRefusal[]): string[] {
  if (refusals.length === 0) return [];
  const lines = [
    `mandu: git was refused in ${refusals.length === 1 ? "this repository" : `these ${refusals.length} repositories`} for the session: ` +
      `${refusals.length === 1 ? "its" : "their"} history holds a key you locked, and this launch had no sanitized copy ` +
      "(the file guard refused the object files; nothing was read):",
  ];
  for (const r of refusals) {
    lines.push(`  ${r.repo}${/could not be told/.test(r.why) ? ` (${r.why})` : ""}`);
  }
  lines.push(
    "  To work in one: start mandu in it (its history is then prepared at launch), or run " +
      "`mandu policy suggest --root <repository>` and apply what it finds.",
  );
  return lines;
}

/**
 * Plan 14 §11.1 R1: register each refused repository with the arbiter's
 * known-repository registry (`registerRepository`, data plane, add-only), so
 * the arbiter resolves its locks from now on. The guard asks already at the
 * refusal; this repeats it after the session, awaited, for a guard that
 * ended before its request went out. Best-effort: an arbiter that refuses
 * (not a work tree, a bare repository, a full registry) or predates the op
 * changes nothing. Returns the repositories newly added.
 */
export async function registerRefusedRepositories(
  refusals: readonly GitLockRefusal[],
  call: (op: string, args: Record<string, unknown>) => Promise<unknown>,
): Promise<string[]> {
  const added: string[] = [];
  for (const r of refusals) {
    try {
      const got = (await call("registerRepository", { root: r.repo })) as { added?: unknown; root?: unknown } | null;
      if (got?.added === true && typeof got.root === "string") added.push(got.root);
    } catch { /* best-effort */ }
  }
  return added;
}

/** A file's text, never through a symlink (one planted in the scope dir);
 *  null when absent or unreadable. */
function readNoFollow(p: string): string | null {
  let fd: number;
  try { fd = openSync(p, constants.O_RDONLY | constants.O_NOFOLLOW); } catch { return null; }
  try { return readFileSync(fd, "utf8"); } catch { return null; } finally { closeSync(fd); }
}

/** Read the notice file of a launch; the lines to print (none when the file
 *  is absent or empty). */
export function readGitLockNotice(file: string, read: (p: string) => string | null = readNoFollow): string[] {
  return gitLockNoticeLines(readGitLockRefusals(file, read));
}

/** The refused repositories the notice file of a launch names. */
export function readGitLockRefusals(file: string, read: (p: string) => string | null = readNoFollow): GitLockRefusal[] {
  const text = read(file);
  return text === null ? [] : parseGitLockNotice(text);
}
