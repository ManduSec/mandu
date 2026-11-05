/**
 * locked-object-note — the `[mandu:locked]` note: a public result in which
 * git reports it could not read an object Mandu locked, or could not remove
 * a protected file's read-only copy (confidentiality.md §7.1, "git's report
 * on a history rewrite"; 2026-10-26, 2026-10-27).
 *
 * Mandu-new (no reference origin).
 *
 * The launcher's object-store twins keep every stored version of a
 * protected secret file unreadable to the agent (§7.2a), so git prints
 * `unable to open loose object <id>: Permission denied`. Read alone, that
 * looks like a broken repository: on the Codex take of 2026-10-27
 * (demo-git-history-scrub) the model ran filter-repo with `--replace-text`
 * and `--invert-paths` in one pass, which reads every blob and fails, then
 * tried to chmod and move the object, and at last replaced the history with
 * one new root commit, dropping every commit. The arbiter names the locked
 * ids (`lockedObjects`) and the paths git could not remove
 * (`protectedCopies`) on a public result; this module words the note.
 *
 * Static text, the object ids the arbiter matched against its locked set,
 * and paths the result already shows: no byte of the result, no value, so
 * the note is no oracle. It explains only: no mask is raised or lowered by
 * it, and a masked result never gets it. Every command the note recommends
 * is pinned on real git with a locked version by the stack test
 * git-locked-object-report.
 *
 * One module, two copies (both model proxies); the source is
 * interceptors/anthropic-proxy/src/locked-object-note.ts: change it, then run
 * `node scripts/copies/module-copies.mjs generate`.
 */

/** The marker of the locked-object note (for tests and the dashboard; NOT a
 *  trust marker). */
export const LOCKED_NOTE_MARKER = "[mandu:locked]";

/** At most this many ids or paths are named. */
const NAMED_MAX = 8;

/** The note for a result whose git could not read objects Mandu locked:
 *  static text and the ids the arbiter matched against its locked set
 *  (full hex object ids only, at most eight, shown as 12 digits), nothing
 *  of the result. Null when no id is valid. Pure. */
export function lockedObjectNote(ids: readonly string[]): string | null {
  const valid = [...new Set(ids.filter((id) => /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(id)))].slice(0, NAMED_MAX);
  if (valid.length === 0) return null;
  const named = valid.map((id) => id.slice(0, 12)).join(", ");
  return `${LOCKED_NOTE_MARKER} git could not read ${named}: Mandu keeps the stored versions of protected secret files unreadable in this session, and ${valid.length === 1 ? "this object is one" : "these objects are such versions"}. The repository is not damaged: do not chmod or move the object, re-clone or re-create the repository, or replace its history with a new root commit (that drops every commit). Commands that do not read a locked version still work. To scrub history with git filter-repo, run two passes: first --path <file> --invert-paths alone (it reads no file content), then --replace-text on what is left; one pass with both reads every version and fails. git filter-branch --index-filter 'git rm -q --cached --ignore-unmatch <file>' also works. To keep a file one of whose old versions is locked, put a clean blob in its place in an --index-filter: git update-index --cacheinfo 100644,<clean blob id>,<path> where git ls-files -s <path> shows the locked id (a clean blob: git rev-parse <later commit>:<path>, or git hash-object -w on a file you write). git show, log -p, log --stat and a tree filter fail on a locked version, so check a rewrite with git log --all --name-status or git log --all -- <path>.`;
}

/** The note for a result in which git could not remove a work-tree file
 *  (2026-10-27): the paths (as the result already shows them, plain ones
 *  only, at most eight) and static text. Null when no path is plain. Pure. */
export function protectedCopyNote(paths: readonly string[]): string | null {
  const valid = [...new Set(paths.filter((p) => p.length > 0 && p.length <= 256 && !/[\u0000-\u001f\u007f']/.test(p)))].slice(0, NAMED_MAX);
  if (valid.length === 0) return null;
  const named = valid.map((p) => `'${p}'`).join(", ");
  return `${LOCKED_NOTE_MARKER} git could not remove ${named}: when that is a protected secret file, Mandu keeps it in your working tree as a read-only copy in this session, so git cannot overwrite or delete it there (the repository is not damaged and needs no re-creating, and the file stays as it is). Rewriting history does not need to touch it: remove the file from every commit with git filter-branch --index-filter 'git rm -q --cached --ignore-unmatch <path>' (not --tree-filter), and do not git reset --hard, git checkout or git rm (without --cached) over that path.`;
}
