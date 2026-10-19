/**
 * moved-files-notice — the end-of-session notice of a protected file the
 * agent moved with its folder whose label could not follow it
 * (docs/design/confidentiality/guard-file-identity.md §2, 2026-10-16).
 *
 * The guard holds every protected file by its inode for the session, and,
 * after a folder rename stood, asks the arbiter to label each moved file's
 * new path so the next session knows it. When that label cannot be recorded
 * (the arbiter is down) and the rename cannot be undone, the file sits at a
 * path the next session does not know: in the guard-only posture it would
 * read raw there. The guard appends `<old path>\t<new path>` to this notice
 * file (opened once at load, never through a link: net-supervisor
 * `git_lock::open_notice`); the launcher prints the lines after the agent
 * exits, with how to protect the file again.
 *
 * Pure except `readMovedNotice`. `Mandu-new`.
 */
import { closeSync, constants, openSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** The notice file's name in the scope directory. */
export const MOVED_NOTICE_NAME = "moved-unlabelled";

/** At most this many files are named at the end of a session. */
export const MOVED_NOTICE_MAX = 20;

/** The notice file of a launch. */
export function movedNoticeFile(scopeRunDir: string): string {
  return join(scopeRunDir, MOVED_NOTICE_NAME);
}

/** The `movedNotice` field of the guard policy file. Pure. */
export function movedNoticeField(scopeRunDir: string): { movedNotice: string } {
  return { movedNotice: movedNoticeFile(scopeRunDir) };
}

/** One file moved with no label at its new path. */
export interface MovedUnlabelled {
  from: string;
  to: string;
}

/** Control characters and the Unicode bidi formatting characters (LRM, RLM,
 *  the embeddings and overrides, the isolates: a path that reorders the line
 *  it is printed on) become spaces; the guard writes them so too
 *  (net-supervisor `git_lock::notice_field`). Pure. */
export function cleanNoticeField(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, " ").trim();
}

/** The notice file's entries: absolute paths only, each new path once, all
 *  of them (`movedNoticeLines` prints at most MOVED_NOTICE_MAX and counts
 *  the rest). Pure. */
export function parseMovedNotice(text: string): MovedUnlabelled[] {
  const out: MovedUnlabelled[] = [];
  const seen = new Set<string>();
  for (const line of text.split("\n")) {
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    const from = cleanNoticeField(line.slice(0, tab)).slice(0, 4096);
    const to = cleanNoticeField(line.slice(tab + 1)).slice(0, 4096);
    if (!from.startsWith("/") || !to.startsWith("/") || seen.has(to)) continue;
    seen.add(to);
    out.push({ from, to });
  }
  return out;
}

/** What the person reads at the end of the session: at most
 *  MOVED_NOTICE_MAX files, and how many more there were. Pure. */
export function movedNoticeLines(moved: readonly MovedUnlabelled[]): string[] {
  if (moved.length === 0) return [];
  const shown = moved.slice(0, MOVED_NOTICE_MAX);
  const more = moved.length - shown.length;
  return [
    `mandu: ! ${moved.length === 1 ? "a protected file was" : `${moved.length} protected files were`} moved with ${moved.length === 1 ? "its folder" : "their folders"} ` +
      "and Mandu could not record where, so the next session would not protect " + (moved.length === 1 ? "it" : "them") + " there:",
    ...shown.map((m) => `  ${m.to}  (was ${m.from})`),
    ...(more > 0 ? [`  … and ${more} more`] : []),
    "  Give each new path a rule again (the dashboard's Rules page, or `paths:` in your policy.yaml; " +
      "`mandu paths` shows where it is); `mandu why <path>` says how it is treated now.",
  ];
}

function readNoFollow(p: string): string | null {
  let fd: number;
  try { fd = openSync(p, constants.O_RDONLY | constants.O_NOFOLLOW); } catch { return null; }
  try { return readFileSync(fd, "utf8"); } catch { return null; } finally { closeSync(fd); }
}

/** The files the notice file of a launch names. */
export function readMovedNotice(file: string, read: (p: string) => string | null = readNoFollow): MovedUnlabelled[] {
  const text = read(file);
  return text === null ? [] : parseMovedNotice(text);
}
