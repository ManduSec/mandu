/**
 * tool-error-notice.ts — a tool's own error about a path, with no file byte
 * in it (confidentiality.md §7.1, "A tool's error about a secret path",
 * 2026-10-26).
 *
 * A call that NAMES a secret path is masked at that path's level whatever it
 * returns (the path-derived precaution). That is right for a file's content,
 * and wrong for the agent runtime's own error saying the file is not there or
 * the write was refused: masked, the model never learns the file is missing
 * (live, demo-staging-admin-request: a wrong path, Read's "File does not
 * exist" and `cat`'s "No such file or directory" both came back as
 * placeholders, and the model guessed on for the rest of the turn) or that
 * its write failed (demo-local-health-summary: a Write refused with EACCES,
 * masked, and the model told the human it was done).
 *
 * The release is for EXACT shapes only, each matched against the WHOLE
 * result (Claude Code's token-budget tail aside: withoutHarnessBudgetTail),
 * whose every free span is a byte the model itself wrote in the call or the
 * runtime's own framing:
 *
 *   Read   `File does not exist. Note: your current working directory is
 *          <cwd>.` (Claude Code's Read and Edit validation, 2.1.295), and
 *          only when the call's own `file_path` is absolute and does not
 *          exist on this machine now. A Read of a real file is rendered
 *          behind a line-number gutter, so no file's content can equal it;
 *          the one free span is the agent's working directory. The "Did you
 *          mean <path>?" form is NOT released: it names another file.
 *   Bash   an optional `Exit code N` line, then 1-8 lines each exactly one
 *          program's ENOENT / EACCES report on a path that is a word of the
 *          call's own command (`cat: P: No such file or directory`, `ls:
 *          cannot access 'P': …`, `bash: line 1: P: …`, …). A file whose
 *          content is such a line can carry only bytes the model wrote; a
 *          line with anything else, or an extra line, keeps the mask.
 *   Write / Edit / MultiEdit   `EACCES|EPERM|EROFS: <its fixed text>,
 *          open|rename '<path>[.tmp.<pid>.<hex>]'[ -> '<path>']` on the
 *          call's own `file_path` (Node's own error text for the atomic
 *          write). Its content is what the model wrote, never the file's.
 *
 * Pure but for one `existsSync` (the Read rule); never throws.
 *
 * Mandu-new module (no reference origin).
 */
import { existsSync } from "node:fs";
import { isAbsolute } from "node:path";
import { withoutHarnessBudgetTail } from "./claude-code-inbound.js";

/** The largest result this rule looks at: an error is a line or a few. */
const ERROR_NOTICE_MAX = 4096;
/** At most this many report lines in a shell result. */
const SHELL_ERROR_MAX_LINES = 8;

const READ_ENOENT_PREFIX = "File does not exist. Note: your current working directory is ";

/** A path span as printed: no control character, no quote, bounded. */
const PATH_SPAN = "([^\\u0000-\\u001f\\u007f'\"]{1,1024})";
const ERRNO_TEXT = "(?:No such file or directory|Permission denied|Is a directory|Not a directory)";

/** One program's report on one path. Group 1 is always the path. */
const SHELL_ERROR_LINE_RES: readonly RegExp[] = [
  // cat, head, tail, grep, wc, sort, cut, sed, awk, base64, xxd, od, less, more, tac, nl, strings, md5sum, sha256sum
  new RegExp(`^(?:cat|head|tail|grep|egrep|fgrep|wc|sort|uniq|cut|sed|awk|gawk|base64|xxd|od|less|more|tac|nl|strings|md5sum|sha1sum|sha256sum|file|stat|readlink|realpath|source|\\.): ${PATH_SPAN}: ${ERRNO_TEXT}$`),
  // GNU coreutils' quoted forms: head/tail/wc/stat "cannot open 'P' for reading:", ls/stat "cannot access 'P':"
  new RegExp(`^(?:head|tail|wc|sort|stat|ls|du|cp|mv|chmod|touch|file|md5sum|sha256sum): cannot (?:open|access|stat) '${PATH_SPAN}'(?: for reading)?: ${ERRNO_TEXT}$`),
  // bash / sh / zsh redirections and `source`
  new RegExp(`^(?:bash|sh|zsh|/bin/bash|/bin/sh|/usr/bin/bash): (?:line \\d{1,6}: )?${PATH_SPAN}: ${ERRNO_TEXT}$`),
  // jq
  new RegExp(`^jq: error: Could not open ${PATH_SPAN}: ${ERRNO_TEXT}$`),
];

/** The words of a shell command a report's path may name: whitespace-split,
 *  each with surrounding quotes and redirection marks stripped, and each
 *  `NAME=value` assignment's value. */
function commandWords(command: string): Set<string> {
  const out = new Set<string>();
  for (const raw of command.split(/[\s;|&()`]+/)) {
    if (raw === "") continue;
    const w = raw.replace(/^[<>0-9]*[<>]+/, "").replace(/^['"]+|['"]+$/g, "");
    if (w !== "") out.add(w);
    const eq = w.indexOf("=");
    if (eq > 0) out.add(w.slice(eq + 1).replace(/^['"]+|['"]+$/g, ""));
  }
  return out;
}

/** The value past Claude Code's budget tail, trimmed; null when too long. */
function bodyOf(value: string): string | null {
  if (typeof value !== "string") return null;
  const body = withoutHarnessBudgetTail(value).body.trim();
  if (body === "" || body.length > ERROR_NOTICE_MAX) return null;
  return body;
}

/** Read: exactly the "File does not exist" answer, for an absolute
 *  `file_path` that does not exist on this machine. */
export function isReadMissingFileNotice(value: string, params: Record<string, unknown> | undefined, exists: (p: string) => boolean = existsSync): boolean {
  const body = bodyOf(value);
  if (body === null || body.includes("\n")) return false;
  if (!body.startsWith(READ_ENOENT_PREFIX) || !body.endsWith(".")) return false;
  const cwd = body.slice(READ_ENOENT_PREFIX.length, -1);
  // the cwd as Claude Code prints it: an absolute path, nothing after it
  if (!/^\/[^\u0000-\u001f\u007f]{0,1023}$/.test(cwd) || / Did you mean /.test(cwd)) return false;
  const fp = params?.["file_path"];
  if (typeof fp !== "string" || !isAbsolute(fp)) return false;
  try {
    return !exists(fp);
  } catch {
    return false;
  }
}

/** Bash: only report lines on paths the command names (and Claude Code's
 *  `Exit code N` line first). */
export function isShellPathErrorOutput(value: string, params: Record<string, unknown> | undefined): boolean {
  const body = bodyOf(value);
  if (body === null) return false;
  const command = params?.["command"];
  if (typeof command !== "string" || command === "") return false;
  const lines = body.split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
  if (/^Exit code \d{1,3}$/.test(lines[0] ?? "")) lines.shift();
  if (lines.length === 0 || lines.length > SHELL_ERROR_MAX_LINES) return false;
  const words = commandWords(command);
  for (const line of lines) {
    let path: string | undefined;
    for (const re of SHELL_ERROR_LINE_RES) {
      const m = re.exec(line);
      if (m) { path = m[1]; break; }
    }
    if (path === undefined || !words.has(path)) return false;
  }
  return true;
}

const WRITE_ERRNO = "(?:EACCES: permission denied|EPERM: operation not permitted|EROFS: read-only file system)";

/** Write / Edit / MultiEdit: Node's own refusal of the write on the call's
 *  own `file_path` (open, or the atomic write's rename from its temp file). */
export function isWriteRefusalNotice(value: string, params: Record<string, unknown> | undefined): boolean {
  const body = bodyOf(value);
  if (body === null || body.includes("\n")) return false;
  const fp = params?.["file_path"];
  if (typeof fp !== "string" || fp === "" || /[\u0000-\u001f\u007f']/.test(fp)) return false;
  const p = fp.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const shapes = [
    new RegExp(`^${WRITE_ERRNO}, open '${p}'$`),
    new RegExp(`^${WRITE_ERRNO}, rename '${p}\\.tmp\\.\\d{1,10}\\.[0-9a-f]{1,32}' -> '${p}'$`),
  ];
  return shapes.some((re) => re.test(body));
}

// ─────────────────────────────────────────────────────────────────────────────
// git's own words about a history rewrite and a locked object (2026-10-26,
// confidentiality.md §7.1, "git's report on a history rewrite").
//
// demo-git-history-scrub, live on Haiku 4.5: the model's filter-branch named
// `.env`, so its whole output (git's progress, `rm '.env'`, "Ref … was
// rewritten") came back as a placeholder, and `git log -p` stopped at the
// locked `.env` version with "unable to read <id>". The model could not
// verify its rewrite and told the person the history was clean when the
// hard-coded key was still in it. These lines carry no file byte: fixed git
// text, counts, object ids (no secret: every tree names its blobs' ids, and
// `git log --raw` prints them), ref names, and a path the command names.
// ─────────────────────────────────────────────────────────────────────────────

/** At most this many lines (after `\r` progress splitting) in a git report. */
const GIT_REPORT_MAX_LINES = 400;
const HEX = "[0-9a-f]{40}|[0-9a-f]{64}";
const REF = "[A-Za-z0-9._/-]{1,200}";

/** git's fixed lines: the filter-branch banner and its messages. */
const GIT_FIXED_LINES: ReadonlySet<string> = new Set([
  "WARNING: git-filter-branch has a glut of gotchas generating mangled history",
  "\t rewrites.  Hit Ctrl-C before proceeding to abort, then use an",
  "\t alternative filtering tool such as 'git filter-repo'",
  "\t (https://github.com/newren/git-filter-repo/) instead.  See the",
  "\t filter-branch manual page for more details; to squelch this warning,",
  "\t set FILTER_BRANCH_SQUELCH_WARNING=1.",
  "Proceeding with filter-branch...",
  "Cannot create a new backup.",
  "A previous backup already exists in refs/original/",
  "Force overwriting the backup with -f",
  "Cannot rewrite branches: You have unstaged changes.",
  "Cannot rewrite branches: Your index contains uncommitted changes.",
  "You need to run this command from the toplevel of the working tree.",
  "Everything up-to-date",
  "Repacking your repo and cleaning out old unneeded objects",
]);

/** git's lines with free spans that are counts, ids or ref names. */
const GIT_LINE_RES: readonly RegExp[] = [
  /^Rewrite (?:[0-9a-f]{40}|[0-9a-f]{64}) \(\d{1,9}\/\d{1,9}\)(?: \(\d{1,9} seconds? passed, remaining \d{1,9} predicted\))?$/,
  new RegExp(`^(?:WARNING: )?Ref '${REF}' (?:was rewritten|is unchanged|was deleted)$`),
  /^(?:Enumerating|Counting|Compressing|Writing) objects: (?:\d{1,3}% \(\d{1,12}\/\d{1,12}\)|\d{1,12})(?:, [\d.]{1,12} (?:[KMG]i)?B(?: \| [\d.]{1,12} (?:[KMG]i)?B\/s)?)?(?:, done\.)?$/,
  /^Delta compression using up to \d{1,6} threads$/,
  /^Total \d{1,12} \(delta \d{1,12}\), reused \d{1,12} \(delta \d{1,12}\)(?:, pack-reused \d{1,12}(?: \(from \d{1,12}\))?)?$/,
  /^Parsed \d{1,9} commits$/,
  /^New history written in [\d.]{1,12} seconds(?:; now repacking\/cleaning\.\.\.)?$/,
  /^Completely finished after [\d.]{1,12} seconds\.$/,
  // a push's per-ref lines (the URL line is judged on its own below)
  new RegExp(`^ (?:\\+ [0-9a-f]{7,64}\\.\\.\\.[0-9a-f]{7,64}|  [0-9a-f]{7,64}\\.\\.[0-9a-f]{7,64}|\\* \\[new branch\\]|- \\[deleted\\]) {1,20}${REF} {1,40}-> ${REF}(?: {1,40}\\(forced update\\))?$`),
];

/** git's reports of an object it could not read. Group 1 is the id. */
const GIT_UNREADABLE_RES: readonly RegExp[] = [
  new RegExp(`^error: unable to open loose object (${HEX}): Permission denied$`),
  new RegExp(`^(?:fatal|error): unable to read (${HEX})$`),
  new RegExp(`^(?:fatal|error): bad object (${HEX})$`),
  new RegExp(`^error: Could not read (${HEX})$`),
  new RegExp(`^fatal: missing blob object '(${HEX})'$`),
  new RegExp(`^error: (${HEX}): object corrupt or missing: \\.git/objects/[0-9a-f]{2}/(?:[0-9a-f]{38}|[0-9a-f]{62})$`),
  new RegExp(`^missing blob (${HEX})$`),
];
/** git's own EACCES on a loose object: the evidence that the object is one
 *  whose copy is unreadable in this session (the object twins make a
 *  protected version's loose copy mode 000, §7.2a). The id is group 1, or
 *  groups 1 and 2 (its fan-out directory and file). */
const GIT_EACCES_RES: readonly RegExp[] = [
  new RegExp(`^error: unable to open loose object (${HEX}): Permission denied$`),
  /^error: unable to mmap \.git\/objects\/([0-9a-f]{2})\/([0-9a-f]{38}|[0-9a-f]{62}): Permission denied$/,
];
/** filter-branch's progress, which git prints before the next line's text
 *  on the same line (`\r` in a terminal, spaces in a pipe). */
const REWRITE_PREFIX_RE = /^Rewrite (?:[0-9a-f]{40}|[0-9a-f]{64}) \(\d{1,9}\/\d{1,9}\)(?: \(\d{1,9} seconds? passed, remaining \d{1,9} predicted\))? +(?!\()/;

/** One report line without filter-branch's progress before it. */
function reportLine(line: string): string {
  let rest = line;
  // each commit's progress in turn (a pipe has no `\r` between them)
  for (let i = 0; i < 64; i++) {
    const next = rest.replace(REWRITE_PREFIX_RE, "");
    if (next === rest || next === "") break;
    rest = next;
  }
  return rest;
}

/** The ids `lines` show git could not open for EACCES. */
function eaccesIds(lines: readonly string[]): Set<string> {
  const out = new Set<string>();
  for (const raw of lines) {
    const line = reportLine(raw);
    for (const re of GIT_EACCES_RES) {
      const m = re.exec(line);
      if (m) out.add(m[2] !== undefined ? `${m[1]}${m[2]}` : m[1]!);
    }
  }
  return out;
}

/** Is `line` git's report of an object whose copy is unreadable here: its
 *  EACCES line, or an unreadable shape for an id the same output shows
 *  EACCES for or the locked set holds? */
function isUnreadableLine(line: string, eacces: ReadonlySet<string>, lockedObject: ((id: string) => boolean) | undefined): boolean {
  if (GIT_EACCES_RES.some((re) => re.test(line))) return true;
  for (const re of GIT_UNREADABLE_RES) {
    const m = re.exec(line);
    if (m && (eacces.has(m[1]!) || (lockedObject !== undefined && lockedObject(m[1]!)))) return true;
  }
  return false;
}

/** The object ids `value` reports git could not read whose copy is
 *  unreadable here (an EACCES line for it in the same output) or that the
 *  lookup calls locked (Mandu's locked set): what the proxy's note
 *  explains. Pure; never throws. */
export function lockedObjectsIn(value: string, lockedObject: ((id: string) => boolean) | undefined): string[] {
  if (typeof value !== "string" || value.length > 256 * 1024) return [];
  const lines = value.split(/[\r\n]+/).map((l) => l.trimEnd());
  const out = eaccesIds(lines);
  for (const raw of lines) {
    const line = reportLine(raw);
    for (const re of GIT_UNREADABLE_RES) {
      const m = re.exec(line);
      if (m && lockedObject !== undefined && lockedObject(m[1]!)) out.add(m[1]!);
    }
  }
  return [...out];
}

/** A push's `To <url>` line: a remote with no user part (`@`: a URL could
 *  carry a token as its user) and no space. */
const GIT_PUSH_TO_RE = /^(?:To|From) [^\s@]{1,512}$/;

/** git's EACCES on removing a work-tree file (2026-10-27, demo-git-history-
 *  scrub on Haiku 4.5: filter-branch's checkout of the rewritten head, and
 *  `git reset --hard`, could not remove the twinned `.env`, which Mandu
 *  keeps read-only). Group 1 is the path as git prints it. */
const GIT_UNLINK_RES: readonly RegExp[] = [
  /^warning: unable to unlink '([^\u0000-\u001f\u007f']{1,1024})': Permission denied$/,
  /^error: unable to unlink old '([^\u0000-\u001f\u007f']{1,1024})': Permission denied$/,
];
/** The reset that followed such an EACCES: fixed text and a ref. */
const GIT_RESET_REFUSED_RE = /^fatal: Could not reset index file to revision '[A-Za-z0-9._\/~^@{}-]{1,200}'\.$/;

/** The work-tree paths `value` says git could not remove for EACCES (the
 *  exact GIT_UNLINK_RES lines; at most eight): what the proxy's note
 *  explains. Pure; never throws. */
export function unlinkDeniedPathsIn(value: string): string[] {
  if (typeof value !== "string" || value.length > 256 * 1024) return [];
  const out = new Set<string>();
  for (const raw of value.split(/[\r\n]+/)) {
    const line = reportLine(raw.trimEnd());
    for (const re of GIT_UNLINK_RES) {
      const m = re.exec(line);
      if (m) out.add(m[1]!);
    }
    if (out.size >= 8) break;
  }
  return [...out];
}

/**
 * Bash: a git command's whole report, line by line (`\r` progress split
 * too), each line one of git's own shapes above, an `rm '<path>'` for a path
 * the command names, a shell's path error (SHELL_ERROR_LINE_RES), or git's
 * report of an object whose copy is unreadable here (its EACCES line, or an
 * id Mandu's locked set holds); optionally Claude Code's
 * `Exit code N` line first. The command must run git. Anything else (a
 * commit's subject, a diff, `remote:` text, `HEAD is now at …`) fails the
 * whole result. Pure; never throws.
 */
export function isGitNoContentReport(
  value: string,
  params: Record<string, unknown> | undefined,
  lockedObject: ((id: string) => boolean) | undefined,
): boolean {
  if (typeof value !== "string") return false;
  const body = withoutHarnessBudgetTail(value).body;
  if (body.trim() === "" || body.length > 64 * 1024) return false;
  const command = params?.["command"];
  if (typeof command !== "string" || !/(^|[\s;&|(])git(\s|$)/.test(command)) return false;
  const words = commandWords(command);
  const lines = body.split(/[\r\n]/).map((l) => l.replace(/[ ]+$/, "")).filter((l) => l !== "");
  if (/^Exit code \d{1,3}$/.test(lines[0] ?? "")) lines.shift();
  if (lines.length === 0 || lines.length > GIT_REPORT_MAX_LINES) return false;
  const eacces = eaccesIds(lines);
  for (const raw of lines) {
    const line = reportLine(raw);
    if (GIT_FIXED_LINES.has(line)) continue;
    if (GIT_LINE_RES.some((re) => re.test(line))) continue;
    if (GIT_PUSH_TO_RE.test(line)) continue;
    // `Rewrite <id> (n/m) (…)    rm '.env'`: git rm's report after the progress
    const rm = /^(?:Rewrite (?:[0-9a-f]{40}|[0-9a-f]{64}) \(\d{1,9}\/\d{1,9}\)(?: \(\d{1,9} seconds? passed, remaining \d{1,9} predicted\))? +)?rm '([^\u0000-\u001f\u007f']{1,1024})'$/.exec(line);
    if (rm && words.has(rm[1]!)) continue;
    // git refused to remove a work-tree file (a protected file's read-only
    // copy, 2026-10-27): only for a path the command names
    const unlink = GIT_UNLINK_RES.map((re) => re.exec(line)).find((m) => m !== null);
    if (unlink && words.has(unlink[1]!)) continue;
    if (GIT_RESET_REFUSED_RE.test(line)) continue;
    let path: string | undefined;
    for (const re of SHELL_ERROR_LINE_RES) {
      const m = re.exec(line);
      if (m) { path = m[1]; break; }
    }
    if (path !== undefined && words.has(path)) continue;
    if (isUnreadableLine(line, eacces, lockedObject)) continue;
    return false;
  }
  return true;
}
