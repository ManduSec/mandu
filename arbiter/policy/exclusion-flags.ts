/**
 * exclusion-flags — a search that excludes a labelled folder
 * (docs/design/confidentiality/exclusion-flags.md). Mandu-new (no reference
 * origin).
 *
 * The path rules read every word of a shell command as a possible path, so
 * `grep -rIl -i park . --exclude-dir=bank` read as naming the labelled
 * `bank/` and its whole output was masked (demo-c2), though no grep ever
 * opens the word `--exclude-dir=bank`, however the command is parsed.
 * `withoutGrepExclusions` gives the classify's path scan the command with
 * each such word blanked, when the command is one plain grep; anything else
 * is returned unchanged.
 *
 * PURE.
 */

/** Anywhere in the command, quoted or not: a control operator, a
 *  redirection, an expansion, a glob, a brace, a comment, a history mark, a
 *  `~`, `^` and `%` (zsh's extended glob, a job spec), an escape, a line
 *  break, a tab, a NUL. */
const UNSAFE_RE = /[;&|<>()$`\\*?[\]{}#!~^%\r\n\t\0]/;

/** A word this rule blanks: `--exclude-dir=NAME`, NAME one plain path
 *  segment (an optional trailing `/`), never `.` or `..`. */
const EXCLUDE_DIR_RE = /^--exclude-dir=(?!\.\.?\/?$)[A-Za-z0-9._+-]+\/?$/;

interface Word { text: string; raw: string; start: number; end: number }

/** The command's words with their spans: spaces separate, `'…'` and `"…"`
 *  group. Null for an unterminated quote. */
function words(command: string): Word[] | null {
  const out: Word[] = [];
  let i = 0;
  const n = command.length;
  while (i < n) {
    if (command[i] === " ") { i++; continue; }
    const start = i;
    let text = "";
    while (i < n && command[i] !== " ") {
      const c = command[i]!;
      if (c === "'" || c === '"') {
        const end = command.indexOf(c, i + 1);
        if (end < 0) return null;
        text += command.slice(i + 1, end);
        i = end + 1;
        continue;
      }
      text += c;
      i++;
    }
    out.push({ text, raw: command.slice(start, i), start, end: i });
  }
  return out;
}

/** The spans of `command`'s words that are `--exclude-dir=NAME` (design
 *  note §2, X1 and X2), when the command is ONE plain grep; null when it is
 *  not one. Pure. */
export function grepExclusionSpans(command: string): Array<{ start: number; end: number }> | null {
  if (typeof command !== "string" || command.length > 4096 || UNSAFE_RE.test(command)) return null;
  const ws = words(command);
  if (ws === null || ws.length < 2) return null;
  const first = ws[0]!;
  if (first.raw !== first.text || !["grep", "egrep", "fgrep"].includes(first.text)) return null;
  // A word after `--`, or right after an option that opens its argument
  // as a file (`-f`, a cluster ending in `f`, `--file`, `--exclude-from`),
  // names the file literally called `--exclude-dir=NAME`: kept, so the
  // catalog still reads that name (implementation review round 1).
  const spans: Array<{ start: number; end: number }> = [];
  let operandsOnly = false;
  for (let k = 1; k < ws.length; k++) {
    const w = ws[k]!;
    const prev = ws[k - 1]!.text;
    // `--` quoted or not ends the options (implementation review round 2)
    if (w.text === "--") { operandsOnly = true; continue; }
    // after `-f` (or a cluster ending in it) or ANY long option written
    // without `=` (`--file`, `--exclude-from`, ugrep's `--from`, a GNU
    // abbreviation such as `--exclude-f`), the word may be that option's
    // file argument
    if (operandsOnly || /^-[^-]*f$/.test(prev) || /^--[^=]+$/.test(prev)) continue;
    if (w.raw === w.text && EXCLUDE_DIR_RE.test(w.text)) spans.push({ start: w.start, end: w.end });
  }
  return spans;
}

/** `command` with each `--exclude-dir=NAME` word (`grepExclusionSpans`)
 *  blanked by spaces of its length, or `command` itself when there is
 *  none. Pure. */
export function withoutGrepExclusions(command: string): string {
  const spans = grepExclusionSpans(command);
  if (spans === null || spans.length === 0) return command;
  let out = "";
  let at = 0;
  for (const s of spans) {
    out += command.slice(at, s.start) + " ".repeat(s.end - s.start);
    at = s.end;
  }
  return out + command.slice(at);
}
