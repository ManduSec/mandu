/**
 * exclusion-flags — a search that excludes a labelled path
 * (docs/design/confidentiality/exclusion-flags.md). Mandu-new (no reference
 * origin).
 *
 * The path rules read every word of a shell command as a possible path, so
 * `grep -rIl -i park . --exclude-dir=bank` read as naming the labelled
 * `bank/` and its whole output was masked (demo-c2), and so did Codex's
 * `rg -n token notes-app --glob '!*.env'` (demo-notion-token, 2026-10-27),
 * though no grep or rg ever opens such a word as the labelled path, however
 * the command is parsed. `withoutSearchExclusions` gives the classify's path
 * scan the command with each such word blanked (X1-X7); anything it cannot
 * prove is one is left as written.
 *
 * PURE.
 */

/** The shell tools whose command field the three call sites blank
 *  (`labelForClassify`, the unmapped-input scan, the clean-tree
 *  counterfactual's never-answered strings). */
export const SEARCH_EXCLUSION_SHELL_TOOLS: ReadonlySet<string> = new Set(["Bash", "bash", "shell", "exec_command", "local_shell", "exec"]);

/** X4: refused anywhere outside quotes: an expansion, a redirection, a
 *  subshell or group, a comment, a history mark, a glob, `~`, `^`, `%` (zsh's
 *  extended glob, a job spec), an escape. `&` and `|` are handled apart. */
const UNQUOTED_UNSAFE = new Set([..."$`\\(){}<>#~^%!*?[]"]);

/** X4: refused inside `"…"`: an expansion, an escape, a history mark. */
const DOUBLE_QUOTED_UNSAFE = new Set([..."$`\\!"]);

/** X2: a word this rule blanks in a grep: `--exclude-dir=NAME`, NAME one
 *  plain path segment (an optional trailing `/`), never `.` or `..`. */
const EXCLUDE_DIR_RE = /^--exclude-dir=(?!\.\.?\/?$)[A-Za-z0-9._+-]+\/?$/;

/** X7: `--exclude=NAME` (one plain segment, never `.` or `..`). */
const EXCLUDE_NAME_RE = /^--exclude=(?!\.\.?$)[A-Za-z0-9._+-]+$/;

/** X7: `--exclude='GLOB'` as written: one single-quoted string. */
const EXCLUDE_QUOTED_RAW_RE = /^--exclude='[^']+'$/;

/** X6: the glob word of the two-word pair as written: one single-quoted
 *  string beginning with `!`. */
const NEGATED_GLOB_RAW_RE = /^'![^']*'$/;

/** X6: the one-word form as written. */
const NEGATED_GLOB_ONE_WORD_RAW_RE = /^--i?glob='![^']*'$/;

/** X6: the option words of the pair, unquoted. */
const GLOB_OPTIONS = new Set(["-g", "--glob", "--iglob"]);

interface Word { text: string; raw: string; start: number; end: number }

/** X4: the command's segments, split exactly on `&&`, `||`, `;` and `|`
 *  outside quotes, each a list of words with their spans (spaces separate,
 *  `'…'` and `"…"` group). Null when anything is refused: more than 4 KiB,
 *  a character outside printable ASCII (a line break, a tab, a NUL), an
 *  unterminated quote, a character of UNQUOTED_UNSAFE outside quotes or of
 *  DOUBLE_QUOTED_UNSAFE inside `"…"`, a lone `&`, `|&`, a word starting
 *  with `=` (zsh's `=cmd` expansion), an empty segment. */
function segments(command: string): Word[][] | null {
  if (typeof command !== "string" || command.length > 4096 || !/^[\x20-\x7e]*$/.test(command)) return null;
  const segs: Word[][] = [];
  let seg: Word[] = [];
  let i = 0;
  const n = command.length;
  const endSegment = (): boolean => {
    if (seg.length === 0) return false;
    segs.push(seg);
    seg = [];
    return true;
  };
  while (i < n) {
    const c = command[i]!;
    if (c === " ") { i++; continue; }
    if (c === ";") { if (!endSegment()) return null; i++; continue; }
    if (c === "|") {
      if (command[i + 1] === "&") return null;
      if (!endSegment()) return null;
      i += command[i + 1] === "|" ? 2 : 1;
      continue;
    }
    if (c === "&") {
      if (command[i + 1] !== "&") return null;
      if (!endSegment()) return null;
      i += 2;
      continue;
    }
    if (c === "=") return null;
    const start = i;
    let text = "";
    while (i < n && !" ;|&".includes(command[i]!)) {
      const q = command[i]!;
      if (q === "'" || q === '"') {
        const end = command.indexOf(q, i + 1);
        if (end < 0) return null;
        const inner = command.slice(i + 1, end);
        if (q === '"' && [...inner].some((x) => DOUBLE_QUOTED_UNSAFE.has(x))) return null;
        text += inner;
        i = end + 1;
        continue;
      }
      if (UNQUOTED_UNSAFE.has(q)) return null;
      text += q;
      i++;
    }
    seg.push({ text, raw: command.slice(start, i), start, end: i });
  }
  if (!endSegment()) return null;
  return segs;
}

/** X3: may `prev` take the next word as a FILE argument? `-f` or a short
 *  cluster ending in it, or (for grep) ANY long option written without `=`
 *  (`--file`, `--exclude-from`, ugrep's `--from`, a GNU abbreviation such
 *  as `--exclude-f`). */
const grepFileArg = (prev: string): boolean => /^-[^-]*f$/.test(prev) || /^--[^=]+$/.test(prev);

/** X3 for rg (no abbreviations): `-f` or a short cluster ending in it,
 *  `--file`, `--ignore-file`. */
const rgFileArg = (prev: string): boolean => /^-[^-]*f$/.test(prev) || prev === "--file" || prev === "--ignore-file";

/** A grep segment's spans: each `--exclude-dir=NAME` (X2), `--exclude=NAME`
 *  or `--exclude='GLOB'` (X7) word, never after `--` nor as a file
 *  argument (X3). */
function grepSpans(ws: Word[], out: Array<{ start: number; end: number }>): void {
  for (let k = 1; k < ws.length; k++) {
    const w = ws[k]!;
    // `--` quoted or not ends the options (implementation review round 2)
    if (w.text === "--") return;
    if (grepFileArg(ws[k - 1]!.text)) continue;
    const plain = w.raw === w.text;
    if ((plain && (EXCLUDE_DIR_RE.test(w.text) || EXCLUDE_NAME_RE.test(w.text))) || EXCLUDE_QUOTED_RAW_RE.test(w.raw)) {
      out.push({ start: w.start, end: w.end });
    }
  }
}

/** An rg segment's spans (X6): the pair `-g|--glob|--iglob '!…'` (the
 *  option unquoted, the glob one single-quoted string beginning with `!`),
 *  both words; or the one word `--glob='!…'` / `--iglob='!…'`. Never after
 *  `--` nor as a file argument (X3). */
function rgSpans(ws: Word[], out: Array<{ start: number; end: number }>): void {
  for (let k = 1; k < ws.length; k++) {
    const w = ws[k]!;
    if (w.text === "--") return;
    if (rgFileArg(ws[k - 1]!.text)) continue;
    if (NEGATED_GLOB_ONE_WORD_RAW_RE.test(w.raw)) { out.push({ start: w.start, end: w.end }); continue; }
    const g = ws[k + 1];
    if (w.raw === w.text && GLOB_OPTIONS.has(w.text) && g !== undefined && NEGATED_GLOB_RAW_RE.test(g.raw)) {
      out.push({ start: w.start, end: w.end }, { start: g.start, end: g.end });
      k++;
    }
  }
}

/** The spans of `command`'s exclusion words (X1-X7), in order; null when
 *  the command is refused as a whole (X4). Pure. */
export function searchExclusionSpans(command: string): Array<{ start: number; end: number }> | null {
  const segs = segments(command);
  if (segs === null) return null;
  const spans: Array<{ start: number; end: number }> = [];
  for (const ws of segs) {
    const first = ws[0]!;
    // X1, X5: the first word exactly the program's bare name, unquoted
    if (first.raw !== first.text) continue;
    if (first.text === "rg") rgSpans(ws, spans);
    else if (["grep", "egrep", "fgrep"].includes(first.text)) grepSpans(ws, spans);
  }
  return spans;
}

/** `command` with each exclusion word (`searchExclusionSpans`) blanked by
 *  spaces of its length, or `command` itself when there is none. Pure. */
export function withoutSearchExclusions(command: string): string {
  const spans = searchExclusionSpans(command);
  if (spans === null || spans.length === 0) return command;
  let out = "";
  let at = 0;
  for (const s of spans) {
    out += command.slice(at, s.start) + " ".repeat(s.end - s.start);
    at = s.end;
  }
  return out + command.slice(at);
}
