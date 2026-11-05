/**
 * dir-listing — "A folder's names" (plan 10 §11.8, 2026-10-17): the content
 * half of the release of a names-only `ls` of a labelled folder.
 *
 * Found live (demo-c2, mode `secrets`): the model ran `ls mail/inbox bank/`
 * to see what was in the inbox and the statements folder. `bank/` is labelled
 * `no-model`, so the command NAMES a secret path and the path-derived
 * precaution (the classify verdict, `labelForClassify`) masked the whole
 * result: the model saw one symbol where an unlabelled folder shows its file
 * names. A label protects a file's CONTENT; a folder's entry names are
 * metadata the confidentiality model does not cover (plan 13 §4.9: names are
 * a channel left open, and `find .`, a command that does not name the folder,
 * already prints them in clear).
 *
 * RULE (whole result only, exact):
 *   - the call's command is ONE plain `ls` (`plainLsCommand`): no other
 *     command, no `;`, `&&`, `|`, `&`, subshell, redirection, expansion,
 *     glob, comment or variable assignment; only the options `-1`, `-a`,
 *     `-A` (in any cluster), `--all`, `--almost-all`, `--color=never|auto`
 *     and `--`, so no option that prints metadata (`-l`, `-s`, `-i`, `-F`,
 *     `-p`, `--full-time`) or reads deeper (`-R`, `-d`) passes; at least one
 *     operand;
 *   - every operand resolves (absolute, `~/…`, or relative to the directory
 *     the guard says the call's shell started in) to an existing path, no two
 *     to the same one;
 *   - the output (`keyListingLines`'s framing: on Codex after Codex's own
 *     head, at most one final newline, at most 16 KiB, no token, not empty)
 *     is EXACTLY what `ls` prints for those operands, one name a line (a
 *     pipe, not a terminal): the file operands as written, then each folder's
 *     entries as `readdir` gives them now (hidden ones per `-a`/`-A`, `.` and
 *     `..` with `-a`), under a `<operand>:` header and after a blank line
 *     when there is more than one operand. Every entry of each folder, each
 *     once, in one of two orders: byte order (uutils `ls`, any `C` locale)
 *     or the locale order GNU `ls` uses under `en_US.UTF-8` (punctuation
 *     ignored), the same order for the whole output;
 *   - a folder holding an entry name that is not plain UTF-8 or holds a
 *     control character (a newline would split one name over two lines) is
 *     never matched, nor a folder of more than 4096 entries.
 *
 * Every released byte is then a name the folder holds (or an operand the
 * model wrote, a header `:`, a blank line), in an order fixed up to two
 * choices: no file's content, no size, date, mode or owner. The arbiter
 * answers it in `callTaint`, on the evidence of the other twin rules (a tree
 * the guard recorded, no raw open of a secret in it, a mapped tool), and the
 * proxies run the value backstop before they lower the mask.
 * `plainLsListingPaths` is pure (the caller's `ListingFs` reads the folders);
 * `hostListingFs` is the arbiter's reader. The arbiter's read is at most a
 * confirmation of names the output already holds, never of any content.
 */
import { lstatSync, opendirSync, statSync } from "node:fs";
import { posix } from "node:path";

import { keyListingLines, type TwinOutputOpts } from "./claude-code-inbound.js";

/** A folder with more entries than this is not tested (the host reader
 *  stops one past it, so a huge folder costs no more than a small one). */
export const DIR_LISTING_MAX_ENTRIES = 4096;
/** At most this many operands. */
const DIR_LISTING_MAX_OPERANDS = 32;

/** What `ls` hides: `default` (no `-a`/`-A`: every name starting with `.`),
 *  `almost` (`-A`: only `.` and `..`), `all` (`-a`: nothing, `.` and `..`
 *  printed too). */
export type LsHidden = "default" | "almost" | "all";

/** A plain `ls` command: what it hides and its operands as the shell passes
 *  them (quotes removed). */
export interface PlainLs {
  hidden: LsHidden;
  operands: string[];
}

/** A character no plain `ls` command here holds, anywhere (quoted or not):
 *  a control operator, a redirection, an expansion, a glob, a brace, a
 *  comment, a history mark, an escape, a line break. Conservative: a folder
 *  name holding one is simply not released. */
const UNSAFE_COMMAND_RE = /[;&|<>()$`\\*?[\]{}#!\r\n\t\0]/;

/** The options a names-only listing may carry. Anything else (`-l`, `-s`,
 *  `-i`, `-R`, `-d`, `-F`, `-p`, `-t`, `-S`, `-r`, `--full-time`, …)
 *  leaves the command unparsed and the mask standing. */
const LONG_OPTIONS: Record<string, LsHidden | null> = {
  "--all": "all",
  "--almost-all": "almost",
  "--color=never": null,
  "--color=no": null,
  "--color=none": null,
  "--color=auto": null,
  "--color=tty": null,
  "--color=if-tty": null,
};

/** Split a command into words: spaces separate, `'…'` and `"…"` group
 *  (nothing inside them is special, since `UNSAFE_COMMAND_RE` already
 *  refused `$`, a backquote and `\`). Null for an unterminated quote. */
function plainWords(command: string): string[] | null {
  const words: string[] = [];
  let i = 0;
  const n = command.length;
  while (i < n) {
    if (command[i] === " ") { i++; continue; }
    let word = "";
    while (i < n && command[i] !== " ") {
      const c = command[i]!;
      if (c === "'" || c === '"') {
        const end = command.indexOf(c, i + 1);
        if (end < 0) return null;
        word += command.slice(i + 1, end);
        i = end + 1;
        continue;
      }
      word += c;
      i++;
    }
    words.push(word);
  }
  return words;
}

/**
 * The command as a plain `ls`, or null (see the RULE above). `ls` must be
 * the first word exactly (no path to it, no `command`, no assignment before
 * it); options may come anywhere before `--`, as GNU `ls` takes them. Pure.
 */
export function plainLsCommand(command: string): PlainLs | null {
  if (typeof command !== "string" || command.length > 4096 || UNSAFE_COMMAND_RE.test(command)) return null;
  const words = plainWords(command.trim());
  if (words === null || words[0] !== "ls") return null;
  let hidden: LsHidden = "default";
  const operands: string[] = [];
  let optionsDone = false;
  for (const w of words.slice(1)) {
    if (!optionsDone && w === "--") { optionsDone = true; continue; }
    if (!optionsDone && w.startsWith("--")) {
      if (!Object.prototype.hasOwnProperty.call(LONG_OPTIONS, w)) return null;
      const h = LONG_OPTIONS[w]!;
      if (h !== null) hidden = h;
      continue;
    }
    if (!optionsDone && w.startsWith("-") && w !== "-") {
      for (const c of w.slice(1)) {
        if (c === "a") hidden = "all";
        else if (c === "A") hidden = "almost";
        else if (c !== "1") return null;
      }
      continue;
    }
    if (w === "") return null;
    operands.push(w);
  }
  if (operands.length === 0 || operands.length > DIR_LISTING_MAX_OPERANDS) return null;
  return { hidden, operands };
}

/** What the caller's filesystem says of one resolved operand: a folder and
 *  its entry names (`readdir`, without `.` and `..`), a non-folder, or
 *  nothing (missing, unreadable, a name that is not plain UTF-8: null). */
export type ListingEntry = { dir: string[] } | { file: true } | null;

export interface ListingFs {
  /** The operand resolved where the shell read it, or null (relative with
   *  no known start directory, `~user`, …). */
  resolve(operand: string): string | null;
  /** What is at the resolved path, following a symlink as `ls` does for an
   *  operand. */
  entry(path: string): ListingEntry;
}

/** A name `ls` prints on one line as written: valid UTF-8 (the caller
 *  decodes and re-encodes to check) and no control character. */
const PLAIN_NAME_RE = /^[^\u0000-\u001f\u007f]+$/;

type Compare = (a: string, b: string) => number;

/** Byte order: uutils `ls`, and GNU `ls` under any `C` locale. */
const byteOrder: Compare = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
/** GNU `ls` under `en_US.UTF-8` (glibc's ISO 14651 table: punctuation
 *  ignored at the first levels, `README.md` among the `r`s, `.env` among
 *  the `e`s). Measured against GNU coreutils' `ls` 2026-10-17. */
const localeOrder: Compare = new Intl.Collator("en", { ignorePunctuation: true }).compare;
const ORDERS: readonly Compare[] = [byteOrder, localeOrder];

/** Is `got` exactly `want` (a set of distinct names) in a non-decreasing
 *  order under `cmp`? Ties (names the order holds equal) may come in either
 *  order. */
function isOrderedListing(got: readonly string[], want: ReadonlySet<string>, cmp: Compare): boolean {
  if (got.length !== want.size) return false;
  const seen = new Set<string>();
  for (let i = 0; i < got.length; i++) {
    const g = got[i]!;
    if (!want.has(g) || seen.has(g)) return false;
    seen.add(g);
    if (i > 0 && cmp(got[i - 1]!, g) > 0) return false;
  }
  return true;
}

/** The entries `ls` shows of a folder under `hidden`. */
function shownEntries(names: readonly string[], hidden: LsHidden): string[] {
  if (hidden === "all") return [".", "..", ...names];
  if (hidden === "almost") return [...names];
  return names.filter((n) => !n.startsWith("."));
}

/**
 * The folders (and files) a names-only `ls` listed, when `value` is exactly
 * that listing (see the RULE above); null otherwise. Returns the resolved
 * operand paths, folders first in the order the output gives them. Pure but
 * for `fs`.
 */
export function plainLsListingPaths(
  value: string,
  command: string,
  fs: ListingFs,
  opts: TwinOutputOpts = {},
): string[] | null {
  const ls = plainLsCommand(command);
  if (ls === null) return null;
  const lines = keyListingLines(opts.codexHead === true ? value : withoutHarnessTail(value), opts);
  if (lines === null) return null;
  const files: Array<{ word: string; path: string }> = [];
  const dirs: Array<{ word: string; path: string; shown: Set<string> }> = [];
  const paths = new Set<string>();
  for (const word of ls.operands) {
    const resolved = fs.resolve(word);
    if (resolved === null || !resolved.startsWith("/")) return null;
    const path = posix.normalize(resolved).replace(/(?<=.)\/+$/, "");
    if (paths.has(path)) return null; // `ls` would list it twice
    paths.add(path);
    const e = fs.entry(path);
    if (e === null) return null;
    if ("file" in e) {
      // `ls f.txt/` fails on a file: no listing
      if (!PLAIN_NAME_RE.test(word) || word.endsWith("/")) return null;
      files.push({ word, path });
      continue;
    }
    if (e.dir.length > DIR_LISTING_MAX_ENTRIES || !e.dir.every((n) => PLAIN_NAME_RE.test(n))) return null;
    if (!PLAIN_NAME_RE.test(word)) return null;
    dirs.push({ word, path, shown: new Set(shownEntries(e.dir, ls.hidden)) });
  }
  const many = ls.operands.length > 1;
  for (const cmp of ORDERS) {
    // `ls` sorts its file operands, then its folder operands, by the same
    // order as the entries. Two operands the order holds equal: ambiguous.
    const f = [...files].sort((a, b) => cmp(a.word, b.word));
    const d = [...dirs].sort((a, b) => cmp(a.word, b.word));
    if (f.some((x, i) => i > 0 && cmp(f[i - 1]!.word, x.word) === 0)) continue;
    if (d.some((x, i) => i > 0 && cmp(d[i - 1]!.word, x.word) === 0)) continue;
    let at = 0;
    let ok = true;
    for (const x of f) {
      if (lines[at] !== x.word) { ok = false; break; }
      at++;
    }
    for (const x of ok ? d : []) {
      if (at > 0) {
        if (lines[at] !== "") { ok = false; break; }
        at++;
      }
      if (many) {
        if (lines[at] !== `${x.word}:`) { ok = false; break; }
        at++;
      }
      const group = lines.slice(at, at + x.shown.size);
      if (!isOrderedListing(group, x.shown, cmp)) { ok = false; break; }
      at += x.shown.size;
    }
    if (ok && at === lines.length) return [...d.map((x) => x.path), ...f.map((x) => x.path)];
  }
  return null;
}

// ── A folder's names beside another command (folder-listing-compound.md) ──

/** L1: anywhere in a compound (quoted or not): a pipe, a redirection, a
 *  subshell, an expansion, a glob, a brace, a comment, a history mark, `^`,
 *  `~` and `%` (zsh's extended glob, a job spec), an escape, and anything
 *  outside printable ASCII (a line break, a tab, a NUL, a vertical tab, a
 *  non-ASCII space the shell does not split on but a trim drops:
 *  implementation review round 1). `;` and `&&` separate segments; a lone
 *  `&` and `||` refuse. */
const COMPOUND_UNSAFE_RE = /[|<>()$`\\*?[\]{}#!^~%]|[^\x20-\x7e]/;
/** L3: the programs a part may start with besides a path to a program: a
 *  builtin in neither bash nor zsh, and none of them `ls`. */
const COMPOUND_PROGRAMS: ReadonlySet<string> = new Set(["git", "cat", "head", "tail", "wc", "grep", "sort", "uniq", "file", "stat", "date", "python3", "node"]);
/** L1: at most this many segments. */
const COMPOUND_MAX_SEGMENTS = 8;

/** A compound of one plain `ls` and other commands (L1-L3). */
export interface CompoundLs {
  /** The segments as written, trimmed. */
  segments: string[];
  /** Which one is the `ls`: the first or the last. */
  lsIndex: number;
  ls: PlainLs;
}

/**
 * The command as one plain `ls` beside other commands, or null
 * (folder-listing-compound.md §2, L1-L3): split on `;` and `&&` outside
 * quotes into 2 to 8 non-empty segments; exactly one is a plain `ls`
 * (`plainLsCommand`), the first or the last; each other segment's first
 * word is written with no quote and no `=`, is not `ls`, and is a path to a
 * program (it holds a `/`) or one of `COMPOUND_PROGRAMS`. Pure; the caller
 * checks that a `/` word is no directory (interactive bash's `autocd`).
 */
export function compoundLsCommand(command: string): CompoundLs | null {
  if (typeof command !== "string" || command.length > 4096 || COMPOUND_UNSAFE_RE.test(command)) return null;
  if (/\|\|/.test(command)) return null;
  const segments: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (quote !== null) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (c === ";") { segments.push(cur); cur = ""; continue; }
    if (c === "&") {
      if (command[i + 1] !== "&" || command[i + 2] === "&") return null; // a lone `&` or `&&&`
      segments.push(cur); cur = ""; i++; continue;
    }
    cur += c;
  }
  if (quote !== null) return null;
  segments.push(cur);
  const trimmed = segments.map((x) => x.trim());
  if (trimmed.length < 2 || trimmed.length > COMPOUND_MAX_SEGMENTS || trimmed.some((x) => x === "")) return null;
  let lsIndex = -1;
  let ls: PlainLs | null = null;
  for (const [i, seg] of trimmed.entries()) {
    const words = plainWords(seg);
    if (words === null || words.length === 0) return null;
    const first = words[0]!;
    if (first === "ls") {
      const p = plainLsCommand(seg);
      if (p === null || ls !== null) return null;
      ls = p;
      lsIndex = i;
      continue;
    }
    const raw = seg.split(" ")[0]!;
    if (raw !== first || first.includes("=") || /^ls$/.test(first.split("/").pop() ?? "")) return null;
    if (!first.includes("/") && !COMPOUND_PROGRAMS.has(first)) return null;
  }
  if (ls === null || (lsIndex !== 0 && lsIndex !== trimmed.length - 1)) return null;
  return { segments: trimmed, lsIndex, ls };
}

/** L4: the command rebuilt from its other segments, joined by `; `, read by
 *  its OWN split (never another spelling's offsets), or null when it is not
 *  such a compound or its `ls` is not at `lsIndex` among `count` segments. */
export function compoundWithoutLs(command: string, lsIndex: number, count: number): string | null {
  const c = compoundLsCommand(command);
  if (c === null || c.lsIndex !== lsIndex || c.segments.length !== count) return null;
  return c.segments.filter((_, i) => i !== lsIndex).join("; ");
}

/**
 * L5: the folders the listing segment `ls` names, when the output's first
 * (`lsIndex` 0) or last lines are exactly its listing (`plainLsListingPaths`
 * over those lines) and the rest is at least one line; null otherwise. With
 * the single listing's framing (`keyListingLines`: Codex's head, one final
 * newline, no token). The split is at the one line count the folders give;
 * two counts that both match refuse. Pure but for `fs`.
 */
export function compoundListingPaths(
  value: string,
  lsSegment: string,
  first: boolean,
  fs: ListingFs,
  opts: TwinOutputOpts = {},
): string[] | null {
  const lines = keyListingLines(value, opts);
  if (lines === null || lines.length < 2) return null;
  let found: string[] | null = null;
  for (let k = 1; k < lines.length; k++) {
    const part = first ? lines.slice(0, k) : lines.slice(lines.length - k);
    const paths = plainLsListingPaths(part.join("\n"), lsSegment, fs);
    if (paths === null) continue;
    if (found !== null) return null;
    found = paths;
  }
  return found;
}

/** L8: does an argv the guard recorded run `ls` (its program's name) with
 *  exactly `ls`'s operands, every option a names-only one
 *  (`plainLsCommand`'s)? Pure. */
export function lsArgvMatches(argv: readonly string[], ls: PlainLs): boolean {
  if (argv.length === 0 || (argv[0]!.split("/").pop() ?? "") !== "ls") return false;
  if (argv.slice(1).some((w) => /['" ]|[^\x20-\x7e]/.test(w) || UNSAFE_COMMAND_RE.test(w))) return false;
  const p = plainLsCommand(["ls", ...argv.slice(1)].join(" "));
  return p !== null && p.operands.length === ls.operands.length && p.operands.every((o, i) => o === ls.operands[i]);
}

/** Is `argv` an exec of a program named `ls` at all? */
export function isLsArgv(argv: readonly string[]): boolean {
  return argv.length > 0 && (argv[0]!.split("/").pop() ?? "") === "ls";
}

/**
 * The host's view for `plainLsListingPaths`, as the arbiter reads it (it runs
 * as the user, outside the agent's sandbox, and only compares: a name it
 * reads reaches the model only when the output already holds it). An operand
 * is read as absolute, `~`/`~/…` under `home`, or relative to `startDir`
 * (the directory the guard says the call's shell started in; none ⇒ no
 * relative operand resolves). A folder's names are read as bytes, and one
 * that is not valid UTF-8 makes the folder unmatched. Any error: null.
 */
export function hostListingFs(startDir: string | null, home: string): ListingFs {
  return {
    resolve(word) {
      if (word.startsWith("/")) return word;
      if (word === "~" || word.startsWith("~/")) return home.startsWith("/") ? posix.join(home, word.slice(1)) : null;
      if (word.startsWith("~")) return null;
      return startDir !== null && startDir.startsWith("/") ? posix.resolve(startDir, word) : null;
    },
    entry(path) {
      try {
        const st = statSync(path);
        if (!st.isDirectory()) return { file: true };
        // Read at most one entry past the bound: a huge folder costs no
        // more than a small one. Names as bytes (`encoding: "buffer"`, which
        // node's opendir takes though its types name only text encodings).
        const dir = opendirSync(path, { encoding: "buffer" as BufferEncoding });
        const names: string[] = [];
        try {
          for (let d = dir.readSync(); d !== null; d = dir.readSync()) {
            if (names.length >= DIR_LISTING_MAX_ENTRIES) return null;
            const b: unknown = d.name;
            if (!Buffer.isBuffer(b)) return null;
            const n = b.toString("utf8");
            if (!Buffer.from(n, "utf8").equals(b)) return null;
            names.push(n);
          }
        } finally {
          dir.closeSync();
        }
        return { dir: names };
      } catch {
        return null;
      }
    },
  };
}

// ── Paths only: `find` and `ls … | grep …` (2026-10-26) ─────────────────────
//
// "Release paths-only" (the maintainer's decision, 2026-10-26). Live on the
// Claude subscription drills (demo-scam-email, Haiku 4.5): the model looked
// for the September statement with `find bank -name "*sept*" -o …` and `ls
// bank/ | grep -i sep`. Both name the labelled `bank/`, so both came back as
// one placeholder; the model guessed `bank/september.pdf`, its uploads failed
// out of sight, and it told the person they were done. A plain `ls` of the
// same folder was already released (above): these commands print the same
// kind of byte, names, filtered.
//
// RULE (whole result only, exact; on the same evidence as the plain `ls`):
//   - the command is ONE pipeline: a `find` or a names-only `ls` of one
//     folder, then up to four filters (`grep`, `egrep`, `fgrep`, `head`,
//     `tail`, `sort`, `uniq`) with only the options below, and at most a
//     `2>/dev/null` on any part; no `;`, `&&`, `||`, `&`, subshell, other
//     redirection, expansion, escape, comment, or glob outside quotes.
//     Quotes may hold a glob (a `-name` pattern) or a grep pattern, never
//     `$`, a backquote or `\`.
//   - `find`: operands first, then only `-name`/`-iname`/`-path`/`-ipath`
//     PATTERN, `-type f|d|l`, `-maxdepth`/`-mindepth` N, `-o`/`-or`/`-a`/
//     `-and`/`-not`, `-print`. Nothing that prints anything but a path
//     (`-ls`, `-printf`, `-fprint`, `-print0`) and nothing that runs or
//     reads (`-exec`, `-execdir`, `-ok`, `-delete`, `-newer`, `-size`, …).
//   - `grep`: `-i`, `-v`, `-E`, `-F`, `-w`, `-x` (clustered or not) and one
//     pattern (or `-e PATTERN`); never a file operand, `-f`, `-o`, `-c`,
//     `-l`, `-n`, `-H`. `head`/`tail`: `-n N` or `-N`. `sort`: `-r`, `-u`,
//     `-f`, `-V`. `uniq`: no option. (`xargs`, `cat` and every other
//     program: not a filter here.)
//   - the output (`keyListingLines`' framing) has at most 4096 lines, and
//     EVERY line is a path the listing could have printed: for `find`, an
//     operand as written, or that operand, `/`, and a path below it that
//     exists now (each part a plain name, no `.` or `..`); for `ls`, a name
//     its folder holds now (per `-a`/`-A`). Read on the host, where the
//     call's shell started.
//
// Every released byte is then a name or a path that exists (or an operand
// the model wrote); which ones, and their order, depend only on the
// command's literal patterns and the folder, never on a file's content: the
// evidence (no process in the tree read a secret raw) rules out a program
// choosing names by what a secret holds. `ls -l`/`-la` and every metadata
// option stay masked (the maintainer's decision: sizes, dates, owners).

/** Unquoted, a pipeline word may hold only these. */
const PATHS_ONLY_BARE_RE = /^[A-Za-z0-9_./~+,:=@%-]+$/;
/** Quoted, never these (an expansion, even inside `"…"`). A backslash there
 *  is the pattern's (grep reads `\|`): with no `$` or backquote it starts no
 *  expansion, and `\"` ends the quote early, which leaves an unterminated
 *  one (refused). */
const PATHS_ONLY_QUOTED_BAD_RE = /[$`\u0000-\u001f\u007f]/;
const FIND_TESTS_WITH_ARG: ReadonlySet<string> = new Set(["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename"]);
const FIND_FLAGS: ReadonlySet<string> = new Set(["-o", "-or", "-a", "-and", "-not", "-print"]);
const PATHS_ONLY_MAX_FILTERS = 4;
const PATHS_ONLY_MAX_LINES = 4096;
/** The one redirection a part may carry: stderr thrown away. */
const DEV_NULL_RE = / 2>\/dev\/null(?= |\||$)/g;

/** A pipeline part's words; null on anything outside the grammar. */
function pipelineWords(part: string): string[] | null {
  const words: string[] = [];
  let i = 0;
  const n = part.length;
  while (i < n) {
    if (part[i] === " ") { i++; continue; }
    let word = "";
    while (i < n && part[i] !== " ") {
      const c = part[i]!;
      if (c === "'" || c === '"') {
        const end = part.indexOf(c, i + 1);
        if (end < 0) return null;
        const inner = part.slice(i + 1, end);
        if (PATHS_ONLY_QUOTED_BAD_RE.test(inner)) return null;
        word += inner;
        i = end + 1;
        continue;
      }
      let j = i;
      while (j < n && part[j] !== " " && part[j] !== "'" && part[j] !== '"') j++;
      const bare = part.slice(i, j);
      if (!PATHS_ONLY_BARE_RE.test(bare)) return null;
      word += bare;
      i = j;
    }
    words.push(word);
  }
  return words;
}

/** Claude Code's own reminders it appends to a tool result, as exact text
 *  (2.1.295): the token budget (digits only) and the task-tools nudge (no
 *  free byte). Live 2026-10-26 (demo-scam-email): a `find`'s output came
 *  with both, and a listing that ends in them was no listing. */
const HARNESS_TAIL_RES: readonly RegExp[] = [
  /\s*<system-reminder>\s*<total_tokens>\d{1,12} tokens left<\/total_tokens>\s*<\/system-reminder>\s*$/,
  /\s*<system-reminder>\nThe task tools haven't been used recently\. If you're working on tasks that would benefit from tracking progress, consider using TaskCreate to add new tasks and TaskUpdate to update task status \(set to in_progress when starting, completed when done\)\. Also consider cleaning up the task list if it has become stale\. Only use these if relevant to the current work\. This is just a gentle reminder - ignore if not applicable\.\n\n<\/system-reminder>\s*$/,
];

/** `value` without Claude Code's own trailing reminders (HARNESS_TAIL_RES,
 *  exact; at most four); anything else is left, and fails the listing. */
export function withoutHarnessTail(value: string): string {
  let v = value;
  for (let i = 0; i < 4; i++) {
    const re = HARNESS_TAIL_RES.find((r) => r.test(v));
    if (re === undefined) break;
    v = v.replace(re, "\n");
  }
  return v;
}

/** The listing a paths-only pipeline makes: `find` with its operands, or a
 *  names-only `ls` of one folder. */
export type PathsOnlyListing =
  | { kind: "find"; operands: string[] }
  | { kind: "ls"; hidden: LsHidden; operand: string };

/** Is `args` (after the program `prog`) a filter this rule allows? */
function isAllowedFilter(prog: string, args: readonly string[]): boolean {
  if (prog === "uniq") return args.length === 0;
  if (prog === "head" || prog === "tail") {
    if (args.length === 0) return true;
    if (args.length === 1) return /^-\d{1,6}$/.test(args[0]!);
    return args.length === 2 && args[0] === "-n" && /^\d{1,6}$/.test(args[1]!);
  }
  if (prog === "sort") return args.every((a) => /^-[rufV]+$/.test(a));
  if (prog === "grep" || prog === "egrep" || prog === "fgrep") {
    let patterns = 0;
    for (let k = 0; k < args.length; k++) {
      const a = args[k]!;
      if (a === "-e") {
        if (k + 1 >= args.length) return false;
        k++;
        patterns++;
        continue;
      }
      if (patterns === 0 && a.startsWith("-") && a.length > 1) {
        if (!/^-[ivEFwx]+$/.test(a)) return false;
        continue;
      }
      patterns++;
    }
    // one pattern and nothing after it (a second word is a file to read)
    return patterns === 1;
  }
  return false;
}

/** The command as a paths-only pipeline (see the RULE above), or null. Pure. */
export function pathsOnlyCommand(command: string): PathsOnlyListing | null {
  if (typeof command !== "string" || command.length > 4096) return null;
  const bare = command.trim().replace(DEV_NULL_RE, "");
  // Split on the pipes outside quotes; outside quotes nothing but the bare
  // word characters, spaces and quotes (pipelineWords judges each run), and
  // inside them never `$` or a backquote (PATHS_ONLY_QUOTED_BAD_RE): a
  // grep pattern may hold `\|` or `(`, which only grep reads.
  const parts: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (const c of bare) {
    if (quote !== null) {
      if (c === quote) quote = null;
      cur += c;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (c === "|") { parts.push(cur.trim()); cur = ""; continue; }
    if (!/[A-Za-z0-9_./~+,:=@% -]/.test(c)) return null;
    cur += c;
  }
  if (quote !== null) return null;
  parts.push(cur.trim());
  if (parts.length > PATHS_ONLY_MAX_FILTERS + 1 || parts.some((x) => x === "")) return null;
  const head = pipelineWords(parts[0]!);
  if (head === null || head.length === 0) return null;
  for (const x of parts.slice(1)) {
    const w = pipelineWords(x);
    if (w === null || w.length === 0 || !isAllowedFilter(w[0]!, w.slice(1))) return null;
  }
  if (head[0] === "ls") {
    // an `ls` alone prints every name: the plain-ls rule above holds it to
    // exactly that; only a filter after it may leave names out
    if (parts.length < 2) return null;
    if (head.some((w) => /[*?[\]'" ]/.test(w))) return null;
    const ls = plainLsCommand(head.join(" "));
    if (ls === null || ls.operands.length !== 1) return null;
    return { kind: "ls", hidden: ls.hidden, operand: ls.operands[0]! };
  }
  if (head[0] !== "find") return null;
  const operands: string[] = [];
  let k = 1;
  for (; k < head.length && !head[k]!.startsWith("-"); k++) {
    if (head[k] === "" || /[*?[\]]/.test(head[k]!)) return null;
    operands.push(head[k]!);
  }
  if (operands.length === 0 || operands.length > DIR_LISTING_MAX_OPERANDS) return null;
  for (; k < head.length; k++) {
    const w = head[k]!;
    if (FIND_FLAGS.has(w)) continue;
    if (FIND_TESTS_WITH_ARG.has(w)) {
      if (k + 1 >= head.length) return null;
      k++;
      continue;
    }
    if (w === "-type") {
      if (!/^[fdl]$/.test(head[k + 1] ?? "")) return null;
      k++;
      continue;
    }
    if (w === "-maxdepth" || w === "-mindepth") {
      if (!/^\d{1,3}$/.test(head[k + 1] ?? "")) return null;
      k++;
      continue;
    }
    return null;
  }
  return { kind: "find", operands };
}

/** What the caller's filesystem says of a path below a folder: whether it
 *  exists (not following a symlink at the end, as `find` prints it). */
export interface PathsOnlyFs extends ListingFs {
  exists(path: string): boolean;
}

/**
 * The folders a paths-only pipeline listed, when every line of `value` is a
 * path the listing could have printed (see the RULE above); null otherwise.
 * Pure but for `fs`.
 */
export function pathsOnlyListingPaths(
  value: string,
  command: string,
  fs: PathsOnlyFs,
  opts: TwinOutputOpts = {},
): string[] | null {
  const p = pathsOnlyCommand(command);
  if (p === null) return null;
  const lines = keyListingLines(opts.codexHead === true ? value : withoutHarnessTail(value), opts);
  if (lines === null || lines.length > PATHS_ONLY_MAX_LINES) return null;
  if (p.kind === "ls") {
    const resolved = fs.resolve(p.operand);
    if (resolved === null || !resolved.startsWith("/")) return null;
    const path = posix.normalize(resolved).replace(/(?<=.)\/+$/, "");
    const e = fs.entry(path);
    if (e === null || "file" in e) return null;
    if (e.dir.length > DIR_LISTING_MAX_ENTRIES || !e.dir.every((n) => PLAIN_NAME_RE.test(n))) return null;
    const shown = new Set(shownEntries(e.dir, p.hidden));
    return lines.every((l) => shown.has(l)) ? [path] : null;
  }
  const roots: Array<{ word: string; path: string }> = [];
  for (const word of p.operands) {
    const resolved = fs.resolve(word);
    if (resolved === null || !resolved.startsWith("/")) return null;
    const path = posix.normalize(resolved).replace(/(?<=.)\/+$/, "");
    if (fs.entry(path) === null) return null;
    roots.push({ word, path });
  }
  for (const line of lines) {
    if (line === "" || !PLAIN_NAME_RE.test(line)) return null;
    let ok = false;
    for (const r of roots) {
      // find prints the operand as written, then `/` and the path below it
      // (an operand ending in `/` keeps that one slash)
      const stem = r.word.replace(/(?<=.)\/+$/, "");
      if (line === r.word || line === stem) { ok = true; break; }
      const prefix = r.word.endsWith("/") ? r.word : `${stem}/`;
      if (!line.startsWith(prefix)) continue;
      const rel = line.slice(prefix.length);
      if (rel === "" || rel.split("/").some((s) => s === "" || s === "." || s === "..")) continue;
      if (fs.exists(posix.join(r.path, rel))) { ok = true; break; }
    }
    if (!ok) return null;
  }
  return roots.map((r) => r.path);
}

/** `hostListingFs` with the existence test `find`'s lines need. */
export function hostPathsOnlyFs(startDir: string | null, home: string): PathsOnlyFs {
  const base = hostListingFs(startDir, home);
  return {
    ...base,
    exists(path) {
      try {
        lstatSync(path);
        return true;
      } catch {
        return false;
      }
    },
  };
}
