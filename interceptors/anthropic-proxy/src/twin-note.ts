/**
 * twin-note — the symbol-twin shell note (docs/design/integrity/symbol-twin-shell-blindness.md).
 *
 * Under the fs rung an untrusted workspace file exists in the AgentView as one
 * or more symbol-token lines, so a shell `grep` / `sed` over it returns nothing
 * and T-LLM gets an empty result with no hint that the emptiness is structural
 * (watch-20260918T085750: U4/U6/U18/I12-4 answered "no such file" / "the file
 * is short" with confidence). This module computes a per-call note the proxy
 * appends OUTSIDE the symbolized span of a Bash tool_result.
 *
 * SECURITY (design §3/§4.2): the note is a trusted-code-derived signal. Its
 * inputs are (1) path tokens of the MODEL'S OWN `command` (in-context,
 * model-authored), (2) a TCB predicate over the AgentView twin's bytes —
 * "does this regular, non-symlink file consist solely of $MDU: tokens?" — and
 * (3) those tokens, which are opaque handles a `Read` of the same path would
 * return verbatim. No byte of the HumanView original, of the command's output,
 * and no line count / size / hash of the original enters the note. The note is
 * NEVER matched out of the result bytes (unlike the arbiter's trusted harness
 * shapes): a file whose content equals the note text, `cat`'d by the agent,
 * arrives inside the Bash body and is symbolized whole.
 *
 * UTILITY-ONLY: every error path yields no note; nothing here may throw into
 * the request path.
 */

import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { isAbsolute, join as joinPath, resolve as resolvePath, sep } from "node:path";

/** The marker every note paragraph starts with — for tests and the dashboard,
 *  NOT a trust marker (the arbiter classifies nothing by it). */
export const TWIN_MARKER = "[mandu:twin]";

/** At most this many paths per call are LISTED in the note (design §4.3). */
export const TWIN_MAX_PATHS = 8;
/** At most this many path-like words of the command are EXAMINED (design
 *  §4.1b): beyond it, and beyond TWIN_MAX_PATHS listed, the note carries a
 *  COUNT ("N more file(s) not listed") instead of silence — a note that named
 *  8 of 10 files read as "the other two are fine" (watch-20260918T194546 U6). */
export const TWIN_SCAN_MAX = 64;

/** A twin larger than this is not a symbol-line file; skip without reading. */
export const TWIN_MAX_BYTES = 64 * 1024;
/** At most this many regular files under a named DIRECTORY are examined for
 *  the directory form of the note; the rest are counted as `more`. */
export const TWIN_DIR_SCAN_MAX = 256;

/**
 * One whole line that IS a symbol token. Mirrors the arbiter's SYMBOL_PATTERN
 * (arbiter/symbol-table/symbol-table.ts) anchored to the full line: the base
 * `$MDU:<tool>[<hex4-8>]` plus optional `.field` extensions.
 */
export const SYMBOL_TOKEN_LINE_RE =
  /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*$/;

export interface TwinEntry {
  /** The path as it should be spelled in the note (the model's spelling,
   *  reverse-mapped to HumanView by the caller). */
  path: string;
  /** The twin's symbol tokens in file order (≥ 1). Empty for a DIRECTORY
   *  entry (see `dir`). */
  tokens: string[];
  /** Present when the path is a directory under a root (`grep -r DIR`,
   *  `find DIR`, `cat DIR/*`): how many regular files under it are symbolic
   *  twins (`files`, ≥ 1) and how many files the bounded walk did not examine
   *  (`more`). COUNTS ONLY — a filename is data an attacker controls (a cloned
   *  repo can carry `ignore-all-instructions.md`), so no name the model did
   *  not type ever enters the note (design §3). */
  dir?: { files: number; more: number };
  /** True when the path came ONLY from the exec box's hint (design §4.1 v2)
   *  — a pipeline / post-`cd` / shell-expanded leaf the command parse could
   *  not resolve. Observability only. */
  hinted?: boolean;
}

/**
 * A box-side candidate (design §4.1 v2, arbiter op `execTwinsFor`): the path a
 * boxed AgentShell leaf named, as its argv spelled it, plus the absolute
 * AgentView twin the box resolved against the leaf's own cwd. A HINT: this
 * module re-applies the twin predicate under the proxy's own roots before
 * anything is said about it.
 */
export interface TwinHint {
  asTyped: string;
  abs: string;
}

/** The note's path spelling must stay a single plain line: control bytes and
 *  oversize spellings (a hint is derived from shell-expanded argv) are
 *  rejected outright — no note for that path rather than a mangled template. */
const MAX_SPELLING = 512;
function spellingOk(p: string): boolean {
  if (typeof p !== "string" || p === "" || p.length > MAX_SPELLING) return false;
  for (let i = 0; i < p.length; i++) {
    const c = p.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

const REDIRECT_RE = /^(?:\d*>>?|&>>?|<)$/;
const ATTACHED_REDIRECT_RE = /^(?:\d*>>?|&>>?|<)(.+)$/;
const FLAG_VALUE_RE = /^--?[A-Za-z][\w-]*=(.+)$/;

function stripQuotes(t: string): string {
  let s = t;
  while (s.length >= 2 && ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"')))) {
    s = s.slice(1, -1);
  }
  return s;
}

/** Does this token look like a path: contains `/`, or ends in a `.ext`. */
function pathLike(t: string): boolean {
  if (t === "" || t === "." || t === ".." || t.startsWith("-")) return false;
  if (t.includes("://")) return false;
  if (t.includes("/")) return true;
  return /\.[A-Za-z0-9]{1,16}$/.test(t) && !/^\d+(\.\d+)*$/.test(t);
}

/**
 * The path-looking words of a shell command line, in order, de-duplicated,
 * at most TWIN_SCAN_MAX (see `extractPathCandidatesDetailed` for the count of
 * words past that bound): split on whitespace and the shell separators
 * `| ; & ( )`, strip quotes and a `--flag=` prefix, keep words containing `/`
 * or a `.ext`, drop flags, URLs and redirection TARGETS (`> out.txt`,
 * `>>log`, `2>err`, `< in`). Best-effort tokenization — a word the model
 * spelled in a way this misses simply gets no note.
 */
export function extractPathCandidates(command: string): string[] {
  return extractPathCandidatesDetailed(command).candidates;
}

/** A bare word (`docs`, `src`: no `/`, no `.`, `[A-Za-z0-9_-]+`) that could
 *  name a DIRECTORY (`grep -r X docs`). Kept apart from `candidates` (the
 *  file-ish words) and tried by `findTwinsDetailed` as a directory only;
 *  `TODO`, `RC-2026` and the like never resolve to one. The program word
 *  (first word) is excluded. */
const BARE_WORD_RE = /^[A-Za-z0-9_-]+$/;

/** `.` / `..` name a DIRECTORY the command searched (`grep -r X .`, `find .`)
 *  — the most common spelling of "this folder". `pathLike` rejects them and
 *  BARE_WORD_RE does not match them, so they used to vanish; the directory-only
 *  leg is exactly right for them. (Live watch U6, 2026-09-20: a recursive grep
 *  over `.` got no note on haiku, sonnet or opus, and two of them answered
 *  "no such code".) The `cd` target is still excluded upstream. */
const DOT_DIR_RE = /^\.{1,2}$/;

const GLOB_META_RE = /[*?[]/;

/** The directory part of a GLOB word (`*.txt` → `.`, `docs/*.md` → `docs`,
 *  `<root>/*.txt` → `<root>`), or null when the word has no glob
 *  metacharacter or the directory part itself is a glob. The proxy sees the
 *  command text BEFORE the shell expands it, so a glob never names a file —
 *  but its directory does, and the DIRECTORY form of the note (counts only,
 *  never a filename the model did not type) is the right answer for it. */
export function globParent(word: string): string | null {
  if (!GLOB_META_RE.test(word)) return null;
  const i = word.lastIndexOf("/");
  const dir = i < 0 ? "." : i === 0 ? "/" : word.slice(0, i);
  return GLOB_META_RE.test(dir) ? null : dir;
}

export function extractPathCandidatesDetailed(command: string): { candidates: string[]; bareWords: string[]; unexamined: number } {
  const out: string[] = [];
  const bare: string[] = [];
  let unexamined = 0;
  if (typeof command !== "string" || command === "") return { candidates: out, bareWords: bare, unexamined };
  // Per pipeline/chain segment, so each segment's PROGRAM word (`cat`,
  // `grep` after a `|`) is known and never taken as a bare directory word.
  const words: { raw: string; isFirst: boolean }[] = [];
  for (const seg of command.split(/[|;&()]+/)) {
    const ws = seg.split(/\s+/).filter((w) => w !== "");
    ws.forEach((raw, i) => words.push({ raw, isFirst: i === 0 }));
  }
  let skipNext = false;
  let afterCd = false;
  for (const { raw, isFirst } of words) {
    if (skipNext) { skipNext = false; continue; }
    let w = stripQuotes(raw);
    // the target of `cd` / `pushd` is where the command RUNS, not what it
    // reads — never a directory candidate (bare or path-like)
    const cdTarget = afterCd;
    afterCd = w === "cd" || w === "pushd";
    if (cdTarget) continue;
    if (REDIRECT_RE.test(w)) { skipNext = true; continue; }
    if (ATTACHED_REDIRECT_RE.test(w)) continue;
    const fv = FLAG_VALUE_RE.exec(w);
    if (fv) {
      w = stripQuotes(fv[1]!);
      // `--include='*.txt'` is a NAME FILTER, not a location: a slash-less
      // glob in a flag value says nothing about which directory was searched
      // (that is the command's positional `docs` or `.`), so it names nothing.
      if (GLOB_META_RE.test(w) && !w.includes("/")) continue;
    }
    if (!pathLike(w)) {
      const dirWord = DOT_DIR_RE.test(w) || (BARE_WORD_RE.test(w) && !w.startsWith("-"));
      if (!isFirst && dirWord && !bare.includes(w) && bare.length < TWIN_SCAN_MAX) bare.push(w);
      continue;
    }
    if (out.includes(w)) continue;
    if (out.length >= TWIN_SCAN_MAX) { unexamined++; continue; }
    out.push(w);
  }
  return { candidates: out, bareWords: bare, unexamined };
}

/**
 * The symbol tokens of an AgentView twin, or null when the file is not a twin
 * (not a regular non-symlink file, larger than TWIN_MAX_BYTES, empty, or any
 * non-empty line is not exactly one symbol token). Any error → null.
 */
export function twinTokens(absPath: string): string[] | null {
  try {
    const st = lstatSync(absPath);
    if (!st.isFile() || st.isSymbolicLink()) return null;
    if (st.size === 0 || st.size > TWIN_MAX_BYTES) return null;
    const text = readFileSync(absPath, "utf8");
    const tokens: string[] = [];
    for (const line of text.split(/\r?\n/)) {
      const t = line.trim();
      if (t === "") continue;
      if (!SYMBOL_TOKEN_LINE_RE.test(t)) return null;
      tokens.push(t);
    }
    return tokens.length > 0 ? tokens : null;
  } catch {
    return null;
  }
}

/**
 * The directory form's counts: walk `absDir` (depth-first, symlinks and
 * `.git` skipped, at most TWIN_DIR_SCAN_MAX regular files examined) and
 * count the symbolic twins. `files` = twins seen; `more` = regular files past
 * the bound (not examined). Null when the walk fails or finds no twin.
 */
export function dirTwinCounts(absDir: string): { files: number; more: number } | null {
  try {
    const st = lstatSync(absDir);
    if (!st.isDirectory() || st.isSymbolicLink()) return null;
    let examined = 0;
    let files = 0;
    let more = 0;
    const stack = [absDir];
    while (stack.length > 0) {
      const dir = stack.pop()!;
      let names: string[];
      try { names = readdirSync(dir); } catch { continue; }
      names.sort();
      for (const name of names) {
        if (name === ".git") continue;
        const p = joinPath(dir, name);
        let ps;
        try { ps = lstatSync(p); } catch { continue; }
        if (ps.isSymbolicLink()) continue;
        if (ps.isDirectory()) { stack.push(p); continue; }
        if (!ps.isFile()) continue;
        if (examined >= TWIN_DIR_SCAN_MAX) { more++; continue; }
        examined++;
        if (twinTokens(p)) files++;
      }
    }
    return files > 0 ? { files, more } : null;
  } catch {
    return null;
  }
}

function underRoot(abs: string, root: string): boolean {
  const r = root.endsWith(sep) ? root.slice(0, -sep.length) : root;
  return abs === r || abs.startsWith(r + sep);
}

/**
 * Resolve one path candidate against the AgentView roots: an absolute path
 * must sit under a root; a relative one joins each root in turn (the box's
 * cwd is the AgentView root unless the model `cd`'d, in which case the join
 * misses and the path is skipped). Returns the absolute twin path or null.
 */
export function resolveCandidate(candidate: string, agentViewRoots: readonly string[]): string | null {
  for (const root of agentViewRoots) {
    if (typeof root !== "string" || root === "") continue;
    const abs = isAbsolute(candidate) ? resolvePath(candidate) : resolvePath(root, candidate);
    if (!underRoot(abs, resolvePath(root))) continue;
    if (isAbsolute(candidate)) return abs;
    try {
      lstatSync(abs);
      return abs;
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * The twins a command touched: candidates → resolved under a root → symbolic.
 * `spell` renders the path for the note (the caller passes the HumanView
 * reverse map so the note is spelled like every other path on the wire).
 * Never throws.
 */
export function findTwins(
  command: string,
  agentViewRoots: readonly string[],
  spell: (asTyped: string) => string = (p) => p,
  hints: readonly TwinHint[] = [],
): TwinEntry[] {
  return findTwinsDetailed(command, agentViewRoots, spell, hints).entries;
}

/** `findTwins` plus `more`: how many files the command named that the note
 *  does NOT list — symbolic twins past TWIN_MAX_PATHS (parse or hint), words
 *  past the parse's scan bound, and what the box's own hint reported as left
 *  out (`hintMore`). A count, never a name. */
export function findTwinsDetailed(
  command: string,
  agentViewRoots: readonly string[],
  spell: (asTyped: string) => string = (p) => p,
  hints: readonly TwinHint[] = [],
  hintMore = 0,
): { entries: TwinEntry[]; more: number } {
  const out: TwinEntry[] = [];
  const seen = new Set<string>();
  let more = Number.isFinite(hintMore) && hintMore > 0 ? Math.floor(hintMore) : 0;
  const push = (asTyped: string, abs: string, hinted: boolean): void => {
    if (seen.has(abs)) return;
    const tokens = twinTokens(abs);
    const dir = tokens ? null : dirTwinCounts(abs);
    if (!tokens && !dir) return;
    let path = asTyped;
    try { path = spell(asTyped); } catch { path = asTyped; }
    if (!spellingOk(path)) return;
    seen.add(abs);
    if (out.length >= TWIN_MAX_PATHS) { more++; return; }
    const entry: TwinEntry = tokens ? { path, tokens } : { path, tokens: [], dir: dir! };
    if (hinted) entry.hinted = true;
    out.push(entry);
  };
  try {
    // (1) the model's own command text — the v1 cut.
    const parsed = extractPathCandidatesDetailed(command);
    more += parsed.unexamined;
    for (const cand of parsed.candidates) {
      // A glob word stands for its DIRECTORY (see globParent). An absolute
      // candidate comes back from resolveCandidate unchecked, so the parent
      // must really be a directory before the directory form applies.
      const globDir = globParent(cand);
      const word = globDir ?? cand;
      const abs = resolveCandidate(word, agentViewRoots);
      if (!abs) continue;
      if (globDir !== null) {
        try { if (!lstatSync(abs).isDirectory()) continue; } catch { continue; }
      }
      push(word, abs, false);
    }
    // (1b) bare words, as DIRECTORIES only (`grep -r X docs`): a word that
    // resolves under a root to a directory holding a twin gets the directory
    // form; anything else is silently not a path.
    for (const word of parsed.bareWords) {
      const abs = resolveCandidate(word, agentViewRoots);
      if (!abs || seen.has(abs)) continue;
      try { if (!lstatSync(abs).isDirectory()) continue; } catch { continue; }
      push(word, abs, false);
    }
    // (2) the box's leaf-level hints (v2): each `abs` must sit under one of
    // THIS proxy's roots (a foreign-session or out-of-view path is dropped),
    // and the twin predicate is re-applied over its bytes — the hint decides
    // nothing on its own.
    for (const h of hints) {
      if (!h || typeof h.abs !== "string" || typeof h.asTyped !== "string") continue;
      if (!isAbsolute(h.abs) || !spellingOk(h.asTyped)) continue;
      const abs = resolvePath(h.abs);
      if (!agentViewRoots.some((r) => typeof r === "string" && r !== "" && underRoot(abs, resolvePath(r)))) continue;
      push(h.asTyped, abs, true);
    }
  } catch {
    return { entries: out, more };
  }
  return { entries: out, more };
}

/**
 * The note text — the fixed template of design §4.3, one paragraph per twin,
 * paragraphs joined by a blank line, plus — when `more` > 0 — one closing
 * sentence with the COUNT of named files the note does not list. No free
 * text about untrusted content.
 */
export function buildTwinNote(entries: readonly TwinEntry[], more = 0): string {
  const paras: string[] = [];
  for (const e of entries.slice(0, TWIN_MAX_PATHS)) {
    if (e.dir) {
      const f = e.dir.files;
      const extra = e.dir.more > 0 ? ` (${e.dir.more} more file${e.dir.more === 1 ? "" : "s"} under it not counted)` : "";
      paras.push(
        `${TWIN_MARKER} ${e.path} is a directory holding ${f} untrusted file${f === 1 ? "" : "s"} whose content is stored as opaque symbols${extra}. ` +
          "Shell content search and line addressing over them see nothing — this empty result is expected. " +
          "To use their content: list the directory, Read each file to obtain its token, then inspect_symbol the token for what you need.",
      );
      continue;
    }
    const n = e.tokens.length;
    const what = n === 1
      ? `the opaque symbol ${e.tokens[0]} (1 token)`
      : `the opaque symbols (${n} tokens):\n${e.tokens.join("\n")}`;
    paras.push(
      `${TWIN_MARKER} ${e.path} is an untrusted file: in this workspace its content is ${what}. ` +
        "Shell content search and line addressing over it see nothing — this empty result is expected. " +
        "To use its content: Read the file, then inspect_symbol the token for what you need; " +
        "to copy it verbatim, write the token itself.",
    );
  }
  const n = Number.isFinite(more) && more > 0 ? Math.floor(more) : 0;
  if (n > 0) {
    paras.push(
      `${TWIN_MARKER} This command named ${n} more file${n === 1 ? "" : "s"} not listed here; ` +
        "any other untrusted file in this workspace is stored the same way — Read it to obtain its token.",
    );
  }
  return paras.join("\n\n");
}

/** `{ paths, tokens[, hinted][, more] }` for the tool_result event (no
 *  content): `hinted` counts the paths only the exec box's leaf hint
 *  surfaced; `more` the named files the note left out (a count). */
export function twinNoteSummary(entries: readonly TwinEntry[], more = 0): { paths: string[]; tokens: number; hinted?: number; more?: number; dirs?: number } {
  const hinted = entries.filter((e) => e.hinted).length;
  const dirs = entries.filter((e) => e.dir).length;
  const n = Number.isFinite(more) && more > 0 ? Math.floor(more) : 0;
  return {
    paths: entries.map((e) => e.path),
    tokens: entries.reduce((n, e) => n + e.tokens.length, 0),
    ...(hinted > 0 ? { hinted } : {}),
    ...(n > 0 ? { more: n } : {}),
    ...(dirs > 0 ? { dirs } : {}),
  };
}
