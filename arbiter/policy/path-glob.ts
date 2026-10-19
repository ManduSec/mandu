/**
 * path-glob — gitignore-style patterns for `policy.yaml paths:` labels
 * (docs/design/confidentiality/confidentiality.md §6.1).
 *
 * Mandu-new (no reference origin). A literal `paths:` entry names one file or
 * one subtree; a law that wants "every `*.pem` anywhere" or "the `contracts`
 * dir of every drill workspace" had to enumerate them. A pattern says it once.
 *
 * ── WHY NOT REGEX ───────────────────────────────────────────────────────────
 * Three failure modes, each of which is a SILENT MISLABEL (§6 names that as the
 * risk that kills a labeling deployment):
 *   - an unanchored regex over-matches (`.*\.env` also hits `x.env.bak`), and an
 *     over-matching `public` entry is a quiet declassification;
 *   - "most specific label wins" has no meaning between two regexes;
 *   - the JS regex engine backtracks, and the resolver runs on EVERY classify:
 *     one bad pattern in the law would stall the security daemon.
 * A glob is segment-aware by construction (the property path-labels.ts already
 * calls load-bearing: `/a/docs` must never cover `/a/docs-public`), has a
 * natural specificity (its literal prefix), and is matched here WITHOUT the
 * regex engine: a wildcard walk per segment, O(pattern × name), and a small
 * table over the segments for `**`. No input makes it exponential.
 *
 * ── THE GRAMMAR ─────────────────────────────────────────────────────────────
 *   *        any run of characters inside ONE path segment (dotfiles included)
 *   ?        exactly one character inside a segment
 *   [abc] [a-z] [!abc]   one character from (or, with `!`/`^`, not from) a set
 *   **       as a WHOLE segment: zero or more segments
 *   \x       the character x, literally (so a real `*` in a file name is `\*`)
 * A pattern is ANCHORED: it starts with `/`, `~/`, or a leading `**` segment
 * ("anywhere on the machine"). There
 * is no negation (`!pattern`): carving a public file out of a secret pattern is
 * a second entry with `level: public`, decided by the precedence rule, so the
 * exception is a visible row of the law rather than a modifier on another row.
 *
 * `recursive` keeps its meaning (gitignore's too: a matched directory covers
 * what is below it): recursive (the default) ⇒ the pattern covers a path it
 * matches AND every descendant of one; `recursive: false` ⇒ the matched path only.
 */

import { homedir } from "os";
import path from "path";

type SegToken =
  | { t: "lit"; c: string }
  | { t: "one" }
  | { t: "any" }
  | { t: "set"; negate: boolean; chars: string; ranges: Array<[string, string]> };

type Segment = { kind: "globstar" } | { kind: "name"; tokens: SegToken[]; literal: string | null };

export interface CompiledPathGlob {
  /** The pattern as the law states it, `~` expanded — what `via` / `rule` show. */
  pattern: string;
  segments: Segment[];
  /** The leading run of fully literal segments, as a path ("" for a pattern
   *  that leads with `**`). Its LENGTH is the pattern's specificity (path-labels.ts). */
  literalPrefix: string;
}

/** Does the string contain an UNESCAPED glob metacharacter? A `paths:` entry
 *  without one is a literal label, exactly as before patterns existed. */
export function hasGlobMeta(raw: string): boolean {
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === "\\") { i++; continue; }
    if (c === "*" || c === "?" || c === "[") return true;
  }
  return false;
}

/** Hard bounds — a law file is human-written; anything past these is a mistake
 *  or an attack on the resolver's per-classify cost. */
export const MAX_GLOB_LENGTH = 512;
export const MAX_GLOB_SEGMENTS = 32;

function parseSegment(seg: string, errors: string[]): Segment | null {
  if (seg === "**") return { kind: "globstar" };
  const tokens: SegToken[] = [];
  let literal: string | null = "";
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i]!;
    if (c === "\\") {
      if (i + 1 >= seg.length) { errors.push("a trailing '\\' escapes nothing"); return null; }
      const lit = seg[++i]!;
      tokens.push({ t: "lit", c: lit });
      if (literal !== null) literal += lit;
    } else if (c === "*") {
      if (seg[i + 1] === "*") { errors.push(`'**' must be a whole path segment (got '${seg}'); inside a segment use a single '*'`); return null; }
      tokens.push({ t: "any" });
      literal = null;
    } else if (c === "?") {
      tokens.push({ t: "one" });
      literal = null;
    } else if (c === "[") {
      let j = i + 1;
      let negate = false;
      if (seg[j] === "!" || seg[j] === "^") { negate = true; j++; }
      let chars = "";
      const ranges: Array<[string, string]> = [];
      let closed = false;
      let first = true;
      for (; j < seg.length; j++) {
        let ch = seg[j]!;
        if (ch === "]" && !first) { closed = true; break; }
        first = false;
        if (ch === "\\" && j + 1 < seg.length) ch = seg[++j]!;
        if (seg[j + 1] === "-" && j + 2 < seg.length && seg[j + 2] !== "]") {
          let hi = seg[j + 2]!;
          let skip = 2;
          if (hi === "\\" && j + 3 < seg.length) { hi = seg[j + 3]!; skip = 3; }
          if (hi < ch) { errors.push(`the range '${ch}-${hi}' in '${seg}' is reversed`); return null; }
          ranges.push([ch, hi]);
          j += skip;
        } else {
          chars += ch;
        }
      }
      if (!closed) { errors.push(`'[' in '${seg}' is never closed (a literal '[' is '\\[')`); return null; }
      tokens.push({ t: "set", negate, chars, ranges });
      literal = null;
      i = j;
    } else {
      tokens.push({ t: "lit", c });
      if (literal !== null) literal += c;
    }
  }
  return { kind: "name", tokens, literal };
}

/**
 * Compile a pattern, or say why it is not one. Pure; the validator reports the
 * errors at boot/reload (a law that does not parse never loads) and the policy
 * compile keeps the result.
 */
export function compilePathGlob(raw: string, home: string = homedir()): { glob: CompiledPathGlob } | { errors: string[] } {
  const errors: string[] = [];
  if (typeof raw !== "string" || raw.trim() === "") return { errors: ["the pattern is empty"] };
  let p = raw.trim();
  const anywhere = p === "**" || p.startsWith("**/");
  if (p.length > MAX_GLOB_LENGTH) return { errors: [`the pattern is longer than ${MAX_GLOB_LENGTH} characters`] };
  if (p === "~") p = home;
  else if (p.startsWith("~/")) p = path.posix.join(home, p.slice(2));
  else if (anywhere) p = "/" + p;
  if (!p.startsWith("/")) return { errors: ["a pattern is anchored: it starts with '/', '~/' or '**/' (anywhere)"] };
  const rawSegs = p.split("/").filter((s) => s !== "");
  if (rawSegs.length === 0) return { errors: ["the pattern names no path"] };
  if (rawSegs.length > MAX_GLOB_SEGMENTS) return { errors: [`the pattern has more than ${MAX_GLOB_SEGMENTS} segments`] };
  const segments: Segment[] = [];
  for (const s of rawSegs) {
    if (s === "." || s === "..") { errors.push(`'${s}' segments are not allowed in a pattern (write the resolved path)`); continue; }
    const seg = parseSegment(s, errors);
    if (!seg) continue;
    // `**/**` says nothing `**` does not; keep one so the table stays small
    if (seg.kind === "globstar" && segments[segments.length - 1]?.kind === "globstar") continue;
    segments.push(seg);
  }
  if (errors.length > 0) return { errors };
  if (segments.every((s) => s.kind === "globstar")) return { errors: ["the pattern matches every path on the machine; label a directory instead"] };
  const lead: string[] = [];
  for (const s of segments) {
    if (s.kind !== "name" || s.literal === null) break;
    lead.push(s.literal);
  }
  // displayed as the law wrote it (`~` expanded): a leading `**` stays unrooted
  const pattern = (anywhere ? "" : "/") + rawSegs.join("/");
  return { glob: { pattern, segments, literalPrefix: lead.length ? "/" + lead.join("/") : "" } };
}

function setHas(tok: Extract<SegToken, { t: "set" }>, c: string): boolean {
  let hit = tok.chars.includes(c);
  if (!hit) for (const [lo, hi] of tok.ranges) if (c >= lo && c <= hi) { hit = true; break; }
  return hit !== tok.negate;
}

/** One segment against one name: the classic star-backtrack wildcard walk.
 *  Worst case O(tokens × name); never exponential. */
function segmentMatches(tokens: readonly SegToken[], name: string): boolean {
  let ti = 0, ni = 0, starT = -1, starN = 0;
  while (ni < name.length) {
    const tok = tokens[ti];
    if (tok && tok.t === "any") { starT = ti++; starN = ni; continue; }
    if (tok && (tok.t === "one" || (tok.t === "lit" && tok.c === name[ni]) || (tok.t === "set" && setHas(tok, name[ni]!)))) { ti++; ni++; continue; }
    if (starT === -1) return false;
    ti = starT + 1;
    ni = ++starN;
  }
  while (tokens[ti]?.t === "any") ti++;
  return ti === tokens.length;
}

/**
 * Does the pattern cover the ABSOLUTE, normalized path? `recursive` ⇒ a path
 * below a matched path is covered too. A table over (pattern segment, path
 * segment): O(segments × depth) cells, each one segment match.
 */
export function pathGlobMatches(glob: CompiledPathGlob, absPath: string, recursive: boolean): boolean {
  const names = absPath.split("/").filter((s) => s !== "");
  const segs = glob.segments;
  const P = segs.length, N = names.length;
  // reach[i][j]: can segs[i..] cover names[j..] ?  Filled from the end.
  const reach: boolean[][] = Array.from({ length: P + 1 }, () => new Array<boolean>(N + 1).fill(false));
  for (let j = 0; j <= N; j++) reach[P]![j] = recursive ? true : j === N; // pattern spent: the rest is "below"
  for (let i = P - 1; i >= 0; i--) {
    const seg = segs[i]!;
    for (let j = N; j >= 0; j--) {
      if (seg.kind === "globstar") {
        reach[i]![j] = reach[i + 1]![j]! || (j < N && reach[i]![j + 1]!);
      } else {
        reach[i]![j] = j < N && segmentMatches(seg.tokens, names[j]!) && reach[i + 1]![j + 1]!;
      }
    }
  }
  return reach[0]![0]!;
}

/**
 * Does the pattern's FINAL segment match this file name? null when the pattern
 * ends in `**` or a bare `*` (it then names a whole directory's contents, not a
 * class of file names). For the "does this pattern TARGET secret-shaped names?"
 * report (secret-catalog.ts `patternTargetsCatalogSecret`); decides nothing.
 */
export function pathGlobLastSegmentMatches(glob: CompiledPathGlob, name: string): boolean | null {
  const last = glob.segments[glob.segments.length - 1];
  if (!last || last.kind === "globstar") return null;
  if (last.tokens.length === 1 && last.tokens[0]!.t === "any") return null;
  return segmentMatches(last.tokens, name);
}
