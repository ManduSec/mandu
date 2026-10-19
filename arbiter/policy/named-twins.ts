/**
 * named-twins — the twin each secret file a shell command NAMES would give a
 * read of that file on its own (confidentiality.md §7.1, "the path-derived
 * note", the way to the file itself, 2026-10-19).
 *
 * Mandu-new (no reference origin).
 *
 * ── THE GAP ─────────────────────────────────────────────────────────────────
 *
 * A command that names a secret file (`ls -R taxes/; cat taxes/2025/* | head`)
 * has its WHOLE output masked, and the model proxy's note said why and how to
 * read the OTHER files (a command of their own). It said nothing about the
 * secret file itself, so a model that needed it (the tax return's summary of
 * the `demo-tax-extension` demo under Mandu's defaults, 2026-10-19, 2 takes of
 * 3) read "hidden from you" as "locked" and gave up, though a read of that one
 * file would have given its twin: each line's label, each value a placeholder
 * it could place in the task.
 *
 * ── THE ANSWER ──────────────────────────────────────────────────────────────
 *
 * The arbiter's classify op answers, beside the verdict's `namedPaths`, the
 * twin a read of each named file on its own gives (`namedTwins`): `fields`
 * (a structured twin, each secret value a placeholder), `lines` (a document
 * twin, each line's label kept and its value a placeholder), `whole` (the
 * whole-file twin: one placeholder for the file) or `text` (an own-text twin:
 * Mandu read every place of it that can hold a secret and found none). A
 * token the arbiter cannot place on files, or whose files are not all
 * registered with one twin kind, gets no answer, and the note says nothing
 * about it: the claim is made only where it is true.
 *
 * The answer holds the model's own token and a kind, never a byte of a file
 * nor a path the model did not write. It explains only: the result stays
 * masked whole, whatever it says. Pure: the file system and the twin lookup
 * are injected.
 */

import { isAbsolute, join, resolve as resolvePath } from "node:path";

/** The twin a read of a secret file on its own gives (see the header). */
export type NamedTwinKind = "fields" | "lines" | "whole" | "text";

/** One named token's answer: the token as the model wrote it, and the twin
 *  kind every secret file it names shares. */
export interface NamedTwin {
  path: string;
  twin: NamedTwinKind;
}

/** The bounds of one answer. Past any of them a token gets no answer. */
export const NAMED_TWIN_LIMITS = {
  /** Tokens looked at (the proxy names at most 3 in its note). */
  tokens: 6,
  /** Entries read from one directory while expanding a glob. */
  dirEntries: 512,
  /** Files one glob token may name. */
  files: 16,
  /** Path segments of one token. */
  segments: 32,
} as const;

/** What the expansion reads of the file system. */
export interface NamedTwinFs {
  /** `"file"`, `"dir"`, or null (missing, or anything else). Follows links,
   *  as the shell's `cat` does. */
  kind(path: string): "file" | "dir" | null;
  /** The names in a directory, or null when it cannot be read. */
  list(dir: string): string[] | null;
}

export interface NamedTwinsOptions {
  /** The directory a relative token is read in (the call's start directory,
   *  or the leading `cd` of its command); undefined: relative tokens get no
   *  answer. */
  base: string | undefined;
  /** The HOME a `~/` token is read under; undefined: such tokens get none. */
  home: string | undefined;
  fs: NamedTwinFs;
  /** Is the file at this absolute path secret (labelled or registered)? */
  isSecretFile(path: string): boolean;
  /** The twin a read of this secret file gives, or null when it has none
   *  Mandu serves (not registered, or no twin). */
  twinKindOf(path: string): NamedTwinKind | null;
}

const GLOB_RE = /[*?[]/;

/** One path segment against one shell glob segment: `*` any run, `?` one
 *  character, `[set]` / `[!set]` / `[^set]` one of (or not of) a set with
 *  ranges. A leading `.` of the name is matched only by a literal `.`, as the
 *  shell does. Linear DP, no regex. Null for a pattern this reader does not
 *  take (an unterminated `[`, a backslash). */
export function globSegmentMatches(pattern: string, name: string): boolean | null {
  type Tok = { t: "lit"; c: string } | { t: "one" } | { t: "any" } | { t: "set"; neg: boolean; test: (c: string) => boolean };
  const toks: Tok[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "\\") return null;
    if (c === "*") { if (toks[toks.length - 1]?.t !== "any") toks.push({ t: "any" }); continue; }
    if (c === "?") { toks.push({ t: "one" }); continue; }
    if (c === "[") {
      let j = i + 1;
      let neg = false;
      if (pattern[j] === "!" || pattern[j] === "^") { neg = true; j++; }
      const start = j;
      if (pattern[j] === "]") j++;
      while (j < pattern.length && pattern[j] !== "]") j++;
      if (j >= pattern.length) return null;
      const body = pattern.slice(start, j);
      const singles = new Set<string>();
      const ranges: Array<[string, string]> = [];
      for (let k = 0; k < body.length; k++) {
        if (body[k + 1] === "-" && k + 2 < body.length) { ranges.push([body[k]!, body[k + 2]!]); k += 2; }
        else singles.add(body[k]!);
      }
      toks.push({ t: "set", neg, test: (ch) => singles.has(ch) || ranges.some(([a, b]) => ch >= a && ch <= b) });
      i = j;
      continue;
    }
    toks.push({ t: "lit", c });
  }
  if (name.startsWith(".") && !(toks[0]?.t === "lit" && toks[0].c === ".")) return false;
  // dp[j]: the first i tokens match the first j characters
  let dp = new Array<boolean>(name.length + 1).fill(false);
  dp[0] = true;
  for (const tok of toks) {
    const next = new Array<boolean>(name.length + 1).fill(false);
    if (tok.t === "any") {
      let seen = false;
      for (let j = 0; j <= name.length; j++) { seen = seen || dp[j]!; next[j] = seen; }
    } else {
      for (let j = 1; j <= name.length; j++) {
        if (!dp[j - 1]) continue;
        const ch = name[j - 1]!;
        const ok = tok.t === "one" ? true : tok.t === "lit" ? ch === tok.c : tok.test(ch) !== tok.neg;
        if (ok) next[j] = true;
      }
    }
    dp = next;
  }
  return dp[name.length]!;
}

/** The absolute place of a token as the shell reads it: absolute, `~/…`
 *  under `home`, or relative under `base`; null when it has no known place
 *  (a `~user`, a brace, an expansion, a relative token with no base). */
function placeOf(token: string, base: string | undefined, home: string | undefined): string | null {
  if (token === "" || /[{}$`'"\\\s]/.test(token)) return null;
  if (token === "~" || token.startsWith("~/")) return home !== undefined && isAbsolute(home) ? join(home, token.slice(1)) : null;
  if (token.startsWith("~")) return null;
  if (isAbsolute(token)) return resolvePath(token);
  return base !== undefined && isAbsolute(base) ? resolvePath(base, token) : null;
}

/** The files a token names, as the shell would expand it (a glob's matches
 *  in sorted order; a plain path when it is a file); null when there are
 *  none, or past a bound. A directory names no file here (a listing of it
 *  reads no content). */
export function namedFiles(token: string, base: string | undefined, home: string | undefined, fs: NamedTwinFs): string[] | null {
  const abs = placeOf(token, base, home);
  if (abs === null) return null;
  if (!GLOB_RE.test(token)) return fs.kind(abs) === "file" ? [abs] : null;
  const segs = abs.split("/").filter((s) => s !== "");
  if (segs.length > NAMED_TWIN_LIMITS.segments) return null;
  let places = ["/"];
  for (const [i, seg] of segs.entries()) {
    const last = i === segs.length - 1;
    const out: string[] = [];
    for (const dir of places) {
      if (!GLOB_RE.test(seg)) { out.push(join(dir, seg)); continue; }
      const names = fs.list(dir);
      if (names === null) continue;
      if (names.length > NAMED_TWIN_LIMITS.dirEntries) return null;
      for (const n of [...names].sort()) {
        const m = globSegmentMatches(seg, n);
        if (m === null) return null;
        if (m) out.push(join(dir, n));
      }
    }
    if (out.length > NAMED_TWIN_LIMITS.files * (last ? 1 : 4)) return null;
    places = out;
  }
  const files = places.filter((p) => fs.kind(p) === "file");
  return files.length > 0 ? files : null;
}

/**
 * The twin answer for the tokens a classify verdict names (`namedPaths`):
 * for each token, in order, the kind every SECRET file it names shares, when
 * it names at least one secret file and each has a twin of that one kind.
 * Tokens with no answer are left out. Pure over the injected reads.
 */
export function namedTwinsFor(tokens: readonly string[] | undefined, opts: NamedTwinsOptions): NamedTwin[] {
  const out: NamedTwin[] = [];
  for (const token of (tokens ?? []).slice(0, NAMED_TWIN_LIMITS.tokens)) {
    if (typeof token !== "string" || token.length > 400 || out.some((o) => o.path === token)) continue;
    const files = namedFiles(token, opts.base, opts.home, opts.fs);
    if (files === null) continue;
    const secret = files.filter((f) => opts.isSecretFile(f));
    if (secret.length === 0) continue;
    const kinds = new Set(secret.map((f) => opts.twinKindOf(f)));
    if (kinds.size !== 1 || kinds.has(null)) continue;
    out.push({ path: token, twin: [...kinds][0]! });
  }
  return out;
}
