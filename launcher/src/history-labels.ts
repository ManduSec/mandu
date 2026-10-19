/**
 * history-labels — which paths a repository's HISTORY holds that the human
 * labels put above `public` (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md
 * §8.1; confidentiality.md §7.2a "Gone paths").
 *
 * The object twins (git-object-twins.ts) started from the files a launch
 * confines, which exist. A labelled file that was committed and later deleted
 * (the deploy key of C17) is in no file on disk, so nothing led a launch to
 * its history. The arbiter now hands the launcher the human labels
 * (`gitHistoryLocks`: policy.yaml `paths:` and the dashboard's, EVERY level,
 * since a `public` label carves a file out of a labelled folder), and this
 * module decides each path a history walk sees by the same rule every
 * confidentiality derivation uses.
 *
 * MIRROR of arbiter/policy/path-glob.ts (`compilePathGlob`, `pathGlobMatches`)
 * and arbiter/policy/path-labels.ts (`resolvePathLabel`, `isPathPrefix`): the
 * launcher never imports the arbiter package (it typechecks and ships
 * standalone), so the rule is restated here and pinned against the
 * arbiter's by tests/stack/git-history-locks-parity.test.ts
 * over a corpus of labels and paths. Change one, change both.
 *
 * It also holds the KEYS a history walk is cached and compared by (plan 14
 * §11.1 R2): the arbiter resolves the same labels into blob ids in the
 * background (arbiter/policy/history-labels.ts is a COPY of this file below
 * the header, held identical by tests/stack/
 * lock-resolution-parity.test.ts), and the launcher uses the arbiter's
 * answer for a repository only when both compute the same `resolutionKey`.
 *
 * Pure: no filesystem, no git.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, a mirror of Mandu's own
 * arbiter modules named above (no reference origin).
 */
import { createHash } from "node:crypto";
import { dirname, join, posix } from "node:path";

/** One human label as `gitHistoryLocks` answers it: a literal as its
 *  normalized absolute path, a pattern as compiled (`~` expanded, `**` + "/…"
 *  when unrooted). */
export interface HistoryLabel {
  path: string;
  level: string;
  recursive: boolean;
  glob?: true;
}

const RANK: Record<string, number> = { "public": 0, "any-model": 1, "local-model": 2, "no-model": 3 };

/** A level's rank; an unknown level ranks as `no-model` (fail closed, as the
 *  arbiter's parser does). */
export function levelRank(level: string): number {
  return RANK[level] ?? 3;
}

// ── patterns (mirror of path-glob.ts) ───────────────────────────────────────

type SegToken =
  | { t: "lit"; c: string }
  | { t: "one" }
  | { t: "any" }
  | { t: "set"; negate: boolean; chars: string; ranges: Array<[string, string]> };

type Segment = { kind: "globstar" } | { kind: "name"; tokens: SegToken[]; literal: string | null };

export interface HistoryGlob {
  segments: Segment[];
  /** The leading literal segments as a path ("" when the pattern leads with `**`). */
  literalPrefix: string;
}

function parseSegment(seg: string): Segment | null {
  if (seg === "**") return { kind: "globstar" };
  const tokens: SegToken[] = [];
  let literal: string | null = "";
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i]!;
    if (c === "\\") {
      if (i + 1 >= seg.length) return null;
      const lit = seg[++i]!;
      tokens.push({ t: "lit", c: lit });
      if (literal !== null) literal += lit;
    } else if (c === "*") {
      if (seg[i + 1] === "*") return null;
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
          if (hi < ch) return null;
          ranges.push([ch, hi]);
          j += skip;
        } else {
          chars += ch;
        }
      }
      if (!closed) return null;
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

/** A compiled pattern, or null when it is not one (the arbiter's validator
 *  refuses such a law, so a null here matches NOTHING, as the arbiter's
 *  resolver does). The arbiter sends patterns already `~`-expanded. */
export function compileHistoryGlob(raw: string): HistoryGlob | null {
  if (typeof raw !== "string" || raw.trim() === "") return null;
  let p = raw.trim();
  if (p === "**" || p.startsWith("**/")) p = "/" + p;
  if (!p.startsWith("/")) return null;
  const segments: Segment[] = [];
  for (const s of p.split("/").filter((x) => x !== "")) {
    if (s === "." || s === "..") return null;
    const seg = parseSegment(s);
    if (seg === null) return null;
    if (seg.kind === "globstar" && segments[segments.length - 1]?.kind === "globstar") continue;
    segments.push(seg);
  }
  if (segments.length === 0 || segments.every((s) => s.kind === "globstar")) return null;
  const lead: string[] = [];
  for (const s of segments) {
    if (s.kind !== "name" || s.literal === null) break;
    lead.push(s.literal);
  }
  return { segments, literalPrefix: lead.length ? "/" + lead.join("/") : "" };
}

function setHas(tok: Extract<SegToken, { t: "set" }>, c: string): boolean {
  let hit = tok.chars.includes(c);
  if (!hit) for (const [lo, hi] of tok.ranges) if (c >= lo && c <= hi) { hit = true; break; }
  return hit !== tok.negate;
}

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

/** Does the pattern cover the absolute path (and, `recursive`, what is below
 *  a path it matches)? */
export function historyGlobMatches(glob: HistoryGlob, absPath: string, recursive: boolean): boolean {
  const names = absPath.split("/").filter((s) => s !== "");
  const segs = glob.segments;
  const P = segs.length, N = names.length;
  const reach: boolean[][] = Array.from({ length: P + 1 }, () => new Array<boolean>(N + 1).fill(false));
  for (let j = 0; j <= N; j++) reach[P]![j] = recursive ? true : j === N;
  for (let i = P - 1; i >= 0; i--) {
    const seg = segs[i]!;
    for (let j = N; j >= 0; j--) {
      if (seg.kind === "globstar") reach[i]![j] = reach[i + 1]![j]! || (j < N && reach[i]![j + 1]!);
      else reach[i]![j] = j < N && segmentMatches(seg.tokens, names[j]!) && reach[i + 1]![j + 1]!;
    }
  }
  return reach[0]![0]!;
}

// ── precedence (mirror of path-labels.ts resolvePathLabel) ──────────────────

/** Is `ancestor` a path-SEGMENT prefix of `p` (or equal to it)? */
export function isPathPrefix(ancestor: string, p: string): boolean {
  if (ancestor === p) return true;
  return p.startsWith(ancestor.endsWith("/") ? ancestor : ancestor + "/");
}

/** Labels with their patterns compiled once. */
export interface CompiledHistoryLabels {
  labels: ReadonlyArray<HistoryLabel & { compiled: HistoryGlob | null }>;
  /** Literal labels by path, for the exact-match rule. */
  exact: ReadonlyMap<string, HistoryLabel>;
}

export function compileHistoryLabels(labels: readonly HistoryLabel[]): CompiledHistoryLabels {
  const exact = new Map<string, HistoryLabel>();
  const out = labels.map((l) => {
    if (!l.glob) exact.set(l.path, l);
    return { ...l, compiled: l.glob ? compileHistoryGlob(l.path) : null };
  });
  return { labels: out, exact };
}

function tieBeats(a: HistoryLabel, b: HistoryLabel): boolean {
  if (!!a.glob !== !!b.glob) return !!a.glob;
  if (!a.glob) return false;
  if (a.level !== b.level) return levelRank(a.level) > levelRank(b.level);
  return a.path < b.path;
}

/** The deciding label's level for an absolute, normalized path, or null when
 *  no label covers it: an exact literal wins; else the longest literal prefix
 *  among recursive literal ancestors and matching patterns; on a tie a
 *  pattern beats a literal, then the stricter level, then the pattern text. */
export function resolveHistoryLevel(absPath: string, c: CompiledHistoryLabels): string | null {
  const p = posix.normalize(absPath);
  const hit = c.exact.get(p);
  if (hit) return hit.level;
  let best: HistoryLabel | null = null;
  let bestSpec = -1;
  for (const l of c.labels) {
    let spec: number;
    if (l.glob) {
      if (l.compiled === null || !historyGlobMatches(l.compiled, p, l.recursive)) continue;
      spec = l.compiled.literalPrefix.length;
    } else {
      if (!l.recursive || !isPathPrefix(l.path, p)) continue;
      spec = l.path.length;
    }
    if (best === null || spec > bestSpec || (spec === bestSpec && tieBeats(l, best))) {
      best = l;
      bestSpec = spec;
    }
  }
  return best === null ? null : best.level;
}

/** Is the path labelled above `public` (its history is hidden)? */
export function labelledAbovePublic(absPath: string, c: CompiledHistoryLabels): boolean {
  const level = resolveHistoryLevel(absPath, c);
  return level !== null && levelRank(level) > 0;
}

/**
 * The labels plus, for each whose literal path (a pattern: its literal
 * prefix) has a different real spelling, a copy under that spelling. The
 * repositories are found by real path; a label written through a symlink
 * (`~/work` → `/mnt/data/work`) must still decide their history paths. Every
 * label is copied, `public` ones too, so a carve-out keeps winning under the
 * real spelling. Pure given `real`.
 */
export function withRealSpellings(labels: readonly HistoryLabel[], real: (p: string) => string): HistoryLabel[] {
  const out = [...labels];
  const seen = new Set(labels.map((l) => `${l.glob ? "g" : "l"}\0${l.path}`));
  const add = (l: HistoryLabel): void => {
    const k = `${l.glob ? "g" : "l"}\0${l.path}`;
    if (!seen.has(k)) { seen.add(k); out.push(l); }
  };
  for (const l of labels) {
    if (!l.glob) {
      const r = real(l.path);
      if (r !== l.path) add({ ...l, path: r });
      continue;
    }
    const g = compileHistoryGlob(l.path);
    if (g === null || g.literalPrefix === "" || !l.path.startsWith(g.literalPrefix + "/")) continue;
    const r = real(g.literalPrefix);
    if (r !== g.literalPrefix) add({ ...l, path: r + l.path.slice(g.literalPrefix.length) });
  }
  return out;
}

/**
 * What a history walk of the repository at `root` must read to find every
 * labelled path inside it: the pathspecs (relative to `root`) under which a
 * label above `public` may decide a path, or `null` for the whole history (a
 * recursive label on the root or an ancestor of it, a pattern whose literal
 * prefix is the root, above it or empty). `[]` when no label above `public`
 * can reach inside the repository (no walk). Pure.
 */
export function historyPathspecs(root: string, c: CompiledHistoryLabels): string[] | null {
  const specs = new Set<string>();
  for (const l of c.labels) {
    if (levelRank(l.level) === 0) continue; // a public label hides nothing on its own
    const base = l.glob ? (l.compiled === null ? null : l.compiled.literalPrefix) : l.path;
    if (base === null) continue;
    if (base === "" || isPathPrefix(base, root)) {
      // The label sits on the root or above it: every path of the repository
      // may be decided by it (a literal needs `recursive` to reach below
      // itself; a pattern always may match inside).
      if (l.glob || l.recursive) return null;
      continue;
    }
    if (isPathPrefix(root, base)) specs.add(posix.relative(root, base));
  }
  return [...specs].sort();
}

// ── the walk's keys (shared with the arbiter's resolver, plan 14 §11.1 R2) ──

/** The history walk's arguments after the revisions. `--root` so a root
 *  commit's files are listed whatever `log.showRoot` says. Part of the walk's
 *  base key: changing them re-walks every repository once. */
export const HISTORY_WALK_ARGS: readonly string[] = ["-m", "--root", "--format=", "--raw", "-z", "--no-abbrev", "--no-renames"];

/** What besides the tips decides the walk's output: the git version, the
 *  walk's arguments, and what rewrites history as git sees it (the shallow
 *  boundary, grafts, replace refs). Pure. */
export function walkBaseKey(parts: { gitVersion: string; shallow: string; grafts: string; replaceRefs: string }): string {
  return createHash("sha256")
    .update(JSON.stringify([HISTORY_WALK_ARGS, parts.gitVersion.trim(), parts.shallow, parts.grafts, parts.replaceRefs]))
    .digest("hex");
}

/** The cache key of a label walk: every label (a `public` carve-out changes
 *  what is kept too) and the pathspecs. Pure. */
export function labelWalkKey(labels: readonly HistoryLabel[], pathspecs: readonly string[] | null): string {
  const norm = [...labels].map((l) => [l.path, l.level, l.recursive, l.glob === true]).sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  return createHash("sha256").update(JSON.stringify([norm, pathspecs])).digest("hex").slice(0, 32);
}

/** The filter key of one repository's label walk: the labels' key and the
 *  pathspecs that bound the walk there. Pure. */
export function labelFilterKey(labelKey: string, specs: readonly string[] | null): string {
  return `${labelKey}:${JSON.stringify(specs)}`;
}

/** What one repository's label resolution was computed from: its root, the
 *  filter (labels + pathspecs), the base and the tips (every ref, every
 *  reflog entry). Equal keys, equal history blobs: the launcher uses the
 *  arbiter's blobs for a repository only on an equal key. Pure. */
export function resolutionKey(root: string, filterKey: string, base: string, tips: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify([root, filterKey, base, [...tips].sort()])).digest("hex");
}

/** `p` with its nearest existing ancestor replaced by that ancestor's real
 *  path (a gone path keeps its missing tail). Pure given `realpath`. */
export function realSpellingOf(p: string, realpath: (p: string) => string | null): string {
  let head = p;
  let tail = "";
  for (;;) {
    const r = realpath(head);
    if (r !== null) return tail === "" ? r : join(r, tail);
    const up = dirname(head);
    if (up === head) return p;
    tail = tail === "" ? head.slice(up.length).replace(/^\//, "") : join(head.slice(up.length).replace(/^\//, ""), tail);
    head = up;
  }
}
