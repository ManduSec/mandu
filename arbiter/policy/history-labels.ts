/**
 * history-labels (arbiter copy) — which paths a repository's HISTORY holds
 * that the human labels put above `public`, and the keys a history walk is
 * cached and compared by (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md
 * §11.1 R2).
 *
 * The arbiter's background resolver (lock-resolution.ts) turns every path
 * label into the blob ids of its versions in each known repository, and the
 * launcher's object twins use those ids in place of their own walk when the
 * two computed the same `resolutionKey`. So both must decide a history path,
 * bound a walk and key it the SAME way: this file is a COPY of
 * launcher/src/history-labels.ts below this header (the launcher and the
 * arbiter ship standalone and never import each other), held identical by
 * tests/stack/lock-resolution-parity.test.ts, which also runs
 * both resolutions over one corpus of repositories. Its precedence rule is
 * itself pinned against path-labels.ts `resolvePathLabel` there and in
 * git-history-locks-parity.test.ts. Change the launcher's file, copy it here.
 *
 * Pure but for walkShallowRule, whose git calls go through the runner it is
 * handed: no filesystem.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, copied from
 * launcher/src/history-labels.ts (itself a mirror of path-glob.ts and
 * path-labels.ts); no reference origin.
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

/**
 * What the walk honours of the state that rewrites history as git sees it
 * (security fix 2026-10-21, confidentiality.md §7.2a "What the walk does
 * not let a repository hide"). A graft (`info/grafts`), a replace ref
 * (`refs/replace/*`) or a shallow file (`shallow`) written into a
 * repository cut commits out of `git log` while their objects stay in the
 * store, readable by `git show <commit>:<file>`; the agent can write `.git`.
 * So every hardened git call runs with replace refs off and an empty graft
 * file (hardened-git.ts: GIT_NO_REPLACE_OBJECTS, GIT_GRAFT_FILE=/dev/null),
 * and the walk honours the shallow file only where it is TRUE: when no
 * parent of any commit it names is in the store (walkShallowRule). Part of
 * the base key, so a walk cached by the earlier rule is never used.
 */
export const HISTORY_WALK_REWRITES = "rewrites:v2 replace-refs=off grafts=off shallow=true-boundaries-only locked-memory";

/** What besides the tips decides the walk's output: the git version, the
 *  walk's arguments and rule (HISTORY_WALK_REWRITES), and the shallow
 *  boundary it honours (walkShallowRule `honoured`). Pure. */
export function walkBaseKey(parts: { gitVersion: string; shallow: string }): string {
  return createHash("sha256")
    .update(JSON.stringify([HISTORY_WALK_ARGS, HISTORY_WALK_REWRITES, parts.gitVersion.trim(), parts.shallow]))
    .digest("hex");
}

/** A git call of the shallow rule: `args` with `input` on stdin. */
export type ShallowRuleGit = (args: string[], input: string) => Promise<{ code: number; stdout: string }>;

/** How the walk treats the shallow file: the global options it runs with,
 *  and the boundary it honours (the base key's part: "" for none). */
export interface ShallowRule {
  args: string[];
  honoured: string;
}

/** The commits of a shallow file (sorted, unique), or null when a line is
 *  not an object name of `hexLen` hex digits. Pure. */
export function parseShallowEntries(text: string, hexLen: number): string[] | null {
  const re = new RegExp(`^[0-9a-f]{${hexLen}}$`);
  const out = new Set<string>();
  for (const l of text.split("\n")) {
    if (l === "") continue;
    if (!re.test(l)) return null;
    out.add(l);
  }
  return [...out].sort();
}

/** `rev-list --no-walk --parents` output: commit → its parents. Pure. */
export function parseParentLines(out: string, hexLen: number): Map<string, string[]> {
  const re = new RegExp(`^[0-9a-f]{${hexLen}}$`);
  const m = new Map<string, string[]>();
  for (const l of out.split("\n")) {
    const w = l.trim().split(" ").filter((x) => x !== "");
    if (w.length === 0 || !w.every((x) => re.test(x))) continue;
    m.set(w[0]!, w.slice(1));
  }
  return m;
}

/** The objects `cat-file --batch-check=%(objectname) %(objecttype)` found
 *  (a missing one reads `<name> missing`). Pure. */
export function parsePresentObjects(out: string): Set<string> {
  const s = new Set<string>();
  for (const l of out.split("\n")) {
    const [name, type] = l.trim().split(" ");
    if (name !== undefined && name !== "" && type !== undefined && type !== "missing") s.add(name);
  }
  return s;
}

/** The global options that make a walk ignore the shallow file. */
export const IGNORE_SHALLOW_ARGS: readonly string[] = ["--shallow-file", ""];

/**
 * The shallow rule (HISTORY_WALK_REWRITES). A shallow file is honoured only
 * when every commit it names has no parent in the store: a true boundary
 * (a `git clone --depth` keeps nothing beyond it, so walking past it would
 * fail on the missing parents). Anything else (an entry whose parent is
 * present: the shallow file cuts history the store holds; a line that is
 * not an object name; a git call that fails) IGNORES the whole file
 * (IGNORE_SHALLOW_ARGS): the walk goes on through every present parent, and
 * where a forged entry sits beside a true boundary it fails on the missing
 * parents, which refuses the launch (fail-closed). An empty or absent file
 * costs no git call.
 */
export async function walkShallowRule(git: ShallowRuleGit, shallowText: string, hexLen: number): Promise<ShallowRule> {
  const entries = parseShallowEntries(shallowText, hexLen);
  const ignore: ShallowRule = { args: [...IGNORE_SHALLOW_ARGS], honoured: "" };
  if (entries === null) return ignore;
  if (entries.length === 0) return { args: [], honoured: "" };
  const honour: ShallowRule = { args: [], honoured: entries.join("\n") };
  // Each entry's parents, read past the shallow file itself (which hides
  // them); an entry the store lacks names nothing to cut.
  const p = await git([...IGNORE_SHALLOW_ARGS, "rev-list", "--no-walk", "--parents", "--ignore-missing", "--stdin"], `${entries.join("\n")}\n`);
  if (p.code !== 0) return ignore;
  const parents = [...new Set([...parseParentLines(p.stdout, hexLen).values()].flat())].sort();
  if (parents.length === 0) return honour;
  const c = await git(["cat-file", "--batch-check=%(objectname) %(objecttype)"], `${parents.join("\n")}\n`);
  if (c.code !== 0) return ignore;
  const present = parsePresentObjects(c.stdout);
  return parents.some((x) => present.has(x)) ? ignore : honour;
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
