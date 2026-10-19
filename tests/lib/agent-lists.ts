/**
 * agent-lists — finds hand-copied lists of agents in source text, for the
 * agent registry's tests (scripts/agents/agent-registry.mjs;
 * docs/design/agents/supported-agents.md §5.7). Every list of agents is the
 * registry or a named filter over it; this is how a test sees one that is not.
 *
 * What counts as a list: at least `min` (4) distinct agent ids together,
 *   - `list`: a run of quoted ids separated by `,` or `|` (an array, a
 *     `Set`, a type union, a call's arguments), other quoted words between
 *     them allowed (`"shell"`, `"codex-code"`);
 *   - `rows`: `id: "<agent>"` fields close together (an array of rows);
 *   - `keys`: an object literal keyed by agent ids (plain JS only: a
 *     TypeScript table is typed `Record<Agent, …>`, so the type checker
 *     names it when an agent is added).
 * Four, not all: when an agent is added, an old copy of the others is still
 * found. A subset of three or fewer is not looked for.
 *
 * Pure: text in, findings out; `sourceFiles` is the one reader of the disk.
 * Mandu-new test plumbing (no reference origin).
 */
import { existsSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

export type ListForm = "list" | "rows" | "keys";

export interface FoundList {
  form: ListForm;
  /** 1-based line of the list's start */
  line: number;
  /** the agent ids it names, in order of first appearance */
  ids: string[];
  /** every word the list holds (a `list`'s quoted words, else its ids) */
  words: string[];
}

const lineAt = (text: string, i: number): number => text.slice(0, i).split("\n").length;
const distinct = (xs: readonly string[]): string[] => [...new Set(xs)];

/** The quoted-word runs naming at least `min` distinct ids. */
function lists(text: string, ids: ReadonlySet<string>, min: number): FoundList[] {
  const out: FoundList[] = [];
  const run = /(?:(["'])[a-z0-9-]+\1\s*[,|]\s*)+(["'])[a-z0-9-]+\2/g;
  for (const m of text.matchAll(run)) {
    const words = [...m[0].matchAll(/(["'])([a-z0-9-]+)\1/g)].map((w) => w[2]!);
    const named = distinct(words.filter((w) => ids.has(w)));
    if (named.length >= min) out.push({ form: "list", line: lineAt(text, m.index!), ids: named, words });
  }
  return out;
}

/** `id: "<agent>"` fields, grouped while each is within `gap` characters of the last. */
function rows(text: string, ids: ReadonlySet<string>, min: number, gap = 200): FoundList[] {
  const out: FoundList[] = [];
  let group: Array<{ id: string; at: number }> = [];
  const flush = (): void => {
    const named = distinct(group.map((g) => g.id));
    if (named.length >= min) out.push({ form: "rows", line: lineAt(text, group[0]!.at), ids: named, words: named });
    group = [];
  };
  for (const m of text.matchAll(/\bid\s*:\s*(["'])([a-z0-9-]+)\1/g)) {
    if (!ids.has(m[2]!)) continue;
    if (group.length && m.index! - group[group.length - 1]!.at > gap) flush();
    group.push({ id: m[2]!, at: m.index! });
  }
  if (group.length) flush();
  return out;
}

/** Object literals keyed by at least `min` distinct ids (`claude: …` or
 *  `"claude": …`), read with a bracket stack that skips strings and comments. */
function keyed(text: string, ids: ReadonlySet<string>, min: number): FoundList[] {
  const out: FoundList[] = [];
  const stack: Array<{ at: number; keys: string[] }> = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i]!;
    if (c === "/" && text[i + 1] === "/") { const e = text.indexOf("\n", i); i = e < 0 ? n : e; continue; }
    if (c === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < n && text[j] !== c) j += text[j] === "\\" ? 2 : 1;
      const word = text.slice(i + 1, j);
      let k = j + 1;
      while (k < n && /\s/.test(text[k]!)) k++;
      if (text[k] === ":" && ids.has(word) && stack.length) stack[stack.length - 1]!.keys.push(word);
      i = j + 1;
      continue;
    }
    if (c === "{") { stack.push({ at: i, keys: [] }); i++; continue; }
    if (c === "}") {
      const top = stack.pop();
      const named = distinct(top?.keys ?? []);
      if (top && named.length >= min) out.push({ form: "keys", line: lineAt(text, top.at), ids: named, words: named });
      i++;
      continue;
    }
    const w = /^[A-Za-z_$][\w$]*/.exec(text.slice(i, i + 64));
    if (w) {
      let k = i + w[0].length;
      while (k < n && (text[k] === " " || text[k] === "\t")) k++;
      const prev = i > 0 ? text[i - 1]! : "";
      if (text[k] === ":" && text[k + 1] !== ":" && ids.has(w[0]) && !/[.\w$]/.test(prev) && stack.length) stack[stack.length - 1]!.keys.push(w[0]);
      i += w[0].length;
      continue;
    }
    i++;
  }
  return out.sort((a, b) => a.line - b.line);
}

/** The agent lists in one file's text. `keys` is looked for in plain JS only
 *  (`.js`, `.mjs`). */
export function findAgentLists(text: string, agentIds: readonly string[], o: { file?: string; min?: number } = {}): FoundList[] {
  const ids = new Set(agentIds);
  const min = o.min ?? 4;
  const plainJs = o.file === undefined || /\.m?js$/.test(o.file);
  return [...lists(text, ids, min), ...rows(text, ids, min), ...(plainJs ? keyed(text, ids, min) : [])].sort((a, b) => a.line - b.line);
}

/** The agent ids a stretch of text names as whole words. */
export function idsNamed(text: string, agentIds: readonly string[]): string[] {
  return agentIds.filter((id) => new RegExp(`(?<![\\w-])${id}(?![\\w-])`).test(text));
}

/** The text from `marker` to the bracket that closes the first `{` or `[`
 *  after it (or to `until`, when given); null when the marker is absent. */
export function sliceFrom(text: string, marker: string, until?: string): string | null {
  const at = text.indexOf(marker);
  if (at < 0) return null;
  if (until !== undefined) {
    const end = text.indexOf(until, at);
    return end < 0 ? null : text.slice(at, end + until.length);
  }
  const open = text.slice(at).search(/[[{]/);
  if (open < 0) return null;
  let depth = 0;
  for (let i = at + open; i < text.length; i++) {
    const c = text[i];
    if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") { depth--; if (depth === 0) return text.slice(at, i + 1); }
  }
  return null;
}

/** The source files under `roots` (repo-relative directories or files):
 *  TypeScript and JavaScript, no test file (`*.test.*`, a `test/` or
 *  `fixtures/` directory), nothing under node_modules or dist. Repo-relative,
 *  sorted. A root that does not exist is skipped (the public tree lacks the
 *  maintainers' directories). */
export function sourceFiles(repo: string, roots: readonly string[]): string[] {
  const out: string[] = [];
  const keep = (rel: string): boolean =>
    /\.(?:ts|mts|js|mjs)$/.test(rel) && !/\.d\.(?:ts|mts)$/.test(rel) && !/\.test\.[mc]?[jt]s$/.test(rel) && !/(?:^|\/)(?:test|fixtures)\//.test(rel);
  const walk = (abs: string): void => {
    let entries;
    try { entries = readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === "dist" || e.name.startsWith(".")) continue;
      const p = join(abs, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) { const rel = relative(repo, p); if (keep(rel)) out.push(rel); }
    }
  };
  for (const r of roots) {
    const abs = join(repo, r);
    if (/\.[a-z]+$/.test(r)) { if (keep(r) && existsSync(abs)) out.push(r); } else walk(abs);
  }
  return [...new Set(out)].sort();
}
