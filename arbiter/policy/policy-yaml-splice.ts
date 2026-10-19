/**
 * policy-yaml-splice — write a changed policy document back into the
 * person's own `policy.yaml` text, keeping their comments and layout
 * (docs/design/ui/policy-surface.md §8.4.6 "Comments are kept"). Mandu-new
 * (no reference origin).
 *
 * The arbiter's writer is js-yaml, which keeps no comments: a dump of the
 * changed document drops every one the person wrote (first-session tour
 * item 17: an agent's lock made while a hand edit waited in Approvals
 * re-saved that hand edit without its comments). js-yaml reports no source
 * positions either, so, like the dashboard's "Show in policy.yaml"
 * (dashboard/src/rule-source.ts), the text is cut by indentation: a block
 * mapping into its entries, a block sequence into its items, each with the
 * comment lines directly above it. What did not change is copied as it was
 * written; what changed is spliced one level down where both sides are block
 * mappings or sequences; a new or rewritten entry is dumped at its place.
 * Sequence items are matched by value, then by their `id` / `path` / `name`
 * / `app` / `host` / `blob`, so a lock whose level changed keeps the
 * comments inside it. An entry rewritten whole keeps the comment at the end
 * of its old head line (`readers: [psql]   # the backup job`).
 *
 * SAFE BY CONSTRUCTION: the result is used only when it parses to exactly the
 * document a plain dump would give (`isDeepStrictEqual` over js-yaml's own
 * reading of both); anything this module does not understand (flow style at
 * the top, document markers, anchors, a chunk that does not read back as the
 * value it stands for) answers `null`, and the caller writes the plain dump.
 * The bytes written always mean the document that was judged.
 */
import { isDeepStrictEqual } from "node:util";
import yaml from "js-yaml";

/** The dump options of the store's writer (policy-document-store.ts). */
export const POLICY_DUMP_OPTIONS = { lineWidth: 100, noRefs: true, sortKeys: false } as const;

type Obj = Record<string, unknown>;

function isPlainObject(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Date);
}

const indentOf = (l: string): number => l.length - l.trimStart().length;
const isBlank = (l: string): boolean => l.trim() === "";
const isComment = (l: string): boolean => l.trimStart().startsWith("#");
const isDash = (l: string): boolean => /^-(\s|$)/.test(l.trimStart());

/** One entry of a block: the lines before it that stay where they are
 *  (`gap`: blank lines, and comments a blank line separates from it), the
 *  comment lines directly above it (`attached`), and its own lines (`body`,
 *  the head line first). */
interface Entry {
  gap: string[];
  attached: string[];
  body: string[];
}

/** Cut a block at `ind` into its entries (heads: `- ` lines for a sequence,
 *  key lines for a mapping) and the comment / blank lines after the last
 *  one. Null when a content line does not fit the block. */
function split(lines: readonly string[], ind: number, seq: boolean): { entries: Entry[]; tail: string[] } | null {
  const entries: Entry[] = [];
  let buf: string[] = [];
  let cur: Entry | null = null;
  for (const l of lines) {
    if (isBlank(l) || isComment(l)) {
      buf.push(l);
      continue;
    }
    const i = indentOf(l);
    const dash = isDash(l);
    if (i === ind && (seq ? dash : !dash)) {
      let k = buf.length;
      while (k > 0 && isComment(buf[k - 1]!)) k--;
      cur = { gap: buf.slice(0, k), attached: buf.slice(k), body: [l] };
      entries.push(cur);
      buf = [];
      continue;
    }
    // A continuation: deeper, or (a mapping only) a compact sequence written
    // at its key's indent (`paths:` then `- path: …`).
    if (cur === null || i < ind || (i === ind && (seq || !dash))) return null;
    cur.body.push(...buf, l);
    buf = [];
  }
  return { entries, tail: buf };
}

/** Read a chunk at `ind` on its own. */
function load(lines: readonly string[], ind: number): unknown {
  return yaml.load(lines.map((l) => l.slice(Math.min(ind, indentOf(l)))).join("\n"));
}

/** `value` dumped as a block at `ind`. */
function dumpAt(value: unknown, ind: number): string[] {
  const pad = " ".repeat(ind);
  return yaml.dump(value, POLICY_DUMP_OPTIONS).replace(/\n$/, "").split("\n").map((l) => (l === "" ? l : pad + l));
}

const has = (o: Obj, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k) && o[k] !== undefined;

/** The comment at the end of an entry's head line (`readers: [psql]   #
 *  the backup job`), with the spaces before it; null when there is none.
 *  Found as the first ` #` the line reads the same without (a `#` inside a
 *  quoted string is not one: the line no longer reads the same). */
function trailingComment(head: string, ind: number): string | null {
  let whole: unknown;
  try {
    whole = load([head], ind);
  } catch {
    return null;
  }
  for (const m of head.matchAll(/\s+#/g)) {
    const cut = head.slice(0, m.index);
    if (cut.trim() === "" || isComment(cut)) return null;
    try {
      if (isDeepStrictEqual(load([cut], ind), whole)) return head.slice(m.index);
    } catch {
      // not a cut point: a `#` inside a quoted string
    }
  }
  return null;
}

/** An entry rewritten whole (`dumped`), keeping the comment at the end of
 *  its old head line on the new one, so a value changed in place (a reader
 *  pinned: `readers: [psql]   # the backup job` becomes a block list) does
 *  not lose the person's note on it. The caller's read-back check still
 *  decides whether the bytes are used. */
function keepTrailing(dumped: string[], oldHead: string, ind: number): string[] {
  const c = trailingComment(oldHead, ind);
  if (c === null || dumped.length === 0) return dumped;
  return [dumped[0]! + c, ...dumped.slice(1)];
}

/** The children of an entry whose head holds no inline value, spliced. */
function spliceChildren(children: readonly string[], parentInd: number, before: unknown, after: unknown): string[] | null {
  const first = children.find((l) => !isBlank(l) && !isComment(l));
  if (first === undefined) return null; // an inline value: the caller dumps it
  const ci = indentOf(first);
  const dash = isDash(first);
  if (ci < parentInd || (ci === parentInd && !dash)) return null;
  if (dash && Array.isArray(before) && Array.isArray(after)) return spliceSequence(children, ci, before, after);
  if (!dash && ci > parentInd && isPlainObject(before) && isPlainObject(after)) return spliceMapping(children, ci, before, after);
  return null;
}

function spliceMapping(lines: readonly string[], ind: number, before: Obj, after: Obj): string[] | null {
  const s = split(lines, ind, false);
  if (!s) return null;
  const pairs: Array<[string, Entry]> = [];
  const seen = new Set<string>();
  for (const e of s.entries) {
    const v = load(e.body, ind);
    if (!isPlainObject(v)) return null;
    const ks = Object.keys(v);
    if (ks.length !== 1) return null;
    const k = ks[0]!;
    // Each chunk must read back as exactly the value it stands for.
    if (seen.has(k) || !has(before, k) || !isDeepStrictEqual(v[k], before[k])) return null;
    seen.add(k);
    pairs.push([k, e]);
  }
  if (seen.size !== Object.keys(before).filter((k) => has(before, k)).length) return null;
  const out: string[] = [];
  for (const [k, e] of pairs) {
    out.push(...e.gap);
    if (!has(after, k)) continue; // removed, with the comments directly above it
    out.push(...e.attached);
    if (isDeepStrictEqual(before[k], after[k])) {
      out.push(...e.body);
      continue;
    }
    const kids = spliceChildren(e.body.slice(1), ind, before[k], after[k]);
    out.push(...(kids ? [e.body[0]!, ...kids] : keepTrailing(dumpAt({ [k]: after[k] }, ind), e.body[0]!, ind)));
  }
  for (const k of Object.keys(after)) {
    if (has(after, k) && !seen.has(k)) out.push(...dumpAt({ [k]: after[k] }, ind));
  }
  out.push(...s.tail);
  return out;
}

const ID_FIELDS = ["id", "path", "name", "app", "host", "blob"] as const;

function identity(v: unknown): string | null {
  if (!isPlainObject(v)) return null;
  for (const f of ID_FIELDS) if (typeof v[f] === "string") return `${f}\0${v[f] as string}`;
  return null;
}

/** One sequence item whose value changed, spliced where it is a block
 *  mapping (`- key: v` and the lines under it, or `-` alone above them). */
function spliceItem(body: readonly string[], ind: number, before: unknown, after: unknown): string[] | null {
  if (!isPlainObject(before) || !isPlainObject(after)) return null;
  const head = body[0]!;
  const rest = head.slice(ind + 1);
  if (rest.trim() === "" || rest.trimStart().startsWith("#")) {
    const kids = spliceChildren(body.slice(1), ind, before, after);
    return kids ? [head, ...kids] : null;
  }
  const off = 1 + indentOf(rest);
  // Only a plain key on the dash line: not a flow collection, a quoted or
  // block scalar, an anchor, a tag, an alias or a nested sequence.
  if (!/^[A-Za-z0-9_]/.test(rest.trimStart())) return null;
  const inner = ind + off;
  const lines = [" ".repeat(inner) + head.slice(inner), ...body.slice(1)];
  const out = spliceMapping(lines, inner, before, after);
  if (!out || out.length === 0) return null;
  const first = out[0]!;
  if (isBlank(first) || isComment(first) || indentOf(first) !== inner) return null;
  out[0] = first.slice(0, ind) + "-" + first.slice(ind + 1);
  return out;
}

function spliceSequence(lines: readonly string[], ind: number, before: readonly unknown[], after: readonly unknown[]): string[] | null {
  const s = split(lines, ind, true);
  if (!s || s.entries.length !== before.length) return null;
  for (let i = 0; i < before.length; i++) {
    const v = load(s.entries[i]!.body, ind);
    if (!Array.isArray(v) || v.length !== 1 || !isDeepStrictEqual(v[0], before[i])) return null;
  }
  const used = new Set<number>();
  const match: Array<{ i: number; exact: boolean } | null> = after.map((a) => {
    for (let i = 0; i < before.length; i++) {
      if (!used.has(i) && isDeepStrictEqual(before[i], a)) {
        used.add(i);
        return { i, exact: true };
      }
    }
    return null;
  });
  after.forEach((a, j) => {
    if (match[j] !== null) return;
    const id = identity(a);
    if (id === null) return;
    for (let i = 0; i < before.length; i++) {
      if (!used.has(i) && identity(before[i]) === id) {
        used.add(i);
        match[j] = { i, exact: false };
        return;
      }
    }
  });
  const out: string[] = [];
  after.forEach((a, j) => {
    const m = match[j];
    if (m === null) {
      out.push(...dumpAt([a], ind));
      return;
    }
    const e = s.entries[m.i]!;
    out.push(...e.gap, ...e.attached);
    out.push(...(m.exact ? e.body : spliceItem(e.body, ind, before[m.i], a) ?? keepTrailing(dumpAt([a], ind), e.body[0]!, ind)));
  });
  out.push(...s.tail);
  return out;
}

/**
 * `text` (which reads as `before`) changed to read as `after`, with every
 * comment and line the change does not touch kept as written. Null when the
 * text is not in a shape this splices safely; the caller then dumps `after`.
 */
export function spliceYaml(text: string, before: unknown, after: unknown): string | null {
  try {
    if (!isPlainObject(before) || !isPlainObject(after)) return null;
    if (text.includes("\r") || text.includes("\t")) return null;
    // One plain document: no directives or markers, and the text reads as
    // the document it is said to be.
    if (/^(---|\.\.\.|%)/m.test(text)) return null;
    if (!isDeepStrictEqual(yaml.load(text) ?? {}, yaml.load(yaml.dump(before, POLICY_DUMP_OPTIONS)))) return null;
    const lines = text.split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    const out = spliceMapping(lines, 0, before, after);
    if (out === null) return null;
    const result = out.join("\n") + "\n";
    // The check every answer passes: the bytes mean exactly the document.
    if (!isDeepStrictEqual(yaml.load(result) ?? {}, yaml.load(yaml.dump(after, POLICY_DUMP_OPTIONS)))) return null;
    return result;
  } catch {
    return null;
  }
}
