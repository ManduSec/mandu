/**
 * rule-source — the lines of policy.yaml a Rules page row stands for
 * (dashboard.md §4.25g). Mandu-new (no reference origin).
 *
 * The Rules page shows rows projected from the COMPILED law; "Show in
 * policy.yaml" answers with the person's own text: the exact lines, their
 * numbers, comments included. js-yaml reports no source positions, so the
 * file is cut by indentation into its top-level sections and each sequence
 * into its items (with the comment lines directly above an item), and each
 * item is parsed on its own and matched to the row id the same way the
 * compiled law names it (rule-actions.ts, policy-panel.ts). Read-only: this
 * never feeds an edit.
 */
import { homedir } from "node:os";
import path from "node:path";

import yaml from "js-yaml";

export interface RuleSourceLines {
  found: true;
  /** 1-based number of the first line shown. */
  start: number;
  lines: string[];
  /** 1-based numbers of the lines that name this rule (the rest is context). */
  mark: number[];
}
export interface RuleSourceMissing {
  found: false;
  /** Why there is nothing to show, in the page's words. */
  reason: string;
}
export type RuleSource = RuleSourceLines | RuleSourceMissing;

const NOT_WRITTEN = "This rule is not written in policy.yaml. It comes from Mandu's built-in settings.";

interface Block { start: number; end: number } // 0-based, end exclusive

/** Locate the row `id` in the policy file `text`. */
export function locateRule(text: string, id: string, home: string = homedir()): RuleSource {
  const lines = text.split("\n");
  const section = (key: string): Block | null => topSection(lines, key);

  if (id.startsWith("lock:")) {
    const want = pathKey(id.slice("lock:".length), home);
    return firstItem(lines, section("paths"), (v) => {
      const p = (v as { path?: unknown } | null)?.path;
      return typeof p === "string" && pathKey(p, home) === want;
    });
  }
  if (id.startsWith("app:")) {
    const app = id.slice("app:".length);
    return firstItem(lines, section("apps"), (v) => (v as { app?: unknown } | null)?.app === app);
  }
  if (id.startsWith("connect:")) {
    return firstItem(lines, section("destinations"), (v) => connectId(v) === id);
  }
  if (id.startsWith("disposition:")) {
    return keyBlock(lines, section("rules"), id.slice("disposition:".length));
  }
  if (id.startsWith("trusted-origin:") || id.startsWith("untrusted-origin:")) {
    const rest = id.slice(id.indexOf(":") + 1);
    const colon = rest.indexOf(":");
    const kind = rest.slice(0, colon);
    const value = rest.slice(colon + 1);
    const inbound = section("inbound");
    const found = keyBlock(lines, inbound, kind);
    if (!found.found) return found;
    // Mark the lines that name the value itself, when it is written there
    // (a value reached through a named list or a default is not).
    const mark = found.lines.flatMap((l, i) => (mentions(l, value) ? [found.start + i] : []));
    return mark.length ? { ...found, mark } : found;
  }
  return firstItem(lines, section("user_rules"), (v) => (v as { id?: unknown } | null)?.id === id);
}

/** The identity the compiled law gives a path (arbiter path-labels.ts
 *  normalizeLabelPath; a pattern keeps its text). */
function pathKey(p: string, home: string): string {
  const t = p.trim();
  const expanded = t === "~" ? home : t.startsWith("~/") ? path.posix.join(home, t.slice(2)) : t;
  if (/(^|[^\\])[*?[]/.test(t)) return `glob:${expanded}`;
  let n = path.posix.normalize(expanded.replace(/\\([*?[\]\\])/g, "$1"));
  if (n.length > 1 && n.endsWith("/")) n = n.slice(0, -1);
  return n;
}

function connectId(v: unknown): string {
  const d = (v ?? {}) as { host?: unknown; port?: unknown; proto?: unknown };
  const proto = d.proto === "udp" ? "udp" : "tcp";
  const port = d.port === undefined ? 443 : d.port;
  return `connect:${proto}:${String(d.host).trim().toLowerCase()}:${String(port)}`;
}

function mentions(line: string, value: string): boolean {
  const code = line.replace(/\s#.*$/, "");
  return code.includes(value);
}

const indentOf = (l: string): number => l.length - l.trimStart().length;
const isBlank = (l: string): boolean => l.trim() === "";
const isComment = (l: string): boolean => l.trimStart().startsWith("#");

/** The lines under a top-level `key:` (the key line itself excluded). */
function topSection(lines: string[], key: string): Block | null {
  const at = lines.findIndex((l) => new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`).test(l));
  if (at < 0) return null;
  let end = at + 1;
  while (end < lines.length && (isBlank(lines[end]!) || indentOf(lines[end]!) > 0 || isComment(lines[end]!))) end++;
  // Comments at column 0 after the section belong to what follows it.
  while (end > at + 1 && (isBlank(lines[end - 1]!) || (isComment(lines[end - 1]!) && indentOf(lines[end - 1]!) === 0))) end--;
  return { start: at + 1, end };
}

/** Split a block sequence into its items: each from its `- ` line to the
 *  next item, with the comment lines directly above it and without the
 *  blank or comment lines that trail it. */
function items(lines: string[], block: Block): Block[] {
  const heads: number[] = [];
  let indent = -1;
  for (let i = block.start; i < block.end; i++) {
    const l = lines[i]!;
    if (isBlank(l) || isComment(l)) continue;
    if (/^\s*- /.test(l) || /^\s*-$/.test(l)) {
      if (indent < 0) indent = indentOf(l);
      if (indentOf(l) === indent) heads.push(i);
    }
  }
  return heads.map((h, k) => {
    let start = h;
    while (start - 1 >= block.start && isComment(lines[start - 1]!)) start--;
    let end = k + 1 < heads.length ? heads[k + 1]! : block.end;
    while (end > h + 1 && (isBlank(lines[end - 1]!) || isComment(lines[end - 1]!))) end--;
    return { start, end };
  });
}

function firstItem(lines: string[], block: Block | null, match: (v: unknown) => boolean): RuleSource {
  if (!block) return { found: false, reason: NOT_WRITTEN };
  for (const it of items(lines, block)) {
    const chunk = lines.slice(it.start, it.end);
    const head = chunk.findIndex((l) => !isComment(l));
    let value: unknown;
    try {
      const pad = indentOf(chunk[head]!);
      value = (yaml.load(chunk.map((l) => l.slice(Math.min(pad, indentOf(l)))).join("\n")) as unknown[] | null)?.[0];
    } catch {
      continue;
    }
    if (match(value)) {
      return {
        found: true, start: it.start + 1, lines: chunk,
        mark: chunk.flatMap((l, i) => (i >= head && !isComment(l) && !isBlank(l) ? [it.start + 1 + i] : [])),
      };
    }
  }
  return { found: false, reason: NOT_WRITTEN };
}

/** A `key:` inside a mapping block, with the lines indented under it. */
function keyBlock(lines: string[], block: Block | null, key: string): RuleSource {
  if (!block) return { found: false, reason: NOT_WRITTEN };
  const quoted = (k: string): string[] => [k, `"${k}"`, `'${k}'`];
  for (let i = block.start; i < block.end; i++) {
    const l = lines[i]!;
    if (isBlank(l) || isComment(l)) continue;
    // A key may itself hold a colon (`egress:untrusted-destination:`), so
    // match the whole key, then its `:` and a space or the line end.
    const body = l.trimStart();
    const names = quoted(key).some((q) => body.startsWith(`${q}:`) && /^(\s|$)/.test(body.slice(q.length + 1)));
    if (!names) continue;
    const pad = indentOf(l);
    let end = i + 1;
    while (end < block.end && (isBlank(lines[end]!) || indentOf(lines[end]!) > pad)) end++;
    while (end > i + 1 && (isBlank(lines[end - 1]!) || isComment(lines[end - 1]!))) end--;
    let start = i;
    while (start - 1 >= block.start && isComment(lines[start - 1]!)) start--;
    const chunk = lines.slice(start, end);
    return { found: true, start: start + 1, lines: chunk, mark: [i + 1] };
  }
  return { found: false, reason: NOT_WRITTEN };
}
