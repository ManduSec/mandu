/**
 * symbol-format — Pluggable symbol format for Mandu.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted near-verbatim from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-symbol-format.ts
 *   Purpose: defines the SymbolFormat interface, the default `$MDU:`
 *   format, and LLM-escape normalization. (The T-LLM system-prompt builder,
 *   also lifted from that module, now lives in ./handling-prompt.ts.)
 *   Adaptation for Mandu M0: none of substance — this module had no OpenClaw
 *   runtime coupling. Only the file name changed (adfi-symbol-format → symbol-
 *   format) and the module is now consumed by the arbiter rather than the plugin.
 *   Canonical field allocation is Mandu-new (2026-09-11): encode fields
 *   outside the inherited scanner grammar; see mandu.md §9.
 *   Scanner, lookup and unescape behavior otherwise remain unchanged.
 *
 * Defines the SymbolFormat interface and the default $MDU: format.
 * To experiment with alternative formats, implement SymbolFormat and call
 * setActiveFormat() before the arbiter initializes.
 */

import type { ConfidentialityLevel } from "./confidentiality.js";

// ─────────────────────────────────────────────────────────────────────────────
// Interface
// ─────────────────────────────────────────────────────────────────────────────

export interface SymbolFormat {
  /** Human-readable name for logging / config (e.g. "mdu_sym"). */
  name: string;

  /** Substring that every symbol of this format contains (fast pre-check). */
  prefix: string;

  /**
   * Build a full symbol name from parts.
   * @example generate({ tool: "web_fetch", hash: "a1b2", field: "text" })
   *          → "$MDU:web_fetch[a1b2].text"
   * A secret `level` prepends a reserved tag marker INSIDE the grammar
   * (confidentiality.md §2 — presentation only, the table is authoritative):
   * @example generate({ tool: "Read", hash: "3fa9", level: "no-model" })
   *          → "$MDU:nomodel_Read[3fa9]"
   */
  generate(opts: {
    tool: string;
    hash: string;
    field?: string;
    level?: ConfidentialityLevel;
  }): string;

  /**
   * Global regex matching all symbols of this format.
   * MUST have the `g` flag.  Callers reset `lastIndex` before each use.
   */
  pattern: RegExp;

  /** Extract the hash portion from a symbol string, or null if not matched. */
  extractHash(symbol: string): string | null;

  /** Strip prefix + hash, returning the wire field suffix (empty if none).
   * Canonical suffixes may be encoded; original provenance lives in the row. */
  extractFieldPath(symbol: string): string;

}

// ─────────────────────────────────────────────────────────────────────────────
// Default format: $MDU:<tool>[<hash>].<field>
// ─────────────────────────────────────────────────────────────────────────────

const HASH_RE = /\[([0-9a-f]{4,8})\]/;
const FIELD_PATH_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]\.?/;

/** Reserved only for NEW allocations; persisted identifiers are not decoded. */
export const CANONICAL_FIELD_PREFIX = "__mdu_field_";
const FIELD_START_RE = /^[a-zA-Z_]/;
const NON_FIELD_CHARACTER_RE = /[^a-zA-Z0-9_[\].]/;

/** A scanner-complete, injective wire representation of an original field.
 * Fixed-width UTF-16 preserves every JS string (including lone surrogates).
 * Encode the reserved namespace itself so literal names cannot forge another
 * field's representation. This function intentionally is not idempotent:
 * callers supply ORIGINAL metadata, never a previously encoded token suffix. */
export function canonicalSymbolField(field: string): string {
  if (FIELD_START_RE.test(field) && !NON_FIELD_CHARACTER_RE.test(field) && !field.startsWith(CANONICAL_FIELD_PREFIX)) return field;
  const units: string[] = [];
  for (let index = 0; index < field.length; index++) units.push(field.charCodeAt(index).toString(16).padStart(4, "0"));
  return CANONICAL_FIELD_PREFIX + units.join("");
}

/** Aliases applied AFTER shortening, for tags that are still verbose. */
const TOOL_TAG_ALIASES: Record<string, string> = {
  // inspect-mcp's re-symbolized U-LLM output AND the proxy-wrapped MCP
  // tool_result both collapse to the same readable tag.
  inspect_symbol: "inspect",
};

/** Hard cap on the tool tag embedded in a symbol name. */
const MAX_TOOL_TAG = 24;

/**
 * The short, grammar-safe tool tag embedded in a generated symbol NAME.
 * The FULL tool name is provenance and stays in the symbol table's `tool`
 * column (and on every emitted SymbolRef) — only the display tag shortens.
 *
 * Two jobs:
 *  1. SHORTEN: Claude Code reports MCP tools as `mcp__<server>__<tool>`
 *     (e.g. `mcp__mandu-inspect__inspect_symbol`), which made symbol names
 *     unreadable. Only the tool segment carries signal in the name.
 *  2. SANITIZE (security): the symbol grammar is
 *     `$MDU:[a-zA-Z_][a-zA-Z0-9_]*[<hash>]` — any other character (the
 *     `-` in an MCP server name) makes the minted name UNMATCHABLE by
 *     getSymbolPattern(), i.e. invisible to hasSymbols/resolveAllSymbols and
 *     therefore never desymbolized at egress. Every char outside the grammar
 *     is mapped to `_`.
 *
 * Idempotent: shortToolTag(shortToolTag(t)) === shortToolTag(t) — derived
 * allocation paths that re-derive the tool from an existing symbol name (e.g.
 * fs-sync human-edit splits) stay stable. NOTE `inspect` must therefore not
 * alias onward.
 */
/** The confidentiality wire markers a tool tag may not start with. */
export const MARKER_PREFIX_RE = /^(?:nomodel|anymodel|localmodel)_/;

export function shortToolTag(tool: string): string {
  // MCP tools: keep only the trailing tool segment; the server part is
  // provenance, preserved in the symbol table's `tool` column.
  let tag = tool.startsWith("mcp__")
    ? tool.split("__").filter(Boolean).pop() ?? tool
    : tool;
  tag = tag.replace(/[^a-zA-Z0-9_]/g, "_");
  if (!/^[a-zA-Z_]/.test(tag)) tag = `t_${tag}`;
  tag = TOOL_TAG_ALIASES[tag] ?? tag;
  // Reserved confidentiality wire markers (confidentiality.md §2): a real
  // tool whose tag would start with one must not forge a level marker.
  // The pre-rename markers (`sec_`, `secm_`) mean nothing any more and are not
  // reserved. Idempotent: "t_nomodel_x" does not re-match. Truncation below
  // cannot CREATE a prefix, so reserving before the cap is safe.
  if (MARKER_PREFIX_RE.test(tag)) tag = `t_${tag}`;
  if (tag.length > MAX_TOOL_TAG) tag = tag.slice(0, MAX_TOOL_TAG).replace(/_+$/, "") || "tool";
  return tag;
}

export const MDU_SYM_FORMAT: SymbolFormat = {
  name: "mdu_sym",
  prefix: "$MDU:",

  generate({ tool, hash, field, level }) {
    // Level marker INSIDE the tag grammar ([a-zA-Z_][a-zA-Z0-9_]*), so every
    // scanner copy in every package matches secret tokens unchanged
    // (confidentiality.md §2). Presentation only — decisions read the table.
    const marker =
      level === "no-model" ? "nomodel_" :
      level === "local-model" ? "localmodel_" :
      level === "any-model" ? "anymodel_" : "";
    const base = `$MDU:${marker}${shortToolTag(tool)}[${hash}]`;
    return field == null ? base : `${base}.${canonicalSymbolField(field)}`;
  },

  pattern: /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*|\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g,

  extractHash(symbol: string): string | null {
    const m = symbol.match(HASH_RE);
    return m ? m[1] : null;
  },

  extractFieldPath(symbol: string): string {
    return symbol.replace(FIELD_PATH_RE, "");
  },
};

/**
 * Candidate NAMES a token-shaped string may refer to, most-specific first.
 *
 * Models hand back real tokens with glue or mutations the table has never
 * minted (both seen live, 2026-07-16):
 *   - a trailing dot-run: sentence punctuation the scanner grammar swallows,
 *     because field segments may legitimately contain dots
 *     (`…inspect[0e09].result.` at the end of a sentence);
 *   - an INVENTED extra field suffix on a real token
 *     (`$MDU:Read[6819].content` for the real `$MDU:Read[6819]`).
 *
 * The walk: the exact token; the token minus its trailing dot-run; then
 * progressively shorter field paths, down to (and including) the
 * `$MDU:tool[hash]` base. Pure grammar — callers probe the table with each
 * candidate in order, so an exact (more specific) name always wins over a
 * stripped one, and a genuinely unknown token simply matches nothing.
 *
 * EVERY candidate is a string prefix of the input token — callers rely on
 * this to re-attach what the match consumed beyond the resolved name (the
 * sentence punctuation), see resolveAllSymbols.
 */
export function symbolNameCandidates(token: string): string[] {
  const out: string[] = [token];
  const push = (s: string): void => {
    if (!out.includes(s)) out.push(s);
  };
  const trimmed = token.replace(/\.+$/, "");
  if (trimmed !== "") push(trimmed);
  const m = /^(\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\])(.*)$/.exec(trimmed);
  if (!m) return out;
  const base = m[1]!;
  let path = m[2]!;
  while (path.length > 0) {
    const cut = path.lastIndexOf(".");
    if (cut < 0) break;
    path = path.slice(0, cut);
    push(base + path);
  }
  return out;
}

/** A grammar-COMPLETE token (base or base+field path), anchored — the shape a
 *  streaming boundary can legally strand (never a mid-hash fragment). Gates
 *  the alias tier in findByCandidates. */
const COMPLETE_NAME_RE =
  /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*$/;

/**
 * The ONE allocated name that EXTENDS a token the candidate walk missed — the
 * reverse direction of symbolNameCandidates, bounded to be guess-free.
 *
 * Why it exists (third live hit 2026-07-19, pipeline 6420
 * interactive-inspect-extract; earlier 1783831380-3877123 and pipeline 6414):
 * models stream a token's base and its `.field` tail in SEPARATE deltas (a
 * natural BPE/SSE boundary), and a TUI frame interposed between them hands
 * every downstream scanner the BARE BASE — `$MDU:inspect[c72f]` — a name the
 * table never minted (inspect-mcp allocates `…[c72f].result`; the shortening
 * walk above cannot help, it only ever strips). The base then resolved to
 * nothing and the human terminal showed a raw token for the whole session.
 *
 * The rule: the token (trailing sentence-dots trimmed) must be
 * grammar-complete and must extend to allocated names ONLY at a `.` field
 * boundary. One extension → that name. A FAMILY of extensions where the
 * shortest is an ancestor every other one extends (the human-edit
 * `.__mdu_split[n]` shape) → the ancestor: its value is exactly what the full
 * token resolves to. Genuine sibling ambiguity (`.stdout` vs `.stderr`) →
 * null: never guess between different values. Mid-segment prefixes
 * (`…[ab].res` for `…[ab].result`) never match — the boundary check refuses.
 */
export function uniqueFieldExtension(token: string, names: Iterable<string>): string | null {
  const t = token.replace(/\.+$/, "");
  if (!COMPLETE_NAME_RE.test(t)) return null;
  const exts: string[] = [];
  for (const n of names) {
    if (n.length > t.length && n.startsWith(t) && n[t.length] === ".") exts.push(n);
  }
  if (exts.length === 0) return null;
  exts.sort((a, b) => a.length - b.length);
  const head = exts[0]!;
  const headIsAncestor = exts.every(
    (n) => n === head || (n.startsWith(head) && n[head.length] === "."),
  );
  return headIsAncestor ? head : null;
}

/**
 * Probe `get` with each candidate of `token` (symbolNameCandidates order) and
 * return the first hit with the name that produced it. The one lookup walk
 * behind EVERY name→entry read — the data-usage gate's lookup and the
 * resolution paths must stay in lockstep, or a mutated token could be
 * "unknown" to the decision yet resolvable on the surface it gates.
 *
 * `names` (an enumerator thunk over ALL allocated names) arms the ALIAS TIER:
 * after every shortening candidate misses, a token that extends to exactly one
 * allocated name at a field boundary resolves as that name
 * (uniqueFieldExtension — the base↔field SSE-seam recovery). Lockstep applies
 * to this tier too: every walk over the same table must pass its enumerator,
 * or a stranded base would be "unknown" to one gate yet resolvable on another
 * surface. NOTE the returned `name` is then LONGER than the token — leftover
 * slicing (`token.slice(name.length)`) yields "" by construction, so a glued
 * sentence dot after an aliased base is dropped rather than re-attached
 * (accepted: the alias fires on mid-stream fragments, not prose).
 */
export function findByCandidates<T>(
  token: string,
  get: (name: string) => T | undefined,
  names?: () => Iterable<string>,
): { name: string; hit: T } | null {
  for (const name of symbolNameCandidates(token)) {
    const hit = get(name);
    if (hit !== undefined) return { name, hit };
  }
  if (names) {
    const ext = uniqueFieldExtension(token, names());
    if (ext !== null) {
      const hit = get(ext);
      if (hit !== undefined) return { name: ext, hit };
    }
  }
  return null;
}

/**
 * PRESENTATION-ONLY level parse of a symbol NAME — for the handling prompt,
 * dashboard badges, and humans. Every DECISION reads the symbol-table row
 * (confidentiality.md §2: the table is authoritative). No marker is a
 * prefix of another, so the order of the tests does not matter.
 */
export function levelFromSymbolName(name: string): ConfidentialityLevel {
  if (name.startsWith("$MDU:nomodel_")) return "no-model";
  if (name.startsWith("$MDU:localmodel_")) return "local-model";
  if (name.startsWith("$MDU:anymodel_")) return "any-model";
  return "public";
}

// ─────────────────────────────────────────────────────────────────────────────
// LLM escape normalization
// ─────────────────────────────────────────────────────────────────────────────

/**
 * LLMs sometimes Markdown-escape symbol tokens: the leading `$` becomes `\$`,
 * and any underscore in the tool tag or field path (e.g. `web_fetch`,
 * `.text.most_mentioned`) becomes `\_`. The `$MDU:` prefix itself has no
 * underscores, so — unlike the old `$_ADFI_SYM_` prefix — the escape surface
 * is now just the leading `$` and the token tail. This regex matches an
 * optionally-escaped token so unescapeSymbols() can strip the backslashes
 * before downstream symbol resolution runs.
 *
 * The field-accessor tail also has to consume `\_` because models escape
 * underscores anywhere, not just adjacent to the prefix (#260): a token like
 * `.text.most\_mentioned` would otherwise match only up to `.text.most`,
 * leaving `\_mentioned` un-normalized and breaking symbol-table lookup (the
 * registered name has no backslash).
 *
 * Applied to any string before symbol pattern matching.
 */
const ESCAPED_SYM_RE = /\\?\$MDU:(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9])*\[[0-9a-f]{4,8}\](?:\.(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9[\].])*)*/g;

/**
 * Strip Markdown backslash escapes from symbol tokens in a string.
 * Turns `\$MDU:web\_fetch[a1b2]` back into `$MDU:web_fetch[a1b2]`.
 * Only touches sequences that look like Mandu symbols — leaves other text alone.
 */
export function unescapeSymbols(text: string): string {
  ESCAPED_SYM_RE.lastIndex = 0;
  return text.replace(ESCAPED_SYM_RE, (match) => match.replace(/\\/g, ""));
}

// ─────────────────────────────────────────────────────────────────────────────
// Active format (module-level singleton, swappable at init time)
// ─────────────────────────────────────────────────────────────────────────────

let activeFormat: SymbolFormat = MDU_SYM_FORMAT;

export function getActiveFormat(): SymbolFormat {
  return activeFormat;
}

export function setActiveFormat(format: SymbolFormat): void {
  activeFormat = format;
}
