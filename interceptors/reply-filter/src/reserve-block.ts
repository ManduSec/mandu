/**
 * reserve-block — the reserve-block grammar, the reply filter's side: a pure
 * recognizer for the N-row placeholder the proxy sends Claude Code in place of
 * a multi-line token that stands alone on its line, plus the per-row text the
 * filter paints into each reserved row.
 *
 * Mandu user-reply egress chokepoint (interceptors/reply-filter).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE (CONTRIBUTING.md reuse policy)
 *   Mandu-new (no reference origin: the OpenClaw hook resolves a message
 *   object, it never lays out rows). This module MIRRORS the emitter in
 *     interceptors/anthropic-proxy/src/reserve-block.ts
 *   (the proxy expands and collapses blocks; the filter only recognizes and
 *   paints them). The two packages are independent roots, so the grammar is
 *   kept as a local copy; any change to it changes BOTH files in the same
 *   change. Design: docs/design/ui/reply-row-reservation.md §3.1 (grammar),
 *   §3.2 (the cap), §3.7 (painting), §7.1 (phase 0: the byte shapes), §11
 *   (v2: wrapped rows, a block inside a line). The v2 row layout is the
 *   shared module ./reserve-layout.ts (copied verbatim to the arbiter and
 *   the proxy).
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * THE GRAMMAR (§3.1). A token T = `$MDU:<tag>[<hash>]<.field…>` (the filter's
 * SYMBOL_TOKEN_RE) whose value has N ≥ 2 lines (one trailing newline dropped)
 * becomes exactly N lines:
 *
 *     T/1:N                head row: the token verbatim, then `/1:N`
 *     $MDU/<hash>/2        continuation row i, 2 ≤ i ≤ N
 *     …
 *     $MDU/<hash>/N
 *
 *   - 2 ≤ N ≤ 200 (RESERVE_ROWS_LIMIT); the proxy caps N at RESERVE_MAX_ROWS
 *     (default 40, MANDU_REPLY_RESERVE_MAX, clamped to 2..200). When the value
 *     has more lines than N, row N shows `… +K more lines (full value: mandu
 *     dashboard)` with K = lines − (N − 1). The filter reads N from the head,
 *     never from its own env, so a filter and a proxy with different caps
 *     still agree on every row.
 *   - A continuation row carries no `:`, so it never matches the token grammar
 *     or the filter's candidate-prefix hold.
 *   - Claude Code renders a Markdown-escaped head (`\$MDU:x\_y[…]`) unescaped;
 *     the recognizer accepts both spellings anyway (pipe mode sees raw text).
 *
 * V2 (§11.3): the head may be `T/1:N:W:F`, N ROWS of layoutRows(value, W, F)
 * (reserve-layout.ts: Ink's word wrap at content width W, the head row F
 * columns wide, F = 0 meaning the value starts on the row after the head).
 * W is 20..1000, F is 0 or ⌈W/2⌉..W. A v2 block may sit inside a line: text
 * before the head on its row, text (starting with a non-digit) after the last
 * row's marker. The v2 form is tried BEFORE v1 (v1's pattern would take the
 * `/1:5` of `/1:5:78:40`), and a v2-SHAPED suffix (`/1:N:` then a digit)
 * whose numbers are out of range is no head at all, never a v1 head.
 *
 * SECURITY POSTURE: a block carries a token and a line count, never an
 * original. This module renders values only for the human's terminal
 * (HumanView); it performs no IO.
 */

import type { SessionRelay } from "./arbiter-client.js";
import { layoutRows, linesNotShown, type LayoutRow, type LayoutRule } from "./reserve-layout.js";

/** The symbol-token grammar, both spellings (canonical and Markdown-escaped).
 *  MUST equal filter.ts SYMBOL_TOKEN_RE.source (a unit test pins the parity;
 *  kept here, not imported, so this module has no dependency on the stream
 *  filter and the proxy's copy can be diffed against it line for line). */
export const TOKEN_SOURCE =
  "\\\\?\\$MDU:(?:\\\\?_|[a-zA-Z])(?:\\\\?_|[a-zA-Z0-9])*\\[[0-9a-f]{4,8}\\](?:\\.(?:\\\\?_|[a-zA-Z])(?:\\\\?_|[a-zA-Z0-9[\\].])*)*";

/** Smallest N a head can carry (a one-line value is never expanded). */
export const RESERVE_ROWS_MIN = 2;
/** Largest N the grammar admits, whatever the configured cap. */
export const RESERVE_ROWS_LIMIT = 200;
/** Default cap on reserved rows (§3.2 item 6, decision D2). */
export const RESERVE_MAX_ROWS_DEFAULT = 40;

/** The configured cap: MANDU_REPLY_RESERVE_MAX when it is an integer in
 *  2..200, else the default 40 (mirrors the proxy). */
export function reserveMaxRows(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env["MANDU_REPLY_RESERVE_MAX"];
  if (raw === undefined || !/^[0-9]{1,3}$/.test(raw.trim())) return RESERVE_MAX_ROWS_DEFAULT;
  const n = parseInt(raw.trim(), 10);
  return n >= RESERVE_ROWS_MIN && n <= RESERVE_ROWS_LIMIT ? n : RESERVE_MAX_ROWS_DEFAULT;
}

/** The kill switch (§3.2): MANDU_REPLY_RESERVE=0 disables reservation. The
 *  filter then reports `reserve: false` so the proxy never expands; blocks
 *  that arrive anyway are still recognized and painted. */
export function reserveEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env["MANDU_REPLY_RESERVE"] !== "0";
}

/** The variable the launcher sets for an agent whose TUI prints its reply raw
 *  at column 0 and leaves the wrap to the terminal (§17: Goose). The filter
 *  reads it, reports the rule, and paints by it; the agent never sees it
 *  (arbiter-client.ts childEnv). */
export const WRAP_RULE_ENV = "MANDU_REPLY_WRAP_RULE";

/** This session's wrap rule (§17): `terminal` when WRAP_RULE_ENV says so,
 *  else Ink's (every other agent, and anything malformed). */
export function wrapRule(env: NodeJS.ProcessEnv = process.env): LayoutRule {
  return env[WRAP_RULE_ENV]?.trim() === "terminal" ? "terminal" : "ink";
}

/** False when WRAP_RULE_ENV is `none`: the agent's TUI wraps its reply by a
 *  rule no layout here models (OpenCode breaks a word at its punctuation and
 *  lays the reply out narrower than Ink, differential-interactive.md §35), so
 *  the filter reports no `wrap` and the proxy sends only v1 heads, one row
 *  per value line for a token alone on its line (reply-row-reservation.md
 *  §11.4: a relay without `wrap` gets v1). A token inside a sentence then
 *  keeps the one-row splice. */
export function wrapLayoutKnown(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[WRAP_RULE_ENV]?.trim() !== "none";
}

/** The `setSessionRelay` report for this session (reply-row-reservation.md
 *  §3.6, §11.5): `reserve` is true only for the PTY relay, and only while the
 *  kill switch is off; `wrap: true` rides with `reserve` (this filter paints
 *  v2 heads, §11.3) unless the agent's wrap is unmodelled (`none`,
 *  wrapLayoutKnown), and with it `rule: "terminal"` when the agent's TUI
 *  leaves the wrap to the terminal (§17; absent means Ink's);
 *  `cols`/`rows` when known (v2's W derives from `cols`).
 *  run.ts sends it over the HUMAN-plane client only (§11.5: the data socket
 *  refuses the op). */
export function sessionRelay(
  sessionKey: string,
  mode: SessionRelay["mode"],
  size: { cols?: number | undefined; rows?: number | undefined } = {},
  env: NodeJS.ProcessEnv = process.env,
): SessionRelay {
  const reserve = mode === "pty" && reserveEnabled(env);
  return {
    sessionKey,
    mode,
    reserve,
    ...(reserve && wrapLayoutKnown(env) ? { wrap: true } : {}),
    ...(reserve && wrapRule(env) === "terminal" ? { rule: "terminal" as const } : {}),
    ...(typeof size.cols === "number" ? { cols: size.cols } : {}),
    ...(typeof size.rows === "number" ? { rows: size.rows } : {}),
  };
}

/** The v1 head suffix, anchored at the byte right after the token. N is
 *  decimal WITHOUT leading zeros, as the proxy emits and collapses it (its
 *  HEAD_LINE_RE): `/1:05` is not a head on either side. */
const HEAD_SUFFIX_RE = /^\/1:([1-9][0-9]{0,2})(?![0-9])/;
/** A v2-SHAPED suffix: `/1:N:` followed by a digit. Such a suffix is parsed
 *  as v2 or not at all (never as the v1 head `/1:N` beside a stray `:W:F`). */
const HEAD_V2_SHAPE_RE = /^\/1:[0-9]+:[0-9]/;
/** The v2 head suffix `/1:N:W:F` (§11.3), optionally with the break field
 *  `:K` (§14: the proxy inserted a line break K characters after the block,
 *  which the TUI lays out; nothing for the filter to paint): no leading zeros
 *  (F may be `0`), followed by neither a digit nor a `:`. The ranges are
 *  checked in parseHeadSuffix. */
const HEAD_V2_SUFFIX_RE = /^\/1:([1-9][0-9]{0,2}):([1-9][0-9]{1,3}):(0|[1-9][0-9]{0,3})(?::([1-9][0-9]{0,3}))?(?![0-9:])/;
/** Longest head suffix (`/1:200:1000:1000:9999`) plus the byte that must
 *  follow it: how far past a token a caller slices before parseHeadSuffix. */
export const HEAD_SUFFIX_MAX = 22;
/** Smallest and largest content width W of a v2 head (§11.3). */
export const RESERVE_WIDTH_MIN = 20;
export const RESERVE_WIDTH_MAX = 1000;

/** True when (W, F) is a legal v2 layout: W in 20..1000, F 0 or ⌈W/2⌉..W. */
export function validWidths(w: number, f: number): boolean {
  if (!Number.isInteger(w) || !Number.isInteger(f)) return false;
  if (w < RESERVE_WIDTH_MIN || w > RESERVE_WIDTH_MAX) return false;
  return f === 0 || (f >= Math.ceil(w / 2) && f <= w);
}

/** A parsed head suffix: N, its length, and for a v2 head W and F. */
export interface HeadSuffix {
  n: number;
  length: number;
  /** v2 only: the content width. Undefined for a v1 head. */
  w?: number | undefined;
  /** v2 only: the head row's width (0: the value starts on the next row). */
  f?: number | undefined;
  /** v2 only, §14: the break the proxy inserted after the block. */
  k?: number | undefined;
}
/** A continuation row marker (global; reset lastIndex before reuse). The
 *  index has no leading zero, as the proxy's ROW_LINE_RE requires. */
export const CONT_RE = /\$MDU\/([0-9a-f]{4,8})\/([1-9][0-9]{0,2})(?![0-9])/g;
/** The literal anchor every continuation row starts with (fast pre-check). */
export const CONT_ANCHOR = "$MDU/";

/** Parse a head suffix at the start of `s` (the text right after a token):
 *  v2 (`/1:N:W:F`) first, then v1 (`/1:N`). Null when absent, when N is out
 *  of 2..200, or when a v2-shaped suffix is malformed or out of range (no v1
 *  fallback: see HEAD_V2_SHAPE_RE). */
export function parseHeadSuffix(s: string): HeadSuffix | null {
  if (HEAD_V2_SHAPE_RE.test(s)) {
    const v2 = HEAD_V2_SUFFIX_RE.exec(s);
    if (!v2) return null;
    const n = parseInt(v2[1]!, 10);
    const w = parseInt(v2[2]!, 10);
    const f = parseInt(v2[3]!, 10);
    // N = 1 only as a head-only block with a break (§14).
    const nOk = n >= RESERVE_ROWS_MIN || (n === 1 && v2[4] !== undefined);
    if (!nOk || n > RESERVE_ROWS_LIMIT || !validWidths(w, f)) return null;
    return { n, length: v2[0].length, w, f, ...(v2[4] !== undefined ? { k: parseInt(v2[4], 10) } : {}) };
  }
  const m = HEAD_SUFFIX_RE.exec(s);
  if (!m) return null;
  const n = parseInt(m[1]!, 10);
  if (n < RESERVE_ROWS_MIN || n > RESERVE_ROWS_LIMIT) return null;
  return { n, length: m[0].length };
}

/** The hash (hex inside `[…]`) of a token, or "" when it has none. */
export function tokenHash(token: string): string {
  const m = /\[([0-9a-f]{4,8})\]/.exec(token);
  return m ? m[1]! : "";
}

export interface HeadMatch {
  /** Offset of the head in the scanned text. */
  index: number;
  /** Length of the head (token spelling as written + `/1:N`). */
  length: number;
  /** The token with its Markdown escapes stripped. */
  canonical: string;
  hash: string;
  n: number;
  /** v2 only (`T/1:N:W:F`): the content width and the head row's width. */
  w?: number | undefined;
  f?: number | undefined;
}

export interface ContMatch {
  index: number;
  length: number;
  hash: string;
  /** The row index i (2 ≤ i ≤ 200). */
  i: number;
}

/** Every head row marker `T/1:N` in `text` (either spelling of T). */
export function findHeads(text: string): HeadMatch[] {
  const out: HeadMatch[] = [];
  if (!text.includes("$MDU:")) return out;
  const re = new RegExp(TOKEN_SOURCE, "g");
  for (const m of text.matchAll(re)) {
    const end = m.index + m[0].length;
    const suffix = parseHeadSuffix(text.slice(end, end + HEAD_SUFFIX_MAX));
    if (!suffix) continue;
    const canonical = m[0].replace(/\\/g, "");
    out.push({
      index: m.index,
      length: m[0].length + suffix.length,
      canonical,
      hash: tokenHash(canonical),
      n: suffix.n,
      ...(suffix.w !== undefined ? { w: suffix.w, f: suffix.f } : {}),
    });
  }
  return out;
}

/** Every continuation row marker `$MDU/<hash>/<i>` in `text`, 2 ≤ i ≤ 200. */
export function findContinuations(text: string): ContMatch[] {
  const out: ContMatch[] = [];
  if (!text.includes(CONT_ANCHOR)) return out;
  CONT_RE.lastIndex = 0;
  for (const m of text.matchAll(CONT_RE)) {
    const i = parseInt(m[2]!, 10);
    if (i < RESERVE_ROWS_MIN || i > RESERVE_ROWS_LIMIT) continue;
    out.push({ index: m.index, length: m[0].length, hash: m[1]!, i });
  }
  return out;
}

/** A value's lines as the proxy counts them: one trailing newline dropped,
 *  then split on LF (a CR before the LF goes with it). */
export function valueLines(value: string): string[] {
  return value.replace(/\r?\n$/, "").split(/\r?\n/);
}

/** The cap row's note for K lines the reservation could not hold. */
export function moreLinesNote(k: number): string {
  return `… +${k} more lines (full value: mandu dashboard)`;
}

/** The text for reserved row `i` (1-based) of an N-row block over `lines`:
 *  line i; on row N of a capped block the `+K more lines` note; a row past
 *  the value's end (never produced by a well-formed block) is empty. */
export function reserveRowText(lines: readonly string[], i: number, n: number): string {
  if (lines.length > n && i === n) return moreLinesNote(lines.length - (n - 1));
  return lines[i - 1] ?? "";
}

/** What a head announced about its block: N, and for a v2 head W and F. */
export interface HeadShape {
  n: number;
  w?: number | undefined;
  f?: number | undefined;
  /** The terminal's columns when the filter first saw this block (§13): the
   *  width W was laid out for. Absent: unknown, never re-laid out. */
  cols?: number | undefined;
  /** The wrap rule the block's rows are laid out by (§17): the session's,
   *  stamped by the cache. Absent: `ink`. */
  rule?: LayoutRule | undefined;
}

/**
 * The (W, F) a v2 block paints with at the terminal's current width
 * (reply-row-reservation.md §13). The TUI re-lays its transcript out after a
 * resize, and each reserved row stays one row (a marker is one short word),
 * but the rows now start where they did and end `delta` columns sooner:
 *   - the same width or wider: the block's own (W, F). Its rows still fit;
 *     vanilla would join some of them, and N rows cannot shrink.
 *   - narrower by d: W − d, and F − d on the head's row (F = 0 stays 0; a
 *     head row left under half of W − d goes blank, as the proxy's clamp).
 *     A value that no longer fits in N rows shows the cap note on row N.
 *     Below the grammar's minimum width the block keeps its layout (clips).
 * F − d assumes the text before the head keeps its last row. A prefix that
 * wraps anew can push the head right, and the head row then clips at the
 * edge, as every row did before this rule.
 * Null for a v1 head (one row per value line: the width never entered it).
 */
export function paintLayout(head: HeadShape, colsNow?: number | null): { w: number; f: number } | null {
  if (head.w === undefined) return null;
  const w = head.w;
  const f = head.f ?? head.w;
  if (head.cols === undefined || typeof colsNow !== "number" || !Number.isInteger(colsNow)) return { w, f };
  const d = head.cols - colsNow;
  if (d <= 0 || w - d < RESERVE_WIDTH_MIN) return { w, f };
  const w2 = w - d;
  const f2 = f === 0 ? 0 : f - d;
  return { w: w2, f: f2 >= Math.ceil(w2 / 2) ? f2 : 0 };
}

/** A few recent layouts (a block's rows are painted one splice at a time,
 *  and each repaint asks again): keyed by the value (the cache hands out the
 *  same string, so the comparison is cheap) and (W, F, indent). */
const LAYOUT_MEMO_MAX = 8;
const layoutMemo: Array<{ value: string; w: number; f: number; rule: LayoutRule; indent: number; rows: LayoutRow[] }> = [];

/** layoutRows(value, w, f, rule, indent), memoized over the last few blocks. */
export function blockLayout(value: string, w: number, f: number, rule: LayoutRule = "ink", indent = 0): readonly LayoutRow[] {
  for (const e of layoutMemo) {
    if (e.w === w && e.f === f && e.rule === rule && e.indent === indent && e.value === value) return e.rows;
  }
  const rows = layoutRows(value, w, f, rule, indent);
  layoutMemo.unshift({ value, w, f, rule, indent, rows });
  if (layoutMemo.length > LAYOUT_MEMO_MAX) layoutMemo.pop();
  return rows;
}

/**
 * The terminal column a v2 block's content area starts at (§11.2, the TAB
 * stops): the width the block was first seen at minus its W, which is the
 * proxy's `cols − W` (the content indent, plus a list item's). A resize
 * keeps it: the rows start where they did (paintLayout). 0 for a v1 head or
 * an unknown width (TAB stops then count from each line's own start).
 */
export function blockIndent(head: HeadShape): number {
  if (head.w === undefined || head.cols === undefined) return 0;
  return Math.max(0, head.cols - head.w);
}

/**
 * The text for reserved row `i` (1-based) of the block a head announced:
 *   - v1 (`T/1:N`): line i of the value, the cap note on row N of a capped
 *     block (reserveRowText, unchanged);
 *   - v2 (`T/1:N:W:F`, §11.2): row i of layoutRows(value, W, F), already
 *     cleaned (no TAB, no escape: the writers' frame-safe pass is a no-op on
 *     it). When the layout has more rows than N, row N is the cap note, K =
 *     the lines not shown in full on rows 1..N−1. With F = 0 the head row
 *     (row 1) is "" (painted blank at the marker's width).
 *   - `colsNow`, the terminal's current columns: a v2 block on a terminal
 *     narrower than when its head was first seen is laid out anew
 *     (paintLayout, §13).
 *   - a TAB reaches the terminal's tab stop, counted from the content
 *     area's column (blockIndent), as the arbiter counted the rows.
 */
export function blockRowText(value: string, i: number, head: HeadShape, colsNow?: number | null): string {
  const at = paintLayout(head, colsNow);
  if (at === null) return reserveRowText(valueLines(value), i, head.n);
  const rows = blockLayout(value, at.w, at.f, head.rule ?? "ink", blockIndent(head));
  if (rows.length > head.n && i === head.n) return moreLinesNote(linesNotShown(rows, head.n - 1));
  return rows[i - 1]?.text ?? "";
}

/** The head row when the value is unknown (arbiter down, unknown token):
 *  the token and a line-count note in place of `/1:N` (§3.7). Nothing can
 *  leak: there is no value to show. */
export function unknownHeadText(canonical: string, n: number): string {
  return `${canonical} (${n} lines)`;
}

/** The block text the proxy emits for `token` over a value of `lineCount`
 *  lines under `cap` (the mirror of the proxy's expander, used by tests and
 *  kept here so the grammar lives in one file per package). */
export function formatBlock(token: string, lineCount: number, cap: number = RESERVE_MAX_ROWS_DEFAULT): string {
  const n = Math.min(lineCount, cap);
  const hash = tokenHash(token.replace(/\\/g, ""));
  const rows = [`${token}/1:${n}`];
  for (let i = 2; i <= n; i++) rows.push(`$MDU/${hash}/${i}`);
  return rows.join("\n");
}

/** The v2 block (§11.3) for `token` over `value` laid out at (W, F): N =
 *  min(rows, cap). Test mirror of the proxy's v2 expander. */
export function formatBlockV2(
  token: string, value: string, w: number, f: number, cap: number = RESERVE_MAX_ROWS_DEFAULT, rule: LayoutRule = "ink",
): string {
  const n = Math.min(layoutRows(value, w, f, rule).length, cap);
  const hash = tokenHash(token.replace(/\\/g, ""));
  const rows = [`${token}/1:${n}:${w}:${f}`];
  for (let i = 2; i <= n; i++) rows.push(`$MDU/${hash}/${i}`);
  return rows.join("\n");
}

/** Bound on each cache map (the reconciler's CACHE_MAX pattern). */
export const RESERVE_CACHE_MAX = 2048;

/**
 * The session's reserve-block memory, shared by the stream filter and the
 * screen reconciler (one instance per session, run.ts):
 *   - token → value, for heads (values are immutable, so a hit never goes
 *     stale; unknown tokens are NOT cached — the arbiter may learn them);
 *   - hash → the last head seen with that hash (its token and N), which is
 *     how a continuation row, which carries only the hash, finds its value;
 *   - the heads already reported to observability (one event per value).
 * Bounded: the oldest entry is forgotten past RESERVE_CACHE_MAX. Two heads
 * with the same hash but different field paths share continuation rows; the
 * last one seen wins (accepted: both are the same symbol's fields).
 */
export class ReserveValueCache {
  private readonly values = new Map<string, string>();
  private readonly heads = new Map<string, { canonical: string } & HeadShape>();
  private readonly reported = new Set<string>();

  /** `rule`: the session's wrap rule (§17, run.ts wrapRule), stamped on every
   *  head so a block's rows are painted by the rule the proxy counted them
   *  by. */
  constructor(private readonly max = RESERVE_CACHE_MAX, readonly rule: LayoutRule = "ink") {}

  /** True once any head was seen this session (the main-screen reconcile
   *  gate: no block, no scan). */
  get hasHeads(): boolean {
    return this.heads.size > 0;
  }

  getValue(canonical: string): string | undefined {
    return this.values.get(canonical);
  }

  setValue(canonical: string, value: string): void {
    this.bounded(this.values, canonical, value);
  }

  /** Record a head: its token, N, and for a v2 head W and F (undefined for
   *  v1), so a continuation row lays out the same block; `cols`, the
   *  terminal's width now. The width of the FIRST sighting of a block is
   *  kept: a repaint after a resize re-notes the same head (§13). */
  noteHead(hash: string, canonical: string, n: number, w?: number, f?: number, cols?: number | null): void {
    if (hash === "") return;
    const prev = this.heads.get(hash);
    const fNow = w !== undefined ? (f ?? w) : undefined;
    const same = prev !== undefined && prev.canonical === canonical && prev.n === n && prev.w === w && prev.f === fNow;
    const width = same ? prev.cols : typeof cols === "number" && Number.isInteger(cols) && cols > 0 ? cols : undefined;
    this.bounded(this.heads, hash, {
      canonical, n,
      ...(w !== undefined ? { w, f: fNow } : {}),
      ...(width !== undefined ? { cols: width } : {}),
      ...(this.rule !== "ink" ? { rule: this.rule } : {}),
    });
  }

  /** The head last seen for `hash`: its token, N, W and F (undefined for a
   *  v1 head), the width it was first seen at, and value (null while the
   *  value is unknown). Undefined when no head with that hash was seen. */
  headFor(hash: string): ({ canonical: string; value: string | null } & HeadShape) | undefined {
    const h = this.heads.get(hash);
    if (!h) return undefined;
    return { ...h, value: this.values.get(h.canonical) ?? null };
  }

  /** True the FIRST time a head's value is reported (observability: one
   *  record per value, not one per row or repaint). */
  firstReport(canonical: string): boolean {
    if (this.reported.has(canonical)) return false;
    if (this.reported.size >= this.max) {
      const oldest = this.reported.values().next().value;
      if (oldest !== undefined) this.reported.delete(oldest);
    }
    this.reported.add(canonical);
    return true;
  }

  private bounded<V>(map: Map<string, V>, k: string, v: V): void {
    if (!map.has(k) && map.size >= this.max) {
      const oldest = map.keys().next().value;
      if (oldest !== undefined) map.delete(oldest);
    }
    map.delete(k); // re-insert: most recent last
    map.set(k, v);
  }
}
