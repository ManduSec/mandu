/**
 * reserve-block — the reply row reservation grammar: expand a `$MDU:` token
 * that stands alone on its line into an N-row reserve block, collapse a
 * well-formed block back to its token, and strip every leftover fragment.
 *
 * Mandu Track A (interceptors/anthropic-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §3.1 (the block), §3.2 item 4 (which
 * tokens stand alone), §3.4 (collapse and residual strip), §5 (why the strip
 * is the fail-closed choice), §11.3 (the v2 head and mid-line blocks).
 *
 * ONE MODULE, TWO COPIES: copied VERBATIM to interceptors/openai-proxy/src/
 * (Codex, reply-row-reservation.md §11.7), with reserve-context.ts; this is
 * the master, and tests/stack/reserve-layout-parity.test.ts
 * holds the copies equal.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (2026-09-30). The token
 * grammar is a local copy of arbiter/symbol-table/symbol-format.ts
 * ESCAPED_SYM_RE (as interceptors/reply-filter/src/filter.ts SYMBOL_TOKEN_RE
 * copies it). The reply filter carries a matching recognizer; the two must
 * keep this grammar EXACTLY:
 *
 *   T      a token, canonical or Markdown-escaped, with an optional `.field`
 *          path. hash = the hex inside T's first `[...]`, backslashes removed.
 *   head   v1 `T/1:N`: one row per value line (fences; relays without wrap)
 *          v2 `T/1:N:W:F`: the value laid out by reserve-layout.ts
 *          layoutRows(value, W, F); W 20..1000 (the content width), F 0 or
 *          ⌈W/2⌉..W (the free width of the head's row; 0 = the value starts
 *          on the row after the head). N decimal without leading zeros,
 *          2 ≤ N ≤ RESERVE_MAX_LIMIT.
 *          v2 `T/1:N:W:F:K` (§14): the proxy inserted ONE `\n` into the
 *          model's text after the block, K ≥ 1 characters (UTF-16 units)
 *          after the last row, where the value's last row plus that text
 *          wraps on screen. Collapse removes it with the block. With a
 *          break, N may be 1: a head-only block (no rows) for a value that
 *          fits its row but pushes the text after it past the edge.
 *   row i  `$MDU/<hash>/<i>` for i = 2..N (no `:`, so it never matches T)
 *   block  head + for i in 2..N: sep + `$MDU/<hash>/<i>`, sep one of
 *          `\n`       the plain form
 *          `` `\n` `` the span form (§12): T stands in a code span, `` `T` ``,
 *                   and each row gets its own span, `` `T/1:N:W:F` `` then
 *                   `` `$MDU/<hash>/i` ``, the last row closed by the model's
 *                   own backtick (Claude Code joins the lines of ONE span)
 *   N      min(lines | rows, cap); cap = MANDU_REPLY_RESERVE_MAX (2..200,
 *          default 40)
 *
 * A v1 block stands alone on its lines. A v2 block may sit inside a line:
 * prefix text before the head on its line, suffix text after the last row on
 * its line (the suffix never starts with a digit; the expander's eligibility
 * guarantees it). So collapse is positional, not line-based: any
 * `T/1:N[:W:F]` immediately followed by exactly the N−1 rows and then not a
 * digit becomes T, wherever it stands.
 *
 * The property the prompt cache needs, pinned by the unit suite:
 * `collapseText(expand(t)) === t` byte for byte, for any `t` that holds no
 * reserve-block fragment of its own (the residual strip keeps the model from
 * ever writing one), where expand is expandText (v1) or applyExpansions (any
 * token occurrence not followed by a digit, v1 or v2 head).
 *
 * Pure string work: no I/O, never throws, no state.
 */

// ── constants ────────────────────────────────────────────────────────────────

/** The default row cap (D2). */
export const RESERVE_MAX_ROWS = 40;
/** The largest cap `MANDU_REPLY_RESERVE_MAX` may set; collapse accepts any N
 *  up to it, so a block expanded under a larger cap still collapses. */
export const RESERVE_MAX_LIMIT = 200;

/** Every token spelling (canonical or Markdown-escaped), global. */
const TOKEN_SRC =
  String.raw`\\?\$MDU:(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9])*\[[0-9a-f]{4,8}\](?:\.(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9[\].])*)*`;
/** A line that is exactly one token. */
const TOKEN_LINE_RE = new RegExp(`^${TOKEN_SRC}$`);
/** The span form's row separator: close the span, break, open the next. */
const SPAN_SEP = "`\n`";
/** A head (v1 or v2) directly followed by a row's start, anywhere: group 1 =
 *  T, group 2 = N. The rows themselves are checked by hand (collapse). */
const HEAD_ANY_SRC = `(${TOKEN_SRC})/1:([1-9][0-9]*)(?::[0-9]+:[0-9]+(?::([1-9][0-9]*))?)?(?=\\n\\$MDU/|${SPAN_SEP}\\$MDU/|(?<=:[0-9]+:[0-9]+:[1-9][0-9]*))`;
/** A head suffix directly after a token, anywhere (the strip): `/1:N`, plus
 *  up to three `:<digits>` fields (a v2 `:W:F`, its break `:K`, or a
 *  truncated one). */
const HEAD_SUFFIX_RE = new RegExp(`(${TOKEN_SRC})/1:[0-9]+(?::[0-9]+){0,3}`, "g");
/** The base hash inside a token (backslashes removed first). */
const HASH_RE = /\[([0-9a-f]{4,8})\]/;
/** Marker patterns for the strip. A marker directly after a line break goes
 *  with that break, whatever follows it on its line: a whole-line row, or the
 *  last row of a v2 block with suffix text (`pre T\n$MDU/h/2 tail` →
 *  `pre T tail`). */
const MARKER_AFTER_BREAK_RE = /\r?\n\$MDU\/[0-9a-f]{4,8}\/[0-9]+/g;
/** The span form's marker with its separator (`` `T`\n`$MDU/h/2` tail `` →
 *  `` `T` tail ``). Stripped before the plain form. */
const SPAN_MARKER_AFTER_BREAK_RE = /`\r?\n`\$MDU\/[0-9a-f]{4,8}\/[0-9]+/g;
const MARKER_LINE_START_RE = /^\$MDU\/[0-9a-f]{4,8}\/[0-9]+(?:\r?\n|$)/;
const MARKER_ANY_RE = /\$MDU\/[0-9a-f]{4,8}\/[0-9]+/g;

// ── small helpers ────────────────────────────────────────────────────────────

/** The canonical spelling of a token (Markdown escapes removed). */
export function canonicalToken(token: string): string {
  return token.replace(/\\/g, "");
}

/** The base hash of a token, or null when it has none. */
export function tokenHash(token: string): string | null {
  const m = HASH_RE.exec(canonicalToken(token));
  return m ? m[1]! : null;
}

/** The cap from `MANDU_REPLY_RESERVE_MAX`: an integer 2..200, else the
 *  default 40. */
export function parseReserveMax(raw: string | undefined): number {
  if (raw === undefined) return RESERVE_MAX_ROWS;
  const s = raw.trim();
  if (!/^[0-9]+$/.test(s)) return RESERVE_MAX_ROWS;
  const n = Number(s);
  return n >= 2 && n <= RESERVE_MAX_LIMIT ? n : RESERVE_MAX_ROWS;
}

/** Whether expansion is enabled: the kill switch `MANDU_REPLY_RESERVE=0`
 *  turns it off; anything else (or unset) leaves it on. */
export function reserveEnabled(raw: string | undefined): boolean {
  return raw?.trim() !== "0";
}

/** The v2 head's layout: the content width W and the head row's free
 *  width F (reply-row-reservation.md §11.3). */
export interface ReserveLayout {
  width: number;
  first: number;
}

/** W bounds (§11.3; the arbiter refuses anything else). */
export const RESERVE_MIN_WIDTH = 20;
export const RESERVE_MAX_WIDTH = 1000;

/** Whether (W, F) is a layout the grammar and the arbiter accept: W an
 *  integer 20..1000, F 0 or an integer ⌈W/2⌉..W. */
export function validLayout(width: number, first: number): boolean {
  if (!Number.isInteger(width) || width < RESERVE_MIN_WIDTH || width > RESERVE_MAX_WIDTH) return false;
  if (!Number.isInteger(first)) return false;
  return first === 0 || (first >= Math.ceil(width / 2) && first <= width);
}

/** The head row's suffix after T: `/1:N`, or `/1:N:W:F` with a layout,
 *  `/1:N:W:F:K` with a layout and a break (§14). */
export function reserveHeadSuffix(rows: number, layout?: ReserveLayout, brk?: number): string {
  if (!layout) return `/1:${rows}`;
  return `/1:${rows}:${layout.width}:${layout.first}` + (brk !== undefined ? `:${brk}` : "");
}

/** Whether K is a break the grammar carries: an integer ≥ 1. */
export function validBreak(brk: number | undefined): boolean {
  return brk === undefined || (Number.isInteger(brk) && brk >= 1);
}

/** One reserve block for token `token` (as written) and N rows: a v1 head
 *  without `layout`, a v2 head with it; `span`, the span form (the token
 *  stands between a code span's backticks, which stay the model's). */
export function reserveBlock(token: string, rows: number, layout?: ReserveLayout, span = false, brk?: number): string {
  const hash = tokenHash(token) ?? "";
  const sep = span ? SPAN_SEP : "\n";
  let out = token + reserveHeadSuffix(rows, layout, brk);
  for (let i = 2; i <= rows; i++) out += `${sep}$MDU/${hash}/${i}`;
  return out;
}

/** One token occurrence in a text (the v2 scanner). */
export interface TokenMatch {
  /** The token as written, field path included. */
  token: string;
  start: number;
  end: number;
}

/** Every token occurrence, left to right (greedy: a field path is part of
 *  its token, as in the reply filter's SYMBOL_TOKEN_RE). */
export function findTokens(text: string): TokenMatch[] {
  if (!text.includes("$MDU:")) return [];
  const out: TokenMatch[] = [];
  for (const m of text.matchAll(new RegExp(TOKEN_SRC, "g"))) {
    out.push({ token: m[0], start: m.index, end: m.index + m[0].length });
  }
  return out;
}

/** One expansion to apply: the token at [start, end) becomes its block. */
export interface TokenExpansion {
  start: number;
  end: number;
  /** The token as written (text.slice(start, end)). */
  token: string;
  rows: number;
  /** Absent: a v1 head. */
  layout?: ReserveLayout;
  /** The span form (§12). */
  span?: boolean;
  /** With a layout: insert `\n` this many characters after the token (§14).
   *  The text there must hold no line break, and the next expansion must
   *  start after it. */
  brk?: number;
}

/** Apply expansions (ascending, non-overlapping) to `text`. Expansion only
 *  ever appends the head suffix and the rows after T, so collapse restores
 *  the text exactly as long as no expanded token is followed by a digit. */
export function applyExpansions(text: string, exps: readonly TokenExpansion[]): string {
  if (exps.length === 0) return text;
  let out = "";
  let at = 0;
  for (const x of exps) {
    const brk = x.layout ? x.brk : undefined;
    out += text.slice(at, x.start) + reserveBlock(x.token, x.rows, x.layout, x.span === true, brk);
    at = x.end;
    if (brk !== undefined) {
      out += text.slice(at, at + brk) + "\n";
      at += brk;
    }
  }
  return out + text.slice(at);
}

// ── eligibility ──────────────────────────────────────────────────────────────

/** Where a text sits in its content block (the streaming expander scans
 *  regions of a block). Defaults describe a whole block. */
export interface TextEdges {
  /** Position 0 is at a line start (the block start, or after `\n`). */
  lineStart?: boolean;
  /** The text's end is the block's end. False: a token that runs to the end
   *  is not proven alone on its line (more text may follow). */
  textEnd?: boolean;
}

/** One token that stands alone on its line. */
export interface StandaloneToken {
  /** The token as written (escapes kept). */
  token: string;
  /** Its canonical spelling (escapes removed). */
  canonical: string;
  hash: string;
  /** Offsets of the token in the text. */
  start: number;
  end: number;
}

/**
 * Every token occurrence whose preceding char is the text start (when
 * `lineStart`) or `\n`, and whose following char, after the whole token
 * including its field path, is `\n` or the text end (when `textEnd`).
 */
export function standaloneTokens(text: string, edges: TextEdges = {}): StandaloneToken[] {
  const lineStart = edges.lineStart !== false;
  const textEnd = edges.textEnd !== false;
  const out: StandaloneToken[] = [];
  if (!text.includes("$MDU:")) return out;
  let from = 0;
  for (;;) {
    const nl = text.indexOf("\n", from);
    const end = nl < 0 ? text.length : nl;
    const atStart = from > 0 || lineStart;
    const atEnd = nl >= 0 || textEnd;
    if (atStart && atEnd && end > from) {
      const line = text.slice(from, end);
      if (TOKEN_LINE_RE.test(line)) {
        const hash = tokenHash(line);
        if (hash !== null) out.push({ token: line, canonical: canonicalToken(line), hash, start: from, end });
      }
    }
    if (nl < 0) break;
    from = nl + 1;
  }
  return out;
}

// ── expand ───────────────────────────────────────────────────────────────────

/** Line count for a token: the canonical spelling first, then as written. */
function linesFor(shapes: ReadonlyMap<string, number>, t: StandaloneToken): number | undefined {
  return shapes.get(t.canonical) ?? shapes.get(t.token);
}

/** The rows a token with `lines` value lines reserves under `cap`, or 0 when
 *  it is not expanded (fewer than 2 lines, an invalid count or cap). */
export function reserveRows(lines: number | undefined | null, cap: number): number {
  if (typeof lines !== "number" || !Number.isInteger(lines) || lines < 2) return 0;
  if (!Number.isInteger(cap) || cap < 2) return 0;
  return Math.min(lines, cap, RESERVE_MAX_LIMIT);
}

/**
 * Replace every standalone token whose shape says ≥ 2 lines with its reserve
 * block of min(lines, cap) rows. `shapes` maps a token (canonical spelling,
 * or as written) to its value's line count. Everything else is untouched.
 */
export function expandText(
  text: string,
  shapes: ReadonlyMap<string, number>,
  cap: number,
  edges: TextEdges = {},
): string {
  const cands = standaloneTokens(text, edges);
  if (cands.length === 0) return text;
  let out = "";
  let at = 0;
  for (const c of cands) {
    const rows = reserveRows(linesFor(shapes, c), cap);
    if (rows === 0) continue;
    out += text.slice(at, c.start) + reserveBlock(c.token, rows);
    at = c.end;
  }
  return at === 0 ? text : out + text.slice(at);
}

// ── collapse ─────────────────────────────────────────────────────────────────

/** Collapse, with the number of blocks collapsed. */
export function collapseTextCounted(text: string): { text: string; collapsed: number } {
  if (!text.includes("/1:") || !text.includes("\n")) return { text, collapsed: 0 };
  // (a head-only block's break is a \n too, so the pre-check holds)
  const re = new RegExp(HEAD_ANY_SRC, "g");
  let out = "";
  let at = 0;
  let collapsed = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const token = m[1]!;
    const n = Number(m[2]);
    const brk = m[3] !== undefined ? Number(m[3]) : undefined;
    const hash = tokenHash(token);
    let end = m.index + m[0].length;
    // N = 1 only as a head-only block with a break (§14).
    let ok = hash !== null && n <= RESERVE_MAX_LIMIT && (n >= 2 || (n === 1 && brk !== undefined));
    // One separator for the whole block: the plain form or the span form.
    const sep = text.startsWith(SPAN_SEP, end) ? SPAN_SEP : "\n";
    for (let i = 2; ok && i <= n; i++) {
      const row = `${sep}$MDU/${hash}/${i}`;
      if (text.startsWith(row, end)) end += row.length;
      else ok = false;
    }
    // The last row must not run on into more digits (`/2` vs `/23`).
    if (ok && end < text.length && /[0-9]/.test(text[end]!)) ok = false;
    // §14: the inserted break, K characters on, with no break before it.
    let cut = -1;
    if (ok && brk !== undefined) {
      if (end + brk < text.length && text[end + brk] === "\n" && !text.slice(end, end + brk).includes("\n")) cut = end + brk;
      else ok = false;
    }
    if (!ok) {
      re.lastIndex = m.index + 1;
      continue;
    }
    out += text.slice(at, m.index) + token;
    if (cut >= 0) {
      out += text.slice(end, cut);
      end = cut + 1;
    }
    at = end;
    collapsed++;
    re.lastIndex = end;
  }
  return collapsed === 0 ? { text, collapsed: 0 } : { text: out + text.slice(at), collapsed };
}

/**
 * Replace every well-formed reserve block with T: a head `T/1:N` or
 * `T/1:N:W:F` (digits), wherever it stands, immediately followed by exactly
 * `\n$MDU/<hash>/2` … `\n$MDU/<hash>/N` (hash = T's; or the span form, each
 * `\n` as `` `\n` ``) and then not a digit. A head with a break `:K` (§14)
 * also needs a `\n` exactly K characters after the last row, none before
 * it; that `\n` goes with the block.
 * Anything else is left for stripResiduals.
 */
export function collapseText(text: string): string {
  return collapseTextCounted(text).text;
}

// ── residual strip ───────────────────────────────────────────────────────────

/**
 * Remove every reserve-block fragment: a `/1:<digits>` suffix directly after
 * a token, with up to two more `:<digits>` fields (v2 `:W:F`), and every
 * continuation marker `$MDU/<hex>/<n>`. A marker directly after a line break
 * goes with that break, whatever follows it on its line (so a mangled
 * mid-line block `pre T/1:4:78:40\n$MDU/h/2\n$MDU/h/3 tail` strips to
 * `pre T tail`); a marker at the text start that is a whole line goes with
 * the following break; any other marker goes alone. Returns how many
 * fragments were removed. The span form's marker goes with its `` `\n` ``
 * separator (`` `T/1:3:78:40`\n`$MDU/h/2`\n`$MDU/h/3` tail `` → `` `T` tail ``).
 */
export function stripResiduals(text: string): { text: string; removed: number } {
  if (!text.includes("$MDU")) return { text, removed: 0 };
  let removed = 0;
  let t = text;
  if (t.includes("/1:")) {
    HEAD_SUFFIX_RE.lastIndex = 0;
    t = t.replace(HEAD_SUFFIX_RE, (_m, tok: string) => {
      removed++;
      return tok;
    });
  }
  if (t.includes("$MDU/")) {
    SPAN_MARKER_AFTER_BREAK_RE.lastIndex = 0;
    t = t.replace(SPAN_MARKER_AFTER_BREAK_RE, () => {
      removed++;
      return "";
    });
    MARKER_AFTER_BREAK_RE.lastIndex = 0;
    t = t.replace(MARKER_AFTER_BREAK_RE, () => {
      removed++;
      return "";
    });
    let m: RegExpExecArray | null;
    while ((m = MARKER_LINE_START_RE.exec(t)) !== null) {
      removed++;
      t = t.slice(m[0].length);
    }
    MARKER_ANY_RE.lastIndex = 0;
    t = t.replace(MARKER_ANY_RE, () => {
      removed++;
      return "";
    });
  }
  return { text: t, removed };
}
