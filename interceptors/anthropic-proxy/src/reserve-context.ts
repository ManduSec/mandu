/**
 * reserve-context — v2 eligibility for reply row reservation: where a `$MDU:`
 * token sits in the model's Markdown (fence, list, the text before it on its
 * line), and whether, and with which head, it is expanded.
 *
 * Mandu Track A (interceptors/anthropic-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §11.4 (eligibility, v2), §11.2 (the
 * layout rule this reuses, src/reserve-layout.ts), §3.2 (v1 eligibility).
 * PROVENANCE: NEW Mandu code (2026-09-30). Copied VERBATIM, with
 * reserve-block.ts, to interceptors/openai-proxy/src/ (Codex, §11.7);
 * tests/stack/reserve-layout-parity.test.ts holds the copies
 * equal. Change this copy and copy it out.
 *
 * Pure: no I/O, never throws. The streaming expander (sse-reserve-expand.ts)
 * keeps one LineContext per text content block, advances it over the
 * MODEL's raw text (never the expanded text), and asks `decideReserve` for
 * each token once its following character is known.
 *
 * THE ONE RULE THE GEOMETRY KEEPS: F (the head row's free width) may be too
 * SMALL, never too large. Too small wastes columns on the head's row; too
 * large clips the value's first row at the right edge. F = 0 ("the value
 * starts on the row after the head") is right wherever the head lands, so
 * every position this cannot model exactly falls back to it:
 *   - exact: the text before the head on its row is plain (no character
 *     Markdown may remove, no leading whitespace, no other token), so its
 *     rendered width is its raw width and the wrap is reserve-layout's
 *     wrapLine. Then the head is on the prefix's last row when even the
 *     widest possible head fits there (F = W − p − glue), on its own row when
 *     even the narrowest possible head does not (F = W − glue), and F = 0 in
 *     between (the head's width depends on N, which depends on F);
 *   - not exact: Markdown only removes characters, so the raw width is an
 *     upper bound. When the raw prefix and the widest head fit on one row,
 *     the head is surely there, at most p columns in: F = W − p − glue.
 *     Otherwise F = 0.
 *   - F below ⌈W/2⌉ becomes 0 (the grammar's range).
 *
 * A token that is a code span's whole content, `` `T` ``, takes the span form
 * (reserve-block.ts, §12) when the caller enables it (`codeSpan`; the agent's
 * renderer was probed for it). Its backticks never show: the span closes on
 * the character right after T, so the opening backtick is no glue (vanilla
 * lays the value out from the same column).
 *
 * THE `terminal` RULE (§17, Goose): a TUI that prints the model's text raw at
 * column 0 and leaves the wrap to the terminal. Then W is the full width (no
 * content indent, no list indent: a list item's marker is text on its row),
 * nothing on the line is Markdown (backticks are drawn, so a code span is
 * plain text and the span form never applies), and the head's column is the
 * terminal's own arithmetic over the raw prefix (terminalColumn), so F is
 * exact. The structural refusals (heading, blockquote, table, link text) and
 * the ⌈W/2⌉ clamp stay as they are.
 */

import { layoutGlyphWidth, layoutWidth, wrapLine, type LayoutRule } from "./reserve-layout.js";
import { RESERVE_MAX_WIDTH, RESERVE_MIN_WIDTH, canonicalToken } from "./reserve-block.js";

/** A list item's leading spaces, marker and spaces (§11.4 "the indent"). */
export const LIST_ITEM_RE = /^( *)([-*+]|[0-9]{1,9}[.)]) +/;
/** A fence line: ``` or ~~~ (three or more) after optional indentation. */
const FENCE_RE = /^[ \t]*(`{3,}|~{3,})(.*)$/;
/** The character before a mid-line token (the line start is ""). */
const BEFORE_OK = new Set(["", " ", "\t", "*", "_", "\"", "'"]);
/** The character after a mid-line token (the line end is "" or "\n"). */
const AFTER_OK_RE = /^(?:\s|[.,;:!?)*_"'])$/;
const HEADING_RE = /^ {0,3}#/;
const QUOTE_RE = /^ *>/;
/** Characters Markdown may remove or re-render. A prefix holding one is
 *  measured as an upper bound, never exactly. */
const MARKDOWN_RE = /[*_`\\~[\]<>&!|#\t]/;
/** The content indent Claude Code puts before a reply's text (§11.1). */
export const CONTENT_INDENT = 2;

/** Per text content block: where the next character of the model's text
 *  lands. */
export interface LineContext {
  /** The raw text of the current line so far. */
  line: string;
  /** The fence open at the start of the current line, or null. */
  fence: { ch: string; n: number } | null;
  /** The list indent the current line inherits (0: none). */
  listCarry: number;
  /** A reserve block was already inserted earlier on this line. */
  lineExpanded: boolean;
}

export function newLineContext(): LineContext {
  return { line: "", fence: null, listCarry: 0, lineExpanded: false };
}

/** Advance the context over `text` (the model's raw text). */
export function advanceContext(ctx: LineContext, text: string): void {
  let from = 0;
  for (;;) {
    const nl = text.indexOf("\n", from);
    if (nl < 0) {
      if (from < text.length) ctx.line += text.slice(from);
      return;
    }
    ctx.line += text.slice(from, nl);
    endLine(ctx);
    from = nl + 1;
  }
}

/** A line is complete: update the fence and the list carry, start a new one. */
function endLine(ctx: LineContext): void {
  const line = ctx.line.endsWith("\r") ? ctx.line.slice(0, -1) : ctx.line;
  const f = FENCE_RE.exec(line);
  if (ctx.fence) {
    // Closes with the same character, at least as long, nothing after it.
    if (f && f[1]![0] === ctx.fence.ch && f[1]!.length >= ctx.fence.n && f[2]!.trim() === "") ctx.fence = null;
  } else if (f) {
    ctx.fence = { ch: f[1]![0]!, n: f[1]!.length };
  } else if (/^[ \t]*$/.test(line)) {
    ctx.listCarry = 0;
  } else {
    const li = LIST_ITEM_RE.exec(line);
    if (li) ctx.listCarry = li[0].length;
  }
  ctx.line = "";
  ctx.lineExpanded = false;
}

/** What to do with one token. */
export type ReserveDecision =
  | { kind: "none"; reason: string }
  /** A v1 head: one row per value line (`lines`). */
  | { kind: "v1" }
  /** A v2 head at (width, first). `standalone`: an older arbiter's lines-only
   *  answer may still give a v1 head. `span`: the span form (§12). */
  | { kind: "v2"; width: number; first: number; standalone: boolean; span: boolean };

export interface DecideInput {
  /** The context at the token (ctx.line = the raw line text before it). */
  ctx: LineContext;
  /** The token as written, field path included. */
  token: string;
  /** The character after the token: "" = the line ends at the block end;
   *  null = not known (never expanded). */
  after: string | null;
  /** The relay's terminal columns when it paints v2 heads (`wrap: true`);
   *  null = a v1 relay. */
  cols: number | null;
  /** The row cap (bounds N's digits in the head). */
  cap: number;
  /** The span form for a token that is a whole code span (§12). Off: a
   *  token inside a code span is never expanded. */
  codeSpan?: boolean;
  /** The model's text after the token up to its line end, when known (the
   *  expander holds a line with a token until it ends, §14). A `|` in it
   *  makes the line a table row. Undefined: not known (not checked). */
  rest?: string;
  /** The TUI's wrap rule (§17); absent: `ink`. */
  rule?: LayoutRule;
}

const none = (reason: string): ReserveDecision => ({ kind: "none", reason });

/**
 * The column a terminal's cursor stands at after printing `text` from column
 * 0 of a `width`-column row with autowrap on (§17): a glyph that does not fit
 * starts the next row, a TAB moves to the next multiple of 8 on its row.
 * Null when the column is not the terminal's plain arithmetic: a control
 * byte other than TAB, a TAB at the edge, or text that fills its last row to
 * the edge (the cursor then waits to wrap, and a frame-safe splice written
 * with autowrap off would land on that row's last cell, not the next row).
 */
export function terminalColumn(text: string, width: number): number | null {
  let col = 0;
  for (const ch of text) {
    if (ch === "\t") {
      if (col >= width) return null;
      col = Math.min(width - 1, (Math.floor(col / 8) + 1) * 8);
      continue;
    }
    if (/[\x00-\x1f\x7f]/.test(ch)) return null;
    const w = layoutGlyphWidth(ch);
    if (w === 0) continue;
    if (col + w > width) col = 0;
    col += w;
  }
  return col >= width ? null : col;
}

/** §17: the decision for one token under the `terminal` rule. */
function decideTerminal(inp: DecideInput, prefix: string, lineEnd: boolean, standalone: boolean): ReserveDecision {
  const { ctx, token, cols, cap } = inp;
  if (cols === null || !Number.isInteger(cols)) return standalone ? { kind: "v1" } : none("the relay does not wrap (v1)");
  const W = cols;
  const widthOk = W >= RESERVE_MIN_WIDTH && W <= RESERVE_MAX_WIDTH;
  const headHi = layoutWidth(token) + `/1:${cap}:${W}:${W}`.length;
  if (standalone) {
    // A fence is drawn raw too (the §17.1 probe): its rows wrap like prose.
    if (!widthOk || headHi > W) return { kind: "v1" };
    return { kind: "v2", width: W, first: W, standalone: true, span: false };
  }
  if (ctx.fence !== null || FENCE_RE.test(prefix)) return none("inside a fenced code block");
  if (!widthOk) return none(`content width ${W} outside ${RESERVE_MIN_WIDTH}..${RESERVE_MAX_WIDTH}`);
  if (ctx.lineExpanded) return none("a block already sits on this line");
  const before = prefix === "" ? "" : prefix[prefix.length - 1]!;
  if (!BEFORE_OK.has(before) && before !== "`") return none(`character before: ${JSON.stringify(before)}`);
  if (!(lineEnd || AFTER_OK_RE.test(inp.after!) || inp.after === "`")) return none(`character after: ${JSON.stringify(inp.after)}`);
  if (HEADING_RE.test(prefix)) return none("a heading");
  if (QUOTE_RE.test(prefix)) return none("a blockquote");
  if (prefix.includes("|") || (inp.rest ?? "").includes("|")) return none("a table row");
  if (prefix.lastIndexOf("[") > prefix.lastIndexOf("]")) return none("inside link text");
  let first: number;
  if (prefix.includes("$MDU")) {
    // Another token earlier on the line: its one-row splice moves the head.
    first = 0;
  } else {
    const p = terminalColumn(prefix, W);
    if (p === null) return none("the text before the token has no plain column");
    first = W - p;
  }
  if (first !== 0 && first < Math.ceil(W / 2)) first = 0;
  return { kind: "v2", width: W, first, standalone: false, span: false };
}

/** Width with every TAB counted as a full tab stop (an upper bound). */
function widthHi(s: string): number {
  return layoutWidth(s.replace(/\t/g, "        "));
}

/** §11.4: the decision for one token. */
export function decideReserve(inp: DecideInput): ReserveDecision {
  const { ctx, token, after, cols, cap } = inp;
  if (after === null) return none("the following character is not known");
  const prefix = ctx.line;
  const lineEnd = after === "" || after === "\n";
  const standalone = prefix === "" && lineEnd;
  if (inp.rule === "terminal") return decideTerminal(inp, prefix, lineEnd, standalone);
  if (ctx.fence !== null || FENCE_RE.test(prefix)) {
    return standalone ? { kind: "v1" } : none("inside a fenced code block");
  }
  if (cols === null || !Number.isInteger(cols)) return standalone ? { kind: "v1" } : none("the relay does not wrap (v1)");

  const li = LIST_ITEM_RE.exec(prefix);
  const listIndent = li ? li[0].length : ctx.listCarry;
  const W = cols - CONTENT_INDENT - listIndent;
  const tokenHi = layoutWidth(token);
  const tokenLo = layoutWidth(canonicalToken(token));
  // The head's width depends on N (≤ cap) and F (≤ W): bound it both ways.
  const headHi = tokenHi + `/1:${cap}:${W}:${W}`.length;
  const headLo = tokenLo + `/1:2:${W}:0`.length;
  const widthOk = W >= RESERVE_MIN_WIDTH && W <= RESERVE_MAX_WIDTH;

  if (standalone) {
    if (!widthOk || headHi > W) return { kind: "v1" };
    return { kind: "v2", width: W, first: W, standalone: true, span: false };
  }

  // ── a token inside a line ──
  if (!widthOk) return none(`content width ${W} outside ${RESERVE_MIN_WIDTH}..${RESERVE_MAX_WIDTH}`);
  if (ctx.lineExpanded) return none("a block already sits on this line");
  const before = prefix === "" ? "" : prefix[prefix.length - 1]!;
  // Inside a code span: only `` `T` ``, a single backtick on each side, and
  // only in the span form. The char after the closing backtick is not known
  // yet; a longer closing run only costs the rendering (collapse is exact).
  const span = (prefix.match(/`/g)?.length ?? 0) % 2 === 1;
  if (span) {
    if (inp.codeSpan !== true) return none("inside a code span");
    if (before !== "`" || prefix.endsWith("``") || prefix.endsWith("\\`") || after !== "`") {
      return none("inside a code span, not all of it");
    }
  } else {
    if (!BEFORE_OK.has(before)) return none(`character before: ${JSON.stringify(before)}`);
    if (!(lineEnd || AFTER_OK_RE.test(after))) return none(`character after: ${JSON.stringify(after)}`);
  }
  if (HEADING_RE.test(prefix)) return none("a heading");
  if (QUOTE_RE.test(prefix)) return none("a blockquote");
  if (prefix.includes("|") || (inp.rest ?? "").includes("|")) return none("a table row");
  if (prefix.lastIndexOf("[") > prefix.lastIndexOf("]")) return none("inside link text");

  // The head word is the glue (non-space text right before T) plus the head.
  const body = li ? prefix.slice(li[0].length) : prefix;
  const cut = body.lastIndexOf(" ") + 1;
  const lead = body.slice(0, cut);
  // The span's opening backtick is not rendered (the span closes after T).
  const glue = span ? body.slice(cut, -1) : body.slice(cut);
  const glueHi = widthHi(glue);
  const glueLo = MARKDOWN_RE.test(glue) ? 0 : layoutWidth(glue);
  if (glueHi + headHi > W) return none("the head word does not fit in a row");

  let first: number;
  if (body.includes("$MDU")) {
    // Another token earlier on the line: its one-row splice moves the head.
    first = 0;
  } else if (!MARKDOWN_RE.test(lead) && !/^\s/.test(lead)) {
    const rows = wrapLine(lead, W, W);
    const p = layoutWidth(rows[rows.length - 1]!);
    if (p + glueHi + headHi <= W) first = W - p - glueHi;
    else if (p + glueLo + headLo > W) first = W - glueHi; // the head starts a row
    else first = 0;
  } else {
    const p = widthHi(lead);
    first = p + glueHi + headHi <= W ? W - p - glueHi : 0;
  }
  if (first !== 0 && first < Math.ceil(W / 2)) first = 0;
  return { kind: "v2", width: W, first, standalone: false, span };
}

// ── §14: where the text after a mid-line block wraps ─────────────────────────

/** Text that would start a Markdown block on a line of its own. A break must
 *  never make the rest of a sentence a list item, heading, quote, fence,
 *  table, HTML block or setext underline. */
const BLOCK_START_RE = /^(?: {0,3}(?:[-*+](?:\s|$)|[0-9]{1,9}[.)](?:\s|$)|#|>|`{3}|~{3}|<|\||=+\s*$|-+\s*$))/;

/** The largest K the head carries (four digits: the filter's grammar). */
export const SUFFIX_BREAK_MAX = 9999;

export interface SuffixBreakInput {
  /** The model's text after the token (after the span form's closing
   *  backtick too, which is part of it), up to its line end, no line break. */
  suffix: string;
  /** The display width of the value's last row (symbolShape `last`). */
  last: number;
  /** The display width of the last row's marker `$MDU/<hash>/<N>`: the TUI
   *  lays the text out after the marker, the screen after the value. */
  marker: number;
  /** W, the content width. */
  width: number;
  /** Backticks on the line before the token (odd: the token is in a span). */
  lineTicks: number;
  /** The TUI's wrap rule (§17); absent: `ink`. */
  rule?: LayoutRule;
}

/**
 * §17, the `terminal` rule: the terminal breaks the text after the value
 * where its row is full, mid-word, so the break goes exactly there: K = the
 * characters of the suffix that fit after the value's last row (after the
 * marker, when the marker is wider: the filter pads the row to it). Null
 * when the suffix fits, when it holds another token or a control byte (its
 * width is not the raw width), or when not one character fits (K ≥ 1).
 */
function suffixBreakTerminal(inp: SuffixBreakInput): number | null {
  const { suffix, width } = inp;
  if (suffix === "" || suffix.includes("$MDU") || /[\x00-\x1f\x7f]/.test(suffix)) return null;
  let cur = Math.max(inp.last, inp.marker);
  let k = 0;
  for (const ch of suffix) {
    const w = layoutGlyphWidth(ch);
    if (cur + w > width) return k >= 1 && k <= SUFFIX_BREAK_MAX ? k : null;
    cur += w;
    k += ch.length;
  }
  return null;
}

/**
 * Where to insert one `\n` into the text after a mid-line block so that it
 * never clips (reply-row-reservation.md §14): the text continues after the
 * value's last row as far as it fits in both worlds (after the value on the
 * screen, after the marker in the TUI), then breaks where wrap-ansi would,
 * after the space before the first word that does not fit. The rest starts a
 * row of its own and the TUI wraps it as vanilla does. Returns K, the break's
 * offset in `suffix` (the `\n` goes before `suffix[K]`), or null: no break is
 * needed, or none is safe:
 *   - the text holds another token (its one-row splice changes widths), a
 *     TAB or a double space (wrap-ansi's spacing is not modeled);
 *   - the value's last word plus the text glued to it does not fit (vanilla
 *     would move the value's own last word);
 *   - a word wider than W (a hard break), a break inside a code span or an
 *     unclosed `[`, or a rest that would open a Markdown block.
 * Widths are raw: Markdown only removes characters, so a break is never
 * later than vanilla's (the text never clips; it may break a word early).
 */
export function suffixBreak(inp: SuffixBreakInput): number | null {
  const { suffix, width } = inp;
  if (suffix === "" || suffix.includes("\n")) return null;
  if (inp.rule === "terminal") return suffixBreakTerminal(inp);
  if (suffix.includes("$MDU") || suffix.includes("\t") || suffix.includes("  ")) return null;
  const r = Math.max(inp.last, inp.marker);
  const glue = /^\S*/.exec(suffix)![0];
  let cur = r + widthHi(glue);
  if (cur > width) return null;
  let pos = glue.length;
  while (pos < suffix.length) {
    // suffix[pos] is a single space; the word runs to the next space.
    const nextSpace = suffix.indexOf(" ", pos + 1);
    const word = suffix.slice(pos + 1, nextSpace < 0 ? suffix.length : nextSpace);
    if (word === "") return null; // trailing space: nothing left to place
    const w = widthHi(word);
    if (w > width) return null;
    if (cur + 1 + w > width) {
      const k = pos + 1;
      const before = suffix.slice(0, k);
      if ((inp.lineTicks + (before.match(/`/g)?.length ?? 0)) % 2 === 1) return null;
      if (before.lastIndexOf("[") > before.lastIndexOf("]")) return null;
      if (BLOCK_START_RE.test(suffix.slice(k))) return null;
      return k <= SUFFIX_BREAK_MAX ? k : null;
    }
    cur += 1 + w;
    pos = nextSpace < 0 ? suffix.length : nextSpace;
  }
  return null;
}
