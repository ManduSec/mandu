/**
 * reserve-layout — the rows a resolved value occupies under the agent's TUI
 * (docs/design/ui/reply-row-reservation.md §11.2): by default a TUI that wraps
 * text the way Ink does (word wrap; Claude Code, Codex); with the `terminal`
 * rule (§17) a TUI that prints its reply at column 0 and leaves the wrap to
 * the terminal (character wrap at the full width; Goose).
 *
 * ONE MODULE, FOUR COPIES. The arbiter counts the rows (`symbolShape`), the
 * model proxies wrap the model's own prefix with the same rule (to learn the
 * head row's free width), and the reply filter paints the rows. The packages
 * are independent roots, so this file is copied VERBATIM to
 *   interceptors/reply-filter/src/reserve-layout.ts     (the canonical copy)
 *   arbiter/ipc/reserve-layout.ts
 *   interceptors/anthropic-proxy/src/reserve-layout.ts  (Claude)
 *   interceptors/openai-proxy/src/reserve-layout.ts     (Codex)
 * and tests/stack/reserve-layout-parity.test.ts fails unless
 * the four are byte-identical. Change the canonical copy and copy it out.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (2026-09-30). The wrap
 * is a re-implementation of the algorithm of `wrap-ansi` (MIT, the
 * `hard: true, trim: false` path Ink calls), on plain text only: values are
 * cleaned of escapes first, so the ANSI bookkeeping is not needed. Pinned
 * against vanilla Claude Code 2.1.285 screens (reply-row-reservation.md
 * §11.1). The `terminal` rule (2026-10-07) is a terminal's autowrap, pinned
 * against vanilla Goose 1.53.0 screens (§17.1). A TAB counts its stop from
 * the column `indent` names (§11.2, §19.7): the terminal's column 0 for a
 * TUI whose stops are the screen's (Codex), the content area's own for one
 * that expands each TAB from its text (Claude Code 2.1.295 and later).
 *
 * Pure: no I/O, never throws, no state.
 */

/**
 * The wrap rule a TUI lays its reply out by (§17):
 *   - `ink`: wrap-ansi's greedy word wrap (`hard: true, trim: false`), the
 *     rule Ink and Codex's renderer apply (the default);
 *   - `terminal`: no wrap of the TUI's own; the terminal's autowrap breaks
 *     a row when the next glyph does not fit (a wide glyph that would
 *     straddle the edge moves whole to the next row).
 */
export type LayoutRule = "ink" | "terminal";

/** The rules, for validation where a rule arrives over a wire. */
export const LAYOUT_RULES: readonly LayoutRule[] = ["ink", "terminal"];

/** Terminal tab stops: every 8 columns. */
export const LAYOUT_TAB_STOP = 8;

/** CSI escape sequences (any final byte). */
const LAYOUT_CSI_RE = /\x1b\[[0-9;:?]*[@-~]/g;
/** C0 controls other than TAB, and DEL. */
const LAYOUT_C0_RE = /[\x00-\x08\x0a-\x1f\x7f]/g;
/** East Asian Wide / Fullwidth ranges a terminal renders two columns wide
 *  (the reply filter's WIDE_RE). */
const LAYOUT_WIDE_RE = /[ᄀ-ᅟ⺀-〾ぁ-㏿㐀-䶿一-鿿ꀀ-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦\u{1f300}-\u{1f64f}\u{1f900}-\u{1f9ff}\u{20000}-\u{2fffd}\u{30000}-\u{3fffd}]/u;
/** Combining marks, zero-width characters and variation selectors. */
const LAYOUT_ZERO_RE = /[\p{M}​-‏⁠︀-️]/u;

/** Display width of one code point. */
export function layoutGlyphWidth(ch: string): number {
  if (LAYOUT_ZERO_RE.test(ch)) return 0;
  return LAYOUT_WIDE_RE.test(ch) ? 2 : 1;
}

/** Display width of a string. */
export function layoutWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += layoutGlyphWidth(ch);
  return w;
}

/** A value's lines: one trailing line break dropped, split on any break. */
export function layoutLines(value: string): string[] {
  let v = value;
  if (v.endsWith("\r\n")) v = v.slice(0, -2);
  else if (v.endsWith("\n") || v.endsWith("\r")) v = v.slice(0, -1);
  return v.split(/\r\n|\r|\n/);
}

/** One line cleaned for a frame: escapes and control bytes removed, each TAB
 *  expanded to the spaces that reach the next tab stop (the next multiple of
 *  8 of the column counted from the TUI's TAB origin), the line's first
 *  glyph sitting at column `col0` of that count (§11.2: the content area's
 *  `indent`, plus the head's offset on its row). `col0` absent, negative or
 *  not an integer counts from 0, the line's own start. */
export function cleanLine(line: string, col0: number = 0): string {
  const flat = line.replace(LAYOUT_CSI_RE, "").replace(LAYOUT_C0_RE, "");
  if (!flat.includes("\t")) return flat;
  let col = Number.isInteger(col0) && col0 > 0 ? col0 : 0;
  let out = "";
  for (const ch of flat) {
    if (ch === "\t") {
      const n = LAYOUT_TAB_STOP - (col % LAYOUT_TAB_STOP);
      out += " ".repeat(n);
      col += n;
    } else {
      out += ch;
      col += layoutGlyphWidth(ch);
    }
  }
  return out;
}

/** Break `word` into the rows, filling the last row first (wrap-ansi's
 *  wrapWord). `cap(r)` is row r's width. */
function wrapWord(rows: string[], word: string, cap: (r: number) => number): void {
  let visible = layoutWidth(rows[rows.length - 1]!);
  const chars = [...word];
  for (let k = 0; k < chars.length; k++) {
    const ch = chars[k]!;
    const w = layoutGlyphWidth(ch);
    if (visible + w <= cap(rows.length - 1)) {
      rows[rows.length - 1] += ch;
    } else {
      rows.push(ch);
      visible = 0;
    }
    visible += w;
    if (visible === cap(rows.length - 1) && k < chars.length - 1) {
      rows.push("");
      visible = 0;
    }
  }
  // A last row that holds only zero-width glyphs joins the row above.
  if (visible === 0 && rows[rows.length - 1]!.length > 0 && rows.length > 1) {
    const tail = rows.pop()!;
    rows[rows.length - 1] += tail;
  }
}

/**
 * Wrap one cleaned line: the first row is `first` columns wide, every later
 * row `width`. wrap-ansi's `hard: true, trim: false` algorithm: greedy on
 * single spaces, a space always kept (at a break it ends the upper row), a
 * word wider than a row broken by columns. `first` 0 is treated as `width`
 * (the caller places the line on its own row). Widths below 1 become 1.
 */
export function wrapLine(line: string, width: number, first: number = width): string[] {
  const W = Math.max(1, Math.floor(width));
  const F = first > 0 ? Math.max(1, Math.floor(first)) : W;
  const cap = (r: number): number => (r === 0 ? F : W);
  const rows: string[] = [""];
  const words = line.split(" ");
  for (let i = 0; i < words.length; i++) {
    const word = words[i]!;
    const len = layoutWidth(word);
    let rowLen = layoutWidth(rows[rows.length - 1]!);
    if (i !== 0) {
      if (rowLen >= cap(rows.length - 1)) {
        rows.push("");
        rowLen = 0;
      }
      rows[rows.length - 1] += " ";
      rowLen++;
    }
    const c = cap(rows.length - 1);
    if (len > W) {
      const remaining = c - rowLen;
      const breaksThisRow = 1 + Math.floor((len - remaining - 1) / W);
      const breaksNextRow = Math.floor((len - 1) / W);
      if (breaksNextRow < breaksThisRow) rows.push("");
      wrapWord(rows, word, cap);
      continue;
    }
    // A word that does not fit goes to the next row. On a first row narrower
    // than the rest that holds nothing yet, it goes too (never past `first`).
    if (rowLen + len > c && len > 0 && (rowLen > 0 || c < W)) {
      rows.push("");
    }
    rows[rows.length - 1] += word;
  }
  return rows;
}

/**
 * Wrap one cleaned line the way a terminal's autowrap does (the `terminal`
 * rule, §17): glyph by glyph, a new row when the next glyph does not fit,
 * spaces kept where they fall (at a row's start too). The first row is
 * `first` columns wide, every later row `width`; `first` 0 is treated as
 * `width`. A zero-width glyph stays on the row of the glyph before it.
 * Widths below 1 become 1; a glyph wider than a row gets a row of its own.
 */
export function wrapLineTerminal(line: string, width: number, first: number = width): string[] {
  const W = Math.max(1, Math.floor(width));
  const F = first > 0 ? Math.max(1, Math.floor(first)) : W;
  const rows: string[] = [""];
  let visible = 0;
  for (const ch of line) {
    const w = layoutGlyphWidth(ch);
    const cap = rows.length === 1 ? F : W;
    if (w > 0 && visible > 0 && visible + w > cap) {
      rows.push("");
      visible = 0;
    }
    rows[rows.length - 1] += ch;
    visible += w;
  }
  return rows;
}

/** One laid-out row: its text and the index of the value line it belongs to
 *  (-1 for the empty head row of `first` 0). */
export interface LayoutRow {
  text: string;
  line: number;
}

/**
 * The rows `value` occupies at content width `width`, the first row
 * `first` wide (`first` 0: line 1 starts on the row after the head, which
 * stays empty), under the TUI's wrap `rule` (default `ink`). Every line gets
 * at least one row.
 *
 * `indent` is the column of the content area's left edge in the count a
 * TAB's stops follow (§19.7): for a TUI whose stops are the screen's, the
 * relay's columns minus `width` (2 for a Codex reply, more in a list item, 0
 * under the `terminal` rule); for one that expands each TAB from its text
 * (Claude Code), 0. A TAB reaches that tab stop (cleanLine): line 1 on a
 * head row `first` wide starts at column `indent + width − first` (that row
 * ends at the right edge), every other line at `indent`. Absent (or not a
 * positive integer): 0, the stops counted from the content area itself.
 */
export function layoutRows(
  value: string, width: number, first: number = width, rule: LayoutRule = "ink", indent: number = 0,
): LayoutRow[] {
  const out: LayoutRow[] = [];
  const lines = layoutLines(value);
  const wrap = rule === "terminal" ? wrapLineTerminal : wrapLine;
  const left = Number.isInteger(indent) && indent > 0 ? indent : 0;
  if (first === 0) out.push({ text: "", line: -1 });
  for (let k = 0; k < lines.length; k++) {
    const f = k === 0 && first > 0 ? first : width;
    const col0 = left + Math.max(0, width - f);
    for (const text of wrap(cleanLine(lines[k]!, col0), width, f)) out.push({ text, line: k });
  }
  return out;
}

/** How many value lines are not shown in full on rows 0..shown-1 (the cap
 *  note's K). */
export function linesNotShown(rows: readonly LayoutRow[], shown: number): number {
  const last = rows[rows.length - 1];
  if (!last || shown >= rows.length) return 0;
  const lineCount = last.line + 1;
  const next = rows[shown];
  // Lines up to next.line - 1 are complete; next.line is at best partial.
  return next ? lineCount - Math.max(0, next.line) : 0;
}
