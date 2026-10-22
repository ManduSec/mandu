/**
 * screen-reconcile — the fullscreen-aware half of the user-reply egress
 * filter: a per-row SCREEN-CELL model that reads symbol tokens (and reserve-
 * block rows, on both screens) back off the rendered screen and repaints
 * their values in place.
 *
 * Mandu user-reply egress chokepoint (interceptors/reply-filter). Mandu-new
 * (no reference origin — the OpenClaw hook resolves a message object; Mandu
 * resolves a byte stream, and this module resolves a SCREEN).
 *
 * WHY (docs/testing/differential-interactive.md §17/§19): the stream filter
 * (filter.ts) resolves a token where it is CONTIGUOUS in the byte stream,
 * wrap insertions looked through. Claude Code's alt-screen ("fullscreen")
 * renderer paints with CELL-DIFF repaints: the last frame of a reply row can
 * write `$MDU:Read[d49`, jump the cursor over a column it believes unchanged,
 * then write `]` — the token is never contiguous on the wire, only on the
 * screen. The glue set that lets the stream filter look through wrap
 * artifacts deliberately EXCLUDES cursor moves (they position every word of a
 * repainted row; treating them as glue caused three earlier live bugs), so
 * the stream alone cannot reassemble it. This module keeps TWO terminal
 * models — what the TUI believes it painted (fed the child's raw bytes) and
 * what the human's terminal really shows (fed the filter's output, repaints
 * included) — and after every write reconciles the rows that carry a token:
 * desired(row) = the TUI's row with each token replaced by its value; where
 * the human's row differs, the row is repainted from the first differing
 * column and the cursor is put back where the TUI believes it is.
 *
 * SECURITY POSTURE: identical to filter.ts — UTILITY-ONLY. The human's
 * terminal is HumanView; a token this module fails to resolve stays an opaque
 * symbol on screen (nothing leaks), and any failure (arbiter unreachable,
 * modeling surprise) degrades to NO repaint. It never gates.
 *
 * SCOPE, deliberately narrow (v1):
 *   - TOKENS are reconciled while the TUI is on the ALTERNATE screen
 *     (`?1049h`/`?47h`). On the MAIN screen the inline renderer's stream
 *     splice + column translation (soak 60/60 + 12/12, differential-
 *     interactive.md §8) stay the only writer for tokens, except after a
 *     SPLIT FRAGMENT: Claude Code's inline renderer diffs cells too (2.1.273,
 *     §30), so a frame that paints a token over a row whose cell at the same
 *     offset already holds the token's glyph writes `$MDU:` CHA `omodel_…`.
 *     maskFragments blanks that fragment, and the reconciles of that write
 *     and the next (`maskPass`) take the main screen's token rows as the
 *     alternate screen's: the value is painted, an unresolvable fragment gets
 *     the TUI's cells back. The main screen's token rows are taken also to
 *     CLOSE UP a value narrower than its token (below), unless the row also
 *     holds a wider value (that row stays the stream's).
 *   - RESERVE-BLOCK ROWS (reply-row-reservation.md §3.7) are reconciled on
 *     BOTH screens: phase 0 (§7.1) found that a re-layout frame repaints
 *     marker rows by cell diff on the main screen too, writing only the
 *     changed cells (`\r ESC[12C ESC[1B 3`), which no stream can splice. On
 *     the main screen only rows carrying a head (`T/1:N`) or continuation
 *     (`$MDU/<hash>/<i>`) marker are touched, plus rows this module painted
 *     before (tracked as xterm markers, which follow a line as the main
 *     screen scrolls). desired(row) replaces each marker with its line of
 *     the value (the cap note on row N of a capped block; `T (N lines)` and
 *     blank rows when the value is unknown), by the same pad/clip rules.
 *     A continuation row whose head never reached the screen (a block
 *     taller than a fullscreen renderer's viewport shows only its tail)
 *     finds its head through `blockLookup`, the proxy's record in the
 *     arbiter (§3.8). Every row that holds a value stays owned, even when
 *     the stream already painted it right: the TUI believes it holds the
 *     shorter marker, so a later cell diff can leave the value's tail
 *     behind (§3.7).
 *   - The models are viewport-sized (no scrollback; on the main screen both
 *     scroll together, fed the same line feeds, so a viewport row means the
 *     same line in both).
 *   - Addressing: the alternate screen is repainted with absolute CUP; the
 *     MAIN screen with moves RELATIVE to the TUI's cursor (CUU/CUD + CHA),
 *     because the relay does not start at the real terminal's top-left (a
 *     shell prompt sits above), so the models' row 0 is not the terminal's;
 *     distances from the cursor are what the TUI and the terminal agree on.
 *   - A repaint carries NO styling: it resets the pen (`ESC[0m`), paints the
 *     row's cells from the first differing column, erases to the row end, and
 *     restores the TUI's cursor with an absolute CUP. Ink emits every styled
 *     run self-contained (open + close codes per segment), so a reset pen
 *     between two of its writes changes nothing it relies on; a TUI that
 *     keeps a pen across writes would see one plain run — accepted.
 *   - Values render FRAME-SAFELY (filter.ts frameSafeValue: one row, control
 *     bytes stripped; a TAB expands to the next 8-column tab stop from the
 *     value's exact column in desired(row), so a row the stream filter
 *     spliced with its one-space fallback is repainted to the tab-stop
 *     form), and clipped at the row's right edge when longer — cells the
 *     TUI painted after the token shift right and clip with it (the stream
 *     filter clips the same way, filter.ts CLIP PAST THE EDGE, so a row it
 *     wrote compares equal; before 2026-10-17 it let those cells wrap onto
 *     rows the TUI never counted, which no row reconcile can undo). A value
 *     SHORTER than its unit is NOT padded (CLOSE UP, 2026-10-05): the stream
 *     filter pads it to the unit's width for the TUI's cursor math, which
 *     left a run of spaces inside the human's line (`KEY='sk_live_…      '`,
 *     the first-session tour, differential-interactive.md §31); the repaint
 *     shifts the cells after the value LEFT and erases the row's tail, so
 *     the human reads `KEY='sk_live_…'`.
 *     The TUI still believes the unit's cells are there; a later cell diff
 *     of the row lands at the TUI's columns, and the next reconcile repaints
 *     the row from the truth again (the convergence below, the same as for a
 *     wider value). Multi-line values cannot be reflowed from outside the
 *     renderer (the stream filter's stated limit; full fidelity stays on the
 *     other HumanView surfaces), unless the proxy reserved the rows: then
 *     each reserved row gets its own line (docs/design/ui/reply-row-reservation.md
 *     §3.7).
 *   - OPENCODE'S RENDERER (differential-interactive.md §35): its final
 *     Markdown render draws a token's `[hash]` as a link with the brackets
 *     hidden, and it breaks a word that does not fit its row at its
 *     punctuation (`$MDU:` / `nomodel_read[0155]`). A row scan therefore also
 *     reads a token by its CONCEALED spelling (concealedSpelling), once that
 *     token resolved here or one of the spellings the run allows
 *     (concealedCandidates) resolves; a spelling two tokens share is never
 *     painted. A unit split between two rows (softWrapJoin) is joined: its
 *     upper piece is dropped and the value painted where its lower piece
 *     starts, the row Ink would have moved the word to.
 *   - Residuals, stated honestly: a token the renderer soft-wraps across
 *     MORE than two rows renders raw; a value whose wide (CJK) glyphs the width
 *     estimate under-measures may clip a cell early; a repaint lands between
 *     two TUI frames, so a cell-diff frame that assumes the token is still
 *     on screen and rewrites part of it is reconciled again on the next
 *     write (one extra repaint, never a stuck token). Reserve rows add
 *     (reply-row-reservation.md §3.7): a cell-diff fragment on a row that
 *     scrolls into scrollback within the same write stays there (the
 *     reconciler only reaches the viewport); a repaint resets the pen, so a
 *     fenced block's code color is dropped on a repainted row; and the
 *     main screen's relative addressing assumes the TUI's and the terminal's
 *     cursors sit on the same line. The frame-safe stream keeps that true,
 *     and so does feeding the TUI model only the bytes the stream filter has
 *     let through (feedTui's `held`: a held reserve head's line break once
 *     put the model a row ahead, and the repaint landed a row up). A TUI
 *     move the model clamps at its top row but the terminal does not would
 *     break it — Ink's inline renderer does not move above its frame.
 *
 * CONVERGENCE: the stream filter still splices a contiguous token inline (no
 * flash for the common case); its output is what feeds the human model, so a
 * row the splice already made right compares equal and is left alone. Only
 * the shapes the stream cannot see — the cell-diff split, a longer value's
 * overrun of cells painted in an EARLIER frame, a value the TUI's next diff
 * partially overwrote with token bytes — produce a repaint, and so does a
 * value narrower than its token, whose stream pad the repaint closes up
 * (differential-interactive.md §31).
 *
 * NO SYMBOL BYTE ON THE ALTERNATE SCREEN'S WIRE (differential-interactive.md
 * §19.1, the echo-fidelity-long @160x40 flake): the stream filter's output
 * passed a split fragment such as `$MDU/` (CHA) `101/3` through raw, and the
 * repaint healed the row only after the bytes had reached the terminal. On
 * the alternate screen maskFragments() now blanks every `$MDU` run in the
 * stream's output before it is written, and a repaint blanks any `$MDU` run
 * the human's row does not already show; the cells that stay unresolvable
 * get the TUI's own cells back one reconcile later (a restore pass), after
 * the frame a read boundary may have cut is complete. The main screen keeps
 * the stream's bytes as they are but for a split fragment (an incomplete run
 * cut off by an escape, §30): a masked run on a row that scrolls away within
 * the write cannot be restored there, and only a fragment, which would have
 * stayed raw, is worth that.
 *
 * COST: two headless xterm instances (`@xterm/headless`, pure JS, zero
 * transitive deps — the same emulator the differential harness's screen
 * model uses) parse every byte once more, plus one row scan per write (on
 * the main screen a cheap `$MDU` text check per row first). One
 * arbiter round-trip per DISTINCT token (values are immutable, cached for the
 * session); an unknown token is retried at most every `unknownRetryMs`.
 */

import * as xtermHeadlessNs from "@xterm/headless";
import type { ReserveBlockInfo } from "./arbiter-client.js";
import { frameSafeValue, glyphWidth, SYMBOL_TOKEN_RE, type ReplyResolver } from "./filter.js";
import {
  HEAD_SUFFIX_MAX,
  ReserveValueCache,
  blockRowText,
  findContinuations,
  parseHeadSuffix,
  tokenHash,
  unknownHeadText,
} from "./reserve-block.js";

type Terminal = import("@xterm/headless").Terminal;
type IBufferLine = import("@xterm/headless").IBufferLine;
type IMarker = import("@xterm/headless").IMarker;
type IBuffer = import("@xterm/headless").IBuffer;
// @xterm/headless ships a UMD/CJS bundle — under ESM its named exports load
// under `default`, under a CJS transpile on the namespace itself (the same
// shim as tests/lib/screen.ts).
const { Terminal } = ((xtermHeadlessNs as { default?: unknown }).default ??
  xtermHeadlessNs) as typeof import("@xterm/headless");

export interface ScreenReconcilerOptions {
  cols: number;
  rows: number;
  /** Observability seam (best-effort, awaited): one call per token a repaint
   *  resolved, (token, value). */
  onResolve?: (before: string, after: string) => Promise<void> | void;
  /** How long an UNKNOWN token (the arbiter returned it unchanged — its
   *  `.field` delta may still be in flight) waits before it is asked again.
   *  Default 300ms. */
  unknownRetryMs?: number;
  /** The session's reserve-block memory, shared with the stream filter
   *  (reserve-block.ts): a continuation row finds its value through the head
   *  the stream (or this module) saw. Default: a private instance. */
  reserveCache?: ReserveValueCache;
  /** The arbiter's record of a block the proxy expanded, by the hash its
   *  continuation rows carry (reply-row-reservation.md §3.8): for a row
   *  whose head never reached the screen (a block taller than a fullscreen
   *  renderer's viewport). Absent, or null: the row paints blank, as before. */
  blockLookup?: (hash: string) => Promise<ReserveBlockInfo | null>;
}

/** One splice unit on a rendered row: a symbol token, a reserve-block head
 *  row marker (`T/1:N`) or a continuation row marker (`$MDU/<hash>/<i>`).
 *  `index`/`length` are offsets into the row's text. */
type RowSub =
  | { kind: "token"; index: number; length: number; canonical: string }
  | { kind: "head"; index: number; length: number; canonical: string; hash: string; n: number; w?: number | undefined; f?: number | undefined }
  | { kind: "cont"; index: number; length: number; hash: string; i: number }
  // The piece of a unit the TUI soft-wrapped onto another row (softWrapJoin):
  // its cells are removed and the rest of the row closes up.
  | { kind: "drop"; index: number; length: number };

/** A token or reserve head starting a string: its canonical token, the
 *  token's length as spelled there, and the head suffix after it, if any. */
interface UnitAt {
  canonical: string;
  tokenLength: number;
  suffix: ReturnType<typeof parseHeadSuffix>;
}

/** Answers "which known token does the concealed spelling at the start of
 *  `rest` stand for" (ScreenReconciler.matchConcealed), or null. */
type ConcealedMatcher = (rest: string) => { canonical: string; length: number } | null;

/** The splice unit for a token found at `index` (head when a suffix follows). */
function unitSub(index: number, u: UnitAt, length = u.tokenLength + (u.suffix?.length ?? 0)): RowSub {
  return u.suffix
    ? { kind: "head", index, length, canonical: u.canonical, hash: tokenHash(u.canonical), n: u.suffix.n, w: u.suffix.w, f: u.suffix.f }
    : { kind: "token", index, length, canonical: u.canonical };
}

/** A CONCEALED token run (differential-interactive.md §35): `$MDU:` and the
 *  token's characters with its brackets gone, as OpenCode draws a token
 *  whose `[hash]` its Markdown renderer took for a link (`$MDU:nomodel_read80f1`). */
const CONCEALED_RUN_RE = /\\?\$MDU:[A-Za-z0-9_\\]+(?:\.[A-Za-z_\\][A-Za-z0-9_\\]*)*/g;

/** Every splice unit on a row's text, in column order. A token followed by
 *  `/1:N` (v1) or `/1:N:W:F` (v2) is ONE head unit (never a token beside a
 *  stray suffix). A unit may sit anywhere on the row: a v2 head after prefix
 *  text, a last row's marker before suffix text (reply-row-reservation.md
 *  §11.3); the cells around it are kept. With `concealed`, a token drawn
 *  without its brackets (§35) is a unit too, when the matcher knows it. */
function rowSubs(text: string, concealed?: ConcealedMatcher): RowSub[] {
  const subs: RowSub[] = [];
  if (text.includes("$MDU:")) {
    SYMBOL_TOKEN_RE.lastIndex = 0;
    for (const m of text.matchAll(SYMBOL_TOKEN_RE)) {
      const canonical = m[0].replace(/\\/g, "");
      const end = m.index + m[0].length;
      const suffix = parseHeadSuffix(text.slice(end, end + HEAD_SUFFIX_MAX));
      subs.push(unitSub(m.index, { canonical, tokenLength: m[0].length, suffix }));
    }
    if (concealed) {
      CONCEALED_RUN_RE.lastIndex = 0;
      for (const m of text.matchAll(CONCEALED_RUN_RE)) {
        if (text[m.index + m[0].length] === "[") continue; // a bracketed token (or a fragment of one)
        if (subs.some((s) => s.index <= m.index && m.index < s.index + s.length)) continue;
        const hit = concealed(text.slice(m.index));
        if (!hit) continue;
        const end = m.index + hit.length;
        const suffix = parseHeadSuffix(text.slice(end, end + HEAD_SUFFIX_MAX));
        subs.push(unitSub(m.index, { canonical: hit.canonical, tokenLength: hit.length, suffix }));
      }
    }
  }
  for (const c of findContinuations(text)) subs.push({ kind: "cont", index: c.index, length: c.length, hash: c.hash, i: c.i });
  return subs.sort((a, b) => a.index - b.index);
}

/** How a token reads once a Markdown renderer has drawn its `[hash]` (and
 *  any bracketed field index) as a link: without the brackets, unescaped.
 *  Pure. */
export function concealedSpelling(canonical: string): string {
  return canonical.replace(/\\/g, "").replace(/[[\]]/g, "");
}

/** The canonical tokens a concealed run could stand for (§35): the run's
 *  first segment split into a tag and a 4-8 digit hex hash at each place
 *  the grammar allows, with the run's field path and without it. Several
 *  candidates are normal; the arbiter knows at most one of them in
 *  practice, and the caller accepts a run only when exactly one spelling
 *  resolves. Pure. */
export function concealedCandidates(run: string): Array<{ canonical: string; length: number }> {
  const m = /^\$MDU:([A-Za-z0-9_]+)((?:\.[A-Za-z_][A-Za-z0-9_]*)*)/.exec(run.replace(/\\/g, ""));
  if (!m || run.includes("\\")) return []; // an escaped spelling is not guessed
  const seg = m[1]!;
  const field = m[2] ?? "";
  const out: Array<{ canonical: string; length: number }> = [];
  for (let k = 4; k <= 8 && k < seg.length; k++) {
    const tag = seg.slice(0, seg.length - k);
    const hash = seg.slice(seg.length - k);
    if (!/^[0-9a-f]+$/.test(hash) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(tag)) continue;
    const base = `$MDU:${tag}[${hash}]`;
    if (field !== "") out.push({ canonical: base + field, length: 5 + seg.length + field.length });
    out.push({ canonical: base, length: 5 + seg.length });
  }
  return out;
}

/** True when the character after a token spelled `len` long in `rest` ends
 *  it: nothing, or anything that cannot continue the token's grammar. */
function endsToken(rest: string, len: number): boolean {
  const next = rest[len];
  if (next === undefined) return true;
  if (/[A-Za-z0-9_[\]\\]/.test(next)) return false;
  return !(next === "." && /[A-Za-z_]/.test(rest[len + 1] ?? ""));
}

/** A `$MDU` run that ends a row's text (its last non-blank glyph): the head
 *  of a unit the TUI may have soft-wrapped onto the next row. */
const RUN_AT_END_RE = /\\?\$MDU[A-Za-z0-9_:[\].\/\\]*$/;
/** The leading glyphs of a row that can continue such a run (no `$`: a row
 *  that starts a token or a continuation marker is its own unit). */
const LEAD_RE = /^( *)([A-Za-z0-9_:[\].\/\\]+)/;

/**
 * The unit a soft wrap split between two rows (differential-interactive.md
 * §35): OpenCode's renderer breaks a word that does not fit at its
 * punctuation (`$MDU:nomodel_read[` / `0155]/1:3:78:78`), so neither row
 * holds a whole token. `upper` is the upper row's text (right-trimmed),
 * `lower` the next row's. Returns where the unit starts on the upper row, how
 * many of its glyphs sit at the start of the lower row (after its indent),
 * and the unit, when the two pieces joined parse as ONE token or reserve
 * head that spans the break and ends there; else null. Pure.
 */
export function softWrapJoin(
  upper: string,
  lower: string,
  concealed?: ConcealedMatcher,
): { index: number; upperLength: number; lowerIndex: number; lowerLength: number; unit: UnitAt } | null {
  const r = RUN_AT_END_RE.exec(upper);
  if (!r) return null;
  const lead = LEAD_RE.exec(lower);
  if (!lead) return null;
  const run = r[0];
  const joined = run + lead[2]!;
  let canonical: string;
  let tokenLength: number;
  const tok = new RegExp(`^(?:${SYMBOL_TOKEN_RE.source})`).exec(joined);
  if (tok) {
    canonical = tok[0].replace(/\\/g, "");
    tokenLength = tok[0].length;
  } else {
    const hit = concealed?.(joined);
    if (!hit) return null;
    canonical = hit.canonical;
    tokenLength = hit.length;
  }
  const suffix = parseHeadSuffix(joined.slice(tokenLength, tokenLength + HEAD_SUFFIX_MAX));
  const unitLength = tokenLength + (suffix?.length ?? 0);
  if (unitLength <= run.length) return null; // the upper row holds the whole unit
  if (!suffix && !endsToken(joined, tokenLength)) return null;
  if (suffix && /[A-Za-z0-9_]/.test(joined[unitLength] ?? "")) return null;
  return {
    index: r.index,
    upperLength: run.length,
    lowerIndex: lead[1]!.length,
    lowerLength: unitLength - run.length,
    unit: { canonical, tokenLength, suffix },
  };
}

/** A relative row move (CUU/CUD) from row `from` to row `to` (0-based). */
function moveRows(from: number, to: number): string {
  if (to < from) return `\x1b[${from - to}A`;
  if (to > from) return `\x1b[${to - from}B`;
  return "";
}

/** One screen cell that starts a glyph (wide-glyph continuation cells are
 *  folded into the glyph's `width`). */
interface Cell {
  ch: string;
  width: number;
}

/** A run of symbol-grammar bytes from `$MDU` (or its Markdown-escaped
 *  `\$MDU`) on: a token or reserve head (`$MDU:tag[hash].field/1:N`), a
 *  continuation marker (`$MDU/hash/i`), or any prefix or fragment of one.
 *  All ASCII, so one byte is one column (maskFragments). */
const MASK_RUN_RE = /\\?\$MDU[A-Za-z0-9_:[\].\/\\]*/g;

/** A MASK_RUN_RE run that the next escape sequence cuts off, styling (SGR)
 *  and erase-to-end (EL) looked through: the stream filter's glue set, so
 *  what follows is a write-head move or a mode toggle (filter.ts
 *  GLUE_ESCAPE). CUT_AT_END_RE also takes a run that ends the write, for a
 *  read boundary inside the escape (the filter holds the partial escape and
 *  lets the run go). */
const GLUE = "\\x1b\\[[0-9;:]*[mK]";
const CUT = `\\x1b(?!\\[[0-9;:]*[mK])`;
const CUT_RUN_RE = new RegExp(`${MASK_RUN_RE.source}(?=(?:${GLUE})*${CUT})`, "g");
const CUT_AT_END_RE = new RegExp(`${MASK_RUN_RE.source}(?=(?:${GLUE})*(?:${CUT}|$))`, "g");
/** A whole splice unit (escapes stripped): a token with an optional field
 *  path, a reserve head (`T/1:N`, `T/1:N:W:F`) or a continuation marker. */
const WHOLE_UNIT_RE = new RegExp(
  `^(?:${SYMBOL_TOKEN_RE.source}(?:\\/1:[0-9]{1,3}(?::[0-9]{1,4}:[0-9]{1,4})?)?|\\$MDU\\/[0-9a-f]{4,8}\\/[1-9][0-9]{0,2})$`,
);

/** The main screen's mask (maskFragments): every INCOMPLETE run the next
 *  escape cuts off, written as spaces of the same width. A whole unit the
 *  stream let through (one the arbiter does not know) is left as is.
 *  `escapeNext`: the bytes after `out` (the stream filter's held tail) start
 *  an escape, so a run that ends `out` is cut off too. */
export function splitFragments(out: string, escapeNext = false): string {
  const re = escapeNext ? CUT_AT_END_RE : CUT_RUN_RE;
  re.lastIndex = 0;
  return out.replace(re, (run) => (WHOLE_UNIT_RE.test(run.replace(/\\/g, "")) ? run : " ".repeat(run.length)));
}

const DEFAULT_UNKNOWN_RETRY_MS = 300;
/** Bound the value/unknown caches (a session mints at most this many DISTINCT
 *  tokens before the oldest entries are forgotten — re-resolved on demand). */
const CACHE_MAX = 2048;

// glyphWidth (the wide-glyph width estimate) lives in filter.ts since
// 2026-09-20 (frameSafeValue's tab expansion needs it); re-exported here for
// the existing importers.
export { glyphWidth };

/** The cells of one buffer line, glyph-start cells only, in column order. */
function lineCells(line: IBufferLine | undefined, cols: number): Cell[] {
  const cells: Cell[] = [];
  if (!line) return cells;
  for (let x = 0; x < cols; x++) {
    const c = line.getCell(x);
    if (!c) break;
    const w = c.getWidth();
    if (w === 0) continue; // continuation of the previous wide glyph
    const ch = c.getChars();
    cells.push({ ch: ch === "" ? " " : ch, width: w });
  }
  return cells;
}

/** Cells → the row's text plus, per text index, the column the glyph starts
 *  at (the index map the token scan needs — a wide glyph before a token
 *  shifts every later column by one). */
function rowText(cells: Cell[]): { text: string; colOf: number[] } {
  let text = "";
  const colOf: number[] = [];
  let col = 0;
  for (const c of cells) {
    for (let i = 0; i < c.ch.length; i++) colOf.push(col); // surrogate pairs share a column
    text += c.ch;
    col += c.width;
  }
  return { text, colOf };
}

/** Cells → a per-COLUMN array (continuation columns hold ""), right-trimmed
 *  of blank cells, for column-exact comparison of two rows. */
function columns(cells: Cell[]): string[] {
  const out: string[] = [];
  for (const c of cells) {
    out.push(c.ch);
    for (let i = 1; i < c.width; i++) out.push("");
  }
  while (out.length && (out[out.length - 1] === " " || out[out.length - 1] === "")) out.pop();
  return out;
}

/** Split a string into glyph cells (code points, width-estimated). */
function textCells(s: string): Cell[] {
  return [...s].map((ch) => ({ ch, width: glyphWidth(ch) }));
}

/** Clip a cell row to `cols` columns (a wide glyph that would straddle the
 *  edge is dropped, like a terminal with auto-wrap off would clip it). */
function clipCells(cells: Cell[], cols: number): Cell[] {
  const out: Cell[] = [];
  let used = 0;
  for (const c of cells) {
    if (used + c.width > cols) break;
    out.push(c);
    used += c.width;
  }
  return out;
}

export class ScreenReconciler {
  private tui: Terminal;
  private human: Terminal;
  private cols: number;
  private rows: number;
  private pending: Promise<void> = Promise.resolve();
  /** Rows (0-based) whose real content this module last painted — they are
   *  re-checked even when no token is on them any more (the TUI's cell-diff
   *  may have left our value bytes where it now believes other text is). */
  private readonly owned = new Set<number>();
  /** MAIN-screen rows this module last painted, as markers on the TUI
   *  model's normal buffer: the main screen SCROLLS (the inline renderer's
   *  line feeds at the bottom row), so a row index would go stale; a marker
   *  follows its line and is disposed when the line scrolls off. */
  private readonly mainOwned = new Set<IMarker>();
  private readonly values = new Map<string, string>();
  private readonly unknownAt = new Map<string, number>();
  /** Concealed spelling (§35) → the canonical token it stands for, for every
   *  token resolved this session; null when two known tokens conceal alike
   *  (ambiguous: neither is painted from that spelling). */
  private readonly concealedKnown = new Map<string, string | null>();
  private readonly unknownRetryMs: number;
  private readonly reserve: ReserveValueCache;
  /** Repaints emitted so far (observability / tests). */
  repaints = 0;

  constructor(
    private readonly resolver: ReplyResolver,
    opts: ScreenReconcilerOptions,
  ) {
    this.cols = Math.max(1, opts.cols);
    this.rows = Math.max(1, opts.rows);
    this.unknownRetryMs = opts.unknownRetryMs ?? DEFAULT_UNKNOWN_RETRY_MS;
    this.reserve = opts.reserveCache ?? new ReserveValueCache();
    this.blockLookup = opts.blockLookup;
    this.onResolve = opts.onResolve;
    this.tui = new Terminal({ cols: this.cols, rows: this.rows, allowProposedApi: true, scrollback: 0 });
    this.human = new Terminal({ cols: this.cols, rows: this.rows, allowProposedApi: true, scrollback: 0 });
  }

  private readonly onResolve: ScreenReconcilerOptions["onResolve"];
  private readonly blockLookup: ScreenReconcilerOptions["blockLookup"];
  /** Hashes whose block the arbiter did not know (or could not be asked),
   *  and when: asked again only after unknownRetryMs. */
  private readonly blockUnknownAt = new Map<string, number>();

  /** Bytes the CHILD wrote (what the TUI believes is on screen). `held` is
   *  how many of the LAST bytes written so far the stream filter still holds
   *  (filter.ts `held`: a possible in-flight token, a carried escape): they
   *  wait here and reach the TUI model only when a later call releases them,
   *  so both models describe the same moment. A model that ran ahead of the
   *  terminal put the TUI's cursor a row below the real one whenever a read
   *  ended just after a reserve head's line break (the head held), and the
   *  relative repaint of the head row then landed on the row above it
   *  (reply-row-reservation.md §3.7, "Both models see the same bytes"). */
  feedTui(bytes: string, held = 0): void {
    const all = this.tuiHeld + bytes;
    const keep = Math.min(Math.max(0, held), all.length);
    const release = all.slice(0, all.length - keep);
    this.tuiHeld = all.slice(all.length - keep);
    if (release === "") return;
    this.pending = this.pending.then(() => new Promise<void>((r) => this.tui.write(release, r)));
  }
  /** The child's bytes the stream filter still holds (see feedTui). */
  private tuiHeld = "";

  /** Bytes that reached the HUMAN'S terminal (the filter's output, our own
   *  repaints included — the caller feeds exactly what it wrote to stdout). */
  feedHuman(bytes: string): void {
    if (bytes === "") return;
    this.pending = this.pending.then(() => new Promise<void>((r) => this.human.write(bytes, r)));
  }

  /**
   * The stream filter's output for a write, made safe to send BEFORE the
   * reconcile that follows it: while the TUI is on the ALTERNATE screen,
   * every `$MDU` run the stream let through (a token prefix or a marker
   * fragment a cell diff split around a cursor move, e.g. `$MDU/` CHA
   * `101/3`; an unknown token; prose about the grammar) is replaced by
   * spaces of the same width, so the cursor lands exactly where the TUI's
   * bytes put it and no symbol byte reaches the human's terminal. The next
   * reconcile() paints every RESOLVABLE unit on the TUI's rows as before (the
   * fragment's row, once the TUI's cells spell a whole marker or token). The
   * cells that stay unresolvable (an unknown token, prose about the grammar,
   * a fragment whose frame a read boundary cut short) get the TUI's own cells
   * back one reconcile LATER, after the next write or the relay's idle drain:
   * every row whose TUI cells hold `$MDU` is re-read then, so an unknown
   * token stays an opaque token and prose stays prose, but a frame cut right
   * after `$MDU/` is completed by its next read before anything is restored
   * (restoring at once would send `$MDU/content follows:` raw). Call it after
   * feedTui() for the same write (the screen it judges is the TUI's after the
   * write), and feed the human model what it returns.
   *
   * Main screen: only a SPLIT FRAGMENT is masked (splitFragments): an
   * INCOMPLETE `$MDU` run (not a whole token, reserve head or continuation
   * marker) that the next escape sequence cuts off, styling looked through.
   * That is the shape of an inline cell diff that skips a cell the previous
   * frame already holds (`$MDU:` CHA `omodel_Read[5ccd]` over `Running…`,
   * differential-interactive.md §30); the reconcile that follows treats the
   * write's token rows as the alternate screen's (reconcile, `maskPass`),
   * and an unresolvable fragment gets the TUI's cells back one reconcile
   * later. Every other run (a complete token the arbiter does not know,
   * prose about the grammar) goes out as the stream wrote it, because a
   * masked run on a row that scrolls away within the write stays blank
   * (§19.1); a split fragment on such a row would have stayed raw instead.
   * Never throws: a modeling surprise returns `out` unchanged.
   */
  async maskFragments(out: string): Promise<string> {
    if (!out.includes("$MDU")) return out;
    try {
      await this.pending;
      const alt = this.fullscreen;
      let masked: string;
      if (alt) {
        MASK_RUN_RE.lastIndex = 0;
        masked = out.replace(MASK_RUN_RE, (run) => " ".repeat(run.length));
      } else {
        // tuiHeld: the child's bytes the stream filter still holds (feedTui
        // ran for this write first); a partial escape there cuts off a run
        // that ends this output.
        masked = splitFragments(out, this.tuiHeld.startsWith("\x1b"));
      }
      if (masked !== out) {
        this.maskAge = 0;
        this.maskAlt = alt;
      }
      return masked;
    } catch {
      return out;
    }
  }
  /** maskFragments blanked a run whose cells are still to be restored:
   *  null, none; 0, in the write just made (its frame may be incomplete);
   *  1, a reconcile has run since, so the next one re-reads the rows. */
  private maskAge: number | null = null;
  /** The screen the pending mask was made on (a mask whose buffer is gone
   *  has nothing left to restore). */
  private maskAlt = false;
  /** True while masked cells wait for their restore pass: the relay's idle
   *  drain re-arms on it, so a TUI that goes quiet still gets its truth. */
  get restorePending(): boolean {
    return this.maskAge !== null;
  }

  /** Wait for every queued write to land in both models. */
  settle(): Promise<void> {
    return this.pending;
  }

  /** Both models follow the terminal's size (the relay forwards SIGWINCH and
   *  the pty reflows; so must the models). */
  async resize(cols: number, rows: number): Promise<void> {
    await this.pending;
    this.cols = Math.max(1, cols);
    this.rows = Math.max(1, rows);
    this.tui.resize(this.cols, this.rows);
    this.human.resize(this.cols, this.rows);
    this.owned.clear();
    this.releaseMain();
  }

  /** True while the TUI is on the alternate screen (every token-bearing row
   *  is reconciled; on the main screen only reserve-block rows are). */
  get fullscreen(): boolean {
    return this.tui.buffer.active.type === "alternate";
  }

  /** The TUI's own belief of its screen, right-trimmed (tests / diagnostics). */
  async tuiLines(): Promise<string[]> {
    await this.pending;
    return this.linesOf(this.tui);
  }

  /** What the human's terminal shows, right-trimmed (tests / diagnostics). */
  async humanLines(): Promise<string[]> {
    await this.pending;
    return this.linesOf(this.human);
  }

  private linesOf(t: Terminal): string[] {
    const buf = t.buffer.active;
    const lines: string[] = [];
    for (let y = 0; y < this.rows; y++) {
      lines.push(rowText(lineCells(buf.getLine(y), this.cols)).text.trimEnd());
    }
    return lines;
  }

  /**
   * Reconcile the rows that carry a splice unit (or that this module painted
   * before) and return the repaint bytes — ALREADY fed to the human model; the
   * caller writes them to the terminal verbatim (empty when nothing differs).
   *   - ALTERNATE screen: every token-bearing row, and every reserve-block row.
   *   - MAIN screen: rows carrying a reserve-block marker (head or
   *     continuation), and, in the two reconciles after maskFragments masked
   *     a split fragment there (`maskPass`), every token-bearing row, as on
   *     the alternate screen; otherwise a token on the main screen keeps the
   *     stream-only path. The repaint addresses rows with RELATIVE moves from
   *     the TUI's cursor (the main screen does not start at the real
   *     terminal's top-left, so an absolute row would miss; relative distances
   *     are what the TUI and the terminal agree on).
   * Never throws: a modeling surprise or an unreachable arbiter yields ""
   * (utility posture).
   */
  async reconcile(now = Date.now()): Promise<string> {
    try {
      await this.pending;
      const alt = this.fullscreen;
      if (!alt) this.owned.clear();
      // A masked stream write (maskFragments), one reconcile on: every row
      // whose TUI cells hold `$MDU` is re-read this pass, resolvable or not,
      // so the cells the mask blanked get the TUI's truth back.
      let recheck = false;
      // A mask is pending on this screen: its token rows are reconciled this
      // pass (on the main screen too, where they otherwise stay the stream's).
      let maskPass = false;
      if (this.maskAge !== null) {
        if (this.maskAlt !== alt) this.maskAge = null; // the masked buffer is gone
        else if (this.maskAge >= 1) {
          recheck = true;
          maskPass = true;
          this.maskAge = null;
        } else {
          maskPass = true;
          this.maskAge = 1;
        }
      }
      const tb = this.tui.buffer.active;
      const hb = this.human.buffer.active;
      const ownedRows = alt ? this.owned : this.mainOwnedRows();
      let out = "";
      let cy = tb.cursorY; // main screen: where the relative moves start from
      const regionActive = !alt && this.scrollRegionActive();
      const concealed: ConcealedMatcher = (rest) => this.matchConcealed(rest);
      const joins = await this.softWrapJoins(tb, now, concealed);
      for (let y = 0; y < this.rows; y++) {
        const tLine = tb.getLine(y);
        // Cheap pre-check (main screen, every write): no `$MDU` on the row, not ours.
        if (!alt && !ownedRows.has(y) && !joins.has(y) && !(tLine?.translateToString(true) ?? "").includes("$MDU")) continue;
        const tCells = lineCells(tLine, this.cols);
        const { text, colOf } = rowText(tCells);
        if (text.includes("$MDU:")) await this.learnConcealed(text, now);
        let subs = text.includes("$MDU") ? rowSubs(text, concealed) : [];
        // A unit a soft wrap split (§35): its piece on the upper row is
        // dropped, and the unit is painted where its piece on the lower row
        // starts (whatever the row scan read in those cells gives way).
        for (const j of joins.get(y) ?? []) {
          subs = subs.filter((s) => s.index + s.length <= j.index || s.index >= j.index + j.length);
          subs.push(j);
        }
        subs.sort((a, b) => a.index - b.index);
        const reserveRow = subs.some((s) => s.kind === "head" || s.kind === "cont");
        // Main screen: a token-only row is the stream's alone, but in a mask
        // pass (a split fragment of it went out blank), and but for a row
        // where a value is NARROWER than its token: the stream pads it to the
        // token's width (filter.ts renderValue, the TUI's cursor math), and
        // only the cell model can close that gap (`narrowOnly`, below).
        const narrowOnly = !alt && !reserveRow && !ownedRows.has(y) && !maskPass;
        // While the TUI holds a partial scroll region (Codex inserts history
        // lines under DECSTBM), a relative move can stop at a margin: such a
        // row waits for a later write, when the region is reset.
        if (narrowOnly && regionActive) continue;
        const keep = ownedRows.has(y) || (recheck && text.includes("$MDU"));
        if (subs.length === 0 && !keep) continue;

        // desired(row): the TUI's cells with each RESOLVED unit replaced.
        // On the alternate screen (on the main screen in a mask pass),
        // outside a restore pass, a `$MDU` run the
        // TUI's cells hold that the human's row does not already show there
        // (an unknown token, prose, a fragment of a frame still being
        // written) is painted BLANK and restored one reconcile later, so a
        // repaint never sends a symbol byte mid-frame either (maskFragments).
        const have = columns(lineCells(hb.getLine(y), this.cols));
        const holdBack = (alt || maskPass) && !recheck;
        const tuiCells = (from: number, to: number, atCol: number): Cell[] => {
          const seg = sliceCols(tCells, from, to);
          if (!holdBack) return seg;
          const r = blankNewRuns(seg, atCol, have, this.cols);
          if (r.blanked && this.maskAge === null) {
            this.maskAge = 1;
            this.maskAlt = alt;
          }
          return r.cells;
        };
        const width = (cells: Cell[]): number => cells.reduce((a, c) => a + c.width, 0);
        let desired: Cell[] = [];
        let consumedCol = 0; // columns of tCells already copied
        let substituted = 0;
        let narrowed = false; // a value narrower than its unit (no pad, CLOSE UP)
        let widened = false; // a value wider than its unit (shift right, clip)
        const resolvedHere: Array<[string, string]> = [];
        for (const m of subs) {
          const reported = resolvedHere.length;
          const rendered = await this.renderSub(m, now, resolvedHere);
          if (rendered === null) continue;
          const startCol = colOf[m.index]!;
          const endIdx = m.index + m.length;
          const endCol = endIdx < colOf.length ? colOf[endIdx]! : tCells.reduce((a, c) => a + c.width, 0);
          desired = desired.concat(tuiCells(consumedCol, startCol, width(desired)));
          const tokenCols = endCol - startCol;
          // The value's first glyph lands where desired(row) has grown to
          // (NOT the token's TUI column: an earlier, wider value on the row
          // shifts it). The cell model knows that column exactly, so a TAB in
          // the value expands to the next 8-column tab stop counted from the
          // session's TAB origin (the screen's column 0, or the TUI's text
          // column, reply-row-reservation.md §19.7), which is what the
          // vanilla screen shows (frameSafeValue's startCol form).
          const valueCol = desired.reduce((a, c) => a + c.width, 0);
          const vCells = textCells(frameSafeValue(rendered, valueCol, this.reserve.spliceTabOrigin));
          const vCols = vCells.reduce((a, c) => a + c.width, 0);
          // CLOSE UP (2026-10-05): a value narrower than its unit is NOT
          // padded to the unit's width; the cells the TUI painted after the
          // unit shift LEFT and the row's tail is erased (EL below), so the
          // human reads `KEY='value'`, never `KEY='value      '` (the stream
          // pads, for the TUI's cursor math; the repaint closes the gap).
          if (vCols < tokenCols) narrowed = true;
          else if (vCols > tokenCols) widened = true;
          // A token the human's row already shows resolved (the stream's
          // padded splice at the token's column, or an earlier close-up at
          // the value's) was reported by whoever painted it: a repaint that
          // only closes the gap reports nothing new.
          if (m.kind === "token" && (showsAt(have, startCol, vCells) || showsAt(have, valueCol, vCells))) {
            resolvedHere.length = reported;
          }
          desired = desired.concat(vCells);
          consumedCol = endCol;
          substituted += 1;
        }
        if (substituted === 0 && !keep) continue; // nothing resolvable here (yet)
        // A main-screen token row is taken only to close a narrower value's
        // gap; a row that also holds a WIDER value stays the stream's (its
        // wrap-off splice and column translation, differential-interactive.md
        // §10/§11), so the main screen's widening path is unchanged.
        if (narrowOnly && (!narrowed || widened)) continue;
        desired = clipCells(desired.concat(tuiCells(consumedCol, Infinity, width(desired))), this.cols);

        const want = columns(desired);
        let from = 0;
        while (from < want.length && from < have.length && want[from] === have[from]) from += 1;
        if (from === want.length && from === have.length) {
          // Already right (the stream splice did it, or a previous repaint).
          // A row holding a value is still OURS: the TUI believes it holds the
          // shorter marker, so a later cell diff that writes non-marker text
          // over it (no EL past the marker's width) leaves the value's tail
          // behind unless this row is reconciled again (the 33-row block's
          // `DIFF_S1_DONEnovember DL30END`, reply-row-reservation.md §3.7).
          if (substituted > 0) this.own(alt, y, ownedRows);
          else this.release(alt, y);
          continue;
        }
        if (from < want.length && want[from] === "") from -= 1; // never start inside a wide glyph
        let paint = "";
        let col = 0;
        for (const c of desired) {
          if (col >= from) paint += c.ch;
          col += c.width;
        }
        const paintedTo = col; // columns the row now spans (its right-trimmed content)
        if (alt) {
          out += `\x1b[${y + 1};${from + 1}H\x1b[0m${paint}`;
        } else {
          out += `${moveRows(cy, y)}\x1b[${from + 1}G\x1b[0m${paint}`;
          cy = y;
        }
        // Erase the rest of the row — unless the paint reached the last
        // column, where EL would erase the cell the pending-wrap cursor still
        // sits on.
        if (paintedTo < this.cols) out += "\x1b[K";
        if (substituted > 0) this.own(alt, y, ownedRows);
        else this.release(alt, y);
        for (const [tok, val] of resolvedHere) await this.emitResolve(tok, val);
      }
      if (out === "") return "";
      // Restore the cursor where the TUI believes it is (clamped: a pending-
      // wrap cursor reports one past the last column).
      const cx = Math.min(tb.cursorX, this.cols - 1) + 1;
      out += alt ? `\x1b[${tb.cursorY + 1};${cx}H` : `${moveRows(cy, tb.cursorY)}\x1b[${cx}G`;
      this.repaints += 1;
      this.feedHuman(out);
      await this.pending;
      return out;
    } catch {
      return ""; // utility posture: never worse than no repaint
    }
  }

  /** True when the TUI model holds a scroll region (DECSTBM) narrower than
   *  the screen. Read from the emulator's internals (no public API); unknown
   *  counts as none, the behavior every other main-screen repaint has. */
  private scrollRegionActive(): boolean {
    try {
      const b = (this.tui as unknown as { _core?: { buffer?: { scrollTop?: unknown; scrollBottom?: unknown } } })._core?.buffer;
      if (typeof b?.scrollTop !== "number" || typeof b.scrollBottom !== "number") return false;
      return b.scrollTop > 0 || b.scrollBottom < this.rows - 1;
    } catch {
      return false;
    }
  }

  /** The text one splice unit renders to (frameSafeValue is applied by the
   *  caller, at the unit's column), or null to leave the TUI's cells:
   *   - token: its value; null while unknown or unreachable;
   *   - head: row 1 of its block (v1: line 1; v2: row 1 of the layout, ""
   *     when F = 0) or the cap note, or `T (N lines)` when the value is
   *     unknown — reported once per value, whole;
   *   - continuation: row i of the block its hash's head announced (or the
   *     cap note), or "" (a blank row of the marker's width) when unknown;
   *   - drop: "" (the upper piece of a unit a soft wrap split, §35). */
  private async renderSub(m: RowSub, now: number, resolvedHere: Array<[string, string]>): Promise<string | null> {
    if (m.kind === "drop") return "";
    if (m.kind === "token") {
      const value = await this.lookup(m.canonical, now);
      if (value !== null) resolvedHere.push([m.canonical, value]);
      return value;
    }
    if (m.kind === "head") {
      let value = this.reserve.getValue(m.canonical) ?? null;
      if (value === null) {
        value = await this.lookup(m.canonical, now);
        if (value !== null) this.reserve.setValue(m.canonical, value);
      }
      this.reserve.noteHead(m.hash, m.canonical, m.n, m.w, m.f, this.cols);
      if (value === null) return unknownHeadText(m.canonical, m.n);
      if (this.reserve.firstReport(m.canonical)) resolvedHere.push([m.canonical, value]);
      return blockRowText(value, 1, this.reserve.headFor(m.hash) ?? m, this.cols);
    }
    const head = this.reserve.headFor(m.hash) ?? (await this.headFromArbiter(m.hash, now, resolvedHere));
    return head && head.value !== null ? blockRowText(head.value, m.i, head, this.cols) : "";
  }

  /** A continuation row whose head never reached the screen (§3.8): the
   *  block the proxy recorded, its head noted as if it had been seen, and
   *  its value resolved as a head's is. Undefined when there is no lookup,
   *  the arbiter has no record (asked again after the backoff), or the
   *  value is unknown. */
  private async headFromArbiter(
    hash: string, now: number, resolvedHere: Array<[string, string]>,
  ): Promise<ReturnType<ReserveValueCache["headFor"]>> {
    if (!this.blockLookup) return undefined;
    const askedAt = this.blockUnknownAt.get(hash);
    if (askedAt !== undefined && now - askedAt < this.unknownRetryMs) return undefined;
    let b: ReserveBlockInfo | null = null;
    try {
      b = await this.blockLookup(hash);
    } catch {
      b = null;
    }
    if (!b || typeof b.token !== "string" || typeof b.n !== "number") {
      this.remember(this.blockUnknownAt, hash, now);
      return undefined;
    }
    this.blockUnknownAt.delete(hash);
    this.reserve.noteHead(hash, b.token, b.n, b.width, b.first, this.cols);
    let value = this.reserve.getValue(b.token) ?? null;
    if (value === null) {
      value = await this.lookup(b.token, now);
      if (value !== null) this.reserve.setValue(b.token, value);
    }
    if (value !== null && this.reserve.firstReport(b.token)) resolvedHere.push([b.token, value]);
    return this.reserve.headFor(hash);
  }

  /** Viewport rows (0-based) of the live main-screen markers; disposed
   *  markers (their line scrolled off) are forgotten. */
  private mainOwnedRows(): Set<number> {
    const rows = new Set<number>();
    const base = this.tui.buffer.normal.baseY;
    for (const mk of this.mainOwned) {
      if (mk.isDisposed || mk.line < 0) {
        this.mainOwned.delete(mk);
        continue;
      }
      const y = mk.line - base;
      if (y >= 0 && y < this.rows) rows.add(y);
    }
    return rows;
  }

  private own(alt: boolean, y: number, ownedRows: Set<number>): void {
    if (alt) {
      this.owned.add(y);
      return;
    }
    if (ownedRows.has(y)) return;
    const mk = this.tui.registerMarker(y - this.tui.buffer.active.cursorY);
    if (mk) {
      this.mainOwned.add(mk);
      ownedRows.add(y);
    }
  }

  private release(alt: boolean, y: number): void {
    if (alt) {
      this.owned.delete(y);
      return;
    }
    const base = this.tui.buffer.normal.baseY;
    for (const mk of this.mainOwned) {
      if (mk.line - base === y) {
        mk.dispose();
        this.mainOwned.delete(mk);
      }
    }
  }

  private releaseMain(): void {
    for (const mk of this.mainOwned) mk.dispose();
    this.mainOwned.clear();
  }

  /** Value for a canonical token, or null when unknown (the arbiter returned
   *  it unchanged; retried after unknownRetryMs) or unreachable. */
  private async lookup(canonical: string, now: number): Promise<string | null> {
    const hit = this.values.get(canonical);
    if (hit !== undefined) return hit;
    const askedAt = this.unknownAt.get(canonical);
    if (askedAt !== undefined && now - askedAt < this.unknownRetryMs) return null;
    let resolved: string;
    try {
      resolved = await this.resolver.desymbolize(canonical);
    } catch {
      return null;
    }
    if (resolved === canonical) {
      this.remember(this.unknownAt, canonical, now);
      return null;
    }
    this.unknownAt.delete(canonical);
    this.remember(this.values, canonical, resolved);
    this.noteCanonical(canonical);
    return resolved;
  }

  /** Remember how a resolved token reads concealed (§35); a second token
   *  that conceals alike makes the spelling ambiguous for good. */
  private noteCanonical(canonical: string): void {
    const spelling = concealedSpelling(canonical);
    const prev = this.concealedKnown.get(spelling);
    if (prev === undefined) this.remember(this.concealedKnown, spelling, canonical);
    else if (prev !== null && prev !== canonical) this.concealedKnown.set(spelling, null);
  }

  /** The known token whose concealed spelling starts `rest` and ends there
   *  (the longest such spelling), or null — also when that spelling is
   *  ambiguous. Never guesses: a spelling is known only once its token
   *  resolved (lookup, or learnConcealed's candidates). */
  private matchConcealed(rest: string): { canonical: string; length: number } | null {
    let best: { spelling: string; canonical: string | null } | null = null;
    for (const [spelling, canonical] of this.concealedKnown) {
      if (!rest.startsWith(spelling) || !endsToken(rest, spelling.length)) continue;
      if (!best || spelling.length > best.spelling.length) best = { spelling, canonical };
    }
    return best && best.canonical !== null ? { canonical: best.canonical, length: best.spelling.length } : null;
  }

  /** Learn the concealed runs on a row that no resolved token explains yet
   *  (§35: a transcript the TUI re-rendered, concealed, before this module
   *  saw the bracketed token): each spelling the run could stand for
   *  (concealedCandidates) is asked once; whichever the arbiter knows is
   *  remembered by lookup. Unknown spellings wait unknownRetryMs. */
  private async learnConcealed(text: string, now: number): Promise<void> {
    for (const m of [...text.matchAll(CONCEALED_RUN_RE)]) {
      if (text[m.index + m[0].length] === "[") continue;
      const rest = text.slice(m.index);
      if (this.matchConcealed(rest)) continue;
      for (const c of concealedCandidates(m[0])) {
        if (endsToken(rest, c.length)) await this.lookup(c.canonical, now);
      }
    }
  }

  /** The units a soft wrap split between two rows of the TUI's screen
   *  (§35, softWrapJoin), by row: on the upper row a `drop` of its piece,
   *  on the lower row the unit itself where its piece starts. Only a unit
   *  whose value resolves is joined; otherwise both rows stay the TUI's
   *  (an unknown token stays opaque, as everywhere). */
  private async softWrapJoins(tb: IBuffer, now: number, concealed: ConcealedMatcher): Promise<Map<number, RowSub[]>> {
    const joins = new Map<number, RowSub[]>();
    const add = (y: number, s: RowSub): void => {
      const list = joins.get(y) ?? [];
      list.push(s);
      joins.set(y, list);
    };
    let lowerText: string | null = null;
    for (let y = 0; y + 1 < this.rows; y++) {
      const upperText = lowerText ?? (tb.getLine(y)?.translateToString(true) ?? "");
      lowerText = tb.getLine(y + 1)?.translateToString(true) ?? "";
      if (!upperText.includes("$MDU")) continue;
      // Rows are scanned as cell text (rowText): the same indices rowSubs uses.
      const upper = rowText(lineCells(tb.getLine(y), this.cols)).text.trimEnd();
      if (upper.includes("$MDU:")) await this.learnConcealed(upper, now);
      const lower = rowText(lineCells(tb.getLine(y + 1), this.cols)).text;
      const j = softWrapJoin(upper, lower, concealed);
      if (!j) continue;
      if ((await this.lookup(j.unit.canonical, now)) === null) continue;
      add(y, { kind: "drop", index: j.index, length: j.upperLength });
      add(y + 1, unitSub(j.lowerIndex, j.unit, j.lowerLength));
    }
    return joins;
  }

  private remember<V>(map: Map<string, V>, k: string, v: V): void {
    if (map.size >= CACHE_MAX) {
      const oldest = map.keys().next().value;
      if (oldest !== undefined) map.delete(oldest);
    }
    map.set(k, v);
  }

  private async emitResolve(before: string, after: string): Promise<void> {
    if (!this.onResolve) return;
    try {
      await this.onResolve(before, after);
    } catch {
      // Observability is best-effort, never disturbs the stream.
    }
  }

  dispose(): void {
    this.tui.dispose();
    this.human.dispose();
  }
}

/** `seg` (TUI cells that will land at column `atCol` of the human's row)
 *  with each `$MDU` run the human's row (`have`, per column) does not
 *  already show at that place replaced by blank cells (screen-reconcile's
 *  hold-back; runs are ASCII, one column per glyph). */
function blankNewRuns(seg: Cell[], atCol: number, have: string[], cols: number): { cells: Cell[]; blanked: boolean } {
  const { text, colOf } = rowText(seg);
  if (!text.includes("$MDU")) return { cells: seg, blanked: false };
  const cells = seg.slice();
  let blanked = false;
  MASK_RUN_RE.lastIndex = 0;
  for (const m of text.matchAll(MASK_RUN_RE)) {
    // Only the part left of the right edge can be on screen (a wider value
    // earlier on the row shifts the run right; the row clips there).
    const col = atCol + colOf[m.index]!;
    const shown = Math.max(0, Math.min(m[0].length, cols - col));
    if (have.slice(col, col + shown).join("") === m[0].slice(0, shown)) continue; // already on screen
    // Cell index of the run's first glyph: runs are ASCII, so cells and
    // text indices advance together from there.
    let k = 0;
    for (let i = 0; i < m.index; i += cells[k]!.ch.length, k += 1);
    for (let j = 0; j < m[0].length; j++) cells[k + j] = { ch: " ", width: 1 };
    blanked = true;
  }
  return { cells, blanked };
}

/** True when `have` (a human row, per column) shows `cells` from `col` on
 *  (blank cells past the row's right-trimmed end count as spaces). */
function showsAt(have: string[], col: number, cells: Cell[]): boolean {
  const want = columns(cells);
  if (want.length === 0) return false;
  for (let i = 0; i < want.length; i++) {
    if ((have[col + i] ?? " ") !== want[i]) return false;
  }
  return true;
}

/** The cells of a row between two COLUMN positions [from, to). */
function sliceCols(cells: Cell[], from: number, to: number): Cell[] {
  const out: Cell[] = [];
  let col = 0;
  for (const c of cells) {
    if (col >= from && col + c.width <= to) out.push(c);
    col += c.width;
    if (col >= to) break;
  }
  return out;
}
