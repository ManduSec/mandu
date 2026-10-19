/**
 * tiles-rows.ts — the session page's count tiles, row by row, from the
 * stylesheet's own numbers (dashboard.md §4.25 *The tiles fill their rows
 * evenly*). Shared by the unit test (`css-tiles-rows.test.ts`, the
 * stylesheet on disk) and the stack test (`tests/stack/agent-tiles-rows.test.ts`,
 * the served one).
 *
 * jsdom lays out nothing, so the rows are computed here. The tiles span
 * #main's column (files-name-room.ts `pageColumn`). `.tiles` holding n
 * tiles gets the columns the cascade gives it at a width: a
 * `.tiles:has(> .tile:nth-child(n):last-child)` rule whose width query holds
 * outranks `.tiles` (its specificity), and of two such rules the later
 * wins. `repeat(auto-fit, minmax(min(L, 100%), 1fr))` makes as many columns
 * of at least L as fit with the gaps, at least one and at most n (auto-fit
 * collapses the empty ones, and their gaps); `repeat(k, minmax(0, 1fr))`
 * makes k. Any other `.tiles` selector or columns value throws, so a
 * stylesheet change fails a test rather than drifting. Checked against a
 * headless Chromium at 16 widths from 320 to 1280 px with 1 to 7 tiles:
 * every arrangement the same (the breakpoints at 405, 614, 822, 1031 and
 * 1151 px included), and with the phone rule (2026-10-18) at 11 widths from
 * 280 to 613 px with 1 to 6 (the breakpoints at 304 and 405 px included).
 */
import { flattenCss, stripComments } from "./css-flatten.js";
import { fileNameRoom } from "./files-name-room.js";

/** How many tiles the page draws in the `secrets` mode, at most: reached
 *  the AI unmasked, masked, read before marked, blocked, sent, waiting
 *  (home.js renderAgent). A seventh, the untrusted items, is the frozen
 *  masking modes' only. */
export const MAX_TILES = 6;

/** The tiles' grid at one width: its declared columns, how many columns,
 *  the tiles in each row, and each tile's width. */
export interface TilesGrid { tracks: string; cols: number; rows: number[]; tile: number }

const HAS = /^\.tiles:has\(> \.tile:nth-child\((\d+)\):last-child\)$/;

/** A length in px (`180px`). */
function px(v: string): number {
  const m = /^(\d+(?:\.\d+)?)px$/.exec(v.trim());
  if (!m) throw new Error(`tiles-rows: not a length in px: "${v}"`);
  return Number(m[1]);
}

/** The model over the product page's stylesheet text `css` (mandu.css and
 *  app.css, as index.html links them). */
export function tilesRows(css: string) {
  const room = fileNameRoom(css);
  const selectors = new Set(flattenCss(stripComments(css)).flatMap((r) => r.selectors).filter((s) => /^\.tiles\b/.test(s)));
  const counted = new Map<number, string>();
  for (const s of selectors) {
    if (s === ".tiles") continue;
    const m = HAS.exec(s);
    if (!m) throw new Error(`tiles-rows: a .tiles rule this model cannot read: "${s}"`);
    counted.set(Number(m[1]), s);
  }
  // The rules hold their numbers in declarations the cascade reaches; a
  // selector declared only for other properties is not a columns rule.
  const declared = (w: number, selector: string): string | null => {
    try { return room.at(w, selector, "grid-template-columns"); } catch { return null; }
  };
  const grid = (w: number, n: number, tracks: string): TilesGrid => {
    const box = room.pageColumn(w);
    const gap = px(room.at(w, ".tiles", "gap"));
    const t = tracks.replace(/\s+/g, " ").trim();
    const auto = /^repeat\(auto-fit, minmax\(min\((\d+(?:\.\d+)?px), 100%\), 1fr\)\)$/.exec(t);
    const fixed = /^repeat\((\d+), minmax\(0, 1fr\)\)$/.exec(t);
    let cols: number;
    if (auto) cols = Math.min(n, Math.max(1, Math.floor((box + gap) / (px(auto[1]!) + gap))));
    else if (fixed) cols = Number(fixed[1]);
    else throw new Error(`tiles-rows: columns this model cannot read at ${w}px: "${tracks}"`);
    const rows: number[] = [];
    for (let left = n; left > 0; left -= cols) rows.push(Math.min(cols, left));
    return { tracks: t, cols, rows, tile: (box - (cols - 1) * gap) / cols };
  };
  /** `.tiles` alone: what auto-fit draws, as before the rows were evened. */
  const autoFit = (w: number, n: number): TilesGrid => grid(w, n, room.at(w, ".tiles", "grid-template-columns"));
  /** What the stylesheet draws for `n` tiles in a window `w` px wide. */
  const at = (w: number, n: number): TilesGrid => {
    const s = counted.get(n);
    const has = s ? declared(w, s) : null;
    return grid(w, n, has ?? room.at(w, ".tiles", "grid-template-columns"));
  };
  /** The least width `.tiles` gives a tile, from its auto-fit minimum. */
  const tileMin = (w: number): number => {
    const m = /minmax\(min\((\d+(?:\.\d+)?px), 100%\)/.exec(room.at(w, ".tiles", "grid-template-columns"));
    if (!m) throw new Error("tiles-rows: .tiles has no auto-fit minimum");
    return px(m[1]!);
  };
  return { at, autoFit, tileMin, counted: [...counted.keys()].sort((a, b) => a - b) };
}

/** No row holds two tiles more than another. */
export function even(g: TilesGrid): boolean {
  return Math.max(...g.rows) - Math.min(...g.rows) <= 1;
}

/** The tiles' row arrangement as Chromium's probe printed it (`3+1`). */
export function arrangement(g: TilesGrid): string {
  return g.rows.join("+");
}
