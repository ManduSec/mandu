/**
 * nav-row.ts — the product page's page links on a phone, from the
 * stylesheet's own numbers (dashboard.md §4.25 *The page links fit a small
 * phone*). Shared by the unit test (`css-nav-fits.test.ts`, the stylesheet
 * on disk) and the stack test (`tests/stack/nav-fits-count.test.ts`, the
 * served one).
 *
 * jsdom lays out nothing, so the room the links need is computed here. At
 * 719 px and narrower (640 until Scan joined, 2026-10-21) the nav is a row
 * of its own under the brand and the status (`order: 3; flex-basis:
 * 100%`), as wide as the top bar's content box: the window less
 * `.top-inner`'s side padding. Each link is its word and its side padding;
 * the Approvals link adds its gap and the count's pill (the digits and the
 * pill's side padding). In a flex row the links sit `#nav`'s gap apart. A
 * link never shrinks below its word (a flex item's automatic minimum), so
 * what does not fit runs past the row, which then scrolls. In a grid of
 * `repeat(N, auto)` columns (narrower than 500 px) each column is as wide
 * as its widest link, the columns `#nav`'s gap apart, and `rows` counts
 * the rows. A link the stylesheet hides (`display: none`) takes no room,
 * and a `min-width` makes a short link as wide as it says.
 *
 * Wider than that the links share one bar with the brand and the status
 * (`bar`): the bar's content box less the brand, the status and the two
 * gaps between them is what the links have.
 *
 * The words' widths are what a headless Chromium measured with the bundled
 * IBM Plex Sans: each word at 15 px, at 400 and at the current page's 500,
 * and each digit of the count at 12 px, 600. The model reads nothing else
 * of the text: a word it has no width for, another size or weight, or a
 * nav that is not a row of its own throws, so a change there fails a test
 * rather than drifting. Checked against that Chromium at 320 px with a
 * count of 1: 316 px, 317 on Approvals (where its word is 500), under the
 * links' old room (10 px a side, 2 px apart); 275 and 276 under the
 * narrow rule; with 12, 323/324 and 282/283. With History (2026-10-18)
 * and Home hidden: 275/276 (Approvals or History current, where their
 * words are 500) at 320 px with a count of 1, 282/283 with 12; 324/325
 * and 331/332 at 375 px; and at 641 px with 99, 363 (Settings current) under the middle rule
 * beside the 66 px brand and the 94 px "Protection on". With Scan
 * (2026-10-21; its word 34 px at both weights) and Home shown again, as
 * two rows of three below 500 px: 255.67 (Approvals current, 1 waiting),
 * 261 (History current, 12), 262 (Approvals, 99) and 225 (Scan current,
 * none) at 320, 375 and 499 px; one row at 500 px: 443.67, 450, 450 and
 * 413 of its 460; in the bar at 720 px (each link at least 50 px),
 * 409.67, 416, 416 (5.31 to spare beside "Protection unknown") and 379; at
 * 840 px, 511.67, 518, 518 (6.53 to spare beside "Protection unknown") and
 * 481.
 */
import { fileNameRoom, px, sidePadding } from "./files-name-room.js";

/** Each page link's word: its width in px at 15 px, at 400 and at 500. */
export const WORD_PX: Readonly<Record<string, readonly [number, number]>> = {
  Home: [40, 40],
  Approvals: [68, 69],
  Rules: [38, 38],
  Settings: [55, 55],
  History: [48, 49],
  Scan: [34, 34],
};
/** The brand "Mandu" at 21 px, 700, its letters 0.02em closer. */
export const BRAND_PX = 66;
/** The status at 13 px, its dot and gap included: what it says, and its width. */
export const STATUS_PX: Readonly<Record<string, number>> = {
  "Protection on": 94,
  "Protection off": 95,
  "Not connected": 102,
  "Protection unknown": 132,
};
/** A digit of the count at 12 px, 600 (IBM Plex Sans's digits are all as wide). */
export const DIGIT_PX = 7;
/** What the row keeps to spare: another platform may draw a word a pixel
 *  or two wider than the Chromium the widths come from. */
export const MARGIN = 4;

/** The links as the page draws them: their words in order, the page each
 *  opens (its `data-page-link`), the current page's place among them (-1:
 *  none), and the count's text ("" when it is hidden). */
export interface DrawnNav { words: string[]; pages: string[]; current: number; count: string }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The nav of a page in jsdom (`doc`), as it is drawn. */
export function drawnNav(doc: El): DrawnNav {
  const links = [...doc.querySelectorAll("#nav a")] as El[];
  const count = doc.getElementById("nav-approvals-count");
  return {
    words: links.map((a) => String(a.firstChild?.textContent ?? "").trim()),
    pages: links.map((a) => String(a.getAttribute("data-page-link"))),
    current: links.findIndex((a) => a.getAttribute("aria-current") === "page"),
    count: count && !count.hidden ? String(count.textContent) : "",
  };
}

/** The model over the product page's stylesheet text `css` (mandu.css and
 *  app.css, as index.html links them). */
export function navRow(css: string) {
  const room = fileNameRoom(css);
  const at = room.at;
  const declares = (w: number, selector: string, prop: string): string | null => {
    try { return at(w, selector, prop); } catch { return null; }
  };
  const expect = (w: number, selector: string, prop: string, value: string): void => {
    const v = declares(w, selector, prop);
    if (v !== value) throw new Error(`nav-row: ${selector} ${prop} is ${v ?? "not declared"} at ${w}px; the widths were measured at ${value}`);
  };
  /** The row's width in a window `w` px wide: the top bar's content box. */
  const row = (w: number): number => {
    if (at(w, "*", "box-sizing") !== "border-box") throw new Error("nav-row: the model needs every box sized border-box");
    if (declares(w, "#nav", "order") !== "3" || declares(w, "#nav", "flex-basis") !== "100%") throw new Error(`nav-row: the nav is not a row of its own at ${w}px`);
    return Math.min(w, px(at(w, ".top-inner", "max-width"), w)) - sidePadding(at(w, ".top-inner", "padding"), w);
  };
  /** Does the stylesheet hide the link to `page` in a window `w` px wide? */
  const hidden = (w: number, page: string): boolean => {
    const v = declares(w, `#nav a[data-page-link="${page}"]`, "display");
    if (v !== null && v !== "none") throw new Error(`nav-row: the ${page} link is display: ${v} at ${w}px`);
    return v === "none";
  };
  /** The px the links need in a window `w` px wide, as `nav` draws them. */
  const need = (w: number, nav: DrawnNav): number => {
    expect(w, "#nav a", "font-size", "15px");
    if (declares(w, "#nav a", "font-weight") !== null) throw new Error("nav-row: a link's word was measured at 400");
    expect(w, '#nav a[aria-current="page"]', "font-weight", "500");
    const pad = sidePadding(at(w, "#nav a", "padding"), w);
    const least = declares(w, "#nav a", "min-width");
    const min = least === null ? 0 : px(least, w);
    if (nav.pages.length !== nav.words.length) throw new Error("nav-row: a link without its page");
    let pill = 0;
    if (nav.count !== "") {
      if (!/^\d+$/.test(nav.count)) throw new Error(`nav-row: the count "${nav.count}" is not digits`);
      expect(w, ".count", "font-size", "12px");
      expect(w, ".count", "font-weight", "600");
      pill = px(at(w, "#nav a", "gap"), w) + nav.count.length * DIGIT_PX + sidePadding(at(w, ".count", "padding"), w);
    }
    // Each shown link's width: its word, its padding, the count in Approvals.
    const widths: number[] = [];
    nav.words.forEach((word, i) => {
      const width = WORD_PX[word];
      if (!width) throw new Error(`nav-row: no width measured for the link "${word}"`);
      if (hidden(w, nav.pages[i]!)) {
        if (nav.pages[i] === "approvals") throw new Error("nav-row: the link that carries the count is hidden");
        return;
      }
      widths.push(Math.max(min, width[i === nav.current ? 1 : 0] + pad + (nav.pages[i] === "approvals" ? pill : 0)));
    });
    const gap = px(at(w, "#nav", "gap"), w);
    const cols = columns(w);
    if (cols === null) return widths.reduce((a, b) => a + b, 0) + Math.max(0, widths.length - 1) * gap;
    // A grid of `cols` auto columns: each as wide as its widest link.
    const colWidth = Array.from({ length: cols }, (_, c) => Math.max(0, ...widths.filter((_, i) => i % cols === c)));
    return colWidth.reduce((a, b) => a + b, 0) + (cols - 1) * gap;
  };
  /** The nav's columns when it is a grid in a window `w` px wide (null: a
   *  flex row). Only `repeat(N, auto)` is modelled. */
  const columns = (w: number): number | null => {
    const display = declares(w, "#nav", "display");
    if (display === "flex") return null;
    if (display !== "grid") throw new Error(`nav-row: the nav is display: ${display} at ${w}px`);
    const m = /^repeat\((\d+),\s*auto\)$/.exec(at(w, "#nav", "grid-template-columns"));
    if (!m) throw new Error(`nav-row: the grid's columns are ${at(w, "#nav", "grid-template-columns")} at ${w}px; only repeat(N, auto) is modelled`);
    return Number(m[1]);
  };
  /** The rows the links take in a window `w` px wide. */
  const rows = (w: number, nav: DrawnNav): number => {
    const cols = columns(w);
    const shown = nav.pages.filter((p) => !hidden(w, p)).length;
    return cols === null ? 1 : Math.ceil(shown / cols);
  };
  /** What the row has to spare (negative: the links run past it). */
  const spare = (w: number, nav: DrawnNav): number => row(w) - need(w, nav);
  /** Wider than 640 px, what the bar has to spare in a window `w` px wide
   *  with the brand, the links as `nav` draws them and the status saying
   *  `status` (negative: the status runs past its room). */
  const bar = (w: number, nav: DrawnNav, status: string): number => {
    if (declares(w, "#nav", "order") !== null) throw new Error(`nav-row: the nav is a row of its own at ${w}px`);
    if (at(w, "*", "box-sizing") !== "border-box") throw new Error("nav-row: the model needs every box sized border-box");
    expect(w, ".brand", "font-size", "21px");
    expect(w, ".brand", "font-weight", "700");
    expect(w, ".top-status", "font-size", "13px");
    expect(w, ".top-status", "gap", "8px");
    const said = STATUS_PX[status];
    if (said === undefined) throw new Error(`nav-row: no width measured for the status "${status}"`);
    const content = Math.min(w, px(at(w, ".top-inner", "max-width"), w)) - sidePadding(at(w, ".top-inner", "padding"), w);
    return content - BRAND_PX - said - 2 * px(at(w, ".top-inner", "gap"), w) - need(w, nav);
  };
  return { at, declares, row, need, spare, bar, hidden, columns, rows };
}
