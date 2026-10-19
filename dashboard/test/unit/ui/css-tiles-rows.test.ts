/**
 * css-tiles-rows — a session's page draws its count tiles in even rows: no
 * tile sits alone under the others when the same tiles fit in even rows
 * (dashboard.md §4.25 *The tiles fill their rows evenly*). Mandu-new.
 *
 * The tiles (`#agent-facts`, one per count: reached the AI unmasked,
 * masked, read before marked, blocked, sent, waiting) were a plain
 * `repeat(auto-fit, minmax(min(180px, 100%), 1fr))` grid: as many in a row
 * as fit, the rest on the next. A headless Chromium over the served page
 * drew the tour's four tiles as 3 + 1 at 614 to 821 px (at 720 px "send
 * with a real value filled in" alone under three, beside two empty cells),
 * five tiles as 4 + 1 and six as 4 + 2 from 822 px (and 5 + 1 at 1031 to
 * 1150 px, where five fit). Now the rows stay as few and are filled evenly:
 * 2 + 2, 3 + 2, 3 + 3; five keep their one row where five fit.
 *
 * jsdom has no layout, so:
 *   E1  the geometry, from the stylesheet's own numbers (tiles-rows.ts over
 *       #main's frame): for 1 to 6 tiles at every window from 320 to
 *       1600 px, the rows are as few as auto-fit's and no row holds two
 *       tiles more than another;
 *   E2  no tile that shares its row is narrower than auto-fit's 180 px,
 *       and no column is left empty;
 *   E3  wherever auto-fit's rows were already even, the stylesheet draws
 *       exactly auto-fit's columns: 1 to 3 tiles at every width, four
 *       below 614 px and from 822 px, five and six below 822 px;
 *   E4  the session page in jsdom, its styles as each width applies them:
 *       four tiles at 720 px in two columns and at 613 and 822 px as
 *       auto-fit; three at 720 px as auto-fit; five at 1280 px in three
 *       and at 1040 px in five; six at 1040 px in three. The rules count
 *       the tiles the page draws (`:nth-child(n):last-child`), so the
 *       tiles are the grid's only children.
 *   E5  on a phone (2026-10-18, §4.25 *On a phone*): under 614 px two to
 *       six tiles sit two to a row at every window from 320 px, and one
 *       tile takes the row. Under 405 px #main's column fits no two 180 px
 *       tiles, so each took a whole row (four as 1+1+1+1, about 400 px at
 *       390 px); a 130 px minimum there fits two from a 304 px window,
 *       never three. Narrower than that, one to a row again.
 * The layout itself is the run's Chromium probe (before and after: 1 to 7
 * tiles at 16 widths from 320 to 1280 px; every arrangement as this model
 * computes it; on a phone, 1 to 6 tiles at 11 widths from 280 to 613 px:
 * no label word cut, no page wider than its window).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, PUB, T, load, tick } from "./home-js-fixtures.js";
import { resolveCssVars, stylesAt } from "./css-flatten.js";
import { MAX_TILES, arrangement, even, tilesRows } from "./tiles-rows.js";
import { fileNameRoom } from "./files-name-room.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const TILES = tilesRows(CSS);
const WIDTHS = Array.from({ length: 1600 - 320 + 1 }, (_, i) => 320 + i);
const COUNTS = Array.from({ length: MAX_TILES }, (_, i) => i + 1);

test("E1: 1 to 6 tiles at every window from 320 to 1600 px: as few rows as auto-fit's, and no row two tiles short of another", () => {
  /** Each uneven arrangement with the windows that draw it. */
  const uneven = new Map<string, number[]>();
  for (const n of COUNTS) {
    for (const w of WIDTHS) {
      const g = TILES.at(w, n);
      const before = TILES.autoFit(w, n);
      assert.equal(g.rows.length, before.rows.length, `${n} tiles at ${w}px: ${arrangement(g)}, auto-fit ${arrangement(before)}`);
      if (!even(g)) {
        const k = `${n} tiles as ${arrangement(g)}`;
        uneven.set(k, [...(uneven.get(k) ?? []), w]);
      }
    }
  }
  assert.deepEqual([...uneven].map(([k, ws]) => `${k} at ${ws[0]}-${ws.at(-1)}px (${ws.length} widths)`), [], "every row arrangement is even");
});

test("E2: no tile that shares its row is narrower than auto-fit's minimum, and no column is empty", () => {
  for (const n of COUNTS) {
    for (const w of WIDTHS) {
      const g = TILES.at(w, n);
      assert.ok(g.cols <= n, `${n} tiles at ${w}px: ${g.cols} columns, so one is empty`);
      if (g.cols > 1) assert.ok(g.tile >= TILES.tileMin(w) - 1e-9, `${n} tiles at ${w}px: each ${g.tile.toFixed(1)}px, under ${TILES.tileMin(w)}px`);
    }
  }
});

test("E3: wherever auto-fit's rows were already even, the stylesheet draws auto-fit's own columns", () => {
  for (const n of COUNTS) {
    for (const w of WIDTHS) {
      const before = TILES.autoFit(w, n);
      if (!even(before)) continue;
      const g = TILES.at(w, n);
      // Five tiles where five fit are one even row either way; the rule
      // that keeps them there names the five columns auto-fit makes.
      if (g.tracks !== before.tracks) assert.equal(arrangement(g), arrangement(before), `${n} tiles at ${w}px: ${g.tracks}`);
    }
  }
  // Exactly the windows that change, and to what (the model's own numbers).
  const changed = (n: number) => WIDTHS.filter((w) => arrangement(TILES.at(w, n)) !== arrangement(TILES.autoFit(w, n)));
  const span = (ws: number[]) => ws.length ? `${ws[0]}-${ws.at(-1)}` + (ws.length !== ws.at(-1)! - ws[0]! + 1 ? " (with gaps)" : "") : "none";
  assert.deepEqual([1, 2, 3].map((n) => span(changed(n))), ["none", "none", "none"]);
  assert.equal(span(changed(4)), "614-821");
  assert.deepEqual([...new Set(changed(4).map((w) => arrangement(TILES.at(w, 4))))], ["2+2"]);
  assert.equal(span(changed(5).filter((w) => w < 1031)), "822-1030");
  assert.equal(span(changed(5).filter((w) => w > 1150)), "1151-1600");
  assert.equal(changed(5).filter((w) => w >= 1031 && w <= 1150).length, 0, "five keep their one row where five fit");
  assert.deepEqual([...new Set(changed(5).map((w) => arrangement(TILES.at(w, 5))))], ["3+2"]);
  assert.equal(span(changed(6)), "822-1600");
  assert.deepEqual([...new Set(changed(6).map((w) => arrangement(TILES.at(w, 6))))], ["3+3"]);
});

/** A session page whose tiles are `n` of: masked, read before marked,
 *  blocked, sent, waiting, and (6) reached the AI unmasked. */
function pageWith(n: number) {
  const page = JSON.parse(JSON.stringify(AGENT));
  const card = { what: [T("The file "), { kind: "code", text: "~/ws/.env" }], level: "No AI", saw: "masked", ref: "bbbbbbbbbbbbbbbbbbbbbbb1", lines: [{ tone: "good", parts: [T("The AI got only a placeholder, never the real value.")] }] };
  page.secrets = { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: n >= 4 ? 1 : 0 }, secrets: [card] };
  page.blocked = 1;
  page.sent = 1;
  page.waiting = n >= 5 ? AGENT.waiting : [];
  if (n >= 6) { page.holds = false; page.violations = 1; }
  return page;
}

test("E4: the session page in jsdom draws its tiles in the columns each width's stylesheet gives them", async () => {
  const AUTO = "repeat(auto-fit, minmax(min(180px, 100%), 1fr))";
  const PHONE = "repeat(auto-fit, minmax(min(130px, 100%), 1fr))";
  // Tiles, window, the columns the page computes, the rows the model gives.
  const cases: Array<[number, number, string, string]> = [
    [4, 720, "repeat(2, minmax(0, 1fr))", "2+2"], [4, 613, AUTO, "2+2"], [4, 822, AUTO, "4"],
    [4, 390, PHONE, "2+2"], [4, 320, PHONE, "2+2"], [4, 404, PHONE, "2+2"], [4, 405, AUTO, "2+2"],
    [3, 720, AUTO, "3"], [3, 320, PHONE, "2+1"],
    [5, 1280, "repeat(3, minmax(0, 1fr))", "3+2"], [5, 1040, "repeat(5, minmax(0, 1fr))", "5"],
    [6, 1040, "repeat(3, minmax(0, 1fr))", "3+3"],
  ];
  for (const [n, width, cols, rows] of cases) {
    const { doc, err } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": pageWith(n) } });
    assert.equal(err, null);
    const sheet = doc.createElement("style");
    sheet.textContent = resolveCssVars(stylesAt(CSS, width));
    doc.head.append(sheet);
    await tick(40);
    const box = doc.getElementById("agent-facts");
    const kids = [...box.children] as El[];
    assert.equal(kids.length, n, `${n} tiles drawn: ${kids.map((k) => k.textContent).join(" | ")}`);
    assert.ok(kids.every((k) => k.classList.contains("tile")), "the tiles are the grid's only children");
    assert.equal(box.getAttribute("style"), null, "no inline style: the stylesheet decides");
    assert.equal(doc.defaultView.getComputedStyle(box).gridTemplateColumns, cols, `${n} tiles at ${width}px`);
    assert.equal(arrangement(TILES.at(width, n)), rows, `the model agrees at ${width}px`);
  }
});

test("E5: on a phone, under 614 px, two to six tiles sit two to a row from a 320 px window, and one tile takes the row", () => {
  const room = fileNameRoom(CSS);
  /** The 180 px tiles alone, as the page drew them before (columns). */
  const before = (w: number) => Math.max(1, Math.floor((room.pageColumn(w) + 12) / (180 + 12)));
  for (let w = 320; w <= 613; w++) {
    assert.equal(TILES.at(w, 1).cols, 1, `one tile at ${w}px takes the row`);
    for (let n = 2; n <= MAX_TILES; n++) {
      const g = TILES.at(w, n);
      assert.equal(g.cols, 2, `${n} tiles at ${w}px: ${arrangement(g)}`);
      assert.ok(g.tile >= TILES.tileMin(w) - 1e-9 && g.tile >= 130, `${n} tiles at ${w}px: each ${g.tile.toFixed(1)}px`);
    }
    assert.equal(arrangement(TILES.at(w, 4)), "2+2", `four tiles at ${w}px`);
  }
  // Where the phone rule changes the page: exactly 320 to 404 px, where
  // 180 px tiles took a whole row each.
  const changed = WIDTHS.filter((w) => w < 614 && before(w) !== TILES.at(w, 4).cols);
  assert.equal(`${changed[0]}-${changed.at(-1)} (${changed.length})`, "320-404 (85)");
  assert.ok(changed.every((w) => before(w) === 1), "each tile took a whole row there");
  assert.deepEqual([4, 3, 6, 5].map((n) => arrangement(TILES.at(390, n))), ["2+2", "2+1", "2+2+2", "2+2+1"], "at 390 px");
  // The rows are half as many: four tiles in two rows at 390 px, not four.
  assert.equal(TILES.at(390, 4).rows.length, 2);
  // Narrower than a 304 px window two 130 px tiles do not fit: one to a row.
  assert.equal(TILES.at(303, 4).cols, 1);
  assert.equal(TILES.at(304, 4).cols, 2);
  // Never three on a phone: the phone rule's widest window still fits two.
  assert.equal(TILES.autoFit(404, 6).cols, 2);
});
