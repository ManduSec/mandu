/**
 * css-top-bar-sticks — on a wide window the product page's top bar stays at
 * the top of the window while the page scrolls under it, and the window
 * keeps the bar's room above what it scrolls into view (dashboard.md §4.25
 * *The bar stays in sight on a wide window*). Mandu-new.
 *
 * Until 2026-10-26 `#top` had no position rule: the Approvals count and the
 * protection status scrolled away after a long page's first screen (a
 * 1280 px render of a recorded session page was 4,499 px tall). Since then:
 *
 *   S1  from 830 px, where the bar is one 64 px row, `#top` is sticky at
 *       the window's top, above the Rules page's bar of changes to save and
 *       under the help notes; `html` keeps a `scroll-padding-top` of the
 *       bar's 65 px and at most 16 px more;
 *   S2  at 320, 390, 799 and 829 px (two or three rows) the bar is not
 *       sticky: it scrolls away, and the window keeps only 8 px above what
 *       it scrolls into view, so a marked turn's ring is not cut off at the
 *       screen's top (2026-10-31); its height stays 64 px from 830 px (the
 *       squeezed links of 830 to 969 px included);
 *   S3  the bar's ground is opaque in both themes, so text scrolls under it
 *       cleanly;
 *   S4  print still hides the bar;
 *   S5  home.js's own "is it in view" checks start below the bar
 *       (`barRoom`, the window's `scroll-padding-top`), never at the
 *       window's top edge, which is under it.
 * The layout itself is the stack test's real Chromium
 * (tests/stack/top-bar-sticks.test.ts); jsdom has none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const HOME_JS = readFileSync(join(PUB, "js", "home.js"), "utf8");

/** The value `prop` ends with on `sel` (named exactly) in a window `width`
 *  px wide, in source order; null: no rule sets it. `css` defaults to the
 *  served styles. */
function at(width: number, sel: string, prop: string, css = CSS): string | null {
  let v: string | null = null;
  for (const r of flattenCss(stylesAt(css, width))) if (r.selectors.includes(sel)) v = declValue(r.block, prop) ?? v;
  return v;
}
const px = (v: string | null): number => {
  const m = /^(\d+(?:\.\d+)?)px$/.exec(v ?? "");
  assert.ok(m, `a length in px: ${v}`);
  return Number(m![1]);
};
/** The bar's height where it is one row: its row and its bottom border. */
function barHeight(width: number): number {
  const border = /^(\d+)px\b/.exec(at(width, "#top", "border-bottom") ?? "");
  assert.ok(border, "the bar has its bottom border");
  return px(at(width, ".top-inner", "height")) + Number(border![1]);
}

test("S1: from 830 px the top bar is sticky at the window's top, above the bar of changes to save and under the help notes, and the window keeps its room", () => {
  const pending = Number(at(1280, ".files-pending", "z-index"));
  const help = Number(at(1280, ".help-pop", "z-index"));
  for (const width of [830, 900, 969, 970, 1280, 1920]) {
    const where = `at ${width}px`;
    assert.equal(at(width, "#top", "position"), "sticky", where);
    assert.equal(at(width, "#top", "top"), "0", where);
    const z = Number(at(width, "#top", "z-index"));
    assert.ok(z > pending && z < help, `${where}: z-index ${z} between the changes bar's ${pending} and the help notes' ${help}`);
    const room = px(at(width, "html", "scroll-padding-top"));
    const bar = barHeight(width);
    assert.equal(bar, 65, `${where}: the bar is its 64 px row and a 1 px border`);
    assert.ok(room >= bar && room <= bar + 16, `${where}: the window keeps ${room} px, the bar's ${bar} and a little more`);
  }
});

test("S2: under 830 px the bar scrolls away and the window keeps 8 px above what it scrolls into view, not the bar's room; from 830 px its row stays 64 px", () => {
  for (const width of [320, 390, 540, 799, 829]) {
    const where = `at ${width}px`;
    assert.equal(at(width, "#top", "position"), null, `${where}: not sticky`);
    assert.equal(at(width, "#top", "z-index"), null, where);
    assert.equal(at(width, "html", "scroll-padding-top"), "8px", `${where}: 8 px kept, not the bar's room`);
    assert.equal(at(width, ".top-inner", "height"), "auto", `${where}: the bar wraps to its rows`);
  }
  for (const width of [830, 969, 970, 1280]) assert.equal(at(width, ".top-inner", "height"), "64px", `at ${width}px the bar is one 64 px row`);
  // Only the one width query makes it sticky.
  const sticky = flattenCss(stripComments(CSS)).filter((r) => r.selectors.includes("#top") && declValue(r.block, "position") !== null);
  assert.deepEqual(sticky.map((r) => r.media), ["@media (min-width: 830px)"]);
});

test("S3: the bar's ground is opaque in the light theme and the dark", () => {
  for (const theme of ["light", "dark"] as const) {
    const ground = at(1280, "#top", "background", resolveCssVars(CSS, theme));
    assert.match(ground ?? "", /^#[0-9a-f]{6}$/, `${theme}: an opaque color (${ground})`);
  }
});

test("S4: print still hides the top bar", () => {
  const print = flattenCss(stripComments(CSS)).filter((r) => r.media === "@media print" && r.selectors.includes("#top"));
  assert.ok(print.length > 0, "a print rule names #top");
  assert.ok(print.some((r) => declValue(r.block, "display") === "none !important"));
});

test("S5: home.js's in-view checks start below the bar, never at the window's top edge", () => {
  assert.match(HOME_JS, /function barRoom\(\) \{\n\s+return parseFloat\(getComputedStyle\(document\.documentElement\)\.scrollPaddingTop\) \|\| 0;/);
  assert.doesNotMatch(HOME_JS, /\.top < 0\b/, "no check compares a box's top with 0");
  assert.match(HOME_JS, /btn\.getBoundingClientRect\(\)\.top < barRoom\(\)/, "a reply folded again keeps its button out from under the bar");
  assert.match(HOME_JS, /b\.top < barRoom\(\)/, "Back to History brings its row out from under the bar");
});
