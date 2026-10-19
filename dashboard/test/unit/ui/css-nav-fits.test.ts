/**
 * css-nav-fits — on a small phone the page links fit their row when
 * something waits for you, so none is cut (dashboard.md §4.25 *The page
 * links fit a small phone*). Mandu-new.
 *
 * At 640 px and narrower the links take a row of their own, the page's
 * column (288 px at 320). With nothing waiting the four links needed 287
 * px, 288 on Approvals; the count's pill beside Approvals adds 29 px for
 * one digit and 36 for two. A headless Chromium over the served page with
 * one request waiting drew "Home · Approvals 1 · Rules · Settir" at 320
 * px: Settings ran 29 px past the row at 320 to 355 px, on every page, and
 * the row scrolled sideways with no sign that it did. Since 2026-10-15,
 * narrower than 375 px, the links sit closer and fit with up to 99
 * waiting.
 *
 * History joined them on 2026-10-18 (§4.25ae). Five links do not fit a
 * phone's row (387 px with one waiting at 375), so there the Home word is hidden: the brand
 * beside it links Home. Narrower than 375 px the links have 5 px a side,
 * at least 50 px each, and the count's pill 6 px a side. From 641 px the
 * links share the bar with the brand and the status, and until 768 px they
 * have 7 px a side and 2 px between them, no more than the four needed.
 *
 * jsdom has no layout, so:
 *   F1  the model (nav-row.ts) gives Chromium's numbers at 375 and 320 px
 *       on a phone's row, and at 641 px in the bar;
 *   F2  every window from 320 to 640 px, every page current, no count and
 *       a count of 1 to 99: the links fit with 4 px to spare;
 *   F3  the row still scrolls where it must (a three-digit count at
 *       320 px runs past it), at every window up to 640 px;
 *   F4  the rules touch only the windows they name: narrower than 375 px,
 *       375 to 640, 641 to 767, and from 768 px the links keep their room;
 *   F5  the page in jsdom draws what the model reads: the five links, the
 *       current page marked, and the count beside Approvals; with that
 *       count it fits at 320 px, and the Home word is hidden there;
 *   F6  the Home word is hidden up to 640 px and shown from 641, no other
 *       link is ever hidden, and each shown link is at least 50 px wide;
 *   F7  from 641 px the brand, the five links (up to 99 waiting) and the
 *       status fit the bar with 4 px to spare; "Protection unknown" from
 *       660 px (it fitted from 664 px beside the four).
 * The layout itself is the run's Chromium probe (before and after, every
 * page at widths from 320 to 1280 px, counts 1, 12 and 99, each status).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, PUB, home, load, tick } from "./home-js-fixtures.js";
import { resolveCssVars, stylesAt } from "./css-flatten.js";
import { MARGIN, drawnNav, navRow, type DrawnNav } from "./nav-row.js";

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const NAV = navRow(CSS);
const WORDS = ["Home", "Approvals", "Rules", "Settings", "History"];
const PAGES = ["home", "approvals", "rules", "settings", "history"];
const nav = (current: number, count: string): DrawnNav => ({ words: WORDS, pages: PAGES, current, count });
const PHONES = Array.from({ length: 640 - 320 + 1 }, (_, i) => 320 + i);
const BARS = Array.from({ length: 1280 - 641 + 1 }, (_, i) => 641 + i);
const [HOME, APPROVALS, , SETTINGS, HISTORY] = [0, 1, 2, 3, 4];

test("F1: the model gives Chromium's numbers, on a phone's row at 375 and 320 px and in the bar at 641 px", () => {
  // From 375 px the links keep the room every phone gave them; Home's word
  // is hidden, so it adds nothing even where it is the current page.
  assert.equal(NAV.row(375), 343);
  const both = (w: number, count: string) => [NAV.need(w, nav(SETTINGS, count)), NAV.need(w, nav(APPROVALS, count)), NAV.need(w, nav(HISTORY, count)), NAV.need(w, nav(HOME, count))];
  assert.deepEqual(both(375, ""), [295, 296, 296, 295], "nothing waiting");
  assert.deepEqual(both(375, "1"), [324, 325, 325, 324], "one waiting");
  assert.deepEqual(both(375, "12"), [331, 332, 332, 331], "twelve waiting");
  // At 320 px, the narrow rule.
  assert.equal(NAV.row(320), 288);
  assert.deepEqual(both(320, ""), [251, 252, 252, 251], "nothing waiting");
  assert.deepEqual(both(320, "1"), [275, 276, 276, 275], "one waiting");
  assert.deepEqual(both(320, "12"), [282, 283, 283, 282], "twelve waiting");
  // At 641 px, the five links under the middle rule, beside the brand and the status.
  assert.equal(NAV.need(641, nav(SETTINGS, "99")), 363);
  assert.ok(Math.abs(NAV.bar(641, nav(SETTINGS, "99"), "Protection on") - 28.26) < 0.01, `${NAV.bar(641, nav(SETTINGS, "99"), "Protection on")}px to spare`);
});

test("F2: from 320 to 640 px, on every page, with nothing or up to 99 waiting, the links fit their row with room to spare", () => {
  const short: string[] = [];
  for (const w of PHONES) {
    for (let current = 0; current < WORDS.length; current++) {
      // The pill is as wide for every count of as many digits.
      for (const count of ["", "1", "9", "10", "99"]) {
        const spare = NAV.spare(w, nav(current, count));
        if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, count "${count}": ${spare}px to spare`);
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
});

test("F3: the row still scrolls where it must, at every window up to 640 px", () => {
  for (const w of PHONES) assert.equal(NAV.at(w, "#nav", "overflow-x"), "auto", `${w}px`);
  assert.ok(NAV.spare(320, nav(1, "100")) < 0, "a three-digit count runs past the row at 320 px, which then scrolls");
});

test("F4: each rule touches only the windows it names; from 768 px the links keep their room", () => {
  for (const w of [...PHONES, ...BARS]) {
    const [pad, gap, countGap, pill, least] =
      w < 375 ? ["6px 5px", "0", "5px", "1px 6px", "50px"]
      : w <= 640 ? ["6px 10px", "2px", "8px", "1px 7px", null]
      : w < 768 ? ["8px 7px", "2px", "8px", "1px 7px", null]
      : ["8px 14px", "6px", "8px", "1px 7px", null];
    assert.equal(NAV.at(w, "#nav a", "padding"), pad, `${w}px: a link's padding`);
    assert.equal(NAV.at(w, "#nav", "gap"), gap, `${w}px: the links' gap`);
    assert.equal(NAV.at(w, "#nav a", "gap"), countGap, `${w}px: the count's gap`);
    assert.equal(NAV.at(w, ".count", "padding"), pill, `${w}px: the count's pill`);
    assert.equal(NAV.declares(w, "#nav a", "min-width"), least, `${w}px: a link's least width`);
  }
  // Nothing else of the links or the count changes with the window.
  assert.equal(NAV.at(320, "#nav a", "font-size"), NAV.at(1280, "#nav a", "font-size"));
  assert.equal(NAV.at(320, ".count", "font-size"), NAV.at(1280, ".count", "font-size"));
});

test("F5: the page in jsdom draws what the model reads, and with its count the links fit at 320 px", async () => {
  const two = { ...ASK, id: "egr-2" };
  const { doc, err } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: home({ waiting: [ASK, two] }) });
  assert.equal(err, null);
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(CSS, 320));
  doc.head.append(sheet);
  await tick(40);
  const drawn = drawnNav(doc);
  assert.deepEqual(drawn, { words: WORDS, pages: PAGES, current: 1, count: "2" }, "the five links, Approvals current, two waiting");
  const count = doc.getElementById("nav-approvals-count");
  assert.equal(count.parentElement.getAttribute("data-page-link"), "approvals", "the count sits in the Approvals link");
  assert.equal(count.className, "count");
  const link = doc.querySelector('#nav a[data-page-link="rules"]');
  assert.equal(doc.defaultView.getComputedStyle(link).paddingLeft, "5px", "at 320 px a link has 5 px a side");
  assert.equal(doc.defaultView.getComputedStyle(link).minWidth, "50px", "and at least 50 px");
  for (const a of doc.querySelectorAll("#nav a")) assert.equal(a.getAttribute("style"), null, "no inline style: the stylesheet decides");
  assert.equal(doc.defaultView.getComputedStyle(doc.querySelector('#nav a[data-page-link="home"]')).display, "none", "the Home word is hidden at 320 px");
  assert.equal(doc.querySelector("a.brand").getAttribute("data-page-link"), "home", "the brand links Home");
  assert.ok(NAV.spare(320, drawn) >= MARGIN, `${NAV.spare(320, drawn)}px to spare`);
  // Nothing waiting: the count is hidden and adds nothing.
  const none = load({ url: "http://127.0.0.1:4500/mandu/settings", homeVm: home({ waiting: [], window: { ...home().window, waiting: 0 } }) });
  assert.equal(none.err, null);
  await tick(40);
  assert.deepEqual(drawnNav(none.doc), { words: WORDS, pages: PAGES, current: 3, count: "" });
});

test("F6: the Home word is hidden up to 640 px and shown from 641, no other link is ever hidden, and each shown link is at least 50 px wide", () => {
  for (const w of [...PHONES, ...BARS]) {
    assert.equal(NAV.hidden(w, "home"), w <= 640, `${w}px: the Home word`);
    for (const page of PAGES.slice(1)) assert.equal(NAV.hidden(w, page), false, `${w}px: ${page}`);
    for (let i = 0; i < WORDS.length; i++) {
      if (NAV.hidden(w, PAGES[i]!)) continue;
      // One link alone, not current: its word, its padding, its least width.
      const alone: DrawnNav = { words: [WORDS[i]!], pages: [PAGES[i]!], current: -1, count: "" };
      assert.ok(NAV.need(w, alone) >= 50, `${w}px: ${WORDS[i]} is ${NAV.need(w, alone)}px wide`);
    }
  }
});

test("F7: from 641 px the brand, the five links with up to 99 waiting and the status fit the bar with room to spare", () => {
  const short: string[] = [];
  for (const w of BARS) {
    for (let current = 0; current < WORDS.length; current++) {
      for (const count of ["", "1", "99"]) {
        for (const status of ["Protection on", "Protection off", "Not connected", ...(w >= 660 ? ["Protection unknown"] : [])]) {
          const spare = NAV.bar(w, nav(current, count), status);
          if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, count "${count}", "${status}": ${spare}px to spare`);
        }
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
  // The middle rule needs no more than the four links did at 14 px a side
  // (368 px with 99 waiting, Approvals current), so no status has less room.
  assert.ok(NAV.need(641, nav(APPROVALS, "99")) <= 368, `${NAV.need(641, nav(APPROVALS, "99"))}px`);
});
