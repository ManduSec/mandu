/**
 * css-nav-fits — on a small phone the page links fit their row when
 * something waits for you, so none is cut (dashboard.md §4.25 *The page
 * links fit a small phone*). Mandu-new.
 *
 * Until 2026-10-15 a headless Chromium over the served page with one
 * request waiting drew "Home · Approvals 1 · Rules · Settir" at 320 px:
 * Settings ran 29 px past the row at 320 to 355 px, on every page, and the
 * row scrolled sideways with no sign that it did. History joined the links
 * on 2026-10-18 (with the Home word hidden on a phone), and Scan on
 * 2026-10-21 (§4.25ai): six words do not fit one 288 px row at 320 px at
 * any padding that leaves a link room to tap (the words alone are 283 px),
 * nor did they fit the bar beside the brand and the status at 641 px (22 px
 * past it). So, since 2026-10-21:
 *
 *   - narrower than 500 px the links are two rows of three columns
 *     (`repeat(3, auto)`), each centred in its column, 10 px a side;
 *   - from 500 to 719 px they are one row of their own, 10 px a side;
 *   - from 720 px they share the bar with the brand and the status: 7 px a
 *     side, 2 px apart and at least 50 px each until 840 px, 14 px a side
 *     and 6 px apart from there;
 *   - the Home word is shown at every width again (the brand links Home too).
 *
 * jsdom has no layout, so:
 *   F1  the model (nav-row.ts) gives Chromium's numbers: the grid at 320
 *       and 375 px, the row at 500 px, the bar at 720 and 840 px;
 *   F2  every window from 320 to 719 px, every page current, no count and
 *       a count of 1 to 99: the links fit with 4 px to spare, in two rows
 *       below 500 px and one from there;
 *   F3  the row still scrolls where it must, at every window up to 719 px:
 *       the grid holds even three digits at 320 px, the one row at 500 px
 *       not four;
 *   F4  the rules touch only the windows they name: below 500, 500 to 719,
 *       720 to 839, and from 840 px the links keep their room;
 *   F5  the page in jsdom draws what the model reads: the six links, the
 *       current page marked, the count beside Approvals; at 320 px a grid
 *       of three columns that fits, every word shown;
 *   F6  no link is ever hidden, and each is at least 50 px wide;
 *   F7  from 720 px the brand, the six links (up to 99 waiting) and every
 *       status fit the bar with 4 px to spare.
 * The layout itself is the run's Chromium probe (every width from 320 to
 * 1280 px named above, counts 1, 12 and 99, each status): no sideways
 * scroll of the page or the row at any of them.
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
const WORDS = ["Home", "Approvals", "Rules", "Settings", "History", "Scan"];
const PAGES = ["home", "approvals", "rules", "settings", "history", "scan"];
const nav = (current: number, count: string): DrawnNav => ({ words: WORDS, pages: PAGES, current, count });
const PHONES = Array.from({ length: 719 - 320 + 1 }, (_, i) => 320 + i);
const BARS = Array.from({ length: 1280 - 720 + 1 }, (_, i) => 720 + i);
const [, APPROVALS, , , HISTORY, SCAN] = [0, 1, 2, 3, 4, 5];

test("F1: the model gives Chromium's numbers: the grid at 320 and 375 px, the row at 500 px, the bar at 720 and 840 px", () => {
  const four = (w: number) => [NAV.need(w, nav(APPROVALS, "1")), NAV.need(w, nav(HISTORY, "12")), NAV.need(w, nav(APPROVALS, "99")), NAV.need(w, nav(SCAN, ""))];
  assert.equal(NAV.row(320), 288);
  assert.equal(NAV.row(375), 343);
  assert.deepEqual(four(320), [255, 261, 262, 225], "two rows of three: each column as wide as its widest link");
  assert.deepEqual(four(375), [255, 261, 262, 225]);
  assert.equal(NAV.rows(320, nav(APPROVALS, "1")), 2);
  assert.equal(NAV.row(500), 460);
  assert.deepEqual(four(500), [443, 450, 450, 413], "one row of six");
  assert.equal(NAV.rows(500, nav(APPROVALS, "1")), 1);
  assert.deepEqual(four(720), [409, 416, 416, 379], "in the bar, 7 px a side, each at least 50 px");
  assert.deepEqual(four(840), [511, 518, 518, 481], "in the bar, 14 px a side");
  const unknown = (w: number) => NAV.bar(w, nav(APPROVALS, "99"), "Protection unknown");
  assert.ok(Math.abs(unknown(720) - 5.2) < 0.01, `${unknown(720)}px to spare at 720 px (Chromium: 5.31)`);
  assert.ok(Math.abs(unknown(840) - 6.4) < 0.01, `${unknown(840)}px to spare at 840 px (Chromium: 6.53)`);
});

test("F2: from 320 to 719 px, on every page, with nothing or up to 99 waiting, the links fit with room to spare: two rows below 500 px, one from there", () => {
  const short: string[] = [];
  for (const w of PHONES) {
    for (let current = 0; current < WORDS.length; current++) {
      // The pill is as wide for every count of as many digits.
      for (const count of ["", "1", "9", "10", "99"]) {
        const spare = NAV.spare(w, nav(current, count));
        if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, count "${count}": ${spare}px to spare`);
        assert.equal(NAV.rows(w, nav(current, count)), w < 500 ? 2 : 1, `${w}px: the rows`);
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
});

test("F3: the row still scrolls where it must, at every window up to 719 px", () => {
  for (const w of PHONES) assert.equal(NAV.at(w, "#nav", "overflow-x"), "auto", `${w}px`);
  assert.ok(NAV.spare(320, nav(APPROVALS, "100")) >= MARGIN, "the grid holds a three-digit count at 320 px");
  assert.ok(NAV.spare(500, nav(APPROVALS, "1000")) < 0, "four digits run past the one row at 500 px, which then scrolls");
});

test("F4: each rule touches only the windows it names; from 840 px the links keep their room", () => {
  for (const w of [...PHONES, ...BARS]) {
    const [display, pad, gap, least] =
      w < 500 ? ["grid", "6px 10px", "2px", null]
      : w < 720 ? ["flex", "6px 10px", "2px", null]
      : w < 840 ? ["flex", "8px 7px", "2px", "50px"]
      : ["flex", "8px 14px", "6px", null];
    assert.equal(NAV.at(w, "#nav", "display"), display, `${w}px: the links' layout`);
    assert.equal(NAV.columns(w), w < 500 ? 3 : null, `${w}px: the columns`);
    assert.equal(NAV.at(w, "#nav a", "padding"), pad, `${w}px: a link's padding`);
    assert.equal(NAV.at(w, "#nav", "gap"), gap, `${w}px: the links' gap`);
    assert.equal(NAV.declares(w, "#nav", "order"), w < 720 ? "3" : null, `${w}px: a row of its own`);
    assert.equal(NAV.at(w, "#nav a", "gap"), "8px", `${w}px: the count's gap`);
    assert.equal(NAV.at(w, ".count", "padding"), "1px 7px", `${w}px: the count's pill`);
    assert.equal(NAV.declares(w, "#nav a", "min-width"), least, `${w}px: a link's least width`);
    assert.equal(NAV.declares(w, "#nav a", "justify-content"), w < 500 || (w >= 720 && w < 840) ? "center" : null, `${w}px: a link's word centred in its room`);
  }
  // Nothing else of the links or the count changes with the window.
  assert.equal(NAV.at(320, "#nav a", "font-size"), NAV.at(1280, "#nav a", "font-size"));
  assert.equal(NAV.at(320, ".count", "font-size"), NAV.at(1280, ".count", "font-size"));
});

test("F5: the page in jsdom draws what the model reads, and with its count the links fit at 320 px as two rows of three", async () => {
  const two = { ...ASK, id: "egr-2" };
  const { doc, err } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: home({ waiting: [ASK, two] }) });
  assert.equal(err, null);
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(CSS, 320));
  doc.head.append(sheet);
  await tick(40);
  const drawn = drawnNav(doc);
  assert.deepEqual(drawn, { words: WORDS, pages: PAGES, current: 1, count: "2" }, "the six links, Approvals current, two waiting");
  const count = doc.getElementById("nav-approvals-count");
  assert.equal(count.parentElement.getAttribute("data-page-link"), "approvals", "the count sits in the Approvals link");
  assert.equal(count.className, "count");
  const navEl = doc.getElementById("nav");
  assert.equal(doc.defaultView.getComputedStyle(navEl).display, "grid", "at 320 px a grid");
  assert.equal(doc.defaultView.getComputedStyle(navEl).gridTemplateColumns, "repeat(3, auto)");
  const link = doc.querySelector('#nav a[data-page-link="scan"]');
  assert.equal(link.getAttribute("href"), "/mandu/scan", "Scan opens the Scan page");
  assert.equal(doc.defaultView.getComputedStyle(link).paddingLeft, "10px");
  for (const a of doc.querySelectorAll("#nav a")) {
    assert.equal(a.getAttribute("style"), null, "no inline style: the stylesheet decides");
    assert.notEqual(doc.defaultView.getComputedStyle(a).display, "none", `${a.textContent.trim()} is shown`);
  }
  assert.equal(doc.querySelector("a.brand").getAttribute("data-page-link"), "home", "the brand links Home too");
  assert.ok(NAV.spare(320, drawn) >= MARGIN, `${NAV.spare(320, drawn)}px to spare`);
  // Nothing waiting: the count is hidden and adds nothing; Scan current on its page.
  const none = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: home({ waiting: [], window: { ...home().window, waiting: 0 } }) });
  assert.equal(none.err, null);
  await tick(40);
  assert.deepEqual(drawnNav(none.doc), { words: WORDS, pages: PAGES, current: SCAN, count: "" });
});

test("F6: no link is ever hidden, and each is at least 50 px wide", () => {
  for (const w of [...PHONES, ...BARS]) {
    for (let i = 0; i < WORDS.length; i++) {
      assert.equal(NAV.hidden(w, PAGES[i]!), false, `${w}px: ${PAGES[i]}`);
      // One link alone, not current: its word, its padding, its least width.
      const alone: DrawnNav = { words: [WORDS[i]!], pages: [PAGES[i]!], current: -1, count: "" };
      assert.ok(NAV.need(w, alone) >= 50, `${w}px: ${WORDS[i]} is ${NAV.need(w, alone)}px wide`);
    }
  }
});

test("F7: from 720 px the brand, the six links with up to 99 waiting and every status fit the bar with room to spare", () => {
  const short: string[] = [];
  for (const w of BARS) {
    for (let current = 0; current < WORDS.length; current++) {
      for (const count of ["", "1", "99"]) {
        for (const status of ["Protection on", "Protection off", "Not connected", "Protection unknown"]) {
          const spare = NAV.bar(w, nav(current, count), status);
          if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, count "${count}", "${status}": ${spare}px to spare`);
        }
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
});
