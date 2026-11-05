/**
 * css-nav-fits — on a small phone the page links fit their row when
 * something waits for you, so none is cut (dashboard.md §4.25 *The page
 * links fit a small phone*). Mandu-new.
 *
 * Until 2026-10-15 a headless Chromium over the served page with one
 * request waiting drew "Home · Approvals 1 · Rules · Settir" at 320 px:
 * Settings ran 29 px past the row at 320 to 355 px, on every page, and the
 * row scrolled sideways with no sign that it did. History joined the links
 * on 2026-10-18 (with the Home word hidden on a phone), Scan on 2026-10-21
 * (§4.25ai: two rows of three below 500 px, the Home word shown again), and
 * Plugins on 2026-10-25 (§4.25aj): seven words fit neither two rows of a
 * 288 px phone row (four columns need 346 px) nor the bar beside the brand
 * and "Protection unknown" below 800 px. The Rules link's mark for changes
 * not saved (2026-10-25, §4.25n *The top bar says when Rules has changes
 * not saved*) needs up to 28 px more beside the Approvals count, so each
 * breakpoint moved 20 or 30 px. Since then:
 *
 *   - up to 829 px the links are a row of their own under the brand, and
 *     the Home word is hidden (the brand above them links Home);
 *   - narrower than 540 px that row is two rows of three columns
 *     (`repeat(3, auto)`), each link centred in its column, 10 px a side:
 *     Approvals, Rules, Settings over History, Scan, Plugins;
 *   - from 540 to 829 px they are one row, 10 px a side;
 *   - from 830 px all seven share the bar with the brand and the status:
 *     7 px a side, 2 px apart and at least 50 px each until 970 px, 14 px a
 *     side and 6 px apart from there.
 *
 * jsdom has no layout, so:
 *   F1  the model (nav-row.ts) gives Chromium's numbers: the grid at 320
 *       and 375 px, the row at 540 px, the bar at 830 and 970 px;
 *   F2  every window from 320 to 829 px, every page current, no count and
 *       a count of 1 to 99: the links fit with 4 px to spare, in two rows
 *       below 540 px and one from there;
 *   F3  the row still scrolls where it must, at every window up to 829 px:
 *       the grid holds even three digits at 320 px, the one row at 540 px
 *       not five waiting with two not saved;
 *   F4  the rules touch only the windows they name: below 540, 540 to 829,
 *       830 to 969, and from 970 px the links keep their room;
 *   F5  the page in jsdom draws what the model reads: the seven links, the
 *       current page marked, the count beside Approvals; at 320 px a grid
 *       of three columns that fits, the Home word hidden and the brand
 *       linking Home; Plugins opens the Plugins page;
 *   F6  only the Home word is ever hidden, and only up to 829 px; each link
 *       is at least 50 px wide;
 *   F7  from 830 px the brand, the seven links (up to 99 waiting) and every
 *       status fit the bar with 4 px to spare;
 *   F8  with the Rules mark too (1 to 99 not saved) the links fit every
 *       window from 320 to 1280 px with 4 px to spare, beside every status
 *       in the bar; only a 320 to 325 px phone with two digits in both runs
 *       past its row, which then scrolls;
 *   F9  the page in jsdom draws the mark in the Rules link, a ring with no
 *       fill, as tall as the count, and its digits read at AA (4.5:1) on
 *       the bar, a hovered link and the current page, light and dark.
 * While Mandu refuses your last edit to policy.yaml the same slot shows
 * "!" in a warn ring (2026-10-27, #215; dashboard.md §4.25 *The top bar's
 * two marks*):
 *   F10 the "!" ring needs exactly the room of a one-digit ring, so with
 *       up to 99 waiting it fits wherever "9" not saved fits, 320 and
 *       390 px among them;
 *   F11 the page in jsdom draws it in the warn ink and edge with no fill,
 *       as wide as a one-digit ring: its "!" reads at AA (4.5:1) and its
 *       ring at 3:1 on the bar and a hovered link, light and dark; on the
 *       current page the "!" takes the link's ink (AA) and the ring keeps
 *       the warn (3:1);
 *   F12 under forced colors it is drawn in the link's color, as the ring
 *       of changes not saved is.
 * The layout itself is the run's Chromium probe (2026-10-25: the stylesheet
 * at 320, 326, 375, 539, 540, 829, 830, 969, 970 and 1280 px with 99
 * waiting, 9 or 99 not saved and "Protection unknown"): no sideways scroll
 * of the page or the row and no status cut at any of them but the row's
 * 2 px at 320 px with 99 and 99, as F8 says.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, PUB, home, load, tick } from "./home-js-fixtures.js";
import { contrastRatio, forcedColorsModel, resolveCssVars, stylesAt } from "./css-flatten.js";
import { MARGIN, drawnNav, navRow, type DrawnNav } from "./nav-row.js";

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const NAV = navRow(CSS);
const WORDS = ["Home", "Approvals", "Rules", "Settings", "History", "Scan", "Plugins"];
const PAGES = ["home", "approvals", "rules", "settings", "history", "scan", "plugins"];
const nav = (current: number, count: string): DrawnNav => ({ words: WORDS, pages: PAGES, current, count });
const PHONES = Array.from({ length: 829 - 320 + 1 }, (_, i) => 320 + i);
const BARS = Array.from({ length: 1280 - 830 + 1 }, (_, i) => 830 + i);
const STATUSES = ["Protection on", "Protection off", "Not connected", "Protection unknown", "Protection failed"];
const [, APPROVALS, , , HISTORY, SCAN, PLUGINS] = [0, 1, 2, 3, 4, 5, 6];

test("F1: the model gives Chromium's numbers: the grid at 320 and 375 px, the row at 540 px, the bar at 830 and 970 px", () => {
  const four = (w: number) => [NAV.need(w, nav(APPROVALS, "1")), NAV.need(w, nav(HISTORY, "12")), NAV.need(w, nav(APPROVALS, "99")), NAV.need(w, nav(SCAN, ""))];
  assert.equal(NAV.row(320), 288);
  assert.equal(NAV.row(375), 343);
  assert.deepEqual(four(320), [255, 261, 262, 225], "two rows of three, Home hidden: each column as wide as its widest link");
  assert.deepEqual(four(375), [255, 261, 262, 225]);
  assert.equal(NAV.rows(320, nav(APPROVALS, "1")), 2);
  assert.equal(NAV.rows(539, nav(APPROVALS, "1")), 2, "two rows up to 539 px");
  assert.ok(Math.abs(NAV.row(540) - 496.8) < 0.01);
  assert.deepEqual(four(540), [453, 460, 460, 423], "one row of six (Home hidden; Chromium: 450 px of links and 10 of gaps with 99)");
  assert.equal(NAV.rows(540, nav(APPROVALS, "1")), 1);
  assert.deepEqual(four(830), [475, 482, 482, 445], "in the bar, all seven, 7 px a side, each at least 50 px (Chromium: 470 px of links and 12 of gaps)");
  assert.deepEqual(four(970), [595, 602, 602, 565], "in the bar, 14 px a side (Chromium: 566 and 36)");
  const unknown = (w: number) => NAV.bar(w, nav(APPROVALS, "99"), "Protection unknown");
  assert.ok(Math.abs(unknown(830) - 33.8) < 0.01, `${unknown(830)}px to spare at 830 px`);
  assert.ok(Math.abs(unknown(970) - 34.2) < 0.01, `${unknown(970)}px to spare at 970 px`);
  // The Rules mark: 17 px with one digit, 24 with two, 4 px from its word (Chromium).
  const marked = (w: number, unsaved: string) => NAV.need(w, { ...nav(APPROVALS, "99"), unsaved }) - NAV.need(w, nav(APPROVALS, "99"));
  assert.deepEqual([marked(540, "9"), marked(540, "99"), marked(830, "9"), marked(970, "99")], [21, 28, 21, 28], "the Rules link grows by its gap and the ring (Chromium: 58 → 79 and 86 px at 540, 52 → 73 at 830, 66 → 94 at 970)");
  assert.equal(NAV.need(320, { ...nav(APPROVALS, "99"), unsaved: "99" }), 290, "Chromium: the row 2 px past its 288 at 320 px");
});

test("F2: from 320 to 829 px, on every page, with nothing or up to 99 waiting, the links fit with room to spare: two rows below 540 px, one from there", () => {
  const short: string[] = [];
  for (const w of PHONES) {
    for (let current = 0; current < WORDS.length; current++) {
      // The pill is as wide for every count of as many digits.
      for (const count of ["", "1", "9", "10", "99"]) {
        const spare = NAV.spare(w, nav(current, count));
        if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, count "${count}": ${spare}px to spare`);
        assert.equal(NAV.rows(w, nav(current, count)), w < 540 ? 2 : 1, `${w}px: the rows`);
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
});

test("F3: the row still scrolls where it must, at every window up to 829 px", () => {
  for (const w of PHONES) assert.equal(NAV.at(w, "#nav", "overflow-x"), "auto", `${w}px`);
  assert.ok(NAV.spare(320, nav(APPROVALS, "100")) >= MARGIN, "the grid holds a three-digit count at 320 px");
  assert.ok(NAV.spare(540, { ...nav(APPROVALS, "10000"), unsaved: "99" }) < 0, "five digits waiting and two not saved run past the one row at 540 px, which then scrolls");
});

test("F4: each rule touches only the windows it names; from 970 px the links keep their room", () => {
  for (const w of [...PHONES, ...BARS]) {
    const [display, pad, gap, least] =
      w < 540 ? ["grid", "6px 10px", "2px", null]
      : w < 830 ? ["flex", "6px 10px", "2px", null]
      : w < 970 ? ["flex", "8px 7px", "2px", "50px"]
      : ["flex", "8px 14px", "6px", null];
    assert.equal(NAV.at(w, "#nav", "display"), display, `${w}px: the links' layout`);
    assert.equal(NAV.columns(w), w < 540 ? 3 : null, `${w}px: the columns`);
    assert.equal(NAV.at(w, "#nav a", "padding"), pad, `${w}px: a link's padding`);
    assert.equal(NAV.at(w, "#nav", "gap"), gap, `${w}px: the links' gap`);
    assert.equal(NAV.declares(w, "#nav", "order"), w < 830 ? "3" : null, `${w}px: a row of its own`);
    assert.equal(NAV.at(w, "#nav a", "gap"), "8px", `${w}px: the count's gap`);
    assert.equal(NAV.at(w, ".count", "padding"), "1px 7px", `${w}px: the count's pill`);
    assert.equal(NAV.at(w, '#nav a[data-page-link="rules"]', "gap"), "4px", `${w}px: the Rules mark's gap`);
    assert.equal(NAV.at(w, ".unsaved-mark", "padding"), "0 4px", `${w}px: the Rules mark's ring`);
    assert.equal(NAV.declares(w, "#nav a", "min-width"), least, `${w}px: a link's least width`);
    assert.equal(NAV.declares(w, "#nav a", "justify-content"), w < 540 || (w >= 830 && w < 970) ? "center" : null, `${w}px: a link's word centred in its room`);
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
  assert.deepEqual(drawn, { words: WORDS, pages: PAGES, current: 1, count: "2", unsaved: "" }, "the seven links, Approvals current, two waiting, nothing not saved");
  const count = doc.getElementById("nav-approvals-count");
  assert.equal(count.parentElement.getAttribute("data-page-link"), "approvals", "the count sits in the Approvals link");
  assert.equal(count.className, "count");
  const navEl = doc.getElementById("nav");
  assert.equal(doc.defaultView.getComputedStyle(navEl).display, "grid", "at 320 px a grid");
  assert.equal(doc.defaultView.getComputedStyle(navEl).gridTemplateColumns, "repeat(3, auto)");
  assert.equal(doc.querySelector('#nav a[data-page-link="scan"]').getAttribute("href"), "/mandu/scan", "Scan opens the Scan page");
  const link = doc.querySelector('#nav a[data-page-link="plugins"]');
  assert.equal(link.getAttribute("href"), "/mandu/plugins", "Plugins opens the Plugins page");
  assert.equal(doc.defaultView.getComputedStyle(link).paddingLeft, "10px");
  for (const a of doc.querySelectorAll("#nav a")) {
    assert.equal(a.getAttribute("style"), null, "no inline style: the stylesheet decides");
    const page = a.getAttribute("data-page-link");
    assert.equal(doc.defaultView.getComputedStyle(a).display === "none", page === "home", `${a.textContent.trim()}: only the Home word is hidden at 320 px`);
  }
  assert.equal(doc.querySelector("a.brand").getAttribute("data-page-link"), "home", "the brand links Home");
  assert.ok(NAV.spare(320, drawn) >= MARGIN, `${NAV.spare(320, drawn)}px to spare`);
  // Nothing waiting: the count is hidden and adds nothing; Plugins current on its page.
  const none = load({ url: "http://127.0.0.1:4500/mandu/plugins", homeVm: home({ waiting: [], window: { ...home().window, waiting: 0 } }) });
  assert.equal(none.err, null);
  await tick(40);
  assert.deepEqual(drawnNav(none.doc), { words: WORDS, pages: PAGES, current: PLUGINS, count: "", unsaved: "" });
});

test("F6: only the Home word is ever hidden, only up to 829 px, where the brand links Home; each link is at least 50 px wide", () => {
  for (const w of [...PHONES, ...BARS]) {
    for (let i = 0; i < WORDS.length; i++) {
      assert.equal(NAV.hidden(w, PAGES[i]!), PAGES[i] === "home" && w < 830, `${w}px: ${PAGES[i]}`);
      // One link alone, not current: its word, its padding, its least width.
      const alone: DrawnNav = { words: [WORDS[i]!], pages: [PAGES[i]!], current: -1, count: "" };
      if (!NAV.hidden(w, PAGES[i]!)) assert.ok(NAV.need(w, alone) >= 50, `${w}px: ${WORDS[i]} is ${NAV.need(w, alone)}px wide`);
    }
  }
});

test("F7: from 830 px the brand, the seven links with up to 99 waiting and every status fit the bar with room to spare", () => {
  const short: string[] = [];
  for (const w of BARS) {
    for (let current = 0; current < WORDS.length; current++) {
      for (const count of ["", "1", "99"]) {
        for (const status of STATUSES) {
          const spare = NAV.bar(w, nav(current, count), status);
          if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, count "${count}", "${status}": ${spare}px to spare`);
        }
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
});

test("F8: with the Rules mark too, from 320 to 1280 px the links fit with room to spare, beside every status in the bar; only a 320 to 325 px phone with two digits in both scrolls", () => {
  const short: string[] = [];
  const past: string[] = [];
  for (const w of [...PHONES, ...BARS]) {
    for (let current = 0; current < WORDS.length; current++) {
      for (const count of ["", "1", "9", "10", "99"]) {
        for (const unsaved of ["1", "9", "10", "99"]) {
          const drawn = { ...nav(current, count), unsaved };
          if (w >= 830) {
            for (const status of STATUSES) {
              const spare = NAV.bar(w, drawn, status);
              if (spare < MARGIN) short.push(`${w}px, ${WORDS[current]} current, "${count}" waiting, "${unsaved}" not saved, "${status}": ${spare}px to spare`);
            }
            continue;
          }
          assert.equal(NAV.rows(w, drawn), w < 540 ? 2 : 1, `${w}px: the rows`);
          const spare = NAV.spare(w, drawn);
          if (spare >= MARGIN) continue;
          if (w < 326 && count.length + unsaved.length >= 4) past.push(`${w}:${count}:${unsaved}`);
          else short.push(`${w}px, ${WORDS[current]} current, "${count}" waiting, "${unsaved}" not saved: ${spare}px to spare`);
        }
      }
    }
  }
  assert.deepEqual(short.slice(0, 8), [], `${short.length} cases short of ${MARGIN}px`);
  assert.deepEqual([...new Set(past.map((p) => p.split(":")[0]))], ["320", "321", "322", "323", "324", "325"], "only 320 to 325 px, with two digits in both, run past");
});

test("F9: the page in jsdom draws the Rules mark in its link: a ring with no fill, as tall as the count, its digits at AA on the bar, a hovered link and the current page, light and dark", async () => {
  const stored = JSON.stringify([{ path: "/home/u/ws/notes.md", display: "~/ws/notes.md", level: "no-model", bindings: [], recursive: false, before: "Like any other file", target: null }]);
  for (const theme of ["light", "dark"] as const) {
    for (const url of ["http://127.0.0.1:4500/mandu/", "http://127.0.0.1:4500/mandu/rules"]) {
      const { doc, err } = load({ url, homeVm: home({ waiting: [ASK] }), storage: { "mandu.files.pending": stored } });
      assert.equal(err, null);
      const sheet = doc.createElement("style");
      sheet.textContent = resolveCssVars(stylesAt(CSS, 1280), theme);
      doc.head.append(sheet);
      await tick(40);
      const where = `${theme}, ${url.endsWith("rules") ? "Rules current" : "Home"}`;
      const drawn = drawnNav(doc);
      assert.equal(drawn.unsaved, "1", `${where}: the mark says 1`);
      assert.equal(drawn.count, "1", `${where}: beside the Approvals count`);
      const mark = doc.getElementById("nav-rules-unsaved");
      const link = mark.parentElement;
      assert.equal(link.getAttribute("data-page-link"), "rules", "the mark sits in the Rules link");
      assert.equal(mark.className, "unsaved-mark", "its own style, never the count's");
      const cs = doc.defaultView.getComputedStyle(mark);
      const count = doc.defaultView.getComputedStyle(doc.getElementById("nav-approvals-count"));
      assert.ok(cs.backgroundColor === "" || cs.backgroundColor === "rgba(0, 0, 0, 0)" || cs.backgroundColor === "transparent", `${where}: no fill (${cs.backgroundColor})`);
      assert.notEqual(cs.backgroundColor, count.backgroundColor, `${where}: never the count's amber`);
      assert.equal(cs.borderTopWidth, "1px");
      assert.equal(cs.borderTopStyle, "solid");
      // As tall as the count: the 1px edge stands for its 1px padding.
      assert.equal(parseFloat(cs.paddingTop) + parseFloat(cs.borderTopWidth), parseFloat(count.paddingTop), `${where}: as tall as the count`);
      assert.equal(cs.fontSize, count.fontSize);
      assert.equal(cs.lineHeight, count.lineHeight);
      // The digits and the ring are the link's ink (no color of their own).
      const ink = doc.defaultView.getComputedStyle(link).color;
      assert.equal(cs.color, ink, `${where}: the link's own ink`);
      // The grounds: the bar's, a hovered link's (jsdom applies no :hover,
      // so its rule is read), the current page's.
      const hover = /#nav a:hover\s*\{[^}]*background:\s*([^;]+);/.exec(sheet.textContent)?.[1]?.trim();
      const grounds = url.endsWith("rules") ? { current: doc.defaultView.getComputedStyle(link).backgroundColor }
        : { bar: doc.defaultView.getComputedStyle(doc.getElementById("top")).backgroundColor, hover };
      for (const [what, ground] of Object.entries(grounds)) {
        assert.ok(ground, `${where}: the ${what} ground is known`);
        const ratio = contrastRatio(ink, ground!);
        assert.ok(ratio >= 4.5, `${where}: the mark on the ${what} ground reads ${ratio.toFixed(2)}:1`);
      }
    }
  }
});

const REFUSED_HOME = () => home({ waiting: [ASK], policyFile: { valid: false, path: "/home/u/.mandu/policy.yaml", problemCount: 1, refusedAt: null } });

test("F10: the refused \"!\" needs the room of a one-digit ring, so with up to 99 waiting it fits wherever \"9\" not saved fits, 320 and 390 px among them", () => {
  for (const w of [...PHONES, ...BARS]) {
    for (let current = 0; current < WORDS.length; current++) {
      for (const count of ["", "1", "9", "10", "99"]) {
        assert.equal(NAV.need(w, { ...nav(current, count), unsaved: "!" }), NAV.need(w, { ...nav(current, count), unsaved: "9" }), `${w}px, ${WORDS[current]} current, "${count}" waiting: "!" as wide as "9"`);
      }
    }
  }
  for (const w of [320, 390]) {
    for (let current = 0; current < WORDS.length; current++) {
      const spare = NAV.spare(w, { ...nav(current, "99"), unsaved: "!" });
      assert.ok(spare >= MARGIN, `${w}px, ${WORDS[current]} current, 99 waiting: ${spare}px to spare`);
    }
  }
  // Not vacuous: the ring's least width is what holds it at one digit's.
  assert.equal(NAV.at(1280, ".unsaved-mark.refused", "min-width"), "17px");
});

test("F11: the page in jsdom draws the refused \"!\" in a warn ring with no fill, a digit's ring wide, its glyph at AA and its ring at 3:1 on the bar and a hovered link, light and dark; on the current page the glyph in the link's ink", async () => {
  for (const theme of ["light", "dark"] as const) {
    for (const url of ["http://127.0.0.1:4500/mandu/approvals", "http://127.0.0.1:4500/mandu/rules"]) {
      const { doc, err } = load({ url, homeVm: REFUSED_HOME() });
      assert.equal(err, null);
      const sheet = doc.createElement("style");
      sheet.textContent = resolveCssVars(stylesAt(CSS, 1280), theme);
      doc.head.append(sheet);
      await tick(40);
      const current = url.endsWith("rules");
      const where = `${theme}, ${current ? "Rules current" : "Approvals"}`;
      const drawn = drawnNav(doc);
      assert.equal(drawn.unsaved, "!", `${where}: the slot says "!"`);
      assert.equal(drawn.count, "1", `${where}: beside the Approvals count`);
      const mark = doc.getElementById("nav-rules-unsaved");
      const link = mark.parentElement;
      assert.equal(mark.className, "unsaved-mark refused");
      const win = doc.defaultView;
      const cs = win.getComputedStyle(mark);
      const count = win.getComputedStyle(doc.getElementById("nav-approvals-count"));
      assert.ok(["", "rgba(0, 0, 0, 0)", "transparent"].includes(cs.backgroundColor), `${where}: no fill (${cs.backgroundColor})`);
      assert.notEqual(cs.backgroundColor, count.backgroundColor, `${where}: never the count's amber pill`);
      assert.equal(cs.borderTopWidth, "1px");
      assert.equal(cs.borderTopStyle, "solid");
      assert.equal(parseFloat(cs.paddingTop) + parseFloat(cs.borderTopWidth), parseFloat(count.paddingTop), `${where}: as tall as the count`);
      assert.equal(cs.minWidth, "17px", `${where}: a one-digit ring's width`);
      assert.equal(cs.textAlign, "center");
      // The warn, as the theme resolves it (the count's fill).
      const warn = count.backgroundColor;
      assert.equal(cs.borderTopColor, warn, `${where}: the ring is the warn`);
      const hover = /#nav a:hover\s*\{[^}]*background:\s*([^;]+);/.exec(sheet.textContent)?.[1]?.trim();
      const grounds = current ? { current: win.getComputedStyle(link).backgroundColor }
        : { bar: win.getComputedStyle(doc.getElementById("top")).backgroundColor, hover };
      assert.equal(cs.color, current ? win.getComputedStyle(link).color : warn, `${where}: the "!" in ${current ? "the link's ink" : "the warn"}`);
      for (const [what, ground] of Object.entries(grounds)) {
        assert.ok(ground, `${where}: the ${what} ground is known`);
        const glyph = contrastRatio(cs.color, ground!);
        const ring = contrastRatio(cs.borderTopColor, ground!);
        assert.ok(glyph >= 4.5, `${where}: the "!" on the ${what} ground reads ${glyph.toFixed(2)}:1`);
        assert.ok(ring >= 3, `${where}: the ring on the ${what} ground reads ${ring.toFixed(2)}:1`);
      }
    }
  }
});

test("F12: under forced colors the refused mark is drawn in the link's color, as the ring of changes not saved is", async () => {
  for (const url of ["http://127.0.0.1:4500/mandu/approvals", "http://127.0.0.1:4500/mandu/rules"]) {
    const { doc, err } = load({ url, homeVm: REFUSED_HOME() });
    assert.equal(err, null);
    const sheet = doc.createElement("style");
    sheet.textContent = forcedColorsModel(resolveCssVars(stylesAt(CSS, 1280, { forcedColors: true })));
    doc.head.append(sheet);
    await tick(40);
    const mark = doc.getElementById("nav-rules-unsaved");
    assert.equal(mark.className, "unsaved-mark refused");
    const win = doc.defaultView;
    const cs = win.getComputedStyle(mark);
    const ink = win.getComputedStyle(mark.parentElement).color;
    assert.equal(cs.color, ink, `${url}: the "!" in the link's color`);
    assert.equal(cs.borderTopColor, ink, `${url}: the ring in the link's color`);
  }
});
