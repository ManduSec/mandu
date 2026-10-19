/**
 * css-grid-columns-fit — a grid column is never wider than its box, on the
 * product page and in the inspector (dashboard.md §4.25 *A grid column is
 * never wider than its box*). Mandu-new.
 *
 * A grid of `repeat(auto-fit, minmax(320px, 1fr))` columns never makes a
 * column narrower than 320 px, even in a narrower box. Until 2026-10-14 the
 * agent page's Your secrets cards were such a grid: a headless Chromium at
 * 320 px measured each card 320 px wide in its 288 px box, 16 px past the
 * screen, and the whole page scrolled sideways (336 px). The ▶ Run drills
 * dialog's scenario list (340 px) cut its rows 75, 38 and 9 px inside its
 * box at 320, 360 and 390 px. Now every such column's minimum is
 * `min(<length>, 100%)`: the same column wherever the box is at least that
 * wide, the box's width where it is not.
 *
 * jsdom has no layout, so this pins the rule, and that the drawn grids
 * compute it:
 *   - the stylesheets (mandu.css, app.css, dev/dashboard.css, every @media
 *     block): no auto-fit or auto-fill column has a fixed minimum that its
 *     box does not bound; each grid keeps its own minimum where it fits;
 *   - no script draws a grid's columns inline, so the stylesheet decides
 *     for every grid the pages draw;
 *   - the agent page as a 320 px phone applies its styles: the facts' tiles
 *     (their phone minimum, 130 px) and the Your secrets cards compute the
 *     bound;
 *   - the inspector as a 390 px phone applies its styles: the drills
 *     dialog's scenario list computes it.
 * The layout itself is the run's Chromium probe (before: the cards 16 px
 * past a 320 px screen; after: none at 320 to 1280 px, and every width of
 * 352 px and more unchanged).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

import { AGENT, PUB, T, load, tick } from "./home-js-fixtures.js";
import { devPagesDir, NO_DEV_PAGES } from "./dev-pages.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The developer view's pages; null in a tree without them (dev-pages.ts). */
const DEV = devPagesDir();
/** A developer-view file's text, empty without the developer view. */
const readDev = (file: string): string => (DEV ? readFileSync(join(DEV, file), "utf8") : "");
const read = (dir: string, file: string): string => readFileSync(join(dir, file), "utf8");
/** Each front-end's own styles, as its index.html links them. */
const PRODUCT_CSS = `${read(PUB, "mandu.css")}\n${read(PUB, "app.css")}`;
const INSPECTOR_CSS = `${read(PUB, "mandu.css")}\n${readDev("dashboard.css")}`;
const SHEETS: Array<[string, string]> = [["mandu.css", read(PUB, "mandu.css")], ["app.css", read(PUB, "app.css")], ...(DEV ? [["dev/dashboard.css", readDev("dashboard.css")] as [string, string]] : [])];

/** The top-level parts of `s` split at `sep` (a comma or a space), parens
 *  balanced. */
function topLevel(s: string, sep: "," | " "): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0 && (sep === "," ? c === "," : /\s/.test(c!))) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
  }
  out.push(s.slice(start));
  return out.map((p) => p.trim()).filter(Boolean);
}

/** The tracks each `repeat(auto-fit | auto-fill, …)` of a columns value
 *  repeats. */
function autoTracks(value: string): string[] {
  const out: string[] = [];
  const re = /repeat\(\s*(?:auto-fit|auto-fill)\s*,/g;
  for (let m = re.exec(value); m; m = re.exec(value)) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    for (; i < value.length && depth > 0; i++) {
      if (value[i] === "(") depth++;
      else if (value[i] === ")") depth--;
    }
    out.push(...topLevel(value.slice(start, i - 1), " "));
  }
  return out;
}

/** A track's minimum: the first of a `minmax(min, max)`, else the track. */
function trackMin(track: string): string {
  const m = /^minmax\((.*)\)$/.exec(track);
  return m ? topLevel(m[1]!, ",")[0]! : track;
}

/** A fixed length (px, em, rem, ch, vw…), which a narrower box does not
 *  shrink; `0`, a percentage, `auto` and the content keywords are not. */
const FIXED = /\d(?:\.\d+)?(?!fr\b)[a-z]+\b/;
/** A fixed length its box bounds: `min(<length>, 100%)`, either order. */
const BOUNDED = /^min\(\s*(?:[\d.]+[a-z]+\s*,\s*100%|100%\s*,\s*[\d.]+[a-z]+)\s*\)$/;

/** Every rule of the three stylesheets with auto-fit / auto-fill columns:
 *  the sheet, its selectors and @media, and each repeated track. */
const AUTO_GRIDS = SHEETS.flatMap(([sheet, css]) =>
  flattenCss(stripComments(css)).flatMap((r) => {
    const cols = declValue(r.block, "grid-template-columns");
    const tracks = cols === null ? [] : autoTracks(cols);
    return tracks.length ? [{ sheet, selectors: r.selectors, media: r.media, tracks }] : [];
  }),
);

test("the stylesheets: every auto-fit and auto-fill column's minimum is bounded by its box, at every width", () => {
  const where = (g: (typeof AUTO_GRIDS)[number]) => `${g.sheet} ${g.selectors.join(", ")}${g.media ? ` (${g.media})` : ""}`;
  const swept = AUTO_GRIDS.flatMap((g) => g.selectors);
  for (const sel of [".secret-cards", ...(DEV ? [".watch-scenarios"] : [])]) assert.ok(swept.includes(sel), `the sweep reads ${sel} (it is not empty)`);
  for (const g of AUTO_GRIDS) {
    for (const track of g.tracks) {
      const min = trackMin(track);
      if (!FIXED.test(min)) continue;
      assert.match(min, BOUNDED, `${where(g)}: the column's minimum ${min} is a fixed length its box does not bound; a narrower box (a phone) is overrun. Write minmax(min(${min}, 100%), …)`);
    }
  }
});

test("the stylesheets: each grid keeps its own column wherever its box is that wide", () => {
  // The bound changes nothing at a width where the column fits (Chromium:
  // the same tracks at 360, 390, 760 and 1280 px); a smaller length or a
  // 0 minimum would change every width.
  const expected: Array<[string, string, string]> = [
    ["app.css", ".secret-cards", "repeat(auto-fit, minmax(min(320px, 100%), 1fr))"],
    ["app.css", ".tiles", "repeat(auto-fit, minmax(min(180px, 100%), 1fr))"],
    ["dev/dashboard.css", ".watch-scenarios", "repeat(auto-fill, minmax(min(340px, 100%), 1fr))"],
    ["dev/dashboard.css", ".prot-presets", "repeat(auto-fit, minmax(min(200px, 100%), 1fr))"],
    ["dev/dashboard.css", ".egress-testflow-form", "repeat(auto-fit, minmax(min(180px, 100%), 1fr))"],
  ];
  // The one smaller minimum a @media gives a grid, where its own column no
  // longer fits two to a row: the session page's tiles on a phone, under
  // 405 px (§4.25 *On a phone*).
  const phone: Array<[string, string, string, string]> = [
    ["app.css", ".tiles", "@media (max-width: 404px)", "repeat(auto-fit, minmax(min(130px, 100%), 1fr))"],
  ];
  for (const [sheet, sel, cols] of expected.filter(([sheet]) => DEV || !sheet.startsWith("dev/"))) {
    const found = AUTO_GRIDS.filter((g) => g.sheet === sheet && g.selectors.includes(sel));
    const own = phone.filter(([s, x]) => s === sheet && x === sel);
    assert.equal(found.length, 1 + own.length, `${sheet} ${sel}: one auto-fit rule in no @media${own.length ? ", and its phone rule" : ""}`);
    assert.equal(found.filter((g) => g.media === null).length, 1);
    assert.deepEqual(found.filter((g) => g.media !== null).map((g) => g.media), own.map(([, , media]) => media));
    for (const [, , media, phoneCols] of own) {
      const rule = flattenCss(stripComments(SHEETS.find(([s]) => s === sheet)![1])).find((r) => r.media === media && r.selectors.includes(sel))!;
      assert.equal(declValue(rule.block, "grid-template-columns"), phoneCols, `${sheet} ${sel} (${media})`);
    }
    const css = SHEETS.find(([s]) => s === sheet)![1];
    const rule = flattenCss(stripComments(css)).find((r) => r.media === null && r.selectors.includes(sel))!;
    assert.equal(declValue(rule.block, "grid-template-columns"), cols, `${sheet} ${sel}`);
  }
});

test("no script draws a grid's columns inline: the stylesheet decides for every grid the pages draw", () => {
  const scripts = [
    ...readdirSync(join(PUB, "js")).filter((f) => f.endsWith(".js")).map((f) => [`js/${f}`, read(join(PUB, "js"), f)]),
    ...(DEV ? readdirSync(join(DEV, "js")) : []).filter((f) => f.endsWith(".js")).map((f) => [`dev/js/${f}`, readDev("js/" + f)]),
  ];
  assert.ok(scripts.some(([f]) => f === "js/home.js") && (!DEV || scripts.some(([f]) => f === "dev/js/drills.js")), "the sweep reads both front-ends' scripts");
  for (const [file, src] of scripts) {
    assert.doesNotMatch(src!, /gridTemplateColumns|grid-template-columns|\.style\.grid\b|gridTemplate\b/, `${file} sets a grid's columns inline`);
  }
});

test("the agent page as a 320 px phone: the facts' tiles and the Your secrets cards are never wider than their box", async () => {
  const card = (file: string, ref: string) => ({
    what: [T("The file "), { kind: "code", text: file }], level: "No AI", saw: "masked", ref,
    lines: [{ tone: "good", parts: [T("The AI got only a placeholder, never the real value.")] }],
  });
  const page = JSON.parse(JSON.stringify(AGENT));
  page.secrets = { mode: "secrets", flagged: false, more: 0, counts: { masked: 2, early: 0 }, secrets: [card("~/ws/.env", "bbbbbbbbbbbbbbbbbbbbbbb1"), card("~/ws/creds.json", "bbbbbbbbbbbbbbbbbbbbbbb2")] };
  const { doc, err } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": page } });
  assert.equal(err, null);
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(PRODUCT_CSS, 320));
  doc.head.append(sheet);
  await tick(40);
  const win = doc.defaultView;
  /** The grid `#id`'s computed columns; answers how many `child` it holds. */
  const grid = (id: string, child: string, cols: string): number => {
    const box = doc.getElementById(id);
    assert.equal(box.getAttribute("style"), null, `#${id}: no inline style, the stylesheet decides`);
    const cs = win.getComputedStyle(box);
    assert.equal(cs.display, "grid");
    assert.equal(cs.gridTemplateColumns, cols, `#${id}: a column never wider than its box`);
    const kids = [...box.querySelectorAll(`:scope > ${child}`)] as El[];
    for (const c of kids) assert.equal(c.getAttribute("style"), null, `a ${child} sets no width of its own`);
    return kids.length;
  };
  assert.equal(doc.getElementById("agent-secrets-block").hidden, false, "Your secrets is drawn");
  assert.equal(grid("agent-secrets", ".secret-card", "repeat(auto-fit, minmax(min(320px, 100%), 1fr))"), 2, "one card per secret");
  assert.equal(win.getComputedStyle(doc.querySelector(".secret-card")).minWidth, "0px", "a card's long words wrap inside it");
  // At 320 px the tiles' phone minimum (130 px, two to a row) applies.
  assert.ok(grid("agent-facts", ".tile", "repeat(auto-fit, minmax(min(130px, 100%), 1fr))") > 0, "the facts' tiles are drawn");
});

test("the inspector as a 390 px phone: the ▶ Run drills dialog's scenario list is never wider than its box", { skip: NO_DEV_PAGES }, () => {
  // The static markup is enough: drills.js fills the list, the stylesheet
  // lays it out (and no script draws a grid's columns, above).
  const dom = new JSDOM(readDev("index.html"));
  const doc = dom.window.document;
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(INSPECTOR_CSS, 390));
  doc.head.append(sheet);
  const box = doc.getElementById("watch-scenarios");
  assert.ok(box?.closest("#run-drills-dialog"), "the list is in the ▶ Run drills dialog");
  assert.equal(box!.getAttribute("style"), null);
  const cs = dom.window.getComputedStyle(box!);
  assert.equal(cs.display, "grid");
  assert.equal(cs.gridTemplateColumns, "repeat(auto-fill, minmax(min(340px, 100%), 1fr))");
  dom.window.close();
});
