/**
 * css-help-target — a "?" help button, and its Preview-tag and warning-mark
 * forms, is a 24 px target that stops short of the link before it
 * (dashboard.md §4.25u *A help button is a 24 px target*). Mandu-new.
 *
 * Until 2026-10-28 every help button was an 18 × 18 px circle, and nothing
 * around it took a tap: on Home's counts line the "?" of *What masked means*
 * sat 3 px after the link "2 secrets masked before the AI saw them", so a
 * tap a few pixels off it opened the session or History instead of the note
 * (WCAG 2.2 2.5.8 asks 24 × 24 px). The circle keeps its look; an invisible
 * `::before`, 4 px past its padding box, takes the taps around it, and the
 * help takes 3 px more room before it.
 *
 *   A1  the stylesheet: `.help-btn` is positioned, and its `::before` is an
 *       empty, absolutely placed box 4 px past it on every side; no other
 *       rule, at any width, in print or in forced colors, names that
 *       `::before`;
 *   A2  the page in jsdom under its styles, light and dark, at 1280 and
 *       390 px: every help button the page draws (Home's "?" by the masked
 *       count, the Preview tag and the warning mark by an agent's name,
 *       *What the AI has now ?* on Approvals, the Models form's notes)
 *       resolves to a hit area of at least 24 × 24 px: its box less its
 *       border, plus the `::before`'s 4 px each side;
 *   A3  nothing a line holds moves: `.help` stays an inline block, centred
 *       on the line (`vertical-align: middle`), the circle stays 18 px with
 *       its 16 px line, the heading's help keeps its own place, and the
 *       counts line sets no line height of its own; the help has 3 px
 *       before it, so the hit area's 3 px past the circle stops short of a
 *       link a space before it.
 *
 * jsdom lays out nothing and computes no pseudo-element, so the `::before`
 * is read off the stylesheet (A1) and added to the box jsdom computes (A2).
 * The hit area itself, measured with `elementFromPoint` in a real Chromium
 * over the real arbiter and dashboard: tests/stack/help-target.test.ts.
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, perSelector, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const RULES = flattenCss(stripComments(CSS));
/** How far the `::before` reaches past the button's padding box. */
const REACH = 4;

/** The last value `prop` gets on `sel` outside any at-rule (null: none). */
function value(sel: string, prop: string): string | null {
  let v: string | null = null;
  for (const r of RULES) if (r.media === null && r.selectors.includes(sel)) v = declValue(r.block, prop) ?? v;
  return v;
}

/** The page at `width` in `theme`, with a sheet holding its styles. */
function styled(doc: El, theme: "light" | "dark", width: number): void {
  const sheet = doc.createElement("style");
  sheet.textContent = perSelector(resolveCssVars(stylesAt(CSS, width), theme));
  doc.head.append(sheet);
}

const PREVIEW = { label: "Goose", sentence: "Goose support is a preview.", issues: "https://example.com/issues" };
/** Home with a masked count, and an agent with a Preview tag and a warning mark. */
async function homePage(): Promise<El> {
  const vm = home({ window: { hours: 24, sessions: 2, masked: 2, secretsMasked: 2, secretsEarly: 1, untrusted: 0, blocked: 0, sent: 0, waiting: 1, counted: 2 } });
  const agents = vm.agents as Record<string, unknown>[];
  agents[0] = { ...agents[0], preview: PREVIEW, notice: "Goose 9.9 is newer than the versions Mandu was tested with." };
  const { doc } = load({ homeVm: vm });
  await tick();
  return doc;
}
/** Approvals with the question's card open: its *What the AI has now ?*. */
async function approvalsPage(): Promise<El> {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: home({ waiting: [ASK] }) });
  await tick();
  return doc;
}

test("A1: .help-btn is positioned and its ::before is an empty box 4 px past it on every side, named by no other rule", () => {
  assert.equal(value(".help-btn", "position"), "relative");
  assert.equal(value(".help-btn::before", "content"), '""');
  assert.equal(value(".help-btn::before", "position"), "absolute");
  assert.equal(value(".help-btn::before", "inset"), `-${REACH}px`);
  for (const side of ["top", "right", "bottom", "left"]) assert.equal(value(".help-btn::before", side), null, `no ${side} of its own`);
  // Nothing else draws, hides or moves it: under a width, in print, in forced colors.
  const other = RULES.filter((r) => r.selectors.some((s) => /\.(help|notice|preview)-btn[^,]*::?before/.test(s)) && !(r.media === null && r.selectors.join() === ".help-btn::before"));
  assert.deepEqual(other.map((r) => `${r.media ?? ""} ${r.selectors.join(", ")}`), []);
  // The page's one ::before rule for every element is the reduce-motion reset, which only stops transitions.
  for (const r of RULES.filter((x) => x.selectors.includes("*::before"))) {
    assert.match(r.media ?? "", /prefers-reduced-motion/, "only the reduce-motion reset names every ::before");
    assert.equal(declValue(r.block, "content") ?? declValue(r.block, "position") ?? declValue(r.block, "inset"), null);
  }
});

test("A2: every help button the page draws, light and dark, at 1280 and 390 px, resolves to a hit area of at least 24 × 24 px", async () => {
  for (const theme of ["light", "dark"] as const) {
    for (const width of [1280, 390]) {
      const homeDoc = await homePage();
      const asks = await approvalsPage();
      styled(homeDoc, theme, width);
      styled(asks, theme, width);
      const at = `${theme} at ${width}px`;
      const found = {
        masked: homeDoc.querySelector("#hero-facts .help-btn"),
        preview: homeDoc.querySelector(".row .name .preview-btn"),
        notice: homeDoc.querySelector(".row .name .notice-btn"),
        aiNow: asks.querySelector("#approvals-waiting .ask .ask-detail .help-btn"),
        models: homeDoc.querySelector(".choice-line .help-btn"),
      };
      for (const [name, b] of Object.entries(found)) assert.ok(b, `${at}: the page draws the ${name} help`);
      assert.match(found.preview.textContent, /\S{2,}/, `${at}: the Preview tag holds its word`);
      const short: string[] = [];
      for (const [name, b] of Object.entries(found) as [string, El][]) {
        const cs = b.ownerDocument.defaultView.getComputedStyle(b);
        assert.equal(cs.position, "relative", `${at}: ${name} is positioned, so its ::before sits on it`);
        const px = (v: string) => (v === "auto" ? null : Number.parseFloat(v));
        const border = (a: string, z: string) => (cs[`border${a}Style`] === "none" ? 0 : px(cs[`border${a}Width`])!) + (cs[`border${z}Style`] === "none" ? 0 : px(cs[`border${z}Width`])!);
        const h = px(cs.height)! - border("Top", "Bottom") + 2 * REACH;
        // The Preview tag's width is its word's (`auto`): wider than 24 with its 7 px padding each side.
        const w = cs.width === "auto" ? 24 + px(cs.paddingLeft)! + px(cs.paddingRight)! : px(cs.width)! - border("Left", "Right") + 2 * REACH;
        if (!(w >= 24 && h >= 24)) short.push(`${name} ${w} × ${h} (${cs.width} × ${cs.height})`);
      }
      assert.deepEqual(short, [], `${at}: every help button's hit area is at least 24 × 24 px`);
    }
  }
});

test("A3: no line moves: .help stays a middle-aligned inline block, the circle 18 px on a 16 px line, the heading's help in its place, and the help has 3 px before it", async () => {
  assert.equal(value(".help", "display"), "inline-block");
  assert.equal(value(".help", "vertical-align"), "middle");
  assert.equal(value(".help", "margin-left"), "3px");
  assert.equal(value("h1 .help", "margin-left"), "4px");
  assert.equal(value("h1 .help", "vertical-align"), "6px");
  assert.equal(value(".help-btn", "width"), "18px");
  assert.equal(value(".help-btn", "height"), "18px");
  assert.match(value(".help-btn", "font") ?? "", /\b11px\/16px\b/);
  // The counts line takes the page's line height: no rule gives it one.
  const lines = RULES.filter((r) => r.selectors.some((s) => /(^|\s)\.facts\b/.test(s)) && declValue(r.block, "line-height") !== null);
  assert.deepEqual(lines.map((r) => r.selectors.join(", ")), []);
  // The ::before is out of the flow: it adds nothing to a line's height.
  assert.equal(value(".help-btn::before", "position"), "absolute");
  // The 3 px before it outlasts the 3 px the hit area reaches past the 18 px
  // circle's 1 px border, so a link a space before it is never touched.
  const border = Number.parseFloat(/(\d+)px solid/.exec(value(".help-btn", "border") ?? "")![1]!);
  assert.ok(Number.parseFloat(value(".help", "margin-left")!) >= REACH - border, "the help's room before it covers the reach past its circle");
  // In jsdom, light and dark: the counts line's help computes as the rules say.
  for (const theme of ["light", "dark"] as const) {
    const doc = await homePage();
    styled(doc, theme, 1280);
    const help = doc.querySelector("#hero-facts .help");
    const cs = doc.defaultView.getComputedStyle(help);
    assert.equal(cs.verticalAlign, "middle", `${theme}`);
    assert.equal(cs.display, "inline-block", `${theme}`);
    assert.equal(doc.defaultView.getComputedStyle(doc.getElementById("hero-facts")).lineHeight, doc.defaultView.getComputedStyle(doc.getElementById("hero-facts").parentElement).lineHeight, `${theme}: the counts line keeps its parent's line height`);
  }
});
