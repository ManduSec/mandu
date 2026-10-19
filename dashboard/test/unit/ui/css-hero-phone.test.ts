/**
 * css-hero-phone — on a phone Home's hero puts its icon above the headline,
 * smaller, and its words take the column's whole width (dashboard.md §4.25,
 * Home). Mandu-new.
 *
 * The hero kept its desktop layout at every width: a 56 px icon tile beside
 * the text with a 24 px gap, so at 320 px 80 px of the 288 px column held
 * only the (aria-hidden) icon, and headless Chromium drew "One question is
 * waiting for you." in four lines of 34 px type and its sentence in six: the
 * hero alone was 494 px tall, and the waiting card it announces started below
 * a 568 px screen. At 640 px and narrower the hero is now a column, the icon
 * 40 px (its glyph 22 px) and the headline 28 px: two lines and four at
 * 320 px, the hero 386 px tall.
 *
 *   H1  the stylesheet: under `max-width: 640px` the hero is a column, the
 *       icon 40 px with a 22 px glyph, the headline 28 px; nothing else
 *       there names the hero;
 *   H2  641 px and wider keep the desktop values (a row, 56 px, 28 px glyph,
 *       34 px headline);
 *   H3  the page in jsdom under each width's styles: at 640 and 390 px the
 *       hero computes as a column with the smaller icon and headline, at
 *       641 and 1280 px as before; every verdict, "Not connected." too, keeps
 *       its icon (a glyph inside it) and the icon's colours of the desktop.
 * The layout itself is measured by hand in headless Chromium (320, 390 and
 * 1280 px, before and after); jsdom has none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const RULES = flattenCss(stripComments(CSS));
const PHONE = "@media (max-width: 640px)";

/** The last value `prop` gets on `sel` in rules under `media` (null: none). */
function value(sel: string, prop: string, media: string | null): string | null {
  let v: string | null = null;
  for (const r of RULES) {
    if (r.media !== media || !r.selectors.includes(sel)) continue;
    v = declValue(r.block, prop) ?? v;
  }
  return v;
}

test("H1: under max-width 640px the hero is a column, its icon 40 px with a 22 px glyph, its headline 28 px", () => {
  assert.equal(value(".hero", "flex-direction", PHONE), "column");
  assert.equal(value(".hero-icon", "width", PHONE), "40px");
  assert.equal(value(".hero-icon", "height", PHONE), "40px");
  assert.equal(value(".hero-icon svg", "width", PHONE), "22px");
  assert.equal(value(".hero-icon svg", "height", PHONE), "22px");
  assert.equal(value(".hero h1", "font-size", PHONE), "28px");
  // No other width query names the hero, and the phone rule leaves the
  // verdicts' colours to the rules outside it.
  const others = RULES.filter((r) => r.media !== null && r.media !== PHONE && /^@media \((max|min)-width/.test(r.media) && r.selectors.some((s) => /\.hero\b|\.hero-/.test(s)));
  assert.deepEqual(others.map((r) => `${r.media} ${r.selectors.join(", ")}`), []);
  const phone = RULES.filter((r) => r.media === PHONE && r.selectors.some((s) => /\.hero\b|\.hero-/.test(s)));
  assert.ok(phone.every((r) => r.selectors.every((s) => !s.includes("data-verdict"))), "no verdict rule on a phone");
  assert.ok(phone.every((r) => declValue(r.block, "background") === null && declValue(r.block, "color") === null), "no colour on a phone");
});

test("H2: 641 px and wider keep the desktop hero", () => {
  assert.equal(value(".hero", "display", null), "flex");
  assert.equal(value(".hero", "flex-direction", null), null, "a row, flex's own");
  assert.equal(value(".hero", "gap", null), "24px");
  assert.equal(value(".hero-icon", "width", null), "56px");
  assert.equal(value(".hero-icon", "height", null), "56px");
  assert.equal(value(".hero-icon svg", "width", null), "28px");
  assert.equal(value(".hero h1", "font-size", null), "34px");
  // The styles a 641 px window applies to the hero are the 1280 px window's.
  const heroRules = (w: number) => stylesAt(CSS, w).split("\n").filter((l) => /(^|[\s,])\.hero[\s.,[{-]/.test(l));
  assert.deepEqual(heroRules(641), heroRules(1280));
  assert.notDeepEqual(heroRules(640), heroRules(641));
});

const VERDICTS = ["protected", "quiet", "secrets-only", "waiting", "failed", "off"] as const;

/** Home drawn in jsdom under the styles of a `width` px window; `vm` null:
 *  the server's 503 `unreachable` ("Not connected."). */
async function heroAt(width: number, vm: unknown) {
  const routes: Record<string, unknown> = vm === null ? { "GET home": { status: 503, body: { error: "unreachable" } } } : {};
  const { doc, err } = load({ homeVm: vm ?? undefined, routes });
  assert.equal(err, null);
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(CSS, width));
  doc.head.append(sheet);
  await tick(40);
  const hero = doc.getElementById("hero") as El;
  const icon = hero.querySelector(".hero-icon") as El;
  const cs = (e: El) => doc.defaultView.getComputedStyle(e);
  return {
    verdict: hero.dataset.verdict as string,
    direction: cs(hero).flexDirection as string,
    icon: [cs(icon).width, cs(icon).height] as string[],
    glyph: icon.querySelector("svg") ? cs(icon.querySelector("svg")).width as string : null,
    colours: [cs(icon).backgroundColor, cs(icon).color] as string[],
    h1: cs(doc.getElementById("hero-headline")).fontSize as string,
    headline: doc.getElementById("hero-headline").textContent as string,
    sentence: doc.getElementById("hero-sentence").textContent as string,
  };
}

test("H3: Home in jsdom: a column with the smaller icon and headline up to 640 px, the desktop hero from 641 px, every verdict keeping its icon and colours", async () => {
  const cases: Array<[string, unknown]> = [
    ...VERDICTS.map((v): [string, unknown] => [v, home({ verdict: v, headline: `The ${v} headline.`, sentence: `The ${v} sentence.` })]),
    ["unknown", null],
  ];
  for (const [verdict, vm] of cases) {
    const desk = await heroAt(1280, vm);
    assert.equal(desk.verdict, verdict);
    assert.deepEqual([desk.direction, desk.icon, desk.glyph, desk.h1], ["row", ["56px", "56px"], "28px", "34px"], `${verdict} at 1280 px`);
    assert.deepEqual(await heroAt(641, vm), desk, `${verdict}: 641 px draws the 1280 px hero`);
    for (const width of [640, 390, 320]) {
      const ph = await heroAt(width, vm);
      assert.equal(ph.verdict, verdict);
      assert.deepEqual([ph.direction, ph.icon, ph.glyph, ph.h1], ["column", ["40px", "40px"], "22px", "28px"], `${verdict} at ${width} px`);
      assert.deepEqual(ph.colours, desk.colours, `${verdict} at ${width} px keeps its icon's colours`);
      assert.deepEqual([ph.headline, ph.sentence], [desk.headline, desk.sentence], `${verdict} at ${width} px says the same`);
      assert.ok(ph.headline && ph.sentence, `${verdict}: a headline and a sentence`);
    }
  }
  // The verdicts' colours differ, so the check above would see one lost.
  const waiting = await heroAt(390, home({ verdict: "waiting" }));
  const failed = await heroAt(390, home({ verdict: "failed" }));
  assert.notDeepEqual(waiting.colours, failed.colours);
});
