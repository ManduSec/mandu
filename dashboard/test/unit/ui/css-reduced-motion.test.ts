/**
 * css-reduced-motion — both front-ends follow the system's "reduce motion"
 * setting (dashboard.md §4.25k *Motion follows the system's setting*).
 * Mandu-new.
 *
 * Until 2026-10-14 neither page read `prefers-reduced-motion`. A headless
 * Chromium with the setting emulated drew three pulses that never stop (the
 * red invariant banner, a running session's chip, a starting service's
 * dot), slid every dialog in, faded a glow on every jump, rotated carets,
 * slid the switch's knob, and scrolled every scripted jump for ~800 ms
 * (Chromium animates a script's `behavior: 'smooth'` whatever the setting).
 * Now, under that setting only:
 *   - mandu.css (both pages) ends every transition at once, `!important`;
 *   - dev/dashboard.css stops each never-ending animation and the dialog's
 *     slide (`animation: none`), and holds each jump's highlight still for
 *     its time, then drops it (`steps(1, end)`);
 *   - every scripted jump of the inspector scrolls through render-helpers.js
 *     `scrollMotion()`, which reads the setting at each jump.
 *
 * jsdom applies no media query and has no `matchMedia`, so this pins the
 * stylesheets as text, computes the drawn elements with the reduce blocks
 * unwrapped (css-flatten `stylesAt(css, w, { reducedMotion: true })`), and
 * runs the inspector's Rules panel with a stubbed `matchMedia`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

import { PUB } from "./home-js-fixtures.js";
import { devPagesDir, NO_DEV_PAGES } from "./dev-pages.js";
import { declValue, flattenCss, perSelector, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The developer view's pages; null in a tree without them (dev-pages.ts). */
const DEV = devPagesDir();
/** A developer-view file's text, empty without the developer view. */
const readDev = (file: string): string => (DEV ? readFileSync(join(DEV, file), "utf8") : "");
const read = (dir: string, file: string): string => readFileSync(join(dir, file), "utf8");
const SHEETS: Array<[string, string]> = [["mandu.css", read(PUB, "mandu.css")], ["app.css", read(PUB, "app.css")], ...(DEV ? [["dev/dashboard.css", readDev("dashboard.css")] as [string, string]] : [])];
const REDUCE = /\(prefers-reduced-motion:\s*reduce\)/;
const isReduce = (media: string | null): boolean => !!media && REDUCE.test(media);

/** Every rule that animates outside a reduce block: its sheet, selector,
 *  and whether it never ends. */
const ANIMATED = SHEETS.flatMap(([sheet, css]) => flattenCss(stripComments(css))
  .filter((r) => !isReduce(r.media))
  .flatMap((r) => {
    const anim = declValue(r.block, "animation") ?? declValue(r.block, "animation-name");
    if (!anim || anim === "none") return [];
    const infinite = /\binfinite\b/.test(anim) || declValue(r.block, "animation-iteration-count") === "infinite";
    return r.selectors.map((sel) => ({ sheet, sel, infinite }));
  }));

/** What the reduce blocks of `sheet` declare for exactly `sel`. */
function reduceDecls(sheet: string, sel: string): string[] {
  const css = SHEETS.find(([name]) => name === sheet)![1];
  return flattenCss(stripComments(css))
    .filter((r) => isReduce(r.media) && r.selectors.includes(sel))
    .map((r) => r.block);
}

test("every animation of either page stops, or holds still, under reduce motion", () => {
  // Not vacuous: the inspector's three pulses, its dialog and its five jump
  // highlights are found.
  const sels = ANIMATED.map((a) => a.sel);
  // (The inspector's only where this tree has the developer view.)
  if (DEV) {
    for (const sel of [".banner.violation", ".s-status-running", ".dot-starting", ".drawer-panel", ".ruleref-flash", "#protection-panel.jump-flash", "tr.jump-flash td", ".sys-entry.flash", ".pr-row.flash > .pr-cell", ".pr-row.flash > .pr-ai"]) {
      assert.ok(sels.includes(sel), `the sweep finds ${sel}`);
    }
    assert.deepEqual(ANIMATED.filter((a) => a.infinite && a.sheet === "dev/dashboard.css").map((a) => a.sel).sort(), [".banner.violation", ".dot-starting", ".s-status-running"]);
  }
  // The product's never-ending motion is the scan figure's (§4.25ai): its
  // lanes' dots and the key and mask riding them, each stopped below.
  assert.deepEqual(ANIMATED.filter((a) => a.infinite && a.sheet === "app.css").map((a) => a.sel).sort(), [".sf-lane", ".sf-ride", ".sf-ride-v"]);
  for (const a of ANIMATED) {
    const blocks = reduceDecls(a.sheet, a.sel);
    const stops = blocks.some((b) => declValue(b, "animation") === "none" || declValue(b, "animation-name") === "none");
    const holds = blocks.some((b) => declValue(b, "animation-timing-function") === "steps(1, end)");
    if (a.infinite) {
      assert.ok(stops, `${a.sheet} ${a.sel}: a never-ending animation has \`animation: none\` under reduce motion`);
    } else {
      assert.ok(stops || holds, `${a.sheet} ${a.sel}: an animation stops (\`animation: none\`) or holds still (\`steps(1, end)\`) under reduce motion`);
    }
  }
});

test("every transition of either page ends at once under reduce motion; no reduce block brings one back", () => {
  const shared = flattenCss(stripComments(SHEETS[0]![1])).filter((r) => isReduce(r.media));
  const all = shared.find((r) => ["*", "*::before", "*::after"].every((s) => r.selectors.includes(s)));
  assert.ok(all, "mandu.css, which both pages load first, has one reduce rule for every element and its ::before and ::after");
  assert.equal(declValue(all!.block, "transition"), "none !important", "it ends every transition, and a page's later rule cannot take that back");
  for (const [sheet, css] of SHEETS) {
    for (const r of flattenCss(stripComments(css)).filter((x) => isReduce(x.media))) {
      for (const prop of ["transition", "transition-duration", "animation-duration"]) {
        const v = declValue(r.block, prop);
        assert.ok(v === null || /^none\b/.test(v), `${sheet} "${r.selectors.join(", ")}": a reduce block never sets ${prop}: ${v}`);
      }
      assert.equal(declValue(r.block, "animation-iteration-count"), null, `${sheet} "${r.selectors.join(", ")}": a reduce block never repeats an animation`);
    }
  }
  // Both pages load the shared sheet before their own (so its reduce rule
  // reaches every element of either).
  const productHtml = read(PUB, "index.html");
  const devHtml = readDev("index.html");
  assert.ok(productHtml.indexOf('href="mandu.css') > 0 && productHtml.indexOf('href="mandu.css') < productHtml.indexOf('href="app.css'));
  if (DEV) assert.ok(devHtml.indexOf('href="../mandu.css') > 0 && devHtml.indexOf('href="../mandu.css') < devHtml.indexOf('href="dashboard.css'));
});

/** `fn` over a document styled with `css` (one rule per selector, so jsdom
 *  applies what a browser does) holding `body`. */
function drawn(css: string, body: string, fn: (doc: El, w: El) => void): void {
  const dom = new JSDOM(`<!doctype html><html><head><style>${perSelector(css)}</style></head><body>${body}</body></html>`);
  try { fn(dom.window.document, dom.window); } finally { dom.window.close(); }
}

const INSPECTOR_BODY = `<div id="banner" class="banner violation">Flagged</div>
  <span class="s-status s-status-running">R</span><span class="dot dot-starting"></span>
  <div class="drawer-panel">dialog</div>
  <table><tbody><tr class="ruleref-flash"><td>rule</td></tr><tr class="jump-flash"><td id="jump-td">answer</td></tr></tbody></table>
  <div id="protection-panel" class="jump-flash"></div><div class="sys-entry flash"></div>
  <div class="pr-row flash"><div class="pr-cell"></div><div class="pr-ai"></div></div>`;
const PRODUCT_BODY = `<button class="switch" role="switch" aria-checked="true"><span class="knob"></span></button>
  <div class="rules-folder" aria-expanded="false"><span class="rules-folder-caret"></span></div>`;
const INSPECTOR_CSS = `${SHEETS[0]![1]}\n${SHEETS[2]?.[1] ?? ""}`;
const PRODUCT_CSS = `${SHEETS[0]![1]}\n${SHEETS[1]![1]}`;

test("the inspector as a reduce-motion system draws it: the pulses and the dialog stand still, each jump's highlight holds still", { skip: NO_DEV_PAGES }, () => {
  const pulses = ["#banner", ".s-status-running", ".dot-starting"];
  const flashes = [".ruleref-flash", "#jump-td", "#protection-panel", ".sys-entry", ".pr-cell", ".pr-ai"];
  drawn(stylesAt(INSPECTOR_CSS, 1280, { reducedMotion: true }), INSPECTOR_BODY, (doc, w) => {
    const cs = (sel: string) => w.getComputedStyle(doc.querySelector(sel));
    for (const sel of [...pulses, ".drawer-panel"]) assert.equal(cs(sel).animation, "none", `${sel} does not move`);
    for (const sel of flashes) {
      assert.notEqual(cs(sel).animation, "none", `${sel} keeps its highlight`);
      assert.equal(cs(sel).animationTimingFunction, "steps(1, end)", `${sel}: held still, then gone`);
    }
  });
  // Without the setting, as before.
  drawn(stylesAt(INSPECTOR_CSS, 1280), INSPECTOR_BODY, (doc, w) => {
    const cs = (sel: string) => w.getComputedStyle(doc.querySelector(sel));
    for (const sel of pulses) assert.equal(cs(sel).animation, "flare 1.1s ease-in-out infinite", `${sel} pulses`);
    assert.equal(cs(".drawer-panel").animation, "dialog-in .14s ease-out");
    for (const sel of flashes) assert.notEqual(cs(sel).animationTimingFunction, "steps(1, end)", `${sel} fades`);
  });
});

test("the product page as a reduce-motion system draws it: the switch and the folder caret change at once", () => {
  const moving = [".switch", ".knob", ".rules-folder-caret"];
  drawn(stylesAt(PRODUCT_CSS, 1280, { reducedMotion: true }), PRODUCT_BODY, (doc, w) => {
    for (const sel of moving) assert.equal(w.getComputedStyle(doc.querySelector(sel)).transition, "none", `${sel} changes at once`);
  });
  drawn(stylesAt(PRODUCT_CSS, 1280), PRODUCT_BODY, (doc, w) => {
    assert.deepEqual(moving.map((sel) => w.getComputedStyle(doc.querySelector(sel)).transition), ["background 120ms", "left 120ms", "transform 0.15s"], "as before without the setting");
  });
});

test("no script of either page scrolls smoothly but through scrollMotion, which reads the setting", () => {
  const scripts = [...(DEV ? readdirSync(join(DEV, "js")) : []).map((f) => ["dev/js/" + f, readDev("js/" + f)]), ...readdirSync(join(PUB, "js")).map((f) => ["js/" + f, read(join(PUB, "js"), f)])]
    .filter(([f]) => f!.endsWith(".js"));
  assert.ok(scripts.length >= (DEV ? 10 : 1), `the sweep reads the scripts (${scripts.length})`);
  const smooth: string[] = [];
  let jumps = 0;
  for (const [file, src] of scripts) {
    for (const [i, line] of src!.split("\n").entries()) {
      if (/['"`]smooth['"`]/.test(line) && !/^\s*(\*|\/\/|\/\*)/.test(line)) smooth.push(`${file}:${i + 1}`);
      if (/behavior:\s*scrollMotion\(\)|\?\s*scrollMotion\(\)/.test(line)) jumps++;
      if (/scroll(IntoView|To|By)\b[^;]*behavior:/.test(line)) {
        assert.match(line, /behavior:\s*(scrollMotion\(\)|smooth \? scrollMotion\(\) : 'auto'|'auto')/, `${file}:${i + 1} scrolls through scrollMotion`);
      }
    }
  }
  // The product page scrolls nothing smoothly; the inspector's only 'smooth'
  // is its scrollMotion's own, and it makes thirteen scripted jumps.
  assert.deepEqual(smooth, DEV ? ["dev/js/render-helpers.js:" + (readDev("js/" + "render-helpers.js").split("\n").findIndex((l) => /return reduce \? 'auto' : 'smooth'/.test(l)) + 1)] : [],
    "the only 'smooth' is scrollMotion's own");
  if (DEV) assert.equal(jumps, 13, "the inspector's thirteen scripted jumps");
});
