/**
 * css-switch-knob — an on/off switch's knob reads at least 3:1 on its track,
 * on and off, in every palette of mandu.css (dashboard.md §4.25k *A switch's
 * knob reads 3:1 on its track*). Mandu-new.
 *
 * The knob is the part that shows whether a switch is on (WCAG 2.1 SC 1.4.11
 * asks 3:1 for it). Until 2026-10-29 it was always white: on the dark
 * theme's green track (`--ok` `#5fc48f`) it read 2.15:1, on its grey one
 * (`--ink-4` `#989791`) 2.93:1. It is now the panel's color, a dark knob in
 * the dark theme and the same white in the light one.
 *
 *   K1  in each palette block (light, the dark one that follows the system,
 *       the chosen dark one, print's light one), the knob reads ≥ 3:1 on
 *       the off track and on the on track;
 *   K2  the light and print knob is still white: the light look is kept;
 *   K3  the knob's color is a palette token, so a new palette block cannot
 *       leave it white.
 *
 * Forced colors draws its own knob in system colors (css-forced-colors).
 * Across the real arbiter and dashboard in a Chromium:
 * tests/stack/switch-knob-contrast.test.ts. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB } from "./home-js-fixtures.js";
import { contrastRatio, declValue, flattenCss, stripComments } from "./css-flatten.js";

const SHARED = stripComments(readFileSync(join(PUB, "mandu.css"), "utf8"));
const APP = readFileSync(join(PUB, "app.css"), "utf8");

/** The tokens declared in the first block whose selector `at` matches. */
function block(at: RegExp): Map<string, string> {
  const open = SHARED.search(at);
  assert.ok(open >= 0, `mandu.css has a ${at} block`);
  const body = SHARED.slice(SHARED.indexOf("{", open) + 1, SHARED.indexOf("}", open));
  return new Map([...body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1]!, m[2]!.trim().toLowerCase()]));
}
const LIGHT = block(/:root\s*\{/);
/** Each palette: the light tokens overlaid with its block, as the cascade does. */
const PALETTES = {
  light: LIGHT,
  "dark (the system's)": new Map([...LIGHT, ...block(/:root:not\(\[data-theme="light"\]\)\s*\{/)]),
  "dark (chosen)": new Map([...LIGHT, ...block(/:root\[data-theme="dark"\]\s*\{/)]),
  print: new Map([...LIGHT, ...block(/:root:root:root\s*\{/)]),
};

/** The background app.css gives `selector`, outside any media query. */
function background(selector: string): string {
  const rules = flattenCss(stripComments(APP)).filter((r) => r.media === null && r.selectors.includes(selector));
  const values = rules.map((r) => declValue(r.block, "background")).filter((v): v is string => v !== null);
  assert.equal(values.length, 1, `app.css sets one background on ${selector}`);
  return values[0]!;
}
/** `value` with its `var(--x)` resolved in `tokens`. */
function resolve(value: string, tokens: Map<string, string>): string {
  let out = value;
  for (let pass = 0; pass < 4 && out.includes("var("); pass += 1) {
    out = out.replace(/var\((--[a-z0-9-]+)\)/g, (all, name: string) => tokens.get(name) ?? all);
  }
  return out;
}

/** A hex color in six digits (`#fff` → `#ffffff`). */
const hex6 = (c: string): string => (/^#[0-9a-f]{3}$/.test(c) ? `#${[...c.slice(1)].map((d) => d + d).join("")}` : c);

const KNOB = background(".switch .knob");
const OFF = background(".switch");
const ON = background('.switch[aria-checked="true"]');

test("K1: in every palette the knob reads 3:1 at the least on the off track and on the on track", () => {
  for (const [name, tokens] of Object.entries(PALETTES)) {
    const knob = resolve(KNOB, tokens);
    for (const [state, track] of [["off", resolve(OFF, tokens)], ["on", resolve(ON, tokens)]] as const) {
      const ratio = contrastRatio(knob, track);
      assert.ok(ratio >= 3, `${name}, ${state}: the knob ${knob} reads ${ratio.toFixed(2)}:1 on its track ${track}, under 3:1`);
    }
  }
});

test("K2: the light and print knob is still white", () => {
  assert.equal(hex6(resolve(KNOB, PALETTES.light)), "#ffffff");
  assert.equal(hex6(resolve(KNOB, PALETTES.print)), "#ffffff");
});

test("K3: the knob's color is a palette token, and both dark palettes give it the same", () => {
  assert.match(KNOB, /^var\(--[a-z0-9-]+\)$/, "the knob names a token, not a color");
  assert.equal(resolve(KNOB, PALETTES["dark (the system's)"]), resolve(KNOB, PALETTES["dark (chosen)"]));
  assert.notEqual(hex6(resolve(KNOB, PALETTES["dark (chosen)"])), "#ffffff", "dark: the knob is not white");
});
