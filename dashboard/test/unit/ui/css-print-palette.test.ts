/**
 * css-print-palette — a page printed or saved as PDF reads dark on white,
 * whatever the theme on screen (dashboard.md §4.25b *On paper, the light
 * palette*). Mandu-new.
 *
 * Until 2026-10-26 a print kept the theme's colours: from the dark theme a
 * session's heading printed #989794 on white (about 2.9:1), the dim time
 * line darker than the heading, a masked chip as a dark filled bar, and
 * with "Background graphics" on the page was black. mandu.css now ends its
 * palette with an `@media print` block holding the light values.
 *
 *   L1  the print block sets every palette variable of the light `:root`
 *       (each one a dark block overrides, each colour) to the light value,
 *       plus `color-scheme: light`, and nothing else;
 *   L2  each of its selectors outranks both dark rules (the one that
 *       follows the system and the pinned `data-theme="dark"`), so it wins
 *       in whichever order they come;
 *   L3  it comes after both dark blocks: css-shared-system's `blockAfter`
 *       reads the first block after each palette selector.
 *
 * jsdom applies no `@media print` rule, so the computed colours under the
 * print media are proved in a real Chromium: tests/stack/agent-page-print.test.ts.
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { flattenCss, stripComments } from "./css-flatten.js";

const SHARED = stripComments(readFileSync(join(process.cwd(), "public", "mandu.css"), "utf8"));
const RULES = flattenCss(SHARED);
const SYSTEM_DARK = ':root:not([data-theme="light"])';
const PINNED_DARK = ':root[data-theme="dark"]';

/** A block's declarations, in order. */
function decls(block: string): Map<string, string> {
  return new Map(block.split(";").map((d) => d.trim()).filter(Boolean)
    .map((d) => [d.slice(0, d.indexOf(":")).trim(), d.slice(d.indexOf(":") + 1).trim()] as [string, string]));
}
/** The one rule of `selector` (under `media`, or none). */
function rule(selector: string, media: string | null) {
  const found = RULES.filter((r) => r.media === media && r.selectors.includes(selector));
  assert.equal(found.length, 1, `mandu.css has one ${selector} rule${media ? ` under ${media}` : ""}`);
  return found[0]!;
}
const LIGHT = decls(rule(":root", null).block);
const DARKS = [rule(SYSTEM_DARK, "@media (prefers-color-scheme: dark)"), rule(PINNED_DARK, null)].map((r) => decls(r.block));
const PRINTS = RULES.filter((r) => r.media === "@media print");

/** CSS specificity [ids, classes / attributes / pseudo-classes, types] of a
 *  compound selector list as mandu.css writes them: `:not(x)` and `:is(x)`
 *  count their argument, `:where(x)` nothing. Enough for the palette rules. */
function specificity(sel: string): [number, number, number] {
  const s: [number, number, number] = [0, 0, 0];
  let rest = sel.trim();
  while (rest.length > 0) {
    let m: RegExpExecArray | null;
    if ((m = /^:(not|is|where)\(((?:[^()]|\([^()]*\))*)\)/.exec(rest))) {
      if (m[1] !== "where") {
        const inner = m[2]!.split(",").map(specificity).sort((a, b) => b[0] - a[0] || b[1] - a[1] || b[2] - a[2])[0]!;
        for (const i of [0, 1, 2] as const) s[i] += inner[i];
      }
    } else if ((m = /^#[\w-]+/.exec(rest))) s[0] += 1;
    else if ((m = /^(?:\.[\w-]+|\[[^\]]*\]|::?[\w-]+)/.exec(rest))) {
      if (m[0].startsWith("::")) s[2] += 1;
      else s[1] += 1;
    } else if ((m = /^(?:[a-z][\w-]*|\*)/i.exec(rest))) { if (m[0] !== "*") s[2] += 1; }
    else if ((m = /^\s*[>+~\s]\s*/.exec(rest))) { /* a combinator */ }
    else throw new Error(`specificity: cannot read "${rest}" in "${sel}"`);
    rest = rest.slice(m[0].length);
  }
  return s;
}
const outranks = (a: [number, number, number], b: [number, number, number]) =>
  a[0] !== b[0] ? a[0] > b[0] : a[1] !== b[1] ? a[1] > b[1] : a[2] > b[2];

test("specificity counts as CSS does, for the selectors the palette uses", () => {
  assert.deepEqual(specificity(":root"), [0, 1, 0]);
  assert.deepEqual(specificity(SYSTEM_DARK), [0, 2, 0], ":not() counts its attribute");
  assert.deepEqual(specificity(PINNED_DARK), [0, 2, 0]);
  assert.deepEqual(specificity(":root:root:root"), [0, 3, 0]);
  assert.deepEqual(specificity(":where(:root)"), [0, 0, 0]);
  assert.deepEqual(specificity("html#page .a > p::before"), [1, 1, 3]);
  assert.ok(outranks([0, 3, 0], [0, 2, 0]) && !outranks([0, 2, 0], [0, 2, 0]) && outranks([1, 0, 0], [0, 9, 9]));
});

test("L1: the print block is the light palette: every light theme value, the same, and color-scheme light", () => {
  assert.equal(PRINTS.length, 1, "mandu.css has one @media print rule");
  const print = decls(PRINTS[0]!.block);
  assert.equal(print.get("color-scheme"), "light", "the browser draws its own parts light too");
  // The palette: what either dark block overrides, and every colour.
  const palette = new Set([...DARKS.flatMap((d) => [...d.keys()]), ...[...LIGHT].filter(([, v]) => /^#[0-9a-f]{3,8}$/i.test(v)).map(([k]) => k)]);
  palette.delete("color-scheme");
  assert.ok(palette.size >= 27, `the palette is read (${palette.size} variables)`);
  for (const k of palette) {
    assert.ok(LIGHT.has(k), `${k} has a light value`);
    assert.equal(print.get(k), LIGHT.get(k), `on paper ${k} is the light ${LIGHT.get(k)}`);
  }
  const extra = [...print.keys()].filter((k) => k !== "color-scheme" && !palette.has(k));
  assert.deepEqual(extra, [], "the print block sets the palette only");
});

test("L2: each print selector outranks both dark rules, in whichever order they come", () => {
  for (const sel of PRINTS[0]!.selectors) {
    assert.match(sel, /^:root\b/, `${sel} is the root`);
    for (const dark of [SYSTEM_DARK, PINNED_DARK]) {
      assert.ok(outranks(specificity(sel), specificity(dark)), `${sel} ${specificity(sel)} outranks ${dark} ${specificity(dark)}`);
    }
  }
});

test("L3: the print block comes after both dark blocks", () => {
  const at = SHARED.indexOf("@media print");
  assert.ok(at > SHARED.indexOf(`${SYSTEM_DARK} {`) && at > SHARED.indexOf(`${PINNED_DARK} {`), "after the two dark blocks");
  assert.ok(SHARED.indexOf(":root {") < SHARED.indexOf(`${SYSTEM_DARK} {`), "the light block stays the first :root block");
});
