/**
 * product-top-bar.test — dashboard.md §4.25: the product page's top bar keeps
 * its contents in the SAME column as the page below it. The bar's background
 * spans the window, but the brand, the nav and the "Protection on" status sit
 * inside `.top-inner`, which carries #main's max-width and side padding, so
 * the status's right edge lines up with the cards instead of drifting to the
 * window's far edge on a wide screen. A string check on the shipped files.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const PUBLIC = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..", "public");
const HTML = readFileSync(join(PUBLIC, "index.html"), "utf8");
const CSS = readFileSync(join(PUBLIC, "app.css"), "utf8");

function rule(selector: string): string {
  const esc = selector.replace(/[.#]/g, (c) => "\\" + c);
  const m = CSS.match(new RegExp(`(?:^|\\n)${esc} \\{([^}]*)\\}`));
  assert.ok(m, `no top-level ${selector} rule in app.css`);
  return m[1];
}
function prop(body: string, name: string): string | undefined {
  return body.match(new RegExp(`(?:^|[;\\s])${name}:\\s*([^;]+);`))?.[1].trim();
}

test("the brand, the nav and the status sit inside .top-inner in the header", () => {
  const header = HTML.match(/<header id="top">([\s\S]*?)<\/header>/)?.[1];
  assert.ok(header, "missing <header id=\"top\">");
  const inner = header.match(/<div class="top-inner">([\s\S]*)<\/div>\s*$/)?.[1];
  assert.ok(inner, "the header's contents are not wrapped in .top-inner");
  for (const id of [/class="brand"/, /id="nav"/, /id="top-status"/]) assert.match(inner, id);
});

test(".top-inner shares #main's column: same max-width, same side padding", () => {
  const top = rule(".top-inner");
  const main = rule("#main");
  assert.equal(prop(top, "max-width"), prop(main, "max-width"));
  const side = (p: string | undefined) => p?.split(/\s+(?![^(]*\))/)[1];
  assert.equal(side(prop(top, "padding")), side(prop(main, "padding")));
  assert.equal(prop(rule("#top"), "max-width"), undefined, "the bar itself stays full width");
});
