/**
 * css-no-word-alone — the product page's lines of words do not end with one
 * word alone (dashboard.md §4.25u, *No word alone on a last line*).
 *
 * Until 2026-10-17 headless Chromium drew Approvals' cell label "If you
 * click Allow once or Always allow" with "Allow" alone on its second line at
 * 1280 px, and at 390 px ten notes and rows ended on one word. Now app.css
 * balances a heading or a label and lets prose move a word down:
 *
 *   N1  the app.css contract: `h1, h2, h3, .k, .proposal-k` are
 *       `text-wrap-style: balance`, `p, li, dd, .v` are `text-wrap-style:
 *       pretty`; the longhand, never the `text-wrap` shorthand on them (it
 *       also sets `text-wrap-mode: wrap`, undoing a `nowrap` a row
 *       inherits); no later rule takes the style back, and none of them
 *       touches `white-space`;
 *   N2  jsdom under app.css: Approvals' label, a heading, a note, a card's
 *       cell, a list row and a glossary entry compute those styles; a code
 *       kept whole stays `nowrap`.
 *
 * Across the real arbiter and dashboard: tests/stack/no-word-alone.test.ts.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";

import { PUB } from "./home-js-fixtures.js";
import { declValue, flattenCss, stripComments } from "./css-flatten.js";

const BALANCED = ["h1", "h2", "h3", ".k", ".proposal-k"];
const PRETTY = ["p", "li", "dd", ".v"];

test("N1: app.css balances a heading or a label and lets prose move a word down, with the longhand only, and nothing takes it back", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rules = flattenCss(css);
  const find = (sels: string[]) => rules.findIndex((r) => r.media === null && sels.every((s) => r.selectors.includes(s)) && r.selectors.length === sels.length);
  const bal = find(BALANCED);
  const pre = find(PRETTY);
  assert.ok(bal >= 0, "one rule for the headings and labels");
  assert.ok(pre >= 0, "one rule for the prose");
  assert.equal(declValue(rules[bal]!.block, "text-wrap-style"), "balance");
  assert.equal(declValue(rules[pre]!.block, "text-wrap-style"), "pretty");
  for (const at of [bal, pre]) {
    assert.equal(declValue(rules[at]!.block, "text-wrap"), null, "not the shorthand: it would set text-wrap-mode too");
    assert.equal(declValue(rules[at]!.block, "white-space"), null, "where a line may break is not this rule's");
    assert.equal(declValue(rules[at]!.block, "text-wrap-mode"), null, "nor its mode");
  }
  // No later rule naming one of these selectors (alone or as its subject)
  // sets the style back or uses the shorthand.
  const subjects = [...BALANCED, ...PRETTY];
  const subjectOf = (sel: string): string => sel.split(/[\s>+~]+/).pop() ?? sel;
  rules.forEach((r, i) => {
    if (i === bal || i === pre) return;
    const named = r.selectors.filter((s) => subjects.includes(subjectOf(s)));
    if (!named.length) return;
    assert.equal(declValue(r.block, "text-wrap"), null, `${named.join(", ")}: no text-wrap shorthand`);
    assert.equal(declValue(r.block, "text-wrap-style"), null, `${named.join(", ")}: the style is the two rules'`);
  });
});

test("N2: under app.css the label, a heading, a note, a cell, a row and a glossary entry compute their styles; a kept-whole code stays on one line", () => {
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  const dom = new JSDOM(`<!doctype html><style>${css}</style>
    <h1 id="h1">Approvals</h1><h2 id="h2">Rule changes your agent asked for</h2>
    <p class="note" id="note">A change applies when the protection service next starts.</p>
    <div class="ask"><div class="ask-detail"><div><div class="k" id="k">If you click Allow once or Always allow</div><div class="v" id="v">The AI's next request goes to <code>api.stripe.com</code>.</div></div></div></div>
    <div class="proposal"><div class="proposal-k" id="pk">This would let</div><ul class="proposal-rows"><li id="li">Let your agent's programs connect to any address</li></ul></div>
    <dl><dt>Masked</dt><dd id="dd">Before the AI saw it, Mandu replaced the real text.</dd></dl>
    <p id="own">Start it with <code class="code-whole">mandu dashboard</code>.</p>`);
  const win = dom.window;
  const style = (id: string, prop: string): string => win.getComputedStyle(win.document.getElementById(id)!).getPropertyValue(prop);
  for (const id of ["h1", "h2", "k", "pk"]) assert.equal(style(id, "text-wrap-style"), "balance", `${id}: balanced`);
  for (const id of ["note", "v", "li", "dd", "own"]) assert.equal(style(id, "text-wrap-style"), "pretty", `${id}: prose`);
  assert.equal(win.getComputedStyle(win.document.querySelector("code.code-whole")!).whiteSpace, "nowrap", "a kept-whole code still on one line");
});
