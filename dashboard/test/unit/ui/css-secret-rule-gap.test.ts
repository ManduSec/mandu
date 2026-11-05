/**
 * css-secret-rule-gap — a session card's *Change it in Rules* and *Show its
 * steps* sit apart (dashboard.md §4.25b *A card shows its steps*, queue
 * #247). Mandu-new.
 *
 * Since #179 a *Your secrets* card ended with one line holding the file's
 * link and the button, joined by a bare text space in a `.secret-rule` that
 * set only its font size. In a headless Chromium at 1280 and 375 px the
 * link's right edge sat 3 px from the button's left edge: the link read as
 * a label stuck to the button, and on a phone a thumb on the link's end
 * pressed the button. Now:
 *
 *   R1  the stylesheet: a card's `.secret-rule` (`.secret-card >
 *       .secret-rule`) is a wrapping flex row, its items centred, with a
 *       column gap of at least 8 px (16) and a row gap (8), at every width
 *       (no query sets it back); the plain `.secret-rule` keeps only its
 *       font size, so the Scan page's `.scan-rule` (a link alone, outside
 *       any card) is drawn as before;
 *   R2  the page as jsdom draws it with a 1280 and a 390 px window's
 *       styles: a card with both has exactly the link then the button, no
 *       text node between them, and its row computes `display: flex`; a
 *       card with only the button, or only the links, holds just those
 *       (since queue #250 a card with a file also ends with *Its other
 *       sessions*); the words, the link's address and the button's are as
 *       before.
 *
 * jsdom lays out nothing: the gap in pixels is measured in a real Chromium
 * by the stack test (tests/stack/session-page-secret-steps.test.ts, K5).
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, PUB, T, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const ROW = ".secret-card > .secret-rule";

test("R1: a card's last line is a wrapping flex row with a gap of at least 8 px between its controls, and the plain .secret-rule keeps only its font size", () => {
  const rules = flattenCss(stripComments(CSS));
  /** Each value `prop` takes for `selector`, with the query that sets it. */
  const values = (selector: string, prop: string) =>
    rules.filter((r) => r.selectors.includes(selector) && declValue(r.block, prop) !== null).map((r) => [String(r.media), declValue(r.block, prop)]);
  assert.deepEqual(values(ROW, "display"), [["null", "flex"]], "a flex row");
  assert.deepEqual(values(ROW, "flex-wrap"), [["null", "wrap"]], "that wraps");
  assert.deepEqual(values(ROW, "align-items"), [["null", "center"]], "its items centred on the row");
  const gap = values(ROW, "gap");
  assert.equal(gap.length, 1, "one gap, set at every width");
  const [rowGap, colGap = rowGap] = String(gap[0]![1]).split(/\s+/).map((v) => parseFloat(v));
  assert.equal(gap[0]![0], "null");
  assert.ok(colGap! >= 8, `a column gap of at least 8 px (${colGap})`);
  assert.ok(rowGap! >= 4, `a row gap when it wraps (${rowGap})`);
  // No other rule, in any query, lays out a .secret-rule otherwise.
  const others = rules.filter((r) => r.selectors.some((s) => /\.secret-rule$/.test(s) && s !== ROW)
    && ["display", "gap", "column-gap", "flex-wrap", "flex-direction"].some((p) => declValue(r.block, p) !== null));
  assert.deepEqual(others.map((r) => r.selectors.join(", ")), [], "the plain .secret-rule (the Scan page's .scan-rule) is laid out as before");
  assert.deepEqual(values(".secret-rule", "font-size"), [["null", "14px"]]);
});

// ── R2: the page ─────────────────────────────────────────────────────────────

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const lines = [{ tone: "good", parts: [T("The AI got only its masked version, never the real value.")] }];
const BOTH = { what: [T("The environment variable "), { kind: "code", text: "STRIPE_KEY" }], level: "No AI", saw: "masked", lines, file: "~/app/.env", steps: ["s-1"], turns: [AGENT.story[1]!.id] };
const BUTTON = { what: [{ kind: "code", text: "DB_PASSWORD" }], level: "No AI", saw: "masked", lines, steps: ["s-1"], turns: [AGENT.story[1]!.id] };
const LINK = { what: [T("The file "), { kind: "code", text: "~/app/old.key" }], level: "No AI", saw: "masked", lines, file: "~/app/old.key" };
const PAGE = { ...AGENT, waiting: [], secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 3, early: 0 }, secrets: [BOTH, BUTTON, LINK] } };

test("R2: a card with both controls holds the link then the button, no text between them, in a flex row at 1280 and 390 px; a card with one holds that one", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick(40);
  const sheet = doc.createElement("style");
  doc.head.append(sheet);
  const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as El[];
  assert.equal(cards.length, 3);
  const row = (c: El) => c.querySelector(":scope > .secret-rule");
  const kids = (c: El) => ([...row(c).childNodes] as El[]).map((n) => (n.nodeType === 3 ? `text:${JSON.stringify(n.textContent)}` : `${n.tagName.toLowerCase()}:${n.textContent}`));
  // Since queue #250 a card with a file ends with Its other sessions too,
  // in the same row, no text between (§4.25b *A card finds its other sessions*).
  assert.deepEqual(kids(cards[0]), ["a:Change it in Rules", "button:Show its steps", "a:Its other sessions"], "the link, then the button, nothing between them");
  assert.deepEqual(kids(cards[1]), ["button:Show its steps"], "a key with no file (and no key name): the button alone");
  assert.deepEqual(kids(cards[2]), ["a:Change it in Rules", "a:Its other sessions"], "a card with no steps: the links alone");
  assert.equal(row(cards[0]).querySelector("a").getAttribute("href"), "/mandu/rules?file=~/app/.env", "the link opens Rules at its file, as before");
  for (const width of [1280, 390]) {
    sheet.textContent = resolveCssVars(stylesAt(CSS, width));
    for (const c of cards) {
      const cs = doc.defaultView.getComputedStyle(row(c));
      assert.equal(cs.display, "flex", `${width} px: the card's row is a flexbox`);
      assert.equal(cs.flexWrap, "wrap", `${width} px: that wraps`);
    }
  }
  // The button still filters the story.
  row(cards[0]).querySelector("button").click();
  assert.equal(row(cards[0]).querySelector("button").textContent, "Show every turn");
  assert.ok(doc.getElementById("agent-secret-only"), "the story's filter line is drawn");
});
