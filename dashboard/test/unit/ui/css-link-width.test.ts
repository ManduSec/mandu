/**
 * css-link-width — a text link that sits in one of the page's columns is
 * only as wide as its words (dashboard.md §4.25 *Page frame*). Mandu-new.
 *
 * "Back to home" (`a.back`, the session page and History) sits in
 * `.page-head`, and "… in Approvals" (`.cards > a.more`, Home and the session
 * page) in `.cards`: both column flexboxes. With no alignment of their own,
 * each link stretched to the column: in a headless Chromium at 1280 px both
 * were 944 px wide around words of 85 and about 305 px. A click in the blank
 * space right of the words followed the link and left the page, the pointer
 * was a hand across the whole row, and the focus ring 944 px wide. Now each
 * is `align-self: flex-start`:
 *
 *   K1  the stylesheet: `.page-head` and `.cards` are column flexboxes, and
 *       `.back` and `.cards > .more` take `align-self: flex-start` at every
 *       width (no media query sets them back);
 *   K2  the pages as jsdom draws them with the styles a 1280, 390 and 320 px
 *       window applies: the session page's and History's "Back to home",
 *       Home's "1 rule change your agent asked for is in Approvals" and
 *       "1 more question in Approvals", and the session page's "1 rule
 *       change this agent asked for is in Approvals" each compute
 *       `align-self: flex-start` in a column flexbox; the words are as
 *       before.
 *
 * jsdom lays out nothing: the widths are the run's Chromium probe, and the
 * stack test measures them (tests/stack/product-link-width.test.ts). Axes:
 * none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, ASK, PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const WIDTHS = [1280, 390, 320];

test("K1: the two columns are column flexboxes, and their text links start at the column's edge at every width", () => {
  const rules = flattenCss(stripComments(CSS));
  /** Each value `prop` takes for `selector`, with the query that sets it. */
  const values = (selector: string, prop: string) =>
    rules.filter((r) => r.selectors.includes(selector) && declValue(r.block, prop) !== null).map((r) => [String(r.media), declValue(r.block, prop)]);
  for (const column of [".page-head", ".cards"]) {
    assert.deepEqual(values(column, "display"), [["null", "flex"]], `${column} is a flexbox`);
    assert.deepEqual(values(column, "flex-direction"), [["null", "column"]], `${column} is a column`);
  }
  for (const link of [".back", ".cards > .more"]) {
    assert.deepEqual(values(link, "align-self"), [["null", "flex-start"]], `${link} is only as wide as its words, at every width`);
  }
  // No other rule, in any query, aligns them otherwise.
  const others = rules.filter((r) => declValue(r.block, "align-self") !== null
    && r.selectors.some((s) => /\.(back|more)$/.test(s) && s !== ".back" && s !== ".cards > .more"));
  assert.deepEqual(others.map((r) => r.selectors.join(", ")), [], "no other rule aligns a .back or a .more");
});

// ── K2: the pages ────────────────────────────────────────────────────────────

const BASE = "http://127.0.0.1:4500/mandu";
const PENDING = "GET policy/proposals?status=pending";
const request = (id: string) => ({
  id, status: "pending", requester: "Your agent", session: "s1", createdAt: Date.now() - 60_000,
  headline: "Your agent wants to change a rule",
  rows: [[{ kind: "text", text: "Let " }, { kind: "code", text: "/srv/app/.env" }, { kind: "text", text: " be sent to api.stripe.com" }]],
  wouldLet: [], capped: false, overBroad: false, warnings: [], reason: null, onDisk: false,
});
const HISTORY_ROW = {
  id: "s1", agent: "Claude Code", title: "Fix the test", cwd: null, startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null,
};
/** Four questions (Home shows three, then "1 more question in Approvals")
 *  and one rule change the agent asked for. */
const ROUTES = {
  [PENDING]: { proposals: [request("pp-000001")] },
  "GET home/agent?session=s1": { ...AGENT, waiting: [] },
  "GET home/history": { total: 1, rows: [HISTORY_ROW], next: null },
};
const HOME = home({ waiting: [1, 2, 3, 4].map((i) => ({ ...ASK, id: `egr-${i}` })) });

/** The page at `path`, its styles as each window applies them. */
async function page(path: string): Promise<{ doc: El; at: (width: number) => void }> {
  const { doc } = load({ url: BASE + path, homeVm: HOME, routes: ROUTES });
  await tick(40);
  const sheet = doc.createElement("style");
  doc.head.append(sheet);
  return { doc, at: (width) => { sheet.textContent = resolveCssVars(stylesAt(CSS, width)); } };
}
/** The link's alignment and its column's direction, at `width`. */
function laid(doc: El, at: (width: number) => void, link: El, width: number): string[] {
  at(width);
  const cs = doc.defaultView.getComputedStyle.bind(doc.defaultView);
  return [cs(link.parentElement).display, cs(link.parentElement).flexDirection, cs(link).alignSelf];
}
const SNUG = ["flex", "column", "flex-start"];

test("K2: Back to home on the session page and on History, and the links to Approvals on Home and the session page, start at their column's edge at 1280, 390 and 320 px", async () => {
  const agent = await page("/agents/s1");
  const history = await page("/history");
  const homePage = await page("/");
  const cases: Array<[string, { doc: El; at: (w: number) => void }, string, string]> = [
    ["the session page's Back to home", agent, "#page-agent .page-head > a.back", "Back to home"],
    ["the session page's link to its rule change", agent, "#agent-waiting > a.more", "1 rule change this agent asked for is in Approvals"],
    ["History's Back to home", history, "#page-history .page-head > a.back", "Back to home"],
    ["Home's link to the rule change", homePage, "#home-waiting > a.more[data-ask]", "1 rule change your agent asked for is in Approvals"],
    ["Home's link to the other questions", homePage, "#home-waiting > a.more:not([data-ask])", "1 more question in Approvals"],
  ];
  for (const [what, { doc, at }, selector, words] of cases) {
    const link = doc.querySelector(selector);
    assert.ok(link, `${what} is drawn`);
    assert.equal(link.textContent, words, `${what}: its words, as before`);
    for (const w of WIDTHS) assert.deepEqual(laid(doc, at, link, w), SNUG, `${what} at ${w}px: only as wide as its words in its column`);
  }
});
