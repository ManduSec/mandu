/**
 * home-js-ask-headings.test — dashboard.md §4.25u, *Each question and
 * rule change is a heading*. The cards that wait for an answer are the part of the product
 * page a person must act on, and a screen-reader user moves through a page
 * by its headings (the H key in NVDA and JAWS, the VoiceOver rotor). Until
 * 2026-10-27 a question's and a rule change's headline was a plain div, so
 * reaching the third question meant reading through the first two, cells
 * and buttons included (WCAG 2.1 SC 1.3.1).
 *
 *   A1  on Approvals every waiting card (a send, a held message, a
 *       program's send of the files it holds) and the rule change has
 *       exactly one heading: its headline, an h3, the element its
 *       `aria-labelledby` names, its words and code chips as before;
 *   A2  a card under *From sessions that have ended* has an h4, under that
 *       group's h3; with every question ended there is no group head and
 *       the card's heading is an h3;
 *   A3  Home's short cards and the session page's *Needs your OK* have
 *       one h3 each, under their h2;
 *   A4  the heading levels of Home, Approvals and the session page never
 *       skip (h1, h2, h3, h4);
 *   A5  under the page's styles, light and dark, the h3 and the h4 look as
 *       the div they replace did: font size, weight, colour, margin and
 *       display, and never a heading's balanced wrap.
 *
 * Over the real arbiter and dashboard: tests/stack/ask-card-headings.test.ts.
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, ASK, PUB, T, home, load, tick } from "./home-js-fixtures.js";
import { perSelector, resolveCssVars, stylesAt } from "./css-flatten.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const C = (text: string) => ({ kind: "code", text });
const LIVE = { ...ASK, id: "live-1", sentence: [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C("api.stripe.com")] };
const PROMPT = {
  ...ASK, id: "prompt-1", family: "prompt",
  sentence: [T("Claude Code wants to send your message to the AI. It holds "), C("acme.codename"), T(".")],
  actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
};
const HOLDER = {
  ...ASK, id: "holder-1",
  sentence: [T("Claude Code's program wants to send data from "), C("~/ws/app/.env"), T(" to "), C("hooks.slack.com")],
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
};
const ENDED = { ...ASK, id: "ended-1", askerEnded: true, sentence: [T("Codex wants to send your secret "), C("GITHUB_TOKEN"), T(" to "), C("gist.github.com")] };
const PROPOSAL = {
  id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[T("Trust content from "), C("https://pypi.org/"), T(" and show it to the AI unmasked")]],
  wouldLet: [], capped: false, overBroad: false,
};
const ROUTES = {
  "GET policy/proposals?status=pending": { proposals: [PROPOSAL] },
  "GET prompt-filters/holds": { holds: [] },
};
const WORDS: Record<string, string> = {
  "live-1": "Claude Code wants to send your secret STRIPE_KEY to api.stripe.com",
  "prompt-1": "Claude Code wants to send your message to the AI. It holds acme.codename.",
  "holder-1": "Claude Code's program wants to send data from ~/ws/app/.env to hooks.slack.com",
  "ended-1": "Codex wants to send your secret GITHUB_TOKEN to gist.github.com",
  "pp-000001": "Your agent wants to change a rule",
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const said = (e: El) => String(e.textContent).replace(/\s+/g, " ").trim();
const HEADS = "h1, h2, h3, h4, h5, h6";
/** The headings a screen reader lists on a page: none inside a hidden part. */
const listed = (doc: El, page: string) => ([...doc.querySelectorAll(`#page-${page} :is(${HEADS})`)] as El[])
  .filter((h) => !h.closest("[hidden]"));
/** A card's one heading, checked to be what names it; returns it. */
function headingOf(doc: El, card: El): El {
  const heads = [...card.querySelectorAll(HEADS)] as El[];
  assert.equal(heads.length, 1, `${card.dataset.id}: one heading`);
  const h = heads[0];
  assert.ok(h.classList.contains("ask-sentence"), `${card.dataset.id}: the headline is the heading`);
  assert.equal(doc.getElementById(card.getAttribute("aria-labelledby")), h, `${card.dataset.id}: the group is named by its heading`);
  assert.equal(card.getAttribute("role"), "group");
  assert.equal(h.querySelector("div, p"), null, "the heading holds only words and code");
  return h;
}
const noSkip = (levels: number[], where: string) => levels.forEach((l, i) => {
  if (i) assert.ok(l <= levels[i - 1]! + 1, `${where}: heading ${i} (h${l}) after h${levels[i - 1]}: no level skipped`);
});

async function approvals(waiting: unknown[]): Promise<El> {
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting }), routes: ROUTES });
  await tick();
  return doc;
}

test("A1: on Approvals each waiting card and the rule change has one h3, its headline, which names it", async () => {
  const doc = await approvals([LIVE, PROMPT, HOLDER]);
  const cards = [...doc.querySelectorAll("#approvals-waiting .ask, #approvals-proposals .ask")] as El[];
  assert.deepEqual(cards.map((c) => c.dataset.id).sort(), ["holder-1", "live-1", "pp-000001", "prompt-1"]);
  for (const card of cards) {
    const h = headingOf(doc, card);
    assert.equal(h.tagName, "H3", `${card.dataset.id}: an h3`);
    assert.equal(said(h), WORDS[card.dataset.id], `${card.dataset.id}: the words are the headline's`);
  }
  // The names in it still read as code, kept whole (keepNamesWhole).
  const live = doc.querySelector('#approvals-waiting .ask[data-id="live-1"] h3');
  assert.deepEqual([...live.querySelectorAll("code")].map((c: El) => c.textContent), ["STRIPE_KEY", "api.stripe.com"]);
  assert.ok(live.querySelector("code").classList.contains("code-whole"));
  // Each under its section's h2.
  assert.equal(said(live.closest("section.block").querySelector("h2")), "Waiting for your answer (3)", "with the count of its questions");
  assert.equal(said(doc.querySelector("#approvals-proposals h3").closest("section.block").querySelector("h2")), "Rule changes your agent asked for (1)", "with the count of its cards");
  const ids = cards.map((c) => c.getAttribute("aria-labelledby"));
  assert.equal(new Set(ids).size, ids.length, "each card its own heading id");
});

test("A2: under 'From sessions that have ended' a card's heading is an h4; with every question ended, no group and an h3", async () => {
  const doc = await approvals([LIVE, ENDED]);
  const ended = doc.querySelector('#approvals-waiting .ask[data-id="ended-1"]');
  const h = headingOf(doc, ended);
  assert.equal(h.tagName, "H4");
  assert.equal(said(h), WORDS["ended-1"]);
  const group = [...doc.querySelectorAll("#approvals-waiting .ask-group-head h3")] as El[];
  assert.equal(group.length, 1);
  assert.equal(said(group[0]), "From sessions that have ended");
  assert.ok(group[0].compareDocumentPosition(h) & 4, "the h4 follows its group's h3");
  assert.equal(headingOf(doc, doc.querySelector('#approvals-waiting .ask[data-id="live-1"]')).tagName, "H3", "the live one above stays an h3");
  const alone = await approvals([ENDED]);
  assert.equal(alone.querySelector("#approvals-waiting .ask-group-head"), null, "all ended: no group head");
  assert.equal(headingOf(alone, alone.querySelector('#approvals-waiting .ask[data-id="ended-1"]')).tagName, "H3");
});

test("A3: Home's short cards and the session page's Needs your OK have one h3 each, under their h2", async () => {
  const { doc } = load({ homeVm: home({ waiting: [LIVE, ENDED, HOLDER] }), routes: ROUTES });
  await tick();
  const cards = [...doc.querySelectorAll("#home-waiting .ask")] as El[];
  assert.equal(cards.length, 3);
  for (const card of cards) {
    const h = headingOf(doc, card);
    assert.equal(h.tagName, "H3", `${card.dataset.id}: Home has no ended group, an h3`);
    assert.equal(said(h), WORDS[card.dataset.id]);
  }
  assert.match(said(doc.getElementById("home-waiting-title")), /^Approvals waiting/);

  const agent = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, waiting: [LIVE, PROMPT] }, ...ROUTES } });
  await tick();
  const mine = [...agent.doc.querySelectorAll("#agent-waiting .ask")] as El[];
  assert.equal(mine.length, 2);
  for (const card of mine) assert.equal(headingOf(agent.doc, card).tagName, "H3");
  assert.equal(said(agent.doc.querySelector("#agent-waiting-block h2")), "Needs your OK");
});

test("A4: the heading levels of Home, Approvals and the session page never skip", async () => {
  const appr = await approvals([LIVE, PROMPT, ENDED]);
  const a = listed(appr, "approvals");
  noSkip(a.map((h) => Number(h.tagName[1])), "Approvals");
  assert.deepEqual(a.map((h) => `${h.tagName} ${said(h)}`).filter((s) => /^H[34]/.test(s)), [
    `H3 ${WORDS["pp-000001"]}`, `H3 ${WORDS["live-1"]}`, `H3 ${WORDS["prompt-1"]}`,
    "H3 From sessions that have ended", `H4 ${WORDS["ended-1"]}`,
  ], "each question in the page's heading list, in page order");

  const { doc } = load({ homeVm: home({ waiting: [LIVE, ENDED] }), routes: ROUTES });
  await tick();
  const h = listed(doc, "home");
  noSkip(h.map((x) => Number(x.tagName[1])), "Home");
  const i = h.findIndex((x) => x.id === "home-waiting-title");
  assert.deepEqual(h.slice(i + 1, i + 3).map((x) => `${x.tagName} ${said(x)}`), [`H3 ${WORDS["live-1"]}`, `H3 ${WORDS["ended-1"]}`], "the questions right under Approvals waiting");

  const agent = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, waiting: [LIVE] }, ...ROUTES } });
  await tick();
  noSkip(listed(agent.doc, "agent").map((x) => Number(x.tagName[1])), "the session page");
});

// ── The look (A5) ───────────────────────────────────────────────────────────

/** The product page's own styles after the browser's own heading rules
 *  (jsdom has none), so a heading not reset reads large, bold and spaced
 *  here as it would on screen. */
const UA = "h3 { display: block; font-size: 1.17em; font-weight: bold; margin: 1em 0; } h4 { display: block; font-weight: bold; margin: 1.33em 0; }";
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
function styled(doc: El, theme: "light" | "dark"): void {
  let sheet = doc.getElementById("headings-styles");
  if (!sheet) {
    sheet = doc.createElement("style");
    sheet.id = "headings-styles";
    doc.head.append(sheet);
  }
  sheet.textContent = perSelector(resolveCssVars(`${UA}\n${stylesAt(CSS, 1280)}`, theme));
}
const look = (doc: El, e: El) => {
  const cs = doc.defaultView.getComputedStyle(e);
  return {
    size: cs.fontSize, weight: cs.fontWeight, color: cs.color, display: cs.display,
    margin: [cs.marginTop, cs.marginRight, cs.marginBottom, cs.marginLeft].map((m: string) => m || "0px").join(" "),
  };
};

test("A5: under the page's styles, light and dark, the h3 and the h4 look as the div they replace did, and are not balanced", async () => {
  const doc = await approvals([LIVE, ENDED]);
  const h3 = doc.querySelector('#approvals-waiting .ask[data-id="live-1"] h3.ask-sentence');
  const h4 = doc.querySelector('#approvals-waiting .ask[data-id="ended-1"] h4.ask-sentence');
  const rule = doc.querySelector("#approvals-proposals h3.ask-sentence");
  // The line as it was before 2026-10-27, beside it: a div.ask-sentence in .ask-body.
  const old = doc.createElement("div");
  old.className = "ask-sentence";
  old.textContent = WORDS["live-1"];
  h3.parentElement.append(old);
  for (const theme of ["light", "dark"] as const) {
    styled(doc, theme);
    const was = look(doc, old);
    assert.equal(was.size, "16px", `${theme}: the line was 16 px`);
    assert.equal(was.weight, "500", `${theme}: at 500`);
    for (const [name, e] of [["a question's h3", h3], ["an ended question's h4", h4], ["a rule change's h3", rule]] as const) {
      assert.deepEqual(look(doc, e), was, `${theme}: ${name} looks as the line did`);
      // A heading is balanced (app.css, §4.25u *No word alone on a last
      // line*); these are not, so a long headline wraps where it did.
      assert.notEqual(doc.defaultView.getComputedStyle(e).getPropertyValue("text-wrap-style"), "balance", `${theme}: ${name} keeps its wrap`);
    }
  }
  // The rule still balances the page's other headings.
  assert.equal(doc.defaultView.getComputedStyle(doc.querySelector("#approvals-waiting-block h2")).getPropertyValue("text-wrap-style"), "balance");
});
