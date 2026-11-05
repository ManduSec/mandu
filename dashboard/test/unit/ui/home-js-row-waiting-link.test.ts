/**
 * home-js-row-waiting-link.test — dashboard.md §4.25 *Agents, not
 * sessions*, §4.25ae *History says what waits for you* and *A link that
 * goes where a tile goes*. Running now, Earlier and History said "1
 * question waiting for you" in a row's counts line as plain text, and the
 * row opened the session page at its top, Needs your OK below every tile.
 * Now the words are a link to the session at its question (`?go=waiting`):
 *
 *   Q1  a Running now, an Earlier and a History row with waiting 1 or 2
 *       draw the words as one link to `/agents/<id>?go=waiting`, named by
 *       its row, the rest of the counts line unchanged; a row with none
 *       draws no link;
 *   Q2  pressed, the session page opens with its first waiting card
 *       focused and scrolled to, `go` dropped from the address, and the
 *       row click does not also run; a modified click is left to the
 *       browser (a new tab at the link's address);
 *   Q3  `parseRoute` reads `?go=waiting`; opened at it with no card left,
 *       Needs your OK's heading has the focus (a rule change still shows
 *       the block); with the block hidden the page opens as a plain link
 *       opens it, with no error.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const HISTORY = "http://127.0.0.1:4500/mandu/history";
const now = new Date().toISOString();
const agent = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: now, lastAt: now, state: "running",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
const rowIn = (doc: El, list: string, id: string) => doc.querySelector(`#${list} .row.agent[data-session="${id}"]`);
const linkIn = (row: El) => row.querySelectorAll("a.agent-waiting-link");
const clickOn = (target: El, init: Record<string, unknown> = {}) =>
  target.dispatchEvent(new target.ownerDocument.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, ...init }));

function assertLink(row: El, id: string, words: string, counts: string) {
  const links = linkIn(row);
  assert.equal(links.length, 1, `${id}: one link`);
  const a = links[0];
  assert.equal(a.getAttribute("href"), `/mandu/agents/${id}?go=waiting`);
  assert.equal(a.dataset.pageLink, "agent");
  assert.equal(a.dataset.session, id);
  assert.equal(a.dataset.land, "waiting");
  assert.equal(a.textContent, words);
  assert.equal(a.closest(".agent-counts"), row.querySelector(".agent-counts"), `${id}: in the counts line`);
  assert.equal(row.querySelector(".agent-counts").textContent, counts, `${id}: the rest of the line unchanged`);
  assert.equal(a.getAttribute("aria-label"), `${words}: Claude Code, Task ${id} in ~/ws`, `${id}: its own words first, then its row, as Details is named`);
  assert.equal(row.querySelector("a.right").getAttribute("aria-label"), `Details: Claude Code, Task ${id} in ~/ws`);
}

test("Q1: Running now, Earlier and History rows draw their waiting questions as one link to the session at Needs your OK, named by the row; a row with none has no link", async () => {
  const homeVm = home({ agents: [
    agent("r1", { state: "waiting", waiting: 1 }),
    agent("r2", { waiting: 0 }),
    agent("e1", { state: "idle", waiting: 2 }),
    agent("e2", { state: "idle" }),
  ] });
  const h = load({ homeVm });
  await tick();
  assertLink(rowIn(h.doc, "home-agents", "r1"), "r1", "1 question waiting for you", "1 question waiting for you, 1 secret masked");
  assertLink(rowIn(h.doc, "home-earlier", "e1"), "e1", "2 questions waiting for you", "1 secret masked, 2 questions waiting for you");
  assert.equal(linkIn(rowIn(h.doc, "home-agents", "r2")).length, 0);
  assert.equal(linkIn(rowIn(h.doc, "home-earlier", "e2")).length, 0);
  // Number and word stay together inside the link.
  assert.deepEqual([...linkIn(rowIn(h.doc, "home-earlier", "e1"))[0].querySelectorAll(".count-word")].map((s: El) => s.textContent), ["2 questions"]);

  const rows = [agent("w1", { state: "waiting", waiting: 1 }), agent("w2", { state: "idle", waiting: 2 }), agent("w3", { state: "idle" })];
  const p = load({ extensions: "", url: HISTORY, homeVm: home(), routes: { "GET home/history": { total: 3, rows, next: null } } });
  await tick();
  // A running History row leads with it, as Running now does; an ended one
  // says it last, as Earlier does (§4.25ae).
  assertLink(rowIn(p.doc, "history-list", "w1"), "w1", "1 question waiting for you", "1 question waiting for you, 1 secret masked");
  assertLink(rowIn(p.doc, "history-list", "w2"), "w2", "2 questions waiting for you", "1 secret masked, 2 questions waiting for you");
  assert.equal(linkIn(rowIn(p.doc, "history-list", "w3")).length, 0);
});

test("Q2: pressed, the session opens at its first waiting card, the row click does not also run, and a modified click is the browser's", async () => {
  const opened: unknown[][] = [];
  const rows = [agent("s1", { state: "idle", waiting: 1 })];
  const { doc, window, calls } = load({
    extensions: "", url: HISTORY, homeVm: home(),
    routes: { "GET home/history": { total: 1, rows, next: null }, "GET home/agent?session=s1": AGENT },
    before: (w) => { w.open = (...a: unknown[]) => { opened.push(a); return null; }; },
  });
  await tick();
  const scrolled: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: El) { scrolled.push(this.className); };
  const link = linkIn(rowIn(doc, "history-list", "s1"))[0];
  // A Ctrl-click: neither the page's nor the row's, so the browser opens the link's own address.
  const ctrl = new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true });
  link.dispatchEvent(ctrl);
  assert.equal(ctrl.defaultPrevented, false, "left to the browser");
  assert.deepEqual(opened, [], "the row click did not open Details' address in a new tab");
  assert.equal(window.location.pathname, "/mandu/history");
  clickOn(link);
  await tick(40);
  assert.equal(calls.filter((c) => c.url === "/mandu/api/home/agent?session=s1").length, 1, "one read of the page: the row click did not open it again");
  assert.deepEqual(opened, []);
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1", "used once: a reload or Back does not land again");
  const card = doc.activeElement;
  assert.ok(card.classList.contains("ask"), "a waiting card has the focus");
  assert.equal(card.parentElement.id, "agent-waiting");
  assert.equal(card, doc.querySelector("#agent-waiting .ask"), "the first one");
  assert.ok(scrolled.some((c) => /\bask\b/.test(c)), "and is scrolled to");
});

test("Q3: ?go=waiting is read; with no card left the heading of Needs your OK has the focus, with the block hidden the page opens plainly", async () => {
  const opened = load({ url: "http://127.0.0.1:4500/mandu/agents/s1?go=waiting", homeVm: home(), routes: { "GET home/agent?session=s1": AGENT } });
  assert.deepEqual(JSON.parse(opened.window.eval("JSON.stringify(parseRoute('/mandu/agents/x', '?go=waiting'))")), { page: "agent", session: "x", ask: null, go: "waiting" });
  await tick(40);
  assert.ok(opened.doc.activeElement.classList.contains("ask"), "a typed address lands as the link does");
  assert.equal(opened.window.location.search, "", "and drops `go`");

  // Answered meanwhile, a rule change this agent asked for still shows the block.
  const change = {
    id: "pp-000001", status: "pending", requester: "Your agent", session: "s1", createdAt: Date.now() - 60_000,
    headline: "Your agent wants to change a rule", rows: [[{ kind: "text", text: "Let it be sent to api.stripe.com" }]],
    wouldLet: [], capped: false, overBroad: false, warnings: [], reason: null, onDisk: false,
  };
  // Pressed from History, where the page already knows it (a typed address
  // may draw the page before the rule changes are read: then the block is
  // hidden at the landing, the last case below).
  const answered = load({
    extensions: "", url: HISTORY, homeVm: home({ waiting: [] }),
    routes: {
      "GET home/history": { total: 1, rows: [agent("s1", { state: "idle", waiting: 1 })], next: null },
      "GET policy/proposals?status=pending": { proposals: [change] }, "GET home/agent?session=s1": { ...AGENT, waiting: [] },
    },
  });
  assert.equal(answered.err, null);
  await tick();
  clickOn(linkIn(rowIn(answered.doc, "history-list", "s1"))[0]);
  await tick(40);
  const block = answered.doc.getElementById("agent-waiting-block");
  assert.equal(block.hidden, false, "the rule change keeps Needs your OK shown");
  assert.equal(block.querySelector(".ask"), null, "no card");
  assert.equal(answered.doc.activeElement, block.querySelector("h2"), "the heading of Needs your OK has the focus");

  const none = load({ url: "http://127.0.0.1:4500/mandu/agents/s1?go=waiting", homeVm: home({ waiting: [] }), routes: { "GET home/agent?session=s1": { ...AGENT, waiting: [] } } });
  assert.equal(none.err, null);
  await tick(40);
  assert.equal(none.doc.getElementById("page-agent").hidden, false, "the page is drawn");
  assert.equal(none.doc.getElementById("agent-waiting-block").hidden, true);
  assert.equal(none.doc.activeElement.closest?.("#agent-waiting-block") ?? null, null, "nothing hidden takes the focus");
  assert.equal(none.window.location.search, "", "`go` is dropped all the same");
});
