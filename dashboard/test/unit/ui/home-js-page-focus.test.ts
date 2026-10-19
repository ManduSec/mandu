/**
 * home-js-page-focus.test — a page change of the PRODUCT page gives the
 * keyboard focus to the page shown (public/js/home.js `focusPage` and
 * `focusMarked`, dashboard.md §4.25 *A page change moves the focus*).
 *
 * Until 2026-10-10 nothing moved it. A link inside a page stayed focused in
 * the section the change hid. In a browser the focus fell to <body>, a
 * screen reader said nothing of the new page, and a Tab from a link to an
 * earlier page left the document. Now each navigation (a link, Back or
 * Forward, a notification, a link that opens at a card) focuses the new
 * page's heading. Where the page scrolls by itself once a visit, the marked
 * card or step takes the focus from that heading, and takes it back when a
 * poll draws it again. The first load leaves the focus alone, and so does
 * a person who moved it first.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * Each link is focused before its click, as a keyboard's Enter does. Axes:
 * none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, FILES_ROUTES, home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";

const BASE = "http://127.0.0.1:4500/mandu";
const ASK2 = { ...ASK, id: "egr-2", askedAt: Date.now() - 120_000 };
const ANSWERED = { id: "egr-9", sentence: [{ kind: "text", text: "Codex CLI wanted to send a file" }], outcome: "blocked", decidedAt: Date.now() - 30_000, actions: [] };
const two = () => home({ waiting: [ASK, ASK2], answered: [ANSWERED] });

/** The h1 of the page shown, and that it is the only page shown. */
function shownHeading(doc: any) {
  const shown = [...doc.querySelectorAll("#main > section[data-page]")].filter((s: any) => !s.hidden) as any[];
  assert.equal(shown.length, 1, "one page is shown");
  return shown[0].querySelector("h1");
}
/** Enter on a link: it has the focus, then the click. */
async function press(link: any) {
  assert.ok(link, "the link is there");
  link.focus();
  link.click();
  await tick();
}
const navLink = (doc: any, page: string) => doc.querySelector(`#nav [data-page-link="${page}"]`);
const approvalsCard = (doc: any, id: string) => [...doc.querySelectorAll("#approvals-waiting .ask")].find((c: any) => c.dataset.id === id) as any;
/** Back or Forward: jsdom traverses the history on two chained 0 ms timers
 *  and changes the URL and fires popstate in the second, so the wait is on
 *  the URL. Until 2026-10-11 it was one 30 ms timer, which a stall of 30 ms
 *  before the first traversal timer let run first (pipeline 10259). */
const traverse = async (window: any, way: "back" | "forward") => {
  const from = window.location.pathname;
  window.history[way]();
  await waitWhile(() => window.location.pathname === from);
  await tick();
};
const poll = async (doc: any, window: any) => {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
};

test("each page the nav opens has the focus on its heading, which a screen reader reads", async () => {
  const { doc } = load();
  await tick();
  for (const [page, words] of [["approvals", "Approvals"], ["rules", "Rules"], ["settings", "Settings"], ["home", "One question is waiting for you."]]) {
    await press(navLink(doc, page));
    const h1 = shownHeading(doc);
    assert.equal(doc.activeElement, h1, `${page}: the focus is on the page's heading`);
    assert.equal(h1.textContent, words);
    assert.equal(h1.getAttribute("tabindex"), "-1", "focusable by the page, not a Tab stop");
  }
});

test("a link inside a page: the focus goes to the new page's heading, never left on the link the change hid", async () => {
  const { doc, window } = load();
  await tick();
  // Home › Running now: an agent's row opens its page.
  const link = doc.querySelector('#home-agents a[data-page-link="agent"][data-session="s1"]');
  await press(link);
  assert.equal(doc.getElementById("page-agent").hidden, false, "the agent page is shown");
  assert.equal(link.closest("section[data-page]").hidden, true, "the link's page is hidden");
  assert.equal(doc.activeElement, doc.getElementById("agent-name"), "the focus is on the agent's name");
  assert.equal(doc.activeElement.textContent, AGENT.agent);
  // Its Back to home, to a page before it: opened from Home in this tab, it
  // is Back (§4.25ad *The back link names where you came from*), which
  // jsdom traverses on timers, so the wait is on the URL.
  const back = doc.querySelector('#page-agent a.back[data-page-link="home"]');
  back.focus();
  back.click();
  await waitWhile(() => window.location.pathname !== "/mandu/");
  await tick();
  assert.equal(doc.activeElement, doc.getElementById("hero-headline"), "Home's verdict");
});

test("Back and Forward give the focus to the heading of the page they show", async () => {
  const { doc, window } = load();
  await tick();
  await press(navLink(doc, "rules"));
  await press(navLink(doc, "settings"));
  await traverse(window, "back");
  assert.equal(window.location.pathname, "/mandu/rules");
  assert.equal(doc.activeElement, shownHeading(doc));
  assert.equal(doc.activeElement.textContent, "Rules");
  await traverse(window, "forward");
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.equal(doc.activeElement.textContent, "Settings");
});

test("the first load leaves the focus where the browser puts it", async () => {
  for (const url of [BASE + "/", BASE + "/rules", BASE + "/settings", BASE + "/approvals/egr-2", BASE + "/agents/s1"]) {
    const { doc } = load({ url, homeVm: two() });
    await tick();
    assert.equal(doc.activeElement, doc.body, url);
  }
});

test("Details: the marked Approvals card takes the focus from the heading", async () => {
  const { doc } = load({ homeVm: two() });
  await tick();
  await press(doc.querySelectorAll("#home-waiting .ask-details")[1]);
  const card = approvalsCard(doc, "egr-2");
  assert.ok(card.classList.contains("focus"), "marked");
  assert.equal(doc.activeElement, card, "the focus is on the marked card");
  assert.equal(card.getAttribute("tabindex"), "-1");
});

test("already answered: the marked row takes the focus; no longer waiting: the note that says so", async () => {
  const answered = load({ homeVm: two() });
  await tick();
  answered.window.history.pushState(null, "", "/mandu/approvals/egr-9");
  answered.window.dispatchEvent(new answered.window.PopStateEvent("popstate"));
  await tick();
  assert.equal(answered.doc.activeElement, answered.doc.querySelector("#approvals-answered .row.answered.focus"));
  const gone = load({ homeVm: two() });
  await tick();
  gone.window.history.pushState(null, "", "/mandu/approvals/egr-404");
  gone.window.dispatchEvent(new gone.window.PopStateEvent("popstate"));
  await tick();
  const note = gone.doc.getElementById("approvals-focus-note");
  assert.equal(note.textContent, "That question is no longer waiting for you.");
  assert.equal(gone.doc.activeElement, note);
});

test("a poll that draws the marked card again gives the new card the focus back; a plain visit marks and moves nothing more", async () => {
  const { doc, window, setHome } = load({ homeVm: two() });
  await tick();
  await press(doc.querySelectorAll("#home-waiting .ask-details")[1]);
  const before = approvalsCard(doc, "egr-2");
  assert.equal(doc.activeElement, before);
  setHome(home({ waiting: [ASK, { ...ASK2, count: 2 }], answered: [ANSWERED] }));
  await poll(doc, window);
  const after = approvalsCard(doc, "egr-2");
  assert.notEqual(after, before, "the cards were drawn again");
  assert.equal(doc.activeElement, after, "the focus is on the card drawn now, not lost to the page");
  // The person moves on, to a button of another card: a later redraw
  // takes nothing back to the mark.
  const button = [...approvalsCard(doc, "egr-1").querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any;
  button.focus();
  setHome(home({ waiting: [ASK, { ...ASK2, count: 3 }], answered: [ANSWERED] }));
  await poll(doc, window);
  assert.notEqual(approvalsCard(doc, "egr-2"), after, "drawn again");
  assert.notEqual(doc.activeElement, approvalsCard(doc, "egr-2"), "a focus the person moved is not taken back to the mark");
  // The nav's Approvals: no mark, the heading.
  await press(navLink(doc, "approvals"));
  assert.equal(doc.activeElement, shownHeading(doc));
});

test("the agent page opened at an answer: the step where Mandu asked takes the focus", async () => {
  const { doc } = load({
    url: BASE + "/approvals",
    homeVm: home({ waiting: [], answered: [{ ...ANSWERED, id: "egr-7", sessions: ["s1"] }] }),
    routes: { "GET home/agent?session=s1&ask=egr-7": { ...AGENT, focus: { ask: "egr-7", turnId: "turn:i2", stepId: "r7", match: "exact" } } },
  });
  await tick();
  const link = [...doc.querySelectorAll("#approvals-answered a.ask-link")].find((a: any) => a.dataset.ask === "egr-7");
  await press(link);
  const step = [...doc.querySelectorAll("#agent-story [data-step-id]")].find((s: any) => s.dataset.stepId === "r7") as any;
  assert.ok(step.classList.contains("focus"), "marked");
  assert.equal(doc.activeElement, step, "the focus is on the marked step");
});

test("a person who moves the focus before the page has drawn keeps it", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const { doc } = load({
    url: BASE + "/approvals",
    homeVm: home({ waiting: [], answered: [{ ...ANSWERED, id: "egr-7", sessions: ["s1"] }] }),
    routes: { "GET home/agent?session=s1&ask=egr-7": () => gate.then(() => ({ ...AGENT, focus: { ask: "egr-7", turnId: "turn:i2", stepId: "r7", match: "exact" } })) },
  });
  await tick();
  await press([...doc.querySelectorAll("#approvals-answered a.ask-link")].find((a: any) => a.dataset.ask === "egr-7"));
  assert.equal(doc.activeElement, doc.getElementById("agent-name"), "the heading, while the page is read");
  const trace = doc.getElementById("agent-trace");
  trace.focus();
  release();
  await tick();
  assert.ok(doc.querySelector("#agent-story .step.focus"), "the step is marked");
  assert.equal(doc.activeElement, trace, "the focus stays where the person put it");
});

test("a link that opens at a card: the card's heading takes the focus once the card is drawn", async () => {
  const { doc } = load({ url: BASE + "/settings", routes: {
    ...FILES_ROUTES, "GET policy/sensitivity-labels": { labels: labelSettingsVM(null, undefined, null) }, "GET suggestions": { suggestions: [], count: 0, scan: null },
  } });
  await tick();
  await press(doc.querySelector("#settings-labels .labels-note a"));
  await tick();
  assert.equal(doc.activeElement, doc.getElementById("suggested-title"), "Keys Mandu found's heading");
  assert.equal(doc.activeElement.closest("section[data-page]").id, "page-rules");
});
