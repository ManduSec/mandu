/**
 * home-js-approvals-focus.test — a Home "Waiting for you" card's Details link
 * opens the same question in Approvals, marked (dashboard.md §4.25
 * "Details"): the link, the mark and its survival across a repaint, the
 * already-answered and gone cases, answering the marked card, a
 * notification click, and a plain Approvals visit marking nothing.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

const ASK2 = { ...ASK, id: "egr-2", askedAt: Date.now() - 120_000 };
const ANSWERED = { id: "egr-9", sentence: [{ kind: "text", text: "Codex CLI wanted to send a file" }], outcome: "blocked", decidedAt: Date.now() - 30_000, actions: [] };
const two = () => home({ waiting: [ASK, ASK2], answered: [ANSWERED] });
const approvalsCard = (doc: any, id: string) => [...doc.querySelectorAll("#approvals-waiting .ask")].find((c: any) => c.dataset.id === id) as any;
const marked = (doc: any) => [...doc.querySelectorAll("#page-approvals .focus")].map((x: any) => x.dataset.id);
const note = (doc: any) => doc.getElementById("approvals-focus-note");
const where = (window: any) => window.location.pathname + window.location.search;

test("each Home card links to its question in Approvals; Approvals' own cards do not", async () => {
  const { doc } = load({ homeVm: two() });
  await tick();
  const links = [...doc.querySelectorAll("#home-waiting .ask .ask-details")] as any[];
  assert.deepEqual(links.map((a) => a.textContent), ["Details in Approvals", "Details in Approvals"]);
  assert.deepEqual(links.map((a) => a.getAttribute("href")), ["/mandu/approvals/egr-1", "/mandu/approvals/egr-2"]);
  assert.equal(links[0].dataset.pageLink, "approvals");
  assert.equal(doc.querySelectorAll("#approvals-waiting .ask-details").length, 0, "Approvals already shows everything");
});

test("Details opens Approvals with that card marked; the URL can be reloaded or shared", async () => {
  const { doc, window } = load({ homeVm: two() });
  await tick();
  (doc.querySelectorAll("#home-waiting .ask-details")[1] as any).click();
  await tick();
  assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is showing");
  assert.equal(where(window), "/mandu/approvals/egr-2");
  assert.deepEqual(marked(doc), ["egr-2"], "only that card");
  assert.ok(approvalsCard(doc, "egr-2").classList.contains("expanded"), "in full");
  assert.equal(note(doc).hidden, true, "no note while it is waiting");
});

test("opened straight from the URL, the mark survives the poll's repaint", async () => {
  const { doc, window, setHome } = load({ url: "http://127.0.0.1:4500/mandu/approvals/egr-2", homeVm: two() });
  await tick();
  assert.deepEqual(marked(doc), ["egr-2"]);
  const before = approvalsCard(doc, "egr-2");
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  // A poll with the same answer leaves the cards as they are (§4.25 *The
  // poll keeps your place*), the mark on them.
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.equal(approvalsCard(doc, "egr-2"), before, "the same answer: the cards are left as they are");
  assert.deepEqual(marked(doc), ["egr-2"]);
  // A poll whose answer changed rebuilds them, and the mark comes back.
  setHome(home({ waiting: [ASK, { ...ASK2, count: 2 }], answered: [ANSWERED] }));
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.notEqual(approvalsCard(doc, "egr-2"), before, "the cards were rebuilt");
  assert.deepEqual(marked(doc), ["egr-2"], "and the mark came back");
});

test("already answered: the note says so and its Answered earlier row is marked", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals/egr-9", homeVm: two() });
  await tick();
  assert.equal(note(doc).hidden, false);
  assert.equal(note(doc).textContent, "That question was already answered. Its answer is marked below, under Answered earlier.");
  assert.deepEqual(marked(doc), ["egr-9"]);
  assert.ok(doc.querySelector("#approvals-answered .row.answered.focus"));
});

test("gone (timed out, or the agent stopped): the note, nothing marked", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals/egr-404", homeVm: two() });
  await tick();
  assert.equal(note(doc).hidden, false);
  assert.equal(note(doc).textContent, "That question is no longer waiting for you.");
  assert.deepEqual(marked(doc), []);
});

test("an id is compared as a value, never used as a selector", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals/" + encodeURIComponent("\"],*,[x=\""), homeVm: two() });
  await tick();
  assert.deepEqual(marked(doc), [], "a selector-shaped id marks nothing");
  assert.equal(note(doc).textContent, "That question is no longer waiting for you.");
});

test("answering the marked card drops the mark and the ask from the URL (no 'already answered' about your own answer)", async () => {
  let answered = false;
  const { doc, window, setHome } = load({
    url: "http://127.0.0.1:4500/mandu/approvals/egr-2",
    homeVm: two(),
    routes: { "POST egress/approvals/egr-2/deny": () => { answered = true; setHome(home({ waiting: [ASK], answered: [{ ...ANSWERED, id: "egr-2" }, ANSWERED] })); return { ok: true }; } },
  });
  await tick();
  const block = [...approvalsCard(doc, "egr-2").querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any;
  block.click();
  await tick();
  assert.equal(answered, true);
  assert.equal(where(window), "/mandu/approvals", "the ask left the URL");
  assert.equal(note(doc).hidden, true);
  assert.deepEqual(marked(doc), []);
});

test("a notification click opens Approvals at its question", async () => {
  const first = load();
  await tick();
  const stored = {
    "mandu.home.notifyPrimed": first.window.localStorage.getItem("mandu.home.notifyPrimed")!,
    "mandu.home.seenAsks": first.window.localStorage.getItem("mandu.home.seenAsks")!,
  };
  const { doc, window, notes } = load({ storage: stored, homeVm: home({ waiting: [ASK, ASK2] }) });
  await tick();
  assert.equal(notes.length, 1);
  window.focus = () => {};
  notes[0]!.note.onclick();
  await tick();
  assert.equal(where(window), "/mandu/approvals/egr-2");
  assert.deepEqual(marked(doc), ["egr-2"]);
});

test("a plain visit to Approvals (the nav link) marks nothing and shows no note", async () => {
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/approvals/egr-2", homeVm: two() });
  await tick();
  (doc.querySelector('#nav [data-page-link="home"]') as any).click();
  await tick();
  (doc.querySelector('#nav [data-page-link="approvals"]') as any).click();
  await tick();
  assert.equal(where(window), "/mandu/approvals");
  assert.deepEqual(marked(doc), []);
  assert.equal(note(doc).hidden, true);
});
