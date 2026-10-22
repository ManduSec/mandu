/**
 * home-js-approvals-focus.test — a Home "Waiting for you" card's Details link
 * opens the same question in Approvals, marked (dashboard.md §4.25
 * "Details"): the link, the mark and its survival across a repaint, the
 * already-answered and gone cases, answering the marked card, a
 * notification click, and a plain Approvals visit marking nothing. A link to
 * a rule change (§4.25 *Details*): a waiting request's card, a change made
 * under Rule changes, the change an approved request made, and the words for
 * one that is gone or past the rows drawn.
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

// ── A link to a rule change (§4.25 *Details*) ────────────────────────────────

const PENDING = "GET policy/proposals?status=pending";
const CHANGES = "GET policy/changes?limit=21";
const request = (id: string) => ({
  id, status: "pending", requester: "Your agent", session: "s1", createdAt: Date.now() - 60_000,
  headline: "Your agent wants to change a rule",
  rows: [[{ kind: "text", text: "Let " }, { kind: "code", text: "pypi.org" }, { kind: "text", text: " be reached" }]],
  wouldLet: [], capped: false, overBroad: false, warnings: [], reason: null, onDisk: false,
});
const change = (id: string, over: Record<string, unknown> = {}) => ({
  id, sentence: "Your agent tightened your rules", session: null, createdAt: Date.now() - 120_000, undone: false, undoable: true,
  rows: [[{ kind: "text", text: "Make " }, { kind: "code", text: "/x.pem" }, { kind: "text", text: " a secret no AI may read" }]], ...over,
});
const at = (id: string) => "http://127.0.0.1:4500/mandu/approvals/" + encodeURIComponent(id);
const ROUTES = {
  [PENDING]: { proposals: [request("pp-000001"), request("pp-000002")] },
  [CHANGES]: { changes: [change("pc-000002"), change("pc-000001", { sentence: "You approved a change your agent asked for", proposalId: "pp-000009" })] },
};
const ruleRow = (doc: any, id: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: any) => r.dataset.id === id) as any;

test("a waiting request: its card is marked, no note", async () => {
  const { doc } = load({ url: at("pp-000002"), homeVm: two(), routes: ROUTES });
  await tick(40);
  assert.deepEqual(marked(doc), ["pp-000002"]);
  assert.equal(note(doc).hidden, true);
});

test("a change made: its Rule changes row is marked, no note", async () => {
  const { doc } = load({ url: at("pc-000002"), homeVm: two(), routes: ROUTES });
  await tick(40);
  assert.deepEqual(marked(doc), ["pc-000002"]);
  assert.ok(ruleRow(doc, "pc-000002").classList.contains("focus"));
  assert.equal(note(doc).hidden, true);
});

test("an approved request: the change it made is marked, and the note says so", async () => {
  const { doc } = load({ url: at("pp-000009"), homeVm: two(), routes: ROUTES });
  await tick(40);
  assert.deepEqual(marked(doc), ["pc-000001"], "the row whose request it was");
  assert.equal(note(doc).hidden, false);
  assert.equal(note(doc).textContent, "That rule change was already answered. The change it made is marked below, under Rule changes.");
});

test("a rule change neither waiting nor listed: a request changed nothing; a change is not among those listed", async () => {
  const gone = load({ url: at("pp-000404"), homeVm: two(), routes: ROUTES });
  await tick(40);
  assert.deepEqual(marked(gone.doc), []);
  assert.equal(note(gone.doc).textContent, "That rule change is no longer waiting, and it changed none of your rules.");
  const missing = load({ url: at("pc-000404"), homeVm: two(), routes: ROUTES });
  await tick(40);
  assert.deepEqual(marked(missing.doc), []);
  assert.equal(note(missing.doc).hidden, false);
  assert.equal(note(missing.doc).textContent, "That rule change is not among the changes listed.");
});

test("past the newest 20: the note says Show more reaches older ones, for a change and a request alike", async () => {
  const many = Array.from({ length: 21 }, (_, i) => change("pc-" + String(100 + i).padStart(6, "0")));
  for (const id of ["pc-000404", "pp-000404"]) {
    const { doc } = load({ url: at(id), homeVm: two(), routes: { ...ROUTES, [CHANGES]: { changes: many } } });
    await tick(40);
    assert.ok(doc.querySelector("#approvals-rule-history .changes-more"), "Show more is offered");
    assert.deepEqual(marked(doc), []);
    assert.equal(note(doc).textContent, "That rule change is not among the changes listed. Show more, under Rule changes, reaches older ones.", id);
  }
});

test("a rule change's id is compared as a value: one shaped like a selector marks nothing and throws nothing", async () => {
  for (const id of ['pc-"],*,[x="', 'pp-"],.row,[x="']) {
    const { doc, err } = load({ url: at(id), homeVm: two(), routes: ROUTES });
    await tick(40);
    assert.equal(err, null);
    assert.deepEqual(marked(doc), [], id);
    assert.match(note(doc).textContent, /^That rule change (is not among the changes listed|is no longer waiting)/);
  }
});

test("nothing is said before the Rule changes list is read; the mark comes when it lands, and a redraw keeps it", async () => {
  let release!: () => void;
  const late = new Promise<void>((r) => { release = r; });
  let list = ROUTES[CHANGES];
  const { doc, window } = load({ url: at("pc-000001"), homeVm: two(), routes: { ...ROUTES, [CHANGES]: () => late.then(() => list) } });
  await tick(40);
  assert.equal(note(doc).hidden, true, "no 'not among the changes' while the list is out");
  assert.deepEqual(marked(doc), []);
  release();
  await tick(40);
  assert.deepEqual(marked(doc), ["pc-000001"], "marked once the list landed after Home's answer");
  const before = ruleRow(doc, "pc-000001");
  list = { changes: [change("pc-000003"), ...ROUTES[CHANGES].changes] };
  // A poll whose list changed draws the rows again: the mark comes back.
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(40);
  assert.ok(ruleRow(doc, "pc-000003"), "the new row is drawn");
  assert.notEqual(ruleRow(doc, "pc-000001"), before, "the rows were drawn again");
  assert.deepEqual(marked(doc), ["pc-000001"]);
});

test("answering the marked request drops it from the URL, and the note never calls your answer an earlier one", async () => {
  let pending = [request("pp-000001"), request("pp-000002")];
  const { doc, window } = load({
    url: at("pp-000002"), homeVm: two(),
    routes: {
      ...ROUTES,
      [PENDING]: () => ({ proposals: pending }),
      "POST policy/proposals/pp-000002": () => { pending = [request("pp-000001")]; return { proposal: { ...request("pp-000002"), status: "denied" } }; },
    },
  });
  await tick(40);
  assert.deepEqual(marked(doc), ["pp-000002"]);
  const card = [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: any) => c.dataset.id === "pp-000002") as any;
  ([...card.querySelectorAll("button")].find((b: any) => b.textContent === "Not now") as any).click();
  await tick(40);
  assert.equal(where(window), "/mandu/approvals", "the request left the URL");
  assert.deepEqual(marked(doc), []);
  assert.equal(note(doc).hidden, true);
});
