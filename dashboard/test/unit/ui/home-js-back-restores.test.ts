/**
 * home-js-back-restores.test — Back and Forward keep your place on the
 * PRODUCT page (public/js/home.js `savePlace`, `historyLand`, `agentBack`;
 * dashboard.md §4.25 *Back and Forward keep your place*, §4.25ae *Back
 * returns to the row you opened*, §4.25ad *The back link names where you
 * came from*).
 *
 * Until 2026-10-18 every page change scrolled to the top and read History
 * again from nothing, Back included: after Show more twice and a row's
 * Details, Back showed the first 25 rows at the top. The session page's link
 * always read "Back to home". Now:
 *
 *   B1  a push saves the page's place in the entry it leaves ({y, rows,
 *       opened}); Back into History reads that many rows, scrolls there and
 *       gives the opened row the focus; Forward then Back does it again;
 *   B2  more rows than one read brings: it reads on, a page at a time, and
 *       the poll reads nothing while it does; a row pushed down by new
 *       sessions is still read and landed on;
 *   B3  a link to History starts it fresh: one page, at the top, the focus on
 *       its heading;
 *   B4  the back link says "Back to History", "Back to Approvals" or "Back to
 *       home" for where the page was opened from, and is Back (the page keeps
 *       its place) only when that page is the entry before it in this tab;
 *       opened fresh, it is a link Home;
 *   B4b from Rules, Settings, Plugins or Scan (since 2026-10-29, #196) it
 *       names that page too, "Back to Rules" and so on (PAGE_NAMES), its
 *       href that page under the base path, and a click is Back; opened from
 *       another session's page that was itself opened fresh, or fresh, it
 *       still reads "Back to home";
 *   B4c a chain of session pages (Newer, Older, any link between them;
 *       since 2026-11-03, #291) keeps the page it started from: from Rules
 *       two steps on, "Back to Rules", and a click goes back the three
 *       entries to Rules' place, no entry added; from Home, "Back to home"
 *       and Back the same way; from a fresh load, "Back to home" and a link
 *       Home; a tab that no longer holds the entries gets the link;
 *   B5  Back to Approvals opened at a question keeps your place;
 *   B6  Rules and Settings (since 2026-10-22): Back returns to how far down
 *       you were once the page's reads have drawn (a page shorter until
 *       then held it above), a scroll made meanwhile stays, a top-bar link
 *       starts at the top; a place wins over the card the address names
 *       (`/rules#your-rules`); Rules left with text in Find a rule comes
 *       back at its top, Find empty.
 *   B7  Scan (since 2026-10-29, #228): Back returns the section folds you
 *       had open, the rows each had drawn (its own Show more read again, a
 *       page at a time), the row folds you had opened (their examples read
 *       again), then your place; Forward then Back does it again; a
 *       top-bar link opens it at its top, folded; with text in a Find one,
 *       Back opens it at its top, Find empty; a scan kept meanwhile with
 *       fewer rows and no such row throws nothing and reads to its end.
 *   B8  Plugins (since 2026-10-31, #243): one read, so the place is the
 *       scroll alone; Back from a card's *Open its session* (the session
 *       page's "Back to Plugins") returns to where you were once the read
 *       has drawn, Forward then Back does it again, and a top-bar link
 *       opens it at its top.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * jsdom has no layout: the place is read as the page's scrollTo calls. Axes:
 * none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, rulesPage, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";
import { homeScanCard, scanPageVM, type LastScanWire } from "../../../src/view-model/last-scan.js";
import { scanAfter, scanHead, scanItemDetail, scanSectionPage } from "../../../src/view-model/last-scan-pages.js";
import { pluginsPage } from "../../../src/view-model/plugins.js";

const BASE = "http://127.0.0.1:4500/mandu";
const row = (id: string) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null,
});
const id = (i: number) => `s${String(i).padStart(3, "0")}`;
const rows = (from: number, to: number) => Array.from({ length: to - from }, (_, i) => row(id(from + i)));
/** 60 sessions, 25 a page. */
const SIXTY = {
  "GET home/history": { total: 60, rows: rows(0, 25), next: id(24) },
  [`GET home/history?after=${id(24)}`]: { total: 60, rows: rows(25, 50), next: id(49) },
  [`GET home/history?after=${id(49)}`]: { total: 60, rows: rows(50, 60), next: null },
  "GET home/history?limit=60": { total: 60, rows: rows(0, 60), next: null },
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyRows = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowOf = (doc: any, s: string) => historyRows(doc).find((r) => r.dataset.session === s);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyCalls = (calls: any[]) => calls.filter((c) => c.url.startsWith("/mandu/api/home/history")).map((c) => c.url.slice("/mandu/api/".length));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const backLink = (doc: any) => doc.getElementById("agent-back");

/** The page's scroll as a browser keeps it: scrollTo moves scrollY, and
 *  each call is recorded. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function scrolling(window: any) {
  const to: number[] = [];
  Object.defineProperty(window, "scrollY", { value: 0, writable: true, configurable: true });
  window.scrollTo = (_x: number, y: number) => { to.push(y); window.scrollY = y; };
  return to;
}
/** Back or Forward: jsdom traverses on timers, so the wait is on the URL
 *  (home-js-page-focus.test.ts `traverse`). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function traverse(window: any, way: "back" | "forward") {
  const from = window.location.pathname + window.location.search;
  window.history[way]();
  await waitWhile(() => window.location.pathname + window.location.search === from);
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function showMore(doc: any) {
  doc.querySelector("#history-list .history-more button").click();
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function press(link: any) {
  assert.ok(link, "the link is there");
  link.focus();
  link.click();
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

test("B1: Back into History reads the rows you had loaded, scrolls to your place and focuses the row you opened; Forward then Back does it again", async () => {
  const { doc, window, calls } = load({ extensions: "", url: BASE + "/history", homeVm: home(), routes: SIXTY });
  const to = scrolling(window);
  await tick();
  await showMore(doc);
  await showMore(doc);
  assert.equal(historyRows(doc).length, 60);
  window.scrollTo(0, 1800);
  const saved: unknown[] = [];
  const replace = window.history.replaceState.bind(window.history);
  window.history.replaceState = (state: unknown, ...rest: unknown[]) => { saved.push(state); return replace(state, ...rest); };
  await press(rowOf(doc, id(54)).querySelector("a"));
  window.history.replaceState = replace;
  assert.equal(doc.getElementById("page-agent").hidden, false, "the agent page is shown");
  assert.deepEqual(JSON.parse(JSON.stringify((saved[0] as { place: unknown }).place)), { y: 1800, rows: 60, opened: id(54) }, "the entry left keeps its place");
  assert.equal(window.history.state.from, "history", "the new entry names the page it came from");
  assert.equal(to.at(-1), 0, "the agent page starts at its top");

  for (const round of [1, 2]) {
    const mark = to.length;
    await traverse(window, "back");
    assert.equal(window.location.pathname, "/mandu/history");
    await waitWhile(() => doc.activeElement !== rowOf(doc, id(54)));
    assert.equal(historyCalls(calls).at(-1), "home/history?limit=60", `round ${round}: one read of the 60 rows loaded`);
    assert.equal(historyRows(doc).length, 60, "as many rows as were loaded");
    assert.equal(to.at(-1), 1800, "the page is back at its place");
    assert.ok(!to.slice(mark).includes(0), "never sent to the top on the way");
    assert.equal(doc.activeElement, rowOf(doc, id(54)), "the row opened has the focus");
    assert.equal(rowOf(doc, id(54)).getAttribute("tabindex"), "-1", "focusable, not a Tab stop");
    if (round === 1) {
      await traverse(window, "forward");
      assert.equal(doc.getElementById("page-agent").hidden, false);
      assert.equal(backLink(doc).textContent, "Back to History", "Forward: still from History");
    }
  }
});

test("B2: more rows than one read: it reads on, the poll waits for it, and a row pushed down by new sessions is still landed on", async () => {
  const out: ((v: unknown) => void)[] = [];
  const routes = {
    "GET home/history?limit=100": { total: 150, rows: rows(0, 100), next: id(99) },
    [`GET home/history?after=${id(99)}&limit=50`]: () => new Promise((r) => out.push(r)),
  };
  const { doc, window, calls } = load({ extensions: "", homeVm: home(), routes });
  const to = scrolling(window);
  await tick();
  window.history.pushState({ place: { y: 5000, rows: 150, opened: id(120) } }, "", "/mandu/history");
  window.dispatchEvent(new window.PopStateEvent("popstate"));
  await tick();
  assert.deepEqual(historyCalls(calls), ["home/history?limit=100", `home/history?after=${id(99)}&limit=50`], "100 at most a read, then the rest");
  await poll(doc);
  assert.equal(historyCalls(calls).length, 2, "no poll read while the restore is out");
  out[0]!({ total: 150, rows: rows(100, 150), next: null });
  await tick();
  assert.equal(historyRows(doc).length, 150);
  assert.equal(doc.activeElement, rowOf(doc, id(120)));
  assert.equal(to.at(-1), 5000);

  // Two sessions came in since: the 30 newest end at a row before the one
  // opened, so it reads on to it.
  const pushed = load({ extensions: "", homeVm: home(), routes: {
    "GET home/history?limit=30": { total: 32, rows: [row("n0"), row("n1"), ...rows(0, 28)], next: id(27) },
    [`GET home/history?after=${id(27)}&limit=25`]: { total: 32, rows: rows(28, 30), next: null },
  } });
  scrolling(pushed.window);
  await tick();
  pushed.window.history.pushState({ place: { y: 900, rows: 30, opened: id(29) } }, "", "/mandu/history");
  pushed.window.dispatchEvent(new pushed.window.PopStateEvent("popstate"));
  await tick();
  assert.equal(historyRows(pushed.doc).length, 32);
  assert.equal(pushed.doc.activeElement, rowOf(pushed.doc, id(29)), "the row opened, pushed down, has the focus");
});

test("B3: a link to History starts it fresh: one page, at the top, the focus on its heading", async () => {
  const { doc, window, calls } = load({ extensions: "", url: BASE + "/history", homeVm: home(), routes: SIXTY });
  const to = scrolling(window);
  await tick();
  await showMore(doc);
  window.scrollTo(0, 1200);
  await press(doc.querySelector('#nav [data-page-link="home"]'));
  await press(doc.getElementById("home-history"));
  assert.equal(historyCalls(calls).at(-1), "home/history", "one page, no limit");
  assert.equal(historyRows(doc).length, 25);
  assert.equal(to.at(-1), 0, "at the top");
  assert.equal(doc.activeElement, doc.querySelector("#page-history h1"));
});

test("B4: the back link names where the page was opened from, and is Back only when that page is the entry before it in this tab", async () => {
  // From Home: "Back to home", and it is Back.
  const fromHome = load({ homeVm: home() });
  await tick();
  await press(fromHome.doc.querySelector('#home-agents a[data-page-link="agent"][data-session="s1"]'));
  assert.equal(backLink(fromHome.doc).textContent, "Back to home");
  let backs = 0;
  const back = fromHome.window.history.back.bind(fromHome.window.history);
  fromHome.window.history.back = () => { backs++; back(); };
  const length = fromHome.window.history.length;
  backLink(fromHome.doc).click();
  await waitWhile(() => fromHome.window.location.pathname !== "/mandu/");
  assert.equal(backs, 1, "Back, not a new page");
  assert.equal(fromHome.window.history.length, length, "no entry added");

  // From History: "Back to History" (B1 follows it back).
  const fromHistory = load({ extensions: "", url: BASE + "/history", homeVm: home(), routes: SIXTY });
  await tick();
  await press(rowOf(fromHistory.doc, id(3)).querySelector("a"));
  assert.equal(backLink(fromHistory.doc).textContent, "Back to History");
  assert.equal(backLink(fromHistory.doc).getAttribute("href"), "/mandu/history");
  backLink(fromHistory.doc).click();
  await waitWhile(() => fromHistory.window.location.pathname !== "/mandu/history");
  await waitWhile(() => fromHistory.doc.activeElement !== rowOf(fromHistory.doc, id(3)));
  assert.equal(fromHistory.doc.activeElement, rowOf(fromHistory.doc, id(3)), "the row opened has the focus");

  // From an Approvals card's See what the agent was doing: "Back to
  // Approvals", and Approvals is back at the place it was left.
  const fromApprovals = load({ url: BASE + "/approvals", homeVm: home() });
  const to = scrolling(fromApprovals.window);
  await tick();
  fromApprovals.window.scrollTo(0, 900);
  await press(fromApprovals.doc.querySelector("#approvals-waiting a.ask-link"));
  assert.equal(backLink(fromApprovals.doc).textContent, "Back to Approvals");
  backLink(fromApprovals.doc).click();
  await waitWhile(() => fromApprovals.window.location.pathname !== "/mandu/approvals");
  await tick();
  assert.equal(to.at(-1), 900, "Approvals is back at its place");
  assert.equal(fromApprovals.doc.activeElement, fromApprovals.doc.querySelector("#page-approvals h1"));

  // Opened fresh (a new tab, a typed address): "Back to home", a link Home.
  const fresh = load({ url: BASE + "/agents/s1", homeVm: home() });
  await tick();
  assert.equal(backLink(fresh.doc).textContent, "Back to home");
  let freshBacks = 0;
  fresh.window.history.back = () => { freshBacks++; };
  const before = fresh.window.history.length;
  await press(backLink(fresh.doc));
  assert.equal(freshBacks, 0, "not Back: there is no page before it here");
  assert.equal(fresh.window.location.pathname, "/mandu/");
  assert.equal(fresh.window.history.length, before + 1, "Home, as a link opens it");
  assert.equal(fresh.doc.getElementById("page-home").hidden, false);
});

for (const [page, name] of [["rules", "Rules"], ["settings", "Settings"], ["plugins", "Plugins"], ["scan", "Scan"]] as const) {
  test(`B4b ${name}: opened from ${name} by a pushed page change, the back link reads "Back to ${name}", links /${page}, and is Back`, async () => {
    const { doc, window } = load({ url: `${BASE}/${page}`, homeVm: home() });
    await tick();
    // A link to a session on that page (Rules' "this session", Plugins'
    // "Open its session", a notice's link): any page link is a push.
    const link = doc.createElement("a");
    link.href = "/mandu/agents/s1";
    link.dataset.pageLink = "agent";
    link.dataset.session = "s1";
    link.textContent = "this session";
    doc.querySelector(`#page-${page}`).append(link);
    await press(link);
    assert.equal(window.location.pathname, "/mandu/agents/s1");
    assert.equal(backLink(doc).textContent, `Back to ${name}`);
    assert.equal(backLink(doc).getAttribute("href"), `/mandu/${page}`, "a new tab opens that page, under the base path");
    let backs = 0;
    const back = window.history.back.bind(window.history);
    window.history.back = () => { backs++; back(); };
    const length = window.history.length;
    backLink(doc).click();
    await waitWhile(() => window.location.pathname !== `/mandu/${page}`);
    assert.equal(backs, 1, "Back, not a new page");
    assert.equal(window.history.length, length, "no entry added");
    assert.equal(doc.getElementById(`page-${page}`).hidden, false);
  });
}

test("B4b: opened from another session's page opened fresh, the back link still reads \"Back to home\" and links Home", async () => {
  const { doc, window } = load({ url: BASE + "/agents/s1", homeVm: home() });
  await tick();
  assert.equal(backLink(doc).textContent, "Back to home");
  const link = doc.createElement("a");
  link.href = "/mandu/agents/s2";
  link.dataset.pageLink = "agent";
  link.dataset.session = "s2";
  doc.querySelector("#page-agent").append(link);
  await press(link);
  assert.equal(window.location.pathname, "/mandu/agents/s2");
  assert.equal(backLink(doc).textContent, "Back to home");
  assert.equal(backLink(doc).getAttribute("href"), "/mandu/");
  assert.equal(backLink(doc).dataset.back, "", "a link Home, not Back");
});

/** A link to the session `id` put on the page shown and clicked: any page
 *  link is a push (Newer and Older are such links, the neighbours test). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function chainTo(doc: any, window: any, page: string, id: string) {
  const link = doc.createElement("a");
  link.href = `/mandu/agents/${id}`;
  link.dataset.pageLink = "agent";
  link.dataset.session = id;
  doc.querySelector(`#page-${page}`).append(link);
  await press(link);
  link.remove();
  assert.equal(window.location.pathname, `/mandu/agents/${id}`);
}

test("B4c: a chain of session pages started from Rules reads 'Back to Rules' and goes back the whole chain to Rules' place", async () => {
  const { doc, window } = load({ url: `${BASE}/rules`, homeVm: home() });
  const to = scrolling(window);
  await tick();
  window.scrollTo(0, 1300);
  await chainTo(doc, window, "rules", "s1");
  await chainTo(doc, window, "agent", "s2");
  await chainTo(doc, window, "agent", "s3");
  assert.equal(backLink(doc).textContent, "Back to Rules");
  assert.equal(backLink(doc).getAttribute("href"), "/mandu/rules");
  assert.equal(backLink(doc).dataset.back, "3");
  assert.deepEqual({ from: window.history.state.from, origin: window.history.state.origin, depth: window.history.state.depth }, { from: "agent", origin: "rules", depth: 2 });
  const gone: number[] = [];
  const go = window.history.go.bind(window.history);
  window.history.go = (n: number) => { gone.push(n); go(n); };
  const length = window.history.length;
  backLink(doc).click();
  await waitWhile(() => window.location.pathname !== "/mandu/rules");
  await tick();
  assert.deepEqual(gone, [-3], "three Backs at once");
  assert.equal(window.history.length, length, "no entry added");
  assert.equal(doc.getElementById("page-rules").hidden, false);
  assert.equal(to.at(-1), 1300, "Rules is back at its place");
});

test("B4c: a chain started from Home reads 'Back to home' and goes back to Home; from a fresh load, 'Back to home' and a link Home", async () => {
  const fromHome = load({ homeVm: home() });
  await tick();
  await press(fromHome.doc.querySelector('#home-agents a[data-page-link="agent"][data-session="s1"]'));
  await chainTo(fromHome.doc, fromHome.window, "agent", "s2");
  assert.equal(backLink(fromHome.doc).textContent, "Back to home");
  assert.equal(backLink(fromHome.doc).dataset.back, "2");
  const length = fromHome.window.history.length;
  backLink(fromHome.doc).click();
  await waitWhile(() => fromHome.window.location.pathname !== "/mandu/");
  assert.equal(fromHome.window.history.length, length, "Back, not a new page");

  const fresh = load({ url: BASE + "/agents/s1", homeVm: home() });
  await tick();
  await chainTo(fresh.doc, fresh.window, "agent", "s2");
  await chainTo(fresh.doc, fresh.window, "agent", "s3");
  assert.equal(backLink(fresh.doc).textContent, "Back to home");
  assert.equal(backLink(fresh.doc).getAttribute("href"), "/mandu/");
  assert.equal(backLink(fresh.doc).dataset.back, "", "no page before the chain: a link Home");
  let gone = 0;
  fresh.window.history.go = () => { gone++; };
  fresh.window.history.back = () => { gone++; };
  await press(backLink(fresh.doc));
  assert.equal(gone, 0, "not Back");
  assert.equal(fresh.window.location.pathname, "/mandu/");
});

test("B4c: a chain whose entries the tab no longer holds names its page but is a link to it", async () => {
  const { doc, window } = load({ url: BASE + "/agents/s9", homeVm: home() });
  await tick();
  // An entry that says it is the third step from History, in a tab of two entries.
  window.history.pushState({ from: "agent", origin: "history", depth: 3 }, "", "/mandu/agents/s1");
  window.dispatchEvent(new window.PopStateEvent("popstate"));
  await tick();
  assert.equal(backLink(doc).textContent, "Back to History");
  assert.equal(backLink(doc).getAttribute("href"), "/mandu/history");
  assert.equal(backLink(doc).dataset.back, "", "a link: going back four entries would leave the tab");
});

test("B5: Back to Approvals opened at a question keeps your place, and its marked card still takes the focus", async () => {
  const { doc, window } = load({ homeVm: home() });
  const to = scrolling(window);
  await tick();
  await press(doc.querySelector("#home-waiting .ask-details"));
  const card = () => doc.querySelector("#approvals-waiting .ask.focus");
  assert.equal(doc.activeElement, card(), "the marked card has the focus");
  window.scrollTo(0, 700);
  await press(card().querySelector("a.ask-link"));
  assert.equal(backLink(doc).textContent, "Back to Approvals");
  const mark = to.length;
  await traverse(window, "back");
  assert.match(window.location.pathname, /^\/mandu\/approvals\//);
  assert.equal(doc.activeElement, card(), "the marked card has the focus again");
  assert.deepEqual(to.slice(mark), [700], "the place you left, never the top");
});

/** A page as tall as `max` says (the page shorter until its read draws, as
 *  a browser clamps it): scrollTo moves scrollY no further, and each call is
 *  recorded. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function clamped(window: any) {
  const to: number[] = [];
  const page = { max: 10_000 };
  Object.defineProperty(window, "scrollY", { value: 0, writable: true, configurable: true });
  window.scrollTo = (_x: number, y: number) => { to.push(y); window.scrollY = Math.min(y, page.max); };
  return { to, page };
}
/** The cards scrolled into view (landAtCard), by id. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function cardScrolls(window: any) {
  const ids: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: { id: string }) { ids.push(this.id); };
  return ids;
}
/** A read the test answers (`answer`) once `held` is set; else at once. */
function heldRead(body: unknown) {
  const out: ((v: unknown) => void)[] = [];
  const read = { held: false, out, answer: () => { for (const r of out.splice(0)) r(body); } };
  return { read, route: () => (read.held ? new Promise((r) => out.push(r)) : body) };
}
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } };
const SUMMARY = { summary: null };

for (const [page, route, body] of [["rules", "GET policy/panel", PANEL], ["settings", "GET control/summary", SUMMARY]] as const) {
  const name = page === "rules" ? "Rules" : "Settings";
  test(`B6 ${name}: Back returns to where you were once its reads have drawn, and the focus is on its heading`, async () => {
    const { read, route: answer } = heldRead(body);
    const { doc, window } = load({ url: `${BASE}/${page}`, homeVm: home(), routes: { [route]: answer } });
    const { to, page: tall } = clamped(window);
    await tick();
    window.scrollTo(0, 900);
    await press(doc.querySelector('#nav [data-page-link="approvals"]'));
    assert.equal(to.at(-1), 0, "Approvals starts at its top");
    // Back: the read is out, and the page holds only 400 px of scroll.
    read.held = true;
    tall.max = 400;
    const mark = to.length;
    await traverse(window, "back");
    assert.equal(window.location.pathname, `/mandu/${page}`);
    assert.equal(window.scrollY, 400, "held above until the read draws");
    assert.equal(doc.activeElement, doc.querySelector(`#page-${page} h1`), "the focus on the page's heading");
    tall.max = 10_000;
    read.answer();
    await tick();
    assert.equal(window.scrollY, 900, "back where you were once it has drawn");
    assert.ok(!to.slice(mark).includes(0), "never sent to the top on the way");
    assert.equal(doc.activeElement, doc.querySelector(`#page-${page} h1`), "the focus stays on the heading");
  });

  test(`B6 ${name}: a scroll made before its read draws stays, and a top-bar link starts at the top`, async () => {
    const { read, route: answer } = heldRead(body);
    const { doc, window } = load({ url: `${BASE}/${page}`, homeVm: home(), routes: { [route]: answer } });
    const { to, page: tall } = clamped(window);
    await tick();
    window.scrollTo(0, 900);
    await press(doc.querySelector('#nav [data-page-link="history"]'));
    read.held = true;
    tall.max = 400;
    await traverse(window, "back");
    assert.equal(window.scrollY, 400);
    tall.max = 10_000;
    window.scrollTo(0, 250); // the person scrolls while the read is out
    read.answer();
    await tick();
    assert.equal(window.scrollY, 250, "your scroll stays");

    // A link starts fresh: away, then the top-bar link back.
    window.scrollTo(0, 700);
    read.held = false;
    await press(doc.querySelector('#nav [data-page-link="home"]'));
    await press(doc.querySelector(`#nav [data-page-link="${page}"]`));
    await tick();
    assert.equal(window.location.pathname, `/mandu/${page}`);
    assert.equal(to.at(-1), 0, "a link opens it at its top");
    assert.equal(window.scrollY, 0);
  });
}

for (const [page, key, card] of [["rules", "your-rules", "rules-block"], ["settings", "notifications", "settings-notify-block"]] as const) {
  test(`B6 ${page}: Back to /${page}#${key} keeps your place, not its card`, async () => {
    const { doc, window } = load({ url: `${BASE}/${page}#${key}`, homeVm: home() });
    const cards = cardScrolls(window);
    const { to } = clamped(window);
    await tick();
    await tick();
    assert.deepEqual(cards, [card], "a typed address opens at its card");
    window.scrollTo(0, 1500);
    await press(doc.querySelector('#nav [data-page-link="approvals"]'));
    const mark = to.length;
    await traverse(window, "back");
    await tick();
    assert.equal(window.location.hash, `#${key}`, "the address still names the card");
    assert.deepEqual(cards, [card], "Back scrolls to no card");
    assert.deepEqual(to.slice(mark), [1500], "the place you left");
    assert.equal(doc.activeElement, doc.querySelector(`#page-${page} h1`), "the focus on the page's heading, not the card's");
  });
}

test("B6 Rules: left with text in Find a rule, Back opens it at its top with Find empty", async () => {
  const { doc, window } = rulesPage();
  const { to } = clamped(window);
  await tick();
  window.scrollTo(0, 1200);
  const find = doc.getElementById("rules-find");
  find.value = "example";
  find.dispatchEvent(new window.Event("input"));
  window.scrollTo(0, 300);
  await press(doc.querySelector('#nav [data-page-link="approvals"]'));
  const mark = to.length;
  await traverse(window, "back");
  await tick();
  assert.equal(window.location.pathname, "/mandu/rules");
  assert.equal(doc.getElementById("rules-find").value, "", "Find is never kept");
  assert.deepEqual(to.slice(mark), [0], "the top: a place in the narrowed list is not one in the whole");
});

/** A kept scan whose folded tier ("looks") has `n` rows. */
function scanRecord(n: number): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-21T09:00:00.000Z", sessions: { "claude-code": 3 }, duringMandu: 0, known: 0,
    findings: Array.from({ length: n }, (_, i) => ({ kind: "github-token", preview: "ghp_…", sessions: 1, agents: ["codex"], how: { "your-message": 1 }, projects: [`~/fixtures-${i}`], duringMandu: 0 })),
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 },
    sends: [], sendsDropped: 0, suggestions: { pending: 0, filed: 0, covered: 0 },
  };
}
/** The Scan page's routes over the kept scan `at.rec` (its `rev`
 *  `at.rev`): the head, and the paged reads answered from the server's own
 *  paging (home-js-scan.test.ts `paged`), each asked path kept in `asked`. */
function scanServer(at: { rec: LastScanWire; rev: string }, asked: string[]) {
  return {
    routes: { "GET scan": () => ({ scan: scanHead(scanPageVM(at.rec), at.rev) }) },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    before: (window: any) => {
      const inner = window.fetch;
      window.fetch = (url: string, init: unknown) => {
        const m = /\/api\/(scan\/(section|item)\/([^?]+))(?:\?(.*))?$/.exec(url);
        if (!m) return inner(url, init);
        asked.push(`${m[1]}${m[4] ? `?${m[4]}` : ""}`);
        const params = new URLSearchParams(m[4] ?? "");
        const answer = (status: number, body: unknown) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
        if (params.get("rev") !== at.rev) return answer(409, { error: "the scan changed: read the page again", changed: true });
        const page = scanPageVM(at.rec);
        const body = m[2] === "section"
          ? scanSectionPage(page, decodeURIComponent(m[3]!), { after: scanAfter(params.get("after")), q: params.get("q") ?? "" })
          : scanItemDetail(page, decodeURIComponent(m[3]!));
        return body === null ? answer(404, { error: "no such row" }) : answer(200, body);
      };
    },
  };
}
const pause = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const looks = (doc: any) => doc.querySelector('#scan-sections [data-section="looks"]');
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const scanRows = (doc: any) => [...looks(doc).querySelectorAll(".scan-item")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const scanRow = (doc: any, rid: string) => scanRows(doc).find((r) => r.dataset.id === rid);
/** A link to a session placed in `where` (a row's fold), pressed: a push. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function toSession(doc: any, where: any) {
  const link = doc.createElement("a");
  link.href = "/mandu/agents/s1";
  link.dataset.pageLink = "agent";
  link.dataset.session = "s1";
  link.textContent = "Open the session";
  where.append(link);
  await press(link);
  assert.equal(doc.getElementById("page-agent").hidden, false, "the session's page is shown");
}
/** The Scan page at /scan with its folded tier opened, Show more pressed
 *  once (50 rows) and row 31's Details and examples opened. */
async function scanOpened(at: { rec: LastScanWire; rev: string }, asked: string[]) {
  const server = scanServer(at, asked);
  const loaded = load({ url: BASE + "/scan", homeVm: { ...home(), scan: { ...homeScanCard(at.rec), rev: at.rev } }, ...server });
  const { doc } = loaded;
  const to = scrolling(loaded.window);
  await tick(30);
  const fold = looks(doc).querySelector("details.scan-fold");
  assert.equal(fold.open, false, "the long tier starts folded");
  fold.open = true;
  assert.equal(scanRows(doc).length, 25);
  looks(doc).querySelector(".scan-section-body > button.btn").click();
  await tick(10);
  assert.equal(scanRows(doc).length, 50, "Show more drew the next page");
  const rid = scanRows(doc)[30].dataset.id as string;
  scanRow(doc, rid).querySelector("details.scan-more").open = true;
  await pause(20);
  await tick(10);
  assert.ok(scanRow(doc, rid).querySelector(".scan-detail"), "its examples are drawn");
  return { ...loaded, to, rid };
}

test("B7 Scan: Back opens the fold you had open, reads the rows you had drawn, opens the row's Details again, then scrolls to your place; Forward then Back does it again", async () => {
  const asked: string[] = [];
  const { doc, window, to, rid } = await scanOpened({ rec: scanRecord(60), rev: "r1" }, asked);
  window.scrollTo(0, 2400);
  await toSession(doc, scanRow(doc, rid).querySelector("details.scan-more"));
  assert.equal(to.at(-1), 0, "the session's page starts at its top");
  for (const round of [1, 2]) {
    const mark = to.length;
    const from = asked.length;
    await traverse(window, "back");
    assert.equal(window.location.pathname, "/mandu/scan");
    await waitWhile(() => !scanRow(doc, rid)?.querySelector(".scan-detail"));
    await tick(10);
    assert.equal(looks(doc).querySelector("details.scan-fold").open, true, `round ${round}: the fold is open again`);
    assert.equal(scanRows(doc).length, 50, "the rows you had drawn");
    assert.deepEqual(asked.slice(from), ["scan/section/looks?after=25&rev=r1", `scan/item/${rid}?rev=r1`], "one Show more read, then the row's examples");
    assert.equal(scanRow(doc, rid).querySelector("details.scan-more").open, true, "the row's Details and examples is open");
    assert.equal(scanRows(doc).filter((r) => r.querySelector("details.scan-more").open).length, 1, "no other row's");
    assert.equal(to.at(-1), 2400, "back at your place");
    assert.ok(!to.slice(mark).includes(0), "never sent to the top on the way");
    if (round === 1) {
      await traverse(window, "forward");
      assert.equal(doc.getElementById("page-agent").hidden, false);
      assert.equal(backLink(doc).textContent, "Back to Scan");
    }
  }
});

test("B7 Scan: a top-bar link opens it at its top, folded, its first page; Home's See the whole scan does too", async () => {
  const asked: string[] = [];
  const { doc, window, to } = await scanOpened({ rec: scanRecord(60), rev: "r1" }, asked);
  window.scrollTo(0, 2400);
  await press(doc.querySelector('#nav [data-page-link="home"]'));
  for (const link of ['#nav [data-page-link="scan"]', "#home-scan-open"]) {
    const from = asked.length;
    await press(doc.querySelector(link));
    await tick(30);
    assert.equal(window.location.pathname, "/mandu/scan");
    assert.equal(to.at(-1), 0, `${link}: at its top`);
    assert.equal(looks(doc).querySelector("details.scan-fold").open, false, "folded");
    assert.equal(scanRows(doc).length, 25, "its first page");
    assert.equal(doc.querySelectorAll("#scan-sections details.scan-more[open]").length, 0, "no row open");
    assert.deepEqual(asked.slice(from), [], "nothing read past the head");
    await press(doc.querySelector('#nav [data-page-link="home"]'));
  }
});

test("B7 Scan: left with text in Find one, Back opens it at its top, Find empty, the fold you had open still open", async () => {
  const asked: string[] = [];
  const { doc, window, to } = await scanOpened({ rec: scanRecord(60), rev: "r1" }, asked);
  window.scrollTo(0, 1200);
  const input = looks(doc).querySelector("input.scan-filter");
  input.value = "fixtures-4";
  input.dispatchEvent(new window.Event("input"));
  await pause(200);
  await tick(10);
  assert.ok(asked.at(-1)!.startsWith("scan/section/looks?after=0&q=fixtures-4&"), "the find asked the server");
  window.scrollTo(0, 300);
  await toSession(doc, scanRows(doc)[0]);
  const mark = to.length;
  const from = asked.length;
  await traverse(window, "back");
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/scan");
  assert.equal(looks(doc).querySelector("input.scan-filter").value, "", "Find is never kept");
  assert.equal(looks(doc).querySelector("details.scan-fold").open, true, "the fold you had open");
  assert.equal(scanRows(doc).length, 25, "its first page: the found rows answered the query");
  assert.deepEqual(asked.slice(from), [], "nothing read past the head");
  assert.ok(to.slice(mark).length > 0 && to.slice(mark).every((y) => y === 0), `the top: ${JSON.stringify(to.slice(mark))}`);
});

test("B7 Scan: a scan kept meanwhile, with fewer rows and none of the row you had opened: Back reads to its end, throws nothing and keeps your place", async () => {
  const asked: string[] = [];
  const at = { rec: scanRecord(60), rev: "r1" };
  const { doc, window, to, err } = await scanOpened(at, asked);
  window.scrollTo(0, 2400);
  await toSession(doc, scanRows(doc)[30]);
  Object.assign(at, { rec: scanRecord(30), rev: "r2" });
  const from = asked.length;
  await traverse(window, "back");
  await tick(30);
  await pause(20);
  assert.equal(err, null);
  assert.equal(looks(doc).querySelector("details.scan-fold").open, true);
  assert.equal(scanRows(doc).length, 30, "read to the section's end");
  assert.deepEqual(asked.slice(from), ["scan/section/looks?after=25&rev=r2"], "one read: the section ends there");
  assert.equal(doc.querySelectorAll("#scan-sections details.scan-more[open]").length, 0, "no row of the old scan opened");
  assert.equal(to.at(-1), 2400, "your place, as near as the page allows");
});

/** Plugins with four attached agents, a card each: a page that scrolls. */
const AGENTS = ["main", "work", "ops", "home"];
const PLUGINS = {
  plugins: JSON.parse(JSON.stringify(pluginsPage({
    serviceRunning: true,
    sessions: AGENTS.map((agent) => ({ session: `openclaw:${agent}`, kind: "openclaw-plugin" as const, agent, declared: true, answering: true, poolState: null, secrets: { found: 1, registered: 1, at: "2026-10-25T09:00:01.000Z" }, route: null })),
    live: new Map(AGENTS.map((agent) => [`openclaw:${agent}`, Date.now() - 60_000])),
    known: new Set(AGENTS.map((agent) => `openclaw:${agent}`)),
  }))),
};

test("B8 Plugins: Back from a card's Open its session returns to where you were once its read has drawn; Forward then Back does it again", async () => {
  const { read, route } = heldRead(PLUGINS);
  const { doc, window } = load({ url: `${BASE}/plugins`, homeVm: home(), routes: { "GET plugins": route } });
  const { to, page: tall } = clamped(window);
  await tick(30);
  const cards = doc.querySelectorAll("#page-plugins .plugin-card");
  assert.equal(cards.length, AGENTS.length, "a card per attached agent");
  window.scrollTo(0, 1200);
  await press(cards[cards.length - 1].querySelector('.plugin-links a[data-page-link="agent"]'));
  assert.equal(window.location.pathname, "/mandu/agents/openclaw%3Ahome");
  assert.equal(backLink(doc).textContent, "Back to Plugins");
  assert.equal(to.at(-1), 0, "the session page starts at its top");

  for (const round of [1, 2]) {
    // The read is out, and the page holds only 400 px of scroll until it draws.
    read.held = true;
    tall.max = 400;
    const mark = to.length;
    if (round === 1) {
      backLink(doc).click();
      await waitWhile(() => window.location.pathname !== "/mandu/plugins");
      await tick();
    } else {
      await traverse(window, "back");
    }
    assert.equal(window.location.pathname, "/mandu/plugins");
    assert.equal(doc.getElementById("page-plugins").hidden, false);
    assert.equal(window.scrollY, 400, `round ${round}: held above until the read draws`);
    tall.max = 10_000;
    read.answer();
    await tick();
    assert.equal(window.scrollY, 1200, `round ${round}: back where you were once it has drawn`);
    assert.ok(!to.slice(mark).includes(0), `round ${round}: never sent to the top on the way`);
    assert.equal(doc.querySelectorAll("#page-plugins .plugin-card").length, AGENTS.length);
    if (round === 1) {
      read.held = false;
      await traverse(window, "forward");
      assert.equal(window.location.pathname, "/mandu/agents/openclaw%3Ahome", "Forward: the session page again");
    }
  }
});

test("B8 Plugins: a scroll made before its read draws stays, and a top-bar link opens it at its top", async () => {
  const { read, route } = heldRead(PLUGINS);
  const { doc, window } = load({ url: `${BASE}/plugins`, homeVm: home(), routes: { "GET plugins": route } });
  const { to, page: tall } = clamped(window);
  await tick(30);
  window.scrollTo(0, 1200);
  await press(doc.querySelector('#page-plugins .plugin-links a[data-page-link="agent"]'));
  read.held = true;
  tall.max = 400;
  await traverse(window, "back");
  assert.equal(window.scrollY, 400);
  tall.max = 10_000;
  window.scrollTo(0, 250); // the person scrolls while the read is out
  read.answer();
  await tick();
  assert.equal(window.scrollY, 250, "your scroll stays");

  // A link starts fresh: away, then the top-bar link back.
  window.scrollTo(0, 900);
  read.held = false;
  await press(doc.querySelector('#nav [data-page-link="home"]'));
  await press(doc.querySelector('#nav [data-page-link="plugins"]'));
  await tick();
  assert.equal(window.location.pathname, "/mandu/plugins");
  assert.equal(to.at(-1), 0, "a link opens it at its top");
  assert.equal(window.scrollY, 0);
});
