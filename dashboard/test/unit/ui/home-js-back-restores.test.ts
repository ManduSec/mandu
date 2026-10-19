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
 *       opened fresh, it is a link Home.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * jsdom has no layout: the place is read as the page's scrollTo calls. Axes:
 * none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

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
