/**
 * home-js-agent-neighbours.test — the Newer and Older links at the end of a
 * session's page (public/js/home.js `renderAgentNeighbours`; dashboard.md
 * §4.25b *Newer and older sessions*).
 *
 *   N1  both neighbours: two links in the nav after What happened, each
 *       an ordinary page link (`data-page-link="agent"`, `data-session`,
 *       its href) named by the agent, what you asked and its time ("14:05"
 *       today, "yesterday 22:10", else the clock words), the arrows hidden
 *       from a screen reader;
 *   N2  only `older` (the newest session): one link; a fallback label (no
 *       title) names the agent and the time only;
 *   N3  none (absent `neighbours`, a drill run): the nav is empty and
 *       hidden;
 *   N4  a page that could not be read hides it, and a page read again
 *       draws it again;
 *   N5  a click opens that session's page, whose back link reads "Back to
 *       home" when the first session was opened with no page before it (a
 *       typed address); Back returns to the session you left;
 *   N6  (#291) opened from History, then Older twice: the third session's
 *       back link still reads "Back to History", links History, and a click
 *       goes back the three entries to it (no entry added), where the row
 *       you opened has the focus; Forward reaches that first session again,
 *       "Back to History" too, and the browser's Back still steps one
 *       session at a time, each naming History.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * The real browser is tests/stack/agent-neighbours.test.ts.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, CLOCK, home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const BASE = "http://127.0.0.1:4500/mandu";
const now = new Date();
const TODAY = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 1).toISOString();
const YESTERDAY = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, 22, 10).toISOString();
const EARLIER = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 10, 9, 5).toISOString();
const NEWER = { id: "s3", agent: "Claude Code", title: "Fix the login test", at: TODAY };
const OLDER = { id: "s1", agent: "Codex CLI", title: "What is in .env?", at: YESTERDAY };
const page = (id: string, neighbours?: unknown) => ({ ...AGENT, id, waiting: [], ...(neighbours === undefined ? {} : { neighbours }) });

function open(routes: Record<string, unknown>, id = "s2") {
  return load({ url: `${BASE}/agents/${id}`, homeVm: home({ waiting: [] }), routes });
}
const nav = (doc: Doc) => doc.getElementById("agent-neighbours");
const links = (doc: Doc) => [...nav(doc).querySelectorAll("a")] as Doc[];
const words = (x: Doc) => String(x.textContent).replace(/\s+/g, " ").trim();
async function drawn(doc: Doc) {
  await waitWhile(() => doc.getElementById("agent-name").textContent === "Agent");
  await tick();
}

test("N1: both neighbours draw two page links after What happened, each named by its agent, what you asked and its time", async () => {
  const { doc } = open({ "GET home/agent?session=s2": page("s2", { newer: NEWER, older: OLDER }) });
  await drawn(doc);
  assert.equal(nav(doc).hidden, false);
  assert.equal(nav(doc).getAttribute("aria-label"), "Other sessions");
  assert.equal(nav(doc).previousElementSibling.id, "agent-story-block", "under What happened");
  const [newer, older] = links(doc);
  assert.match(words(newer), /^← Newer: Claude Code · Fix the login test · 00:01$/);
  assert.match(words(older), /^Older: Codex CLI · What is in \.env\? · yesterday 22:10 →$/);
  for (const [a, id] of [[newer, "s3"], [older, "s1"]] as const) {
    assert.equal(a.dataset.pageLink, "agent");
    assert.equal(a.dataset.session, id);
    assert.equal(new URL(a.href).pathname, `/mandu/agents/${id}`, "a real address: a middle click opens a tab");
    assert.equal(a.querySelector(".neighbour-arrow").getAttribute("aria-hidden"), "true");
    assert.match(a.querySelector("time").title, new RegExp(`^${CLOCK}$`), "the clock time in full on hover");
  }
});

test("N2: only older draws one link; a fallback label names the agent and time only; an older day reads as the clock", async () => {
  const { doc } = open({ "GET home/agent?session=s2": page("s2", { newer: null, older: { id: "s1", agent: "Claude Code", title: null, at: EARLIER } }) });
  await drawn(doc);
  assert.equal(links(doc).length, 1);
  assert.match(words(links(doc)[0]), new RegExp(`^Older: Claude Code · ${CLOCK.replace(/\\d\{2\}:\\d\{2\}$/, "09:05")} →$`));
  assert.ok(links(doc)[0].classList.contains("older"));
});

test("N3: no neighbours (a drill run, a session alone): the nav is empty and hidden", async () => {
  for (const n of [undefined, { newer: null, older: null }]) {
    const { doc } = open({ "GET home/agent?session=s2": page("s2", n) });
    await drawn(doc);
    assert.equal(nav(doc).hidden, true);
    assert.equal(nav(doc).children.length, 0);
  }
});

test("N4: a page that could not be read hides the links drawn before; read again, they are back", async () => {
  let found = true;
  const { doc, window } = open({
    "GET home/agent?session=s2": () => found ? page("s2", { newer: NEWER, older: OLDER }) : { ...page("s2", { newer: NEWER, older: OLDER }), found: false },
  });
  await drawn(doc);
  assert.equal(links(doc).length, 2);
  // Away and Back: the page is read again, and now not found.
  const away = async () => {
    doc.querySelector('#nav [data-page-link="history"]').click();
    await tick();
    window.history.back();
    await waitWhile(() => !window.location.pathname.endsWith("/agents/s2"));
    await tick(30);
  };
  found = false;
  await away();
  await waitWhile(() => doc.getElementById("agent-name").textContent !== "Session not found");
  assert.equal(nav(doc).hidden, true);
  assert.equal(nav(doc).children.length, 0);
  found = true;
  await away();
  await waitWhile(() => links(doc).length !== 2);
  assert.equal(nav(doc).hidden, false);
});

test("N5: opened by its address, a click opens that session's page, its back link 'Back to home'; Back returns to the session left", async () => {
  const { doc, window, calls } = open({
    "GET home/agent?session=s2": page("s2", { newer: NEWER, older: OLDER }),
    "GET home/agent?session=s3": { ...page("s3", { newer: null, older: { ...OLDER, id: "s2" } }), agent: "Claude Code", title: "Fix the login test" },
  });
  await drawn(doc);
  links(doc)[0].click();
  await waitWhile(() => !window.location.pathname.endsWith("/agents/s3"));
  await waitWhile(() => links(doc).length !== 1);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s3"), "the newer session's page is read");
  assert.equal(doc.getElementById("agent-back").textContent, "Back to home", "as from any other session's page");
  assert.equal(links(doc)[0].dataset.session, "s2", "its own Older is the session left");
  window.history.back();
  await waitWhile(() => !window.location.pathname.endsWith("/agents/s2"));
  await waitWhile(() => links(doc).length !== 2);
  assert.equal(links(doc)[1].dataset.session, "s1");
});

const historyRow = (r: { id: string; agent: string; title: string; at: string }) => ({
  id: r.id, agent: r.agent, title: r.title, cwd: "/home/u/ws", startedAt: r.at, lastAt: r.at, state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null,
});

test("N6: opened from History, then Older twice: the back link still reads 'Back to History' and a click goes back the whole chain to History", async () => {
  const S2 = { id: "s2", agent: "Claude Code", title: "Look at the build", at: YESTERDAY };
  const { doc, window } = load({
    extensions: "", url: `${BASE}/history`, homeVm: home({ waiting: [] }),
    routes: {
      "GET home/history": { total: 3, rows: [historyRow(NEWER), historyRow(S2), historyRow(OLDER)], next: null },
      "GET home/agent?session=s3": { ...page("s3", { newer: null, older: S2 }), agent: "Claude Code", title: "Fix the login test" },
      "GET home/agent?session=s2": page("s2", { newer: NEWER, older: OLDER }),
      "GET home/agent?session=s1": page("s1", { newer: S2, older: null }),
    },
  });
  const rowOf = (s: string) => doc.querySelector(`#history-list .row.agent[data-session="${s}"]`);
  await waitWhile(() => !rowOf("s3"));
  const back = () => doc.getElementById("agent-back");
  const at = (id: string) => waitWhile(() => !window.location.pathname.endsWith(`/agents/${id}`));
  rowOf("s3").querySelector("a").click();
  await at("s3");
  await drawn(doc);
  assert.equal(back().textContent, "Back to History", "one step from History, as before");
  for (const [from, to] of [["s3", "s2"], ["s2", "s1"]]) {
    await waitWhile(() => !(nav(doc).querySelector("a.older")?.dataset.session === to));
    nav(doc).querySelector("a.older").click();
    await at(to);
    await tick();
    assert.equal(back().textContent, "Back to History", `${from} → Older → ${to}: still the page the chain started from`);
  }
  assert.equal(new URL(back().href).pathname, "/mandu/history", "a new tab opens History");
  assert.equal(back().dataset.back, "3", "three entries back: s1, s2 and s3's");

  // The browser's Back steps one session at a time, each naming History.
  window.history.back();
  await at("s2");
  await tick();
  assert.equal(back().textContent, "Back to History");
  assert.equal(back().dataset.back, "2");
  window.history.forward();
  await at("s1");
  await tick();

  const length = window.history.length;
  back().click();
  await waitWhile(() => window.location.pathname !== "/mandu/history");
  await waitWhile(() => doc.activeElement !== rowOf("s3"));
  assert.equal(doc.getElementById("page-history").hidden, false);
  assert.equal(window.history.length, length, "no entry added: Back, not a new page");
  assert.equal(doc.activeElement, rowOf("s3"), "the row you opened has the focus");

  window.history.forward();
  await at("s3");
  await tick();
  assert.equal(back().textContent, "Back to History", "Forward: the first session, still from History");
  assert.equal(back().dataset.back, "1");
});
