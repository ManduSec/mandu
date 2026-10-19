/**
 * home-js-poll-focus.test — the 10 s poll keeps your place on Home and the
 * keyboard focus on every list it draws again (dashboard.md §4.25 *The poll
 * keeps your place* and *The poll keeps the focus*).
 *
 * Until 2026-10-11 Home's top status, hero, first-run card, exposure notice,
 * Running now and Earlier, and Rules' Built-in protections and its pending
 * line, were emptied and drawn again at every poll, whatever the answer. A
 * headless Chromium showed a focused Details link and the hero's "?" falling
 * to <body> within 10 s, with the note the "?" opened closed, and the top
 * bar's live region was written again every 10 s. A changed answer (the
 * agent did more) dropped the focus of any control in a list the poll drew
 * again, on Home, Approvals and the agent page. Now:
 *
 *   - a poll that brings nothing new draws none of those sections; the rows'
 *     "started …" / "ended …" stay current in place;
 *   - each section draws again when what it shows changed;
 *   - after a changed answer the focus goes back to the control drawn at its
 *     place that reads the same (a Details link by its session, even when the
 *     rows moved), an opened "?" opens again, and a control that is gone
 *     gives the focus to its section's heading;
 *   - a card or a list's line an answer gave the focus keeps it, drawn anew
 *     (2026-10-12: it fell to <body>, having lost its tabindex);
 *   - a focus outside what was drawn again, or none, is not moved.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new
 * test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, tick } from "./home-js-fixtures.js";

const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
const now = () => new Date().toISOString();
const agent = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: "Task " + id, cwd: "/home/u/ws", startedAt: now(), lastAt: now(), state: "running",
  stats: { flows: 1, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
  secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, holds: true, waiting: 0, ...over,
});
/** A quiet Home: protected, a secret masked (so the hero has its "?"), two agents running, one ended. */
const quiet = (over: Record<string, unknown> = {}) => home({
  verdict: "protected", headline: "Your secrets are guarded.", waiting: [], protection: { level: "secrets", configured: "secrets", connected: true },
  window: { hours: 24, sessions: 3, masked: 1, secretsMasked: 1, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 },
  agents: [agent("s1"), agent("s3"), agent("s2", { state: "idle", title: "Old task" })],
  ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const details = (doc: any, list: string, session: string) => [...doc.querySelectorAll(`#${list} a`)].find((a: any) => a.dataset.session === session && a.textContent === "Details") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const heroHelp = (doc: any) => doc.querySelector("#hero-facts .help-btn") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const noteOf = (btn: any) => btn.ownerDocument.getElementById(btn.getAttribute("aria-controls"));

test("a poll that brings nothing new draws none of Home's sections: the focus, the nodes and an opened note stay", async () => {
  const { doc } = load({ homeVm: quiet() });
  await tick(40);
  const link = details(doc, "home-agents", "s3");
  const earlier = details(doc, "home-earlier", "s2");
  const status = doc.getElementById("top-status").firstChild;
  const hero = doc.getElementById("hero-facts").firstChild;
  assert.ok(link && earlier && status && hero);
  link.focus();
  await poll(doc);
  assert.equal(doc.activeElement, link, "Running now's Details keeps the focus: the row was not drawn again");
  assert.equal(details(doc, "home-earlier", "s2"), earlier, "Earlier was not drawn again");
  assert.equal(doc.getElementById("top-status").firstChild, status, "the top bar's live region was not written again");
  assert.equal(doc.getElementById("hero-facts").firstChild, hero, "the hero was not drawn again");
  // The "?" opened: still open, with the focus, after the next poll.
  const help = heroHelp(doc);
  help.focus();
  help.click();
  assert.equal(help.getAttribute("aria-expanded"), "true");
  await poll(doc);
  assert.equal(doc.activeElement, help);
  assert.equal(help.getAttribute("aria-expanded"), "true", "the note the reader opened stays open");
  assert.equal(noteOf(help).hidden, false);
});

test("the top bar's live region is written only when what it says changed", async () => {
  const page = load({ homeVm: quiet() });
  const { doc } = page;
  await tick(40);
  const host = doc.getElementById("top-status");
  let writes = 0;
  new doc.defaultView.MutationObserver((m: unknown[]) => { writes += m.length; }).observe(host, { childList: true, subtree: true, characterData: true });
  await poll(doc);
  await poll(doc);
  assert.equal(writes, 0, "two polls with the same answer: not one write");
  page.setHome(quiet({ protection: { level: "off", configured: "off", connected: true } }));
  await poll(doc);
  assert.ok(writes > 0);
  assert.match(host.textContent, /^Protection off$/);
});

test("a row's moment stays current although the row is not drawn again", async () => {
  const startedAt = new Date(Date.now() - 3 * 60_000).toISOString();
  const { doc } = load({ homeVm: quiet({ agents: [agent("s1", { startedAt })] }) });
  await tick(40);
  const t = doc.querySelector("#home-agents time");
  assert.equal(t.textContent, "3 minutes ago");
  t.textContent = "stale";
  t.title = "";
  await poll(doc);
  assert.equal(doc.querySelector("#home-agents time"), t, "the row was not drawn again");
  assert.equal(t.textContent, "3 minutes ago", "refreshWhen wrote its words again from its datetime");
  assert.notEqual(t.title, "", "and its clock time on hover");
});

test("each section draws again when what it shows changed", async () => {
  const page = load({ homeVm: quiet() });
  const { doc } = page;
  await tick(40);
  const text = (id: string) => doc.getElementById(id).textContent.replace(/\s+/g, " ");
  page.setHome(quiet({
    window: { hours: 24, sessions: 3, masked: 4, secretsMasked: 4, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 },
    agents: [agent("s1", { title: "A new prompt" }), agent("s3", { blocked: 2 }), agent("s2", { state: "idle", title: "Old task", lastAt: new Date(Date.now() - 7_200_000).toISOString() })],
    history: { total: 10 },
    exposure: { headline: "Another agent can reach Mandu's own controls.", sentence: "It can.", causes: [], fix: "Restart it." },
    builtIn: { note: "on", items: ["Secrets are masked."] },
  }));
  await poll(doc);
  assert.match(text("hero-facts"), /4 secrets masked/);
  assert.match(text("home-agents"), /A new prompt/);
  assert.match(text("home-agents"), /2 actions blocked/);
  assert.match(text("home-history"), /10 sessions/);
  assert.match(text("home-earlier"), /ended 2 hours ago/);
  assert.equal(doc.getElementById("home-exposure").hidden, false);
  assert.match(text("builtin-list"), /Secrets are masked\./);
  // The first-run card comes and goes with its answer.
  page.setHome(quiet({ agents: [], firstRun: { mode: "secrets", headline: "Start your first agent.", protects: "Mandu protects…", steps: [{ id: "one", title: "Run it", text: "Run it." }] } }));
  await poll(doc);
  assert.equal(doc.getElementById("home-first-run").hidden, false);
  assert.match(text("home-agents"), /No agent is running right now/);
});

test("a changed answer gives the focus back to the same agent's Details, also when the rows moved", async () => {
  const page = load({ homeVm: quiet() });
  const { doc } = page;
  await tick(40);
  const old = details(doc, "home-agents", "s3");
  old.focus();
  // A new agent comes first, and s3 did more.
  page.setHome(quiet({ agents: [agent("s4"), agent("s1"), agent("s3", { secrets: { masked: 2, early: 0 } }), agent("s2", { state: "idle", title: "Old task" })] }));
  await poll(doc);
  const now3 = details(doc, "home-agents", "s3");
  assert.notEqual(now3, old, "the row was drawn again");
  assert.match(now3.closest(".row").textContent, /2 secrets masked/);
  assert.equal(doc.activeElement, now3, "s3's own Details, never the row now at its rank");
});

test("a control that is gone gives the focus to its section's heading, never <body>", async () => {
  const page = load({ homeVm: quiet() });
  const { doc } = page;
  await tick(40);
  details(doc, "home-agents", "s3").focus();
  // s3 ended: its row moves to Earlier.
  page.setHome(quiet({ agents: [agent("s1"), agent("s3", { state: "idle" }), agent("s2", { state: "idle", title: "Old task" })] }));
  await poll(doc);
  const heading = doc.getElementById("home-agents").closest("section.block").querySelector("h2");
  assert.equal(doc.activeElement, heading, "Running now's heading");
  assert.equal(heading.getAttribute("tabindex"), "-1", "a heading is no Tab stop");
});

test("the hero's opened \"?\": its counts change, and the \"?\" keeps the focus with its note open", async () => {
  const page = load({ homeVm: quiet() });
  const { doc } = page;
  await tick(40);
  const old = heroHelp(doc);
  old.focus();
  old.click();
  page.setHome(quiet({ window: { hours: 24, sessions: 3, masked: 2, secretsMasked: 2, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 } }));
  await poll(doc);
  const help = heroHelp(doc);
  assert.notEqual(help, old, "the hero was drawn again");
  assert.equal(doc.activeElement, help);
  assert.equal(help.getAttribute("aria-expanded"), "true");
  assert.equal(noteOf(help).hidden, false);
});

test("the agent page: the agent did more, and a focused story button keeps the focus, its fold as it was", async () => {
  let vm: unknown = AGENT;
  const { doc } = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": () => vm } });
  await tick(40);
  const button = (label: RegExp) => [...doc.querySelectorAll("#agent-story button")].find((b: any) => label.test(b.textContent)) as any;
  const hidden = button(/^Show what was hidden$/);
  hidden.focus();
  hidden.click();
  const opened = hidden.textContent;
  vm = { ...AGENT, blocked: 2, story: [{ ...AGENT.story[0], summary: "Mandu blocked 2 actions." }, AGENT.story[1]] };
  await poll(doc);
  const now = doc.activeElement;
  assert.notEqual(now, hidden, "the story was drawn again");
  assert.equal(now.tagName, "BUTTON");
  assert.equal(now.textContent, opened, "the same toggle, put back as it was left");
  assert.ok(doc.getElementById("agent-story").contains(now));
});

test("Approvals: a changed list gives the focus back to the same question's link", async () => {
  const ASK2 = { ...ASK, id: "egr-2" };
  const page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2] }) });
  const { doc } = page;
  await tick(40);
  const link = (id: string) => [...doc.querySelectorAll("#approvals-waiting a")].find((a: any) => a.dataset.ask === id) as any;
  const old = link("egr-2");
  old.focus();
  // The agent tried egr-1 again: the arbiter counts it on the same question.
  page.setHome(home({ waiting: [{ ...ASK, count: 2 }, ASK2] }));
  await poll(doc);
  assert.notEqual(link("egr-2"), old, "the list was drawn again");
  assert.equal(doc.activeElement, link("egr-2"));
  assert.equal(link("egr-2").hasAttribute("tabindex"), false, "a link given the focus back stays a Tab stop");
});

/** Enter on an answer button: the browser drops the focus of the button
 *  the answer turned off to <body> (home-js-answer-focus.test.ts). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(btn: any): void {
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const answerIn = (doc: any, list: string, id: string, label: string) =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [...doc.querySelectorAll(`#${list} .ask[data-id="${id}"] button`)].find((b: any) => b.textContent === label) as any;

// Until 2026-10-12 a card or a list's line an answer landed on (focusThere
// gives it a tabindex) was drawn anew by the next changed answer without
// one, and focus() alone left the focus on <body>.
test("Home: the card an answer gave the focus keeps it when a poll brings another question", async () => {
  const ASK2 = { ...ASK, id: "egr-2" };
  const ASK3 = { ...ASK, id: "egr-3" };
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ homeVm: home({ waiting: [ASK, ASK2] }), routes: {
    "POST egress/approvals/egr-1/deny": () => (page.setHome(home({ waiting: [ASK2] })), {}),
  } });
  const { doc } = page;
  await tick(40);
  press(answerIn(doc, "home-waiting", "egr-1", "Block"));
  await tick(40);
  const card = (id: string) => doc.querySelector(`#home-waiting .ask[data-id="${id}"]`);
  const old = card("egr-2");
  assert.equal(doc.activeElement, old, "the answer gave the next card the focus");
  page.setHome(home({ waiting: [ASK2, ASK3] }));
  await poll(doc);
  assert.notEqual(card("egr-2"), old, "the list was drawn again");
  assert.equal(doc.activeElement, card("egr-2"), "the same question's card, never <body>");
  assert.equal(card("egr-2").getAttribute("tabindex"), "-1", "a card is no Tab stop");
});

test("Approvals: the list's line an answer gave the focus keeps it when a poll draws the list again", async () => {
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  const none = (answered: unknown[]) => home({ waiting: [], answered, verdict: "protected", headline: "Your secrets are guarded." });
  page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK] }), routes: {
    "POST egress/approvals/egr-1/approve-once": () => (page.setHome(none([])), {}),
  } });
  const { doc } = page;
  await tick(40);
  press(answerIn(doc, "approvals-waiting", "egr-1", "Allow once"));
  await tick(40);
  const line = () => doc.querySelector("#approvals-waiting .empty");
  const old = line();
  assert.equal(doc.activeElement, old, "the last answer lands on the list's line");
  // An answer given elsewhere: Answered earlier has a new row, and the
  // poll draws both lists again.
  page.setHome(none([{ id: "old", sentence: [{ kind: "text", text: "An old send" }], outcome: "blocked", decidedAt: Date.now() - 5_000, actions: [] }]));
  await poll(doc);
  assert.ok(doc.querySelector('#approvals-answered [data-id="old"]'), "Answered earlier was drawn again");
  assert.notEqual(line(), old, "the line was drawn again");
  assert.equal(doc.activeElement, line(), "the line keeps the focus, never <body>");
  assert.equal(line().textContent, "Nothing is waiting for you.");
});

test("a focus outside what was drawn again, or none, is not moved", async () => {
  const page = load({ homeVm: quiet() });
  const { doc } = page;
  await tick(40);
  // The block's own link is not drawn by the poll.
  const open = doc.querySelector('#home-waiting-block a[data-page-link="approvals"]');
  open.focus();
  page.setHome(quiet({ agents: [agent("s9")] }));
  await poll(doc);
  assert.equal(doc.activeElement, open);
  // No focus: a poll that draws a list again moves none to it.
  open.blur();
  assert.equal(doc.activeElement, doc.body);
  page.setHome(quiet({ agents: [agent("s8")] }));
  await poll(doc);
  assert.equal(doc.activeElement, doc.body);
});
