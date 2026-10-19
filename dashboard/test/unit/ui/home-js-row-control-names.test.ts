/**
 * home-js-row-control-names.test — a control that every row of a list
 * repeats says which row it belongs to (public/js/home.js `agentRow`,
 * `loadRuleHistory`, `rowControlName`; dashboard.md §4.25 *Details,
 * Undo and the agent link name their row*).
 *
 * Until 2026-10-12 a headless Chromium read three links named "Details" on
 * Home, one per agent row, each to a different agent's page. Approvals ›
 * *Rule changes* had three "Undo" buttons and four "See what the agent was
 * doing" links, in rows whose sentence two of them shared ("Your agent
 * tightened your rules"). A screen reader's list of links or buttons said
 * the same word once per row, with nothing to tell them apart. Now each is
 * named by its row, its own word first (WCAG 2.5.3), as Settings' rows
 * have been since 2026-10-11:
 *
 *   - Home's Details: "Details: <agent>, <what its row says>", under Running
 *     now and Earlier;
 *   - a Rule changes row's Undo and link: "Undo: <what the change did>",
 *     "See what the agent was doing: <…>": the first line under the
 *     sentence, ", and N more" for a longer change, the sentence for a
 *     change that lists none;
 *   - the visible words, the addresses, the rows' group names and the
 *     focus are as before; a link elsewhere (Answered earlier) keeps its
 *     name; server text stays text.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, proxy and dashboard,
 * tests/stack/row-control-names.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { T, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const CHANGES = "GET policy/changes?limit=21";
const LINK = "See what the agent was doing";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const agent = (id: string, name: string, title: string | null, state: string, cwd: string | null = null) => ({
  id, agent: name, title, cwd, state, startedAt: new Date(Date.now() - 120_000).toISOString(), lastAt: new Date(Date.now() - 60_000).toISOString(),
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
  secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, holds: true, waiting: state === "waiting" ? 1 : 0,
});
const AGENTS = [
  agent("r1", "Claude Code", "Fix the test", "running", "/home/u/ws"),
  agent("w1", "Claude Code", "Deploy the site", "waiting", "/home/u/api"),
  agent("n1", "Codex CLI", null, "running"),
  agent("e1", "Claude Code", "Old task", "idle"),
  agent("e2", "Claude Code", null, "idle"),
];
const homeOf = (agents: unknown[]) => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded.", agents });
const details = (doc: Doc) => [...doc.querySelectorAll("#home-agents a, #home-earlier a")].filter((a: Doc) => a.textContent === "Details");
const detailsOf = (doc: Doc, session: string) => details(doc).find((a: Doc) => a.dataset.session === session);

const code = (text: string) => ({ kind: "code", text });
const make = (path: string) => [T("Make "), code(path), T(" a secret no AI may read")];
const change = (id: string, sentence: string, rows: unknown[][], over: Record<string, unknown> = {}) => ({
  id, sentence, rows, createdAt: Date.now() - 60_000, undone: false, undoable: true, session: null, ...over,
});
const CI = change("pc-000004", "Your agent tightened your rules", [make("~/proj/ci.conf")], { session: "s2" });
const DEPLOY = change("pc-000003", "Your agent tightened your rules", [make("~/proj/deploy.conf")], { session: "s1" });
const BOUND = change("pc-000002", "You approved a change your agent asked for",
  [[...make("~/proj/.env"), T(", may be sent to "), code("api.stripe.com")], make("~/proj/.npmrc")], { session: "s1" });
const BARE = change("pc-000001", "You changed your rules", []);
const rowOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === id);
const undoOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector("button");
const linkOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector("a.ask-link");
const groupName = (doc: Doc, row: Doc) => doc.getElementById(row.getAttribute("aria-labelledby"))?.textContent;
const quiet = (over: Record<string, unknown> = {}) => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded.", ...over });

async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
function assertUnique(names: string[], where: string): void {
  assert.equal(new Set(names).size, names.length, `${where}: no two share a name (${JSON.stringify(names)})`);
}

// ── Home ──────────────────────────────────────────────────────────────────────

test("Home: each row's Details is named by its agent and what its row says, under Running now and Earlier; no two share a name", async () => {
  const { doc, err } = load({ homeVm: homeOf(AGENTS) });
  assert.equal(err, null);
  await tick(40);
  const want: Record<string, string> = {
    r1: "Details: Claude Code, Fix the test in ~/ws",
    w1: "Details: Claude Code, Deploy the site in ~/api",
    n1: "Details: Codex CLI, No prompt yet",
    e1: "Details: Claude Code, Old task",
    e2: "Details: Claude Code, No prompt reached the AI",
  };
  assert.equal(details(doc).length, 5, "one Details per row");
  for (const [session, name] of Object.entries(want)) {
    const a = detailsOf(doc, session);
    assert.ok(a, `${session}: drawn`);
    assert.equal(a.getAttribute("aria-label"), name);
    assert.equal(a.textContent, "Details", "the eye still reads Details");
    assert.ok(a.getAttribute("aria-label").startsWith(a.textContent), "its own word first (WCAG 2.5.3)");
    assert.equal(a.getAttribute("href"), `/mandu/agents/${session}`, "to the same page as before");
  }
  assert.ok(doc.getElementById("home-agents").contains(detailsOf(doc, "r1")));
  assert.ok(doc.getElementById("home-earlier").contains(detailsOf(doc, "e1")));
  assertUnique(details(doc).map((a: Doc) => a.getAttribute("aria-label")), "Home's Details");
});

test("Home: two agents waiting for your OK in one folder get two names, each from what you asked (§4.25 *Agents, not sessions*)", async () => {
  // Both rows once read "Waiting for your OK in ~/api": the same name twice.
  const { doc, err } = load({ homeVm: homeOf([
    agent("w1", "Claude Code", "Deploy the site", "waiting", "/home/u/api"),
    agent("w2", "Claude Code", "Rotate the API key", "waiting", "/home/u/api"),
  ]) });
  assert.equal(err, null);
  await tick(40);
  assert.equal(detailsOf(doc, "w1").getAttribute("aria-label"), "Details: Claude Code, Deploy the site in ~/api");
  assert.equal(detailsOf(doc, "w2").getAttribute("aria-label"), "Details: Claude Code, Rotate the API key in ~/api");
  assertUnique(details(doc).map((a: Doc) => a.getAttribute("aria-label")), "two waiting rows");
});

test("Home: a poll that changes what a row says names its Details again, and keeps the focus on it", async () => {
  const page = load({ homeVm: homeOf(AGENTS) });
  await tick(40);
  detailsOf(page.doc, "r1").focus();
  page.setHome(homeOf([{ ...AGENTS[0], title: "Fix the flaky test" }, ...AGENTS.slice(1)]));
  await poll(page.doc);
  const a = detailsOf(page.doc, "r1");
  assert.equal(a.getAttribute("aria-label"), "Details: Claude Code, Fix the flaky test in ~/ws");
  assert.equal(page.doc.activeElement, a, "the same row's Details keeps the focus, never <body>");
});

test("Home: a prompt with markup is named by its text, never parsed", async () => {
  const { doc } = load({ homeVm: homeOf([agent("x1", "Claude Code", "Read <img src=x onerror=alert(1)> now", "running")]) });
  await tick(40);
  assert.equal(detailsOf(doc, "x1").getAttribute("aria-label"), "Details: Claude Code, Read <img src=x onerror=alert(1)> now");
  assert.equal(doc.querySelector("#home-agents img"), null);
});

// ── Approvals › Rule changes ──────────────────────────────────────────────────

test("Rule changes: two rows with one sentence: each Undo and link is named by what its change did", async () => {
  const { doc, err } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [CI, DEPLOY, BOUND, BARE] } } });
  assert.equal(err, null);
  await tick(40);
  const want: Record<string, string> = {
    [CI.id]: "Make ~/proj/ci.conf a secret no AI may read",
    [DEPLOY.id]: "Make ~/proj/deploy.conf a secret no AI may read",
    [BOUND.id]: "Make ~/proj/.env a secret no AI may read, may be sent to api.stripe.com, and 1 more",
  };
  for (const [id, about] of Object.entries(want)) {
    const undo = undoOf(doc, id);
    assert.equal(undo.textContent, "Undo", `${id}: the eye still reads Undo`);
    assert.equal(undo.getAttribute("aria-label"), "Undo: " + about, `${id}: Undo`);
    const a = linkOf(doc, id);
    assert.equal(a.textContent, LINK, `${id}: the eye still reads the link`);
    assert.equal(a.getAttribute("aria-label"), LINK + ": " + about, `${id}: the link`);
  }
  assert.equal(linkOf(doc, CI.id).getAttribute("href"), "/mandu/agents/s2", "each to its own agent");
  assert.equal(linkOf(doc, DEPLOY.id).getAttribute("href"), "/mandu/agents/s1");
  // A change that lists nothing is named by its sentence; it has no agent.
  assert.equal(undoOf(doc, BARE.id).getAttribute("aria-label"), "Undo: You changed your rules");
  assert.equal(linkOf(doc, BARE.id), null);
  const host = doc.getElementById("approvals-rule-history");
  assertUnique([...host.querySelectorAll("button")].map((b: Doc) => b.getAttribute("aria-label")), "Undo");
  assertUnique([...host.querySelectorAll("a")].map((b: Doc) => b.getAttribute("aria-label")), "the links");
});

test("Rule changes: the rows are still named by their sentence, and a row with no Undo draws none", async () => {
  const done = change("pc-000005", "You undid an earlier change", [[T("Loosened: "), code("~/proj/ci.conf")]], { undoable: false });
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [CI, done] } } });
  await tick(40);
  const row = rowOf(doc, CI.id);
  assert.equal(row.getAttribute("role"), "group");
  assert.equal(groupName(doc, row), "Your agent tightened your rules", "the sentence, never the change's lines");
  assert.equal(undoOf(doc, done.id), null, "an undone change offers no Undo");
  assert.equal(groupName(doc, rowOf(doc, done.id)), "You undid an earlier change");
});

test("Rule changes: a named Undo still undoes, and a poll keeps the focus on it", async () => {
  let changes = [CI, DEPLOY];
  const { doc, calls } = load({ url: APPROVALS, homeVm: quiet(), routes: {
    [CHANGES]: () => ({ changes }),
    "POST policy/changes/pc-000003/undo": () => ((changes = [CI, { ...DEPLOY, undone: true, undoable: false }]), {}),
  } });
  await tick(40);
  undoOf(doc, CI.id).focus();
  changes = [change("pc-000006", "You changed your rules", [make("~/proj/new.pem")]), CI, DEPLOY];
  await poll(doc);
  assert.ok(rowOf(doc, "pc-000006"), "the new change is drawn");
  assert.equal(doc.activeElement, undoOf(doc, CI.id), "the same row's Undo keeps the focus, never another's");
  assert.equal(doc.activeElement.getAttribute("aria-label"), "Undo: Make ~/proj/ci.conf a secret no AI may read");
  changes = [CI, DEPLOY];
  await poll(doc);
  undoOf(doc, DEPLOY.id).focus();
  undoOf(doc, DEPLOY.id).click();
  await tick(40);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-000003/undo"), "the change undone is the row's own");
  assert.match(rowOf(doc, DEPLOY.id).textContent, /Undone/);
  assert.equal(doc.activeElement, rowOf(doc, DEPLOY.id), "the row keeps the focus, as before");
});

test("Rule changes: a change's words with markup name its controls as text, never parsed", async () => {
  const odd = change("pc-000007", "Your agent tightened your rules", [make("~/proj/<b>x</b>.pem")], { session: "s1" });
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [odd] } } });
  await tick(40);
  assert.equal(undoOf(doc, odd.id).getAttribute("aria-label"), "Undo: Make ~/proj/<b>x</b>.pem a secret no AI may read");
  assert.equal(rowOf(doc, odd.id).querySelector("b"), null);
});

test("a link outside these lists keeps its name: Answered earlier's link has no aria-label", async () => {
  const answered = { id: "egr-9", sentence: [T("Claude Code wanted to send a file")], outcome: "blocked", decidedAt: Date.now() - 30_000, actions: [], sessions: ["s1"] };
  const { doc } = load({ url: APPROVALS, homeVm: quiet({ answered: [answered] }), routes: { [CHANGES]: { changes: [] } } });
  await tick(40);
  const a = doc.querySelector("#approvals-answered a.ask-link");
  assert.ok(a, "the answer links where it was asked");
  assert.equal(a.textContent, LINK);
  assert.equal(a.hasAttribute("aria-label"), false);
});
