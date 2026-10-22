/**
 * home-js-proposal-asker.test — a rule change you asked for that is still
 * waiting is never credited to your agent (public/js/home.js
 * `askedByAgent`; view-model/policy-proposals.ts `byAgent`; dashboard.md
 * §4.25 *A rule change you asked for is never credited to your agent*).
 *
 * The product page's own writes propose on the admin channel and approve at
 * once (`applyAsHuman`); when the approval fails (policy.yaml changed on
 * disk just before), the request stays waiting. Until 2026-10-15 its card
 * read "You wants to change a rule", put the page's own note ("Changed on
 * the Rules page (remove)") under "Your agent says", sat under the heading
 * "Rule changes your agent asked for", and Home linked it as "1 rule change
 * your agent asked for is in Approvals". Now, for a request that is not
 * from the agent: "You want to change a rule", its note under "Note", the
 * heading "Rule changes waiting for you" (a held change to policy.yaml
 * too), Home's "1 rule change waits for you in Approvals", and a refile
 * "since this was asked". An agent's request reads exactly as before, and
 * a card the server sent without `byAgent` reads as the agent's.
 *
 * An agent's request also names the agent and folder that asked, from
 * Home's row of its session (`proposalAsker`; dashboard.md *A rule change
 * and the agent that asked*): "Codex wants to change a rule", its moment
 * line "· from Codex in ~/blog", as a question's card (§4.25u *A question
 * says which session asked*). A session Home does not model reads "Your
 * agent wants to change a rule", no folder.
 *
 * The cards are the real view model's (`toProposalCard`) over the rows the
 * arbiter records. Drives the PRODUCT page script in jsdom over the shared
 * fetch stub (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/own-rule-change-waiting.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { toProposalCard, type PolicyProposalRow } from "../../../src/view-model/policy-proposals.js";
import { CLOCK, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const PENDING = "GET policy/proposals?status=pending";
const NOTE = "Changed on the Rules page (remove)";

/** A pending request as the arbiter records it. */
function row(id: string, over: Partial<PolicyProposalRow> = {}): PolicyProposalRow {
  return {
    id,
    edits: [{ op: "unlock-path", path: "/home/u/notes/id_rsa" }],
    reason: NOTE,
    requestedBy: "rules-page",
    sessionKey: null,
    relaxes: [{ facet: "paths", direction: "relax", subject: "/home/u/notes/id_rsa", detail: "" }],
    tightens: [],
    status: "pending",
    createdAt: Date.now() - 60_000,
    resolvedAt: null,
    resolvedBy: null,
    changeId: null,
    supersededBy: null,
    ...over,
  };
}
const YOURS = toProposalCard(row("pp-000001"));
const AGENTS = toProposalCard(row("pp-000002", {
  edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }],
  reason: "I need the package index",
  requestedBy: "agent:s1",
  sessionKey: "s1",
  relaxes: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "" }],
}));
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });
/** Home with no row for the agent's session `s1` (older than Home's window). */
const unmodeled = () => home({ agents: home().agents.filter((a: { id: string }) => a.id !== "s1") });
/** Home whose row for `s1` is `agent` in `cwd`. */
const modeled = (agent: string, cwd: string | null) =>
  home({ agents: home().agents.map((a: { id: string }) => (a.id === "s1" ? { ...a, agent, cwd } : a)) });

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const head = (doc: Doc): string => doc.querySelector("#approvals-proposals-block h2").textContent;
const cardOf = (doc: Doc, id: string): Doc => [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: Doc) => c.dataset.id === id);
const label = (card: Doc): string => card.querySelector(".agent-says .proposal-k").textContent;
const homeLink = (doc: Doc): string => doc.querySelector("#home-waiting .more").textContent;
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}

test("Approvals: your own request left waiting says 'You want to change a rule', its note is a Note, under 'Rule changes waiting for you'", async () => {
  assert.equal(YOURS.byAgent, false);
  const { doc } = load({ url: APPROVALS, routes: { [PENDING]: { proposals: [YOURS] } } });
  await tick(30);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false);
  assert.equal(head(doc), "Rule changes waiting for you");
  const card = cardOf(doc, "pp-000001");
  assert.equal(card.querySelector(".ask-sentence").textContent, "You want to change a rule");
  assert.equal(label(card), "Note");
  assert.equal(card.querySelector(".agent-says-text").textContent, NOTE, "the note is still shown, as text");
  assert.doesNotMatch(doc.getElementById("approvals-proposals-block").textContent, /your agent|You wants/i, "nothing in the block credits it to the agent");
});

test("Home: your own request waiting links 'waits for you', never 'your agent asked for'", async () => {
  const { doc } = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [YOURS] } } });
  await tick(30);
  assert.equal(homeLink(doc), "1 rule change waits for you in Approvals");
});

test("an agent's request whose session Home does not model reads as before: its headline, 'Your agent says', the heading, Home's line", async () => {
  assert.equal(AGENTS.byAgent, true);
  const { doc } = load({ url: APPROVALS, homeVm: unmodeled(), routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  assert.equal(head(doc), "Rule changes your agent asked for");
  const card = cardOf(doc, "pp-000002");
  assert.equal(card.querySelector(".ask-sentence").textContent, "Your agent wants to change a rule");
  assert.equal(label(card), "Your agent says");
  const atHome = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  assert.equal(homeLink(atHome.doc), "1 rule change your agent asked for is in Approvals");
  // A card the server sent without byAgent reads as the agent's, as before.
  const { byAgent: _dropped, ...older } = AGENTS;
  const old = load({ url: APPROVALS, homeVm: unmodeled(), routes: { [PENDING]: { proposals: [older] } } });
  await tick(30);
  assert.equal(head(old.doc), "Rule changes your agent asked for");
  assert.equal(label(cardOf(old.doc, "pp-000002")), "Your agent says");
});

test("both waiting: each card labels its own words, the heading and Home's line say they wait for you", async () => {
  const { doc } = load({ url: APPROVALS, routes: { [PENDING]: { proposals: [AGENTS, YOURS] } } });
  await tick(30);
  assert.equal(head(doc), "Rule changes waiting for you");
  assert.equal(label(cardOf(doc, "pp-000002")), "Your agent says", "the agent's words stay the agent's");
  assert.equal(label(cardOf(doc, "pp-000001")), "Note");
  assert.equal(cardOf(doc, "pp-000001").querySelector(".ask-sentence").textContent, "You want to change a rule");
  const atHome = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [AGENTS, YOURS] } } });
  await tick(30);
  assert.equal(homeLink(atHome.doc), "2 rule changes wait for you in Approvals");
});

test("the heading follows the list a poll brings: yours, then only the agent's, then a held change to policy.yaml", async () => {
  const routes: Record<string, unknown> = { [PENDING]: { proposals: [YOURS] } };
  const { doc } = load({ url: APPROVALS, routes });
  await tick(30);
  assert.equal(head(doc), "Rule changes waiting for you");
  routes[PENDING] = { proposals: [AGENTS] };
  await poll(doc);
  assert.equal(head(doc), "Rule changes your agent asked for");
  const held = toProposalCard(row("pp-000003", { edits: [], reason: null, requestedBy: "file", diskHash: "ab".repeat(32) }));
  routes[PENDING] = { proposals: [held] };
  await poll(doc);
  assert.equal(head(doc), "Rule changes waiting for you", "a held change to policy.yaml is not the agent's either");
  routes[PENDING] = { proposals: [] };
  await poll(doc);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true);
});

test("Allow on your own request that is refiled: 'The rules changed since this was asked'; an agent's keeps 'since your agent asked'", async () => {
  const refiled = toProposalCard(row("pp-000004"));
  const routes: Record<string, unknown> = {
    [PENDING]: { proposals: [YOURS] },
    "POST policy/proposals/pp-000001": { proposal: { ...YOURS, status: "superseded" }, refiled },
  };
  const { doc } = load({ url: APPROVALS, routes });
  await tick(30);
  routes[PENDING] = { proposals: [refiled] };
  ([...cardOf(doc, "pp-000001").querySelectorAll("button")].find((b: Doc) => b.textContent === "Allow") as Doc).click();
  await tick(30);
  const block = doc.getElementById("approvals-proposals").textContent;
  assert.match(block, /The rules changed since this was asked; here is the updated request\./);
  assert.doesNotMatch(block, /your agent/i);

  const agentRefiled = toProposalCard(row("pp-000005", { requestedBy: "agent:s1", sessionKey: "s1", edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }] }));
  const agentRoutes: Record<string, unknown> = {
    [PENDING]: { proposals: [AGENTS] },
    "POST policy/proposals/pp-000002": { proposal: { ...AGENTS, status: "superseded" }, refiled: agentRefiled },
  };
  const theirs = load({ url: APPROVALS, routes: agentRoutes });
  await tick(30);
  agentRoutes[PENDING] = { proposals: [agentRefiled] };
  ([...cardOf(theirs.doc, "pp-000002").querySelectorAll("button")].find((b: Doc) => b.textContent === "Allow") as Doc).click();
  await tick(30);
  assert.match(theirs.doc.getElementById("approvals-proposals").textContent, /The rules changed since your agent asked; here is the updated request\./);
});

const sub = (card: Doc): Doc => card.querySelector(".ask-sub");

test("an agent's request names the agent and folder of its session: 'Codex wants to change a rule', '· from Codex in ~/blog'", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: modeled("Codex", "/home/u/blog"), routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  const card = cardOf(doc, "pp-000002");
  assert.equal(card.querySelector(".ask-sentence").textContent, "Codex wants to change a rule");
  const line = sub(card);
  assert.match(line.textContent, new RegExp(`^${CLOCK} · .+ · from Codex in ~/blog$`), "the moment, then the folder, no period");
  const from = line.querySelector(".ask-from");
  assert.ok(from, "drawn as a question card's askedFrom");
  assert.equal(from.querySelector("code").textContent, "~/blog", "the folder is code");
  assert.equal(label(card), "Your agent says", "the agent's words keep their label");
  assert.equal(head(doc), "Rule changes your agent asked for", "the heading is unchanged");
  const see = [...card.querySelectorAll("a")].find((a: Doc) => /See what the agent was doing/.test(a.textContent));
  assert.ok(see && /\/agents\/s1\b/.test(see.getAttribute("href")), "the link still opens the session");
  const atHome = load({ homeVm: { ...modeled("Codex", "/home/u/blog"), waiting: [], verdict: "protected" }, routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  assert.equal(homeLink(atHome.doc), "1 rule change your agent asked for is in Approvals", "Home's line is unchanged");
});

test("a session with no folder names the agent only; an agent of no known kind keeps 'Your agent', its folder 'from your agent'", async () => {
  const bare = load({ url: APPROVALS, homeVm: modeled("Claude Code", null), routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  const card = cardOf(bare.doc, "pp-000002");
  assert.equal(card.querySelector(".ask-sentence").textContent, "Claude Code wants to change a rule");
  assert.equal(sub(card).querySelector(".ask-from"), null);
  assert.doesNotMatch(sub(card).textContent, /from/);
  const unknown = load({ url: APPROVALS, homeVm: modeled("The agent", "/home/u/blog"), routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  const other = cardOf(unknown.doc, "pp-000002");
  assert.equal(other.querySelector(".ask-sentence").textContent, "Your agent wants to change a rule");
  assert.match(sub(other).textContent, / · from your agent in ~\/blog$/);
});

test("a session Home does not model: 'Your agent wants to change a rule', no 'from'", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: unmodeled(), routes: { [PENDING]: { proposals: [AGENTS] } } });
  await tick(30);
  const card = cardOf(doc, "pp-000002");
  assert.equal(card.querySelector(".ask-sentence").textContent, "Your agent wants to change a rule");
  assert.doesNotMatch(sub(card).textContent, /from/);
});

test("your own waiting request and a held change to policy.yaml read as today, even with session s1 on Home", async () => {
  const held = toProposalCard(row("pp-000003", { edits: [], reason: null, requestedBy: "file", diskHash: "ab".repeat(32), sessionKey: "s1" }));
  const yours = toProposalCard(row("pp-000006", { sessionKey: "s1" }));
  assert.equal(held.session, null);
  assert.equal(yours.session, null);
  const { doc } = load({ url: APPROVALS, homeVm: modeled("Codex", "/home/u/blog"), routes: { [PENDING]: { proposals: [yours, held] } } });
  await tick(30);
  assert.equal(cardOf(doc, "pp-000006").querySelector(".ask-sentence").textContent, "You want to change a rule");
  assert.equal(cardOf(doc, "pp-000003").querySelector(".ask-sentence").textContent, held.headline);
  for (const id of ["pp-000006", "pp-000003"]) assert.doesNotMatch(sub(cardOf(doc, id)).textContent, /from/);
  assert.match(sub(cardOf(doc, "pp-000003")).textContent, /^Seen /, "a held change keeps 'Seen '");
});

test("a poll that brings the session's row names the agent, keeping the typed ALLOW and its focus", async () => {
  const wide = toProposalCard(row("pp-000007", {
    edits: [{ op: "allow-connect", host: "*" }],
    reason: "I need the network",
    requestedBy: "agent:s1",
    sessionKey: "s1",
    relaxes: [{ facet: "connect", direction: "relax", subject: "*", detail: "" }],
  }));
  assert.equal(wide.overBroad, true);
  const { doc, setHome } = load({ url: APPROVALS, homeVm: unmodeled(), routes: { [PENDING]: { proposals: [wide] } } });
  await tick(30);
  assert.equal(cardOf(doc, "pp-000007").querySelector(".ask-sentence").textContent, "Your agent wants to change a rule");
  const box = cardOf(doc, "pp-000007").querySelector(".proposal-confirm");
  box.focus();
  box.value = "ALL";
  box.dispatchEvent(new doc.defaultView.Event("input"));
  setHome(modeled("Codex", "/home/u/blog"));
  await poll(doc);
  const card = cardOf(doc, "pp-000007");
  assert.equal(card.querySelector(".ask-sentence").textContent, "Codex wants to change a rule");
  assert.match(sub(card).textContent, / · from Codex in ~\/blog$/);
  const again = card.querySelector(".proposal-confirm");
  assert.equal(again.value, "ALL", "what you typed is kept");
  assert.equal(doc.activeElement, again, "the focus is kept");
});
