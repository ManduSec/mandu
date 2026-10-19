/**
 * home-js-agent-rule-change.test — a rule change your agent asked for and
 * the agent that asked find each other (public/js/home.js `drawAgentPage`,
 * `proposalCard`; dashboard.md §4.25 *A rule change and the agent that
 * asked*).
 *
 * Until 2026-10-12 the request's card projection dropped the session
 * (view-model/policy-proposals.ts `toProposalCard`). A headless Chromium
 * drew the nav badge "Approvals 1" and Home's "1 rule change your agent
 * asked for is in Approvals" over the agent page of the agent that asked,
 * which said nothing of it: its *Needs your OK* is hidden with no question.
 * The request's card on Approvals, where you decide whether to loosen a
 * rule, was the one card with no way to the agent that asked, while a
 * question's card says "See what the agent was doing". Now the card carries
 * `session` for an agent's request, and:
 *
 *   - the agent page of that session shows *Needs your OK* with "No
 *     question is waiting for you." (or its questions) and the link "1 rule
 *     change this agent asked for is in Approvals"; another agent's page,
 *     a request with no session and a held change to policy.yaml leave it
 *     as it was; a poll that brings or takes the request draws it again,
 *     and a focus on the link stays on it;
 *   - the request's card says "See what the agent was doing", which opens
 *     that agent's page.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, anthropic-proxy and
 * dashboard, tests/stack/agent-page-rule-change.test.ts. Axes: none
 * (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, home, load, tick } from "./home-js-fixtures.js";

const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const PENDING = "GET policy/proposals?status=pending";
const AGENT_READ = "GET home/agent?session=s1";
const NOTHING = "Nothing is waiting for you.";
const NO_QUESTION = "No question is waiting for you.";
const LINK = "1 rule change this agent asked for is in Approvals";

const request = (id: string, over: Record<string, unknown> = {}) => ({
  id, status: "pending", requester: "Your agent", session: "s1", createdAt: Date.now() - 60_000,
  headline: "Your agent wants to change a rule",
  rows: [[{ kind: "text", text: "Let " }, { kind: "code", text: "/srv/app/.env" }, { kind: "text", text: " be sent to api.stripe.com" }]],
  wouldLet: [], capped: false, overBroad: false, warnings: [], reason: null, onDisk: false, ...over,
});
/** The agent page of s1 with no question waiting. */
const quietAgent = (over: Record<string, unknown> = {}) => ({ ...AGENT, waiting: [], ...over });
/** Home with no question waiting. */
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const block = (doc: Doc) => doc.getElementById("agent-waiting-block");
const lines = (doc: Doc) => [...doc.querySelectorAll("#agent-waiting .empty")].map((e: Doc) => e.textContent);
const link = (doc: Doc) => doc.querySelector("#agent-waiting a.more");
const cardOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: Doc) => c.dataset.id === id);
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("the agent page of the agent that asked: Needs your OK, 'No question is waiting for you.' and a link to Approvals", async () => {
  const { doc } = load({ url: AGENT_URL, homeVm: quiet(), routes: { [PENDING]: { proposals: [request("pp-000001")] }, [AGENT_READ]: quietAgent() } });
  await tick(40);
  assert.equal(block(doc).hidden, false, "the block shows");
  assert.deepEqual(lines(doc), [NO_QUESTION], "never 'Nothing' over its own request");
  const a = link(doc);
  assert.equal(a.textContent, LINK);
  assert.equal(a.getAttribute("href"), "/mandu/approvals");
  assert.equal(a.dataset.pageLink, "approvals");
  assert.equal(doc.querySelector("#agent-waiting button"), null, "no Allow or Not now on the agent page");
  // The link opens Approvals, with the request's card.
  a.click();
  await tick(40);
  assert.equal(doc.getElementById("page-approvals").hidden, false);
  assert.ok(cardOf(doc, "pp-000001"), "the request's card");
});

test("two of its requests: the plural; another agent's request is not counted", async () => {
  const { doc } = load({ url: AGENT_URL, homeVm: quiet(), routes: {
    [PENDING]: { proposals: [request("pp-000001"), request("pp-000002", { session: "s2" }), request("pp-000003")] },
    [AGENT_READ]: quietAgent(),
  } });
  await tick(40);
  assert.equal(link(doc).textContent, "2 rule changes this agent asked for are in Approvals");
  assert.equal(doc.getElementById("nav-approvals-count").textContent, "3", "the badge counts every request, as before");
});

test("another agent's page, a request with no session, a held change to policy.yaml: the block stays hidden", async () => {
  for (const [what, p] of [
    ["another agent", request("pp-000001", { session: "s2" })],
    ["no session (an older server)", request("pp-000001", { session: undefined })],
    ["no session recorded", request("pp-000001", { session: null })],
    ["a held change to policy.yaml", request("pp-000001", { onDisk: true, requester: "policy.yaml" })],
  ] as const) {
    const { doc } = load({ url: AGENT_URL, homeVm: quiet(), routes: { [PENDING]: { proposals: [p] }, [AGENT_READ]: quietAgent() } });
    await tick(40);
    assert.equal(doc.getElementById("nav-approvals-count").textContent, "1", `${what}: the request was read`);
    assert.equal(block(doc).hidden, true, `${what}: no Needs your OK`);
    assert.equal(link(doc), null, `${what}: no link`);
    assert.deepEqual(lines(doc), [NOTHING], `${what}: the hidden list as before`);
  }
});

test("a question beside its request: the question's card and the link, no line; the tile counts the question", async () => {
  const { doc } = load({ url: AGENT_URL, homeVm: quiet(), routes: { [PENDING]: { proposals: [request("pp-000001")] }, [AGENT_READ]: { ...AGENT } } });
  await tick(40);
  assert.equal(block(doc).hidden, false);
  assert.ok(doc.querySelector('#agent-waiting .ask[data-id="egr-1"]'), "the question's card");
  assert.deepEqual(lines(doc), []);
  assert.equal(link(doc).textContent, LINK);
  const cards = [...doc.querySelectorAll("#agent-waiting > *")];
  assert.ok(cards.indexOf(link(doc)) > cards.indexOf(doc.querySelector('#agent-waiting .ask[data-id="egr-1"]')), "the link comes after the cards");
  const tile = [...doc.querySelectorAll("#agent-facts .tile")].find((t: Doc) => /waiting for you/.test(t.textContent));
  assert.equal(tile.querySelector(".big").textContent, "1", "the tile counts the questions, as before");
});

test("a poll that brings its request, or takes it away, draws the block again; a focus on the link is kept", async () => {
  let pending: unknown[] = [];
  let vm = quietAgent();
  const { doc } = load({ url: AGENT_URL, homeVm: quiet(), routes: { [PENDING]: () => ({ proposals: pending }), [AGENT_READ]: () => vm } });
  await tick(40);
  assert.equal(block(doc).hidden, true, "nothing waits: hidden");
  // The agent asks: the next poll reads it; the page itself is unchanged.
  pending = [request("pp-000001")];
  await poll(doc);
  assert.equal(block(doc).hidden, false);
  assert.deepEqual(lines(doc), [NO_QUESTION]);
  assert.equal(link(doc).textContent, LINK);
  // The focus on the link; the agent did more: the page is drawn again and
  // the link, reading the same, keeps the focus.
  const old = link(doc);
  old.focus();
  vm = quietAgent({ blocked: 2 });
  await poll(doc);
  assert.notEqual(link(doc), old, "drawn again");
  assert.equal(doc.activeElement, link(doc), "the link keeps the focus, never <body>");
  // The agent asks again: the link says 2, another action by its words, so
  // the focus goes to its section's heading (pollRefocus), never <body>.
  pending = [request("pp-000001"), request("pp-000002")];
  await poll(doc);
  assert.equal(link(doc).textContent, "2 rule changes this agent asked for are in Approvals");
  assert.equal(doc.activeElement, block(doc).querySelector("h2"));
  // Answered in another tab: the next poll reads none.
  pending = [];
  await poll(doc);
  assert.equal(block(doc).hidden, true);
  assert.equal(link(doc), null);
});

test("the request's card links the agent that asked: 'See what the agent was doing' opens its page", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: {
    [PENDING]: { proposals: [request("pp-000001"), request("pp-000002", { session: null }), request("pp-000003", { overBroad: true })] },
    [AGENT_READ]: quietAgent(),
  } });
  await tick(40);
  const a = cardOf(doc, "pp-000001").querySelector("a.ask-link");
  assert.equal(a.textContent, "See what the agent was doing");
  assert.equal(a.getAttribute("href"), "/mandu/agents/s1");
  assert.equal(a.dataset.session, "s1");
  assert.equal(cardOf(doc, "pp-000002").querySelector("a.ask-link"), null, "no session: no link");
  // A wide change: the link, then why it asks for ALLOW, then the field.
  const foot = cardOf(doc, "pp-000003").querySelector(".proposal-confirm").parentElement;
  const kids = [...foot.children].map((k: Doc) => k.className);
  assert.ok(kids.indexOf("ask-link") === 0 && kids.indexOf("proposal-confirm") > 0, `the link comes first: ${kids.join(", ")}`);
  // The click opens the agent page of s1, which links the requests back.
  a.click();
  await tick(40);
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(doc.getElementById("agent-name").textContent, "Claude Code");
  assert.equal(link(doc).textContent, "2 rule changes this agent asked for are in Approvals");
});
