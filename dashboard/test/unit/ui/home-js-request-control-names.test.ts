/**
 * home-js-request-control-names.test — the controls on a card of a rule
 * change your agent asked for say which request they answer
 * (public/js/home.js `proposalCard`, `changeWords`, `rowControlName`;
 * dashboard.md §4.25 *Details, Undo and the agent link name their row*).
 *
 * Every request of your agent has one headline, "Your agent wants to
 * change a rule", and the card is a group named by it. Until 2026-10-12 two
 * waiting requests drew two buttons named "Allow", two named "Not now",
 * two links named "See what the agent was doing" and, for two wide
 * changes, two fields named "Type ALLOW to confirm this wide change", in
 * two groups of one name: a screen reader's list of buttons said "Allow,
 * Not now, Allow, Not now", with nothing to say which request each one
 * loosens. Now each is named by what its request changes, its own words
 * first (WCAG 2.5.3), as a Rule changes row's Undo is since run 2030:
 *
 *   - the first line the card draws, ", and N more" for a longer request;
 *     a held change to policy.yaml, which lists no edit, by its first
 *     "This would let" line; a card with neither, by its headline;
 *   - never the reason your agent gave (untrusted words, drawn last);
 *   - the visible words, the group names, the addresses, what Allow and
 *     Not now post and the focus are as before; server text stays text.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, proxy and dashboard,
 * tests/stack/request-control-names.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { T, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const PENDING = "GET policy/proposals?status=pending";
const LINK = "See what the agent was doing";
const FIELD = "Type ALLOW to confirm this wide change";
const HEADLINE = "Your agent wants to change a rule";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const code = (text: string) => ({ kind: "code", text });
const send = (path: string, host: string) => [T("Make "), code(path), T(" a secret no AI may read, may be sent to "), code(host)];
const request = (id: string, rows: unknown[][], over: Record<string, unknown> = {}) => ({
  id, status: "pending", requester: "Your agent", session: "s1", createdAt: Date.now() - 60_000,
  headline: HEADLINE, rows, wouldLet: [[T("Your agent could send that file there")]], capped: false,
  overBroad: false, warnings: [], reason: null, onDisk: false, ...over,
});
const STRIPE = request("pp-000001", [send("/srv/app/.env", "api.stripe.com")], { reason: "TRUSTME: the deploy needs it" });
const GITHUB = request("pp-000002", [send("/srv/app/.env", "api.github.com")], { session: "s2" });
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });
const cardOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: Doc) => c.dataset.id === id);
const buttonOf = (doc: Doc, id: string, words: string) => [...cardOf(doc, id).querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const linkOf = (doc: Doc, id: string) => cardOf(doc, id).querySelector("a.ask-link");
const fieldOf = (doc: Doc, id: string) => cardOf(doc, id).querySelector(".proposal-confirm");
const groupName = (doc: Doc, card: Doc) => doc.getElementById(card.getAttribute("aria-labelledby"))?.textContent;
const names = (doc: Doc, sel: string) => [...doc.querySelectorAll(`#approvals-proposals ${sel}`)].map((x: Doc) => x.getAttribute("aria-label"));
function assertUnique(list: string[], where: string): void {
  assert.equal(new Set(list).size, list.length, `${where}: no two share a name (${JSON.stringify(list)})`);
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
const open = (proposals: unknown[], routes: Record<string, unknown> = {}) =>
  load({ url: APPROVALS, homeVm: quiet(), routes: { [PENDING]: { proposals }, ...routes } });

test("two requests with one headline: each card's Allow, Not now and link are named by what it changes; no two share a name", async () => {
  const { doc, err } = open([STRIPE, GITHUB]);
  assert.equal(err, null);
  await tick(40);
  const want: Record<string, string> = {
    [STRIPE.id]: "Make /srv/app/.env a secret no AI may read, may be sent to api.stripe.com",
    [GITHUB.id]: "Make /srv/app/.env a secret no AI may read, may be sent to api.github.com",
  };
  for (const [id, about] of Object.entries(want)) {
    for (const words of ["Allow", "Not now"]) {
      const b = buttonOf(doc, id, words);
      assert.ok(b, `${id}: ${words} drawn`);
      assert.equal(b.getAttribute("aria-label"), `${words}: ${about}`, `${id}: ${words}`);
      assert.ok(b.getAttribute("aria-label").startsWith(b.textContent), "its own words first (WCAG 2.5.3)");
    }
    const a = linkOf(doc, id);
    assert.equal(a.textContent, LINK, `${id}: the eye still reads the link`);
    assert.equal(a.getAttribute("aria-label"), `${LINK}: ${about}`, `${id}: the link`);
  }
  assert.equal(linkOf(doc, STRIPE.id).getAttribute("href"), "/mandu/agents/s1", "each to its own agent, as before");
  assert.equal(linkOf(doc, GITHUB.id).getAttribute("href"), "/mandu/agents/s2");
  // The cards are still groups named by their headline, alike.
  for (const id of [STRIPE.id, GITHUB.id]) {
    const card = cardOf(doc, id);
    assert.equal(card.getAttribute("role"), "group");
    assert.equal(groupName(doc, card), HEADLINE, "the headline, never the request's lines");
  }
  assertUnique(names(doc, "button"), "the answers");
  assertUnique(names(doc, "a.ask-link"), "the agent links");
});

test("a longer request: its first line and how many more; a wide change's ALLOW field is named too", async () => {
  const wide = request("pp-000003", [send("/srv/app/.env", "*"), [T("Trust "), code("*.example.com")], [T("Let your agent connect to "), code("*")]], { overBroad: true });
  const other = request("pp-000004", [send("/srv/app/id_rsa", "*")], { overBroad: true });
  const { doc } = open([wide, other]);
  await tick(40);
  const about = "Make /srv/app/.env a secret no AI may read, may be sent to *, and 2 more";
  assert.equal(buttonOf(doc, wide.id, "Allow").getAttribute("aria-label"), `Allow: ${about}`);
  assert.equal(buttonOf(doc, wide.id, "Not now").getAttribute("aria-label"), `Not now: ${about}`);
  assert.equal(linkOf(doc, wide.id).getAttribute("aria-label"), `${LINK}: ${about}`);
  const field = fieldOf(doc, wide.id);
  assert.equal(field.getAttribute("aria-label"), `${FIELD}: ${about}`);
  assert.equal(field.getAttribute("placeholder"), "Type ALLOW to confirm", "the placeholder is as before");
  assert.ok(field.getAttribute("aria-label").startsWith(field.getAttribute("placeholder")), "its own words first");
  assert.equal(fieldOf(doc, other.id).getAttribute("aria-label"), `${FIELD}: Make /srv/app/id_rsa a secret no AI may read, may be sent to *`);
  assertUnique(names(doc, ".proposal-confirm"), "the ALLOW fields");
  // The ALLOW gate is as before: Allow waits for the typed word.
  assert.equal(buttonOf(doc, wide.id, "Allow").disabled, true);
  field.value = "ALLOW";
  field.dispatchEvent(new doc.defaultView.Event("input"));
  assert.equal(buttonOf(doc, wide.id, "Allow").disabled, false);
});

test("a held change to policy.yaml is named by what it would let; a card that lists nothing, by its headline", async () => {
  const disk = request("pp-000005", [], {
    onDisk: true, requester: "policy.yaml", session: null,
    headline: "policy.yaml was changed on disk and would loosen 2 rules. Nothing changes until you approve",
    wouldLet: [[T("Any AI could read "), code("~/proj/.env")], [T("Your agent could connect to "), code("evil.example")]],
  });
  const bare = request("pp-000006", [], { wouldLet: [], session: null });
  const { doc } = open([disk, bare]);
  await tick(40);
  assert.equal(buttonOf(doc, disk.id, "Allow").getAttribute("aria-label"), "Allow: Any AI could read ~/proj/.env, and 1 more");
  assert.equal(buttonOf(doc, disk.id, "Not now").getAttribute("aria-label"), "Not now: Any AI could read ~/proj/.env, and 1 more");
  assert.equal(linkOf(doc, disk.id), null, "a held disk change has no agent to link");
  assert.equal(buttonOf(doc, bare.id, "Allow").getAttribute("aria-label"), `Allow: ${HEADLINE}`);
  assert.equal(linkOf(doc, bare.id), null, "no session: no link");
});

test("the reason your agent gave is drawn on the card, and never in a name", async () => {
  const { doc } = open([STRIPE, GITHUB]);
  await tick(40);
  assert.match(cardOf(doc, STRIPE.id).querySelector(".agent-says-text").textContent, /TRUSTME/, "the reason is drawn, as before");
  for (const x of doc.querySelectorAll("#approvals-proposals [aria-label]")) {
    assert.doesNotMatch(x.getAttribute("aria-label"), /TRUSTME|deploy needs/, "the reason is never a name");
  }
});

test("a request's words with markup name its controls as text, never parsed", async () => {
  const odd = request("pp-000007", [send("/srv/<b>x</b>.env", "<img src=x onerror=alert(1)>")]);
  const { doc } = open([odd]);
  await tick(40);
  assert.equal(buttonOf(doc, odd.id, "Allow").getAttribute("aria-label"), "Allow: Make /srv/<b>x</b>.env a secret no AI may read, may be sent to <img src=x onerror=alert(1)>");
  assert.equal(cardOf(doc, odd.id).querySelector("b, img"), null);
});

test("a named Allow and Not now answer their own request; a poll that brings another keeps the focus on the same card's Allow", async () => {
  let pending: unknown[] = [STRIPE, GITHUB];
  const posts: Array<{ url: string; body: unknown }> = [];
  const { doc, calls } = open([], {
    [PENDING]: () => ({ proposals: pending }),
    "POST policy/proposals/pp-000002": (b: unknown) => ((pending = pending.filter((p) => (p as { id: string }).id !== GITHUB.id)), posts.push({ url: "pp-000002", body: b }), {}),
    "POST policy/proposals/pp-000001": (b: unknown) => ((pending = pending.filter((p) => (p as { id: string }).id !== STRIPE.id)), posts.push({ url: "pp-000001", body: b }), {}),
  });
  await tick(40);
  // The focus on the GitHub card's Allow; your agent asks again: the cards
  // are drawn again, and the focus stays on that card's Allow.
  buttonOf(doc, GITHUB.id, "Allow").focus();
  const third = request("pp-000008", [send("/srv/app/.npmrc", "registry.npmjs.org")]);
  pending = [third, STRIPE, GITHUB];
  await poll(doc);
  assert.ok(cardOf(doc, third.id), "the new request is drawn");
  assert.equal(doc.activeElement, buttonOf(doc, GITHUB.id, "Allow"), "the same card's Allow keeps the focus, never another's");
  assert.equal(doc.activeElement.getAttribute("aria-label"), "Allow: Make /srv/app/.env a secret no AI may read, may be sent to api.github.com");
  // Allow named for api.github.com approves that request, and only it.
  doc.activeElement.click();
  await tick(40);
  assert.deepEqual(posts, [{ url: "pp-000002", body: { verdict: "approved" } }]);
  assert.equal(cardOf(doc, GITHUB.id), undefined, "answered: its card is gone");
  // Not now named for api.stripe.com denies that request, and only it.
  const no = buttonOf(doc, STRIPE.id, "Not now");
  assert.equal(no.getAttribute("aria-label"), "Not now: Make /srv/app/.env a secret no AI may read, may be sent to api.stripe.com");
  no.click();
  await tick(40);
  assert.deepEqual(posts[1], { url: "pp-000001", body: { verdict: "denied" } });
  assert.equal(posts.length, 2);
  assert.ok(cardOf(doc, third.id), "the third request still waits");
  assert.equal(calls.filter((c) => c.method === "POST").length, 2, "two answers posted, no more");
});
