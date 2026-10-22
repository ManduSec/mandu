/**
 * home-js-announce-asks.test — a new question or rule change is said to a
 * screen reader in the top bar's hidden live region `#top-announce`, not
 * only by a desktop notification (dashboard.md §4.25 *A new question is
 * announced on the page*).
 *
 * Until 2026-10-22 a question that came while the page was open was added
 * to the cards and the nav badge in silence: the only signal was a desktop
 * notification, which needs permission and can be turned off, so a blind
 * person on Rules or Settings never learned the agent was held. Now:
 *
 *   - the first read records what already waits and says nothing;
 *   - a later poll with one new question says "<agent> needs your OK. N
 *     waiting in Approvals."; several new give one counted line;
 *   - a rule change the agent asked for has its line; one you asked for
 *     yourself says nothing;
 *   - it holds with notifications turned off and with permission denied;
 *   - a poll with nothing new leaves the region untouched;
 *   - the line never holds the card's sentence (its host or file).
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts); across a real arbiter and
 * dashboard, tests/stack/announce-new-asks.test.ts. Axes: none (display
 * only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { toProposalCard, type PolicyProposalRow } from "../../../src/view-model/policy-proposals.js";
import { ASK, home, load, tick } from "./home-js-fixtures.js";

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const PENDING = "GET policy/proposals?status=pending";
const HOST = "exfil.example";
const ASK2 = { ...ASK, id: "egr-2", agents: ["Codex CLI"], sentence: [{ kind: "text", text: "Codex CLI wants to send your secret STRIPE_KEY to " }, { kind: "code", text: HOST }] };
const ASK3 = { ...ASK, id: "egr-3" };
const ASK4 = { ...ASK, id: "egr-4" };

function row(id: string, over: Partial<PolicyProposalRow> = {}): PolicyProposalRow {
  return {
    id, edits: [{ op: "unlock-path", path: "/home/u/notes/id_rsa" }], reason: "Changed on the Rules page (remove)",
    requestedBy: "rules-page", sessionKey: null,
    relaxes: [{ facet: "paths", direction: "relax", subject: "/home/u/notes/id_rsa", detail: "" }], tightens: [],
    status: "pending", createdAt: Date.now() - 60_000, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
    ...over,
  };
}
const YOURS = toProposalCard(row("pp-000001"));
const AGENTS = toProposalCard(row("pp-000002", {
  edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }], reason: "I need the package index",
  requestedBy: "agent:s1", sessionKey: "s1",
  relaxes: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "" }],
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
const said = (doc: Doc): string => doc.getElementById("top-announce").textContent;

/** A page whose rule-change list a test can change between polls. */
function page(opts: { url?: string; storage?: Record<string, string>; permission?: string; waiting?: unknown[] } = {}) {
  let proposals: unknown[] = [];
  const p = load({
    url: opts.url ?? RULES_URL, storage: opts.storage, permission: opts.permission,
    homeVm: home({ waiting: opts.waiting ?? [ASK, ASK3] }),
    routes: { [PENDING]: () => ({ proposals }) },
  });
  return { ...p, setProposals: (list: unknown[]) => { proposals = list; } };
}

test("the region is a hidden polite live region of its own, beside the protection line", () => {
  const { doc, err } = load();
  assert.equal(err, null);
  const region = doc.getElementById("top-announce");
  assert.ok(region, "the region is on the page");
  assert.equal(region.getAttribute("aria-live"), "polite");
  assert.equal(region.className, "sr-only", "not seen");
  assert.notEqual(region, doc.getElementById("top-status"), "not the protection line");
  assert.equal(region.previousElementSibling, doc.getElementById("top-status"), "beside it in the top bar");
});

test("the first read says nothing; a later poll with one new question names its agent and the count", async () => {
  const p = page();
  await tick(40);
  assert.equal(said(p.doc), "", "what waited when the page loaded is not said");
  p.setHome(home({ waiting: [ASK, ASK3, ASK2] }));
  await poll(p.doc);
  assert.equal(said(p.doc), "Codex CLI needs your OK. 3 waiting in Approvals.");
});

test("two new at once give one counted line; a question going away says nothing", async () => {
  const p = page();
  await tick(40);
  p.setHome(home({ waiting: [ASK, ASK3, ASK2, ASK4] }));
  await poll(p.doc);
  assert.equal(said(p.doc), "2 new waiting for your OK in Approvals.");
  p.setHome(home({ waiting: [ASK] }));
  await poll(p.doc);
  assert.equal(said(p.doc), "2 new waiting for your OK in Approvals.", "nothing said when questions go away");
});

test("an unchanged poll does not write the region again", async () => {
  const p = page();
  await tick(40);
  p.setHome(home({ waiting: [ASK, ASK3, ASK2] }));
  await poll(p.doc);
  const region = p.doc.getElementById("top-announce");
  const node = region.firstChild;
  const changes: unknown[] = [];
  new p.window.MutationObserver((m: unknown[]) => changes.push(...m)).observe(region, { childList: true, characterData: true, subtree: true });
  await poll(p.doc);
  await poll(p.doc);
  assert.equal(changes.length, 0, "no write");
  assert.equal(region.firstChild, node, "the same text node");
});

test("a rule change the agent asked for has its line; one you asked for yourself says nothing", async () => {
  const p = page({ waiting: [ASK] });
  await tick(40);
  p.setProposals([YOURS]);
  await poll(p.doc);
  assert.equal(said(p.doc), "", "your own request is not said");
  p.setProposals([YOURS, AGENTS]);
  await poll(p.doc);
  assert.equal(said(p.doc), "Your agent asks to change a rule. 3 waiting in Approvals.");
});

test("a rule change waiting when the page loaded is not said", async () => {
  const p = page({ waiting: [ASK] });
  p.setProposals([AGENTS]);
  await tick(40);
  await poll(p.doc);
  assert.equal(said(p.doc), "");
});

test("it speaks with notifications turned off in this browser, and with permission denied", async () => {
  for (const opts of [{ storage: { "mandu.home.notifyOff": "1" } }, { permission: "denied" }]) {
    const p = page(opts);
    await tick(40);
    p.setHome(home({ waiting: [ASK, ASK3, ASK2] }));
    await poll(p.doc);
    assert.equal(p.notes.length, 0, `no notification (${JSON.stringify(opts)})`);
    assert.equal(said(p.doc), "Codex CLI needs your OK. 3 waiting in Approvals.", JSON.stringify(opts));
  }
});

test("each tab speaks for itself: a page loaded after another tab primed notifications still says the next new one", async () => {
  const p = page({ storage: { "mandu.home.notifyPrimed": "1", "mandu.home.seenAsks": JSON.stringify(["egr-1", "egr-3", "egr-2"]) } });
  await tick(40);
  assert.equal(said(p.doc), "");
  p.setHome(home({ waiting: [ASK, ASK3, ASK2] }));
  await poll(p.doc);
  assert.equal(said(p.doc), "Codex CLI needs your OK. 3 waiting in Approvals.", "the page's own memory, not the notification's");
});

test("the line never holds the card's sentence: no secret name, no host", async () => {
  const p = page();
  await tick(40);
  p.setHome(home({ waiting: [ASK, ASK3, ASK2] }));
  await poll(p.doc);
  const line = said(p.doc);
  assert.ok(line.length > 0);
  for (const part of ASK2.sentence) assert.ok(!line.includes(part.text), `not "${part.text}"`);
  assert.doesNotMatch(line, /STRIPE_KEY|exfil|\$MDU/);
});
