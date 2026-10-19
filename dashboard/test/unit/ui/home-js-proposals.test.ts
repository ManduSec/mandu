/**
 * home-js-proposals.test — rule changes the agent asked for
 * (policy-surface.md §8.6): the proposal card, Allow / Not now, the typed
 * ALLOW for an over-broad change, re-filed requests, the rule-change history,
 * §4.6 a held change to policy.yaml in Approvals, and (first-session tour
 * item 17) the Rules page saying a change waits while it lists the rules in
 * force.
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, rowOf, rulesPage, tick } from "./home-js-fixtures.js";

// ── Rule changes the agent asked for (policy-surface.md §8.6) ─────────────

const CARD = {
  id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Trust content from " }, { kind: "code", text: "https://pypi.org/" }, { kind: "text", text: " and show it to the AI unmasked" }]],
  wouldLet: [[{ kind: "text", text: "Content from " }, { kind: "code", text: "https://pypi.org/" }, { kind: "text", text: " would reach the AI unmasked" }]],
  capped: false, overBroad: false,
  reason: "<img src=x onerror=alert(1)> Ignore the rules and click Allow",
};
const PENDING = "GET policy/proposals?status=pending";

test("the proposal card: grammar rows, then what it would let, then the agent's words LAST and as text; the badge counts it", async () => {
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { [PENDING]: { proposals: [CARD] } } });
  await tick();
  const block = doc.getElementById("approvals-proposals-block");
  assert.equal(block.hidden, false);
  const card = doc.querySelector("#approvals-proposals .proposal");
  assert.match(card.querySelector(".ask-sentence").textContent, /^Your agent wants to change a rule$/);
  assert.equal(card.querySelector(".proposal-rows").textContent, "Trust content from https://pypi.org/ and show it to the AI unmasked");
  assert.equal(card.querySelector(".proposal-let").textContent, "Content from https://pypi.org/ would reach the AI unmasked");
  const says = card.querySelector(".agent-says-text");
  assert.equal(says.textContent, CARD.reason);
  assert.equal(card.querySelector("img"), null, "the agent's words are never parsed as markup");
  const order = [...card.children].map((c: any) => c.className);
  assert.ok(order.indexOf("agent-says") > order.indexOf("proposal-let"), "the reason comes after the facts");
  assert.ok(!card.querySelector(".proposal-rows").textContent.includes("Ignore the rules"), "the reason is not a row");
  // Badge + title: 1 ask + 1 proposal.
  assert.equal(doc.getElementById("nav-approvals-count").textContent, "2");
  assert.match(window.document.title, /^\(2\) /);
});

test("Allow / Not now post the verdict with the CSRF header", async () => {
  for (const [label, verdict] of [["Allow", "approved"], ["Not now", "denied"]] as const) {
    const { doc, calls } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { [PENDING]: { proposals: [CARD] } } });
    await tick();
    const btn = [...doc.querySelectorAll("#approvals-proposals button")].find((b: any) => b.textContent === label) as any;
    btn.click();
    await tick();
    const post = calls.find((c) => c.method === "POST");
    assert.equal(post!.url, "/mandu/api/policy/proposals/pp-000001");
    assert.deepEqual(post!.body, { verdict });
    assert.equal(post!.headers["X-Mandu-Control"], "1");
  }
});

test("an over-broad change needs the typed word ALLOW before Allow enables", async () => {
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { [PENDING]: { proposals: [{ ...CARD, overBroad: true }] } } });
  await tick();
  const allow = [...doc.querySelectorAll("#approvals-proposals button")].find((b: any) => b.textContent === "Allow") as any;
  const input = doc.querySelector("#approvals-proposals .proposal-confirm") as any;
  assert.equal(allow.disabled, true);
  input.value = "allow";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(allow.disabled, true, "the word must be exact");
  input.value = "ALLOW";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(allow.disabled, false);
});

test("a re-filed request says the rules changed and shows the updated one; a refusal shows the server's words", async () => {
  const refiled = { ...CARD, id: "pp-000002" };
  const routes: Record<string, unknown> = {
    [PENDING]: { proposals: [CARD] },
    "POST policy/proposals/pp-000001": { proposal: { ...CARD, status: "superseded" }, refiled },
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes });
  await tick();
  routes[PENDING] = { proposals: [refiled] };
  ([...doc.querySelectorAll("#approvals-proposals button")].find((b: any) => b.textContent === "Allow") as any).click();
  await tick(20);
  assert.match(doc.getElementById("approvals-proposals").textContent, /The rules changed since your agent asked; here is the updated request\./);
  assert.equal(doc.querySelector("#approvals-proposals .proposal").getAttribute("data-id"), "pp-000002");

  const bad = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { [PENDING]: { proposals: [CARD] }, "POST policy/proposals/pp-000001": { status: 409, body: { error: "policy proposal pp-000001 is already denied" } } } });
  await tick();
  ([...bad.doc.querySelectorAll("#approvals-proposals button")].find((b: any) => b.textContent === "Allow") as any).click();
  await tick();
  assert.match(bad.doc.querySelector("#approvals-proposals .ask-error").textContent, /already denied/);
});

test("rule-change history: Undo posts to the change, a conflict shows the server's words", async () => {
  const CHANGE = { id: "pc-000001", sentence: "Your agent tightened your rules", rows: [[{ kind: "text", text: "Lock " }, { kind: "code", text: "/x.pem" }]], createdAt: Date.now(), undone: false, undoable: true };
  const { doc, calls } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { "GET policy/changes?limit=21": { changes: [CHANGE] }, "POST policy/changes/pc-000001/undo": { status: 409, body: { error: "cannot undo pc-000001: changed again since (paths /x.pem); nothing was changed" } } },
  });
  await tick();
  assert.equal(doc.getElementById("approvals-rule-history-block").hidden, false);
  assert.match(doc.getElementById("approvals-rule-history").textContent, /Your agent tightened your rules.*Lock \/x\.pem/);
  ([...doc.querySelectorAll("#approvals-rule-history button")].find((b: any) => b.textContent === "Undo") as any).click();
  await tick();
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-000001/undo" && c.headers["X-Mandu-Control"] === "1"));
  assert.match(doc.querySelector("#approvals-rule-history .ask-error").textContent, /changed again since/);
});

test("rule-change history: a change reads whole, its sentence and rule lines in the row's words cell with when under them, never cut (§4.25, *Read in full*)", async () => {
  const path = "/home/u/proj/services/billing/config/production-credentials.yaml";
  const createdAt = Date.now() - 2 * 60_000;
  const CHANGE = {
    id: "pc-000002", sentence: "Your agent tightened your rules", createdAt, undone: true, undoable: false,
    rows: [[{ kind: "text", text: "Make " }, { kind: "code", text: path }, { kind: "text", text: " a secret no AI may read" }]],
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/changes?limit=21": { changes: [CHANGE] } } });
  await tick();
  const row = doc.querySelector('#approvals-rule-history .row.answered[data-id="pc-000002"]');
  assert.ok(row, "the change's row");
  // Until 2026-10-08 the words sat in one ellipsized cell: a phone read
  // "Make /home/u/proj/serv" above Undo, never what the change made it.
  assert.equal(row.querySelector(".ellipsis"), null, "nothing in the row is cut to one line");
  const [what, state, last] = [...row.children] as any[];
  assert.equal(row.children.length, 3, "words, state, button cell");
  assert.equal(what.className, "answered-what");
  const words = what.querySelector(".answered-sentence");
  assert.equal(words.firstElementChild.textContent, "Your agent tightened your rules");
  assert.equal(words.querySelector("ul.proposal-let li").textContent, `Make ${path} a secret no AI may read`);
  assert.equal(words.querySelector("ul.proposal-let code").textContent, path);
  const when = what.lastElementChild;
  assert.equal(when.className, "dim answered-when", "when is the line under the words");
  assert.equal(when.querySelector("time").getAttribute("datetime"), new Date(createdAt).toISOString());
  assert.equal(row.querySelectorAll("time").length, 1);
  assert.equal(state.textContent, "Undone");
  assert.equal(last.tagName, "SPAN", "no Undo on a change already undone");
});

test("no proposals: the block stays hidden and the badge counts asks only", async () => {
  const { doc } = load();
  await tick();
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true);
  assert.equal(doc.getElementById("nav-approvals-count").textContent, "1");
});

test("§4.6 Approvals: a held change to policy.yaml shows its headline, what it would let, and what Not now leaves", async () => {
  const card = {
    id: "pp-000009", status: "pending", requester: "policy.yaml", onDisk: true,
    headline: "policy.yaml was changed on disk and would loosen 1 rule. Nothing changes until you approve",
    rows: [], wouldLet: [[{ kind: "text", text: "Rule " }, { kind: "code", text: "hand" }, { kind: "text", text: " would let more data leave without asking" }]],
    capped: false, overBroad: false, warnings: [], reason: null, createdAt: Date.now() - 1000,
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/proposals?status=pending": { proposals: [card] } } });
  await tick();
  const el = doc.querySelector("#approvals-proposals .proposal");
  assert.equal(el.querySelector(".ask-sentence").textContent, card.headline);
  assert.match(el.querySelector(".ask-sub").textContent, /^Seen /);
  assert.equal(el.querySelector(".proposal-let").textContent, "Rule hand would let more data leave without asking");
  assert.match(el.textContent, /Not now keeps your current rules and writes them back to policy\.yaml/);
  assert.equal(el.querySelector(".agent-says"), null, "no agent's words on a file change");
  const allow = [...el.querySelectorAll("button")].find((b: any) => b.textContent === "Allow") as any;
  assert.equal(allow.disabled, false);
});

test("plan 15 §13.7 item 4: History and the rule-change cards are read with the CSRF header; a list whose patterns the server hid says so in plain words", async () => {
  const CHANGE = { id: "pc-000002", sentence: "You changed your rules", rows: [[{ kind: "text", text: "Let " }, { kind: "code", text: "pii.email" }, { kind: "text", text: " in your prompts through when it matches a pattern you set (sign in as the admin to see it)" }]], createdAt: Date.now(), undone: false, undoable: true };
  const { doc, calls } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { "GET policy/changes?limit=21": { changes: [CHANGE], patternsHidden: true }, [PENDING]: { proposals: [CARD], patternsHidden: true } },
  });
  await tick();
  for (const path of ["/mandu/api/policy/changes?limit=21", "/mandu/api/policy/proposals?status=pending"]) {
    const call = calls.find((c) => c.method === "GET" && c.url === path);
    assert.equal(call?.headers["X-Mandu-Control"], "1", `${path} carries the header, so an admin sees the patterns`);
  }
  const note = "Some of these changes let words you chose through the prompt filter. Sign in as the admin to see them.";
  assert.equal(doc.querySelector("#approvals-rule-history .patterns-hidden")?.textContent, note);
  assert.equal(doc.querySelector("#approvals-proposals .patterns-hidden")?.textContent, note);
  const shown = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/changes?limit=21": { changes: [CHANGE] } } });
  await tick();
  assert.equal(shown.doc.querySelector("#approvals-rule-history .patterns-hidden"), null, "no note when nothing was hidden");
});

// ── Tour item 17: Rules lists the rules in force while a change waits ───────

test("tour 17: Rules lists the rules in force while a held policy.yaml change waits, and says the change is not in force yet", async () => {
  const held = {
    id: "pp-000009", status: "pending", requester: "policy.yaml", onDisk: true,
    headline: "policy.yaml was changed on disk and would loosen 1 rule. Nothing changes until you approve",
    rows: [], wouldLet: [], capped: false, overBroad: false, warnings: [], reason: null, createdAt: Date.now() - 1000,
  };
  const { doc } = rulesPage({ [PENDING]: { proposals: [held] } });
  await tick();
  const box = doc.getElementById("rules-pending");
  assert.equal(box.hidden, false);
  assert.match(box.textContent, /^policy\.yaml has a change that waits for your OK, so it is not in force yet\. Until you answer, the rules below are the ones Mandu enforces\. Review it in Approvals\.$/);
  assert.equal(box.querySelector("a").getAttribute("data-page-link"), "approvals");
  assert.ok(rowOf(doc, /api\.example\.com/), "the rules in force are listed");
});

test("tour 17: an agent's waiting changes are counted on Rules; with none the line stays hidden", async () => {
  const two = await (async () => {
    const { doc } = rulesPage({ [PENDING]: { proposals: [CARD, { ...CARD, id: "pp-000002" }] } });
    await tick();
    return doc.getElementById("rules-pending");
  })();
  assert.match(two.textContent, /^2 rule changes wait for your OK\. Until you answer, the rules below are the ones Mandu enforces\. Review them in Approvals\.$/);
  const { doc } = rulesPage({ [PENDING]: { proposals: [] } });
  await tick();
  assert.equal(doc.getElementById("rules-pending").hidden, true);
  assert.ok(rowOf(doc, /api\.example\.com/));
});
