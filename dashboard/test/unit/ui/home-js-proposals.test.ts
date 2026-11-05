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
import { readFileSync } from "node:fs";

import { home, load, rowOf, rulesPage, tick } from "./home-js-fixtures.js";

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
  input.value = "ALLO";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(allow.disabled, true, "the word must be typed whole");
  input.value = "ALLOW";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(allow.disabled, false);
});

// ── The typed ALLOW takes any case, and Enter (dashboard.md §4.25) ─────────
// A phone keyboard capitalises the first letter of a field: a-l-l-o-w gave
// "Allow", and Allow stayed grey with nothing on the card saying why.

const WIDE_URL = "http://127.0.0.1:4500/mandu/approvals";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function typeIn(window: any, input: any, text: string): void {
  input.value = text;
  input.dispatchEvent(new window.Event("input"));
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function enter(window: any, input: any): void {
  input.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
}

test("the ALLOW box counts the word in any case, trimmed; a wrong word shows the hint, which describes the box", async () => {
  const { doc, window } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [{ ...CARD, overBroad: true }] } } });
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal") as any;
  const allow = card.querySelector(".proposal-allow");
  const input = card.querySelector(".proposal-confirm");
  const hint = card.querySelector(".confirm-hint");
  assert.ok(hint, "the card has the hint line");
  assert.equal(hint.hidden, true, "nothing typed: no hint");
  assert.equal(input.getAttribute("aria-describedby"), null);
  for (const word of ["Allow", "allow", " ALLOW ", "ALLOW"]) {
    typeIn(window, input, word);
    assert.equal(allow.disabled, false, `"${word}" turns Allow on`);
    assert.equal(hint.hidden, true, `"${word}": no hint`);
  }
  for (const word of ["ALLO", "ALLOWED", "al low"]) {
    typeIn(window, input, word);
    assert.equal(allow.disabled, true, `"${word}" keeps Allow off`);
    assert.equal(hint.hidden, false, `"${word}": the hint says why`);
    assert.equal(hint.textContent, "Type the word ALLOW to turn on Allow.");
    assert.equal(input.getAttribute("aria-describedby"), hint.id, "the hint describes the box");
  }
  typeIn(window, input, "");
  assert.equal(allow.disabled, true, "empty keeps Allow off");
  assert.equal(hint.hidden, true, "empty: no hint");
  assert.equal(input.getAttribute("aria-describedby"), null);
});

test("the ALLOW box asks a phone for capitals and no corrections", async () => {
  const { doc } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [{ ...CARD, overBroad: true }] } } });
  await tick();
  const input = doc.querySelector("#approvals-proposals .proposal-confirm") as any;
  assert.equal(input.getAttribute("autocapitalize"), "characters");
  assert.equal(input.getAttribute("autocorrect"), "off");
  assert.equal(input.getAttribute("spellcheck"), "false");
  assert.equal(input.getAttribute("autocomplete"), "off");
});

test("Enter in the ALLOW box presses Allow once when it is on, and does nothing when it is off", async () => {
  const { doc, window, calls } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [{ ...CARD, overBroad: true }] } } });
  await tick();
  const input = doc.querySelector("#approvals-proposals .proposal-confirm") as any;
  const posts = () => calls.filter((c) => c.method === "POST");
  typeIn(window, input, "allo");
  enter(window, input);
  await tick();
  assert.equal(posts().length, 0, "off: Enter posts nothing");
  typeIn(window, input, "allow");
  enter(window, input);
  enter(window, input);
  await tick();
  assert.equal(posts().length, 1, "on: Enter posts the approval once, a second Enter while it is out does not");
  assert.equal(posts()[0].url, "/mandu/api/policy/proposals/pp-000001");
  assert.deepEqual(posts()[0].body, { verdict: "approved" });
});

test("a narrow change has no ALLOW box and no hint", async () => {
  const { doc } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [CARD] } } });
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal") as any;
  assert.equal(card.querySelector(".proposal-confirm"), null);
  assert.equal(card.querySelector(".confirm-hint"), null);
  assert.equal(card.querySelector(".proposal-allow").disabled, false);
});

// ── Where a wide change's line is drawn (dashboard.md §4.25 *A wide change
// says what is open*, *Where the line is drawn*): at 1280 px the line ran on
// from the link, and the field and the answers wrapped to the left.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const footOf = (card: any) => card.querySelector(".proposal-allow").closest(".proposal-foot");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tabOrder = (el: any) => ([...el.querySelectorAll("a[href], input, button")] as any[]).map((c) => c.getAttribute("aria-label") ? c.getAttribute("aria-label").split(":")[0] : c.textContent || c.className);

test("a wide change: its line stands right above the foot, never in it; the foot is the link, then the field, Allow and Not now", async () => {
  const { doc } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [{ ...CARD, overBroad: true, session: "s1", byAgent: true }] } } });
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal") as any;
  const why = card.querySelector(".wide-why");
  const foot = footOf(card);
  assert.ok(why && foot, "the line and the foot are drawn");
  assert.equal(why.tagName, "DIV", "a line of its own");
  assert.equal(why.parentElement, card, "a line of the card");
  assert.equal(why.nextElementSibling, foot, "right before the foot");
  assert.equal(foot.querySelector(".wide-why"), null, "not in the foot");
  assert.ok(why.classList.contains("dim"), "the note's ink");
  assert.equal(why.textContent, "This change has no limit on one side.", "its words as before (no sentences sent)");
  assert.deepEqual([...foot.children].map((c: any) => c.className), ["ask-link", "proposal-confirm", "ask-actions", "confirm-hint"], "the link, the field, the answers, the hint line");
  assert.match(foot.querySelector(".ask-link").getAttribute("style"), /margin-right:\s*auto/, "the link keeps the left; the rest goes right");
  assert.deepEqual(tabOrder(card), ["See what the agent was doing", "Type ALLOW to confirm this wide change", "Allow", "Not now"], "the Tab order is unchanged");
  assert.ok(card.contains(card.querySelector(".proposal-confirm")), "the field stays in its card (the poll keeps a card being typed in)");
});

test("a wide change with no session: the line and the field, no link; the field takes the left margin past a phone's width", async () => {
  const { doc } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [{ ...CARD, overBroad: true, session: null }] } } });
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal") as any;
  const foot = footOf(card);
  assert.equal(card.querySelector(".wide-why").nextElementSibling, foot);
  assert.equal(card.querySelector(".ask-link"), null, "no session: no link");
  assert.deepEqual([...foot.children].map((c: any) => c.className), ["proposal-confirm", "ask-actions", "confirm-hint"]);
  const css = readFileSync(new URL("../../../public/app.css", import.meta.url), "utf8");
  assert.match(css, /@media \(min-width: 641px\) \{ \.proposal-foot > \.proposal-confirm:first-child \{ margin-left: auto; \} \}/, "with no link the field and the answers sit right");
  assert.match(css, /\.wide-why \{ font-size: 14px; \}/, "the line keeps its size");
});

test("a change that is not wide: no line, the foot is the link and the two answers as before", async () => {
  const { doc } = load({ url: WIDE_URL, routes: { [PENDING]: { proposals: [{ ...CARD, session: "s1", byAgent: true }] } } });
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal") as any;
  assert.equal(card.querySelector(".wide-why"), null);
  const foot = footOf(card);
  assert.deepEqual([...foot.children].map((c: any) => c.className), ["ask-link", "ask-actions"]);
  assert.match(foot.querySelector(".ask-link").getAttribute("style"), /margin-right:\s*auto/);
  assert.deepEqual(tabOrder(foot), ["See what the agent was doing", "Allow", "Not now"]);
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

// ── A link to one rule change opens Approvals at it (dashboard.md §4.25 *Details*) ──

test("Home's line and the Rules banner open Approvals at the one rule change waiting, and at Approvals itself for two", async () => {
  const homeLink = (doc: any) => doc.querySelector("#home-waiting a.more");
  const one = load({ routes: { [PENDING]: { proposals: [CARD] } } });
  await tick();
  assert.equal(homeLink(one.doc).textContent, "1 rule change your agent asked for is in Approvals");
  assert.equal(homeLink(one.doc).getAttribute("href"), "/mandu/approvals/pp-000001");
  // A click opens Approvals with that card marked.
  homeLink(one.doc).click();
  await tick();
  assert.equal(one.window.location.pathname, "/mandu/approvals/pp-000001");
  assert.deepEqual([...one.doc.querySelectorAll("#page-approvals .focus")].map((x: any) => x.dataset.id), ["pp-000001"]);
  const two = load({ routes: { [PENDING]: { proposals: [CARD, { ...CARD, id: "pp-000002" }] } } });
  await tick();
  assert.equal(homeLink(two.doc).textContent, "2 rule changes your agent asked for are in Approvals");
  assert.equal(homeLink(two.doc).getAttribute("href"), "/mandu/approvals");

  const banner = async (proposals: unknown[]) => {
    const { doc } = rulesPage({ [PENDING]: { proposals } });
    await tick();
    return doc.querySelector("#rules-pending a");
  };
  assert.equal((await banner([CARD])).getAttribute("href"), "/mandu/approvals/pp-000001");
  assert.equal((await banner([CARD, { ...CARD, id: "pp-000002" }])).getAttribute("href"), "/mandu/approvals");
});

test("a poll that swaps the one waiting change for another points Home's line at the new one", async () => {
  let proposals = [CARD];
  const { doc, window } = load({ routes: { [PENDING]: () => ({ proposals }) } });
  await tick();
  assert.equal(doc.querySelector("#home-waiting a.more").getAttribute("href"), "/mandu/approvals/pp-000001");
  proposals = [{ ...CARD, id: "pp-000007" }];
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.equal(doc.querySelector("#home-waiting a.more").getAttribute("href"), "/mandu/approvals/pp-000007");
});

// ── An answer to a rule change says what it did (dashboard.md §4.25 *An answer says what it did*) ──
// Until 2026-10-25 an answered rule change just went: the block hid with its
// last card, nothing said to tell the agent, and the Undo sat at the bottom
// of Approvals under Rule changes.

const ASKED = {
  ...CARD, id: "pp-000004", byAgent: true, session: "s1",
  rows: [[{ kind: "code", text: "~/shop/.env" }, { kind: "text", text: " may be sent to " }, { kind: "code", text: "api.stripe.com" }]],
  wouldLet: [[{ kind: "code", text: "~/shop/.env" }, { kind: "text", text: " would reach " }, { kind: "code", text: "api.stripe.com" }]],
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const lineWords = (x: any): string => String(x.textContent).replace(/\s+/g, " ").trim();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const proposalButton = (doc: any, id: string, label: string): any =>
  [...doc.querySelectorAll(`#approvals-proposals .proposal`)].find((c: any) => c.dataset.id === id)
    .querySelector(label === "Allow" ? ".proposal-allow" : "button.primary");
/** Approvals with `cards` waiting; the answer to `id` takes it away and
 *  answers `reply`. */
function proposalsAnswered(cards: unknown[], id: string, reply: unknown) {
  let pending = cards;
  const page = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: {
      [PENDING]: () => ({ proposals: pending }),
      [`POST policy/proposals/${id}`]: () => ((pending = pending.filter((p: any) => p.id !== id)), reply),
    },
  });
  return page;
}

test("Allow on the only rule change leaves its block shown with a line: what was allowed, to tell the agent, and Undo it at the change's row", async () => {
  const { doc } = proposalsAnswered([ASKED], "pp-000004", { proposal: { ...ASKED, status: "approved" }, changeId: "pc-000012" });
  await tick();
  proposalButton(doc, "pp-000004", "Allow").click();
  await tick(30);
  assert.equal(doc.querySelector("#approvals-proposals .proposal"), null, "the card went");
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "the block stays shown");
  assert.equal(doc.getElementById("approvals-proposals-head").textContent, "Rule changes Claude Code asked for", "named by the change answered, as its session's agent");
  const line = doc.querySelector("#approvals-proposals .answer-line");
  assert.equal(lineWords(line), "Allowed: Claude Code's rule change: ~/shop/.env may be sent to api.stripe.com. It is in force now. Tell Claude Code it may go on. Undo it");
  assert.equal(line.getAttribute("role"), "status");
  assert.equal(line.querySelector("strong").textContent, "Allowed:");
  assert.deepEqual([...line.querySelectorAll("code")].map((c: any) => c.textContent), ["~/shop/.env", "api.stripe.com"], "the names as code, as on the card");
  const undo = line.querySelector("a");
  assert.equal(undo.textContent, "Undo it");
  assert.equal(undo.getAttribute("href"), "/mandu/approvals/pc-000012");
  assert.equal(undo.dataset.ask, "pc-000012");
  assert.ok(!lineWords(line).includes("Ignore the rules"), "never the agent's reason");
  assert.equal(line.querySelector("img"), null);
});

test("Not now says the rules stay; a held policy.yaml edit's Not now says the file was written back; neither has a link", async () => {
  const { doc } = proposalsAnswered([ASKED, { ...ASKED, id: "pp-000005" }], "pp-000004", { proposal: { ...ASKED, status: "denied" } });
  await tick();
  proposalButton(doc, "pp-000004", "Not now").click();
  await tick(30);
  const line = doc.querySelector("#approvals-proposals .answer-line");
  assert.equal(lineWords(line), "Not now: Claude Code's rule change: ~/shop/.env may be sent to api.stripe.com. Your rules stay as they are.");
  assert.equal(line.querySelector("a"), null);
  assert.equal(doc.getElementById("approvals-proposals").firstElementChild, line, "where the card was, above the next one");

  const held = {
    id: "pp-000009", status: "pending", requester: "policy.yaml", onDisk: true, byAgent: false, session: null,
    headline: "policy.yaml was changed on disk and would loosen 1 rule. Nothing changes until you approve",
    rows: [], wouldLet: [[{ kind: "text", text: "Rule " }, { kind: "code", text: "hand" }, { kind: "text", text: " would let more data leave without asking" }]],
    capped: false, overBroad: false, warnings: [], reason: null, createdAt: Date.now() - 1000,
  };
  const disk = proposalsAnswered([held], "pp-000009", { proposal: { ...held, status: "denied" } });
  await tick();
  proposalButton(disk.doc, "pp-000009", "Not now").click();
  await tick(30);
  assert.equal(lineWords(disk.doc.querySelector("#approvals-proposals .answer-line")),
    "Not now: The change to policy.yaml: Rule hand would let more data leave without asking. Your rules stay as they are, and policy.yaml was written back to match them.");
});

test("a rule change no agent asked for says nothing about telling one; an older server's Allow has no Undo link", async () => {
  const mine = { ...ASKED, id: "pp-000006", requester: "You", byAgent: false, session: null, reason: null };
  const { doc } = proposalsAnswered([mine], "pp-000006", { proposal: { ...mine, status: "approved" } });
  await tick();
  proposalButton(doc, "pp-000006", "Allow").click();
  await tick(30);
  const line = doc.querySelector("#approvals-proposals .answer-line");
  assert.equal(lineWords(line), "Allowed: Your rule change: ~/shop/.env may be sent to api.stripe.com. It is in force now.");
  assert.equal(line.querySelector("a"), null, "no change id, no link");
  assert.equal(doc.getElementById("approvals-proposals-head").textContent, "Rule changes waiting for you", "the heading still names whose it was");
});

// ── Rule changes count their cards (dashboard.md §4.25 *Rule changes count their cards*) ──
// The questions' heading says how many wait, "Waiting for your answer (5)"
// (#208); until 2026-11-04 the rule changes' heading above it was bare, so
// with several waiting a person counted the cards.

test("§4.25 Rule changes count their cards: '(3)', an Allow lowers it, a poll raises it, a same poll leaves it, only an answer's line left has none", async () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let pending: any[] = ["pp-000021", "pp-000022", "pp-000023"].map((id) => ({ ...ASKED, id }));
  const reply = (id: string) => () => {
    const p = pending.find((c) => c.id === id);
    pending = pending.filter((c) => c.id !== id);
    return { proposal: { ...p, status: "approved" } };
  };
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: {
      [PENDING]: () => ({ proposals: pending }),
      "POST policy/proposals/pp-000021": reply("pp-000021"),
      "POST policy/proposals/pp-000022": reply("pp-000022"),
      "POST policy/proposals/pp-000023": reply("pp-000023"),
      "POST policy/proposals/pp-000024": reply("pp-000024"),
    },
  });
  const poll = async () => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(30); };
  await tick(30);
  const h2 = doc.getElementById("approvals-proposals-head");
  const words = doc.getElementById("approvals-proposals-words");
  const count = doc.getElementById("approvals-proposals-count");
  const cards = () => doc.querySelectorAll("#approvals-proposals .proposal").length;
  assert.equal(h2.textContent, "Rule changes Claude Code asked for (3)");
  assert.equal(words.textContent, "Rule changes Claude Code asked for", "the words as before, in their own span");
  assert.equal(count.textContent.trim(), "(3)");
  assert.ok(count.classList.contains("muted"), "muted, as the questions' count");
  assert.equal(count.parentElement, h2);
  assert.equal(cards(), 3, "the count is the cards listed");

  // A poll with the same changes leaves the count as written: not written again.
  const text = count.firstChild;
  await poll();
  assert.equal(count.firstChild, text, "written only when it changes");
  assert.equal(h2.textContent, "Rule changes Claude Code asked for (3)");

  // An Allow that takes a card off lowers it with the redraw that follows.
  proposalButton(doc, "pp-000021", "Allow").click();
  await tick(30);
  assert.equal(cards(), 2);
  assert.equal(h2.textContent, "Rule changes Claude Code asked for (2)");

  // A poll that brings one more raises it.
  pending = [...pending, { ...ASKED, id: "pp-000024" }];
  await poll();
  assert.equal(cards(), 3);
  assert.equal(h2.textContent, "Rule changes Claude Code asked for (3)");

  // Nothing left but the last answer's line: the words alone, no count.
  for (const id of ["pp-000022", "pp-000023", "pp-000024"]) {
    proposalButton(doc, id, "Allow").click();
    await tick(30);
  }
  assert.equal(cards(), 0);
  assert.ok(doc.querySelector("#approvals-proposals .answer-line"), "the answer's line stays");
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "and keeps the block shown");
  assert.equal(count.textContent, "");
  assert.equal(h2.textContent, "Rule changes Claude Code asked for", "the words alone end the heading");
});

// ── A rule change from a session that has ended (dashboard.md §4.25 *An answer says what it did*) ──
// The card says the agent that asked has ended, in a question's words
// (§4.34 *After you answer*), and Allow tells no one to go on: no agent
// waits for it. Until 2026-11-02 the line said "Tell Claude Code it may go
// on." whether or not that session was still running.

/** Approvals with ASKED from session `s7`, whose row on Home is `state`
 *  (none: Home does not list it); Allow answers it. */
function askedFrom(state: string | null) {
  const base = home();
  const row = { ...(base.agents as any[])[0], id: "s7", cwd: "/home/u/shop", state, waiting: 0 };
  const card = { ...ASKED, id: "pp-000021", session: "s7" };
  let pending: unknown[] = [card];
  return load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    homeVm: home({ agents: state === null ? base.agents : [...(base.agents as any[]), row] }),
    routes: {
      [PENDING]: () => ({ proposals: pending }),
      ["POST policy/proposals/pp-000021"]: () => ((pending = []), { proposal: { ...card, status: "approved" }, changeId: "pc-000031" }),
    },
  });
}
const ENDED = "The agent that asked has ended, so nothing is waiting on this now.";

test("a rule change whose session has ended says so on its card, and Allow says it is in force without telling the agent to go on", async () => {
  const { doc } = askedFrom("idle");
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal");
  const sub = lineWords(card.querySelector(".ask-sub"));
  assert.ok(sub.endsWith("· from Claude Code in ~/shop. " + ENDED), sub);
  assert.equal(card.querySelector(".ask-sub .ask-ended").textContent.trim(), ENDED, "drawn as a question's ended sentence");
  assert.ok(!sub.includes("Your answer counts"), "a rule change asks nothing again");
  proposalButton(doc, "pp-000021", "Allow").click();
  await tick(30);
  const line = doc.querySelector("#approvals-proposals .answer-line");
  assert.equal(lineWords(line), "Allowed: Claude Code's rule change: ~/shop/.env may be sent to api.stripe.com. It is in force now. Undo it");
  assert.equal(line.querySelector("a").getAttribute("href"), "/mandu/approvals/pc-000031", "Undo is unchanged");
});

test("a rule change from a running session keeps its card and its 'Tell … it may go on'; a session Home does not list says neither", async () => {
  for (const [state, agent] of [["running", "Claude Code"], [null, "Your agent"]] as const) {
    const { doc } = askedFrom(state);
    await tick();
    const card = doc.querySelector("#approvals-proposals .proposal");
    assert.equal(card.querySelector(".ask-ended"), null, `${state}: no ended sentence`);
    assert.ok(!lineWords(card).includes("has ended"), `${state}`);
    proposalButton(doc, "pp-000021", "Allow").click();
    await tick(30);
    const tell = agent === "Your agent" ? "your agent" : agent;
    assert.equal(lineWords(doc.querySelector("#approvals-proposals .answer-line")),
      `Allowed: ${agent}'s rule change: ~/shop/.env may be sent to api.stripe.com. It is in force now. Tell ${tell} it may go on. Undo it`, `${state}`);
  }
});

test("a session that ends while its rule change is drawn: the next poll adds the ended sentence to the card", async () => {
  const page = askedFrom("running");
  await tick();
  assert.equal(page.doc.querySelector("#approvals-proposals .proposal .ask-ended"), null);
  const vm: any = home({ agents: [...(home().agents as any[]), { ...(home().agents as any[])[0], id: "s7", cwd: "/home/u/shop", state: "idle", waiting: 0 }] });
  page.setHome(vm);
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(30);
  assert.equal(page.doc.querySelector("#approvals-proposals .proposal .ask-ended").textContent.trim(), ENDED);
});

test("a re-filed answer shows its notice and no line; a 409 keeps the card with its words and no line", async () => {
  const refiled = { ...ASKED, id: "pp-000007" };
  const routes: Record<string, unknown> = {
    [PENDING]: { proposals: [ASKED] },
    "POST policy/proposals/pp-000004": { proposal: { ...ASKED, status: "superseded" }, refiled },
  };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes });
  await tick();
  routes[PENDING] = { proposals: [refiled] };
  proposalButton(doc, "pp-000004", "Allow").click();
  await tick(30);
  assert.match(doc.getElementById("approvals-proposals").textContent, /here is the updated request\./);
  assert.equal(doc.querySelector("#approvals-proposals .answer-line"), null);

  const bad = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { [PENDING]: { proposals: [ASKED] }, "POST policy/proposals/pp-000004": { status: 409, body: { error: "policy proposal pp-000004 is already denied" } } } });
  await tick();
  proposalButton(bad.doc, "pp-000004", "Allow").click();
  await tick(30);
  assert.match(bad.doc.querySelector("#approvals-proposals .proposal .ask-error").textContent, /already denied/);
  assert.equal(bad.doc.querySelector("#approvals-proposals .answer-line"), null);
});

test("a poll keeps the rule change's line; leaving the page drops it and the empty block hides again", async () => {
  const { doc, window } = proposalsAnswered([ASKED], "pp-000004", { proposal: { ...ASKED, status: "approved" }, changeId: "pc-000012" });
  await tick();
  proposalButton(doc, "pp-000004", "Allow").click();
  await tick(30);
  const line = doc.querySelector("#approvals-proposals .answer-line");
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(doc.querySelector("#approvals-proposals .answer-line"), line, "kept by the poll");
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false);
  doc.querySelector("#nav [data-page-link=rules]").click();
  await tick(30);
  doc.querySelector("#nav [data-page-link=approvals]").click();
  await tick(30);
  assert.equal(doc.querySelector("#approvals-proposals .answer-line"), null, "left with the page");
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true, "no empty block");
});
