/**
 * home-js-question-names.test — a question has a name (dashboard.md §4.25
 * *A question has a name*). Mandu-new test.
 *
 * The cards of a page offer the same answer buttons beside their words:
 * three questions on Home or Approvals are three "Allow once", "Always
 * allow", "Block". Until 2026-10-11 a card was a bare <div>, so a screen
 * reader that Tabbed to a button read "Allow once, button" with no word of
 * what it allows, and the card an answer gave the focus to (§4.25 *An answer
 * keeps the focus in its list*) had no name either. Now each card or row
 * that asks for an answer, or records one, is a group named by its own
 * words (`role="group"`, `aria-labelledby`):
 *
 *   - Home's and Approvals' waiting cards and the agent page's Needs your OK
 *     (the question's sentence);
 *   - Answered earlier (*Block instead*), a rule change your agent asked for
 *     (Allow / Not now), Rule changes (Undo), the possible-keys card, and the
 *     rows of the note under your message (*Let it through*);
 *   - the name is the words alone, never the buttons, the moment or a link;
 *   - the ids are numbered as drawn: unique while Home and Approvals draw
 *     the same question, kept by a poll that draws nothing new, and no key
 *     of the poll's focus place (DRAWN_ID);
 *   - a refused answer's words describe its button, and the card keeps its
 *     name.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, tick, FILES_ROUTES } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const T = (text: string) => ({ kind: "text", text });
const ASK2 = { ...ASK, id: "egr-2", sentence: [T("Codex CLI wants to send your secret "), { kind: "code", text: "GITHUB_TOKEN" }, T(" to "), { kind: "code", text: "gist.example" }] };
const ASK3 = { ...ASK, id: "egr-3", sentence: [T("Claude Code wants to run "), { kind: "code", text: "curl paste.example" }] };
const ASK_NAME = "Claude Code wants to send text from a file to <img src=x onerror=alert(1)>";
const ADMIN_403 = { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } };

const squash = (s: string) => s.replace(/\s+/g, " ").trim();
/** The accessible name `aria-labelledby` gives `x`: the text of each
 *  element it names, as a browser computes it for plain text. */
function nameOf(x: El): string {
  const ids = String(x.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean);
  return squash(ids.map((id) => x.ownerDocument.getElementById(id)?.textContent ?? `<no element ${id}>`).join(" "));
}
const cardsOf = (doc: El, list: string): El[] => [...doc.getElementById(list).children].filter((c: El) => c.dataset.id !== undefined);
const cardOf = (doc: El, list: string, id: string): El => cardsOf(doc, list).find((c) => c.dataset.id === id);
const button = (root: El, label: string): El => [...root.querySelectorAll("button")].find((b: El) => b.textContent === label);
/** A group named by words inside it; `name` is what a screen reader reads. */
function assertNamed(card: El, name: string, what: string): void {
  assert.ok(card, `${what}: drawn`);
  assert.equal(card.getAttribute("role"), "group", `${what}: a group`);
  assert.equal(nameOf(card), name, `${what}: named by its own words`);
  const words = card.ownerDocument.getElementById(card.getAttribute("aria-labelledby"));
  assert.ok(card.contains(words), `${what}: the words are its own`);
  assert.equal(words.querySelector("button, a"), null, `${what}: the name holds no control`);
}
function assertUniqueIds(doc: El): void {
  const ids = [...doc.querySelectorAll("[id]")].map((x: El) => x.id);
  assert.deepEqual(ids.filter((id, i) => ids.indexOf(id) !== i), [], "no id is drawn twice");
}
/** Enter on a button: the click answers, and the browser drops the focus
 *  of the button the answer turned off to <body>, as Chromium does (jsdom
 *  keeps it; home-js-answer-focus.test.ts). */
function press(btn: El): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the answer turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}

test("Home and Approvals: each waiting card is a group named by its question, never its buttons, and no id repeats though both draw it", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2] }) });
  await tick();
  for (const list of ["home-waiting", "approvals-waiting"]) {
    assert.deepEqual(cardsOf(doc, list).map((c) => c.dataset.id), ["egr-1", "egr-2"], `${list}: both questions`);
    assertNamed(cardOf(doc, list, "egr-1"), ASK_NAME, `${list} egr-1`);
    assertNamed(cardOf(doc, list, "egr-2"), "Codex CLI wants to send your secret GITHUB_TOKEN to gist.example", `${list} egr-2`);
    for (const c of cardsOf(doc, list)) {
      for (const label of ["Allow once", "Always allow", "Block"]) assert.ok(c.contains(button(c, label)), `${list}: ${label} is in its question's group`);
    }
  }
  // Home's short card: the name is the question, not its why, moment or Details link.
  const short = cardOf(doc, "home-waiting", "egr-1");
  assert.match(short.textContent, /Details in Approvals/);
  assert.doesNotMatch(nameOf(short), /Details|masked|ago/);
  // Server text stays text in the name too.
  assert.equal(doc.querySelector("img"), null);
  assertUniqueIds(doc);
});

test("Answered earlier, a rule change your agent asked for, Rule changes and the possible-keys card are named by their own words", async () => {
  const answered = { id: "egr-9", sentence: [T("Claude Code wanted to send a file to "), { kind: "code", text: "drop.example" }], outcome: "allowed", decidedAt: Date.now() - 30_000, actions: [{ approve: false }], sessions: ["s1"] };
  const proposal = { id: "pp-000001", status: "pending", requester: "Your agent", headline: "Your agent wants to trust content from pypi.org", createdAt: Date.now() - 60_000, rows: [[T("Trust content from pypi.org")]], wouldLet: [], capped: false, overBroad: false, reason: "" };
  const change = { id: "pc-000001", sentence: "Your agent tightened your rules", rows: [[T("Hide ~/x.pem from the AI")]], createdAt: Date.now(), undone: false, undoable: true };
  const key: SuggestionWire = {
    id: "pp-000004", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-4", source: "git-history", repoRoot: "/home/u/proj",
    edits: [{ op: "lock-path", path: "/home/u/proj/deploy/id_rsa", level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
    evidence: { paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: true, findings: [] },
    impact: { historicalVersions: 1, workingTreeChanges: false, files: [] },
    historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  };
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [ASK], answered: [answered] }), routes: {
    ...FILES_ROUTES,
    "GET policy/proposals?status=pending": { proposals: [proposal] },
    "GET policy/changes?limit=21": { changes: [change] },
    "GET suggestions": { suggestions: suggestionRows([key], "/home/u", "linux"), count: 1, scan: null },
  } });
  await tick(30);

  const row = cardOf(doc, "approvals-answered", "egr-9");
  assertNamed(row, "Claude Code wanted to send a file to drop.example", "Answered earlier");
  assert.ok(row.contains(button(row, "Block instead")));
  assert.match(row.textContent, /See what the agent was doing/, "the row's link is drawn, outside its name");

  const asked = cardOf(doc, "approvals-proposals", "pp-000001");
  assertNamed(asked, "Your agent wants to trust content from pypi.org", "a rule change your agent asked for");
  assert.ok(asked.contains(button(asked, "Not now")));

  const undo = cardOf(doc, "approvals-rule-history", "pc-000001");
  assertNamed(undo, "Your agent tightened your rules", "Rule changes: the sentence, not the rows under it");
  assert.match(undo.textContent, /Hide ~\/x\.pem/);
  assert.ok(undo.contains(button(undo, "Undo")));

  const keys = doc.querySelector("#approvals-suggestions .suggestion-card");
  assertNamed(keys, "Mandu found 1 possible key in this project's git history", "the possible-keys card");
  assert.ok(keys.contains(button(keys, "Review them")));
  assertUniqueIds(doc);
});

test("the agent page: Needs your OK and each row of the note under your message are named", async () => {
  const note = { lines: ["One value in your prompt was hidden from the AI (an email address)."], items: [
    { eventId: "ev-1", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: true, canLetSession: true, canShow: false },
    { eventId: "ev-1", index: 1, category: "pii.phone", words: "", state: "hidden", canLetOnce: true, canLetSession: false, canShow: false },
  ], ts: "2026-09-25T10:00:00.000Z" };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": { ...AGENT, waiting: [ASK3], story: [{ ...AGENT.story[0], promptNote: note }, { ...AGENT.story[1], promptNote: null }] },
  } });
  await tick(30);
  assertNamed(cardOf(doc, "agent-waiting", "egr-3"), "Claude Code wants to run curl paste.example", "Needs your OK");
  const rows = [...doc.querySelectorAll("#agent-story .prompt-note-item")] as El[];
  assert.equal(rows.length, 2);
  assertNamed(rows[0], "An email address", "a note row, in words");
  assert.ok(rows[0].contains(button(rows[0], "Let it through in this message")));
  assertNamed(rows[1], "pii.phone", "a note row the server sent without words: its category");
  assertUniqueIds(doc);
});

test("a poll: a list that did not change keeps its names; a list drawn again is named again, and the focused answer keeps the focus", async () => {
  const page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2] }) });
  const { doc } = page;
  await tick();
  const card = cardOf(doc, "approvals-waiting", "egr-2");
  const label = card.getAttribute("aria-labelledby");
  button(card, "Block").focus();
  await poll(doc);
  assert.equal(cardOf(doc, "approvals-waiting", "egr-2"), card, "the same questions: the card stays");
  assert.equal(card.getAttribute("aria-labelledby"), label, "and its name");
  // A new question above it: the list is drawn again from nothing.
  page.setHome(home({ waiting: [ASK3, ASK, ASK2] }));
  await poll(doc);
  const now = cardOf(doc, "approvals-waiting", "egr-2");
  assert.notEqual(now, card, "drawn again");
  assertNamed(now, "Codex CLI wants to send your secret GITHUB_TOKEN to gist.example", "egr-2 drawn again");
  assertNamed(cardOf(doc, "approvals-waiting", "egr-3"), "Claude Code wants to run curl paste.example", "the new question");
  assert.equal(doc.activeElement, button(now, "Block"), "the poll keeps the focus on the same answer (its numbered name is no key)");
  assertUniqueIds(doc);
});

test("a refused answer: its words describe the button pressed, and its card keeps the question's name", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2] }), routes: { "POST egress/approvals/egr-2/approve-once": ADMIN_403 } });
  await tick();
  const card = cardOf(doc, "approvals-waiting", "egr-2");
  press(button(card, "Allow once"));
  await tick(30);
  const again = button(cardOf(doc, "approvals-waiting", "egr-2"), "Allow once");
  assert.equal(again.disabled, false);
  assert.equal(doc.activeElement, again, "the button pressed has the focus back");
  assert.match(squash(doc.getElementById(again.getAttribute("aria-describedby")).textContent), /^Sign in first: /);
  assertNamed(cardOf(doc, "approvals-waiting", "egr-2"), "Codex CLI wants to send your secret GITHUB_TOKEN to gist.example", "the refused card");
  assertUniqueIds(doc);
});
