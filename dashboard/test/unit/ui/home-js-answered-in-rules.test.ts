/**
 * home-js-answered-in-rules.test — a remembered answer under Approvals ›
 * Answered earlier opens where Rules keeps it (dashboard.md §4.25 *A
 * remembered answer opens where Rules keeps it*, §4.25h). An Always allowed
 * or Blocked row ends its when line with "Kept in Rules"; Allowed once, Send
 * without it and an answer that no longer applies, which Rules does not
 * keep or offers no change for, do not. The click opens Rules with that
 * answer's row open, as its ⋯ opens it (Remove), the focus on its ⋯; a Find
 * a rule text that would hide it is emptied; an answer forgotten meanwhile
 * says so; a modifier click is the browser's, at `/rules#answer-<id>`, and
 * that address opens the row too.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { RULES_PANEL, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const DAY = 86_400_000;
const S = (text: string) => [{ kind: "text", text }];
/** Answered earlier as /api/home carries it: egr-7 and egr-6 are the
 *  standing answers RULES_PANEL lists under Your rules. */
const ANSWERED = [
  { id: "egr-7", sentence: S("Claude Code wants to send a file to paste.example"), outcome: "allowed", decidedAt: Date.now() - 2 * DAY, sessions: ["s8", "s9"], actions: [{ approve: false, label: "Block instead" }] },
  { id: "egr-6", sentence: S("Claude Code wants to send to old.example"), outcome: "blocked", decidedAt: null, sessions: [], actions: [{ approve: true, label: "Allow instead" }] },
  { id: "once-1", sentence: S("A send allowed once"), outcome: "allowed-once-used", decidedAt: Date.now() - DAY, sessions: ["s1"], actions: [] },
  { id: "strip-1", sentence: S("A send without it"), outcome: "without", decidedAt: Date.now() - DAY, sessions: ["s1"], actions: [] },
  { id: "stale-1", sentence: S("An old program answer"), outcome: "allowed", decidedAt: Date.now() - DAY, sessions: [], actions: [], staleNote: "This answer no longer applies." },
];
const NOTE = "That answer is no longer kept: you will be asked next time.";

function approvals(routes: Record<string, unknown> = {}, url = APPROVALS_URL) {
  return load({ url, homeVm: home({ waiting: [], answered: ANSWERED }), routes: { "GET policy/panel": RULES_PANEL, ...routes } });
}
const answeredRow = (doc: any, id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"]`);
const keptLink = (doc: any, id: string) => answeredRow(doc, id).querySelector("a.kept-link");
const ruleRow = (doc: any, key: string) => ([...doc.querySelectorAll("#rules-list .row[data-rule]")] as any[]).find((r) => r.getAttribute("data-rule") === key);

test("an Always allowed and a Blocked row end their when line with Kept in Rules; Allowed once, Send without it and No longer applies do not", async () => {
  const { doc } = approvals();
  await tick();
  const allowed = answeredRow(doc, "egr-7").querySelector(".answered-when");
  assert.match(allowed.textContent, /See what the agent was doing \(asked in 2 sessions, this shows the latest\)\. Kept in Rules$/);
  assert.equal(keptLink(doc, "egr-7").getAttribute("href"), "/mandu/rules#answer-egr-7");
  // No time and no session recorded: the line is the link alone.
  assert.equal(answeredRow(doc, "egr-6").querySelector(".answered-when").textContent, "Kept in Rules");
  assert.equal(keptLink(doc, "egr-6").getAttribute("href"), "/mandu/rules#answer-egr-6");
  for (const id of ["once-1", "strip-1", "stale-1"]) assert.equal(keptLink(doc, id), null, id + ": Rules does not keep it");
  assert.doesNotMatch(answeredRow(doc, "once-1").textContent, /Kept in Rules/);
});

test("Kept in Rules opens Rules with the answer's row open, Remove in it, the focus on its ⋯", async () => {
  const { doc, window } = approvals();
  await tick();
  const scrolled: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id || this.getAttribute("data-rule") || this.className); };
  keptLink(doc, "egr-7").click();
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/rules");
  assert.equal(doc.getElementById("page-rules").hidden, false);
  const row = ruleRow(doc, "answer:egr-7");
  assert.ok(row, "the answer's row is drawn");
  assert.ok(row.classList.contains("open"), "open, as its ⋯ opens it");
  const detail = row.nextElementSibling;
  assert.ok(detail.classList.contains("rule-detail"));
  const remove = detail.querySelector(".rule-remove");
  assert.equal(remove.textContent, "Remove");
  assert.match(remove.getAttribute("aria-label"), /^Remove your answer about /);
  assert.equal(doc.querySelectorAll("#rules-list .rule-detail").length, 1, "only that row is open");
  assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus is on the row's ⋯");
  assert.ok(scrolled.includes("rules-block") && scrolled.includes("answer:egr-7"), JSON.stringify(scrolled));
  assert.equal(doc.getElementById("rules-answer-note").hidden, true, "no note");
});

test("a Find a rule text that would hide the row is emptied", async () => {
  const { doc } = approvals();
  await tick();
  keptLink(doc, "egr-6").click();
  // Typed before Rules' reads drew (no key reaches the window: an input
  // event alone), so the row would be hidden.
  const box = doc.getElementById("rules-find");
  box.value = "api.example";
  box.dispatchEvent(new doc.defaultView.Event("input"));
  await tick(30);
  assert.equal(box.value, "", "the box is empty");
  const row = ruleRow(doc, "answer:egr-6");
  assert.ok(row && row.classList.contains("open"), "the row is drawn, open");
  assert.equal(doc.activeElement, row.querySelector(".file-more"));
});

test("an answer Rules no longer keeps opens Your rules with a note, the focus on its heading; a page change drops the note", async () => {
  const panel = { panel: { ...RULES_PANEL.panel, queue: RULES_PANEL.panel.queue.filter((v) => v.id !== "egr-7") } };
  const { doc } = approvals({ "GET policy/panel": panel });
  await tick();
  keptLink(doc, "egr-7").click();
  await tick(30);
  const note = doc.getElementById("rules-answer-note");
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, NOTE);
  assert.equal(ruleRow(doc, "answer:egr-7"), undefined);
  assert.equal(doc.querySelectorAll("#rules-list .rule-detail").length, 0, "nothing opened");
  assert.equal(doc.activeElement, doc.querySelector("#rules-block h2"));
  doc.querySelector('#nav [data-page-link="approvals"]').click();
  await tick();
  assert.equal(note.hidden, true);
});

test("with the answers unread, Kept in Rules opens Your rules without claiming the answer is gone", async () => {
  const { doc } = approvals({ "GET policy/panel": { panel: { ...RULES_PANEL.panel, verdictsKnown: false, queue: [] } } });
  await tick();
  keptLink(doc, "egr-7").click();
  await tick(30);
  assert.equal(doc.getElementById("rules-answer-note").hidden, true);
  assert.equal(doc.activeElement, doc.querySelector("#rules-block h2"));
});

test("a modifier click is the browser's; the address it opens lands on the row", async () => {
  const { doc, window } = approvals();
  await tick();
  let prevented: boolean | null = null;
  const spy = (e: any) => { prevented = e.defaultPrevented; e.preventDefault(); };
  doc.addEventListener("click", spy);
  keptLink(doc, "egr-7").dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true }));
  doc.removeEventListener("click", spy);
  assert.equal(prevented, false, "not handled by the page");
  await tick();
  assert.equal(window.location.pathname, "/mandu/approvals");

  // The new tab: the address names the row.
  const tab = load({ url: "http://127.0.0.1:4500/mandu/rules#answer-egr-7", routes: { "GET policy/panel": RULES_PANEL } });
  await tick(30);
  const row = ruleRow(tab.doc, "answer:egr-7");
  assert.ok(row && row.classList.contains("open"), "the row is open");
  assert.ok(row.nextElementSibling.querySelector(".rule-remove"));
  assert.equal(tab.doc.activeElement, row.querySelector(".file-more"));
  assert.equal(tab.window.location.hash, "", "used once: the address is the page's own");
});
