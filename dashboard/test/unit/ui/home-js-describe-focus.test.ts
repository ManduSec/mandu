/**
 * home-js-describe-focus.test — Rules › Describe what you want keeps the
 * keyboard focus through its requests (public/js/home.js `describeWaits`,
 * `describeAnswered`, `tryRow`, `applySuggestion`; dashboard.md §4.25
 * *Describe what you want keeps the focus*).
 *
 * Suggest rules, Try it and Apply go off while they ask the server, Cancel
 * hides, and Describe it again and Discard go with their card: a browser
 * drops the focus of each to the page (<body>). Until 2026-10-14 a headless
 * Chromium left it there after every one of them, and for the whole time
 * the helper worked (up to a minute). Now:
 *
 *   - Suggest rules and Describe it again: the focus waits on the card's
 *     heading while the helper works; suggestions shown, their first line
 *     takes it; refused or nothing came back, Suggest rules, on again,
 *     described by what came back; cancelled, Suggest rules;
 *   - Cancel: Suggest rules; Discard: the Undo of the line it leaves, and
 *     that Undo: the first line of the suggestion drawn again;
 *   - Try it: the button has it back, described by its answer;
 *   - Apply: applied, the line that says so; refused, Apply, described by
 *     the refusal;
 *   - only a focus the press left: one the person moved stays, and a press
 *     made without the focus moves nothing.
 *
 * The line of an Apply (§4.25 *Every change made on Rules ends with an Undo
 * or a link*, 2026-10-25): with a `pc-…` change id, Undo (off until Your
 * rules is read again) and See it in Approvals at that change; Undo posts
 * the change's undo, then the line says "Undone." or the refusal; no id
 * keeps the sentence of before. ALLOW typed while Apply is out leaves Apply
 * off.
 *
 * jsdom keeps the focus of a button turned off or hidden; `press` drops it,
 * as Chromium does, only while the button still has it (a focus the page
 * moved first stays where it was put), as in home-js-suggested-focus.test.ts.
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/describe-focus.test.ts. Axes: none (display only). Mandu-new
 * test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const SUGGESTION = {
  model: "claude-haiku-4-5",
  note: "I did not add GitHub.",
  rows: [
    { parts: [{ kind: "text", text: "Lock " }, { kind: "code", text: "~/.ssh" }], loosens: false, overBroad: false },
    { parts: [{ kind: "text", text: "Let data go to " }, { kind: "code", text: "pypi.org" }], loosens: true, overBroad: false, tryable: true },
  ],
  loosens: [{ line: [{ kind: "text", text: "Your data to " }, { kind: "code", text: "pypi.org" }] }],
  edits: [{ op: "lock-path", path: "~/.ssh", level: "no-model" }, { op: "allow-connect", host: "pypi.org" }],
  expected: ["release\u0000pypi.org"],
};
const TRIED = {
  now: [{ kind: "text", text: "Your data to " }, { kind: "code", text: "pypi.org" }, { kind: "text", text: " needs your OK" }],
  after: [{ kind: "text", text: "Your data to " }, { kind: "code", text: "pypi.org" }, { kind: "text", text: " is sent" }],
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const byId = (doc: Doc, id: string) => doc.getElementById(id);
const heading = (doc: Doc) => doc.querySelector("#describe-block h2");
const firstLine = (doc: Doc) => doc.querySelector("#describe-result .suggestion .proposal-k");
const button = (doc: Doc, words: string) => [...doc.querySelectorAll("#describe-result button")].find((b: Doc) => b.textContent === words);
const describedBy = (doc: Doc, b: Doc): string | null => {
  const id = b.getAttribute("aria-describedby");
  return id ? doc.getElementById(id)?.textContent ?? `(no #${id})` : null;
};

/** Enter on a button that goes off (or goes) while it acts. Chromium drops
 *  its focus to the page, but only while the button still has it. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  if (btn.ownerDocument.activeElement !== btn) return;
  if (btn.isConnected && !btn.disabled && !btn.hidden) return;
  const off = btn.disabled;
  btn.disabled = false;
  btn.blur();
  btn.disabled = off;
}
/** Enter (or Space) on a control that keeps working: it has the focus. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}
/** A held answer: the route waits until the test answers it. */
function held() {
  let answer: (v: unknown) => void = () => {};
  const route = () => new Promise((r) => { answer = r; });
  return { route, answer: (v: unknown) => answer(v) };
}
/** Write the sentence, and Enter on Suggest rules. */
function suggest(doc: Doc, sentence = "Keep ~/.ssh secret. We use PyPI."): void {
  byId(doc, "describe-text").value = sentence;
  press(byId(doc, "describe-submit"));
}
async function opened(routes: Record<string, unknown>, before?: (window: Doc) => void) {
  const page = load({ url: RULES_URL, routes, before });
  await tick();
  assert.equal(page.doc.getElementById("page-rules").hidden, false);
  return page;
}

test("Suggest rules: the focus waits on the card's heading while the helper works, and the suggestion opens on its first line", async () => {
  const h = held();
  const { doc } = await opened({ "POST policy/assistant": h.route });
  const submit = byId(doc, "describe-submit");
  suggest(doc);
  assert.equal(submit.disabled, true, "off while the helper works");
  assert.equal(doc.activeElement, heading(doc), "the card's heading, never <body>");
  assert.equal(heading(doc).textContent, "Describe what you want");
  assert.equal(heading(doc).getAttribute("tabindex"), "-1", "a heading is no Tab stop");
  assert.match(byId(doc, "describe-status").textContent, /^Working out the rules/);
  await tick();
  assert.equal(doc.activeElement, heading(doc), "still waiting");
  h.answer(SUGGESTION);
  await tick();
  assert.equal(submit.disabled, false);
  assert.equal(doc.activeElement, firstLine(doc), "the suggestion's first line");
  assert.equal(firstLine(doc).textContent, "Suggested rules");
  assert.equal(firstLine(doc).getAttribute("tabindex"), "-1", "no Tab stop");
  assert.equal(submit.getAttribute("aria-describedby"), null, "nothing was refused");
});

test("refused, or nothing came back: Suggest rules, on again, has the focus, described by what came back; suggestions later drop the description", async () => {
  for (const [answer, words] of [
    [{ status: 503, body: { error: "Mandu's helper uses Claude Code or Codex on this computer, or an Anthropic API key, and found neither. Sign in to Claude Code (claude), then press Suggest rules again.", unconfigured: true, reason: "no-channel" } }, /^Mandu's helper uses Claude Code or Codex .* and found neither\. Sign in to Claude Code \(claude\), then press Suggest rules again\.$/],
    [{ status: 422, body: { error: "The suggestion was not a valid rule change.", problems: ["edits[0]: path: must be a non-empty string"] } }, /not a valid rule change.*must be a non-empty string.*Try saying it another way\.$/],
    [{ ...SUGGESTION, rows: [] }, /^No rule changes came back\. Try saying it another way\.$/],
  ] as const) {
    let n = 0;
    const { doc } = await opened({ "POST policy/assistant": () => (n++ === 0 ? answer : SUGGESTION) });
    const submit = byId(doc, "describe-submit");
    suggest(doc);
    await tick();
    assert.equal(submit.disabled, false);
    assert.equal(doc.activeElement, submit, "Suggest rules, on again");
    assert.match((describedBy(doc, submit) ?? "").replace(/\s+/g, " ").trim(), words, "described by what came back");
    suggest(doc);
    await tick();
    assert.equal(doc.activeElement, firstLine(doc));
    assert.equal(submit.getAttribute("aria-describedby"), null, "suggestions drop the description");
  }
});

test("Cancel: pressed with the focus, Suggest rules takes it; pressed while the focus waits on the heading, too", async () => {
  // The page's own fetch stub never cancels: this one does, as a browser's.
  const cancellable = (window: Doc) => {
    const answer = window.fetch;
    window.fetch = (url: string, init: Doc = {}) => url.endsWith("/api/policy/assistant")
      ? new Promise((_r, no) => init.signal.addEventListener("abort", () => no(new window.DOMException("The operation was aborted.", "AbortError"))))
      : answer(url, init);
  };
  for (const withFocus of [true, false]) {
    const { doc } = await opened({}, cancellable);
    const submit = byId(doc, "describe-submit");
    const cancel = byId(doc, "describe-cancel");
    suggest(doc);
    await tick();
    assert.equal(cancel.hidden, false);
    assert.equal(doc.activeElement, heading(doc));
    if (withFocus) enter(cancel);
    else cancel.click();
    await tick();
    assert.equal(cancel.hidden, true);
    assert.equal(byId(doc, "describe-status").textContent, "Cancelled.");
    assert.equal(doc.activeElement, submit, withFocus ? "Cancel gone: Suggest rules" : "from the heading: Suggest rules");
    assert.equal(submit.getAttribute("aria-describedby"), null);
  }
});

test("Cancel with the focus when the answer comes first: Suggest rules takes it; a focus moved elsewhere meanwhile stays, also once back on the heading", async () => {
  const h = held();
  const { doc } = await opened({ "POST policy/assistant": h.route });
  const submit = byId(doc, "describe-submit");
  const cancel = byId(doc, "describe-cancel");
  suggest(doc);
  cancel.focus();
  h.answer(SUGGESTION);
  await tick();
  assert.equal(cancel.hidden, true);
  assert.equal(doc.activeElement, submit, "Cancel gone: Suggest rules, never <body>");

  // The person moves the focus to the box while the helper works.
  const h2 = held();
  const again = await opened({ "POST policy/assistant": h2.route });
  suggest(again.doc);
  const box = byId(again.doc, "describe-text");
  box.focus();
  assert.equal(again.doc.activeElement, box);
  h2.answer(SUGGESTION);
  await tick();
  assert.ok(firstLine(again.doc), "the suggestion is drawn");
  assert.equal(again.doc.activeElement, box, "the person's focus stays");

  // A move off the heading ends the wait, also once the focus is back on
  // the heading (as a scan's does).
  const h3 = held();
  const back = await opened({ "POST policy/assistant": h3.route });
  suggest(back.doc);
  byId(back.doc, "describe-text").focus();
  heading(back.doc).focus();
  h3.answer(SUGGESTION);
  await tick();
  assert.ok(firstLine(back.doc), "the suggestion is drawn");
  assert.equal(back.doc.activeElement, heading(back.doc), "the wait ended with the move: the answer takes nothing");
});

test("a press made without the focus moves nothing", async () => {
  const h = held();
  const { doc } = await opened({ "POST policy/assistant": h.route });
  byId(doc, "describe-text").value = "Keep ~/.ssh secret.";
  byId(doc, "describe-submit").click();
  assert.equal(doc.activeElement, doc.body, "the heading never took it");
  h.answer(SUGGESTION);
  await tick();
  assert.equal(doc.activeElement, doc.body, "nor the suggestion");
});

test("Try it: the button has the focus back, described by its answer; refused, by the refusal", async () => {
  let n = 0;
  const { doc } = await opened({
    "POST policy/assistant": SUGGESTION,
    "POST policy/assistant/try": () => (n++ === 0 ? TRIED : { status: 503, body: { error: "unreachable", unreachable: true } }),
  });
  suggest(doc);
  await tick();
  const btn = doc.querySelector("#describe-result .try-row");
  press(btn);
  assert.equal(doc.activeElement, doc.body, "off while it asks: the focus fell");
  await tick();
  assert.equal(doc.activeElement, btn, "Try it, on again");
  assert.equal(btn.disabled, false);
  assert.equal(describedBy(doc, btn), "Now: Your data to pypi.org needs your OKAfter: Your data to pypi.org is sent");
  press(btn);
  await tick();
  assert.equal(doc.activeElement, btn);
  assert.equal(doc.querySelectorAll("#describe-result .try-result").length, 1, "one answer");
  assert.match(describedBy(doc, btn) ?? "", /^The protection service is not running/, "described by the refusal");
});

test("Apply: applied, the line that says so takes the focus", async () => {
  const { doc } = await opened({ "POST policy/assistant": SUGGESTION, "POST policy/assistant/apply": { applied: true, changeId: "pc-000003" } });
  suggest(doc);
  await tick();
  press(button(doc, "Apply"));
  await tick(20);
  const done = doc.querySelector("#describe-result .describe-done");
  assert.match(done.textContent, /^Applied\./);
  assert.equal(doc.activeElement, done, "the line, never <body>");
  assert.equal(done.getAttribute("tabindex"), "-1");
});

test("Apply refused (409): Apply has the focus back, described by the refusal; Describe it again waits on the heading, then opens the new suggestion", async () => {
  const h = held();
  let n = 0;
  const { doc } = await opened({
    "POST policy/assistant": () => (n++ === 0 ? SUGGESTION : h.route()),
    "POST policy/assistant/apply": { status: 409, body: { error: "the rules changed since the preview; applying would now loosen more than shown" } },
  });
  suggest(doc);
  await tick();
  const apply = button(doc, "Apply");
  press(apply);
  await tick();
  assert.equal(doc.activeElement, apply, "Apply, on again");
  assert.match(describedBy(doc, apply) ?? "", /rules changed since the preview/);
  const again = button(doc, "Describe it again");
  press(again);
  assert.equal(again.isConnected, false, "its card is gone");
  assert.equal(doc.activeElement, heading(doc), "the heading, never <body>");
  h.answer(SUGGESTION);
  await tick();
  assert.equal(doc.activeElement, firstLine(doc), "the new suggestion's first line");
});

test("Apply with a focus moved meanwhile, and Discard", async () => {
  let answer: (v: unknown) => void = () => {};
  const { doc } = await opened({
    "POST policy/assistant": SUGGESTION,
    "POST policy/assistant/apply": () => new Promise((r) => { answer = r; }),
  });
  suggest(doc);
  await tick();
  press(button(doc, "Apply"));
  const box = byId(doc, "describe-text");
  box.focus();
  answer({ applied: true, changeId: "pc-000004" });
  await tick(20);
  assert.ok(doc.querySelector("#describe-result .describe-done"));
  assert.equal(doc.activeElement, box, "the person's focus stays");

  suggest(doc);
  await tick();
  press(button(doc, "Discard"));
  // Until 2026-10-28 Discard hid the card and gave the focus to Suggest
  // rules; now its line with Undo takes the card place (§4.25n *Describe
  // can undo its Discard*).
  assert.equal(byId(doc, "describe-result").hidden, false);
  assert.equal(doc.activeElement, button(doc, "Undo"), "Discard gone: the Undo of its line");
});

test("Discard: Undo has the focus; Undo: the suggestion's first line, Suggested rules; a press without the focus moves nothing", async () => {
  const { doc } = await opened({ "POST policy/assistant": SUGGESTION });
  suggest(doc);
  await tick();
  press(button(doc, "Discard"));
  const undo = button(doc, "Undo");
  assert.equal(doc.activeElement, undo, "the line's Undo, never <body>");
  assert.equal(undo.getAttribute("aria-label"), "Undo the discard in Describe what you want");
  assert.equal(describedBy(doc, undo), "Suggestion discarded.");
  press(undo);
  assert.equal(undo.isConnected, false, "the line is gone");
  assert.equal(doc.activeElement, firstLine(doc), "the suggestion opens on its first line");
  assert.equal(firstLine(doc).textContent, "Suggested rules");

  const box = byId(doc, "describe-text");
  box.focus();
  button(doc, "Discard").click();
  assert.equal(doc.activeElement, box, "a click made elsewhere leaves the focus");
  button(doc, "Undo").click();
  assert.equal(doc.activeElement, box, "and so does Undo");
  assert.ok(firstLine(doc), "the suggestion is back");
});

// ── The line of an Apply: Undo and a link to the change (dashboard.md §4.25
// *Every change made on Rules ends with an Undo or a link*) ─────────────────

const line = (doc: Doc) => doc.querySelector("#describe-result .describe-done");
const undoOf = (doc: Doc) => [...line(doc).querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");

test("Apply with a change id: the line says Applied, with Undo and See it in Approvals at that change; Undo is off until Your rules is read again", async () => {
  let reads = 0;
  let readHeld = false;
  let release: () => void = () => {};
  const { doc, window } = await opened({
    "POST policy/assistant": SUGGESTION,
    "POST policy/assistant/apply": { applied: true, changeId: "pc-000042" },
    "GET policy/panel": () => {
      reads++;
      if (!readHeld) return { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } };
      return new Promise((r) => { release = () => r({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } }); });
    },
  });
  suggest(doc);
  await tick();
  readHeld = true;
  const before = reads;
  press(button(doc, "Apply"));
  await tick();
  assert.equal(reads, before + 1, "Your rules is read again");
  const done = line(doc);
  assert.equal(done.querySelector("span").textContent, "Applied. Your rules are updated.");
  assert.equal(doc.activeElement, done, "the line takes the focus, as before");
  const undo = undoOf(doc);
  assert.ok(undo, "Undo on the line");
  assert.equal(undo.getAttribute("aria-label"), "Undo the change in Describe what you want");
  assert.equal(describedBy(doc, undo), "Applied. Your rules are updated.");
  assert.equal(undo.disabled, true, "off while the apply's reads are out");
  const link = done.querySelector("a.change-link");
  assert.equal(link.textContent, "See it in Approvals");
  assert.equal(link.getAttribute("href"), "/mandu/approvals/pc-000042");
  assert.equal(link.dataset.ask, "pc-000042");
  release();
  await tick(20);
  assert.equal(undo.disabled, false, "on once Your rules and Rule changes are read");

  // Following the link opens Approvals at that change.
  link.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
  assert.equal(window.location.pathname, "/mandu/approvals/pc-000042");
});

test("Undo on the line posts the change's undo, then the line says Undone. and has the focus; Your rules is read again", async () => {
  const posted: string[] = [];
  let reads = 0;
  const { doc, calls } = await opened({
    "POST policy/assistant": SUGGESTION,
    "POST policy/assistant/apply": { applied: true, changeId: "pc-000042" },
    "POST policy/changes/pc-000042/undo": () => (posted.push("undo"), { undone: true }),
    "GET policy/panel": () => (reads++, { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } }),
  });
  suggest(doc);
  await tick();
  press(button(doc, "Apply"));
  await tick(20);
  const undo = undoOf(doc);
  const before = reads;
  press(undo);
  assert.equal(undo.disabled, true, "off while it posts");
  await tick(20);
  assert.deepEqual(posted, ["undo"]);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/policy/changes/pc-000042/undo")).length, 1, "posted once");
  assert.equal(line(doc).textContent, "Undone.");
  assert.equal(line(doc).querySelector("button, a"), null, "nothing more to press");
  assert.equal(doc.activeElement, line(doc), "the line, never <body>");
  assert.equal(reads, before + 1, "Your rules is read again");
});

test("a refused Undo: the line says the refusal's words", async () => {
  const { doc } = await opened({
    "POST policy/assistant": SUGGESTION,
    "POST policy/assistant/apply": { applied: true, changeId: "pc-000042" },
    "POST policy/changes/pc-000042/undo": { status: 409, body: { error: "A later change touched these rules. Undo that one first." } },
  });
  suggest(doc);
  await tick();
  press(button(doc, "Apply"));
  await tick(20);
  press(undoOf(doc));
  await tick(20);
  assert.equal(line(doc).textContent, "A later change touched these rules. Undo that one first.");
  assert.equal(doc.activeElement, line(doc));
});

test("Apply with no change id (an older server): the sentence of before, no Undo, no link", async () => {
  for (const changeId of [null, undefined, "egr-1"]) {
    const { doc } = await opened({
      "POST policy/assistant": SUGGESTION,
      "POST policy/assistant/apply": { applied: true, changeId },
    });
    suggest(doc);
    await tick();
    press(button(doc, "Apply"));
    await tick(20);
    assert.equal(line(doc).textContent, "Applied. Your rules are updated, and you can undo this under Rule changes in Approvals.");
    assert.equal(line(doc).querySelector("button, a"), null, String(changeId));
  }
});

test("a wide change: typing in its ALLOW box while Apply is out leaves Apply off, and Enter sends nothing more", async () => {
  const WIDE = { ...SUGGESTION, rows: SUGGESTION.rows.map((r, i) => (i === 1 ? { ...r, overBroad: true } : r)) };
  const h = held();
  const { doc, window, calls } = await opened({ "POST policy/assistant": WIDE, "POST policy/assistant/apply": h.route });
  suggest(doc);
  await tick();
  const typed = doc.querySelector("#describe-result .proposal-confirm");
  const apply = button(doc, "Apply");
  typed.value = "ALLOW";
  typed.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, false, "ALLOW typed: Apply is on");
  press(apply);
  assert.equal(apply.disabled, true, "off while it posts");
  typed.value = "ALLOWX";
  typed.dispatchEvent(new window.Event("input"));
  typed.value = "ALLOW";
  typed.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, true, "typing does not turn it back on");
  typed.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  apply.click();
  const posts = () => calls.filter((c) => c.url.endsWith("/api/policy/assistant/apply")).length;
  assert.equal(posts(), 1, "one Apply sent");
  // (A held answer is always a 200 here; a refused Apply turning back on is
  // home-js-describe.test.ts's.)
  h.answer({ applied: true, changeId: "pc-000043" });
  await tick(20);
  assert.equal(posts(), 1, "still one");
  assert.equal(line(doc).querySelector("span").textContent, "Applied. Your rules are updated.");
});
