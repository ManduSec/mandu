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
 *   - Cancel and Discard: Suggest rules;
 *   - Try it: the button has it back, described by its answer;
 *   - Apply: applied, the line that says so; refused, Apply, described by
 *     the refusal;
 *   - only a focus the press left: one the person moved stays, and a press
 *     made without the focus moves nothing.
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
  assert.equal(byId(doc, "describe-result").hidden, true);
  assert.equal(doc.activeElement, byId(doc, "describe-submit"), "Discard gone: Suggest rules");
});
