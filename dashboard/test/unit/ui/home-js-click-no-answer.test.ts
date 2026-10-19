/**
 * home-js-click-no-answer.test — a click on the PRODUCT page that gets no
 * answer says so where it was made (public/js/home.js `answerOf`;
 * dashboard.md §4.25 *A click with no answer says so*).
 *
 * Until 2026-10-10 `apiPost` threw when no answer came (the dashboard server
 * gone, the network down). Eight of its callers had no catch: a rule's
 * Remove or its effect menu, a past answer turned around or removed, the
 * Undo of the Rules, Models, Sensitivity labels and Prompt filters notices,
 * Settings › Protection's switch. Their row stayed disabled over an
 * unhandled rejection and nothing was said. The callers that caught it said
 * "could not reach the server" under a hero that says "The dashboard could
 * not reach its own server. Refresh in a moment." for the same cause. Now
 * every request answers status 0 with no answer, which refusalText says in
 * the hero's words; only Describe's own Cancel still throws, and says
 * "Cancelled.".
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real arbiter and dashboard, tests/stack/
 * product-click-no-answer.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { JS, load, tick, rulesPage, rowOf, openRule } from "./home-js-fixtures.js";

const GONE = "The dashboard could not reach its own server. Refresh in a moment.";
const noAnswer = () => { throw new TypeError("Failed to fetch"); };
const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const RULES_URL = "http://127.0.0.1:4500/mandu/rules";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const button = (node: any, label: string) => ([...node.querySelectorAll("button")] as any[]).find((b) => b.textContent === label);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const disabled = (node: any) => ([...node.querySelectorAll("button, select")] as any[]).filter((b) => b.disabled).map((b) => b.textContent || b.className);

/** Run `fn` and return the unhandled rejections it left behind. */
async function unhandledDuring(fn: () => Promise<void>): Promise<string[]> {
  const seen: string[] = [];
  const on = (e: unknown) => seen.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", on);
  try {
    await fn();
    await new Promise((r) => setTimeout(r, 20));
  } finally {
    process.off("unhandledRejection", on);
  }
  return seen;
}

test("Rules: a rule's effect menu and Remove with no answer give the row back and say so on it", async () => {
  const left = await unhandledDuring(async () => {
    const { doc } = rulesPage({ "POST policy/rules/change": noAnswer });
    await tick();
    const row = rowOf(doc, /api\.example\.com/);
    const menu = row.querySelector("select.effect-select");
    menu.value = "flip";
    menu.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
    await tick();
    assert.equal(row.querySelector(".ask-error")?.textContent, GONE);
    assert.equal(menu.disabled, false, "the menu works again");

    const more = openRule(doc, /api\.example\.com/);
    button(more, "Remove").click();
    await tick();
    assert.equal(more.querySelector(".ask-error")?.textContent, GONE, "Remove says it under the rule");
    assert.deepEqual(disabled(doc.getElementById("rules-list")), [], "no control is left disabled");
  });
  assert.deepEqual(left, [], "no unhandled rejection");
});

test("Rules: a past answer turned around (Always blocked) and its Remove with no answer say so on its row", async () => {
  const left = await unhandledDuring(async () => {
    const { doc, calls } = rulesPage({ "POST egress/approvals/egr-7/deny": noAnswer, "POST egress/approvals/egr-7/forget": noAnswer });
    await tick();
    const menu = rowOf(doc, /paste\.example/).querySelector("select.effect-select");
    menu.value = "flip";
    menu.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
    await tick();
    assert.equal(rowOf(doc, /paste\.example/).querySelector(".ask-error")?.textContent, GONE);
    assert.deepEqual(disabled(doc.getElementById("rules-list")), [], "the menu works again");
    const more = openRule(doc, /paste\.example/);
    button(more, "Remove").click();
    await tick();
    assert.equal(more.querySelector(".ask-error")?.textContent, GONE, "Remove says it under the answer");
    assert.deepEqual(disabled(doc.getElementById("rules-list")), [], "no control is left disabled");
    assert.ok(calls.some((c) => c.url.endsWith("/egress/approvals/egr-7/deny")));
    assert.ok(calls.some((c) => c.url.endsWith("/egress/approvals/egr-7/forget")));
    assert.equal(doc.getElementById("rules-notice").hidden, true, "nothing claims it changed");
  });
  assert.deepEqual(left, [], "no unhandled rejection");
});

test("Rules: Undo with no answer says so in the notice, never a disabled Undo", async () => {
  const left = await unhandledDuring(async () => {
    const { doc } = rulesPage({
      "POST policy/rules/change": { applied: true, changeId: "pc-000004" },
      "POST policy/changes/pc-000004/undo": noAnswer,
    });
    await tick();
    button(openRule(doc, /api\.example\.com/), "Remove").click();
    await tick();
    const notice = doc.getElementById("rules-notice");
    assert.match(notice.textContent, /^Rule removed\./);
    button(notice, "Undo").click();
    await tick();
    assert.equal(notice.textContent, GONE);
    assert.equal(notice.hidden, false);
  });
  assert.deepEqual(left, [], "no unhandled rejection");
});

test("Settings › Protection: the switch with no answer says so in its note and keeps what it showed", async () => {
  const left = await unhandledDuring(async () => {
    const { doc, window } = load({ url: SETTINGS_URL, routes: {
      "GET config/axes": { ok: true, effective: { integrity: false, confidentiality: true }, effectiveMode: "secrets" },
      "POST config/axes": noAnswer,
    } });
    await tick();
    const sw = doc.getElementById("switch-protection");
    assert.equal(sw.getAttribute("aria-checked"), "true");
    window.prompt = () => "OFF";
    sw.click();
    await tick();
    assert.equal(doc.getElementById("settings-protect-note").textContent, GONE);
    assert.equal(sw.getAttribute("aria-checked"), "true", "nothing changed");
  });
  assert.deepEqual(left, [], "no unhandled rejection");
});

test("Settings › Models: Undo with no answer says so in the notice", async () => {
  const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, where: "Your own model", tokenEnv: null, placement: "host", placementWords: "On this computer", allowPlainHttp: false, notEncrypted: false };
  const left = await unhandledDuring(async () => {
    const { doc } = load({ url: SETTINGS_URL, routes: {
      "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models: [OLLAMA] } },
      "POST policy/models/change": { applied: true, changeId: "pc-000009", note: "New sessions no longer use it." },
      "POST policy/changes/pc-000009/undo": noAnswer,
    } });
    await tick();
    button(doc.querySelector("#settings-models .model-row"), "Remove").click();
    await tick();
    const notice = doc.getElementById("models-notice");
    assert.match(notice.textContent, /^Removed ollama\./);
    button(notice, "Undo").click();
    await tick();
    assert.equal(notice.textContent, GONE);
  });
  assert.deepEqual(left, [], "no unhandled rejection");
});

test("Home: an answer with no answer says the hero's words on the card, never 'could not reach the server'", async () => {
  const { doc } = load({ routes: { "POST egress/approvals/egr-1/approve-once": noAnswer } });
  await tick();
  const btn = button(doc.querySelector("#home-waiting .ask"), "Allow once");
  btn.click();
  await tick();
  assert.equal(doc.querySelector("#home-waiting .ask .ask-error")?.textContent, GONE);
  assert.equal(btn.disabled, false, "the buttons work again");
});

test("Describe: no answer is said in the result; the page's own Cancel still says Cancelled.", async () => {
  const describe = (doc: any, window: any) => {
    doc.getElementById("describe-text").value = "Keep ~/.ssh secret.";
    doc.getElementById("describe-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  };
  const gone = load({ url: RULES_URL, routes: { "POST policy/assistant": noAnswer } });
  await tick();
  describe(gone.doc, gone.window);
  await tick();
  assert.equal(gone.doc.querySelector("#describe-result .ask-error")?.textContent, GONE);
  assert.equal(gone.doc.getElementById("describe-status").textContent, "");

  // A request still out when Cancel is pressed: fetch rejects on the abort.
  const out = load({ url: RULES_URL });
  await tick();
  const realFetch = out.window.fetch;
  out.window.fetch = (url: string, init: any = {}) => (url.endsWith("/api/policy/assistant")
    ? new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new out.window.DOMException("The operation was aborted.", "AbortError"))))
    : realFetch(url, init));
  describe(out.doc, out.window);
  await tick();
  out.doc.getElementById("describe-cancel").click();
  await tick();
  assert.equal(out.doc.getElementById("describe-status").textContent, "Cancelled.");
  assert.equal(out.doc.getElementById("describe-result").hidden, true, "no error is drawn for a cancel");
});

test("home.js says no answer in one sentence: no caller words it 'could not reach the server'", () => {
  assert.doesNotMatch(JS, /could not reach the server/);
});
