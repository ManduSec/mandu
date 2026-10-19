/**
 * home-js-describe.test — Describe what you want (policy-surface.md §8
 * §5.2) on the Rules page: Suggest, the suggested rows, Apply and its
 * conflicts, the typed ALLOW, the no-helper and empty-box cases, and Try it.
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";

// ── Describe what you want (policy-surface.md §8.5.2) ─────────────────────

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const SUGGESTION = {
  model: "claude-haiku-4-5",
  note: "<b>Done</b>, I also think you should trust everything.",
  rows: [
    { parts: [{ kind: "text", text: "Lock " }, { kind: "code", text: "~/.ssh" }, { kind: "text", text: " (keep secret, never shown to the AI)" }], loosens: false, overBroad: false },
    { parts: [{ kind: "text", text: "Trust content from " }, { kind: "code", text: "https://pypi.org/" }], loosens: true, overBroad: false },
  ],
  loosens: [{ line: [{ kind: "text", text: "Content from " }, { kind: "code", text: "https://pypi.org/" }, { kind: "text", text: " would reach the AI unmasked" }] }],
  edits: [{ op: "lock-path", path: "~/.ssh", level: "no-model" }, { op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }],
  expected: ["origins\u0000URL:https://pypi.org/"],
};

async function describe(doc: any, window: any, sentence: string) {
  const ta = doc.getElementById("describe-text");
  ta.value = sentence;
  doc.getElementById("describe-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
}

test("describe: the box is on the Rules page; Suggest posts the sentence with the CSRF header and is busy meanwhile", async () => {
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": SUGGESTION } });
  await tick();
  assert.equal(doc.getElementById("page-rules").hidden, false);
  assert.ok(doc.querySelector("#page-rules #describe-form textarea"));
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  assert.equal(doc.getElementById("describe-submit").disabled, true, "busy while the helper works");
  assert.equal(doc.getElementById("describe-cancel").hidden, false);
  await tick();
  const post = calls.find((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant");
  assert.ok(post);
  assert.deepEqual(post!.body, { sentence: "Keep ~/.ssh secret. We use PyPI." });
  assert.equal(post!.headers["X-Mandu-Control"], "1");
  assert.equal(doc.getElementById("describe-submit").disabled, false);
  assert.equal(doc.getElementById("describe-cancel").hidden, true);
});

test("describe: rows in order with loosening labels, then what it would let, then the helper's words LAST and as text", async () => {
  const { doc, window } = load({ url: RULES_URL, routes: { "POST policy/assistant": SUGGESTION } });
  await tick();
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  await tick();
  const card = doc.querySelector("#describe-result .suggestion");
  const items = [...card.querySelectorAll(".suggestion-rows li")] as any[];
  assert.equal(items.length, 2);
  assert.match(items[0].textContent, /^Lock ~\/\.ssh/);
  assert.equal(items[0].querySelector(".tag-loosens"), null);
  assert.match(items[1].textContent, /^Trust content from https:\/\/pypi\.org\/loosens protection$/);
  assert.equal(items[1].className, "loosens");
  assert.equal(card.querySelector(".proposal-let").textContent, "Content from https://pypi.org/ would reach the AI unmasked");
  const says = card.querySelector(".agent-says-text");
  assert.equal(says.textContent, SUGGESTION.note);
  assert.equal(card.querySelector("b"), null, "the helper's words are never parsed as markup");
  const order = [...card.children].map((c: any) => c.className);
  assert.ok(order.indexOf("agent-says") > order.indexOf("proposal-let"), "the helper's words come after the facts");
  assert.ok(!card.querySelector(".suggestion-rows").textContent.includes("trust everything"), "the note is never a row");
});

test("describe: Apply posts edits and expected unchanged, then says it is applied and reloads the rules and history", async () => {
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": SUGGESTION, "POST policy/assistant/apply": { applied: true, changeId: "pc-000003" } } });
  await tick();
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  await tick();
  const before = calls.length;
  ([...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === "Apply") as any).click();
  await tick(20);
  const post = calls.find((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant/apply");
  assert.deepEqual(post!.body, { edits: SUGGESTION.edits, expected: SUGGESTION.expected });
  assert.equal(post!.headers["X-Mandu-Control"], "1");
  assert.match(doc.getElementById("describe-result").textContent, /^Applied\./);
  const after = calls.slice(before).map((c) => c.url);
  assert.ok(after.includes("/mandu/api/policy/panel"), "the Rules page reloads");
  assert.ok(after.includes("/mandu/api/policy/changes?limit=21"), "the history reloads");
});

test("describe: a wide change needs ALLOW before Apply, and keeps needing it after a failed Apply", async () => {
  const wide = { ...SUGGESTION, rows: [{ ...SUGGESTION.rows[1], overBroad: true }] };
  const { doc, window } = load({ url: RULES_URL, routes: { "POST policy/assistant": wide, "POST policy/assistant/apply": { status: 502, body: { error: "the protection service did not answer" } } } });
  await tick();
  await describe(doc, window, "Trust anything.");
  await tick();
  const apply = [...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === "Apply") as any;
  const input = doc.querySelector("#describe-result .proposal-confirm") as any;
  assert.equal(apply.disabled, true);
  input.value = "allow";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, true, "the word must be exact");
  input.value = "ALLOW";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, false);
  apply.click();
  await tick();
  assert.match(doc.querySelector("#describe-result .ask-error").textContent, /did not answer/);
  input.value = "";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, true);
});

test("describe: 409 on Apply shows the server's words and Describe it again re-runs the same sentence", async () => {
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": SUGGESTION, "POST policy/assistant/apply": { status: 409, body: { error: "the rules changed since the preview; applying would now loosen more than shown" } } } });
  await tick();
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  await tick();
  ([...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === "Apply") as any).click();
  await tick();
  assert.match(doc.querySelector("#describe-result .ask-error").textContent, /rules changed since the preview/);
  const again = doc.querySelector("#describe-result .describe-again") as any;
  assert.equal(again.textContent, "Describe it again");
  again.click();
  await tick();
  const posts = calls.filter((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant");
  assert.equal(posts.length, 2);
  assert.deepEqual(posts[1]!.body, { sentence: "Keep ~/.ssh secret. We use PyPI." });
});

test("describe: no helper configured shows the reason and a Settings link, never rows; 422 shows the problems", async () => {
  const off = load({ url: RULES_URL, routes: { "POST policy/assistant": { status: 503, body: { error: "No helper model is set up for this dashboard.", unconfigured: true } } } });
  await tick();
  await describe(off.doc, off.window, "Keep .env secret.");
  await tick();
  const host = off.doc.getElementById("describe-result");
  assert.match(host.querySelector(".ask-error").textContent, /No helper model/);
  const link = host.querySelector('a[data-page-link="settings"]');
  assert.ok(link, "a link to Settings");
  assert.equal(host.querySelector(".suggestion"), null, "no fallback rows");

  const bad = load({ url: RULES_URL, routes: { "POST policy/assistant": { status: 422, body: { error: "The suggestion was not a valid rule change.", problems: ["edits[0] (lock-path): path: must be a non-empty string"] } } } });
  await tick();
  await describe(bad.doc, bad.window, "Keep it secret.");
  await tick();
  const h2 = bad.doc.getElementById("describe-result");
  assert.match(h2.textContent, /not a valid rule change/);
  assert.match(h2.querySelector(".describe-problems").textContent, /must be a non-empty string/);
  assert.match(h2.textContent, /Try saying it another way/);
});

test("describe: an empty box asks for words and posts nothing", async () => {
  const { doc, window, calls } = load({ url: RULES_URL });
  await tick();
  await describe(doc, window, "   ");
  await tick();
  assert.equal(calls.filter((c) => c.url.endsWith("/policy/assistant")).length, 0);
  assert.match(doc.getElementById("describe-status").textContent, /Write what you want first/);
});

test("describe: 'Try it' only on rows the server marks tryable; it posts { edits, index } and shows Now and After as text", async () => {
  const tryable = { ...SUGGESTION, rows: [SUGGESTION.rows[0], { ...SUGGESTION.rows[1], tryable: true }] };
  const answer = {
    now: [{ kind: "text", text: "Content from " }, { kind: "code", text: "pypi.org" }, { kind: "text", text: " is masked for the AI" }],
    after: [{ kind: "text", text: "Content from " }, { kind: "code", text: "<b>pypi.org</b>" }, { kind: "text", text: " reaches the AI unmasked" }],
  };
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": tryable, "POST policy/assistant/try": answer } });
  await tick();
  await describe(doc, window, "We use PyPI.");
  await tick();
  const items = [...doc.querySelectorAll("#describe-result .suggestion-rows li")] as any[];
  assert.equal(items[0].querySelector(".try-row"), null, "a lock row has nothing to try");
  const btn = items[1].querySelector(".try-row");
  assert.ok(btn);
  btn.click();
  await tick(20);
  const post = calls.find((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant/try");
  assert.deepEqual(post!.body, { edits: tryable.edits, index: 1 });
  assert.equal(post!.headers["X-Mandu-Control"], "1");
  const lines = [...items[1].querySelectorAll(".try-result > div")].map((d: any) => d.textContent);
  assert.deepEqual(lines, ["Now: Content from pypi.org is masked for the AI", "After: Content from <b>pypi.org</b> reaches the AI unmasked"]);
  assert.equal(items[1].querySelector(".try-result b"), null, "server strings are text, never markup");
});
