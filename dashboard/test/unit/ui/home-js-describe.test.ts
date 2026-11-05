/**
 * home-js-describe.test — Describe what you want (policy-surface.md §8
 * §5.2) on the Rules page: Suggest, the suggested rows, Apply and its
 * conflicts, the typed ALLOW, the no-helper and empty-box cases, Try it,
 * and the box's 2,000-character limit said (a count past 1,800, a line when
 * a paste is cut) and Ctrl/Cmd+Enter pressing Suggest rules.
 * With no helper, the card says why in the page's words by the answer's
 * `reason` (the server's HELPER_WORDS, the command as code), the original
 * text only under Details for `other`, and no Settings link.
 * Before anything is written, a line under the card's note names the AI
 * that reads the box (or says none can, in the 503's words without its
 * "again"), read when Rules opens, on the box's focus past 30 s and after
 * each press's answer; a 501 or no answer draws none, and Suggest rules
 * stays on. While the 503's alert says why under the box, a not-ready
 * line is hidden.
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { HELPER_WORDS, type AssistantUnavailableReason } from "../../../src/policy-assistant.js";

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
  input.value = "ALLO";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, true, "the word must be typed whole");
  input.value = "allow";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, false, "in any case");
  apply.click();
  await tick();
  assert.match(doc.querySelector("#describe-result .ask-error").textContent, /did not answer/);
  assert.equal(apply.disabled, false, "the typed word still counts after the failed Apply");
  input.value = "";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(apply.disabled, true);
});

test("describe: the ALLOW box counts the word in any case, trimmed, says when it does not, and Enter presses Apply once", async () => {
  const wide = { ...SUGGESTION, rows: [{ ...SUGGESTION.rows[1], overBroad: true }] };
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": wide, "POST policy/assistant/apply": { ok: true } } });
  await tick();
  await describe(doc, window, "Trust anything.");
  await tick();
  const apply = [...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === "Apply") as any;
  const input = doc.querySelector("#describe-result .proposal-confirm") as any;
  const hint = doc.querySelector("#describe-result .confirm-hint") as any;
  assert.equal(input.getAttribute("autocapitalize"), "characters");
  assert.equal(input.getAttribute("autocorrect"), "off");
  assert.equal(input.getAttribute("spellcheck"), "false");
  assert.equal(input.getAttribute("autocomplete"), "off");
  assert.equal(hint.hidden, true, "nothing typed: no hint");
  const type = (text: string) => { input.value = text; input.dispatchEvent(new window.Event("input")); };
  const enter = () => input.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  const applies = () => calls.filter((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant/apply");
  for (const word of ["ALLO", "ALLOWED"]) {
    type(word);
    assert.equal(apply.disabled, true, `"${word}" keeps Apply off`);
    assert.equal(hint.hidden, false);
    assert.equal(hint.textContent, "Type the word ALLOW to turn on Apply.");
    assert.equal(input.getAttribute("aria-describedby"), hint.id);
  }
  enter();
  await tick();
  assert.equal(applies().length, 0, "off: Enter applies nothing");
  for (const word of ["Allow", "allow", " ALLOW "]) {
    type(word);
    assert.equal(apply.disabled, false, `"${word}" turns Apply on`);
    assert.equal(hint.hidden, true);
  }
  type("");
  assert.equal(apply.disabled, true, "empty keeps Apply off");
  assert.equal(hint.hidden, true, "empty: no hint");
  type("Allow");
  enter();
  enter();
  await tick();
  assert.equal(applies().length, 1, "on: Enter applies once");
  assert.deepEqual(applies()[0].body, { edits: wide.edits, expected: wide.expected });
});

test("describe: a wide row says so beside its words, and the foot says what it opens (dashboard.md §4.25 *A wide change says what is open*)", async () => {
  const opens = [{ kind: "text", text: "This lets your agent's programs connect to any address." }];
  const wide = {
    ...SUGGESTION,
    rows: [SUGGESTION.rows[0], { parts: [{ kind: "text", text: "Let your agent's programs connect to any address" }], loosens: true, overBroad: true, overBroadWhy: [opens] }],
    overBroadWhy: [opens],
    edits: [SUGGESTION.edits[0], { op: "allow-connect", host: "*" }],
  };
  const { doc, window } = load({ url: RULES_URL, routes: { "POST policy/assistant": wide } });
  await tick();
  await describe(doc, window, "Let it reach anything.");
  await tick();
  const items = [...doc.querySelectorAll("#describe-result .suggestion-rows li")] as any[];
  assert.deepEqual(items.map((li) => li.querySelector(".tag-wide")?.textContent ?? null), [null, "Wide: type ALLOW"], "only the wide row is marked");
  const why = doc.querySelector("#describe-result .wide-why") as any;
  assert.equal(why.textContent, "This lets your agent's programs connect to any address. Type ALLOW if you mean it.");
  assert.ok(why.classList.contains("dim"));
  assert.equal(why.nextElementSibling, doc.querySelector("#describe-result .proposal-confirm"), "the line sits before the field");
  const apply = [...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === "Apply") as any;
  assert.equal(apply.disabled, true, "Apply still waits for the typed word");
});

test("approvals: a wide change's foot names what it opens, a code part kept whole, and the warning case keeps its line", async () => {
  const card = (id: string, over: Record<string, unknown>) => ({
    id, status: "pending", requester: "Your agent", byAgent: true, session: null, createdAt: Date.now() - 60_000,
    rows: [[{ kind: "text", text: "Always allow sending masked data from " }, { kind: "code", text: "docs.python.org" }, { kind: "text", text: " to anywhere" }]],
    wouldLet: [], capped: false, overBroad: true, warnings: [], reason: null, ...over,
  });
  const sendAny = [{ kind: "text", text: "This lets masked data from " }, { kind: "code", text: "docs.python.org" }, { kind: "text", text: " be sent anywhere." }];
  const proposals = [
    card("pp-000001", { overBroadWhy: [sendAny, [{ kind: "text", text: "And 1 more wide change." }]] }),
    card("pp-000002", { overBroadWhy: [], warnings: [[{ kind: "text", text: "lab would count as your own model" }]] }),
    card("pp-000003", {}),
  ];
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/proposals?status=pending": { proposals } } });
  await tick();
  const foot = (id: string) => doc.querySelector(`#approvals-proposals [data-id="${id}"] .wide-why`) as any;
  assert.equal(foot("pp-000001").textContent, "This lets masked data from docs.python.org be sent anywhere. And 1 more wide change. Type ALLOW if you mean it.");
  assert.equal(foot("pp-000001").querySelector("code").textContent, "docs.python.org", "the host is a name, as in the row");
  assert.equal(foot("pp-000002").textContent, "Read the warning above before you allow this.", "the warning case as before");
  assert.equal(foot("pp-000003").textContent, "This change has no limit on one side.", "an older server's card: the old words");
  const first = doc.querySelector('#approvals-proposals [data-id="pp-000001"]') as any;
  const allow = first.querySelector(".proposal-allow");
  const input = first.querySelector(".proposal-confirm");
  assert.equal(allow.disabled, true, "Allow waits for the typed word");
  input.value = "ALLOW";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(allow.disabled, false);
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

test("describe: no helper configured says why in the page's words, by reason, with no Settings link and never rows; 422 shows the problems", async () => {
  const codes: Record<AssistantUnavailableReason, string[]> = {
    "no-channel": ["claude"],
    "not-installed": ["mandu doctor"],
    "api-key-missing": ["ANTHROPIC_API_KEY"],
    "cli-missing": ["claude"],
    other: [],
  };
  for (const reason of Object.keys(codes) as AssistantUnavailableReason[]) {
    const detail = reason === "other" ? "declared model endpoint 'x' cannot be read (fail closed)" : undefined;
    const off = load({ url: RULES_URL, routes: { "POST policy/assistant": { status: 503, body: { error: HELPER_WORDS[reason], unconfigured: true, reason, ...(detail ? { detail } : {}) } } } });
    await tick();
    await describe(off.doc, off.window, "Keep .env secret.");
    await tick();
    const host = off.doc.getElementById("describe-result");
    const said = host.querySelector(".ask-error");
    assert.equal(said.getAttribute("role"), "alert");
    assert.equal(said.textContent, HELPER_WORDS[reason], `${reason}: the page's words are the server's`);
    assert.deepEqual([...said.querySelectorAll("code")].map((c: any) => c.textContent), codes[reason], `${reason}: the command as code`);
    assert.equal(host.querySelector("a"), null, `${reason}: no link (Settings fixes none of these)`);
    assert.equal(host.querySelector(".suggestion"), null, "no fallback rows");
    const fold = host.querySelector("details.describe-detail");
    if (detail) {
      assert.equal(fold.querySelector("summary").textContent, "Details");
      assert.equal(fold.open, false, "folded");
      assert.equal(fold.querySelector(".dim").textContent, detail, "the original text, as text");
    } else assert.equal(fold, null, `${reason}: no Details`);
  }

  // A reason the page does not know: its general words, the server's text
  // under Details.
  const odd = load({ url: RULES_URL, routes: { "POST policy/assistant": { status: 503, body: { error: "No assistant model is set up: <b>x</b>", unconfigured: true, reason: "later" } } } });
  await tick();
  await describe(odd.doc, odd.window, "Keep .env secret.");
  await tick();
  const oh = odd.doc.getElementById("describe-result");
  assert.equal(oh.querySelector(".ask-error").textContent, "Mandu's helper cannot run right now.");
  assert.equal(oh.querySelector("details.describe-detail .dim").textContent, "No assistant model is set up: <b>x</b>");
  assert.equal(oh.querySelector("b"), null, "never markup");

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

// ── The limit, said, and Ctrl+Enter (dashboard.md *Describe what you want*) ──

/** The box's text set as typing does: the value, then an input event. */
function type(doc: any, window: any, text: string) {
  const ta = doc.getElementById("describe-text");
  ta.value = text;
  ta.dispatchEvent(new window.Event("input", { bubbles: true }));
}
/** A paste of `text` over the box's selection, then the box as the browser
 *  leaves it: cut at its maxlength. jsdom has no ClipboardEvent. */
function paste(doc: any, window: any, text: string) {
  const ta = doc.getElementById("describe-text");
  const e = new window.Event("paste", { bubbles: true, cancelable: true });
  Object.defineProperty(e, "clipboardData", { value: { getData: (t: string) => (t === "text/plain" ? text : "") } });
  ta.dispatchEvent(e);
  const from = ta.selectionStart;
  const to = ta.selectionEnd;
  const room = 2000 - (ta.value.length - (to - from));
  ta.value = ta.value.slice(0, from) + text.replace(/\r\n?/g, "\n").slice(0, room) + ta.value.slice(to);
  const input = new window.Event("input", { bubbles: true });
  Object.defineProperty(input, "inputType", { value: "insertFromPaste" });
  ta.dispatchEvent(input);
}
const CUT = "Only the first 2,000 characters fit. Mandu's helper reads only those: shorten it or describe the rules in your own words.";

test("describe: the box is described by its count and cut line, and Suggest rules names its shortcut", async () => {
  const { doc } = load({ url: RULES_URL });
  await tick();
  const ta = doc.getElementById("describe-text");
  assert.equal(ta.getAttribute("maxlength"), "2000", "the cap is the server's SENTENCE_MAX");
  assert.equal(ta.getAttribute("aria-describedby"), "describe-where describe-count describe-cut", "the line naming the AI first, then the count and the cut line");
  assert.equal(doc.getElementById("describe-submit").getAttribute("aria-keyshortcuts"), "Control+Enter Meta+Enter");
  const count = doc.getElementById("describe-count");
  assert.equal(count.hidden, true, "an empty box: no count");
  assert.equal(count.getAttribute("role"), null, "the count is no live region");
  assert.equal(count.getAttribute("aria-live"), null);
  assert.equal(doc.getElementById("describe-cut").getAttribute("role"), "status");
  assert.equal(doc.getElementById("describe-cut").textContent, "");
});

test("describe: no count up to 1,800 characters, a quiet count past it", async () => {
  const { doc, window } = load({ url: RULES_URL });
  await tick();
  const count = doc.getElementById("describe-count");
  type(doc, window, "x".repeat(1799));
  assert.equal(count.hidden, true, "1,799: no count");
  type(doc, window, "x".repeat(1800));
  assert.equal(count.hidden, true, "1,800: no count");
  type(doc, window, "x".repeat(1801));
  assert.equal(count.hidden, false);
  assert.equal(count.textContent, "1,801 of 2,000 characters");
  type(doc, window, "x".repeat(1950));
  assert.equal(count.textContent, "1,950 of 2,000 characters");
  type(doc, window, "x".repeat(2000));
  assert.equal(count.textContent, "2,000 of 2,000 characters");
  assert.equal(doc.getElementById("describe-cut").textContent, "", "typed to the limit: no cut line");
  type(doc, window, "short");
  assert.equal(count.hidden, true, "back under: the count goes");
});

test("describe: a paste cut at 2,000 says so once, and editing back under the limit clears it", async () => {
  const { doc, window } = load({ url: RULES_URL });
  await tick();
  const cut = doc.getElementById("describe-cut");
  const ta = doc.getElementById("describe-text");
  paste(doc, window, "Our policy. ".repeat(100));
  assert.equal(ta.value.length, 1200);
  assert.equal(cut.textContent, "", "a paste that fits: no line");
  ta.setSelectionRange(1200, 1200);
  paste(doc, window, "More of it.\r\n".repeat(100));
  assert.equal(ta.value.length, 2000, "the box keeps the first 2,000");
  assert.equal(cut.textContent, CUT);
  assert.equal(doc.getElementById("describe-count").textContent, "2,000 of 2,000 characters");
  type(doc, window, "x".repeat(1990));
  ta.setSelectionRange(1990, 1990);
  assert.equal(cut.textContent, "", "edited under the limit: the line goes");
  // A paste whose CRLF lines fit once counted as one character each: no line.
  paste(doc, window, "a\r\nb\r\nc\r\n");
  assert.equal(ta.value.length, 1996);
  assert.equal(cut.textContent, "", "CRLF counts as one character, as the box counts it");
  // A paste over a selection counts what it replaces.
  ta.setSelectionRange(0, 1996);
  paste(doc, window, "y".repeat(2000));
  assert.equal(cut.textContent, "", "replacing the whole text with 2,000 fits");
  ta.setSelectionRange(0, 0);
  paste(doc, window, "z");
  assert.equal(cut.textContent, CUT, "one more at the limit is cut");
  // Further edits and cut pastes at the limit keep it, unchanged (said
  // once); one under clears it.
  const changes: unknown[] = [];
  new window.MutationObserver((r: unknown[]) => changes.push(...r)).observe(cut, { childList: true, characterData: true, subtree: true });
  ta.dispatchEvent(new window.Event("input", { bubbles: true }));
  paste(doc, window, "z");
  await tick();
  assert.equal(cut.textContent, CUT);
  assert.deepEqual(changes, [], "the live line is not written again");
  type(doc, window, ta.value.slice(0, 1999));
  assert.equal(cut.textContent, "");
});

test("describe: Ctrl+Enter and Meta+Enter press Suggest rules once with the box's text; Enter and Shift+Enter do not; a press while it runs starts nothing", async () => {
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": SUGGESTION } });
  await tick();
  const ta = doc.getElementById("describe-text");
  const posts = () => calls.filter((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant");
  const key = (over: Record<string, boolean>) => {
    const e = new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true, ...over });
    ta.dispatchEvent(e);
    return e;
  };
  ta.value = "Keep ~/.ssh secret.\nWe use PyPI.";
  ta.focus();
  for (const over of [{}, { shiftKey: true }] as Record<string, boolean>[]) {
    const e = key(over);
    assert.equal(e.defaultPrevented, false, "a new line, as before");
  }
  await tick();
  assert.equal(posts().length, 0, "Enter and Shift+Enter post nothing");

  const e = key({ ctrlKey: true });
  assert.equal(e.defaultPrevented, true, "no new line");
  assert.equal(doc.getElementById("describe-submit").disabled, true, "busy, as for the button");
  key({ ctrlKey: true });
  key({ metaKey: true });
  await tick();
  assert.equal(posts().length, 1, "once: the shortcut obeys the button's state");
  assert.deepEqual(posts()[0]!.body, { sentence: "Keep ~/.ssh secret.\nWe use PyPI." });
  assert.equal(doc.activeElement, ta, "the focus stays in the box");
  assert.ok(doc.querySelector("#describe-result .suggestion"), "the suggestion is drawn");

  ta.value = "Keep .env secret.";
  key({ metaKey: true });
  await tick();
  assert.equal(posts().length, 2, "Cmd+Enter on a Mac");
  assert.deepEqual(posts()[1]!.body, { sentence: "Keep .env secret." });
});

// ── Discard leaves a line with Undo (dashboard.md §4.25n *Describe can undo
// its Discard*): the answer is slow and an outside model call, so Discard
// keeps it in page memory, and Undo draws it again without a request ──────

const resultButton = (doc: any, words: string) => [...doc.querySelectorAll("#describe-result button")].find((b: any) => b.textContent === words) as any;
const suggestionText = (doc: any) => {
  const card = doc.querySelector("#describe-result .suggestion");
  return {
    rows: [...card.querySelectorAll(".suggestion-rows li")].map((li: any) => li.textContent),
    lets: card.querySelector(".proposal-let")?.textContent ?? null,
    note: card.querySelector(".agent-says-text")?.textContent ?? null,
  };
};

test("describe: Discard leaves \"Suggestion discarded.\" with Undo; Undo draws the same rows, what it would let and the note, and posts nothing", async () => {
  const tryable = { ...SUGGESTION, rows: [SUGGESTION.rows[0], { ...SUGGESTION.rows[1], tryable: true }] };
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": tryable } });
  await tick();
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  await tick();
  const before = suggestionText(doc);
  const posts = () => calls.filter((c) => c.method === "POST").length;
  const posted = posts();
  resultButton(doc, "Discard").click();
  const host = doc.getElementById("describe-result");
  assert.equal(host.hidden, false, "the line stays in the card");
  assert.equal(host.querySelector(".suggestion"), null, "the suggestion is gone");
  const line = host.querySelector(".describe-done");
  assert.equal(line.querySelector("span").textContent, "Suggestion discarded.");
  const undo = resultButton(doc, "Undo");
  assert.ok(undo, "Undo on the line");
  assert.equal(undo.getAttribute("aria-label"), "Undo the discard in Describe what you want");
  assert.equal(doc.getElementById(undo.getAttribute("aria-describedby")).textContent, "Suggestion discarded.");

  undo.click();
  await tick();
  assert.equal(host.querySelector(".describe-done"), null, "the line goes");
  assert.deepEqual(suggestionText(doc), before, "the same rows, This would let and note");
  assert.equal(host.querySelectorAll(".try-row").length, 1, "its Try it is back");
  assert.ok(resultButton(doc, "Apply") && resultButton(doc, "Discard"));
  assert.equal(posts(), posted, "Discard and Undo post nothing");
});

test("describe: a wide suggestion comes back from Undo with an empty ALLOW box and Apply off", async () => {
  const wide = { ...SUGGESTION, rows: [{ ...SUGGESTION.rows[1], overBroad: true }] };
  const { doc, window } = load({ url: RULES_URL, routes: { "POST policy/assistant": wide } });
  await tick();
  await describe(doc, window, "Trust anything.");
  await tick();
  const input = doc.querySelector("#describe-result .proposal-confirm") as any;
  input.value = "ALLOW";
  input.dispatchEvent(new window.Event("input"));
  assert.equal(resultButton(doc, "Apply").disabled, false);
  resultButton(doc, "Discard").click();
  resultButton(doc, "Undo").click();
  const back = doc.querySelector("#describe-result .proposal-confirm") as any;
  assert.ok(back, "the ALLOW box is back");
  assert.notEqual(back, input, "a new box");
  assert.equal(back.value, "", "never typed in for the person");
  assert.equal(resultButton(doc, "Apply").disabled, true, "Apply waits for ALLOW again");
});

test("describe: Suggest rules pressed again removes the line, and the discarded suggestion is never drawn again", async () => {
  const second = { ...SUGGESTION, note: "A second answer.", rows: [SUGGESTION.rows[0]], loosens: [] };
  let n = 0;
  const { doc, window } = load({ url: RULES_URL, routes: { "POST policy/assistant": () => (n++ === 0 ? SUGGESTION : second) } });
  await tick();
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  await tick();
  resultButton(doc, "Discard").click();
  const undo = resultButton(doc, "Undo");
  await describe(doc, window, "Keep ~/.ssh secret.");
  assert.equal(doc.querySelector("#describe-result .describe-done"), null, "the line goes at the press");
  await tick();
  assert.deepEqual(suggestionText(doc).note, "A second answer.");
  undo.click();
  await tick();
  assert.equal(suggestionText(doc).note, "A second answer.", "an old Undo draws nothing");
  assert.equal(doc.querySelectorAll("#describe-result .suggestion").length, 1);
  resultButton(doc, "Discard").click();
  resultButton(doc, "Undo").click();
  assert.equal(suggestionText(doc).note, "A second answer.", "Undo brings back the newest answer only");
});

test("describe: Apply after Undo posts the same body as Apply before Discard", async () => {
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "POST policy/assistant": SUGGESTION, "POST policy/assistant/apply": { status: 502, body: { error: "the protection service did not answer" } } } });
  await tick();
  await describe(doc, window, "Keep ~/.ssh secret. We use PyPI.");
  await tick();
  const applies = () => calls.filter((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant/apply");
  resultButton(doc, "Apply").click();
  await tick();
  assert.equal(applies().length, 1);
  resultButton(doc, "Discard").click();
  resultButton(doc, "Undo").click();
  assert.equal(doc.querySelector("#describe-result .ask-error"), null, "the card comes back as it came, without the refusal");
  resultButton(doc, "Apply").click();
  await tick();
  assert.equal(applies().length, 2);
  assert.deepEqual(applies()[1].body, applies()[0].body);
  assert.deepEqual(applies()[1].body, { edits: SUGGESTION.edits, expected: SUGGESTION.expected });
});

// ── Which AI reads what you write (dashboard.md, *Describe says which AI reads your words*) ──

const CHANNEL = "GET policy/assistant/channel";
const RULES_TAIL = " A summary of your rules goes with it: the files, sites and models they name, never a secret's value.";
const WHERE: Record<string, [string, string[]]> = {
  api: ["What you write here goes to Anthropic's API, so that an AI can suggest rules." + RULES_TAIL, []],
  "api-custom": ["What you write here goes to the AI at the address in ANTHROPIC_BASE_URL, so that it can suggest rules." + RULES_TAIL, ["ANTHROPIC_BASE_URL"]],
  claude: ["What you write here goes through Claude Code on this computer to the AI it uses (Anthropic's, unless Claude Code is set otherwise), so that it can suggest rules." + RULES_TAIL, []],
  "claude-custom": ["What you write here goes through Claude Code on this computer to the AI at the address in ANTHROPIC_BASE_URL, so that it can suggest rules." + RULES_TAIL, ["ANTHROPIC_BASE_URL"]],
  codex: ["What you write here goes through Codex on this computer to the AI it uses (OpenAI's, unless Codex is set otherwise), so that it can suggest rules." + RULES_TAIL, []],
};

test("describe: Rules opens with a line under the note naming the AI that reads the box, in the note style; the box is described by it", async () => {
  for (const [via, [text, codes]] of Object.entries(WHERE)) {
    const { doc, calls } = load({ url: RULES_URL, routes: { [CHANNEL]: { ready: true, via } } });
    await tick();
    const line = doc.getElementById("describe-where");
    assert.equal(line.hidden, false, via);
    assert.equal(line.textContent, text, via);
    assert.equal(line.className, "note", `${via}: a fact, not a warning`);
    assert.equal(line.getAttribute("role"), null, `${via}: not announced on open`);
    assert.deepEqual([...line.querySelectorAll("code")].map((c: any) => c.textContent), codes, `${via}: the variable as code`);
    assert.equal(line.previousElementSibling.textContent, "Say it in your own words. A helper suggests rules, and nothing changes until you press Apply.", "under the card's note");
    assert.ok(doc.getElementById("describe-text").getAttribute("aria-describedby").split(" ").includes("describe-where"));
    const read = calls.find((c) => c.url === "/mandu/api/policy/assistant/channel");
    assert.ok(read, via);
    assert.equal(read!.method, "GET");
    assert.equal(read!.headers["X-Mandu-Control"], "1", "an admin read");
    assert.equal(calls.filter((c) => c.url === "/mandu/api/policy/assistant/channel").length, 1, "read once on open");
    assert.equal(doc.getElementById("describe-submit").disabled, false);
  }
});

/** The 503's words as the line says them before a press: no "again". */
const beforePress = (reason: AssistantUnavailableReason) => HELPER_WORDS[reason].replace(", then press Suggest rules again.", ", then press Suggest rules.");
const CODES: Record<AssistantUnavailableReason, string[]> = {
  "no-channel": ["claude"], "not-installed": ["mandu doctor"], "api-key-missing": ["ANTHROPIC_API_KEY"], "cli-missing": ["claude"], other: [],
};

test("describe: with no helper the line has the 503's words without \"again\" (nothing was pressed yet), and Suggest rules stays on", async () => {
  for (const reason of Object.keys(HELPER_WORDS) as AssistantUnavailableReason[]) {
    const { doc } = load({ url: RULES_URL, routes: { [CHANNEL]: { ready: false, reason } } });
    await tick();
    const line = doc.getElementById("describe-where");
    assert.equal(line.hidden, false, reason);
    assert.equal(line.textContent, beforePress(reason), `${reason}: the words the 503 draws, before a press`);
    assert.doesNotMatch(line.textContent, /\bagain\b/, `${reason}: no "again" before any press`);
    assert.deepEqual([...line.querySelectorAll("code")].map((c: any) => c.textContent), CODES[reason], `${reason}: the command as code`);
    assert.equal(line.className, "note");
    assert.equal(doc.getElementById("describe-submit").disabled, false, `${reason}: signing in can fix it before the press`);
  }
  const odd = load({ url: RULES_URL, routes: { [CHANNEL]: { ready: false, reason: "later" } } });
  await tick();
  assert.equal(odd.doc.getElementById("describe-where").textContent, "Mandu's helper cannot run right now.");
});

test("describe: a 501, a refused read, no answer or an answer it does not know draws no line", async () => {
  const answers: unknown[] = [
    { status: 501, body: { error: "this arbiter has no rule assistant ops" } },
    { status: 403, body: { error: "sign in" } },
    () => { throw new TypeError("Failed to fetch"); },
    { ready: true, via: "carrier-pigeon" },
    {},
  ];
  for (const answer of answers) {
    const { doc } = load({ url: RULES_URL, routes: { [CHANNEL]: answer } });
    await tick();
    const line = doc.getElementById("describe-where");
    assert.equal(line.hidden, true, JSON.stringify(answer));
    assert.equal(line.textContent, "");
    assert.equal(doc.getElementById("describe-submit").disabled, false);
  }
});

test("describe: the box's focus reads the channel again once the last read is over 30 s old, not before", async () => {
  let via = "claude";
  const { doc, window, calls } = load({ url: RULES_URL, routes: { [CHANNEL]: () => ({ ready: true, via }) } });
  await tick();
  const reads = () => calls.filter((c) => c.url === "/mandu/api/policy/assistant/channel").length;
  assert.equal(reads(), 1);
  const realNow = window.Date.now;
  const t0 = realNow();
  const box = doc.getElementById("describe-text");
  try {
    window.Date.now = () => t0 + 10_000;
    via = "codex";
    box.dispatchEvent(new window.FocusEvent("focus"));
    await tick();
    assert.equal(reads(), 1, "not within 30 s");
    assert.equal(doc.getElementById("describe-where").textContent, WHERE.claude![0]);
    window.Date.now = () => t0 + 31_000;
    box.dispatchEvent(new window.FocusEvent("focus"));
    await tick();
    assert.equal(reads(), 2, "past 30 s");
    assert.equal(doc.getElementById("describe-where").textContent, WHERE.codex![0], "the line follows the new answer");
    window.Date.now = () => t0 + 40_000;
    box.dispatchEvent(new window.FocusEvent("focus"));
    await tick();
    assert.equal(reads(), 2, "30 s from the last read, not the first");
  } finally {
    window.Date.now = realNow;
  }
});

test("describe: a press answered 503 hides the not-ready line while its alert says why; a press that returns rows clears it, and the line follows the new read", async () => {
  let channel: unknown = { ready: false, reason: "no-channel" };
  let answer: unknown = { status: 503, body: { error: HELPER_WORDS["no-channel"], unconfigured: true, reason: "no-channel" } };
  const { doc, window } = load({ url: RULES_URL, routes: { [CHANNEL]: () => channel, "POST policy/assistant": () => answer } });
  await tick();
  const line = doc.getElementById("describe-where");
  const host = doc.getElementById("describe-result");
  const submit = doc.getElementById("describe-submit");
  assert.equal(line.hidden, false);
  assert.equal(line.textContent, beforePress("no-channel"));

  await describe(doc, window, "Keep .env secret.");
  await tick();
  const alert = host.querySelector(".ask-error");
  assert.equal(alert.getAttribute("role"), "alert");
  assert.equal(alert.textContent, HELPER_WORDS["no-channel"], "the alert keeps the 503's words, \"again\" included: a press was made");
  assert.match(alert.textContent, /\bagain\b/);
  assert.equal(line.hidden, true, "one sentence, said once: the line above is hidden");
  assert.equal(submit.getAttribute("aria-describedby"), "describe-result", "Suggest rules is still described by the alert");
  assert.ok(doc.getElementById("describe-text").getAttribute("aria-describedby").startsWith("describe-where "), "the box's description list is unchanged");

  // The focus past 30 s reads the line again: still hidden while the alert stands.
  const realNow = window.Date.now;
  const t0 = realNow();
  try {
    window.Date.now = () => t0 + 31_000;
    doc.getElementById("describe-text").dispatchEvent(new window.FocusEvent("focus"));
    await tick();
    assert.equal(line.hidden, true, "a later read keeps it hidden while the alert says the same");
  } finally {
    window.Date.now = realNow;
  }

  // Signed in meanwhile: the next press returns rows, the alert goes, and the line names Claude Code.
  channel = { ready: true, via: "claude" };
  answer = SUGGESTION;
  await describe(doc, window, "Keep .env secret.");
  await tick();
  assert.equal(host.querySelector(".ask-error"), null, "the alert is cleared");
  assert.ok(host.querySelector(".suggestion"), "the suggestion is drawn");
  assert.equal(line.hidden, false);
  assert.equal(line.textContent, WHERE.claude![0], "the line follows what the press found");
});

test("describe: a press on Suggest rules with no focus on the box reads the channel again once its answer is drawn", async () => {
  let channel: unknown = { ready: false, reason: "no-channel" };
  const { doc, calls } = load({ url: RULES_URL, routes: { [CHANNEL]: () => channel, "POST policy/assistant": SUGGESTION } });
  await tick();
  const reads = () => calls.filter((c) => c.url === "/mandu/api/policy/assistant/channel").length;
  const line = doc.getElementById("describe-where");
  assert.equal(reads(), 1);
  assert.equal(line.textContent, beforePress("no-channel"));
  channel = { ready: true, via: "claude" };
  doc.getElementById("describe-text").value = "Keep .env secret.";
  const submit = doc.getElementById("describe-submit");
  submit.click();
  assert.notEqual(doc.activeElement, doc.getElementById("describe-text"), "the box never had the focus");
  await tick();
  assert.ok(doc.querySelector("#describe-result .suggestion"), "the rows came back");
  assert.equal(reads(), 2, "read once more, after the answer");
  assert.equal(line.hidden, false);
  assert.equal(line.textContent, WHERE.claude![0], "the line follows the new answer");
});

test("describe: an older channel read that lands after a newer one draws nothing", async () => {
  const pending: Array<(v: unknown) => void> = [];
  const { doc, window } = load({
    url: RULES_URL,
    before: (w: any) => {
      const real = w.fetch;
      w.fetch = (url: string, init: any = {}) => {
        if (!String(url).endsWith("/api/policy/assistant/channel")) return real(url, init);
        return new Promise((resolve) => pending.push(resolve));
      };
    },
  });
  await tick();
  const answer = (body: unknown) => ({ ok: true, status: 200, json: () => Promise.resolve(body) });
  assert.equal(pending.length, 1, "read on open, still out");
  const realNow = window.Date.now;
  const t0 = realNow();
  try {
    window.Date.now = () => t0 + 31_000;
    doc.getElementById("describe-text").dispatchEvent(new window.FocusEvent("focus"));
  } finally {
    window.Date.now = realNow;
  }
  await tick();
  assert.equal(pending.length, 2, "a newer read");
  pending[1]!(answer({ ready: true, via: "codex" }));
  await tick();
  const line = doc.getElementById("describe-where");
  assert.equal(line.textContent, WHERE.codex![0]);
  pending[0]!(answer({ ready: false, reason: "no-channel" }));
  await tick();
  assert.equal(line.textContent, WHERE.codex![0], "the older read draws nothing");
  assert.equal(line.hidden, false);
});

// ── A suggested send rule says when the mode leaves it nothing to decide
// (dashboard.md *Describe what you want*): in the Secrets mode a rule for a
// host never covers a secret and only secrets are masked, so a suggested
// `release` row says so before Apply, in Your rules' own words (§4.25e) ──

const IDLE_WORDS = "Decides nothing in the Secrets mode: a rule for a host never covers your secrets, and this mode masks only secrets.";
const axes = (integrity: boolean, confidentiality: boolean) => ({
  ok: true, effective: { integrity, confidentiality },
  effectiveMode: confidentiality ? (integrity ? "full" : "secrets") : (integrity ? "injection" : "off"),
});
const SEND_SUGGESTION = {
  model: "claude-haiku-4-5",
  note: null,
  rows: [
    { parts: [{ kind: "text", text: "Never send anything to " }, { kind: "code", text: "paste.example" }], loosens: false, overBroad: false, tryable: true },
    { parts: [{ kind: "text", text: "Always allow sending to " }, { kind: "code", text: "pypi.org" }], loosens: true, overBroad: false, tryable: true },
    { parts: [{ kind: "text", text: "Make " }, { kind: "code", text: "~/proj/.env" }, { kind: "text", text: " a secret no AI may read" }], loosens: false, overBroad: false },
  ],
  loosens: [{ line: [{ kind: "text", text: "Data could be sent to " }, { kind: "code", text: "pypi.org" }] }],
  edits: [
    { op: "release", to: { host: "paste.example" }, mode: "block" },
    { op: "release", to: { host: "pypi.org" }, mode: "allow" },
    { op: "lock-path", path: "/home/u/proj/.env", level: "no-model" },
  ],
  expected: ["release\u0000pypi.org"],
};
const suggestedRows = (doc: any) => [...doc.querySelectorAll("#describe-result .suggestion-rows li")] as any[];
const modeNote = (li: any) => li.querySelector(".rule-mode-note");

test("describe: in the Secrets mode each suggested send rule says it decides nothing, in Your rules' words, before its Try it; a file row does not", async () => {
  const { doc, window } = load({ url: RULES_URL, routes: { "GET config/axes": axes(false, true), "POST policy/assistant": SEND_SUGGESTION } });
  await tick();
  await describe(doc, window, "Never send anything to paste sites. We use PyPI. Keep .env secret.");
  await tick();
  const [block, allow, file] = suggestedRows(doc);
  for (const [name, li] of [["block row", block], ["allow row", allow]] as const) {
    const line = modeNote(li);
    assert.equal(line?.textContent, IDLE_WORDS, `${name}: the line, word for word Your rules'`);
    assert.ok(line.classList.contains("dim"), `${name}: muted`);
    assert.equal(line.nextElementSibling, li.querySelector(".try-row"), `${name}: just before its Try it`);
  }
  assert.ok(modeNote(allow).previousElementSibling.classList.contains("tag-loosens"), "after the row's tags");
  assert.equal(modeNote(file), null, "a file level decides in this mode: no line");
  assert.equal(doc.querySelectorAll("#describe-result .rule-mode-note").length, 2, "only on the rows, never in the card's head");
  assert.equal(doc.querySelector("#describe-result .suggestion .proposal-k").textContent, "Suggested rules");
});

test("describe: with the integrity axis on, the axes unread, or protection off, no suggested row has the line", async () => {
  for (const [what, answer] of [["full", axes(true, true)], ["unread", { status: 500, body: { error: "down" } }], ["off", axes(false, false)]] as const) {
    const { doc, window } = load({ url: RULES_URL, routes: { "GET config/axes": answer, "POST policy/assistant": SEND_SUGGESTION } });
    await tick();
    await describe(doc, window, "Never send anything to paste sites.");
    await tick();
    assert.equal(suggestedRows(doc).length, 3, `${what}: the rows are drawn`);
    assert.equal(doc.querySelectorAll("#describe-result .rule-mode-note").length, 0, `${what}: no line`);
  }
});

test("describe: in the Secrets mode Try it is still drawn and Apply posts {edits, expected} unchanged", async () => {
  const { doc, window, calls } = load({ url: RULES_URL, routes: { "GET config/axes": axes(false, true), "POST policy/assistant": SEND_SUGGESTION, "POST policy/assistant/apply": { applied: true, changeId: "pc-000264" } } });
  await tick();
  await describe(doc, window, "Never send anything to paste sites. We use PyPI.");
  await tick();
  assert.deepEqual(suggestedRows(doc).map((li) => !!li.querySelector(".try-row")), [true, true, false], "Try it on the tryable rows");
  resultButton(doc, "Apply").click();
  await tick(20);
  const post = calls.find((c) => c.method === "POST" && c.url === "/mandu/api/policy/assistant/apply");
  assert.deepEqual(post!.body, { edits: SEND_SUGGESTION.edits, expected: SEND_SUGGESTION.expected });
});

test("describe: after Discard and its Undo the suggestion drawn again still has the line", async () => {
  const { doc, window } = load({ url: RULES_URL, routes: { "GET config/axes": axes(false, true), "POST policy/assistant": SEND_SUGGESTION } });
  await tick();
  await describe(doc, window, "Never send anything to paste sites.");
  await tick();
  resultButton(doc, "Discard").click();
  assert.equal(doc.querySelectorAll("#describe-result .rule-mode-note").length, 0, "gone with the card");
  resultButton(doc, "Undo").click();
  await tick();
  assert.deepEqual(suggestedRows(doc).map((li) => modeNote(li)?.textContent ?? null), [IDLE_WORDS, IDLE_WORDS, null]);
});

test("describe: if the rows and the edits ever differ in number, no row gets the line rather than a wrong one", async () => {
  const drifted = { ...SEND_SUGGESTION, rows: SEND_SUGGESTION.rows.slice(1) };
  const { doc, window } = load({ url: RULES_URL, routes: { "GET config/axes": axes(false, true), "POST policy/assistant": drifted } });
  await tick();
  await describe(doc, window, "Never send anything to paste sites.");
  await tick();
  assert.equal(suggestedRows(doc).length, 2);
  assert.equal(doc.querySelectorAll("#describe-result .rule-mode-note").length, 0);
});
