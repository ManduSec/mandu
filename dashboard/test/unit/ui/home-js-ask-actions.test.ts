/**
 * home-js-ask-actions.test — a question card's answers wrap inside the card
 * on a phone (dashboard.md §4.25 *A question's buttons wrap inside its
 * card*). Mandu-new.
 *
 * Every card that asks the person something ends in one row of answer
 * buttons, `.ask-actions`: a wrapping flex row that never shrinks (on Home's
 * wide card the words give way, not the buttons). Until 2026-10-14 nothing
 * bounded it, so it was as wide as all its buttons on one line and its wrap
 * never happened. A headless Chromium with the page's own styles measured a
 * held message's four answers on Approvals 365 px past the card at 390 px
 * (the page scrolled sideways to 714 px, Send masked off screen), Home's
 * three 124 px past, and a send's Block cut at the screen's edge at 320 px.
 *
 * jsdom has no layout, so this pins the rule that fixes it, on the page's
 * own styles at 390 px (mandu.css + app.css, their phone rules applied):
 *   - the stylesheet: the row wraps, never shrinks and is never wider than
 *     its own row (`max-width: 100%`); no rule of the page wraps its
 *     children while it never shrinks without such a bound;
 *   - every card home.js draws with answers (Home and Approvals: a send, a
 *     held message, a program's send; the agent page's Needs your OK; a rule
 *     change your agent asked for; the possible-keys card; a suggested
 *     rule's Discard and Apply) draws them in an `.ask-actions` with no
 *     inline style, which computes that rule.
 * The layout itself is the run's Chromium probe (before: up to 435 px past
 * the card; after: none at 320 to 1280 px, a desktop unchanged).
 *
 * Also beside the answers: Home's short card of a send says which of them
 * cover only the next such request and which are kept until changed under
 * Rules (dashboard.md §4.34, *Home's card says which answers last*), the
 * server's `answersShortParts` on a line of its own before *Details in
 * Approvals*; the expanded card on Approvals says it in full instead.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, AGENT, FILES_ROUTES, PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const RULES = flattenCss(stripComments(CSS));

/** The page's own styles as a 390 px phone applies them (jsdom cascades
 *  them, but applies no width query). */
function styled(doc: El): void {
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(CSS, 390));
  doc.head.append(sheet);
}

/** The one declaration of `prop` for `selector` outside any @media. */
function decl(selector: string, prop: string): string {
  const found = RULES.filter((r) => r.media === null && r.selectors.includes(selector)).map((r) => declValue(r.block, prop)).filter((v) => v !== null);
  assert.equal(found.length, 1, `${selector} declares ${prop} once: ${JSON.stringify(found)}`);
  return found[0]!;
}

/** The answers of each card under `root`: drawn in the card's
 *  `.ask-actions`, no inline style, computing a row that wraps inside the
 *  card. Answers each card's button words, in order. */
function answersOf(root: El, cards: string): string[][] {
  const win = root.ownerDocument.defaultView;
  const found = [...root.querySelectorAll(cards)] as El[];
  assert.ok(found.length > 0, `cards drawn: ${cards}`);
  return found.map((card) => {
    const rows = [...card.querySelectorAll(".ask-actions")] as El[];
    assert.equal(rows.length, 1, "one row of answers per card");
    const row = rows[0];
    assert.equal(row.getAttribute("style"), null, "no inline style: the stylesheet decides");
    const cs = win.getComputedStyle(row);
    assert.equal(cs.display, "flex");
    assert.equal(cs.flexWrap, "wrap", "the buttons wrap");
    assert.equal(cs.flexShrink, "0", "beside the words on a wide card, the words give way");
    assert.equal(cs.maxWidth, "100%", "never wider than its row, so on a phone the wrap happens inside the card");
    const words = [...row.querySelectorAll("button")].map((b: El) => b.textContent);
    assert.ok(words.length > 0, "the row holds the card's answers");
    return words;
  });
}

const HOLDS = { "GET prompt-filters/holds": { holds: [] } };
const PROMPT_ASK = {
  ...ASK, id: "egr-6", family: "prompt",
  sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI. It holds " }, { kind: "code", text: "acme.codename" }, { kind: "text", text: "." }],
  actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
};
const HOLDER = {
  ...ASK, id: "egr-7",
  sentence: [{ kind: "text", text: "Claude Code's program wants to send data from " }, { kind: "code", text: "~/ws/app/.env" }, { kind: "text", text: " to " }, { kind: "code", text: "hooks.slack.com" }],
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
};
const SEND = ["Allow once", "Always allow", "Block"];

const PROPOSAL = {
  id: "pp-000009", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Make " }, { kind: "code", text: "~/proj/.env" }, { kind: "text", text: " a secret no AI may read, may be sent to " }, { kind: "code", text: "api.stripe.com" }]],
  wouldLet: [[{ kind: "code", text: "~/proj/.env" }, { kind: "text", text: " would be protected less" }]],
  capped: false, overBroad: false, reason: "deploy needs it",
};
const KEY: SuggestionWire = {
  id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-1", source: "git-history", repoRoot: "/home/u/proj",
  edits: [{ op: "lock-path", path: "/home/u/proj/deploy/id_rsa", level: "no-model" }],
  sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
  evidence: {
    paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: true,
    findings: [{ blob: "a".repeat(40), paths: ["deploy/id_rsa"], firstCommit: "1111111aaaa", lastCommit: "2222222bbbb", inHead: false, inIndex: false, stillPresent: false,
      detectors: [{ kind: "content-shape", rule: "private-key", mask: "(key block header)…", words: "private key", line: 1 }] }],
  },
  impact: { historicalVersions: 2, workingTreeChanges: false, files: [] },
  historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
} as SuggestionWire;
const SUGGESTIONS = { suggestions: suggestionRows([KEY], "/home/u", "linux"), count: 1, scan: null };
const RULE_SUGGESTION = {
  model: "claude-haiku-4-5", note: "",
  rows: [{ parts: [{ kind: "text", text: "Lock " }, { kind: "code", text: "~/.ssh" }, { kind: "text", text: " (keep secret, never shown to the AI)" }], loosens: false, overBroad: false }],
  loosens: [], edits: [{ op: "lock-path", path: "~/.ssh", level: "no-model" }], expected: [],
};

test("the stylesheet: the answers' row wraps, never shrinks, and is never wider than its own row", () => {
  assert.equal(decl(".ask-actions", "display"), "flex");
  assert.equal(decl(".ask-actions", "flex-wrap"), "wrap");
  assert.equal(decl(".ask-actions", "flex-shrink"), "0");
  assert.equal(decl(".ask-actions", "max-width"), "100%", "without it the row is all its buttons on one line, wider than a phone's card");
  assert.equal(RULES.some((r) => r.media !== null && r.selectors.includes(".ask-actions") && declValue(r.block, "max-width") !== null), false,
    "no phone rule takes the bound away");
});

test("the stylesheet: no rule wraps its children while it never shrinks, unless a max-width bounds it", () => {
  // A wrapping row that never shrinks is as wide as its children on one
  // line; wherever they are wider than its row, it runs past it and the wrap
  // it asks for never happens.
  const both = RULES.filter((r) => declValue(r.block, "flex-wrap") === "wrap" && declValue(r.block, "flex-shrink") === "0");
  assert.ok(both.some((r) => r.selectors.includes(".ask-actions")), "the answers' row is one (the sweep is not empty)");
  for (const r of both) {
    const max = declValue(r.block, "max-width");
    assert.ok(max !== null && max !== "none", `${r.selectors.join(", ")}${r.media ? ` (${r.media})` : ""} wraps and never shrinks, with no max-width`);
  }
});

test("Home: a send's and a held message's answers wrap inside their cards", async () => {
  const vm = home({ waiting: [ASK, PROMPT_ASK], window: { ...home().window, waiting: 2 } });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/", homeVm: vm, routes: HOLDS });
  styled(doc);
  await tick();
  assert.deepEqual(answersOf(doc.getElementById("home-waiting"), ".ask"), [SEND, ["Send as written", "Send masked", "Cancel the message"]]);
});

test("Approvals: a send's, a held message's four and a program's send's answers wrap inside their cards", async () => {
  const vm = home({ waiting: [ASK, PROMPT_ASK, HOLDER], window: { ...home().window, waiting: 3 } });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: vm, routes: HOLDS });
  styled(doc);
  await tick();
  assert.deepEqual(answersOf(doc.getElementById("approvals-waiting"), ".ask.expanded"), [
    SEND,
    ["Send as written", "Send as written for this session", "Send masked", "Cancel the message"],
    ["Allow once", "Allow this session", "Block"],
  ]);
});

test("Approvals: a rule change your agent asked for and the possible-keys card", async () => {
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { ...FILES_ROUTES, "GET policy/proposals?status=pending": { proposals: [PROPOSAL] }, "GET suggestions": SUGGESTIONS },
  });
  styled(doc);
  await tick();
  assert.deepEqual(answersOf(doc.getElementById("approvals-proposals"), ".ask.proposal"), [["Allow", "Not now"]]);
  assert.deepEqual(answersOf(doc.getElementById("approvals-suggestions"), ".ask.suggestion-card"), [["Review them"]]);
});

test("the agent page: Needs your OK", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, waiting: [ASK] } } });
  styled(doc);
  await tick();
  assert.deepEqual(answersOf(doc.getElementById("agent-waiting"), ".ask.expanded"), [SEND]);
});

test("Rules: a suggested rule's Discard and Apply", async () => {
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "POST policy/assistant": RULE_SUGGESTION } });
  styled(doc);
  await tick();
  doc.getElementById("describe-text").value = "Keep ~/.ssh secret.";
  doc.getElementById("describe-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(answersOf(doc.getElementById("describe-result"), ".ask.suggestion"), [["Discard", "Apply"]]);
});

const LASTING = {
  ...ASK, id: "egr-8",
  sentence: [{ kind: "text", text: "Claude Code wants to send your secret " }, { kind: "code", text: "STRIPE_KEY" }, { kind: "text", text: " to " }, { kind: "code", text: "api.stripe.com" }],
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" }, { approve: false, label: "Send without it", scope: "once", strip: true }, { approve: false, label: "Block" }],
  ifStanding: "Mandu remembers it for STRIPE_KEY and api.stripe.com only. You can change it under Rules.",
  ifStandingParts: [{ kind: "text", text: "Mandu remembers it for " }, { kind: "code", text: "STRIPE_KEY" }, { kind: "text", text: " and " }, { kind: "code", text: "api.stripe.com" }, { kind: "text", text: " only. You can change it under " }, { kind: "link", text: "Rules", to: "your-rules" }, { kind: "text", text: "." }],
  answersShort: "Allow once and Send without it cover only the next such request. Always allow and Block are kept for STRIPE_KEY and api.stripe.com until you change them under Rules.",
  answersShortParts: [
    { kind: "text", text: "Allow once and Send without it cover only the next such request. Always allow and Block are kept for " }, { kind: "code", text: "STRIPE_KEY" },
    { kind: "text", text: " and " }, { kind: "code", text: "api.stripe.com" }, { kind: "text", text: " until you change them under " }, { kind: "link", text: "Rules", to: "your-rules" }, { kind: "text", text: "." },
  ],
};

test("Home: a send's short card says which answers last, on a line of its own before Details in Approvals, Rules a link", async () => {
  const vm = home({ waiting: [LASTING, ASK], window: { ...home().window, waiting: 2 } });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/", homeVm: vm, routes: HOLDS });
  await tick();
  const card = doc.querySelector('#home-waiting .ask[data-id="egr-8"]');
  const line = card.querySelector(".ask-sub .ask-answers");
  assert.ok(line, "the line is drawn in the card's sub line");
  assert.equal(line.textContent, LASTING.answersShort);
  assert.deepEqual([...line.querySelectorAll("code")].map((c: El) => c.textContent), ["STRIPE_KEY", "api.stripe.com"], "the names as code");
  const details = card.querySelector(".ask-sub .ask-details");
  assert.equal(details.textContent, "Details in Approvals");
  assert.ok(line.compareDocumentPosition(details) & 4, "before Details in Approvals");
  assert.equal(line.nextElementSibling, details, "the link right after it");
  assert.match(card.querySelector(".ask-sub").textContent, /\. Allow once and Send without it cover .* under Rules\. Details in Approvals$/, "words apart from the moment and the link");
  const rules = line.querySelector("a");
  assert.equal(rules.textContent, "Rules");
  assert.match(rules.getAttribute("href"), /\/rules#your-rules$/);
  // It names only the buttons the card draws.
  const buttons = [...card.querySelectorAll(".ask-actions button")].map((b: El) => b.textContent);
  assert.deepEqual(buttons, ["Allow once", "Always allow", "Send without it", "Block"]);
  const named = /^(.+?) cover only .*?\. (.+?) are kept/.exec(line.textContent)!;
  for (const verb of [...named[1]!.split(" and "), ...named[2]!.split(" and ")]) assert.ok(buttons.includes(verb), `${verb} is a button of the card`);
  // A card without the words (another family, an older server) has none,
  // and its sub line reads as before.
  const plain = doc.querySelector('#home-waiting .ask[data-id="egr-1"]');
  assert.equal(plain.querySelector(".ask-answers"), null);
  assert.match(plain.querySelector(".ask-sub").textContent, /\. Details in Approvals$/);
  // The stylesheet puts it on a line of its own.
  assert.equal(decl(".ask-sub .ask-answers", "display"), "block");
});

test("Approvals: the expanded card does not draw the short line; it says it in full", async () => {
  const vm = home({ waiting: [LASTING], window: { ...home().window, waiting: 1 } });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: vm, routes: HOLDS });
  await tick();
  const card = doc.querySelector('#approvals-waiting .ask.expanded[data-id="egr-8"]');
  assert.ok(card, "Approvals draws the card expanded");
  assert.equal(card.querySelector(".ask-answers"), null);
  assert.ok(card.querySelector(".ask-standing"), "#144's full line instead");
});
