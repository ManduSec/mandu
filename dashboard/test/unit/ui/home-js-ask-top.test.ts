/**
 * home-js-ask-top.test — a question card with a short sentence keeps its
 * icon beside its words (dashboard.md §4.25 *A short question keeps its icon
 * beside its words*). Mandu-new.
 *
 * Every question card draws a header row: the icon (40 px), then the words
 * (`.ask-body`, a 320 px flex basis), 20 px apart, in a row that wraps. A
 * browser sizes that row by its own width before laying it out (a column
 * flex item at fit-content, a row flex item at max-content): the icon, the
 * gap and the sentence's own width. A sentence shorter than 320 px made it
 * narrower than the three, so it wrapped. Until 2026-10-12 a headless
 * Chromium drew Approvals' "Your agent wants to change a rule" and "Claude
 * Code wants to run curl" with a 109 px header holding 49 px of content:
 * the row measured wrapped, then stretched to the card, an empty band above
 * and below the sentence.
 *
 * jsdom has no layout, so this pins the rule that fixes it, on the page's
 * own styles (mandu.css + app.css applied):
 *   - the stylesheet's arithmetic: `.ask-top`'s min-width is the icon's
 *     width, the gap and the words' basis, never less (or the card's width);
 *   - every card that draws an icon (Home, Approvals' waiting cards, a rule
 *     change your agent asked for, the possible-keys card, the agent page's
 *     Needs your OK) draws it in an `.ask-top` with no inline style, which
 *     computes that min-width.
 * The layout itself is the run's Chromium probe (before: 109 px; after:
 * 49 px; a phone's card as before).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, AGENT, FILES_ROUTES, PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments } from "./css-flatten.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const RULES = flattenCss(stripComments(CSS));

/** The page's own styles, applied (jsdom cascades them). */
function styled(doc: El): void {
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(CSS);
  doc.head.append(sheet);
}

/** The one declaration of `prop` for `selector` outside any @media. */
function decl(selector: string, prop: string): string {
  const found = RULES.filter((r) => r.media === null && r.selectors.includes(selector)).map((r) => declValue(r.block, prop)).filter((v) => v !== null);
  assert.equal(found.length, 1, `${selector} declares ${prop} once: ${JSON.stringify(found)}`);
  return found[0]!;
}

const px = (v: string) => {
  const m = /^(\d+)px$/.exec(v);
  assert.ok(m, `a length in px: ${v}`);
  return Number(m![1]);
};

const MIN_WIDTH = "min(100%, 380px)";

/** Each card under `root` that draws an icon draws it in its `.ask-top`:
 *  no inline style, a wrapping flex row that computes the min-width. */
function headersOf(root: El, cards: string): El[] {
  const win = root.ownerDocument.defaultView;
  const found = [...root.querySelectorAll(cards)] as El[];
  assert.ok(found.length > 0, `cards drawn: ${cards}`);
  return found.map((card) => {
    const icon = card.querySelector(".ask-icon");
    assert.ok(icon, "the card has its icon");
    const top = icon.parentElement;
    assert.equal(top.parentElement, card, "the header row is the card's own child");
    assert.equal(top.className, "ask-top", `the header row of "${card.querySelector(".ask-sentence")?.textContent}"`);
    assert.equal(top.getAttribute("style"), null, "no inline style: the stylesheet decides");
    assert.ok(top.querySelector(":scope > .ask-body"), "the words beside the icon");
    const cs = win.getComputedStyle(top);
    assert.equal(cs.display, "flex");
    assert.equal(cs.flexWrap, "wrap", "on a phone the icon still goes above the words");
    assert.equal(cs.gap, "20px");
    assert.equal(cs.minWidth, MIN_WIDTH, "never measured narrower than the icon and the words side by side");
    return top;
  });
}

const SHORT = { ...ASK, id: "egr-short", family: "exec",
  sentence: [{ kind: "text", text: "Claude Code wants to run " }, { kind: "code", text: "curl" }] };

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

test("the stylesheet: the header row's min-width is the icon, the gap and the words' basis, or the card's width", () => {
  assert.equal(decl(".ask-top", "display"), "flex");
  assert.equal(decl(".ask-top", "flex-wrap"), "wrap");
  const m = /^min\(100%, (\d+px)\)$/.exec(decl(".ask-top", "min-width"));
  assert.ok(m, "min-width: min(100%, <px>), so a card narrower than that (a phone) still wraps its icon above the words");
  const icon = px(decl(".ask-icon", "width"));
  const gap = px(decl(".ask-top", "gap"));
  const basis = px(decl(".ask-body", "flex").split(/\s+/)[2] ?? "");
  assert.equal(px(m![1]), icon + gap + basis, `the icon (${icon}), the gap (${gap}) and the words' basis (${basis}) side by side`);
  assert.equal(RULES.some((r) => r.selectors.includes(".suggestion-card-top")), false, "the possible-keys card shares the row's rule");
});

test("Home and Approvals: each waiting card, short or long, draws its icon in an .ask-top", async () => {
  const vm = home({ waiting: [SHORT, ASK], window: { ...home().window, waiting: 2 } });
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/", homeVm: vm });
  styled(doc);
  await tick();
  assert.deepEqual(headersOf(doc.getElementById("home-waiting"), ".ask").map((t: El) => t.querySelector(".ask-sentence").textContent),
    ["Claude Code wants to run curl", "Claude Code wants to send text from a file to <img src=x onerror=alert(1)>"]);
  const a = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: vm });
  styled(a.doc);
  await tick();
  assert.equal(headersOf(a.doc.getElementById("approvals-waiting"), ".ask.expanded").length, 2);
});

test("Approvals: a rule change your agent asked for and the possible-keys card draw their icon in an .ask-top", async () => {
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { ...FILES_ROUTES, "GET policy/proposals?status=pending": { proposals: [PROPOSAL] }, "GET suggestions": SUGGESTIONS },
  });
  styled(doc);
  await tick();
  const [proposal] = headersOf(doc.getElementById("approvals-proposals"), ".ask.proposal");
  assert.equal(proposal.querySelector(".ask-sentence").textContent, "Your agent wants to change a rule");
  const [keys] = headersOf(doc.getElementById("approvals-suggestions"), ".ask.suggestion-card");
  assert.match(keys.querySelector(".ask-sentence").textContent, /^Mandu found 1 possible key in /);
});

test("the agent page: Needs your OK draws its icon in an .ask-top", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, waiting: [SHORT] } } });
  styled(doc);
  await tick();
  const [top] = headersOf(doc.getElementById("agent-waiting"), ".ask.expanded");
  assert.equal(top.querySelector(".ask-sentence").textContent, "Claude Code wants to run curl");
});
