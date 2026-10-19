/**
 * home-js-names-whole.test — dashboard.md §4.25u *Approvals names things
 * whole*. Until 2026-10-16 only a waiting card's headline and cells kept a
 * name whole (`nameCode`, `.code-whole` up to WHOLE_MAX = 24 characters).
 * The rest of Approvals drew plain codes: headless Chromium broke
 * `uploads.example-storage.net` at its hyphen in an *Answered earlier* row
 * at 980 px, and a program's send listed its files as plain codes with the
 * hosts they may go to as text, under a headline and cells that draw each
 * file and host as code. Now every name the page draws there is kept whole
 * when it is short:
 *
 *   W1  *What the program holds*: each file, the copy it came from, the
 *       hosts it may go to and the line naming the files left, as code,
 *       short ones whole; a folder rule's "files in" is words; the text
 *       reads exactly as the strings;
 *   W2  an older server (strings only): the file one code (kept whole when
 *       short), the hosts and the line as text, as before;
 *   W3  *Answered earlier*: the sentence's names, short ones whole, a long
 *       one plain; the words unchanged;
 *   W4  a rule-change request's rows and what it would let, and *Rule
 *       changes* rows: each name through nameCode;
 *   W5  Rules › Describe what you want: the suggested rows and what they
 *       would let, the same;
 *   W6  data is never markup: a name holding tags is text.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, net-proxy verdict and
 * dashboard, tests/stack/approvals-names-whole.test.ts. Axes: none (display
 * only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const RULES = "http://127.0.0.1:4500/mandu/rules";
const PENDING = "GET policy/proposals?status=pending";
const CHANGES = "GET policy/changes?limit=21";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
/** Each code under `node` as `[text]` when kept whole, `text` when not. */
const codes = (node: El): string[] => [...node.querySelectorAll("code")].map((c: El) => {
  assert.ok(c.className === "" || c.className === "code-whole", `only .code-whole is added: ${c.className}`);
  return c.className === "code-whole" ? `[${c.textContent}]` : c.textContent;
});
const T = (text: string) => ({ kind: "text", text });
const C = (text: string) => ({ kind: "code", text });
const words = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

const H = "hooks.slack.com";
const LONG_HOST = "uploads.a-very-long-subdomain-name.example.com";
const LONG_FILE = "/srv/shared/projects/acme/deploy/token";
/** One file of a program's send as the server words it, parts and strings. */
const source = (path: string, nameParts: ReturnType<typeof T>[], mayGoParts: ReturnType<typeof T>[], over: Record<string, unknown> = {}) => ({
  path, name: words(nameParts), nameParts, mayGo: words(mayGoParts), mayGoParts, blocks: true, ...over,
});
const SOURCES = [
  source("/home/u/mandu-try/.env", [C("~/mandu-try/.env")], [T("may go nowhere")], { noAlways: "Each value in it has its own hosts." }),
  source("/home/u/mandu-try/deploy.token", [C("~/mandu-try/deploy.token")], [T("may go to: "), C("db.internal:5432"), T(", "), C("deploy.example.com"), T(", "), C(LONG_HOST)], { always: `Always: add ${H} to deploy.token` }),
  source("/home/u/keys", [T("files in "), C("~/keys")], [T("may go nowhere")], { noAlways: "Its rule covers a whole folder." }),
  source(LONG_FILE, [C(LONG_FILE)], [T("may go to: "), C(H)], { via: "~/out/copy.txt", blocks: false }),
];
const LEFT = [T("The send goes once every file may go to "), C(H), T(". Still in the way: "), C("~/mandu-try/.env"), T(", "), C("~/mandu-try/deploy.token"), T(".")];
const HOLDER = {
  ...ASK, id: "egr-2",
  sentence: [T("Claude Code's program wants to send data from "), C("~/mandu-try/.env"), T(" and "), C("~/mandu-try/deploy.token"), T(" to "), C(H)],
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
  sources: SOURCES, sourcesLeft: words(LEFT), sourcesLeftParts: LEFT,
};

test("W1: What the program holds names each file, its copy, its hosts and the files left in code, short ones whole; the words as the strings", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [HOLDER] }) });
  await tick();
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-2"]');
  assert.ok(card, "the card is drawn");
  const what = [...card.querySelectorAll(".ask-source-what")];
  assert.equal(what.length, 4);
  assert.deepEqual(what.map(codes), [
    ["[~/mandu-try/.env]"],
    ["[~/mandu-try/deploy.token]", "[db.internal:5432]", "[deploy.example.com]", LONG_HOST],
    ["[~/keys]"],
    [LONG_FILE, "[~/out/copy.txt]", `[${H}]`],
  ]);
  assert.deepEqual(what.map((x: El) => x.textContent), [
    "~/mandu-try/.env may go nowhere Not to this place.",
    `~/mandu-try/deploy.token may go to: db.internal:5432, deploy.example.com, ${LONG_HOST} Not to this place.`,
    "files in ~/keys may go nowhere Not to this place.",
    `${LONG_FILE} (copied into ~/out/copy.txt) may go to: ${H}`,
  ], "the words read as before");
  assert.equal(what[2].firstChild.nodeType, 3, "a folder rule's 'files in' is words, outside the code");
  const left = card.querySelector(".ask-sources-left");
  assert.equal(left.textContent, HOLDER.sourcesLeft);
  assert.deepEqual(codes(left), [`[${H}]`, "[~/mandu-try/.env]", "[~/mandu-try/deploy.token]"]);
  // The buttons and the reasons are where they were.
  assert.deepEqual([...card.querySelectorAll(".ask-source-always")].map((b: El) => b.textContent), [`Always: add ${H} to deploy.token`]);
  assert.equal(card.querySelectorAll(".ask-source-why").length, 2);
});

test("W2: from an older server (strings only) the file is one code and the hosts and the line are text, as before", async () => {
  const old = {
    ...HOLDER,
    sources: SOURCES.map(({ nameParts: _n, mayGoParts: _m, ...s }) => s),
    sourcesLeftParts: undefined,
  };
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [old] }) });
  await tick();
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-2"]');
  const what = [...card.querySelectorAll(".ask-source-what")];
  assert.deepEqual(what.map(codes), [["[~/mandu-try/.env]"], ["[~/mandu-try/deploy.token]"], ["[files in ~/keys]"], [LONG_FILE, "[~/out/copy.txt]"]]);
  assert.equal(what[1].textContent, `~/mandu-try/deploy.token may go to: db.internal:5432, deploy.example.com, ${LONG_HOST} Not to this place.`);
  const left = card.querySelector(".ask-sources-left");
  assert.equal(left.textContent, HOLDER.sourcesLeft);
  assert.equal(left.querySelector("code"), null, "the line as text");
  assert.equal(left.childNodes.length, 1, "one text node");
});

test("W3: an Answered earlier row keeps its short names whole, as the card it answered did; a long one may wrap", async () => {
  const sentence = [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C("uploads.example-storage.net")];
  const short = [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C("api.stripe-sandbox.example")];
  const answered = [
    { id: "a1", sentence, outcome: "blocked", decidedAt: Date.now() - 60_000, actions: [{ approve: true, scope: "always" }] },
    { id: "a2", sentence: [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C("api.stripe.com")], outcome: "allowed", decidedAt: Date.now() - 90_000, actions: [] },
    { id: "a3", sentence: short, outcome: "blocked", decidedAt: Date.now() - 120_000, actions: [] },
  ];
  const { doc } = load({ url: APPROVALS, homeVm: home({ answered }) });
  await tick();
  const said = (id: string) => [...doc.querySelectorAll("#approvals-answered .row.answered")].find((r: El) => r.dataset.id === id).querySelector(".answered-sentence");
  assert.deepEqual(codes(said("a1")), ["[STRIPE_KEY]", "uploads.example-storage.net"], "27 characters: past WHOLE_MAX, a plain code");
  assert.deepEqual(codes(said("a2")), ["[STRIPE_KEY]", "[api.stripe.com]"]);
  assert.deepEqual(codes(said("a3")), ["[STRIPE_KEY]", "api.stripe-sandbox.example"]);
  assert.equal(said("a1").textContent, words(sentence), "the words unchanged");
});

test("W4: a rule-change request's rows and what it would let, and Rule changes rows, keep their short names whole", async () => {
  const request = {
    id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
    rows: [[T("Let "), C("~/mandu-try/.env"), T(" be sent to "), C("api.stripe.com")]],
    wouldLet: [[T("Your secret file "), C("~/mandu-try/.env"), T(" could be sent to "), C("api.stripe.com")]],
    capped: false, overBroad: false, reason: null,
  };
  const change = {
    id: "pc-000001", sentence: "Mandu noted a program you allowed to read a file",
    rows: [[T("Loosened: "), C("~/mandu-try/deploy.token")], [T("Locked: "), C(LONG_FILE)]],
    createdAt: Date.now() - 60_000, undone: false, undoable: true, session: null,
  };
  const { doc } = load({ url: APPROVALS, homeVm: home({}), routes: { [PENDING]: { proposals: [request] }, [CHANGES]: { changes: [change] } } });
  await tick(40);
  const card = doc.querySelector('#approvals-proposals .proposal[data-id="pp-000001"]');
  assert.ok(card, "the request is drawn");
  assert.deepEqual(codes(card.querySelector(".proposal-rows")), ["[~/mandu-try/.env]", "[api.stripe.com]"]);
  assert.deepEqual(codes(card.querySelector(".proposal-let")), ["[~/mandu-try/.env]", "[api.stripe.com]"]);
  assert.equal(card.querySelector(".proposal-rows li").textContent, "Let ~/mandu-try/.env be sent to api.stripe.com");
  const row = doc.querySelector('#approvals-rule-history .row[data-id="pc-000001"]');
  assert.ok(row, "the change is drawn");
  assert.deepEqual(codes(row.querySelector(".proposal-let")), ["[~/mandu-try/deploy.token]", LONG_FILE]);
  assert.deepEqual([...row.querySelectorAll(".proposal-let li")].map((li: El) => li.textContent), ["Loosened: ~/mandu-try/deploy.token", `Locked: ${LONG_FILE}`]);
});

test("W5: Rules › Describe what you want: the suggested rows and what they would let keep their short names whole", async () => {
  const suggestion = {
    model: "claude-haiku-4-5", note: "",
    rows: [
      { parts: [T("Make "), C("~/mandu-try/.env"), T(" a secret no AI may read")], loosens: false, overBroad: false },
      { parts: [T("Trust content from "), C("https://pypi.org/simple/some-long-package/")], loosens: true, overBroad: false },
    ],
    loosens: [{ line: [T("Content from "), C("https://pypi.org/")], }],
    edits: [], expected: [],
  };
  const { doc, window } = load({ url: RULES, routes: { "POST policy/assistant": suggestion } });
  await tick();
  doc.getElementById("describe-text").value = "Keep my .env secret. We use PyPI.";
  doc.getElementById("describe-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  const card = doc.querySelector("#describe-result .suggestion");
  assert.ok(card, "the suggestion is drawn");
  assert.deepEqual(codes(card.querySelector(".suggestion-rows")), ["[~/mandu-try/.env]", "https://pypi.org/simple/some-long-package/"]);
  assert.deepEqual(codes(card.querySelector(".proposal-let")), ["[https://pypi.org/]"]);
  assert.equal(card.querySelector(".suggestion-rows li").textContent, "Make ~/mandu-try/.env a secret no AI may read");
});

test("W6: a name holding markup is drawn as its text, never as markup", async () => {
  const evil = "<img src=x onerror=1>";
  const ask = { ...HOLDER, sources: [source("/x", [C(evil)], [T("may go to: "), C(evil)])], sourcesLeftParts: [T("Still: "), C(evil)], sourcesLeft: `Still: ${evil}` };
  const answered = [{ id: "a1", sentence: [T("Sent "), C(evil)], outcome: "blocked", decidedAt: Date.now(), actions: [] }];
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [ask], answered }) });
  await tick();
  assert.equal(doc.querySelector("#page-approvals img"), null, "no element from a name");
  assert.deepEqual(codes(doc.querySelector(".ask-source-what")), [`[${evil}]`, `[${evil}]`]);
  assert.deepEqual(codes(doc.querySelector(".ask-sources-left")), [`[${evil}]`]);
  assert.deepEqual(codes(doc.querySelector("#approvals-answered .answered-sentence")), [`[${evil}]`]);
});
