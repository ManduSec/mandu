/**
 * home-js-ask-names.test — dashboard.md §4.25u *The cells name things as the
 * headline does*. Until 2026-10-16 an Approvals card drew its three cells,
 * and Home's short card its why, as one text node: headless Chromium showed
 * `STRIPE_KEY` and `api.stripe.com` as code in the headline and the same
 * key, its file and the host as text under it, and broke "~/mandu-" /
 * "try/.env" at its hyphen (Approvals at 980 and 320 px, Home at 320 px).
 * Now the server sends each cell as parts too (`whyParts`, …) and home.js
 * draws each name as code, kept on one line when it is short.
 *
 *   N1  nameCode alone: a <code> of the text as given, `.code-whole` up to
 *       WHOLE_MAX (24) characters, plain past it; askCellWords: the parts,
 *       or an older server's text as one text node;
 *   N2  the Approvals card: each cell draws its names as code, short ones
 *       whole and a long one not; the words read as the strings; a count
 *       keeps its word; the headline's short names are whole too;
 *   N3  Home's short card: its why line names the same things;
 *   N4  an older server (strings only): the cells and the why line are
 *       plain text, as before;
 *   N5  data is never markup: a name holding tags is text;
 *   N6  app.css: a name in a card wraps anywhere when it is long (`.ask
 *       code`), and `.code-whole` never wraps.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, stripComments } from "./css-flatten.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
/** Each code under `node` as `[text]` when kept whole, `text` when not. */
const codes = (node: El): string[] => [...node.querySelectorAll("code")].map((c: El) => {
  assert.ok(c.className === "" || c.className === "code-whole", `only .code-whole is added: ${c.className}`);
  assert.equal(c.children.length, 0, "a code holds its text only");
  return c.className === "code-whole" ? `[${c.textContent}]` : c.textContent;
});

const T = (text: string) => ({ kind: "text", text });
const C = (text: string) => ({ kind: "code", text });
const LONG = "/usr/lib/node_modules/npm/bin/npm-cli.js running ~/proj/scripts/deploy.mjs";
/** A send of a named key, as describeAsk words it (the parts and their strings). */
const PARTS = {
  whyParts: [C("STRIPE_KEY"), T(" comes from "), C("~/mandu-try/.env"), T(". Mandu masked it, so the AI never read it. Sending it would show the real secret to "), C("api.stripe.com"), T(".")],
  aiNowParts: [T("The AI read "), C("~/memos/q3.md"), T(", "), C(LONG), T(" and 2 more as they are.")],
  ifAllowedParts: [T("The AI's next request goes to "), C("api.stripe.com"), T(" with the real secret filled in.")],
};
const join_ = (parts: { text: string }[]) => parts.map((p) => p.text).join("");
const SEND = {
  ...ASK,
  sentence: [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C("api.stripe.com")],
  why: join_(PARTS.whyParts), aiNow: join_(PARTS.aiNowParts), ifAllowed: join_(PARTS.ifAllowedParts),
  ...PARTS,
};

test("N1: nameCode keeps a name of up to 24 characters whole and draws a longer one plain; askCellWords draws the parts, or the text as before", () => {
  const { window, doc } = load();
  for (const [name, whole] of [["STRIPE_KEY", true], ["~/mandu-try/.env", true], ["x".repeat(24), true], ["a b", true], ["x".repeat(25), false], [LONG, false]] as const) {
    const c = window.nameCode(name);
    assert.equal(c.tagName, "CODE");
    assert.equal(c.textContent, name, "the text as given");
    assert.equal(c.className, whole ? "code-whole" : "", `${name}: ${whole ? "whole" : "plain"}`);
  }
  const host = doc.createElement("div");
  host.append(window.askCellWords(PARTS.whyParts, "ignored when there are parts"));
  assert.equal(host.textContent, SEND.why);
  assert.deepEqual(codes(host), ["[STRIPE_KEY]", "[~/mandu-try/.env]", "[api.stripe.com]"]);
  for (const none of [undefined, null, []]) {
    const plain = window.askCellWords(none, "A why from an older server, 2 requests.");
    assert.equal(plain.nodeType, 3, "one text node");
    assert.equal(plain.data, "A why from an older server, 2 requests.");
  }
});

test("N2: an Approvals card's cells name things as code, as its headline does; short names whole, a long one not; the words unchanged", async () => {
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [SEND] }) });
  await tick();
  const card = doc.querySelector("#approvals-waiting .ask");
  assert.ok(card, "the card is drawn");
  const head = card.querySelector(".ask-sentence");
  assert.deepEqual(codes(head), ["[STRIPE_KEY]", "[api.stripe.com]"], "the headline's names, kept whole");
  const v = [...card.querySelectorAll(".ask-detail .v")];
  assert.equal(v.length, 3);
  assert.deepEqual(v.map((x: El) => x.textContent), [SEND.why, SEND.aiNow, SEND.ifAllowed], "the words read as the strings");
  assert.deepEqual(codes(v[0]), ["[STRIPE_KEY]", "[~/mandu-try/.env]", "[api.stripe.com]"]);
  assert.deepEqual(codes(v[1]), ["[~/memos/q3.md]", LONG], "a long name may wrap");
  assert.deepEqual(codes(v[2]), ["[api.stripe.com]"]);
  assert.deepEqual([...v[1].querySelectorAll(".count-word")].map((x: El) => x.textContent), ["2 more"], "a count keeps its word");
  // The help next to "masked" and the labels are where they were.
  assert.ok(v[1].previousElementSibling.querySelector(".help-btn"), "the help button by What the AI has now");
  assert.deepEqual([...card.querySelectorAll(".ask-detail .k")].map((k: El) => k.firstChild.textContent), ["Why it stopped", "What the AI has now", "If you click Allow once or Always allow"]);
});

test("N3: Home's short card names the same things in its why line", async () => {
  const { doc } = load({ homeVm: home({ waiting: [SEND] }) });
  await tick();
  const sub = doc.querySelector("#home-waiting .ask .ask-sub");
  assert.ok(sub, "the short card is drawn");
  assert.ok(sub.textContent.startsWith(SEND.why + " "), sub.textContent);
  assert.deepEqual(codes(sub), ["[STRIPE_KEY]", "[~/mandu-try/.env]", "[api.stripe.com]"]);
  assert.ok(sub.querySelector("time"), "the moment follows");
  assert.equal(sub.querySelector("a.ask-details").textContent, "Details in Approvals");
});

test("N4: from an older server (strings only) the cells and the why line are plain text, as before", async () => {
  const old = { ...SEND, whyParts: undefined, aiNowParts: undefined, ifAllowedParts: undefined };
  const approvals = load({ url: APPROVALS_URL, homeVm: home({ waiting: [old] }) });
  await tick();
  const v = [...approvals.doc.querySelectorAll("#approvals-waiting .ask .ask-detail .v")];
  assert.deepEqual(v.map((x: El) => x.textContent), [SEND.why, SEND.aiNow, SEND.ifAllowed]);
  for (const x of v) {
    assert.equal(x.querySelector("code"), null, "no code");
    assert.equal(x.childNodes.length, 1, "one text node");
  }
  const homePage = load({ homeVm: home({ waiting: [old] }) });
  await tick();
  const sub = homePage.doc.querySelector("#home-waiting .ask .ask-sub");
  assert.ok(sub.textContent.startsWith(SEND.why + " "));
  assert.equal(sub.querySelector("code"), null);
});

test("N5: a name holding markup is drawn as its text, never as markup", async () => {
  const evil = "<img src=x onerror=alert(1)>";
  const ask = { ...SEND, whyParts: [C(evil), T(" is a secret file.")], why: `${evil} is a secret file.` };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [ask] }) });
  await tick();
  const v = doc.querySelector("#approvals-waiting .ask .ask-detail .v");
  assert.equal(v.querySelector("img"), null, "no element from the name");
  assert.deepEqual(codes(v), [evil], "28 characters: a plain code");
  assert.equal(v.textContent, ask.why);
});

test("N6: app.css lets a long name in a card wrap anywhere, and never wraps a .code-whole", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const ask = rules.filter((r) => r.media === null && r.selectors.includes(".ask code"));
  assert.ok(ask.some((r) => declValue(r.block, "overflow-wrap") === "anywhere"), ".ask code wraps anywhere when it must");
  const whole = rules.filter((r) => r.media === null && r.selectors.includes("code.code-whole"));
  assert.ok(whole.some((r) => declValue(r.block, "white-space") === "nowrap"), "code.code-whole stays on one line");
});
