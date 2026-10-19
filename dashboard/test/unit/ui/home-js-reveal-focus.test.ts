/**
 * home-js-reveal-focus.test — the agent page's reveal buttons keep the
 * keyboard focus through their request (public/js/home.js `secretValueBox`,
 * `promptReveal`, `focusBack`; dashboard.md §4.25b *Show the real value
 * keeps the focus*).
 *
 * "Show the real value" (a Your secrets card, a masked step) and a prompt
 * filter's "Show what was hidden" go off while they ask the server, and a
 * browser drops the focus of a button turned off to the page (<body>).
 * Until 2026-10-14 a headless Chromium left the focus there once the value
 * showed, and after a refusal too: a screen reader heard neither "Hide it
 * again" nor the refusal, and lost its place on the page. Now:
 *
 *   - the value shown, the button has the focus back, reading "Hide it
 *     again" (named by its secret), open;
 *   - refused, the button has it back, described by the refusal's words;
 *     a retry that works drops them;
 *   - only if it had the focus at the press and the focus fell: a focus the
 *     person moved meanwhile stays, and a press made without the focus
 *     moves nothing;
 *   - "Hide it again" asks nothing, so it keeps its focus as before.
 *
 * jsdom keeps the focus of a button turned off; `press` drops it, as
 * Chromium does (home-js-suggested-focus.test.ts). Drives the PRODUCT page
 * script in jsdom over the shared fetch stub (home-js-fixtures.ts); across
 * the real arbiter, proxy and dashboard, tests/stack/reveal-focus.test.ts.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, M, T, load, tick } from "./home-js-fixtures.js";

const PAGE = "http://127.0.0.1:4500/mandu/agents/s1";
const HIDE = "Hide it again";
const VALUE = "sk-reveal-focus-VALUE";
const REFUSAL = "the protection service no longer holds its value";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const code = (text: string) => ({ kind: "code", text });
const STEP = {
  kind: "action", id: "t1", ts: "2026-09-25T10:00:02.000Z", icon: "file", sentence: [T("Read "), code(".env")], outcome: "secret", note: null,
  split: { ai: [T("Got "), M("secret"), T(" in place of the result.")], real: [T("The result held your secret "), code(".env"), T(".")],
    hidden: { text: null, secret: true, truncated: false, secrets: [{ ref: "aaaaaaaaaaaaaaaaaaaaaaa1", name: ".env" }] } },
};
const CARD = { what: [T("The file "), code("~/ws/.env")], level: "No AI", saw: "masked", lines: [{ tone: "good", parts: [T("The AI got only a placeholder, never the real value.")] }], ref: "bbbbbbbbbbbbbbbbbbbbbbb1" };
const NOTE = {
  lines: ["One value in your prompt was hidden from the AI (an email address)."],
  items: [{ eventId: "ev-1", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: false, canLetSession: false, canShow: true }],
  ts: "2026-09-25T10:00:00.000Z",
};
/** The agent page of s1: one secret step and its Your secrets card, and a
 *  prompt filter's note under the first question. */
function agentPage(): unknown {
  const page = JSON.parse(JSON.stringify(AGENT));
  page.story = [{ ...page.story[0], steps: [STEP], promptNote: NOTE }];
  page.secrets = { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: 0 }, secrets: [CARD] };
  return page;
}
/** The page, its reveal routes answered by `secret` and `prompt` (an
 *  answer, `{status, body}`, or a function of the posted body). */
function open(secret: unknown, prompt: unknown = { original: "me@corp.example" }) {
  return load({ url: PAGE, routes: { "GET home/agent?session=s1": agentPage(), "POST home/reveal": secret, "POST prompt-filters/reveal": prompt } });
}
const cardButton = (doc: Doc) => doc.querySelector("#agent-secrets .secret-card button.secret-reveal");
const stepButton = (doc: Doc) => doc.querySelector("#agent-story .step.split button.secret-reveal");
const promptButton = (doc: Doc) => doc.querySelector("#agent-story .prompt-note-item button.prompt-reveal");
const nameOf = (b: Doc): string => b.getAttribute("aria-label") ?? b.textContent;
const describedBy = (doc: Doc, b: Doc): string | null => {
  const id = b.getAttribute("aria-describedby");
  return id ? doc.getElementById(id)?.textContent ?? `(no #${id})` : null;
};

/** Enter on a button that goes off while it acts: Chromium drops its focus. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it asks");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** An answer the test lets go of when it wants. */
function held() {
  let release: (v: unknown) => void = () => {};
  const answer = new Promise((r) => { release = r; });
  return { route: () => answer, release };
}

test("Show the real value on a Your secrets card and on a step: once the value shows, the button has the focus back, reading Hide it again", async () => {
  const { doc, err } = open({ value: VALUE });
  assert.equal(err, null);
  await tick(40);
  for (const pick of [cardButton, stepButton]) {
    const btn = pick(doc);
    const box = btn.parentElement.querySelector("pre.secret-value");
    press(btn);
    await tick(40);
    assert.equal(box.hidden, false);
    assert.equal(box.textContent, VALUE);
    assert.equal(doc.activeElement, btn, "the focus is back on the button pressed");
    assert.equal(btn.disabled, false);
    assert.equal(btn.textContent, HIDE);
    assert.ok(nameOf(btn).startsWith(`${HIDE}: `), `named by its secret: ${nameOf(btn)}`);
    assert.equal(btn.getAttribute("aria-expanded"), "true");
    assert.equal(btn.getAttribute("aria-describedby"), null, "nothing was refused");
  }
  // Hide it again asks nothing: the button keeps its focus, and the value goes.
  const btn = cardButton(doc);
  const box = btn.parentElement.querySelector("pre.secret-value");
  btn.focus();
  btn.click();
  assert.equal(doc.activeElement, btn);
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(box.textContent, "", "the card's value left the page");
});

test("a refused Show the real value gives the focus back, described by the refusal's words; a retry that works drops them", async () => {
  let calls = 0;
  const { doc } = open(() => (++calls === 1 ? { status: 404, body: { error: REFUSAL } } : { status: 200, body: { value: VALUE } }));
  await tick(40);
  const btn = cardButton(doc);
  press(btn);
  await tick(40);
  assert.equal(doc.activeElement, btn, "the focus is back on the button pressed");
  assert.equal(btn.disabled, false);
  assert.equal(btn.getAttribute("aria-expanded"), "false", "nothing shown");
  const said = describedBy(doc, btn);
  assert.ok(said && said.includes(REFUSAL), `described by the refusal: ${said}`);
  assert.equal(doc.querySelectorAll("#agent-secrets [id^='ask-error-']").length, 1, "one line of words");
  press(btn);
  await tick(40);
  assert.equal(doc.activeElement, btn);
  assert.equal(btn.textContent, HIDE);
  assert.equal(btn.getAttribute("aria-describedby"), null, "the value shows: the refusal no longer describes it");
});

test("a focus the person moved while the value was on its way stays; a press made without the focus moves nothing", async () => {
  const h = held();
  const { doc } = open(h.route);
  await tick(40);
  const btn = cardButton(doc);
  press(btn);
  const back = doc.querySelector("#page-agent a.back");
  back.focus();
  h.release({ value: VALUE });
  await tick(40);
  assert.equal(btn.textContent, HIDE, "the value shows");
  assert.equal(doc.activeElement, back, "the focus stays where the person put it");

  // A press without the focus (a pointer that does not focus, a script).
  const h2 = held();
  const page2 = open(h2.route);
  await tick(40);
  const btn2 = cardButton(page2.doc);
  page2.doc.activeElement?.blur?.();
  btn2.click();
  assert.equal(btn2.disabled, true);
  h2.release({ value: VALUE });
  await tick(40);
  assert.equal(btn2.textContent, HIDE);
  assert.equal(page2.doc.activeElement, page2.doc.body, "nothing took the focus");
});

test("a prompt filter's Show what was hidden: the focus is back once the text shows, and after a refusal, described by it", async () => {
  const { doc } = open({ value: VALUE }, { original: "me@corp.example" });
  await tick(40);
  const btn = promptButton(doc);
  const pre = doc.querySelector("#agent-story .prompt-hidden-text");
  press(btn);
  await tick(40);
  assert.equal(pre.hidden, false);
  assert.equal(pre.textContent, "me@corp.example");
  assert.equal(doc.activeElement, btn, "the focus is back on the button pressed");
  assert.equal(btn.textContent, HIDE);
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(btn.getAttribute("aria-describedby"), null);

  const refused = open({ value: VALUE }, { status: 403, body: { error: "sign in first" } });
  await tick(40);
  const b2 = promptButton(refused.doc);
  press(b2);
  await tick(40);
  assert.equal(refused.doc.activeElement, b2, "the focus is back on the button pressed");
  assert.equal(b2.getAttribute("aria-expanded"), "false");
  const said = describedBy(refused.doc, b2);
  assert.ok(said && /sign in/i.test(said), `described by the refusal: ${said}`);
});
