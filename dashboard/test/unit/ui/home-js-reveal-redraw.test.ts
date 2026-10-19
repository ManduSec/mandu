/**
 * home-js-reveal-redraw.test — the agent page's reveal answers go to the
 * page drawn now (public/js/home.js `secretValueBox`, `promptReveal`,
 * `revealDrawnNow`; dashboard.md §4.25b *Show the real value keeps the
 * focus*).
 *
 * The agent page is drawn again from nothing when a read brings a changed
 * answer (the agent did more, the protection service stopped), also while
 * "Show the real value" or "Show what was hidden" asks the server. Until
 * 2026-10-15 the answer then went to the box the redraw had replaced: the
 * value or the refusal was drawn off the page, and `focusBack` could not
 * give the focus to a button no longer there, so it stayed on <body> (CI
 * job 16259, tests/stack/reveal-focus.test.ts F3). Now:
 *
 *   - the same box drawn now (the same secret, named alike, at its rank
 *     among those) takes the answer: the value, or the refusal's words, and
 *     the focus when the pressed button had it and the focus fell;
 *   - never another secret's box: a card drawn now in another order still
 *     gets its own secret's value only;
 *   - no such box drawn now (the page says "Not connected", the session
 *     left): nothing is drawn, and the focus goes to the page's heading;
 *   - a box drawn now that asks for itself (pressed again meanwhile) or
 *     already shows its value keeps its own answer.
 *
 * jsdom keeps the focus of a button turned off; `press` drops it, as
 * Chromium does (home-js-reveal-focus.test.ts). Drives the PRODUCT page
 * script in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, M, T, load, tick } from "./home-js-fixtures.js";

const PAGE = "http://127.0.0.1:4500/mandu/agents/s1";
const SHOW = "Show the real value";
const HIDE = "Hide it again";
const VALUE = "sk-reveal-redraw-VALUE-A";
const REFUSAL = "the protection service no longer holds its value";
/** The agent page's read and a reveal while the protection service is down. */
const DOWN = { status: 503, body: { error: "protection service unreachable", unreachable: true } };
const REF_A = "aaaaaaaaaaaaaaaaaaaaaaa2";
const REF_B = "bbbbbbbbbbbbbbbbbbbbbbb2";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const code = (text: string) => ({ kind: "code", text });
const STEP = {
  kind: "action", id: "t1", ts: "2026-09-25T10:00:02.000Z", icon: "file", sentence: [T("Read "), code(".env")], outcome: "secret", note: null,
  split: { ai: [T("Got "), M("secret"), T(" in place of the result.")], real: [T("The result held your secret "), code(".env"), T(".")],
    hidden: { text: null, secret: true, truncated: false, secrets: [{ ref: REF_A, name: ".env" }] } },
};
/** A Your secrets card; its line names its ref, so the test tells apart two
 *  cards whose headings read alike. */
const card = (file: string, ref: string) => ({ what: [T("The file "), code(file)], level: "No AI", saw: "masked", lines: [{ tone: "good", parts: [T(`The AI got only a placeholder (${ref.slice(-2)}).`)] }], ref });
const CARD_A = card("~/ws/.env", REF_A);
const CARD_B = card("~/ws/key.pem", REF_B);
/** B named as A is: the same heading words, another secret. */
const CARD_B_ALIKE = card("~/ws/.env", REF_B);
const NOTE = {
  lines: ["One value in your prompt was hidden from the AI (an email address)."],
  items: [{ eventId: "ev-1", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: false, canLetSession: false, canShow: true }],
  ts: "2026-09-25T10:00:00.000Z",
};
/** The agent page of s1: one secret step and the Your secrets `cards`, a
 *  prompt filter's note under the first question; `more` turns: the agent
 *  did more since (a changed answer, so the page is drawn again). */
function agentPage(cards: unknown[] = [CARD_A], more = 0, steps: unknown[] = [STEP]): unknown {
  const page = JSON.parse(JSON.stringify(AGENT));
  page.story = [{ ...page.story[0], steps, promptNote: NOTE }];
  for (let i = 0; i < more; i++) page.story.push({ ...page.story[0], id: `turn:more${i}`, prompt: `Go on ${i}`, steps: [], promptNote: null });
  page.secrets = { mode: "secrets", flagged: false, more: 0, counts: { masked: cards.length, early: 0 }, secrets: cards };
  return page;
}
/** The page, its agent read answered by `read()` each time it asks. Its
 *  reveal requests are held, as by a slow server: `answer(a)` answers the
 *  oldest one still out, with a body or `{status, body}`. */
function open(read: () => unknown, s2: unknown = null) {
  const out: Array<(a: unknown) => void> = [];
  const page = load({ url: PAGE, routes: { "GET home/agent?session=s1": () => read(), "GET home/agent?session=s2": s2 }, before: (w: Doc) => {
    const f0 = w.fetch;
    w.fetch = (url: string, init: Doc = {}) => (/\/reveal$/.test(url)
      ? new Promise((r) => out.push(r)).then((a: Doc) => (a && typeof a === "object" && "status" in a && "body" in a
        ? { ok: a.status < 400, status: a.status, json: () => Promise.resolve(a.body) }
        : { ok: true, status: 200, json: () => Promise.resolve(a) }))
      : f0(url, init));
  } });
  const answer = (a: unknown) => {
    const next = out.shift();
    assert.ok(next, "a reveal request is out");
    next(a);
  };
  return { ...page, answer, out };
}
/** The poll: Home, then the open agent page, read again. */
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
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
const cardOf = (doc: Doc, ref: string) => [...doc.querySelectorAll("#agent-secrets .secret-card")].find((c: Doc) => c.textContent.includes(`(${ref.slice(-2)})`)) as Doc;
const cardButton = (doc: Doc, ref = REF_A) => cardOf(doc, ref)?.querySelector("button.secret-reveal");
const stepButton = (doc: Doc) => doc.querySelector("#agent-story .step.split button.secret-reveal");
const promptButton = (doc: Doc) => doc.querySelector("#agent-story .prompt-note-item button.prompt-reveal");
const boxOf = (btn: Doc) => btn.parentElement.querySelector("pre.secret-value");
const describedBy = (doc: Doc, b: Doc): string | null => {
  const id = b.getAttribute("aria-describedby");
  return id ? doc.getElementById(id)?.textContent ?? `(no #${id})` : null;
};

test("the agent did more while Show the real value asked: the card or step drawn now shows the value, and its button has the focus", async () => {
  let vm = agentPage();
  const { doc, answer } = open(() => vm);
  await tick(40);
  for (const pick of [(d: Doc) => cardButton(d), stepButton]) {
    const pressed = pick(doc);
    press(pressed);
    vm = agentPage([CARD_A], (vm as { story: unknown[] }).story.length);
    await poll(doc);
    const now = pick(doc);
    assert.notEqual(now, pressed, "the page was drawn again while the value was on its way");
    assert.equal(pressed.isConnected, false);
    assert.equal(now.disabled, false, "the button drawn now asks nothing");
    answer({ value: VALUE });
    await tick(40);
    assert.equal(boxOf(now).hidden, false, "the box drawn now shows the value");
    assert.equal(boxOf(now).textContent, VALUE);
    assert.equal(now.textContent, HIDE);
    assert.equal(now.getAttribute("aria-expanded"), "true");
    assert.equal(doc.activeElement, now, "the focus is on the button drawn now");
    assert.equal(now.getAttribute("aria-describedby"), null, "nothing was refused");
    assert.equal(boxOf(pressed).textContent, "", "the box the redraw replaced keeps no value");
    // Hide it again: the value leaves the page.
    now.click();
    assert.equal(boxOf(now).textContent, "");
    assert.ok(!doc.documentElement.outerHTML.includes(VALUE));
  }
});

test("refused after the redraw: the card drawn now says why, and its button has the focus, described by it", async () => {
  let vm = agentPage();
  const { doc, answer } = open(() => vm);
  await tick(40);
  const pressed = cardButton(doc);
  press(pressed);
  vm = agentPage([CARD_A], 1);
  await poll(doc);
  const now = cardButton(doc);
  assert.notEqual(now, pressed);
  answer({ status: 404, body: { error: REFUSAL } });
  await tick(40);
  assert.equal(doc.activeElement, now, "the focus is on the button drawn now");
  assert.equal(now.getAttribute("aria-expanded"), "false", "nothing shown");
  const said = describedBy(doc, now);
  assert.ok(said && said.includes(REFUSAL), `described by the refusal on the page: ${said}`);
  assert.ok(cardOf(doc, REF_A).querySelector(".ask-error"), "the refusal is on the card drawn now");
  assert.equal(doc.querySelectorAll("#agent-secrets .ask-error").length, 1);
});

test("never another secret's box: a card drawn now in another order gets only its own secret's value, also when both read alike", async () => {
  for (const b of [CARD_B, CARD_B_ALIKE]) {
    let vm = agentPage([CARD_A, b]);
    const { doc, answer } = open(() => vm);
    await tick(40);
    // The first card's button, A's; the redraw puts B first.
    const pressed = cardButton(doc, REF_A);
    assert.equal(doc.querySelector("#agent-secrets .secret-card button.secret-reveal"), pressed);
    press(pressed);
    vm = agentPage([b, CARD_A], 1);
    await poll(doc);
    assert.equal(doc.querySelector("#agent-secrets .secret-card"), cardOf(doc, REF_B), "B is first now");
    answer({ value: VALUE });
    await tick(40);
    assert.equal(boxOf(cardButton(doc, REF_A)).textContent, VALUE, "A's card drawn now shows A's value");
    assert.equal(boxOf(cardButton(doc, REF_B)).textContent, "", "B's card shows nothing");
    assert.equal(boxOf(cardButton(doc, REF_B)).hidden, true);
    assert.equal(cardButton(doc, REF_B).textContent, SHOW);
    assert.equal(doc.activeElement, cardButton(doc, REF_A));
  }
});

test("the same secret on two steps: the answer goes to the one pressed, at its place; never to another session's page", async () => {
  const twice = [STEP, { ...STEP, id: "t1b", ts: "2026-09-25T10:00:03.000Z" }];
  let vm = agentPage([CARD_A], 0, twice);
  const { doc, answer, window } = open(() => vm, { ...(agentPage() as object), id: "s2" });
  await tick(40);
  const steps = () => [...doc.querySelectorAll("#agent-story .step.split button.secret-reveal")] as Doc[];
  assert.equal(steps().length, 2);
  const pressed = steps()[1];
  press(pressed);
  vm = agentPage([CARD_A], 1, twice);
  await poll(doc);
  const [first, second] = steps();
  assert.ok(!pressed.isConnected && first && second);
  answer({ value: VALUE });
  await tick(40);
  assert.equal(boxOf(second).textContent, VALUE, "the second step drawn now shows it");
  assert.equal(boxOf(first).textContent, "", "the first one shows nothing");
  assert.equal(doc.activeElement, second);
  second.click();

  // The person opens another session while the value is on its way: its
  // page draws a box of the same key (a ref the server gives one session
  // only), and the answer still goes nowhere.
  press(cardButton(doc));
  window.history.pushState(null, "", "/mandu/agents/s2");
  window.dispatchEvent(new window.PopStateEvent("popstate"));
  await tick(40);
  assert.ok(cardButton(doc), "s2's page has a card of the same key");
  answer({ value: VALUE });
  await tick(40);
  assert.ok(!doc.documentElement.outerHTML.includes(VALUE), "nothing of s1's answer on s2's page");
});

test("the page says Not connected while the answer was on its way: no value or refusal anywhere, and the focus goes to the page's heading", async () => {
  for (const reply of [{ value: VALUE }, DOWN]) {
    let down = false;
    const { doc, answer } = open(() => (down ? DOWN : agentPage()));
    await tick(40);
    const pressed = cardButton(doc);
    const replaced = pressed.closest(".secret-card");
    press(pressed);
    down = true;
    await poll(doc);
    assert.equal(doc.getElementById("agent-name").textContent, "Not connected");
    assert.equal(doc.getElementById("agent-secrets-block").hidden, true);
    answer(reply);
    await tick(40);
    assert.ok(!doc.documentElement.outerHTML.includes(VALUE), "the value is drawn nowhere on the page");
    assert.ok(!replaced.textContent.includes(VALUE), "nor in the card the redraw replaced");
    assert.equal(replaced.querySelector(".ask-error"), null, "no refusal drawn into the replaced card");
    assert.equal(doc.activeElement, doc.getElementById("agent-name"), "the focus is on the page's heading");
  }
});

test("a focus the person moved stays; a box drawn now that asks for itself keeps its own answer", async () => {
  let vm = agentPage();
  const { doc, answer } = open(() => vm);
  await tick(40);
  press(cardButton(doc));
  vm = agentPage([CARD_A], 1);
  await poll(doc);
  const back = doc.querySelector("#page-agent a.back");
  back.focus();
  answer({ value: VALUE });
  await tick(40);
  assert.equal(boxOf(cardButton(doc)).textContent, VALUE, "the value shows in the card drawn now");
  assert.equal(doc.activeElement, back, "the focus stays where the person put it");

  // A press made without the focus (a pointer that does not focus, a
  // script): the answer after a redraw moves nothing, there or nowhere.
  for (const goesDown of [false, true]) {
    let vm1 = agentPage();
    let down = false;
    const p1 = open(() => (down ? DOWN : vm1));
    await tick(40);
    const b1 = cardButton(p1.doc);
    p1.doc.activeElement?.blur?.();
    b1.click();
    assert.equal(b1.disabled, true);
    if (goesDown) down = true;
    else vm1 = agentPage([CARD_A], 1);
    await poll(p1.doc);
    p1.answer({ value: VALUE });
    await tick(40);
    assert.equal(p1.doc.activeElement, p1.doc.body, `nothing took the focus (${goesDown ? "Not connected" : "drawn again"})`);
    if (!goesDown) assert.equal(boxOf(cardButton(p1.doc)).textContent, VALUE, "the value shows in the card drawn now");
  }

  // Pressed again after the redraw: the first answer leaves it to its own.
  let vm2 = agentPage();
  const page2 = open(() => vm2);
  await tick(40);
  press(cardButton(page2.doc));
  vm2 = agentPage([CARD_A], 1);
  await poll(page2.doc);
  const b2 = cardButton(page2.doc);
  press(b2);
  page2.answer({ status: 404, body: { error: REFUSAL } });
  await tick(40);
  assert.equal(b2.disabled, true, "its own request is still out");
  assert.equal(cardOf(page2.doc, REF_A).querySelector(".ask-error"), null, "the first answer is not drawn over it");
  assert.equal(page2.doc.activeElement, page2.doc.body, "nor does it move the focus");
  page2.answer({ value: VALUE });
  await tick(40);
  assert.equal(boxOf(b2).textContent, VALUE);
  assert.equal(page2.doc.activeElement, b2);
});

test("a prompt filter's Show what was hidden: the row drawn now shows the text or the refusal, and its button has the focus", async () => {
  let vm = agentPage();
  const { doc, answer } = open(() => vm);
  await tick(40);
  for (const reply of [{ original: "me@corp.example" }, { status: 403, body: { error: "sign in first" } }]) {
    const pressed = promptButton(doc);
    press(pressed);
    vm = agentPage([CARD_A], (vm as { story: unknown[] }).story.length);
    await poll(doc);
    const now = promptButton(doc);
    assert.notEqual(now, pressed);
    answer(reply);
    await tick(40);
    assert.equal(doc.activeElement, now, "the focus is on the button drawn now");
    const pre = now.closest(".prompt-note").querySelector(".prompt-hidden-text");
    if ("original" in reply) {
      assert.equal(pre.hidden, false);
      assert.equal(pre.textContent, "me@corp.example");
      assert.equal(now.textContent, HIDE);
      now.click();
      assert.equal(pre.textContent, "");
    } else {
      assert.equal(pre.hidden, true);
      const said = describedBy(doc, now);
      assert.ok(said && /sign in/i.test(said), `described by the refusal on the row drawn now: ${said}`);
      assert.ok(now.closest(".prompt-note-item").querySelector(".ask-error"));
    }
  }
});
