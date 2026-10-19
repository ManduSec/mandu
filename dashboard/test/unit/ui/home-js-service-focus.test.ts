/**
 * home-js-service-focus.test — Settings › Protection: the service line's
 * Start and Restart, Restart's question and the poll keep the keyboard
 * focus (dashboard.md §4.25 *The service row keeps the focus*).
 *
 * Every other Settings card kept the focus across its changes since
 * 2026-10-11, and Home's lists across the poll, but the protection service
 * line was left out. Until 2026-10-13, with the focus on its button:
 *
 *   - Start, and Restart now, turned the button off and drew Settings
 *     again: the focus fell to <body>, worked or refused;
 *   - Restart turned itself off and opened its question under the row, with
 *     the focus on <body>: a screen reader heard nothing, and Tab started
 *     over at the top of the page to find Restart now;
 *   - the poll drew the line anew from nothing when the service changed, and
 *     a focused Restart left the page.
 *
 * Now:
 *
 *   - the question takes the focus (its words); Escape is Cancel, and
 *     Cancel gives Restart the focus back; while Restart now is on its way
 *     Cancel is off and Escape does nothing;
 *   - an answer that worked gives the focus to the line, which says what
 *     the service does now;
 *   - a refusal gives it to the button pressed, on again, described by the
 *     words of the refusal (Restart for Restart now); with no such button,
 *     the line;
 *   - the poll gives it to the control drawn again that reads the same,
 *     else the card's heading; the line keeps it, drawn anew;
 *   - a press made without the focus, or a focus moved elsewhere meanwhile,
 *     moves nothing.
 *
 * jsdom keeps the focus of a button turned off, so `dropOnDisable` drops it
 * to <body> at that moment, as Chromium does (protection-js-repaint-focus).
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { ADMIN_SESSION_REQUIRED } from "../../../src/server.js";

const URL = "http://127.0.0.1:4500/mandu/settings";
const RESTART_Q = "Restart Mandu? Agents you are running with mandu right now are blocked until it is back, usually a few seconds.";
const summary = (over: Record<string, unknown> = {}) => ({ summary: {
  available: true, state: "running", name: "Running", sentence: "",
  since: Date.now() - 5 * 60_000, action: { label: "Restart", path: "control/arbiter/restart", confirm: RESTART_Q }, helperNote: null,
  ...over,
} });
const STOPPED = { state: "stopped", name: "Stopped", since: null, sentence: "It starts again by itself when you next start an agent with mandu.", action: { label: "Start", path: "control/arbiter/start", confirm: null } };
const STARTING = { state: "starting", name: "Starting", since: null, sentence: "", action: null };
const CRASHED = { ...STOPPED, state: "crashed", name: "Stopped unexpectedly", sentence: "Press Start, or start an agent with mandu." };
const SIGNED_OUT = { status: 403, body: { error: ADMIN_SESSION_REQUIRED } };
const SIGN_IN = /^Sign in first: in your own terminal, run mandu dashboard/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const line = (doc: Doc) => doc.getElementById("settings-service-main");
const button = (doc: Doc) => line(doc)?.querySelector("button");
const question = (doc: Doc) => doc.getElementById("settings-service-confirm");
const askButton = (doc: Doc, words: string) => [...(question(doc)?.querySelectorAll("button") ?? [])].find((b: Doc) => b.textContent === words);
const focused = (doc: Doc) => doc.activeElement;
const posts = (calls: Array<{ method: string }>) => calls.filter((c) => c.method === "POST").length;

/** A browser drops the focus of a button turned off to <body> (Chromium's
 *  focus fixup); jsdom keeps it, so this does at that moment. jsdom's blur()
 *  ignores a button already off, so blur first. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function dropOnDisable(window: any): void {
  const proto = window.HTMLButtonElement.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, "disabled")!;
  Object.defineProperty(proto, "disabled", {
    configurable: true,
    get() { return desc.get!.call(this); },
    set(v: boolean) { if (v && this.ownerDocument.activeElement === this) this.blur(); desc.set!.call(this, v); },
  });
}

/** Settings open over `routes`, buttons dropping their focus when off. */
async function settings(routes: Record<string, unknown>) {
  const page = load({ url: URL, routes });
  dropOnDisable(page.window);
  await tick();
  return page;
}
/** Enter on `b`: it has the focus, then the click. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(b: any): void {
  b.focus();
  assert.equal(b.ownerDocument.activeElement, b);
  b.click();
}
/** The page's poll, as a return to the tab runs it. */
async function poll(doc: Doc): Promise<void> {
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
/** A key on the focused element. */
function key(doc: Doc, k: string): void {
  focused(doc).dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
}

test("Start that worked: the line takes the focus and reads what the service does now; the poll that draws it again keeps it there", async () => {
  let n = 0;
  const { doc } = await settings({
    "GET control/summary": () => [summary(STOPPED), summary(STARTING), summary()][Math.min(n++, 2)],
    "POST control/arbiter/start": { service: { state: "starting" } },
  });
  const start = button(doc);
  assert.equal(start.textContent, "Start");
  press(start);
  assert.equal(focused(doc), doc.body, "the button goes off while the start is on its way, and the browser drops its focus");
  await tick(30);
  assert.equal(focused(doc), line(doc), "the line has the focus");
  assert.equal(focused(doc).textContent, "Starting.");
  assert.equal(focused(doc).getAttribute("tabindex"), "-1", "focusable, but no Tab stop");

  await poll(doc);
  assert.match(line(doc).textContent, /^Running\. Started /, "the poll drew the line anew");
  assert.equal(focused(doc), line(doc), "the line drawn anew keeps the focus");
});

test("Restart: its question takes the focus and is read; Escape is Cancel and gives Restart the focus back; Cancel too; nothing is sent", async () => {
  const { doc, calls } = await settings({ "GET control/summary": summary(), "POST control/arbiter/restart": { service: { state: "running" } } });
  press(button(doc));
  assert.ok(question(doc), "the question is open");
  const words = question(doc).querySelector("p");
  assert.equal(focused(doc), words, "the question's words have the focus, never <body>");
  assert.equal(words.textContent, RESTART_Q);
  assert.equal(question(doc).getAttribute("role"), "alert", "still announced as it opens");

  key(doc, "Escape");
  assert.equal(question(doc), null, "Escape closed the question");
  assert.equal(focused(doc), button(doc), "Restart, on again, has the focus");
  assert.equal(button(doc).disabled, false);

  // Escape from one of its buttons too; a key with a modifier is no Escape.
  press(button(doc));
  askButton(doc, "Restart now").focus();
  focused(doc).dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", shiftKey: true, bubbles: true, cancelable: true }));
  assert.ok(question(doc), "Shift+Escape leaves the question open");
  key(doc, "Escape");
  assert.equal(question(doc), null);
  assert.equal(focused(doc), button(doc));

  press(button(doc));
  press(askButton(doc, "Cancel"));
  assert.equal(question(doc), null);
  assert.equal(focused(doc), button(doc), "Cancel gives Restart the focus back");
  await tick(30);
  assert.equal(posts(calls), 0, "nothing was sent");
});

test("Restart now that worked: Cancel is off while it is on its way and Escape does nothing; the answer gives the line the focus", async () => {
  let release: (v: unknown) => void = () => {};
  const { doc, calls } = await settings({
    "GET control/summary": () => summary({ since: Date.now() - 1_000 }),
    "POST control/arbiter/restart": () => new Promise((r) => { release = r; }),
  });
  press(button(doc));
  press(askButton(doc, "Restart now"));
  await tick();
  assert.equal(posts(calls), 1, "the restart is on its way");
  assert.equal(askButton(doc, "Restart now").disabled, true);
  assert.equal(askButton(doc, "Cancel").disabled, true, "it cannot be called back, so Cancel is off");
  question(doc).querySelector("p").focus();
  key(doc, "Escape");
  assert.ok(question(doc), "Escape does not close a question already answered");

  release({ service: { state: "running" } });
  await tick(30);
  assert.equal(question(doc), null, "the question is gone");
  assert.equal(focused(doc), line(doc), "the line has the focus");
  assert.match(focused(doc).textContent, /^Running\. Started .*\. Restart$/);
  assert.equal(posts(calls), 1, "one restart");
});

test("a refusal gives the focus back to the button pressed, on again, described by the refusal's words: Start, and Restart for Restart now", async () => {
  const a = await settings({ "GET control/summary": summary(STOPPED), "POST control/arbiter/start": SIGNED_OUT });
  press(button(a.doc));
  await tick(30);
  const start = button(a.doc);
  assert.equal(focused(a.doc), start, "Start, drawn again, has the focus");
  assert.equal(start.textContent, "Start");
  assert.equal(start.disabled, false);
  const said = line(a.doc).querySelector(".ask-error");
  assert.match(said.textContent, SIGN_IN);
  assert.equal(start.getAttribute("aria-describedby"), said.id, "the refusal's words are read with the button");

  const b = await settings({ "GET control/summary": summary(), "POST control/arbiter/restart": SIGNED_OUT });
  press(button(b.doc));
  press(askButton(b.doc, "Restart now"));
  await tick(30);
  assert.equal(question(b.doc), null);
  const restart = button(b.doc);
  assert.equal(focused(b.doc), restart, "Restart has the focus, not the question that is gone");
  assert.equal(restart.getAttribute("aria-describedby"), line(b.doc).querySelector(".ask-error").id);
});

test("a refusal whose row now offers no button: the line, which holds its words, takes the focus", async () => {
  let n = 0;
  const { doc } = await settings({
    "GET control/summary": () => (n++ === 0 ? summary(STOPPED) : summary(STARTING)),
    "POST control/arbiter/start": { status: 503, body: { error: "arbiter is already starting" } },
  });
  press(button(doc));
  await tick(30);
  assert.equal(button(doc), null, "Starting offers no button");
  assert.equal(focused(doc), line(doc));
  assert.equal(line(doc).querySelector(".ask-error").textContent, "arbiter is already starting");
});

test("the poll: Restart drawn again keeps the focus; once the service crashed, the card's heading has it; a focus outside the line stays", async () => {
  let state: Record<string, unknown> = summary();
  const { doc } = await settings({ "GET control/summary": () => state });
  const before = button(doc);
  before.focus();
  state = summary({ since: Date.now() - 1_000 }); // restarted elsewhere
  await poll(doc);
  assert.notEqual(button(doc), before, "the line was drawn anew");
  assert.equal(before.isConnected, false);
  assert.equal(focused(doc), button(doc), "Restart, drawn again, has the focus");

  state = summary(CRASHED);
  await poll(doc);
  assert.equal(button(doc).textContent, "Start");
  assert.equal(focused(doc), doc.getElementById("settings-protection-title"), "Restart is gone: the card's heading, never Start");

  const elsewhere = doc.getElementById("model-open");
  elsewhere.focus();
  state = summary(STOPPED);
  await poll(doc);
  assert.equal(line(doc).querySelector(".service-state").textContent, "Stopped");
  assert.equal(focused(doc), elsewhere, "a focus outside what was drawn is not moved");
});

test("nothing is taken: a press without the focus moves nothing, and a focus moved elsewhere meanwhile stays", async () => {
  const a = await settings({ "GET control/summary": summary(STOPPED), "POST control/arbiter/start": { service: { state: "running" } } });
  button(a.doc).click(); // a browser that does not focus a clicked button
  await tick(30);
  assert.equal(focused(a.doc), a.doc.body);

  // Restart clicked without the focus: its question takes none.
  const b = await settings({ "GET control/summary": summary(), "POST control/arbiter/restart": SIGNED_OUT });
  button(b.doc).click();
  assert.ok(question(b.doc));
  assert.equal(focused(b.doc), b.doc.body, "the question takes no focus the button did not have");
  askButton(b.doc, "Restart now").click();
  await tick(30);
  assert.equal(focused(b.doc), b.doc.body, "nor does the refusal");

  let release: (v: unknown) => void = () => {};
  const c = await settings({
    "GET control/summary": summary(STOPPED),
    "POST control/arbiter/start": () => new Promise((r) => { release = r; }),
  });
  press(button(c.doc));
  await tick();
  const elsewhere = c.doc.getElementById("model-open");
  elsewhere.focus();
  release({ service: { state: "running" } });
  await tick(30);
  assert.equal(focused(c.doc), elsewhere, "the focus the person moved stays");
});
