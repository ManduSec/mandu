/**
 * home-js-suggest-model-focus.test — the model preview of Rules › Keys Mandu
 * found keeps the keyboard focus, and Escape closes it (dashboard.md §4.25t
 * *The preview keeps the focus*), driven in jsdom over the fetch stub of
 * home-js-fixtures.ts with the server's own view models. Mandu-new.
 *
 * Until 2026-10-12, in a headless Chromium, *See what it would send* left
 * the focus on <body> while it asked and after the preview opened; Escape
 * did nothing in the preview; Cancel and Send left the focus on <body>; and
 * Cancel stayed on while a send was on its way, saying "Nothing was sent."
 * of names already sent.
 *
 * Pins: the preview opens with the focus on its headline, never on Send;
 * Escape, Cancel and Close send nothing and give the focus back to *See
 * what it would send*; while a send is on its way Send and Cancel are off,
 * the focus waits on the headline and Escape closes nothing; the run's end
 * gives the focus back; a refused preview gives it back to its button and a
 * refused send to Cancel, each described by the error line; a focus moved
 * elsewhere stays, and an Escape outside the preview, with a modifier, in an
 * IME composition or taken by something else closes nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES } from "./home-js-fixtures.js";
import { suggestionRows } from "../../../src/view-model/suggestions.js";
import { modelPickerVM, modelPreviewVM, modelRunVM, type ModelPreviewWire, type ModelRunWire } from "../../../src/view-model/suggestion-model.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const HOME = "/home/u";
const DIGEST = "c".repeat(64);
const PREVIEW: ModelPreviewWire = {
  axis: true, tier: "names", digest: DIGEST,
  destination: { kind: "default", name: "Claude (claude -p)", location: "external", placement: "network", vendor: "Anthropic" },
  roots: [{ index: 1, root: `${HOME}/proj`, files: 2 }], items: 2, bytes: 120, requests: 1,
  names: ['f1 root 1 "README.md" size=under1KB ext=md', 'd1 root 1 "clients/"'], files: [],
  left: { covered: 0, labelled: 0, tooLong: 0, personal: 0, overCap: 0, detector: 0, registered: 0, flagged: 0, unread: 0 },
  promptVersion: "names-1", confine: { live: true }, expiresAt: 1, walk: { examined: 2, covered: 0, capped: [] },
};
const EMPTY: ModelPreviewWire = { ...PREVIEW, digest: "", items: 0, bytes: 0, requests: 0, names: [] };
const RUN: ModelRunWire = {
  axis: true, running: false, digest: DIGEST, destination: PREVIEW.destination, sent: { requests: 1, items: 2, bytes: 120 },
  counts: { rules: 0, kept: 0, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0, public: 0 },
  filed: [], error: null, ms: 10,
};
const listing = { suggestions: suggestionRows([], HOME), count: 0, scan: null, model: modelPickerVM(true, []) };
const preview = (p: ModelPreviewWire = PREVIEW) => ({ preview: modelPreviewVM(p, HOME) });
const sent = () => ({ run: modelRunVM(RUN, "names"), ...listing });

/** An answer held until the test sends it. */
function held() {
  let send!: (v: unknown) => void;
  const answer = new Promise<unknown>((a) => { send = a; });
  return { answer, send };
}

const byId = (doc: Doc, id: string) => doc.getElementById(id);
const run = (doc: Doc) => byId(doc, "suggest-model-run");
const head = (doc: Doc) => byId(doc, "suggest-model-head");
const dialog = (doc: Doc) => byId(doc, "suggest-model-preview");
const cancel = (doc: Doc) => byId(doc, "suggest-model-cancel");
const sendBtn = (doc: Doc) => byId(doc, "suggest-model-send");
const status = (doc: Doc) => byId(doc, "suggest-model-status").textContent;
const sends = (calls: Array<{ url: string }>) => calls.filter((c) => c.url.includes("model/send")).length;
/** A control's description, as a browser computes it from aria-describedby. */
const described = (c: Doc) => (c.getAttribute("aria-describedby") ?? "").split(/\s+/).filter(Boolean).map((id: string) => c.ownerDocument.getElementById(id)?.textContent ?? "").join(" ");

async function open(routes: Record<string, unknown>) {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": listing, ...routes } });
  await tick();
  byId(page.doc, "suggest-open").click();
  await tick();
  const sel = byId(page.doc, "suggest-model-tier");
  sel.value = "names";
  sel.dispatchEvent(new page.doc.defaultView.Event("change"));
  assert.equal(run(page.doc).disabled, false);
  return page;
}
/** Enter on a button that goes off while it acts: Chromium drops its focus. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** Enter on a button that keeps its focus (a browser that does not drop it). */
function enter(btn: Doc): void {
  btn.focus();
  assert.equal(btn.ownerDocument.activeElement, btn);
  btn.click();
}
/** Escape where the focus is, as a browser sends it. */
function escape(doc: Doc, init: Record<string, unknown> = {}): Doc {
  const ev = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true, ...init });
  (doc.activeElement ?? doc.body).dispatchEvent(ev);
  return ev;
}

test("See what it would send opens the preview with the focus on its headline, never Send; Escape closes it, sends nothing, and gives the focus back", async () => {
  const { doc, calls } = await open({ "POST suggestions/model/preview": preview() });
  press(run(doc));
  await tick();
  assert.equal(dialog(doc).hidden, false);
  assert.equal(doc.activeElement, head(doc), "the headline, never <body>");
  assert.notEqual(doc.activeElement, sendBtn(doc), "never Send: a second Enter sends nothing");
  assert.match(doc.activeElement.textContent, /^This sends 2 file and folder names from 1 folder to Claude \(claude -p\)/);
  assert.equal(head(doc).getAttribute("tabindex"), "-1", "a headline is no Tab stop");
  assert.equal(dialog(doc).getAttribute("aria-labelledby"), "suggest-model-head");

  // Enter again, where the focus is now, presses nothing.
  doc.activeElement.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  await tick();
  assert.equal(sends(calls), 0);

  const ev = escape(doc);
  assert.equal(ev.defaultPrevented, true, "the Escape is taken");
  assert.equal(dialog(doc).hidden, true, "Escape closes the preview");
  assert.equal(status(doc), "Nothing was sent.");
  assert.equal(doc.activeElement, run(doc), "back on See what it would send");
  assert.equal(sends(calls), 0, "Escape sends nothing");

  // A browser that keeps the focus on the button: the same.
  enter(run(doc));
  await tick();
  assert.equal(doc.activeElement, head(doc));
  byId(doc, "suggest-model-list").setAttribute("tabindex", "0");
  byId(doc, "suggest-model-list").focus();
  escape(doc);
  assert.equal(dialog(doc).hidden, true, "Escape from anywhere in the preview");
  assert.equal(doc.activeElement, run(doc));
  assert.equal(sends(calls), 0);
});

test("Cancel and Close send nothing and give the focus back; with the button off, the picker takes it", async () => {
  let answer: unknown = preview();
  const { doc, calls } = await open({ "POST suggestions/model/preview": () => answer });
  enter(run(doc));
  await tick();
  enter(cancel(doc));
  assert.equal(dialog(doc).hidden, true);
  assert.equal(status(doc), "Nothing was sent.");
  assert.equal(doc.activeElement, run(doc), "Cancel: back on See what it would send");

  // Nothing to send: the headline says why, Close closes it.
  answer = preview(EMPTY);
  press(run(doc));
  await tick();
  assert.equal(sendBtn(doc).hidden, true);
  assert.equal(cancel(doc).textContent, "Close");
  assert.equal(doc.activeElement, head(doc));
  assert.match(doc.activeElement.textContent, /^No file or folder name to send/);
  enter(cancel(doc));
  assert.equal(dialog(doc).hidden, true);
  assert.equal(doc.activeElement, run(doc), "Close: back on See what it would send");

  // The picker went to Off meanwhile (the button is off): the picker.
  answer = preview();
  enter(run(doc));
  await tick();
  const sel = byId(doc, "suggest-model-tier");
  sel.value = "off";
  sel.dispatchEvent(new doc.defaultView.Event("change"));
  assert.equal(run(doc).disabled, true);
  head(doc).focus();
  escape(doc);
  assert.equal(dialog(doc).hidden, true);
  assert.equal(doc.activeElement, sel, "the picker, never <body>");
  assert.equal(sends(calls), 0);
});

test("Send: Send and Cancel are off while it is on its way, the focus waits on the headline and Escape closes nothing; the run's end gives the focus back", async () => {
  const hold = held();
  const { doc, calls } = await open({ "POST suggestions/model/preview": preview(), "POST suggestions/model/send": () => hold.answer });
  press(run(doc));
  await tick();
  sendBtn(doc).focus();
  sendBtn(doc).click();
  assert.equal(sends(calls), 1);
  assert.equal(sendBtn(doc).disabled, true);
  assert.equal(cancel(doc).disabled, true, "Cancel is off: the send cannot be called back");
  assert.equal(doc.activeElement, head(doc), "the focus waits on the headline, never <body>");
  assert.equal(status(doc), "Sending…");

  const ev = escape(doc);
  assert.equal(ev.defaultPrevented, false, "not taken");
  assert.equal(dialog(doc).hidden, false, "Escape closes nothing while it is on its way");
  cancel(doc).click();
  assert.equal(dialog(doc).hidden, false);
  assert.equal(status(doc), "Sending…", "never \"Nothing was sent.\" of names already sent");
  assert.equal(sends(calls), 1);

  hold.send(sent());
  await tick(20);
  assert.equal(dialog(doc).hidden, true, "the run ended: the preview closes");
  assert.equal(status(doc), modelRunVM(RUN, "names").line, "the run's line");
  assert.equal(cancel(doc).disabled, false);
  assert.equal(doc.activeElement, run(doc), "back on See what it would send");
});

test("a refused preview gives the focus back to its button, and a refused send to Cancel, on again, each described by the error line", async () => {
  const refused = await open({ "POST suggestions/model/preview": { status: 422, body: { error: "names go only to a model the person chose" } } });
  press(run(refused.doc));
  await tick();
  assert.equal(dialog(refused.doc).hidden, true);
  assert.equal(refused.doc.activeElement, run(refused.doc), "back on See what it would send, on again");
  assert.equal(described(run(refused.doc)), "names go only to a model the person chose");

  const { doc, calls } = await open({
    "POST suggestions/model/preview": preview(),
    "POST suggestions/model/send": { status: 410, body: { error: "This preview is no longer held. Press See what it would send to look again." } },
  });
  press(run(doc));
  await tick();
  enter(sendBtn(doc));
  await tick();
  assert.equal(sends(calls), 1);
  assert.equal(dialog(doc).hidden, false, "the preview stays");
  assert.equal(sendBtn(doc).disabled, true, "Send stays off: look again");
  assert.equal(cancel(doc).disabled, false);
  assert.equal(doc.activeElement, cancel(doc), "Cancel, on again, never Send");
  assert.match(described(cancel(doc)), /no longer held/);
  escape(doc);
  assert.equal(dialog(doc).hidden, true, "Escape closes it again");
  assert.equal(doc.activeElement, run(doc));
  assert.equal(sends(calls), 1);
});

test("nothing is taken: a focus moved elsewhere stays; a press without the focus moves none; an Escape outside, with a modifier, composing or taken closes nothing", async () => {
  const ask = held();
  const hold = held();
  const { doc, calls } = await open({ "POST suggestions/model/preview": () => ask.answer, "POST suggestions/model/send": () => hold.answer });
  const root = byId(doc, "suggest-root");
  press(run(doc));
  root.focus();
  ask.send(preview());
  await tick();
  assert.equal(dialog(doc).hidden, false);
  assert.equal(doc.activeElement, root, "the folder box keeps the focus moved there");

  // Outside the preview: See what it would send, the folder box, the page.
  for (const outside of [run(doc), root, doc.body]) {
    if (outside === doc.body) doc.activeElement.blur();
    else outside.focus();
    escape(doc);
    assert.equal(dialog(doc).hidden, false, `Escape outside the preview closes nothing: ${outside.id || "body"}`);
  }
  cancel(doc).focus();
  assert.equal(doc.activeElement, cancel(doc), "in the preview");
  for (const init of [{ shiftKey: true }, { ctrlKey: true }, { altKey: true }, { metaKey: true }, { isComposing: true }, { keyCode: 229 }]) {
    const ev = escape(doc, init);
    assert.equal(dialog(doc).hidden, false, `the preview stays open: ${JSON.stringify(init)}`);
    assert.equal(ev.defaultPrevented, false);
  }
  const taken = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  taken.preventDefault();
  cancel(doc).dispatchEvent(taken);
  assert.equal(dialog(doc).hidden, false, "an Escape something else took");
  assert.equal(doc.activeElement, cancel(doc));

  // Send, then the focus moved to the folder box: it stays there.
  enter(sendBtn(doc));
  assert.equal(doc.activeElement, head(doc));
  root.focus();
  hold.send(sent());
  await tick(20);
  assert.equal(dialog(doc).hidden, true);
  assert.equal(doc.activeElement, root, "the run's end takes no focus moved elsewhere");

  // A Cancel pressed without the focus (a browser that does not focus a
  // clicked button): it closes, and moves no focus.
  run(doc).click();
  await tick();
  assert.equal(dialog(doc).hidden, false);
  doc.activeElement.blur();
  cancel(doc).click();
  assert.equal(dialog(doc).hidden, true);
  assert.equal(doc.activeElement, doc.body);
  assert.equal(sends(calls), 1);
});
