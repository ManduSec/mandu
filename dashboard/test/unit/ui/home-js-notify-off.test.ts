/**
 * home-js-notify-off.test — Settings › Notifications turns notifications
 * off and on again in this browser, without the browser's settings
 * (dashboard.md §4.25 *Notifications*).
 *
 * Until 2026-10-19 the row's only button was *Turn on*, shown while the
 * permission was `default`: once granted it read "On. …" with no control,
 * and a page cannot take a permission back, so the browser's site settings
 * were the only way to stop them. Now, with permission granted:
 *
 *   - the button reads *Turn off*; a press stores the choice in this
 *     browser (`mandu.home.notifyOff`), the words follow, and the button,
 *     now *Turn on*, keeps the focus (no list drawn again);
 *   - while off a new ask notifies nothing but is recorded as seen, so a
 *     later *Turn on* never brings it back; the next new ask notifies;
 *   - the Home offer row stays hidden;
 *   - where storage fails (private mode) the choice holds for the tab;
 *   - `default`, `denied` and a browser that cannot notify are as before.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub and Notification stub (home-js-fixtures.ts). Axes: none
 * (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const OFF_KEY = "mandu.home.notifyOff";
const ON_WORDS = "On. You get a notification when an agent needs your OK, when protection fails, and when the protection service stops under a running agent.";
const OFF_WORDS = "Off in this browser. The tab title still counts what waits.";
/** A browser that already primed and saw egr-1. */
const PRIMED = { "mandu.home.notifyPrimed": "1", "mandu.home.seenAsks": JSON.stringify(["egr-1"]) };
const ASK2 = { ...ASK, id: "egr-2" };
const ASK3 = { ...ASK, id: "egr-3" };

async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
const seen = (window: any): string[] => JSON.parse(window.localStorage.getItem("mandu.home.seenAsks") || "[]");

test("granted: the row's button reads Turn off, is described by the row's words, and a press turns them off with the focus kept", async () => {
  const { doc, window, err } = load({ url: SETTINGS_URL, storage: PRIMED });
  assert.equal(err, null);
  await tick();
  const btn = doc.getElementById("notify-enable");
  const state = doc.getElementById("notify-state");
  assert.equal(btn.hidden, false, "granted: a button");
  assert.equal(btn.textContent, "Turn off");
  assert.equal(btn.getAttribute("aria-describedby"), "notify-state");
  assert.equal(state.textContent, ON_WORDS);
  btn.focus();
  btn.click();
  assert.equal(window.localStorage.getItem(OFF_KEY), "1", "stored in this browser");
  assert.equal(state.textContent, OFF_WORDS);
  assert.equal(btn.textContent, "Turn on");
  assert.equal(doc.activeElement, btn, "the button keeps the focus");
  assert.equal(doc.getElementById("notify-enable"), btn, "the same button, nothing drawn again");
  assert.equal(doc.getElementById("notify-offer").hidden, true, "the Home offer stays hidden");
  btn.click();
  assert.equal(window.localStorage.getItem(OFF_KEY), null, "Turn on clears it");
  assert.equal(state.textContent, ON_WORDS);
  assert.equal(btn.textContent, "Turn off");
  assert.equal(doc.activeElement, btn);
});

test("while off a new ask shows nothing but is seen; Turn on again: the next new ask notifies and the one seen while off never does", async () => {
  const page = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  assert.equal(page.notes.length, 0, "egr-1 was seen before");
  const btn = page.doc.getElementById("notify-enable");
  btn.click();
  page.setHome(home({ waiting: [ASK, ASK2] }));
  await poll(page.doc);
  assert.equal(page.notes.length, 0, "off: no notification");
  assert.deepEqual(seen(page.window).sort(), ["egr-1", "egr-2"], "but egr-2 is recorded as seen");
  assert.match(page.window.document.title, /^\(2\) Mandu · Settings$/, "the tab title still counts what waits");
  btn.click();
  assert.equal(btn.textContent, "Turn off");
  await poll(page.doc);
  assert.equal(page.notes.length, 0, "turning them on never brings the backlog");
  page.setHome(home({ waiting: [ASK, ASK2, ASK3] }));
  await poll(page.doc);
  assert.equal(page.notes.length, 1, "the next new ask notifies, once");
  assert.equal(page.notes[0]!.title, "Mandu: Claude Code needs your OK");
});

test("the choice is this browser's: a later load reads it, and the Home offer stays hidden", async () => {
  const { doc, notes } = load({ storage: { ...PRIMED, [OFF_KEY]: "1" }, homeVm: home({ waiting: [ASK, ASK2] }) });
  await tick();
  assert.equal(notes.length, 0, "off since an earlier visit");
  assert.equal(doc.getElementById("notify-offer").hidden, true);
  assert.equal(doc.getElementById("notify-enable").textContent, "Turn on");
  assert.equal(doc.getElementById("notify-state").textContent, OFF_WORDS);
});

test("where storage fails, Turn off holds for the tab", async () => {
  const { doc, notes, setHome } = load({
    url: SETTINGS_URL,
    before: (w) => {
      const real = w.localStorage;
      const fail = () => { throw new Error("SecurityError"); };
      Object.defineProperty(w, "localStorage", { configurable: true, get: () => ({ getItem: fail, setItem: fail, removeItem: fail, key: real.key.bind(real), length: 0 }) });
    },
  });
  await tick(); // the first poll primes this tab
  const btn = doc.getElementById("notify-enable");
  btn.click();
  assert.equal(btn.textContent, "Turn on");
  assert.equal(doc.getElementById("notify-state").textContent, OFF_WORDS);
  setHome(home({ waiting: [ASK, ASK2] }));
  await poll(doc);
  assert.equal(notes.length, 0, "off for this tab");
  btn.click();
  assert.equal(btn.textContent, "Turn off");
  setHome(home({ waiting: [ASK, ASK2, ASK3] }));
  await poll(doc);
  assert.ok(notes.length >= 1, "on again for this tab");
});

test("default and denied are as before: Turn on asks the browser, Blocked has no button; a browser that cannot notify has none", async () => {
  const asked = load({ url: SETTINGS_URL, permission: "default", storage: { ...PRIMED, [OFF_KEY]: "1" } });
  await tick();
  const btn = asked.doc.getElementById("notify-enable");
  assert.equal(btn.hidden, false);
  assert.equal(btn.textContent, "Turn on");
  assert.equal(asked.doc.getElementById("notify-state").textContent, "Off.");
  assert.equal(asked.doc.getElementById("notify-offer").hidden, false, "the Home offer as before");
  let requested = 0;
  asked.window.Notification.requestPermission = () => { requested++; asked.window.Notification.permission = "granted"; return Promise.resolve("granted"); };
  btn.click();
  await tick();
  assert.equal(requested, 1, "the press asks the browser");
  // Asking from the button means wanting them: an earlier Turn off is gone.
  assert.equal(asked.window.localStorage.getItem(OFF_KEY), null);
  assert.equal(btn.textContent, "Turn off");
  assert.equal(asked.doc.getElementById("notify-state").textContent, ON_WORDS);

  const denied = load({ url: SETTINGS_URL, permission: "denied", storage: PRIMED });
  await tick();
  assert.equal(denied.doc.getElementById("notify-enable").hidden, true);
  assert.equal(denied.doc.getElementById("notify-state").textContent, "Blocked in this browser. Allow notifications for this site in the browser settings.");
  assert.equal(denied.doc.getElementById("notify-offer").hidden, true);

  const none = load({ url: SETTINGS_URL, storage: PRIMED, before: (w) => { delete w.Notification; } });
  await tick();
  assert.equal(none.err, null);
  assert.equal(none.doc.getElementById("notify-enable").hidden, true);
  assert.match(none.doc.getElementById("notify-state").textContent, /^This browser cannot show notifications here\./);
});

test("another tab's Turn off: this tab's row says so on the storage event", async () => {
  const { doc, window } = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  window.localStorage.setItem(OFF_KEY, "1");
  window.dispatchEvent(new window.StorageEvent("storage", { key: OFF_KEY, newValue: "1" }));
  assert.equal(doc.getElementById("notify-enable").textContent, "Turn on");
  assert.equal(doc.getElementById("notify-state").textContent, OFF_WORDS);
});
