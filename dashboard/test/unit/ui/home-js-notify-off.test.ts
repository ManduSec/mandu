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
 * Since 2026-10-22 (§4.25 *Send a test*) the row also has *Send a test*
 * while they are on: one notification in fixed words and a line under the
 * row saying what happened. Chrome on Android grants the permission but its
 * `Notification` constructor throws (only a service worker may show one);
 * until then `showAlarm` swallowed that and the row read "On." for
 * notifications that could never appear. A throw, from the test or a real
 * alarm, now makes the row say so for the tab.
 *
 * Since 2026-10-26 (§4.25 *Only protection problems*) a "Notify me about"
 * menu (Everything / Only protection problems / Nothing) sits beside the
 * button while permission is granted; Only protection problems silences
 * questions and rule changes and keeps the alarms.
 *
 * Since 2026-10-30 (§4.25 *The button does what it says*): the row's button
 * acts on what it shows, not on a permission that changed since it was
 * drawn (a stale tab's *Turn on* used to store Nothing, in every tab), and
 * the row and Home's offer follow a permission the browser changes: the
 * permissions API's `change` event where there is one, else the poll and
 * the tab showing.
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
const ON_WORDS = "On. You get a notification when an agent needs your OK, when protection fails, when the protection service stops under a running agent, and when another agent can reach Mandu's controls, while a Mandu tab is open in this browser, also in the background.";
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

const TEST = { title: "Mandu: notifications work", body: "This is how Mandu tells you when an agent needs your OK.", tag: "mandu-test" };
const SENT = "Sent. If nothing appeared, your computer may be set to Do Not Disturb or Focus, or may silence this browser in its notification settings.";
const ADVICE = "Use a desktop browser, or keep this tab open: the tab title still counts what waits.";
const CANNOT = "This browser cannot show Mandu's notifications from this page. " + ADVICE;
const BROKEN_ON = "On, but this browser cannot show them from this page. " + ADVICE;
/** Chrome on Android: the permission is granted, the constructor throws. */
function throwing(w: any): void {
  function N() { throw new w.TypeError("Failed to construct 'Notification': Illegal constructor. Use ServiceWorkerRegistration.showNotification() instead."); }
  (N as any).permission = "granted";
  (N as any).requestPermission = () => Promise.resolve("granted");
  w.Notification = N;
}

test("granted and on: Send a test shows one notification in fixed words, says Sent., keeps the focus, and its click focuses the tab", async () => {
  const { doc, window, notes } = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  const test = doc.getElementById("notify-test");
  const result = doc.getElementById("notify-test-result");
  assert.equal(test.hidden, false, "on: a test button");
  assert.equal(test.textContent, "Send a test");
  assert.equal(test.getAttribute("aria-label"), "Send a test notification", "named for its row");
  assert.equal(result.hidden, true, "nothing said before a press");
  assert.equal(result.getAttribute("role"), "status");
  test.focus();
  test.click();
  assert.equal(notes.length, 1, "one notification");
  assert.deepEqual({ title: notes[0]!.title, body: notes[0]!.body, tag: notes[0]!.tag }, TEST);
  assert.equal(result.hidden, false);
  assert.equal(result.textContent, SENT);
  assert.equal(doc.activeElement, test, "the button keeps the focus");
  assert.equal(doc.getElementById("notify-test"), test, "nothing drawn again");
  assert.equal(doc.getElementById("notify-state").textContent, ON_WORDS, "the On line is unchanged");
  let focused = 0;
  window.focus = () => { focused++; };
  notes[0]!.note.onclick();
  assert.equal(focused, 1, "a click on it focuses the tab");
  assert.equal(window.location.pathname, "/mandu/settings", "and opens nothing else");
  // Turn off: the test button and its line go; Turn on: the button is back, the line is not.
  doc.getElementById("notify-enable").click();
  assert.equal(test.hidden, true, "off: no test button");
  assert.equal(result.hidden, true, "and no stale line");
  doc.getElementById("notify-enable").click();
  assert.equal(test.hidden, false);
  assert.equal(result.hidden, true);
});

test("no Send a test while off, denied, default or where the browser cannot notify", async () => {
  const cases: [string, Parameters<typeof load>[0]][] = [
    ["off", { url: SETTINGS_URL, storage: { ...PRIMED, [OFF_KEY]: "1" } }],
    ["denied", { url: SETTINGS_URL, permission: "denied", storage: PRIMED }],
    ["default", { url: SETTINGS_URL, permission: "default", storage: PRIMED }],
    ["unsupported", { url: SETTINGS_URL, storage: PRIMED, before: (w) => { delete w.Notification; } }],
  ];
  for (const [what, opts] of cases) {
    const { doc, err } = load(opts);
    assert.equal(err, null, what);
    await tick();
    assert.equal(doc.getElementById("notify-test").hidden, true, `${what}: no test button`);
    assert.equal(doc.getElementById("notify-test-result").hidden, true, `${what}: no result line`);
  }
});

test("a Notification constructor that throws: Send a test says this browser cannot show them, and the On line says so too", async () => {
  const { doc, err } = load({ url: SETTINGS_URL, storage: PRIMED, before: throwing });
  assert.equal(err, null);
  await tick();
  const state = doc.getElementById("notify-state");
  assert.equal(state.textContent, ON_WORDS, "nothing known before a notification was tried");
  const test = doc.getElementById("notify-test");
  test.focus();
  test.click();
  const result = doc.getElementById("notify-test-result");
  assert.equal(result.hidden, false);
  assert.equal(result.textContent, CANNOT);
  assert.equal(state.textContent, BROKEN_ON);
  assert.equal(doc.activeElement, test, "the button keeps the focus");
  assert.equal(doc.getElementById("notify-offer").hidden, true, "the Home offer stays hidden");
  assert.equal(doc.getElementById("notify-enable").textContent, "Turn off", "still on: Turn off is still there");
});

test("a real alarm whose constructor throws (a new ask) changes the On line for the tab, and a later load starts fresh", async () => {
  const page = load({ url: SETTINGS_URL, storage: PRIMED, before: throwing });
  assert.equal(page.err, null);
  await tick();
  const state = page.doc.getElementById("notify-state");
  assert.equal(state.textContent, ON_WORDS);
  page.setHome(home({ waiting: [ASK, ASK2] }));
  await poll(page.doc);
  assert.deepEqual(seen(page.window).sort(), ["egr-1", "egr-2"], "the ask was tried");
  assert.equal(state.textContent, BROKEN_ON);
  assert.equal(page.doc.getElementById("notify-test-result").hidden, true, "no test was sent");
  assert.equal(page.doc.getElementById("notify-test").hidden, false, "a test can still be tried");
  // Remembered for the tab only: a fresh load with a working browser reads On.
  const fresh = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  assert.equal(fresh.doc.getElementById("notify-state").textContent, ON_WORDS);
});

// ── Only protection problems (2026-10-26, §4.25 *Only protection problems*) ──
// While permission is granted, the row's "Notify me about" menu picks
// Everything (the default), Only protection problems, or Nothing (Turn off).
// One key: absent is Everything, the old '1' is Nothing, 'alarms' is Only
// protection problems. The alarms (protection failed, the service stopped
// under a running agent, another agent reaching the controls) still notify
// with Only protection problems; a question or a rule change does not, but
// is still recorded as seen.

const ALARMS_WORDS = "On for protection problems only. You get a notification when protection fails, when the protection service stops under a running agent, and when another agent can reach Mandu's controls, while a Mandu tab is open in this browser, also in the background. Not for questions or rule changes: the tab title still counts the questions waiting.";
const PENDING = "GET policy/proposals?status=pending";
/** A rule change your agent asked for. */
const AGENT_RULE = {
  id: "pp-7", status: "pending", requester: "Your agent", byAgent: true, reason: "need it",
  headline: "Your agent wants to change a rule", rows: [[{ kind: "text", text: "Allow connecting to " }, { kind: "code", text: "example.net" }]],
  createdAt: Date.now() - 60_000,
};
/** Primed for asks, rule changes, failed sessions and exposures; egr-1 seen. */
const PRIMED_ALL = { ...PRIMED, "mandu.home.seenProposals": "[]", "mandu.home.seenFailed": "[]", "mandu.home.seenExposure": "[]" };
const DOWN_HOME = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
/** Home with its agent s1 running and shown failed. */
function failedHome() {
  const vm = home({ waiting: [], verdict: "failed", headline: "Protection failed." });
  (vm.agents as any[])[0] = { ...(vm.agents as any[])[0], state: "running", waiting: 0, holds: false };
  return vm;
}
const exposedHome = () => home({ waiting: [], exposure: {
  headline: "Another agent can reach Mandu's own controls.", sentence: "An agent was started without the file guard.",
  fix: "Stop that agent.", fixParts: [{ kind: "text", text: "Stop that agent." }], since: 1_790_000_000_000, causes: [],
} });
const kindOf = (doc: any) => doc.getElementById("notify-kind");
function choose(doc: any, value: string): void {
  const sel = kindOf(doc);
  sel.focus();
  sel.value = value;
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
}

test("Notify me about: granted shows the menu at Everything; each choice stores its value, sets the words, Send a test and the button, and keeps the focus", async () => {
  const { doc, window } = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  const row = doc.getElementById("notify-kind-row");
  const sel = kindOf(doc);
  assert.equal(row.hidden, false, "granted: the menu");
  assert.match(row.textContent, /^Notify me about/);
  assert.equal(sel.closest("label"), row, "the menu is named by its label");
  assert.deepEqual([...sel.options].map((o: any) => [o.value, o.textContent]),
    [["all", "Everything"], ["alarms", "Only protection problems"], ["none", "Nothing"]]);
  assert.equal(sel.value, "all", "Everything by default");
  const state = doc.getElementById("notify-state");
  const test = doc.getElementById("notify-test");
  const btn = doc.getElementById("notify-enable");
  const cases: [string, string | null, string, boolean, string][] = [
    ["alarms", "alarms", ALARMS_WORDS, false, "Turn off"],
    ["none", "1", OFF_WORDS, true, "Turn on"],
    ["all", null, ON_WORDS, false, "Turn off"],
  ];
  for (const [value, stored, words, testHidden, label] of cases) {
    choose(doc, value);
    assert.equal(window.localStorage.getItem(OFF_KEY), stored, `${value}: stored`);
    assert.equal(state.textContent, words, `${value}: the words`);
    assert.equal(test.hidden, testHidden, `${value}: Send a test`);
    assert.equal(btn.textContent, label, `${value}: the button`);
    assert.equal(sel.value, value);
    assert.equal(doc.activeElement, sel, `${value}: the menu keeps the focus`);
    assert.equal(kindOf(doc), sel, "nothing drawn again");
  }
  // The button and the menu are one choice: Turn off is Nothing, Turn on is Everything.
  choose(doc, "alarms");
  btn.click();
  assert.equal(sel.value, "none");
  assert.equal(window.localStorage.getItem(OFF_KEY), "1");
  btn.click();
  assert.equal(sel.value, "all");
  assert.equal(window.localStorage.getItem(OFF_KEY), null);
});

test("Notify me about: the old '1' reads as Nothing, 'alarms' as Only protection problems, and a value the page does not know as Everything", async () => {
  for (const [stored, value, words] of [["1", "none", OFF_WORDS], ["alarms", "alarms", ALARMS_WORDS], ["later", "all", ON_WORDS]] as const) {
    const { doc, notes } = load({ url: SETTINGS_URL, storage: { ...PRIMED_ALL, [OFF_KEY]: stored }, homeVm: failedHome() });
    await tick();
    assert.equal(kindOf(doc).value, value, stored);
    assert.equal(doc.getElementById("notify-state").textContent, words, stored);
    assert.equal(notes.length, value === "none" ? 0 : 1, `${stored}: a failed session ${value === "none" ? "notifies nothing" : "notifies"}`);
  }
});

test("Notify me about: no menu while default, denied, or where the browser cannot notify", async () => {
  for (const [what, opts] of [
    ["default", { url: SETTINGS_URL, permission: "default", storage: PRIMED }],
    ["denied", { url: SETTINGS_URL, permission: "denied", storage: PRIMED }],
    ["unsupported", { url: SETTINGS_URL, storage: PRIMED, before: (w: any) => { delete w.Notification; } }],
  ] as [string, Parameters<typeof load>[0]][]) {
    const { doc, err } = load(opts);
    assert.equal(err, null, what);
    await tick();
    assert.equal(doc.getElementById("notify-kind-row").hidden, true, what);
  }
});

test("Only protection problems: a new ask and a new rule change notify nothing and are recorded as seen; switching back brings no backlog", async () => {
  let pending: unknown[] = [];
  const page = load({ url: SETTINGS_URL, storage: { ...PRIMED_ALL, [OFF_KEY]: "alarms" }, routes: { [PENDING]: () => ({ proposals: pending }) } });
  await tick();
  pending = [AGENT_RULE];
  page.setHome(home({ waiting: [ASK, ASK2] }));
  await poll(page.doc);
  assert.equal(page.notes.length, 0, page.notes.map((x) => x.title).join(" | "));
  assert.deepEqual(seen(page.window).sort(), ["egr-1", "egr-2"], "the ask is recorded as seen");
  assert.deepEqual(JSON.parse(page.window.localStorage.getItem("mandu.home.seenProposals")), ["pp-7"], "the rule change too");
  assert.match(page.doc.title, /^\(3\) /, "the tab title still counts them");
  choose(page.doc, "all");
  await poll(page.doc);
  assert.equal(page.notes.length, 0, "Everything again: no backlog");
  page.setHome(home({ waiting: [ASK, ASK2, ASK3] }));
  await poll(page.doc);
  assert.deepEqual(page.notes.map((x) => x.title), ["Mandu: Claude Code needs your OK"], "the next new ask notifies");
});

test("Only protection problems: a newly failed session, the service stopping after a read with a running agent, and an exposure each notify once", async () => {
  let answer: unknown = home({ waiting: [] });
  const page = load({ url: SETTINGS_URL, storage: { ...PRIMED_ALL, [OFF_KEY]: "alarms" }, routes: { "GET home": () => answer } });
  await tick();
  assert.equal(page.notes.length, 0);
  answer = failedHome();
  await poll(page.doc);
  assert.deepEqual(page.notes.map((x) => x.title), ["Mandu: protection failed in Claude Code"]);
  answer = DOWN_HOME; // the read before listed s1 running
  await poll(page.doc);
  assert.deepEqual(page.notes.map((x) => x.title).slice(1), ["Mandu: the protection service stopped"]);
  answer = exposedHome();
  await poll(page.doc);
  assert.deepEqual(page.notes.map((x) => x.title).slice(2), ["Mandu: another agent can reach Mandu's controls"]);
  assert.equal(page.notes.length, 3, "one each");
});

test("Only protection problems: Send a test says what it sends", async () => {
  const { doc, notes } = load({ url: SETTINGS_URL, storage: { ...PRIMED, [OFF_KEY]: "alarms" } });
  await tick();
  doc.getElementById("notify-test").click();
  assert.deepEqual(notes.map((x) => [x.title, x.body, x.tag]), [["Mandu: notifications work", "This is how Mandu tells you when protection fails.", "mandu-test"]]);
  assert.equal(doc.getElementById("notify-test-result").textContent, SENT);
});

test("Notify me about: where storage fails, the choice holds for the tab", async () => {
  let answer: unknown = home({ waiting: [] });
  const { doc, notes } = load({
    url: SETTINGS_URL, routes: { "GET home": () => answer },
    before: (w) => {
      const real = w.localStorage;
      const fail = () => { throw new Error("SecurityError"); };
      Object.defineProperty(w, "localStorage", { configurable: true, get: () => ({ getItem: fail, setItem: fail, removeItem: fail, key: real.key.bind(real), length: 0 }) });
    },
  });
  await tick(); // the first poll primes this tab
  choose(doc, "alarms");
  assert.equal(kindOf(doc).value, "alarms");
  assert.equal(doc.getElementById("notify-state").textContent, ALARMS_WORDS);
  answer = home({ waiting: [ASK, ASK2] });
  await poll(doc);
  assert.equal(notes.length, 0, "an ask: nothing, for this tab");
  answer = failedHome();
  await poll(doc);
  assert.deepEqual(notes.map((x) => x.title), ["Mandu: protection failed in Claude Code"], "an alarm still notifies");
});

test("another tab's Only protection problems: this tab's menu and words follow on the storage event", async () => {
  const { doc, window } = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  window.localStorage.setItem(OFF_KEY, "alarms");
  window.dispatchEvent(new window.StorageEvent("storage", { key: OFF_KEY, newValue: "alarms" }));
  assert.equal(kindOf(doc).value, "alarms");
  assert.equal(doc.getElementById("notify-state").textContent, ALARMS_WORDS);
});

// ── No thanks on Home's offer (2026-10-29, §4.25 *No thanks on Home's offer*) ──
// The offer row showed on every Home visit while the permission was
// `default`, and the only way to make it go was the browser's own prompt
// (and Block, which the page can never undo). Now it names the alarms too,
// and No thanks hides it in this browser (`mandu.home.notifyOfferHidden`,
// not Settings' `notifyOff`) without asking, leaving one line for this load
// that says where to turn them on later; the focus moves to its link.

const OFFER_KEY = "mandu.home.notifyOfferHidden";
const OFFER_WORDS = "Get a notification on this computer when an agent needs your OK or protection fails.";
const LATER_WORDS = "You can turn them on later in Settings › Notifications.";
/** A page with permission `default` that counts its `requestPermission` calls. */
function asking(opts: Parameters<typeof load>[0] = {}) {
  const page = load({ permission: "default", storage: PRIMED, ...opts });
  let asked = 0;
  page.window.Notification.requestPermission = () => { asked++; page.window.Notification.permission = "granted"; return Promise.resolve("granted"); };
  return { ...page, asked: () => asked };
}
/** Storage that throws on every call (private mode). */
function failingStorage(w: any): void {
  const real = w.localStorage;
  const fail = () => { throw new Error("SecurityError"); };
  Object.defineProperty(w, "localStorage", { configurable: true, get: () => ({ getItem: fail, setItem: fail, removeItem: fail, key: real.key.bind(real), length: 0 }) });
}

test("Home's offer, permission default: its words name the alarms, with No thanks and Turn on, each described by the words", async () => {
  const { doc, err } = asking();
  assert.equal(err, null);
  await tick();
  const offer = doc.getElementById("notify-offer");
  assert.equal(offer.hidden, false);
  assert.equal(doc.getElementById("notify-offer-words").textContent, OFFER_WORDS);
  const buttons = [...offer.querySelectorAll("button")];
  assert.deepEqual(buttons.map((b: any) => b.textContent), ["No thanks", "Turn on"]);
  for (const b of buttons) {
    assert.equal(b.className, "btn small", `${b.textContent}: not primary`);
    assert.equal(b.getAttribute("aria-describedby"), "notify-offer-words");
  }
  assert.equal(doc.getElementById("notify-offer-later").hidden, true, "no line before a press");
});

test("No thanks: stored in this browser, the offer goes, the line names Settings › Notifications with the focus on its link, and the browser is never asked", async () => {
  const page = asking();
  await tick();
  const { doc, window } = page;
  const no = doc.getElementById("notify-offer-no");
  no.focus();
  no.click();
  await tick();
  assert.equal(window.localStorage.getItem(OFFER_KEY), "1", "stored under its own key");
  assert.equal(window.localStorage.getItem(OFF_KEY), null, "Settings' choice untouched");
  assert.equal(doc.getElementById("notify-offer").hidden, true);
  const later = doc.getElementById("notify-offer-later");
  assert.equal(later.hidden, false);
  assert.equal(later.textContent, LATER_WORDS);
  const link = doc.getElementById("notify-offer-later-link");
  assert.match(link.href, /\/settings#notifications$/);
  assert.equal(doc.activeElement, link, "the focus is on the link, not lost");
  assert.equal(page.asked(), 0, "requestPermission never called");
  assert.equal(page.notes.length, 0);
  // The link opens Settings at its Notifications card.
  link.click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.equal(window.location.hash, "#notifications");
});

test("a reload with No thanks stored: no offer and no line; Settings still reads Off. with Turn on", async () => {
  const home = asking({ storage: { ...PRIMED, [OFFER_KEY]: "1" } });
  await tick();
  assert.equal(home.doc.getElementById("notify-offer").hidden, true);
  assert.equal(home.doc.getElementById("notify-offer-later").hidden, true, "the line was for that load only");
  const settings = asking({ url: SETTINGS_URL, storage: { ...PRIMED, [OFFER_KEY]: "1" } });
  await tick();
  assert.equal(settings.doc.getElementById("notify-state").textContent, "Off.");
  const btn = settings.doc.getElementById("notify-enable");
  assert.equal(btn.hidden, false);
  assert.equal(btn.textContent, "Turn on");
});

test("Settings' Turn on, granted, clears No thanks: asking means wanting them", async () => {
  const page = asking({ url: SETTINGS_URL, storage: { ...PRIMED, [OFFER_KEY]: "1" } });
  await tick();
  page.doc.getElementById("notify-enable").click();
  await tick();
  assert.equal(page.asked(), 1, "Settings' Turn on still asks the browser");
  assert.equal(page.window.localStorage.getItem(OFFER_KEY), null);
  assert.equal(page.doc.getElementById("notify-state").textContent, ON_WORDS);
});

test("where storage fails, No thanks holds for the tab", async () => {
  const page = asking({ storage: undefined, before: failingStorage });
  assert.equal(page.err, null);
  await tick();
  assert.equal(page.doc.getElementById("notify-offer").hidden, false);
  page.doc.getElementById("notify-offer-no").click();
  await tick();
  assert.equal(page.doc.getElementById("notify-offer").hidden, true);
  assert.equal(page.doc.activeElement, page.doc.getElementById("notify-offer-later-link"));
  await poll(page.doc);
  assert.equal(page.doc.getElementById("notify-offer").hidden, true, "still hidden after a poll");
  assert.equal(page.asked(), 0);
});

test("another tab's No thanks: this tab's offer goes on the storage event, with no line", async () => {
  const { doc, window } = asking();
  await tick();
  assert.equal(doc.getElementById("notify-offer").hidden, false);
  window.localStorage.setItem(OFFER_KEY, "1");
  window.dispatchEvent(new window.StorageEvent("storage", { key: OFFER_KEY, newValue: "1" }));
  assert.equal(doc.getElementById("notify-offer").hidden, true);
  assert.equal(doc.getElementById("notify-offer-later").hidden, true, "the line is the pressing tab's");
});

// ── The button does what it says; the row follows the permission (2026-10-30, §4.25) ──
// The row was drawn from `Notification.permission` only at load, on a press
// and on a storage event, while its button acted on the live permission: a
// tab drawn at `default` whose permission another tab then granted read
// "Off." with Turn on, and its press stored Nothing, in every tab.

const BLOCKED_WORDS = "Blocked in this browser. Allow notifications for this site in the browser settings.";
/** A `navigator.permissions` whose notifications status the test can fire. */
function permissionsApi(w: any): { status: any; queried: string[] } {
  const status = new w.EventTarget();
  const queried: string[] = [];
  Object.defineProperty(w.navigator, "permissions", { configurable: true, value: { query: (d: { name: string }) => { queried.push(d.name); return Promise.resolve(status); } } });
  return { status, queried };
}
/** Captures the page's poll (its one setInterval) so a test can run a tick. */
function capturePoll(w: any): () => void {
  let poll: () => void = () => { throw new Error("no poll registered"); };
  w.setInterval = (fn: () => void) => { poll = fn; return 0; };
  return () => poll();
}

test("(a) a tab drawn at default whose permission was granted elsewhere: Turn on leaves them on (no '1' stored) and the row reads On.", async () => {
  const page = load({ url: SETTINGS_URL, permission: "default", storage: PRIMED });
  await tick();
  const btn = page.doc.getElementById("notify-enable");
  assert.equal(btn.textContent, "Turn on");
  assert.equal(btn.dataset.intent, "on", "the button keeps what it shows");
  let asked = 0;
  page.window.Notification.requestPermission = () => { asked++; return Promise.resolve("granted"); };
  // Another tab's Turn on, Allow: the stored key was absent and stays absent, so no storage event.
  page.window.Notification.permission = "granted";
  btn.focus();
  btn.click();
  await tick();
  assert.equal(page.window.localStorage.getItem(OFF_KEY), null, "Everything, not Nothing");
  assert.equal(asked, 0, "granted already: nothing to ask");
  assert.equal(page.doc.getElementById("notify-state").textContent, ON_WORDS);
  assert.equal(btn.textContent, "Turn off");
  assert.equal(page.doc.activeElement, btn, "the button keeps the focus");
  // And they notify: the next new ask shows one.
  page.setHome(home({ waiting: [ASK, ASK2] }));
  await poll(page.doc);
  assert.deepEqual(page.notes.map((x) => x.title), ["Mandu: Claude Code needs your OK"]);
});

test("(a) a stale Turn on where an earlier choice was Nothing turns them on; a stale Turn off where the permission went away still stores Nothing", async () => {
  const on = load({ url: SETTINGS_URL, permission: "default", storage: { ...PRIMED, [OFF_KEY]: "1" } });
  await tick();
  on.window.Notification.permission = "granted";
  on.doc.getElementById("notify-enable").click();
  assert.equal(on.window.localStorage.getItem(OFF_KEY), null, "Turn on stores Everything");
  assert.equal(on.doc.getElementById("notify-state").textContent, ON_WORDS);

  const off = load({ url: SETTINGS_URL, storage: PRIMED });
  await tick();
  const btn = off.doc.getElementById("notify-enable");
  assert.equal(btn.textContent, "Turn off");
  let asked = 0;
  off.window.Notification.requestPermission = () => { asked++; return Promise.resolve("default"); };
  off.window.Notification.permission = "default"; // reset in the site panel
  btn.click();
  await tick();
  assert.equal(asked, 0, "Turn off never asks the browser");
  assert.equal(off.window.localStorage.getItem(OFF_KEY), "1", "Turn off stores Nothing");
  assert.equal(off.doc.getElementById("notify-state").textContent, "Off.", "drawn from the live permission");
  assert.equal(btn.textContent, "Turn on");
});

test("(b) the permissions change event: denied → granted redraws Blocked to On.; granted → default redraws with the focus kept", async () => {
  let api!: { status: any; queried: string[] };
  const page = load({ url: SETTINGS_URL, permission: "denied", storage: PRIMED, before: (w) => { api = permissionsApi(w); } });
  assert.equal(page.err, null);
  await tick();
  assert.deepEqual(api.queried, ["notifications"]);
  const state = page.doc.getElementById("notify-state");
  const btn = page.doc.getElementById("notify-enable");
  assert.equal(state.textContent, BLOCKED_WORDS);
  assert.equal(btn.hidden, true);
  // Unblocked in the site panel.
  page.window.Notification.permission = "granted";
  api.status.dispatchEvent(new page.window.Event("change"));
  assert.equal(state.textContent, ON_WORDS);
  assert.equal(btn.hidden, false);
  assert.equal(btn.textContent, "Turn off");
  assert.equal(page.doc.getElementById("notify-test").hidden, false, "Send a test is back");
  // Reset to ask: the row says Off. and the focus stays on its button.
  btn.focus();
  page.window.Notification.permission = "default";
  api.status.dispatchEvent(new page.window.Event("change"));
  assert.equal(state.textContent, "Off.");
  assert.equal(btn.textContent, "Turn on");
  assert.equal(page.doc.getElementById("notify-test").hidden, true, "no Send a test for what cannot be shown");
  assert.equal(page.doc.getElementById("notify-enable"), btn, "nothing drawn again");
  assert.equal(page.doc.activeElement, btn, "the focus is kept");
});

test("(c) without the permissions API: a poll tick, or the tab showing, redraws the row and hides Home's offer", async () => {
  let pollTick!: () => void;
  const page = load({ permission: "default", storage: PRIMED, before: (w) => { pollTick = capturePoll(w); } });
  assert.equal(page.err, null);
  assert.equal(page.window.navigator.permissions, undefined, "jsdom has none");
  await tick();
  const offer = page.doc.getElementById("notify-offer");
  assert.equal(offer.hidden, false);
  assert.equal(page.doc.getElementById("notify-state").textContent, "Off.");
  page.window.Notification.permission = "granted"; // Allow in another tab
  pollTick();
  assert.equal(offer.hidden, true, "the offer goes within a poll");
  assert.equal(page.doc.getElementById("notify-state").textContent, ON_WORDS);
  assert.equal(page.doc.getElementById("notify-enable").textContent, "Turn off");
  // The tab showing again does the same.
  page.window.Notification.permission = "denied";
  await poll(page.doc);
  assert.equal(page.doc.getElementById("notify-state").textContent, BLOCKED_WORDS);
});

test("(c) a permissions API that throws or rejects for notifications: the page loads and the poll still follows", async () => {
  for (const query of [() => { throw new TypeError("notifications is not a valid PermissionName"); }, () => Promise.reject(new TypeError("unsupported"))]) {
    let pollTick!: () => void;
    const page = load({
      url: SETTINGS_URL, permission: "denied", storage: PRIMED,
      before: (w) => { pollTick = capturePoll(w); Object.defineProperty(w.navigator, "permissions", { configurable: true, value: { query } }); },
    });
    assert.equal(page.err, null);
    await tick();
    assert.equal(page.doc.getElementById("notify-state").textContent, BLOCKED_WORDS);
    page.window.Notification.permission = "granted";
    pollTick();
    assert.equal(page.doc.getElementById("notify-state").textContent, ON_WORDS);
  }
});

test("(d) Turn off, as shown, still turns them off; a poll with the permission unchanged draws nothing again", async () => {
  let pollTick!: () => void;
  const page = load({ url: SETTINGS_URL, storage: PRIMED, before: (w) => { pollTick = capturePoll(w); } });
  await tick();
  const btn = page.doc.getElementById("notify-enable");
  assert.equal(btn.dataset.intent, "off");
  btn.click();
  assert.equal(page.window.localStorage.getItem(OFF_KEY), "1");
  assert.equal(page.doc.getElementById("notify-state").textContent, OFF_WORDS);
  assert.equal(btn.dataset.intent, "on");
  // Send a test's line survives a poll while nothing changed.
  btn.click();
  page.doc.getElementById("notify-test").click();
  const result = page.doc.getElementById("notify-test-result");
  assert.equal(result.hidden, false);
  pollTick();
  assert.equal(result.hidden, false, "no redraw while the permission is unchanged");
});
