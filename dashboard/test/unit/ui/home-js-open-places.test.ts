/**
 * home-js-open-places.test — Home warns when other people on this computer
 * can open places in Mandu's folder (dashboard.md §4.25q *Home warns about
 * open places*): the card `#home-open-places`, drawn by public/js/home.js
 * `renderOpenPlacesNotice` from /api/home's `openPlaces`, in jsdom over a
 * fetch stub (home-js-fixtures.ts) with a stubbed clipboard.
 *
 * Pins:
 * - the symbol database (or the session history) open: the "real values"
 *   headline; only other places: "can open N places in Mandu's folder";
 * - the places by what they hold, at most three, then "and N more";
 * - `mandu paths` as a command with its Copy; "See every place" opens Where
 *   your data lives (reading it) and moves the focus to its summary;
 * - none: hidden; a poll without it hides it again; a failed poll leaves it;
 * - never a path: the card names places by what they hold.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const SYMBOL_DB = { name: "symbol-db", holds: "the masked values the AI saw, the real values behind them, and your approvals" };
const EVENTS = { name: "events", holds: "session history, kept 90 days; it includes the real values behind masked ones" };
const LAUNCH_LOGS = { name: "launch-logs", holds: "what each launch said: its notices, warnings and helper messages (mandu log shows the latest); the last 20 launches" };
const PACKS = { name: "packs", holds: "rule packs you installed" };
const POLICY = { name: "policy", holds: "your rules: which files, hosts and models count as secret" };

const LOCATIONS = {
  home: "~/.mandu",
  locations: [{ name: "symbol-db", path: "~/.mandu/state/symbols.db", where: "home", holds: SYMBOL_DB.holds, developer: false, exists: true, brokenLink: false, mode: "0644", ownerOnly: false }],
};

function page(homeVm: unknown, routes: Record<string, unknown> = {}) {
  const wrote: string[] = [];
  const p = load({ homeVm, routes: { "GET data-locations": LOCATIONS, ...routes }, before: (w: Doc) => {
    Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => (wrote.push(t), w.Promise.resolve()) } });
  } });
  assert.equal(p.err, null);
  return { ...p, wrote };
}

async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

const items = (doc: Doc) => ([...doc.querySelectorAll("#open-places-list li")] as Doc[]).map((li) => li.textContent);

test("the symbol database open to others: the real-values headline, what it holds, mandu paths with its Copy", async () => {
  const { doc, wrote } = page(home({ openPlaces: [PACKS, SYMBOL_DB] }));
  await tick(40);
  const block = doc.getElementById("home-open-places");
  assert.equal(block.hidden, false);
  assert.equal(block.getAttribute("role"), "status");
  assert.ok(block.classList.contains("update-notice") && block.classList.contains("exposure"), "styled as the policy card");
  assert.equal(block.previousElementSibling.id, "home-policy-refused", "among the top cards, after the policy card");
  assert.equal(doc.getElementById("open-places-headline").textContent, "Other people on this computer can read the real values of your secrets");
  assert.equal(doc.getElementById("open-places-sentence").textContent, "Open to others:");
  assert.deepEqual(items(doc), ["The masked values the AI saw, the real values behind them, and your approvals", "Rule packs you installed"], "the records of real values first");
  const fix = doc.getElementById("open-places-fix");
  assert.equal(fix.querySelectorAll("button.run-copy").length, 1, "one Copy");
  assert.equal(fix.textContent, "Run mandu pathsCopy in a terminal for the command that makes them yours only. See every place");
  const run = fix.querySelector(".run-code");
  assert.equal(run.querySelector("code").textContent, "mandu paths");
  const copy = run.querySelector("button.run-copy");
  assert.ok(copy, "the command has its Copy");
  copy.click();
  await tick();
  assert.deepEqual(wrote, ["mandu paths"]);
  // Never a path: the card names places by what they hold.
  assert.doesNotMatch(block.textContent, /~\/|\/home\/|symbols\.db|0644/);
});

test("the session history alone is real values too; other places only: the count headline", async () => {
  const ev = page(home({ openPlaces: [EVENTS] }));
  await tick(40);
  assert.equal(ev.doc.getElementById("open-places-headline").textContent, "Other people on this computer can read the real values of your secrets");
  const one = page(home({ openPlaces: [LAUNCH_LOGS] }));
  await tick(40);
  assert.equal(one.doc.getElementById("open-places-headline").textContent, "Other people on this computer can open 1 place in Mandu's folder");
  assert.deepEqual(items(one.doc), ["What each launch said: its notices, warnings and helper messages (mandu log shows the latest); the last 20 launches"]);
  const two = page(home({ openPlaces: [LAUNCH_LOGS, PACKS] }));
  await tick(40);
  assert.equal(two.doc.getElementById("open-places-headline").textContent, "Other people on this computer can open 2 places in Mandu's folder");
});

test("more than three places: the records of real values first, in the order of the answer, three in all, then 'and N more'", async () => {
  const { doc } = page(home({ openPlaces: [LAUNCH_LOGS, PACKS, POLICY, EVENTS, SYMBOL_DB] }));
  await tick(40);
  assert.deepEqual(items(doc), [
    "Session history, kept 90 days; it includes the real values behind masked ones",
    "The masked values the AI saw, the real values behind them, and your approvals",
    "What each launch said: its notices, warnings and helper messages (mandu log shows the latest); the last 20 launches",
    "and 2 more",
  ]);
});

test("See every place opens Where your data lives, reads it, and moves the focus to it", async () => {
  const { doc, window, calls } = page(home({ openPlaces: [SYMBOL_DB] }));
  await tick(40);
  const fold = doc.getElementById("home-data");
  assert.equal(fold.open, false, "closed by default");
  const link = doc.querySelector("#open-places-fix a");
  assert.equal(link.textContent, "See every place");
  assert.match(link.getAttribute("href"), /^\/mandu\/#home-data$/);
  const click = new window.MouseEvent("click", { bubbles: true, cancelable: true });
  link.dispatchEvent(click);
  assert.equal(click.defaultPrevented, true, "a plain click stays on the page");
  await tick(40);
  assert.equal(fold.open, true);
  assert.equal(doc.activeElement, fold.querySelector("summary"), "the focus moves to the section");
  assert.ok(calls.some((c) => c.url.endsWith("/api/data-locations")), "the list is read, as opening it by hand does");
  assert.equal(doc.querySelectorAll("#home-data-list .data-where-row").length, 1);
  // Pressed again with the section open: read again, the focus there.
  const before = calls.filter((c) => c.url.endsWith("/api/data-locations")).length;
  link.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick(40);
  assert.equal(fold.open, true);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/data-locations")).length, before + 1);
  assert.equal(doc.activeElement, fold.querySelector("summary"));
  // A modifier click is the browser's.
  const ctrl = new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true });
  link.dispatchEvent(ctrl);
  assert.equal(ctrl.defaultPrevented, false);
});

test("none open: hidden; a poll without them hides the card again; a failed poll leaves it as drawn", async () => {
  const none = page(home());
  await tick(40);
  assert.equal(none.doc.getElementById("home-open-places").hidden, true);
  for (const bad of [[], null, "events", [{ name: "events" }], [{ holds: "x" }]]) {
    const p = page(home({ openPlaces: bad }));
    await tick(40);
    assert.equal(p.doc.getElementById("home-open-places").hidden, true, JSON.stringify(bad));
  }

  let fail = false;
  let vm: unknown = home({ openPlaces: [SYMBOL_DB] });
  const { doc } = page(undefined, { "GET home": () => (fail ? { status: 500, body: {} } : vm) });
  await tick(40);
  const block = doc.getElementById("home-open-places");
  assert.equal(block.hidden, false);
  const li = doc.querySelector("#open-places-list li");
  await poll(doc);
  assert.equal(doc.querySelector("#open-places-list li"), li, "the same answer: left as drawn");
  fail = true;
  await poll(doc);
  assert.equal(block.hidden, false, "a failed poll says nothing about the modes: the card stays");
  fail = false;
  vm = home();
  await poll(doc);
  assert.equal(block.hidden, true, "the modes fixed: the card goes on the next poll");
  vm = home({ openPlaces: [LAUNCH_LOGS] });
  await poll(doc);
  assert.equal(block.hidden, false, "open again: it comes back");
  assert.equal(doc.getElementById("open-places-headline").textContent, "Other people on this computer can open 1 place in Mandu's folder");
});

test("what a place holds stays text", async () => {
  const { doc } = page(home({ openPlaces: [{ name: "packs", holds: "<img src=x onerror=alert(1)>" }] }));
  await tick(40);
  assert.equal(doc.querySelector("#home-open-places img"), null);
  assert.deepEqual(items(doc), ["<img src=x onerror=alert(1)>"]);
});
