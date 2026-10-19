/**
 * home-js-files-again.test — the file browser under Rules › Add a rule says
 * a stopped protection service in the page's words, and reads its folder
 * again when the service or the dashboard comes back (public/js/home.js;
 * dashboard.md §4.25 *What could not be read is read again*, §4.25m).
 *
 * Until 2026-10-10 the browser printed the route's label error as it came:
 * with the service stopped, "Labels could not be read: the protection
 * service did not answer (connect ENOENT /…/arbiter.sock). You can still
 * choose rules.", a socket path where every other line of the page says
 * the service is not running. And when the service (or the dashboard)
 * came back, Your rules and Settings read again but the open browser kept
 * its note, every row's "Label unknown" and a rule of yours showing "No
 * rule", until you opened another folder; opening the browser again
 * cleared what you had ticked and typed. Now:
 *
 * - a label error that is the failed dial to the service's socket reads
 *   "Labels could not be read. The protection service is not running.
 *   Start it under Settings, or try again in a moment. You can still choose
 *   rules.", the link opening Settings; any other error as the server wrote
 *   it;
 * - a return (a Home poll that answers after one that failed) reads the
 *   folder shown again, once, where it stands: the path box, the ticked
 *   rows, the opened row with the hosts typed in it (and the focus), and
 *   the changes waiting stay; a "What the rules say" that could not be read
 *   asks again;
 * - a listing the browser itself got no answer for, in an outage too short
 *   for the Home poll to see, is read again by the next Home poll that
 *   answers, once: one still unread waits for a return;
 * - a folder that was read is not read again, nor one whose listing is on
 *   its way (the folder you just opened wins); off Rules, a return reads
 *   the browser too, and a visit to Rules then shows it read.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real arbiter and dashboard, tests/stack/
 * product-files-back.test.ts. Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  load, tick, FILES_URL, WS_LIST, CONFIG_LIST, list, fileRows, rowFor, tickRow, openRow, opened, dot,
} from "./home-js-fixtures.js";

const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
const noAnswer = () => { throw new TypeError("Failed to fetch"); };
const DIAL = "the protection service did not answer (connect ENOENT /run/user/1000/mandu/arbiter.sock)";
const unknownList = (labelError: string) => ({
  ...WS_LIST, labels: "unknown", labelError, axis: null, self: null,
  entries: WS_LIST.entries.map((e) => ({ ...e, label: null, inside: 0 })),
});
const NOTE_DOWN = "Labels could not be read. The protection service is not running. Start it under Settings, or try again in a moment. You can still choose rules.";
const GONE = "The dashboard could not reach its own server. Refresh in a moment.";
/** The folder this browser showed last (home.js FILES_LAST_KEY): where the
 *  browser starts while Home, which names the agents' folders, is unread. */
const LAST = { "mandu.files.folder": "/home/u/ws" };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const note = (doc: any) => (doc.getElementById("files-note").hidden ? null : doc.getElementById("files-note").textContent);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const links = (node: any) => [...node.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const unknownChips = (doc: any) => doc.querySelectorAll("#files-list .label-chip.unknown").length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const reads = (calls: { url: string }[], folder: string) => calls.filter((c) => c.url === `/mandu/api/files/list?path=${encodeURIComponent(folder)}`).length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function openBrowser(doc: any) {
  doc.getElementById("rules-add").click();
  await tick();
}

test("the browser's note says a stopped service in the page's words, linked to its Start, never the socket the route could not dial; any other label error as the server wrote it", async () => {
  for (const error of [DIAL, "the protection service did not answer (connect ECONNREFUSED /tmp/mandu-1000/arbiter.sock)"]) {
    const { doc } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: unknownList(error) } });
    await tick();
    await openBrowser(doc);
    assert.equal(note(doc), NOTE_DOWN, error);
    assert.deepEqual(links(doc.getElementById("files-note")), [["Start it under Settings", "/mandu/settings", "settings"]]);
    assert.doesNotMatch(doc.getElementById("page-rules").textContent, /ENOENT|ECONNREFUSED|\.sock/);
    assert.equal(unknownChips(doc), 4, "the labels stay unknown, never ordinary");
  }
  const admin = "admin channel unavailable: this dashboard did not start the protection service (adopted instance)";
  const { doc } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: unknownList(admin) } });
  await tick();
  await openBrowser(doc);
  assert.equal(note(doc), `Labels could not be read: ${admin}. You can still choose rules.`);
  assert.deepEqual(links(doc.getElementById("files-note")), []);
});

test("the service comes back: the browser reads its folder again once, where it stands: the path box, the ticked rows, the opened row with its typed hosts and focus, and the changes waiting stay", async () => {
  let up = false;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [list("/home/u/ws")]: () => (up ? WS_LIST : unknownList(DIAL)),
  } });
  await tick();
  await openBrowser(doc);
  assert.equal(note(doc), NOTE_DOWN);
  assert.match(rowFor(doc, /^config\//).textContent, /Label unknown/);
  // What a person does meanwhile: tick a row, queue a change, open a row
  // and type hosts in it, type a path.
  tickRow(doc, /^config\//);
  dot(doc, /README/, "no-model");
  openRow(doc, /^\.env/);
  await tick();
  const to = doc.getElementById("lock-to") as any;
  to.value = "api.example.com, pay";
  to.focus();
  to.setSelectionRange(5, 5);
  (doc.getElementById("lock-path") as any).value = "~/ws/RE";
  const before = reads(calls, "/home/u/ws");

  up = true;
  await poll(doc);
  assert.equal(reads(calls, "/home/u/ws"), before + 1, "the folder is read again once");
  assert.equal(note(doc), null, "no note: the labels are read");
  assert.equal(unknownChips(doc), 0);
  assert.match(rowFor(doc, /^config\//).textContent, /Your rule/, "a rule of yours shows as yours again");
  assert.equal(rowFor(doc, /^config\//).querySelector("input[type=checkbox]").checked, true, "the tick stays");
  assert.match(doc.getElementById("files-selected").textContent, /1 item ticked/);
  assert.match(doc.getElementById("files-pending-list").textContent, /README/, "the change waiting stays");
  assert.match(rowFor(doc, /README/).textContent, /Will be: No AI \(not saved\)/);
  assert.equal(rowFor(doc, /^\.env/).classList.contains("open"), true, "the opened row stays open");
  assert.match(opened(doc).textContent, /Built in: environment files/, "with what the new listing says of it");
  const typed = doc.getElementById("lock-to") as any;
  assert.equal(typed.value, "api.example.com, pay", "the hosts typed in it stay");
  assert.equal(doc.activeElement, typed, "with the focus");
  assert.equal(typed.selectionStart, 5);
  assert.equal((doc.getElementById("lock-path") as any).value, "~/ws/RE", "the path box keeps what was typed");

  await poll(doc);
  assert.equal(reads(calls, "/home/u/ws"), before + 1, "a poll after that reads nothing again");
});

test("the service comes back: a \"What the rules say\" that could not be read asks again in its open box", async () => {
  let up = true;
  const WHY = { why: { path: "/home/u/ws/.env", display: "~/ws/.env", label: WS_LIST.entries[1]!.label, off: false, lines: [{ term: "Where the label comes from", text: "Built in: environment files" }] } };
  const whyRoute = `GET files/why?path=${encodeURIComponent("/home/u/ws/.env")}`;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [list("/home/u/ws")]: WS_LIST,
    [whyRoute]: () => (up ? WHY : DOWN),
  } });
  await tick();
  await openBrowser(doc);
  up = false;
  await poll(doc);
  openRow(doc, /^\.env/);
  await tick();
  assert.equal(opened(doc).querySelector(".file-why .ask-error").textContent, "The protection service is not running. Start it under Settings, or try again in a moment.");
  const asked = calls.filter((c) => c.url.includes("/api/files/why")).length;
  const listed = reads(calls, "/home/u/ws");
  up = true;
  await poll(doc);
  assert.equal(calls.filter((c) => c.url.includes("/api/files/why")).length, asked + 1, "asked again once");
  assert.match(opened(doc).querySelector(".file-why").textContent, /Where the label comes fromBuilt in: environment files/);
  assert.equal(reads(calls, "/home/u/ws"), listed, "a folder that was read is not read again");
});

test("the dashboard comes back: a browser that got no answer reads where it starts; a listing with no answer in an outage the Home poll never saw is read again by the next poll that answers, once", async () => {
  let gone = true;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (gone ? noAnswer() : undefined),
    [list("/home/u/ws")]: () => (gone ? noAnswer() : WS_LIST),
    [list("~")]: () => (gone ? noAnswer() : WS_LIST),
    [list("/home/u/ws/config")]: () => (gone ? noAnswer() : CONFIG_LIST),
  } });
  await tick();
  await openBrowser(doc);
  assert.equal(note(doc), GONE, "the browser never showed a folder");
  assert.equal(fileRows(doc).length, 0);
  gone = false;
  await poll(doc);
  assert.equal(note(doc), null);
  assert.equal(fileRows(doc).length, 4, "it shows where it starts");
  assert.equal((doc.getElementById("lock-path") as any).value, "~/ws/", "the path box names the folder");

  // An outage too short for the Home poll: only the click into config saw it.
  gone = true;
  rowFor(doc, /^config\//).querySelector(".file-open").click();
  await tick();
  assert.equal(note(doc), GONE);
  gone = false;
  const before = reads(calls, "/home/u/ws");
  await poll(doc); // answers, with no failed poll before it
  assert.equal(reads(calls, "/home/u/ws"), before + 1, "the folder shown is read again");
  assert.equal(note(doc), null, "and the note goes");
  assert.equal(fileRows(doc).length, 4);

  // A listing that keeps failing while the Home poll answers is read again
  // once, then waits for a return: never a read on every poll.
  const failing = { status: 500, body: { error: "could not list the folder: EIO" } };
  const { doc: d2, calls: c2 } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: failing, [list("~")]: failing } });
  await tick();
  await openBrowser(d2);
  assert.equal(note(d2), "could not list the folder: EIO");
  const first = reads(c2, "/home/u/ws");
  await poll(d2);
  await poll(d2);
  await poll(d2);
  assert.equal(reads(c2, "/home/u/ws"), first + 1, "read again once, not on every poll");
});

test("labels that cannot be read while the service answers are read again once, then only on a return", async () => {
  const admin = "admin channel unavailable: this dashboard did not start the protection service (adopted instance)";
  const { doc, calls } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: unknownList(admin) } });
  await tick();
  await openBrowser(doc);
  const first = reads(calls, "/home/u/ws");
  await poll(doc);
  await poll(doc);
  assert.equal(reads(calls, "/home/u/ws"), first + 1);
  assert.match(note(doc)!, /^Labels could not be read: admin channel unavailable/);
});

test("a return does not overtake a folder you just opened, nor read a browser whose folder was read", async () => {
  let up = false;
  let release: (v: unknown) => void = () => {};
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [list("/home/u/ws")]: () => (up ? WS_LIST : unknownList(DIAL)),
    [list("/home/u/ws/config")]: () => new Promise((r) => { release = r; }),
  } });
  await tick();
  await openBrowser(doc);
  assert.equal(note(doc), NOTE_DOWN);
  rowFor(doc, /^config\//).querySelector(".file-open").click(); // on its way
  await tick();
  const before = reads(calls, "/home/u/ws");
  up = true;
  await poll(doc);
  assert.equal(reads(calls, "/home/u/ws"), before, "the return leaves the folder you opened to come");
  release(CONFIG_LIST);
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws/config", "the folder you opened is shown");
  assert.equal(note(doc), null);

  // Read fine: a later return reads nothing.
  const { doc: d2, calls: c2 } = load({ url: FILES_URL, routes: { "GET home": () => (up ? undefined : DOWN), [list("/home/u/ws")]: WS_LIST } });
  await tick();
  await openBrowser(d2);
  const read = reads(c2, "/home/u/ws");
  up = false;
  await poll(d2);
  up = true;
  await poll(d2);
  assert.equal(reads(c2, "/home/u/ws"), read);
});

test("off Rules, a return reads the browser too: a visit to Rules then shows it read, with no read of its own", async () => {
  let up = false;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [list("/home/u/ws")]: () => (up ? WS_LIST : unknownList(DIAL)),
  } });
  await tick();
  await openBrowser(doc);
  assert.equal(note(doc), NOTE_DOWN);
  const nav = (page: string) => doc.querySelector(`[data-page-link="${page}"]`)
    .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
  nav("home");
  await tick();
  up = true;
  await poll(doc);
  const read = reads(calls, "/home/u/ws");
  nav("rules");
  await tick();
  assert.equal(reads(calls, "/home/u/ws"), read, "the visit reads nothing more");
  assert.equal(doc.getElementById("lock-form").hidden, false);
  assert.equal(note(doc), null);
  assert.equal(unknownChips(doc), 0);
});
