/**
 * home-js-files-again-pages.test — the file browser under Rules › Add a
 * rule reads a folder again where it stands as far as it was shown
 * (public/js/home.js `readFolderAgain`, `pagesUpTo`; dashboard.md §4.25m
 * *The browser follows a return*).
 *
 * A folder is listed 500 entries at a time, and Show more reads the next
 * page. A folder whose labels could not be read, or whose listing got no
 * answer, is read again by the next Home poll that answers or by the
 * service's return. Until 2026-10-15 that read asked for the first page
 * only: the rows a Show more brought went, "Show more (N more)" came back, a
 * row opened among them closed, and a focus on one of them moved up to the
 * last row of the first page. A Show more whose page came back without
 * labels marks the folder unread itself, so with the labels unreadable its
 * rows went at the very next poll. Now:
 *
 *   P1  the service comes back: the folder is read again page by page up to
 *       the rows shown (the first page, then the same offset Show more
 *       read); the rows past the first page stay, with their labels now,
 *       the tick and the opened row among them, and the focus on its row;
 *   P2  labels a Show more could not read, while Home answers: the next
 *       poll reads both pages and the rows stay; the note still says the
 *       labels could not be read; a later poll reads nothing more;
 *   P3  a later page that fails while read again: the first page is shown,
 *       Show more says why over it and tries again; the focus never falls
 *       to the page;
 *   P4  a folder of one page is read once, with no offset;
 *   P5  a folder opened while the pages are read wins, and a poll meanwhile
 *       starts no read of its own;
 *   P6  a folder that changed between two pages lists an entry once;
 *   P7  a first page read again without labels and a later one with them:
 *       the note still says the labels could not be read, over the rows
 *       that have none.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real arbiter and dashboard, tests/stack/
 * product-files-again-pages.test.ts. Axes: none (display only). Mandu-new
 * test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, WS_LIST, CONFIG_LIST, NONE, list, fileRows, rowFor, tickRow, openRow, opened } from "./home-js-fixtures.js";

const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
const DIAL = "the protection service did not answer (connect ENOENT /run/user/1000/mandu/arbiter.sock)";
const ADMIN = "admin channel unavailable: this dashboard did not start the protection service (adopted instance)";
const LAST = { "mandu.files.folder": "/home/u/ws" };
const entry = (name: string) => ({ name, path: `/home/u/ws/${name}`, display: `~/ws/${name}`, kind: "file", link: null, label: NONE, inside: 0 });
const PAGE_ONE = { ...WS_LIST, total: 6, more: true };
const PAGE_TWO = { ...WS_LIST, entries: [entry("zeta.txt"), entry("zulu.txt")], total: 6, offset: 4, more: false };
/** A page as a listing without labels gives it (the service stopped). */
const unknown = (page: typeof PAGE_ONE, labelError: string) => ({
  ...page, labels: "unknown", labelError, axis: null, self: null, entries: page.entries.map((e) => ({ ...e, label: null, inside: 0 })),
});
const FIRST = list("/home/u/ws");
const SECOND = `${FIRST}&offset=4`;
const URL_FIRST = `/mandu/api/files/list?path=${encodeURIComponent("/home/u/ws")}`;
const URL_SECOND = `${URL_FIRST}&offset=4`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const note = (doc: any) => (doc.getElementById("files-note").hidden ? null : doc.getElementById("files-note").textContent);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const names = (doc: any) => fileRows(doc).map((r: any) => r.getAttribute("data-path").slice("/home/u/ws/".length));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const moreBtn = (doc: any) => doc.querySelector("#files-list .files-more") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const moreWords = (doc: any) => doc.getElementById("files-more-words")?.textContent ?? null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const unknownChips = (doc: any) => doc.querySelectorAll("#files-list .label-chip.unknown").length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const reads = (calls: { url: string }[], url: string) => calls.filter((c) => c.url === url).length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function openBrowser(doc: any) {
  doc.getElementById("rules-add").click();
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function showMore(doc: any) {
  moreBtn(doc).focus();
  moreBtn(doc).click();
  await tick();
}

test("P1: the service comes back: the folder is read again up to the rows shown, which stay with their tick, the opened row and the focus", async () => {
  let up = false;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [FIRST]: () => (up ? PAGE_ONE : unknown(PAGE_ONE, DIAL)),
    [SECOND]: () => (up ? PAGE_TWO : unknown(PAGE_TWO, DIAL)),
  } });
  await tick();
  await openBrowser(doc);
  await showMore(doc);
  assert.deepEqual(names(doc), ["config", ".env", "<img src=x onerror=alert(1)>.md", "README.md", "zeta.txt", "zulu.txt"]);
  assert.equal(unknownChips(doc), 6, "the labels are unknown, never ordinary");
  // What a person does meanwhile, past the first page: tick a row, open
  // another, and keep the focus on the first.
  tickRow(doc, /^zeta/);
  openRow(doc, /^zulu/);
  await tick();
  rowFor(doc, /^zeta/).querySelector(".file-tick").focus();
  const first = reads(calls, URL_FIRST);
  const second = reads(calls, URL_SECOND);

  up = true;
  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first + 1, "the first page is read again once");
  assert.equal(reads(calls, URL_SECOND), second + 1, "and the next one, at the offset Show more read");
  assert.deepEqual(names(doc), ["config", ".env", "<img src=x onerror=alert(1)>.md", "README.md", "zeta.txt", "zulu.txt"], "the rows past the first page stay");
  assert.equal(moreBtn(doc), null, "no Show more: the folder is shown to its end");
  assert.equal(note(doc), null, "no note: the labels are read");
  assert.equal(unknownChips(doc), 0, "every row has its label, those past the first page too");
  assert.equal(rowFor(doc, /^zeta/).querySelector(".file-tick").checked, true, "the tick stays");
  assert.match(doc.getElementById("files-selected").textContent, /1 item ticked/);
  assert.equal(rowFor(doc, /^zulu/).classList.contains("open"), true, "the opened row stays open");
  assert.ok(opened(doc), "with its details");
  assert.equal(doc.activeElement, rowFor(doc, /^zeta/).querySelector(".file-tick"), "the focus stays on its row");

  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first + 1, "a poll after that reads nothing again");
  assert.equal(reads(calls, URL_SECOND), second + 1);
});

test("P2: labels a Show more could not read, while Home answers: the next poll reads both pages and the rows stay; then only a return reads", async () => {
  let up = true;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [FIRST]: PAGE_ONE,
    [SECOND]: () => (up ? unknown(PAGE_TWO, ADMIN) : DOWN),
  } });
  await tick();
  await openBrowser(doc);
  assert.equal(note(doc), null);
  await showMore(doc);
  assert.deepEqual(names(doc).slice(-2), ["zeta.txt", "zulu.txt"]);
  const first = reads(calls, URL_FIRST);
  const second = reads(calls, URL_SECOND);
  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first + 1, "the folder is read again");
  assert.equal(reads(calls, URL_SECOND), second + 1, "as far as it was shown");
  assert.equal(names(doc).length, 6, "the rows Show more brought stay");
  assert.match(note(doc)!, /^Labels could not be read: admin channel unavailable/, "a page whose labels could not be read still says so");
  assert.equal(unknownChips(doc), 2, "on its rows only");
  await poll(doc);
  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first + 1, "read again once, not on every poll");
  assert.equal(reads(calls, URL_SECOND), second + 1);
  // A return: the page whose labels could not be read is read again.
  up = false;
  await poll(doc);
  up = true;
  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first + 2, "a return reads the folder again");
  assert.equal(reads(calls, URL_SECOND), second + 2, "as far as it was shown");
  assert.equal(names(doc).length, 6);
});

test("P3: a later page that fails while read again leaves the first page, says why over Show more, which tries again; the focus never falls to the page", async () => {
  let up = false;
  let secondReads = 0;
  const EIO = { status: 500, body: { error: "could not list the folder: EIO: i/o error" } };
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [FIRST]: () => (up ? PAGE_ONE : unknown(PAGE_ONE, DIAL)),
    // Show more reads it, the read again fails, the press after that reads it.
    [SECOND]: () => [unknown(PAGE_TWO, DIAL), EIO, PAGE_TWO][Math.min(secondReads++, 2)],
  } });
  await tick();
  await openBrowser(doc);
  await showMore(doc);
  assert.equal(names(doc).length, 6);
  rowFor(doc, /^zulu/).querySelector(".file-tick").focus();

  up = true;
  await poll(doc);
  assert.deepEqual(names(doc), ["config", ".env", "<img src=x onerror=alert(1)>.md", "README.md"], "the first page, read again");
  assert.equal(note(doc), null, "its labels are read");
  assert.equal(moreWords(doc), "Could not read more of this folder: could not list the folder: EIO: i/o error.", "why the rest is not shown, in the server's words");
  assert.equal(moreBtn(doc).textContent, "Show more (2 more)");
  assert.equal(moreBtn(doc).getAttribute("aria-describedby"), "files-more-words");
  assert.notEqual(doc.activeElement, doc.body, "the focus never falls to the page");
  assert.ok(doc.getElementById("files-list").contains(doc.activeElement), "it stays in the list");

  moreBtn(doc).focus();
  moreBtn(doc).click();
  await tick();
  assert.equal(reads(calls, URL_SECOND), 3, "Show more tries again");
  assert.equal(names(doc).length, 6);
  assert.equal(moreWords(doc), null, "an answer drops the words");
});

test("P4: a folder of one page is read again once, with no offset", async () => {
  let up = false;
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [FIRST]: () => (up ? WS_LIST : unknown(WS_LIST as typeof PAGE_ONE, DIAL)),
  } });
  await tick();
  await openBrowser(doc);
  const first = reads(calls, URL_FIRST);
  up = true;
  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first + 1);
  assert.equal(calls.filter((c) => c.url.includes("&offset=")).length, 0, "no further page is asked for");
  assert.equal(names(doc).length, 4);
});

test("P5: a folder opened while the pages are read wins, and a poll meanwhile starts no read of its own", async () => {
  let up = false;
  let hold = false;
  let release: (v: unknown) => void = () => {};
  const { doc, calls } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [FIRST]: () => (up ? PAGE_ONE : unknown(PAGE_ONE, DIAL)),
    [SECOND]: () => (hold ? new Promise((r) => { release = r; }) : unknown(PAGE_TWO, DIAL)),
    [list("/home/u/ws/config")]: CONFIG_LIST,
  } });
  await tick();
  await openBrowser(doc);
  await showMore(doc);
  hold = true;
  up = true;
  await poll(doc); // reads the first page, then waits on the second
  assert.equal(names(doc).length, 6, "the rows drawn stay while the pages are read");
  const first = reads(calls, URL_FIRST);
  // Another return while the second page is on its way: no read of its own.
  up = false;
  await poll(doc);
  up = true;
  await poll(doc);
  assert.equal(reads(calls, URL_FIRST), first, "the pages on their way are not overtaken by a poll");
  rowFor(doc, /^config\//).querySelector(".file-open").click();
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws/config", "the folder you opened is shown");
  release(PAGE_TWO);
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws/config", "the folder read again does not come back over it");
  assert.deepEqual(names(doc), ["config/db.yaml"], "its own rows, none of ws");
  assert.equal(moreBtn(doc), null);
});

test("P6: a folder that changed between two pages lists an entry once", async () => {
  let up = false;
  const { doc } = load({ url: FILES_URL, storage: LAST, routes: {
    "GET home": () => (up ? undefined : DOWN),
    [FIRST]: () => (up ? PAGE_ONE : unknown(PAGE_ONE, DIAL)),
    // A file came in at the top: the first page ends a row earlier, so the
    // second begins with the last row of the first.
    [SECOND]: () => (up ? { ...PAGE_TWO, entries: [WS_LIST.entries[3], ...PAGE_TWO.entries] } : unknown(PAGE_TWO, DIAL)),
  } });
  await tick();
  await openBrowser(doc);
  await showMore(doc);
  up = true;
  await poll(doc);
  assert.deepEqual(names(doc), ["config", ".env", "<img src=x onerror=alert(1)>.md", "README.md", "zeta.txt", "zulu.txt"], "README.md once");
});

test("P7: a first page read again without labels and a later one with them: the note still says the labels could not be read", async () => {
  const { doc } = load({ url: FILES_URL, storage: LAST, routes: { [FIRST]: unknown(PAGE_ONE, ADMIN), [SECOND]: PAGE_TWO } });
  await tick();
  await openBrowser(doc);
  await showMore(doc);
  await poll(doc); // the folder is unread: the next poll reads it again
  assert.equal(names(doc).length, 6);
  assert.match(note(doc)!, /^Labels could not be read: admin channel unavailable/, "never a note gone while rows have no label");
  assert.equal(unknownChips(doc), 4, "the first page's rows");
});
