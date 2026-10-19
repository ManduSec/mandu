/**
 * home-js-files-complete-pages.test — Tab completion on the path box under
 * Rules › Add a rule knows the whole folder, not its first page
 * (public/js/home.js `completePath`, `completionNames`, `unreadMayMatch`;
 * dashboard.md §4.25m *Typed paths and Tab completion*).
 *
 * The listing answers 500 entries a page, folders first and then by name.
 * Until 2026-10-15 completion read the first page only (and the folder the
 * browser showed lent it its first page only), so past 500 entries a name
 * could not be completed, and in a folder of more than 500 folders a name a
 * folder and a file share completed to the folder: `~/big/not` became
 * `~/big/notes/` with `notes.md` beside it. Now:
 *
 *   C1  a folder not shown: Tab completes a name past the first page; each
 *       page is read once;
 *   C2  a name a folder and a file past the page share completes to their
 *       shared start, never to the folder, and the suggestions list both;
 *   C3  the folder the browser shows lends the pages it read: after Show
 *       more, Tab reads nothing; before it, Tab reads the next page once;
 *   C4  a later page that fails: Tab completes only what no unread name
 *       could change (after a folder, a file of any name may follow), else
 *       leaves the text as typed; a Tab on other text, or typing, reads
 *       the page again, and a second Tab on the same text moves the focus
 *       on (home-js-files-tab-moves-on.test.ts);
 *   C5  a folder past 10,000 names: 20 pages are read, once; a name among
 *       them completes, one that may sort past them stays as typed and Tab
 *       moves on;
 *   C6  typing while the pages are read: each page is read once, and only
 *       the newest text is completed;
 *   C7  a folder that changed between two pages: an entry repeated at the
 *       seam is suggested once, and a page that brings nothing new ends
 *       the read;
 *   C8  a folder of one page reads no offset.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real arbiter and dashboard, tests/stack/
 * product-complete-pages.test.ts. Axes: none (display only). Mandu-new
 * test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, WS_LIST, NONE, list, fileRows } from "./home-js-fixtures.js";

type Entry = { name: string; path: string; display: string; kind: string; link: null; label: typeof NONE; inside: number };
const entry = (dir: string, name: string, kind = "file"): Entry =>
  ({ name, path: `/home/u/${dir}/${name}`, display: `~/${dir}/${name}`, kind, link: null, label: NONE, inside: 0 });
/** One folder's listing, 500 entries a page, as the route answers it. */
function folder(dir: string, all: Entry[]) {
  const path = `/home/u/${dir}`;
  const page = (offset: number) => ({
    ...WS_LIST, path, display: `~/${dir}`, crumbs: [], entries: all.slice(offset, offset + 500),
    total: all.length, offset, more: offset + 500 < all.length,
  });
  const routes: Record<string, unknown> = { [list(`~/${dir}`)]: page(0), [list(path)]: page(0) };
  for (let at = 500; at < all.length; at += 500) routes[`${list(path)}&offset=${at}`] = page(at);
  return { routes, page, first: `/mandu/api/files/list?path=${encodeURIComponent(`~/${dir}`)}`, shown: `/mandu/api/files/list?path=${encodeURIComponent(path)}`, at: (n: number) => `/mandu/api/files/list?path=${encodeURIComponent(path)}&offset=${n}` };
}
// 500 folders (d000 … d498, notes), then three files: every file is past the first page.
const BIG = folder("big", [
  ...Array.from({ length: 499 }, (_, i) => entry("big", `d${String(i).padStart(3, "0")}`, "dir")), entry("big", "notes", "dir"),
  entry("big", "notes.md"), entry("big", "zeta-1.env"), entry("big", "zeta-2.env"),
]);
// Files only: f000.txt … f499.txt, then f499a.txt (sorts after f499.txt) and g.txt.
const FLAT = folder("flat", [
  ...Array.from({ length: 500 }, (_, i) => entry("flat", `f${String(i).padStart(3, "0")}.txt`)),
  entry("flat", "f499a.txt"), entry("flat", "g.txt"),
]);
const DOWN = { status: 503, body: { error: "the dashboard could not list the folder" } };

const reads = (calls: { url: string }[], url: string) => calls.filter((c) => c.url === url).length;
const listings = (calls: { url: string }[]) => calls.filter((c) => c.url.includes("/api/files/list")).length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const suggestions = (doc: any) => [...doc.querySelectorAll("#files-suggest option")].map((o: any) => o.value);
/** Tab at the end of `value`, as a person presses it. `stays`: the box
 *  keeps the Tab (it completes, or waits for the folder's names); else the
 *  focus moves on, as when no name is started or nothing can be added
 *  (dashboard.md §4.25m *Tab moves on*). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function tab(doc: any, value: string, stays = true) {
  const input = doc.getElementById("lock-path");
  input.value = value;
  input.setSelectionRange(value.length, value.length);
  const e = new doc.defaultView.KeyboardEvent("keydown", { key: "Tab", cancelable: true });
  input.dispatchEvent(e);
  assert.equal(e.defaultPrevented, stays, stays ? "Tab stays in the path box" : "Tab moves the focus on");
  await tick(30);
  return input.value as string;
}
/** `value` typed into the path box, its last key as a person types it. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function type(doc: any, value: string) {
  const input = doc.getElementById("lock-path");
  input.value = value;
  input.setSelectionRange(value.length, value.length);
  input.dispatchEvent(new doc.defaultView.InputEvent("input", { inputType: "insertText", data: value.slice(-1) }));
  await tick(30);
  return input.value as string;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function openBrowser(doc: any) {
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
}

test("C1: a folder not shown: Tab completes a name past the first page, and each page is read once", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...BIG.routes } });
  await openBrowser(doc);
  assert.equal(await tab(doc, "~/big/zet"), "~/big/zeta-", "the two zeta files are past row 500");
  assert.deepEqual(suggestions(doc), ["~/big/zeta-1.env", "~/big/zeta-2.env"]);
  const input = doc.getElementById("lock-path") as any;
  assert.equal(input.selectionStart, input.value.length, "the caret after what Tab added");
  assert.equal(reads(calls, BIG.first), 1, "the first page once");
  assert.equal(reads(calls, BIG.at(500)), 1, "the next once, at the offset Show more reads");
  assert.equal(await tab(doc, "~/big/zeta-2"), "~/big/zeta-2.env");
  assert.equal(reads(calls, BIG.first) + reads(calls, BIG.at(500)), 2, "a second Tab in the folder reads nothing");
});

test("C2: a name a folder and a file past the page share completes to their shared start, never to the folder", async () => {
  const NOTES = { ...WS_LIST, path: "/home/u/big/notes", display: "~/big/notes", crumbs: [], entries: [], total: 0 };
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...BIG.routes, [list("~/big/notes")]: NOTES } });
  await openBrowser(doc);
  assert.equal(await tab(doc, "~/big/not"), "~/big/notes", "notes/ and notes.md: no slash");
  assert.deepEqual(suggestions(doc), ["~/big/notes/", "~/big/notes.md"]);
  assert.equal(await tab(doc, "~/big/notes."), "~/big/notes.md");
  assert.equal(await tab(doc, "~/big/notes/", false), "~/big/notes/", "a folder typed out stays, and Tab moves on: no name is started");
});

test("C3: the folder the browser shows lends the pages it read: after Show more Tab reads nothing; before it, the next page once", async () => {
  const shown = { "mandu.files.folder": "/home/u/big" };
  const a = load({ url: FILES_URL, storage: shown, routes: { ...FILES_ROUTES, ...BIG.routes } });
  await openBrowser(a.doc);
  assert.equal(fileRows(a.doc).length, 500, "the browser shows the first page");
  const more = a.doc.querySelector("#files-list .files-more") as any;
  more.click();
  await tick();
  assert.equal(fileRows(a.doc).length, 503, "Show more brought the rest");
  const before = listings(a.calls);
  assert.equal(await tab(a.doc, "~/big/zet"), "~/big/zeta-");
  assert.equal(listings(a.calls), before, "Tab reads nothing: the browser read both pages");

  const b = load({ url: FILES_URL, storage: shown, routes: { ...FILES_ROUTES, ...BIG.routes } });
  await openBrowser(b.doc);
  assert.equal(reads(b.calls, BIG.at(500)), 0);
  assert.equal(await tab(b.doc, "~/big/not"), "~/big/notes");
  assert.equal(reads(b.calls, BIG.first) + reads(b.calls, BIG.shown), 1, "the shown folder's first page is not read again");
  assert.equal(reads(b.calls, BIG.at(500)), 1, "the next page once");
  assert.equal(fileRows(b.doc).length, 500, "the list shown is the person's: Tab draws no rows");
});

test("C4: a later page that fails: Tab completes only what no unread name could change; other text or typing reads the page again, a second Tab on the same text moves on", async () => {
  let down = true;
  const routes = { ...FILES_ROUTES, ...FLAT.routes, [`${list("/home/u/flat")}&offset=500`]: () => (down ? DOWN : FLAT.page(500)) };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await openBrowser(doc);
  assert.equal(await tab(doc, "~/flat/f499"), "~/flat/f499", "f499a.txt may be on the page not read: never f499.txt");
  assert.deepEqual(suggestions(doc), ["~/flat/f499.txt"], "the name read is still suggested");
  assert.equal(await tab(doc, "~/flat/f123"), "~/flat/f123.txt", "every name it could be sorts among those read");
  assert.equal(await tab(doc, "~/flat/g"), "~/flat/g", "nothing read starts with g, and a name not read may");
  const failed = reads(calls, FLAT.at(500));
  assert.equal(failed, 3, "each Tab on other text tries the page again");
  assert.equal(await tab(doc, "~/flat/g", false), "~/flat/g", "a second Tab on the same text moves on");
  assert.equal(reads(calls, FLAT.at(500)), failed, "and reads nothing");

  down = false;
  assert.equal(await type(doc, "~/flat/g"), "~/flat/g.txt", "typing tries the page again");
  assert.equal(reads(calls, FLAT.at(500)), failed + 1, "read once more, and it answered");
  assert.equal(await tab(doc, "~/flat/g.txt", false), "~/flat/g.txt", "a whole name: Tab moves on");
  assert.equal(await type(doc, "~/flat/f499"), "~/flat/f499", "f499.txt and f499a.txt share f499");
  assert.deepEqual(suggestions(doc), ["~/flat/f499.txt", "~/flat/f499a.txt"]);
  assert.equal(await tab(doc, "~/flat/f499", false), "~/flat/f499", "nothing to add, every name read: Tab moves on");
  assert.equal(reads(calls, FLAT.at(500)), failed + 1, "the folder is read to its end: nothing more");

  // Folders sort first: after the last folder read, a file of any name may follow.
  let bigDown = true;
  const b = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...BIG.routes, [`${list("/home/u/big")}&offset=500`]: () => (bigDown ? DOWN : BIG.page(500)) } });
  await openBrowser(b.doc);
  assert.equal(await tab(b.doc, "~/big/d123"), "~/big/d123", "a file d123… may be on the page not read: never d123/");
  bigDown = false;
  assert.equal(await type(b.doc, "~/big/d123"), "~/big/d123/", "read to its end: the one folder");

  // A folder read, and the files read end before the name typed: a file of that name may follow.
  const MIX = folder("mix", [entry("mix", "gamma", "dir"), ...Array.from({ length: 499 }, (_, i) => entry("mix", `f${String(i).padStart(3, "0")}.txt`)), entry("mix", "gamma.txt")]);
  let mixDown = true;
  const m = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...MIX.routes, [`${list("/home/u/mix")}&offset=500`]: () => (mixDown ? DOWN : MIX.page(500)) } });
  await openBrowser(m.doc);
  assert.equal(await tab(m.doc, "~/mix/gam"), "~/mix/gam", "gamma.txt may be on the page not read: never gamma/");
  mixDown = false;
  assert.equal(await type(m.doc, "~/mix/gam"), "~/mix/gamma", "gamma/ and gamma.txt share gamma");
});

test("C5: a folder past 10,000 names: 20 pages are read, once; a name among them completes, one that may sort past them stays", async () => {
  const HUGE = folder("huge", Array.from({ length: 10_500 }, (_, i) => entry("huge", `n${String(i).padStart(5, "0")}.txt`)));
  const { doc, calls } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...HUGE.routes } });
  await openBrowser(doc);
  assert.equal(await tab(doc, "~/huge/n01234"), "~/huge/n01234.txt", "on the third page");
  assert.equal(reads(calls, HUGE.first), 1);
  for (let at = 500; at < 10_000; at += 500) assert.equal(reads(calls, HUGE.at(at)), 1, `the page at ${at} once`);
  assert.equal(reads(calls, HUGE.at(10_000)), 0, "no page past 10,000 names");
  assert.equal(await tab(doc, "~/huge/n10200", false), "~/huge/n10200", "past the names read: stays as typed, and Tab moves on");
  assert.equal(await tab(doc, "~/huge/n09876"), "~/huge/n09876.txt", "sorts before the last name read");
  assert.equal(listings(calls), 20 + 1, "the three Tabs read 20 pages, and Add a rule its own folder");
});

test("C6: typing while the pages are read: each page is read once, and only the newest text is completed", async () => {
  let release: () => void = () => {};
  const held = new Promise<void>((r) => { release = r; });
  const routes = { ...FILES_ROUTES, ...BIG.routes, [`${list("/home/u/big")}&offset=500`]: () => held.then(() => BIG.page(500)) };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await openBrowser(doc);
  const input = doc.getElementById("lock-path") as any;
  for (const [value, data] of [["~/big/z", "z"], ["~/big/ze", "e"]]) {
    input.value = value;
    input.setSelectionRange(value!.length, value!.length);
    input.dispatchEvent(new doc.defaultView.InputEvent("input", { inputType: "insertText", data }));
    await tick();
  }
  assert.equal(input.value, "~/big/ze", "nothing completed while the page is out");
  release();
  await tick(30);
  assert.equal(input.value, "~/big/zeta-", "the newest text, completed");
  assert.deepEqual([input.selectionStart, input.selectionEnd], [8, 11], "what typing added is selected, so a key types over it");
  assert.equal(reads(calls, BIG.first), 1, "the first page once");
  assert.equal(reads(calls, BIG.at(500)), 1, "the next once");
});

test("C7: a folder that changed between two pages: an entry repeated at the seam is suggested once, and a page with nothing new ends the read", async () => {
  // The second page starts with the first page's last entry (a file made
  // before it meanwhile), then its own; another read brings only repeats.
  let second = { ...FLAT.page(500), entries: [entry("flat", "f499.txt"), ...FLAT.page(500).entries] };
  const routes = { ...FILES_ROUTES, ...FLAT.routes, [`${list("/home/u/flat")}&offset=500`]: () => second };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await openBrowser(doc);
  assert.equal(await tab(doc, "~/flat/f499"), "~/flat/f499");
  assert.deepEqual(suggestions(doc), ["~/flat/f499.txt", "~/flat/f499a.txt"], "f499.txt once");
  assert.equal(await tab(doc, "~/flat/g"), "~/flat/g.txt");

  second = { ...FLAT.page(500), entries: [entry("flat", "f498.txt"), entry("flat", "f499.txt")], more: true };
  const c = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...FLAT.routes, [`${list("/home/u/flat")}&offset=500`]: () => second } });
  await openBrowser(c.doc);
  assert.equal(await tab(c.doc, "~/flat/g"), "~/flat/g", "nothing new: the read ends, and g may still follow");
  assert.equal(reads(c.calls, FLAT.at(500)), 1, "read once, never again and again at the same place");
  assert.equal(reads(calls, FLAT.at(500)), 1);
});

test("C8: a folder of one page reads no offset", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await openBrowser(doc);
  assert.equal(await tab(doc, "/home/u/ws/co"), "/home/u/ws/config/");
  assert.equal(calls.filter((c) => c.url.includes("offset=")).length, 0);
});
