/**
 * home-js-files-pick-pages.test — the file browser under Rules › Add a rule
 * opens a picked entry past a folder's first page (public/js/home.js
 * `openFolder`, `pagesUpTo`, `pickAhead`; dashboard.md §4.25m *Browsing*).
 *
 * Three ways open a folder with one entry picked: Go with a file's path in
 * the path box, Show in its folder on a Your rules row, and Show in the file
 * browser on an answer. A folder is listed 500 entries at a time, folders
 * first and then by name. Until 2026-10-15 the pick was looked for on the
 * first page only: a file past it was not opened, it stayed behind Show
 * more, the path box that named it read the folder, and Show in its folder
 * gave the focus to the path box. Now the folder is read on, at the offsets
 * Show more reads, down to the page the pick is on:
 *
 *   K1  Go to a file on the second page: its row is opened, the pages down
 *       to it are shown and Show more reads on from there;
 *   K2  Show in its folder on a Your rules row (its path written with ~)
 *       for a file on the third page gives the focus to that row's ⋯;
 *   K3  a pick on the first page reads that page only (a folder rule);
 *   K4  a file that is gone: the read stops where the listing's order puts
 *       it past (never to the folder's end); nothing opened, the path box;
 *   K5  a page that fails: the pages read, Show more says why, nothing
 *       opened, no page after;
 *   K6  at most 10,000 entries are read to find a pick;
 *   K7  a pick an overtaken read left never reads another folder on;
 *   K8  a folder opened while the pages are read wins.
 *
 * The pick is the read's own (`openFolder`'s `opts.pick`). Until 2026-10-15
 * it waited in the page's state (`F.pick`) when its read was refused or
 * overtaken, and the next listing of its folder opened that row unasked and
 * read the folder on to it:
 *
 *   K9  Show in its folder whose read is refused, then Go to that folder:
 *       its first page, nothing opened;
 *   K10 Show more pressed while the pick's read is out: the read is dropped,
 *       and a later Go to the folder opens nothing;
 *   K11 Go to the pick's folder while its read is out: the Go's listing,
 *       nothing opened, and the late answer draws nothing;
 *   K12 Go to a file whose folder's read is refused, then that folder:
 *       nothing opened.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts)
 * with pages of three entries; across the real arbiter and dashboard, with
 * the real 500-entry pages, tests/stack/product-files-pick-pages.test.ts.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, WS_LIST, NONE, list, fileRows, rowFor, treeRow, opened } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const ent = (dir: string, name: string, kind: string) =>
  ({ name, path: `/home/u/${dir}/${name}`, display: `~/${dir}/${name}`, kind, link: null, label: NONE, inside: 0 });
/** ~/big, listed three entries a page: its folders, then its files. */
const BIG = [
  // A folder whose name sorts after the files' names: still before them.
  ...["a", "b", "w", "zed"].map((n) => ent("big", n, "dir")),
  ...["m.txt", "n.txt", "p.txt", "q.txt", "r.txt", "x.txt", "y.txt"].map((n) => ent("big", n, "file")),
];
const SIZE = 3;
const listing = (dir: string, all: ReturnType<typeof ent>[], offset: number, size = SIZE) => ({
  ...WS_LIST, path: `/home/u/${dir}`, display: `~/${dir}`, parent: "/home/u",
  crumbs: [{ name: "~", path: "/home/u" }, { name: dir, path: `/home/u/${dir}` }],
  entries: all.slice(offset, offset + size), total: all.length, offset, more: offset + size < all.length,
});
const at = (dir: string, offset: number) => `${list(`/home/u/${dir}`)}&offset=${offset}`;
const url = (dir: string, offset: number) => `/mandu/api/files/list?path=${encodeURIComponent(`/home/u/${dir}`)}${offset ? `&offset=${offset}` : ""}`;
/** The listing's answer to a file's path: open its folder with it picked. */
const aFile = (p: string) => ({ status: 400, body: { error: "That is a file, not a folder.", path: p, file: true } });
function bigRoutes(): Record<string, unknown> {
  const r: Record<string, unknown> = { ...FILES_ROUTES };
  for (let o = 0; o < BIG.length; o += SIZE) r[o ? at("big", o) : list("/home/u/big")] = listing("big", BIG, o);
  for (const n of ["n.txt", "q.txt"]) r[list(`~/big/${n}`)] = aFile(`/home/u/big/${n}`);
  // A rule written with ~ opens its folder as written.
  r[list("~/big")] = listing("big", BIG, 0);
  return r;
}
const fileRule = (path: string, covers: "subtree" | "exact") => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [], level: "no-model",
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: covers === "subtree" ? "and everything inside" : "this file only", effect: "x" },
});
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  fileRule("~/big/q.txt", "exact"), fileRule("/home/u/big/b", "subtree"), fileRule("/home/u/big/o.txt", "exact"),
] } };

const names = (doc: Doc) => fileRows(doc).map((r: Doc) => r.getAttribute("data-path").replace(/^\/home\/u\/[^/]+\//, ""));
const openName = (doc: Doc) => doc.querySelector("#files-list .row.file.open")?.getAttribute("data-path") ?? null;
const moreBtn = (doc: Doc) => doc.querySelector("#files-list .files-more") as Doc;
const moreWords = (doc: Doc) => doc.getElementById("files-more-words")?.textContent ?? null;
const reads = (calls: { url: string }[], u: string) => calls.filter((c) => c.url === u).length;
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
/** A delayed answer: the route answers once `open()` is called. */
function gate<T>(body: T) {
  let open!: () => void;
  const p = new Promise<void>((r) => (open = r));
  return { route: () => p.then(() => body), open };
}

async function openBrowser(doc: Doc) {
  doc.getElementById("rules-add").click();
  await tick();
}
async function go(doc: Doc, path: string) {
  const input = doc.getElementById("lock-path");
  input.focus();
  input.value = path;
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick(30);
}
/** Show in its folder under a Your rules row, pressed with the keyboard. */
async function showInFolder(doc: Doc, name: RegExp) {
  treeRow(doc, name).querySelector(".file-more").click();
  const btn = button(opened(doc), "Show in its folder");
  btn.focus();
  btn.click();
  await tick(30);
}

test("K1: Go to a file on the second page opens its row, with the pages down to it; Show more reads on from there", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: bigRoutes() });
  await tick();
  await openBrowser(doc);
  await go(doc, "~/big/n.txt");
  assert.deepEqual(names(doc), ["a", "b", "w", "zed", "m.txt", "n.txt"], "the first page and the one the file is on");
  assert.equal(openName(doc), "/home/u/big/n.txt", "the file's row is opened");
  assert.ok(opened(doc), "with its details");
  assert.equal(reads(calls, url("big", 3)), 1, "the second page is read once");
  assert.equal(reads(calls, url("big", 6)), 0, "and nothing past the page the file is on");
  assert.match(moreBtn(doc).textContent, /Show more \(5 more\)/);
  assert.equal(doc.getElementById("lock-path").value, "~/big/", "the box reads its folder, as for a file on the first page");
  assert.equal(doc.activeElement, doc.getElementById("lock-path"), "the focus stays in the box");
  moreBtn(doc).click();
  await tick();
  assert.equal(reads(calls, url("big", 6)), 1, "Show more reads the next page, after the ones shown");
  assert.deepEqual(names(doc).slice(6), ["p.txt", "q.txt", "r.txt"]);
  assert.equal(openName(doc), "/home/u/big/n.txt", "the row stays opened");
});

test("K2: Show in its folder on a rule (written with ~) for a file on the third page gives the focus to that row's ⋯", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: { ...bigRoutes(), "GET policy/panel": PANEL } });
  await tick();
  await showInFolder(doc, /^q\.txt/);
  assert.equal(doc.getElementById("lock-form").hidden, false, "the browser is open");
  assert.deepEqual(names(doc), ["a", "b", "w", "zed", "m.txt", "n.txt", "p.txt", "q.txt", "r.txt"]);
  const row = rowFor(doc, /^q\.txt/);
  assert.equal(row.classList.contains("open"), true, "the file's row is opened");
  assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus followed the page to its ⋯");
  assert.equal(reads(calls, url("big", 3)), 1);
  assert.equal(reads(calls, url("big", 6)), 1);
  assert.equal(reads(calls, url("big", 9)), 0, "never past the page it is on");
});

test("K3: a pick on the first page reads that page only", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: { ...bigRoutes(), "GET policy/panel": PANEL } });
  await tick();
  await showInFolder(doc, /^b$/);
  assert.deepEqual(names(doc), ["a", "b", "w"]);
  assert.equal(openName(doc), "/home/u/big/b", "the folder's row is opened");
  assert.equal(doc.activeElement, rowFor(doc, /^b\/?$/).querySelector(".file-more"));
  assert.equal(calls.filter((c) => c.url.includes("offset=")).length, 0, "no page past the first is read");
  assert.match(moreBtn(doc).textContent, /Show more \(8 more\)/);
});

test("K4: a file that is gone: the read stops where the listing's order has passed it; nothing is opened", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: { ...bigRoutes(), "GET policy/panel": PANEL } });
  await tick();
  await showInFolder(doc, /^o\.txt/);
  assert.equal(reads(calls, url("big", 3)), 1, "n.txt sorts before o.txt: read on");
  assert.equal(reads(calls, url("big", 6)), 1, "r.txt sorts after it");
  assert.equal(reads(calls, url("big", 9)), 0, "so the read stops: o.txt cannot follow");
  assert.equal(openName(doc), null, "nothing is opened");
  assert.equal(names(doc).length, 9, "the pages read are shown");
  assert.equal(doc.activeElement, doc.getElementById("lock-path"), "the path box, as for a file not listed");
});

test("K5: a page that fails: the pages read, Show more says why, nothing opened", async () => {
  const routes = bigRoutes();
  routes[at("big", 3)] = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await tick();
  await openBrowser(doc);
  await go(doc, "~/big/q.txt");
  assert.deepEqual(names(doc), ["a", "b", "w"], "the first page");
  assert.equal(openName(doc), null);
  assert.match(moreWords(doc)!, /^Could not read more of this folder/, "Show more says why");
  assert.ok(moreBtn(doc), "and stays to try again");
  assert.equal(reads(calls, url("big", 6)), 0, "no page after the one that failed");
  assert.notEqual(doc.activeElement, doc.body, "the focus never falls to the page");
});

test("K6: at most 10,000 entries are read to find a pick", async () => {
  // Hidden folders, so the rows read are not drawn (files-hidden off).
  const many = Array.from({ length: 10_000 }, (_, i) => ent("huge", `.d${String(i).padStart(5, "0")}`, "dir"));
  const all = [...many, ent("huge", "z.txt", "file")];
  const routes: Record<string, unknown> = { ...FILES_ROUTES, [list("~/huge/z.txt")]: aFile("/home/u/huge/z.txt") };
  for (let o = 0; o < all.length; o += 5000) routes[o ? at("huge", o) : list("/home/u/huge")] = listing("huge", all, o, 5000);
  const { doc, calls } = load({ url: FILES_URL, routes, storage: { "mandu.files.hidden": "0" } });
  await tick();
  await openBrowser(doc);
  await go(doc, "~/huge/z.txt");
  assert.equal(reads(calls, url("huge", 5000)), 1, "read on to 10,000 entries");
  assert.equal(reads(calls, url("huge", 10000)), 0, "and no further");
  assert.equal(openName(doc), null, "the file past them is not opened");
  assert.match(moreBtn(doc).textContent, /Show more \(1 more\)/, "Show more brings it");
});

test("K7: a pick an overtaken read left never reads another folder on", async () => {
  const slow = gate(listing("big", BIG, 0));
  const home = { ...listing("u", BIG.map((e) => ({ ...e, path: e.path.replace("/big/", "/"), display: e.display.replace("/big/", "/") })), 0),
    path: "/home/u", display: "~", crumbs: [{ name: "~", path: "/home/u" }] };
  const routes = { ...bigRoutes(), "GET policy/panel": PANEL, [list("~/big")]: slow.route, [list("~")]: home };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await tick();
  await showInFolder(doc, /^q\.txt/);
  // Home pressed before ~/big answers: the home folder is the one shown.
  doc.getElementById("files-home").click();
  await tick(30);
  slow.open();
  await tick(30);
  assert.equal(calls.filter((c) => c.url.includes("offset=")).length, 0, "no page past the first of either folder is read");
  assert.equal(openName(doc), null, "nothing is opened");
  assert.equal(names(doc).length, 3, "the home folder's first page");
});

test("K8: a folder opened while the pages are read wins", async () => {
  const slow = gate(listing("big", BIG, 3));
  const routes = { ...bigRoutes(), [at("big", 3)]: slow.route, [list("~/ws")]: WS_LIST };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await tick();
  await openBrowser(doc);
  const shown = names(doc);
  await go(doc, "~/big/q.txt");
  assert.equal(reads(calls, url("big", 3)), 1, "the second page is on its way");
  await go(doc, "~/ws");
  slow.open();
  await tick(30);
  assert.deepEqual(names(doc), shown, "the folder opened last is shown");
  assert.equal(reads(calls, url("big", 6)), 0, "the pages of ~/big are read no further");
  assert.equal(openName(doc), null);
  assert.equal(doc.getElementById("lock-path").value, "~/ws/");
});

test("K9: Show in its folder whose read is refused leaves no pick: Go to that folder opens nothing", async () => {
  const routes = bigRoutes();
  routes[list("~/big")] = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
  const { doc, calls } = load({ url: FILES_URL, routes: { ...routes, "GET policy/panel": PANEL } });
  await tick();
  await showInFolder(doc, /^q\.txt/);
  assert.equal(doc.getElementById("files-note").hidden, false, "the page says the folder could not be opened");
  assert.equal(fileRows(doc).length, 0);
  await go(doc, "/home/u/big");
  assert.deepEqual(names(doc), ["a", "b", "w"], "the folder's first page");
  assert.equal(openName(doc), null, "nothing is opened");
  assert.equal(calls.filter((c) => c.url.includes("offset=")).length, 0, "and no page past the first is read");
  assert.match(moreBtn(doc).textContent, /Show more \(8 more\)/);
});

test("K10: Show more pressed while the pick's read is out: the read is dropped, and Go to the folder later opens nothing", async () => {
  const slow = gate(listing("big", BIG, 0));
  const { doc, calls } = load({ url: FILES_URL, routes: { ...bigRoutes(), "GET policy/panel": PANEL, [list("~/big")]: slow.route } });
  await tick();
  await openBrowser(doc);
  await go(doc, "/home/u/big");
  await showInFolder(doc, /^q\.txt/);
  moreBtn(doc).click();
  await tick(30);
  assert.equal(reads(calls, url("big", 3)), 1, "Show more read the second page");
  slow.open();
  await tick(30);
  assert.deepEqual(names(doc), ["a", "b", "w", "zed", "m.txt", "n.txt"], "the late answer draws nothing over Show more's rows");
  assert.equal(openName(doc), null);
  await go(doc, "~/big");
  assert.deepEqual(names(doc), ["a", "b", "w"], "Go shows the folder's first page");
  assert.equal(openName(doc), null, "nothing is opened");
  assert.equal(reads(calls, url("big", 3)), 1, "and no page is read for the pick dropped");
  assert.equal(reads(calls, url("big", 6)), 0);
});

test("K11: Go to the pick's folder while its read is out: the Go's listing, nothing opened, and the late answer draws nothing", async () => {
  const slow = gate(listing("big", BIG, 0));
  const { doc, calls } = load({ url: FILES_URL, routes: { ...bigRoutes(), "GET policy/panel": PANEL, [list("~/big")]: slow.route } });
  await tick();
  await showInFolder(doc, /^q\.txt/);
  await go(doc, "/home/u/big");
  assert.deepEqual(names(doc), ["a", "b", "w"], "the folder's first page");
  assert.equal(openName(doc), null, "nothing is opened");
  slow.open();
  await tick(30);
  assert.deepEqual(names(doc), ["a", "b", "w"]);
  assert.equal(openName(doc), null);
  assert.equal(calls.filter((c) => c.url.includes("offset=")).length, 0, "no page past the first is read");
  assert.equal(doc.getElementById("lock-path").value, "~/big/");
});

test("K12: Go to a file whose folder's read is refused, then Go to that folder: nothing opened", async () => {
  const routes = bigRoutes();
  routes[list("/home/u/big")] = { status: 500, body: { error: "could not list the folder: EIO" } };
  const { doc, calls } = load({ url: FILES_URL, routes });
  await tick();
  await openBrowser(doc);
  await go(doc, "~/big/q.txt");
  assert.equal(doc.getElementById("files-note").hidden, false, "the page says the folder could not be opened");
  await go(doc, "~/big");
  assert.deepEqual(names(doc), ["a", "b", "w"], "the folder's first page");
  assert.equal(openName(doc), null, "nothing is opened");
  assert.equal(calls.filter((c) => c.url.includes("offset=")).length, 0, "no page past the first is read");
});
