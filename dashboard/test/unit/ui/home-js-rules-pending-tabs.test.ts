/**
 * home-js-rules-pending-tabs.test — Changes to save, and the suggestions
 * skipped, are the same in every tab of the product page (dashboard.md
 * §4.25n *Changes to save are the same in every tab*).
 *
 * Until 2026-10-26 each tab read the stored list (`mandu.files.pending`)
 * and the skipped suggestions (`mandu.files.skipped`) once, at load, and
 * wrote its own copy over them: a choice made in one tab was lost when
 * another wrote, a Save in one left the other offering the same change
 * again, and a Discard in one left the other's suggestions ticked. Now a
 * `storage` event (what the browser gives every OTHER tab when one writes)
 * takes the lists as stored:
 *
 *   T1  a choice added in another tab: the bar counts it, its row says
 *       "Will be: … (not saved)", the top bar's mark counts it;
 *   T2  the key removed (a Save or a Discard elsewhere): the bar hides and
 *       the mark goes;
 *   T3  the skip key changed: a ticked suggestion is unticked;
 *   T4  a damaged value reads as empty, and is not written over;
 *   T5  `key: null` (the storage cleared) reads both lists;
 *   T6  an event while this tab's Save is on its way waits for its answer:
 *       a Save that worked takes only what it sent, and a choice made in
 *       the other tab meanwhile still waits; a refused Save keeps both;
 *   T7  the event writes neither key back, and on a page other than Rules
 *       changes only the mark and asks the server nothing; on Rules it asks
 *       only what the changes would do (files/impact), never a Save;
 *   T8  the focus is kept: on a row's menu in Add a rule, and from a Drop
 *       in the bar drawn away to the bar's heading, never <body>.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display and this
 * browser's storage only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, rowFor, menuOf, waiting } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const PENDING = "mandu.files.pending";
const SKIPPED = "mandu.files.skipped";
const change = (name: string, level: string) => ({
  path: `/home/u/ws/${name}`, display: `~/ws/${name}`, level, bindings: [], recursive: false, before: "Like any other file", target: null,
});
const NOTES = change("notes.md", "no-model");
const README = change("README.md", "no-model");
const ONE = JSON.stringify([NOTES]);
const BOTH = JSON.stringify([NOTES, README]);

/** Another tab of this browser writes `key` (null: removes it; `key` null:
 *  clears the storage): the store changes and THIS window gets the event,
 *  as a browser gives it every tab but the writer. */
function otherTab(window: Doc, key: string | null, value: string | null) {
  const before = key === null ? null : window.localStorage.getItem(key);
  window.otherTabWrites = true;
  if (key === null) window.localStorage.clear();
  else if (value === null) window.localStorage.removeItem(key);
  else window.localStorage.setItem(key, value);
  window.otherTabWrites = false;
  window.dispatchEvent(new window.StorageEvent("storage", { key, oldValue: before, newValue: value, storageArea: window.localStorage, url: FILES_URL }));
}
/** Every write this page makes to its storage from now on (otherTab's own
 *  are the other tab's). */
function writes(window: Doc): string[] {
  const seen: string[] = [];
  const proto = window.Storage.prototype;
  const set = proto.setItem, del = proto.removeItem;
  proto.setItem = function (k: string, v: string) { if (!window.otherTabWrites) seen.push(`set ${k}`); return set.call(this, k, v); };
  proto.removeItem = function (k: string) { if (!window.otherTabWrites) seen.push(`remove ${k}`); return del.call(this, k); };
  return seen;
}

const bar = (doc: Doc) => doc.getElementById("files-pending");
const count = (doc: Doc) => doc.getElementById("files-pending-count").textContent;
const drops = (doc: Doc) => [...doc.querySelectorAll("#files-pending-list button")].map((b: Doc) => b.getAttribute("aria-label"));
const mark = (doc: Doc) => { const m = doc.getElementById("nav-rules-unsaved"); return m.hidden ? null : m.textContent; };

/** Rules with All files open on ~/ws (README.md listed). */
async function rules(storage: Record<string, string>, routes: Record<string, unknown> = {}) {
  const page = load({ url: FILES_URL, storage, routes: { ...FILES_ROUTES, ...routes } });
  assert.equal(page.err, null);
  await tick();
  page.doc.getElementById("rules-add").click();
  await tick();
  assert.ok(rowFor(page.doc, /README/), "All files lists README.md");
  return page;
}

test("T1: a choice added in another tab shows here: the bar counts it, its row says \"(not saved)\", the mark counts it", async () => {
  const { window, doc } = await rules({ [PENDING]: ONE });
  assert.equal(count(doc), "1");
  assert.equal(mark(doc), "1");
  assert.equal(waiting(rowFor(doc, /README/)), false);
  otherTab(window, PENDING, BOTH);
  await tick();
  assert.equal(bar(doc).hidden, false);
  assert.equal(count(doc), "2", "both changes wait");
  assert.deepEqual(drops(doc), ["Drop the change to ~/ws/notes.md", "Drop the change to ~/ws/README.md"]);
  const row = rowFor(doc, /README/);
  assert.equal(waiting(row), true, "the row's menu shows the change waiting");
  assert.match(row.textContent, /Will be: No AI \(not saved\)/);
  assert.equal(mark(doc), "2", "the top bar says 2");
});

test("T2: the key removed in another tab (a Save there): the bar hides and the mark goes", async () => {
  const { window, doc } = await rules({ [PENDING]: BOTH });
  assert.equal(count(doc), "2");
  otherTab(window, PENDING, null);
  await tick();
  assert.equal(bar(doc).hidden, true, "nothing waits");
  assert.equal(mark(doc), null);
  assert.equal(waiting(rowFor(doc, /README/)), false);
  assert.doesNotMatch(rowFor(doc, /README/).textContent, /not saved/);
});

test("T3: the skip key changed in another tab (its Discard): a ticked suggestion is unticked here", async () => {
  const wire: SuggestionWire = {
    id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-1", source: "git-history", repoRoot: "/home/u/proj",
    edits: [{ op: "lock-path", path: "/home/u/proj/deploy/id_rsa", level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read",
    evidence: { paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: false,
      findings: [{ blob: "a".repeat(40), paths: ["deploy/id_rsa"], firstCommit: "1111111", lastCommit: "2222222", inHead: true, inIndex: true, stillPresent: true,
        detectors: [{ kind: "content-shape", rule: "private-key", mask: "(key block header)…", words: "private key", line: 1 }] }] },
    impact: { historicalVersions: 0, workingTreeChanges: false, files: [] },
    historyOnly: false, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  } as SuggestionWire;
  const { window, doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": { suggestions: suggestionRows([wire], "/home/u", "linux"), count: 1, scan: null } } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  const tickBox = () => doc.querySelector('#files-suggested-list .row[data-id="pp-000001"] input.file-tick');
  assert.equal(tickBox().checked, true, "ticked: it waits to be saved");
  assert.equal(count(doc), "1");
  otherTab(window, SKIPPED, JSON.stringify(["pp-000001"]));
  await tick();
  assert.equal(tickBox().checked, false, "skipped in the other tab, so here too");
  assert.equal(bar(doc).hidden, true, "nothing waits: a Save here applies nothing thrown away there");
  // Ticked again there: ticked here.
  otherTab(window, SKIPPED, null);
  await tick();
  assert.equal(tickBox().checked, true);
  assert.equal(count(doc), "1");
});

test("T4: a damaged value reads as empty, and is not written over", async () => {
  const { window, doc } = await rules({ [PENDING]: ONE });
  const seen = writes(window);
  otherTab(window, PENDING, "{not json");
  await tick();
  assert.equal(bar(doc).hidden, true);
  assert.equal(mark(doc), null);
  assert.deepEqual(seen, [], "nothing written back");
  assert.equal(window.localStorage.getItem(PENDING), "{not json");
  // A list of something else is no list either.
  otherTab(window, PENDING, JSON.stringify({ path: "/home/u/ws/README.md" }));
  await tick();
  assert.equal(bar(doc).hidden, true);
  otherTab(window, PENDING, JSON.stringify([null, 3, { level: "no-model" }, README]));
  await tick();
  assert.deepEqual(drops(doc), ["Drop the change to ~/ws/README.md"], "only the entries with a path");
});

test("T5: key null (the storage cleared in another tab) reads both lists: nothing waits, nothing is skipped", async () => {
  const { window, doc } = await rules({ [PENDING]: BOTH, [SKIPPED]: JSON.stringify(["pp-000009"]) });
  assert.equal(mark(doc), "2");
  otherTab(window, null, null);
  await tick();
  assert.equal(bar(doc).hidden, true);
  assert.equal(mark(doc), null);
  // The other storage events this page listens to are not ours to keep.
  assert.equal(window.localStorage.length, 0, "nothing written back");
});

test("T6: an event while this tab's Save is on its way waits for its answer; the Save takes only what it sent", async () => {
  // A Save that works: notes.md is saved; README.md, chosen in the other
  // tab meanwhile, still waits, here and in the store.
  const saves: Doc[] = [];
  let open: () => void = () => {};
  const gate = new Promise<void>((r) => { open = r; });
  const page = await rules({ [PENDING]: ONE }, {});
  const { window, doc } = page;
  const real = window.fetch;
  window.fetch = (url: string, init: Doc = {}) => {
    if (init.method === "POST" && url.endsWith("/api/files/labels")) {
      saves.push(JSON.parse(init.body));
      return gate.then(() => ({ ok: true, status: 200, json: () => Promise.resolve({ applied: true, changeId: "pc-000031", page: 0 }) }));
    }
    return real(url, init);
  };
  doc.getElementById("files-save").click();
  await tick(3);
  assert.equal(saves.length, 1);
  assert.deepEqual(saves[0].changes.map((c: Doc) => c.path), [NOTES.path], "the Save sent notes.md");
  otherTab(window, PENDING, BOTH);
  await tick();
  assert.equal(count(doc), "1", "on its way: the bar is as the Save left it");
  open();
  await tick(30);
  assert.equal(saves.length, 1, "nothing sent again");
  assert.deepEqual(drops(doc), ["Drop the change to ~/ws/README.md"], "README.md, chosen meanwhile, still waits");
  assert.equal(mark(doc), "1");
  assert.deepEqual(JSON.parse(window.localStorage.getItem(PENDING)).map((p: Doc) => p.path), [README.path], "and is kept in the store");
  assert.equal(saves[0].changes.length, 1);

  // A refused Save: both wait.
  let open2: () => void = () => {};
  const gate2 = new Promise<void>((r) => { open2 = r; });
  const two = await rules({ [PENDING]: ONE });
  const real2 = two.window.fetch;
  two.window.fetch = (url: string, init: Doc = {}) => init.method === "POST" && url.endsWith("/api/files/labels")
    ? gate2.then(() => ({ ok: false, status: 403, json: () => Promise.resolve({ error: "Sign in first: open the admin link." }) }))
    : real2(url, init);
  two.doc.getElementById("files-save").click();
  await tick(3);
  otherTab(two.window, PENDING, BOTH);
  await tick();
  assert.equal(count(two.doc), "1");
  open2();
  await tick(30);
  assert.match(two.doc.getElementById("lock-error").textContent, /Sign in first/);
  assert.equal(count(two.doc), "2", "refused: both wait");
  assert.equal(two.window.localStorage.getItem(PENDING), BOTH, "the store keeps the other tab's list");
});

test("T7: the event writes neither key back; off Rules it changes only the mark and asks nothing; on Rules no Save", async () => {
  const home = load({ storage: { [PENDING]: ONE } });
  await tick(20);
  assert.equal(mark(home.doc), "1");
  const seen = writes(home.window);
  const asked = home.calls.length;
  otherTab(home.window, PENDING, BOTH);
  await tick();
  assert.equal(mark(home.doc), "2", "Home: the mark says 2");
  assert.deepEqual(seen, [], "nothing written");
  assert.deepEqual(home.calls.slice(asked).map((c) => c.url), [], "no request");
  // Back on Rules, the bar shows both.
  home.doc.querySelector('#nav a[data-page-link="rules"]').click();
  await tick(30);
  assert.equal(count(home.doc), "2");
  assert.deepEqual(drops(home.doc), ["Drop the change to ~/ws/notes.md", "Drop the change to ~/ws/README.md"]);

  const { window, doc, calls } = await rules({ [PENDING]: ONE });
  const seen2 = writes(window);
  const from = calls.length;
  otherTab(window, PENDING, BOTH);
  await tick();
  otherTab(window, SKIPPED, JSON.stringify(["pp-000001"]));
  await tick();
  assert.equal(count(doc), "2");
  assert.deepEqual(seen2, [], "nothing written");
  const urls = calls.slice(from).map((c) => `${c.method} ${c.url}`);
  assert.ok(urls.every((u) => u === "POST /mandu/api/files/impact"), `only what the changes would do: ${urls.join(", ")}`);
  const impact = calls.slice(from).filter((c) => c.url.endsWith("/files/impact")).pop();
  assert.deepEqual((impact?.body as Doc).changes.map((c: Doc) => c.path), [NOTES.path, README.path], "for the list as it is now");
});

test("T8: the focus is kept: on a row's menu in Add a rule; from a Drop drawn away, the bar's heading", async () => {
  const { window, doc } = await rules({ [PENDING]: ONE });
  menuOf(rowFor(doc, /README/)).focus();
  otherTab(window, PENDING, BOTH);
  await tick();
  assert.equal(doc.activeElement, menuOf(rowFor(doc, /README/)), "the README.md menu, drawn anew, has the focus");
  assert.equal(waiting(rowFor(doc, /README/)), true);

  const drop = [...doc.querySelectorAll("#files-pending-list button")].find((b: Doc) => b.getAttribute("aria-label") === "Drop the change to ~/ws/notes.md");
  drop.focus();
  otherTab(window, PENDING, JSON.stringify([README]));
  await tick();
  assert.equal(doc.activeElement, bar(doc).querySelector("h3"), "the bar's heading, never another row's Drop");
  // The focus elsewhere moves nothing.
  const add = doc.getElementById("rules-add");
  add.focus();
  otherTab(window, PENDING, BOTH);
  await tick();
  assert.equal(doc.activeElement, add);
});
