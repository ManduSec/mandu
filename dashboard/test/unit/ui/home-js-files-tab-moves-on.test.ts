/**
 * home-js-files-tab-moves-on.test — Tab in the path box under Rules › Add a
 * rule finishes the name being typed, and otherwise moves the focus on as
 * on any field (public/js/home.js `tabCompletes`, `completionOf`;
 * dashboard.md §4.25m *Tab moves on*).
 *
 * Until 2026-10-15 the box kept every Tab without Shift while its text
 * ended at the caret or the selection, then asked whether there was a
 * name to finish. The box always holds the folder shown (`~/ws/`), and a
 * Tab into it selects all of it, so the keyboard could not leave the box
 * but backwards: Go, the list, the ticked items, Your rules and the rest of
 * the page were out of reach of Tab. A Tab the box keeps is one whose
 * keydown is defaultPrevented; any other moves the focus on. Now:
 *
 *   M1  a Tab on the way in (the whole text selected) moves on;
 *   M2  no name started (the text ends with /, as after Go) moves on:
 *       `~/ws/config/` is no longer filled in with the one name inside;
 *   M3  a pattern, a relative path, a text without / move on, and
 *       Shift+Tab is never kept;
 *   M4  every name of the folder read and nothing to add (a whole name, a
 *       name nothing starts with): moves on at once, reading nothing;
 *   M5  a name that completes: the box keeps the Tab and finishes it; the
 *       next Tab moves on;
 *   M6  what typing added is selected: Tab takes it (the caret to the end)
 *       and stays, a folder's name without filling in one inside it; the
 *       next Tab moves on;
 *   M7  a folder that cannot be listed: the first Tab waits for it and
 *       stays, the second on the same text moves on and reads nothing;
 *       typing gives Tab another try;
 *   M8  Tabs while the names are on their way wait for that one read; then
 *       nothing to add moves on at once.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * across the real arbiter and dashboard, tests/stack/
 * product-path-box-tab.test.ts. Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, WS_LIST, NONE, list } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const box = (doc: Doc) => doc.getElementById("lock-path");
const listings = (calls: { url: string }[]) => calls.filter((c) => c.url.includes("/api/files/list")).length;
const reads = (calls: { url: string }[], path: string) => calls.filter((c) => c.url.endsWith(`/api/files/list?path=${encodeURIComponent(path)}`)).length;

/** Tab on the path box as it stands; true when the box keeps it. */
async function press(doc: Doc, init: Record<string, unknown> = {}) {
  const e = new doc.defaultView.KeyboardEvent("keydown", { key: "Tab", cancelable: true, ...init });
  box(doc).dispatchEvent(e);
  await tick(30);
  return e.defaultPrevented as boolean;
}
/** Tab with `value` in the box, the caret (or the selection `sel`) at its end. */
async function tabAt(doc: Doc, value: string, sel?: [number, number]) {
  const input = box(doc);
  input.value = value;
  input.setSelectionRange(...(sel ?? [value.length, value.length]));
  return press(doc);
}
/** `value` typed into the box, its last key as a person types it. */
async function type(doc: Doc, value: string) {
  const input = box(doc);
  input.value = value;
  input.setSelectionRange(value.length, value.length);
  input.dispatchEvent(new doc.defaultView.InputEvent("input", { inputType: "insertText", data: value.slice(-1) }));
  await tick(30);
}
async function openBrowser() {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...EXTRA } });
  await tick();
  page.doc.getElementById("rules-add").click();
  await tick();
  assert.equal(box(page.doc).value, "~/ws/", "the browser shows ~/ws, and the box says so");
  return page;
}

const GONE = { status: 404, body: { error: "no such folder", path: "/home/u/gone" } };
const EXTRA: Record<string, unknown> = { [list("~/gone")]: GONE };

test("M1: a Tab on the way in (the whole text selected) moves on, and reads nothing", async () => {
  const { doc, calls } = await openBrowser();
  const before = listings(calls);
  assert.equal(await tabAt(doc, "~/ws/", [0, 5]), false, "Tab moves on");
  assert.equal(box(doc).value, "~/ws/");
  assert.equal(await tabAt(doc, "~/ws/READ", [0, 9]), false, "a name all selected too");
  assert.equal(box(doc).value, "~/ws/READ", "nothing finished");
  assert.equal(listings(calls), before, "no listing read");
});

test("M2: no name started (the text ends with /, as after Go) moves on, and the one name in a folder is not filled in", async () => {
  const { doc, calls } = await openBrowser();
  assert.equal(await tabAt(doc, "~/ws/"), false, "after Go: Tab moves on");
  assert.equal(await tabAt(doc, "~/ws/config/"), false);
  assert.equal(box(doc).value, "~/ws/config/", "never ~/ws/config/db.yaml");
  assert.equal(reads(calls, "~/ws/config"), 0, "the folder is not read for it");
});

test("M3: a pattern, a relative path or a text without / move on; Shift+Tab is never kept", async () => {
  const { doc } = await openBrowser();
  for (const v of ["**/*.pem", "~/ws/*.env", "relative/path", "~"]) {
    assert.equal(await tabAt(doc, v), false, `${v}: Tab moves on`);
    assert.equal(box(doc).value, v);
  }
  box(doc).value = "~/ws/READ";
  box(doc).setSelectionRange(9, 9);
  assert.equal(await press(doc, { shiftKey: true }), false, "Shift+Tab goes back");
  assert.equal(box(doc).value, "~/ws/READ");
});

test("M4: every name read and nothing to add moves on at once, reading nothing", async () => {
  const { doc, calls } = await openBrowser();
  const before = listings(calls);
  assert.equal(await tabAt(doc, "~/ws/README.md"), false, "a whole name");
  assert.equal(box(doc).value, "~/ws/README.md");
  assert.equal(await tabAt(doc, "~/ws/nothing-like-this"), false, "a name nothing starts with");
  assert.equal(box(doc).value, "~/ws/nothing-like-this");
  assert.equal(await tabAt(doc, "/home/u/ws/README.md"), false, "the folder written out in full");
  assert.equal(listings(calls), before, "the names are the shown folder's: no listing read");
});

test("M5: a name that completes keeps the Tab and is finished; the next Tab moves on", async () => {
  const { doc } = await openBrowser();
  assert.equal(await tabAt(doc, "~/ws/READ"), true, "the box keeps the Tab");
  assert.equal(box(doc).value, "~/ws/README.md");
  assert.equal(box(doc).selectionStart, 14, "the caret after the name");
  assert.equal(await press(doc), false, "the next Tab moves on");
  assert.equal(box(doc).value, "~/ws/README.md");
  assert.equal(await tabAt(doc, "~/ws/co"), true);
  assert.equal(box(doc).value, "~/ws/config/", "a folder, with its /");
  assert.equal(await press(doc), false, "and then no name is started");
});

test("M6: what typing added is selected: Tab takes it and stays; the next Tab moves on", async () => {
  const { doc, calls } = await openBrowser();
  await type(doc, "~/ws/READ");
  assert.equal(box(doc).value, "~/ws/README.md");
  assert.deepEqual([box(doc).selectionStart, box(doc).selectionEnd], [9, 14], "typing selected what it added");
  assert.equal(await press(doc), true, "Tab takes it");
  assert.deepEqual([box(doc).selectionStart, box(doc).selectionEnd], [14, 14], "the caret after it");
  assert.equal(box(doc).value, "~/ws/README.md");
  assert.equal(await press(doc), false, "the next Tab moves on");

  await type(doc, "~/ws/con");
  assert.equal(box(doc).value, "~/ws/config/");
  assert.deepEqual([box(doc).selectionStart, box(doc).selectionEnd], [8, 12]);
  assert.equal(await press(doc), true, "Tab takes the folder's name");
  assert.deepEqual([box(doc).selectionStart, box(doc).selectionEnd], [12, 12]);
  assert.equal(box(doc).value, "~/ws/config/", "nothing inside it filled in");
  assert.equal(reads(calls, "~/ws/config"), 0);
  assert.equal(await press(doc), false, "the next Tab moves on");
});

test("M7: a folder that cannot be listed: the first Tab waits and stays, the second moves on; typing gives Tab another try", async () => {
  const { doc, calls } = await openBrowser();
  assert.equal(await tabAt(doc, "~/gone/x"), true, "the names are not read yet: the box keeps the Tab");
  assert.equal(box(doc).value, "~/gone/x");
  assert.equal(reads(calls, "~/gone"), 1);
  assert.equal(await press(doc), false, "the second Tab on the same text moves on");
  assert.equal(reads(calls, "~/gone"), 1, "and reads nothing");
  assert.equal(await press(doc), false, "and so does every one after it");
  // The x typed again: the same text, and another try.
  await type(doc, "~/gone/x");
  const typed = reads(calls, "~/gone");
  assert.equal(await press(doc), true, "typed text: Tab tries again");
  assert.equal(reads(calls, "~/gone"), typed + 1);
  assert.equal(await press(doc), false);
});

test("M8: Tabs while the names are on their way wait for that one read; then nothing to add moves on at once", async () => {
  let release: () => void = () => {};
  const held = new Promise<void>((r) => { release = r; });
  const entry = (name: string) => ({ name, path: `/home/u/slow/${name}`, display: `~/slow/${name}`, kind: "file", link: null, label: NONE, inside: 0 });
  const SLOW = { ...WS_LIST, path: "/home/u/slow", display: "~/slow", crumbs: [], entries: [entry("alpha-2.txt"), entry("alpha.txt")], total: 2 };
  EXTRA[list("~/slow")] = () => held.then(() => SLOW);
  try {
    const { doc, calls } = await openBrowser();
    assert.equal(await tabAt(doc, "~/slow/al"), true);
    assert.equal(await press(doc), true, "the read is still out: this Tab waits for it too");
    assert.equal(box(doc).value, "~/slow/al");
    release();
    await tick(30);
    assert.equal(box(doc).value, "~/slow/alpha", "finished once");
    assert.equal(reads(calls, "~/slow"), 1, "one read for both Tabs");
    assert.equal(await press(doc), false, "alpha.txt and alpha-2.txt share alpha: the next Tab moves on");
    assert.equal(reads(calls, "~/slow"), 1);
  } finally {
    delete EXTRA[list("~/slow")];
  }
});
