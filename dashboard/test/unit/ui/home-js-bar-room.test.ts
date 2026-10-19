/**
 * home-js-bar-room.test — on the product page's Rules, Changes to save never
 * hides the keyboard focus (dashboard.md §4.25n *It never hides the focus*).
 *
 * The bar is sticky at the bottom of the window, over the rules. Until
 * 2026-10-14 the page kept no room for it: in a headless Chromium at
 * 1280×800 with three changes waiting, 48 of 118 Tab stops (the rules'
 * menus, Add a rule, Sending data's menus) were scrolled to the window's
 * bottom edge, entirely under the bar, and 21 more partly (75 of 118 at
 * 390×844); and a label chosen in a row near the window's bottom left that
 * menu under the bar that came up with it. Now:
 *
 *   - app.css keeps `--bar-room` below what the window scrolls into view
 *     (scroll-padding-bottom), except while the focus is in the bar itself
 *     (the window would scroll to the bar's own place in the page);
 *   - home.js trackBarRoom watches the bar: `--bar-room` is its height, its
 *     12px margin and 8px more while it is shown, and nothing while it, or
 *     its page, is hidden;
 *   - a bar that comes or grows over the focused control scrolls that
 *     control into view, above it; a control above the bar, in the bar, or
 *     no focus at all moves nothing.
 *
 * jsdom lays out nothing and has no ResizeObserver: fake-resize.ts gives the
 * page one, and each test gives the bar and the focused control their place
 * in the window (a 1280×800 window, the bar's 259px measured in Chromium).
 * Drives the PRODUCT page script (public/js/home.js) over the shared fetch
 * stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { load, tick, FILES_URL, FILES_ROUTES, PUB, menuOf, treeRow } from "./home-js-fixtures.js";
import { fakeResize } from "./fake-resize.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const fileRule = (path: string, level: string) => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers: "exact", bindings: [], level,
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: "this file only", effect: "x" },
});
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  fileRule("/home/u/ws/deploy.token", "no-model"),
  fileRule("/home/u/ws/README.md", "any-model"),
] } };
const WAITING = JSON.stringify([{ path: "/home/u/ws/notes.md", display: "~/ws/notes.md", level: "no-model", bindings: [], recursive: false, before: "Like any other file", target: null }]);

/** The Rules page with a ResizeObserver; `storage` the changes waiting. */
function rules(storage: Record<string, string> = {}) {
  const ro = fakeResize();
  const page = load({ url: FILES_URL, storage, routes: { ...FILES_ROUTES, "GET policy/panel": PANEL }, before: (w) => ro.install(w) });
  return { ...page, ro };
}
/** Put `el` at `top` in the window, `height` high (jsdom lays out nothing). */
function place(el: Doc, top: number, height: number): void {
  el.getBoundingClientRect = () => ({ top, bottom: top + height, height, left: 20, right: 1260, width: 1240, x: 20, y: top });
}
/** Each scrollIntoView `el` is asked for, by its `block` (the page's own
 *  objects are of jsdom's realm, so they are not compared whole). */
function scrolls(el: Doc): string[] {
  const asked: string[] = [];
  el.scrollIntoView = (o: Doc) => { asked.push(String(o && o.block)); };
  return asked;
}
const bar = (doc: Doc) => doc.getElementById("files-pending");
const room = (doc: Doc) => doc.documentElement.style.getPropertyValue("--bar-room");
/** Where the bar sits while stuck in an 800px window: 12px above its bottom. */
const BAR_TOP = 800 - 12 - 259;

/** The page's stylesheets, comments dropped, as `selector { body }` rules. */
function rulesOf(file: string): Array<{ sel: string; body: string }> {
  const css = readFileSync(join(PUB, file), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  return [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1]!.trim(), body: m[2]!.trim() }));
}

test("the stylesheet keeps the bar's room below what the window scrolls to, except for a control in the bar; the bar is sticky 12px above the window's bottom", () => {
  const all = [...rulesOf("mandu.css"), ...rulesOf("app.css")];
  const padding = all.filter((r) => /scroll-padding/.test(r.body));
  assert.deepEqual(padding.map((r) => r.sel), ["html:not(:has(#files-pending:focus-within))"], "one rule, on the window, off while the focus is in the bar");
  assert.equal(padding[0]!.body.replace(/;$/, ""), "scroll-padding-bottom: var(--bar-room, 0px)", "the room home.js measures, none until it does");
  const own = all.find((r) => r.sel === ".files-pending");
  assert.ok(own, "the bar's own rule");
  assert.match(own.body, /position: sticky; bottom: 12px;/, "home.js counts its 12px margin into the room");
});

test("trackBarRoom: the room is the bar's height, its 12px margin and 8px more while it is shown, and nothing once it is hidden", async () => {
  const { doc, ro, err } = rules({ "mandu.files.pending": WAITING });
  assert.equal(err, null);
  await tick();
  assert.equal(bar(doc).hidden, false, "a change waits");
  assert.equal(ro.watched(bar(doc)), true, "the bar is watched");
  place(bar(doc), BAR_TOP, 258.4);
  ro.resized(bar(doc));
  assert.equal(room(doc), "279px", "259 (whole pixels) + 12 + 8");
  // It grows (the impact note came, the question asks): the room follows.
  place(bar(doc), 400, 388);
  ro.resized(bar(doc));
  assert.equal(room(doc), "408px");
  // Discard: the bar is hidden, a box of no height; so is a bar on a page not shown.
  doc.getElementById("files-discard").click();
  await tick();
  assert.equal(bar(doc).hidden, true);
  place(bar(doc), 0, 0);
  ro.resized(bar(doc));
  assert.equal(room(doc), "", "no room kept");
});

test("trackBarRoom: a bar over the focused control scrolls that control into view, nearest; a control above it, in it, or no focus moves nothing", async () => {
  const { doc, ro } = rules({ "mandu.files.pending": WAITING });
  await tick();
  place(bar(doc), BAR_TOP, 259);
  const menu = menuOf(treeRow(doc, /^deploy\.token/));
  const asked = scrolls(menu);
  menu.focus();
  assert.equal(doc.activeElement, menu);
  // Under the bar: scrolled into view, where the room keeps it above the bar.
  place(menu, 700, 34);
  ro.resized(bar(doc));
  assert.deepEqual(asked, ["nearest"]);
  // Partly under it (its bottom 4px into the bar): the same.
  place(menu, BAR_TOP - 30, 34);
  ro.resized(bar(doc));
  assert.equal(asked.length, 2);
  // Above the bar, whole: nothing moves.
  place(menu, 300, 34);
  ro.resized(bar(doc));
  assert.equal(asked.length, 2, "a control in view stays where it is");
  // A control in the bar is the bar's own.
  const save = doc.getElementById("files-save");
  const saveAsked = scrolls(save);
  save.focus();
  place(save, BAR_TOP + 200, 34);
  ro.resized(bar(doc));
  assert.deepEqual(saveAsked, [], "Save, in the bar, never scrolls the window");
  // No focus: <body>, which spans the page in a browser.
  save.blur();
  assert.equal(doc.activeElement, doc.body);
  const bodyAsked = scrolls(doc.body);
  place(doc.body, -400, 3000);
  ro.resized(bar(doc));
  assert.deepEqual(bodyAsked, [], "<body> moves nothing");
  assert.equal(asked.length + saveAsked.length, 2);
});

test("a label chosen in a row near the window's bottom: the bar comes up over that menu, and the menu, drawn again with the focus, is scrolled above it", async () => {
  const { doc, ro } = rules();
  await tick();
  assert.equal(bar(doc).hidden, true, "nothing waits yet");
  ro.resized(bar(doc));
  assert.equal(room(doc), "", "no bar, no room");
  const old = menuOf(treeRow(doc, /^README/));
  old.focus();
  old.value = "no-model";
  old.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick();
  const now = menuOf(treeRow(doc, /^README/));
  assert.notEqual(now, old, "the tree was drawn again");
  assert.equal(doc.activeElement, now, "the same row's menu keeps the focus (§4.25 *A label chosen in Your rules keeps the focus*)");
  assert.equal(bar(doc).hidden, false, "the change waits in the bar");
  // The browser lays the bar out over the menu, then tells its observer.
  const asked = scrolls(now);
  place(bar(doc), BAR_TOP, 259);
  place(now, 740, 34);
  ro.resized(bar(doc));
  assert.equal(room(doc), "279px");
  assert.deepEqual(asked, ["nearest"], "the menu is scrolled above the bar");
});

test("a browser without ResizeObserver: the page still boots, and keeps no room", async () => {
  const { doc, err } = load({ url: FILES_URL, storage: { "mandu.files.pending": WAITING }, routes: { ...FILES_ROUTES, "GET policy/panel": PANEL } });
  assert.equal(err, null);
  await tick();
  assert.equal(bar(doc).hidden, false);
  assert.equal(room(doc), "", "jsdom's bar has no height, and nothing watches it");
});
