/**
 * home-js-discard-undo.test — on the product page's Rules, Discard in
 * Changes to save leaves a line with Undo that brings the changes back
 * (dashboard.md §4.25n *Discard can be undone*).
 *
 * Until 2026-10-25 Discard threw every level chosen and every ticked key
 * of Mandu's scan away at once, beside Save, with no word and no way back.
 * Now the notice above Your rules says "3 changes discarded." with Undo;
 * Undo puts the levels back in Changes to save (and in localStorage) and
 * ticks the keys again, posts nothing, and gives the focus to the bar's
 * heading. A new change in the bar, or anything else written into the
 * notice (a Save), drops the Undo; a key gone from the next read stays
 * gone, and the line says so.
 *
 * Drop on one row does the same for that one change (§4.25n *Drop can be
 * undone*, 2026-10-28): "Your change to ~/ws/notes.md dropped." with Undo,
 * which puts the row back where it was, as it was, unless a newer choice
 * for its path waits; a second Drop takes the first one's Undo.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only), as
 * every home-js suite. Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, rowFor, choose } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const REPO = "/home/u/proj";
const key = (id: string, file: string): SuggestionWire => ({
  id, kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: `k-${id}`, source: "git-history", repoRoot: REPO,
  edits: [{ op: "lock-path", path: `${REPO}/deploy/${file}`, level: "no-model" }],
  sentence: `Make ~/proj/deploy/${file} a secret no AI may read (only in git history)`,
  evidence: { paths: [`deploy/${file}`], blobs: ["a".repeat(40)], historyOnly: true, findings: [] },
  impact: { historicalVersions: 2, workingTreeChanges: false, files: [] },
  historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
} as SuggestionWire);
const listing = (keys: SuggestionWire[]) => ({ suggestions: suggestionRows(keys, "/home/u", "linux"), count: keys.length, scan: null });

const change = (name: string, level: string) => ({
  path: `/home/u/ws/${name}`, display: `~/ws/${name}`, level, bindings: [], recursive: false, before: "Like any other file", target: null,
});
const TWO = JSON.stringify([change("notes.md", "no-model"), change("todo.md", "no-model")]);
const PENDING = "mandu.files.pending";

const notice = (doc: Doc) => doc.getElementById("rules-notice");
const undoOf = (doc: Doc) => notice(doc).querySelector("button");
const bar = (doc: Doc) => doc.getElementById("files-pending");
const rows = (doc: Doc) => [...doc.querySelectorAll("#files-pending-list li")].map((li: Doc) => li.querySelector("code")?.textContent ?? li.textContent);
const hit = (btn: Doc) => { btn.focus(); btn.click(); };
/** What the page sent that changes something: everything but the impact
 *  line's own read (POST files/impact works out, never saves). */
const writes = (calls: { url: string; method: string }[]) => calls.filter((c) => c.method === "POST" && !c.url.endsWith("/files/impact"));

/** Rules with two levels waiting and Keys Mandu found open (its keys
 *  ticked, in the bar). `keys` answers each read of the suggestions. */
async function page(keys: () => SuggestionWire[], storage = TWO, routes: Record<string, unknown> = {}) {
  const p = load({ url: FILES_URL, storage: { [PENDING]: storage }, routes: { ...FILES_ROUTES,
    "GET suggestions": () => listing(keys()),
    ...routes,
  } });
  await tick();
  p.doc.getElementById("suggest-open").click();
  await tick();
  return p;
}

test("Discard: two levels and a ticked key are thrown away, and the notice says \"3 changes discarded.\" with Undo", async () => {
  const { doc, window, calls } = await page(() => [key("pp-000001", "id_rsa")]);
  assert.equal(doc.getElementById("files-pending-count").textContent, "3", "two levels and the key wait");
  hit(doc.getElementById("files-discard"));
  assert.equal(bar(doc).hidden, true, "nothing waits");
  assert.equal(window.localStorage.getItem(PENDING), null, "no pending entry kept");
  assert.equal(notice(doc).hidden, false);
  assert.equal(notice(doc).firstChild.textContent, "3 changes discarded.");
  const undo = undoOf(doc);
  assert.ok(undo, "with Undo");
  assert.equal(undo.textContent, "Undo the discard");
  assert.equal(undo.getAttribute("aria-label"), "Undo the discard in Your rules");
  assert.equal(undo.getAttribute("aria-describedby"), "rules-notice-words", "described by the notice's words");
  assert.equal(doc.activeElement, doc.getElementById("rules-title"), "the focus on the Your rules heading, above the notice");
  assert.deepEqual(writes(calls), [], "Discard saves nothing");
});

test("Undo: the bar comes back with the same three rows, the key ticked again, the levels in localStorage, the focus on the bar's heading, and nothing posted", async () => {
  const { doc, window, calls } = await page(() => [key("pp-000001", "id_rsa")]);
  const before = rows(doc);
  hit(doc.getElementById("files-discard"));
  hit(undoOf(doc));
  await tick();
  assert.equal(bar(doc).hidden, false, "the changes wait again");
  assert.deepEqual(rows(doc), before, "the same list");
  assert.equal(doc.getElementById("files-pending-count").textContent, "3");
  const tick1 = doc.querySelector("#files-suggested-list input[type=checkbox]");
  assert.equal(tick1?.checked, true, "the key is ticked again");
  assert.equal(window.localStorage.getItem("mandu.files.skipped"), null, "no longer skipped in this browser");
  const kept = JSON.parse(window.localStorage.getItem(PENDING) ?? "[]");
  assert.deepEqual(kept.map((p: Doc) => [p.path, p.level]), [["/home/u/ws/notes.md", "no-model"], ["/home/u/ws/todo.md", "no-model"]], "both levels kept again");
  assert.equal(notice(doc).textContent, "Your changes are back. Nothing is saved until you press Save.");
  assert.equal(undoOf(doc), null, "the line has no Undo of its own");
  const h3 = bar(doc).querySelector("h3");
  assert.equal(doc.activeElement, h3, "the bar's heading");
  assert.equal(h3.textContent, "Changes to save 3");
  assert.deepEqual(writes(calls), [], "Undo posts nothing");
  assert.ok(calls.some((c) => c.method === "POST" && c.url.endsWith("/files/impact")), "what the changes do is worked out again");
});

test("Undo leaves a key the person skipped before Discard skipped", async () => {
  const { doc } = await page(() => [key("pp-000001", "id_rsa"), key("pp-000002", "id_ed25519")]);
  const skip = [...doc.querySelectorAll("#files-pending-list button")].find((b: Doc) => b.getAttribute("aria-label") === "Skip the suggestion for id_ed25519");
  skip.click();
  assert.equal(doc.getElementById("files-pending-count").textContent, "3");
  hit(doc.getElementById("files-discard"));
  assert.equal(notice(doc).firstChild.textContent, "3 changes discarded.", "the skipped key was not in the bar");
  hit(undoOf(doc));
  await tick();
  assert.equal(doc.getElementById("files-pending-count").textContent, "3");
  assert.ok(!rows(doc).some((r) => /id_ed25519/.test(r)), "the key skipped by its own Skip stays skipped");
});

test("A new level chosen after Discard drops the Undo: the line keeps its words", async () => {
  const { doc } = await page(() => [], "[]");
  doc.getElementById("rules-add").click();
  await tick();
  choose(rowFor(doc, /^README\.md/), "no-model");
  await tick();
  hit(doc.getElementById("files-discard"));
  assert.equal(notice(doc).firstChild.textContent, "1 change discarded.");
  assert.ok(undoOf(doc));
  choose(rowFor(doc, /^<img/), "no-model");
  await tick();
  assert.equal(undoOf(doc), null, "no Undo: the discarded change would mix with the new one");
  assert.equal(notice(doc).textContent, "1 change discarded.");
  assert.deepEqual(rows(doc).length, 1, "only the new change waits");
});

test("Ticking a key again after Discard drops the Undo", async () => {
  const { doc } = await page(() => [key("pp-000001", "id_rsa")], "[]");
  hit(doc.getElementById("files-discard"));
  assert.equal(notice(doc).firstChild.textContent, "1 change discarded.");
  const box = doc.querySelector("#files-suggested-list input[type=checkbox]");
  assert.equal(box.checked, false, "skipped by Discard");
  box.checked = true;
  box.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick();
  assert.equal(undoOf(doc), null);
});

test("A Save after Discard: the notice is the save's, without the discard's Undo", async () => {
  let keys: SuggestionWire[] = [];
  const { doc, calls } = await page(() => keys, TWO, {
    "POST suggestions/apply": () => ({ applied: [{ id: "pp-000003", changeId: "pc-000031" }], refused: [], ...listing([]) }),
  });
  hit(doc.getElementById("files-discard"));
  assert.equal(notice(doc).firstChild.textContent, "2 changes discarded.");
  // A scan finds a new key meanwhile: it waits in the bar, ticked.
  keys = [key("pp-000003", "id_dsa")];
  doc.getElementById("suggest-open").click();
  doc.getElementById("suggest-open").click();
  await tick();
  assert.equal(bar(doc).hidden, false);
  hit(doc.getElementById("files-save"));
  await tick(30);
  assert.equal(writes(calls).length, 1, "the key is saved");
  assert.equal(notice(doc).firstChild.textContent, "1 suggestion saved.");
  const undo = undoOf(doc);
  assert.ok(undo, "the save's own Undo");
  assert.notEqual(undo.textContent, "Undo the discard");
});

test("Undo after the next read no longer lists a discarded key: the rest comes back, and the line says how many", async () => {
  let keys = [key("pp-000001", "id_rsa")];
  const { doc, window } = await page(() => keys);
  hit(doc.getElementById("files-discard"));
  assert.equal(notice(doc).firstChild.textContent, "3 changes discarded.");
  // The scan ran again and no longer finds the key.
  keys = [];
  doc.getElementById("suggest-open").click();
  doc.getElementById("suggest-open").click();
  await tick();
  hit(undoOf(doc));
  await tick();
  assert.equal(notice(doc).textContent, "2 of 3 changes are back; 1 key is no longer found. Nothing is saved until you press Save.");
  assert.equal(doc.getElementById("files-pending-count").textContent, "2");
  assert.equal(JSON.parse(window.localStorage.getItem(PENDING) ?? "[]").length, 2);
  assert.equal(doc.activeElement, bar(doc).querySelector("h3"));
});

test("Undo with every discarded key gone: nothing comes back, the line says so, and the focus is on the Your rules heading", async () => {
  let keys = [key("pp-000001", "id_rsa")];
  const { doc } = await page(() => keys, "[]");
  hit(doc.getElementById("files-discard"));
  keys = [];
  doc.getElementById("suggest-open").click();
  doc.getElementById("suggest-open").click();
  await tick();
  hit(undoOf(doc));
  await tick();
  assert.equal(notice(doc).textContent, "None of your changes could come back: 1 key is no longer found.");
  assert.equal(bar(doc).hidden, true);
  assert.equal(doc.activeElement, doc.getElementById("rules-title"));
});

test("The Undo is not kept across a reload", async () => {
  const { doc, window } = await page(() => []);
  hit(doc.getElementById("files-discard"));
  assert.ok(undoOf(doc));
  const again = load({ url: FILES_URL, storage: Object.fromEntries(Object.entries(window.localStorage)), routes: FILES_ROUTES });
  await tick();
  assert.equal(again.doc.getElementById("rules-notice").hidden, true, "a new page says nothing of it");
  assert.equal(again.doc.getElementById("files-pending").hidden, true, "and nothing waits");
});

// Drop on one row (dashboard.md §4.25n *Drop can be undone*): until
// 2026-10-28 it threw that one choice away with no word and no way back.

const NOTES = { ...change("notes.md", "any-model"), bindings: ["api.example.com"], recursive: true };
const TODO = change("todo.md", "no-model");
const PAIR = JSON.stringify([NOTES, TODO]);
const dropOf = (doc: Doc, display: string) => [...doc.querySelectorAll("#files-pending-list button")]
  .find((b: Doc) => b.getAttribute("aria-label") === `Drop the change to ${display}`);

test("Drop on one of two rows: \"Your change to ~/ws/notes.md dropped.\" with Undo, the focus on the bar's heading", async () => {
  const { doc, window, calls } = await page(() => [], PAIR);
  assert.equal(doc.getElementById("files-pending-count").textContent, "2");
  hit(dropOf(doc, "~/ws/notes.md"));
  assert.deepEqual(rows(doc), ["~/ws/todo.md"]);
  assert.deepEqual(JSON.parse(window.localStorage.getItem(PENDING) ?? "[]").map((p: Doc) => p.path), [TODO.path], "dropped in this browser too");
  assert.equal(notice(doc).hidden, false);
  assert.equal(notice(doc).firstChild.textContent, "Your change to ~/ws/notes.md dropped.");
  assert.equal(notice(doc).querySelector("code")?.textContent, "~/ws/notes.md", "the name as code");
  const undo = undoOf(doc);
  assert.ok(undo, "with Undo");
  assert.equal(undo.textContent, "Undo");
  assert.equal(undo.getAttribute("aria-label"), "Undo the drop in Your rules");
  assert.equal(undo.getAttribute("aria-describedby"), "rules-notice-words", "described by the notice's words");
  assert.equal(doc.activeElement, bar(doc).querySelector("h3"), "the bar's heading, never the other row's Drop");
  assert.deepEqual(writes(calls), [], "Drop saves nothing");
});

test("Undo after Drop: the row is back where it was, with its level, hosts and reach, the other row untouched, nothing posted", async () => {
  const { doc, window, calls } = await page(() => [], PAIR);
  const before = [...doc.querySelectorAll("#files-pending-list li")].map((li: Doc) => li.textContent);
  hit(dropOf(doc, "~/ws/notes.md"));
  hit(undoOf(doc));
  await tick();
  assert.deepEqual([...doc.querySelectorAll("#files-pending-list li")].map((li: Doc) => li.textContent), before, "the same two rows, in the same order");
  assert.equal(doc.getElementById("files-pending-count").textContent, "2");
  assert.deepEqual(JSON.parse(window.localStorage.getItem(PENDING) ?? "[]"), [NOTES, TODO], "kept in this browser again, exactly as it was");
  assert.equal(notice(doc).textContent, "Your change is back. Nothing is saved until you press Save.");
  assert.equal(undoOf(doc), null, "the line has no Undo of its own");
  assert.equal(doc.activeElement, bar(doc).querySelector("h3"), "the bar's heading");
  assert.deepEqual(writes(calls), [], "Undo posts nothing");
  assert.ok(calls.filter((c) => c.method === "POST" && c.url.endsWith("/files/impact")).length >= 2, "what the changes do is worked out again");
});

test("Undo after Drop keeps a newer choice for the same path, and says so", async () => {
  const { doc, window } = await page(() => [], PAIR);
  hit(dropOf(doc, "~/ws/notes.md"));
  // Another tab chooses a level for the same file meanwhile.
  const newer = { ...NOTES, level: "no-model", bindings: [] };
  const value = JSON.stringify([TODO, newer]);
  const old = window.localStorage.getItem(PENDING);
  window.localStorage.setItem(PENDING, value);
  window.dispatchEvent(new window.StorageEvent("storage", { key: PENDING, oldValue: old, newValue: value, storageArea: window.localStorage, url: FILES_URL }));
  assert.equal(doc.getElementById("files-pending-count").textContent, "2");
  hit(undoOf(doc));
  await tick();
  assert.deepEqual(JSON.parse(window.localStorage.getItem(PENDING) ?? "[]"), [TODO, newer], "the newer choice is not overwritten");
  assert.equal(notice(doc).textContent, "Your change to ~/ws/notes.md is not back: a newer change to it waits.");
  assert.equal(doc.activeElement, bar(doc).querySelector("h3"));
});

test("A level chosen after Drop drops its Undo: the line keeps its words", async () => {
  const { doc } = await page(() => [], PAIR);
  hit(dropOf(doc, "~/ws/todo.md"));
  assert.ok(undoOf(doc));
  doc.getElementById("rules-add").click();
  await tick();
  choose(rowFor(doc, /^README\.md/), "no-model");
  await tick();
  assert.equal(undoOf(doc), null, "no Undo: the dropped change would mix with the new one");
  assert.equal(notice(doc).textContent, "Your change to ~/ws/todo.md dropped.");
});

test("A second Drop takes the first Drop's Undo: Undo brings back only the second row", async () => {
  const { doc } = await page(() => [], PAIR);
  hit(dropOf(doc, "~/ws/notes.md"));
  hit(dropOf(doc, "~/ws/todo.md"));
  assert.equal(bar(doc).hidden, true, "nothing waits");
  assert.equal(notice(doc).firstChild.textContent, "Your change to ~/ws/todo.md dropped.");
  assert.equal(notice(doc).querySelectorAll("button").length, 1, "one Undo, for the last drop");
  assert.equal(doc.activeElement, doc.getElementById("rules-title"), "the bar gone: the Your rules heading");
  hit(undoOf(doc));
  await tick();
  assert.deepEqual(rows(doc), ["~/ws/todo.md"]);
  assert.equal(doc.getElementById("files-pending-count").textContent, "1");
  assert.equal(doc.activeElement, bar(doc).querySelector("h3"));
});
