/**
 * home-js-file-rule.test — on the product page's Rules, a rule that reaches
 * everything inside a path that is a FILE reads as that file (dashboard.md
 * §4.25f *A rule on a file reads as a file*). Mandu-new.
 *
 * A `paths:` entry with no `recursive:` key reaches everything inside its
 * path, and a saved Keys Mandu found suggestion writes one on a file. Until
 * 2026-10-11 Your rules drew it with a folder icon, its opened row said "Your
 * rule, and everything inside" and "A folder label covers everything inside
 * it…", a label made in the inspector read "and everything inside", and a
 * change to it waited in Changes to save as "…, and everything inside".
 *
 * The server says which rules name a file (`pathIsFile`, server/path-kinds.ts);
 * the page draws those as files and keeps the rule's reach for its edits
 * (`covers`), so a change saved here keeps the entry as written.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, treeRows, treeRow, opened, choose } from "./home-js-fixtures.js";

const rule = (path: string, reach: string, more: Record<string, unknown> = {}) => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null,
  level: "no-model", bindings: [], actions: { remove: true, flip: null },
  plain: { subject: path, reach, effect: "No AI" }, ...more,
});
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  // As the server words a suggestion saved from Keys Mandu found.
  rule("/home/u/proj/deploy/staging.conf", "this file only", { covers: "subtree", pathIsFile: true }),
  rule("/home/u/proj/secrets", "and everything inside", { covers: "subtree" }),
  rule("/home/u/proj/exact.token", "this file only", { covers: "exact" }),
] } };
// A label made in the inspector (Lock it) on a file: no `recursive` sent.
const SECRETS = { panel: { labels: [
  { path: "/home/u/proj/inspector.token", levelClass: "strict", modelOk: false, scope: "subtree", pathIsFile: true, pattern: false, bindings: [], source: "user" },
] } };

function page(routes: Record<string, unknown> = {}) {
  return load({ url: FILES_URL, routes: { "GET policy/panel": PANEL, "GET secrets": SECRETS, ...routes } });
}
const icon = (row: any) => row.querySelector(".row-icon").innerHTML as string;
const name = (row: any) => (row.querySelector(".file-name").textContent as string).trim();

test("a rule reaching everything inside a file is drawn and worded as that file, in the tree and its opened row; a folder rule keeps its words", async () => {
  const { doc } = page();
  await tick();
  assert.equal(treeRows(doc).length, 4);
  const staging = treeRow(doc, /staging\.conf/);
  const folder = treeRow(doc, /^secrets$/);
  const exact = treeRow(doc, /exact\.token/);
  const inspector = treeRow(doc, /inspector\.token/);
  assert.equal(name(staging), "deploy/staging.conf this file only");
  assert.equal(name(folder), "secrets and everything inside");
  assert.equal(name(inspector), "inspector.token this file only", "a label made elsewhere, the same words");
  assert.equal(icon(staging), icon(exact), "a file's icon");
  assert.equal(icon(inspector), icon(exact), "a file's icon");
  assert.notEqual(icon(staging), icon(folder), "never the folder's");

  staging.querySelector(".file-more").click();
  const text = opened(doc).textContent as string;
  assert.match(text, /Your rule, this file only/);
  assert.doesNotMatch(text, /everything inside/, "no folder note");
  assert.ok([...opened(doc).querySelectorAll("button")].some((b: any) => b.textContent === "Show in its folder"));

  treeRow(doc, /^secrets$/).querySelector(".file-more").click();
  assert.match(opened(doc).textContent, /Your rule, and everything inside/);
  assert.match(opened(doc).textContent, /A folder's rule covers everything inside it, except files with a rule of their own\./);
});

test("a change to that rule waits as a change to the file, and is saved with the rule's reach kept (recursive: true)", async () => {
  const saves: any[] = [];
  const { doc, calls } = page({ "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: "pc-000021", page: 0 }) });
  await tick();
  choose(treeRow(doc, /staging\.conf/), "any-model");
  choose(treeRow(doc, /^secrets$/), "local-model");
  const lines = [...doc.querySelectorAll("#files-pending-list li")].map((li: any) => li.textContent as string);
  const staging = lines.find((l) => l.includes("staging.conf"))!;
  assert.match(staging, /^~\/proj\/deploy\/staging\.conf No AI → Any AI, when it asks/);
  assert.doesNotMatch(staging, /everything inside/, "a file has nothing inside");
  assert.match(lines.find((l) => l.includes("secrets"))!, /and everything inside/, "a folder still says it");
  doc.getElementById("files-save").click();
  await tick();
  assert.equal(saves.length, 1, calls.map((c) => c.url).join(" "));
  const sent = Object.fromEntries((saves[0].changes as Array<{ path: string }>).map((c) => [c.path, c]));
  assert.deepEqual(sent["/home/u/proj/deploy/staging.conf"], { path: "/home/u/proj/deploy/staging.conf", level: "any-model", recursive: true },
    "the entry keeps its reach: no `recursive: false`, so nothing is narrowed or asked");
  assert.deepEqual(sent["/home/u/proj/secrets"], { path: "/home/u/proj/secrets", level: "local-model", recursive: true });
});
