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

// ── dashboard.md §4.25f *A rule on nothing says so* ────────────────────────────
const MISSING_WORDS = "Nothing at this path on this computer. The rule applies if something appears here; if you meant another file, check the spelling.";
const MISSING_PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  // A typo for .env, as the server marks it (path-kinds.ts found nothing there).
  rule("/home/u/shop/.evn", "and everything inside", { covers: "subtree", missing: true, plain: { subject: "/home/u/shop/.evn", reach: "and everything inside", effect: "No AI", opens: "Only programs you allow" } }),
  rule("/home/u/shop/.env", "and everything inside", { covers: "subtree" }),
  rule("/home/u/shop/old.token", "this file only", { covers: "exact", missing: true }),
  // A pattern is never marked by the server; drawn without the line even so.
  rule("/home/u/shop/*.key", "every matching file", { covers: "pattern", missing: true }),
] } };
const missingLine = (row: any) => row.querySelector(".file-missing")?.textContent as string | undefined;

test("a rule whose path has nothing on this computer says so under its name, with the file icon; its reach, its opened row's words and Find a rule are as said", async () => {
  const saves: any[] = [];
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": MISSING_PANEL, "GET secrets": { panel: { labels: [] } },
    "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: "pc-000022", page: 0 }) } });
  await tick();
  const typo = treeRow(doc, /\.evn$/);
  const real = treeRow(doc, /^\.env$/);
  const old = treeRow(doc, /old\.token/);
  const pattern = treeRows(doc).find((r) => r.getAttribute("data-path") === "/home/u/shop/*.key");
  assert.equal(missingLine(typo), MISSING_WORDS);
  assert.equal(missingLine(old), MISSING_WORDS, "an exact rule too");
  assert.equal(missingLine(real), undefined, "a path that is there draws as before");
  assert.equal(missingLine(pattern), undefined, "a pattern never");
  // First under its name, where Opens it goes; Opens it still follows.
  const lines = [...typo.querySelector(".file-text").children].map((c: any) => c.className);
  assert.deepEqual(lines.slice(0, 3), ["file-name", "dim file-missing", "dim file-opens"]);
  // The reach the rule has is kept in its words; the icon is a file's.
  assert.equal(name(typo), ".evn and everything inside");
  assert.equal(icon(typo), icon(old), "a file's icon");
  assert.notEqual(icon(typo), icon(real), "never the folder's");

  typo.querySelector(".file-more").click();
  const text = opened(doc).textContent as string;
  assert.match(text, /Your rule, and everything inside/);
  assert.ok(text.includes(MISSING_WORDS), "the opened row says it");
  assert.doesNotMatch(text, /A folder's rule covers everything inside it/, "in place of the folder note");
  treeRow(doc, /^\.env$/).querySelector(".file-more").click();
  assert.ok(!(opened(doc).textContent as string).includes(MISSING_WORDS));
  assert.match(opened(doc).textContent, /A folder's rule covers everything inside it/, "a folder rule keeps its note");

  // A change to it keeps the rule's reach (ruleShape's kind is unchanged).
  choose(treeRow(doc, /\.evn$/), "any-model");
  const pending = [...doc.querySelectorAll("#files-pending-list li")].map((li: any) => li.textContent as string).find((l) => l.includes(".evn"))!;
  assert.match(pending, /and everything inside/);
  doc.getElementById("files-save").click();
  await tick();
  const sent = (saves[0]?.changes as Array<{ path: string; recursive?: boolean }> | undefined)?.find((c) => c.path === "/home/u/shop/.evn");
  assert.equal(sent?.recursive, true, "saved with its reach");
});

test("Find a rule finds a rule on nothing by its name as before, and not by the line's words", async () => {
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": MISSING_PANEL, "GET secrets": { panel: { labels: [] } } } });
  await tick();
  const find = (q: string) => {
    const box = doc.getElementById("rules-find");
    box.value = q;
    box.dispatchEvent(new doc.defaultView.Event("input"));
  };
  find(".evn");
  await tick();
  assert.deepEqual(treeRows(doc).map((r) => r.getAttribute("data-path")), ["/home/u/shop/.evn"]);
  assert.equal(missingLine(treeRows(doc)[0]), MISSING_WORDS);
  find("check the spelling");
  await tick();
  assert.equal(treeRows(doc).length, 0, "the line is not a rule's words");
});

test("a rule made on this page (a label from /api/secrets) on a path with nothing there says so the same way; one that is there, and a pattern, do not", async () => {
  const label = (path: string, more: Record<string, unknown> = {}) => ({
    path, level: "no-model", levelClass: "strict", modelOk: false, scope: "subtree", pattern: false, bindings: [], source: "user", ...more,
  });
  // As /api/secrets marks them (path-kinds.ts): a moved project's .env, an
  // exact label on a deleted file; a file that is there; a pattern.
  const labels = [
    label("/home/u/old-shop/.env", { missing: true }),
    label("/home/u/old-shop/deploy.token", { scope: "exact", missing: true }),
    label("/home/u/shop/.env", { pathIsFile: true }),
    label("/home/u/shop/*.pem", { pattern: true, missing: true }),
  ];
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } }, "GET secrets": { panel: { labels } } } });
  await tick();
  const byPath = (p: string) => treeRows(doc).find((r) => r.getAttribute("data-path") === p);
  const moved = byPath("/home/u/old-shop/.env");
  const gone = byPath("/home/u/old-shop/deploy.token");
  const there = byPath("/home/u/shop/.env");
  const pattern = byPath("/home/u/shop/*.pem");
  assert.ok(moved && gone && there && pattern, treeRows(doc).map((r) => r.getAttribute("data-path")).join(" "));
  assert.equal(missingLine(moved), MISSING_WORDS);
  assert.equal(missingLine(gone), MISSING_WORDS, "an exact label too");
  assert.equal(missingLine(there), undefined, "a path that is there draws as before");
  assert.equal(missingLine(pattern), undefined, "a pattern never");
  // The reach is kept in its words; the icon is a file's, never a folder's.
  assert.equal(name(moved), ".env and everything inside");
  assert.equal(icon(moved), icon(there), "a file's icon");
  assert.equal(icon(gone), icon(there), "a file's icon");

  moved.querySelector(".file-more").click();
  const text = opened(doc).textContent as string;
  assert.ok(text.includes(MISSING_WORDS), "the opened row says it");
  assert.doesNotMatch(text, /A folder's rule covers everything inside it/, "in place of the folder note");
  byPath("/home/u/shop/.env")!.querySelector(".file-more").click();
  assert.ok(!(opened(doc).textContent as string).includes(MISSING_WORDS), "nor in the opened row of one that is there");
});

// ── §4.25f *A rule on nothing says so*: the folder head and the heading line ──
const note = (doc: any) => doc.getElementById("files-missing");
const noteButtons = (doc: any) => [...note(doc).querySelectorAll("button")] as any[];
const folderHead = (doc: any, full: string) => ([...doc.querySelectorAll("#files-tree .rules-folder")] as any[]).find((f) => f.title === full);
const folderWords = (head: any) => head.querySelector(".dim").textContent as string;
const findBox = (doc: any, q: string) => {
  const box = doc.getElementById("rules-find");
  box.value = q;
  box.dispatchEvent(new doc.defaultView.Event("input"));
};
const panelOf = (rules: unknown[]) => ({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: rules } });
const NO_LABELS = { panel: { labels: [] } };

test("the Files and folders heading names the rules on nothing as buttons, and their folder head counts them; a rule that is there and a pattern are not counted", async () => {
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": MISSING_PANEL, "GET secrets": NO_LABELS } });
  await tick();
  assert.equal(note(doc).hidden, false);
  assert.equal(note(doc).textContent, "2 rules name a path where nothing is on this computer: ~/shop/.evn, ~/shop/old.token.");
  assert.deepEqual(noteButtons(doc).map((b) => b.textContent), ["~/shop/.evn", "~/shop/old.token"], "the real .env and the pattern are not among them");
  assert.ok(!doc.querySelector("#files-tree").contains(note(doc)), "outside the list");
  assert.equal(folderWords(folderHead(doc, "~/shop")), "3 rules, 2 on a path where nothing is", "the pattern is not in the tree, nor counted");
});

test("past three rules on nothing the heading line names three and says how many more", async () => {
  const rules = ["a", "b", "c", "d", "e"].map((x) => rule(`/home/u/gone/${x}.token`, "this file only", { covers: "exact", missing: true }));
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": panelOf(rules), "GET secrets": NO_LABELS } });
  await tick();
  assert.equal(noteButtons(doc).length, 3);
  assert.match(note(doc).textContent, /^5 rules name a path where nothing is on this computer: ~\/gone\/a\.token, ~\/gone\/b\.token, ~\/gone\/c\.token, and 2 more, each marked below\.$/);
  assert.equal(folderWords(folderHead(doc, "~/gone")), "5 rules, 5 on a path where nothing is");
});

test("with no rule on nothing there is no heading line and the folder heads read as before", async () => {
  const { doc } = page();
  await tick();
  assert.equal(note(doc).hidden, true);
  assert.equal(note(doc).textContent, "");
  const heads = [...doc.querySelectorAll("#files-tree .rules-folder")] as any[];
  assert.ok(heads.length > 0);
  for (const h of heads) assert.doesNotMatch(folderWords(h), /nothing/);
  assert.equal(folderWords(folderHead(doc, "~/proj")), "4 rules");
});

const FOLDED_PANEL = panelOf([
  rule("/home/u/shop/.evn", "and everything inside", { covers: "subtree", missing: true }),
  rule("/home/u/shop/.env", "and everything inside", { covers: "subtree" }),
  rule("/home/u/notes/a.txt", "this file only", { covers: "exact" }),
  rule("/home/u/notes/b.txt", "this file only", { covers: "exact" }),
  rule("/home/u/**/*.key", "every matching file", { covers: "pattern", missing: true }),
]);

test("a folded folder still says it holds a rule on nothing, and the heading line's button unfolds it, opens that row and focuses its ⋯", async () => {
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": FOLDED_PANEL, "GET secrets": NO_LABELS } });
  await tick();
  assert.equal(folderWords(folderHead(doc, "~/shop")), "2 rules, 1 on a path where nothing is");
  assert.equal(folderWords(folderHead(doc, "~/notes")), "2 rules", "a folder with none reads as before");
  assert.equal(note(doc).textContent, "1 rule names a path where nothing is on this computer: ~/shop/.evn.", "the pattern is never counted");
  folderHead(doc, "~/shop").click();
  assert.equal(folderHead(doc, "~/shop").getAttribute("aria-expanded"), "false");
  // Drawn again (a row of another folder opened): still folded, still said.
  treeRow(doc, /^a\.txt$/).querySelector(".file-more").click();
  assert.equal(folderHead(doc, "~/shop").getAttribute("aria-expanded"), "false");
  assert.equal(folderWords(folderHead(doc, "~/shop")), "2 rules, 1 on a path where nothing is");

  noteButtons(doc)[0].click();
  assert.equal(folderHead(doc, "~/shop").getAttribute("aria-expanded"), "true", "unfolded");
  const row = treeRow(doc, /\.evn$/);
  assert.ok(row.classList.contains("open"), "the row is opened");
  assert.ok((opened(doc).textContent as string).includes(MISSING_WORDS));
  assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus is on its ⋯");
});

test("the heading line counts every rule while Find a rule has text, and its button empties a box that hides the rule and lands on the row", async () => {
  const { doc } = load({ url: FILES_URL, routes: { "GET policy/panel": FOLDED_PANEL, "GET secrets": NO_LABELS } });
  await tick();
  findBox(doc, ".env");
  await tick();
  assert.equal(treeRow(doc, /\.evn$/), undefined, "the box hides it");
  assert.equal(folderWords(folderHead(doc, "~/shop")), "1 rule", "the folder words count what was found");
  assert.equal(note(doc).hidden, false, "the line does not come and go with the box");
  assert.equal(noteButtons(doc).length, 1);
  noteButtons(doc)[0].click();
  assert.equal(doc.getElementById("rules-find").value, "", "the box is emptied");
  const row = treeRow(doc, /\.evn$/);
  assert.ok(row?.classList.contains("open"));
  assert.equal(doc.activeElement, row.querySelector(".file-more"));

  findBox(doc, "shop");
  await tick();
  assert.equal(folderWords(folderHead(doc, "~/shop")), "2 rules, 1 on a path where nothing is", "found, it is counted");
  findBox(doc, "zzz-none");
  await tick();
  assert.equal(note(doc).hidden, true, "hidden with the group when the box finds none of its rules");
});

// ── dashboard.md §4.25f *A rule finds its sessions* (queue #250) ────────────────
const sessionsLink = (doc: any) => opened(doc).querySelector("a.rule-sessions-link") as any;

test("an opened rule on a path links Its sessions on History, searched for the path as the row names it; a pattern has none", async () => {
  const { doc, window, calls } = load({ url: FILES_URL, routes: {
    "GET policy/panel": MISSING_PANEL, "GET secrets": NO_LABELS,
    "GET home/history?q=~%2Fshop%2F.evn": { total: 0, rows: [], next: null, query: { text: "~/shop/.evn", all: 3 } },
  } });
  await tick();
  // A path that is there (drawn as a folder here), an exact file and a rule on nothing.
  for (const [re, path] of [[/^\.env$/, "~/shop/.env"], [/old\.token/, "~/shop/old.token"], [/\.evn$/, "~/shop/.evn"]] as const) {
    treeRow(doc, re).querySelector(".file-more").click();
    const a = sessionsLink(doc);
    assert.ok(a, `a link under ${path}`);
    assert.equal(a.textContent, "Its sessions on History");
    assert.equal(a.getAttribute("href"), "/mandu/history?q=" + encodeURIComponent(path), "a plain link, the path searched");
    assert.equal(a.getAttribute("data-land"), "q:" + path, "History lands searched");
    assert.equal(a.getAttribute("aria-label"), "Its sessions on History: " + path, "named by its row");
    assert.equal(a.getAttribute("data-page-link"), "history");
    const line = [...a.parentElement.children].map((c: any) => c.textContent);
    assert.equal(line[line.length - 1], "Its sessions on History", "after Show in its folder");
    assert.ok(line.includes("Show in its folder"));
  }
  // A pattern: the search matches words, not globs.
  treeRows(doc).find((r) => r.getAttribute("data-path") === "/home/u/shop/*.key")!.querySelector(".file-more").click();
  assert.ok(opened(doc), "the pattern's row is opened");
  assert.equal(sessionsLink(doc), null, "no link under a pattern");

  // A click opens History with the box filled and the list searched.
  treeRow(doc, /\.evn$/).querySelector(".file-more").click();
  sessionsLink(doc).click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?q=" + encodeURIComponent("~/shop/.evn"));
  assert.equal(doc.getElementById("history-q").value, "~/shop/.evn");
  assert.ok(calls.some((c: any) => c.url === "/mandu/api/home/history?q=~%2Fshop%2F.evn"), calls.map((c: any) => c.url).join(" "));
});
