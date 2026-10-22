/**
 * home-js-explorer.test — Your rules' Files and folders list: your file rules
 * as a tree (§4.25f nesting), ONE label menu per row and its hosts (§4.25p),
 * keyboard moves, and Add a rule kept open in this browser.
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  load, tick, FILES_URL, WS_LIST, CONFIG_LIST, list, FILES_ROUTES, fileRows, PUB,
  rowFor, menuOf, optionOf, pressed, choose, waiting, openRow, opened, treeRows, treeRow,
} from "./home-js-fixtures.js";
import { resolveCssVars } from "./css-flatten.js";

test("explorer: Your rules lists your file rules as a tree, each with its label menu; ⋯ says more, and 'Show in its folder' opens Add a rule with it opened", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  assert.equal(doc.getElementById("lock-form").hidden, true, "Add a rule is closed until asked for");
  assert.equal(doc.getElementById("rules-add").getAttribute("aria-expanded"), "false");
  assert.equal(calls.filter((c) => c.url.includes("/api/files/list")).length, 0, "nothing is listed until Add a rule is opened");
  const rows = treeRows(doc);
  assert.equal(rows.length, 1, "the label made on this page (the rules file's own rows come from the panel)");
  assert.match(rows[0].textContent, /~\/ws\/\.env this file only/);
  assert.deepEqual(pressed(rows[0]), ["no-model"], "the label in force is the menu's choice");
  assert.equal(doc.querySelector(".files-cols, .level-dot"), null, "no columns of dots");
  assert.equal(rows[0].querySelector(".label-pick").getAttribute("data-level"), "no-model", "its dot is coloured for the label");
  rows[0].querySelector(".file-more").click();
  assert.equal(treeRows(doc)[0].classList.contains("open"), true);
  const detail = opened(doc);
  assert.equal(treeRows(doc)[0].nextElementSibling, detail, "it opens under its row");
  assert.match(detail.textContent, /\/home\/u\/ws\/\.envNo AIYour rule, this file only/);
  assert.match(detail.textContent, /Saved by Mandu, not in policy\.yaml/);
  const show = [...detail.querySelectorAll("button")].find((b: any) => b.textContent === "Show in its folder") as any;
  show.click();
  await tick();
  assert.equal(doc.getElementById("lock-form").hidden, false);
  assert.ok(calls.some((c) => c.url === "/mandu/api/files/list?path=%2Fhome%2Fu%2Fws"));
  assert.equal(rowFor(doc, /^\.env/).classList.contains("open"), true);
});

test("explorer: each row's menu shows the label in force; its hosts show beside it and change on their own with Update; a choice shows as waiting; the label in force again drops it", async () => {
  const saves: any[] = [];
  const withHosts = { ...WS_LIST, entries: WS_LIST.entries.map((e, i) => (i === 0 ? { ...e, label: { ...e.label, bindings: ["db.internal"] } } : e)) };
  const { doc } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: withHosts, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: "pc-000011", page: 0 }) } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const config = () => rowFor(doc, /^config\//);
  assert.deepEqual(pressed(config()), ["no-model"], "the label in force is chosen");
  assert.deepEqual(([...menuOf(config()).options] as any[]).map((o) => `${o.value}:${o.textContent}`),
    [":Remove my rule", "no-model:No AI", "local-model:Your own AI only (none listed)", "any-model:Any AI, when it asks", "public:Not secret"], "one menu, each label named for the reader");
  assert.equal(optionOf(config(), "public").title, "Not secret. Treated like any other file, even if it looks like a secret (a test .env, for example).");
  assert.deepEqual(([...config().querySelectorAll(".host-chip")] as any[]).map((c) => c.textContent), ["db.internal"], "the hosts in force, in the row");
  // Edit opens the row with the hosts in focus.
  config().querySelector(".file-hosts-edit").click();
  assert.match(opened(doc).textContent, /~\/ws\/configNo AIYour rule/);
  const to = doc.getElementById("lock-to") as any;
  assert.equal(doc.activeElement, to);
  assert.equal(to.value, "db.internal", "the hosts in force, ready to edit");
  to.value = "db.internal, backup.internal";
  doc.getElementById("files-to-update").click();
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/ws\/config.*No AI; may be sent to db\.internal, backup\.internal, and everything inside/);
  assert.equal(waiting(config()), true, "the choice waits until Save");
  assert.equal((doc.getElementById("lock-to") as any).value, "db.internal, backup.internal", "the waiting hosts are shown");
  assert.deepEqual(([...config().querySelectorAll(".host-chip")] as any[]).map((c) => c.textContent), ["db.internal", "backup.internal"]);
  // Not secret has no hosts to edit.
  choose(config(), "public");
  assert.equal((doc.getElementById("lock-to") as any).disabled, true);
  assert.equal(doc.getElementById("files-to-update"), null);
  assert.equal((doc.getElementById("lock-to") as any).value, "db.internal", "the hosts in force stay shown, greyed");
  assert.deepEqual(pressed(config()), ["public"]);
  assert.equal(waiting(config()), true);
  assert.match(doc.getElementById("files-pending-list").textContent, /No AI → Not secret/, "the label it replaces is named");
  assert.equal(config().querySelectorAll(".host-chip").length, 0);
  // The label in force again, with its hosts: nothing is left to save.
  choose(config(), "no-model");
  assert.equal(doc.getElementById("files-pending").hidden, true, "choosing what the rule says drops the change");
  assert.deepEqual(pressed(config()), ["no-model"]);
  // Another secret label starts from the hosts in force.
  choose(config(), "any-model");
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes, [{ path: "/home/u/ws/config", level: "any-model", bindings: ["db.internal"], recursive: true }]);
});

test("§4.25p two questions: each rule row has a second menu, where it may be sent; Needs your OK drops the hosts, Listed hosts opens the hosts field, Not secret is the first menu's too", async () => {
  const saves: any[] = [];
  const row = (path: string, level: string, bindings: string[], opens?: string) => ({
    id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers: "exact", bindings, level,
    actions: { remove: true, flip: null },
    plain: { subject: path, reach: "this file only", effect: "x", ...(opens ? { opens } : {}) },
  });
  const panel = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
    row("/home/u/proj/.env", "no-model", ["api.stripe.com"], "deploy (your word) may open the real file. Other programs get a masked copy."),
    row("/home/u/notes.md", "any-model", [], "Programs get a masked copy."),
    row("/home/u/pub.txt", "public", [], undefined),
  ] } };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": panel, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: "pc-000012", page: 0 }) } });
  await tick();
  const sendOf = (r: any) => r.querySelector("select.send-select") as any;
  const env = () => treeRow(doc, /proj\/\.env/);
  const notes = () => treeRow(doc, /notes\.md/);
  const pub = () => treeRow(doc, /pub\.txt/);
  // The heads name the two questions; each row answers both.
  assert.match(doc.querySelector(".files-heads").textContent, /Which AI may read it.*Where it may be sent/);
  assert.deepEqual(([...sendOf(env()).options] as any[]).map((o) => `${o.value}:${o.textContent}`),
    ["ask:Needs your OK", "hosts:Listed hosts without asking", "public:Not secret"]);
  assert.equal(sendOf(env()).value, "hosts");
  assert.deepEqual(([...env().querySelectorAll(".host-chip")] as any[]).map((c) => c.textContent), ["api.stripe.com"]);
  assert.equal(sendOf(notes()).value, "ask", "no hosts: the default, Needs your OK, is said");
  assert.equal(sendOf(pub()).value, "public");
  assert.equal(menuOf(pub()).value, "public", "Not secret answers both questions");
  assert.match(sendOf(env()).querySelector('option[value="hosts"]').title, /^Listed hosts without asking\. For a secret: the hosts listed on its rule get the real value/);
  // The third relation, read only: who may open the real file.
  assert.match(env().querySelector(".file-opens").textContent, /^Opens it deploy \(your word\) may open the real file\./);
  assert.equal(pub().querySelector(".file-opens"), null, "Not secret: nothing to open");
  // Needs your OK on a row with hosts: the same label, no hosts, waiting for Save.
  const pick = (r: any, v: string) => { const m = sendOf(r); m.value = v; m.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true })); };
  pick(env(), "ask");
  assert.equal(waiting(env()), true);
  assert.equal(sendOf(env()).value, "ask");
  assert.equal(env().querySelectorAll(".host-chip").length, 0);
  assert.match(env().querySelector(".file-pending").textContent, /^Will be: No AI \(not saved\)$/);
  // Back to the hosts in force: choosing them again drops the change.
  pick(env(), "hosts");
  assert.equal(doc.activeElement, doc.getElementById("lock-to"), "Listed hosts opens the row with the hosts field");
  const to = doc.getElementById("lock-to") as any;
  to.value = "api.stripe.com";
  doc.getElementById("files-to-update").click();
  assert.equal(doc.getElementById("files-pending").hidden, true, "the rule as it is: nothing to save");
  // Not secret in the second menu is the label Not secret.
  pick(notes(), "public");
  assert.equal(menuOf(notes()).value, "public");
  assert.equal(waiting(notes()), true);
  // Leaving Not secret from the second menu keeps any AI and asks before sending.
  pick(pub(), "ask");
  assert.equal(menuOf(pub()).value, "any-model");
  assert.equal(sendOf(pub()).value, "ask");
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes.map((c: any) => [c.path, c.level, c.bindings ?? []]).sort(), [
    ["/home/u/notes.md", "public", []],
    ["/home/u/pub.txt", "any-model", []],
  ]);
});

test("explorer: Enter in the hosts field queues them; the arrow keys in a menu stay the menu's; a folded tree folder stays folded", async () => {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET policy/panel": TREE_PANEL } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  openRow(doc, /^config\//);
  const to = doc.getElementById("lock-to") as any;
  to.value = "db.internal";
  to.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/ws\/config.*may be sent to db\.internal/);
  const key = (target: any, k: string) => target.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
  const menu = menuOf(rowFor(doc, /README/));
  menu.focus();
  for (const k of ["ArrowDown", "ArrowLeft"]) key(menu, k);
  assert.equal(doc.activeElement, menu, "Down in a menu does not move to the next row");
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws", "Left in a menu is not Up one folder");
  // Your rules: a folder folded shut stays shut when a row is opened.
  doc.getElementById("rules-add-close").click();
  assert.equal(doc.getElementById("lock-form").hidden, true);
  const ws = () => ([...doc.querySelectorAll("#files-tree .rules-folder")] as any[]).find((f) => f.title === "~/ws");
  ws().click();
  assert.equal(ws().getAttribute("aria-expanded"), "false");
  treeRow(doc, /app\.conf/).querySelector(".file-more").click();
  assert.equal(ws().getAttribute("aria-expanded"), "false");
  assert.equal(ws().nextElementSibling.hidden, true);
});

test("explorer: Add a rule left open is kept in this browser; a typed path is listed; Close shuts it", async () => {
  const a = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  a.doc.getElementById("rules-add").click();
  await tick();
  assert.equal(a.window.localStorage.getItem("mandu.files.view"), "all");
  const b = load({ url: FILES_URL, routes: FILES_ROUTES, storage: { "mandu.files.view": "all" } });
  await tick();
  assert.equal(b.doc.getElementById("lock-form").hidden, false);
  assert.equal(b.doc.getElementById("rules-add").getAttribute("aria-expanded"), "true");
  assert.equal(fileRows(b.doc).length, 4, "opens where the agent worked, without a click");
  b.doc.getElementById("rules-add").click();
  assert.equal(b.doc.getElementById("lock-form").hidden, true, "the button closes it again");
  assert.equal(b.window.localStorage.getItem("mandu.files.view"), "labeled");
  const c = load({ url: FILES_URL, routes: { ...FILES_ROUTES, [list("~/ws/config")]: CONFIG_LIST }, storage: { "mandu.files.view": "all" } });
  await tick();
  (c.doc.getElementById("lock-path") as any).value = "~/ws/config";
  c.doc.getElementById("files-go").dispatchEvent(new c.doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(c.doc.getElementById("lock-form").hidden, false);
  assert.equal(c.doc.getElementById("files-crumbs").textContent, "~/ws/config");
  assert.ok(c.calls.some((x) => x.url === "/mandu/api/files/list?path=~%2Fws%2Fconfig"), "the typed folder is listed");
});

test("§4.25p the browser names its menus: heads over Add a rule's list; a greyed second menu with no rule says to choose who may read it first, until a level is picked; an inherited one keeps its words", async () => {
  const FIRST = "Choose who may read it first. Then you can choose where it may be sent.";
  const { doc } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  const heads = doc.getElementById("files-list-heads") as any;
  assert.equal(heads.hidden, true, "no heads before there is a list to stand over");
  doc.getElementById("rules-add").click();
  await tick();
  assert.ok(doc.getElementById("lock-form").contains(heads), "the heads are Add a rule's own");
  assert.equal(heads.hidden, false);
  assert.equal(heads.getAttribute("aria-hidden"), "true", "each menu has its own name");
  assert.equal(heads.textContent, "File or folderWhich AI may read itWhere it may be sent");
  assert.equal(heads.nextElementSibling, doc.getElementById("files-list"), "right over the list");
  assert.equal(doc.getElementById("files-self").nextElementSibling, heads, "after the This folder: line");
  const send = () => rowFor(doc, /^README\.md/).querySelector("select.send-select") as any;
  assert.equal(send().disabled, true, "no rule: the first menu starts one");
  assert.equal(send().options[send().selectedIndex].textContent, "No rule");
  assert.equal(send().title, FIRST, "a pointer learns why it is greyed");
  assert.equal(send().getAttribute("aria-label"), `Where ~/ws/README.md may be sent. ${FIRST}`, "a screen reader hears it after the menu's name");
  choose(rowFor(doc, /^README\.md/), "no-model");
  assert.equal(waiting(rowFor(doc, /^README\.md/)), true, "a waiting change");
  assert.equal(send().disabled, false, "a level picked turns the menu on");
  assert.equal(send().title, "");
  assert.equal(send().getAttribute("aria-label"), "Where ~/ws/README.md may be sent", "the sentence is gone");
  // An inherited label keeps inheritedSend's words.
  (rowFor(doc, /^config/).querySelector(".file-open") as any).click();
  await tick();
  const db = rowFor(doc, /^db\.yaml/).querySelector("select.send-select") as any;
  assert.equal(db.disabled, true);
  assert.equal(db.title, "Where ~/ws/config/db.yaml may be sent: needs your OK. From your rule on ~/ws/config. Change it there.");
  assert.equal(db.getAttribute("aria-label"), db.title);
  assert.ok(!db.title.includes(FIRST));
  assert.equal(doc.getElementById("files-list-heads").hidden, false);
});

test("§4.25p the browser's heads stand over rows only: an empty folder has none", async () => {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, [list("/home/u/ws")]: { ...WS_LIST, entries: [], total: 0 } } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  assert.match(doc.getElementById("files-list").textContent, /This folder is empty\./);
  assert.equal(doc.getElementById("files-list-heads").hidden, true);
});

// ── dashboard.md §4.25f: Files and folders as a tree ─────────────────────────

// A file rule row as policy-panel.ts serves it, with its `level` (§4.25n).
const lockRow = (path: string, covers: "subtree" | "exact" | "pattern", effect = "No AI") => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [],
  level: effect === "Not secret" ? "public" : effect === "Any AI, when it asks" ? "any-model" : "no-model",
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: covers === "pattern" ? "every matching file" : covers === "subtree" ? "and everything inside" : "this file only", effect },
});
const TREE_PANEL = { panel: { available: true, verdictsKnown: true,
  yourRules: [
    lockRow("/home/u/proj", "subtree"),
    lockRow("/home/u/proj/test/.env", "exact", "Not secret"),
    lockRow("/home/u/proj/docs", "subtree", "Any AI, when it asks"),
    lockRow("/home/u/proj/docs/keys.txt", "exact"),
    lockRow("/home/u/ws/a", "subtree"),
    lockRow("/home/u/ws/b", "subtree"),
    lockRow("/etc/app.conf", "exact"),
    lockRow("**/ws-*/memo/**", "pattern"),
    lockRow("**/ws-*/memo/pub/**", "pattern", "Not secret"),
    lockRow("**/ws-*/partner/**", "pattern"),
  ],
  queue: [
    { id: "egr-3", status: "approved", scope: "always", where: "file", subject: "fs:Read:read", target: "/home/u/proj/secret.db", count: 1, actions: [{ approve: false, label: "Block instead" }], plain: { subject: "/home/u/proj/secret.db", reach: "opening this file", effect: "Always allowed" } },
  ] } };

test("§4.25f: the Labeled tree nests by path: inside a folder rule, under a shared folder; patterns listed first, never parents", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": TREE_PANEL } });
  await tick();
  const tree = doc.getElementById("files-tree");
  const items = ([...tree.querySelectorAll(".row.file-rule, .rules-folder")] as any[])
    .map((e) => `${/--depth:(\d+)/.exec(e.getAttribute("style") ?? "")?.[1] ?? 0} ${e.classList.contains("rules-folder") ? "folder " : ""}${e.querySelector("code").textContent}`);
  assert.deepEqual(items, [
    "0 **/ws-*/memo/**",
    "0 **/ws-*/memo/pub/**",
    "0 **/ws-*/partner/**",
    "0 /etc/app.conf",
    "0 ~/proj",
    "1 docs",
    "2 keys.txt",
    "1 test/.env",
    "0 folder ~/ws/",
    "1 .env",
    "1 a",
    "1 b",
  ], "a pattern inside a pattern is a sibling, not a child: the stricter one wins a tie, not the deeper one");
  assert.match(tree.textContent, /Patterns apply to every file that matches/);
  const folders = [...tree.querySelectorAll(".rules-folder")] as any[];
  assert.match(folders[0].textContent, /3 rules/);
  assert.equal(folders[0].title, "~/ws", "the full folder in the tooltip");
  const keys = ([...tree.querySelectorAll(".row.file-rule")] as any[]).find((r) => /keys\.txt/.test(r.textContent));
  assert.equal(keys.title, "/home/u/proj/docs/keys.txt", "the full path in the tooltip");
  assert.deepEqual(pressed(keys), ["no-model"], "a nested rule has its menu like any other");
  keys.querySelector(".file-more").click();
  assert.equal(treeRow(doc, /keys\.txt/).classList.contains("open"), true, "and opens like any other");
  assert.equal(treeRow(doc, /keys\.txt/).nextElementSibling.classList.contains("file-detail"), true);
  // An answer about one file stays in the list, under its own group.
  assert.match(doc.getElementById("rules-list").textContent, /Your answers about files.*secret\.db/);

  // A folder heading folds and unfolds its rules.
  const folder = doc.querySelector("#files-tree .rules-folder");
  const kids = folder.nextElementSibling;
  assert.equal(kids.className, "rules-children");
  folder.click();
  assert.equal(folder.getAttribute("aria-expanded"), "false");
  assert.equal(kids.hidden, true);
  folder.click();
  assert.equal(kids.hidden, false);
});

// The tree is as long as its rules (§4.25f, 2026-10-14). Until then it wore
// the file browser's class, a box of its own 60vh / 560px high: at 390×844
// one rule of six showed whole. jsdom lays nothing out, so the box is read
// off the page's own styles, applied: a height of its own, or an overflow
// that scrolls.
const STYLES = resolveCssVars(["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n"));
const scrolls = (v: string) => /\b(auto|scroll)\b/.test(v);

test("§4.25f: the tree is as long as its rules, as Sending data is: no box of its own; a folder's entries keep theirs", async () => {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET policy/panel": TREE_PANEL } });
  const sheet = doc.createElement("style");
  sheet.textContent = STYLES;
  doc.head.append(sheet);
  await tick();
  const css = (id: string) => doc.defaultView.getComputedStyle(doc.getElementById(id));
  const drawn = ([...doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).map((r) => r.getAttribute("data-path"));
  for (const r of TREE_PANEL.panel.yourRules) assert.ok(drawn.includes(r.subject), `${r.subject} is drawn`);
  for (const id of ["files-tree", "rules-list"]) {
    const s = css(id);
    assert.deepEqual([s.overflow, s.overflowX, s.overflowY].filter(scrolls), [], `#${id} does not scroll by itself`);
    assert.equal(s.maxHeight, "none", `#${id} has no height of its own`);
  }
  doc.getElementById("rules-add").click();
  await tick();
  assert.ok(fileRows(doc).length > 0, "Add a rule lists a folder");
  const browser = css("files-list");
  assert.equal(browser.overflowY, "auto", "a folder's entries scroll in their own box: a folder can hold thousands");
  assert.notEqual(browser.maxHeight, "none");
});

test("§4.25p per value (plan 13 §5.2): a rule with values: shows Per value, read only, with where each value may go; a level chosen keeps them", async () => {
  const saves: any[] = [];
  const send = "STRIPE_KEY may be sent only to api.stripe.com; AWS_* only to amazonaws.com; a program holding the whole file may send it nowhere without asking.";
  const panel = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
    {
      id: "lock:/home/u/ws/app/.env", kind: "lock", subject: "/home/u/ws/app/.env", effect: "x", reach: null, hits: null, covers: "exact", bindings: [], level: "no-model",
      values: [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: ["amazonaws.com"] }],
      actions: { remove: true, flip: null },
      plain: { subject: "/home/u/ws/app/.env", reach: "this file only", effect: "No AI", opens: "Programs get a masked copy.", send },
    },
  ] } };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": panel, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: "pc-000013", page: 0 }) } });
  await tick();
  const env = () => treeRow(doc, /app\/\.env/);
  const sel = env().querySelector("select.send-select") as any;
  assert.deepEqual(([...sel.options] as any[]).map((o) => `${o.value}:${o.textContent}`), ["values:Per value"], "one state, Per value");
  assert.equal(sel.disabled, true, "read only: the per-value hosts change in policy.yaml");
  assert.equal(env().querySelector(".send-pick").getAttribute("data-send"), "values");
  assert.equal(env().querySelector(".file-values").textContent, send, "the sentence, in plan 13 §5.3's form");
  assert.equal(env().querySelectorAll(".host-chip").length, 0, "no file-wide chips that would read as every value's");
  // The first menu still changes the level, and the send menu stays per value.
  choose(env(), "any-model");
  assert.equal(waiting(env()), true);
  assert.equal((env().querySelector("select.send-select") as any).value, "values", "a level chosen keeps the values (the save keeps values:)");
  // Not secret has nothing to send per value: the menu says Not secret.
  choose(env(), "public");
  assert.equal((env().querySelector("select.send-select") as any).value, "public");
  choose(env(), "any-model");
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes.map((c: any) => [c.path, c.level, c.bindings ?? []]), [["/home/u/ws/app/.env", "any-model", []]], "only the level and the file's own hosts are sent");
});

test("explorer: a label chosen on a rule of the rules file names that rule's version as the list read it (dashboard.md §4.25m)", async () => {
  const V = "7".repeat(32);
  const saves: any[] = [];
  const panel = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
    { id: "lock:/home/u/ws/app.conf", kind: "lock", subject: "/home/u/ws/app.conf", effect: "x", reach: null, hits: null, covers: "exact", level: "no-model", bindings: [], version: V,
      actions: { remove: true, flip: null }, plain: { subject: "/home/u/ws/app.conf", reach: "this file only", effect: "No AI" } },
  ] } };
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET policy/panel": panel, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: "pc-000012", page: 0 }) } });
  await tick();
  choose(treeRow(doc, /app\.conf/), "local-model");
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes, [{ path: "/home/u/ws/app.conf", level: "local-model", recursive: false, version: V }]);
});
