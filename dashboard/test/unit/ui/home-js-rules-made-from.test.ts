/**
 * home-js-rules-made-from.test — the Rules page's "Files made from your
 * secrets" card (dashboard.md §4.25aa *Files made from your secrets*): the
 * files Mandu labelled on its own because what wrote them held a secret
 * (`panel.derived` of /api/secrets, view-model/secrets.ts), painted by
 * public/js/home.js renderMadeFromSecrets, in jsdom over the fetch stub of
 * home-js-fixtures.ts.
 *
 * Pins: hidden with no rows or no `derived` (an older arbiter), and its
 * section link with it; closed until Show; what wrote each file in words
 * (an AI session's write, a program that held a secret, a copy), a real
 * session linked to its page and no raw key ever shown; an overridden row
 * says your rule decides now, with the level a later session reads; Change
 * who may read it opens the file in Rules; 20 entries, then Show more;
 * three or more files in one folder fold into one folder row (#191), which
 * states a level or a writer only when all its files share it, opens to its
 * files 20 at a time and stays open, the focus kept, across a Rules read;
 * read only; the product words, no inspector vocabulary. In Add a rule, a file
 * made from a secret says what wrote it in the card's words (writerWords),
 * in its line, its opened row and its send menu's tooltip, with a way back
 * to its row in the card; with no row, a sentence true of every writer.
 * Axes: none (display only).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, home, FILES_ROUTES, WS_LIST, chip, list, rowFor, type Call } from "./home-js-fixtures.js";
import { toSecretsPanel, type DerivedLabelWire } from "../../../src/view-model/secrets.js";

const BASE = "http://127.0.0.1:4500/mandu";
const SESSION = "1791300000-467";
const AT = Date.UTC(2026, 9, 21, 9, 15);

const WRITE: DerivedLabelWire = { path: "/home/u/shop/notes.md", level: "no-model", bindings: [], sessionKey: SESSION, tool: "Write", updatedAt: AT, effective: "no-model", overridden: false };
const BUILD: DerivedLabelWire = { path: "/home/u/app/dist/config.js", level: "no-model", bindings: [], sessionKey: "proc:4242:1791300001", tool: "process", updatedAt: AT - 60_000, effective: "no-model", overridden: false };
const COPY: DerivedLabelWire = { path: "/home/u/app/.env.bak", level: "no-model", bindings: [], sessionKey: "guard", tool: "identity", updatedAt: AT - 120_000, effective: "no-model", overridden: false };
const MOVED: DerivedLabelWire = { path: "/home/u/app/.env.old", level: "local-model", bindings: [], sessionKey: "guard", tool: "rename", updatedAt: AT - 180_000, effective: "local-model", overridden: false };
const RELEASED: DerivedLabelWire = { path: "/home/u/app/report.md", level: "no-model", bindings: [], sessionKey: SESSION, tool: null, updatedAt: AT - 240_000, effective: "any-model", overridden: true };

/** The answer of /api/secrets as the server builds it, with `derived`. */
const secrets = (derived: DerivedLabelWire[] | undefined) =>
  ({ enabled: true, panel: toSecretsPanel({ enabled: true, secrets: [], ...(derived ? { derived } : {}) }) });

const page = (answer: unknown) => load({ url: `${BASE}/rules`, routes: { ...FILES_ROUTES, "GET secrets": answer } });

const card = (doc: any) => doc.getElementById("made-from-block");
const rows = (doc: any) => [...doc.querySelectorAll("#made-from-list .made-from-row")] as any[];
const rowOf = (doc: any, path: string) => rows(doc).find((r) => r.getAttribute("data-path") === path);
const sectionLink = (doc: any) => doc.querySelector('#page-rules nav.section-links a[data-section="made-from"]');
const open = async (doc: any) => { doc.getElementById("made-from-open").click(); await tick(); };

test("§4.25aa Files made from your secrets: no rows, or an older arbiter with no such list, is no card and no link to it", async () => {
  for (const [what, answer] of [
    ["no rows", secrets([])],
    ["no derived field", secrets(undefined)],
    ["a panel without derived (older arbiter)", { enabled: true, panel: { labels: [], secrets: [] } }],
    ["a failed read", { status: 500, body: { error: "x" } }],
  ] as const) {
    const { doc, err } = page(answer);
    await tick();
    assert.equal(err, null, what);
    assert.equal(card(doc).hidden, true, what);
    assert.equal(sectionLink(doc)?.closest("li").hidden, true, `${what}: the section link hides with the card`);
  }
});

test("§4.25aa: closed until Show; the count is in the title; Show opens the list, Hide closes it", async () => {
  const { doc } = page(secrets([WRITE, BUILD, COPY]));
  await tick();
  assert.equal(card(doc).hidden, false);
  assert.equal(sectionLink(doc).closest("li").hidden, false, "its section link shows with it");
  assert.equal(doc.getElementById("made-from-title").textContent, "Files made from your secrets (3)");
  const btn = doc.getElementById("made-from-open");
  assert.equal(btn.textContent, "Show");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(doc.getElementById("made-from-view").hidden, true, "closed by default");
  assert.equal(rows(doc).length, 0);
  await open(doc);
  assert.equal(btn.textContent, "Hide");
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(doc.getElementById("made-from-view").hidden, false);
  assert.equal(rows(doc).length, 3);
  assert.match(doc.getElementById("made-from-view").textContent.trim(), /^Mandu keeps these files as secret as what they were made from/);
  await open(doc);
  assert.equal(doc.getElementById("made-from-view").hidden, true);
  assert.equal(btn.getAttribute("aria-expanded"), "false");
});

test("§4.25aa: what wrote each file, in words: an AI session's write links its session; a program and a copy link nothing; no raw key is shown", async () => {
  const { doc } = page(secrets([BUILD, COPY, WRITE, MOVED]));
  await tick();
  await open(doc);
  assert.deepEqual(rows(doc).map((r) => r.getAttribute("data-path")), [WRITE.path, BUILD.path, COPY.path, MOVED.path], "newest first");
  const write = rowOf(doc, WRITE.path);
  assert.equal(write.querySelector("code").textContent, "~/shop/notes.md");
  assert.equal(write.querySelector(".made-from-level").textContent, "No AI");
  assert.equal(write.querySelector(".made-from-how").textContent, "written by the AI's Write in this session");
  const link = write.querySelector("a.made-from-session");
  assert.equal(link.getAttribute("href"), `/mandu/agents/${SESSION}`);
  assert.equal(link.dataset.pageLink, "agent");
  assert.ok(write.querySelector("time.when"), "when it was written");
  const build = rowOf(doc, BUILD.path);
  assert.equal(build.querySelector(".made-from-how").textContent, "written by a program that held a secret");
  assert.equal(build.querySelector("a.made-from-session"), null);
  const copy = rowOf(doc, COPY.path);
  assert.equal(copy.querySelector(".made-from-how").textContent, "copied from a secret file");
  assert.equal(copy.querySelector("a.made-from-session"), null);
  assert.equal(rowOf(doc, MOVED.path).querySelector(".made-from-how").textContent, "moved from a secret file");
  assert.equal(rowOf(doc, MOVED.path).querySelector(".made-from-level").textContent, "Your own AI only");
  const text = card(doc).textContent;
  for (const raw of ["proc:", "4242", "guard", "identity", "rename", "process"]) assert.ok(!text.includes(raw), `no raw ${raw}`);
  // Only links are its controls: the sessions, the files and Show more; nothing writes.
  assert.equal(card(doc).querySelectorAll("select, input").length, 0);
});

test("§4.25aa: Change who may read it opens the file in Rules (?file=), in Add a rule", async () => {
  const copy = { ...COPY, path: "/home/u/ws/README.md" }; // a file the fixture's folder lists
  const { doc, window } = page(secrets([copy]));
  await tick();
  await open(doc);
  const change = rowOf(doc, copy.path).querySelector("a.made-from-change");
  assert.equal(change.textContent, "Change who may read it");
  assert.equal(change.getAttribute("href"), "/mandu/rules?file=/home/u/ws/README.md");
  assert.equal(change.getAttribute("aria-label"), "Change who may read ~/ws/README.md");
  assert.equal(change.dataset.pageLink, "rules");
  assert.equal(change.dataset.file, copy.path, "a click lands at the file as ?file= does");
  change.click();
  await tick(); await tick();
  assert.equal(window.location.pathname, "/mandu/rules");
  assert.equal(doc.getElementById("page-rules").hidden, false);
  const opened = doc.querySelector('#files-list .row.file.open[data-path="/home/u/ws/README.md"]');
  assert.ok(opened, "the file is open in Add a rule");
});

test("§4.25aa: an overridden row says your rule decides now, with the level a later session reads", async () => {
  const { doc } = page(secrets([RELEASED]));
  await tick();
  await open(doc);
  const r = rowOf(doc, RELEASED.path);
  assert.equal(r.querySelector(".made-from-level").textContent, "Your rule decides now: Any AI, when it asks");
  assert.ok(r.querySelector(".made-from-level").classList.contains("overridden"));
  assert.equal(r.querySelector(".made-from-how").textContent, "written by the AI in this session", "no tool recorded: the AI, still its session");
});

test("§4.25aa: 25 rows show 20, then Show more brings the rest, the first new row's link focused", async () => {
  // One file in each of 25 folders: none folds (#191), so 25 entries.
  const many = Array.from({ length: 25 }, (_, i) => ({ ...COPY, path: `/home/u/app/p${String(i).padStart(2, "0")}/chunk.js`, updatedAt: AT - i * 1000 }));
  const { doc } = page(secrets(many));
  await tick();
  assert.equal(doc.getElementById("made-from-title").textContent, "Files made from your secrets (25)");
  await open(doc);
  assert.equal(rows(doc).length, 20);
  const line = doc.querySelector("#made-from-more .made-from-more-line");
  assert.ok(line, "a Show more line");
  assert.match(line.textContent, /^5 more files\. Show more$/);
  line.querySelector("button").click();
  await tick();
  assert.equal(rows(doc).length, 25);
  assert.equal(doc.querySelector("#made-from-more .made-from-more-line"), null, "nothing left");
  assert.equal(doc.activeElement, rows(doc)[20].querySelector("a.made-from-change"));
});

test("§4.25aa: a long path breaks at its slashes", async () => {
  const deep = { ...COPY, path: "/home/u/projects/a-long-project-name/deploy/staging/secrets/service-account.json" };
  const { doc } = page(secrets([deep]));
  await tick();
  await open(doc);
  const code = rowOf(doc, deep.path).querySelector("code");
  assert.ok(code.querySelectorAll(".name-part").length > 1, "longName split it");
  assert.equal(code.textContent, "~/projects/a-long-project-name/deploy/staging/secrets/service-account.json");
});

// ── Many files in one folder fold into one row (§4.25aa *Many rows*, #191) ─

const folders = (doc: any) => [...doc.querySelectorAll("#made-from-list .made-from-folder")] as any[];
const folderOf = (doc: any, at: string) => folders(doc).find((f) => f.getAttribute("data-folder") === at);
const folderFiles = (f: any) => [...f.querySelectorAll(".made-from-folder-list .made-from-row")].map((r) => r.getAttribute("data-path"));
const showBtn = (f: any) => f.querySelector("button.made-from-folder-open");
/** `k` files a program wrote in `dir`, newest first, from `at` back. */
const built = (dir: string, k: number, at = AT, over: Partial<DerivedLabelWire> = {}) =>
  Array.from({ length: k }, (_, i) => ({ ...BUILD, path: `${dir}/a${String(i).padStart(3, "0")}.js`, updatedAt: at - i * 1000, ...over }));

test("§4.25aa many rows: three files in one folder are one row, '3 files', with the level and writer all share; two stay rows", async () => {
  const three = built("/home/u/projects/a-long-project-name/dist/assets", 3);
  const two = built("/home/u/shop/lib", 2, AT - 10_000);
  const { doc } = page(secrets([...three, ...two, WRITE]));
  await tick();
  assert.equal(doc.getElementById("made-from-title").textContent, "Files made from your secrets (6)", "the heading counts files");
  await open(doc);
  assert.equal(folders(doc).length, 1);
  const f = folderOf(doc, "/home/u/projects/a-long-project-name/dist/assets/");
  assert.ok(f, "the direct parent, as data");
  assert.equal(f.querySelector(".made-from-folder-head code").textContent, "~/projects/a-long-project-name/dist/assets/");
  assert.ok(f.querySelector("code").querySelectorAll(".name-part").length > 1, "broken at its slashes (longName)");
  assert.equal(f.querySelector(".made-from-files").textContent, "3 files");
  assert.equal(f.querySelector(".made-from-level").textContent, "No AI");
  assert.equal(f.querySelector(".made-from-how").textContent, "written by a program that held a secret");
  assert.equal(f.querySelector("time.when").getAttribute("datetime"), new Date(AT).toISOString(), "the newest file's time");
  assert.equal(f.querySelector("a.made-from-change"), null, "no folder action");
  assert.equal(f.querySelector("a.made-from-session"), null);
  assert.equal(f.classList.contains("made-from-row"), false, "a folder is not a file row");
  assert.deepEqual(folderFiles(f), [], "closed");
  // Newest first, entries together: the folder (AT), WRITE (AT), then lib's two plain rows.
  const top = [...doc.getElementById("made-from-list").children].map((li: any) => li.getAttribute("data-folder") ?? li.getAttribute("data-path"));
  assert.deepEqual(top, ["/home/u/projects/a-long-project-name/dist/assets/", WRITE.path, two[0]!.path, two[1]!.path]);
});

test("§4.25aa many rows: a folder states a level or a writer only when every file shares it", async () => {
  const mixedLevel = built("/home/u/a", 3).map((d, i) => (i === 2 ? { ...d, level: "local-model", effective: "local-model" } : d));
  const mixedWriter = built("/home/u/b", 3, AT - 10_000).map((d, i) => (i === 1 ? { ...d, tool: "identity", sessionKey: "guard" } : d));
  const overriddenOne = built("/home/u/c", 3, AT - 20_000).map((d, i) => (i === 0 ? { ...d, overridden: true, effective: "no-model" } : d));
  const allOverridden = built("/home/u/d", 3, AT - 30_000, { overridden: true, effective: "any-model" });
  const { doc } = page(secrets([...mixedLevel, ...mixedWriter, ...overriddenOne, ...allOverridden]));
  await tick();
  await open(doc);
  const a = folderOf(doc, "/home/u/a/");
  assert.equal(a.querySelector(".made-from-level"), null, "two levels: none");
  assert.equal(a.querySelector(".made-from-how").textContent, "written by a program that held a secret");
  const b = folderOf(doc, "/home/u/b/");
  assert.equal(b.querySelector(".made-from-level").textContent, "No AI");
  assert.equal(b.querySelector(".made-from-how"), null, "two writers: none");
  assert.equal(b.querySelector(".made-from-folder-head").textContent.includes("copied"), false);
  const c = folderOf(doc, "/home/u/c/");
  assert.equal(c.querySelector(".made-from-level"), null, "one row your rule overrides says other words: none");
  const d = folderOf(doc, "/home/u/d/");
  assert.equal(d.querySelector(".made-from-level").textContent, "Your rule decides now: Any AI, when it asks");
  assert.ok(d.querySelector(".made-from-level").classList.contains("overridden"));
  // Whatever a folder says, each of its files says too.
  for (const at of folders(doc).map((f) => f.getAttribute("data-folder") as string)) {
    const head = folderOf(doc, at).querySelector(".made-from-folder-head");
    const said = { level: head.querySelector(".made-from-level")?.textContent, how: head.querySelector(".made-from-how")?.textContent };
    showBtn(folderOf(doc, at)).click();
    await tick();
    const files = [...folderOf(doc, at).querySelectorAll(".made-from-folder-list .made-from-row")] as any[];
    assert.equal(files.length, 3);
    for (const r of files) {
      if (said.level) assert.equal(r.querySelector(".made-from-level").textContent, said.level, at);
      if (said.how) assert.equal(r.querySelector(".made-from-how").textContent, said.how, at);
    }
  }
});

test("§4.25aa many rows: Show opens the folder (aria-expanded, aria-controls), its files newest first, 20 then Show more; Hide closes it", async () => {
  const many = built("/home/u/shop/dist", 45);
  const { doc } = page(secrets([...many].reverse()));
  await tick();
  await open(doc);
  const f = folderOf(doc, "/home/u/shop/dist/");
  assert.equal(f.querySelector(".made-from-files").textContent, "45 files");
  const btn = showBtn(f);
  assert.equal(btn.textContent, "Show");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  const listId = btn.getAttribute("aria-controls");
  assert.equal(doc.getElementById(listId)?.closest(".made-from-folder"), f, "it controls the folder's own list");
  assert.equal(doc.getElementById(listId).hidden, true);
  btn.click();
  await tick();
  const opened = folderOf(doc, "/home/u/shop/dist/");
  const b2 = showBtn(opened);
  assert.equal(b2.textContent, "Hide");
  assert.equal(b2.getAttribute("aria-expanded"), "true");
  assert.equal(doc.activeElement, b2, "the focus stays on the pressed button");
  assert.equal(doc.getElementById(b2.getAttribute("aria-controls")).hidden, false);
  assert.deepEqual(folderFiles(opened), many.slice(0, 20).map((d) => d.path), "newest first, 20");
  assert.equal(opened.querySelector(".made-from-folder-list .made-from-row .made-from-how").textContent, "written by a program that held a secret", "each as today's row");
  const more = () => folderOf(doc, "/home/u/shop/dist/").querySelector("button.show-rest");
  assert.match(more().closest(".row").textContent, /^25 more files in ~\/shop\/dist\/\. Show more$/);
  more().click();
  await tick();
  assert.equal(folderFiles(folderOf(doc, "/home/u/shop/dist/")).length, 40);
  assert.equal(doc.activeElement, folderOf(doc, "/home/u/shop/dist/").querySelectorAll(".made-from-folder-list a.made-from-change")[20], "the first new row's link");
  more().click();
  await tick();
  assert.equal(folderFiles(folderOf(doc, "/home/u/shop/dist/")).length, 45);
  assert.equal(more(), null, "nothing left");
  assert.equal(doc.querySelector("#made-from-more .made-from-more-line"), null, "one entry: no Show more for the card");
  showBtn(folderOf(doc, "/home/u/shop/dist/")).click();
  await tick();
  const shut = folderOf(doc, "/home/u/shop/dist/");
  assert.equal(showBtn(shut).getAttribute("aria-expanded"), "false");
  assert.deepEqual(folderFiles(shut), []);
  assert.equal(doc.activeElement, showBtn(shut));
});

test("§4.25aa many rows: the direct parent only: dist/ and dist/assets/ are two folder rows", async () => {
  const { doc } = page(secrets([...built("/home/u/shop/dist", 3), ...built("/home/u/shop/dist/assets", 4, AT - 5000)]));
  await tick();
  await open(doc);
  assert.deepEqual(folders(doc).map((f) => [f.getAttribute("data-folder"), f.querySelector(".made-from-files").textContent]),
    [["/home/u/shop/dist/", "3 files"], ["/home/u/shop/dist/assets/", "4 files"]]);
});

test("§4.25aa many rows: the card's paging counts a folder row as one entry; the heading still counts files", async () => {
  const big = built("/home/u/shop/dist", 300);
  const singles = Array.from({ length: 25 }, (_, i) => ({ ...COPY, path: `/home/u/f${String(i).padStart(2, "0")}/x.env`, updatedAt: AT - 1_000_000 - i * 1000 }));
  const { doc } = page(secrets([...singles, ...big]));
  await tick();
  assert.equal(doc.getElementById("made-from-title").textContent, "Files made from your secrets (325)");
  await open(doc);
  const top = () => [...doc.getElementById("made-from-list").children] as any[];
  assert.equal(top().length, 20, "the folder and 19 files");
  assert.equal(top()[0].getAttribute("data-folder"), "/home/u/shop/dist/");
  assert.equal(rows(doc).length, 19, "the folder's files stay folded");
  const line = doc.querySelector("#made-from-more .made-from-more-line");
  assert.match(line.textContent, /^6 more files\. Show more$/);
  line.querySelector("button").click();
  await tick();
  assert.equal(top().length, 26);
  assert.equal(doc.activeElement, top()[20].querySelector("a.made-from-change"));
});

test("§4.25aa many rows: a Rules read with the same answer keeps a folder open, its pages and the focus", async () => {
  const many = built("/home/u/shop/dist", 30);
  const answer = secrets(many);
  const { doc, calls, setHome } = load({
    url: `${BASE}/rules`, homeVm: home({ rulesVersion: "v1" }),
    routes: { ...FILES_ROUTES, "GET secrets": answer, "GET policy/changes?limit=1": { changes: [{ id: "pc-000001", createdAt: Date.now() + 3_600_000 }] } },
  });
  const poll = async () => {
    Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
    doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
    await tick(30);
  };
  await tick();
  await poll();
  await open(doc);
  showBtn(folderOf(doc, "/home/u/shop/dist/")).click();
  await tick();
  folderOf(doc, "/home/u/shop/dist/").querySelector("button.show-rest").click();
  await tick();
  assert.equal(folderFiles(folderOf(doc, "/home/u/shop/dist/")).length, 30);
  const third = folderOf(doc, "/home/u/shop/dist/").querySelectorAll("a.made-from-change")[2];
  third.focus();
  const reads = (c: Call[]) => c.filter((x) => x.url.endsWith("/api/secrets")).length;
  const n = reads(calls);
  setHome(home({ rulesVersion: "v2" }));
  await poll();
  assert.equal(reads(calls), n + 1, "Rules was read again");
  const f = folderOf(doc, "/home/u/shop/dist/");
  assert.equal(third.isConnected, false, "drawn again");
  assert.equal(showBtn(f).getAttribute("aria-expanded"), "true", "still open");
  assert.equal(folderFiles(f).length, 30, "its pages kept");
  assert.equal(doc.activeElement, f.querySelectorAll("a.made-from-change")[2], "the focus on the same file's link");
  // The folder's own button keeps the focus too.
  showBtn(f).focus();
  setHome(home({ rulesVersion: "v3" }));
  await poll();
  assert.equal(reads(calls), n + 2);
  assert.equal(doc.activeElement, showBtn(folderOf(doc, "/home/u/shop/dist/")));
  assert.equal(showBtn(folderOf(doc, "/home/u/shop/dist/")).getAttribute("aria-expanded"), "true");
});

test("§4.25aa: the card's words are the product's: no inspector term, no session key", async () => {
  const { doc } = page(secrets([WRITE, BUILD, COPY, MOVED, RELEASED]));
  await tick();
  await open(doc);
  const words = card(doc).textContent;
  assert.doesNotMatch(words, /taint|derived|watermark|symboliz|egress|arbiter|\$MDU/i, words);
  assert.ok(!words.includes(SESSION), "the session key is only in a link's address, never in the words");
});

// ── Add a rule says what wrote a file made from a secret (§4.25aa, #189) ────

const APP = "/home/u/app";
const MADE = "Made from a secret: something that held a secret wrote it";
const derivedEntry = (name: string, level = "no-model") => ({
  name, path: `${APP}/${name}`, display: `~/app/${name}`, kind: "file", link: null, inside: 0,
  label: chip(level, level === "any-model" ? "Any AI, when it asks" : "No AI", "written", MADE),
});
const APP_LIST = {
  ...WS_LIST, path: APP, display: "~/app", parent: "/home/u",
  crumbs: [{ name: "~", path: "/home/u" }, { name: "app", path: APP }],
  entries: [derivedEntry("config.js"), derivedEntry("notes.txt"), derivedEntry("old.txt", "local-model"), derivedEntry("summary.md", "any-model"), derivedEntry("later.md")],
  total: 5,
};
const rec = (name: string, tool: string | null, sessionKey: string, at: number): DerivedLabelWire =>
  ({ path: `${APP}/${name}`, level: "no-model", bindings: [], sessionKey, tool, updatedAt: at, effective: "no-model", overridden: false });
const RECORDS = [
  rec("config.js", "process", "proc:4242:1791300001", AT),
  rec("notes.txt", "identity", "guard", AT - 1000),
  rec("old.txt", "rename", "guard", AT - 2000),
  rec("summary.md", "Write", SESSION, AT - 3000),
  // later.md has no record: not in the list yet.
];
const WORDS: Record<string, string> = {
  "config.js": "Written by a program that held a secret",
  "notes.txt": "Copied from a secret file",
  "old.txt": "Moved from a secret file",
  "summary.md": "Written by the AI's Write",
  "later.md": MADE,
};
const appPage = (answer: unknown, file = `${APP}/config.js`) =>
  load({ url: `${BASE}/rules?file=${file}`, routes: { ...FILES_ROUTES, [list(APP)]: APP_LIST, "GET secrets": answer } });
const fromLine = (row: any) => row.querySelector(".file-from");
const fromWords = (row: any) => fromLine(row).firstChild.textContent;

test("§4.25aa Add a rule: a file made from a secret says what wrote it in the card's words, in its line, its opened row and its send tooltip", async () => {
  for (const name of Object.keys(WORDS)) {
    const { doc, err } = appPage(secrets(RECORDS), `${APP}/${name}`);
    await tick(); await tick();
    assert.equal(err, null);
    const row = doc.querySelector(`#files-list .row.file[data-path="${APP}/${name}"]`);
    assert.ok(row, `${name} listed`);
    assert.equal(fromWords(row), WORDS[name], `${name}: its line`);
    const see = fromLine(row).querySelector("button.made-from-see");
    if (name === "later.md") assert.equal(see, null, "no record: no way to a row that is not there");
    else assert.equal(see?.textContent, "See it in Files made from your secrets", `${name}: the way to its row`);
    assert.ok(row.classList.contains("open"), `${name} opened by ?file=`);
    const detail = doc.querySelector("#files-list .file-detail .detail-label");
    assert.equal(detail.querySelector("span.dim").textContent, WORDS[name], `${name}: the opened row`);
    assert.equal(!!detail.querySelector("button.made-from-see"), name !== "later.md");
    const send = row.querySelector("select.send-select");
    assert.ok(send.title.includes(" " + WORDS[name] + "."), `${name}: the tooltip names the same writer: ${send.title}`);
    assert.equal(send.getAttribute("aria-label"), send.title);
    assert.ok(!doc.getElementById("page-rules").textContent.includes("Written by the AI after it read a secret"));
  }
});

test("§4.25aa Add a rule: with no list (a failed read, an older server, none yet), every such file says the sentence true of every writer", async () => {
  for (const [what, answer] of [
    ["a failed read", { status: 500, body: { error: "x" } }],
    ["no derived field", secrets(undefined)],
    ["an empty list", secrets([])],
  ] as const) {
    const { doc } = appPage(answer);
    await tick(); await tick();
    for (const name of Object.keys(WORDS)) {
      const row = rowFor(doc, new RegExp("^" + name.replace(".", "\\.")));
      assert.equal(fromWords(row), MADE, `${what}: ${name}`);
      assert.equal(row.querySelector("button.made-from-see"), null, `${what}: no way to the card`);
    }
  }
});

test("§4.25aa Add a rule: See it in Files made from your secrets opens the card at the file's row and focuses its Change who may read it", async () => {
  const { doc } = appPage(secrets(RECORDS));
  await tick(); await tick();
  assert.equal(doc.getElementById("made-from-view").hidden, true, "the card starts closed");
  const before = doc.activeElement;
  const row = doc.querySelector(`#files-list .row.file[data-path="${APP}/notes.txt"]`);
  assert.equal(doc.activeElement, before, "drawing the line moves no focus");
  row.querySelector("button.made-from-see").click();
  await tick();
  assert.equal(doc.getElementById("made-from-view").hidden, false, "the card is open");
  assert.equal(doc.getElementById("made-from-open").getAttribute("aria-expanded"), "true");
  // The four records share ~/app/: the jump opens that folder row (#191).
  const folder = doc.querySelector("#made-from-list .made-from-folder");
  assert.equal(folder.getAttribute("data-folder"), `${APP}/`);
  assert.equal(folder.querySelector("button.made-from-folder-open").getAttribute("aria-expanded"), "true");
  assert.equal(doc.activeElement, rowOf(doc, `${APP}/notes.txt`).querySelector("a.made-from-change"));
  assert.equal(rowOf(doc, `${APP}/notes.txt`).querySelector(".made-from-how").textContent, "copied from a secret file", "the card's own words are unchanged");
});

test("§4.25aa Add a rule: a file past the card's first 20 rows shows enough pages to reach its row", async () => {
  const many = Array.from({ length: 45 }, (_, i) => rec(`chunk-${String(i).padStart(2, "0")}.js`, "process", "proc:1:2", AT - i * 1000));
  const target = rec("later.md", "Write", SESSION, AT - 100_000); // the oldest: row 46, on the third page
  const { doc } = appPage(secrets([...many, target]), `${APP}/later.md`);
  await tick(); await tick();
  const row = doc.querySelector(`#files-list .row.file[data-path="${APP}/later.md"]`);
  assert.equal(fromWords(row), "Written by the AI's Write");
  row.querySelector("button.made-from-see").click();
  await tick();
  assert.equal(rows(doc).length, 46, "three pages drawn");
  assert.equal(doc.activeElement, rowOf(doc, `${APP}/later.md`).querySelector("a.made-from-change"));
  // All 46 share ~/app/: one folder row, opened at as many of its pages (#191).
  const folder = doc.querySelector("#made-from-list .made-from-folder");
  assert.equal(folder.getAttribute("data-folder"), `${APP}/`);
  assert.equal(folder.querySelector("button.made-from-folder-open").getAttribute("aria-expanded"), "true");
  assert.equal(rowOf(doc, `${APP}/later.md`).closest(".made-from-folder"), folder);
});

test("§4.25aa Add a rule: a file past the card's first 20 entries shows enough of the card's pages to reach it", async () => {
  // One file in each of 45 folders, then the target in ~/app/: 46 entries, none folded.
  const many = Array.from({ length: 45 }, (_, i) => ({ ...rec("x.js", "process", "proc:1:2", AT - i * 1000), path: `/home/u/p${String(i).padStart(2, "0")}/x.js` }));
  const target = rec("later.md", "Write", SESSION, AT - 100_000);
  const { doc } = appPage(secrets([...many, target]), `${APP}/later.md`);
  await tick(); await tick();
  doc.querySelector(`#files-list .row.file[data-path="${APP}/later.md"]`).querySelector("button.made-from-see").click();
  await tick();
  assert.equal(doc.querySelectorAll("#made-from-list .made-from-folder").length, 0);
  assert.equal(rows(doc).length, 46, "three pages drawn");
  assert.equal(doc.activeElement, rowOf(doc, `${APP}/later.md`).querySelector("a.made-from-change"));
});

test("§4.25aa Add a rule: a list drawn before /api/secrets answers says what wrote each file once it does", async () => {
  let answer: (v: unknown) => void = () => {};
  const late = new Promise((r) => { answer = r; });
  const { doc } = load({ url: `${BASE}/rules`, routes: { ...FILES_ROUTES, [list(APP)]: APP_LIST, "GET secrets": () => late } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  doc.getElementById("lock-path").value = APP;
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick(30);
  const row = () => doc.querySelector(`#files-list .row.file[data-path="${APP}/config.js"]`);
  assert.equal(fromWords(row()), MADE, "not read yet: the sentence true of every writer");
  answer(secrets(RECORDS));
  await tick(); await tick();
  assert.equal(fromWords(row()), "Written by a program that held a secret");
  assert.ok(row().querySelector("button.made-from-see"));
});
