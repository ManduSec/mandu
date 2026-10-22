/**
 * home-js-by-who.test — the Rules page's "Who may get your secrets" card
 * (dashboard.md §4.25aa, confidentiality plan 13 §5.3): the server's
 * per-principal projection (view-model/rules-by-who.ts) painted by
 * public/js/home.js as three tabs over one read-only list, in jsdom over the
 * fetch stub of home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { tick, load, PUB, RULES_PANEL } from "./home-js-fixtures.js";
import { contrastRatio, declValue, flattenCss, resolveCssVars, stripComments } from "./css-flatten.js";
import { byWhoRules, toByWhoVM } from "../../../src/view-model/rules-by-who.js";

/** Plan 13 Figure 3's example, projected as the server does. */
const VM = toByWhoVM(byWhoRules([
  { path: "/home/u/proj/README.md", level: "public", bindings: [], recursive: false },
  { path: "/home/u/proj/.env", level: "no-model", bindings: ["api.stripe.com"], recursive: false, readers: [{ app: "deploy", prints: "nothing" }, "psql"] },
  { path: "/home/u/.ssh", level: "no-model", bindings: [], recursive: true, readers: ["ssh"], others: "twin" },
  { path: "/home/u/notes", level: "any-model", bindings: [], recursive: true },
  { path: "/home/u/contracts", level: "local-model", bindings: [], recursive: true },
], []), [{ name: "vllm-1", url: "http://127.0.0.1:8000/v1", wire: "openai-chat", local: true }], { home: "/home/u" });

/** The Rules page with `byWho` as the by-who route's answer, and the stored tab. */
const page = (byWho: unknown = { byWho: VM }, storage?: Record<string, string>) =>
  load({ url: "http://127.0.0.1:4500/mandu/rules", storage, routes: { "GET policy/panel": RULES_PANEL, "GET policy/by-who": byWho } });

const card = (doc: any) => doc.getElementById("by-who-block");
const tabs = (doc: any) => [...doc.querySelectorAll("#by-who-block [role=tab]")] as any[];
const selected = (doc: any) => tabs(doc).find((b) => b.getAttribute("aria-selected") === "true")?.textContent;
const rows = (doc: any) => [...doc.querySelectorAll("#by-who-list .by-who-row")] as any[];
const names = (doc: any) => rows(doc).map((r) => r.querySelector(".by-who-name > :first-child").textContent);
const rowNamed = (doc: any, name: string) => rows(doc).find((r) => r.querySelector(".by-who-name > :first-child").textContent === name);
/** A row's lists as `label: item; item`, as a person reads them. */
const listsOf = (r: any) => ([...r.querySelectorAll(".by-who-group")] as any[]).map((g) =>
  `${g.querySelector(".by-who-label").textContent}: ${([...g.querySelectorAll("li")] as any[]).map((li) => li.textContent).join("; ")}`);

test("§4.25aa: the card is hidden until the rules are read: an older server, a failed read, rules unread", async () => {
  for (const [what, answer] of [
    ["an older server", {}],
    ["a failed read", { status: 500, body: { error: "x" } }],
    ["unread rules", { byWho: toByWhoVM(null, null) }],
  ] as const) {
    const { doc, err } = page(answer);
    await tick();
    assert.equal(err, null);
    assert.equal(card(doc).hidden, true, what);
  }
});

test("§4.25aa: Programs first: each program's files under what it may do, Any other program last", async () => {
  const { doc } = page();
  await tick();
  assert.equal(card(doc).hidden, false);
  assert.equal(doc.getElementById("by-who-title").textContent, "Who may get your secrets");
  assert.deepEqual(tabs(doc).map((b) => b.textContent), ["Programs", "Hosts", "AI"]);
  assert.equal(selected(doc), "Programs");
  assert.deepEqual(names(doc), ["deploy", "psql", "ssh", "Any other program"]);
  // Only what differs from Any other program, and a line for the rest (§4.25aa *Only what differs*).
  assert.deepEqual(listsOf(rowNamed(doc, "deploy")), ["Opens the real file: ~/proj/.env (your word)"]);
  const rest = rowNamed(doc, "deploy").querySelector(".by-who-groups > .by-who-rest");
  assert.equal(rest?.textContent, "The rest (3): as any other program, below.");
  assert.equal(rest.previousElementSibling.className, "by-who-group", "under its lists");
  assert.ok(rest.classList.contains("by-who-none"), "the row's muted note style");
  assert.equal(rest.querySelector("button, a"), null, "the rest line is not a link");
  assert.deepEqual(listsOf(rowNamed(doc, "Any other program")), [
    "Gets a masked copy: ~/.ssh and everything inside; ~/contracts and everything inside; ~/notes and everything inside",
    "Refused: ~/proj/.env",
  ], "the closing row is unchanged");
  assert.equal(rowNamed(doc, "Any other program").querySelector(".by-who-rest"), null);
  assert.equal(listsOf(rowNamed(doc, "ssh"))[0], "Opens the real file: ~/.ssh and everything inside (checked by Mandu)");
  assert.deepEqual(listsOf(rowNamed(doc, "psql")), ["Never gets the real file: it prints or runs what it reads: ~/proj/.env"]);
  assert.equal(rowNamed(doc, "deploy").querySelector(".by-who-name code").textContent, "deploy", "a program's name is code");
  const any = rowNamed(doc, "Any other program");
  assert.ok(any.classList.contains("any"));
  assert.equal(any.querySelector(".by-who-name strong").textContent, "Any other program", "the closing row is words, not a name");
  assert.equal(any.querySelector(".by-who-about").textContent, "A program no rule names.");
  assert.match(doc.getElementById("by-who-note").textContent, /^Opening a file does not let a program send it/);
  // Each list's mark has the colour of what it allows.
  assert.equal(rowNamed(doc, "deploy").querySelector(".by-who-group .dot").className, "dot ok");
});

test("§4.25aa Only what differs: a program that gets everything as any other program shows that line, never Nothing under your rules", async () => {
  const same = toByWhoVM(byWhoRules([
    { path: "/home/u/.aws", level: "no-model", bindings: [], recursive: true, readers: ["aws"], others: "twin" },
  ], []), null, { home: "/home/u" });
  const { doc } = page({ byWho: same });
  await tick();
  const aws = rowNamed(doc, "aws");
  assert.equal(aws.querySelectorAll(".by-who-group").length, 0);
  assert.equal(aws.querySelector(".by-who-groups").textContent, "Everything: as any other program, below.");
  assert.doesNotMatch(card(doc).textContent, /Nothing under your rules/);
  // A row with neither lists nor a rest line (an older server) still says so.
  const { doc: older } = page({ byWho: { ...same, programs: { ...same.programs, rows: same.programs.rows.map((r) => ({ ...r, rest: undefined })) } } });
  await tick();
  assert.equal(rowNamed(older, "aws").querySelector(".by-who-groups").textContent, "Nothing under your rules.");
});

test("§4.25aa: read only: the only controls in the list are the files that open their rows, and nothing is written when a tab is chosen or a file pressed", async () => {
  const { doc, calls } = withRules();
  await tick();
  for (const b of tabs(doc)) {
    b.click();
    await tick();
    assert.equal(doc.querySelectorAll("#by-who-list select, #by-who-list input, #by-who-list a").length, 0);
    const buttons = [...doc.querySelectorAll("#by-who-list button")] as any[];
    assert.ok(buttons.length > 0);
    for (const x of buttons) assert.ok(x.classList.contains("by-who-link"), x.textContent);
    buttons[0].click();
    await tick();
  }
  assert.deepEqual(calls.filter((c) => c.method !== "GET" && c.url !== "/api/files/why").map((c) => c.url), [], "no write");
});

// ── A file opens its rule's row under Your rules (§4.25aa *Where*) ──────────

/** A file rule row as policy-panel.ts serves it (home-js-explorer.test.ts). */
const lockRow = (path: string, covers: "subtree" | "exact") => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [], level: "no-model",
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: covers === "subtree" ? "and everything inside" : "this file only", effect: "No AI" },
});
/** Your rules with VM's files but ~/contracts (the two reads disagree for a
 *  moment): ~/proj/README.md and ~/proj/.env share the folder heading
 *  ~/proj; ~/ws/b and the fixtures' page label ~/ws/.env the heading ~/ws. */
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  lockRow("/home/u/proj/README.md", "exact"),
  lockRow("/home/u/proj/.env", "exact"),
  lockRow("/home/u/.ssh", "subtree"),
  lockRow("/home/u/notes", "subtree"),
  lockRow("/home/u/ws/b", "exact"),
] } };
const withRules = (storage?: Record<string, string>) =>
  load({ url: "http://127.0.0.1:4500/mandu/rules", storage, routes: { "GET policy/panel": PANEL, "GET policy/by-who": { byWho: VM } } });
/** The file `text` under `group` in the row named `name`. */
const fileIn = (doc: any, name: string, group: string, text: string) => {
  const g = ([...rowNamed(doc, name).querySelectorAll(".by-who-group")] as any[]).find((x) => x.querySelector(".by-who-label").textContent === group);
  assert.ok(g, `${name}: ${group}`);
  const li = ([...g.querySelectorAll("li")] as any[]).find((x) => x.querySelector("code").textContent === text);
  assert.ok(li, `${name} › ${group}: ${text}`);
  return li;
};
const treeRowOf = (doc: any, path: string) => ([...doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).find((r) => r.getAttribute("data-path") === path);
/** The tree row for `path` is open (its detail under it) and its ⋯ has the focus. */
const assertOpened = (doc: any, path: string, where: string) => {
  const row = treeRowOf(doc, path);
  assert.ok(row, `${where}: Your rules has a row for ${path}`);
  assert.ok(row.classList.contains("open"), `${where}: its row is open`);
  assert.ok(row.nextElementSibling?.classList.contains("file-detail"), `${where}: what the rules say is under it`);
  assert.equal(doc.querySelectorAll("#files-tree .file-detail").length, 1, `${where}: one row open`);
  assert.equal(doc.activeElement, row.querySelector(".file-more"), `${where}: the focus is on its ⋯`);
  assert.equal(row.closest("[hidden]"), null, `${where}: in sight, not folded`);
};

test("§4.25aa: in each tab a file opens its rule's row under Your rules, with the focus on its ⋯; a value opens its file's", async () => {
  const { doc } = withRules();
  await tick();
  const link = fileIn(doc, "deploy", "Opens the real file", "~/proj/.env").querySelector("button.by-who-link");
  assert.ok(link, "a file is a button");
  assert.equal(link.getAttribute("type"), "button");
  assert.equal(link.querySelector("code").textContent, "~/proj/.env", "holding the same chip");
  assert.equal(link.getAttribute("aria-label"), "Show the rule for ~/proj/.env in Your rules");
  link.click();
  await tick();
  assertOpened(doc, "/home/u/proj/.env", "Programs");
  tabs(doc)[1].click();
  fileIn(doc, "api.stripe.com", "Gets the real value without asking", "~/proj/.env").querySelector("button").click();
  await tick();
  assertOpened(doc, "/home/u/proj/.env", "Hosts (already open: it stays open)");
  fileIn(doc, "Any other host", "Not secret, so it may go anywhere", "~/proj/README.md").querySelector("button").click();
  await tick();
  assertOpened(doc, "/home/u/proj/README.md", "Hosts");
  tabs(doc)[2].click();
  fileIn(doc, "Any AI", "May read it when it asks", "~/notes").querySelector("button").click();
  await tick();
  assertOpened(doc, "/home/u/notes", "AI");
  // A per-value item ("~/x/.env: STRIPE_KEY") opens its file's row.
  const perValue = toByWhoVM(byWhoRules([
    { path: "/home/u/proj/.env", level: "no-model", bindings: [], recursive: false, values: [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }], wholeBindings: [] },
  ], []), [], { home: "/home/u" });
  const v = load({ url: "http://127.0.0.1:4500/mandu/rules", storage: { "mandu.rules.byWho": "hosts" }, routes: { "GET policy/panel": PANEL, "GET policy/by-who": { byWho: perValue } } });
  await tick();
  const value = fileIn(v.doc, "api.stripe.com", "Gets the real value without asking", "~/proj/.env: STRIPE_KEY").querySelector("button");
  assert.equal(value.getAttribute("aria-label"), "Show the rule for ~/proj/.env: STRIPE_KEY in Your rules");
  value.click();
  await tick();
  assertOpened(v.doc, "/home/u/proj/.env", "a value");
});

test("§4.25aa: a rule inside a folded folder is unfolded first; a folder not above it stays folded", async () => {
  const { doc } = withRules();
  await tick();
  const folder = (title: string) => ([...doc.querySelectorAll("#files-tree .rules-folder")] as any[]).find((f) => f.title === title);
  assert.ok(folder("~/proj") && folder("~/ws"), "two folder headings");
  folder("~/proj").click();
  folder("~/ws").click();
  assert.equal(folder("~/proj").getAttribute("aria-expanded"), "false");
  assert.notEqual(treeRowOf(doc, "/home/u/proj/.env").closest("[hidden]"), null, "folded out of sight");
  fileIn(doc, "deploy", "Opens the real file", "~/proj/.env").querySelector("button").click();
  await tick();
  assert.equal(folder("~/proj").getAttribute("aria-expanded"), "true");
  assertOpened(doc, "/home/u/proj/.env", "folded");
  assert.equal(folder("~/ws").getAttribute("aria-expanded"), "false", "a folder not above the rule stays folded");
  // ~/.ssh is under no heading: ~/proj, folded again, stays folded.
  folder("~/proj").click();
  fileIn(doc, "ssh", "Opens the real file", "~/.ssh").querySelector("button").click();
  await tick();
  assert.equal(folder("~/proj").getAttribute("aria-expanded"), "false");
  assertOpened(doc, "/home/u/.ssh", "outside any heading");
});

test("§4.25aa: a file whose rule has no row in Your rules is plain code, with no button; with Your rules unread every file is", async () => {
  const { doc } = withRules();
  await tick();
  const li = fileIn(doc, "Any other program", "Gets a masked copy", "~/contracts");
  assert.equal(li.querySelector("button"), null, "no row for ~/contracts: nothing points to it");
  assert.equal(li.querySelector("code").parentElement, li);
  assert.ok(fileIn(doc, "Any other program", "Gets a masked copy", "~/notes").querySelector("button"), "its neighbour has a row");
  const unread = page({ byWho: VM });
  await tick();
  // RULES_PANEL holds only a pattern none of VM's files is.
  assert.equal(unread.doc.querySelectorAll("#by-who-list button").length, 0);
  const failed = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": { status: 500, body: { error: "x" } }, "GET policy/by-who": { byWho: VM } } });
  await tick();
  assert.equal(failed.doc.querySelectorAll("#by-who-list button").length, 0, "Your rules could not be read");
});

test("§4.25aa: the note sends the reader to the files, which now go there", () => {
  const html = readFileSync(join(PUB, "index.html"), "utf8");
  assert.match(html, /To change one, press its file to open it under Your rules\.<\/p>/);
  assert.doesNotMatch(html, /use its file's menus under Your rules/);
});

test("§4.25aa: Hosts and AI tabs; the tab chosen is remembered; arrow keys move between tabs", async () => {
  const { doc, window } = page();
  await tick();
  tabs(doc)[1].click();
  assert.equal(selected(doc), "Hosts");
  assert.equal(doc.getElementById("by-who-list").getAttribute("aria-labelledby"), "by-who-tab-hosts");
  assert.deepEqual(names(doc), ["api.stripe.com", "Any other host"]);
  assert.deepEqual(listsOf(rowNamed(doc, "api.stripe.com")), ["Gets the real value without asking: ~/proj/.env"]);
  assert.deepEqual(listsOf(rowNamed(doc, "Any other host")), ["Not secret, so it may go anywhere: ~/proj/README.md"]);
  assert.match(doc.getElementById("by-who-note").textContent, /may send only where both may go/);
  assert.equal(window.localStorage.getItem("mandu.rules.byWho"), "hosts");
  // ArrowRight from Hosts: AI, focused.
  tabs(doc)[1].dispatchEvent(new window.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.equal(selected(doc), "AI");
  assert.equal(doc.activeElement, tabs(doc)[2]);
  assert.deepEqual(tabs(doc).map((b) => b.tabIndex), [-1, -1, 0], "one tab stop");
  assert.deepEqual(names(doc), ["Any AI", "vllm-1"]);
  assert.deepEqual(listsOf(rowNamed(doc, "Any AI")), [
    "Reads it as written: ~/proj/README.md",
    "May read it when it asks: ~/notes and everything inside",
    "Always sees it masked: ~/.ssh and everything inside; ~/contracts and everything inside; ~/proj/.env",
  ]);
  assert.equal(rowNamed(doc, "vllm-1").querySelector(".by-who-about").textContent, "Your own AI, on this computer.");
  // Home wraps around to Programs; a fresh page opens the tab last chosen.
  tabs(doc)[2].dispatchEvent(new window.KeyboardEvent("keydown", { key: "Home", bubbles: true }));
  assert.equal(selected(doc), "Programs");
  const again = page({ byWho: VM }, { "mandu.rules.byWho": "models" });
  await tick();
  assert.equal(selected(again.doc), "AI");
  const junk = page({ byWho: VM }, { "mandu.rules.byWho": "nonsense" });
  await tick();
  assert.equal(selected(junk.doc), "Programs", "an unknown stored tab is the first");
});

test("§4.25aa: no secret rule says so; rules partly read say the lists may miss files", async () => {
  const { doc } = page({ byWho: toByWhoVM([], null) });
  await tick();
  assert.equal(card(doc).hidden, false);
  assert.equal(doc.querySelector("#by-who-list .empty").textContent, "No rule of yours makes a file secret yet.");
  const partial = page({ byWho: { ...VM, partial: true } });
  await tick();
  assert.match(partial.doc.getElementById("by-who-note").textContent, /^Some rules made on this page could not be read, so these lists may miss files\. /);
});

test("§4.25aa: the card's words pass the product sweep (no inspector term, masked never placeholder)", async () => {
  const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:|placeholder|twin\b|binding|opener|principal/i;
  const { doc } = page();
  await tick();
  let text = card(doc).textContent;
  for (const b of tabs(doc)) { b.click(); text += card(doc).textContent; }
  assert.doesNotMatch(text, FORBIDDEN);
});

test("§4.25aa: the styles: a 12px floor, and at phone width the lists go under the name", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rules = flattenCss(css).filter((r) => r.selectors.some((s) => /by-who/.test(s)));
  assert.ok(rules.length > 0);
  assert.ok(rules.some((r) => r.selectors.includes(".by-who-none") && declValue(r.block, "font-size") === "13px"), "the rest line is .by-who-none's 13px");
  assert.ok(rules.some((r) => r.selectors.includes(".by-who-rest")), "the rest line's own rule is under the floor's sweep");
  for (const r of rules) {
    const size = declValue(r.block, "font-size");
    if (size) assert.ok(Number.parseFloat(size) >= 12, `${r.selectors.join(", ")}: ${size}`);
  }
  // `code` is 0.9em: the card sets its code sizes itself, so none falls under 12px.
  assert.ok(rules.some((r) => r.selectors.includes(".by-who-items code") && declValue(r.block, "font-size") === "13px"));
  const narrow = rules.filter((r) => r.media === "@media (max-width: 640px)" && r.selectors.includes(".row.by-who-row"));
  assert.equal(declValue(narrow[0]!.block, "grid-template-columns"), "minmax(0, 1fr)", "one column on a phone");
  const wide = rules.find((r) => r.media === null && r.selectors.includes(".row.by-who-row"))!;
  assert.match(declValue(wide.block, "grid-template-columns") ?? "", /minmax\(0, 1fr\)$/, "the lists' column shrinks, so no row scrolls sideways");
});

test("§4.25aa: a file that opens its rule is the same chip in the link colour, inline so a long name wraps, and reads 4.5:1 in both themes", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rules = flattenCss(css);
  const at = (sel: string) => rules.find((r) => r.media === null && r.selectors.includes(sel));
  assert.equal(declValue(at(".by-who-items .by-who-link")!.block, "display"), "inline", "not .link-btn's inline-flex: the name's parts wrap");
  assert.equal(declValue(at(".by-who-link code")!.block, "color"), "var(--accent)");
  assert.equal(declValue(at(".by-who-link:hover code")!.block, "text-decoration"), "underline");
  assert.ok(at(".by-who-link:focus-visible"), "a focus ring");
  for (const theme of ["light", "dark"] as const) {
    const flat = flattenCss(resolveCssVars(`${readFileSync(join(PUB, "mandu.css"), "utf8")}\n${css}`, theme));
    const value = (sel: string, prop: string) => declValue(flat.find((r) => r.media === null && r.selectors.includes(sel) && declValue(r.block, prop))!.block, prop)!;
    for (const sel of [".by-who-link code", ".by-who-link:hover code"]) {
      const ratio = contrastRatio(value(sel, "color"), value("code", "background"));
      assert.ok(ratio >= 4.5, `${theme}: ${sel} reads ${ratio.toFixed(2)}:1 on the chip`);
    }
  }
});
