/**
 * home-js-place-links.test — a sentence that sends you somewhere links that
 * place (dashboard.md §4.25 *The hero links where it points*, §4.25p,
 * §4.34): "Settings › Models" opens Settings at its Models card with the
 * focus on Add a model; "Change it under Rules" on an Approvals card opens
 * that file's rule on Rules, or Your rules for a file with none; "Turn it on
 * in Settings" under Built-in protections opens Settings › Protection. A
 * modifier click is the browser's, at the card's address. The ⚠ mark on a
 * closed rule row is a button that opens the row, where its words are said
 * in full. A place the page does not know is text.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick, treeRows } from "./home-js-fixtures.js";

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const NO_OWN = "No AI of your own is listed, so no AI reads this file. Add one in Settings › Models.";
const NO_OWN_PARTS = [
  { kind: "text", text: "No AI of your own is listed, so no AI reads this file. Add one in " },
  { kind: "link", text: "Settings › Models", to: "models" },
  { kind: "text", text: "." },
];
const RULE = {
  id: "lock:/home/u/notes", kind: "lock", subject: "/home/u/notes", level: "local-model", bindings: [],
  plain: { subject: "/home/u/notes", reach: "and everything inside", effect: "Your own AI only" },
  actions: { remove: true, flip: null }, warning: NO_OWN, warningParts: NO_OWN_PARTS,
};
const panel = (rules: unknown[], extra: Record<string, unknown> = {}) => ({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: rules, models: [], ...extra } });

/** Records the ids scrollIntoView is called on. */
function scrolls(window: any): string[] {
  const seen: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: any) { seen.push(this.id || this.className); };
  return seen;
}
/** A click with ctrl held: the page leaves it to the browser. */
function modifierClick(window: any, a: any): boolean {
  let prevented: boolean | null = null;
  const spy = (e: any) => { prevented = e.defaultPrevented; e.preventDefault(); };
  window.document.addEventListener("click", spy);
  a.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true }));
  window.document.removeEventListener("click", spy);
  return prevented === true;
}

test("an opened rule's warning links Settings › Models: a plain click opens Settings at Models, the focus on Add a model; a modifier click is the browser's", async () => {
  const { doc, window } = load({ url: RULES_URL, routes: { "GET policy/panel": panel([RULE]) } });
  await tick();
  const row = treeRows(doc).find((r) => r.getAttribute("data-path") === "/home/u/notes");
  assert.ok(row, "the rule is drawn");
  row.click();
  const warn = doc.querySelector("#files-tree .file-detail .rule-warn");
  assert.equal(warn.textContent, NO_OWN, "the words are unchanged");
  const links = [...warn.querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href")]), [["Settings › Models", "/mandu/settings#models"]]);
  const seen = scrolls(window);
  assert.equal(modifierClick(window, links[0]), false, "a modifier click is not handled by the page");
  await tick();
  assert.equal(window.location.pathname, "/mandu/rules");
  links[0].click();
  assert.equal(doc.querySelector("#files-tree .file-detail") !== null, true, "the click does not close the row it sits in");
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.equal(window.location.hash, "#models", "the address names the card");
  assert.ok(seen.includes("settings-models-block"), JSON.stringify(seen));
  assert.equal(doc.activeElement, doc.getElementById("model-open"), "the focus is on Add a model");
  assert.equal(doc.activeElement.textContent, "Add a model");
});

test("a label made on the page (no server parts) links the same place; with Add a model hidden, the focus goes to the Models heading", async () => {
  const label = { path: "/home/u/memo", levelClass: "local-only", modelOk: false, scope: "exact", pattern: false, bindings: [], source: "user" };
  // No models field: the list was not read, so Add a model is hidden.
  const { doc } = load({ url: RULES_URL, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } },
    "GET secrets": { panel: { labels: [label] } },
  } });
  await tick();
  const row = treeRows(doc).find((r) => r.getAttribute("data-path") === "/home/u/memo");
  row.click();
  const warn = doc.querySelector("#files-tree .file-detail .rule-warn");
  assert.equal(warn.textContent, NO_OWN);
  const a = warn.querySelector("a");
  assert.equal(a.getAttribute("href"), "/mandu/settings#models");
  a.click();
  await tick(30);
  assert.equal(doc.getElementById("model-open").hidden, true);
  assert.equal(doc.activeElement, doc.querySelector("#settings-models-block h2"), "the card heading");
});

test("the ⚠ mark on a closed rule row is a button that opens the row, where its words are said with their link", async () => {
  const { doc } = load({ url: RULES_URL, routes: { "GET policy/panel": panel([RULE]) } });
  await tick();
  const row = () => treeRows(doc).find((r) => r.getAttribute("data-path") === "/home/u/notes");
  const mark = row().querySelector(".file-warn-mark");
  assert.equal(mark.tagName, "BUTTON");
  assert.equal(mark.getAttribute("type"), "button");
  assert.equal(mark.getAttribute("aria-label"), NO_OWN, "named by its words");
  assert.equal(doc.querySelector("#files-tree .file-detail"), null, "closed");
  mark.click();
  assert.ok(row().classList.contains("open"), "the row opened");
  assert.equal(doc.querySelector("#files-tree .file-detail .rule-warn").textContent, NO_OWN);
  // Pressed again with the row open: it stays open.
  row().querySelector(".file-warn-mark").click();
  assert.ok(row().classList.contains("open"));
  assert.equal(doc.querySelectorAll("#files-tree .file-detail").length, 1);
});

test("Rules › Who may get your secrets › AI: Your own AI's line links Settings › Models", async () => {
  const byWho = {
    available: true, partial: false, secretCount: 1,
    programs: { rows: [], note: "" }, hosts: { rows: [], note: "" },
    models: { rows: [{
      name: "Your own AI", about: "None is listed in Settings › Models, so no AI reads these files.", kind: "named",
      aboutParts: [{ kind: "text", text: "None is listed in " }, { kind: "link", text: "Settings › Models", to: "models" }, { kind: "text", text: ", so no AI reads these files." }],
      groups: [],
    }], note: "" },
  };
  const { doc } = load({ url: RULES_URL, storage: { "mandu.rules.byWho": "models" }, routes: { "GET policy/panel": panel([RULE]), "GET policy/by-who": { byWho } } });
  await tick();
  const line = [...doc.querySelectorAll(".by-who-about")].find((p: any) => /None is listed/.test(p.textContent)) as any;
  assert.ok(line, "the line is drawn");
  assert.equal(line.textContent, "None is listed in Settings › Models, so no AI reads these files.");
  assert.deepEqual([...line.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href")]), [["Settings › Models", "/mandu/settings#models"]]);
});

test("Rules › Built-in protections, protection off: Turn it on in Settings opens Settings at Protection", async () => {
  const builtIn = {
    note: "protection is off",
    items: ["Mandu only watches: nothing is masked, and your secrets are not guarded. Turn it on in Settings."],
    itemsParts: [[
      { kind: "text", text: "Mandu only watches: nothing is masked, and your secrets are not guarded. " },
      { kind: "link", text: "Turn it on in Settings", to: "protection" },
      { kind: "text", text: "." },
    ]],
    issuers: null,
  };
  const { doc, window } = load({ url: RULES_URL, homeVm: home({ builtIn }) });
  await tick();
  const item = doc.querySelector("#builtin-list li");
  assert.equal(item.textContent, builtIn.items[0]);
  const a = item.querySelector("a");
  assert.deepEqual([a.textContent, a.getAttribute("href")], ["Turn it on in Settings", "/mandu/settings#protection"]);
  const seen = scrolls(window);
  a.click();
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.ok(seen.includes("settings-protection-block"), JSON.stringify(seen));
  const sw = doc.getElementById("switch-protection");
  assert.equal(doc.activeElement, sw.disabled ? doc.querySelector("#settings-protection-block h2") : sw);
});

// ── Approvals: a file that takes no Always (§4.34) ───────────────────────────

const H = "hooks.slack.com";
const HOLDER = {
  ...ASK, id: "egr-58",
  sentence: [{ kind: "text", text: "Claude Code's program wants to send data from " }, { kind: "code", text: "~/keys/id" }, { kind: "text", text: " to " }, { kind: "code", text: H }],
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: false, label: "Block" }],
  sources: [
    {
      // A file inside a folder rule (the arbiter names the file itself).
      path: "/home/u/notes/a.md", name: "~/notes/a.md", mayGo: "may go nowhere", blocks: true,
      noAlways: "Its rule covers a whole folder, so Mandu does not change it from here. Change it under Rules.",
      noAlwaysParts: [
        { kind: "text", text: "Its rule covers a whole folder, so Mandu does not change it from here. " },
        { kind: "link", text: "Change it under Rules", to: "rule", path: "/home/u/notes/a.md" },
        { kind: "text", text: "." },
      ],
    },
    {
      path: "/home/u/plain.txt", name: "~/plain.txt", mayGo: "may go nowhere", blocks: true,
      noAlways: "It is no longer marked secret, so Mandu does not know where the copy may go. Mark it under Rules.",
      noAlwaysParts: [
        { kind: "text", text: "It is no longer marked secret, so Mandu does not know where the copy may go. " },
        { kind: "link", text: "Mark it under Rules", to: "rule", path: "/home/u/plain.txt" },
        { kind: "text", text: "." },
      ],
    },
  ],
};
const whyLinks = (doc: any) => [...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-58"] .ask-source-why a')] as any[];

test("Approvals: Change it under Rules links that file by its path, never a value; a plain click opens Rules with the folder rule that decides it open", async () => {
  const { doc, window } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }), routes: { "GET policy/panel": panel([RULE]) } });
  await tick();
  const why = [...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-58"] .ask-source-why')].map((x: any) => x.textContent);
  assert.deepEqual(why, HOLDER.sources.map((s) => s.noAlways), "the words are unchanged");
  const links = whyLinks(doc);
  assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href"), a.getAttribute("aria-label")]), [
    ["Change it under Rules", "/mandu/rules?file=/home/u/notes/a.md", "Change it under Rules: ~/notes/a.md"],
    ["Mark it under Rules", "/mandu/rules?file=/home/u/plain.txt", "Mark it under Rules: ~/plain.txt"],
  ]);
  assert.equal(modifierClick(window, links[0]), false, "a modifier click is the browser's");
  links[0].click();
  await tick(40);
  assert.equal(window.location.pathname, "/mandu/rules");
  const row = treeRows(doc).find((r) => r.getAttribute("data-path") === "/home/u/notes");
  assert.ok(row.classList.contains("open"), "the folder rule over the file is open");
  assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
});

test("Approvals: Mark it under Rules for a file with no rule of its own opens Rules at Your rules, its heading focused", async () => {
  const { doc, window } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }), routes: { "GET policy/panel": panel([RULE]) } });
  await tick();
  const seen = scrolls(window);
  whyLinks(doc)[1].click();
  await tick(40);
  assert.equal(window.location.pathname, "/mandu/rules");
  assert.equal(window.location.hash, "#your-rules");
  assert.ok(seen.includes("rules-block"), JSON.stringify(seen));
  assert.equal(doc.querySelector("#files-tree .file-detail"), null, "no row opened");
  assert.equal(doc.activeElement, doc.querySelector("#rules-block h2"));
});

test("a place the page does not know, or a rule part with no path, is text", async () => {
  const odd = {
    ...HOLDER, id: "egr-58",
    sources: [{ ...HOLDER.sources[0], noAlwaysParts: [
      { kind: "text", text: "Its rule covers a whole folder. " },
      { kind: "link", text: "Change it under Rules", to: "rule" },
      { kind: "text", text: " " },
      { kind: "link", text: "<b>Elsewhere</b>", to: "nowhere", path: "/home/u/notes/a.md" },
    ] }],
  };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [odd] }) });
  await tick();
  const why = doc.querySelector('#approvals-waiting .ask[data-id="egr-58"] .ask-source-why');
  assert.equal(why.textContent, "Its rule covers a whole folder. Change it under Rules <b>Elsewhere</b>");
  assert.equal(why.querySelector("a, b"), null);
});

test("Approvals: a folder rule written with ~ in the rules file decides a file the card names by its full path: its row opens", async () => {
  const tilde = { ...RULE, id: "lock:~/notes", subject: "~/notes", plain: { ...RULE.plain, subject: "~/notes" }, warning: undefined, warningParts: undefined };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }), routes: { "GET policy/panel": panel([tilde]) } });
  await tick();
  whyLinks(doc)[0].click();
  await tick(40);
  const row = treeRows(doc).find((r) => r.getAttribute("data-path") === "~/notes");
  assert.ok(row, JSON.stringify(treeRows(doc).map((r) => r.getAttribute("data-path"))));
  assert.ok(row.classList.contains("open"));
  assert.equal(doc.activeElement, row.querySelector(".file-more"));
});

test("Approvals: a file whose name reads as a pattern opens its own rule, drawn under Patterns, not the folder rule above it", async () => {
  const file = "/home/u/notes/key[1].txt";
  const own = { ...RULE, id: `lock:${file}`, subject: file, plain: { subject: file, reach: "", effect: "Always masked" }, level: "no-model", warning: undefined, warningParts: undefined };
  const card = { ...HOLDER, sources: [{ ...HOLDER.sources[0], path: file, name: "~/notes/key[1].txt", noAlwaysParts: [
    { kind: "text", text: "Its name reads as a pattern, so Mandu does not write a rule for it from here. " },
    { kind: "link", text: "Change it under Rules", to: "rule", path: file },
    { kind: "text", text: "." },
  ] }] };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [card] }), routes: { "GET policy/panel": panel([RULE, own]) } });
  await tick();
  whyLinks(doc)[0].click();
  await tick(40);
  const row = treeRows(doc).find((r) => r.getAttribute("data-path") === file);
  assert.ok(row, JSON.stringify(treeRows(doc).map((r) => r.getAttribute("data-path"))));
  assert.ok(row.classList.contains("open"), "its own rule");
  assert.equal(doc.querySelectorAll("#files-tree .row.file-rule.open").length, 1, "and only it");
});
