/**
 * home-js-rules-find.test — Rules › Your rules' *Find a rule* box
 * (dashboard.md §4.25f *Find a rule*), in jsdom over the fetch stub of
 * home-js-fixtures.ts: typing keeps only the rows whose drawn words hold
 * the text (a file by its `~/…` path, its Opens it programs and its hosts;
 * a send rule by its host and file; a connection by its address and port),
 * the tree keeps and opens the folders on the way to each match, a group
 * with none is not drawn, the count says "3 of 27", nothing found says so
 * with Clear, Escape and a page change empty the box, a redraw keeps it,
 * Changes to save is never narrowed, and no read is made for it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { load, tick, PUB, FILES_ROUTES, CONFIG_LIST, list } from "./home-js-fixtures.js";
import { byWhoRules, toByWhoVM } from "../../../src/view-model/rules-by-who.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";

/** A file rule as policy-panel.ts serves it. */
const lockRow = (path: string, covers: "subtree" | "exact", more: Record<string, unknown> = {}, plain: Record<string, unknown> = {}) => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [], level: "no-model",
  actions: { remove: true, flip: null }, ...more,
  plain: { subject: path, reach: covers === "subtree" ? "and everything inside" : "this file only", effect: "No AI", opens: "Programs get a masked copy.", ...plain },
});
/** A send rule (release-allow) as policy-panel.ts serves it. */
const sendRow = (id: string, host: string, reach: string) => ({
  id, kind: "release-allow", subject: host, effect: "sending allowed", reach, hits: 1, actions: { remove: true, flip: "block" },
  plain: { subject: host, reach, effect: "Always allowed" },
});
/** A connection rule (connect-allow), its words around its names. */
const connectRow = (spec: string, subject: string, words: string, parts: Array<{ kind: string; text: string }>) => ({
  id: `connect:${spec}`, kind: "connect-allow", subject, reach: null, hits: null, effect: "the agent may connect there",
  actions: { remove: true, flip: null },
  plain: { subject: words, subjectParts: parts, reach: "your agent's programs connecting", effect: "Always allowed, from the agent's next start" },
});

/**
 * Seven rules: four in the tree (~/proj/.env and ~/proj/deploy.token share
 * the folder heading ~/proj; ~/.ssh holds ~/.ssh/config), and in the rest a
 * send rule, a connection on port 2222 and an answer about a host. The send
 * rule's raw subject (`api.github.com`) is worded differently on the page
 * (`GitHub's API`), standing in for a form the page does not draw.
 */
const PANEL = { panel: { available: true, verdictsKnown: true, yourRules: [
  lockRow("/home/u/proj/.env", "exact", { bindings: ["api.stripe.com"] }, { effect: "No AI; may be sent to api.stripe.com", opens: "docker-compose (your word) may open the real file. Other programs are refused." }),
  lockRow("/home/u/proj/deploy.token", "exact"),
  lockRow("/home/u/.ssh", "subtree", {}, { opens: "ssh (checked by Mandu) may open the real file. Other programs get a masked copy." }),
  lockRow("/home/u/.ssh/config", "exact", { level: "any-model" }, { effect: "Any AI, when it asks", opens: "Programs get a masked copy." }),
  { ...sendRow("r-0001", "api.github.com", "sending ~/proj/deploy.token from any source"), plain: { subject: "GitHub's API", reach: "sending ~/proj/deploy.token from any source", effect: "Always allowed" } },
  connectRow("tcp:*:2222", "*:2222", "any address on port 2222", [{ kind: "text", text: "any address on port " }, { kind: "code", text: "2222" }]),
], queue: [
  { id: "egr-7", status: "approved", scope: "always", where: "network", target: "paste.example", count: 1, actions: [{ approve: false, label: "Block instead" }],
    plain: { subject: "paste.example", reach: "sending only the file ~/ws/notes.md", effect: "Always allowed" }, sessions: [], resolvedAt: null },
] } };
const ROUTES = { ...FILES_ROUTES, [list("~/ws/config")]: CONFIG_LIST, "GET policy/panel": PANEL, "GET secrets": { panel: { labels: [] } }, "POST files/impact": { impact: null, page: 0 } };
const page = (storage?: Record<string, string>) => load({ url: RULES, storage, routes: ROUTES });

const box = (doc: any) => doc.getElementById("rules-find");
async function type(doc: any, text: string) {
  box(doc).focus();
  box(doc).value = text;
  box(doc).dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await tick();
}
const count = (doc: any) => doc.getElementById("rules-count").textContent;
/** The tree as drawn: `depth [folder ]label`, folded folders' rows left out. */
const tree = (doc: any) => ([...doc.querySelectorAll("#files-tree .row.file-rule, #files-tree .rules-folder")] as any[])
  .filter((e) => !e.closest("[hidden]"))
  .map((e) => `${/--depth:(\d+)/.exec(e.getAttribute("style") ?? "")?.[1] ?? 0} ${e.classList.contains("rules-folder") ? "folder " : ""}${e.querySelector("code").textContent}${e.getAttribute("data-find") === "context" ? " (on the way)" : ""}`);
/** The rows of the other groups, by group title. */
const rest = (doc: any) => ([...doc.querySelectorAll("#rules-list .rules-group")] as any[]).map((g) => {
  const title = g.firstChild.textContent.trim();
  const rows = ([...g.nextElementSibling.querySelectorAll(".row.rule")] as any[]).map((r) => r.querySelector(".rule-text").firstChild.textContent);
  return `${title}: ${rows.join(", ")}`;
});
const groupShown = (doc: any) => !doc.getElementById("files-group").hidden;
const none = (doc: any) => doc.getElementById("rules-find-none");

test("§4.25f Find a rule: the box sits in Your rules' heading, empty, and an empty box draws every rule with the plain count", async () => {
  const { doc, err } = page();
  await tick();
  assert.equal(err, null);
  const b = box(doc);
  assert.equal(b.tagName, "INPUT");
  assert.equal(b.type, "search");
  assert.equal(b.getAttribute("aria-label"), "Find a rule");
  assert.equal(b.closest(".block-head"), doc.querySelector("#rules-block > .block-head"), "beside the heading");
  assert.equal(b.value, "");
  assert.equal(count(doc), "7");
  assert.deepEqual(tree(doc), ["0 ~/.ssh", "1 config", "0 folder ~/proj/", "1 .env", "1 deploy.token"]);
  assert.deepEqual(rest(doc), ["Sending data: GitHub's API, paste.example", "Programs and connections: any address on port 2222"]);
  assert.equal(none(doc).hidden, true);
});

test("§4.25f Find a rule: a file by its path as drawn, in the ~/ form, and by its last name", async () => {
  const { doc } = page();
  await tick();
  await type(doc, "deploy.TOKEN");
  // The send rule's second line names the file too: it is kept.
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 deploy.token"]);
  assert.deepEqual(rest(doc), ["Sending data: GitHub's API"]);
  assert.equal(count(doc), "2 of 7");
  await type(doc, "~/proj/.env");
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 .env"]);
  assert.deepEqual(rest(doc), []);
  assert.equal(doc.getElementById("rules-list").hidden, true, "no other group is drawn");
  assert.equal(count(doc), "1 of 7");
  await type(doc, "/home/u/.ssh/config");
  assert.deepEqual(tree(doc), ["0 ~/.ssh (on the way)", "1 config"], "the folder rule above it stays, as the way there");
  assert.equal(count(doc), "1 of 7", "the rule on the way is not counted");
});

test("§4.25f Find a rule: a file by a program of its Opens it line, and by a host it may be sent to", async () => {
  const { doc } = page();
  await tick();
  await type(doc, "docker-compose");
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 .env"]);
  assert.deepEqual(rest(doc), []);
  await type(doc, "ssh (checked");
  assert.deepEqual(tree(doc), ["0 ~/.ssh"]);
  await type(doc, "api.stripe.com");
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 .env"]);
  assert.equal(count(doc), "1 of 7");
});

test("§4.25f Find a rule: a send rule by its host and its file, a connection by its port; a group with no match is not drawn", async () => {
  const { doc } = page();
  await tick();
  await type(doc, "paste.example");
  assert.deepEqual(rest(doc), ["Sending data: paste.example"]);
  assert.equal(groupShown(doc), false, "Files and folders: no match, its title not drawn");
  assert.equal(doc.getElementById("files-heads").hidden, true);
  assert.equal(doc.getElementById("files-tree").hidden, true);
  await type(doc, "2222");
  assert.deepEqual(rest(doc), ["Programs and connections: any address on port 2222"]);
  await type(doc, "notes.md");
  assert.deepEqual(rest(doc), ["Sending data: paste.example"], "an answer by the file it covers");
  await type(doc, "");
  assert.equal(groupShown(doc), true, "an empty box draws the group again");
  assert.equal(count(doc), "7");
});

test("§4.25f Find a rule: only the words drawn are matched, never the raw subject a row keeps for its tooltip", async () => {
  const { doc } = page();
  await tick();
  await type(doc, "api.github.com");
  assert.deepEqual(rest(doc), [], "the raw form the page words differently is not found");
  assert.deepEqual(tree(doc), []);
  assert.match(none(doc).textContent, /^No rule mentions “api\.github\.com”\. Clear/);
  await type(doc, "GitHub's API");
  assert.deepEqual(rest(doc), ["Sending data: GitHub's API"]);
});

test("§4.25f Find a rule: a folded folder with a match opens; emptying the box gives back the person's own folds", async () => {
  const { doc } = page();
  await tick();
  const folder = () => ([...doc.querySelectorAll("#files-tree .rules-folder")] as any[]).find((f) => f.title === "~/proj");
  folder().click();
  assert.equal(folder().getAttribute("aria-expanded"), "false");
  assert.deepEqual(tree(doc), ["0 ~/.ssh", "1 config", "0 folder ~/proj/"]);
  await type(doc, "deploy");
  assert.equal(folder().getAttribute("aria-expanded"), "true", "opened for the match");
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 deploy.token"]);
  assert.match(folder().textContent, /1 rule$/, "it counts the rules found under it");
  // Folding it while the box holds text changes only what is drawn.
  folder().click();
  assert.equal(folder().getAttribute("aria-expanded"), "false");
  folder().click();
  await type(doc, "");
  assert.equal(folder().getAttribute("aria-expanded"), "false", "the person's fold is back");
  assert.match(folder().textContent, /2 rules$/);
});

test("§4.25f Find a rule: nothing found says so with Clear; a path-like text offers Add a rule with the path filled in", async () => {
  const { doc, calls } = page();
  await tick();
  const before = calls.length;
  await type(doc, "stripe-live");
  assert.equal(none(doc).hidden, false);
  assert.equal(none(doc).querySelectorAll("p").length, 1, "not a path: no Add a rule line");
  assert.equal(count(doc), "0 of 7");
  await type(doc, "~/ws/config");
  const lines = [...none(doc).querySelectorAll("p")] as any[];
  assert.equal(lines.length, 2);
  assert.equal(lines[0].textContent, "No rule mentions “~/ws/config”. Clear");
  assert.equal(lines[1].textContent, "To make one, add a rule.");
  assert.deepEqual(calls.slice(before).map((c) => c.url), [], "typing reads nothing");
  lines[1].querySelector("button").click();
  await tick();
  assert.equal(doc.getElementById("lock-form").hidden, false, "Add a rule opened");
  assert.match(doc.getElementById("lock-path").value, /^~\/ws\/config\/?$/, "the path is in the path box");
  assert.ok(calls.some((c) => c.url.includes("files/list") && c.url.includes(encodeURIComponent("~/ws/config"))), "and opened, as Go opens it");
  assert.equal(doc.activeElement, doc.getElementById("lock-path"));
  // Clear empties the box, draws every rule, and gives the box the focus.
  none(doc).querySelector("button").click();
  await tick();
  assert.equal(box(doc).value, "");
  assert.equal(count(doc), "7");
  assert.equal(none(doc).hidden, true);
  assert.equal(doc.activeElement, box(doc));
});

test("§4.25f Find a rule: Escape empties the box; an empty box leaves Escape alone", async () => {
  const { doc } = page();
  await tick();
  await type(doc, "2222");
  const esc = () => {
    const e = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    box(doc).dispatchEvent(e);
    return e.defaultPrevented;
  };
  assert.equal(esc(), true);
  await tick();
  assert.equal(box(doc).value, "");
  assert.equal(count(doc), "7");
  assert.equal(doc.activeElement, box(doc), "the focus stays in the box");
  assert.equal(esc(), false, "nothing to empty");
});

test("§4.25f Find a rule: the focus stays in the box while typing, and a redraw (the page's own read after a change) keeps the text and applies it again", async () => {
  const { doc, calls } = load({ url: RULES, routes: { ...ROUTES, "POST policy/rules/change": { applied: true, changeId: "c1" } } });
  await tick();
  await type(doc, "deploy");
  assert.equal(doc.activeElement, box(doc), "typing draws the rows, never the box");
  assert.equal(count(doc), "2 of 7");
  const reads = calls.filter((c) => c.url.endsWith("/api/policy/panel")).length;
  // Turn the send rule around from its menu: Rules reads the rules again.
  const sel = doc.querySelector("#rules-list .row.rule select.effect-select");
  sel.value = "flip";
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick();
  assert.equal(calls.filter((c) => c.url.endsWith("/api/policy/panel")).length, reads + 1, "read again");
  assert.equal(box(doc).value, "deploy");
  assert.equal(count(doc), "2 of 7");
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 deploy.token"]);
});

test("§4.25f Find a rule: a file pressed under Who may get your secrets empties a box that would hide its rule (#15)", async () => {
  const vm = toByWhoVM(byWhoRules([
    { path: "/home/u/proj/.env", level: "no-model", bindings: ["api.stripe.com"], recursive: false, readers: [{ app: "docker-compose", prints: "nothing" }] },
  ], []), [], { home: "/home/u" });
  const { doc } = load({ url: RULES, routes: { ...ROUTES, "GET policy/by-who": { byWho: vm } } });
  await tick();
  await type(doc, "2222");
  const link = doc.querySelector('#by-who-list button[aria-label="Show the rule for ~/proj/.env in Your rules"]');
  assert.ok(link);
  link.click();
  await tick();
  assert.equal(box(doc).value, "", "emptied");
  assert.equal(count(doc), "7");
  const row = ([...doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).find((r) => r.getAttribute("data-path") === "/home/u/proj/.env");
  assert.ok(row.classList.contains("open"), "its row opened");
  // A box that already shows the row is kept.
  await type(doc, "docker");
  doc.querySelector('#by-who-list button[aria-label="Show the rule for ~/proj/.env in Your rules"]').click();
  await tick();
  assert.equal(box(doc).value, "docker");
});

test("§4.25f Find a rule: a row the box hides closes, and Changes to save still lists a change on it", async () => {
  const waiting = JSON.stringify([{ path: "/home/u/proj/deploy.token", display: "~/proj/deploy.token", level: "any-model", bindings: [], recursive: false, before: "No AI", target: null }]);
  const { doc } = page({ "mandu.files.pending": waiting });
  await tick();
  const row = () => ([...doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).find((r) => r.getAttribute("data-path") === "/home/u/proj/deploy.token");
  row().querySelector(".file-more").click();
  await tick();
  assert.ok(row().classList.contains("open"));
  const listed = () => ([...doc.querySelectorAll("#files-pending-list li")] as any[]).map((li) => li.querySelector("code")?.textContent);
  assert.deepEqual(listed(), ["~/proj/deploy.token"]);
  await type(doc, "2222");
  assert.equal(row(), undefined, "hidden");
  assert.equal(doc.getElementById("files-pending").hidden, false, "Changes to save is not narrowed");
  assert.deepEqual(listed(), ["~/proj/deploy.token"]);
  await type(doc, "");
  assert.equal(row().classList.contains("open"), false, "it was closed with it");
});

test("§4.25f Find a rule: a page change empties the box", async () => {
  const { doc } = page();
  await tick();
  await type(doc, "2222");
  (doc.querySelector('#nav [data-page-link="settings"]') as any).click();
  await tick();
  (doc.querySelector('#nav [data-page-link="rules"]') as any).click();
  await tick();
  assert.equal(box(doc).value, "");
  assert.equal(count(doc), "7");
  assert.equal(doc.defaultView.location.search, "", "never in the address");
});

test("§4.25f Find a rule: the box is between the heading and Add a rule, and goes under the heading on a phone", () => {
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  assert.match(css, /\.rules-find \{[^}]*flex: 0 1 260px;[^}]*min-width: 0;/);
  assert.match(css, /@media \(max-width: 560px\) \{ \.rules-find \{ order: 3; flex: 1 1 100%; \} \}/);
  assert.match(css, /#rules-block > \.block-head \{ flex-wrap: wrap;/);
  const html = readFileSync(join(PUB, "index.html"), "utf8");
  assert.ok(html.indexOf('id="rules-title"') < html.indexOf('id="rules-find"') && html.indexOf('id="rules-find"') < html.indexOf('id="rules-add"'));
});
