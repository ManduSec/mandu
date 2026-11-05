/**
 * home-js-rules-find.test — Rules › Your rules' *Find a rule* box
 * (dashboard.md §4.25f *Find a rule*), in jsdom over the fetch stub of
 * home-js-fixtures.ts: typing keeps only the rows whose drawn words hold
 * the text (a file by its `~/…` path, its Opens it programs and its hosts;
 * a send rule by its host and file; a connection by its address and port),
 * the tree keeps and opens the folders on the way to each match, a group
 * with none is not drawn, the count says "3 of 27", nothing found says so
 * with Clear, Escape and a page change empty the box, a redraw keeps it,
 * Changes to save is never narrowed, and no read is made for it, except one:
 * a full path no row holds is asked of files/why, once typing stops, and the
 * line under it says which rule or built-in covers it (#209).
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
  plain: { subject: path, reach: covers === "subtree" ? "and everything inside" : "this file only", effect: "No AI", opens: "Programs get a masked copy.", opensDefault: true, ...plain },
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
  lockRow("/home/u/proj/.env", "exact", { bindings: ["api.stripe.com"] }, { effect: "No AI; may be sent to api.stripe.com", opens: "docker-compose (your word) may open the real file. Other programs are refused.", opensDefault: false }),
  lockRow("/home/u/proj/deploy.token", "exact"),
  lockRow("/home/u/.ssh", "subtree", {}, { opens: "ssh (checked by Mandu) may open the real file. Other programs get a masked copy.", opensDefault: false }),
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

test("§4.25p Find a rule: a default row's Opens it words, not drawn, are not matched; a drawn line still is", async () => {
  const { doc } = page();
  await tick();
  // Three rules have no readers: (their words are "Programs get a masked
  // copy.", drawn once under the caption); only ~/.ssh draws "masked".
  await type(doc, "masked");
  assert.deepEqual(tree(doc), ["0 ~/.ssh"]);
  assert.equal(count(doc), "1 of 7");
  await type(doc, "docker-compose");
  assert.deepEqual(tree(doc), ["0 folder ~/proj/", "1 .env"], "a program its rule names");
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
  // files/why could not answer: the full path keeps the plain offer.
  const { doc, calls, fire } = covering({ "GET policy/panel": PANEL, [whyRoute("~/ws/config")]: { status: 503, body: { error: "unreachable" } } });
  await tick();
  const before = calls.length;
  await type(doc, "stripe-live");
  assert.equal(none(doc).hidden, false);
  assert.equal(none(doc).querySelectorAll("p").length, 1, "not a path: no Add a rule line");
  assert.equal(count(doc), "0 of 7");
  assert.deepEqual(calls.slice(before).map((c) => c.url), [], "typing text that is not a full path reads nothing");
  await type(doc, "~/ws/config");
  await fire();
  const lines = [...none(doc).querySelectorAll("p")] as any[];
  assert.equal(lines.length, 2);
  assert.equal(lines[0].textContent, "No rule mentions “~/ws/config”. Clear");
  assert.equal(lines[1].textContent, "To make one, add a rule.");
  assert.deepEqual(calls.slice(before).map((c) => c.url), ["/mandu/api/files/why?path=" + encodeURIComponent("~/ws/config")], "a full path no row holds: exactly one files/why read");
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

// ── A path no rule names says what covers it (§4.25f, #209) ─────────────────

/** A pattern rule of yours, for the line that names one. */
const PEM = lockRow("/home/u/**/*.pem", "subtree");
const COVER_PANEL = { panel: { ...PANEL.panel, yourRules: [...PANEL.panel.yourRules, PEM] } };
const whyRoute = (path: string) => `GET files/why?path=${encodeURIComponent(path)}`;
/** files/why's answer for a path, its label as fileLabel words it. */
const whyOf = (path: string, label: Record<string, unknown>, off = false) => ({
  why: { path, display: path, label: { level: "no-model", levelClass: "strict", words: "No AI", bindings: [], removable: false, ...label }, off, lines: [] },
});
/**
 * The Rules page with the Find delay (400 ms) held until `fire()`, and
 * files/why answers held until `release()` while `hold` is set.
 */
function covering(routes: Record<string, unknown> = {}) {
  const later = new Map<number, () => void>();
  const held: Array<() => void> = [];
  const ctl = { hold: false };
  let id = 1_000_000;
  const r = load({ url: RULES, routes: { ...ROUTES, "GET policy/panel": COVER_PANEL, ...routes }, before: (w: any) => {
    const st = w.setTimeout;
    const ct = w.clearTimeout;
    w.setTimeout = (fn: () => void, ms?: number, ...a: unknown[]) => (ms === 400 ? (later.set(++id, fn), id) : st(fn, ms, ...a));
    w.clearTimeout = (i: number) => (later.has(i) ? later.delete(i) : ct(i));
    const f0 = w.fetch;
    w.fetch = (url: string, init?: unknown) => (ctl.hold && url.includes("/files/why")
      ? new Promise((res) => held.push(() => res(f0(url, init))))
      : f0(url, init));
  } });
  return {
    ...r, ctl,
    waiting: () => later.size,
    fire: async () => { const fns = [...later.values()]; later.clear(); for (const f of fns) f(); await tick(); },
    release: async () => { for (const f of held.splice(0)) f(); await tick(); },
    reads: () => r.calls.filter((c) => c.url.includes("/api/files/why")).map((c) => decodeURIComponent(c.url.split("path=")[1])),
  };
}
const lines = (doc: any) => ([...none(doc).querySelectorAll("p")] as any[]).map((p) => p.textContent);

test("§4.25f A path no rule names: a folder rule above it says so, and Show that rule puts that rule in the box, its row open", async () => {
  const p = covering({ [whyRoute("~/.ssh/known_hosts")]: whyOf("/home/u/.ssh/known_hosts", { source: "inherited", from: "From your rule on ~/.ssh", via: "/home/u/.ssh" }) });
  await tick();
  await type(p.doc, "~/.ssh/known_hosts");
  assert.deepEqual(lines(p.doc), ["No rule mentions “~/.ssh/known_hosts”. Clear", "Checking what covers it…"]);
  assert.deepEqual(p.reads(), [], "not before typing stops");
  await p.fire();
  assert.deepEqual(p.reads(), ["~/.ssh/known_hosts"], "one read, of the path as typed");
  const call = p.calls.find((c) => c.url.includes("/api/files/why"))!;
  assert.equal(call.headers["X-Mandu-Control"], "1", "the page's control read, as the browser's Why");
  assert.deepEqual(lines(p.doc), [
    "No rule mentions “~/.ssh/known_hosts”. Clear",
    "Your rule on ~/.ssh covers it: No AI. Show that rule",
    "To give it a rule of its own, add a rule.",
  ]);
  assert.equal(none(p.doc).getAttribute("role"), "status", "said to a screen reader");
  const show = ([...none(p.doc).querySelectorAll("button")] as any[]).find((b) => b.textContent === "Show that rule");
  show.click();
  await tick();
  assert.equal(box(p.doc).value, "~/.ssh");
  assert.deepEqual(tree(p.doc), ["0 ~/.ssh", "1 config"], "the deciding rule is drawn");
  const row = ([...p.doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).find((r) => r.getAttribute("data-path") === "/home/u/.ssh");
  assert.ok(row.classList.contains("open"), "its row opened");
  assert.equal(p.doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
  assert.equal(none(p.doc).hidden, true);
  assert.deepEqual(p.reads(), ["~/.ssh/known_hosts", "/home/u/.ssh"], "Find reads nothing more; the opened row reads its own What the rules say");
});

test("§4.25f A path no rule names: a pattern, a built-in, a file made from a secret, a model's key, and nothing", async () => {
  const p = covering({
    [whyRoute("~/certs/server.pem")]: whyOf("/home/u/certs/server.pem", { source: "pattern", from: "Matches your rule ~/**/*.pem", via: "/home/u/**/*.pem" }),
    [whyRoute("~/.aws/credentials")]: whyOf("/home/u/.aws/credentials", { source: "builtin", from: "Built in: AWS credentials", via: "builtin:aws" }),
    [whyRoute("~/ws/out.txt")]: whyOf("/home/u/ws/out.txt", { source: "written", from: "Made from a secret: something that held a secret wrote it", via: null }),
    [whyRoute("~/.config/mandu/models/key")]: whyOf("/home/u/.config/mandu/models/key", { source: "model-key", from: "The key for a model in Settings › Models", via: "/home/u/.config/mandu/models/key" }),
    [whyRoute("~/ws/plain.txt")]: whyOf("/home/u/ws/plain.txt", { source: "none", from: "", via: null, level: "public", words: "Like any other file" }),
  });
  await tick();
  const say = async (path: string) => { await type(p.doc, path); await p.fire(); return lines(p.doc).slice(1); };
  assert.deepEqual(await say("~/certs/server.pem"), ["It matches your rule ~/**/*.pem: No AI. Show that rule", "To give it a rule of its own, add a rule."]);
  ([...none(p.doc).querySelectorAll("button")] as any[]).find((b) => b.textContent === "Show that rule").click();
  await tick();
  assert.equal(box(p.doc).value, "~/**/*.pem");
  assert.ok(tree(p.doc).some((t) => t.endsWith("*.pem")), "the pattern's row is drawn");

  assert.deepEqual(await say("~/.aws/credentials"), ["Mandu keeps it secret without a rule (Built in: AWS credentials): No AI. See Built-in protections", "To give it a rule of its own, add a rule."]);
  const builtin = none(p.doc).querySelector("a");
  assert.equal(builtin.getAttribute("href"), "/mandu/rules#built-in");

  assert.deepEqual(await say("~/ws/out.txt"), ["Mandu keeps it secret because something holding a secret wrote it. See Files made from your secrets", "To give it a rule of its own, add a rule."]);
  assert.equal(none(p.doc).querySelector("a").getAttribute("href"), "/mandu/rules#made-from");

  assert.deepEqual(await say("~/.config/mandu/models/key"), ["It is the key of a model in Settings › Models. Open Settings › Models", "To give it a rule of its own, add a rule."]);
  const models = none(p.doc).querySelector("a");
  assert.equal(models.getAttribute("href"), "/mandu/settings#models");

  assert.deepEqual(await say("~/ws/plain.txt"), ["No rule and no built-in protection covers it. To protect it, add a rule."], "nothing covers it: the offer is the line");
  assert.equal(none(p.doc).querySelectorAll("button").length, 2, "Clear and add a rule");
  assert.deepEqual(p.reads(), ["~/certs/server.pem", "~/.aws/credentials", "~/ws/out.txt", "~/.config/mandu/models/key", "~/ws/plain.txt"]);

  // Open Settings › Models goes there, as the section link does.
  await say("~/.config/mandu/models/key");
  none(p.doc).querySelector("a").click();
  await tick();
  assert.equal(p.doc.defaultView.location.pathname, "/mandu/settings");
});

test("§4.25f A path no rule names: See Built-in protections goes to that card on Rules", async () => {
  const p = covering({ [whyRoute("~/.aws/credentials")]: whyOf("/home/u/.aws/credentials", { source: "builtin", from: "Built in: AWS credentials", via: "builtin:aws" }) });
  await tick();
  await type(p.doc, "~/.aws/credentials");
  await p.fire();
  none(p.doc).querySelector("a").click();
  await tick();
  assert.equal(p.doc.defaultView.location.pathname, "/mandu/rules", "the page stays");
  assert.equal(p.doc.defaultView.location.hash, "#built-in", "at the card's section");
});

test("§4.25f A path no rule names: with protection off, the line says none of it is enforced now", async () => {
  const p = covering({
    [whyRoute("~/.ssh/known_hosts")]: whyOf("/home/u/.ssh/known_hosts", { source: "inherited", from: "From your rule on ~/.ssh", via: "/home/u/.ssh" }, true),
    [whyRoute("~/ws/plain.txt")]: whyOf("/home/u/ws/plain.txt", { source: "none", from: "", via: null, level: "public", words: "Like any other file" }, true),
  });
  await tick();
  await type(p.doc, "~/.ssh/known_hosts");
  await p.fire();
  assert.equal(lines(p.doc)[1], "Your rule on ~/.ssh covers it: No AI. Show that rule Protection is off, so none of this is enforced now.");
  await type(p.doc, "~/ws/plain.txt");
  await p.fire();
  assert.equal(lines(p.doc)[1], "No rule and no built-in protection covers it. To protect it, add a rule. Protection is off, so none of this is enforced now.");
});

test("§4.25f A path no rule names: two quick edits send one read, and an answer for text no longer in the box is dropped", async () => {
  const p = covering({
    [whyRoute("~/ws/b")]: whyOf("/home/u/ws/b", { source: "inherited", from: "From your rule on ~/.ssh", via: "/home/u/.ssh" }),
    [whyRoute("~/ws/bc")]: whyOf("/home/u/ws/bc", { source: "none", from: "", via: null, level: "public", words: "Like any other file" }),
    [whyRoute("~/ws/bcd")]: whyOf("/home/u/ws/bcd", { source: "builtin", from: "Built in: SSH keys", via: "builtin:ssh" }),
  });
  await tick();
  await type(p.doc, "~/ws/a");
  await type(p.doc, "~/ws/b");
  assert.equal(p.waiting(), 1, "one read waits");
  await p.fire();
  assert.deepEqual(p.reads(), ["~/ws/b"], "the first text was never read");
  // A read out while typing goes on: its answer is not drawn for new text.
  p.ctl.hold = true;
  await type(p.doc, "~/ws/bc");
  await p.fire();
  await type(p.doc, "~/ws/bcd");
  await p.release();
  assert.deepEqual(lines(p.doc).slice(1), ["Checking what covers it…"], "~/ws/bc's answer dropped");
  p.ctl.hold = false;
  await p.fire();
  assert.match(lines(p.doc)[1], /^Mandu keeps it secret without a rule \(Built in: SSH keys\)/);
  // Emptying the box drops a read still waiting.
  await type(p.doc, "~/ws/bcde");
  await type(p.doc, "");
  assert.equal(p.waiting(), 0);
  assert.deepEqual(p.reads(), ["~/ws/b", "~/ws/bc", "~/ws/bcd"]);
});

test("§4.25f A path no rule names: a refused read (401, 503) leaves the plain lines, no error; text that is not a full path reads nothing", async () => {
  const p = covering({
    [whyRoute("~/ws/a")]: { status: 401, body: { error: "admin session required" } },
    [whyRoute("/srv/b")]: { status: 503, body: { error: "unreachable" } },
  });
  await tick();
  for (const path of ["~/ws/a", "/srv/b"]) {
    await type(p.doc, path);
    await p.fire();
    assert.deepEqual(lines(p.doc), [`No rule mentions “${path}”. Clear`, "To make one, add a rule."]);
    assert.equal(none(p.doc).querySelector(".ask-error"), null);
  }
  const before = p.reads().length;
  for (const text of ["paste.example.org", "stripe-live", ".env", "~/ws/*.key", "**/*.key", "~/ws/[ab]", "ssh-agent"]) {
    await type(p.doc, text);
    assert.equal(p.waiting(), 0, `${text}: no read waits`);
  }
  assert.equal(p.reads().length, before, "nothing read for text that is not a full path");
});

// ── An empty Your rules has nothing to find (#141) ──────────────────────────
// With no rule of any kind (or Your rules unread) the box is hidden and the
// tree's column heads are not drawn over the line that says so; the box is
// never hidden while it holds text or has the focus, and is left as drawn
// until the first read answers.

const EMPTY = { panel: { available: true, verdictsKnown: true, yourRules: [], queue: [] } };
const NO_LABELS = { panel: { labels: [] } };
/** Rules over a policy/panel route that answers `panels` in turn (the last
 *  one again after). */
function rulesOf(...panels: unknown[]) {
  let i = 0;
  return load({ url: RULES, routes: { ...ROUTES, "GET secrets": NO_LABELS, "GET policy/panel": () => panels[Math.min(i++, panels.length - 1)],
    "POST policy/rules/change": { applied: true, changeId: "c1" } } });
}
const heads = (doc: any) => doc.getElementById("files-heads");
const treeLine = (doc: any) => doc.getElementById("files-tree").textContent;
const SEND_ONLY = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  { ...sendRow("r-0001", "api.github.com", "sending ~/proj/deploy.token from any source") },
] } };
const ONE_FILE = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [lockRow("/home/u/proj/.env", "exact")] } };
/** A change made on the page (the send rule turned around from its menu):
 *  Rules reads its rules again. */
async function flipSend(doc: any) {
  const sel = doc.querySelector("#rules-list .row.rule select.effect-select");
  sel.focus();
  sel.value = "flip";
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick();
}

test("§4.25f An empty Your rules (#141): no rule, so no column heads over the empty line and no Find a rule box; Add a rule stays", async () => {
  const { doc, err } = rulesOf(EMPTY);
  await tick();
  assert.equal(err, null);
  assert.equal(heads(doc).hidden, true, "no heads over the empty line");
  assert.equal(doc.getElementById("files-group").hidden, false, "the group's title stays");
  assert.match(treeLine(doc), /^No file or folder has a rule of yours yet\. Add a rule to mark one secret\.$/);
  assert.equal(box(doc).hidden, true, "nothing to find");
  assert.ok(box(doc).isConnected, "hidden, not removed");
  assert.equal(doc.getElementById("rules-add").hidden, false);
  assert.equal(count(doc), "");
});

test("§4.25f An empty Your rules (#141): unread, the heads and the box are hidden over the could-not-be-read line", async () => {
  const { doc } = rulesOf({ status: 503, body: { error: "unavailable" } });
  await tick();
  assert.match(treeLine(doc), /Your rules could not be read/);
  assert.equal(heads(doc).hidden, true);
  assert.equal(doc.getElementById("files-group").hidden, false, "the group's title stays");
  assert.equal(box(doc).hidden, true, "it could find nothing");
});

test("§4.25f An empty Your rules (#141): one file rule draws the heads and the box", async () => {
  const { doc } = rulesOf(ONE_FILE);
  await tick();
  assert.equal(heads(doc).hidden, false);
  assert.equal(box(doc).hidden, false);
  assert.deepEqual(tree(doc), ["0 ~/proj/.env"]);
});

test("§4.25f An empty Your rules (#141): a send rule and no file rule shows the box, with no heads over the empty file line", async () => {
  const { doc } = rulesOf(SEND_ONLY);
  await tick();
  assert.equal(box(doc).hidden, false, "a rule to find");
  assert.equal(heads(doc).hidden, true, "no heads over the empty file line");
  assert.match(treeLine(doc), /^No file or folder has a rule of yours yet\./);
  assert.deepEqual(rest(doc), ["Sending data: api.github.com"]);
});

test("§4.25f An empty Your rules (#141): a box with text keeps its text and No rule mentions when the last rule goes", async () => {
  const { doc } = rulesOf(SEND_ONLY, EMPTY);
  await tick();
  await type(doc, "github");
  assert.deepEqual(rest(doc), ["Sending data: api.github.com"]);
  await flipSend(doc);
  // The change's own refocus leaves the box; its text keeps it.
  assert.notEqual(doc.activeElement, box(doc));
  assert.equal(count(doc), "", "no rule left");
  assert.equal(box(doc).hidden, false, "never hidden while it holds text");
  assert.equal(box(doc).value, "github");
  assert.match(none(doc).textContent, /^No rule mentions “github”\. Clear/);
  // Clear empties it in place: the focus goes to the box, which stays.
  ([...none(doc).querySelectorAll("button")] as any[]).find((b) => b.textContent === "Clear").click();
  await tick();
  assert.equal(box(doc).value, "");
  assert.equal(doc.activeElement, box(doc), "Clear gives the focus to the box");
  assert.equal(box(doc).hidden, false, "a focused box stays");
});

test("§4.25f An empty Your rules (#141): a focused box emptied in place stays; the next draw without the focus hides it", async () => {
  const { doc, window } = rulesOf(SEND_ONLY, EMPTY);
  await tick();
  await type(doc, "github");
  await flipSend(doc);
  await type(doc, "");
  assert.equal(doc.activeElement, box(doc));
  assert.equal(box(doc).hidden, false, "focused: it stays");
  box(doc).blur();
  window.renderRules();
  assert.equal(box(doc).hidden, true, "empty and not focused, with no rule: hidden");
});

test("§4.25f An empty Your rules (#141): a re-read that brings the first rule shows the box, the focus where it was", async () => {
  const { doc, window } = rulesOf(EMPTY, ONE_FILE);
  await tick();
  assert.equal(box(doc).hidden, true);
  assert.equal(heads(doc).hidden, true);
  const add = doc.getElementById("rules-add");
  add.focus();
  await window.loadRules();
  await tick();
  assert.equal(box(doc).hidden, false, "shown with the first rule");
  assert.equal(heads(doc).hidden, false, "the heads too");
  assert.equal(doc.activeElement, add, "the focus is not moved");
});

test("§4.25f An empty Your rules (#141): the box is left as drawn while the first read is out", async () => {
  let answer: (v: unknown) => void = () => {};
  const held = new Promise((r) => { answer = r; });
  const { doc, window } = load({ url: RULES, routes: { ...ROUTES, "GET secrets": NO_LABELS }, before: (w: any) => {
    const real = w.fetch;
    w.fetch = (url: string, init?: unknown) => (String(url).endsWith("/api/policy/panel") ? held.then(() => real(url, init)) : real(url, init));
  } });
  await tick();
  // A draw before the first answer (nothing read yet, so no row): no blink.
  window.renderRules();
  assert.equal(box(doc).hidden, false, "not hidden before the read answers");
  answer(null);
  await tick();
  // ROUTES' panel has rules: still shown.
  assert.equal(box(doc).hidden, false);
});
