/**
 * home-js-rule-changes-find.test — dashboard.md §4.25 *Finding a rule change*.
 * Approvals › Rule changes, where every rule change can be undone, could
 * only be paged: the change to undo had to be found by pressing Show more
 * and reading every row. Now a box above the list ("Find a change") keeps
 * the changes whose words hold every word typed, case aside, matched on the
 * page over one read of the newest 500 (`policy/changes?limit=500`):
 *
 *   F1  no change: no box; one change: the box;
 *   F2  "stripe" keeps the rows naming `api.stripe.com`: one read of the
 *       newest 500 when the search starts, none for the keys after it; the
 *       count "10 of 41 changes match", `?changes=` in the address (replaced),
 *       the focus kept in the box; two words must both match;
 *   F3  the agent Home names for the session of a change, and its folder as
 *       `~/…`, match ("claude ws"); a session Home does not list does not;
 *   F4  "undone" finds an undone change;
 *   F5  none found: "No change matches “pastebin”." with Clear, which empties
 *       the box and the address and lists the newest 20 with no read;
 *       Escape in the box does the same;
 *   F6  `?changes=` on load fills the box and lists the matches; a link to
 *       one change (`/approvals/<pc-…>`) starts with no search; past 500
 *       the count says "of the newest 500 changes";
 *   F7  a poll with the same read draws nothing again (the rows stay the
 *       same elements, the focus in the box); Undo on a found row works and
 *       the row stays found, now "Undone";
 *   F8  Show more under a search draws the next 20 matches from the read
 *       kept, with no read;
 *   F9  on Rules, an opened file rule whose origin names a recorded change
 *       has "Find its changes" after "See this change in Approvals":
 *       `/approvals?changes=<its ~/ path>#rule-changes`, a grouped row's
 *       full path (not the leaf it draws); no record or a program
 *       (`app:`) row has none;
 *   F10 a click opens Approvals with the box holding the path, only the
 *       matching changes and the count; Back returns to Rules; an ordinary
 *       link to Approvals still opens the search empty.
 *   F11 *None found is said*: while a search finds none, the status line
 *       holds the list's "No change matches “…”." (no Clear), `.sr-only`
 *       and not hidden, so a screen reader announces it; a poll that brings
 *       a new change and still finds none leaves its text node as it was
 *       (no second announcement); a search that finds some shows the count,
 *       seen; Clear empties the line and hides it.
 *   F12 a send rule to one host links "Find its changes" searched for that
 *       host (`pastebin.com`), and a connection rule for its host alone
 *       (`pypi.org:443` searches `pypi.org`, so a change made with no port
 *       is found too), each named by its row; following one lands on Rule
 *       changes with the box filled and only the matching rows. None for a
 *       send to anywhere, a send to two hosts, a connection to any address,
 *       a built-in protection, a program, or a rule with no recorded origin.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rule-changes-find.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, opened, tick, treeRow } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

const URL = "http://127.0.0.1:4500/mandu/approvals";
const T = (text: string) => ({ kind: "text", text });
const C = (text: string) => ({ kind: "code", text });
const id = (i: number) => "pc-" + String(1000 - i).padStart(6, "0");
/** Change `i`: every fourth lets a send to api.stripe.com, the rest make a file secret. */
const change = (i: number, over: Record<string, unknown> = {}) => ({
  id: id(i), sentence: "You changed a rule on the Rules page", session: null, createdAt: Date.now() - (i + 1) * 60_000, undone: false, undoable: true,
  rows: i % 4 === 0
    ? [[T("Always allow sending to "), C("api.stripe.com")]]
    : [[T("Make "), C(`~/proj/f${i}.pem`), T(" a secret no AI may read")]],
  ...over,
});
const ALL = Array.from({ length: 41 }, (_, i) => change(i));
const STRIPE = ALL.filter((_, i) => i % 4 === 0);
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });
const routesFor = (all: unknown[]) => ({
  "GET policy/proposals?status=pending": { proposals: [] },
  "GET policy/changes?limit=21": () => ({ changes: all.slice(0, 21) }),
  "GET policy/changes?limit=500": () => ({ changes: all.slice(0, 500) }),
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rows = (doc: Doc) => [...doc.querySelectorAll("#approvals-rule-history .row.answered")] as Doc[];
const ids = (doc: Doc) => rows(doc).map((r) => r.dataset.id);
const form = (doc: Doc) => doc.getElementById("changes-search");
const box = (doc: Doc) => doc.getElementById("changes-q");
const count = (doc: Doc) => doc.getElementById("changes-count");
const empty = (doc: Doc) => doc.querySelector("#approvals-rule-history .empty");
const more = (doc: Doc) => doc.querySelector("#approvals-rule-history .changes-more button.show-rest");
const reads = (calls: Array<{ url: string }>, limit: number) => calls.filter((c) => c.url === "/mandu/api/policy/changes?limit=" + limit).length;
const type = (doc: Doc, text: string) => {
  box(doc).focus();
  box(doc).value = text;
  box(doc).dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
};
const settle = async () => { await new Promise((r) => setTimeout(r, 300)); await tick(40); };
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("F1: no change, no box; one change, the box", async () => {
  const none = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor([]) });
  await tick(40);
  assert.equal(form(none.doc).hidden, true, "nothing to find");
  const one = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor([change(1)]) });
  await tick(40);
  const f = form(one.doc);
  assert.equal(f.hidden, false);
  assert.equal(f.getAttribute("role"), "search");
  assert.ok(f.classList.contains("history-search") && f.classList.contains("answered-search"), "the classes of Find an answer");
  assert.equal(one.doc.querySelector('label[for="changes-q"]').textContent, "Find a change");
  assert.equal(box(one.doc).getAttribute("placeholder"), "A file, a host or the agent");
  assert.ok(f.nextElementSibling === one.doc.getElementById("approvals-rule-history"), "above the rows");
  assert.equal(count(one.doc).hidden, true, "no count without a search");
});

test("F2: 'stripe' keeps the rows naming api.stripe.com; one read of 500, then none; the count, the address, the focus; two words must both match", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.equal(rows(doc).length, 20);
  const entries = window.history.length;
  type(doc, "str");
  type(doc, "STRIPE");
  await settle();
  assert.equal(reads(calls, 500), 1, "one read of the newest 500 once the typing stopped");
  assert.deepEqual(ids(doc), STRIPE.map((c) => c.id), "only the changes naming api.stripe.com, case aside");
  assert.equal(count(doc).hidden, false);
  assert.equal(count(doc).textContent, "11 of 41 changes match");
  assert.equal(count(doc).getAttribute("role"), "status");
  assert.equal(more(doc), null, "every match drawn: no Show more");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?changes=STRIPE");
  assert.equal(window.history.length, entries, "the address is replaced, not pushed");
  assert.equal(doc.activeElement, box(doc), "the focus stays in the box");
  for (const r of rows(doc)) assert.ok([...r.querySelectorAll("button")].some((b: Doc) => b.textContent === "Undo"), "each found row keeps its Undo");
  // Two words: both must match, in any order; the keys after the first search read nothing.
  type(doc, "allow stripe");
  await settle();
  assert.equal(ids(doc).length, STRIPE.length);
  type(doc, "stripe f4.pem");
  await settle();
  assert.equal(rows(doc).length, 0, "no row names both");
  type(doc, "f13 secret");
  await settle();
  assert.deepEqual(ids(doc), [id(13)]);
  assert.equal(count(doc).textContent, "1 of 41 changes matches");
  assert.equal(reads(calls, 500), 1, "the read kept is matched again, never read per search");
});

test("F3: the agent Home names, and its folder, match; a session Home does not list does not", async () => {
  const named = { before: "", after: " tightened your rules" };
  const list = [
    change(1, { who: "agent", session: "s1", sentence: "Your agent tightened your rules", named }),
    change(2, { who: "agent", session: "s9", sentence: "Your agent tightened your rules", named }),
    change(3),
  ];
  const { doc } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(list) });
  await tick(40);
  await poll(doc);
  type(doc, "claude");
  await settle();
  assert.deepEqual(ids(doc), [id(1)], "Claude Code, as Home names session s1");
  assert.match(rows(doc)[0].textContent, /^Claude Code tightened your rules/);
  type(doc, "claude ~/ws");
  await settle();
  assert.deepEqual(ids(doc), [id(1)], "its folder as ~/ws");
  type(doc, "your agent");
  await settle();
  assert.deepEqual(ids(doc), [id(2)], "the session Home does not list keeps the words of the server");
});

test("F4: 'undone' finds an undone change", async () => {
  const list = [change(1), change(2, { undone: true, undoable: false }), change(3)];
  const { doc } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(list) });
  await tick(40);
  type(doc, "undone");
  await settle();
  assert.deepEqual(ids(doc), [id(2)]);
  assert.match(rows(doc)[0].textContent, /Undone/);
});

test("F5: none found says so with Clear, which empties the box and the address and lists the newest 20; Escape does the same", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  type(doc, "pastebin");
  await settle();
  assert.equal(rows(doc).length, 0);
  assert.equal(empty(doc).textContent, "No change matches “pastebin”. Clear");
  assert.equal(count(doc).hidden, false, "the status line says it too");
  assert.equal(count(doc).classList.contains("sr-only"), true, "to a screen reader only: on screen the list says so");
  assert.equal(count(doc).textContent, "No change matches “pastebin”.");
  assert.equal(doc.getElementById("approvals-rule-history-block").hidden, false, "the list stays, with its box");
  const r500 = reads(calls, 500);
  empty(doc).querySelector("button.history-clear").click();
  await tick(40);
  assert.equal(box(doc).value, "");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals");
  assert.deepEqual(ids(doc), ALL.slice(0, 20).map((c) => c.id), "the newest 20 again");
  assert.ok(more(doc), "with Show more");
  assert.equal(reads(calls, 500), r500, "with no read");
  assert.equal(doc.activeElement, box(doc), "the box has the focus");
  // Escape in the box: the same.
  type(doc, "pastebin");
  await settle();
  assert.equal(rows(doc).length, 0);
  const esc = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  box(doc).dispatchEvent(esc);
  await tick(40);
  assert.equal(esc.defaultPrevented, true, "Escape taken by the box");
  assert.equal(box(doc).value, "");
  assert.equal(window.location.search, "");
  assert.equal(rows(doc).length, 20);
  // An empty box leaves Escape alone.
  const again = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  box(doc).dispatchEvent(again);
  assert.equal(again.defaultPrevented, false);
});

test("F6: ?changes= on load fills the box; a link to one change has no search; past 500 the count says the newest 500", async () => {
  const { doc, calls } = load({ extensions: "", url: URL + "?q=x&changes=stripe", homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.equal(box(doc).value, "stripe", "the box shows the address's search");
  assert.equal(doc.getElementById("answered-q").value, "x", "beside the search of Answered earlier");
  assert.equal(doc.defaultView.location.search, "?q=x&changes=stripe");
  assert.ok(reads(calls, 500) >= 1, "the newest 500 read (the load and its first poll)");
  assert.equal(reads(calls, 21), 0, "never the newest 21 of a list with no search");
  assert.deepEqual(ids(doc), STRIPE.map((c) => c.id), "the matches, never the newest 20 first");
  assert.equal(count(doc).textContent, "11 of 41 changes match");
  // A link to Approvals starts without the search.
  (doc.querySelector('[data-page-link="home"]') as Doc).click();
  await tick(40);
  (doc.querySelector('[data-page-link="approvals"]') as Doc).click();
  await tick(40);
  assert.equal(box(doc).value, "");
  assert.equal(rows(doc).length, 20);
  assert.equal(doc.defaultView.location.search, "");

  // An address that opens one change has no search, so its row is drawn and marked.
  const marked = load({ extensions: "", url: URL + "/" + id(3) + "?changes=stripe", homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.equal(box(marked.doc).value, "");
  const row = rows(marked.doc).find((r) => r.dataset.id === id(3));
  assert.ok(row && row.classList.contains("focus"), "the change is marked");
  // Typing a search there drops the change from the address, and its mark.
  type(marked.doc, "stripe");
  await settle();
  assert.equal(marked.window.location.pathname + marked.window.location.search, "/mandu/approvals?changes=stripe");
  assert.equal(marked.doc.querySelector("#page-approvals .focus"), null, "no mark left");

  // 600 on record, of which the route gives the newest 500.
  const many = Array.from({ length: 600 }, (_, i) => change(i));
  const big = load({ extensions: "", url: URL + "?changes=stripe", homeVm: quiet(), routes: routesFor(many) });
  await tick(40);
  assert.equal(count(big.doc).textContent, "125 of the newest 500 changes match");
  assert.equal(rows(big.doc).length, 20, "the newest 20 matches");
});

test("F7: a poll with the same read draws nothing again; Undo on a found row works and the row stays found", async () => {
  let all = ALL.slice();
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: quiet(), routes: {
    ...routesFor([]),
    "GET policy/changes?limit=21": () => ({ changes: all.slice(0, 21) }),
    "GET policy/changes?limit=500": () => ({ changes: all }),
    [`POST policy/changes/${id(8)}/undo`]: () => ((all = all.map((c) => (c.id === id(8) ? { ...c, undone: true, undoable: false } : c))), {}),
  } });
  await tick(40);
  type(doc, "stripe");
  await settle();
  const before = rows(doc);
  const r500 = reads(calls, 500);
  await poll(doc);
  assert.ok(reads(calls, 500) > r500, "the poll reads the 500 the search matches");
  assert.deepEqual(rows(doc), before, "the same elements: nothing drawn again");
  assert.equal(doc.activeElement, box(doc), "the focus stays in the box");
  assert.equal(doc.defaultView.location.search, "?changes=stripe");
  // Undo on a found row.
  const row = rows(doc).find((r) => r.dataset.id === id(8));
  const undo = [...row.querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
  undo.click();
  await tick(60);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === `/mandu/api/policy/changes/${id(8)}/undo`));
  const after = rows(doc).find((r) => r.dataset.id === id(8));
  assert.ok(after, "still found");
  assert.match(after.textContent, /Undone/);
  assert.equal(ids(doc).length, STRIPE.length, "the search still holds");
});

test("F8: Show more under a search draws the next 20 matches from the read kept, with no read", async () => {
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  type(doc, "secret");
  await settle();
  const matches = ALL.filter((_, i) => i % 4 !== 0);
  assert.equal(rows(doc).length, 20);
  assert.equal(count(doc).textContent, `${matches.length} of 41 changes match`);
  const said = doc.getElementById(more(doc).getAttribute("aria-describedby"));
  assert.equal(said.textContent, `Showing 20 of ${matches.length} changes that match.`);
  const r500 = reads(calls, 500);
  const r21 = reads(calls, 21);
  more(doc).click();
  await tick(40);
  assert.deepEqual(ids(doc), matches.map((c) => c.id));
  assert.equal(doc.activeElement, rows(doc)[20], "the first new row takes the focus");
  assert.equal(reads(calls, 500), r500);
  assert.equal(reads(calls, 21), r21);
});

// ── A rule's origin line opens its changes (§4.25 *Finding a rule change*) ────

const RULES = "http://127.0.0.1:4500/mandu/rules";
const FIND = "Find its changes";
const lock = (path: string, covers: string, reach: string | null) => ({
  id: `lock:${path}`, kind: "lock", subject: path, covers, effect: "x", reach, hits: null, level: "no-model", bindings: [], actions: { remove: true, flip: null },
  plain: { subject: path, reach, effect: "No AI may read it" },
});
const RULE_PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  lock("/home/u/app", "subtree", "and everything inside"),
  lock("/home/u/app/.env", "exact", null),
  lock("/home/u/old.pem", "exact", null),
  { id: "r-0001", kind: "release-allow", subject: "api.example.com", effect: "sending allowed", reach: "from any source to api.example.com", hits: 2, actions: { remove: true, flip: "block" } },
  { id: "app:psql", kind: "lock", subject: "psql", effect: "program rule", reach: null, hits: null, actions: { remove: false, flip: null } },
] } };
const recorded = (changeId: string) => ({ recorded: true, sentence: "You added this on the Rules page", at: Date.now() - 3_600_000, session: null, changedSince: false, changeId });
const ORIGINS = {
  origins: { "lock:/home/u/app": recorded("pc-000005"), "lock:/home/u/app/.env": recorded("pc-000007"), "r-0001": recorded("pc-000004"), "app:psql": recorded("pc-000002") },
  complete: true,
  unrecorded: { recorded: false, sentence: "No record of who added this", at: null, session: null, changedSince: false, changeId: null },
};
/** Seven changes: three name ~/app/.env (one of them ~/app/.env.local, which the words match too), the rest other files or a host. */
const FILE_CHANGES = [
  change(0, { rows: [[T("Make "), C("~/app/.env"), T(" a secret no AI may read")]] }),
  change(1, { rows: [[T("Make "), C("~/app/notes.md"), T(" a secret no AI may read")]] }),
  change(2, { rows: [[T("Let "), C("~/app/.env.local"), T(" be sent to "), C("api.example.com")]] }),
  change(3),
  change(4, { rows: [[T("Make "), C("~/app/.env"), T(" a secret no AI may read, and send it nowhere")]] }),
  change(5, { rows: [[T("Make "), C("~/app"), T(" and everything inside a secret")]] }),
  change(6),
];
const rulesWith = () => load({ extensions: "", url: RULES, homeVm: quiet(), routes: { "GET policy/panel": RULE_PANEL, "GET policy/rules/origins": ORIGINS, ...routesFor(FILE_CHANGES) } });
const listRow = (doc: Doc, re: RegExp) => ([...doc.querySelectorAll("#rules-list .row")] as Doc[]).find((r) => re.test(r.textContent));
const openListRule = (doc: Doc, re: RegExp) => {
  const more = listRow(doc, re).querySelector(".file-more");
  if (more.getAttribute("aria-expanded") !== "true") more.click();
  return listRow(doc, re).nextElementSibling as Doc;
};
const findLink = (line: Doc) => line.querySelector("a.change-find-link");

test("F9: an opened file rule with a recorded origin links Find its changes, by its full ~/ path; no record or a program row has none", async () => {
  const { doc } = rulesWith();
  await tick();
  // `.env` is drawn under its folder's rule as `.env`; the link names ~/app/.env.
  const env = treeRow(doc, /^\.env$/);
  assert.ok(env, "the grouped row draws its leaf name");
  env.click();
  const line = opened(doc).querySelector(".rule-origin");
  assert.match(line.textContent, /^You added this on the Rules page, .+\. See this change in Approvals · Find its changes$/);
  const a = findLink(line);
  assert.equal(a.textContent, FIND);
  assert.equal(a.getAttribute("href"), "/mandu/approvals?changes=~%2Fapp%2F.env#rule-changes", "the full path, as a change row names it");
  assert.equal(a.dataset.pageLink, "approvals");
  assert.equal(a.dataset.land, "changes:~/app/.env");
  assert.equal(a.getAttribute("aria-label"), `${FIND}: ~/app/.env`, "named by its rule");
  // The folder's rule: its own path.
  treeRow(doc, /^~\/app$/).click();
  assert.equal(findLink(opened(doc).querySelector(".rule-origin")).getAttribute("href"), "/mandu/approvals?changes=~%2Fapp#rule-changes");
  // No recorded change: no link to it, nor to find its changes.
  treeRow(doc, /old\.pem/).click();
  const none = opened(doc).querySelector(".rule-origin");
  assert.equal(none.textContent, "No record of who added this.");
  assert.equal(none.querySelector("a"), null);
  // A program's row keeps the change link alone (a send row has both: F12).
  const other = openListRule(doc, /psql/).querySelector(".rule-origin");
  assert.equal(other.querySelectorAll("a.change-link").length, 1, "its change link");
  assert.equal(findLink(other), null, "no Find its changes");
});

test("F10: Find its changes opens Approvals searched for that file, the matches and the count; Back returns to Rules; a plain link to Approvals starts empty", async () => {
  const { doc, window, calls } = rulesWith();
  await tick();
  treeRow(doc, /^\.env$/).click();
  findLink(opened(doc).querySelector(".rule-origin")).click();
  await waitWhile(() => rows(doc).length === 0 || ids(doc).length === FILE_CHANGES.length);
  await tick(40);
  assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
  assert.equal(window.location.pathname + window.location.search + window.location.hash, "/mandu/approvals?changes=~%2Fapp%2F.env#rule-changes");
  assert.equal(form(doc).hidden, false);
  assert.equal(box(doc).value, "~/app/.env", "the box holds the path");
  assert.deepEqual(ids(doc), [id(0), id(2), id(4)], "only the changes naming it (.env.local too: the search matches words)");
  assert.equal(count(doc).hidden, false);
  assert.equal(count(doc).textContent, "3 of 7 changes match");
  assert.equal(reads(calls, 500) >= 1, true, "the read a search matches");
  assert.ok(doc.getElementById("approvals-rule-history-block").contains(doc.activeElement), "it lands at Rule changes, the focus on its heading");
  // Back: Rules again.
  window.history.back();
  await waitWhile(() => window.location.pathname !== "/mandu/rules");
  await tick();
  assert.equal(doc.getElementById("page-rules").hidden, false, "Back returns to Rules");
  // A plain link to Approvals (the top bar's) opens the search empty.
  (doc.querySelector('#nav [data-page-link="approvals"]') as Doc).click();
  await tick(40);
  assert.equal(box(doc).value, "");
  assert.equal(window.location.search, "");
  assert.equal(ids(doc).length, FILE_CHANGES.length, "every change listed");
  // So does the link to one change: it is marked, never searched.
  doc.querySelector('#nav [data-page-link="rules"]').click();
  await tick();
  treeRow(doc, /^\.env$/).click();
  if (!opened(doc)) treeRow(doc, /^\.env$/).click();
  opened(doc).querySelector(".rule-origin a.change-link").click();
  await tick(40);
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals/pc-000007");
  assert.equal(box(doc).value, "");
});

test("F11: none found is said to a screen reader, once; a search that finds some shows its count; Clear empties the line", async () => {
  let all = ALL;
  const { doc } = load({ extensions: "", url: `${URL}?changes=pastebin`, homeVm: quiet(), routes: {
    ...routesFor([]),
    "GET policy/changes?limit=21": () => ({ changes: all.slice(0, 21) }),
    "GET policy/changes?limit=500": () => ({ changes: all }),
  } });
  await tick(40);
  const line = count(doc);
  assert.equal(line.textContent, "No change matches “pastebin”.");
  assert.equal(line.hidden, false, "shown, so its change is announced");
  assert.equal(line.classList.contains("sr-only"), true);
  const said = line.firstChild;
  // A new change that does not match: the list is drawn again, the line's
  // words are the same, so it is not written again.
  all = [change(-1, { rows: [[T("Make "), C("~/proj/new.pem"), T(" a secret no AI may read")]] }), ...ALL];
  await poll(doc);
  assert.equal(empty(doc).textContent, "No change matches “pastebin”. Clear");
  assert.equal(line.firstChild, said, "a poll that finds none again does not write the line again");
  type(doc, "stripe");
  await settle();
  assert.equal(line.textContent, "11 of 42 changes match");
  assert.equal(line.hidden, false);
  assert.equal(line.classList.contains("sr-only"), false, "a count is seen, as before");
  type(doc, "pastebin");
  await settle();
  assert.equal(line.classList.contains("sr-only"), true, "none again: said again");
  empty(doc).querySelector("button.history-clear").click();
  await tick(40);
  assert.equal(line.textContent, "");
  assert.equal(line.hidden, true);
  assert.equal(line.classList.contains("sr-only"), false);
});

// ── A send or connection rule opens its changes too (§4.25 *Finding a rule change*) ──

const SEND_PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  { id: "r-send", kind: "release-allow", subject: "pastebin.com", effect: "sending allowed", reach: "from any source to pastebin.com", hits: 0, actions: { remove: true, flip: "block" } },
  { id: "r-any", kind: "release-allow", subject: "anywhere", effect: "sending allowed", reach: "from docs.python.org to any destination", hits: 0, actions: { remove: true, flip: "block" },
    plain: { subject: "anywhere", subjectParts: [{ kind: "text", text: "anywhere" }], reach: "from docs.python.org", effect: "Always allowed" } },
  { id: "r-two", kind: "release-block", subject: "a.example, b.example", effect: "sending blocked", reach: "from any source to a.example, b.example", hits: 0, actions: { remove: true, flip: "allow" } },
  { id: "r-none", kind: "release-allow", subject: "unrecorded.example", effect: "sending allowed", reach: "from any source to unrecorded.example", hits: 0, actions: { remove: true, flip: "block" } },
  { id: "connect:tcp:pypi.org:443", kind: "connect-allow", subject: "pypi.org:443", effect: "the agent may connect there", reach: null, hits: null, actions: { remove: true, flip: null },
    plain: { subject: "pypi.org:443", subjectParts: [{ kind: "code", text: "pypi.org:443" }], reach: "your agent's programs connecting", effect: "Allowed" } },
  { id: "connect:tcp:*:8080", kind: "connect-allow", subject: "*:8080", effect: "the agent may connect there", reach: null, hits: null, actions: { remove: true, flip: null },
    plain: { subject: "any address on port 8080", subjectParts: [{ kind: "text", text: "any address on port " }, { kind: "code", text: "8080" }], reach: "your agent's programs connecting", effect: "Allowed" } },
  { id: "disposition:egress:untrusted-destination", kind: "disposition", subject: "egress:untrusted-destination", effect: "set to Block", reach: null, hits: 0, actions: { remove: true, flip: null },
    plain: { subject: "sending to a place you have not trusted", reach: "a built-in protection", effect: "Blocked, instead of asking you" } },
  { id: "app:psql", kind: "lock", subject: "psql", effect: "program rule", reach: null, hits: null, actions: { remove: false, flip: null } },
] } };
const SEND_ORIGINS = {
  origins: Object.fromEntries(["r-send", "r-any", "r-two", "connect:tcp:pypi.org:443", "connect:tcp:*:8080", "disposition:egress:untrusted-destination", "app:psql"].map((k, i) => [k, recorded(id(i))])),
  complete: true,
  unrecorded: { recorded: false, sentence: "No record of who added this", at: null, session: null, changedSince: false, changeId: null },
};
/** Six changes: two name pastebin.com (a send, and adding the host to a file), two pypi.org (one made with no port), two neither. */
const HOST_CHANGES = [
  change(0, { rows: [[T("Always allow sending masked data from "), T("anywhere"), T(" to "), C("pastebin.com")]] }),
  change(1, { rows: [[T("Let your agent's programs connect to "), C("pypi.org")]] }),
  change(2, { rows: [[T("Always add "), C("pastebin.com"), T(" to "), C("~/app/.env")]] }),
  change(3, { rows: [[T("Let your agent's programs connect to "), C("pypi.org:443")]] }),
  change(4, { rows: [[T("Let your agent's programs connect to "), C("files.example:443")]] }),
  change(5),
];
const sendRules = () => load({ extensions: "", url: RULES, homeVm: quiet(), routes: { "GET policy/panel": SEND_PANEL, "GET policy/rules/origins": SEND_ORIGINS, ...routesFor(HOST_CHANGES) } });

test("F12: a send rule to one host and a connection rule link Find its changes, the host searched; none where no one name is right", async () => {
  const { doc, window } = sendRules();
  await tick();
  // The send rule: its host.
  const send = openListRule(doc, /pastebin\.com/).querySelector(".rule-origin");
  assert.match(send.textContent, /See this change in Approvals · Find its changes$/);
  const a = findLink(send);
  assert.equal(a.getAttribute("href"), "/mandu/approvals?changes=pastebin.com#rule-changes");
  assert.equal(a.dataset.land, "changes:pastebin.com");
  assert.equal(a.dataset.pageLink, "approvals");
  assert.equal(a.getAttribute("aria-label"), `${FIND}: pastebin.com`, "named by its rule");
  // The connection rule: its host alone, named by its row.
  const conn = findLink(openListRule(doc, /pypi\.org:443/).querySelector(".rule-origin"));
  assert.equal(conn.getAttribute("href"), "/mandu/approvals?changes=pypi.org#rule-changes", "the host, so a change made with no port is found too");
  assert.equal(conn.dataset.land, "changes:pypi.org");
  assert.equal(conn.getAttribute("aria-label"), `${FIND}: pypi.org:443`);
  // No one name: the change link alone.
  for (const re of [/^anywhere/, /a\.example, b\.example/, /any address on port/, /a place you have not trusted/, /psql/]) {
    const line = openListRule(doc, re).querySelector(".rule-origin");
    assert.equal(line.querySelectorAll("a.change-link").length, 1, `${re}: its change link`);
    assert.equal(findLink(line), null, `${re}: no Find its changes`);
  }
  // No recorded origin: no link at all.
  const none = openListRule(doc, /unrecorded\.example/).querySelector(".rule-origin");
  assert.equal(none.querySelector("a"), null);

  // Following the connection's: Rule changes searched for pypi.org, both changes found.
  findLink(openListRule(doc, /pypi\.org:443/).querySelector(".rule-origin")).click();
  await waitWhile(() => rows(doc).length === 0 || ids(doc).length === HOST_CHANGES.length);
  await tick(40);
  assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
  assert.equal(window.location.pathname + window.location.search + window.location.hash, "/mandu/approvals?changes=pypi.org#rule-changes");
  assert.equal(box(doc).value, "pypi.org");
  assert.deepEqual(ids(doc), [id(1), id(3)], "the change made with no port and the one with it");
  assert.equal(count(doc).textContent, "2 of 6 changes match");
  // Back, and the send's: the send and the host added to a file.
  window.history.back();
  await waitWhile(() => window.location.pathname !== "/mandu/rules");
  await tick();
  findLink(openListRule(doc, /pastebin\.com/).querySelector(".rule-origin")).click();
  await waitWhile(() => box(doc).value !== "pastebin.com" || !ids(doc).includes(id(0)));
  assert.deepEqual(ids(doc), [id(0), id(2)], "every change naming the host");
  assert.equal(count(doc).textContent, "2 of 6 changes match");
});
