/**
 * home-js-history-count-meanings.test — dashboard.md §4.25 *What the counts
 * mean*, History's fold (§4.25ae). Every History row ends in a counts line
 * ("2 secrets masked, 1 send with a real value filled in"), led by marks
 * ("protection was off", "less protection than usual"), and nothing on the
 * page said what any of them mean; Home's "?" and a session page's fold do,
 * from one list (`COUNT_MEANINGS`). Now, under History's search:
 *
 *   H1  a closed fold *What the counts mean* lists a term and meaning for
 *       each kind of count a drawn row shows, in the counts line's order,
 *       in `COUNT_MEANINGS`' words, and nothing else;
 *   H2  the marks add theirs (protection failed, was off, less protection
 *       than usual), in the server's and the alarm's words, before the
 *       counts; the frozen levels' untrusted items and "waiting for you"
 *       add none;
 *   H3  no drawn row with a count or a mark, an empty record or a failed
 *       read: the fold is hidden;
 *   H4  a poll or a read with the same kinds leaves the fold's node, its
 *       list and its open state alone; a search that brings new kinds
 *       draws them, the fold kept open; one that brings none hides it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
const fold = (doc: El) => doc.getElementById("history-count-meanings");
const entries = (doc: El): [string, string][] => [...fold(doc).querySelectorAll("dt")].map((dt: El) => [dt.textContent, dt.nextElementSibling.textContent]);
const terms = (doc: El) => entries(doc).map(([t]) => t);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const type = (doc: El, text: string) => {
  const box = doc.getElementById("history-q");
  box.focus();
  box.value = text;
  box.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
};
const settle = async () => { await new Promise((r) => setTimeout(r, 300)); await tick(); };

const MASKED = "The AI got only the masked version of each, from the first time it could see it.";
const SENT = "Each went to a destination allowed to receive it.";

test("H1: a closed fold under the search lists the masked and sent counts the rows show, in their order and COUNT_MEANINGS' words, nothing else", async () => {
  const rows = [row("s2", { sent: 3 }), row("s1", { secrets: { masked: 2, early: 0 } })];
  const { doc, err } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 2, rows, next: null } } });
  assert.equal(err, null);
  await tick();
  const f = fold(doc);
  assert.equal(f.tagName, "DETAILS");
  assert.equal(f.hidden, false);
  assert.equal(f.open, false, "closed by default: one line");
  assert.equal(f.querySelector("summary").textContent, "What the counts mean");
  assert.equal(doc.getElementById("history-search").nextElementSibling, f, "right under the search");
  assert.ok(f.nextElementSibling.contains(doc.getElementById("history-list")), "above the list");
  assert.deepEqual(entries(doc), [
    ["Secrets masked before the AI saw them", MASKED],
    ["Sends with a real value filled in", SENT],
  ], "the counts line's order: masked before sent, though the sending row is first");
  // The session page's fold and Home's "?" read the same words: the sent
  // count's "?" on Home says "Each went …" of two or more.
  assert.match(doc.querySelector("#history-list").textContent, /3 sends with a real value filled in/);
});

test("H2: the marks add theirs before the counts, in the server's and the alarm's words; untrusted items and waiting questions add none", async () => {
  const rows = [
    row("s5", { untrusted: 4, waiting: 2 }),
    row("s4", { lessProtection: true, blocked: 1 }),
    row("s3", { protectionOff: true }),
    row("s2", { holds: false, secrets: { masked: 0, early: 1 } }),
  ];
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 4, rows, next: null } } });
  await tick();
  assert.match(doc.querySelector("#history-list").textContent, /4 untrusted items masked/, "the untrusted count is drawn on its row");
  assert.deepEqual(entries(doc), [
    ["Protection failed", "Something reached the AI unmasked. Open its page to see what."],
    ["Protection was off", "Mandu only watched in it: nothing was masked or blocked."],
    ["Less protection than usual", "Not all of Mandu's protections started for it."],
    ["Secrets the AI read before they were marked secrets", "The AI read the real value as it was, before it was marked a secret."],
    ["Actions blocked", "Each is a step Mandu stopped: a command, a file or a send."],
  ]);
  assert.doesNotMatch(fold(doc).textContent, /untrusted|waiting/i, "no entry for the untrusted items nor the questions waiting");
});

test("H3: no row with a count or a mark, an empty record or a failed read: the fold is hidden", async () => {
  const plain = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 2, rows: [row("s2", { untrusted: 3 }), row("s1", { waiting: 1 })], next: null } } });
  await tick();
  assert.equal(fold(plain.doc).hidden, true, "untrusted items and a waiting question alone: hidden");
  assert.deepEqual(entries(plain.doc), []);
  const empty = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 0, rows: [], next: null } } });
  await tick();
  assert.equal(fold(empty.doc).hidden, true, "an empty record: hidden");
  const failed = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": () => ({ status: 500, body: { error: "boom" } }) } });
  await tick();
  assert.match(failed.doc.getElementById("history-list").textContent, /Could not read the history/);
  assert.equal(fold(failed.doc).hidden, true, "a failed read: hidden");
});

test("H4: the same kinds leave the fold alone, open as left; a search with new kinds draws them, still open; one with none hides it", async () => {
  let i = 0;
  const all = [
    { total: 2, rows: [row("s2", { secrets: { masked: 1, early: 0 } }), row("s1")], next: null },
    // The poll: a count changed, its kinds did not.
    { total: 2, rows: [row("s2", { secrets: { masked: 5, early: 0 } }), row("s1")], next: null },
  ];
  const routes = {
    "GET home/history": () => all[Math.min(i++, all.length - 1)],
    "GET home/history?q=deploy": { total: 1, rows: [row("s7", { secrets: { masked: 1, early: 0 }, blocked: 2, protectionOff: true })], next: null, query: { text: "deploy", all: 2 } },
    "GET home/history?q=nothing": { total: 1, rows: [row("s8")], next: null, query: { text: "nothing", all: 2 } },
  };
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes });
  await tick();
  const f = fold(doc);
  const dt = f.querySelector("dt");
  assert.deepEqual(terms(doc), ["Secrets masked before the AI saw them"]);
  f.open = true;
  const summary = f.querySelector("summary");
  summary.focus();
  await poll(doc);
  assert.match(doc.getElementById("history-list").textContent, /5 secrets masked/, "the poll drew the changed row");
  assert.equal(fold(doc), f, "the same fold");
  assert.equal(f.querySelector("dt"), dt, "its list not drawn again");
  assert.equal(f.open, true, "open as left");
  assert.equal(doc.activeElement, summary, "the focus kept");

  type(doc, "deploy");
  await settle();
  assert.deepEqual(terms(doc), ["Protection was off", "Secrets masked before the AI saw them", "Actions blocked"], "the new kinds, in order");
  assert.equal(fold(doc), f);
  assert.equal(f.open, true, "still open");
  assert.equal(f.hidden, false);

  type(doc, "nothing");
  await settle();
  assert.equal(f.hidden, true, "no count nor mark among the matches: hidden");
  assert.equal(f.open, true, "and open again once shown, as left");
});
