/**
 * home-js-home-count-meanings.test — dashboard.md §4.25 *What the counts
 * mean*, *Home's fold*. Home's Running now and Earlier end each row in the
 * same counts line as History ("less protection than usual, 2 secrets
 * masked, 1 action blocked"), and nothing on Home said what a row's marks
 * mean. Now, under Earlier (under Running now when Earlier is hidden):
 *
 *   W1  a closed fold *What the counts mean* lists a term and meaning for
 *       each kind of mark or count a row drawn in EITHER list shows, in the
 *       counts line's order, in `COUNT_MEANINGS`' words (History's
 *       fold's), and nothing else;
 *   W2  Earlier hidden (no ended session): the fold sits under Running
 *       now and lists Running now's kinds;
 *   W3  no drawn row with a count or a mark, or a failed read: hidden;
 *   W4  a poll with the same kinds leaves the fold's node, its list, its
 *       open state and the focus alone, even when only one list changed
 *       (Earlier's unchanged rows still count); a poll with a new kind
 *       draws its list again, still open;
 *   W5  Earlier's Show it (them) draws more rows: their kinds join the list.
 *
 * History's fold (home-js-history-count-meanings.test.ts) shares the
 * helper and stays as it was.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const now = () => new Date().toISOString();
const row = (id: string, state: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: now(), lastAt: now(), state,
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
const vm = (agents: unknown[]) => home({ waiting: [], agents });
const fold = (doc: El) => doc.getElementById("home-count-meanings");
const entries = (doc: El): [string, string][] => [...fold(doc).querySelectorAll("dt")].map((dt: El) => [dt.textContent, dt.nextElementSibling.textContent]);
const terms = (doc: El) => entries(doc).map(([t]) => t);
const poll = async (doc: El) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

const LESS = "Not all of Mandu's protections started for it.";
const MASKED = "The AI got only the masked version of each, from the first time it could see it.";
const BLOCKED = "Each is a step Mandu stopped: a command, a file or a send.";

test("W1: a closed fold under Earlier lists the kinds both lists' rows show, in the counts line's order and COUNT_MEANINGS' words, nothing else", async () => {
  const { doc, err } = load({ extensions: "", homeVm: vm([
    row("r1", "running", { lessProtection: true, untrusted: 2, waiting: 1 }),
    row("e1", "idle", { secrets: { masked: 2, early: 0 }, blocked: 1 }),
  ]) });
  assert.equal(err, null);
  await tick();
  const f = fold(doc);
  assert.equal(f.tagName, "DETAILS");
  assert.ok(f.classList.contains("count-meanings") && f.classList.contains("glossary"), "History's fold's look");
  assert.equal(f.hidden, false);
  assert.equal(f.open, false, "closed by default: one line");
  assert.equal(f.querySelector("summary").textContent, "What the counts mean");
  assert.equal(doc.getElementById("home-earlier-block").nextElementSibling, f, "right under Earlier");
  assert.ok(f.nextElementSibling.contains(doc.getElementById("home-data")), "above Where your data lives");
  assert.match(doc.getElementById("home-agents").textContent, /less protection than usual/);
  assert.match(doc.getElementById("home-earlier").textContent, /2 secrets masked, 1 action blocked/);
  assert.deepEqual(entries(doc), [
    ["Less protection than usual", LESS],
    ["Secrets masked before the AI saw them", MASKED],
    ["Actions blocked", BLOCKED],
  ], "the running row's mark first, then the ended row's counts; no untrusted items nor waiting question");
});

test("W2: with Earlier hidden the fold sits under Running now and lists its rows' kinds", async () => {
  const { doc } = load({ extensions: "", homeVm: vm([row("r1", "running", { protectionOff: true, sent: 1 })]) });
  await tick();
  assert.equal(doc.getElementById("home-earlier-block").hidden, true, "no ended session: Earlier is hidden");
  assert.equal(fold(doc).hidden, false);
  assert.deepEqual(entries(doc), [
    ["Protection was off", "Mandu only watched in it: nothing was masked or blocked."],
    ["Sends with a real value filled in", "Each went to a destination allowed to receive it."],
  ]);
});

test("W3: no row with a count or a mark, or a failed read: the fold is hidden", async () => {
  const quiet = load({ extensions: "", homeVm: vm([row("r1", "running", { untrusted: 3 }), row("e1", "idle", { waiting: 1 })]) });
  await tick();
  assert.equal(fold(quiet.doc).hidden, true, "untrusted items and a waiting question alone: hidden");
  assert.deepEqual(entries(quiet.doc), []);
  const none = load({ extensions: "", homeVm: vm([]) });
  await tick();
  assert.equal(fold(none.doc).hidden, true, "no session: hidden");

  // A read that fails after one that drew kinds hides it, never the last
  // kinds under "Could not check".
  let fail = false;
  const failed = load({ extensions: "", routes: { "GET home": () => (fail ? { status: 500, body: { error: "boom" } } : vm([row("e1", "idle", { holds: false })])) } });
  await tick();
  assert.deepEqual(terms(failed.doc), ["Protection failed"]);
  assert.equal(fold(failed.doc).hidden, false);
  fail = true;
  await poll(failed.doc);
  assert.match(failed.doc.getElementById("home-agents").textContent, /Could not check/);
  assert.equal(fold(failed.doc).hidden, true, "a failed read: hidden");
});

test("W4: a poll with the same kinds leaves the fold alone, open and focused; a new kind draws its list again, still open", async () => {
  const earlier = row("e1", "idle", { secrets: { masked: 1, early: 0 } });
  const { doc, setHome } = load({ extensions: "", homeVm: vm([row("r1", "running"), earlier]) });
  await tick();
  const f = fold(doc);
  const dt = f.querySelector("dt");
  assert.deepEqual(terms(doc), ["Secrets masked before the AI saw them"]);
  f.open = true;
  const summary = f.querySelector("summary");
  summary.focus();
  // Running now changes (a block), Earlier does not: Earlier's rows still count.
  setHome(vm([row("r1", "running", { title: "Renamed" }), earlier]));
  await poll(doc);
  assert.match(doc.getElementById("home-agents").textContent, /Renamed/, "the poll drew Running now again");
  assert.equal(fold(doc), f, "the same fold");
  assert.equal(f.querySelector("dt"), dt, "its list not drawn again");
  assert.deepEqual(terms(doc), ["Secrets masked before the AI saw them"], "Earlier's unchanged row still counts");
  assert.equal(f.open, true, "open as left");
  assert.equal(doc.activeElement, summary, "the focus kept");

  setHome(vm([row("r1", "running", { title: "Renamed", blocked: 2 }), earlier]));
  await poll(doc);
  assert.deepEqual(terms(doc), ["Secrets masked before the AI saw them", "Actions blocked"], "the new kind, in order");
  assert.equal(fold(doc), f);
  assert.equal(f.open, true, "still open");
});

test("W5: Earlier's Show it draws more rows, and their kinds join the fold", async () => {
  // Eleven ended sessions: the eleventh (cut) is the only one with a count.
  const ended = Array.from({ length: 11 }, (_, i) => row(`e${i}`, "idle", i === 10 ? { blocked: 1 } : {}));
  const { doc } = load({ extensions: "", homeVm: vm(ended) });
  await tick();
  assert.equal(fold(doc).hidden, true, "no drawn row has a count");
  const more = [...doc.querySelectorAll("#home-earlier button")].find((b: El) => /^Show (it|them)$/.test(b.textContent));
  assert.ok(more, "Earlier has its Show it");
  more.click();
  await tick();
  assert.match(doc.getElementById("home-earlier").textContent, /1 action blocked/);
  assert.equal(fold(doc).hidden, false);
  assert.deepEqual(terms(doc), ["Actions blocked"]);
});
