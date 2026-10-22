/**
 * history-search.test — dashboard.md §4.25ae *Finding a session*: the pure
 * match History's search runs (`historyMatches`, `historyWords`) and the
 * view model carrying it (`buildHistoryViewModel`'s `query`).
 *
 * A session is found by its agent's name or its prompt label as the row
 * reads them, every word, case aside; a blank search finds every session;
 * the search is cut at HISTORY_QUERY_MAX. The label is what the AI saw, each
 * masked item spelled "[masked]": a search for a secret's real value never
 * finds the session whose prompt held it (the route is open signed out).
 * Since 2026-10-22 its folder (`SessionRef.cwd`) is matched too, `~/…` as the
 * row draws it and in full as its title shows it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { SessionRef } from "../../../src/event-source/contract.js";
import { buildHistoryViewModel, historyMatches, historyWords, HISTORY_QUERY_MAX } from "../../../src/view-model/home.js";

const ref = (id: string, over: Partial<SessionRef> = {}): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3, firstTs: "2026-09-01T10:00:00.000Z", lastTs: "2026-09-01T10:05:00.000Z", violated: false, agent: "claude", status: "idle", ...over,
} as SessionRef);
const found = (list: SessionRef[], q: string | null | undefined) => historyMatches(list, q).map((s) => s.id);

const VALUE = "sk_live_51HistorySearchCanary9xQ";
const SYM = "$MDU:env_STRIPE_API_KEY[3fa9c2]";
const LIST = [
  ref("a", { label: "Fix deploy/staging.conf before Friday" }),
  ref("b", { label: "Why does the Staging build fail?", agent: "codex" }),
  ref("c", { label: null }),
  ref("d", { label: "claude launch: 7 rung(s) live", labelFrom: "posture", agent: "goose" }),
  ref("e", { label: `What is ${SYM}?` }),
];

test("a search finds by the prompt label, case aside, every word in it", () => {
  assert.deepEqual(found(LIST, "staging"), ["a", "b"]);
  assert.deepEqual(found(LIST, "STAGING"), ["a", "b"], "case aside");
  assert.deepEqual(found(LIST, "deploy/staging.conf"), ["a"]);
  assert.deepEqual(found(LIST, "staging friday"), ["a"], "every word, in any order");
  assert.deepEqual(found(LIST, "friday staging"), ["a"]);
  assert.deepEqual(found(LIST, "staging tuesday"), [], "a word not in it: no match");
});

test("a search finds by the agent's name as the row reads it", () => {
  assert.deepEqual(found(LIST, "codex"), ["b"]);
  assert.deepEqual(found(LIST, "Claude Code"), ["a", "c", "e"]);
  assert.deepEqual(found(LIST, "codex staging"), ["b"], "the agent and the prompt together");
  assert.deepEqual(found(LIST, "goose"), ["d"], "a session with no prompt is found by its agent");
});

test("no prompt: never matched by a label it does not show (none, or a fallback)", () => {
  assert.deepEqual(found(LIST, "rung"), [], "the launcher's posture line is not the row's label");
  assert.deepEqual(found(LIST, "launch"), []);
  assert.deepEqual(found([ref("x", { label: null, agent: undefined })], "agent"), ["x"], "an unknown agent reads 'The agent'");
});

test("a blank search finds every session, in order", () => {
  for (const q of ["", "   ", "\t\n", null, undefined]) assert.deepEqual(found(LIST, q), ["a", "b", "c", "d", "e"], JSON.stringify(q));
  assert.deepEqual(historyWords("  Fix   the\tBuild "), ["fix", "the", "build"]);
});

test("the search is cut at HISTORY_QUERY_MAX", () => {
  assert.equal(HISTORY_QUERY_MAX, 200);
  const long = "staging " + "x".repeat(300);
  assert.equal(historyWords(long).join(" ").length, HISTORY_QUERY_MAX);
  // Cut, the long word's tail is gone, but what is left must still be in it.
  assert.deepEqual(found(LIST, long), []);
  assert.deepEqual(found(LIST, " ".repeat(HISTORY_QUERY_MAX) + "staging"), ["a", "b", "c", "d", "e"], "a word past the cap is not read");
});

test("the match never reads an original: a masked item is '[masked]', its value and its token are not searched", () => {
  assert.deepEqual(found(LIST, VALUE), [], "the secret's real value");
  assert.deepEqual(found(LIST, VALUE.slice(0, 12)), [], "a piece of it");
  assert.deepEqual(found(LIST, "STRIPE_API_KEY"), [], "the token's own words");
  assert.deepEqual(found(LIST, "3fa9c2"), [], "the token's hash");
  assert.deepEqual(found(LIST, "$MDU"), []);
  assert.deepEqual(found(LIST, "what is [masked]?"), ["e"], "the label as the page spells it");
  // Even a list holding the value in a NON-prompt label (data a fallback
  // would show) does not match it: such a label is not the row's.
  assert.deepEqual(found([ref("z", { label: `STRIPE_KEY=${VALUE}`, labelFrom: "posture" })], VALUE), []);
});

test("the view model carries the search: total counts the matches, query.all every session", () => {
  const vm = buildHistoryViewModel({ total: 2, page: [ref("a"), ref("b")], next: null, facts: new Map(), query: { text: "staging", all: 214 } });
  assert.deepEqual(vm.query, { text: "staging", all: 214 });
  assert.equal(vm.total, 2);
  const plain = buildHistoryViewModel({ total: 5, page: [ref("a")], next: "a", facts: new Map() });
  assert.equal("query" in plain, false, "no search: no query field");
});

// ── The folder (§4.25ae, 2026-10-22): the row says "in ~/projects/shop" ──
const HOME = "/home/u";
const FOLDERS = [
  ref("f1", { label: "fix the flaky test", cwd: "/home/u/projects/shop" }),
  ref("f2", { label: "Add a login page", cwd: "/home/u/projects/shop" }),
  ref("f3", { label: "Add a login page", cwd: "/home/u/projects/payments" }),
  ref("f4", { label: "Tidy the shop's README" }),
  ref("f5", { label: "Read the logs", cwd: "/srv/shop-data" }),
];
const inFolder = (q: string, home = HOME) => historyMatches(FOLDERS, q, home).map((s) => s.id);

test("a word only in the folder finds the session", () => {
  assert.deepEqual(inFolder("payments"), ["f3"]);
  assert.deepEqual(inFolder("PROJECTS"), ["f1", "f2", "f3"], "case aside");
  assert.deepEqual(inFolder("shop"), ["f1", "f2", "f4", "f5"], "the folder, or the prompt (f4), or a folder outside home (f5)");
});

test("the folder as the row draws it (~) and in full (its title) both find it", () => {
  assert.deepEqual(inFolder("~/projects/shop"), ["f1", "f2"]);
  assert.deepEqual(inFolder("/home/u/projects/shop"), ["f1", "f2"]);
  assert.deepEqual(inFolder("~/srv"), [], "a folder outside home is not drawn with ~");
  assert.deepEqual(inFolder("/srv/shop-data"), ["f5"], "outside home: as recorded");
  assert.deepEqual(historyMatches(FOLDERS, "~/projects/shop", "").map((s) => s.id), [], "no home known: no ~ form");
  assert.deepEqual(historyMatches(FOLDERS, "~/u/projects/shop", "/home").map((s) => s.id), ["f1", "f2"], "another home: ~ is that one");
});

test("every word must hold across the label and the folder together", () => {
  assert.deepEqual(inFolder("shop login"), ["f2"], "the folder and the prompt");
  assert.deepEqual(inFolder("login shop"), ["f2"], "in any order");
  assert.deepEqual(inFolder("payments flaky"), [], "each word somewhere, but not in one session");
  assert.deepEqual(inFolder("claude shop"), ["f1", "f2", "f4", "f5"], "the agent and the folder");
});

test("a session with no folder recorded is matched as before", () => {
  assert.deepEqual(inFolder("readme"), ["f4"]);
  assert.deepEqual(found(LIST, "staging"), ["a", "b"], "the list without folders, no home: unchanged");
  assert.deepEqual(historyMatches(LIST, "staging", HOME).map((s) => s.id), ["a", "b"]);
  assert.deepEqual(inFolder("home/u"), ["f1", "f2", "f3"], "a piece of the full path (its title); f4 has no folder");
});

test("a masked key is never matched with a folder either", () => {
  const list = [ref("m", { label: `What is ${SYM}?`, cwd: "/home/u/projects/shop" })];
  for (const q of [VALUE, VALUE.slice(0, 12), "STRIPE_API_KEY", "3fa9c2", "$MDU", `shop ${VALUE}`]) {
    assert.deepEqual(historyMatches(list, q, HOME).map((s) => s.id), [], q);
  }
  assert.deepEqual(historyMatches(list, "shop [masked]", HOME).map((s) => s.id), ["m"]);
});
