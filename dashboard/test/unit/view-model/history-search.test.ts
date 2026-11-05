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
 * row draws it and in full as its title shows it. Since 2026-11-02 (#249) a
 * session its listing does not find is found by its secrets' and hosts'
 * names from its facts (`historyFactsMatch`): never a value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { SessionRef } from "../../../src/event-source/contract.js";
import { buildHistoryViewModel, historyFactNames, historyFactsMatch, historyListing, historyMatches, historyWords, HISTORY_QUERY_MAX, type HomeSessionFacts } from "../../../src/view-model/home.js";
import { sendHosts, sentHosts, type SessionKept } from "../../../src/view-model/session-kept.js";
import type { StoryTurn } from "../../../src/view-model/agent-page-types.js";

const ref = (id: string, over: Partial<SessionRef> = {}): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3, firstTs: "2026-09-01T10:00:00.000Z", lastTs: "2026-09-01T10:05:00.000Z", violated: false, agent: "claude", status: "idle", ...over,
} as SessionRef);
const found = (list: SessionRef[], q: string | null | undefined) => historyMatches(list, q).map((s) => s.id);

const VALUE = "sk_" + "live_51HistorySearchCanary9xQ";
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

// ── By a secret or a host (§4.25ae, #249) ────────────────────────────────────
const fact = (names: string[] = []) => ({ count: names.length, names });
const kept = (over: Partial<SessionKept> = {}): SessionKept => ({
  mode: "secrets", flagged: false, masked: fact(["STRIPE_KEY in ~/proj/.env"]), early: fact(["the file ~/proj/deploy/staging.conf"]),
  unmasked: fact(), blocked: 1, sent: fact(["api.stripe.com"]), unchecked: false, ...over,
});
const FACTS: Pick<HomeSessionFacts, "kept" | "hosts"> = { kept: kept(), hosts: ["api.stripe.com", "pastebin.com"] };
const TOUR = ref("t", { label: "What is in .env?", cwd: "/home/u/proj" });
const byFacts = (q: string, f: Pick<HomeSessionFacts, "kept" | "hosts"> | undefined = FACTS, s: SessionRef = TOUR) =>
  historyFactsMatch(historyWords(q), historyListing(s, HOME), f, HOME);
/** The found names alone (`byFacts` without where each came up). */
const names = (q: string, f: Pick<HomeSessionFacts, "kept" | "hosts"> | undefined = FACTS) => byFacts(q, f)?.map((n) => n.name) ?? null;

test("B1: a secret's name, its file in ~/… and in full, a sent and a blocked host each find the session, with the names found", () => {
  assert.deepEqual(names("STRIPE_KEY"), ["STRIPE_KEY in ~/proj/.env"], "the variable's name, case aside");
  assert.deepEqual(names("stripe_key"), ["STRIPE_KEY in ~/proj/.env"]);
  assert.deepEqual(names("staging.conf"), ["the file ~/proj/deploy/staging.conf"], "a secret read before it was marked");
  assert.deepEqual(names("~/proj/deploy/staging.conf"), ["the file ~/proj/deploy/staging.conf"], "the path as drawn");
  assert.deepEqual(names("/home/u/proj/deploy/staging.conf"), ["the file ~/proj/deploy/staging.conf"], "the path in full");
  assert.deepEqual(names("api.stripe.com"), ["a send to api.stripe.com"], "a sent host");
  assert.deepEqual(names("pastebin.com"), ["a blocked send to pastebin.com"], "a host a send was stopped on its way to: blocked, not sent (#301)");
  assert.deepEqual(names("stripe"), ["STRIPE_KEY in ~/proj/.env", "a send to api.stripe.com"], "every name a word is in");
  const off = { kept: kept({ mode: "off", masked: fact(), early: fact(), unmasked: fact(["GH_TOKEN in ~/proj/.env"]) }), hosts: [] };
  assert.deepEqual(names("GH_TOKEN", off), ["GH_TOKEN in ~/proj/.env"], "a secret not masked in an Off session");
});

test("B2: every word must hold, between the listing and the names together", () => {
  assert.deepEqual(names("STRIPE_KEY pastebin"), ["STRIPE_KEY in ~/proj/.env", "a blocked send to pastebin.com"]);
  assert.deepEqual(names("claude pastebin"), ["a blocked send to pastebin.com"], "the agent's name and a host");
  assert.deepEqual(names("proj pastebin"), ["STRIPE_KEY in ~/proj/.env", "the file ~/proj/deploy/staging.conf", "a blocked send to pastebin.com"], "the folder and a host: the names holding a word");
  assert.equal(byFacts("STRIPE_KEY tuesday"), null, "a word in neither: not found");
  assert.equal(byFacts("zzz"), null);
  assert.equal(byFacts("send"), null, "a host is read alone, never the words around it");
  assert.equal(historyFactsMatch([], historyListing(TOUR, HOME), FACTS, HOME), null, "no word: nothing to find");
});

test("B3: no facts, no kept or a session whose leak check fired: only its listing finds it", () => {
  assert.equal(historyFactsMatch(["stripe_key"], historyListing(TOUR, HOME), undefined, HOME), null, "not counted");
  assert.equal(byFacts("STRIPE_KEY", { hosts: ["api.stripe.com"] }), null, "no kept: nothing claimed");
  const flagged = { kept: kept({ flagged: true }), hosts: ["api.stripe.com"] };
  assert.equal(byFacts("STRIPE_KEY", flagged), null, "its card names nothing");
  assert.equal(byFacts("api.stripe.com", flagged), null);
  assert.deepEqual(historyFactNames(flagged), { secrets: [], hosts: [], sent: [] });
  assert.deepEqual(historyMatches([TOUR], ".env", HOME).map((s) => s.id), ["t"], "its listing still finds it");
});

test("B4: never a value: a search for a secret's value, a piece of it or a token finds nothing, and a token in a name is '[masked]'", () => {
  const withToken = { kept: kept({ masked: fact([`${SYM} in ~/proj/.env`]) }), hosts: [] };
  for (const q of [VALUE, VALUE.slice(0, 12), "3fa9c2", "$MDU", "STRIPE_API_KEY"]) {
    assert.equal(byFacts(q, withToken), null, q);
    assert.equal(byFacts(q), null, q);
  }
  assert.deepEqual(historyFactNames(withToken).secrets, ["[masked] in ~/proj/.env", "the file ~/proj/deploy/staging.conf"]);
});

test("B5: the view model carries `found` only on a row found by its facts", () => {
  const vm = buildHistoryViewModel({ total: 2, page: [ref("a"), ref("t")], next: null, facts: new Map(), query: { text: "stripe", all: 9 }, found: new Map([["t", [{ name: "a send to api.stripe.com", go: "sent" as const }]], ["a", []]]) });
  assert.deepEqual(vm.rows.map((r) => r.found), [undefined, [{ name: "a send to api.stripe.com", go: "sent" }]]);
  assert.equal("found" in vm.rows[0]!, false, "found by its own words: nothing more");
  const capped = buildHistoryViewModel({ total: 0, page: [], next: "x", facts: new Map(), query: { text: "stripe", all: 300, through: 200, of: 300 } });
  assert.deepEqual(capped.query, { text: "stripe", all: 300, through: 200, of: 300 });
});

test("B6: sendHosts lists the hosts of sends that went and of web steps blocked, each once; sentHosts keeps to the sent", () => {
  const code = (text: string) => ({ kind: "code" as const, text });
  const text = (t: string) => ({ kind: "text" as const, text: t });
  const step = (icon: string, outcome: string, sentence: Array<{ kind: "code" | "text"; text: string }>) =>
    ({ kind: "action", id: `${icon}${outcome}${sentence.length}`, ts: "", icon, sentence, outcome, note: null, split: null });
  const turns = [{ steps: [
    step("web", "blocked", [text("Mandu blocked a request to "), code("pastebin.com"), text(" that carried "), code("STRIPE_KEY")]),
    step("web", "sent", [text("Sent a request to "), code("api.stripe.com"), text(" with "), code("STRIPE_KEY"), text(" filled in")]),
    step("web", "blocked", [text("Mandu blocked a connection to "), code("the network")]),
    step("web", "plain", [text("Connected to "), code("example.com")]),
    step("file", "blocked", [text("Mandu blocked access to a file: "), code("id_rsa")]),
    step("run", "blocked", [text("Mandu stopped a command: "), code("curl evil.example")]),
    step("web", "sent", [text("Sent a request to "), code("api.stripe.com"), text(" with "), code("X"), text(" filled in")]),
  ] }] as unknown as StoryTurn[];
  assert.deepEqual(sendHosts(turns), ["pastebin.com", "api.stripe.com"]);
  assert.deepEqual(sentHosts(turns), ["api.stripe.com"], "the launcher line's hosts, unchanged");
});

test("B7: a host only blocked is 'a blocked send to', going to the blocked steps; a sent one, to the sent steps; a secret, to Your secrets (#301)", () => {
  // api.stripe.com: a sent step; pastebin.com: a blocked web step only.
  assert.deepEqual(byFacts("pastebin"), [{ name: "a blocked send to pastebin.com", go: "blocked" }]);
  assert.deepEqual(byFacts("api.stripe.com"), [{ name: "a send to api.stripe.com", go: "sent" }]);
  assert.deepEqual(byFacts("stripe"), [{ name: "STRIPE_KEY in ~/proj/.env", go: "secrets" }, { name: "a send to api.stripe.com", go: "sent" }]);
  assert.deepEqual(byFacts("staging.conf"), [{ name: "the file ~/proj/deploy/staging.conf", go: "secrets" }], "a secret read early: Your secrets too");
  assert.deepEqual(historyFactNames(FACTS), { secrets: ["STRIPE_KEY in ~/proj/.env", "the file ~/proj/deploy/staging.conf"], hosts: ["api.stripe.com", "pastebin.com"], sent: ["api.stripe.com"] });
  // A host both sent to and blocked (the tour's api.stripe.com): named once, as a send.
  const both = { kept: kept({ sent: fact(["api.stripe.com"]) }), hosts: ["api.stripe.com"] };
  assert.deepEqual(byFacts("api.stripe.com", both), [{ name: "a send to api.stripe.com", go: "sent" }]);
  // No send went anywhere: every host is blocked.
  const none = { kept: kept({ sent: fact() }), hosts: ["api.stripe.com", "pastebin.com"] };
  assert.deepEqual(byFacts("com", none), [{ name: "a blocked send to api.stripe.com", go: "blocked" }, { name: "a blocked send to pastebin.com", go: "blocked" }]);
  // A token in a host is cleaned the same way on both sides: still a send.
  const tok = { kept: kept({ sent: fact([SYM]) }), hosts: [SYM] };
  assert.deepEqual(byFacts("[masked]", tok), [{ name: "a send to [masked]", go: "sent" }]);
  // Still names only: a flagged session and a value find nothing.
  const flagged = { kept: kept({ flagged: true }), hosts: ["pastebin.com"] };
  assert.equal(byFacts("pastebin", flagged), null);
  for (const q of [VALUE, VALUE.slice(0, 12), "$MDU"]) assert.equal(byFacts(q), null, q);
});
