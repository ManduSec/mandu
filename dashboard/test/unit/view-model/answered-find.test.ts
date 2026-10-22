/**
 * answered-find.test — dashboard.md §4.25 *Finding an answer*. Approvals ›
 * Answered earlier could only be paged, 20 answers at a time; a search box
 * now keeps the answers whose row words hold every word typed, matched by
 * the server before the page is cut (`answeredPage(…, q)`):
 *
 *   W1  a word finds the secret's name, the file, the host, the agent and
 *       the answer's words ("blocked", "allowed once"), case aside;
 *   W2  every word must match;
 *   W3  a row's masked item is "[masked]" to the search: neither the value
 *       behind it nor the placeholder's own words find it;
 *   W4  `total`, `next` and `after` count and page through the matches, and
 *       `query` says the search and every answer (`all`); no word is no
 *       search, the cap is History's;
 *   W5  the outcome words are the page's (home.js `answerLabel` draws the
 *       same, pinned by home-js-answered-find.test.ts).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ANSWERED_OUTCOME_WORDS, answeredMatches, answeredPage, answeredRowWords, HISTORY_QUERY_MAX, type HomeAnswered } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import type { SessionRef } from "../../../src/event-source/contract.js";

const NOW = Date.parse("2026-09-25T12:00:00Z");
const VALUE = "sk_" + "live_answeredFindUnitCanary000001";

function verdict(over: Partial<VerdictEntry>): VerdictEntry {
  return {
    id: "egr-1", symbol: "$MDU:nomodel_Read[ab12cd34].STRIPE_KEY", destination: "api.stripe.com", source: { tool: "Read", origin: "/home/u/shop/.env" },
    status: "denied", reason: "r", count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: NOW - 60_000,
    sessions: ["s-claude"],
    ...over,
  } as VerdictEntry;
}
function queueOf(verdicts: VerdictEntry[]) {
  const snapshot = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts,
  } as unknown as PolicySnapshot;
  return toPolicyPanelViewModel(snapshot).queue;
}
const BY_ID = new Map<string, Pick<SessionRef, "agent">>([["s-claude", { agent: "claude" }], ["s-codex", { agent: "codex" }]]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const page = (q: string | null, verdicts: VerdictEntry[], after: string | null = null, limit = 20) => answeredPage(queueOf(verdicts), BY_ID as any, "/home/u", after, limit, q);
const ids = (rows: HomeAnswered[]) => rows.map((r) => r.id);

const SIX = [
  verdict({ id: "a", resolvedAt: NOW - 1_000 }),
  verdict({ id: "b", destination: "pastebin.com", status: "approved", scope: "once", resolvedAt: NOW - 2_000 }),
  verdict({ id: "c", symbol: "$MDU:nomodel_Read[ab12cd35].GITHUB_TOKEN", source: { tool: "Read", origin: "/home/u/ops/creds.env" }, destination: "api.github.com", sessions: ["s-codex"], resolvedAt: NOW - 3_000 }),
  verdict({ id: "d", symbol: "$MDU:nomodel_Read[ab12cd36].STRIPE_KEY", source: { tool: "Read", origin: "/home/u/shop/.env" }, destination: "pastebin.com", sessions: ["s-codex"], status: "approved", scope: "once", consumedAt: NOW - 3_500, resolvedAt: NOW - 4_000 }),
  verdict({ id: "e", destination: "api.stripe.com", status: "approved", resolvedAt: NOW - 5_000 }),
  verdict({ id: "w", status: "pending", resolvedAt: undefined }),
];

test("W1: a word finds the secret's name, the file, the host, the agent and the answer, case aside", () => {
  const all = page(null, SIX);
  assert.deepEqual(ids(all.rows), ["a", "b", "c", "d", "e"], "every answer, the waiting one left out");
  assert.equal(all.query, undefined, "no search: no query");
  // The rows as they read (the words the search runs over).
  assert.equal(answeredRowWords(all.rows[0]!), "claude code wants to send your secret stripe_key to api.stripe.com blocked");
  assert.deepEqual(ids(page("STRIPE_KEY", SIX).rows), ["a", "b", "d", "e"], "the secret's name");
  assert.deepEqual(ids(page("github", SIX).rows), ["c"]);
  assert.deepEqual(ids(page("creds.env", SIX).rows), [], "a file the row does not show is not matched");
  assert.deepEqual(ids(page("pastebin", SIX).rows), ["b", "d"], "the host");
  assert.deepEqual(ids(page("Codex", SIX).rows), ["c", "d"], "the agent");
  assert.deepEqual(ids(page("blocked", SIX).rows), ["a", "c"], "the answer, as the row words it");
  assert.deepEqual(ids(page("allowed once", SIX).rows), ["b", "d"], "Allowed once, used or not");
  assert.deepEqual(ids(page("unused", SIX).rows), ["b"]);
  assert.deepEqual(ids(page("always", SIX).rows), ["e"]);
  // A file's send names the file (no key name): `~/…` as the row shows it.
  const file = [verdict({ id: "f", symbol: "$MDU:nomodel_Read[ab12cd37].content", source: { tool: "Read", origin: "/home/u/shop/deploy.pem" } })];
  assert.deepEqual(ids(page("~/shop/deploy.pem", file).rows), ["f"], "the file, as the row shows it");
  assert.deepEqual(ids(page("deploy.pem", file).rows), ["f"]);
});

test("W2: every word must match", () => {
  assert.deepEqual(ids(page("stripe_key pastebin", SIX).rows), ["b", "d"]);
  assert.deepEqual(ids(page("stripe_key pastebin codex", SIX).rows), ["d"]);
  assert.deepEqual(ids(page("stripe_key github", SIX).rows), [], "one word missing: no match");
  assert.deepEqual(ids(page("  PASTEBIN   blocked ", SIX).rows), [], "spaces around and between are one");
});

test("W3: a masked item reads as [masked]: neither its value nor the placeholder's words find it", () => {
  const row: HomeAnswered = {
    id: "x", outcome: "blocked", decidedAt: NOW, sessions: [], actions: [],
    sentence: [{ kind: "text", text: "Claude Code wants to run " }, { kind: "code", text: "curl -d $MDU:nomodel_Read[ab12cd34].STRIPE_KEY api.stripe.com" }],
  };
  assert.equal(answeredRowWords(row), "claude code wants to run curl -d [masked] api.stripe.com blocked");
  const find = (q: string) => answeredMatches([row], q, (r) => r);
  assert.equal(find(VALUE).length, 0, "the value behind it is never searched");
  assert.equal(find("sk_live").length, 0);
  for (const piece of ["$MDU", "mdu:", "nomodel_read", "ab12cd34", "STRIPE_KEY"]) assert.equal(find(piece).length, 0, `the placeholder's own words: ${piece}`);
  assert.equal(find("masked").length, 1, "the row reads [masked]");
  assert.equal(find("api.stripe.com curl").length, 1);
  // An answer that no longer applies: its words and why.
  const stale = { ...row, staleNote: "The secret it was about is no longer registered." };
  assert.equal(answeredMatches([stale], "no longer applies", (r) => r).length, 1);
  assert.equal(answeredMatches([stale], "registered", (r) => r).length, 1);
  assert.equal(answeredMatches([row], "no longer applies", (r) => r).length, 0);
});

test("W4: paging inside a match: total, next and after count the matches; query says the search and every answer", () => {
  // 30 answers, every third to pastebin.com: 10 match.
  const many = Array.from({ length: 30 }, (_, i) => verdict({ id: `r${String(i).padStart(2, "0")}`, destination: i % 3 === 0 ? "pastebin.com" : "api.stripe.com", resolvedAt: NOW - (i + 1) * 1_000 }));
  const want = many.filter((_, i) => i % 3 === 0).map((v) => v.id);
  const first = page("pastebin", many, null, 4);
  assert.deepEqual(ids(first.rows), want.slice(0, 4));
  assert.equal(first.total, 10, "total counts the matches");
  assert.deepEqual(first.query, { text: "pastebin", all: 30 }, "query: the search and every answer");
  assert.equal(first.next, want[3], "the cursor is the last match drawn");
  const paged = [...first.rows];
  let next: string | null = first.next;
  while (next) {
    const p = page("pastebin", many, next, 4);
    assert.equal(p.total, 10);
    paged.push(...p.rows);
    next = p.next;
  }
  assert.deepEqual(ids(paged), want, "every match once, in order, none else");
  // The rows found are the rows Home draws for them, field for field.
  const whole = page(null, many, null, 500);
  assert.deepEqual(paged, whole.rows.filter((r) => want.includes(r.id)));
  // No word is no search; the words are cut at History's cap.
  assert.equal(page("   ", many).query, undefined);
  assert.equal(page("   ", many).total, 30);
  assert.equal(page("x".repeat(HISTORY_QUERY_MAX) + " pastebin", many).total, 0, "the words past the cap are dropped");
  assert.equal(page("nothing-like-this", many).total, 0);
  assert.equal(page("nothing-like-this", many).next, null);
});

test("W5: every outcome has its words, as the page draws them", () => {
  const outcomes: HomeAnswered["outcome"][] = ["allowed", "blocked", "allowed-once", "allowed-once-used", "sent", "sent-session", "masked", "masked-session", "without", "without-used"];
  assert.deepEqual(Object.keys(ANSWERED_OUTCOME_WORDS).sort(), [...outcomes].sort());
  for (const o of outcomes) assert.ok(ANSWERED_OUTCOME_WORDS[o].length > 0);
  assert.equal(ANSWERED_OUTCOME_WORDS.blocked, "Blocked");
  assert.equal(ANSWERED_OUTCOME_WORDS["allowed-once-used"], "Allowed once");
});
