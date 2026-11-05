/**
 * history-find-facts.test — dashboard.md §4.25ae *By a secret or a host*
 * (#249), over the real DashboardServer, FileEventSource and HomeFacts, with
 * the recorded first-session tour (fixtures/tour-1791164083-1418381.ndjson,
 * fake secrets: `STRIPE_KEY` in `~/mandu-try/.env` masked, the file
 * `~/mandu-try/deploy/staging.conf` read before it was marked, a send to
 * `api.stripe.com` blocked and one let through) and plain sessions newer
 * than it:
 *
 *   H1  `?q=STRIPE_KEY`, `staging.conf`, `api.stripe.com`, `.env` in full
 *       each list the tour with `found`, the names it was found by; a
 *       session found by its own words has none; `zzz` lists none; `total`
 *       counts the matches, with no `query.through` (it looked through
 *       every session);
 *   H2  a search for one of the tour's fake values, or a `$MDU` token,
 *       finds nothing, and no answer carries a value or a token;
 *   H3  the budget: with 205 newer plain sessions the first read looks
 *       through HISTORY_SCAN_BUDGET of them, finds none, and says so
 *       (`query.through` 200 of 206, `next` the last looked through, no
 *       "none" claimed); the next read goes on from there, finds the tour
 *       and, having reached the oldest, counts it exactly;
 *   H4  pages: a word in 30 sessions' prompts pages 25 then 5, `total` 30;
 *   H5  with the switch, both hold: the tour (Mandu stepped in) is kept,
 *       with `found`;
 *   H6  a host Mandu blocked every send to (the tour with one more blocked
 *       request, to `pastebin.com`) is found as "a blocked send to
 *       pastebin.com", going to the blocked steps, never "a send to"; the
 *       tour's `api.stripe.com`, both sent to and blocked, stays "a send
 *       to" at the sent steps; a secret goes to Your secrets (#301).
 *
 * Each case fails on master, whose search reads the listing alone.
 * Axes: display only, no arbiter runs (the file source serves no posture).
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { HISTORY_SCAN_BUDGET, type HistoryVM } from "../../src/view-model/home.js";

/** A found row's names alone (without where each came up). */
const names = (row: { found?: Array<{ name: string }> } | undefined) => row?.found?.map((n) => n.name);

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "fixtures");
const TOUR = "1791164083-1418381";
const HOME = "/home/user";
const FAKE_VALUES = ["sk_live_fake_123456", "FAKE-STAGING-TOKEN-0000", "FAKE-STRIPE-KEY-0000"];

const dirs: string[] = [];
const servers: DashboardServer[] = [];
after(async () => {
  for (const s of servers) await s.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** A session with one prompt and a reply, at `ts`. */
function plain(dir: string, sid: string, ts: string, prompt: string): void {
  writeFileSync(join(dir, `${sid}.ndjson`), JSON.stringify({
    id: `ev_${sid}`, sessionId: sid, turn: 0, ts, seq: 0, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: `▸ user\n${prompt}`, original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  }) + "\n");
}

/** The tour's lines with one more request Mandu blocked, to `pastebin.com`
 *  (a copy of its blocked send to `api.stripe.com`, just after it): a host
 *  only blocked, never sent to. */
function withBlockedPastebin(text: string): string {
  const lines = text.split("\n").filter(Boolean);
  const i = lines.findIndex((l) => l.includes('"kind":"net_action"') && l.includes('"action":"blocked"'));
  assert.ok(i >= 0, "the tour has a blocked send");
  const e = JSON.parse(lines[i]!) as Record<string, unknown>;
  const pb = JSON.parse(JSON.stringify({ ...e, id: `${String(e.id)}:pastebin`, ts: new Date(Date.parse(String(e.ts)) + 50).toISOString() }).split("api.stripe.com").join("pastebin.com").split("egr-1").join("egr-pb"));
  lines.splice(i + 1, 0, JSON.stringify(pb));
  return lines.join("\n") + "\n";
}

/** The tour (`edit`: its lines changed first) and `n` plain sessions after it (newer), the i-th's prompt from `prompt`. */
async function serve(n: number, prompt: (i: number) => string, edit?: (text: string) => string): Promise<(query: string) => Promise<{ vm: HistoryVM; text: string }>> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-history-find-facts-"));
  dirs.push(dir);
  const tour = join(FIXTURES_DIR, `tour-${TOUR}.ndjson`);
  if (edit) writeFileSync(join(dir, `${TOUR}.ndjson`), edit(readFileSync(tour, "utf8")));
  else copyFileSync(tour, join(dir, `${TOUR}.ndjson`));
  for (let i = 0; i < n; i++) plain(dir, `sess-p${String(i).padStart(3, "0")}`, new Date(Date.parse("2026-10-06T00:00:00.000Z") + i * 60_000).toISOString(), prompt(i));
  const server = new DashboardServer({ source: new FileEventSource(dir), fileBrowserHome: HOME, log: () => {} });
  servers.push(server);
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  return async (query) => {
    const res = await fetch(`${base}/api/home/history${query}`);
    assert.equal(res.status, 200, "signed out, the History read is open");
    const text = await res.text();
    return { vm: JSON.parse(text) as HistoryVM, text };
  };
}

const q = (words: string, more = "") => `?q=${encodeURIComponent(words)}${more}`;

test("H1: a secret's name, its file and a host each find the tour, with the names it was found by; its own words need none", async () => {
  const read = await serve(3, (i) => (i === 0 ? "Why does the stripe webhook fail?" : `Rename the parser helper ${i}.`));
  const cases: Array<[string, string[]]> = [
    ["STRIPE_KEY", ["STRIPE_KEY in ~/mandu-try/.env"]],
    ["staging.conf", ["the file ~/mandu-try/deploy/staging.conf"]],
    ["api.stripe.com", ["a send to api.stripe.com"]],
    ["/home/user/mandu-try/.env", ["STRIPE_KEY in ~/mandu-try/.env"]],
  ];
  for (const [words, found] of cases) {
    const { vm } = await read(q(words));
    assert.deepEqual(vm.rows.map((r) => r.id), [TOUR], words);
    assert.deepEqual(names(vm.rows[0]), found, `${words}: why it is listed`);
    assert.equal(vm.total, 1);
    assert.equal(vm.next, null);
    assert.deepEqual(vm.query, { text: words.toLowerCase(), all: 4 }, `${words}: every session looked through, so no through`);
  }
  // "stripe": the plain session by its prompt (no found), the tour by its facts.
  const { vm: both } = await read(q("stripe"));
  assert.deepEqual(both.rows.map((r) => r.id), ["sess-p000", TOUR]);
  assert.equal("found" in both.rows[0]!, false, "found by its own words: nothing more");
  assert.deepEqual(names(both.rows[1]), ["STRIPE_KEY in ~/mandu-try/.env", "a send to api.stripe.com"]);
  // ".env" is in the tour's first prompt: found by its own words.
  const { vm: env } = await read(q(".env"));
  assert.deepEqual(env.rows.map((r) => r.id), [TOUR]);
  assert.equal("found" in env.rows[0]!, false);
  const { vm: none } = await read(q("zzz"));
  assert.deepEqual(none.rows, []);
  assert.equal(none.total, 0);
  assert.equal(none.next, null);
});

test("H2: the oracle: a search for a value or a token finds nothing, and no answer carries one", async () => {
  const read = await serve(2, (i) => `Rename the parser helper ${i}.`);
  // Each answer but its `query.text`, which repeats what was typed.
  const texts: string[] = [];
  const served = (vm: HistoryVM) => JSON.stringify({ ...vm, query: vm.query ? { ...vm.query, text: undefined } : undefined });
  for (const words of [...FAKE_VALUES, FAKE_VALUES[0]!.slice(0, 12), "$MDU", "$MDU:"]) {
    const { vm } = await read(q(words));
    assert.deepEqual(vm.rows, [], `${words}: matching reads names, never originals`);
    assert.equal(vm.total, 0);
    texts.push(served(vm));
  }
  for (const words of ["STRIPE_KEY", "staging.conf", "api.stripe.com", "stripe", ""]) {
    const { vm, text } = await read(q(words));
    texts.push(served(vm), text);
  }
  for (const t of texts) {
    for (const v of FAKE_VALUES) assert.ok(!t.includes(v), `CONFIDENTIALITY VIOLATION: History served ${v}`);
    assert.doesNotMatch(t, /\$MDU:/, "nor a token");
  }
});

test("H3: past the budget a read says how far it looked, never that none matches, and the next goes on and counts exactly", async () => {
  const n = HISTORY_SCAN_BUDGET + 5;
  const read = await serve(n, (i) => `Rename the parser helper ${i}.`);
  const { vm: first } = await read(q("STRIPE_KEY"));
  assert.deepEqual(first.rows, []);
  assert.deepEqual(first.query, { text: "stripe_key", all: n + 1, through: HISTORY_SCAN_BUDGET, of: n + 1 });
  assert.ok(first.next, "Show more goes on");
  assert.equal(first.next, `sess-p${String(n - HISTORY_SCAN_BUDGET).padStart(3, "0")}`, "from the last session looked through");
  const { vm: second } = await read(q("STRIPE_KEY", `&after=${encodeURIComponent(first.next!)}`));
  assert.deepEqual(second.rows.map((r) => r.id), [TOUR]);
  assert.deepEqual(names(second.rows[0]), ["STRIPE_KEY in ~/mandu-try/.env"]);
  assert.equal(second.next, null);
  assert.equal(second.total, 1, "it reached the oldest: the count is exact");
  assert.deepEqual(second.query, { text: "stripe_key", all: n + 1 });
  // A word every session's listing holds: no facts read to match, but the
  // look-through still bounds the count, and says so.
  const { vm: listed } = await read(q("claude"));
  assert.equal(listed.total, HISTORY_SCAN_BUDGET, "the matches among those looked through");
  assert.equal(listed.query?.through, HISTORY_SCAN_BUDGET);
  assert.equal(listed.rows.length, 25);
});

test("H4: a search pages through its matches: total counts them, next and the second page", async () => {
  const read = await serve(40, (i) => (i % 4 === 0 ? `Tidy the docs ${i}.` : `Rename the parser helper ${i}.`));
  const { vm: page1 } = await read(q("parser"));
  assert.equal(page1.total, 30);
  assert.equal(page1.rows.length, 25);
  assert.equal(page1.next, page1.rows[24]!.id);
  assert.equal(page1.query?.through, undefined);
  const { vm: page2 } = await read(q("parser", `&after=${encodeURIComponent(page1.next!)}`));
  assert.equal(page2.rows.length, 5);
  assert.equal(page2.total, 30);
  assert.equal(page2.next, null);
  assert.deepEqual(new Set([...page1.rows, ...page2.rows].map((r) => r.id)).size, 30);
});

test("H5: with the switch both hold, and the tour keeps its found names", async () => {
  const read = await serve(3, (i) => `Rename the parser helper ${i}.`);
  const { vm } = await read(q("api.stripe.com", "&only=stepped-in"));
  assert.deepEqual(vm.rows.map((r) => r.id), [TOUR]);
  assert.deepEqual(names(vm.rows[0]), ["a send to api.stripe.com"]);
  assert.deepEqual(vm.only, { through: 4 });
  assert.equal(vm.total, 4, "every session it may look through");
  const { vm: plainOnly } = await read(q("parser", "&only=stepped-in"));
  assert.deepEqual(plainOnly.rows, [], "the plain sessions match, but Mandu did not step in");
});

test("H6: a host Mandu blocked every send to is 'a blocked send to', going to the blocked steps; one both sent to and blocked stays 'a send to' (#301)", async () => {
  const read = await serve(2, (i) => `Rename the parser helper ${i}.`, withBlockedPastebin);
  const { vm, text } = await read(q("pastebin"));
  assert.deepEqual(vm.rows.map((r) => r.id), [TOUR]);
  assert.equal(vm.rows[0]!.found?.[0]?.name, "a blocked send to pastebin.com");
  assert.deepEqual(vm.rows[0]!.found, [{ name: "a blocked send to pastebin.com", go: "blocked" }]);
  assert.doesNotMatch(text, /a send to pastebin/, "never read as sent");
  const { vm: stripe } = await read(q("api.stripe.com"));
  assert.deepEqual(stripe.rows[0]!.found, [{ name: "a send to api.stripe.com", go: "sent" }], "sent once and blocked once: a send");
  const { vm: key } = await read(q("STRIPE_KEY"));
  assert.deepEqual(key.rows[0]!.found, [{ name: "STRIPE_KEY in ~/mandu-try/.env", go: "secrets" }]);
  const { vm: com } = await read(q(".com"));
  assert.deepEqual(com.rows[0]!.found, [{ name: "a send to api.stripe.com", go: "sent" }, { name: "a blocked send to pastebin.com", go: "blocked" }]);
  for (const t of [text, JSON.stringify(stripe), JSON.stringify(com)]) {
    for (const v of FAKE_VALUES) assert.ok(!t.includes(v), `CONFIDENTIALITY VIOLATION: History served ${v}`);
    assert.doesNotMatch(t, /\$MDU:/);
  }
});
