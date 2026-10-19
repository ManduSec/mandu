/**
 * history-stepped-in.test — dashboard.md §4.25ae *Only the sessions where
 * Mandu stepped in*, over the real DashboardServer and the fixture sessions
 * (product-only build): `GET /api/home/history?only=stepped-in` keeps
 * exactly the rows of the plain read that `steppedIn` keeps, in order,
 * counted the same; a question still waiting keeps a session; any other
 * `only` is no filter; with `q`, both hold; signed out, metadata only.
 *
 * Axes: the stub snapshot serves the Secrets posture; display only, no
 * arbiter runs.
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import { steppedIn, type HistoryVM } from "../../src/view-model/home.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");
const NOW = Date.now();

// The two fixture sessions (Mandu stepped in on both: a failed protection,
// untrusted items masked) and two plain ones, a prompt and a reply each.
const DIR = mkdtempSync(join(tmpdir(), "mandu-history-stepped-in-"));
for (const f of ["sess-7af3.ndjson", "sess-bad9.ndjson"]) copyFileSync(join(FIXTURES_DIR, f), join(DIR, f));
const PLAIN = ["sess-plain1", "sess-plain2"];
for (const [i, sid] of PLAIN.entries()) {
  writeFileSync(join(DIR, `${sid}.ndjson`), JSON.stringify({
    id: `01J00000000000000000PLAIN${i}`, sessionId: sid, turn: 0, ts: `2026-06-1${5 + i}T10:00:00.000Z`, seq: 0, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: `▸ user\nRename the parser helper ${i}.`, original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  }) + "\n");
}
after(() => rmSync(DIR, { recursive: true, force: true }));

/** A file source behind which an arbiter serves the Secrets posture and a
 *  queue of `waiting` pending asks, one per session named. */
class QueueSource extends FileEventSource {
  constructor(dir: string, private readonly waiting: string[]) { super(dir); }
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    const verdicts: VerdictEntry[] = this.waiting.map((sid, i) => ({
      id: `egr-${i}`, symbol: `$MDU:nomodel_Read[${i}abc].STRIPE_KEY`, destination: "api.stripe.com", status: "pending",
      reason: "secret symbol (no-model) at unbound destination", count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000,
      resolvedAt: null, sessions: [sid],
    } as VerdictEntry));
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true },
      usage: { rules: [], sensitivePaths: [] },
      verdicts,
    } as unknown as PolicySnapshot;
  }
}

const servers: DashboardServer[] = [];
after(async () => { for (const s of servers) await s.close(); });

async function serve(waiting: string[] = []): Promise<(query: string) => Promise<{ vm: HistoryVM; text: string }>> {
  const server = new DashboardServer({ source: new QueueSource(DIR, waiting), log: () => {} });
  servers.push(server);
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  return async (query) => {
    const res = await fetch(`${base}/api/home/history${query}`);
    assert.equal(res.status, 200, "signed out, the History read is open");
    const text = await res.text();
    return { vm: JSON.parse(text) as HistoryVM, text };
  };
}

test("?only=stepped-in keeps exactly the rows steppedIn keeps, in order and counted the same; total still counts every session", async () => {
  const read = await serve();
  const { vm: all } = await read("?limit=100");
  assert.equal(all.rows.length, 4);
  const kept = all.rows.filter(steppedIn);
  assert.deepEqual(all.rows.filter((r) => !steppedIn(r)).map((r) => r.id).sort(), PLAIN, "the plain sessions are the ones not kept");
  assert.equal(kept.length, 2);
  const { vm, text } = await read("?only=stepped-in&limit=100");
  assert.deepEqual(vm.rows, kept, "the same rows, as the plain read draws them");
  assert.equal(vm.total, all.total);
  assert.equal(vm.next, null);
  assert.deepEqual(vm.only, { through: all.total }, "every session looked through");
  assert.doesNotMatch(text, /\$MDU:|ignore all prior instructions|acme\.example/, "metadata only");
  // Page by page, the same rows.
  const first = (await read("?only=stepped-in&limit=1")).vm;
  assert.deepEqual(first.rows.map((r) => r.id), [kept[0]!.id]);
  if (kept.length > 1) {
    assert.ok(first.next, "more to look through");
    const second = (await read(`?only=stepped-in&limit=1&after=${encodeURIComponent(first.next!)}`)).vm;
    assert.deepEqual(second.rows.map((r) => r.id), [kept[1]!.id]);
  }
  // Any other value is no filter.
  const other = (await read("?only=everything&limit=100")).vm;
  assert.deepEqual(other.rows.map((r) => r.id), all.rows.map((r) => r.id));
  assert.equal("only" in other, false);
});

test("a question still waiting keeps a plain session; with q, both hold", async () => {
  const plainRead = await serve();
  const { vm: all } = await plainRead("?limit=100");
  const plain = all.rows.find((r) => r.id === PLAIN[0]);
  assert.ok(plain && !steppedIn(plain), "a plain session");
  const read = await serve([plain.id]);
  const { vm } = await read("?only=stepped-in&limit=100");
  const row = vm.rows.find((r) => r.id === plain.id);
  assert.ok(row, "kept: a question it raised waits");
  assert.equal(row.waiting, 1);
  // With a search: the matches that Mandu stepped in on.
  const word = "parser";
  const found = (await read(`?q=${encodeURIComponent(word)}&limit=100`)).vm;
  const both = (await read(`?q=${encodeURIComponent(word)}&only=stepped-in&limit=100`)).vm;
  assert.deepEqual(both.rows.map((r) => r.id), found.rows.filter(steppedIn).map((r) => r.id));
  assert.deepEqual(found.rows.map((r) => r.id).sort(), PLAIN, "the search finds both plain sessions");
  assert.deepEqual(both.rows.map((r) => r.id), [plain.id], "and the switch keeps the one waiting");
  assert.equal(both.total, found.total, "total counts the search's matches");
  assert.equal(both.query?.text, word);
});
