/**
 * history-stepped-in.test — dashboard.md §4.25ae *Only the sessions where
 * Mandu stepped in*, over the real DashboardServer and the fixture sessions
 * (product-only build): `GET /api/home/history?only=stepped-in` keeps
 * exactly the rows of the plain read that `historyFlagged` keeps, in
 * order, counted the same, a session that ran with protection off among
 * them (2026-10-30, nightly #183), and so is a session where a protection
 * did not start (`lessProtection`, Shoemaker #267); a question still waiting keeps a
 * session, and so does an ended one whose believed exit names changes
 * Mandu did not apply (`notApplied`, §4.25b, on Home's rows too); any other
 * `only` is no filter; with `q`, both hold (`total` then every session it
 * may look through, since #249); signed out, metadata only.
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
import { historyFlagged, steppedIn, type HistoryVM } from "../../src/view-model/home.js";

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
// A session that ran with protection off (the launcher's recorded mode, as
// the arbiter reported it): nothing masked, nothing blocked.
const OFF = "sess-off1";
writeFileSync(join(DIR, `${OFF}.ndjson`), [
  {
    id: "01J00000000000000000OFF000", sessionId: OFF, turn: 0, ts: "2026-06-14T09:00:00.000Z", seq: 0, callId: null, parentId: null,
    kind: "launch_posture", view: "HumanView", boundary: "shell", emitter: "launcher", target: "claude",
    protection: { mode: "off", integrity: false, confidentiality: false, reported: true },
  },
  {
    id: "01J00000000000000000OFF001", sessionId: OFF, turn: 0, ts: "2026-06-14T09:00:01.000Z", seq: 1, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: "▸ user\nTidy the README.", original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  },
].map((e) => JSON.stringify(e)).join("\n") + "\n");
// A session where one of Mandu's protections did not start (the launcher's
// own line, so its listing health counts `droppedProtections: 1`) and
// nothing else happened: protection on, nothing masked, nothing blocked.
const LESS = "sess-less1";
const DROP_LINE = "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)";
writeFileSync(join(DIR, `${LESS}.ndjson`), [
  {
    id: "01J0000000000000000LESS000", sessionId: LESS, turn: 0, ts: "2026-06-13T09:00:00.000Z", seq: 0, callId: null, parentId: null,
    kind: "launch_posture", view: "HumanView", boundary: "shell", emitter: "launcher", target: "claude", live: ["fs"], dropped: [DROP_LINE],
    protection: { mode: "secrets", integrity: false, confidentiality: true, reported: true },
    input: null, output: null, invariant: { violatedInvariant: false },
  },
  {
    id: "01J0000000000000000LESS001", sessionId: LESS, turn: 0, ts: "2026-06-13T09:00:01.000Z", seq: 1, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: "▸ user\nFix the typo in the changelog.", original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  },
].map((e) => JSON.stringify(e)).join("\n") + "\n");
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

test("?only=stepped-in keeps exactly the rows historyFlagged keeps, an Off session and a less protected one among them, in order and counted the same; total still counts every session", async () => {
  const read = await serve();
  const { vm: all } = await read("?limit=100");
  assert.equal(all.rows.length, 6);
  const kept = all.rows.filter(historyFlagged);
  assert.deepEqual(all.rows.filter((r) => !historyFlagged(r)).map((r) => r.id).sort(), PLAIN, "the plain sessions are the ones not kept");
  assert.equal(kept.length, 4);
  const off = all.rows.find((r) => r.id === OFF)!;
  assert.equal(off.protectionOff, true, "the recorded mode is off");
  assert.equal(steppedIn(off), false, "Mandu did not step in there");
  assert.ok(kept.includes(off), "yet the switch keeps it: its counts line says protection was off");
  const less = all.rows.find((r) => r.id === LESS)!;
  assert.equal(less.lessProtection, true, "a protection did not start in it");
  assert.equal(less.protectionOff, false, "protection was on");
  assert.equal(steppedIn(less), false, "Mandu did not step in there");
  assert.ok(kept.includes(less), "yet the switch keeps it (Shoemaker #267): its counts line says less protection than usual");
  const { vm, text } = await read("?only=stepped-in&limit=100");
  assert.deepEqual(vm.rows, kept, "the same rows, as the plain read draws them, the Off and the less protected one in their place");
  assert.equal(vm.rows.find((r) => r.id === OFF)?.protectionOff, true);
  assert.equal(vm.rows.find((r) => r.id === LESS)?.lessProtection, true);
  assert.doesNotMatch(text, /net-proxy|8790|WITHOUT/, "a mark, never the launch line");
  assert.equal(vm.total, all.total);
  assert.equal(vm.next, null);
  assert.deepEqual(vm.only, { through: all.total }, "every session looked through");
  assert.doesNotMatch(text, /\$MDU:|ignore all prior instructions|acme\.example/, "metadata only");
  // Page by page, the same rows.
  const first = (await read("?only=stepped-in&limit=1")).vm;
  assert.deepEqual(first.rows.map((r) => r.id), [kept[0]!.id]);
  let next = first.next;
  for (const want of kept.slice(1)) {
    assert.ok(next, "more to look through");
    const page = (await read(`?only=stepped-in&limit=1&after=${encodeURIComponent(next!)}`)).vm;
    assert.deepEqual(page.rows.map((r) => r.id), [want.id]);
    next = page.next;
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
  assert.deepEqual(both.rows.map((r) => r.id), found.rows.filter(historyFlagged).map((r) => r.id));
  assert.deepEqual(found.rows.map((r) => r.id).sort(), PLAIN, "the search finds both plain sessions");
  assert.deepEqual(both.rows.map((r) => r.id), [plain.id], "and the switch keeps the one waiting");
  // Since #249 a search also reads each session's secrets and hosts, so
  // how many match is not known before every session is read: with the
  // switch, `total` is every session it may look through, as without a
  // search (§4.25ae *By a secret or a host*).
  assert.equal(both.total, all.total, "total counts every session the switch may look through");
  assert.deepEqual(both.only, { through: all.total });
  assert.equal(both.query?.text, word);
});

test("a believed launcher exit naming changed masked copies gives the session's Home and History rows notApplied, a count only; the same exit as a claim gives none; the switch keeps it (§4.25b *Home and History say so*)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-history-not-applied-"));
  try {
    const at = (s: number) => new Date(NOW - 3_600_000 + s * 1000).toISOString();
    const session = (sid: string, exit: Record<string, unknown>) => [
      {
        id: `01J0000000000000000${sid}0`, sessionId: sid, turn: 0, ts: at(0), seq: 0, callId: null, parentId: null,
        kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
        input: { symbolized: "▸ user\nAdd STRIPE_WEBHOOK_SECRET to .env.", original: null, differs: false, symbols: [] },
        output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
      },
      {
        id: `01J0000000000000000${sid}1`, sessionId: sid, turn: 0, ts: at(1), seq: 1, callId: null, parentId: null,
        kind: "session_exit", view: "HumanView", boundary: "shell", emitter: "launcher", input: null, output: null,
        invariant: { violatedInvariant: false }, code: 0, durationMs: 1000, discardedWrites: ["/h/app/.env"], ...exit,
      },
    ].map((e) => JSON.stringify(e)).join("\n") + "\n";
    writeFileSync(join(dir, "sess-lost.ndjson"), session("LOST", {}));
    writeFileSync(join(dir, "sess-claim.ndjson"), session("CLAIM", { claimed: true }));
    const server = new DashboardServer({ source: new FileEventSource(dir), log: () => {} });
    servers.push(server);
    const base = `http://127.0.0.1:${await server.listen(0)}`;
    const read = async (path: string) => {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.status, 200, path);
      return res.text();
    };
    const histText = await read("/api/home/history?limit=100");
    const hist = JSON.parse(histText) as HistoryVM;
    const row = (id: string) => hist.rows.find((r) => r.id === id)!;
    assert.equal(row("sess-lost").state, "idle");
    assert.equal(row("sess-lost").notApplied, 1);
    assert.equal("notApplied" in row("sess-claim"), false, "a claim never raises it");
    assert.equal(steppedIn(row("sess-lost")), false, "Home's last-stepped-in line does not name it");
    const only = JSON.parse(await read("/api/home/history?only=stepped-in&limit=100")) as HistoryVM;
    assert.deepEqual(only.rows.map((r) => r.id), ["sess-lost"], "the switch keeps it, not the claim");
    const homeText = await read("/api/home");
    const homeVm = JSON.parse(homeText) as { agents: { id: string; state: string; notApplied?: number }[] };
    const earlier = homeVm.agents.find((a) => a.id === "sess-lost")!;
    assert.equal(earlier.state, "idle");
    assert.equal(earlier.notApplied, 1, "Home's Earlier row");
    assert.equal("notApplied" in homeVm.agents.find((a) => a.id === "sess-claim")!, false);
    for (const text of [histText, homeText]) assert.doesNotMatch(text, /\/h\/app|~\/app/, "a count, never the path");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
