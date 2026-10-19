/**
 * history-waiting.test — dashboard.md §4.25ae *History says what waits for
 * you*, over the real DashboardServer and the fixture sessions (product-only
 * build): `GET /api/home/history` counts on each row the questions its
 * session raised that still wait, from the queue Home reads.
 *
 *   - the arbiter's snapshot serves the queue: each pending ask counted on
 *     the session that raised it last, an answered one on none;
 *   - an older arbiter whose snapshot has no queue: the approvals op fills
 *     it in, as for Home;
 *   - no arbiter: nothing is said to wait;
 *   - signed out, the answer is metadata only: no event payload, no token.
 *
 * Axes: the stub snapshot serves the Secrets posture; display only, no
 * arbiter runs.
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import type { HistoryVM } from "../../src/view-model/home.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");
const BAD = "sess-bad9";
const GOOD = "sess-7af3";
const NOW = Date.now();

const ask = (id: string, sessions: string[], over: Partial<VerdictEntry> = {}): VerdictEntry => ({
  id, symbol: `$MDU:nomodel_Read[${id.slice(-1)}abc].STRIPE_KEY`, destination: "api.stripe.com", status: "pending",
  reason: "secret symbol (no-model) at unbound destination", count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000,
  resolvedAt: null, sessions, ...over,
} as VerdictEntry);
const QUEUE: VerdictEntry[] = [
  ask("egr-1", [GOOD]),
  ask("egr-2", [GOOD, BAD], { destination: "hooks.example.com" }),
  ask("egr-3", [GOOD], { destination: "paste.example", status: "denied", resolvedAt: NOW - 1_000 }),
];

/** A file source behind which an arbiter serves the Secrets posture and,
 *  unless it is an older one, the queue. */
class QueueSource extends FileEventSource {
  constructor(dir: string, private readonly queue: VerdictEntry[] | undefined) { super(dir); }
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true },
      usage: { rules: [], sensitivePaths: [] },
      ...(this.queue ? { verdicts: this.queue } : {}),
    } as unknown as PolicySnapshot;
  }
}

const servers: DashboardServer[] = [];
after(async () => { for (const s of servers) await s.close(); });

async function history(opts: ConstructorParameters<typeof DashboardServer>[0]): Promise<{ vm: HistoryVM; text: string }> {
  const server = new DashboardServer({ ...opts, log: () => {} });
  servers.push(server);
  const res = await fetch(`http://127.0.0.1:${await server.listen(0)}/api/home/history`);
  assert.equal(res.status, 200);
  const text = await res.text();
  return { vm: JSON.parse(text) as HistoryVM, text };
}
const waitingOf = (vm: HistoryVM) => Object.fromEntries(vm.rows.filter((r) => r.id === GOOD || r.id === BAD).map((r) => [r.id, r.waiting]));

test("History's rows count the questions each session raised that still wait, on the one that raised each last; signed out, no payload", async () => {
  const { vm, text } = await history({ source: new QueueSource(FIXTURES_DIR, QUEUE) });
  assert.deepEqual(waitingOf(vm), { [GOOD]: 1, [BAD]: 1 });
  for (const r of vm.rows) if (r.id !== GOOD && r.id !== BAD) assert.equal(r.waiting, 0, r.id);
  assert.doesNotMatch(text, /\$MDU:|ignore all prior instructions|acme\.example/, "metadata only");
});

test("an older arbiter's snapshot has no queue: the approvals op fills it in, as for Home; no arbiter: nothing waits", async () => {
  const older = await history({
    source: new QueueSource(FIXTURES_DIR, undefined),
    approvalsArbiter: { egressApprovals: async () => QUEUE, resolveEgressApproval: async () => { throw new Error("not asked"); } },
  });
  assert.deepEqual(waitingOf(older.vm), { [GOOD]: 1, [BAD]: 1 });
  const none = await history({ source: new FileEventSource(FIXTURES_DIR) });
  assert.deepEqual(waitingOf(none.vm), { [GOOD]: 0, [BAD]: 0 });
});
