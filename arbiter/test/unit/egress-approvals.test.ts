/**
 * egress-approvals.test.ts — the arbiter-side egress-approval queue over a real
 * Unix socket (Mandu-new test, no reference origin).
 *
 * Stands up a real ArbiterServer wired to the engine-backed policy (symbolLookup
 * over the live SymbolMap) and exercises the interactive approval queue end to
 * end over an actual socket:
 *   - A NETWORK desymbolizationDecision that denies (untrusted destination)
 *     records ONE pending entry; a repeat of the same {symbol, destination}
 *     increments count, still one entry.
 *   - egressApprovals lists it (status pending).
 *   - resolveEgressApproval(id, approve:true) → approved, and the SAME
 *     {symbol, destination} decision then returns allow:true (human-approved).
 *   - resolveEgressApproval(id, approve:false) → denied, the decision stays
 *     blocked (requiresApproval:false, human-denied).
 *   - Unknown id → error. A different {symbol, destination} is independent.
 *   - Session attribution: a request's sessionKey lands in the row's `sessions`
 *     (store-level order/cap/persistence + server-level threading; never a
 *     decision input).
 *
 * Run: npm run test:unit
 */

import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { EgressApprovalStore } from "../../policy/egress-approvals.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;
let server: ArbiterServer;
let client: ArbiterClient;
let socketPath: string;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-egr-approval-"));
  socketPath = join(workdir, "arbiter.sock");
  server = new ArbiterServer({
    socketPath,
    dbPath: join(workdir, "symbols.db"),
    adminSocketPath: join(workdir, "admin.sock"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  await server.listen();
  client = new ArbiterClient(join(workdir, "admin.sock"));
  await client.connect();
});

after(async () => {
  client.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

// Each test allocates a FRESH symbol (unique value) so the {symbol, destination}
// key is independent across tests — no cross-test state in the shared store.
let counter = 0;
beforeEach(() => { counter += 1; });

async function symbolize(value: string, field = "text"): Promise<string> {
  return client.symbolize({ tool: "WebFetch", field, value });
}

const EVIL = "https://evil.example/collect";

// ─────────────────────────────────────────────────────────────────────────────

test("denied network egress records ONE pending entry; a repeat increments count", async () => {
  const sym = await symbolize(`secret-${counter}`);

  // First attempt → denied (untrusted destination), upserts a pending entry.
  const d1 = await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  assert.equal(d1.allow, false);
  assert.equal((d1 as { requiresApproval: boolean }).requiresApproval, true);

  const after1 = (await client.egressApprovals()).filter((a) => a.symbol === sym && a.destination === EVIL);
  assert.equal(after1.length, 1, "exactly one entry for this {symbol, destination}");
  assert.equal(after1[0].status, "pending");
  assert.equal(after1[0].count, 1);
  const firstSeen = after1[0].firstSeen;

  // Second IDENTICAL attempt → still denied, still ONE entry, count incremented.
  const d2 = await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  assert.equal(d2.allow, false);

  const after2 = (await client.egressApprovals()).filter((a) => a.symbol === sym && a.destination === EVIL);
  assert.equal(after2.length, 1, "still exactly one entry (idempotent upsert)");
  assert.equal(after2[0].count, 2);
  assert.equal(after2[0].firstSeen, firstSeen, "firstSeen is stable");
  assert.ok(after2[0].lastSeen >= firstSeen, "lastSeen advances (or equal)");
});

test("egressApprovals lists the pending entry, filterable by status", async () => {
  const sym = await symbolize(`token-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });

  const pending = await client.egressApprovals("pending");
  const mine = pending.filter((a) => a.symbol === sym && a.destination === EVIL);
  assert.equal(mine.length, 1);
  assert.equal(mine[0].status, "pending");
  assert.match(mine[0].reason, /untrusted destination/);

  // It is NOT in the approved/denied lists yet.
  const approved = await client.egressApprovals("approved");
  assert.equal(approved.filter((a) => a.symbol === sym).length, 0);
});

test("approve → subsequent identical decision returns allow:true (human-approved)", async () => {
  const sym = await symbolize(`approve-me-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });

  const entry = (await client.egressApprovals("pending")).find((a) => a.symbol === sym && a.destination === EVIL);
  assert.ok(entry, "entry must be queued");

  const resolved = await client.resolveEgressApproval(entry!.id, true);
  assert.equal(resolved.status, "approved");
  assert.equal(resolved.id, entry!.id);

  // The SAME {symbol, destination} now resolves to allow.
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  assert.equal(d.allow, true);
  assert.equal(d.reason, "human-approved");
});

test("deny → subsequent identical decision stays blocked (requiresApproval:false, human-denied)", async () => {
  const sym = await symbolize(`deny-me-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });

  const entry = (await client.egressApprovals("pending")).find((a) => a.symbol === sym && a.destination === EVIL);
  assert.ok(entry, "entry must be queued");

  const resolved = await client.resolveEgressApproval(entry!.id, false);
  assert.equal(resolved.status, "denied");

  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  assert.equal(d.allow, false);
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, false, "no re-prompt after a human denial");
  assert.equal(d.reason, "human-denied");
});

test("resolveEgressApproval with an unknown id errors", async () => {
  await assert.rejects(
    () => client.resolveEgressApproval("egr-does-not-exist", true),
    /unknown egress-approval id/,
  );
});

test("a different {symbol, destination} is an independent entry", async () => {
  const symA = await symbolize(`indep-a-${counter}`);
  const symB = await symbolize(`indep-b-${counter}`);
  const DEST_B = "https://other-attacker.example/x";

  await client.desymbolizationDecision({ symbol: symA, boundary: "network", destination: EVIL });
  await client.desymbolizationDecision({ symbol: symB, boundary: "network", destination: DEST_B });

  // Approving A leaves B untouched.
  const entryA = (await client.egressApprovals("pending")).find((a) => a.symbol === symA && a.destination === EVIL);
  assert.ok(entryA);
  await client.resolveEgressApproval(entryA!.id, true);

  const dA = await client.desymbolizationDecision({ symbol: symA, boundary: "network", destination: EVIL });
  assert.equal(dA.allow, true, "A approved");

  const dB = await client.desymbolizationDecision({ symbol: symB, boundary: "network", destination: DEST_B });
  assert.equal(dB.allow, false, "B still pending → blocked");
  assert.equal((dB as { requiresApproval: boolean }).requiresApproval, true);

  // Same symbol A but a DIFFERENT destination is also independent (not approved).
  const dAOther = await client.desymbolizationDecision({ symbol: symA, boundary: "network", destination: DEST_B });
  assert.equal(dAOther.allow, false, "A→other-destination is a distinct, unapproved key");
});

test("a symbol-as-command denial (non-network) does NOT enter the network queue", async () => {
  const sym = await symbolize(`cmd-${counter}`);
  const before = (await client.egressApprovals()).length;
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "shell", asCommand: true });
  assert.equal(d.allow, false);
  // The queue only tracks NETWORK egress (it needs a {symbol, destination} key).
  const afterList = await client.egressApprovals();
  assert.equal(afterList.length, before, "no queue entry for a non-network denial");
});

test("an allow-path network egress does NOT queue (unknown symbol → no-op)", async () => {
  const before = (await client.egressApprovals()).length;
  const d = await client.desymbolizationDecision({
    symbol: "$MDU:WebFetch[ffff].text",
    boundary: "network",
    destination: EVIL,
  });
  assert.equal(d.allow, true, "unknown symbol → nothing to leak → allow");
  const afterList = await client.egressApprovals();
  assert.equal(afterList.length, before, "an allow verdict never queues");
});

// ── EgressApprovalStore unit tests (no socket; injectable clock) ─────────────

test("store: recordPending is idempotent by key, increments count, keeps firstSeen", () => {
  let t = 1000;
  const store = new EgressApprovalStore({ now: () => t });
  const a = store.recordPending("$sym", "dest", "reason-1");
  assert.equal(a.status, "pending");
  assert.equal(a.count, 1);
  assert.equal(a.firstSeen, 1000);
  assert.equal(a.lastSeen, 1000);

  t = 2000;
  const b = store.recordPending("$sym", "dest", "reason-2");
  assert.equal(b.id, a.id, "same key → same entry");
  assert.equal(b.count, 2);
  assert.equal(b.firstSeen, 1000, "firstSeen unchanged");
  assert.equal(b.lastSeen, 2000, "lastSeen bumped");
  assert.equal(store.list().length, 1);
});

test("store: lookup reflects resolve; list filters and copies", () => {
  const store = new EgressApprovalStore({ now: () => 1 });
  const e = store.recordPending("$s", "d", "r");
  assert.equal(store.lookup("$s", "d"), "pending");

  const resolved = store.resolve(e.id, true);
  assert.equal(resolved?.status, "approved");
  assert.equal(store.lookup("$s", "d"), "approved");

  assert.equal(store.list({ status: "approved" }).length, 1);
  assert.equal(store.list({ status: "pending" }).length, 0);

  // list() returns copies — mutating one must not corrupt the store.
  const copy = store.list()[0];
  copy.status = "denied";
  assert.equal(store.lookup("$s", "d"), "approved");
});

test("store: resolve on an unknown id returns undefined", () => {
  const store = new EgressApprovalStore();
  assert.equal(store.resolve("nope", true), undefined);
});

// ── SQLite persistence: the queue survives a arbiter restart ──────────────────

test("store: persists across restart — a second instance over the SAME DB sees prior entries", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-persist-"));
  const dbPath = join(dir, "symbols.db");
  try {
    let t = 1000;
    const clock = () => t;

    // ── Instance #1: record a pending + an approved entry, then "shut down".
    const s1 = new EgressApprovalStore({ now: clock, dbPath });
    const pending = s1.recordPending("$sym-pending", "https://evil.example/x", "untrusted destination");
    assert.equal(pending.status, "pending");

    t = 1100;
    const toApprove = s1.recordPending("$sym-approved", "https://ok.example/y", "untrusted destination");
    t = 1200;
    const approved = s1.resolve(toApprove.id, true);
    assert.equal(approved?.status, "approved");
    s1.close();

    // ── Instance #2: a fresh store over the SAME file == a arbiter restart. Its
    // in-memory maps start empty and must hydrate from the table.
    t = 9000;
    const s2 = new EgressApprovalStore({ now: clock, dbPath });

    // list() returns both persisted entries.
    const all = s2.list();
    assert.equal(all.length, 2, "both entries recovered from disk");

    // lookup() returns the persisted status per pair.
    assert.equal(s2.lookup("$sym-pending", "https://evil.example/x"), "pending");
    assert.equal(s2.lookup("$sym-approved", "https://ok.example/y"), "approved");

    // The approved pair would now ALLOW on the next egress decision: the arbiter's
    // gate consults lookup() === "approved" and short-circuits to allow. We assert
    // the persisted status the gate keys on rather than re-running the gate here.
    assert.equal(
      s2.lookup("$sym-approved", "https://ok.example/y"),
      "approved",
      "approved pair persists → gate would allow after restart",
    );

    // Recovered counts/timestamps round-trip exactly.
    const recoveredApproved = all.find((a) => a.symbol === "$sym-approved");
    assert.equal(recoveredApproved?.count, 1);
    assert.equal(recoveredApproved?.firstSeen, 1100);
    assert.equal(recoveredApproved?.lastSeen, 1200, "lastSeen from the resolve persisted");

    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("store: UNIQUE(symbol,destination) keeps idempotency across restart (no dup row, count carries)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-idem-"));
  const dbPath = join(dir, "symbols.db");
  try {
    let t = 1000;
    const clock = () => t;

    const s1 = new EgressApprovalStore({ now: clock, dbPath });
    const first = s1.recordPending("$dup", "https://evil.example/z", "r1");
    assert.equal(first.count, 1);
    s1.close();

    // Restart, then re-record the SAME {symbol, destination}: must update the
    // existing row (count → 2), never insert a duplicate.
    t = 2000;
    const s2 = new EgressApprovalStore({ now: clock, dbPath });
    assert.equal(s2.list().length, 1, "one row hydrated");
    const again = s2.recordPending("$dup", "https://evil.example/z", "r2");
    assert.equal(again.id, first.id, "same key → same (recovered) id");
    assert.equal(again.count, 2, "count carried across restart and incremented");
    assert.equal(again.firstSeen, 1000, "firstSeen preserved from the pre-restart row");
    assert.equal(again.lastSeen, 2000);
    assert.equal(s2.list().length, 1, "still exactly one row — no duplicate");
    s2.close();

    // Confirm at the persistence layer too: a THIRD instance still sees one row
    // with count 2 (the upsert wrote through, no dup).
    const s3 = new EgressApprovalStore({ now: clock, dbPath });
    const rows = s3.list();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].count, 2);
    s3.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("store: a write error surfaces but does not corrupt in-memory state", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-werr-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const store = new EgressApprovalStore({ dbPath });
    const e = store.recordPending("$s", "d", "r");
    // Close the underlying DB out from under the store, then mutate. The write
    // throws (loud), but the in-memory entry is already updated and consistent.
    store.close();
    assert.throws(() => store.recordPending("$s", "d", "r2"));
    // In-memory state still reflects the (attempted) mutation: count advanced,
    // key still resolvable — no corruption / no lost entry.
    assert.equal(store.lookup("$s", "d"), "pending");
    const live = store.list().find((a) => a.id === e.id);
    assert.equal(live?.count, 2, "in-memory count advanced despite the write failure");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Session attribution (EgressApproval.sessions) ─────────────────────────────
// Attribution ONLY — no decision reads it; a pending row names the sessions
// that created/bumped it (most-recent-LAST, capped at 8, oldest evicted).

test("store: recordPending stamps sessions; same key refreshes to the end, distinct keys accumulate", () => {
  const store = new EgressApprovalStore({ now: () => 1 });
  const a = store.recordPending("$s", "d", "r", "sess-A");
  assert.deepEqual(a.sessions, ["sess-A"]);

  store.recordPending("$s", "d", "r", "sess-B");
  assert.deepEqual(store.list()[0]!.sessions, ["sess-A", "sess-B"], "distinct keys accumulate");

  // Repeat with the SAME key: no duplicate — the key moves to the END
  // (most-recent-LAST).
  store.recordPending("$s", "d", "r", "sess-A");
  assert.deepEqual(store.list()[0]!.sessions, ["sess-B", "sess-A"]);

  // No sessionKey → attribution untouched (never cleared).
  store.recordPending("$s", "d", "r");
  assert.deepEqual(store.list()[0]!.sessions, ["sess-B", "sess-A"]);
});

test("store: the 9th distinct session key evicts the oldest (cap 8)", () => {
  const store = new EgressApprovalStore({ now: () => 1 });
  for (let i = 1; i <= 9; i += 1) store.recordPending("$s", "d", "r", `sess-${i}`);
  assert.deepEqual(
    store.list()[0]!.sessions,
    ["sess-2", "sess-3", "sess-4", "sess-5", "sess-6", "sess-7", "sess-8", "sess-9"],
    "capped at 8 — sess-1 (oldest) evicted",
  );
});

test("store: sessions survive a restart — a second instance over the SAME DB", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-sess-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const s1 = new EgressApprovalStore({ now: () => 1000, dbPath });
    s1.recordPending("$sym", "dest", "r", "sess-A");
    s1.recordPending("$sym", "dest", "r", "sess-B");
    s1.recordPending("$bare", "dest", "r"); // no key → []
    s1.close();

    const s2 = new EgressApprovalStore({ now: () => 2000, dbPath });
    assert.deepEqual(
      s2.list().find((a) => a.symbol === "$sym")?.sessions,
      ["sess-A", "sess-B"],
      "sessions hydrate in order",
    );
    assert.deepEqual(s2.list().find((a) => a.symbol === "$bare")?.sessions, []);
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});


test("sessionKey on a gated request lands in the queue row's sessions (both gate families)", async () => {
  // Network egress family.
  const sym = await symbolize(`sess-net-${counter}`);
  await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL, sessionKey: "sess-A",
  });
  const netEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(netEntry);
  assert.deepEqual(netEntry!.sessions, ["sess-A"]);

  // fs-path family.
  const probe = `/opt/sess-probe-${counter}`;
  await client.fsPathDecision({
    tool: "Read", path: probe, mode: "read", workspaceRoots: [], sessionKey: "sess-A",
  });
  const fsEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Read:read" && a.destination === probe,
  );
  assert.ok(fsEntry);
  assert.deepEqual(fsEntry!.sessions, ["sess-A"]);
});

test("a gated request WITHOUT sessionKey leaves sessions []", async () => {
  const sym = await symbolize(`sess-none-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);
  assert.deepEqual(entry!.sessions, []);
});

// ── Decision provenance (policy-surface.md §9.3): a standing human verdict
// stamps `verdict:<entryId>` on the short-circuited decision, on BOTH the
// network-egress and fs-path key families. The prose reason stays; the ruleRef
// is the machine-readable join the dashboard uses to link the event to the
// Policy panel's verdict row.
test("a human verdict stamps verdict:<id> provenance on both gate families", async () => {
  // Network egress family.
  const sym = await symbolize(`prov-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const netEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(netEntry);
  await client.resolveEgressApproval(netEntry!.id, true);
  const allowed = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal(allowed.allow, true);
  assert.deepEqual(allowed.ruleRef, { source: "verdict", id: `verdict:${netEntry!.id}` });
  await client.resolveEgressApproval(netEntry!.id, false);
  const denied = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal(denied.allow, false);
  assert.deepEqual(denied.ruleRef, { source: "verdict", id: `verdict:${netEntry!.id}` });

  // fs-path family (the egr-2 incident's shape).
  const probe = `/opt/prov-probe-${counter}`;
  const fresh = await client.fsPathDecision({
    tool: "Glob", path: probe, mode: "read", workspaceRoots: [],
  });
  assert.equal(fresh.allow, false);
  assert.equal(fresh.ruleRef?.id, "fs:default-deny");
  const fsEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Glob:read" && a.destination === probe,
  );
  assert.ok(fsEntry);
  await client.resolveEgressApproval(fsEntry!.id, true);
  const fsAllowed = await client.fsPathDecision({
    tool: "Glob", path: probe, mode: "read", workspaceRoots: [],
  });
  assert.equal(fsAllowed.allow, true);
  assert.deepEqual(fsAllowed.ruleRef, { source: "verdict", id: `verdict:${fsEntry!.id}` });
});

// A queued deny names its queue row (approvalId) so a session's gate events can
// be joined back to the Pending tab (policy-surface.md §9.5). All three key
// families; fresh AND repeat attempts carry the SAME id (the row is upserted).
test("a queued deny carries approvalId — same id on repeat, all three families", async () => {
  // Network egress family.
  const sym = await symbolize(`appr-${counter}`);
  const fresh = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal(fresh.allow, false);
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);
  assert.equal((fresh as { approvalId?: string }).approvalId, entry!.id);
  const repeat = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal((repeat as { approvalId?: string }).approvalId, entry!.id, "repeat bumps the SAME row");

  // fs-path family.
  const probe = `/opt/appr-probe-${counter}`;
  const fsDeny = await client.fsPathDecision({
    tool: "Read", path: probe, mode: "read", workspaceRoots: [],
  });
  assert.equal(fsDeny.allow, false);
  const fsEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Read:read" && a.destination === probe,
  );
  assert.ok(fsEntry);
  assert.equal((fsDeny as { approvalId?: string }).approvalId, fsEntry!.id);

  // exec-escalate family.
  const esc = await client.escalateExec({
    argv: ["curl", `https://appr-${counter}.example`], resource: "network",
  });
  assert.equal(esc.requiresApproval, true);
  const escEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "exec-escalate:network" && a.id === esc.approvalId,
  );
  assert.ok(escEntry, "escalation approvalId names its queue row");

  // A verdict short-circuit does NOT carry approvalId — its join key is the
  // ruleRef (verdict:<id>); nothing was queued.
  await client.resolveEgressApproval(entry!.id, false);
  const denied = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal((denied as { approvalId?: string }).approvalId, undefined);
});

// ── Verdict audit trail (policy-surface.md §9.6) ─────────────────────────────

test("resolvedAt: null while pending, stamped on resolve, survives restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-audit-"));
  const dbPath = join(dir, "mandu.db");
  try {
    let t = 1000;
    const store = new EgressApprovalStore({ dbPath, now: () => t });
    const e = store.recordPending("$sym", "dest", "reason");
    assert.equal(e.resolvedAt, null, "pending carries no resolution time");
    t = 2000;
    store.recordPending("$sym", "dest", "reason"); // repeat bumps lastSeen only
    assert.equal(store.list()[0]!.resolvedAt, null);
    t = 3000;
    store.resolve(e.id, true);
    assert.equal(store.list()[0]!.resolvedAt, 3000, "resolve stamps the clock");
    store.close();

    const reopened = new EgressApprovalStore({ dbPath });
    try {
      assert.equal(reopened.list()[0]!.resolvedAt, 3000, "resolvedAt hydrates");
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resolving a verdict lands ONE approval_resolved audit event in arbiter-admin", async () => {
  const sym = await symbolize(`audit-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);
  const before = (await client.events("arbiter-admin")).length;
  await client.resolveEgressApproval(entry!.id, false);
  const events = await client.events("arbiter-admin");
  assert.equal(events.length, before + 1, "exactly one audit event per resolution");
  const ev = events[events.length - 1]! as Record<string, any>;
  assert.equal(ev.kind, "approval_resolved");
  assert.equal(ev.emitter, "arbiter");
  assert.match(String(ev.output?.symbolized ?? ""), /DENIED by human/);
  assert.deepEqual(ev.policy?.ruleRef, { source: "verdict", id: `verdict:${entry!.id}` });
  // Audit lines carry key strings only — never a resolved value.
  assert.ok(!JSON.stringify(ev).includes(`audit-${counter}`), "no raw value in the audit event");
});

// ── Verdict scope: allow-once (dashboard.md §4.18's second verb) ──────────────
// "once" satisfies exactly ONE gated decision, then no longer applies; the next
// attempt for the pair re-queues a fresh ask. "always" (the default) keeps the
// pre-scope standing semantics untouched.

test("store: a once-verdict is spent by consumeOnce; recordPending then resets a fresh pending cycle", () => {
  let t = 1000;
  const store = new EgressApprovalStore({ now: () => t });
  const e = store.recordPending("$sym", "dest", "reason", "sess-a");
  assert.equal(e.scope, "always", "pending rows carry the default scope");
  assert.equal(e.consumedAt, null);

  t = 2000;
  const resolved = store.resolve(e.id, true, "once");
  assert.equal(resolved!.status, "approved");
  assert.equal(resolved!.scope, "once");
  assert.equal(resolved!.consumedAt, null, "resolving arms, not spends");

  t = 3000;
  const spent = store.consumeOnce(e.id);
  assert.equal(spent!.consumedAt, 3000, "consumption stamps the clock");
  assert.equal(spent!.status, "approved", "status is untouched by consumption");
  assert.equal(store.consumeOnce(e.id), undefined, "consumption is single");

  // The spent verdict's next attempt: recordPending resets the SAME row to a
  // fresh pending cycle, keeping the pair's identity and history.
  t = 4000;
  const again = store.recordPending("$sym", "dest", "new reason", "sess-b");
  assert.equal(again.id, e.id, "same row — the pair keeps its id");
  assert.equal(again.status, "pending");
  assert.equal(again.resolvedAt, null);
  assert.equal(again.scope, "always");
  assert.equal(again.consumedAt, null);
  assert.equal(again.count, 2, "count history accumulates");
  assert.equal(again.firstSeen, 1000, "firstSeen is stable");
  assert.deepEqual(again.sessions, ["sess-a", "sess-b"], "attribution accumulates");
});

test("store: consumeOnce guards — unknown id, pending row, always-scope are no-ops", () => {
  const store = new EgressApprovalStore();
  assert.equal(store.consumeOnce("egr-999"), undefined, "unknown id");
  const pending = store.recordPending("$a", "d1", "r");
  assert.equal(store.consumeOnce(pending.id), undefined, "unresolved rows cannot be spent");
  const standing = store.recordPending("$b", "d2", "r");
  store.resolve(standing.id, true); // default scope: always
  assert.equal(store.consumeOnce(standing.id), undefined, "a standing verdict is never consumed");
  assert.equal(store.lookupEntry("$b", "d2")!.consumedAt, null);
});

test("store: scope + consumedAt persist across restart; re-resolve re-arms a spent row", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-scope-"));
  const dbPath = join(dir, "mandu.db");
  try {
    let t = 1000;
    const store = new EgressApprovalStore({ dbPath, now: () => t });
    const e = store.recordPending("$sym", "dest", "reason");
    store.resolve(e.id, true, "once");
    t = 2000;
    store.consumeOnce(e.id);
    store.close();

    const reopened = new EgressApprovalStore({ dbPath, now: () => t });
    try {
      const row = reopened.lookupEntry("$sym", "dest");
      assert.equal(row!.scope, "once", "scope hydrates");
      assert.equal(row!.consumedAt, 2000, "consumedAt hydrates");
      // Re-resolving (the Permissions "change your answer" flow) re-arms.
      t = 3000;
      const rearmed = reopened.resolve(row!.id, true, "once");
      assert.equal(rearmed!.consumedAt, null, "re-resolve clears consumption");
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("allow-once end to end: ONE allowed decision, then the pair re-queues a fresh ask", async () => {
  const sym = await symbolize(`once-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);

  const resolved = await client.resolveEgressApproval(entry!.id, true, "once");
  assert.equal(resolved.status, "approved");
  assert.equal(resolved.scope, "once");

  // Use 1: the once-verdict short-circuits to allow, with verdict provenance.
  const allowed = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal(allowed.allow, true);
  assert.deepEqual(allowed.ruleRef, { source: "verdict", id: `verdict:${entry!.id}` });

  // Use 2: the verdict is spent — the gate runs again, denies, and re-queues
  // the SAME row as a fresh pending ask.
  const reasked = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal(reasked.allow, false);
  assert.equal((reasked as { requiresApproval: boolean }).requiresApproval, true);
  assert.equal((reasked as { approvalId?: string }).approvalId, entry!.id, "same row re-queued");
  const requeued = (await client.egressApprovals("pending")).find((a) => a.id === entry!.id);
  assert.ok(requeued, "the row is pending again");
  assert.equal(requeued!.scope, "always", "the fresh cycle carries the default scope");
  assert.equal(requeued!.consumedAt, null);
  assert.equal(requeued!.resolvedAt, null);
});

test("deny-once end to end: ONE short-circuited deny, then the pair re-queues", async () => {
  const sym = await symbolize(`deny-once-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);
  await client.resolveEgressApproval(entry!.id, false, "once");

  // Use 1: denied WITHOUT re-queueing (the verdict's one use).
  const denied = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal(denied.allow, false);
  assert.equal((denied as { requiresApproval: boolean }).requiresApproval, false);
  assert.deepEqual(denied.ruleRef, { source: "verdict", id: `verdict:${entry!.id}` });

  // Next attempt: spent → pending again (the human is asked again).
  const reasked = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: EVIL,
  });
  assert.equal((reasked as { requiresApproval: boolean }).requiresApproval, true);
  assert.equal((reasked as { approvalId?: string }).approvalId, entry!.id);
});

test("allow-once on the fs family: the shared consultation enacts scope at every gate", async () => {
  const probe = `/opt/once-probe-${counter}`;
  await client.fsPathDecision({ tool: "Read", path: probe, mode: "read", workspaceRoots: [] });
  const fsEntry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === "fs:Read:read" && a.destination === probe,
  );
  assert.ok(fsEntry);
  await client.resolveEgressApproval(fsEntry!.id, true, "once");

  const allowed = await client.fsPathDecision({
    tool: "Read", path: probe, mode: "read", workspaceRoots: [],
  });
  assert.equal(allowed.allow, true);
  assert.deepEqual(allowed.ruleRef, { source: "verdict", id: `verdict:${fsEntry!.id}` });

  const reasked = await client.fsPathDecision({
    tool: "Read", path: probe, mode: "read", workspaceRoots: [],
  });
  assert.equal(reasked.allow, false);
  assert.equal((reasked as { requiresApproval?: boolean }).requiresApproval, true);
  assert.equal((reasked as { approvalId?: string }).approvalId, fsEntry!.id, "same row re-queued");
});

test("consuming a once-verdict lands ONE approval_consumed audit event in arbiter-admin", async () => {
  const sym = await symbolize(`consume-audit-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);
  await client.resolveEgressApproval(entry!.id, true, "once");

  // The resolution's own audit line names the scope.
  const resolvedEv = (await client.events("arbiter-admin")).at(-1)! as Record<string, any>;
  assert.equal(resolvedEv.kind, "approval_resolved");
  assert.match(String(resolvedEv.output?.symbolized ?? ""), /APPROVED by human \(once; /);

  const before = (await client.events("arbiter-admin")).length;
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const events = await client.events("arbiter-admin");
  assert.equal(events.length, before + 1, "exactly one audit event per consumption");
  const ev = events[events.length - 1]! as Record<string, any>;
  assert.equal(ev.kind, "approval_consumed");
  assert.equal(ev.emitter, "arbiter");
  assert.equal(ev.sessionId, "arbiter-admin");
  assert.equal(ev.policy?.usage, "allow");
  assert.deepEqual(ev.policy?.ruleRef, { source: "verdict", id: `verdict:${entry!.id}` });
  assert.ok(!JSON.stringify(ev).includes(`consume-audit-${counter}`), "no raw value in the audit event");
});

test("resolve without scope stays standing: repeat decisions keep allowing (pre-scope behavior)", async () => {
  const sym = await symbolize(`standing-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find(
    (a) => a.symbol === sym && a.destination === EVIL,
  );
  assert.ok(entry);
  const resolved = await client.resolveEgressApproval(entry!.id, true);
  assert.equal(resolved.scope, "always", "absent scope lands on the standing default");
  for (let i = 0; i < 3; i++) {
    const d = await client.desymbolizationDecision({
      symbol: sym, boundary: "network", destination: EVIL,
    });
    assert.equal(d.allow, true, `standing approval holds on use ${i + 1}`);
  }
  const row = (await client.egressApprovals("approved")).find((a) => a.id === entry!.id);
  assert.ok(row, "still approved — never consumed");
  assert.equal(row!.consumedAt, null);
});

// ── forget: "Remove" on a past answer (dashboard.md §4.25 Rules page) ─────────

test("store: forget deletes a resolved verdict; pending and unknown ids are refused", () => {
  const store = new EgressApprovalStore();
  const a = store.recordPending("$sym-f1", "https://x.example/", "untrusted destination");
  assert.equal(store.forget(a.id), undefined, "a pending ask cannot be forgotten");
  assert.equal(store.forget("egr-999"), undefined);
  store.resolve(a.id, true);
  const gone = store.forget(a.id);
  assert.equal(gone?.status, "approved", "returns the entry as it was");
  assert.equal(store.lookup("$sym-f1", "https://x.example/"), undefined);
  assert.equal(store.list().length, 0);
  const again = store.recordPending("$sym-f1", "https://x.example/", "untrusted destination");
  assert.equal(again.status, "pending", "the next attempt asks again");
  assert.notEqual(again.id, a.id, "a fresh id, never a reused one");
});

test("store: a forgotten verdict stays forgotten across restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-forget-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const s1 = new EgressApprovalStore({ dbPath });
    const a = s1.recordPending("$sym-f2", "https://y.example/", "untrusted destination");
    s1.resolve(a.id, false);
    assert.ok(s1.forget(a.id));
    s1.close();
    const s2 = new EgressApprovalStore({ dbPath });
    assert.equal(s2.lookup("$sym-f2", "https://y.example/"), undefined);
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("forgetEgressApproval: an approved pair is asked again on its next attempt", async () => {
  const sym = await symbolize(`forget-me-${counter}`);
  await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  const entry = (await client.egressApprovals("pending")).find((a) => a.symbol === sym && a.destination === EVIL)!;
  await assert.rejects(() => client.forgetEgressApproval(entry.id), /still waiting for an answer/);
  await client.resolveEgressApproval(entry.id, true);
  assert.equal((await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL })).allow, true);

  const forgotten = await client.forgetEgressApproval(entry.id);
  assert.equal(forgotten.status, "approved");
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "network", destination: EVIL });
  assert.equal(d.allow, false, "forgetting an allow never leaves it allowed");
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, true, "it asks again");
  await assert.rejects(() => client.forgetEgressApproval("egr-no-such"), /unknown egress-approval id/);
});

// ── withdraw (the !437 leftover (4), made durable) and ids never reused ─────

test("store: withdraw removes a PENDING row only, from memory and the DB; an answered row is untouched; the gate then finds no prior answer", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-withdraw-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const s1 = new EgressApprovalStore({ dbPath });
    const moot = s1.recordPending("open:/usr/bin/cat#" + "c".repeat(64), "/w/.env", "cat wants to read it");
    const answered = s1.recordPending("open:/usr/bin/psql#" + "c".repeat(64), "/w/.env", "psql wants to read it");
    s1.resolve(answered.id, false);
    assert.equal(s1.withdraw(answered.id), undefined, "an answer is never withdrawn");
    assert.equal(s1.withdraw("egr-no-such"), undefined);
    const gone = s1.withdraw(moot.id);
    assert.equal(gone?.id, moot.id);
    assert.equal(gone?.status, "pending", "removed as it was: never turned into an answer");
    assert.equal(s1.lookup(moot.symbol, moot.destination), undefined, "no prior answer: the gate decides by the law");
    assert.equal(s1.withdraw(moot.id), undefined, "once");
    s1.close();
    const s2 = new EgressApprovalStore({ dbPath });
    assert.deepEqual(s2.list().map((a) => [a.id, a.status]), [[answered.id, "denied"]], "the DB row is gone after a restart; the answer stays");
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("store: an id is never reused after withdraw or forget, across restarts (a stale answer cannot land on another question)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egr-seq-"));
  const dbPath = join(dir, "symbols.db");
  try {
    const s1 = new EgressApprovalStore({ dbPath });
    const a = s1.recordPending("open:/usr/bin/cat#" + "c".repeat(64), "/w/.env", "moot");
    const b = s1.recordPending("$sym-forget", "https://x.example/", "untrusted destination");
    assert.deepEqual([a.id, b.id], ["egr-1", "egr-2"]);
    s1.resolve(b.id, true);
    assert.ok(s1.forget(b.id));
    assert.ok(s1.withdraw(a.id));
    assert.equal(s1.list().length, 0, "the table is empty");
    s1.close();
    const s2 = new EgressApprovalStore({ dbPath });
    const c = s2.recordPending("$sym-new", "https://y.example/", "untrusted destination");
    assert.equal(c.id, "egr-3", "past the removed rows' ids");
    s2.close();
    const s3 = new EgressApprovalStore({ dbPath });
    assert.equal(s3.recordPending("$sym-newer", "https://z.example/", "untrusted destination").id, "egr-4");
    s3.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
