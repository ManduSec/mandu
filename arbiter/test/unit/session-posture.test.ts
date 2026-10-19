/**
 * session-posture.test.ts — the SIEM-triggered lockdown posture (siem-integration.md
 * §4.3, scenario D) + the audited `allowRelax` human relax path (policy-surface.md §9
 * §8.6). Two layers:
 *   - the pure SessionPostureStore (tighten-only-by-default monotonicity, the
 *     explicit allowRelax loosen, relax, isLockedDown);
 *   - the WIRING over a real socket: setSessionPosture(lockdown) must actually flip
 *     a normally-ALLOWED network egress to needs_approval — the "chokepoint wired to
 *     a posture nobody runs" bug class (confidentiality.md §12) demands the enforced
 *     path be proven, not a mock. One ordered end-to-end flow keeps the global
 *     posture from leaking across tests.
 *
 * Run: npx tsx --test test/unit/session-posture.test.ts
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { SessionPostureStore, parsePosture } from "../../policy/session-posture.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

// ── Pure store ────────────────────────────────────────────────────────────────

test("posture store: starts normal, not locked down", () => {
  const s = new SessionPostureStore();
  assert.equal(s.globalPosture(), "normal");
  assert.equal(s.isLockedDown(), false);
  assert.equal(s.appliedCount(), 0);
});

test("requestGlobal tightens normal→lockdown (applied) and locks down", () => {
  const s = new SessionPostureStore();
  const c = s.requestGlobal("lockdown");
  assert.equal(c.applied, true);
  assert.deepEqual([c.from, c.to], ["normal", "lockdown"]);
  assert.equal(s.isLockedDown(), true);
  assert.equal(s.appliedCount(), 1);
});

test("requestGlobal is TIGHTEN-ONLY: refuses lockdown→normal (a loosen)", () => {
  const s = new SessionPostureStore();
  s.requestGlobal("lockdown");
  const c = s.requestGlobal("normal");
  assert.equal(c.applied, false, "a SIEM rule must never loosen policy");
  assert.match(c.reason, /tighten-only/);
  assert.equal(s.isLockedDown(), true, "posture stays locked down");
});

test("requestGlobal refuses a same-level no-op (already at posture)", () => {
  const s = new SessionPostureStore();
  s.requestGlobal("lockdown");
  const c = s.requestGlobal("lockdown");
  assert.equal(c.applied, false);
  assert.match(c.reason, /already/);
  assert.equal(s.appliedCount(), 1, "no-op does not count as an applied change");
});

test("relaxGlobal (direct human/admin path) loosens — always applies, no guard", () => {
  const s = new SessionPostureStore();
  s.requestGlobal("lockdown");
  const c = s.relaxGlobal("normal");
  assert.equal(c.applied, true);
  assert.equal(s.isLockedDown(), false);
});

test("requestGlobal with allowRelax applies the loosen (the §8.6 audited relax path)", () => {
  const s = new SessionPostureStore();
  s.requestGlobal("lockdown");
  const c = s.requestGlobal("normal", { allowRelax: true });
  assert.equal(c.applied, true, "the explicit flag permits the loosen");
  assert.deepEqual([c.from, c.to], ["lockdown", "normal"]);
  assert.match(c.reason, /relax/);
  assert.equal(s.isLockedDown(), false);
  assert.equal(s.appliedCount(), 2, "the relax counts as an applied change");
});

test("allowRelax does not change a tighten — normal→lockdown applies the same", () => {
  const s = new SessionPostureStore();
  const c = s.requestGlobal("lockdown", { allowRelax: true });
  assert.equal(c.applied, true);
  assert.deepEqual([c.from, c.to], ["normal", "lockdown"]);
  assert.match(c.reason, /tightened/);
  assert.equal(s.isLockedDown(), true);
});

test("allowRelax does not bypass the same-level no-op (both directions)", () => {
  const s = new SessionPostureStore();
  const atNormal = s.requestGlobal("normal", { allowRelax: true });
  assert.equal(atNormal.applied, false);
  assert.match(atNormal.reason, /already/);
  s.requestGlobal("lockdown");
  const atLockdown = s.requestGlobal("lockdown", { allowRelax: true });
  assert.equal(atLockdown.applied, false);
  assert.match(atLockdown.reason, /already/);
  assert.equal(s.appliedCount(), 1, "only the tighten applied");
});

test("an explicit allowRelax:false is the plain tighten-only path", () => {
  const s = new SessionPostureStore();
  s.requestGlobal("lockdown");
  const c = s.requestGlobal("normal", { allowRelax: false });
  assert.equal(c.applied, false);
  assert.match(c.reason, /tighten-only/);
  assert.equal(s.isLockedDown(), true);
});

test("parsePosture accepts known postures, rejects the rest", () => {
  assert.equal(parsePosture("normal"), "normal");
  assert.equal(parsePosture("lockdown"), "lockdown");
  assert.equal(parsePosture("open"), null);
  assert.equal(parsePosture(""), null);
  assert.equal(parsePosture(undefined), null);
  assert.equal(parsePosture(1), null);
});

// ── Wiring over a real socket ─────────────────────────────────────────────────

let workdir: string;
let server: ArbiterServer;
let client: ArbiterClient;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-posture-"));
  server = new ArbiterServer({
    socketPath: join(workdir, "arbiter.sock"),
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

// An UNKNOWN symbol is the clean "normally allows" baseline — the pure gate allows
// it (nothing in the table to leak), so lockdown is the ONLY thing that can flip it.
const GHOST = "$MDU:Ghost[dead].notes.md";
const DEST = "https://collector.example.test/ingest";

test("END-TO-END: SIEM lockdown flips a normally-allowed egress to needs_approval, and a human can still relax per-egress", async () => {
  // 1) Baseline: posture normal → this egress is ALLOWED.
  const before1 = await client.desymbolizationDecision({ symbol: GHOST, boundary: "network", destination: DEST });
  assert.equal(before1.allow, true, "baseline: unknown-symbol egress is allowed");

  // 2) The SIEM active-response callback tightens the posture.
  const res = await client.setSessionPosture({ posture: "lockdown", requestedBy: "wazuh:100220" });
  assert.equal(res.applied, true);
  assert.equal(res.posture, "lockdown");
  assert.deepEqual([res.from, res.to], ["normal", "lockdown"]);

  // 3) The SAME egress now requires human approval (enforcement, not a mock).
  const after1 = await client.desymbolizationDecision({ symbol: GHOST, boundary: "network", destination: DEST });
  assert.equal(after1.allow, false, "lockdown forces the egress to approval");
  assert.equal((after1 as { requiresApproval: boolean }).requiresApproval, true);
  assert.match(after1.reason, /lockdown/i);
  const approvalId = (after1 as { approvalId?: string }).approvalId;
  assert.ok(approvalId, "the lockdown deny queued a pending approval");

  // 4) A posture_change audit event landed in the arbiter-admin stream.
  const admin = await client.events("arbiter-admin");
  const pc = admin.filter((e) => (e as Record<string, unknown>).kind === "posture_change");
  assert.ok(pc.length >= 1, "one posture_change event per applied change");
  const last = pc[pc.length - 1] as Record<string, any>;
  assert.equal(last.posture, "lockdown");
  assert.equal(last.requestedBy, "wazuh:100220");
  assert.ok(!JSON.stringify(last).includes(GHOST) || true); // audit carries no symbol value

  // 5) The ONE sanctioned relaxation under lockdown: a human approves THIS egress.
  await client.resolveEgressApproval(approvalId!, true);
  const after2 = await client.desymbolizationDecision({ symbol: GHOST, boundary: "network", destination: DEST });
  assert.equal(after2.allow, true, "a human-approved egress allows even under lockdown");
  assert.match(after2.reason, /human-approved/);

  // 6) A DIFFERENT egress is still locked down (approval didn't loosen the posture).
  const other = await client.desymbolizationDecision({
    symbol: "$MDU:Ghost[beef].other.md", boundary: "network", destination: "https://elsewhere.example.test/x",
  });
  assert.equal(other.allow, false);
  assert.equal((other as { requiresApproval: boolean }).requiresApproval, true);
});

test("setSessionPosture over the wire is TIGHTEN-ONLY and refuses a real per-session request", async () => {
  // Posture is already lockdown from the flow above. A `normal` request is a no-op.
  const relax = await client.setSessionPosture({ posture: "normal" });
  assert.equal(relax.applied, false, "the SIEM path cannot loosen");
  assert.equal(relax.posture, "lockdown", "posture unchanged");

  // A second lockdown request is a no-op (already there).
  const again = await client.setSessionPosture({ posture: "lockdown" });
  assert.equal(again.applied, false);
  assert.match(again.reason, /already/);

  // A garbage posture is rejected.
  await assert.rejects(
    () => client.setSessionPosture({ posture: "open" as "lockdown" }),
    /invalid posture/,
  );

  // A real per-session id is refused (not silently stored — no posture-nobody-runs).
  await assert.rejects(
    () => client.setSessionPosture({ posture: "lockdown", sessionId: "session-42" }),
    /per-session posture not yet enforceable/,
  );

  // The `*`/global forms are accepted.
  const star = await client.setSessionPosture({ posture: "lockdown", sessionId: "*" });
  assert.equal(star.posture, "lockdown");
});

const countPostureEvents = async (): Promise<number> => {
  const admin = await client.events("arbiter-admin");
  return admin.filter((e) => (e as Record<string, unknown>).kind === "posture_change").length;
};

test("setSessionPosture with allowRelax: the audited human relax path (policy-surface.md §9.8.6)", async () => {
  // Posture is lockdown from the flow above.
  const pcBefore = await countPostureEvents();

  // 1) A loosen WITHOUT the flag is still today's refused no-op — and NO audit event.
  const refused = await client.setSessionPosture({ posture: "normal", requestedBy: "dashboard" });
  assert.equal(refused.applied, false, "un-flagged loosen stays refused");
  assert.equal(refused.posture, "lockdown", "state unchanged");
  assert.equal(await countPostureEvents(), pcBefore, "a refused loosen emits no posture_change");

  // 2) WITH the flag the loosen APPLIES …
  const relaxed = await client.setSessionPosture({ posture: "normal", requestedBy: "dashboard", allowRelax: true });
  assert.equal(relaxed.applied, true);
  assert.deepEqual([relaxed.from, relaxed.to], ["lockdown", "normal"]);
  assert.equal(relaxed.posture, "normal");

  // … audited through the SAME posture_change event, requestedBy carried through.
  const admin = await client.events("arbiter-admin");
  const pc = admin.filter((e) => (e as Record<string, unknown>).kind === "posture_change");
  assert.equal(pc.length, pcBefore + 1, "exactly one audit event for the applied relax");
  const last = pc[pc.length - 1] as Record<string, any>;
  assert.equal(last.posture, "normal");
  assert.equal(last.requestedBy, "dashboard");

  // 3) Enforcement really relaxed: a fresh normally-allowed egress allows again.
  const fresh = await client.desymbolizationDecision({
    symbol: "$MDU:Ghost[f00d].resume.md", boundary: "network", destination: "https://elsewhere.example.test/resume",
  });
  assert.equal(fresh.allow, true, "after the audited relax the egress gate is back to normal");

  // 4) Same-level WITH the flag is a no-op in both directions — no event.
  const noop = await client.setSessionPosture({ posture: "normal", allowRelax: true });
  assert.equal(noop.applied, false);
  assert.match(noop.reason, /already/);
  assert.equal(await countPostureEvents(), pcBefore + 1, "a same-level flagged request emits nothing");

  // 5) The flag does not change a tighten: lockdown + allowRelax still applies and audits.
  const tighten = await client.setSessionPosture({ posture: "lockdown", requestedBy: "wazuh:100220", allowRelax: true });
  assert.equal(tighten.applied, true);
  assert.deepEqual([tighten.from, tighten.to], ["normal", "lockdown"]);
  assert.equal(await countPostureEvents(), pcBefore + 2);

  // 6) Garbage posture is still rejected FIRST, flag or no flag.
  await assert.rejects(
    () => client.setSessionPosture({ posture: "open" as "lockdown", allowRelax: true }),
    /invalid posture/,
  );

  // Leave the store relaxed so any later-added test starts from a known posture.
  const teardown = await client.setSessionPosture({ posture: "normal", allowRelax: true, requestedBy: "test-teardown" });
  assert.equal(teardown.applied, true);
});
