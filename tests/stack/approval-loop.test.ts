/**
 * approval-loop.test.ts — the REAL-ARBITER cross-component approval loop
 * (Mandu-new). The un-deferred twin of dashboard/test/component/approval-loop.test.ts:
 * that file pins the dashboard side of the contract against a MOCK arbiter and
 * recorded (dashboard.md §4.18) that "the real-arbiter cross-component version
 * belongs in tests/, deferred until the inbox grows a second verb
 * (allow-once)". The second verb landed (policy-surface.md §9.8.7), so this is
 * that version: REAL ArbiterServer over a real Unix socket, REAL DashboardServer
 * over real HTTP, REAL ArbiterClient adapters on both dashboard surfaces
 * (ArbiterEventSource for the panel snapshot, the approvals client for the
 * verdict ops) — no mocks anywhere in the loop.
 *
 * What it pins:
 *   P1  a network egress the gate denies (requiresApproval) surfaces as a
 *       pending row in the dashboard-served panel VM, with the three §8.7
 *       verbs (Allow once / Always allow / Block) — arbiter store → policySnapshot
 *       op → ArbiterEventSource → toPolicyPanelViewModel over real HTTP;
 *   P2  POST …/approve-once (CSRF'd) lands scope:"once" in the ARBITER's
 *       store through the real resolve op, and the re-served panel row is
 *       once-scoped;
 *   P3  the once-verdict is worth exactly ONE gated decision: the next
 *       identical decision allows with verdict:<id> provenance, the one after
 *       re-queues the SAME row as a fresh pending ask (the §8.7 loop), and the
 *       re-served panel shows it pending again;
 *   P4  the audit trail is complete in the reserved arbiter-admin stream:
 *       approval_resolved (naming the once scope) then approval_consumed.
 *
 * Run: npm test  (tests/)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── REAL components under test (imported across package boundaries) ───────────
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { ApprovalsArbiter } from "../../dashboard/src/server.js";
import type { PolicyPanelVM, QueueRowVM } from "../../dashboard/src/view-model/policy-panel.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const EVIL = "https://evil.example/collect";
const CSRF = { "X-Mandu-Control": "1" };

test("real-arbiter approval loop: pending row → Allow once (approve-once) over HTTP → one allowed use → fresh ask", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-approval-loop-"));
  const socketPath = join(tmp, "arbiter.sock");

  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: join(tmp, "admin.sock"), // human-decision ops (policy-surface.md §2.6)
    humanSocketPath: humanSockIn(tmp), // originals-returning reads (arbiter-human-plane.md)
    eventDir: join(tmp, "events"),
    log: () => {},
  });
  await arbiter.listen();

  // The gate driver (stands in for the proxies' decision calls — the same
  // desymbolizationDecision op, over the same real socket: the human plane,
  // where only a gate's ask spends an Allow once, arbiter-human-plane.md
  // §10.3) and the dashboard's approvals surface ride separate connections,
  // like production.
  const gate = new ArbiterClient(humanSockIn(tmp));
  await gate.connect();
  const approvalsClient = new ArbiterClient(join(tmp, "admin.sock")); // the dashboard's admin channel
  await approvalsClient.connect();
  // The audit read-back: `events` is human-plane only (arbiter-human-plane.md).
  const humanReader = new ArbiterClient(humanSockIn(tmp));
  await humanReader.connect();

  // The real client satisfies the dashboard's structural ApprovalsArbiter
  // surface directly (same op names, wider result type) — pin that with an
  // explicit adapter so a drift in either signature fails HERE, loudly.
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => approvalsClient.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) =>
      approvalsClient.resolveEgressApproval(approvalId, approve, scope),
  };

  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath }),
    approvalsArbiter,
    log: () => {},
  });
  const port = await dashboard.listen(0);
  const baseUrl = `http://127.0.0.1:${port}`;

  const fetchPanel = async (): Promise<PolicyPanelVM> => {
    const res = await fetch(`${baseUrl}/api/policy/panel`);
    assert.equal(res.status, 200);
    return ((await res.json()) as { panel: PolicyPanelVM }).panel;
  };

  try {
    // ── P1: a real gate deny queues a pending row the dashboard serves ────────
    const symbol = await gate.symbolize({
      tool: "WebFetch",
      field: "text",
      value: "exfil-me-approval-loop",
    });
    const deny = await gate.desymbolizationDecision({
      symbol,
      boundary: "network",
      destination: EVIL,
      sessionKey: "sess-int-loop",
    });
    assert.equal(deny.allow, false);
    assert.equal((deny as { requiresApproval?: boolean }).requiresApproval, true);
    const approvalId = (deny as { approvalId?: string }).approvalId;
    assert.ok(approvalId, "the queued deny names its row");

    const panel1 = await fetchPanel();
    assert.equal(panel1.available, true);
    assert.equal(panel1.verdictsKnown, true);
    const row1 = panel1.queue.find((r: QueueRowVM) => r.id === approvalId);
    assert.ok(row1, "the pending row reaches the served panel VM");
    assert.equal(row1!.status, "pending");
    assert.equal(row1!.subject, symbol);
    assert.equal(row1!.target, EVIL);
    assert.deepEqual(row1!.sessions, ["sess-int-loop"], "session attribution survives the whole pipeline");
    assert.deepEqual(
      row1!.actions,
      [
        { approve: true, scope: "once", label: "Allow once" },
        { approve: true, label: "Always allow" },
        { approve: false, label: "Block" },
      ],
      "the §8.7 three-verb row shape, served off the REAL snapshot",
    );

    // ── P2: the third verb over real HTTP lands scope=once in the store ───────
    const resOnce = await fetch(
      `${baseUrl}/api/egress/approvals/${approvalId}/approve-once`,
      { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } },
    );
    assert.equal(resOnce.status, 200);
    const { approval } = (await resOnce.json()) as {
      approval: { status: string; scope?: string; consumedAt?: number | null };
    };
    assert.equal(approval.status, "approved");
    assert.equal(approval.scope, "once");

    const panel2 = await fetchPanel();
    const row2 = panel2.queue.find((r: QueueRowVM) => r.id === approvalId)!;
    assert.equal(row2.status, "approved");
    assert.equal(row2.scope, "once");
    assert.equal(row2.consumedAt, null, "armed, not yet spent");

    // ── P3: exactly one allowed decision, then the SAME row asks again ────────
    const use = await gate.desymbolizationDecision({
      symbol,
      boundary: "network",
      destination: EVIL,
      sessionKey: "sess-int-loop",
    });
    assert.equal(use.allow, true, "the one use the human granted");
    assert.deepEqual(use.ruleRef, { source: "verdict", id: `verdict:${approvalId}` });

    const reask = await gate.desymbolizationDecision({
      symbol,
      boundary: "network",
      destination: EVIL,
      sessionKey: "sess-int-loop",
    });
    assert.equal(reask.allow, false, "the once-verdict is spent");
    assert.equal((reask as { requiresApproval?: boolean }).requiresApproval, true);
    assert.equal(
      (reask as { approvalId?: string }).approvalId,
      approvalId,
      "the pair keeps its row identity across the re-queue",
    );

    const panel3 = await fetchPanel();
    const row3 = panel3.queue.find((r: QueueRowVM) => r.id === approvalId)!;
    assert.equal(row3.status, "pending", "the served panel shows the fresh ask");
    assert.equal(row3.scope, "always", "the fresh cycle carries the default scope");
    assert.equal(row3.resolvedAt, null);
    assert.equal(row3.count, 2, "ask history accumulates on the one row");

    // ── P4: the arbiter-admin audit pair, in order ────────────────────────────
    const adminEvents = (await humanReader.events("arbiter-admin")) as Array<
      Record<string, unknown>
    >;
    const kinds = adminEvents.map((e) => e["kind"]);
    const resolvedIdx = kinds.indexOf("approval_resolved");
    const consumedIdx = kinds.indexOf("approval_consumed");
    assert.ok(resolvedIdx !== -1, "the verdict audited");
    assert.ok(consumedIdx !== -1, "the consumption audited");
    assert.ok(resolvedIdx < consumedIdx, "resolution precedes consumption");
    const resolvedEv = adminEvents[resolvedIdx]! as { output?: { symbolized?: string } };
    assert.match(String(resolvedEv.output?.symbolized ?? ""), /APPROVED by human \(once; /);
    const consumedEv = adminEvents[consumedIdx]! as {
      policy?: { usage?: string; ruleRef?: unknown };
    };
    assert.equal(consumedEv.policy?.usage, "allow");
    assert.deepEqual(consumedEv.policy?.ruleRef, {
      source: "verdict",
      id: `verdict:${approvalId}`,
    });
  } finally {
    await dashboard.close(); // closes its ArbiterEventSource too
    gate.close();
    approvalsClient.close();
    humanReader.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
