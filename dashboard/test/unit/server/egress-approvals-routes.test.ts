/**
 * egress-approvals-routes.test — offline unit tests for the dashboard's
 * interactive egress-approval-queue HTTP routes (server.ts:
 * /api/egress/approvals + /api/egress/approvals/<id>/{approve,deny}).
 *
 * Mandu-new test (NO reference origin). NOTHING real is spawned: the test
 * injects a FAKE ApprovalsArbiter (a plain in-memory object implementing only the
 * two methods the server calls) plus a trivial no-op EventSource into a real
 * DashboardServer, listens on an ephemeral port, and drives the routes with
 * `fetch` (mirrors control-routes.test.ts).
 *
 * It pins the route layer's contract + security wiring:
 *   - GET /api/egress/approvals returns the arbiter list ([] when empty, the
 *     pending entry once seeded, honoring ?status=);
 *   - POST .../<id>/approve|deny mutates via the arbiter and REQUIRES the CSRF
 *     header X-Mandu-Control (missing → 403, mutation never runs);
 *   - an unknown id → 404 (arbiter rejects);
 *   - with NO arbiter client injected → 404 "arbiter not connected";
 *   - with a password set, an authed route 302s to /login.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DashboardServer,
  type DashboardServerOptions,
  type ApprovalsArbiter,
  type EgressApproval,
  type ApprovalStatus,
} from "../../../src/server.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";

// ── a trivial no-op EventSource (the 4-method seam) ───────────────────────────

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> {
    return [];
  },
  async readEvents(): Promise<ManduEvent[]> {
    return [];
  },
  subscribe(): () => void {
    return () => {};
  },
  close(): void {},
};

// ── a FAKE ApprovalsArbiter (in-memory queue) ──────────────────────────────────

interface FakeApprovalsCtl {
  /** Seed a pending entry (as the arbiter's recordPending would). Returns it. */
  seedPending(symbol: string, destination: string, reason: string): EgressApproval;
}

function makeFakeApprovals(): { arbiter: ApprovalsArbiter; ctl: FakeApprovalsCtl } {
  const byId = new Map<string, EgressApproval>();
  let seq = 0;
  const ctl: FakeApprovalsCtl = {
    seedPending(symbol, destination, reason) {
      const now = Date.now();
      const entry: EgressApproval = {
        id: `egr-${++seq}`,
        symbol,
        destination,
        status: "pending",
        reason,
        count: 1,
        firstSeen: now,
        lastSeen: now,
      };
      byId.set(entry.id, entry);
      return entry;
    },
  };
  const arbiter: ApprovalsArbiter = {
    async egressApprovals(status?: ApprovalStatus): Promise<EgressApproval[]> {
      const out = [...byId.values()].filter((e) => !status || e.status === status);
      return out.map((e) => ({ ...e }));
    },
    async resolveEgressApproval(
      approvalId: string,
      approve: boolean,
      scope?: "once" | "always",
      opts?: { strip?: boolean },
    ): Promise<EgressApproval> {
      const entry = byId.get(approvalId);
      if (!entry) throw new Error(`unknown approval id '${approvalId}'`);
      // As the arbiter takes "Send without it" only on a secret's
      // placeholder card, and refuses it on any other (send-without.ts).
      if (opts?.strip === true) {
        if (approve || !entry.symbol.startsWith("$MDU:")) {
          throw new Error(`egress-approval ${approvalId} cannot be answered Send without it: this question is not about a secret's placeholder in a request`);
        }
        Object.assign(entry, { status: "denied", scope: "once", strip: true, lastSeen: Date.now() });
        return { ...entry };
      }
      // As the arbiter refuses a moot question (resolveEgressApproval, the
      // !437 leftover (4)): one about a printer.
      if (entry.status === "pending" && entry.symbol.startsWith("open:/usr/bin/cat#")) {
        throw new Error(`egress-approval ${approvalId} no longer applies: cat prints or copies the bytes it reads to whatever reads its output, so no answer lets it read the file raw (plan 13 D8, printers admit nothing)`);
      }
      // As the arbiter refuses an Always on a held message under a locked
      // administrator's `ask` row (plan 15 §12, 2026-10-04).
      if (entry.status === "pending" && entry.onceOnly === true && scope !== "once") {
        throw new Error(`egress-approval ${approvalId}: your administrator set acme.codename to ask every time (/etc/mandu/policy.d/10-org.yaml), so it takes no answer for the session; answer it for this message only`);
      }
      entry.status = approve ? "approved" : "denied";
      entry.scope = scope === "once" ? "once" : "always";
      entry.lastSeen = Date.now();
      return { ...entry };
    },
  };
  return { arbiter, ctl };
}

// ── server harness ────────────────────────────────────────────────────────────

interface Harness {
  baseUrl: string;
  ctl: FakeApprovalsCtl;
  close(): Promise<void>;
}

async function startServer(extra: Partial<DashboardServerOptions> = {}): Promise<Harness> {
  const { arbiter, ctl } = makeFakeApprovals();
  const server = new DashboardServer({
    source: fakeSource,
    approvalsArbiter: arbiter,
    log: () => {},
    ...ADMIN_OPTS,
    ...extra,
  });
  const port = await server.listen(0);
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    ctl,
    close: () => server.close(),
  };
}

const CSRF = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE };

// ── tests ─────────────────────────────────────────────────────────────────────

test("GET /api/egress/approvals → [] when the queue is empty", async () => {
  const h = await startServer();
  try {
    const res = await fetch(`${h.baseUrl}/api/egress/approvals`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { approvals: EgressApproval[] };
    assert.deepEqual(body.approvals, []);
  } finally {
    await h.close();
  }
});

test("GET /api/egress/approvals lists a seeded pending entry", async () => {
  const h = await startServer();
  try {
    const seeded = h.ctl.seedPending("$MDU:x[ab12]", "evil.example.com", "untrusted egress");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals?status=pending`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { approvals: EgressApproval[] };
    assert.equal(body.approvals.length, 1);
    const a = body.approvals[0]!;
    assert.equal(a.id, seeded.id);
    assert.equal(a.symbol, "$MDU:x[ab12]");
    assert.equal(a.destination, "evil.example.com");
    assert.equal(a.status, "pending");
    assert.equal(a.reason, "untrusted egress");
  } finally {
    await h.close();
  }
});

test("POST /api/egress/approvals/<id>/approve (with CSRF) flips status→approved", async () => {
  const h = await startServer();
  try {
    const seeded = h.ctl.seedPending("$MDU:y[cd34]", "host.example", "reason");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/approve`, {
      method: "POST",
      headers: CSRF,
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { approval: EgressApproval };
    assert.equal(body.approval.id, seeded.id);
    assert.equal(body.approval.status, "approved");

    // The fake's authoritative state agrees, and it no longer shows as pending.
    const pendingRes = await fetch(`${h.baseUrl}/api/egress/approvals?status=pending`);
    const { approvals } = (await pendingRes.json()) as { approvals: EgressApproval[] };
    assert.equal(approvals.length, 0);
  } finally {
    await h.close();
  }
});

test("POST /api/egress/approvals/<id>/approve-once (with CSRF) lands scope=once on the arbiter", async () => {
  const h = await startServer();
  try {
    const seeded = h.ctl.seedPending("$MDU:o[9x9x]", "host.example", "reason");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/approve-once`, {
      method: "POST",
      headers: CSRF,
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { approval: EgressApproval };
    assert.equal(body.approval.status, "approved");
    assert.equal(body.approval.scope, "once", "the route threads scope through the arbiter surface");

    // Plain approve stays standing — the third verb never leaks into the others.
    const seeded2 = h.ctl.seedPending("$MDU:p[8y8y]", "host.example", "reason");
    const res2 = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded2.id}/approve`, {
      method: "POST",
      headers: CSRF,
    });
    const body2 = (await res2.json()) as { approval: EgressApproval };
    assert.equal(body2.approval.scope, "always");

    // A verb off the regex is not a route at all.
    const bad = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/approve-twice`, {
      method: "POST",
      headers: CSRF,
    });
    assert.equal(bad.status, 404);
  } finally {
    await h.close();
  }
});

test("POST /api/egress/approvals/<id>/send-without (with CSRF): a once denial carrying strip; refused on a content-agnostic card → 409, nothing changed", async () => {
  const h = await startServer();
  try {
    const seeded = h.ctl.seedPending("$MDU:nomodel_Read[ab12cd34]", "api.github.com", "secret at unbound destination");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/send-without`, { method: "POST", headers: CSRF });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { approval: EgressApproval };
    assert.equal(body.approval.status, "denied", "never an approval");
    assert.equal(body.approval.scope, "once");
    assert.equal(body.approval.strip, true);

    const session = h.ctl.seedPending("session-net:s1", "evil.example", "a HIGH session's request");
    const refused = await fetch(`${h.baseUrl}/api/egress/approvals/${session.id}/send-without`, { method: "POST", headers: CSRF });
    assert.equal(refused.status, 409);
    assert.match(((await refused.json()) as { error: string }).error, /cannot be answered Send without it/);
    const { approvals } = (await (await fetch(`${h.baseUrl}/api/egress/approvals?status=pending`)).json()) as { approvals: EgressApproval[] };
    assert.ok(approvals.some((a) => a.id === session.id), "the refused card still waits");

    // CSRF still required.
    const noCsrf = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/send-without`, { method: "POST" });
    assert.equal(noCsrf.status, 403);
  } finally {
    await h.close();
  }
});

test("POST /api/egress/approvals/<id>/deny (with CSRF) flips status→denied", async () => {
  const h = await startServer();
  try {
    const seeded = h.ctl.seedPending("$MDU:z[ef56]", "host.example", "reason");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/deny`, {
      method: "POST",
      headers: CSRF,
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { approval: EgressApproval };
    assert.equal(body.approval.status, "denied");
  } finally {
    await h.close();
  }
});

test("POST without the X-Mandu-Control header → 403, mutation never runs", async () => {
  const h = await startServer();
  try {
    const seeded = h.ctl.seedPending("$MDU:q[1122]", "host.example", "reason");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/${seeded.id}/approve`, {
      method: "POST",
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { error: string };
    assert.match(body.error, /X-Mandu-Control/);

    // Untouched — still pending.
    const pendingRes = await fetch(`${h.baseUrl}/api/egress/approvals?status=pending`);
    const { approvals } = (await pendingRes.json()) as { approvals: EgressApproval[] };
    assert.equal(approvals.length, 1);
    assert.equal(approvals[0]!.status, "pending");
  } finally {
    await h.close();
  }
});

test("POST for an unknown id → 404 (arbiter rejects)", async () => {
  const h = await startServer();
  try {
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/egr-nope/approve`, {
      method: "POST",
      headers: CSRF,
    });
    assert.equal(res.status, 404);
    const body = (await res.json()) as { error: string };
    assert.match(body.error, /unknown approval id/);
  } finally {
    await h.close();
  }
});

test("with no arbiter client injected → 404 'arbiter not connected'", async () => {
  // Construct directly with no approvalsArbiter.
  const server = new DashboardServer({ source: fakeSource, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const getRes = await fetch(`${base}/api/egress/approvals`);
    assert.equal(getRes.status, 404);
    assert.match(((await getRes.json()) as { error: string }).error, /arbiter not connected/);

    const postRes = await fetch(`${base}/api/egress/approvals/egr-1/approve`, {
      method: "POST",
      headers: CSRF,
    });
    assert.equal(postRes.status, 404);
    assert.match(((await postRes.json()) as { error: string }).error, /arbiter not connected/);
  } finally {
    await server.close();
  }
});

test("attachArbiterSurfaces late-binds the approvals surface after a cold boot, set-once", async () => {
  // The supervised cold-boot ordering (server-main): the constructor-time
  // connect fails (no arbiter exists before autostart), the routes answer 404,
  // then autostart's retry attaches the connected surface WITHOUT a restart.
  const server = new DashboardServer({ source: fakeSource, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    assert.equal((await fetch(`${base}/api/egress/approvals`)).status, 404, "cold boot → not connected");

    const { arbiter, ctl } = makeFakeApprovals();
    const seeded = ctl.seedPending("$MDU:Read[aa].x", "evil.test", "r");
    server.attachArbiterSurfaces(arbiter);
    const res = await fetch(`${base}/api/egress/approvals`);
    assert.equal(res.status, 200, "attached → routes serve");
    const body = (await res.json()) as { approvals: EgressApproval[] };
    assert.equal(body.approvals[0]?.id, seeded.id);

    // SET-ONCE: a later attach must not replace the live connection.
    const other = makeFakeApprovals();
    other.ctl.seedPending("$MDU:Read[bb].y", "other.test", "r2");
    server.attachArbiterSurfaces(other.arbiter);
    const again = (await (await fetch(`${base}/api/egress/approvals`)).json()) as {
      approvals: EgressApproval[];
    };
    assert.deepEqual(
      again.approvals.map((a) => a.id),
      [seeded.id],
      "first-attached arbiter still serves",
    );
  } finally {
    await server.close();
  }
});

test("behind the sign-in gate, the egress routes answer 401 before they run", async () => {
  const h = await startServer({ basicAuth: { user: "u", password: "secret pass" } });
  try {
    // No sign-in session → the gate answers before the egress routes.
    const getRes = await fetch(`${h.baseUrl}/api/egress/approvals`, { redirect: "manual" });
    assert.equal(getRes.status, 401);
    assert.match(((await getRes.json()) as { error: string }).error, /sign in required/);

    const postRes = await fetch(`${h.baseUrl}/api/egress/approvals/egr-1/approve`, {
      method: "POST",
      headers: CSRF,
      redirect: "manual",
    });
    assert.equal(postRes.status, 401);
  } finally {
    await h.close();
  }
});

test("POST Always on a held message under a locked ask row → 409 with the arbiter's reason; Allow once is taken (plan 15 §12)", async () => {
  const h = await startServer();
  try {
    const row = h.ctl.seedPending(`prompt:acme.codename#${"a".repeat(32)}`, `model:s1#turn:${"b".repeat(32)}`, "held");
    row.onceOnly = true;
    for (const verb of ["approve", "deny"]) {
      const res = await fetch(`${h.baseUrl}/api/egress/approvals/${row.id}/${verb}`, { method: "POST", headers: CSRF });
      assert.equal(res.status, 409, verb);
      assert.match(((await res.json()) as { error: string }).error, /answer it for this message only/);
    }
    const once = await fetch(`${h.baseUrl}/api/egress/approvals/${row.id}/approve-once`, { method: "POST", headers: CSRF });
    assert.equal(once.status, 200);
  } finally {
    await h.close();
  }
});

test("POST for a question that no longer applies → 409 with the arbiter's reason (the !437 leftover (4))", async () => {
  const h = await startServer();
  try {
    const row = h.ctl.seedPending(`open:/usr/bin/cat#${"c".repeat(64)}`, "/w/.env", "cat wants to read it");
    const res = await fetch(`${h.baseUrl}/api/egress/approvals/${row.id}/approve`, { method: "POST", headers: CSRF });
    assert.equal(res.status, 409);
    const body = (await res.json()) as { error: string; approvalId: string };
    assert.match(body.error, /no longer applies: cat prints or copies/);
    assert.equal(body.approvalId, row.id);
  } finally {
    await h.close();
  }
});
