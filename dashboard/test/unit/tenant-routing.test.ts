/**
 * tenant-routing.test — one store per request (policy-surface.md
 * §2.7 1c): the dashboard serves the LIVE or the TEST tenant for every route,
 * chosen by `?tenant=` (explicit), else the `mandu_tenant` cookie, else live.
 *
 * Offline: two fake EventSources (live holds session L, test holds T) and two
 * fake ApprovalsArbiters on a real DashboardServer. Pins:
 *   - default → live; cookie → test; `?tenant=` wins over the cookie;
 *   - GET /api/tenants advertises what exists and which one this request got;
 *   - the approvals surface follows the tenant too (Approvals never mixes);
 *   - no test tenant configured: /api/tenants = ["live"], an explicit
 *     `?tenant=test` is 404, a STALE test cookie falls back to live (the page
 *     must never blank), garbage is 400;
 *   - attachArbiterSurfaces(…, "test") late-binds the test surfaces set-once;
 *   - the PRODUCT never follows the cookie (dashboard.md §6.y): /api/home and
 *     /api/home/agent, and any route sent with `X-Mandu-Front: product`, are
 *     the live store unless `?tenant=` names one;
 *   - a tenant whose arbiter is down (a real ArbiterEventSource over a socket
 *     nobody listens on) answers 503 {error, tenant, unreachable}; any other
 *     failure stays 500.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { join } from "node:path";

import { DashboardServer, type ApprovalsArbiter, type EgressApproval } from "../../src/server.js";
import { requestedTenant, isProductRequest, isArbiterUnreachable } from "../../src/server/tenant.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "./admin-session.js";
import { ArbiterEventSource, type EventSource, type SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import { tmpDir } from "./tmp-dir.js";

function source(ids: string[]): EventSource {
  return {
    async listSessions(): Promise<SessionRef[]> {
      return ids.map((id) => ({ id, label: null, eventCount: 1, firstTs: null, lastTs: null, violated: false }));
    },
    async readEvents(): Promise<ManduEvent[]> { return []; },
    subscribe(): () => void { return () => {}; },
    close(): void {},
  };
}

function approvals(id: string): { arbiter: ApprovalsArbiter; calls: string[] } {
  const calls: string[] = [];
  const row: EgressApproval = {
    id, symbol: "$MDU:x[ab12]", destination: "d.example", status: "pending", reason: "r", count: 1, firstSeen: 1, lastSeen: 1,
  };
  return {
    calls,
    arbiter: {
      async egressApprovals() { return [row]; },
      async resolveEgressApproval(approvalId, approve) { calls.push(approvalId); return { ...row, status: approve ? "approved" : "denied" }; },
    },
  };
}

async function sessionIds(base: string, path = "/api/sessions", headers: Record<string, string> = {}): Promise<string[]> {
  const res = await fetch(`${base}${path}`, { headers });
  assert.equal(res.status, 200, `${path} → ${res.status}`);
  const body = (await res.json()) as { sessions: { id: string }[] };
  return body.sessions.map((s) => s.id);
}

test("two tenants: default live, cookie → test, ?tenant= wins; /api/tenants reports both + current", async () => {
  const liveA = approvals("live-1");
  const testA = approvals("test-1");
  const server = new DashboardServer({
    source: source(["L"]),
    approvalsArbiter: liveA.arbiter,
    testTenant: { source: source(["T"]), approvalsArbiter: testA.arbiter },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    assert.deepEqual(await sessionIds(base), ["L"]);
    assert.deepEqual(await sessionIds(base, "/api/sessions", { Cookie: "mandu_tenant=test" }), ["T"]);
    assert.deepEqual(await sessionIds(base, "/api/sessions?tenant=live", { Cookie: "mandu_tenant=test" }), ["L"], "?tenant= beats the cookie");
    assert.deepEqual(await sessionIds(base, "/api/sessions?tenant=test"), ["T"]);

    const t1 = (await (await fetch(`${base}/api/tenants`)).json()) as { tenants: string[]; current: string };
    assert.deepEqual(t1, { tenants: ["live", "test"], current: "live" });
    const t2 = (await (await fetch(`${base}/api/tenants`, { headers: { Cookie: "mandu_tenant=test" } })).json()) as { current: string };
    assert.equal(t2.current, "test");

    // Approvals (the approvals surface) follows the tenant — the live queue never
    // shows a test ask and a test verdict never reaches the live arbiter.
    const liveQ = (await (await fetch(`${base}/api/egress/approvals`)).json()) as { approvals: { id: string }[] };
    assert.deepEqual(liveQ.approvals.map((a) => a.id), ["live-1"]);
    const testQ = (await (await fetch(`${base}/api/egress/approvals?tenant=test`)).json()) as { approvals: { id: string }[] };
    assert.deepEqual(testQ.approvals.map((a) => a.id), ["test-1"]);
    const res = await fetch(`${base}/api/egress/approvals/test-1/approve?tenant=test`, {
      method: "POST",
      headers: { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE },
    });
    assert.equal(res.status, 200);
    assert.deepEqual(testA.calls, ["test-1"]);
    assert.deepEqual(liveA.calls, []);

    const bad = await fetch(`${base}/api/sessions?tenant=staging`);
    assert.equal(bad.status, 400);
  } finally {
    await server.close();
  }
});

test("live only: /api/tenants = [live]; explicit ?tenant=test → 404; a stale test cookie falls back to live", async () => {
  const server = new DashboardServer({ source: source(["L"]), log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const t = (await (await fetch(`${base}/api/tenants`, { headers: { Cookie: "mandu_tenant=test" } })).json()) as {
      tenants: string[]; current: string;
    };
    assert.deepEqual(t, { tenants: ["live"], current: "live" }, "a stale cookie is answered as live, never blanked");
    assert.deepEqual(await sessionIds(base, "/api/sessions", { Cookie: "mandu_tenant=test" }), ["L"]);
    const explicit = await fetch(`${base}/api/sessions?tenant=test`);
    assert.equal(explicit.status, 404);
    assert.match(((await explicit.json()) as { error: string }).error, /no test tenant/);
    // The page itself still serves under the stale cookie.
    const page = await fetch(`${base}/`, { headers: { Cookie: "mandu_tenant=test" } });
    assert.equal(page.status, 200);
  } finally {
    await server.close();
  }
});

test("attachArbiterSurfaces(…, 'test') late-binds the test tenant's surfaces set-once; live stays untouched", async () => {
  const server = new DashboardServer({
    source: source(["L"]),
    testTenant: { source: source(["T"]) },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    assert.equal((await fetch(`${base}/api/egress/approvals?tenant=test`)).status, 404, "cold: not connected");
    assert.equal((await fetch(`${base}/api/egress/approvals`)).status, 404, "live has no surface either");
    const first = approvals("t-first");
    server.attachArbiterSurfaces(first.arbiter, undefined, undefined, undefined, "test");
    const q = (await (await fetch(`${base}/api/egress/approvals?tenant=test`)).json()) as { approvals: { id: string }[] };
    assert.deepEqual(q.approvals.map((a) => a.id), ["t-first"]);
    assert.equal((await fetch(`${base}/api/egress/approvals`)).status, 404, "binding the test tenant did not touch live");
    const second = approvals("t-second");
    server.attachArbiterSurfaces(second.arbiter, undefined, undefined, undefined, "test");
    const again = (await (await fetch(`${base}/api/egress/approvals?tenant=test`)).json()) as { approvals: { id: string }[] };
    assert.deepEqual(again.approvals.map((a) => a.id), ["t-first"], "set-once");
  } finally {
    await server.close();
  }
});

// ── The product never follows the inspector's cookie (dashboard.md §6.y) ─────

/** A test tenant whose arbiter is down: the real event source over a socket
 *  nobody listens on (connect ENOENT, the error a stopped test-arbiter gives). */
function downSource(): ArbiterEventSource {
  return new ArbiterEventSource({ socketPath: join(tmpDir("mdu-tenant-"), "test-arbiter.sock") });
}

test("product routes ignore the test cookie: /api/home is the live store, and so is a shared route sent with X-Mandu-Front: product", async () => {
  const liveA = approvals("live-1");
  const testA = approvals("test-1");
  const down = downSource();
  const server = new DashboardServer({
    source: source(["L"]),
    approvalsArbiter: liveA.arbiter,
    testTenant: { source: down, approvalsArbiter: testA.arbiter },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const COOKIE = { Cookie: "mandu_tenant=test" };
  try {
    // The bug (2026-10-03): the inspector's Tests cookie swapped the product
    // Home for the test store, whose arbiter was down → 500.
    const home = await fetch(`${base}/api/home`, { headers: COOKIE });
    assert.equal(home.status, 200, "the product's home is served for the live tenant whatever the cookie");
    const agent = await fetch(`${base}/api/home/agent?session=L`, { headers: COOKIE });
    assert.equal(agent.status, 200);
    // A shared route: the product says who asked; the inspector still follows the cookie.
    const productQ = (await (await fetch(`${base}/api/egress/approvals`, { headers: { ...COOKIE, "X-Mandu-Front": "product" } })).json()) as { approvals: { id: string }[] };
    assert.deepEqual(productQ.approvals.map((a) => a.id), ["live-1"]);
    const inspectorQ = (await (await fetch(`${base}/api/egress/approvals`, { headers: COOKIE })).json()) as { approvals: { id: string }[] };
    assert.deepEqual(inspectorQ.approvals.map((a) => a.id), ["test-1"], "the inspector keeps its cookie");
    const t = (await (await fetch(`${base}/api/tenants`, { headers: { ...COOKIE, "X-Mandu-Front": "product" } })).json()) as { current: string };
    assert.equal(t.current, "live");
    // An explicit ?tenant= still wins on a product route: the choice is in the URL.
    const explicit = await fetch(`${base}/api/home?tenant=test`);
    assert.equal(explicit.status, 503);
  } finally {
    await server.close();
    down.close();
  }
});

test("a tenant whose arbiter is down answers 503 {error, tenant, unreachable}, never a bare 500", async () => {
  const down = downSource();
  const logs: string[] = [];
  const server = new DashboardServer({
    source: source(["L"]),
    testTenant: { source: down },
    log: (m) => logs.push(m),
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    for (const path of ["/api/sessions", "/api/home?tenant=test", "/api/events?session=T"]) {
      const res = await fetch(`${base}${path}`, { headers: { Cookie: "mandu_tenant=test" } });
      assert.equal(res.status, 503, path);
      assert.match(res.headers.get("content-type") ?? "", /application\/json/, path);
      const body = (await res.json()) as { error: string; tenant: string; unreachable: boolean };
      assert.equal(body.unreachable, true, path);
      assert.equal(body.tenant, "test", path);
      assert.match(body.error, /test tenant's arbiter is not reachable/, path);
      assert.match(body.error, /ENOENT/, `${path}: the cause rides along`);
      assert.match(body.error, /test-arbiter/, `${path}: and what to start`);
    }
    assert.ok(logs.some((l) => /test tenant unreachable/.test(l)));
    // the live tenant is untouched
    assert.deepEqual(await sessionIds(base), ["L"]);
  } finally {
    await server.close();
    down.close();
  }
});

test("any other handler failure stays the 500 it was (only an unreachable arbiter is a 503)", async () => {
  const broken: EventSource = { ...source([]), async listSessions(): Promise<SessionRef[]> { throw new Error("disk on fire"); } };
  const server = new DashboardServer({ source: broken, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/sessions`);
    assert.equal(res.status, 500);
  } finally {
    await server.close();
  }
});

test("requestedTenant / isArbiterUnreachable (pure)", () => {
  const C = { cookie: "a=1; mandu_tenant=test" };
  assert.deepEqual(requestedTenant("/api/sessions", C), { tenant: "test", explicit: false });
  assert.deepEqual(requestedTenant("/api/sessions", {}), { tenant: "live", explicit: false });
  assert.deepEqual(requestedTenant("/api/home", C), { tenant: "live", explicit: false }, "a product-only route");
  assert.deepEqual(requestedTenant("/api/home/agent?session=x", C), { tenant: "live", explicit: false });
  assert.deepEqual(requestedTenant("/api/secrets", { ...C, "x-mandu-front": "product" }), { tenant: "live", explicit: false });
  assert.deepEqual(requestedTenant("/api/secrets", { ...C, "x-mandu-front": "inspector" }), { tenant: "test", explicit: false }, "only `product` opts out");
  assert.deepEqual(requestedTenant("/api/home?tenant=test", C), { tenant: "test", explicit: true });
  assert.deepEqual(requestedTenant("/api/home?tenant=x", {}), { tenant: null, explicit: true });
  assert.deepEqual(requestedTenant("/api/sessions", { cookie: "mandu_tenant=staging" }), { tenant: "live", explicit: false });
  assert.equal(isProductRequest("/api/home", {}), true);
  assert.equal(isProductRequest("/api/sessions", {}), false);
  assert.equal(isArbiterUnreachable(new Error("arbiter connection failed (/s): connect ENOENT /s")), true);
  assert.equal(isArbiterUnreachable(new Error("arbiter connection closed before reply to 'sessions'")), true);
  assert.equal(isArbiterUnreachable(new Error("human plane unavailable: the arbiter at /s names no human socket")), true);
  assert.equal(isArbiterUnreachable(new Error("unknown session x")), false);
  assert.equal(isArbiterUnreachable("arbiter connection failed"), true, "a non-Error throw too");
});
