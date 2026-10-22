/**
 * admin-session.test — the dashboard half of the human/agent boundary
 * (policy-surface.md §2.6; src/server.ts adminToken / trustFront).
 *
 * Offline: a real DashboardServer on an ephemeral port with in-memory fakes.
 * Pins:
 *   - a mutating request WITH the CSRF header but WITHOUT the admin cookie →
 *     403 ADMIN_SESSION_REQUIRED and the arbiter surface is never called
 *     (the same-host process the agent runs can forge the header, not the cookie);
 *   - a missing CSRF header is still answered as before (the CSRF gate runs first);
 *   - GET /login?token=<adminToken> sets the cookie and redirects; a wrong
 *     token is a plain 403; with the cookie the mutation goes through;
 *   - a read that can carry a real value needs the session too (2026-10-05,
 *     read-gate.ts, dashboard.md §6): an `admin` read without it is 403, a
 *     `projection` read is served without its values; a metadata read
 *     (the session list) stays open. The whole table is read-gate.test.ts
 *     and test/component/value-gate.test.ts;
 *   - adminCookie()/adminLoginPath() are the values a client needs; they are
 *     TEST SEAMS: with the dashboard account (or none yet, fail closed) the
 *     token's cookie and link pass the sign-in gate only when the token was
 *     pinned (`pinnedAdminToken`, DASHBOARD_ADMIN_TOKEN), dashboard.md §6.z;
 *   - a write whose arbiter surface throws the admin-unavailable error (an
 *     ADOPTED arbiter — no inherited fd) answers 503 with the remedy, never
 *     404 "unknown id" and never 200.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DashboardServer,
  ADMIN_SESSION_REQUIRED,
  type ApprovalsArbiter,
  type EgressApproval,
} from "../../src/server.js";
import { adminUnavailableError } from "../../src/server/http-util.js";
import { AccountFile, makeAccount, writeAccount } from "../../src/account.js";
import { tmpDir } from "./tmp-dir.js";
import { join } from "node:path";
import { ADMIN_OPTS, ADMIN_COOKIE, ADMIN_TOKEN } from "./admin-session.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};

const CSRF_ONLY = { "X-Mandu-Control": "1" };
const CSRF_ADMIN = { ...CSRF_ONLY, Cookie: ADMIN_COOKIE };

function fakeApprovals(): { arbiter: ApprovalsArbiter; calls: string[] } {
  const calls: string[] = [];
  const row: EgressApproval = {
    id: "egr-1", symbol: "$MDU:x[ab12]", destination: "evil.example", status: "pending",
    reason: "r", count: 1, firstSeen: 1, lastSeen: 1,
  };
  return {
    calls,
    arbiter: {
      async egressApprovals() { return [row]; },
      async resolveEgressApproval(id, approve) {
        calls.push(`${id}:${approve}`);
        return { ...row, status: approve ? "approved" : "denied" };
      },
    },
  };
}

async function start(opts: Partial<ConstructorParameters<typeof DashboardServer>[0]> = {}) {
  const fa = fakeApprovals();
  const server = new DashboardServer({ source: fakeSource, approvalsArbiter: fa.arbiter, log: () => {}, ...ADMIN_OPTS, ...opts });
  const port = await server.listen(0);
  return { server, fa, base: `http://127.0.0.1:${port}`, close: () => server.close() };
}

test("CSRF header without the admin cookie → 403 ADMIN_SESSION_REQUIRED; the arbiter is never called", async () => {
  const h = await start();
  try {
    const res = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF_ONLY });
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as { error: string }).error, ADMIN_SESSION_REQUIRED);
    assert.deepEqual(h.fa.calls, []);
    // A DELETE is a mutation too.
    const del = await fetch(`${h.base}/api/session?session=x`, { method: "DELETE", headers: CSRF_ONLY });
    assert.equal(del.status, 403);
  } finally {
    await h.close();
  }
});

test("a missing CSRF header is answered by the CSRF gate first (unchanged wording)", async () => {
  const h = await start();
  try {
    const res = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST" });
    assert.equal(res.status, 403);
    assert.match(((await res.json()) as { error: string }).error, /X-Mandu-Control/);
  } finally {
    await h.close();
  }
});

test("metadata reads need no session, value-bearing reads do; with the cookie the mutation goes through", async () => {
  const h = await start();
  try {
    assert.equal((await fetch(`${h.base}/api/egress/approvals`)).status, 200);
    assert.equal((await fetch(`${h.base}/api/sessions`)).status, 200);
    // A read that can carry a value (read-gate.ts): an `admin` one is
    // refused with the sentence that says how to sign in, the CSRF header
    // alone (which any process can send) is not enough, the cookie and
    // the header are; a `projection` one is served, without its values.
    for (const headers of [{}, CSRF_ONLY, { Cookie: ADMIN_COOKIE, "Sec-Fetch-Site": "cross-site" }] as Array<Record<string, string>>) {
      const held = await fetch(`${h.base}/api/prompt-filters/holds`, { headers });
      assert.equal(held.status, 403, JSON.stringify(headers));
      assert.equal(((await held.json()) as { error: string }).error, ADMIN_SESSION_REQUIRED);
    }
    assert.notEqual((await fetch(`${h.base}/api/prompt-filters/holds`, { headers: CSRF_ADMIN })).status, 403, "signed in, the gate lets it through");
    assert.notEqual((await fetch(`${h.base}/api/policy/sensitivity-labels`, { headers: { Cookie: ADMIN_COOKIE, "Sec-Fetch-Site": "same-origin" } })).status, 403, "a browser's same-origin read with the cookie");
    const events = (await (await fetch(`${h.base}/api/events?session=x`)).json()) as { valuesShown: boolean };
    assert.equal(events.valuesShown, false);
    const signedIn = (await (await fetch(`${h.base}/api/events?session=x`, { headers: CSRF_ADMIN })).json()) as { valuesShown: boolean };
    assert.equal(signedIn.valuesShown, true);
    const res = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(res.status, 200);
    assert.deepEqual(h.fa.calls, ["egr-1:true"]);
    assert.equal(h.server.adminCookie(), ADMIN_COOKIE, "adminCookie() is the value tests precompute");
    assert.equal(h.server.adminLoginPath(), `/login?token=${ADMIN_TOKEN}`);
  } finally {
    await h.close();
  }
});

test("GET /login?token=<adminToken> sets the session cookie and redirects; a wrong token is a bare 403", async () => {
  const h = await start();
  try {
    const ok = await fetch(`${h.base}/login?token=${ADMIN_TOKEN}`, { redirect: "manual" });
    assert.equal(ok.status, 302);
    const setCookie = ok.headers.get("set-cookie") ?? "";
    assert.match(setCookie, /^mandu_session=[0-9a-f]{64}; Path=\/; HttpOnly; SameSite=Strict$/);
    assert.equal(setCookie.split(";")[0], ADMIN_COOKIE, "the cookie the link sets is the one mutations need");
    assert.equal(ok.headers.get("location"), "/");

    const bad = await fetch(`${h.base}/login?token=nope`, { redirect: "manual" });
    assert.equal(bad.status, 403);
    assert.equal(bad.headers.get("set-cookie"), null);

    // The browser now carries it: the mutation is accepted.
    const cookie = setCookie.split(";")[0]!;
    const res = await fetch(`${h.base}/api/egress/approvals/egr-1/deny`, {
      method: "POST",
      headers: { ...CSRF_ONLY, Cookie: cookie },
    });
    assert.equal(res.status, 200);
  } finally {
    await h.close();
  }
});

test("with the account gate, the admin token passes only when pinned (a test seam)", async () => {
  for (const withAccount of [true, false]) {
    const dir = tmpDir("mandu-admin-token-");
    const file = join(dir, "state", "dashboard-account.json");
    if (withAccount) writeAccount(file, await makeAccount("alice", "a long enough password"));
    const closed = await start({ account: new AccountFile(file) });
    try {
      // Not pinned: neither the link nor the cookie gets past the sign-in.
      assert.equal((await fetch(`${closed.base}/login?token=${ADMIN_TOKEN}`, { redirect: "manual" })).status, 401);
      assert.equal((await fetch(`${closed.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF_ADMIN })).status, 401);
      assert.deepEqual(closed.fa.calls, []);
    } finally {
      await closed.close();
    }
    const pinned = await start({ account: new AccountFile(file), pinnedAdminToken: true });
    try {
      const ok = await fetch(`${pinned.base}/login?token=${ADMIN_TOKEN}`, { redirect: "manual" });
      assert.equal(ok.status, 302, `pinned (${withAccount ? "an account" : "no account"}): the link sets the cookie`);
      assert.equal((ok.headers.get("set-cookie") ?? "").split(";")[0], ADMIN_COOKIE);
      assert.equal((await fetch(`${pinned.base}/login?token=nope`, { redirect: "manual" })).status, 403, "a wrong token: a bare 403, no cookie");
      const res = await fetch(`${pinned.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF_ADMIN });
      assert.equal(res.status, 200, await res.text());
      assert.deepEqual(pinned.fa.calls, ["egr-1:true"]);
    } finally {
      await pinned.close();
    }
  }
});

test("an adopted arbiter (no admin channel) → 503 with the remedy, never 404 and never 200", async () => {
  const calls: string[] = [];
  const approvals: ApprovalsArbiter = {
    async egressApprovals() { return []; },
    async resolveEgressApproval(id) {
      calls.push(id);
      throw adminUnavailableError("this dashboard did not start the arbiter (adopted instance) — restart the services from Settings");
    },
  };
  const server = new DashboardServer({ source: fakeSource, approvalsArbiter: approvals, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const res = await fetch(`${base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(res.status, 503);
    assert.match(((await res.json()) as { error: string }).error, /admin channel unavailable.*restart the services/);
  } finally {
    await server.close();
  }
});

test("GET /login past the gate goes Home (the sign-in page is the gate's)", async () => {
  const h = await start();
  try {
    const res = await fetch(`${h.base}/login`, { redirect: "manual" });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get("location"), "/");
    assert.equal(h.server.signInMode(), "none", "a server built without an account has no sign-in gate (tests only)");
    // A ticket link of an older launcher signs nobody in.
    const ticket = await fetch(`${h.base}/login?ticket=${"0".repeat(32)}`, { redirect: "manual" });
    assert.equal(ticket.headers.get("set-cookie"), null);
  } finally {
    await h.close();
  }
});

test("the 403 without a session says how to sign in", () => {
  assert.match(ADMIN_SESSION_REQUIRED, /^admin session required\b/, "home.js ADMIN_REFUSAL still matches");
  assert.match(ADMIN_SESSION_REQUIRED, /sign in with your Mandu dashboard account \(no account yet: run `mandu dashboard --set-password` in your own terminal\)/);
  assert.doesNotMatch(ADMIN_SESSION_REQUIRED, /sign-in link|DASHBOARD_PASSWORD/);
});
