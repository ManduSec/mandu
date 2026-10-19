/**
 * basic-auth.test — the dashboard's HTTP Basic-auth mode (dashboard.md §6.z;
 * src/server.ts DashboardServerOptions.basicAuth), the auth an HTTP-only front
 * (for example a Cloudflare tunnel) can use.
 *
 * Offline: a real DashboardServer on an ephemeral port with in-memory fakes.
 * Pins:
 *   - with basicAuth set, a request WITHOUT credentials is answered 401 + a
 *     `WWW-Authenticate: Basic` challenge on EVERY route — the app shell,
 *     /api/*, and /login alike (nothing about the app leaks);
 *   - wrong user, wrong password, and a garbled header are the same 401;
 *   - valid credentials serve reads (200) and ARE the admin session: a
 *     mutating request with the CSRF header goes through with NO cookie;
 *   - the CSRF gate still runs first for mutations (missing header → its
 *     own answer, the arbiter is never called);
 *   - the base-path form (`/mandu/...`) is gated the same way;
 *   - without basicAuth the option is inert: the same header changes nothing
 *     (reads open, mutations still need the cookie session).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DashboardServer,
  ADMIN_SESSION_REQUIRED,
  type ApprovalsArbiter,
  type EgressApproval,
} from "../../src/server.js";
import { ADMIN_OPTS } from "./admin-session.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};

const CREDS = { user: "alice", password: "s3cret:with:colons" };
const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;
const GOOD = { Authorization: basic(CREDS.user, CREDS.password) };
const CSRF = { "X-Mandu-Control": "1" };

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

function assertChallenge(res: Response, what: string): void {
  assert.equal(res.status, 401, `${what}: 401`);
  assert.match(res.headers.get("www-authenticate") ?? "", /^Basic realm=/, `${what}: Basic challenge`);
}

test("no credentials → 401 + Basic challenge on every route, including /login and /api", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    for (const path of ["/", "/index.html", "/api/sessions", "/api/egress/approvals", "/login", "/logout"]) {
      const res = await fetch(`${h.base}${path}`, { redirect: "manual" });
      assertChallenge(res, path);
      assert.equal(await res.text(), "Unauthorized", `${path}: no app detail in the body`);
    }
    // A mutation without credentials is 401 too — never the CSRF/admin wording
    // (that would confirm a route exists).
    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF });
    assertChallenge(post, "POST without credentials");
    assert.deepEqual(h.fa.calls, []);
  } finally {
    await h.close();
  }
});

test("wrong user, wrong password, garbled header → the same 401", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const bad = [
      basic("alice", "wrong"),
      basic("root", CREDS.password),
      basic("", ""),
      "Basic not-base64!!",
      "Bearer " + Buffer.from("alice:" + CREDS.password).toString("base64"),
      // Same prefix, one byte short: length mismatch must not short-circuit into a pass.
      `Basic ${Buffer.from(`${CREDS.user}:${CREDS.password}`).toString("base64").slice(0, -4)}`,
    ];
    for (const Authorization of bad) {
      const res = await fetch(`${h.base}/api/sessions`, { headers: { Authorization } });
      assertChallenge(res, Authorization);
    }
  } finally {
    await h.close();
  }
});

test("valid credentials serve reads and ARE the admin session (mutation with CSRF, no cookie)", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const get = await fetch(`${h.base}/api/sessions`, { headers: GOOD });
    assert.equal(get.status, 200);
    assert.equal(get.headers.get("www-authenticate"), null);

    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: { ...CSRF, ...GOOD } });
    assert.equal(post.status, 200, await post.text());
    assert.deepEqual(h.fa.calls, ["egr-1:true"]);

    // The CSRF gate still runs first: credentials alone, no header → its answer, no call.
    const noCsrf = await fetch(`${h.base}/api/egress/approvals/egr-1/deny`, { method: "POST", headers: GOOD });
    assert.equal(noCsrf.status, 403);
    assert.notEqual(((await noCsrf.json()) as { error: string }).error, ADMIN_SESSION_REQUIRED);
    assert.deepEqual(h.fa.calls, ["egr-1:true"]);
  } finally {
    await h.close();
  }
});

test("base-path form: /mandu/... is gated and served the same way", async () => {
  const h = await start({ basicAuth: CREDS, basePath: "/mandu" });
  try {
    assertChallenge(await fetch(`${h.base}/mandu/api/sessions`), "/mandu/api/sessions");
    assertChallenge(await fetch(`${h.base}/mandu/`, { redirect: "manual" }), "/mandu/");
    const ok = await fetch(`${h.base}/mandu/api/sessions`, { headers: GOOD });
    assert.equal(ok.status, 200);
    const post = await fetch(`${h.base}/mandu/api/egress/approvals/egr-1/deny`, { method: "POST", headers: { ...CSRF, ...GOOD } });
    assert.equal(post.status, 200, await post.text());
    assert.deepEqual(h.fa.calls, ["egr-1:false"]);
  } finally {
    await h.close();
  }
});

test("without basicAuth the header is inert: reads open, mutations still need the cookie session", async () => {
  const h = await start();
  try {
    const get = await fetch(`${h.base}/api/sessions`);
    assert.equal(get.status, 200);
    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: { ...CSRF, ...GOOD } });
    assert.equal(post.status, 403);
    assert.equal(((await post.json()) as { error: string }).error, ADMIN_SESSION_REQUIRED);
    assert.deepEqual(h.fa.calls, []);
  } finally {
    await h.close();
  }
});
