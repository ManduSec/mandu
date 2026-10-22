/**
 * account-sign-in.test — the sign-in gate over the Mandu dashboard account
 * FILE (src/server.ts `account` option, src/account.ts; dashboard.md §6.z).
 * The gate's own behaviour (the page, CSRF, redirects, the throttle) is
 * pinned once in basic-auth.test.ts; this file pins what the file adds.
 *
 * Pins:
 *   - no file: FAIL CLOSED: every route is 401, a navigation gets the "no
 *     account yet" page with what to run and no form, and nothing signs in;
 *   - a file: every route is gated; the account's pair signs in on the page
 *     and as a Basic header (the header remembered, so a script's every
 *     request is not a fresh scrypt), and is the admin session;
 *   - `mandu dashboard --set-password` while running applies at once, and a
 *     change of the file ends every sign-in session and every remembered
 *     header, is logged, and Home's `signIn.accountChangedAt` says when;
 *   - an unusable file (mode 644, a link) signs nobody in: the page says
 *     why and what to run, the right password and the right header are
 *     refused;
 *   - the account wins over an in-memory basicAuth pair;
 *   - the server's sign-in mode names it (`account`), and the ticket route
 *     signs nobody in.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, rmSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer, type ApprovalsArbiter, type EgressApproval } from "../../src/server.js";
import { AccountFile, makeAccount, writeAccount } from "../../src/account.js";
import { ADMIN_OPTS } from "./admin-session.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import { tmpDir } from "./tmp-dir.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};
const PASSWORD = "a long enough password";
const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;
const CSRF = { "X-Mandu-Control": "1" };
const NAV = { Accept: "text/html" };

function approvals(): { arbiter: ApprovalsArbiter; calls: string[] } {
  const calls: string[] = [];
  const row: EgressApproval = { id: "egr-1", symbol: "$MDU:x[ab12]", destination: "d", status: "pending", reason: "r", count: 1, firstSeen: 1, lastSeen: 1 };
  return {
    calls,
    arbiter: {
      async egressApprovals() { return [row]; },
      async resolveEgressApproval(id, approve) { calls.push(`${id}:${approve}`); return { ...row, status: approve ? "approved" : "denied" }; },
    },
  };
}

async function start(opts: Partial<ConstructorParameters<typeof DashboardServer>[0]> = {}) {
  const dir = tmpDir("mandu-acct-srv-");
  const path = join(dir, "state", "dashboard-account.json");
  const logs: string[] = [];
  const account = new AccountFile(path, { onChange: (w) => logs.push(`changed: ${w}`) });
  const fa = approvals();
  const server = new DashboardServer({ source: fakeSource, approvalsArbiter: fa.arbiter, log: (m) => logs.push(m), account, ...ADMIN_OPTS, ...opts });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  return { server, path, logs, base, fa, close: () => server.close() };
}

function signIn(base: string, user: string, password: string): Promise<Response> {
  return fetch(`${base}/login`, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: base, ...NAV },
    body: new URLSearchParams({ user, password }).toString(),
  });
}
const cookieOf = (res: Response): string => `mandu_signin=${/mandu_signin=([^;]*)/.exec(res.headers.get("set-cookie") ?? "")?.[1] ?? ""}`;

test("no account file: fail closed, the page says how to make one, nothing signs in", async () => {
  const h = await start();
  try {
    assert.equal(h.server.signInMode(), "no-account");
    for (const p of ["/api/sessions", "/api/home", "/api/stream", "/dev/", "/app.css"]) {
      const res = await fetch(`${h.base}${p}`);
      assert.equal(res.status, 401, p);
      assert.equal(res.headers.get("www-authenticate"), null, p);
    }
    const api = (await (await fetch(`${h.base}/api/sessions`)).json()) as { error: string };
    assert.match(api.error, /no account yet; run `mandu dashboard --set-password`/);
    const page = await fetch(`${h.base}/`, { headers: NAV });
    assert.equal(page.status, 401);
    const html = await page.text();
    assert.match(html, /No account yet\. To make one, run <code>mandu dashboard --set-password<\/code>/);
    assert.doesNotMatch(html, /<form/, "no form to guess at");
    const res = await signIn(h.base, "alice", PASSWORD);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("set-cookie"), null);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Authorization: basic("alice", PASSWORD) } })).status, 401);
    // Made while it runs: the account works at once.
    writeAccount(h.path, await makeAccount("alice", PASSWORD));
    assert.equal(h.server.signInMode(), "account");
    assert.equal((await signIn(h.base, "alice", PASSWORD)).status, 303);
  } finally {
    await h.close();
  }
});

test("an account file gates every route; its pair signs in on the page and as a header, as the admin session", async () => {
  const h = await start();
  try {
    writeAccount(h.path, await makeAccount("alice", PASSWORD));
    assert.equal(h.server.signInMode(), "account");
    for (const p of ["/", "/dev/", "/api/sessions", "/api/stream", "/login?ticket=abc"]) {
      const res = await fetch(`${h.base}${p}`, { redirect: "manual" });
      assert.equal(res.status, 401, p);
      assert.equal(res.headers.get("www-authenticate"), null, p);
    }
    assert.equal((await signIn(h.base, "alice", "wrong password")).status, 401);
    const ok = await signIn(h.base, "alice", PASSWORD);
    assert.equal(ok.status, 303);
    const cookie = cookieOf(ok);
    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: { ...CSRF, Cookie: cookie } });
    assert.equal(post.status, 200, await post.text());

    const header = { Authorization: basic("alice", PASSWORD) };
    const t0 = Date.now();
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: header })).status, 200);
    const first = Date.now() - t0;
    const t1 = Date.now();
    for (let i = 0; i < 5; i++) assert.equal((await fetch(`${h.base}/api/sessions`, { headers: header })).status, 200);
    const five = Date.now() - t1;
    assert.ok(five < first * 5 + 50, `a remembered header costs no scrypt (first ${first} ms, next five ${five} ms)`);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Authorization: basic("alice", "nope") } })).status, 401);
  } finally {
    await h.close();
  }
});

test("a change of the file applies at once and ends every session and remembered header; Home says when", async () => {
  const h = await start();
  try {
    writeAccount(h.path, await makeAccount("alice", PASSWORD));
    const cookie = cookieOf(await signIn(h.base, "alice", PASSWORD));
    const header = { Authorization: basic("alice", PASSWORD) };
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: header })).status, 200);
    const before = (await (await fetch(`${h.base}/api/home`, { headers: { Cookie: cookie, ...CSRF } })).json()) as { signIn?: { accountChangedAt: string | null } };
    assert.ok(before.signIn?.accountChangedAt, "made while running: a change");

    writeAccount(h.path, await makeAccount("alice", "the new password!"));
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } })).status, 401, "the old session ended");
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: header })).status, 401, "the old password no longer works");
    assert.ok(h.logs.some((l) => /every sign-in session ended/.test(l)));
    const again = cookieOf(await signIn(h.base, "alice", "the new password!"));
    const home = (await (await fetch(`${h.base}/api/home`, { headers: { Cookie: again, ...CSRF } })).json()) as { signIn?: { signOut: boolean; accountChangedAt: string | null } };
    assert.equal(home.signIn?.signOut, true);
    assert.ok(home.signIn?.accountChangedAt && Date.parse(home.signIn.accountChangedAt) > Date.parse(before.signIn!.accountChangedAt!));
    // Removed: no account, so fail closed again: the old session is gone.
    rmSync(h.path);
    assert.equal(h.server.signInMode(), "no-account");
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: again } })).status, 401);
  } finally {
    await h.close();
  }
});

test("an unusable file signs nobody in: the page says why, the right password and header are refused", async () => {
  const h = await start();
  try {
    writeAccount(h.path, await makeAccount("alice", PASSWORD));
    chmodSync(h.path, 0o644);
    const page = await fetch(`${h.base}/`, { headers: NAV });
    assert.equal(page.status, 401);
    const html = await page.text();
    assert.match(html, /cannot be used: its file is not as Mandu wrote it/);
    assert.doesNotMatch(html, /readable or writable|mode/, "why is in the log, not on a page a stranger can open");
    assert.match(html, /mandu dashboard --set-password/);
    assert.doesNotMatch(html, /<form/, "no form to fill");
    const res = await signIn(h.base, "alice", PASSWORD);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("set-cookie"), null);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Authorization: basic("alice", PASSWORD) } })).status, 401);
    const api = (await (await fetch(`${h.base}/api/sessions`)).json()) as { error: string };
    assert.match(api.error, /set-password/);
  } finally {
    await h.close();
  }
});

test("the account wins over an in-memory basicAuth pair", async () => {
  const h = await start({ basicAuth: { user: "old", password: "old-pass" } });
  try {
    assert.equal(h.server.signInMode(), "basic-auth", "no file yet: the pair stands in");
    assert.equal(h.server.signInMode() === "basic-auth" && (await fetch(`${h.base}/api/sessions`)).status, 401);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Authorization: basic("old", "old-pass") } })).status, 200);
    writeAccount(h.path, await makeAccount("alice", PASSWORD));
    assert.equal(h.server.signInMode(), "account");
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Authorization: basic("old", "old-pass") } })).status, 401);
    assert.equal((await signIn(h.base, "old", "old-pass")).status, 401);
    assert.equal((await signIn(h.base, "alice", PASSWORD)).status, 303);
  } finally {
    await h.close();
  }
});
