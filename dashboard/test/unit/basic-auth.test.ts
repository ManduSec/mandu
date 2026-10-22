/**
 * basic-auth.test — the dashboard's sign-in gate with the in-memory
 * `basicAuth` pair (dashboard.md §6.z; src/server.ts signInGate), the mode a
 * DASHBOARD_BASIC_AUTH value runs in until it moves into the dashboard
 * account. The account file's own mode: account-sign-in.test.ts.
 *
 * Offline: a real DashboardServer on an ephemeral port with in-memory fakes.
 * Pins:
 *   - without credentials or a session, a browser navigation gets 401 and
 *     the self-contained sign-in page (Username, Password; inline CSS, no
 *     script, no app data), anything else a 401 JSON/plain answer; NEVER a
 *     `WWW-Authenticate` header (no native prompt) — on every route,
 *     /login, /logout and /api alike;
 *   - wrong user, wrong password, and a garbled header are the same 401;
 *   - a valid `Authorization: Basic` header still serves reads and IS the
 *     admin session (a mutation with the CSRF header goes through, no
 *     cookie); the CSRF gate still runs first;
 *   - `POST /login`: right → 303 to the page asked for with an HttpOnly,
 *     SameSite=Strict cookie scoped to the base path (Secure only over
 *     HTTPS); wrong → 401, the one generic line, no cookie; another site's
 *     form (Origin, Referer, Sec-Fetch-Site) → 403, no cookie; `next` never
 *     leaves the dashboard;
 *   - the throttle: five failures within a minute lock sign-in for 30 s
 *     (a right password too, and the header), the next lock is longer, and
 *     a lock ends;
 *   - the session is the admin session; Sign out ends it on the server;
 *   - the base-path form is gated and served the same way;
 *   - without basicAuth the option is inert.
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
import { SESSION_IDLE_MS, THROTTLE_FIRST_LOCK_MS } from "../../src/server/sign-in-gate.js";

const CANARY_SESSION = "sess-canary-41f7";
const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return [{ id: CANARY_SESSION, label: null, eventCount: 1 } as SessionRef]; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};

const CREDS = { user: "alice", password: "s3cret:with:colons" };
const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;
const GOOD = { Authorization: basic(CREDS.user, CREDS.password) };
const CSRF = { "X-Mandu-Control": "1" };
const NAV = { Accept: "text/html,application/xhtml+xml,*/*;q=0.8" };

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
  const logs: string[] = [];
  let now = 1_000_000;
  const server = new DashboardServer({
    source: fakeSource, approvalsArbiter: fa.arbiter, log: (m) => logs.push(m), signInClock: () => now, ...ADMIN_OPTS, ...opts,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  return {
    server, fa, logs, base, origin: base,
    advance: (ms: number) => { now += ms; },
    close: () => server.close(),
  };
}

type H = Awaited<ReturnType<typeof start>>;

/** A form POST to <prefix>/login as the sign-in page sends it. */
function signIn(h: H, fields: Record<string, string>, headers: Record<string, string> = {}, prefix = ""): Promise<Response> {
  return fetch(`${h.base}${prefix}/login`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: h.origin, ...NAV, ...headers },
    body: new URLSearchParams(fields).toString(),
  });
}

function cookieOf(res: Response): string {
  const set = res.headers.get("set-cookie") ?? "";
  const m = /mandu_signin=([^;]*)/.exec(set);
  assert.ok(m && m[1], `a sign-in cookie was set: ${set}`);
  return `mandu_signin=${m[1]}`;
}

function assertNoPrompt(res: Response, what: string): void {
  assert.equal(res.headers.get("www-authenticate"), null, `${what}: no WWW-Authenticate (no native prompt)`);
}

/** The sign-in page and nothing of the app. */
function assertSignInPage(html: string, what: string): void {
  assert.match(html, /<form method="POST" action="[^"]*\/login">/, `${what}: the form posts to /login`);
  assert.match(html, /name="user"/, `${what}: a Username field`);
  assert.match(html, /name="password" type="password"/, `${what}: a Password field`);
  assert.doesNotMatch(html, /<script/i, `${what}: no script`);
  assert.doesNotMatch(html, /<link /i, `${what}: no stylesheet past the gate`);
  assert.doesNotMatch(html, /home\.js|base-path|fetch\(|EventSource/, `${what}: no app shell, no API`);
  assert.ok(!html.includes(CANARY_SESSION), `${what}: no app data`);
}

test("no credentials: a navigation gets the sign-in page, anything else a 401; never WWW-Authenticate", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    for (const path of ["/", "/index.html", "/agents/x", "/login", "/dev/", "/api/home"]) {
      const res = await fetch(`${h.base}${path}`, { redirect: "manual", headers: NAV });
      assert.equal(res.status, 401, `${path}: 401`);
      assertNoPrompt(res, path);
      assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/, `${path}: the page's CSP`);
      assert.equal(res.headers.get("x-frame-options"), "DENY");
      assert.equal(res.headers.get("cache-control"), "no-store");
      assertSignInPage(await res.text(), path);
    }
    for (const path of ["/api/sessions", "/api/egress/approvals", "/api/stream", `/api/sessions/${CANARY_SESSION}/events`]) {
      const res = await fetch(`${h.base}${path}`);
      assert.equal(res.status, 401, `${path}: 401`);
      assertNoPrompt(res, path);
      const body = await res.text();
      assert.match(body, /sign in required/, `${path}: says what to do`);
      assert.ok(!body.includes(CANARY_SESSION), `${path}: no app data`);
    }
    const plain = await fetch(`${h.base}/app.css`);
    assert.equal(plain.status, 401);
    assertNoPrompt(plain, "/app.css");
    // A mutation without credentials is 401 too — never the CSRF/admin wording.
    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: CSRF });
    assert.equal(post.status, 401);
    assertNoPrompt(post, "POST");
    assert.deepEqual(h.fa.calls, []);
    // HEAD of a page: the status and headers, no body.
    const head = await fetch(`${h.base}/`, { method: "HEAD", headers: NAV });
    assert.equal(head.status, 401);
    assertNoPrompt(head, "HEAD");
  } finally {
    await h.close();
  }
});

test("wrong user, wrong password, garbled header → the same 401, no prompt", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const bad = [
      basic("alice", "wrong"),
      basic("root", CREDS.password),
      "Basic not-base64!!",
      "Bearer " + Buffer.from("alice:" + CREDS.password).toString("base64"),
      // Same prefix, one byte short: length mismatch must not short-circuit into a pass.
      `Basic ${Buffer.from(`${CREDS.user}:${CREDS.password}`).toString("base64").slice(0, -4)}`,
    ];
    for (const Authorization of bad) {
      const res = await fetch(`${h.base}/api/sessions`, { headers: { Authorization } });
      assert.equal(res.status, 401, Authorization);
      assertNoPrompt(res, Authorization);
      h.advance(61_000); // keep the throttle out of this test
    }
    assert.ok(h.logs.some((l) => /sign-in failed \(wrong username or password, a Basic header\)/.test(l)), "a failure is logged");
    assert.ok(!h.logs.some((l) => l.includes(CREDS.password) || /alice|root/.test(l)), "no password or typed username in the log");
  } finally {
    await h.close();
  }
});

test("a valid Basic header still serves reads and IS the admin session (mutation with CSRF, no cookie)", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const get = await fetch(`${h.base}/api/sessions`, { headers: GOOD });
    assert.equal(get.status, 200);
    assertNoPrompt(get, "valid");

    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: { ...CSRF, ...GOOD } });
    assert.equal(post.status, 200, await post.text());
    assert.deepEqual(h.fa.calls, ["egr-1:true"]);

    // The CSRF gate still runs first: credentials alone, no header → its answer, no call.
    const noCsrf = await fetch(`${h.base}/api/egress/approvals/egr-1/deny`, { method: "POST", headers: GOOD });
    assert.equal(noCsrf.status, 403);
    assert.notEqual(((await noCsrf.json()) as { error: string }).error, ADMIN_SESSION_REQUIRED);
    assert.deepEqual(h.fa.calls, ["egr-1:true"]);
    // A header is not a sign-in session: Settings offers no Sign out.
    const home = (await (await fetch(`${h.base}/api/home`, { headers: { ...GOOD, ...CSRF } })).json()) as { signIn?: { signOut: boolean } };
    assert.equal(home.signIn?.signOut, false);
  } finally {
    await h.close();
  }
});

test("POST /login right: 303 to the page asked for, an HttpOnly SameSite=Strict cookie; the session is the admin session", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const res = await signIn(h, { user: CREDS.user, password: CREDS.password, next: "/agents/abc?ask=1" });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get("location"), "/agents/abc?ask=1");
    const set = res.headers.get("set-cookie") ?? "";
    assert.match(set, /HttpOnly/);
    assert.match(set, /SameSite=Strict/);
    assert.match(set, /Path=\//);
    assert.doesNotMatch(set, /Secure/, "plain http://127.0.0.1 keeps working: no Secure flag");
    const cookie = cookieOf(res);
    assertNoPrompt(res, "303");

    const shell = await fetch(`${h.base}/`, { headers: { Cookie: cookie, ...NAV } });
    assert.equal(shell.status, 200);
    const api = await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } });
    assert.equal(api.status, 200);
    // The admin session: a mutation with the CSRF header goes through.
    const post = await fetch(`${h.base}/api/egress/approvals/egr-1/approve`, { method: "POST", headers: { ...CSRF, Cookie: cookie } });
    assert.equal(post.status, 200, await post.text());
    assert.deepEqual(h.fa.calls, ["egr-1:true"]);
    // Home tells the page to offer Sign out.
    const home = (await (await fetch(`${h.base}/api/home`, { headers: { Cookie: cookie, ...CSRF } })).json()) as { signIn?: { signOut: boolean; accountChangedAt: string | null } };
    assert.deepEqual(home.signIn, { signOut: true, accountChangedAt: null });
    // GET /login while signed in goes Home.
    const login = await fetch(`${h.base}/login`, { headers: { Cookie: cookie, ...NAV }, redirect: "manual" });
    assert.equal(login.status, 303);
    assert.equal(login.headers.get("location"), "/");
    // Behind HTTPS (a tunnel or front says so), the cookie is Secure.
    const tls = await signIn(h, { user: CREDS.user, password: CREDS.password }, { "X-Forwarded-Proto": "https" });
    assert.equal(tls.status, 303);
    assert.match(tls.headers.get("set-cookie") ?? "", /; Secure/);
  } finally {
    await h.close();
  }
});

test("POST /login wrong: 401, one generic line, no cookie; the same for a wrong user and a wrong password", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const bodies: string[] = [];
    for (const fields of [{ user: CREDS.user, password: "nope" }, { user: "mallory", password: CREDS.password }, { user: "", password: "" }]) {
      const res = await signIn(h, fields);
      assert.equal(res.status, 401);
      assert.equal(res.headers.get("set-cookie"), null, "no cookie");
      assertNoPrompt(res, "wrong");
      const html = await res.text();
      assert.match(html, /Wrong username or password\./);
      assertSignInPage(html, "wrong");
      bodies.push(html.replace(/value="[^"]*" autofocus|value="[^"]*"/g, ""));
    }
    assert.equal(bodies[0], bodies[1], "a wrong user and a wrong password read the same");
    assert.ok(!h.logs.some((l) => l.includes("nope") || l.includes("mallory")), "the log holds neither the password nor the username typed");
  } finally {
    await h.close();
  }
});

test("login CSRF: a sign-in from another site's form is refused with no cookie", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const right = { user: CREDS.user, password: CREDS.password };
    for (const [what, headers] of [
      ["another Origin", { Origin: "http://evil.example" }],
      ["Origin null", { Origin: "null" }],
      ["another port", { Origin: "http://127.0.0.1:1" }],
      ["Sec-Fetch-Site cross-site", { "Sec-Fetch-Site": "cross-site" }],
      ["Sec-Fetch-Site same-site", { "Sec-Fetch-Site": "same-site" }],
    ] as const) {
      const res = await signIn(h, right, headers);
      assert.equal(res.status, 403, what);
      assert.equal(res.headers.get("set-cookie"), null, `${what}: no cookie`);
      assert.match(await res.text(), /did not come from the dashboard's own page/, what);
    }
    // Neither Origin nor Referer: refused (a script signs in with a header).
    const bare = await fetch(`${h.base}/login`, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(right).toString() });
    assert.equal(bare.status, 403);
    assert.equal(bare.headers.get("set-cookie"), null);
    // A Referer of this dashboard stands in for a missing Origin.
    const ref = await fetch(`${h.base}/login`, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded", Referer: `${h.base}/` }, body: new URLSearchParams(right).toString() });
    assert.equal(ref.status, 303);
    // localhost names this dashboard too (the Host check's names).
    const port = new URL(h.base).port;
    const local = await signIn(h, right, { Origin: `http://localhost:${port}` });
    assert.equal(local.status, 303);
  } finally {
    await h.close();
  }
});

test("no open redirect: `next` stays on this dashboard", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const cases: Array<[string, string]> = [
      ["//evil.example/x", "/"],
      ["https://evil.example/", "/"],
      ["/\\evil.example", "/"],
      ["/%0d%0aSet-Cookie:x", "/%0d%0aSet-Cookie:x"],
      ["/ok\r\nX: y", "/"],
      ["javascript:alert(1)", "/"],
      ["/logout", "/"],
      ["", "/"],
      ["/rules#keys-found", "/rules#keys-found"],
    ];
    for (const [next, want] of cases) {
      const res = await signIn(h, { user: CREDS.user, password: CREDS.password, next });
      assert.equal(res.status, 303, next);
      assert.equal(res.headers.get("location"), want, `next=${JSON.stringify(next)}`);
    }
    // The page a navigation asked for rides in the form, escaped.
    const page = await (await fetch(`${h.base}/agents/a"b<c`, { headers: NAV })).text();
    assert.match(page, /name="next" value="\/agents\/a%22b%3Cc"|name="next" value="\/agents\/a&quot;b&lt;c"/);
  } finally {
    await h.close();
  }
});

test("the throttle: 5 failures in a minute lock sign-in (a right password too), longer the next time, and the lock ends", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    for (let i = 1; i <= 4; i++) assert.equal((await signIn(h, { user: "alice", password: `bad${i}` })).status, 401);
    const fifth = await signIn(h, { user: "alice", password: "bad5" });
    assert.equal(fifth.status, 429, "the fifth failure locks");
    assert.match(await fifth.text(), /Too many wrong tries\. Wait 30 seconds/);
    // Locked: the right password is refused, and so is the right header.
    const right = await signIn(h, { user: CREDS.user, password: CREDS.password });
    assert.equal(right.status, 429);
    assert.equal(right.headers.get("set-cookie"), null);
    const header = await fetch(`${h.base}/api/sessions`, { headers: GOOD });
    assert.equal(header.status, 429);
    assert.ok(h.logs.some((l) => /sign-in locked for 30 s/.test(l)), "the lock is logged");
    // The lock ends.
    h.advance(THROTTLE_FIRST_LOCK_MS + 1);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: GOOD })).status, 200);
    // Five more failures: a longer lock (60 s); a success in between would reset it.
    for (let i = 0; i < 4; i++) await signIn(h, { user: "x", password: "y" });
    const again = await signIn(h, { user: "x", password: "y" });
    assert.equal(again.status, 429);
    assert.match(await again.text(), /Wait 60 seconds/);
    h.advance(60_001);
    assert.equal((await signIn(h, { user: CREDS.user, password: CREDS.password })).status, 303, "never locked for good");
    // Failures spread over more than a minute never lock.
    for (let i = 0; i < 8; i++) {
      assert.equal((await signIn(h, { user: "x", password: "y" })).status, 401);
      h.advance(20_000);
    }
  } finally {
    await h.close();
  }
});

test("Sign out ends the session on the server; another site cannot sign you out by POST", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const cookie = cookieOf(await signIn(h, { user: CREDS.user, password: CREDS.password }));
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } })).status, 200);
    const forged = await fetch(`${h.base}/logout`, { method: "POST", redirect: "manual", headers: { Cookie: cookie, Origin: "http://evil.example" } });
    assert.equal(forged.status, 403);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } })).status, 200, "still signed in");

    const out = await fetch(`${h.base}/logout`, { method: "POST", redirect: "manual", headers: { Cookie: cookie, Origin: h.origin } });
    assert.equal(out.status, 303);
    assert.equal(out.headers.get("location"), "/login?out=1");
    assert.match(out.headers.get("set-cookie") ?? "", /mandu_signin=; .*Max-Age=0/);
    // The old cookie is dead even if a browser kept it.
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } })).status, 401);
    const page = await fetch(`${h.base}/login?out=1`, { headers: { Cookie: cookie, ...NAV } });
    assert.equal(page.status, 401);
    assert.match(await page.text(), /You are signed out\./);
  } finally {
    await h.close();
  }
});

test("a session ends after 12 hours idle", async () => {
  const h = await start({ basicAuth: CREDS });
  try {
    const cookie = cookieOf(await signIn(h, { user: CREDS.user, password: CREDS.password }));
    h.advance(SESSION_IDLE_MS - 1000);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } })).status, 200, "used within 12 h: kept");
    h.advance(SESSION_IDLE_MS + 1000);
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: cookie } })).status, 401, "12 h idle: ended");
    // A made-up or another boot's cookie signs nobody in.
    assert.equal((await fetch(`${h.base}/api/sessions`, { headers: { Cookie: "mandu_signin=" + "A".repeat(43) } })).status, 401);
  } finally {
    await h.close();
  }
});

test("base-path form: /mandu/... is gated and served the same way, the cookie scoped to /mandu", async () => {
  const h = await start({ basicAuth: CREDS, basePath: "/mandu" });
  try {
    const page = await fetch(`${h.base}/mandu/`, { redirect: "manual", headers: NAV });
    assert.equal(page.status, 401);
    assert.match(await page.text(), /action="\/mandu\/login"/);
    assert.equal((await fetch(`${h.base}/mandu/api/sessions`)).status, 401);
    assert.equal((await fetch(`${h.base}/mandu/api/sessions`, { headers: GOOD })).status, 200);
    const res = await signIn(h, { user: CREDS.user, password: CREDS.password, next: "/rules" }, {}, "/mandu");
    assert.equal(res.status, 303);
    assert.equal(res.headers.get("location"), "/mandu/rules");
    assert.match(res.headers.get("set-cookie") ?? "", /Path=\/mandu;/);
    const post = await fetch(`${h.base}/mandu/api/egress/approvals/egr-1/deny`, { method: "POST", headers: { ...CSRF, Cookie: cookieOf(res) } });
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
    // No gate (a test server): POST /login makes no session.
    const res = await signIn(h, { user: CREDS.user, password: CREDS.password });
    assert.equal(res.headers.get("set-cookie"), null);
  } finally {
    await h.close();
  }
});
