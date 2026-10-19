/**
 * dashboard-sign-in.test — the human's way to an admin session, across the
 * REAL components (policy-surface.md §2.6 "Signing in"; dashboard
 * src/sign-in.ts; launcher src/dashboard-sign-in.ts).
 *
 * A real ArbiterServer (data, human and admin sockets, `secrets` axes), a
 * real DashboardServer over a real ArbiterEventSource with its approvals on
 * the admin channel, the dashboard's real sign-in socket in the human-plane
 * directory wired as server-main wires it (`signInDepsFor`), and the
 * launcher's real `requestSignInLink`, which is what its dashboard line and
 * `mandu dashboard` call.
 *
 *   S1  before signing in, a held send cannot be answered from the browser:
 *       403 with the sentence that says what to run, the row stays pending;
 *   S2  the launcher gets a one-time link over the sign-in socket; opening it
 *       earns the admin session, and "Allow once" resolves the held send in
 *       the arbiter's store;
 *   S3  the link is spent: a second open (browser history, scrollback) and a
 *       guessed ticket earn nothing;
 *   S4  while a launch whose agent can reach the human-plane directory is on
 *       the arbiter's record, no link is handed out, and the refusal names
 *       the launch; when it ends, links come back;
 *       The same for a launch on a SECOND arbiter whose human socket
 *       shares the directory (the test tenant's shape);
 *   S5  a registry entry naming a sign-in socket outside the human-plane
 *       directory (a planted entry) is never dialled.
 *
 * Under the real guard, that the agent's world cannot connect to the sign-in
 * socket at all is tests/sandbox/dashboard-sign-in-wall.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, ADMIN_SESSION_REQUIRED, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { serveSignInChannel, signInDepsFor, signInSockPath } from "../../dashboard/src/sign-in.js";
import { requestSignInLink } from "../../launcher/src/dashboard-sign-in.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const CSRF = { "X-Mandu-Control": "1" };
const EVIL = "evil.example";

test("the human signs in with a one-time link from the human-plane socket and answers a held send; the agent's position gets none", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-signin-stack-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp); // <tmp>/human/h.sock: the runtime base is <tmp>
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const gate = new ArbiterClient(socketPath); await gate.connect();

  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (id, approve, scope) => admin.resolveEgressApproval(id, approve, scope),
  };
  const source = new ArbiterEventSource({ socketPath, humanSocketPath: humanPath });
  const dashboard = new DashboardServer({ source, approvalsArbiter, log: () => {} });
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  // A second arbiter whose human socket shares the directory (the test
  // tenant's, or a pinned one): a launch records its exposure with its own
  // arbiter only, so the dashboard must ask every one of them.
  const second = new ArbiterServer({
    socketPath: join(tmp, "second.sock"), humanSocketPath: join(tmp, "human", "second.sock"),
    dbPath: join(tmp, "second.sqlite"), eventDir: join(tmp, "events-second"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await second.listen();
  const secondHuman = new ArbiterClient(join(tmp, "human", "second.sock")); await secondHuman.connect();
  // A dead arbiter's leftover socket file is skipped, not a refusal.
  writeFileSync(join(tmp, "human", "dead.sock"), "");
  // Wired as server-main wires it.
  const signIn = await serveSignInChannel(signInSockPath(tmp), signInDepsFor(dashboard, source, join(tmp, "human")));
  const entry = { host: "127.0.0.1", port, signInSock: signIn.path };

  try {
    // A held send: a registered secret on its way to an unbound host.
    const env = join(tmp, ".env");
    writeFileSync(env, "API_KEY=sk-signin-stack-canary-0001\n");
    const reg = await gate.registerSecret({ path: env, sessionKey: "s-signin" });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const deny = await gate.desymbolizationDecision({ symbol: reg.symbol!, boundary: "network", destination: EVIL, sessionKey: "s-signin" });
    assert.equal(deny.allow, false);
    const approvalId = (deny as { approvalId?: string }).approvalId;
    assert.ok(approvalId, `the send is held for the human: ${JSON.stringify(deny)}`);

    // S1: no session, no answer, and the refusal says what to run.
    const refused = await fetch(`${base}/api/egress/approvals/${approvalId}/approve-once`, { method: "POST", headers: CSRF });
    assert.equal(refused.status, 403);
    const body = (await refused.json()) as { error: string };
    assert.equal(body.error, ADMIN_SESSION_REQUIRED);
    assert.match(body.error, /run `mandu dashboard` in your own terminal/);
    assert.equal((await admin.egressApprovals("pending")).some((r) => r.id === approvalId), true, "still pending");

    // S2: the launcher's link, opened once, is the admin session.
    const got = await requestSignInLink(entry, tmp);
    assert.equal(got.kind, "link", JSON.stringify(got));
    const link = (got as { url: string }).url;
    assert.match(link, new RegExp(`^${base}/login\\?ticket=[0-9a-f]{32}$`));
    const opened = await fetch(link, { redirect: "manual" });
    assert.equal(opened.status, 302);
    const cookie = (opened.headers.get("set-cookie") ?? "").split(";")[0]!;
    assert.match(cookie, /^mandu_session=[0-9a-f]{64}$/);
    const allowed = await fetch(`${base}/api/egress/approvals/${approvalId}/approve-once`, { method: "POST", headers: { ...CSRF, Cookie: cookie } });
    assert.equal(allowed.status, 200, await allowed.text());
    const row = (await admin.egressApprovals()).find((r) => r.id === approvalId);
    assert.equal(row?.status, "approved", "the arbiter's store has the human's answer");

    // S3: spent, and a guess is nothing.
    const again = await fetch(link, { redirect: "manual" });
    assert.equal(again.status, 403);
    assert.equal(again.headers.get("set-cookie"), null);
    const guess = await fetch(`${base}/login?ticket=${"a".repeat(32)}`, { redirect: "manual" });
    assert.equal(guess.status, 403);

    // S4: a launch with no wall on the record → no link, the launch named.
    const launch = await human.beginLaunch({
      pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false, sessionId: "unwalled-signin",
    });
    const blocked = await requestSignInLink(entry, tmp);
    assert.equal(blocked.kind, "refused", JSON.stringify(blocked));
    assert.match((blocked as { why: string }).why, new RegExp(`pid ${process.pid} \\(session unwalled-signin\\)`));
    await human.endLaunch(String(launch.token));
    const back = await requestSignInLink(entry, tmp);
    assert.equal(back.kind, "link", `links come back when it ends: ${JSON.stringify(back)}`);
    // The same on the second arbiter: its launch is not on the first's record.
    const other = await secondHuman.beginLaunch({
      pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false, sessionId: "unwalled-second",
    });
    const blocked2 = await requestSignInLink(entry, tmp);
    assert.equal(blocked2.kind, "refused", JSON.stringify(blocked2));
    assert.match((blocked2 as { why: string }).why, /session unwalled-second/);
    await secondHuman.endLaunch(String(other.token));
    assert.equal((await requestSignInLink(entry, tmp)).kind, "link");

    // S5: a planted entry naming a socket elsewhere is never dialled.
    const planted = await requestSignInLink({ ...entry, signInSock: socketPath }, tmp);
    assert.equal(planted.kind, "unavailable");
  } finally {
    await signIn.close();
    await dashboard.close();
    admin.close(); human.close(); gate.close(); secondHuman.close();
    await second.close().catch(() => {});
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
