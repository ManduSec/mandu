/**
 * dashboard-sign-in.test — the human's way to an admin session, across the
 * REAL components (policy-surface.md §2.6 "Signing in", dashboard.md §6.z;
 * dashboard src/sign-in.ts, src/server.ts signInGate; launcher
 * src/dashboard-sign-in.ts, src/dashboard-account.ts).
 *
 * A real ArbiterServer (data, human and admin sockets, `secrets` axes), a
 * real DashboardServer over a real ArbiterEventSource with its approvals on
 * the admin channel and the dashboard account file as server-main passes it,
 * the dashboard's real human-plane socket wired as server-main wires it
 * (`signInDepsFor`), the launcher's real `requestSignInLink` (what its
 * dashboard line and `mandu dashboard` call) and its real
 * `mandu dashboard --set-password` over a scripted terminal.
 *
 *   S1  no account yet: FAIL CLOSED: the held send cannot be answered (401,
 *       the row stays pending), the page says to run `mandu dashboard
 *       --set-password`, and the launcher's line says "no account yet; set
 *       one";
 *   S2  `--set-password` writes the account (a hash only); the running
 *       dashboard uses it at once and the launcher's line says "sign in with
 *       your Mandu dashboard account"; never a link, even while a launch
 *       with no wall is on the record;
 *   S3  the human signs in on the sign-in page and "Allow once" resolves the
 *       held send in the arbiter's store;
 *   S4  a registry entry naming a socket outside the human-plane directory
 *       (a planted entry) is never dialled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { AccountFile } from "../../dashboard/src/account.js";
import { serveSignInChannel, signInDepsFor, signInSockPath } from "../../dashboard/src/sign-in.js";
import { bannerDashboard, requestSignInLink } from "../../launcher/src/dashboard-sign-in.js";
import { accountPath, runSetPassword } from "../../launcher/src/dashboard-account.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const CSRF = { "X-Mandu-Control": "1" };
const EVIL = "evil.example";
const PASSWORD = "the human's own password";

test("no account: nothing is served and the launcher says to set one; set, the human signs in on the page and answers a held send", { timeout: 60_000 }, async () => {
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
  const file = accountPath({ MANDU_HOME: join(tmp, "home") });
  const dashboard = new DashboardServer({ source, approvalsArbiter, account: new AccountFile(file), log: () => {} });
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  // Wired as server-main wires it.
  const signIn = await serveSignInChannel(signInSockPath(tmp), signInDepsFor(dashboard));
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

    // S1: no account yet: fail closed, and everyone says how to make one.
    const refused = await fetch(`${base}/api/egress/approvals/${approvalId}/approve-once`, { method: "POST", headers: CSRF });
    assert.equal(refused.status, 401);
    assert.match(((await refused.json()) as { error: string }).error, /no account yet; run `mandu dashboard --set-password`/);
    assert.equal((await admin.egressApprovals("pending")).some((r) => r.id === approvalId), true, "still pending");
    const page = await fetch(`${base}/`, { headers: { Accept: "text/html" } });
    assert.equal(page.status, 401);
    assert.match(await page.text(), /No account yet\. To make one, run <code>mandu dashboard --set-password<\/code>/);
    const none = await requestSignInLink(entry, tmp);
    assert.deepEqual(none, { kind: "password", with: "no-account" });
    assert.equal(bannerDashboard(`${base}/`, none).part, `dashboard ${base}/ (no account yet; set one: mandu dashboard --set-password)`);

    // S2: `mandu dashboard --set-password`, as the person types it.
    const lines = ["alice"];
    const secrets = [PASSWORD, PASSWORD];
    const said: string[] = [];
    assert.equal(await runSetPassword({
      isTTY: true, path: file,
      askLine: async () => lines.shift() ?? null, askSecret: async () => secrets.shift() ?? null,
      out: (s) => said.push(s), err: (s) => said.push(s),
    }), 0);
    assert.ok(!readFileSync(file, "utf8").includes(PASSWORD), "a hash only on disk");
    assert.ok(!said.join("").includes(PASSWORD), "never printed");
    assert.deepEqual(await requestSignInLink(entry, tmp), { kind: "password", with: "account" }, "the running dashboard uses it at once");
    // Never a link, not even while a launch with no wall is on the record.
    const launch = await human.beginLaunch({
      pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false, sessionId: "unwalled-signin",
    });
    assert.deepEqual(await requestSignInLink(entry, tmp), { kind: "password", with: "account" });
    await human.endLaunch(String(launch.token));
    assert.equal((await fetch(`${base}/login?ticket=${"a".repeat(32)}`, { redirect: "manual" })).status, 401, "an old ticket link is the sign-in page");

    // S3: the sign-in page, then Allow once.
    const form = await fetch(`${base}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: base, Accept: "text/html" },
      body: new URLSearchParams({ user: "alice", password: PASSWORD }).toString(),
    });
    assert.equal(form.status, 303);
    const cookie = /mandu_signin=[^;]+/.exec(form.headers.get("set-cookie") ?? "")?.[0];
    assert.ok(cookie, "a sign-in cookie");
    const allowed = await fetch(`${base}/api/egress/approvals/${approvalId}/approve-once`, { method: "POST", headers: { ...CSRF, Cookie: cookie } });
    assert.equal(allowed.status, 200, await allowed.text());
    const row = (await admin.egressApprovals()).find((r) => r.id === approvalId);
    assert.equal(row?.status, "approved", "the arbiter's store has the human's answer");

    // S4: a planted entry naming a socket elsewhere is never dialled.
    const planted = await requestSignInLink({ ...entry, signInSock: socketPath }, tmp);
    assert.equal(planted.kind, "unavailable");
  } finally {
    await signIn.close();
    await dashboard.close();
    admin.close(); human.close(); gate.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
