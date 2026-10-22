/**
 * dashboard-account-sign-in.test — the Mandu dashboard account's sign-in
 * page across the REAL components (dashboard.md §6.z; dashboard
 * src/server.ts signInGate, src/account.ts; launcher
 * src/dashboard-account.ts).
 *
 * A real ArbiterServer (`secrets` axes) holding a registered secret and a
 * session whose events carry its value; the account written by the
 * LAUNCHER's `--set-password` writer into a scratch Mandu home; a real
 * DashboardServer reading that file over a real ArbiterEventSource; the
 * dashboard's real sign-in socket.
 *
 *   A1  a SEPARATE process on this host (the position of a program the
 *       agent runs) walks every read the dashboard lists, the developer
 *       view, the stream and a mutation, with every header it can forge (the
 *       CSRF header, Sec-Fetch-Site, made-up session cookies, a wrong Basic
 *       header): every answer is 401 or 429 and none carries the value; the
 *       sign-in socket gives no one-time link (the account is the way in);
 *   A2  a browser-like flow: GET / is the sign-in page (no app data: not the
 *       session, not the value, no script, no WWW-Authenticate); a wrong
 *       password is 401 with no cookie; the right one sets the cookie, and
 *       with it /api/home answers 200 and the events read with the CSRF
 *       header carries the value; Sign out ends it: the same cookie is 401.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { AccountFile } from "../../dashboard/src/account.js";
import { serveSignInChannel, signInDepsFor, signInSockPath } from "../../dashboard/src/sign-in.js";
import { allSamples } from "../../dashboard/test/unit/read-route-samples.js";
import { makeAccount, writeAccount, accountPath } from "../../launcher/src/dashboard-account.js";
import { requestSignInLink } from "../../launcher/src/dashboard-sign-in.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const node = async (args: string[]): Promise<{ status: number; stdout: string; stderr: string }> => {
  try {
    const r = await promisify(execFile)(process.execPath, args, { encoding: "utf8", timeout: 100_000, maxBuffer: 16 << 20 });
    return { status: 0, stdout: r.stdout, stderr: r.stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { status: typeof e.code === "number" ? e.code : 1, stdout: e.stdout ?? "", stderr: e.stderr ?? String(err) };
  }
};

const CANARY = "sk-account-gate-stack-canary-5e1d";
const SESSION = "1791200000-778";
const USER = "alice";
const PASSWORD = "the human's own password";

const CRAWLER = `
const [base, canary, pathsJson] = process.argv.slice(1);
const basic = "Basic " + Buffer.from("alice:guess-" + Math.random()).toString("base64");
const forged = [{}, { "X-Mandu-Control": "1" }, { "Sec-Fetch-Site": "same-origin", Accept: "text/html" },
  { "X-Mandu-Control": "1", Cookie: "mandu_signin=" + "A".repeat(43) + "; mandu_session=" + "0".repeat(64) },
  { Authorization: basic, "X-Mandu-Control": "1" }];
const out = [];
for (const path of JSON.parse(pathsJson)) {
  for (const headers of forged) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 1500);
    let status = 0, body = "";
    try {
      const res = await fetch(base + path, { headers, signal: ac.signal });
      status = res.status;
      body = await res.text();
    } catch {}
    clearTimeout(timer);
    out.push({ path, headers: Object.keys(headers).join("+") || "none", status, leak: body.includes(canary) });
  }
}
const post = await fetch(base + "/api/egress/approvals/x/approve", { method: "POST", headers: { "X-Mandu-Control": "1" } });
out.push({ path: "POST approve", headers: "csrf", status: post.status, leak: (await post.text()).includes(canary) });
console.log(JSON.stringify(out));
`;

test("the dashboard account: a same-host process gets nothing; the human signs in on the page, reads the value, and signs out", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-account-stack-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await server.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const source = new ArbiterEventSource({ socketPath, humanSocketPath: humanPath });
  // The account as `mandu dashboard --set-password` writes it, where the
  // path table puts it under this Mandu home.
  const file = accountPath({ MANDU_HOME: join(tmp, "home") });
  writeAccount(file, await makeAccount(USER, PASSWORD));
  const logs: string[] = [];
  const dashboard = new DashboardServer({ source, account: new AccountFile(file), log: (m) => logs.push(m) });
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const signIn = await serveSignInChannel(signInSockPath(tmp), signInDepsFor(dashboard));
  try {
    const env = join(tmp, ".env");
    writeFileSync(env, `API_KEY=${CANARY}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const sym = String(reg.symbol);
    assert.match(sym, /^\$MDU:/, JSON.stringify(reg));
    const now = (): string => new Date().toISOString();
    const dual = (symbolized: string, original: string) => ({ symbolized, original, differs: true, symbols: [{ name: sym, tool: "Read", field: null, origin: env, value: original, confidentiality: "no-model" }] });
    await human.emit({ id: "ag-call", sessionId: SESSION, ts: now(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", input: { symbolized: "Read .env", original: null, differs: false, symbols: [] } } as never);
    await human.emit({ id: "ag-result", sessionId: SESSION, ts: now(), kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", callId: "c1", output: dual(sym, `API_KEY=${CANARY}`) } as never);
    assert.ok(JSON.stringify(await source.readEvents(SESSION)).includes(CANARY), "the store holds the value (what there is to leak)");

    // A1: a separate process, every listed read and more, every forgeable header.
    const paths = [...allSamples(SESSION).map((s) => s.path), "/", "/dev/", "/dev/sessions", "/login", "/api/stream", `/api/sessions/${SESSION}/stream`];
    const run = await node(["--input-type=module", "-e", CRAWLER, base, CANARY, JSON.stringify(paths)]);
    assert.equal(run.status, 0, run.stderr);
    const results = JSON.parse(run.stdout) as Array<{ path: string; headers: string; status: number; leak: boolean }>;
    assert.deepEqual(results.filter((r) => r.leak), [], "no answer carried the value");
    assert.deepEqual(results.filter((r) => r.status !== 401 && r.status !== 429), [], "every answer was the gate's (401, or 429 once the forged Basic headers locked it)");
    // The crawler's wrong Basic headers locked sign-in for the whole
    // dashboard (the throttle is global): wait it out as a person would.
    assert.ok(logs.some((l) => /sign-in locked for 30 s/.test(l)), "the guessing was throttled and logged");
    assert.ok(!logs.some((l) => l.includes(CANARY) || l.includes(PASSWORD)), "the log holds no value and no password");
    // The account is the way in: the sign-in socket gives no one-time link.
    const link = await requestSignInLink({ host: "127.0.0.1", port, signInSock: signIn.path }, tmp);
    assert.deepEqual(link, { kind: "password", with: "account" });

    // The test's own clock cannot move the server's: build a second
    // dashboard on the same file and store for the browser flow (the lock
    // above belongs to the first one, as a lock belongs to a process).
    const fresh = new DashboardServer({ source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }), account: new AccountFile(file), log: () => {} });
    const freshPort = await fresh.listen(0);
    const b = `http://127.0.0.1:${freshPort}`;
    try {
      // A2: GET / is the sign-in page, with nothing of the app.
      const page = await fetch(`${b}/`, { headers: { Accept: "text/html" } });
      assert.equal(page.status, 401);
      assert.equal(page.headers.get("www-authenticate"), null, "no native prompt");
      const html = await page.text();
      assert.match(html, /name="user"[\s\S]*name="password"/);
      for (const bad of [CANARY, SESSION, sym, "<script", "home.js"]) assert.ok(!html.includes(bad), `the sign-in page holds no ${bad}`);

      const form = (password: string) => fetch(`${b}/login`, {
        method: "POST", redirect: "manual",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: b, Accept: "text/html" },
        body: new URLSearchParams({ user: USER, password, next: `/agents/${SESSION}` }).toString(),
      });
      const wrong = await form("not it");
      assert.equal(wrong.status, 401);
      assert.equal(wrong.headers.get("set-cookie"), null, "a wrong password sets no cookie");
      assert.match(await wrong.text(), /Wrong username or password\./);

      const right = await form(PASSWORD);
      assert.equal(right.status, 303);
      assert.equal(right.headers.get("location"), `/agents/${SESSION}`);
      const cookie = /mandu_signin=[^;]+/.exec(right.headers.get("set-cookie") ?? "")?.[0];
      assert.ok(cookie, "a sign-in cookie");
      assert.match(right.headers.get("set-cookie") ?? "", /HttpOnly; SameSite=Strict/);

      const home = await fetch(`${b}/api/home`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } });
      assert.equal(home.status, 200);
      assert.equal(((await home.json()) as { signIn?: { signOut: boolean } }).signIn?.signOut, true, "Settings offers Sign out");
      const events = await (await fetch(`${b}/api/events?session=${SESSION}`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } })).text();
      assert.ok(events.includes(CANARY), "signed in, the human sees the real value");
      assert.match(events, /"valuesShown":true/);

      const out = await fetch(`${b}/logout`, { method: "POST", redirect: "manual", headers: { Cookie: cookie, Origin: b } });
      assert.equal(out.status, 303);
      const after = await fetch(`${b}/api/events?session=${SESSION}`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } });
      assert.equal(after.status, 401, "signed out: the old cookie is refused");
      assert.ok(!(await after.text()).includes(CANARY));
    } finally {
      await fresh.close();
    }
  } finally {
    await signIn.close();
    gate.close();
    human.close();
    await dashboard.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
