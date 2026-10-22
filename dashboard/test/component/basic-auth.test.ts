/**
 * basic-auth.test — E2E: the REAL dashboard entrypoint with
 * DASHBOARD_BASIC_AUTH="user:password" (dashboard.md §6.z), the mode a
 * Cloudflare-tunnel deployment ran in, and the dashboard account it now
 * moves into.
 *
 * Proves, over a real process and socket:
 *   - the pair moves into the account file once: a scrypt hash only (the
 *     password nowhere on disk), mode 0600 under the Mandu home's state/;
 *     the log says so and that the env entry can go, and never prints it;
 *   - the served app (shell, /api, the /mandu base-path mount) gets the
 *     sign-in page or a 401 without credentials, NEVER a
 *     `WWW-Authenticate` header; a Basic header with the pair still serves
 *     it; the sign-in page's form signs in and its cookie serves the API;
 *   - no admin link is printed (the account is the session);
 *   - a later start with the account there ignores another
 *     DASHBOARD_BASIC_AUTH (the account wins, the log says so);
 *   - an account file others can read: the server starts, logs a NOTICE,
 *     and signs nobody in;
 *   - a malformed value (no ':' / empty user) is a start-up REFUSAL (exit 2),
 *     never a silent no-auth server — a typo must not expose symbol originals.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:net";
import { chmodSync, existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { pollUntil, SERVER_TEST_TIMEOUT_MS, START_DEADLINE_MS, waitForPort } from "./server-up.js";
import { tmpDir } from "../unit/tmp-dir.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX = join(PKG_DIR, "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");

const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;
const PASSWORD = "pw:with:colons";

function launch(dir: string, arbSock: string, basicAuth: string): { child: ChildProcess; stderr: () => string } {
  let stderr = "";
  rmSync(join(dir, "port"), { force: true });
  const child = spawn(TSX, [SERVER_MAIN], {
    cwd: PKG_DIR,
    env: {
      ...process.env,
      MANDU_ARBITER_SOCK: arbSock,
      DASHBOARD_PORT: "0",
      DASHBOARD_HOST: "127.0.0.1",
      DASHBOARD_BASIC_AUTH: basicAuth,
      // An explicit reverse-proxy prefix: the built-in default is none (b7).
      DASHBOARD_BASE_PATH: "/mandu",
      DASHBOARD_PASSWORD: "",
      MANDU_PORT_FILE: join(dir, "port"),
      MANDU_RUNTIME_DIR: join(dir, "rt"),
      // Isolated Mandu home too: every default store resolves under it, the
      // test history in ${MANDU_HOME}/runs included (test-history.ts); none
      // may be the host's (test-organization.md §8.4). The account file
      // lands here.
      MANDU_HOME: join(dir, "home"),
      MANDU_TEST_DASHBOARD: "",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });
  return { child, stderr: () => stderr };
}

async function exited(child: ChildProcess, ms = 5000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((r) => { child.once("exit", () => r()); setTimeout(r, ms).unref(); });
}

async function stop(child: ChildProcess): Promise<void> {
  child.kill("SIGTERM");
  await exited(child);
}

async function silentArbiter(dir: string): Promise<{ sock: string; close: () => void }> {
  const sock = join(dir, "arbiter.sock");
  const arb: Server = createServer((s) => s.on("data", () => {}));
  arb.listen(sock);
  await once(arb, "listening");
  return { sock, close: () => arb.close() };
}

test("DASHBOARD_BASIC_AUTH moves into the account; the real server shows the sign-in page, never a native prompt", { timeout: 2 * SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-dashbasic-");
  const arb = await silentArbiter(dir);
  const accountFile = join(dir, "home", "state", "dashboard-account.json");
  let run = launch(dir, arb.sock, `alice:${PASSWORD}`);
  try {
    const base = `http://127.0.0.1:${await waitForPort(join(dir, "port"), run.child, run.stderr)}`;

    // The migration: a hash only, 0600, said once, never printed.
    assert.ok(existsSync(accountFile), "the account file was written");
    const text = readFileSync(accountFile, "utf8");
    assert.ok(!text.includes(PASSWORD) && !text.includes(Buffer.from(PASSWORD).toString("base64")), "no password on disk");
    assert.match(text, /"kdf": "scrypt"/);
    assert.equal(statSync(accountFile).mode & 0o777, 0o600);

    for (const path of ["/", "/mandu/", "/mandu/dev/", "/login"]) {
      const res = await fetch(`${base}${path}`, { redirect: "manual", headers: { Accept: "text/html" } });
      assert.equal(res.status, 401, `${path} without credentials`);
      assert.equal(res.headers.get("www-authenticate"), null, `${path}: no native prompt`);
      const html = await res.text();
      assert.match(html, /name="user"[\s\S]*name="password"/, `${path}: the sign-in page`);
      assert.doesNotMatch(html, /<script/i, `${path}: no script`);
    }
    for (const path of ["/api/sessions", "/mandu/api/sessions", "/mandu/api/stream"]) {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.status, 401, path);
      assert.equal(res.headers.get("www-authenticate"), null, path);
    }
    const wrong = await fetch(`${base}/api/sessions`, { headers: { Authorization: basic("alice", "pw") } });
    assert.equal(wrong.status, 401, "a prefix of the password is not the password");

    const good = { Authorization: basic("alice", PASSWORD) };
    // /api/tenants needs no arbiter round-trip (the mock arbiter is silent);
    // it proves the API is served with credentials, base-path form included.
    const api = await fetch(`${base}/mandu/api/tenants`, { headers: good });
    assert.equal(api.status, 200, "the base-path API with the Basic header");
    assert.equal(((await api.json()) as { current: string }).current, "live");
    const shell = await fetch(`${base}/mandu/`, { headers: good, redirect: "manual" });
    assert.equal(shell.status, 200, "the app shell with credentials");
    assert.match(await shell.text(), /<meta name="base-path"/, "the real shell was served, not an error page");

    // The sign-in page's form, as a browser posts it.
    const form = await fetch(`${base}/mandu/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: base, Accept: "text/html" },
      body: new URLSearchParams({ user: "alice", password: PASSWORD, next: "/scan" }).toString(),
    });
    assert.equal(form.status, 303);
    assert.equal(form.headers.get("location"), "/mandu/scan");
    const cookie = /mandu_signin=[^;]+/.exec(form.headers.get("set-cookie") ?? "")?.[0];
    assert.ok(cookie, "a sign-in cookie");
    assert.equal((await fetch(`${base}/mandu/api/tenants`, { headers: { Cookie: cookie } })).status, 200);

    await pollUntil(() => /moved into the dashboard account/.test(run.stderr()) && /sign-in: the dashboard account/.test(run.stderr()), START_DEADLINE_MS);
    assert.match(run.stderr(), /DASHBOARD_BASIC_AUTH moved into the dashboard account .*You can now remove DASHBOARD_BASIC_AUTH/);
    assert.match(run.stderr(), /sign-in: the dashboard account \(user alice\)/, "the log names the mode");
    assert.ok(!run.stderr().includes(PASSWORD), "the password is never printed");
    assert.doesNotMatch(run.stderr(), /NOTICE: the dashboard account file/, "the migration is the baseline, not a change");
    assert.doesNotMatch(run.stderr(), /login\?token=/, "no admin link is printed — the account is the session");
    await stop(run.child);

    // Started again with another pair: the account wins.
    run = launch(dir, arb.sock, "bob:another-password");
    const base2 = `http://127.0.0.1:${await waitForPort(join(dir, "port"), run.child, run.stderr)}`;
    assert.equal((await fetch(`${base2}/api/tenants`, { headers: { Authorization: basic("bob", "another-password") } })).status, 401);
    assert.equal((await fetch(`${base2}/api/tenants`, { headers: good })).status, 200);
    await pollUntil(() => /DASHBOARD_BASIC_AUTH is ignored/.test(run.stderr()), START_DEADLINE_MS);
    assert.match(run.stderr(), /DASHBOARD_BASIC_AUTH is ignored: the dashboard account is set/);
    await stop(run.child);

    // An account file others can read: nobody signs in, and the log says why.
    chmodSync(accountFile, 0o644);
    run = launch(dir, arb.sock, "");
    const base3 = `http://127.0.0.1:${await waitForPort(join(dir, "port"), run.child, run.stderr)}`;
    assert.equal((await fetch(`${base3}/api/tenants`, { headers: good })).status, 401);
    const page = await (await fetch(`${base3}/`, { headers: { Accept: "text/html" } })).text();
    assert.match(page, /cannot be used/);
    await pollUntil(() => /NOTICE: the dashboard account cannot be used/.test(run.stderr()), START_DEADLINE_MS);
    assert.match(run.stderr(), /readable or writable by others/);
  } finally {
    await stop(run.child);
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a malformed DASHBOARD_BASIC_AUTH refuses to start (exit 2) instead of serving unauthenticated", { timeout: 2 * START_DEADLINE_MS + 60_000 }, async () => {
  for (const bad of ["nocolon", ":emptyuser"]) {
    const dir = tmpDir("mandu-dashbasic-bad-");
    const arb = await silentArbiter(dir);
    const { child, stderr } = launch(dir, arb.sock, bad);
    try {
      await exited(child, START_DEADLINE_MS); // a deadline: returns at the exit
      assert.equal(child.exitCode, 2, `"${bad}": exit 2 (stderr: ${stderr()})`);
      assert.match(stderr(), /DASHBOARD_BASIC_AUTH must be "user:password"/);
      assert.ok(!existsSync(join(dir, "port")), `"${bad}": never listened`);
      assert.ok(!existsSync(join(dir, "home", "state", "dashboard-account.json")), `"${bad}": no account written`);
    } finally {
      await stop(child);
      arb.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
