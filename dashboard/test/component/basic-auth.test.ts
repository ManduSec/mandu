/**
 * basic-auth.test — E2E: the REAL dashboard entrypoint with
 * DASHBOARD_BASIC_AUTH="user:password" (dashboard.md §6.z), the mode
 * a Cloudflare-tunnel deployment runs in.
 *
 * Proves, over a real process and socket, what the unit suite proves in-memory:
 *   - the served app (shell, /api, the /mandu base-path mount) is 401 +
 *     `WWW-Authenticate: Basic` without credentials and 200 with them;
 *   - the start-up log names the mode and prints NO admin link (the
 *     credentials are the admin session; a link in a headless log would be
 *     same-uid readable);
 *   - a malformed value (no ':' / empty user) is a start-up REFUSAL (exit 2),
 *     never a silent no-auth server — a typo must not expose symbol originals.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:net";
import { existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { pollUntil, SERVER_TEST_TIMEOUT_MS, START_DEADLINE_MS, waitForPort } from "./server-up.js";
import { tmpDir } from "../unit/tmp-dir.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX = join(PKG_DIR, "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");

const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;

function launch(dir: string, arbSock: string, basicAuth: string): { child: ChildProcess; stderr: () => string } {
  let stderr = "";
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
      // may be the host's (test-organization.md §8.4).
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

test("DASHBOARD_BASIC_AUTH gates the real server: 401 challenge without, 200 with; no admin link printed", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-dashbasic-");
  const arbSock = join(dir, "arbiter.sock");
  const arb: Server = createServer((s) => s.on("data", () => {}));
  arb.listen(arbSock);
  await once(arb, "listening");
  const { child, stderr } = launch(dir, arbSock, "alice:pw:with:colons");
  try {
    const base = `http://127.0.0.1:${await waitForPort(join(dir, "port"), child, stderr)}`;

    for (const path of ["/", "/mandu/", "/api/sessions", "/mandu/api/sessions", "/login"]) {
      const res = await fetch(`${base}${path}`, { redirect: "manual" });
      assert.equal(res.status, 401, `${path} without credentials`);
      assert.match(res.headers.get("www-authenticate") ?? "", /^Basic realm=/, `${path} challenge`);
    }
    const wrong = await fetch(`${base}/api/sessions`, { headers: { Authorization: basic("alice", "pw") } });
    assert.equal(wrong.status, 401, "a prefix of the password is not the password");

    const good = { Authorization: basic("alice", "pw:with:colons") };
    // /api/tenants needs no arbiter round-trip (the mock arbiter is silent);
    // it proves the API is served with credentials, base-path form included.
    const api = await fetch(`${base}/mandu/api/tenants`, { headers: good });
    assert.equal(api.status, 200, "the base-path API with credentials");
    assert.equal(((await api.json()) as { current: string }).current, "live");
    const shell = await fetch(`${base}/mandu/`, { headers: good, redirect: "manual" });
    assert.equal(shell.status, 200, "the app shell with credentials");
    assert.match(await shell.text(), /<meta name="base-path"/, "the real shell was served, not an error page");

    // Printed right after the port file lands, but it reaches us through a
    // pipe: wait for it (a deadline, not a delay) rather than race it.
    await pollUntil(() => /HTTP Basic auth enabled/.test(stderr()), START_DEADLINE_MS);
    assert.match(stderr(), /HTTP Basic auth enabled \(user alice\)/, "the log names the mode");
    assert.doesNotMatch(stderr(), /login\?token=/, "no admin link is printed — the credentials are the session");
  } finally {
    child.kill("SIGTERM");
    await exited(child);
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a malformed DASHBOARD_BASIC_AUTH refuses to start (exit 2) instead of serving unauthenticated", { timeout: 2 * START_DEADLINE_MS + 60_000 }, async () => {
  for (const bad of ["nocolon", ":emptyuser"]) {
    const dir = tmpDir("mandu-dashbasic-bad-");
    const arbSock = join(dir, "arbiter.sock");
    const arb: Server = createServer((s) => s.on("data", () => {}));
    arb.listen(arbSock);
    await once(arb, "listening");
    const { child, stderr } = launch(dir, arbSock, bad);
    try {
      await exited(child, START_DEADLINE_MS); // a deadline: returns at the exit
      assert.equal(child.exitCode, 2, `"${bad}": exit 2 (stderr: ${stderr()})`);
      assert.match(stderr(), /DASHBOARD_BASIC_AUTH must be "user:password"/);
      assert.ok(!existsSync(join(dir, "port")), `"${bad}": never listened`);
    } finally {
      child.kill("SIGTERM");
      await exited(child);
      arb.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
