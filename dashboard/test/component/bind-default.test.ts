/**
 * bind-default.test — E2E: the REAL dashboard entrypoint's shipped network
 * defaults (dashboard.md §6, 2026-09-25):
 *   - with no DASHBOARD_HOST the server binds LOOPBACK (the launcher's stack
 *     autostart passes no host, so this default is what every first launch
 *     gets), and the start-up line says so;
 *   - with no dashboard account it FAILS CLOSED (dashboard.md §6.z): every
 *     route is 401, a page says "no account yet" and what to run, the log
 *     says so; the account's credentials serve it; a pinned
 *     DASHBOARD_ADMIN_TOKEN (the suites' seam) gets through by its link;
 *   - a non-loopback bind with no account is a start-up REFUSAL (exit 2,
 *     never listened) — the allowlist alone is not authentication, and
 *     neither DASHBOARD_PASSWORD (no longer used: a NOTICE says it is
 *     ignored) nor DASHBOARD_TRUST_FRONT=1 is an account;
 *   - the same bind WITH the account (a file, or DASHBOARD_BASIC_AUTH moved
 *     into one) comes up, and the default remote allowlist is EMPTY (no lab
 *     peer baked in).
 *
 * Each server runs with no autostarted stack, as the spawned process itself
 * (server-up.ts spawnServer), and is stopped and awaited (stopServer:
 * SIGTERM, SIGKILL after a deadline); the stand-in arbiter ends its
 * connections when it closes. A release run of this file passed every test
 * and then stayed alive until the suite's 900 s deadline: a proxy its
 * server's autostart spawned during the server's exit outlived it, still
 * connected to this file's stand-in arbiter (dashboard.md §4.8, *A start
 * under way when the dashboard exits*, 2026-10-23).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { makeAccount, writeAccount } from "../../src/account.js";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pollUntil, SERVER_TEST_TIMEOUT_MS, silentArbiter, spawnServer, START_DEADLINE_MS, stopServer, waitForExit, waitForPort } from "./server-up.js";
import { tmpDir } from "../unit/tmp-dir.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");

function launch(dir: string, arbSock: string, extra: Record<string, string>): { child: ChildProcess; stderr: () => string } {
  let stderr = "";
  const env: Record<string, string | undefined> = {
    ...process.env,
    MANDU_ARBITER_SOCK: arbSock,
    DASHBOARD_PORT: "0",
    DASHBOARD_PASSWORD: "",
    DASHBOARD_BASIC_AUTH: "",
    DASHBOARD_TRUST_FRONT: "",
    DASHBOARD_ALLOW_HOSTS: "",
    MANDU_PORT_FILE: join(dir, "port"),
    MANDU_RUNTIME_DIR: join(dir, "rt"),
    // Isolated Mandu home too: every default store resolves under it, the
    // test history in ${MANDU_HOME}/runs included (test-history.ts); none
    // may be the host's (test-organization.md §8.4).
    MANDU_HOME: join(dir, "home"),
    MANDU_TEST_DASHBOARD: "",
    // No stack: what is under test is the bind and the sign-in gate. The
    // autostart would start a test arbiter and three proxies per server, each
    // one more process to stop at the end.
    DASHBOARD_AUTOSTART: "0",
    ...extra,
  };
  // The point under test is the DEFAULT: make sure no inherited value decides it.
  delete env["DASHBOARD_HOST"];
  Object.assign(env, extra);
  const child = spawnServer(SERVER_MAIN, { cwd: PKG_DIR, env, stdio: ["ignore", "ignore", "pipe"] });
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });
  return { child, stderr: () => stderr };
}

async function withArbiter<T>(fn: (dir: string, arbSock: string) => Promise<T>): Promise<T> {
  const dir = tmpDir("mandu-dashbind-");
  const arbSock = join(dir, "arbiter.sock");
  const arb = await silentArbiter(arbSock);
  try {
    return await fn(dir, arbSock);
  } finally {
    await arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Wait for a start-up line that server-main prints AFTER the port file
 *  lands (the non-loopback notice follows registry registration): asserting
 *  on stderr right after waitUp raced it under a loaded full-suite run. */
async function waitFor(stderr: () => string, re: RegExp): Promise<string> {
  await pollUntil(() => re.test(stderr()), START_DEADLINE_MS, 50);
  return stderr();
}

/** The bound port, once published, and the "up on" line that follows it
 *  (it reaches us through a pipe, after the port file). */
async function waitUp(dir: string, child: ChildProcess, stderr: () => string): Promise<number> {
  const port = await waitForPort(join(dir, "port"), child, stderr);
  await waitFor(stderr, /\[dashboard\] up on /);
  return port;
}

test("no DASHBOARD_HOST → the server binds loopback and says so", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  await withArbiter(async (dir, arbSock) => {
    const { child, stderr } = launch(dir, arbSock, {});
    try {
      const port = await waitUp(dir, child, stderr);
      assert.match(stderr(), new RegExp(`\\[dashboard\\] up on http://127\\.0\\.0\\.1:${port}/`), "the start-up line names loopback");
      // The notice would print right after the registry line: wait for that
      // line so this absence is not checked before the notice could appear.
      assert.doesNotMatch(await waitFor(stderr, /\[dashboard\] registry/), /non-loopback bind/, "no remote-bind notice on the default");
      // No account yet: fail closed.
      const res = await fetch(`http://127.0.0.1:${port}/api/tenants`);
      assert.equal(res.status, 401, "no account: nothing is served");
      assert.match(((await res.json()) as { error: string }).error, /no account yet; run `mandu dashboard --set-password`/);
      const page = await fetch(`http://127.0.0.1:${port}/`, { headers: { Accept: "text/html" } });
      assert.equal(page.status, 401);
      assert.match(await page.text(), /No account yet\. To make one, run <code>mandu dashboard --set-password<\/code>/);
      assert.match(await waitFor(stderr, /no dashboard account yet/), /NOTICE: no dashboard account yet/);
      assert.doesNotMatch(stderr(), /login\?token=|admin link/, "no admin link is printed");
      // Made while it runs (`mandu dashboard --set-password`): served at once.
      writeAccount(join(dir, "home", "state", "dashboard-account.json"), await makeAccount("alice", "a long enough password"));
      const auth = { Authorization: `Basic ${Buffer.from("alice:a long enough password").toString("base64")}` };
      assert.equal((await fetch(`http://127.0.0.1:${port}/api/tenants`, { headers: auth })).status, 200, "served on loopback with the account");
    } finally {
      await stopServer(child);
    }
  });
});

test("DASHBOARD_HOST=0.0.0.0 with no authenticator refuses to start (exit 2, never listened)", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  await withArbiter(async (dir, arbSock) => {
    const { child, stderr } = launch(dir, arbSock, { DASHBOARD_HOST: "0.0.0.0" });
    try {
      await waitForExit(child); // a deadline: returns at the exit
      assert.equal(child.exitCode, 2, `exit 2 (stderr: ${stderr()})`);
      assert.match(stderr(), /refusing to bind 0\.0\.0\.0: a non-loopback bind needs the dashboard account/);
      assert.ok(!existsSync(join(dir, "port")), "it never listened");
    } finally {
      await stopServer(child);
    }
  });
});

for (const [label, extra] of [
  ["DASHBOARD_PASSWORD (no longer an authenticator)", { DASHBOARD_PASSWORD: "pw" }],
  ["DASHBOARD_TRUST_FRONT=1 and no account", { DASHBOARD_TRUST_FRONT: "1" }],
] as const) {
  test(`DASHBOARD_HOST=0.0.0.0 with ${label} refuses to start`, { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
    await withArbiter(async (dir, arbSock) => {
      const { child, stderr } = launch(dir, arbSock, { DASHBOARD_HOST: "0.0.0.0", ...extra });
      try {
        await waitForExit(child); // a deadline: returns at the exit
        assert.equal(child.exitCode, 2, `exit 2 (stderr: ${stderr()})`);
        assert.match(stderr(), /needs the dashboard account/);
        if ("DASHBOARD_PASSWORD" in extra) assert.match(stderr(), /NOTICE: DASHBOARD_PASSWORD is no longer used and is ignored/);
      } finally {
        await stopServer(child);
      }
    });
  });
}

test("a pinned DASHBOARD_ADMIN_TOKEN (the suites' seam) gets through the fail-closed gate by its link", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  await withArbiter(async (dir, arbSock) => {
    const { child, stderr } = launch(dir, arbSock, { DASHBOARD_ADMIN_TOKEN: "f".repeat(32) });
    try {
      const port = await waitUp(dir, child, stderr);
      const link = await fetch(`http://127.0.0.1:${port}/login?token=${"f".repeat(32)}`, { redirect: "manual" });
      assert.equal(link.status, 302);
      const cookie = (link.headers.get("set-cookie") ?? "").split(";")[0]!;
      assert.equal((await fetch(`http://127.0.0.1:${port}/api/tenants`, { headers: { Cookie: cookie } })).status, 200);
      assert.equal((await fetch(`http://127.0.0.1:${port}/api/tenants`)).status, 401, "without it, still closed");
      assert.match(await waitFor(stderr, /DASHBOARD_ADMIN_TOKEN is pinned/), /a test seam/);
    } finally {
      await stopServer(child);
    }
  });
});

for (const [label, extra, account] of [
  ["the dashboard account", {}, true],
  ['DASHBOARD_BASIC_AUTH="u:p" (moved into the account)', { DASHBOARD_BASIC_AUTH: "u:p" }, false],
] as const) {
  test(`DASHBOARD_HOST=0.0.0.0 with ${label} comes up; the default remote allowlist is empty`, { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
    await withArbiter(async (dir, arbSock) => {
      if (account) writeAccount(join(dir, "home", "state", "dashboard-account.json"), await makeAccount("alice", "a long enough password"));
      const { child, stderr } = launch(dir, arbSock, { DASHBOARD_HOST: "0.0.0.0", ...extra });
      try {
        const port = await waitUp(dir, child, stderr);
        assert.match(stderr(), new RegExp(`up on http://0\\.0\\.0\\.0:${port}/`));
        const notice = /non-loopback bind: remote clients limited to \(none — every remote client is denied; set DASHBOARD_ALLOW_HOSTS\)/;
        assert.match(await waitFor(stderr, notice), notice, "no lab peer is admitted by default");
      } finally {
        await stopServer(child);
      }
    });
  });
}
