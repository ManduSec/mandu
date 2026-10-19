/**
 * data-locations.test — E2E: GET /api/data-locations, the product page's
 * "Where your data lives" (on-disk-layout.md §9.2), over the REAL entrypoint
 * (server-main) started with a temporary HOME and MANDU_HOME and
 * DASHBOARD_BASIC_AUTH, the auth the tunnel deployment runs with.
 *
 * Proves over a real process and socket: the route is behind the same auth
 * as every other GET (401 without credentials); it resolves Mandu's folder
 * from the SERVER process's MANDU_HOME and HOME, the home spelled `~`; an
 * owner-only store reads `ownerOnly: true`, one opened to others false, a
 * missing one not there; a developer-only place is marked `developer`, with
 * whether it is there (dashboard.md §4.25q); and no file content is in the
 * response.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:net";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { SERVER_TEST_TIMEOUT_MS, waitForPort } from "./server-up.js";
import type { DataLocations } from "../../src/data-locations.js";
import { tmpDir } from "../unit/tmp-dir.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX = join(PKG_DIR, "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");

const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;

async function exited(child: ChildProcess, ms = 5000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((r) => { child.once("exit", () => r()); setTimeout(r, ms).unref(); });
}

test("GET /api/data-locations: behind the auth, the server's MANDU_HOME with the home as ~, owner-only per store, no contents", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-dataloc-e2e-");
  const home = join(dir, "u");
  const mandu = join(home, "mh");
  mkdirSync(join(mandu, "state"), { recursive: true });
  chmodSync(mandu, 0o700);
  chmodSync(join(mandu, "state"), 0o700);
  mkdirSync(join(mandu, "events"));
  chmodSync(join(mandu, "events"), 0o755);
  writeFileSync(join(mandu, "policy.yaml"), "# canary-content-7f3a\n", { mode: 0o600 });
  mkdirSync(join(mandu, "dev"), { mode: 0o700 }); // a developer's place, there; `runs` is left absent

  const arbSock = join(dir, "arbiter.sock");
  const arb: Server = createServer((s) => s.on("data", () => {}));
  arb.listen(arbSock);
  await once(arb, "listening");
  let stderr = "";
  const child = spawn(TSX, [SERVER_MAIN], {
    cwd: PKG_DIR,
    env: {
      ...process.env,
      HOME: home,
      MANDU_HOME: mandu,
      MANDU_ARBITER_SOCK: arbSock,
      DASHBOARD_PORT: "0",
      DASHBOARD_HOST: "127.0.0.1",
      DASHBOARD_BASIC_AUTH: "alice:pw",
      DASHBOARD_BASE_PATH: "/mandu",
      DASHBOARD_PASSWORD: "",
      MANDU_PORT_FILE: join(dir, "port"),
      MANDU_RUNTIME_DIR: join(dir, "rt"),
      MANDU_TEST_DASHBOARD: "",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });
  try {
    const base = `http://127.0.0.1:${await waitForPort(join(dir, "port"), child, () => stderr)}/mandu`;

    const anon = await fetch(`${base}/api/data-locations`);
    assert.equal(anon.status, 401, "no credentials, no locations");

    const res = await fetch(`${base}/api/data-locations`, { headers: { Authorization: basic("alice", "pw") } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /application\/json/);
    const raw = await res.text();
    assert.doesNotMatch(raw, /canary-content-7f3a/, "locations only, never a file's contents");
    assert.ok(!raw.includes(home + "/"), "every path under the home is spelled ~");
    const body = JSON.parse(raw) as DataLocations;
    assert.equal(body.home, "~/mh", "Mandu's folder from the server process's MANDU_HOME");

    const row = (name: string) => {
      const r = body.locations.find((l) => l.name === name);
      assert.ok(r, name);
      return r;
    };
    assert.deepEqual(
      { path: row("mandu-home").path, exists: row("mandu-home").exists, mode: row("mandu-home").mode, ownerOnly: row("mandu-home").ownerOnly },
      { path: "~/mh", exists: true, mode: "0700", ownerOnly: true },
    );
    assert.equal(row("state-root").ownerOnly, true);
    assert.equal(row("policy").ownerOnly, true);
    assert.deepEqual({ mode: row("events").mode, ownerOnly: row("events").ownerOnly }, { mode: "0755", ownerOnly: false });
    assert.deepEqual({ exists: row("packs").exists, ownerOnly: row("packs").ownerOnly }, { exists: false, ownerOnly: null });
    assert.equal(row("runtime-dir").where, "outside");
    assert.equal(row("runtime-dir").ownerOnly, null);
    assert.match(row("symbol-db").holds, /placeholders the AI saw/);
    assert.deepEqual({ developer: row("dev-root").developer, exists: row("dev-root").exists, path: row("dev-root").path }, { developer: true, exists: true, path: "~/mh/dev" });
    assert.deepEqual({ developer: row("runs-root").developer, exists: row("runs-root").exists }, { developer: true, exists: false });
    assert.equal(row("events").developer, false);
    assert.equal(row("runtime-dir").developer, false);
    assert.ok(raw.length < 16_384, `small (${raw.length} bytes)`);

    const post = await fetch(`${base}/api/data-locations`, { method: "POST", headers: { Authorization: basic("alice", "pw"), "X-Mandu-Control": "1" } });
    assert.notEqual(post.status, 200, "GET only");
  } finally {
    child.kill("SIGTERM");
    await exited(child);
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
