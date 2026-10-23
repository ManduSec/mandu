/**
 * runtime-fallback.test — E2E: the REAL dashboard entrypoint and the private
 * /tmp fallback runtime base (runtime-instances.md §3b).
 *
 * With no MANDU_RUNTIME_DIR, no XDG_RUNTIME_DIR and a TMPDIR too long for an
 * arbiter instance socket (the macOS per-user /var/folders/…/T/ shape), the
 * dashboard's runtime base is <root>/mandu-<uid>:
 *   - absent → created 0700, and the dashboard registers itself inside it;
 *   - present but shared (0755) → the dashboard refuses to start (exit 1,
 *     never listened, nothing written there): a dir another user made first
 *     could hold an impostor `current` arbiter it would otherwise dial.
 * The fallback root is the test hook MANDU_RUNTIME_FALLBACK_ROOT, so the
 * host's real /tmp/mandu-<uid> is never touched.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pollUntil, SERVER_TEST_TIMEOUT_MS, silentArbiter, spawnServer, START_DEADLINE_MS, stopServer, waitForExit, waitForPort } from "./server-up.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");
const UID = process.getuid?.() ?? 0;

interface Rig {
  root: string;
  base: string;
  arbSock: string;
  arb: { close: () => Promise<void> };
  cleanup: () => Promise<void>;
}

async function rig(): Promise<Rig> {
  const root = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-dfb-")));
  mkdirSync(join(root, "T".repeat(70))); // the long TMPDIR (tsx caches under it)
  const arbSock = join(root, "arbiter.sock"); // a stand-in arbiter, pinned explicitly
  const arb = await silentArbiter(arbSock);
  return {
    root, base: join(root, `mandu-${UID}`), arbSock, arb,
    cleanup: async () => { await arb.close(); rmSync(root, { recursive: true, force: true }); },
  };
}

function launch(r: Rig): { child: ChildProcess; stderr: () => string } {
  let stderr = "";
  const env: Record<string, string | undefined> = {
    ...process.env,
    TMPDIR: join(r.root, "T".repeat(70)),
    MANDU_RUNTIME_FALLBACK_ROOT: r.root,
    MANDU_ARBITER_SOCK: r.arbSock,
    DASHBOARD_CONTROL: "0", // no supervisor: this is about the dashboard's own use of the base
    DASHBOARD_PORT: "0",
    MANDU_PORT_FILE: join(r.root, "port"),
    DASHBOARD_PASSWORD: "", DASHBOARD_BASIC_AUTH: "", DASHBOARD_TRUST_FRONT: "", DASHBOARD_ALLOW_HOSTS: "",
    MANDU_TEST_DASHBOARD: "",
  };
  delete env["MANDU_RUNTIME_DIR"];
  delete env["XDG_RUNTIME_DIR"];
  delete env["DASHBOARD_HOST"];
  const child = spawnServer(SERVER_MAIN, { cwd: PKG_DIR, env, stdio: ["ignore", "ignore", "pipe"] });
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });
  return { child, stderr: () => stderr };
}

test("absent fallback: created 0700 and the dashboard registers inside it", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const r = await rig();
  const { child, stderr } = launch(r);
  try {
    await waitForPort(join(r.root, "port"), child, stderr);
    assert.ok(await pollUntil(() => existsSync(join(r.base, "dashboards")) && readdirSync(join(r.base, "dashboards")).length > 0, START_DEADLINE_MS),
      `registered under the fallback (stderr: ${stderr()})`);
    const registryDir = join(r.base, "dashboards");
    const manifest = JSON.parse(readFileSync(join(registryDir, readdirSync(registryDir)[0]!), "utf8")) as { pid: number; signInSock?: string };
    assert.equal(manifest.signInSock, join(r.base, "human", `dashboard-${manifest.pid}.sock`), "the sign-in channel shares the fallback runtime base");
    assert.ok(statSync(manifest.signInSock!).isSocket(), "the registry advertises a served sign-in socket");
    assert.equal(statSync(r.base).mode & 0o777, 0o700, "created private");
    assert.equal(existsSync(join(r.root, "T".repeat(70), "mandu")), false, "nothing under the long TMPDIR");
  } finally {
    await stopServer(child);
    await r.cleanup();
  }
});

test("a SHARED (0755) fallback: the dashboard refuses to start — exit 1, never listened, nothing written there", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const r = await rig();
  mkdirSync(r.base);
  chmodSync(r.base, 0o755);
  const { child, stderr } = launch(r);
  try {
    await waitForExit(child); // a deadline: returns at the exit
    assert.equal(child.exitCode, 1, `exit 1 (stderr: ${stderr()})`);
    assert.match(stderr(), /\[dashboard\] fatal: the Mandu runtime dir .*mandu-\d+ is shared \(mode 0755/);
    assert.equal(existsSync(join(r.root, "port")), false, "it never listened");
    assert.deepEqual(readdirSync(r.base), [], "no registry entry in a dir it does not trust");
  } finally {
    await stopServer(child);
    await r.cleanup();
  }
});
