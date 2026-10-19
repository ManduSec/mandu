/**
 * installed-spawn — the packaging.md §5 installed-mode integration proof: the
 * REAL startContextProxy, driven through Layout.installed(), must spawn the
 * anthropic-proxy from launcher/dist/*.mjs (not tsx-from-src), have it connect
 * to the bundled arbiter via MANDU_ARBITER_CLIENT_MODULE, and publish a
 * matching identity. This closes the loop bundle-smoke leaves open: resolver
 * spec → real service fn → running bundle. Dev-mode spawns are covered by the
 * existing golden-path e2e.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Layout } from "../../src/services/layout.js";
import { realDeps } from "../../src/services/primitives.js";
import { startContextProxy } from "../../src/services/context-proxy.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";
import { waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); the wiring it proves is axis-independent

const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

let tmp: string;
let DIST: string; // <tmp>/dist — a PRIVATE build dir so parallel test files don't race launcher/dist
let arbiter: ChildProcess | undefined;
let sock: string;

before(async () => {
  tmp = mkdtempSync(join(tmpdir(), "mandu-installed-spawn-"));
  DIST = join(tmp, "dist");
  // Build from HEAD into the private dir so the installed spawn can't drift from
  // source AND parallel test files can't race the shared launcher/dist.
  const r = spawnSync("node", [join(PKG_ROOT, "scripts", "build-bundle.mjs"), `--outdir=${DIST}`], { cwd: PKG_ROOT, encoding: "utf8" });
  assert.equal(r.status, 0, `build-bundle failed:\n${r.stdout}\n${r.stderr}`);

  sock = join(tmp, "arb.sock");
  // The BUNDLED arbiter as the daemon (installed-mode all the way down).
  arbiter = spawn("node", ["--no-warnings=ExperimentalWarning", join(DIST, "arbiter.mjs")], {
    env: { ...process.env, MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "rt") },
    stdio: "ignore",
  });
  await waitForPaths(sock, { what: "the bundled arbiter", child: arbiter });
});

after(() => {
  if (arbiter?.pid) { try { process.kill(arbiter.pid, "SIGTERM"); } catch { /* gone */ } }
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test("installed mode: startContextProxy spawns the BUNDLED anthropic-proxy and it identifies correctly", async () => {
  // Port 0: the bundled proxy binds a kernel-assigned port and publishes it
  // through the port file (MANDU_PORT_FILE), so no port is picked here and
  // then raced by a suite running alongside (test-organization.md §8.4).
  const plan = {
    target: "claude",
    proxy: { host: "127.0.0.1", port: 0 },
    openaiProxy: { host: "127.0.0.1", port: 0 },
    arbiterSock: sock,
    scopeId: "installed-spawn-test",
    viewMap: [],
  } as unknown as LaunchPlan;

  // pkgRoot = tmp, whose dist/ holds the freshly-built bundles (private build dir).
  const layout = Layout.installed(tmp);
  assert.equal(layout.mode, "installed");

  const scopeRunDir = join(tmp, "run");
  mkdirSync(scopeRunDir, { recursive: true });
  const res = await startContextProxy(plan, layout, scopeRunDir, realDeps);
  try {
    // The launcher adopted the port the bundled proxy published.
    const portFile = join(scopeRunDir, "anthropic-proxy.port");
    assert.ok(existsSync(portFile), "the bundled proxy published its port file");
    assert.equal(res.port, Number(readFileSync(portFile, "utf8").trim()));
    assert.ok(res.port > 0, "a kernel-assigned port");
    // It came up AND published an identity matching this launch → the bundled
    // proxy loaded the bundled arbiter-client and reached the bundled arbiter.
    const id = await realDeps.probeIdentity(res.host, res.port);
    assert.ok(id, "bundled proxy answered /_mandu/identity");
    assert.equal(id!.mandu, true);
    assert.equal(id!.service, "anthropic-proxy");
    assert.equal(id!.arbiterSock, sock);
  } finally {
    res.stop();
  }
});
