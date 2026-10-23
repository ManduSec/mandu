/**
 * supervisor-close.test — `Supervisor.close()`, the dashboard's exit: it
 * stops every service it spawned AND refuses a spawn after it, so a start
 * still under way cannot outlive the dashboard (dashboard.md §4.8, *A start
 * under way when the dashboard exits*, 2026-10-23).
 *
 * The incident: the autostart awaits a hello probe (up to 1.5 s) before each
 * proxy's spawn. A SIGTERM inside that wait ran shutdownAll(), which found no
 * child to stop; the spawn came while the stop still waited on another
 * service, and the dashboard exited over a detached proxy in its own process
 * group that nothing stopped (a component test's process was then held open
 * by that proxy's connection until the suite's 900 s deadline).
 *
 * The wait before the spawn is held here by the bundle check (`bundleFresh`),
 * which every spawn of a definition with a bundled form awaits. Fake services
 * (node one-liners) record that they ran in a marker file.
 * Axes: none (process control only; no arbiter decision is taken).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";

import type { ServiceDefinition } from "../../../src/supervisor/supervisor.js";
import type { BundleFreshness } from "../../../src/supervisor/supervisor-defs.js";
import { isAlive, mkSup, nodeArgs, registerTmpHooks, sleep, socketDef, tmpdir, waitUntilDead } from "./supervisor-harness.js";

registerTmpHooks();

/** Writes its pid to FAKE_MARK, then listens on FAKE_SOCK. */
const MARK_SCRIPT = `
const net = require('net');
const fs = require('fs');
fs.writeFileSync(process.env.FAKE_MARK, String(process.pid));
try { fs.unlinkSync(process.env.FAKE_SOCK); } catch {}
net.createServer(() => {}).listen(process.env.FAKE_SOCK);
setInterval(() => {}, 1e9);
`;

/** A service whose every spawn first awaits the bundle check. */
function markedDef(): { def: ServiceDefinition; mark: string } {
  const dir = tmpdir();
  const sock = join(dir, "svc.sock");
  const mark = join(dir, "spawned");
  const def: ServiceDefinition = {
    label: "Fake proxy (marked)",
    command: process.execPath,
    args: nodeArgs(MARK_SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock, FAKE_MARK: mark },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
    checkoutBundle: {
      command: process.execPath, args: nodeArgs(MARK_SCRIPT), cwd: dir,
      env: {}, distDir: join(dir, "dist"), repoRoot: dir,
    },
  };
  return { def, mark };
}

/** The bundle check, held until `release()`; `reached` resolves once a spawn waits on it. */
function heldBundleCheck(): { bundleFresh: () => Promise<BundleFreshness>; reached: Promise<void>; release: () => void } {
  let onReached!: () => void;
  let release!: () => void;
  const reached = new Promise<void>((r) => { onReached = r; });
  const held = new Promise<void>((r) => { release = r; });
  return {
    reached,
    release,
    bundleFresh: async () => {
      onReached();
      await held;
      return { fresh: false, reason: "held by the test" };
    },
  };
}

test("close() while a start awaits its spawn: the start is refused, nothing is spawned, and a running service is stopped", async () => {
  const { def: arbiter } = socketDef("Arbiter");
  const { def: proxy, mark } = markedDef();
  const check = heldBundleCheck();
  const logs: string[] = [];
  const sup = mkSup({ arbiter, "anthropic-proxy": proxy }, { autoStartArbiter: false, bundleFresh: check.bundleFresh, log: (m) => logs.push(m) });
  try {
    await sup.start("arbiter");
    const arbiterPid = sup.status().find((s) => s.id === "arbiter")!.pid!;
    const starting = sup.start("anthropic-proxy");
    starting.catch(() => { /* asserted below */ });
    await check.reached;

    await sup.close();
    await waitUntilDead(arbiterPid);
    assert.ok(!isAlive(arbiterPid), "the running service is stopped");

    check.release(); // the wait ends after the stop has looked: the incident's order
    await assert.rejects(starting, /anthropic-proxy: not started: the dashboard is shutting down/);
    await sleep(300);
    assert.ok(!existsSync(mark), "the service was never spawned");
    const row = sup.status().find((s) => s.id === "anthropic-proxy")!;
    assert.equal(row.state, "stopped");
    assert.equal(row.pid, null);
    assert.ok(logs.some((l) => /anthropic-proxy: not started: the dashboard is shutting down/.test(l)), logs.join("\n"));

    await assert.rejects(sup.start("anthropic-proxy"), /shutting down/, "a start after close() is refused too");
    assert.ok(!existsSync(mark), "still never spawned");
  } finally {
    check.release();
    await sup.close();
  }
});

test("shutdownAll() (Stop services) is not final: a start under way still spawns after it, which is why the exit uses close()", async () => {
  const { def: proxy, mark } = markedDef();
  const check = heldBundleCheck();
  const sup = mkSup({ "anthropic-proxy": proxy }, { autoStartArbiter: false, bundleFresh: check.bundleFresh });
  try {
    const starting = sup.start("anthropic-proxy");
    await check.reached;
    await sup.shutdownAll();
    check.release();
    await starting;
    assert.ok(existsSync(mark), "spawned after the stop had looked");
    assert.equal(sup.status().find((s) => s.id === "anthropic-proxy")!.state, "running");
  } finally {
    check.release();
    const pid = sup.status().find((s) => s.id === "anthropic-proxy")!.pid;
    await sup.close();
    if (pid) await waitUntilDead(pid);
  }
});
