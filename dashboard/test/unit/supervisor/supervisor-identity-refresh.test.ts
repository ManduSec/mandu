/**
 * supervisor-identity-refresh.test — the status()-poll re-probe of an ADOPTED,
 * identity-less daemon (supervisor.ts maybeRefreshAdoptedIdentity) on every
 * host, darwin included:
 *
 *   - the probe is fire-and-forget, so a probe that THROWS must never become an
 *     unhandled rejection: Node 22 exits the whole dashboard on one. On darwin
 *     the /proc socket-owner walk threw ENOENT and took the dashboard down on
 *     its next poll; the chain now catches and logs.
 *   - with the REAL default probes (nothing injected) the hello-less daemon's
 *     owner is named (/proc on Linux, lsof + ps on darwin) and Replace takes
 *     over from it through the real cmdline guard.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";

import { type ServiceDefinition } from "../../../src/supervisor/supervisor.js";
import {
  SOCKET_SCRIPT,
  tmpdir,
  nodeArgs,
  mkSup,
  registerTmpHooks,
  waitUntilDead,
  isAlive,
} from "./supervisor-harness.js";

registerTmpHooks();

/** A hello-less external daemon wearing the arbiter's canonical title. */
const TITLED_DRAIN_DAEMON = `
process.title = 'mandu-arbiter';
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer((c) => c.resume());
srv.listen(sock, () => process.stdout.write('drain-daemon: listening\\n'));
setInterval(() => {}, 1e9);
`;

function listening(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ path });
    const done = (v: boolean): void => {
      try { s.destroy(); } catch { /* ignore */ }
      resolve(v);
    };
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
    s.setTimeout(1000, () => done(false));
  });
}

async function spawnDaemon(sock: string, cwd: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, nodeArgs(TITLED_DRAIN_DAEMON), {
    cwd, env: { ...process.env, FAKE_SOCK: sock }, stdio: "ignore",
  });
  const t0 = Date.now();
  while (!(await listening(sock))) {
    if (Date.now() - t0 > 8000) throw new Error("external daemon never listened");
    await new Promise((r) => setTimeout(r, 25));
  }
  return child;
}

function arbiterDef(sock: string, dir: string): ServiceDefinition {
  return {
    label: "Arbiter", command: process.execPath, args: nodeArgs(SOCKET_SCRIPT), cwd: dir,
    env: { FAKE_SOCK: sock }, ready: { kind: "socket", path: sock }, endpoint: sock,
  };
}

test("a socket-owner probe that THROWS is caught and logged: no unhandled rejection, the row stays adopted", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const external = net.createServer((c) => c.resume());
  await new Promise<void>((r) => external.listen(sock, r));
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown): void => { unhandled.push(reason); };
  process.on("unhandledRejection", onUnhandled);
  const logs: string[] = [];
  let calls = 0;
  const sup = mkSup(
    { arbiter: arbiterDef(sock, dir) },
    {
      arbiterSock: sock,
      log: (line: string) => { logs.push(line); },
      discoverSocketOwner: () => {
        calls++;
        throw new Error("ENOENT: no such file or directory, open '/proc/net/unix'");
      },
    },
  );
  try {
    await sup.start("arbiter");
    const t0 = Date.now();
    while (!logs.some((l) => /adopted-identity re-probe failed/.test(l))) {
      if (Date.now() - t0 > 8000) throw new Error(`the failed re-probe was never logged: ${JSON.stringify(logs)}`);
      sup.status(); // each poll kicks the throttled re-probe
      await new Promise((r) => setTimeout(r, 50));
    }
    await new Promise((r) => setTimeout(r, 50)); // let a stray rejection surface
    assert.equal(calls, 1, "the throttle still holds after a failure");
    assert.deepEqual(unhandled, [], "the fire-and-forget chain never rejects unhandled");
    assert.match(logs.find((l) => /re-probe failed/.test(l))!, /arbiter: adopted-identity re-probe failed: ENOENT/);
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running");
    assert.equal(st.adopted, true);
    assert.equal(st.ownerPid, undefined, "no owner is invented");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await sup.shutdownAll();
    await new Promise<void>((r) => external.close(() => r()));
  }
});

test("REAL probes on this host: a hello-less daemon's owner is named, and replace() takes over through the real cmdline guard", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const external = await spawnDaemon(sock, dir);
  const externalPid = external.pid!;
  // Nothing injected: discoverUnixSocketOwner + procCmdlineOf are the real ones.
  const sup = mkSup({ arbiter: arbiterDef(sock, dir) }, { arbiterSock: sock });
  try {
    await sup.start("arbiter");
    const t0 = Date.now();
    let st = sup.status().find((s) => s.id === "arbiter")!;
    while (!st.ownerPid) {
      if (Date.now() - t0 > 10_000) throw new Error("the socket owner was never named on this host");
      await new Promise((r) => setTimeout(r, 50));
      st = sup.status().find((s) => s.id === "arbiter")!;
    }
    assert.equal(st.ownerPid, externalPid, "the listener's real pid");
    assert.match(st.ownerCmdline ?? "", /mandu-arbiter/, "…with its command line (the canonical title)");
    assert.equal(st.identity, null, "no identity is invented");

    await sup.replace("arbiter");
    await waitUntilDead(externalPid);
    assert.equal(isAlive(externalPid), false, "the verified owner was stopped");
    const after = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(after.state, "running");
    assert.equal(after.adopted, false, "the replacement is ours");
  } finally {
    await sup.shutdownAll();
    try { external.kill("SIGKILL"); } catch { /* already gone */ }
    await waitUntilDead(externalPid).catch(() => {});
  }
});
