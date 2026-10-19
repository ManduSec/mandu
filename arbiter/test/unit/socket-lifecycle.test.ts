/**
 * socket-lifecycle.test — the arbiter must not stomp another arbiter's socket.
 *
 * Mandu-new test (no reference origin). Two failure modes were observed live
 * when several arbiters shared one socket path (a dashboard restart + leftover
 * instances):
 *   1. START stomp: a new arbiter blindly `unlinkSync`'d the path and rebound,
 *      orphaning the arbiter that was actually serving there (clients split).
 *   2. DEATH stomp: a dying/old arbiter's close() `unlinkSync`'d the path even
 *      after a SUCCESSOR had rebound it — deleting the live arbiter's socket file
 *      so every client got `connect ENOENT`.
 *
 * The contract: listen() REFUSES when a live arbiter already owns the path, and
 * close() only removes the socket file if it is STILL the inode we bound.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { createDefaultPolicyEngine } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** Resolve once a connect to `path` is accepted (true) or refused (false). */
function probeLive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ path });
    let settled = false;
    const done = (v: boolean): void => {
      if (settled) return;
      settled = true;
      try { s.destroy(); } catch { /* ignore */ }
      resolve(v);
    };
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
    s.setTimeout(1000, () => done(false));
  });
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
async function connectable(path: string): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (await probeLive(path)) return;
    await sleep(20);
  }
  throw new Error(`socket ${path} never became connectable`);
}

function mkServer(socketPath: string, workdir: string): ArbiterServer {
  return new ArbiterServer({
    socketPath,
    dbPath: join(workdir, `symbols-${Math.random().toString(36).slice(2)}.db`),
    eventDir: join(workdir, "events"),
    policy: createDefaultPolicyEngine({}),
    log: () => {},
  });
}

test("listen() REFUSES when a live arbiter already owns the socket (no clobber)", async () => {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-socklife-"));
  const socketPath = join(workdir, "arbiter.sock");
  const a = mkServer(socketPath, workdir);
  await a.listen();
  const inodeA = statSync(socketPath).ino;

  const b = mkServer(socketPath, workdir);
  await assert.rejects(
    () => b.listen(),
    /already listening|already.*arbiter|refus/i,
    "a second arbiter must refuse to take over a live socket",
  );

  // The original arbiter's socket is UNTOUCHED (same inode, still connectable).
  assert.equal(statSync(socketPath).ino, inodeA, "the live socket inode is unchanged");
  await assert.doesNotReject(
    () =>
      new Promise<void>((resolve, reject) => {
        const s = net.connect({ path: socketPath });
        s.once("connect", () => {
          s.destroy();
          resolve();
        });
        s.once("error", reject);
      }),
    "the live arbiter is still reachable after the refused takeover",
  );

  await a.close();
  rmSync(workdir, { recursive: true, force: true });
});

test("listen() reclaims a STALE socket left by a CRASHED arbiter (no live listener)", async () => {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-socklife-"));
  const socketPath = join(workdir, "arbiter.sock");
  // A child binds the socket, prints READY, then idles. SIGKILL leaves a real
  // stale socket FILE (no graceful unlink) — exactly what a crashed arbiter
  // leaves behind. The next arbiter must reclaim it, or it could never restart.
  const child = spawn(process.execPath, [
    "-e",
    `const net=require('net');const s=net.createServer(()=>{});` +
      `s.listen(${JSON.stringify(socketPath)},()=>process.stdout.write('READY\\n'));` +
      `setInterval(()=>{},1e9);`,
  ]);
  await new Promise<void>((resolve) => child.stdout!.on("data", (b: Buffer) => {
    if (b.toString().includes("READY")) resolve();
  }));
  await new Promise<void>((resolve) => { child.once("exit", () => resolve()); child.kill("SIGKILL"); });
  // The crashed child's listener is gone but the socket file lingers.
  for (let i = 0; i < 50 && (await probeLive(socketPath)); i++) await sleep(20);
  assert.ok(existsSync(socketPath), "a crashed arbiter leaves a stale socket file");

  const a = mkServer(socketPath, workdir);
  await assert.doesNotReject(() => a.listen(), "a stale socket must be reclaimable");
  await connectable(socketPath);
  await a.close();
  rmSync(workdir, { recursive: true, force: true });
});

test("a clean stop→start cycle works: close() frees the path for the next arbiter", async () => {
  // Refuse-on-live must NOT break a legitimate restart: once a arbiter close()s,
  // the path is free and the next arbiter binds (this is supervisor.restart).
  const workdir = mkdtempSync(join(tmpdir(), "mandu-socklife-"));
  const socketPath = join(workdir, "arbiter.sock");

  const a = mkServer(socketPath, workdir);
  await a.listen();
  await a.close();
  assert.ok(!existsSync(socketPath), "close() releases its own socket file");

  const b = mkServer(socketPath, workdir);
  await assert.doesNotReject(() => b.listen(), "the next arbiter binds after a clean close()");
  await connectable(socketPath);
  await b.close();
  rmSync(workdir, { recursive: true, force: true });
});
