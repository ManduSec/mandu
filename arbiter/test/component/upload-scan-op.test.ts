/**
 * upload-scan-op.test — the `fileUploadDecision` op over the arbiter's real
 * sockets with files far past the old 8 MiB read limit (confidentiality.md
 * §7, STREAMED, 2026-10-17). Mandu-new.
 *
 * Proves, against a listening ArbiterServer:
 *   - the production client (`ArbiterClient.fileUploadDecision`, on the
 *     human socket) gets the answer for a 64 MiB file although the scan
 *     takes longer than the client's idle timeout: the arbiter's progress
 *     frames re-arm it (the call is ASSERTED to outlast the idle timeout,
 *     so the test cannot pass without them); a file with no registered
 *     value goes, one with a value held;
 *   - while the scan runs, the arbiter answers other clients (the event
 *     loop is free between chunks): a cheap op on the data socket is
 *     answered in a small fraction of the scan's time;
 *   - a raw client that asked `progress: true` hears a frame as soon as the
 *     scan starts and more while it runs, then the answer.
 *
 * PACING (a CI fix of !1833). The guest runs many suites at once, and there
 * the scan ran about 17 times slower than alone (2 MiB/s, where the guest
 * alone and the development host both scan 35 MiB/s): a 1.2 s idle timeout
 * against a 1 s frame cadence and 1 MiB chunks had no margin, and a 96 MiB
 * scan passed the 45 s deadline. So the server here takes the `uploadScan`
 * test knob: frames every 100 ms and a deadline far past any load, and the
 * idle timeout is 1 s; the margins are ratios (the scan outlasts the idle
 * timeout; another client waits a small fraction of the scan), never an
 * absolute speed. The product's own pacing (1 s frames, 5 s idle timeout,
 * 256 KiB chunks) is what confidentiality.md §7 measures.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const KEY = "sk_live_fake_STREAMEDOP_0123456789abcdef";
const MiB = 1024 * 1024;
const IDLE_MS = 1000;
const PROGRESS_MS = 100;

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

/** Pseudo-random bytes (a photo or a video looks like this to the scan). */
function noise(n: number): Buffer {
  const b = Buffer.alloc(n);
  let x = 0x9e3779b9;
  for (let i = 0; i + 4 <= n; i += 4) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    b.writeUInt32LE(x >>> 0, i);
  }
  return b;
}

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-upload-op-"));
  dirs.push(dir);
  const ws = join(dir, "ws");
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, ".env"), `STRIPE_KEY=${KEY}\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, packDir: null,
    uploadScan: { deadlineMs: 600_000, progressMs: PROGRESS_MS },
  });
  await server.listen();
  const reg = server.dispatch({ id: 1, op: "registerSecret", path: join(ws, ".env") } as never, { channel: "admin" }) as { ok: boolean };
  assert.equal(reg.ok, true);
  return { server, ws, sock, humanSock, close: async () => { await server.close(); } };
}

test("a 64 MiB upload is judged over the real sockets: the client outlives its idle timeout, clean goes, a value is held, other clients are answered meanwhile", async () => {
  const r = await rig();
  const human = new ArbiterClient(r.humanSock, { requestTimeoutMs: IDLE_MS });
  const data = new ArbiterClient(r.sock);
  let scanDone = false;
  const latencies: number[] = [];
  let prober: Promise<void> = Promise.resolve();
  try {
    writeFileSync(join(r.ws, "clip.mp4"), noise(64 * MiB));
    const withKey = noise(12 * MiB);
    Buffer.from(KEY).copy(withKey, 9 * MiB - 5);
    writeFileSync(join(r.ws, "deck.pdf"), withKey);

    // another client's cheap op, timed while the scan runs
    prober = (async () => {
      await new Promise((res) => setTimeout(res, 50));
      while (!scanDone) {
        const t0 = Date.now();
        await data.scanSecretValues("nothing secret here");
        if (!scanDone) latencies.push(Date.now() - t0);
        await new Promise((res) => setTimeout(res, 20));
      }
    })();
    const t0 = Date.now();
    const clean = await human.fileUploadDecision({ tool: "message", path: join(r.ws, "clip.mp4"), destination: "", sessionKey: "op-1" });
    const cleanMs = Date.now() - t0;
    scanDone = true;
    await prober;
    const held = await human.fileUploadDecision({ tool: "message", path: join(r.ws, "deck.pdf"), destination: "", sessionKey: "op-1" });

    assert.equal(clean.allow, true, clean.reason);
    assert.equal(clean.ruleRef?.id, "fs:upload-clean");
    assert.ok(cleanMs > IDLE_MS, `the scan (${cleanMs} ms) outlasted the client's idle timeout (${IDLE_MS} ms): only progress frames kept the call alive`);
    assert.equal(held.allow, false);
    assert.equal(held.allow === false && held.requiresApproval, true);
    assert.equal(held.ruleRef?.id, "fs:upload-secret-value");
    assert.ok(latencies.length > 0, "another client was answered while the scan ran");
    const worst = Math.max(...latencies);
    assert.ok(worst < cleanMs / 4, `no answer waited behind the scan (worst ${worst} ms of a ${cleanMs} ms scan)`);
  } finally {
    scanDone = true;
    await prober.catch(() => {});
    human.close();
    data.close();
    await r.close();
  }
});

test("a raw client that asked progress: true hears a frame when the scan starts and more while it runs, then the answer", async () => {
  const r = await rig();
  try {
    writeFileSync(join(r.ws, "big.bin"), noise(16 * MiB));
    const frames: Array<{ f: Record<string, unknown>; at: number }> = [];
    const t0 = Date.now();
    await new Promise<void>((resolve, reject) => {
      const c = createConnection(r.humanSock);
      let buf = "";
      c.on("error", reject);
      c.on("data", (d) => {
        buf += d.toString("utf8");
        for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          if (line === "") continue;
          const f = JSON.parse(line) as Record<string, unknown>;
          frames.push({ f, at: Date.now() - t0 });
          if (f["progress"] !== true) { c.end(); resolve(); }
        }
      });
      c.write(JSON.stringify({ id: 7, op: "fileUploadDecision", progress: true, request: { tool: "message", path: join(r.ws, "big.bin"), destination: "", sessionKey: "op-2" } }) + "\n");
    });
    const last = frames[frames.length - 1]!.f;
    assert.equal(last["id"], 7);
    assert.equal(last["ok"], true);
    assert.equal((last["result"] as { allow: boolean }).allow, true, JSON.stringify(last));
    const progress = frames.slice(0, -1);
    for (const p of progress) assert.deepEqual(p.f, { id: 7, progress: true });
    // one when the scan starts, before its first chunk is matched, and at
    // least one more while 16 MiB is matched (over 100 ms at any speed seen)
    assert.ok(progress.length >= 2, `progress frames: ${JSON.stringify(frames.map((x) => x.at))}`);
    assert.ok(progress[0]!.at < frames[frames.length - 1]!.at, "the first frame came before the answer");
  } finally {
    await r.close();
  }
});
