/**
 * socket-path.test — an over-long Unix socket path is refused, never
 * silently shortened (ipc/socket-path.ts; runtime-instances.md §3a).
 *
 * Mandu-new test (no reference origin). Found 2026-09-28: a hand-started
 * arbiter on a 113-byte path bound `…/arb/arbiter` (the kernel kept the
 * first 107 bytes), so `mandu doctor` looked for `…/arb/arbiter.sock` and
 * reported the arbiter unreachable, with no hint why.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { SUN_PATH_MAX, socketPathProblem } from "../../ipc/socket-path.js";
import { createDefaultPolicyEngine } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** A socket path of exactly `bytes` bytes under `dir` (the directory made). */
function pathOfLength(dir: string, bytes: number): string {
  const sub = join(dir, "d");
  const name = "s".repeat(bytes - sub.length - 1);
  mkdirSync(sub, { recursive: true });
  const p = join(sub, name);
  assert.equal(Buffer.byteLength(p), bytes);
  return p;
}

function mkServer(socketPath: string, workdir: string, dbName = "symbols.db"): ArbiterServer {
  return new ArbiterServer({
    socketPath,
    dbPath: join(workdir, dbName),
    eventDir: join(workdir, "events"),
    policy: createDefaultPolicyEngine({}),
    log: () => {},
  });
}

test("socketPathProblem: fits below the limit, refused at it, measured in bytes", () => {
  assert.equal(socketPathProblem("/run/user/1001/mandu/arbiter.sock"), null);
  assert.equal(socketPathProblem("a".repeat(SUN_PATH_MAX - 1)), null, "SUN_PATH_MAX - 1 bytes + the NUL fit");
  const at = socketPathProblem("a".repeat(SUN_PATH_MAX));
  assert.ok(at !== null && at.includes(`${SUN_PATH_MAX} bytes`), "SUN_PATH_MAX bytes leave no room for the NUL");
  // 36 three-byte characters = 108 bytes although only 36 characters.
  assert.ok(socketPathProblem("가".repeat(36)) !== null, "the limit is bytes, not characters");
  // The size per platform (runtime-base.ts sunPathMaxFor, runtime-instances.md §3b).
  assert.equal(socketPathProblem("a".repeat(103), 104) !== null, false);
  assert.ok(socketPathProblem("a".repeat(104), 104)!.includes("over the 103-byte limit"), "darwin: 103 usable bytes");
  assert.ok(socketPathProblem("rel/" + "x".repeat(200))!.includes("MANDU_ARBITER_SOCK"), "names the fix");
});

test("listen() refuses an over-long path: nothing bound at the shortened name, the DB lock released", async () => {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-sockpath-"));
  try {
    const long = pathOfLength(workdir, SUN_PATH_MAX + 5);
    const a = mkServer(long, workdir);
    // The platform's own limit (SUN_PATH_MAX - 1: 107 on Linux, 103 on macOS / the BSDs).
    await assert.rejects(() => a.listen(), new RegExp(`arbiter socket: the socket path is \\d+ bytes, over the ${SUN_PATH_MAX - 1}-byte limit`));
    assert.deepEqual(readdirSync(join(workdir, "d")), [], "no socket appeared at the shortened name");
    assert.equal(existsSync(long), false);
    // The refusal happened before the symbol-DB claim: the same DB serves a
    // correct path right after.
    const b = mkServer(join(workdir, "ok.sock"), workdir);
    await b.listen();
    await b.close();
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test("the client refuses to dial an over-long path (it would reach whatever sits at the shorter name)", async () => {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-sockpath-"));
  try {
    const long = pathOfLength(workdir, SUN_PATH_MAX + 5);
    const shortened = long.slice(0, SUN_PATH_MAX - 1);
    // A live arbiter AT the shortened name: without the check, the client
    // would connect to it and talk to the wrong arbiter.
    const squat = mkServer(shortened, workdir);
    await squat.listen();
    try {
      const c = new ArbiterClient(long);
      await assert.rejects(() => c.connect(), /arbiter client: the socket path is \d+ bytes/);
      await assert.rejects(() => c.subscribe("s1", 0, () => {}), /arbiter client: the socket path is \d+ bytes/);
      c.close();
    } finally {
      await squat.close();
    }
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});
