/**
 * socket-owner.test — unprivileged unix-socket owner discovery (socket-owner.ts):
 * the /proc/net/unix parser (listener-row selection, symlink-spelling match)
 * and the darwin lsof rung with injected deps, the portable cmdline probe, plus
 * one REAL end-to-end discovery against a spawned child on this host (/proc on
 * Linux, lsof + ps on darwin) — same-uid access is exactly the privilege this
 * module is scoped to, so the integration case runs in any unprivileged CI.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { join } from "node:path";
import { rmSync, symlinkSync, mkdirSync } from "node:fs";
import { spawn } from "node:child_process";

import {
  discoverUnixSocketOwner,
  inodeForUnixSocket,
  lsofUnixSocketOwner,
  pidOwningSocketInode,
  procCmdlineOf,
  type CmdlineSource,
  type LsofDeps,
  type ProcDeps,
} from "../../../src/supervisor/socket-owner.js";
import { tmpDir } from "../tmp-dir.js";

// ── the /proc/net/unix parser, on a pinned fixture ────────────────────────────

// Shape mirrors a real 6.8 kernel: a header line; an accepted-peer row (St 03)
// listing the SAME path as the listener (St 01); an unrelated listener.
const PROC_NET_UNIX = `Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000003 00000000 00000000 0001 03 61083896 /base/instances/i-1/arbiter.sock
0000000000000000: 00000002 00000000 00010000 0001 01 51039912 /base/instances/i-1/arbiter.sock
0000000000000000: 00000002 00000000 00010000 0001 01 38882239 /elsewhere/other.sock
0000000000000000: 00000002 00000000 00010000 0001 01 40000000
`;

function fakeDeps(over: Partial<ProcDeps> = {}): ProcDeps {
  return {
    procNetUnix: () => PROC_NET_UNIX,
    // The promotion-symlink spelling resolves to the instance dir path.
    realpath: (p) => (p === "/base/current/arbiter.sock" ? "/base/instances/i-1/arbiter.sock" : p),
    listPids: () => [],
    listFdLinks: () => [],
    cmdlineOf: () => null,
    ...over,
  };
}

test("inodeForUnixSocket picks the LISTENER row (St 01), not the accepted peer listing the same path", () => {
  assert.equal(inodeForUnixSocket("/base/instances/i-1/arbiter.sock", fakeDeps()), "51039912");
});

test("inodeForUnixSocket matches through the promotion-symlink spelling (current/ → instances/<id>/)", () => {
  assert.equal(inodeForUnixSocket("/base/current/arbiter.sock", fakeDeps()), "51039912");
});

test("inodeForUnixSocket → null for an unbound path and for a vanished socket file", () => {
  assert.equal(inodeForUnixSocket("/nowhere/none.sock", fakeDeps()), null);
  assert.equal(
    inodeForUnixSocket("/gone.sock", fakeDeps({ realpath: () => { throw new Error("ENOENT"); } })),
    null,
  );
});

test("pidOwningSocketInode finds the fd holder and NEVER reports this process itself", () => {
  const deps = fakeDeps({
    listPids: () => [process.pid, 7777],
    listFdLinks: (pid) => (pid === 7777 || pid === process.pid ? ["socket:[51039912]"] : []),
  });
  assert.equal(pidOwningSocketInode("51039912", deps), 7777, "the other pid wins");
  const selfOnly = fakeDeps({
    listPids: () => [process.pid],
    listFdLinks: () => ["socket:[51039912]"],
  });
  assert.equal(pidOwningSocketInode("51039912", selfOnly), null,
    "an in-process listener is not a Replace target — self is skipped");
});

test("discoverUnixSocketOwner never throws: a missing /proc (darwin) or any probe error is the documented null", () => {
  const enoent = (): never => { throw Object.assign(new Error("ENOENT: open '/proc/net/unix'"), { code: "ENOENT" }); };
  assert.equal(discoverUnixSocketOwner("/base/instances/i-1/arbiter.sock", fakeDeps({ procNetUnix: enoent })), null);
  assert.equal(
    discoverUnixSocketOwner("/base/instances/i-1/arbiter.sock", fakeDeps({ listPids: enoent })),
    null,
  );
});

// ── the darwin rung: lsof -F pn over this user's unix sockets ─────────────────

// Shape of a real macOS 26 `lsof -w -n -P -a -U -u <uid> -F pn`: the listener
// and its accepted connection name the BOUND path (as the daemon spelled it,
// /tmp here); a connecting client shows `->0x…`, never the path.
const LSOF_OUT = `p100
f5
n->0x6e2b5f42c683937d
p4242
f12
n/tmp/base/instances/i-1/arbiter.sock
f13
n/tmp/base/instances/i-1/arbiter.sock
p5151
f9
n/elsewhere/other.sock
`;

function lsofDeps(over: Partial<LsofDeps> = {}): LsofDeps {
  const real: Record<string, string> = {
    // the probe spelling (current/) and the bound spelling (/tmp) both resolve to the canonical path
    "/tmp/base/current/arbiter.sock": "/private/tmp/base/instances/i-1/arbiter.sock",
    "/tmp/base/instances/i-1/arbiter.sock": "/private/tmp/base/instances/i-1/arbiter.sock",
  };
  return {
    lsofUnix: () => LSOF_OUT,
    realpath: (p) => real[p] ?? p,
    cmdlineOf: (pid) => (pid === 4242 ? "mandu-arbiter" : null),
    selfPid: 100,
    ...over,
  };
}

test("lsofUnixSocketOwner names the one process holding the bound path, through the symlink and /tmp spellings", () => {
  assert.deepEqual(lsofUnixSocketOwner("/tmp/base/current/arbiter.sock", lsofDeps()), { pid: 4242, cmdline: "mandu-arbiter" });
  assert.deepEqual(lsofUnixSocketOwner("/tmp/base/instances/i-1/arbiter.sock", lsofDeps()), { pid: 4242, cmdline: "mandu-arbiter" });
});

test("lsofUnixSocketOwner → null: a vanished socket file, no match, no lsof, only this process, or TWO holders (ambiguous)", () => {
  const sock = "/tmp/base/current/arbiter.sock";
  assert.equal(lsofUnixSocketOwner(sock, lsofDeps({ realpath: () => { throw new Error("ENOENT"); } })), null);
  assert.equal(lsofUnixSocketOwner("/nowhere/none.sock", lsofDeps()), null);
  assert.equal(lsofUnixSocketOwner(sock, lsofDeps({ lsofUnix: () => "" })), null, "lsof missing, failed or timed out");
  assert.equal(lsofUnixSocketOwner(sock, lsofDeps({ selfPid: 4242 })), null, "an in-process listener is not a Replace target");
  // An old daemon still holds an unlinked socket of the same name while a new
  // one bound the path again: never guess which one to signal.
  const twice = `${LSOF_OUT}p6000\nf7\nn/tmp/base/instances/i-1/arbiter.sock\n`;
  assert.equal(lsofUnixSocketOwner(sock, lsofDeps({ lsofUnix: () => twice })), null);
});

test("procCmdlineOf: /proc on Linux (never ps), `ps -o args=` without /proc; unreadable is null", () => {
  const asked: string[] = [];
  const src = (platform: NodeJS.Platform, proc: () => string, ps: () => string): CmdlineSource => ({
    platform,
    readProcCmdline: () => { asked.push("proc"); return proc(); },
    psArgs: () => { asked.push("ps"); return ps(); },
  });
  assert.equal(procCmdlineOf(7, src("linux", () => "node\0ipc/server-main.ts\0", () => "WRONG")), "node ipc/server-main.ts");
  assert.equal(procCmdlineOf(7, src("linux", () => { throw new Error("EACCES"); }, () => "WRONG")), null);
  assert.deepEqual(asked.splice(0), ["proc", "proc"]);
  assert.equal(procCmdlineOf(7, src("darwin", () => "WRONG", () => "mandu-arbiter   \n")), "mandu-arbiter");
  assert.equal(procCmdlineOf(7, src("darwin", () => "WRONG", () => { throw new Error("ps exited 1"); })), null);
  assert.deepEqual(asked.splice(0), ["ps", "ps"]);
  assert.equal(procCmdlineOf(0, src("darwin", () => "", () => "x")), null);
  assert.deepEqual(asked, [], "a non-pid is never probed");
});

// ── the real thing: discover a spawned child by its listening socket ──────────

test("discoverUnixSocketOwner names a REAL spawned listener's pid (same-uid /proc on Linux, lsof + ps on darwin; no privilege)", async () => {
  const dir = tmpDir("mandu-sockowner-");
  const sock = join(dir, "instances", "i-1", "arbiter.sock");
  mkdirSync(join(dir, "instances", "i-1"), { recursive: true });
  // The promotion-symlink spelling the dashboard actually probes.
  symlinkSync(join(dir, "instances", "i-1"), join(dir, "current"));
  const viaSymlink = join(dir, "current", "arbiter.sock");

  const child = spawn(
    process.execPath,
    ["-e", `
      const net = require('net');
      const srv = net.createServer((c) => c.resume());
      srv.listen(process.env.SOCK, () => process.stdout.write('up\\n'));
      setInterval(() => {}, 1e9);
    `],
    { env: { ...process.env, SOCK: sock }, stdio: "ignore" },
  );
  const up = (): Promise<boolean> =>
    new Promise((resolve) => {
      const s = net.connect({ path: sock });
      s.once("connect", () => { s.destroy(); resolve(true); });
      s.once("error", () => resolve(false));
    });
  try {
    const t0 = Date.now();
    while (!(await up())) {
      if (Date.now() - t0 > 8000) throw new Error("child never listened");
      await new Promise((r) => setTimeout(r, 25));
    }

    const owner = discoverUnixSocketOwner(viaSymlink);
    assert.ok(owner, "the owner is discoverable through the symlink spelling");
    assert.equal(owner!.pid, child.pid, "…and it is the child's REAL pid");
    assert.ok(owner!.cmdline?.includes("net.createServer"), "…with its command line attached");
  } finally {
    child.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
});
