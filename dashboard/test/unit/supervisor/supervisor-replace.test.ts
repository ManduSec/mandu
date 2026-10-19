/**
 * supervisor-replace.test — replace(): the sanctioned takeover of an ADOPTED
 * daemon. stop()/restart() refuse on adoption (supervisor-adopt.test.ts pins
 * that); replace() is the explicit alternative that does the kill the refusal
 * used to delegate to the operator — but only against a hello-verified pid
 * whose /proc cmdline confirms an arbiter (the recycled-pid guard, mirroring
 * launcher/src/reap.ts), sequentially (old pid GONE + endpoint CLEAR before the
 * successor spawns — runtime-instances.md §9), and never silently: every
 * refusal path throws AND persists into status().lastError so the polled panel
 * keeps telling the truth.
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

/**
 * A REAL external daemon (its pid is what replace() must kill): listens on
 * FAKE_SOCK and answers the NDJSON hello handshake with its OWN pid, so the
 * adopt path records a truthful identity.
 */
const HELLO_DAEMON_SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer((c) => {
  c.on('data', (b) => {
    if (b.toString().includes('"hello"')) {
      c.write(JSON.stringify({ id: 1, ok: true, result: {
        pid: process.pid, startedAt: '2026-07-07T00:00:00.000Z',
        instanceId: '20260707-0000-deadbee-p' + process.pid,
        gitRev: 'deadbee', gitDirty: false, sockPath: sock, eventDir: '/e', symbolDb: '/s',
      }}) + '\\n');
    }
  });
});
srv.listen(sock, () => process.stdout.write('hello-daemon: listening\\n'));
setInterval(() => {}, 1e9);
`;

/** A REAL external daemon that DRAINS input but never answers hello — the
 *  identity-less adoption whose only verifiable name is the /proc socket owner. */
const DRAIN_DAEMON_SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer((c) => c.resume());
srv.listen(sock, () => process.stdout.write('drain-daemon: listening\\n'));
setInterval(() => {}, 1e9);
`;

/** Resolve true if something accepts a connection on the unix socket `path`. */
function listening(path: string): Promise<boolean> {
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

/** Spawn an external daemon on `sock` and wait until it listens. */
async function spawnExternalDaemon(
  sock: string,
  cwd: string,
  script: string = HELLO_DAEMON_SCRIPT,
): Promise<ChildProcess> {
  const child = spawn(process.execPath, nodeArgs(script), {
    cwd,
    env: { ...process.env, FAKE_SOCK: sock },
    stdio: "ignore",
  });
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    const t0 = Date.now();
    const tick = async (): Promise<void> => {
      if (await listening(sock)) return resolve();
      if (Date.now() - t0 > 8000) return reject(new Error("external daemon never listened"));
      setTimeout(() => void tick(), 25);
    };
    void tick();
  });
  return child;
}

/** The supervised def: adopts the external daemon; if it ever SPAWNS, the child
 *  is a well-behaved fake that unlinks + rebinds the same socket. */
function replaceableDef(sock: string, dir: string): ServiceDefinition {
  return {
    label: "Arbiter",
    command: process.execPath,
    args: nodeArgs(SOCKET_SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
}

test("replace() takes over an adopted daemon: verified kill, wait-for-gone, then spawn our own", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const external = await spawnExternalDaemon(sock, dir);
  const externalPid = external.pid!;

  const signals: Array<{ pid: number; sig: NodeJS.Signals | 0 }> = [];
  const sup = mkSup(
    { arbiter: replaceableDef(sock, dir) },
    {
      arbiterSock: sock,
      // The guard SEES an arbiter-shaped cmdline for the external pid only.
      procCmdline: (pid) => (pid === externalPid ? "npx tsx ipc/server-main.ts" : null),
      killPid: (pid, sig) => {
        if (sig !== 0) signals.push({ pid, sig });
        process.kill(pid, sig);
      },
    },
  );
  try {
    await sup.start("arbiter");
    const adopted = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(adopted.adopted, true, "precondition: the external daemon was adopted");
    assert.equal(adopted.identity?.pid, externalPid, "precondition: hello recorded the REAL external pid");

    await sup.replace("arbiter");

    assert.ok(signals.some((s) => s.pid === externalPid && s.sig === "SIGTERM"), "the external pid got SIGTERM");
    assert.equal(isAlive(externalPid), false, "the old daemon is gone");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running", "a replacement is up");
    assert.equal(st.adopted, false, "…and it is OURS now (spawned, not adopted)");
    assert.ok(st.pid, "…with a child pid in this process");
    assert.notEqual(st.pid, externalPid, "…that is not the old daemon's pid");
    assert.ok(await listening(sock), "the endpoint is served by the replacement");
  } finally {
    await sup.shutdownAll();
    try { external.kill("SIGKILL"); } catch { /* already gone */ }
  }
});

test("replace() REFUSES on a recycled/unrecognizable pid — nothing is signalled, the daemon survives, lastError persists", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const external = await spawnExternalDaemon(sock, dir);
  const externalPid = external.pid!;

  const signals: number[] = [];
  const sup = mkSup(
    { arbiter: replaceableDef(sock, dir) },
    {
      arbiterSock: sock,
      // The recycled-pid trap: /proc says this pid is NOT an arbiter any more.
      procCmdline: () => "bash -lc sleep-infinity",
      killPid: (pid, sig) => {
        if (sig !== 0) signals.push(pid);
        process.kill(pid, sig);
      },
    },
  );
  try {
    await sup.start("arbiter");
    await assert.rejects(
      () => sup.replace("arbiter"),
      /not verifiably an arbiter/,
      "the cmdline guard refuses before any signal",
    );
    assert.deepEqual(signals, [], "NO signal was sent to the unverified pid");
    assert.equal(isAlive(externalPid), true, "the external daemon is untouched");
    assert.ok(await listening(sock), "…and still serving");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.adopted, true, "the row still tells the truth: adopted, running");
    assert.equal(st.state, "running");
    assert.match(st.lastError!, /not verifiably an arbiter/, "the refusal PERSISTS on the row via lastError");
  } finally {
    await sup.shutdownAll();
    try { external.kill("SIGKILL"); } catch { /* already gone */ }
    await waitUntilDead(externalPid).catch(() => {});
  }
});

test("replace() REFUSES an identity-less adoption when /proc can't name the owner either (no guess-kills)", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  // An external listener that never answers hello → identity stays null.
  // (resume() drains the hello line the probe writes — a paused socket would
  // never consume the probe's EOF, and server.close() would wait forever.)
  const external = net.createServer((c) => c.resume());
  await new Promise<void>((r) => external.listen(sock, r));

  const sup = mkSup(
    { arbiter: replaceableDef(sock, dir) },
    {
      arbiterSock: sock,
      killPid: () => { throw new Error("must not signal anything"); },
      // The discovery fallback finds nothing (the real walk would skip this
      // in-process listener too — self is never a Replace target).
      discoverSocketOwner: () => null,
    },
  );
  try {
    await sup.start("arbiter");
    assert.equal(sup.status().find((s) => s.id === "arbiter")!.identity, null, "precondition: pre-hello daemon");
    await assert.rejects(() => sup.replace("arbiter"), /without a verifiable identity/);
    assert.ok(await listening(sock), "the listener is untouched");
    assert.match(
      sup.status().find((s) => s.id === "arbiter")!.lastError!,
      /without a verifiable identity/,
      "the refusal persists via lastError",
    );
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => external.close(() => r()));
  }
});

test("replace() REFUSES a service that is not an adopted running instance", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const sup = mkSup({ arbiter: replaceableDef(sock, dir) }, { arbiterSock: sock });
  // Never started: state=stopped, adopted=false.
  await assert.rejects(() => sup.replace("arbiter"), /not an adopted running instance/);
});

// ── the adopt-time probe is not final: re-probe + /proc discovery ─────────────

test("a lost hello race heals itself: the status() poll re-probes and fills the identity in", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const identity = {
    pid: 4242, startedAt: "2026-07-07T00:00:00.000Z", instanceId: "20260707-0000-deadbee-p4242",
    gitRev: "deadbee", gitDirty: false, sockPath: sock, eventDir: "/e", symbolDb: "/s",
  };
  // The fake daemon stays SILENT during adoption (the lost boot race), then
  // starts answering hello — exactly the live incident: the resident arbiter
  // answered a by-hand hello probe fine while the panel said "no identity".
  let answerHello = false;
  const fake = net.createServer((c) => {
    c.on("data", (b) => {
      if (answerHello && b.toString().includes('"hello"')) {
        c.write(JSON.stringify({ id: 1, ok: true, result: identity }) + "\n");
      }
    });
  });
  await new Promise<void>((r) => fake.listen(sock, r));

  const sup = mkSup(
    { arbiter: replaceableDef(sock, dir) },
    { arbiterSock: sock, discoverSocketOwner: () => null },
  );
  try {
    await sup.start("arbiter"); // adopt-time probe times out → identity null
    assert.equal(sup.status().find((s) => s.id === "arbiter")!.identity, null, "precondition: the race was lost");

    answerHello = true; // the daemon is reachable now
    const t0 = Date.now();
    let st = sup.status().find((s) => s.id === "arbiter")!;
    while (!st.identity) {
      if (Date.now() - t0 > 8000) throw new Error("identity never refreshed");
      await new Promise((r) => setTimeout(r, 50));
      st = sup.status().find((s) => s.id === "arbiter")!; // each poll kicks the throttled re-probe
    }
    assert.equal(st.identity!.pid, 4242, "the re-probe recorded the daemon's identity");
    assert.equal(st.ownerPid, undefined, "no /proc owner shown once the daemon speaks for itself");
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => fake.close(() => r()));
  }
});

test("a hello-less daemon surfaces its /proc socket owner on status()", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const external = net.createServer((c) => c.resume());
  await new Promise<void>((r) => external.listen(sock, r));

  const sup = mkSup(
    { arbiter: replaceableDef(sock, dir) },
    { arbiterSock: sock, discoverSocketOwner: () => ({ pid: 5150, cmdline: "npx tsx ipc/server-main.ts" }) },
  );
  try {
    await sup.start("arbiter");
    const t0 = Date.now();
    let st = sup.status().find((s) => s.id === "arbiter")!;
    while (!st.ownerPid) {
      if (Date.now() - t0 > 8000) throw new Error("ownerPid never surfaced");
      await new Promise((r) => setTimeout(r, 50));
      st = sup.status().find((s) => s.id === "arbiter")!;
    }
    assert.equal(st.ownerPid, 5150, "the /proc-discovered owner rides the snapshot");
    assert.equal(st.ownerCmdline, "npx tsx ipc/server-main.ts");
    assert.equal(st.identity, null, "…without inventing an identity the daemon never claimed");
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => external.close(() => r()));
  }
});

test("replace() takes over a hello-less daemon via FRESH /proc discovery (still cmdline-guarded)", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const external = await spawnExternalDaemon(sock, dir, DRAIN_DAEMON_SCRIPT);
  const externalPid = external.pid!;

  const discovered: string[] = [];
  const sup = mkSup(
    { arbiter: replaceableDef(sock, dir) },
    {
      arbiterSock: sock,
      discoverSocketOwner: (p) => {
        discovered.push(p);
        return { pid: externalPid, cmdline: null };
      },
      procCmdline: (pid) => (pid === externalPid ? "npx tsx ipc/server-main.ts" : null),
    },
  );
  try {
    await sup.start("arbiter");
    assert.equal(sup.status().find((s) => s.id === "arbiter")!.identity, null, "precondition: no hello identity");

    await sup.replace("arbiter");

    assert.ok(discovered.includes(sock), "replace re-discovered the owner FRESH at kill time");
    assert.equal(isAlive(externalPid), false, "the discovered daemon is gone");
    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running");
    assert.equal(st.adopted, false, "the replacement is ours");
    assert.notEqual(st.pid, externalPid);
  } finally {
    await sup.shutdownAll();
    try { external.kill("SIGKILL"); } catch { /* already gone */ }
    await waitUntilDead(externalPid).catch(() => {});
  }
});
