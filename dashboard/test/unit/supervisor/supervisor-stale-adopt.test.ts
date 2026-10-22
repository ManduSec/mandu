/**
 * supervisor-stale-adopt.test — a STALE arbiter found answering when the
 * supervisor starts its own (runtime-instances.md §4.1b; the 2026-10-21
 * incident: the stack's arbiter, another dashboard's child four days and two
 * releases old, re-adopted by every restart of the service's dashboard while
 * every launch refused it).
 *
 * In instance mode, with no `mandu` session on the stack, the stale arbiter
 * is replaced (the verified SIGTERM of replace(), then this supervisor's own
 * spawn); with a session, when sessions cannot be told, when the pid cannot
 * be verified, in pinned mode, opted out, or when it is not stale, it is
 * adopted as before (and flagged STALE when it is). And `onCrash`: a service
 * this supervisor started that exits on its own is reported once; a stop is
 * not (server-main uses it to end an arbiter-only dashboard with its arbiter).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";

import { type ServiceDefinition, type SupervisorOptions } from "../../../src/supervisor/supervisor.js";
import { SOCKET_SCRIPT, tmpdir, nodeArgs, mkSup, registerTmpHooks, isAlive, socketDef, waitUntil } from "./supervisor-harness.js";

registerTmpHooks();

/** An external arbiter: answers hello with its own pid and `FAKE_VERSION`. */
const HELLO_SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer((c) => {
  c.on('data', (b) => {
    if (b.toString().includes('"hello"')) {
      c.write(JSON.stringify({ id: 1, ok: true, result: {
        pid: process.pid, startedAt: '2026-10-16T21:45:12.710Z', instanceId: '20261016-2145-88da43ace-p' + process.pid,
        gitRev: '88da43ace', gitDirty: false, version: process.env.FAKE_VERSION, protocolVersion: 1,
        sockPath: sock, eventDir: '/e', symbolDb: '/s',
      }}) + '\\n');
    }
  });
});
srv.listen(sock);
setInterval(() => {}, 1e9);
`;

function listening(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ path });
    const done = (v: boolean): void => { try { s.destroy(); } catch { /* ignore */ } resolve(v); };
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
    s.setTimeout(1000, () => done(false));
  });
}

async function external(sock: string, cwd: string, version: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, nodeArgs(HELLO_SCRIPT), { cwd, env: { ...process.env, FAKE_SOCK: sock, FAKE_VERSION: version }, stdio: "ignore" });
  const t0 = Date.now();
  while (!(await listening(sock))) {
    if (Date.now() - t0 > 8000) throw new Error("external arbiter never listened");
    await new Promise((r) => setTimeout(r, 25));
  }
  return child;
}

/** Our own arbiter, if the supervisor spawns one: rebinds the same socket. */
function ownDef(sock: string, dir: string): ServiceDefinition {
  return { label: "Arbiter", command: process.execPath, args: nodeArgs(SOCKET_SCRIPT), cwd: dir, env: { FAKE_SOCK: sock }, ready: { kind: "socket", path: sock }, endpoint: sock };
}

interface Run { logs: string[]; ext: ChildProcess; extPid: number; sock: string; dir: string }

/** Start the supervisor's arbiter over an external one of `version`. */
async function startOver(version: string, opts: Partial<SupervisorOptions> = {}, instance = true): Promise<Run & { sup: ReturnType<typeof mkSup> }> {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const ext = await external(sock, dir, version);
  const extPid = ext.pid!;
  const logs: string[] = [];
  const sup = mkSup({ arbiter: ownDef(sock, dir) }, {
    arbiterSock: sock,
    ...(instance ? { arbiterInstanceBase: dir } : {}),
    eventDir: "/e", // the external one's: ours, not FOREIGN
    ownArbiterBuild: () => ({ version: "0.2.0-beta.7", bundle: null, installed: false }),
    procCmdline: (pid) => (pid === extPid ? "mandu-arbiter" : null),
    liveSessions: () => [],
    log: (m) => logs.push(m),
    ...opts,
  });
  await sup.start("arbiter");
  return { sup, logs, ext, extPid, sock, dir };
}

async function done(r: { sup: ReturnType<typeof mkSup>; ext: ChildProcess }): Promise<void> {
  await r.sup.shutdownAll();
  try { r.ext.kill("SIGKILL"); } catch { /* gone */ }
}

test("a stale arbiter with no session on the stack is replaced: SIGTERMed, then ours runs", async () => {
  const r = await startOver("0.2.0-beta.5");
  try {
    const st = r.sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(isAlive(r.extPid), false, "the stale arbiter is gone");
    assert.equal(st.state, "running");
    assert.equal(st.adopted, false, "this supervisor's own arbiter runs now");
    assert.ok(st.pid && st.pid !== r.extPid);
    assert.ok(await listening(r.sock));
    assert.ok(r.logs.some((l) => /NOT adopting the instance .*STALE — it runs Mandu 0\.2\.0-beta\.5; this dashboard is Mandu 0\.2\.0-beta\.7\. No mandu session uses this stack/.test(l)), r.logs.join("\n"));
    assert.ok(!r.logs.some((l) => /adopted an already-running/.test(l)), "never said adopted");
  } finally { await done(r); }
});

test("a session on the stack keeps the stale arbiter adopted, flagged, naming the sessions", async () => {
  let asked = "";
  const r = await startOver("0.2.0-beta.5", { liveSessions: (b) => { asked = b; return [4242, 4243]; } });
  try {
    assert.equal(asked, r.dir, "the sessions of this supervisor's stack");
    const st = r.sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.adopted, true);
    assert.equal(st.stale, true);
    assert.ok(isAlive(r.extPid), "left running for the sessions");
    assert.ok(r.logs.some((l) => /STALE — .*\(not replaced: mandu sessions pid 4242, 4243 use it\)/.test(l)), r.logs.join("\n"));
  } finally { await done(r); }
});

test("sessions that cannot be told count as in use", async () => {
  const r = await startOver("0.2.0-beta.5", { liveSessions: () => null });
  try {
    assert.equal(r.sup.status().find((s) => s.id === "arbiter")!.adopted, true);
    assert.ok(isAlive(r.extPid));
    assert.ok(r.logs.some((l) => /not replaced: this dashboard cannot tell which mandu sessions use it/.test(l)), r.logs.join("\n"));
  } finally { await done(r); }
});

test("a pid that is not verifiably an arbiter is not signalled: adopted, flagged, the refusal logged", async () => {
  const signals: number[] = [];
  const r = await startOver("0.2.0-beta.5", {
    procCmdline: () => "node -e something",
    killPid: (pid, sig) => { if (sig !== 0) signals.push(pid); process.kill(pid, sig); },
  });
  try {
    assert.deepEqual(signals, []);
    assert.equal(r.sup.status().find((s) => s.id === "arbiter")!.adopted, true);
    assert.ok(r.logs.some((l) => /could not replace the stale arbiter: refusing to replace arbiter: pid \d+ is not verifiably an arbiter/.test(l)), r.logs.join("\n"));
    assert.ok(r.logs.some((l) => /arbiter: STALE — /.test(l)));
  } finally { await done(r); }
});

test("adopted as before: an arbiter of this build, a pinned socket, or replaceStaleOnAdopt off", async () => {
  let asked = 0;
  const same = await startOver("0.2.0-beta.7", { liveSessions: () => { asked++; return []; } });
  try {
    assert.equal(same.sup.status().find((s) => s.id === "arbiter")!.adopted, true, "not stale: adopted");
    assert.equal(asked, 0, "no session scan for an arbiter that is not stale");
  } finally { await done(same); }
  const pinned = await startOver("0.2.0-beta.5", {}, false);
  try {
    assert.equal(pinned.sup.status().find((s) => s.id === "arbiter")!.adopted, true, "a pinned socket is the caller's");
    assert.ok(isAlive(pinned.extPid));
  } finally { await done(pinned); }
  const off = await startOver("0.2.0-beta.5", { replaceStaleOnAdopt: false });
  try {
    assert.equal(off.sup.status().find((s) => s.id === "arbiter")!.adopted, true, "opted out");
    assert.ok(isAlive(off.extPid));
  } finally { await done(off); }
});

test("onCrash: a started service that exits on its own is reported once; a stop is not", async () => {
  const crashes: Array<{ id: string; reason: string }> = [];
  const { def } = socketDef("Arbiter");
  const sup = mkSup({ arbiter: def }, { onCrash: (id, reason) => crashes.push({ id, reason }) });
  try {
    await sup.start("arbiter");
    await sup.stop("arbiter");
    assert.equal(crashes.length, 0, "a stop is no crash");
    await sup.start("arbiter");
    const pid = sup.status().find((s) => s.id === "arbiter")!.pid!;
    process.kill(pid, "SIGKILL");
    await waitUntil(() => crashes.length > 0, 8000, "onCrash");
    assert.equal(crashes.length, 1);
    assert.equal(crashes[0]!.id, "arbiter");
    assert.match(crashes[0]!.reason, /crashed while running \(signal SIGKILL\)/);
  } finally {
    await sup.shutdownAll();
  }
});
