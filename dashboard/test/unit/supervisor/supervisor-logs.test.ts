/**
 * supervisor-logs.test — the supervisor's LOG machinery: the in-memory ring
 * (cap, completeness, 8KB line truncation), live subscribeLogs delivery, and
 * the durable per-module log file. Split from supervisor.test.ts
 * (agent-legibility); shared fixtures live in supervisor-harness.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { execFileSync, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, linkSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";

import { Supervisor, type ServiceDefinition } from "../../../src/supervisor/supervisor.js";
import { endLogFile, logFileWritten, openLogFile, wireLogs } from "../../../src/supervisor/service-logs.js";
import { createServiceRuntime } from "../../../src/supervisor/service-runtime.js";
import type { ServiceId } from "../../../src/supervisor/supervisor-defs.js";
import {
  BURST_SCRIPT,
  tmpdir,
  nodeArgs,
  socketDef,
  mkSup,
  sleep,
  waitUntil,
  waitForLog,
  registerTmpHooks,
  tmpRoot,
} from "./supervisor-harness.js";

registerTmpHooks();

test("ring buffer caps at logRingMax and drops oldest", async () => {
  const dir = tmpdir();
  const sock = join(dir, "ring.sock");
  // Fast emitter: many lines per tick.
  const SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer(() => {});
srv.listen(sock, () => {});
let n = 0;
const t = setInterval(() => {
  for (let i = 0; i < 50; i++) process.stdout.write('line-' + (n++) + '\\n');
}, 5);
setInterval(() => {}, 1e9);
`;
  const def: ServiceDefinition = {
    label: "Ringy",
    command: process.execPath,
    args: nodeArgs(SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  const sup = mkSup({ arbiter: def }, { logRingMax: 100 });
  try {
    await sup.start("arbiter");
    // Wait until the ring is saturated to its cap (proves it spewed past 100),
    // instead of hoping a fixed sleep was long enough under load.
    await waitUntil(() => sup.logs("arbiter").length >= 100, 8000, "ring full");
    const logs = sup.logs("arbiter");
    assert.ok(logs.length <= 100, `ring capped (got ${logs.length})`);
    assert.ok(logs.length > 0, "some lines retained");
  } finally {
    await sup.shutdownAll();
  }
});

test("lines longer than 8KB are truncated", async () => {
  const dir = tmpdir();
  const sock = join(dir, "long.sock");
  const SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer(() => {});
srv.listen(sock, () => {
  process.stdout.write('X'.repeat(20000) + '\\n');
});
setInterval(() => {}, 1e9);
`;
  const def: ServiceDefinition = {
    label: "Longline",
    command: process.execPath,
    args: nodeArgs(SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");
    await waitForLog(sup, "arbiter", (l) => l.startsWith("X"));
    const logs = sup.logs("arbiter");
    const big = logs.find((l) => l.line.startsWith("X"));
    assert.ok(big, "the long line was captured");
    assert.equal(big!.line.length, 8192, "truncated to 8192 chars");
  } finally {
    await sup.shutdownAll();
  }
});

test("subscribeLogs delivers live lines; unsubscribe stops delivery", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");
    const received: string[] = [];
    const unsub = sup.subscribeLogs("arbiter", (l) => received.push(l.line));
    // Poll until the live subscriber has received at least one line.
    await waitUntil(() => received.length > 0, 8000, "subscriber got a line");
    assert.ok(received.length > 0, "subscriber received live lines");

    const countAtUnsub = received.length;
    unsub();
    // Negative assertion (no MORE lines after unsubscribe): a fixed settle window
    // is fine here — there is no positive observable to poll for "nothing".
    await sleep(200);
    assert.equal(received.length, countAtUnsub, "no lines after unsubscribe");
  } finally {
    await sup.shutdownAll();
  }
});


test("in-memory ring keeps the COMPLETE log (default cap > 600 lines)", async () => {
  const dir = tmpdir();
  const sock = join(dir, "burst.sock");
  const def: ServiceDefinition = {
    label: "Burst",
    command: process.execPath,
    args: nodeArgs(BURST_SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  // No logRingMax override → exercise the production DEFAULTS (now 50000).
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");
    // Wait until the LAST line has landed, then assert the FIRST is still present —
    // proving the cap is far above 600 (the old 500 would have evicted "line0").
    await waitForLog(sup, "arbiter", (l) => l === "line599");
    const lines = sup.logs("arbiter").map((l) => l.line);
    assert.ok(lines.includes("line599"), "last line present");
    assert.ok(lines.includes("line0"), "FIRST line still retained (cap > 600)");
  } finally {
    await sup.shutdownAll();
  }
});

test("durable log file: written under logDir with a start marker + the captured lines", async () => {
  const { def } = socketDef("Filey");
  const logDir = join(tmpdir(), "module-logs");
  const sup = mkSup({ arbiter: def }, { logDir });
  try {
    await sup.start("arbiter");
    await waitForLog(sup, "arbiter", (l) => l.includes("listening"));

    const path = sup.logFilePath("arbiter");
    assert.ok(path.startsWith(logDir), `logFilePath under logDir (${path})`);
    // The line is in the ring; the file is written after it, asynchronously:
    // logFileWritten resolves once every line the ring holds is on disk.
    await sup.logFileWritten("arbiter");
    const contents = readFileSync(path, "utf8");
    assert.match(contents, /==== arbiter started .* ====/, "start marker present");
    assert.ok(contents.includes("listening"), "captured stdout line on disk");
  } finally {
    await sup.shutdownAll();
  }
});

test("durable log file: once logFileWritten resolves it holds every line the ring holds, while the stream is open and after the child's exit ended it (CI pipeline 11021: the full log read right after the ring lacked its line)", async () => {
  const { def } = socketDef("Flushy");
  const logDir = join(tmpdir(), "flush-logs");
  const path = join(logDir, "arbiter.log");
  const svc = createServiceRuntime(def);
  openLogFile(svc, "arbiter", logDir, path, new Set<ServiceId>());
  const child = { stdout: new EventEmitter(), stderr: new EventEmitter() };
  wireLogs(svc, child as unknown as ChildProcess, 100);
  child.stdout.emit("data", Buffer.from("FLUSH-CANARY-1\n"));
  assert.ok(svc.ring.some((l) => l.line === "FLUSH-CANARY-1"), "the ring (the live view) has the line at once");
  assert.equal(readFileSync(path, "utf8").includes("FLUSH-CANARY-1"), false, "the file does not yet: it is written asynchronously");
  await logFileWritten(svc, 5000);
  assert.ok(readFileSync(path, "utf8").includes("FLUSH-CANARY-1"), "the file holds it once logFileWritten resolves");
  // The child exits: the stream is ended with a line still queued.
  child.stdout.emit("data", Buffer.from("FLUSH-CANARY-2\n"));
  endLogFile(svc);
  assert.equal(svc.logStream, null);
  await logFileWritten(svc, 5000);
  assert.ok(readFileSync(path, "utf8").includes("FLUSH-CANARY-2"), "an ended stream's queued line is waited for");
  assert.equal(svc.logClosing, null, "and nothing is left pending");
  // Nothing open, nothing pending: it resolves at once.
  await logFileWritten(createServiceRuntime(def), 5000);
});

test("durable log file: truncated on a process's first open, appended to after; a link, a hard link to someone's file or a FIFO at its name gets NO log and is never written through (runtime-instances.md §2)", async () => {
  const dir = tmpdir();
  const logDir = join(dir, "logs");
  const svc = createServiceRuntime(socketDef("Planted").def);
  const truncated = new Set<ServiceId>();
  const closeStream = async (): Promise<void> => {
    const s = svc.logStream;
    if (s) await new Promise<void>((r) => s.end(() => r()));
    svc.logStream = null;
  };
  // An ordinary file: the first open truncates, a later one appends.
  mkdirSync(logDir, { recursive: true });
  writeFileSync(join(logDir, "arbiter.log"), "from an earlier dashboard\n");
  openLogFile(svc, "arbiter", logDir, join(logDir, "arbiter.log"), truncated);
  assert.ok(svc.logStream !== null);
  await closeStream();
  openLogFile(svc, "arbiter", logDir, join(logDir, "arbiter.log"), truncated);
  await closeStream();
  const lines = readFileSync(join(logDir, "arbiter.log"), "utf8").split("\n").filter(Boolean);
  assert.equal(lines.length, 2, lines.join("\n"));
  assert.ok(lines.every((l) => /^==== arbiter started .* ====$/.test(l)), "the earlier contents were truncated once, then appended to");
  // What a planter leaves at a log's name in <runtime base>/logs.
  const victim = join(dir, "victim.rc");
  writeFileSync(victim, "# rc\n");
  symlinkSync(victim, join(logDir, "net-proxy.log"));
  linkSync(victim, join(logDir, "openai-proxy.log"));
  execFileSync("mkfifo", [join(logDir, "anthropic-proxy.log")]);
  for (const id of ["net-proxy", "openai-proxy", "anthropic-proxy"] as ServiceId[]) {
    openLogFile(svc, id, logDir, join(logDir, `${id}.log`), new Set());
    assert.equal(svc.logStream, null, `${id}: no durable log through what was planted`);
  }
  assert.equal(readFileSync(victim, "utf8"), "# rc\n", "never truncated, never appended to");
});

test("durable log file: a <runtime base>/logs that is a link to a folder gets NO log there, a dangling one has no folder made (runtime-instances.md §2, 2026-10-17)", () => {
  const dir = tmpdir();
  const svc = createServiceRuntime(socketDef("PlantedDir").def);
  const victim = join(dir, "victim");
  mkdirSync(victim);
  writeFileSync(join(victim, "keep"), "keep\n");
  symlinkSync(victim, join(dir, "logs"));
  openLogFile(svc, "arbiter", join(dir, "logs"), join(dir, "logs", "arbiter.log"), new Set());
  assert.equal(svc.logStream, null, "no durable log through the linked folder");
  assert.deepEqual(readdirSync(victim), ["keep"], "nothing made in the linked-to folder");
  symlinkSync(join(dir, "elsewhere", "deeper"), join(dir, "logs2"));
  openLogFile(svc, "arbiter", join(dir, "logs2"), join(dir, "logs2", "arbiter.log"), new Set());
  assert.equal(svc.logStream, null);
  assert.equal(existsSync(join(dir, "elsewhere")), false, "the dangling link's target folder was not made");
});

test("logFilePath default: <dirname(arbiterSock)>/logs/<id>.log", () => {
  const sup = new Supervisor({
    repoRoot: tmpRoot,
    arbiterSock: join(tmpRoot, "arbiter.sock"),
    log: () => {},
  });
  assert.equal(sup.logFilePath("arbiter"), join(tmpRoot, "logs", "arbiter.log"));
  assert.equal(
    sup.logFilePath("anthropic-proxy"),
    join(tmpRoot, "logs", "anthropic-proxy.log"),
  );
});

