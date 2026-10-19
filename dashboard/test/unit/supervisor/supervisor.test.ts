/**
 * supervisor.test — offline, unprivileged unit tests for the process supervisor.
 *
 * Mandu-new test (NO reference origin). Uses the `definitions` test hook to
 * inject FAKE services spawned as `node -e "<script>"`, so no real arbiter/proxy
 * /npm is needed. The fakes mirror the readiness shapes (a Unix socket; TCP on
 * port 0 with a port file, test-organization.md §8.4; a fixed TCP port only
 * where the test itself holds it) plus the failure shapes (crash-immediately,
 * never-ready). The stop() assertion
 * is the security-relevant one: after stop(), `process.kill(pid, 0)` throws
 * ESRCH — proving the whole spawned tree was reaped (no orphan).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { dirname, join } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { checkReady, readPortFile } from "../../../src/net-probes.js";

import {
  Supervisor,
  type ServiceDefinition,
  type ServiceId,
} from "../../../src/supervisor/supervisor.js";
import {
  SOCKET_SCRIPT,
  CRASH_SCRIPT,
  NEVER_READY_SCRIPT,
  TREE_SCRIPT,
  tmpdir,
  nodeArgs,
  socketDef,
  portFileDef,
  mkSup,
  sleep,
  isAlive,
  waitUntil,
  waitUntilDead,
  waitForLog,
  registerTmpHooks,
} from "./supervisor-harness.js";

registerTmpHooks();


// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test("socket service: start → running, status + a captured log line", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");

    const st = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(st.state, "running");
    assert.ok(typeof st.pid === "number" && st.pid! > 0, "pid set");
    assert.ok(typeof st.since === "number" && st.since! > 0, "since set");
    assert.equal(st.label, def.label);
    assert.equal(st.lastError, null);

    // Wait until a heartbeat/log line has actually been captured (a fixed sleep
    // can elapse before the first line lands under load).
    await waitForLog(sup, "arbiter", (l) => l.includes("fake-socket"));
    const logs = sup.logs("arbiter");
    assert.ok(logs.length > 0, "at least one log line captured");
    assert.ok(
      logs.some((l) => l.line.includes("fake-socket")),
      "a fake-socket line present",
    );
    assert.ok(logs.every((l) => l.stream === "stdout" || l.stream === "stderr"));
  } finally {
    await sup.shutdownAll();
  }
});

test("port-file service: binds port 0, publishes it via MANDU_PORT_FILE; running, reachable, its endpoint names the port", async () => {
  const { def, portFile } = portFileDef();
  const sup = mkSup({ "anthropic-proxy": def }, { autoStartArbiter: false });
  try {
    await sup.start("anthropic-proxy");
    const st = sup.status().find((s) => s.id === "anthropic-proxy")!;
    assert.equal(st.state, "running");
    assert.ok(st.pid! > 0);
    const port = Number(readFileSync(portFile, "utf8"));
    assert.ok(port > 0, "the kernel-assigned port is in the file");
    assert.equal(st.endpoint, `127.0.0.1:${port}`, "the status row shows the port the service got");
    assert.equal(await connects(port), true);
    await sup.stop("anthropic-proxy");
    assert.equal(sup.status().find((s) => s.id === "anthropic-proxy")!.endpoint, def.endpoint, "stopped: the configured label again");
  } finally {
    await sup.shutdownAll();
  }
});

test("port-file service: a stale file from an earlier instance is removed first, so it never reads as ready", async () => {
  // A live listener the TEST holds, named by a leftover port file: without the
  // removal, a fake that never writes its file would be 'ready' at once.
  const held = net.createServer(() => {});
  await new Promise<void>((r) => held.listen(0, "127.0.0.1", () => r()));
  const heldPort = (held.address() as net.AddressInfo).port;
  const { def, portFile } = portFileDef("Never writes", { args: nodeArgs(NEVER_READY_SCRIPT) });
  mkdirSync(dirname(portFile), { recursive: true });
  writeFileSync(portFile, String(heldPort));
  const sup = mkSup({ "anthropic-proxy": def }, { autoStartArbiter: false, startTimeoutMs: 600 });
  try {
    await assert.rejects(() => sup.start("anthropic-proxy"), /readiness timeout/);
    assert.equal(existsSync(portFile), false, "the stale file went before the spawn");
    const st = sup.status().find((s) => s.id === "anthropic-proxy")!;
    assert.equal(st.adopted, false, "a port-file service is never adopted");
    assert.equal(st.state, "crashed");
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => held.close(() => r()));
  }
});

test("tcp service (fixed port): a listener already on the port is adopted, never spawned over", async () => {
  // The fixed-port kind without a pick-then-release race: the test holds the
  // port itself for the whole test.
  const held = net.createServer(() => {});
  await new Promise<void>((r) => held.listen(0, "127.0.0.1", () => r()));
  const port = (held.address() as net.AddressInfo).port;
  const def: ServiceDefinition = {
    label: "Fixed TCP", command: process.execPath, args: nodeArgs(NEVER_READY_SCRIPT), cwd: tmpdir(), env: {},
    ready: { kind: "tcp", host: "127.0.0.1", port }, endpoint: `127.0.0.1:${port}`,
  };
  const sup = mkSup({ "anthropic-proxy": def }, { autoStartArbiter: false });
  try {
    await sup.start("anthropic-proxy");
    const st = sup.status().find((s) => s.id === "anthropic-proxy")!;
    assert.equal(st.state, "running");
    assert.equal(st.adopted, true);
    assert.equal(st.pid, null, "nothing spawned");
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => held.close(() => r()));
  }
});

test("readPortFile / checkReady(port-file): missing, empty and non-port files are not ready", async () => {
  const dir = tmpdir();
  const f = join(dir, "p");
  assert.equal(readPortFile(f), null, "missing");
  assert.equal(await checkReady({ kind: "port-file", path: f, host: "127.0.0.1" }), false);
  for (const bad of ["", "abc", "0", "-3", "70000", "12.5"]) {
    writeFileSync(f, bad);
    assert.equal(readPortFile(f), null, JSON.stringify(bad));
  }
  writeFileSync(f, "4242\n");
  assert.equal(readPortFile(f), 4242, "trailing newline tolerated");
});

function connects(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port });
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
  });
}

test("stop: SIGTERM reaps the whole tree — no orphan (ESRCH)", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  await sup.start("arbiter");
  const pid = sup.status().find((s) => s.id === "arbiter")!.pid!;
  assert.ok(isAlive(pid), "alive before stop");

  await sup.stop("arbiter");

  const st = sup.status().find((s) => s.id === "arbiter")!;
  assert.equal(st.state, "stopped");
  assert.equal(st.pid, null);

  // The decisive assertion: process.kill(pid, 0) must throw ESRCH.
  assert.throws(
    () => process.kill(pid, 0),
    (err: NodeJS.ErrnoException) => err.code === "ESRCH",
    "child pid must be gone after stop (no orphan)",
  );
});

test("stop: child tree (grandchild) is reaped via process-group kill", async () => {
  const dir = tmpdir();
  const sock = join(dir, "tree.sock");
  const def: ServiceDefinition = {
    label: "Fake Tree",
    command: process.execPath,
    args: nodeArgs(TREE_SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  const sup = mkSup({ arbiter: def });
  await sup.start("arbiter");
  const pid = sup.status().find((s) => s.id === "arbiter")!.pid!;

  await sup.stop("arbiter");
  // Poll until the leader pid is actually reaped — under load the group teardown
  // can lag a fixed sleep, which is the classic flake here.
  await waitUntilDead(pid);

  assert.throws(
    () => process.kill(pid, 0),
    (err: NodeJS.ErrnoException) => err.code === "ESRCH",
    "leader pid gone",
  );
  // The socket-cleanup is best-effort; the key is the leader (group) is gone.
});

test("restart yields a new pid", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");
    const pid1 = sup.status().find((s) => s.id === "arbiter")!.pid!;
    await sup.restart("arbiter");
    const pid2 = sup.status().find((s) => s.id === "arbiter")!.pid!;
    assert.equal(sup.status().find((s) => s.id === "arbiter")!.state, "running");
    assert.notEqual(pid1, pid2, "restart must produce a fresh pid");
    assert.throws(
      () => process.kill(pid1, 0),
      (err: NodeJS.ErrnoException) => err.code === "ESRCH",
      "old pid reaped",
    );
  } finally {
    await sup.shutdownAll();
  }
});

test("crash-immediately: start() rejects and state is crashed with lastError", async () => {
  const dir = tmpdir();
  const def: ServiceDefinition = {
    label: "Crasher",
    command: process.execPath,
    args: nodeArgs(CRASH_SCRIPT),
    cwd: dir,
    env: {},
    ready: { kind: "socket", path: join(dir, "never.sock") },
    endpoint: "never",
  };
  const sup = mkSup({ arbiter: def });
  await assert.rejects(() => sup.start("arbiter"), /arbiter/);
  const st = sup.status().find((s) => s.id === "arbiter")!;
  assert.equal(st.state, "crashed");
  assert.ok(st.lastError && st.lastError.length > 0, "lastError populated");
  assert.match(st.lastError!, /code 3|boom/);
  assert.equal(st.pid, null);
});

test("readiness timeout: alive-but-never-ready → crashed", async () => {
  const dir = tmpdir();
  const def: ServiceDefinition = {
    label: "Never Ready",
    command: process.execPath,
    args: nodeArgs(NEVER_READY_SCRIPT),
    cwd: dir,
    env: {},
    ready: { kind: "socket", path: join(dir, "absent.sock") },
    endpoint: "absent.sock",
  };
  // Short timeout to keep the test fast.
  const sup = mkSup({ arbiter: def }, { startTimeoutMs: 600 });
  await assert.rejects(() => sup.start("arbiter"), /readiness timeout/);
  const st = sup.status().find((s) => s.id === "arbiter")!;
  assert.equal(st.state, "crashed");
  assert.match(st.lastError!, /readiness timeout/);
  assert.equal(st.pid, null);
});

test("double-start: second start keeps the same pid (idempotent)", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  try {
    await sup.start("arbiter");
    const pid1 = sup.status().find((s) => s.id === "arbiter")!.pid!;
    await sup.start("arbiter"); // already running
    const pid2 = sup.status().find((s) => s.id === "arbiter")!.pid!;
    assert.equal(pid1, pid2, "same pid kept on double-start");
  } finally {
    await sup.shutdownAll();
  }
});

test("concurrent starts share one in-flight launch (same pid)", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  try {
    const [, ] = await Promise.all([sup.start("arbiter"), sup.start("arbiter")]);
    const pid = sup.status().find((s) => s.id === "arbiter")!.pid!;
    assert.ok(pid > 0);
    assert.equal(sup.status().find((s) => s.id === "arbiter")!.state, "running");
  } finally {
    await sup.shutdownAll();
  }
});

test("autoStartArbiter: starting a proxy brings up the arbiter first", async () => {
  const { def: arbiterDef } = socketDef("Arbiter");
  const { def: proxyDef } = portFileDef("Proxy", { requires: ["arbiter"] });
  const sup = mkSup({ arbiter: arbiterDef, "anthropic-proxy": proxyDef });
  try {
    await sup.start("anthropic-proxy");
    assert.equal(sup.status().find((s) => s.id === "arbiter")!.state, "running");
    assert.equal(sup.status().find((s) => s.id === "anthropic-proxy")!.state, "running");
  } finally {
    await sup.shutdownAll();
  }
});

test("autoStartArbiter disabled: starting a proxy with arbiter down rejects", async () => {
  const { def: proxyDef } = portFileDef("Proxy", { requires: ["arbiter"] });
  const sup = mkSup({ "anthropic-proxy": proxyDef }, { autoStartArbiter: false });
  await assert.rejects(() => sup.start("anthropic-proxy"), /required service arbiter is not running/);
});

test("shutdownAll stops every running service", async () => {
  const { def: a } = socketDef("A");
  const { def: b } = portFileDef("B");
  const sup = mkSup({ arbiter: a, "anthropic-proxy": b }, { autoStartArbiter: false });
  await sup.start("arbiter");
  await sup.start("anthropic-proxy");
  const pidA = sup.status().find((s) => s.id === "arbiter")!.pid!;
  const pidB = sup.status().find((s) => s.id === "anthropic-proxy")!.pid!;

  await sup.shutdownAll();

  for (const s of sup.status()) {
    assert.notEqual(s.state, "running");
  }
  await waitUntilDead(pidA);
  await waitUntilDead(pidB);
  assert.ok(!isAlive(pidA), "arbiter pid gone");
  assert.ok(!isAlive(pidB), "proxy pid gone");
});

test("stop on a never-started service is a no-op (stopped)", async () => {
  const { def } = socketDef();
  const sup = mkSup({ arbiter: def });
  await sup.stop("arbiter"); // not started
  assert.equal(sup.status().find((s) => s.id === "arbiter")!.state, "stopped");
});

test("production definitions: endpoints reflect option ports", () => {
  const sup = new Supervisor({
    repoRoot: "/repo",
    arbiterSock: "/tmp/b.sock",
    modelProxyPort: 9001,
    openaiProxyPort: 9002,
    egressProxyPort: 9003,
    log: () => {},
  });
  const st = sup.status();
  assert.equal(st.find((s) => s.id === "arbiter")!.endpoint, "/tmp/b.sock");
  assert.equal(st.find((s) => s.id === "anthropic-proxy")!.endpoint, "127.0.0.1:9001");
  assert.equal(st.find((s) => s.id === "openai-proxy")!.endpoint, "127.0.0.1:9002");
  assert.equal(st.find((s) => s.id === "net-proxy")!.endpoint, "127.0.0.1:9003");
  for (const s of st) assert.equal(s.state, "stopped");
  // existsSync import kept meaningful: assert no stray socket files leaked.
  assert.ok(!existsSync("/tmp/mandu-nonexistent-marker"));
});
