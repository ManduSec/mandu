/**
 * supervisor-harness — the shared fixtures for the supervisor unit suites
 * (supervisor.test.ts lifecycle, supervisor-logs.test.ts, supervisor-adopt.test.ts).
 *
 * Extracted from supervisor.test.ts (agent-legibility split) so the 800-line
 * suite can be partitioned by feature area: the fake-service node scripts
 * (spawned via `node -e`), the ServiceDefinition/Supervisor factories, and the
 * poll-an-observable wait helpers that keep the assertions robust under
 * full-suite CPU load.
 */

import { test } from "node:test";
import os from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";

import {
  Supervisor,
  type ServiceDefinition,
  type ServiceId,
} from "../../../src/supervisor/supervisor.js";
import { tmpDir } from "../tmp-dir.js";

// ─────────────────────────────────────────────────────────────────────────────
// Fake-service node scripts (spawned via process.execPath -e <script>)
// ─────────────────────────────────────────────────────────────────────────────

/** Listens on a Unix socket (FAKE_SOCK) and emits a heartbeat line to stdout. */
export const SOCKET_SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer(() => {});
srv.listen(sock, () => { process.stdout.write('fake-socket: listening\\n'); });
setInterval(() => { process.stdout.write('fake-socket: heartbeat\\n'); }, 50);
setInterval(() => {}, 1e9);
`;

/**
 * Binds 127.0.0.1 on port 0 and publishes the port it got to MANDU_PORT_FILE
 * (tmp + rename, as the proxies and the dashboard do), then emits a heartbeat.
 * The supervisor's `port-file` readiness (test-organization.md §8.4): no port
 * is picked and released before the fake starts, so a suite running alongside
 * cannot take it.
 */
export const PORT_FILE_SCRIPT = `
const net = require('net');
const fs = require('fs');
const file = process.env.MANDU_PORT_FILE;
const srv = net.createServer(() => {});
srv.listen(0, '127.0.0.1', () => {
  const port = srv.address().port;
  fs.writeFileSync(file + '.tmp', String(port));
  fs.renameSync(file + '.tmp', file);
  process.stdout.write('fake-tcp: listening on ' + port + '\\n');
});
setInterval(() => { process.stdout.write('fake-tcp: heartbeat\\n'); }, 50);
setInterval(() => {}, 1e9);
`;

/**
 * Opens its readiness socket, THEN writes 600 numbered lines "line0".."line599"
 * to stdout. Used to prove the in-memory ring caps WELL above the old 500 (so the
 * earliest "line0" survives a 600-line burst).
 */
export const BURST_SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer(() => {});
srv.listen(sock, () => {
  process.stdout.write('burst: listening\\n');
  let s = '';
  for (let i = 0; i < 600; i++) s += 'line' + i + '\\n';
  process.stdout.write(s);
});
setInterval(() => {}, 1e9);
`;

/** Exits immediately with a non-zero code (crash before ready). */
export const CRASH_SCRIPT = `process.stderr.write('boom\\n'); process.exit(3);`;

/** Stays alive but NEVER opens its readiness endpoint (→ readiness timeout). */
export const NEVER_READY_SCRIPT = `setInterval(() => {}, 1e9);`;

/**
 * A fake that forks a long-lived grandchild that does NOT share stdio, to prove
 * the process-GROUP kill reaps the whole tree (not just the direct child).
 */
export const TREE_SCRIPT = `
const net = require('net');
const fs = require('fs');
const { spawn } = require('child_process');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
// Grandchild: a detached-ish long sleeper in the same process group.
spawn(process.execPath, ['-e', 'setInterval(()=>{},1e9)'], { stdio: 'ignore' });
const srv = net.createServer(() => {});
srv.listen(sock, () => { process.stdout.write('fake-tree: listening\\n'); });
setInterval(() => {}, 1e9);
`;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

export let tmpRoot: string;
const tmpDirs: string[] = [];

export function tmpdir(): string {
  const d = tmpDir("mandu-sup-");
  tmpDirs.push(d);
  return d;
}

export function nodeArgs(script: string): string[] {
  return ["-e", script];
}

/** A socket-ready fake-service definition with a fresh temp socket path. */
export function socketDef(label = "Fake Socket"): { def: ServiceDefinition; sock: string } {
  const dir = tmpdir();
  const sock = join(dir, "fake.sock");
  const def: ServiceDefinition = {
    label,
    command: process.execPath,
    args: nodeArgs(SOCKET_SCRIPT),
    cwd: dir,
    env: { FAKE_SOCK: sock },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  return { def, sock };
}

/** A TCP fake with `port-file` readiness: it binds port 0 and writes its
 *  port to the file the supervisor names in MANDU_PORT_FILE. */
export function portFileDef(
  label = "Fake TCP",
  extra: Partial<ServiceDefinition> = {},
): { def: ServiceDefinition; portFile: string } {
  const dir = tmpdir();
  const portFile = join(dir, "run", "fake.port");
  const def: ServiceDefinition = {
    label,
    command: process.execPath,
    args: nodeArgs(PORT_FILE_SCRIPT),
    cwd: dir,
    env: {},
    ready: { kind: "port-file", path: portFile, host: "127.0.0.1" },
    endpoint: "127.0.0.1 (port 0)",
    ...extra,
  };
  return { def, portFile };
}

/** Standard options pointing all three ids at injectable fakes. */
export function mkSup(
  definitions: Partial<Record<ServiceId, ServiceDefinition>>,
  overrides: Partial<ConstructorParameters<typeof Supervisor>[0]> = {},
): Supervisor {
  return new Supervisor({
    repoRoot: tmpRoot,
    arbiterSock: join(tmpRoot, "arbiter.sock"),
    startTimeoutMs: 4000,
    stopGraceMs: 800,
    definitions,
    log: () => {},
    ...overrides,
  });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return false;
    return true; // EPERM etc. → still exists
  }
}

/**
 * Poll `pred()` until true or throw after timeoutMs. Used to replace fixed-delay
 * waits: under CPU contention a child-process teardown (or a log line landing in
 * the ring) can take noticeably longer than a hard-coded sleep, which is exactly
 * what makes these tests flake under full-suite load. Polling an OBSERVABLE with
 * a GENEROUS deadline keeps the assertion strict while staying robust under load.
 */
export async function waitUntil(
  pred: () => boolean,
  timeoutMs = 8000,
  label = "condition",
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) {
      throw new Error(`waitUntil(${label}) timed out after ${timeoutMs}ms`);
    }
    await sleep(20);
  }
}

/** Poll until process.kill(pid, 0) reports the pid is gone (ESRCH). */
export function waitUntilDead(pid: number, timeoutMs = 8000): Promise<void> {
  return waitUntil(() => !isAlive(pid), timeoutMs, `pid ${pid} dead`);
}

/** Poll until the service's ring buffer contains a line matching `pred`. */
export function waitForLog(
  sup: Supervisor,
  id: ServiceId,
  pred: (line: string) => boolean,
  timeoutMs = 8000,
): Promise<void> {
  return waitUntil(
    () => sup.logs(id).some((l) => pred(l.line)),
    timeoutMs,
    `log on ${id}`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Setup / teardown — each supervisor-*.test.ts file (its own tsx process) calls
// this once at top level to get the shared tmp root + cleanup.
// ─────────────────────────────────────────────────────────────────────────────

export function registerTmpHooks(): void {
  test.before(() => {
    tmpRoot = tmpDir("mandu-sup-root-");
    tmpDirs.push(tmpRoot);
  });
  test.after(() => {
    for (const d of tmpDirs) {
      try {
        rmSync(d, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  });
}
