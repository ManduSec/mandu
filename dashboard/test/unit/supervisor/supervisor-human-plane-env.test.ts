/**
 * supervisor-human-plane-env.test — the supervisor hands a service that
 * requires the arbiter the arbiter's HUMAN-PLANE socket
 * (docs/design/architecture/arbiter-human-plane.md): MANDU_ARBITER_HUMAN_SOCK is read from
 * the live instance's `hello().humanSock` AT SPAWN, never from a stale value
 * this process carries, and is BLANK (never the data socket) when the arbiter
 * names none.
 *
 * Mandu-new test (NO reference origin); follows supervisor-axis-env.test's
 * fake-service conventions (real spawns of `node -e` scripts, temp sockets).
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync } from "node:fs";
import os from "node:os";
import { join } from "node:path";

import { Supervisor, type ServiceDefinition } from "../../../src/supervisor/supervisor.js";
import { tmpDir } from "../tmp-dir.js";

const tmpDirs: string[] = [];
after(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

function tmpdir(): string {
  const d = tmpDir("mandu-human-env-");
  tmpDirs.push(d);
  return d;
}

/** A fake ARBITER: answers `hello` with HUMAN_SOCK (or no humanSock at all). */
const ARBITER_SCRIPT = `
const net = require('net');
const fs = require('fs');
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer((c) => {
  let buf = '';
  c.on('data', (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf('\\n')) >= 0) {
      const req = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1);
      const result = { pid: process.pid, startedAt: 'x', instanceId: 'fake', gitRev: 'nogit', gitDirty: false,
        sockPath: sock, eventDir: '', symbolDb: '' };
      if (process.env.HUMAN_SOCK) result.humanSock = process.env.HUMAN_SOCK;
      c.write(JSON.stringify({ id: req.id, ok: true, result }) + '\\n');
    }
  });
  c.on('error', () => {});
});
srv.listen(sock);
setInterval(() => {}, 1e9);
`;

/** A fake service that dumps MANDU_ARBITER_HUMAN_SOCK, then opens its socket. */
const DUMP_SCRIPT = `
const net = require('net');
const fs = require('fs');
fs.writeFileSync(process.env.DUMP_FILE, JSON.stringify({ human: process.env.MANDU_ARBITER_HUMAN_SOCK ?? null }));
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
net.createServer(() => {}).listen(sock);
setInterval(() => {}, 1e9);
`;

function rig(humanSock: string | null): { sup: Supervisor; dumpFile: string } {
  const dir = tmpdir();
  const arbSock = join(dir, "arb.sock");
  const proxySock = join(dir, "proxy.sock");
  const dumpFile = join(dir, "dump.json");
  const arbiter: ServiceDefinition = {
    label: "Fake arbiter",
    command: process.execPath,
    args: ["-e", ARBITER_SCRIPT],
    cwd: dir,
    env: { FAKE_SOCK: arbSock, ...(humanSock ? { HUMAN_SOCK: humanSock } : {}) },
    ready: { kind: "socket", path: arbSock },
    endpoint: arbSock,
  };
  const proxy: ServiceDefinition = {
    label: "Dump proxy",
    command: process.execPath,
    args: ["-e", DUMP_SCRIPT],
    cwd: dir,
    env: { FAKE_SOCK: proxySock, DUMP_FILE: dumpFile },
    ready: { kind: "socket", path: proxySock },
    endpoint: proxySock,
    requires: ["arbiter"],
  };
  const sup = new Supervisor({
    repoRoot: dir,
    arbiterSock: arbSock,
    startTimeoutMs: 8000,
    stopGraceMs: 800,
    definitions: { arbiter, "net-proxy": proxy },
    axisEnv: () => ({}),
    log: () => {},
  });
  return { sup, dumpFile };
}

test("a service that requires the arbiter gets the human socket the arbiter names in hello", async () => {
  // A stale value in the dashboard's own env must not win over hello.
  process.env.MANDU_ARBITER_HUMAN_SOCK = "/stale/human.sock";
  const { sup, dumpFile } = rig("/run/fake/mandu/human/inst.sock");
  try {
    await sup.start("net-proxy");
    assert.deepEqual(JSON.parse(readFileSync(dumpFile, "utf8")), { human: "/run/fake/mandu/human/inst.sock" });
  } finally {
    await sup.shutdownAll();
    delete process.env.MANDU_ARBITER_HUMAN_SOCK;
  }
});

test("an arbiter that names no human socket → the service gets it BLANK (never a stale value, never the data socket)", async () => {
  process.env.MANDU_ARBITER_HUMAN_SOCK = "/stale/human.sock";
  const { sup, dumpFile } = rig(null);
  try {
    await sup.start("net-proxy");
    assert.deepEqual(JSON.parse(readFileSync(dumpFile, "utf8")), { human: "" });
  } finally {
    await sup.shutdownAll();
    delete process.env.MANDU_ARBITER_HUMAN_SOCK;
  }
});
