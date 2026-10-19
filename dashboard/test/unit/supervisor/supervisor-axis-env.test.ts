/**
 * supervisor-axis-env.test — the supervisor's ARBITER-spawn axis plumbing
 * (dashboard.md §4.19: config.toml integrity/confidentiality →
 * MANDU_INTEGRITY/MANDU_CONFIDENTIALITY in the spawn env).
 *
 * Mandu-new test (NO reference origin); follows supervisor-harness.ts's
 * fake-service conventions (real spawns of `node -e` scripts, temp sockets).
 * The PURE precedence rules (explicit env wins, config fills only unset keys,
 * both absent → nothing) are pinned in config-axes.test.ts on
 * arbiterAxisSpawnEnv; THIS suite pins the WIRING — the part §4.19 calls the
 * "posture nobody runs" guard:
 *   - the axisEnv fill actually lands in the ARBITER child's environment;
 *   - it is recomputed AT SPAWN TIME (a config change lands on the next
 *     restart, not frozen at supervisor construction);
 *   - non-arbiter services never receive the fill;
 *   - the service definition's own env still wins over the fill (merge order
 *     process.env < axisFill < def.env).
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
  const d = tmpDir("mandu-axis-env-");
  tmpDirs.push(d);
  return d;
}

/** A fake service that DUMPS the axis env vars it sees to DUMP_FILE, then
 *  opens its readiness socket (so start() resolves only after the dump). */
const DUMP_SCRIPT = `
const net = require('net');
const fs = require('fs');
fs.writeFileSync(process.env.DUMP_FILE, JSON.stringify({
  integrity: process.env.MANDU_INTEGRITY ?? null,
  confidentiality: process.env.MANDU_CONFIDENTIALITY ?? null,
}));
const sock = process.env.FAKE_SOCK;
try { fs.unlinkSync(sock); } catch {}
const srv = net.createServer(() => {});
srv.listen(sock, () => { process.stdout.write('dump: listening\\n'); });
setInterval(() => {}, 1e9);
`;

function dumpDef(extraEnv: NodeJS.ProcessEnv = {}): { def: ServiceDefinition; dumpFile: string } {
  const dir = tmpdir();
  const sock = join(dir, "fake.sock");
  const dumpFile = join(dir, "env-dump.json");
  const def: ServiceDefinition = {
    label: "Env dump",
    command: process.execPath,
    args: ["-e", DUMP_SCRIPT],
    cwd: dir,
    env: { FAKE_SOCK: sock, DUMP_FILE: dumpFile, ...extraEnv },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
  };
  return { def, dumpFile };
}

function readDump(dumpFile: string): { integrity: string | null; confidentiality: string | null } {
  return JSON.parse(readFileSync(dumpFile, "utf8")) as ReturnType<typeof readDump>;
}

test("the axisEnv fill lands in the ARBITER child's environment, recomputed per spawn", async () => {
  // The test process itself must not carry the axis vars, or the ...process.env
  // spread would mask what the fill contributes.
  delete process.env.MANDU_INTEGRITY;
  delete process.env.MANDU_CONFIDENTIALITY;

  const { def, dumpFile } = dumpDef();
  let fill: Record<string, string> = { MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" };
  const axisCalls: NodeJS.ProcessEnv[] = [];
  const sup = new Supervisor({
    repoRoot: tmpdir(),
    arbiterSock: def.ready.kind === "socket" ? def.ready.path : "",
    startTimeoutMs: 8000,
    stopGraceMs: 800,
    definitions: { arbiter: def },
    axisEnv: (processEnv) => {
      axisCalls.push(processEnv);
      return fill;
    },
    log: () => {},
  });

  try {
    await sup.start("arbiter");
    assert.deepEqual(readDump(dumpFile), { integrity: "0", confidentiality: "1" });
    assert.equal(axisCalls.length, 1, "axisEnv consulted once per spawn");
    assert.equal(axisCalls[0], process.env, "consulted against the live process env");

    // SPAWN-TIME recompute: a config edit between restarts must land — the
    // §4.19 drawer's whole promise ("restart the protection service to apply").
    fill = { MANDU_INTEGRITY: "1" };
    await sup.stop("arbiter");
    await sup.start("arbiter");
    assert.deepEqual(
      readDump(dumpFile),
      { integrity: "1", confidentiality: null },
      "the second spawn saw the NEW fill, and nothing stale from the first",
    );
    assert.equal(axisCalls.length, 2);
  } finally {
    await sup.shutdownAll();
  }
});

test("non-arbiter services never receive the axis fill", async () => {
  delete process.env.MANDU_INTEGRITY;
  delete process.env.MANDU_CONFIDENTIALITY;

  const arbiter = dumpDef();
  const proxy = dumpDef();
  // The proxy def must not require the arbiter for this test's focus — it
  // doesn't: definitions built by hand carry no `requires`.
  const sup = new Supervisor({
    repoRoot: tmpdir(),
    arbiterSock: arbiter.def.ready.kind === "socket" ? arbiter.def.ready.path : "",
    startTimeoutMs: 8000,
    stopGraceMs: 800,
    definitions: { arbiter: arbiter.def, "net-proxy": proxy.def },
    axisEnv: () => ({ MANDU_INTEGRITY: "0" }),
    log: () => {},
  });

  try {
    await sup.start("net-proxy");
    assert.deepEqual(
      readDump(proxy.dumpFile),
      { integrity: null, confidentiality: null },
      "the fill is arbiter-only (the axes are boot flags the ARBITER reads)",
    );
  } finally {
    await sup.shutdownAll();
  }
});

test("the service definition's own env wins over the axis fill (merge order)", async () => {
  delete process.env.MANDU_INTEGRITY;
  delete process.env.MANDU_CONFIDENTIALITY;

  // def.env pins MANDU_INTEGRITY; the fill tries to set both. def.env last.
  const { def, dumpFile } = dumpDef({ MANDU_INTEGRITY: "1" });
  const sup = new Supervisor({
    repoRoot: tmpdir(),
    arbiterSock: def.ready.kind === "socket" ? def.ready.path : "",
    startTimeoutMs: 8000,
    stopGraceMs: 800,
    definitions: { arbiter: def },
    axisEnv: () => ({ MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" }),
    log: () => {},
  });

  try {
    await sup.start("arbiter");
    assert.deepEqual(readDump(dumpFile), { integrity: "1", confidentiality: "1" });
  } finally {
    await sup.shutdownAll();
  }
});

test("a throwing axisEnv reader degrades to no fill (arbiter defaults), never a failed start", async () => {
  delete process.env.MANDU_INTEGRITY;
  delete process.env.MANDU_CONFIDENTIALITY;

  const { def, dumpFile } = dumpDef();
  const logs: string[] = [];
  const sup = new Supervisor({
    repoRoot: tmpdir(),
    arbiterSock: def.ready.kind === "socket" ? def.ready.path : "",
    startTimeoutMs: 8000,
    stopGraceMs: 800,
    definitions: { arbiter: def },
    axisEnv: () => {
      throw new Error("config unreadable");
    },
    log: (m) => logs.push(m),
  });

  try {
    await sup.start("arbiter");
    assert.deepEqual(readDump(dumpFile), { integrity: null, confidentiality: null });
    assert.ok(
      logs.some((l) => /axis config read failed/.test(l)),
      "the degradation is logged, not silent",
    );
  } finally {
    await sup.shutdownAll();
  }
});
