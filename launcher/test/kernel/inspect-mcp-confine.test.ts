/**
 * inspect-mcp-confine.test — E2E: the MCP config the launcher writes runs
 * inspect-mcp under a kernel TCP confine (confidentiality-plan-11 §8 item 5;
 * inspect-net-confine.ts).
 *
 * Leg 1 (always): `writeMcpConfig` for a plan whose manager decided the
 * confine; the file on disk carries the wrapped argv, and the Codex splice
 * built from the same doc too.
 *
 * Leg 2 (kernel, self-SKIPs without the applier bin or Landlock TCP rules):
 * the REAL applier resolution + kernel probe decide the wrap for a plan whose
 * forwarder, declared local endpoint, model proxy and net-proxy are four
 * real loopback listeners. The prefix written into the config is then run for
 * real in front of a Node probe (a stand-in for the server: the same runtime,
 * nonblocking connects): the forwarder and the endpoint connect, the model
 * proxy and the net-proxy are refused in-kernel (EACCES).
 *
 * Leg 3 (kernel + the connect guard bin): the default posture. The same
 * prefix nested inside the whole-agent wraps (`mandu-net-guard` allowing all
 * four ports, then the whole-agent `--net-only` wrap allowing all four): the
 * guard performs every allowed connect itself, and it must honor the nested
 * confine (net-supervisor landlock_mirror "CONNECTS"), so the answer is the
 * same as leg 2.
 *
 * Leg 4 (kernel): a `local: true` endpoint declared after launch. The port
 * set is fixed when the config is written, so the new port is refused
 * in-kernel, alone and nested under outer wraps that allow it.
 *
 * Leg 5 (kernel): two `local: true` entries, the second marked `helper:
 * true`. Only the helper's entry is dialed (inspect-mcp `helperEndpoint`), so
 * only its port is in the confine: the other local entry is refused
 * in-kernel, and the whole-agent port set leaves it out too (least
 * privilege, model-endpoints.ts `helperEndpointPorts`).
 *
 * Axes: the confine narrows a process's network whatever the mode; `secrets`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planInspectNetConfine } from "../../src/inspect-net-confine.js";
import { helperEndpointGuardSpecs, helperEndpointPorts } from "../../src/model-endpoints.js";
import { computeLandlockNetPorts, planLandlockNet } from "../../src/landlock-net.js";
import { planNetGuard } from "../../src/net-guard.js";
import { codexMcpOverrides } from "../../src/env-compose.js";
import { mcpConfigDoc, writeMcpConfig } from "../../src/services/mcp.js";
import { Layout } from "../../src/services/layout.js";
import { resolveNativeBin } from "../../src/services/native-bins.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: ["curl"], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

function withRunDir<T>(f: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "inspect-confine-e2e-"));
  const saved = process.env["MANDU_MCP_CONFIG"];
  delete process.env["MANDU_MCP_CONFIG"];
  try { return f(dir); } finally {
    if (saved !== undefined) process.env["MANDU_MCP_CONFIG"] = saved;
    rmSync(dir, { recursive: true, force: true });
  }
}

test("leg 1: the written MCP config runs inspect-mcp under the confine; Codex's splice carries it too", () => {
  const applier = "/opt/mandu/native/mandu-landlock-apply";
  const p = plan({
    ullmForwarder: { host: "127.0.0.1", port: 41001 },
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude", forwarderUrl: "http://127.0.0.1:41001" },
    netProxy: { host: "127.0.0.1", port: 41003 },
    modelEndpoints: [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true }],
  });
  const r = planInspectNetConfine(p, { resolveBin: () => applier, staleNote: () => null, probeNet: () => true, log: () => {} });
  assert.ok(r);
  p.inspectMcpWrap = r.wrapArgv;
  withRunDir((dir) => {
    const path = writeMcpConfig(p, Layout.dev("/repo"), dir);
    const doc = JSON.parse(readFileSync(path, "utf8")) as { mcpServers: Record<string, { command: string; args: string[]; env: Record<string, string> }> };
    const inspect = doc.mcpServers["mandu-inspect"]!;
    assert.equal(inspect.command, applier);
    const sep = inspect.args.indexOf("--");
    assert.deepEqual(inspect.args.slice(0, sep + 1), ["--net-only", "--allow-tcp-port", "11434", "--allow-tcp-port", "41001", "--"], "strict: no --skip-unsupported after a passed probe");
    assert.ok(inspect.args.slice(sep + 1).some((a) => a.endsWith("server-main.ts")), "the server follows the separator");
    for (const forbidden of ["8788", "8789", "41003", "22", "443"]) {
      assert.ok(!inspect.args.slice(0, sep).includes(forbidden), `port ${forbidden} is not in the confine`);
    }
    assert.equal(inspect.env["MANDU_ULLM_FORWARDER"], "http://127.0.0.1:41001", "the env is today's");
    assert.notEqual(doc.mcpServers["mandu-policy"]!.command, applier);
  });
  const codexPlan: LaunchPlan = { ...p, target: "codex" };
  const codex = codexMcpOverrides(mcpConfigDoc(codexPlan, Layout.dev("/repo")).mcpServers);
  assert.ok(codex.includes(`mcp_servers.mandu-inspect.command="${applier}"`));
});

// ── the kernel legs ──────────────────────────────────────────────────────────

async function listen(): Promise<{ server: Server; port: number }> {
  const server = createServer((s) => s.destroy());
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  return { server, port: typeof addr === "object" && addr ? addr.port : 0 };
}

/** A Node process that connects to each port and reports `port:OK|<errno>`. */
const PROBE = `
const net = require("net");
const ports = process.argv.slice(1).map(Number);
Promise.all(ports.map((p) => new Promise((r) => {
  const s = net.connect({ host: "127.0.0.1", port: p });
  const t = setTimeout(() => { s.destroy(); r(p + ":TIMEOUT"); }, 3000);
  s.on("connect", () => { clearTimeout(t); s.destroy(); r(p + ":OK"); });
  s.on("error", (e) => { clearTimeout(t); r(p + ":" + (e.code || e.message)); });
}))).then((out) => { process.stdout.write(out.join(" ")); });
`;

function runUnder(prefix: string[], ports: number[]): Map<number, string> {
  const r = spawnSync(prefix[0]!, [...prefix.slice(1), process.execPath, "-e", PROBE, ...ports.map(String)], { encoding: "utf8", timeout: 30_000 });
  assert.equal(r.status, 0, `probe under the wrap failed: ${r.stderr}`);
  return new Map(r.stdout.trim().split(" ").map((kv) => { const [p, v] = kv.split(":"); return [Number(p), v!]; }));
}

async function kernelRig(opts: { otherLocal?: number } = {}) {
  const applier = resolveNativeBin("mandu-landlock-apply");
  if (!applier) return { skip: "mandu-landlock-apply is not built (scripts/build-native.sh)" } as const;
  const fwd = await listen();
  const endpoint = await listen();
  const modelProxy = await listen();
  const netProxy = await listen();
  // With `otherLocal`, a second `local: true` entry listed FIRST, and the
  // rig's endpoint marked as the helper's.
  const modelEndpoints = opts.otherLocal === undefined
    ? [{ name: "ollama", url: `http://127.0.0.1:${endpoint.port}`, wire: "openai-chat" as const, model: "llama3.2", local: true }]
    : [
      { name: "main", url: `http://127.0.0.1:${opts.otherLocal}/v1`, wire: "openai-chat" as const, model: "gpt-oss:20b", local: true },
      { name: "ollama", url: `http://127.0.0.1:${endpoint.port}`, wire: "openai-chat" as const, model: "llama3.2", local: true, helper: true as const },
    ];
  const p = plan({
    proxy: { host: "127.0.0.1", port: modelProxy.port },
    netProxy: { host: "127.0.0.1", port: netProxy.port },
    ullmForwarder: { host: "127.0.0.1", port: fwd.port },
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude", forwarderUrl: `http://127.0.0.1:${fwd.port}` },
    modelEndpoints,
  });
  const notes: string[] = [];
  // The REAL resolver and the REAL kernel probe.
  const r = planInspectNetConfine(p, { log: (m) => notes.push(m) });
  const close = () => { for (const l of [fwd, endpoint, modelProxy, netProxy]) l.server.close(); };
  if (!r) {
    close();
    return { skip: `the confine degraded on this host: ${notes.join(" | ")}` } as const;
  }
  p.inspectMcpWrap = r.wrapArgv;
  // The prefix exactly as written into the MCP config.
  const prefix = withRunDir((dir) => {
    const doc = JSON.parse(readFileSync(writeMcpConfig(p, Layout.dev("/repo"), dir), "utf8")) as { mcpServers: Record<string, { command: string; args: string[] }> };
    const s = doc.mcpServers["mandu-inspect"]!;
    return [s.command, ...s.args.slice(0, s.args.indexOf("--") + 1)];
  });
  return { applier, p, prefix, close, ports: { fwd: fwd.port, endpoint: endpoint.port, modelProxy: modelProxy.port, netProxy: netProxy.port } } as const;
}

function assertConfined(got: Map<number, string>, ports: { fwd: number; endpoint: number; modelProxy: number; netProxy: number }): void {
  assert.equal(got.get(ports.fwd), "OK", "the U-LLM forwarder is reachable");
  assert.equal(got.get(ports.endpoint), "OK", "the declared local endpoint is reachable");
  assert.equal(got.get(ports.modelProxy), "EACCES", "the model proxy is refused in-kernel");
  assert.equal(got.get(ports.netProxy), "EACCES", "the net-proxy is refused in-kernel");
}

test("leg 2 (kernel): the written prefix confines the process: forwarder + endpoint yes, model proxy + net-proxy no", async (t) => {
  const rig = await kernelRig();
  if ("skip" in rig) { t.skip(rig.skip); return; }
  try {
    const all = [rig.ports.fwd, rig.ports.endpoint, rig.ports.modelProxy, rig.ports.netProxy];
    const bare = runUnder(["env"], all);
    for (const p of all) assert.equal(bare.get(p), "OK", "baseline: every listener answers without the wrap");
    assertConfined(runUnder(rig.prefix, all), rig.ports);
  } finally {
    rig.close();
  }
});

test("leg 3 (kernel + guard): nested in the default posture's wraps, the confine still holds", async (t) => {
  const rig = await kernelRig();
  if ("skip" in rig) { t.skip(rig.skip); return; }
  const guard = resolveNativeBin("mandu-net-guard");
  if (!guard) { rig.close(); t.skip("mandu-net-guard is not built (scripts/build-native.sh)"); return; }
  try {
    const all = [rig.ports.fwd, rig.ports.endpoint, rig.ports.modelProxy, rig.ports.netProxy];
    // The whole-agent wraps as the launcher composes them: guard outermost,
    // then the port wrap (both allow all four), then the agent's child.
    const { wrapArgv: guardArgv } = planNetGuard({ binPath: guard, specs: all.map((p) => `tcp:127.0.0.1:${p}`) });
    const wholePorts = computeLandlockNetPorts({ targetProxyPort: rig.ports.modelProxy, netProxyPort: rig.ports.netProxy, ullmForwarderPort: rig.ports.fwd, modelEndpointPorts: [rig.ports.endpoint], strict: true });
    const { wrapArgv: wholeArgv } = planLandlockNet({ applierPath: rig.applier, ports: wholePorts });
    // Baseline inside the whole-agent wraps: the agent itself reaches all four.
    const outer = runUnder([...guardArgv, ...wholeArgv, "env"], all);
    for (const p of all) assert.equal(outer.get(p), "OK", `the agent reaches ${p} (the guard allows it)`);
    // The inspect server is the agent's CHILD (its own process), like live.
    const nested = runUnder([...guardArgv, ...wholeArgv, "/bin/sh", "-c", '"$@"; exit $?', "sh", ...rig.prefix], all);
    assertConfined(nested, rig.ports);
  } finally {
    rig.close();
  }
});

test("leg 4 (kernel): an endpoint declared AFTER launch is outside the launch-time confine, even when the outer wraps allow it", async (t) => {
  // plan 11 §8 item 5 fixes the port set when the MCP config is written; a
  // `local: true` entry added to policy.yaml mid-session is not in it. The
  // failure must be closed: inspect-mcp's connect to the new port is refused
  // in-kernel (it then refuses the call; nothing moves to the default U-LLM,
  // tests/sandbox/endpoint-added-mid-session.test.ts).
  const rig = await kernelRig();
  if ("skip" in rig) { t.skip(rig.skip); return; }
  const late = await listen();
  try {
    assert.ok(!rig.prefix.includes(String(late.port)), "the late port is not in the written prefix");
    const all = [rig.ports.fwd, rig.ports.endpoint, late.port];
    assert.equal(runUnder(["env"], all).get(late.port), "OK", "baseline: the late endpoint answers without the wrap");
    const got = runUnder(rig.prefix, all);
    assert.equal(got.get(rig.ports.endpoint), "OK", "the launch-time endpoint stays reachable");
    assert.equal(got.get(late.port), "EACCES", "the late endpoint is refused in-kernel");

    // Nested in whole-agent wraps that DO allow the late port (say the user
    // re-ran with --landlock-net=<port>): the inspect confine alone refuses it.
    const guard = resolveNativeBin("mandu-net-guard");
    if (guard) {
      const outerPorts = [...all, rig.ports.modelProxy, rig.ports.netProxy];
      const { wrapArgv: guardArgv } = planNetGuard({ binPath: guard, specs: outerPorts.map((p) => `tcp:127.0.0.1:${p}`) });
      const { wrapArgv: wholeArgv } = planLandlockNet({ applierPath: rig.applier, ports: [...outerPorts].sort((a, b) => a - b) });
      assert.equal(runUnder([...guardArgv, ...wholeArgv, "env"], [late.port]).get(late.port), "OK", "the agent itself reaches it");
      const nested = runUnder([...guardArgv, ...wholeArgv, "/bin/sh", "-c", '"$@"; exit $?', "sh", ...rig.prefix], all);
      assert.equal(nested.get(late.port), "EACCES", "the nested inspect confine refuses it under the guard too");
      assert.equal(nested.get(rig.ports.endpoint), "OK");
    }
  } finally {
    late.server.close();
    rig.close();
  }
});

test("leg 5 (kernel): only the helper's entry is in the confine; another local entry is refused in-kernel", async (t) => {
  const other = await listen();
  const rig = await kernelRig({ otherLocal: other.port });
  if ("skip" in rig) { other.server.close(); t.skip(rig.skip); return; }
  try {
    assert.ok(!rig.prefix.includes(String(other.port)), "the other local entry's port is not in the written prefix");
    const endpoints = rig.p.modelEndpoints ?? [];
    // The whole-agent sets (Landlock ports and the connect guard's specs)
    // open the helper's entry and not the other one.
    assert.deepEqual(helperEndpointPorts(endpoints), [rig.ports.endpoint]);
    assert.ok(!helperEndpointGuardSpecs(endpoints).some((s) => s.endsWith(`:${other.port}`)), "the guard set leaves the other entry out");
    const all = [rig.ports.fwd, rig.ports.endpoint, other.port];
    assert.equal(runUnder(["env"], all).get(other.port), "OK", "baseline: the other local entry answers without the wrap");
    const got = runUnder(rig.prefix, all);
    assert.equal(got.get(rig.ports.endpoint), "OK", "the helper's entry is reachable");
    assert.equal(got.get(rig.ports.fwd), "OK", "the U-LLM forwarder is reachable");
    assert.equal(got.get(other.port), "EACCES", "the local entry that is not the helper is refused in-kernel");
  } finally {
    other.server.close();
    rig.close();
  }
});
