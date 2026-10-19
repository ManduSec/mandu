/**
 * inspect-net-confine.test — the inspect-mcp network confine
 * (confidentiality-plan-11 §8 item 5; inspect-net-confine.ts).
 *
 * Pins, with no kernel and no bin:
 *   - the port set: the forwarder's port (else 443) plus each declared
 *     `local: true` endpoint's port, and NEVER the model-proxy, net-proxy or
 *     ssh ports;
 *   - the argv: the whole-agent wrap's exact shape (`--net-only`, one
 *     `--allow-tcp-port` pair per port, `--`; strict, without the whole-agent wrap's `--skip-unsupported`) prefixed
 *     to the server command, in every writer of the inspect entry (the MCP
 *     config, the Codex `-c mcp_servers` splice, the OpenCode config);
 *   - the degrade: no bin or no Landlock TCP ⇒ today's command, one note;
 *     `--no-landlock-net` ⇒ off, silently; OpenClaw ⇒ nothing to wrap.
 *
 * Axes: the confine is independent of the protection axes (it narrows a
 * process's network, whatever the mode); the suite states `full`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DIRECT_ULLM_PORT,
  computeInspectMcpPorts,
  inspectNoProxy,
  planInspectNetConfine,
  wrapServerCommand,
} from "../../src/inspect-net-confine.js";
import { isAttentionNote } from "../../src/launch-banner.js";
import type { ModelEndpoint } from "../../src/model-endpoints.js";
import { inspectMcpConfigDoc, mcpConfigDoc } from "../../src/services/mcp.js";
import { codexMcpOverrides } from "../../src/env-compose.js";
import { buildOpencodeWrapDoc } from "../../src/services/agent-config.js";
import { Layout } from "../../src/services/layout.js";
import { startServices } from "../../src/services/manager.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const APPLIER = "/opt/mandu/bin/mandu-landlock-apply";
const MODEL_PROXY = 8788;
const OPENAI_PROXY = 8789;
const NET_PROXY = 8790;
const FORWARDER = 8791;

const OLLAMA: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true };
const LAN: ModelEndpoint = { name: "gpu", url: "http://192.168.7.20:8000", wire: "openai-chat", model: "qwen", local: true };
const CLOUD: ModelEndpoint = { name: "litellm", url: "https://llm.example.com:4000", wire: "anthropic", local: false };

// Pinned to Linux: the confine is Linux only (a Mac host would otherwise take
// the platform gate, tested at the end of this file).
const okProbe = { resolveBin: () => APPLIER, staleNote: () => null, probeNet: () => true, platform: "linux" as const };

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: MODEL_PROXY }, openaiProxy: { host: "127.0.0.1", port: OPENAI_PROXY },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: ["curl"], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

// ── the port set ─────────────────────────────────────────────────────────────

test("ports: the forwarder when it runs, plus the HELPER's entry only; other local and external entries add nothing", () => {
  // No helper mark: the first local entry (inspect-mcp's helperEndpoint rule).
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: FORWARDER, modelEndpoints: [OLLAMA, CLOUD, LAN] }), [FORWARDER, 11434]);
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: FORWARDER, modelEndpoints: [CLOUD, LAN, OLLAMA] }), [8000, FORWARDER]);
  // The mark picks the entry wherever it sits; the unmarked local entry stays closed.
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: FORWARDER, modelEndpoints: [OLLAMA, { ...LAN, helper: true }] }), [8000, FORWARDER]);
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: FORWARDER, modelEndpoints: [CLOUD] }), [FORWARDER]);
});

test("ports: without a forwarder the default U-LLM dials its vendor directly, so 443 (and not the forwarder)", () => {
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: null, modelEndpoints: [OLLAMA] }), [DIRECT_ULLM_PORT, 11434]);
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: null, modelEndpoints: [] }), [443]);
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: 0, modelEndpoints: [] }), [443], "port 0 = never adopted");
});

test("ports: with the forwarder, 443 is NOT allowed (the vendor is reached only through the relay)", () => {
  assert.ok(!computeInspectMcpPorts({ ullmForwarderPort: FORWARDER, modelEndpoints: [OLLAMA] }).includes(443));
});

test("ports: never the model proxy, the net-proxy or ssh, whatever the plan holds", () => {
  const p = plan({ netProxy: { host: "127.0.0.1", port: NET_PROXY }, ullmForwarder: { host: "127.0.0.1", port: FORWARDER }, modelEndpoints: [OLLAMA, CLOUD] });
  for (const fwd of [p.ullmForwarder!, undefined]) {
    const r = planInspectNetConfine({ ...p, ullmForwarder: fwd }, { ...okProbe, log: () => {} })!;
    for (const forbidden of [MODEL_PROXY, OPENAI_PROXY, NET_PROXY, 22]) {
      assert.ok(!r.ports.includes(forbidden), `port ${forbidden} must never be allowed (${r.ports})`);
      assert.ok(!r.wrapArgv.includes(String(forbidden)), `nor appear in the argv (${r.wrapArgv.join(" ")})`);
    }
  }
});

test("ports: a duplicated endpoint port appears once", () => {
  const twin: ModelEndpoint = { ...OLLAMA, name: "ollama2", url: "http://localhost:11434" };
  assert.deepEqual(computeInspectMcpPorts({ ullmForwarderPort: FORWARDER, modelEndpoints: [OLLAMA, twin] }), [FORWARDER, 11434]);
});

// ── the plan: argv + degrade ─────────────────────────────────────────────────

test("plan: the argv is the whole-agent wrap's shape but STRICT (net-only, one pair per port, no skip-unsupported, --)", () => {
  const notes: string[] = [];
  const r = planInspectNetConfine(
    { ullmForwarder: { host: "127.0.0.1", port: FORWARDER }, modelEndpoints: [OLLAMA] },
    { ...okProbe, log: (m) => notes.push(m) },
  );
  assert.ok(r);
  assert.deepEqual(r.wrapArgv, [APPLIER, "--net-only", "--allow-tcp-port", String(FORWARDER), "--allow-tcp-port", "11434", "--"]);
  assert.ok(!r.wrapArgv.includes("--skip-unsupported"), "a passed probe (fresh or kept) never degrades: a wrong one stops inspect-mcp at the applier");
  assert.deepEqual(r.ports, [FORWARDER, 11434]);
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /inspect_symbol network confine LIVE: .*\[8791, 11434\]/);
  assert.ok(!isAttentionNote(notes[0]!), "a healthy confine is not an attention line");
});

test("plan: --no-landlock-net turns it off, silently", () => {
  const notes: string[] = [];
  assert.equal(planInspectNetConfine({ landlockNet: false }, { ...okProbe, log: (m) => notes.push(m) }), null);
  assert.deepEqual(notes, []);
});

test("plan: no applier bin ⇒ null + ONE note, shown even in the compact display (like landlock-net's)", () => {
  const notes: string[] = [];
  const r = planInspectNetConfine({}, { platform: "linux", resolveBin: () => null, probeNet: () => { throw new Error("must not probe"); }, log: (m) => notes.push(m) });
  assert.equal(r, null);
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /inspect_symbol network confine is unavailable: the mandu-landlock-apply bin is not built/);
  assert.ok(isAttentionNote(notes[0]!), "matches the launch banner's 'not built' marker");
  assert.ok(!notes[0]!.includes("—"), "no em-dash");
});

test("plan: a kernel without Landlock TCP rules ⇒ null + ONE note, not a WARNING", () => {
  const notes: string[] = [];
  const r = planInspectNetConfine({}, { platform: "linux", resolveBin: () => APPLIER, staleNote: () => null, probeNet: () => false, log: (m) => notes.push(m) });
  assert.equal(r, null);
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /no Landlock TCP rules \(needs 6\.7\)/);
  assert.ok(!/WARNING/.test(notes[0]!));
  assert.ok(!isAttentionNote(notes[0]!));
  assert.ok(!notes[0]!.includes("—"));
});

test("plan: a stale bin's warning passes through, and the wrap still applies", () => {
  const notes: string[] = [];
  const r = planInspectNetConfine({}, { platform: "linux", resolveBin: () => APPLIER, staleNote: () => "WARNING: stale bin", probeNet: () => true, log: (m) => notes.push(m) });
  assert.ok(r);
  assert.equal(notes[0], "WARNING: stale bin");
});

// ── the writers of the inspect entry ─────────────────────────────────────────

const WRAP = [APPLIER, "--net-only", "--allow-tcp-port", String(FORWARDER), "--allow-tcp-port", "11434", "--"];

test("wrapServerCommand: prefixes the wrap; an absent / empty wrap leaves the entry as it was", () => {
  const s = { command: "node", args: ["a.mjs"], env: { K: "v" } };
  assert.deepEqual(wrapServerCommand(s, WRAP), { command: APPLIER, args: [...WRAP.slice(1), "node", "a.mjs"], env: { K: "v" } });
  assert.equal(wrapServerCommand(s, undefined), s);
  assert.equal(wrapServerCommand(s, []), s);
});

test("the MCP config: the inspect server runs under the wrap; the policy server does not; env unchanged", () => {
  const layout = Layout.dev("/repo");
  const bare = mcpConfigDoc(plan(), layout).mcpServers;
  const doc = mcpConfigDoc(plan({ inspectMcpWrap: WRAP }), layout).mcpServers;
  const inspect = doc["mandu-inspect"]!;
  assert.equal(inspect.command, APPLIER);
  assert.deepEqual(inspect.args, [...WRAP.slice(1), bare["mandu-inspect"]!.command, ...bare["mandu-inspect"]!.args]);
  assert.deepEqual(inspect.env, bare["mandu-inspect"]!.env, "no net-proxy in this plan: env untouched");
  assert.deepEqual(doc["mandu-policy"], bare["mandu-policy"], "the policy server holds no model bytes and is not wrapped here");
});

test("the MCP config, installed layout: the node bundle command is wrapped the same way", () => {
  const layout = Layout.installed("/pkg");
  const inspect = inspectMcpConfigDoc(plan({ inspectMcpWrap: WRAP }), layout).mcpServers["mandu-inspect"]!;
  assert.equal(inspect.command, APPLIER);
  const sep = inspect.args.indexOf("--");
  assert.equal(inspect.args[sep + 1], "node");
  assert.ok(inspect.args.slice(sep + 2).some((a) => a.endsWith("inspect-mcp.mjs")));
});

test("the MCP config: with the net-proxy on, the helper's LAN model host joins the server's NO_PROXY, confined or not (plan 12 D3)", () => {
  const p = plan({ inspectMcpWrap: WRAP, netProxy: { host: "127.0.0.1", port: NET_PROXY }, noProxyExtra: ["models.corp"], modelEndpoints: [LAN, OLLAMA, CLOUD] });
  const env = inspectMcpConfigDoc(p, Layout.dev("/repo")).mcpServers["mandu-inspect"]!.env;
  assert.equal(env["NO_PROXY"], "127.0.0.1,localhost,::1,api.anthropic.com,api.openai.com,models.corp,192.168.7.20");
  assert.equal(env["no_proxy"], env["NO_PROXY"]);
  // Loopback-only endpoints: the session list already covers them, nothing set.
  const env2 = inspectMcpConfigDoc({ ...p, modelEndpoints: [OLLAMA] }, Layout.dev("/repo")).mcpServers["mandu-inspect"]!.env;
  assert.equal(env2["NO_PROXY"], undefined);
  // A LAN entry that is not the helper is never dialed, so it joins nothing.
  const env2b = inspectMcpConfigDoc({ ...p, modelEndpoints: [OLLAMA, LAN] }, Layout.dev("/repo")).mcpServers["mandu-inspect"]!.env;
  assert.equal(env2b["NO_PROXY"], undefined);
  // Plan 12 D3: without the wrap too. A declared model on another machine is
  // dialed directly, never through the egress proxy (which would decrypt the
  // local-model bytes and dial with its own trust store).
  const env3 = inspectMcpConfigDoc({ ...p, inspectMcpWrap: undefined }, Layout.dev("/repo")).mcpServers["mandu-inspect"]!.env;
  assert.equal(env3["NO_PROXY"], env["NO_PROXY"]);
  // No net-proxy this session: nothing to bypass, never touched.
  const env4 = inspectMcpConfigDoc({ ...p, inspectMcpWrap: undefined, netProxy: undefined }, Layout.dev("/repo")).mcpServers["mandu-inspect"]!.env;
  assert.equal(env4["NO_PROXY"], undefined);
});

test("inspectNoProxy: the helper's entry when it is a non-loopback host, IPv6 bracketed; null without a net-proxy", () => {
  const v6: ModelEndpoint = { ...LAN, name: "v6", url: "http://[fd00::7]:8000" };
  assert.equal(inspectNoProxy(null, [LAN]), null);
  assert.equal(inspectNoProxy("127.0.0.1", [OLLAMA, CLOUD]), null);
  assert.equal(inspectNoProxy("127.0.0.1,localhost", [LAN, { ...LAN, name: "gpu2" }, v6]), "127.0.0.1,localhost,192.168.7.20");
  assert.equal(inspectNoProxy("127.0.0.1,localhost", [LAN, { ...v6, helper: true }]), "127.0.0.1,localhost,[fd00::7]");
  assert.equal(inspectNoProxy("127.0.0.1", [OLLAMA, LAN]), null, "a loopback helper: the session list already names it; the other LAN entry is not the helper");
  assert.equal(inspectNoProxy("127.0.0.1,192.168.7.20", [LAN]), "127.0.0.1,192.168.7.20", "never duplicated");
});

test("Codex: the -c mcp_servers splice built from the doc carries the wrapped command", () => {
  const servers = mcpConfigDoc(plan({ target: "codex", inspectMcpWrap: WRAP }), Layout.dev("/repo")).mcpServers;
  const argv = codexMcpOverrides(servers);
  assert.ok(argv.includes(`mcp_servers.mandu-inspect.command="${APPLIER}"`), argv.join(" "));
  const args = argv.find((a) => a.startsWith("mcp_servers.mandu-inspect.args="))!;
  assert.match(args, /^mcp_servers\.mandu-inspect\.args=\["--net-only","--allow-tcp-port","8791","--allow-tcp-port","11434","--",/);
});

test("OpenCode: the config's local mcp entry starts with the applier", () => {
  const p = plan({ target: "opencode", inspectMcpWrap: WRAP });
  const doc = buildOpencodeWrapDoc({ target: "opencode", scopeId: "sid", tenant: "live", inspect: true, policy: true, proxyUrl: "http://127.0.0.1:8788" }, p, Layout.dev("/repo")) as {
    mcp: Record<string, { command: string[] }>;
  };
  assert.deepEqual(doc.mcp["mandu-inspect"]!.command.slice(0, WRAP.length), WRAP);
  assert.notEqual(doc.mcp["mandu-policy"]!.command[0], APPLIER);
});

// ── the manager decides once, after the forwarder, before every writer ───────

function managerDeps(order: string[], seen: { wrapAtWrite?: string[] | undefined }) {
  return {
    writeAgentConfig: (pl: LaunchPlan) => { order.push("agent-config"); seen.wrapAtWrite = pl.inspectMcpWrap; return { envVar: "OPENCODE_CONFIG", path: "/run/sid/opencode.json" }; },
    startNetProxy: async () => ({ netProxy: { host: "127.0.0.1", port: NET_PROXY }, stop: () => {} }),
    writeExecShims: () => "/shim",
    writeMcpConfig: (pl: LaunchPlan) => { order.push("mcp"); seen.wrapAtWrite = pl.inspectMcpWrap; return "/w/mcp.json"; },
    startContextProxy: async () => ({ host: "127.0.0.1", port: MODEL_PROXY, stop: () => {} }),
    startFsView: async () => null,
    startUllmForwarder: async () => { order.push("forwarder"); return { host: "127.0.0.1", port: FORWARDER, url: `http://127.0.0.1:${FORWARDER}`, stop: async () => {} }; },
    inheritWorkspaceTrust: () => ({ action: "no-config" as const, file: "/x" }),
    inheritCodexTrust: () => ({ action: "no-config" as const, file: "/x" }),
    planInspectNetConfine: (pl: LaunchPlan, log: (m: string) => void) => {
      order.push("confine");
      return planInspectNetConfine(pl, { ...okProbe, log });
    },
  };
}

test("manager: forwarder → confine → MCP config, and the written plan carries the forwarder-port wrap", async () => {
  const order: string[] = [];
  const seen: { wrapAtWrite?: string[] } = {};
  const p = plan({ modelEndpoints: [OLLAMA] });
  const notes: string[] = [];
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", managerDeps(order, seen), (m) => notes.push(m))).stop();
  assert.deepEqual(order, ["forwarder", "confine", "mcp"]);
  assert.deepEqual(seen.wrapAtWrite, WRAP);
  assert.deepEqual(p.mcpServers!["mandu-inspect"]!.command, APPLIER);
  assert.ok(notes.some((n) => n.startsWith("inspect_symbol network confine LIVE")), "the note rides warn() without a doubled prefix");
});

test("manager: OpenCode's config is written after the confine; OpenClaw (in-gateway plugin) is never wrapped", async () => {
  const order: string[] = [];
  const seen: { wrapAtWrite?: string[] } = {};
  await (await startServices(plan({ target: "opencode" }), Layout.dev("/repo"), "/run/sid", managerDeps(order, seen), () => {})).stop();
  assert.ok(order.indexOf("confine") < order.indexOf("agent-config"));
  assert.ok(seen.wrapAtWrite && seen.wrapAtWrite[0] === APPLIER);

  const o2: string[] = [];
  const claw = plan({ target: "openclaw" });
  await (await startServices(claw, Layout.dev("/repo"), "/run/sid", managerDeps(o2, {}), () => {})).stop();
  assert.ok(!o2.includes("confine"));
  assert.equal(claw.inspectMcpWrap, undefined);
});

test("manager: --no-mcp decides nothing; a deps object without the planner leaves the command as today", async () => {
  const o: string[] = [];
  const noMcp = plan({ writeMcp: false });
  await (await startServices(noMcp, Layout.dev("/repo"), "/run/sid", managerDeps(o, {}), () => {})).stop();
  assert.ok(!o.includes("confine"));

  const legacy = managerDeps([], {}) as Partial<ReturnType<typeof managerDeps>>;
  delete legacy.planInspectNetConfine;
  const p = plan();
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", legacy as ReturnType<typeof managerDeps>, () => {})).stop();
  assert.equal(p.inspectMcpWrap, undefined);
  assert.notEqual(p.mcpServers!["mandu-inspect"]!.command, APPLIER);
});

// ── an endpoint declared after launch (plan 11 §8 item 5) ────────────────────

test("launch-time only: the confine is decided from the list the launch read; an endpoint declared later is in no written config", () => {
  // run.ts reads policy.yaml models: once and stores the list on the plan; the
  // manager decides the wrap from it and stores the ARGV (plan.inspectMcpWrap),
  // which every writer of the inspect entry uses as is. A later `local: true`
  // entry therefore gets no port: its connect is refused and inspect_symbol
  // refuses (the kernel half: test/kernel/inspect-mcp-confine.test.ts leg 4 and
  // tests/sandbox/endpoint-added-mid-session.test.ts).
  const p = plan({ ullmForwarder: { host: "127.0.0.1", port: FORWARDER }, modelEndpoints: [OLLAMA] });
  const r = planInspectNetConfine(p, { ...okProbe, log: () => {} });
  assert.ok(r);
  p.inspectMcpWrap = r.wrapArgv;
  const launchArgv = [...r.wrapArgv];
  // The law gains an endpoint mid-session (whatever later holds the list).
  p.modelEndpoints = [OLLAMA, LAN];
  const inspect = inspectMcpConfigDoc(p, Layout.dev("/repo")).mcpServers["mandu-inspect"]!;
  const confinePart = inspect.args.slice(0, inspect.args.indexOf("--"));
  assert.ok(confinePart.includes("11434"), "the launch-time endpoint keeps its port");
  assert.ok(!confinePart.includes("8000"), "the later endpoint's port is not in the written confine");
  assert.deepEqual(r.wrapArgv, launchArgv, "the decided wrap is a value, not a view over the plan's list");
});

test("launch-time only: nothing declared (or the arbiter did not answer) at launch confines to the default U-LLM's port alone", () => {
  for (const fwd of [undefined, { host: "127.0.0.1", port: FORWARDER }]) {
    const r = planInspectNetConfine({ ullmForwarder: fwd, modelEndpoints: [] }, { ...okProbe, log: () => {} });
    assert.ok(r);
    assert.deepEqual(r.ports, [fwd ? FORWARDER : DIRECT_ULLM_PORT]);
  }
});
