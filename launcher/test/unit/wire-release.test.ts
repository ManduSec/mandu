/**
 * wire-release.test — the launch's two steps for serving npm the `.npmrc`
 * twin (confidentiality plan 10 §11.13.1):
 *   - Codex's stdio MCP servers get the proxy variables Codex drops for them
 *     (measured on 0.159.1), through each entry's own `env_vars`, keeping
 *     what it lists; unreadable entries and names that are not bare keys are
 *     left alone;
 *   - `registerWireRelease` goes on the HUMAN socket only, with the session's
 *     NO_PROXY hosts, only when the confidentiality axis and TLS inspection
 *     are on and the human did not opt out (MANDU_WIRE_TWIN=0); a failure
 *     warns once and never throws.
 *
 * Pure tests over an injected readFile and call. No arbiter is built, so no
 * axes are stated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { configuredMcpServers, type ConfiguredMcpServer } from "../../src/mcp-server-config.js";
import {
  CODEX_MCP_PROXY_VARS,
  codexMcpProxyEnvOverrides,
  endLaunchWireRelease,
  launchInspectsTls,
  registerLaunchWireRelease,
  type WireReleasePlan,
} from "../../src/wire-release.js";

const HOME = "/home/u";
const files = (m: Record<string, string>) => (p: string): string | null => (p in m ? m[p]! : null);

test("codex config: an entry's own env_vars is read; a malformed one marks the entry unreadable", () => {
  const got = configuredMcpServers({
    target: "codex", home: HOME, humanCwd: "/w", agentCwd: "/w",
    readFile: files({ [`${HOME}/.codex/config.toml`]: [
      "[mcp_servers.plain]", 'command = "npx"', 'args = ["-y", "pkg"]',
      "[mcp_servers.listed]", 'command = "node"', 'env_vars = ["GITHUB_TOKEN", "HTTPS_PROXY"]',
      "[mcp_servers.odd]", 'command = "node"', "env_vars = [1]", "",
    ].join("\n") }),
  });
  assert.deepEqual(got.map((s) => [s.name, s.envVars ?? null, s.envVarsUnreadable ?? false]), [
    ["plain", null, false],
    ["listed", ["GITHUB_TOKEN", "HTTPS_PROXY"], false],
    ["odd", null, true],
  ]);
});

test("codexMcpProxyEnvOverrides: one env_vars override per server, its own names first, each proxy name once", () => {
  const s = (name: string, extra: Partial<ConfiguredMcpServer> = {}): ConfiguredMcpServer => ({ name, command: "npx", args: [], source: "t", ...extra });
  const out = codexMcpProxyEnvOverrides([
    s("box-tools"),
    s("listed", { envVars: ["GITHUB_TOKEN", "NO_PROXY"] }),
    s("odd", { envVarsUnreadable: true }),
    s("docs server"),
    s("box-tools"),
  ]);
  const all = CODEX_MCP_PROXY_VARS.map((v) => JSON.stringify(v)).join(",");
  assert.deepEqual(out, [
    "-c", `mcp_servers.box-tools.env_vars=[${all}]`,
    "-c", `mcp_servers.listed.env_vars=["GITHUB_TOKEN","NO_PROXY",${CODEX_MCP_PROXY_VARS.filter((v) => v !== "NO_PROXY").map((v) => JSON.stringify(v)).join(",")}]`,
  ]);
  assert.ok(CODEX_MCP_PROXY_VARS.includes("HTTPS_PROXY") && CODEX_MCP_PROXY_VARS.includes("NODE_USE_ENV_PROXY"));
  assert.deepEqual(codexMcpProxyEnvOverrides([]), []);
});

const PLAN: WireReleasePlan = {
  scopeId: "mandu-abc", arbiterHumanSock: "/run/h.sock", effectiveAxes: { integrity: false, confidentiality: true },
  confidentiality: true, netProxy: { host: "127.0.0.1", port: 4242 }, mitmCaCert: "/run/ca.pem", noProxyExtra: ["llm.lan"],
} as WireReleasePlan;

test("registerLaunchWireRelease: the HUMAN socket, the scope id, inspecting, and the session's NO_PROXY hosts", async () => {
  const calls: Array<[string, string, Record<string, unknown>]> = [];
  const notes: string[] = [];
  const r = await registerLaunchWireRelease(PLAN, {}, { call: async (sock, op, args) => { calls.push([sock, op, args]); return { inspecting: true }; }, log: (m) => notes.push(m) });
  assert.equal(r, "registered");
  assert.deepEqual(calls, [["/run/h.sock", "registerWireRelease", {
    sessionKey: "mandu-abc", inspecting: true,
    direct: ["127.0.0.1", "localhost", "::1", "api.anthropic.com", "api.openai.com", "llm.lan"],
  }]]);
  assert.deepEqual(notes, []);
});

test("registerLaunchWireRelease: nothing is sent with the axis off, without TLS inspection, or opted out", async () => {
  const call = async () => { throw new Error("must not be called"); };
  const log = () => {};
  assert.equal(await registerLaunchWireRelease({ ...PLAN, effectiveAxes: { integrity: false, confidentiality: false } } as WireReleasePlan, {}, { call, log }), "off");
  assert.equal(await registerLaunchWireRelease({ ...PLAN, mitmCaCert: undefined } as WireReleasePlan, {}, { call, log }), "off");
  assert.equal(await registerLaunchWireRelease({ ...PLAN, netProxy: undefined } as WireReleasePlan, {}, { call, log }), "off");
  assert.equal(await registerLaunchWireRelease(PLAN, { MANDU_WIRE_TWIN: "0" }, { call, log }), "opted-out");
  assert.equal(launchInspectsTls(PLAN), true);
});

test("registerLaunchWireRelease: no human socket, a failed call or a bad answer warn once, naming the raw read, and never throw", async () => {
  for (const [plan, call, want] of [
    [{ ...PLAN, arbiterHumanSock: undefined }, async () => ({ inspecting: true }), "skipped"],
    [PLAN, async () => { throw new Error("ECONNREFUSED"); }, "failed"],
    [PLAN, async () => ({ nope: 1 }), "failed"],
  ] as const) {
    const notes: string[] = [];
    assert.equal(await registerLaunchWireRelease(plan as WireReleasePlan, {}, { call, log: (m) => notes.push(m) }), want);
    assert.equal(notes.length, 1);
    assert.match(notes[0]!, /^WARNING: mandu: .*npm reads ~\/\.npmrc raw this session/);
  }
});

test("registerLaunchWireRelease: the launcher's pid goes with the word, so the arbiter keeps it across its restart while this launcher runs", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const r = await registerLaunchWireRelease(PLAN, {}, { call: async (_s, _op, args) => { calls.push(args); return { inspecting: true }; }, log: () => {}, pid: 4321 });
  assert.equal(r, "registered");
  assert.equal(calls[0]!["pid"], 4321);
  assert.equal(calls[0]!["inspecting"], true);
});

test("endLaunchWireRelease: a registered word is withdrawn on the human socket at the session's end, with the pid; nothing else is sent, and a failure is quiet", async () => {
  const calls: Array<[string, string, Record<string, unknown>]> = [];
  const call = async (sock: string, op: string, args: Record<string, unknown>) => { calls.push([sock, op, args]); return { inspecting: false }; };
  assert.equal(await endLaunchWireRelease(PLAN, "registered", { call, pid: 4321 }), true);
  assert.deepEqual(calls, [["/run/h.sock", "registerWireRelease", { sessionKey: "mandu-abc", inspecting: false, pid: 4321 }]]);
  for (const r of ["off", "opted-out", "skipped", "failed", null] as const) {
    assert.equal(await endLaunchWireRelease(PLAN, r, { call }), false, String(r));
  }
  assert.equal(await endLaunchWireRelease({ ...PLAN, arbiterHumanSock: undefined } as WireReleasePlan, "registered", { call }), false);
  assert.equal(calls.length, 1, "nothing sent for a word never registered");
  assert.equal(await endLaunchWireRelease(PLAN, "registered", { call: async () => { throw new Error("ECONNREFUSED"); } }), false, "never throws");
});
