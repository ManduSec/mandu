/**
 * model-host-deny.test — the launch side of the model-host deny (agent-sdks.md
 * §4, "The model-host deny"): with the confidentiality axis on, the egress
 * proxy is told to judge model hosts by path, the model hosts leave the
 * tree's NO_PROXY, the connect guard denies them instead of admitting the
 * API host on :443, and a proxy without the deny is never adopted. With the
 * axis off nothing changes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { MODEL_HOST_DENY_HOSTS, NET_PROXY_MODEL_HOST_DENY_ENV, modelHostGuardDenySpecs } from "../../src/model-host-deny.js";
import { computeNetGuardSpecs } from "../../src/net-guard.js";
import { applyNetGuard } from "../../src/net-guard-setup.js";
import { netProxyIdentityMatches, sessionNoProxy, startNetProxy } from "../../src/services/net-proxy.js";
import { inspectMcpConfigDoc } from "../../src/services/mcp.js";
import { Layout } from "../../src/services/layout.js";
import type { ServiceDeps } from "../../src/services/primitives.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
// Axes: each plan states `confidentiality` explicitly (the deny follows that axis).

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, netGuard: true, ...over,
  };
}

function deps(capture: (env: Record<string, string | undefined>) => void): ServiceDeps {
  return {
    probePort: async () => false, probeIdentity: async () => null,
    waitFor: async () => true, waitForFile: async () => true,
    startDetachedCmd: (_c, _a, { env }) => { capture(env); return { pid: 7, stop: () => {} }; },
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
  };
}

test("the hosts: the vendors' API hosts, platform.claude.com and chatgpt.com; the guard denies each on every port", () => {
  assert.deepEqual([...MODEL_HOST_DENY_HOSTS], ["api.anthropic.com", "platform.claude.com", "api.openai.com", "chatgpt.com"]);
  assert.deepEqual(modelHostGuardDenySpecs(), ["tcp:api.anthropic.com:*", "tcp:platform.claude.com:*", "tcp:api.openai.com:*", "tcp:chatgpt.com:*"]);
});

test("the egress proxy gets the deny exactly when the confidentiality axis is on, and says so", async () => {
  const saved = process.env["MANDU_NET_PROXY_PORT"];
  const savedDeny = process.env[NET_PROXY_MODEL_HOST_DENY_ENV];
  process.env["MANDU_NET_PROXY_PORT"] = "8790";
  process.env[NET_PROXY_MODEL_HOST_DENY_ENV] = "1"; // an ambient value never decides
  try {
    let env: Record<string, string | undefined> = {};
    const on = await startNetProxy(plan({ confidentiality: true }), Layout.dev("/repo"), "/run/sid", deps((e) => { env = e; }));
    assert.equal(env[NET_PROXY_MODEL_HOST_DENY_ENV], "1");
    assert.equal(on.modelHostDeny, true);
    const off = await startNetProxy(plan({ confidentiality: false }), Layout.dev("/repo"), "/run/sid", deps((e) => { env = e; }));
    assert.equal(env[NET_PROXY_MODEL_HOST_DENY_ENV], "");
    assert.equal(off.modelHostDeny, false);
    assert.equal(off.mitmDegraded, undefined);
    // TLS inspection turned off under the deny: the launch says the model
    // hosts are refused whole, and what that costs.
    const blind = await startNetProxy(plan({ confidentiality: true, requested: { netProxy: true, netProxyMitm: false, execWrap: false } }), Layout.dev("/repo"), "/run/sid", deps((e) => { env = e; }));
    assert.equal(env[NET_PROXY_MODEL_HOST_DENY_ENV], "1");
    assert.match(blind.mitmDegraded ?? "", /refused whole to the agent's programs/);
  } finally {
    if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved;
    if (savedDeny === undefined) delete process.env[NET_PROXY_MODEL_HOST_DENY_ENV]; else process.env[NET_PROXY_MODEL_HOST_DENY_ENV] = savedDeny;
  }
});

test("a proxy is adopted only when it carries the deny this launch needs", () => {
  const id = (modelHostDeny?: string[]) => ({ mandu: true, service: "net-proxy", arbiterSock: "/b.sock", ...(modelHostDeny ? { modelHostDeny } : {}) });
  assert.equal(netProxyIdentityMatches(id([...MODEL_HOST_DENY_HOSTS]), plan({ confidentiality: true })), true);
  assert.equal(netProxyIdentityMatches(id(), plan({ confidentiality: true })), false, "a proxy without the deny would pass model calls");
  assert.equal(netProxyIdentityMatches(id(), plan({ confidentiality: false })), true, "axis off: unchanged");
  assert.equal(netProxyIdentityMatches(id([...MODEL_HOST_DENY_HOSTS]), plan({ confidentiality: false })), false);
});

test("NO_PROXY: the model hosts leave it under the deny (a MANDU_MODEL_HOSTS entry naming one too); unchanged otherwise", () => {
  const np = { netProxy: { host: "127.0.0.1", port: 8790 }, noProxyExtra: ["llm.lan", "API.openai.com"] };
  assert.equal(sessionNoProxy(np), "127.0.0.1,localhost,::1,api.anthropic.com,api.openai.com,llm.lan,API.openai.com");
  const deny = sessionNoProxy({ ...np, modelHostDeny: true })!;
  assert.equal(deny, "127.0.0.1,localhost,::1,llm.lan");
  assert.equal(sessionNoProxy({ netProxy: undefined, noProxyExtra: [], modelHostDeny: true }), null);
  // The inspect-mcp server's own NO_PROXY (written when its helper model is
  // on another machine) follows the session's.
  const helper = [{ name: "lan", url: "http://llm.lan:8080", wire: "anthropic" as const, local: true, helper: true as const, allowPlainHttp: true as const }];
  const doc = inspectMcpConfigDoc({ ...plan({ netProxy: np.netProxy, modelHostDeny: true, modelEndpoints: helper }), inspectMcpWrap: ["/bin/applier", "--net-only", "--"] }, Layout.dev("/repo"));
  const env = doc.mcpServers["mandu-inspect"]!.env as Record<string, string>;
  assert.equal(env["NO_PROXY"], "127.0.0.1,localhost,::1,llm.lan");
  const docOff = inspectMcpConfigDoc({ ...plan({ netProxy: np.netProxy, modelEndpoints: helper }), inspectMcpWrap: ["/bin/applier", "--net-only", "--"] }, Layout.dev("/repo"));
  assert.equal((docOff.mcpServers["mandu-inspect"]!.env as Record<string, string>)["NO_PROXY"], "127.0.0.1,localhost,::1,api.anthropic.com,api.openai.com,llm.lan");
});

test("the connect guard: under the deny no :443 allowance for the API host, every model host denied; without it, as before", () => {
  const base = { targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: null, strict: false };
  assert.ok(computeNetGuardSpecs({ ...base, apiHost: "api.anthropic.com" }).includes("tcp:api.anthropic.com:443"));
  assert.ok(!computeNetGuardSpecs({ ...base, apiHost: null }).some((s) => s.includes("anthropic")));

  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan({ netProxy: { host: "127.0.0.1", port: 8790 }, modelHostDeny: true, uploadDenyHosts: ["us.i.posthog.com"] }), mut, {
    resolveBin: () => "/bin/g", staleNote: () => null, log: (m) => logs.push(m),
  });
  assert.ok(r);
  const argv = mut.launchPrefix.join(" ");
  for (const h of MODEL_HOST_DENY_HOSTS) assert.ok(argv.includes(`--deny tcp:${h}:*`), `${h} denied: ${argv}`);
  assert.ok(argv.includes("--deny tcp:us.i.posthog.com:*"), "the upload hosts are still denied");
  assert.ok(!argv.includes("--allow tcp:api.anthropic.com:443"), argv);
  assert.ok(logs.some((l) => /model hosts are denied to the agent's programs/.test(l)));

  const old = emptyMutation();
  applyNetGuard(plan({ netProxy: { host: "127.0.0.1", port: 8790 } }), old, { resolveBin: () => "/bin/g", staleNote: () => null, log: () => {} });
  const oldArgv = old.launchPrefix.join(" ");
  assert.ok(oldArgv.includes("--allow tcp:api.anthropic.com:443"), oldArgv);
  assert.ok(!oldArgv.includes("--deny"), oldArgv);
});
