/**
 * upload-deny.test — an agent's upload hosts (supported-agents.md §5.3.4 rule
 * 1): the pure table lookup, and that a non-empty list reaches BOTH network
 * layers: the connect guard's `--deny` argv (applyNetGuard) and the
 * net-proxy's MANDU_NET_PROXY_DENY_HOSTS (startNetProxy), with the deny set
 * part of the net-proxy reuse key.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  codexConfigUploadUrls,
  hostsFromUrlEnv,
  normalizeDenyHosts,
  parseDenyEntry,
  UPLOAD_DENY,
  uploadDenyGuardSpecs,
  uploadDenyHosts,
  uploadDenyProxyOnlyHosts,
  netProxyDenyHosts,
  NET_PROXY_DENY_HOSTS_ENV,
  type UploadDenyEntry,
} from "../../src/upload-deny.js";
import { planNetGuard } from "../../src/net-guard.js";
import { applyNetGuard } from "../../src/net-guard-setup.js";
import { netProxyIdentityMatches, startNetProxy } from "../../src/services/net-proxy.js";
import { Layout } from "../../src/services/layout.js";
import type { ServiceDeps } from "../../src/services/primitives.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";

const TABLE: Record<string, UploadDenyEntry> = {
  example: { fixed: ["Telemetry.Example.com", ".traces.example.net", "bad host"], urlEnv: ["EX_TRACE_URL", "EX_OTLP"] },
};

test("uploadDenyHosts: fixed hosts + the hosts of the set URL env keys, normalized; no row = none", () => {
  const env = { EX_TRACE_URL: "https://Collector.Example.org:4318/v1/traces", EX_OTLP: "", OTHER: "https://x.example/" };
  assert.deepEqual(uploadDenyHosts("example", env, undefined, TABLE), [
    "telemetry.example.com", ".traces.example.net", "collector.example.org:4318",
  ]);
  assert.deepEqual(uploadDenyHosts("claude", env, undefined, TABLE), []);
  assert.deepEqual(uploadDenyHosts("toString", env, undefined, TABLE), [], "no prototype keys");
});

test("the shipped table: every row's fixed hosts parse (a bad spec would stop the guard from starting the agent)", () => {
  for (const [target, row] of Object.entries(UPLOAD_DENY)) {
    for (const h of row.fixed) assert.ok(parseDenyEntry(h), `${target}: ${h}`);
  }
});

test("hostsFromUrlEnv: scheme-less values, IPv6, unparseable and unset keys", () => {
  const env = { A: "langfuse.example:3000", B: "http://[2001:db8::7]:4318/x", C: "::::", D: undefined, E: "http://localhost:3000" };
  assert.deepEqual(hostsFromUrlEnv(env, ["A", "B", "C", "D", "E"]), ["langfuse.example:3000", "[2001:db8::7]:4318", "localhost:3000"]);
});

test("normalizeDenyHosts / uploadDenyGuardSpecs: de-duplicated; tcp:<host>:<port|*>; a .suffix denies its apex at the guard", () => {
  const hosts = normalizeDenyHosts(["A.example", "a.example", ".b.example", "c.example:443", "[2001:db8::1]", "x y"]);
  assert.deepEqual(hosts, ["a.example", ".b.example", "c.example:443", "[2001:db8::1]"]);
  assert.deepEqual(uploadDenyGuardSpecs(hosts), ["tcp:a.example:*", "tcp:b.example:*", "tcp:c.example:443", "tcp:[2001:db8::1]:*"]);
});

test("planNetGuard: one --deny pair per deny spec, after the allows", () => {
  const { wrapArgv } = planNetGuard({ binPath: "/g", specs: ["tcp:*:443"], deny: ["tcp:us.i.posthog.com:*"], extra: ["--x"] });
  assert.deepEqual(wrapArgv, ["/g", "--allow", "tcp:*:443", "--deny", "tcp:us.i.posthog.com:*", "--x", "--skip-unsupported", "--"]);
  assert.deepEqual(planNetGuard({ binPath: "/g", specs: [] }).wrapArgv, ["/g", "--skip-unsupported", "--"], "no deny, no flag");
});

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, netGuard: true, ...over,
  };
}

test("a non-empty list reaches the connect guard: --deny per host, beside the * fallback", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan({ uploadDenyHosts: ["us.i.posthog.com", "collector.example:4318"] }), mut, {
    resolveBin: () => "/bin/g", staleNote: () => null, log: (m) => logs.push(m),
  });
  assert.ok(r);
  const argv = mut.launchPrefix.join(" ");
  assert.match(argv, /--deny tcp:us\.i\.posthog\.com:\* --deny tcp:collector\.example:4318/);
  assert.match(argv, /--allow tcp:\*:443/, "the permissive fallback stays; the deny beats it in the guard");
  assert.ok(logs.some((l) => /2 upload destination\(s\)/.test(l)));
  const none = emptyMutation();
  applyNetGuard(plan(), none, { resolveBin: () => "/bin/g", staleNote: () => null, log: () => {} });
  assert.ok(!none.launchPrefix.includes("--deny"), "no list, no --deny");
});

function deps(capture: (env: Record<string, string | undefined>) => void, over: Partial<ServiceDeps> = {}): ServiceDeps {
  return {
    probePort: async () => false, probeIdentity: async () => null,
    waitFor: async () => true, waitForFile: async () => true,
    startDetachedCmd: (_c, _a, { env }) => { capture(env); return { pid: 7, stop: () => {} }; },
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    ...over,
  };
}

test("a non-empty list reaches the net-proxy's env; none → explicitly empty (an ambient value cannot leak in)", async () => {
  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], deny: process.env[NET_PROXY_DENY_HOSTS_ENV] };
  process.env["MANDU_NET_PROXY_PORT"] = "8790";
  process.env[NET_PROXY_DENY_HOSTS_ENV] = "stale.example";
  try {
    let env: Record<string, string | undefined> = {};
    await startNetProxy(plan({ uploadDenyHosts: ["us.i.posthog.com", ".traces.example"] }), Layout.dev("/repo"), "/run/sid", deps((e) => { env = e; }));
    assert.equal(env[NET_PROXY_DENY_HOSTS_ENV], "us.i.posthog.com,.traces.example");
    await startNetProxy(plan(), Layout.dev("/repo"), "/run/sid", deps((e) => { env = e; }));
    assert.equal(env[NET_PROXY_DENY_HOSTS_ENV], "");
  } finally {
    for (const [k, v] of [["MANDU_NET_PROXY_PORT", saved.port], [NET_PROXY_DENY_HOSTS_ENV, saved.deny]] as const) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});

test("the deny set is part of the net-proxy reuse key: a proxy denying another set is never adopted", () => {
  const id = (denyHosts?: string[]) => ({ mandu: true, service: "net-proxy", arbiterSock: "/b.sock", ...(denyHosts ? { denyHosts } : {}) });
  const p = plan({ uploadDenyHosts: ["us.i.posthog.com", "relay.damus.io"] });
  assert.equal(netProxyIdentityMatches(id(["relay.damus.io", "US.I.POSTHOG.COM"]), p), true, "same set, any order or case");
  assert.equal(netProxyIdentityMatches(id(), p), false, "a proxy with no list would pass the uploads");
  assert.equal(netProxyIdentityMatches(id(["us.i.posthog.com"]), p), false, "a subset would pass one");
  assert.equal(netProxyIdentityMatches(id(), plan()), true, "no list on either side: unchanged");
  assert.equal(netProxyIdentityMatches(id(["us.i.posthog.com"]), plan()), false, "another agent's list is not this launch's");
});

// ── the codex row (supported-agents.md §5.5) ────────────────────────────────

test("codex: the feedback Sentry project and the env's OTLP collectors at both layers; Statsig at the net-proxy only; chatgpt.com never", () => {
  const hosts = uploadDenyHosts("codex", {
    OTEL_EXPORTER_OTLP_ENDPOINT: "https://collector.example:4318", OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://[::1]:4318/v1/traces",
  });
  assert.deepEqual(hosts, ["o33249.ingest.us.sentry.io", "collector.example:4318", "[::1]:4318"]);
  const proxyOnly = uploadDenyProxyOnlyHosts("codex");
  assert.deepEqual(proxyOnly, ["ab.chatgpt.com"]);
  assert.deepEqual(netProxyDenyHosts({ uploadDenyHosts: hosts, netProxyOnlyDenyHosts: proxyOnly }), [...hosts, "ab.chatgpt.com"]);
  for (const h of [...hosts, ...proxyOnly]) {
    assert.ok(h !== "chatgpt.com" && h !== ".chatgpt.com" && h !== "auth.openai.com" && !h.includes("github.com"), h);
  }
});

test("codex: ab.chatgpt.com never reaches the connect guard (it answers on chatgpt.com's CDN addresses); the Sentry host does", () => {
  const hosts = uploadDenyHosts("codex", {});
  const mut = emptyMutation();
  applyNetGuard(plan({ uploadDenyHosts: hosts, netProxyOnlyDenyHosts: uploadDenyProxyOnlyHosts("codex") }), mut, {
    resolveBin: () => "/bin/g", staleNote: () => null, log: () => {},
  });
  const argv = mut.launchPrefix.join(" ");
  assert.match(argv, /--deny tcp:o33249\.ingest\.us\.sentry\.io:\*/);
  assert.ok(!argv.includes("chatgpt.com"), argv);
});

test("codexConfigUploadUrls: every [otel] exporter endpoint (tables, inline, dotted) and the realtime base URLs; nothing else", () => {
  const text = [
    'model = "gpt-5"',
    'experimental_realtime_ws_base_url = "wss://voice.example/v1"',
    "experimental_realtime_webrtc_call_base_url = 'https://call.example'",
    'chatgpt_base_url = "https://chatgpt.com/backend-api/"',
    "",
    "[otel]",
    "log_user_prompt = true",
    'exporter = { otlp-http = { endpoint = "https://logs.example/v1/logs", protocol = "binary" } }',
    "",
    "[otel.trace_exporter.otlp-grpc]",
    'endpoint = "http://traces.example:4317"   # the collector',
    "",
    "[mcp_servers.docs]",
    'url = "https://mcp.example/mcp"',
    'endpoint = "https://not-otel.example"',
    "",
    "[profiles.work]",
    'otel.metrics_exporter = { otlp-http = { endpoint = "https://metrics.example", protocol = "json" } }',
    '# endpoint = "https://commented.example"',
  ].join("\n");
  assert.deepEqual(codexConfigUploadUrls(text), [
    "wss://voice.example/v1", "https://call.example", "https://logs.example/v1/logs", "http://traces.example:4317", "https://metrics.example",
  ]);
  const hosts = uploadDenyHosts("codex", {}, { layers: [{ path: "/u/.codex/config.toml", text }, { path: "/p/.codex/config.toml", text: "[otel]\nexporter = \"none\"\n" }] });
  for (const h of ["voice.example", "call.example", "logs.example", "traces.example:4317", "metrics.example"]) assert.ok(hosts.includes(h), h);
  for (const h of ["mcp.example", "not-otel.example", "commented.example", "chatgpt.com"]) assert.ok(!hosts.includes(h), h);
  // A config the caller could not read, or a malformed one, adds nothing.
  assert.deepEqual(uploadDenyHosts("codex", {}, null), uploadDenyHosts("codex", {}));
  assert.deepEqual(uploadDenyHosts("codex", {}, { layers: [{ text: 7 }] }), uploadDenyHosts("codex", {}));
});
