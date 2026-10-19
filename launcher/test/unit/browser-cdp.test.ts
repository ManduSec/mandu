/**
 * browser-cdp — the launch side of the DevTools relay
 * (docs/design/agents/devtools-relay.md §6) and the provider-key grants
 * that go with it (agent-sign-in.md §3.12): `--browser-cdp` names a Chrome
 * on this machine only; the manager starts the relay after the services
 * whose ports Chrome's must not share, and refuses the launch when it cannot;
 * the agent is given the relay's URL, never Chrome's, and the connect guards
 * admit the relay's port, never Chrome's; TYPESAFE_API_KEY and
 * OPENROUTER_API_KEY are each bound to their own host.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BROWSER_CDP_AGENT_VARS, browserCdpAgentEnv, chromePortRefusal, parseBrowserCdp, unguardedNote, upstreamPort } from "../../src/browser-cdp.js";
import { parse as parseIn } from "../../src/parse.js";
import { composeLaunch } from "../../src/env-compose.js";
import { computeLandlockNetPorts } from "../../src/landlock-net.js";
import { planSeatbeltNet } from "../../src/landlock-net-setup.js";
import { computeNetGuardSpecs } from "../../src/net-guard.js";
import { startServices } from "../../src/services/manager.js";
import { Layout } from "../../src/services/layout.js";
import { PROVIDER_KEY_HOSTS, providerKeyGrantPlans, registerProviderKeyGrants, type EnvKeyGrantLaunch } from "../../src/agent-key-grant.js";
import { NET_PROXY_MODEL_NOTE_ENV, NET_PROXY_MODEL_SERVICES_ENV, modelNoteOf, startNetProxy } from "../../src/services/net-proxy.js";
import { startCdpRelay } from "../../src/services/cdp-relay.js";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ServiceDeps } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";
import { hermetic } from "../lib/test-runtime.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the key grants exist only with the confidentiality axis on

const parse = hermetic(parseIn, 1);

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "shell", argv: ["bash"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: false, bestEffort: false, replyFilter: true, ...over,
  };
}

const deps = {
  writeAgentConfig: () => ({ envVar: "X", path: "/x" }),
  startNetProxy: async () => ({ netProxy: { host: "127.0.0.1", port: 8790 }, stop: () => {} }),
  writeExecShims: () => "/shim",
  writeMcpConfig: () => "/w/.mcp.json",
  startContextProxy: async () => ({ host: "127.0.0.1", port: 8788, stop: () => {} }),
  startFsView: async () => null,
  startUllmForwarder: async () => ({ host: "127.0.0.1", port: 8791, url: "http://127.0.0.1:8791", stop: async () => {} }),
  inheritWorkspaceTrust: () => ({ action: "no-config" as const, file: "/nonexistent/.claude.json" }),
  inheritCodexTrust: () => ({ action: "no-config" as const, file: "/nonexistent/config.toml" }),
};

test("parseBrowserCdp: Chrome's HTTP endpoint on this machine, normalized; a ws:// browser URL becomes its endpoint", () => {
  assert.equal(parseBrowserCdp("http://127.0.0.1:9222"), "http://127.0.0.1:9222");
  assert.equal(parseBrowserCdp(" http://localhost:9333/ "), "http://localhost:9333");
  assert.equal(parseBrowserCdp("ws://127.0.0.1:9222/devtools/browser/abc"), "http://127.0.0.1:9222");
  assert.equal(parseBrowserCdp("http://[::1]:9222"), "http://[::1]:9222");
  assert.equal(upstreamPort("http://127.0.0.1:9222"), 9222);
});

test("parseBrowserCdp: refuses another machine, another scheme, no port, credentials, garbage", () => {
  assert.throws(() => parseBrowserCdp("http://10.0.0.5:9222"), /must name this machine/);
  assert.throws(() => parseBrowserCdp("http://chrome.example:9222"), /must name this machine/);
  assert.throws(() => parseBrowserCdp("https://127.0.0.1:9222"), /http:\/\//);
  assert.throws(() => parseBrowserCdp("http://127.0.0.1"), /needs the port/);
  assert.throws(() => parseBrowserCdp("http://u:p@127.0.0.1:9222"), /no user name/);
  assert.throws(() => parseBrowserCdp("9222"), /debugging endpoint/);
});

test("the flag and the variable reach the plan (the flag wins); none means no relay", () => {
  assert.equal(parse(["--browser-cdp", "http://127.0.0.1:9222", "--", "bash"], {}).browserCdp, "http://127.0.0.1:9222");
  assert.equal(parse(["--browser-cdp=http://localhost:9333", "--", "bash"], {}).browserCdp, "http://localhost:9333");
  assert.equal(parse(["--", "bash"], { MANDU_BROWSER_CDP: "http://127.0.0.1:9444" }).browserCdp, "http://127.0.0.1:9444");
  assert.equal(parse(["--browser-cdp=http://127.0.0.1:9222", "--", "bash"], { MANDU_BROWSER_CDP: "http://127.0.0.1:9444" }).browserCdp, "http://127.0.0.1:9222");
  assert.equal(parse(["--", "bash"], {}).browserCdp, undefined);
  assert.throws(() => parse(["--browser-cdp=http://10.1.1.1:9222", "--", "bash"], {}), /must name this machine/);
});

test("chromePortRefusal: a port the guards admit everywhere, or one of Mandu's own, is refused", () => {
  for (const p of [443, 22, 53, 8790]) assert.match(String(chromePortRefusal(p, [8788, 8790])), /around the relay/, String(p));
  assert.equal(chromePortRefusal(9222, [8788, 8790]), null);
});

test("the agent's environment names the relay in both variables, and Chrome's port nowhere", () => {
  assert.deepEqual(Object.keys(browserCdpAgentEnv("http://127.0.0.1:40111")).sort(), [...BROWSER_CDP_AGENT_VARS].sort());
  const { env } = composeLaunch(plan({ browserCdp: "http://127.0.0.1:9222", cdpRelay: { host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111" } }));
  assert.equal(env["BU_CDP_URL"], "http://127.0.0.1:40111");
  assert.equal(env["MANDU_BROWSER_CDP_URL"], "http://127.0.0.1:40111");
  assert.ok(!JSON.stringify(env).includes(":9222"), "Chrome's own port is not in the agent's environment");
  const none = composeLaunch(plan()).env;
  assert.equal(none["BU_CDP_URL"], undefined);
});

test("the connect guards admit the relay's port and not Chrome's", () => {
  const ports = computeLandlockNetPorts({ targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: null, cdpRelayPort: 40111, strict: true });
  assert.ok(ports.includes(40111));
  assert.ok(!ports.includes(9222));
  const seatbelt = planSeatbeltNet(plan({ landlockNetStrict: true, cdpRelay: { host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111" } }));
  assert.ok(seatbelt.connect.some((c) => c.host === "localhost" && c.port === 40111));
  const specs = computeNetGuardSpecs({ targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: null, cdpRelayPort: 40111, apiHost: null, strict: true });
  assert.ok(specs.includes("tcp:127.0.0.0/8:40111"));
  assert.ok(!specs.some((s) => s.endsWith(":9222")));
  assert.match(unguardedNote("http://127.0.0.1:9222"), /around the DevTools relay/);
});

test("manager: the relay starts on the endpoint and its URL lands on the plan; its stop runs at teardown", async () => {
  const started: string[] = [];
  let stopped = 0;
  const lines: string[] = [];
  const p = plan({ browserCdp: "http://127.0.0.1:9222" });
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...deps,
    startCdpRelay: async (pl) => { started.push(pl.browserCdp!); return { host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111", stop: () => { stopped++; } }; },
  }, (m) => lines.push(m));
  assert.deepEqual(started, ["http://127.0.0.1:9222"]);
  assert.deepEqual(p.cdpRelay, { host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111" });
  assert.ok(lines.some((l) => l.startsWith("cdp-relay LIVE on http://127.0.0.1:40111")), lines.join("\n"));
  await h.stop();
  assert.equal(stopped, 1);
});

test("manager: no --browser-cdp, no relay", async () => {
  let called = false;
  const p = plan();
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", { ...deps, startCdpRelay: async () => { called = true; throw new Error("no"); } }, () => {})).stop();
  assert.equal(called, false);
  assert.equal(p.cdpRelay, undefined);
});

test("manager: a relay that cannot start refuses the launch, unless --best-effort (then no endpoint is given)", async () => {
  const failing = { ...deps, startCdpRelay: async () => { throw new Error("relay boom"); } };
  await assert.rejects(startServices(plan({ browserCdp: "http://127.0.0.1:9222" }), Layout.dev("/repo"), "/run/sid", failing, () => {}), /cdp-relay.*relay boom.*--best-effort/s);
  const p = plan({ browserCdp: "http://127.0.0.1:9222", bestEffort: true });
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", failing, () => {})).stop();
  assert.equal(p.cdpRelay, undefined);
  assert.equal(composeLaunch(p).env["BU_CDP_URL"], undefined);
  // A launcher without the step refuses too.
  await assert.rejects(startServices(plan({ browserCdp: "http://127.0.0.1:9222" }), Layout.dev("/repo"), "/run/sid", deps, () => {}), /cannot start the DevTools relay/);
});

test("manager: Chrome on a port the agent may reach is refused even with --best-effort", async () => {
  const relay = { ...deps, startCdpRelay: async () => ({ host: "127.0.0.1", port: 40111, url: "http://127.0.0.1:40111", stop: () => {} }) };
  for (const ep of ["http://127.0.0.1:443", "http://127.0.0.1:8788"]) {
    await assert.rejects(startServices(plan({ browserCdp: ep, bestEffort: true }), Layout.dev("/repo"), "/run/sid", relay, () => {}), /around the relay/, ep);
  }
});

test("the relay and the egress proxy are started with one session key, the launch's scope id: the proxy takes the relay's refusals for the agent's model by it (devtools-relay.md §3.4)", async () => {
  const run = mkdtempSync(join(tmpdir(), "mdu-relay-session-"));
  const saved = process.env["MANDU_NET_PROXY_PORT"];
  process.env["MANDU_NET_PROXY_PORT"] = "8790";
  try {
    const started: Array<{ args: readonly string[]; env: Record<string, string | undefined> }> = [];
    const deps: ServiceDeps = {
      probePort: async () => false, probeIdentity: async () => null,
      waitFor: async () => true, waitForFile: async () => true,
      startDetachedCmd: (_c, args, o) => {
        started.push({ args, env: o.env as Record<string, string | undefined> });
        writeFileSync(join(run, "cdp-relay.port"), "40111\n");
        return { pid: 7, stop: () => {} };
      },
      runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    };
    const p = plan({ scopeId: "sid-relay-7", confidentiality: true, browserCdp: "http://127.0.0.1:9222", requested: { netProxy: true, execWrap: false } });
    (await startCdpRelay(p, Layout.dev("/repo"), run, deps)).stop();
    await startNetProxy(p, Layout.dev("/repo"), run, deps);
    const [relay, proxy] = started;
    assert.equal(relay!.args[relay!.args.indexOf("--session") + 1], "sid-relay-7");
    assert.equal(relay!.env["MANDU_SESSION_KEY"], "sid-relay-7");
    assert.equal(proxy!.env["MANDU_SESSION_KEY"], "sid-relay-7");
    assert.equal(proxy!.env[NET_PROXY_MODEL_NOTE_ENV], "browser");
  } finally {
    if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved;
    rmSync(run, { recursive: true, force: true });
  }
});

// ── provider keys (agent-sign-in.md §3.12) ──────────────────────────────────

const launch: EnvKeyGrantLaunch = { target: "shell", confidentiality: true, noContextProxy: true };

test("providerKeyGrantPlans: each set provider key, to its own host over https", () => {
  assert.deepEqual(PROVIDER_KEY_HOSTS, { TYPESAFE_API_KEY: "api.typesafe.ai", OPENROUTER_API_KEY: "openrouter.ai" });
  assert.deepEqual(providerKeyGrantPlans(launch, { TYPESAFE_API_KEY: "ts-1", OPENROUTER_API_KEY: "sk-or-1", OTHER_API_KEY: "x" }, {}), [
    { env: "TYPESAFE_API_KEY", grants: [{ field: "TYPESAFE_API_KEY", host: "api.typesafe.ai", https: true }] },
    { env: "OPENROUTER_API_KEY", grants: [{ field: "OPENROUTER_API_KEY", host: "openrouter.ai", https: true }] },
  ]);
  assert.deepEqual(providerKeyGrantPlans(launch, { TYPESAFE_API_KEY: "  " }, {}), []);
});

test("providerKeyGrantPlans: none with the axis off, --no-env-secrets, MANDU_AUTH_SUBSTITUTION=0, or for the key Goose routes", () => {
  const env = { TYPESAFE_API_KEY: "ts-1", OPENROUTER_API_KEY: "sk-or-1" };
  assert.deepEqual(providerKeyGrantPlans({ ...launch, confidentiality: false }, env, {}), []);
  assert.deepEqual(providerKeyGrantPlans({ ...launch, envSecrets: false }, env, {}), []);
  assert.deepEqual(providerKeyGrantPlans(launch, env, { MANDU_AUTH_SUBSTITUTION: "0" }), []);
  const goose = { ...launch, target: "goose" as const, gooseRouting: { provider: "openrouter" as const, subagentProvider: "openrouter" as const, openai: null, compat: [{ provider: "openrouter" as const, upstream: "https://openrouter.ai" }] } };
  assert.deepEqual(providerKeyGrantPlans(goose, env, {}).map((p) => p.env), ["TYPESAFE_API_KEY"]);
});

test("the egress proxy is started with the providers' hosts as model services, from the launcher's own list (an ambient value never widens it)", async () => {
  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], list: process.env[NET_PROXY_MODEL_SERVICES_ENV] };
  process.env["MANDU_NET_PROXY_PORT"] = "8790";
  process.env[NET_PROXY_MODEL_SERVICES_ENV] = "evil.example";
  try {
    let env: Record<string, string | undefined> = {};
    const deps: ServiceDeps = {
      probePort: async () => false, probeIdentity: async () => null,
      waitFor: async () => true, waitForFile: async () => true,
      startDetachedCmd: (_c, _a, o) => { env = o.env as Record<string, string | undefined>; return { pid: 7, stop: () => {} }; },
      runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    };
    await startNetProxy(plan({ confidentiality: true, requested: { netProxy: true, execWrap: false } }), Layout.dev("/repo"), "/run/sid", deps);
    assert.equal(env[NET_PROXY_MODEL_SERVICES_ENV], "api.typesafe.ai,openrouter.ai");
  } finally {
    if (saved.port === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved.port;
    if (saved.list === undefined) delete process.env[NET_PROXY_MODEL_SERVICES_ENV]; else process.env[NET_PROXY_MODEL_SERVICES_ENV] = saved.list;
  }
});

test("the egress proxy's handling note is on only for a launch with a DevTools relay (an ambient value never turns it on)", async () => {
  assert.equal(modelNoteOf({ browserCdp: "http://127.0.0.1:9222" }), "browser");
  assert.equal(modelNoteOf({ browser: true }), "browser");
  assert.equal(modelNoteOf({}), "");
  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], note: process.env[NET_PROXY_MODEL_NOTE_ENV] };
  process.env["MANDU_NET_PROXY_PORT"] = "8790";
  process.env[NET_PROXY_MODEL_NOTE_ENV] = "browser";
  try {
    const seen: Array<string | undefined> = [];
    const deps: ServiceDeps = {
      probePort: async () => false, probeIdentity: async () => null,
      waitFor: async () => true, waitForFile: async () => true,
      startDetachedCmd: (_c, _a, o) => { seen.push((o.env as Record<string, string | undefined>)[NET_PROXY_MODEL_NOTE_ENV]); return { pid: 7, stop: () => {} }; },
      runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    };
    await startNetProxy(plan({ confidentiality: true, requested: { netProxy: true, execWrap: false } }), Layout.dev("/repo"), "/run/sid", deps);
    await startNetProxy(plan({ confidentiality: true, browserCdp: "http://127.0.0.1:9222", requested: { netProxy: true, execWrap: false } }), Layout.dev("/repo"), "/run/sid", deps);
    assert.deepEqual(seen, ["", "browser"]);
  } finally {
    if (saved.port === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved.port;
    if (saved.note === undefined) delete process.env[NET_PROXY_MODEL_NOTE_ENV]; else process.env[NET_PROXY_MODEL_NOTE_ENV] = saved.note;
  }
});

test("registerProviderKeyGrants: one human-plane grant per key; a failure only warns (the key stays masked, unbound)", async () => {
  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  const logs: string[] = [];
  const ok = await registerProviderKeyGrants({ ...launch, arbiterHumanSock: "/h.sock" }, { TYPESAFE_API_KEY: "ts-1", OPENROUTER_API_KEY: "sk-or-1" }, {}, {
    call: async (sock, op, args) => { calls.push({ sock, op, args }); return args["env"] === "OPENROUTER_API_KEY" ? { granted: 0 } : { granted: 1 }; },
    log: (m) => logs.push(m), pid: 42,
  });
  assert.deepEqual(ok, [{ name: "TYPESAFE_API_KEY", hosts: ["api.typesafe.ai"] }]);
  assert.deepEqual(calls.map((c) => [c.sock, c.op, c.args["env"], c.args["pid"]]), [["/h.sock", "registerAuthGrant", "TYPESAFE_API_KEY", 42], ["/h.sock", "registerAuthGrant", "OPENROUTER_API_KEY", 42]]);
  assert.equal(logs.length, 1);
  assert.match(logs[0]!, /OPENROUTER_API_KEY not bound.*waits for your approval/);
  assert.ok(!logs.join("").includes("sk-or-1"), "never the value");
  const none: string[] = [];
  assert.deepEqual(await registerProviderKeyGrants({ ...launch, arbiterHumanSock: null }, { TYPESAFE_API_KEY: "ts-1" }, {}, { call: async () => { throw new Error("unreached"); }, log: (m) => none.push(m) }), []);
  assert.match(none[0]!, /no human-plane socket/);
  const thrown: string[] = [];
  assert.deepEqual(await registerProviderKeyGrants({ ...launch, arbiterHumanSock: "/h.sock" }, { TYPESAFE_API_KEY: "ts-1" }, {}, { call: async () => { throw new Error("socket gone"); }, log: (m) => thrown.push(m) }), []);
  assert.match(thrown[0]!, /socket gone/);
});
