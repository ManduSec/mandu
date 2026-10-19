/**
 * goose-provider-fence — a provider Mandu does not route receives nothing
 * from a `mandu goose` session (supported-agents.md §5.6.3), over the REAL
 * components and with no agent:
 *
 *   the env fence   the launch env exactly as the launcher composes it
 *                   (goose-route.ts gooseRoutePlan over the user's env and
 *                   config, env-compose.ts composeLaunch over the user's env),
 *                   with the user's env pointing EVERY endpoint key of every
 *                   unrouted provider (and a declarative provider's own
 *                   `${VAR}`) at a counting upstream: each key, as a goose
 *                   1.53.0 provider joins its request path to it (what a
 *                   `/model --provider <name>` switch builds mid-session),
 *                   lands on the REAL anthropic-proxy (production wiring,
 *                   real arbiter, `secrets`), which refuses it 403; the
 *                   counting upstream and the routed openai upstream see
 *                   NOTHING;
 *   the host fence  the REAL net-proxy the launcher starts
 *                   (services/net-proxy.ts startNetProxy) with the goose
 *                   launch's deny list: a CONNECT to a bundled provider's host
 *                   and a plain-HTTP request to the user's own declarative
 *                   provider's literal host are refused 403 before any dial,
 *                   the counting upstream sees nothing, a control host is
 *                   reached.
 *
 * The real goose's own leg (its switch reads the fence) is
 * goose-provider-fence.test.ts (CI's guest has goose).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { composeLaunch } from "../../launcher/src/env-compose.js";
import { GOOSE_COMPAT_PROVIDERS, GOOSE_PROVIDER_FENCE, gooseRoutePlan, readGooseConfig } from "../../launcher/src/goose-route.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps, probeIdentity } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { netProxyDenyHosts, uploadDenyHosts, uploadDenyProxyOnlyHosts } from "../../launcher/src/upload-deny.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const CANARY = "GOOSE-FENCE-CANARY-3307 raw tool output";

/** A counting upstream: every request it receives, by host and path. */
async function counting(): Promise<{ server: Server; port: number; seen: string[] }> {
  const seen: string[] = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { seen.push(`${req.method} ${req.headers.host}${req.url} ${b.slice(0, 60)}`); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: (server.address() as AddressInfo).port, seen };
}

/** goose-providers api_client.rs build_url: a trailing `/` on the base, then
 *  the request path joined (a relative path keeps the base's path). */
function gooseUrl(base: string, path: string): URL {
  const u = new URL(base);
  if (u.pathname !== "/" && !u.pathname.endsWith("/")) u.pathname = `${u.pathname}/`;
  return new URL(path, u);
}

function send(url: URL, body: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((done, reject) => {
    const r = httpRequest(
      { host: url.hostname, port: Number(url.port), method: "POST", path: `${url.pathname}${url.search}`, headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), authorization: "Bearer sk-user-provider-key", ...headers } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => done({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

function basePlan(tmp: string, over: Partial<LaunchPlan>): LaunchPlan {
  return {
    target: "goose", argv: ["goose", "session"], scopeId: "goose-fence", tenant: "test", arbiterSock: join(tmp, "arbiter.sock"),
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: tmp, humanCwd: tmp,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: { mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: true, writeMcp: false, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: join(tmp, "human", "h.sock"),
    ...over,
  } as unknown as LaunchPlan;
}

test("the env fence: every endpoint key of every unrouted provider, as the launcher composes the env over the user's, reaches only the real proxy's refusal; the user's provider and the routed upstream see nothing", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-goose-fence-"));
  const user = await counting(); // stands in for every provider the user set up
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(join(tmp, "arbiter.sock"));
  await real.connect();
  const sessionKey = `goose-fence-${process.pid}`;
  assert.equal((await real.setSessionSpec({ sessionKey, spec: "goose", requestedBy: "goose-provider-fence e2e" })).bound, "goose");
  const openaiUp = new MockUpstream();
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(real), // PRODUCTION wiring
    upstream: new MockUpstream().fetcher,
    sessionKey,
    log: () => {},
    // an openai session: the one OpenAI route the launch serves
    openaiUpstreams: { openai: "https://api.openai.com" },
    openaiFetcher: () => openaiUp.fetcher,
  });
  try {
    const port = await proxy.listen(0);
    const userUrl = `http://127.0.0.1:${user.port}`;
    // The user's own Goose setup: every endpoint key at their provider, and
    // a declarative provider of their own whose host is a `${VAR}`.
    const root = join(tmp, "goose-root");
    mkdirSync(join(root, "config", "custom_providers"), { recursive: true });
    writeFileSync(join(root, "config", "custom_providers", "corp.json"), JSON.stringify({ name: "corp_llm", engine: "openai", base_url: "${CORP_LLM_HOST}/v1/chat/completions" }));
    const userEnv: Record<string, string> = { GOOSE_PATH_ROOT: root, CORP_LLM_HOST: userUrl };
    for (const f of GOOSE_PROVIDER_FENCE) userEnv[f.key] = f.form === "command" ? "/usr/bin/true" : f.form === "url" ? userUrl : "127.0.0.1";
    // the Chat Completions providers this launch does not route: their keys
    // are pinned at their own proxy route, refused the same way
    for (const c of GOOSE_COMPAT_PROVIDERS) userEnv[c.hostKey] = userUrl;
    const plan = gooseRoutePlan(["goose", "session"], userEnv, readGooseConfig(userEnv));
    assert.equal(plan.refusal, null);
    const launch = composeLaunch(basePlan(tmp, { proxy: { host: "127.0.0.1", port }, gooseRouting: plan.routing } as Partial<LaunchPlan>));
    const agentEnv = { ...userEnv, ...launch.env }; // the spawn: the launch's keys win

    const urlKeys = [...GOOSE_PROVIDER_FENCE.filter((f) => f.form === "url").map((f) => f.key), ...GOOSE_COMPAT_PROVIDERS.map((c) => c.hostKey), "CORP_LLM_HOST"];
    for (const key of urlKeys) {
      for (const path of ["v1/chat/completions", "api/chat", "v1/messages"]) {
        const u = gooseUrl(agentEnv[key]!, path);
        assert.equal(u.port, String(port), `${key}: ${u.href} is the proxy`);
        const r = await send(u, JSON.stringify({ model: "m", stream: true, messages: [{ role: "tool", content: CANARY }] }));
        assert.equal(r.status, 403, `${key} + ${path}: ${r.body}`);
        assert.match(r.body, /did not route that provider/, key);
        assert.ok(!r.body.includes(CANARY), "the refusal never echoes the request");
      }
    }
    for (const f of GOOSE_PROVIDER_FENCE.filter((x) => x.form !== "url")) {
      assert.notEqual(agentEnv[f.key], userEnv[f.key], `${f.key}: the user's value is overridden`);
    }
    // a switch to the routed openai provider still goes through (the control)
    const ok = await send(gooseUrl(agentEnv["OPENAI_HOST"]!, "v1/chat/completions"), JSON.stringify({ model: "gpt-4o", stream: false, messages: [{ role: "user", content: "hi" }] }));
    assert.notEqual(ok.status, 403, ok.body);
    assert.equal(openaiUp.requests.length, 1, "the routed provider's own request reached its upstream");
    assert.ok(!openaiUp.requests.some((q) => q.bodyText.includes(CANARY)), "no fenced request reached the routed upstream");
    assert.deepEqual(user.seen, [], "INVARIANT: no unrouted provider received anything");
  } finally {
    await proxy.close().catch(() => {});
    real.close();
    await server.close().catch(() => {});
    user.server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the host fence: the real net-proxy started with a goose launch's list refuses a bundled provider's host and the user's declarative provider's host before any dial; a control host is reached", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-goose-fence-np-"));
  const up = await counting();
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const savedPort = process.env["MANDU_NET_PROXY_PORT"];
  delete process.env["MANDU_NET_PROXY_PORT"]; // port 0: the port-file handshake
  let stop = (): void => {};
  try {
    // The user's declarative provider at a literal host, and a control name:
    // both route to the counting upstream through mock-sites, so a deny that
    // failed would reach it.
    const root = join(tmp, "goose-root");
    mkdirSync(join(root, "config", "custom_providers"), { recursive: true });
    writeFileSync(join(root, "config", "custom_providers", "cloud.json"), JSON.stringify({ name: "cloud_llm", engine: "openai", base_url: `http://llm.vendor.test:${up.port}/v1` }));
    const routes = join(tmp, "routes.yaml");
    writeFileSync(routes, `hosts:\n${["llm.vendor.test", "control.vendor.test", "api.groq.com"].map((h) => `  - host: "${h}"\n    to: "127.0.0.1:${up.port}"\n`).join("")}`);
    const env = { GOOSE_PATH_ROOT: root };
    // what run.ts computes for a goose launch
    const plan = basePlan(tmp, {
      uploadDenyHosts: uploadDenyHosts("goose", env, readGooseConfig(env)),
      netProxyOnlyDenyHosts: uploadDenyProxyOnlyHosts("goose"),
      mockSitesPath: routes,
    } as Partial<LaunchPlan>);
    assert.ok(plan.uploadDenyHosts!.includes(`llm.vendor.test:${up.port}`), plan.uploadDenyHosts!.join(","));
    const r = await startNetProxy(plan, Layout.dev(REPO), tmp, realDeps);
    stop = r.stop;
    const port = r.netProxy.port;
    // the identity carries the whole list: a launch with another list would not adopt this proxy
    const id = await probeIdentity("127.0.0.1", port);
    assert.deepEqual([...(id?.denyHosts ?? [])].sort(), netProxyDenyHosts(plan).sort());

    // a bundled provider's host (a `/model --provider groq` switch): 403
    for (const target of ["api.groq.com:443", "chatgpt.com:443", "x.api.individual.githubcopilot.com:443"]) {
      const head = await new Promise<string>((done, reject) => {
        const s = netConnect(port, "127.0.0.1", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
        let buf = "";
        s.setEncoding("utf8");
        s.on("data", (c: string) => { buf += c; if (buf.includes("\r\n\r\n")) { done(buf); s.destroy(); } });
        s.on("error", reject);
        setTimeout(() => reject(new Error(`CONNECT ${target} timed out`)), 5000).unref();
      });
      assert.match(head, /^HTTP\/1\.1 403/, target);
    }
    // the user's declarative provider (plain HTTP through the proxy): 403, nothing reached
    const viaProxy = (host: string, body: string) => new Promise<{ status: number; body: string }>((done, reject) => {
      const url = `http://${host}:${up.port}/v1/chat/completions`;
      const q = httpRequest({ host: "127.0.0.1", port, method: "POST", path: url, headers: { host: `${host}:${up.port}`, "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => done({ status: res.statusCode ?? 0, body: b }));
      });
      q.on("error", reject);
      q.end(body);
    });
    const denied = await viaProxy("llm.vendor.test", JSON.stringify({ messages: [{ role: "tool", content: CANARY }] }));
    assert.equal(denied.status, 403, denied.body);
    assert.match(denied.body, /provider Mandu does not route/);
    assert.ok(!denied.body.includes(CANARY));
    assert.deepEqual(up.seen, [], "INVARIANT: the provider's host saw NOTHING");
    // control: another name to the same upstream is not on the list
    const ok = await viaProxy("control.vendor.test", "{}");
    assert.equal(ok.status, 200, ok.body);
    assert.equal(up.seen.length, 1);
  } finally {
    stop();
    if (savedPort === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = savedPort;
    await server.close();
    up.server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
