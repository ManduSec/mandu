/**
 * upload-deny — an agent's own transcript / trace upload is denied at the
 * network layer (supported-agents.md §5.3.4 rule 1), end to end over the REAL
 * components and with no agent: the launcher computes the deny list
 * (upload-deny.ts `uploadDenyHosts`, here from a test table row with a fixed
 * host and a URL env key), starts the REAL net-proxy process the way a launch
 * does (services/net-proxy.ts `startNetProxy`, real deps), gated by a real
 * arbiter in `secrets` mode. A plain-HTTP upload and a CONNECT to a listed
 * host are refused with 403 and a counting upstream standing in for the
 * upload host sees nothing; the same upstream under another spelling (a
 * control) is reached. The proxy publishes the list in its identity, so a
 * later launch with another list would not adopt it. The connect guard's leg
 * (`--deny` beats `tcp:*:*`) is launcher.net-guard-live.
 *
 * The upload host and the control are NAMES a mock-sites host route sends to
 * the loopback upstream: the net-proxy relays nothing to this machine
 * (blocked-destinations.ts, 2026-10-05), so the upstream's own address
 * through the proxy is refused, which the last leg checks.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps, probeIdentity } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { uploadDenyGuardSpecs, uploadDenyHosts, uploadDenyProxyOnlyHosts, type UploadDenyEntry } from "../../launcher/src/upload-deny.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const PAYLOAD = "TRANSCRIPT-ORIGINAL-TOOL-OUTPUT-c0ffee";

function post(proxyPort: number, url: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((done, reject) => {
    const u = new URL(url);
    const r = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: "POST", path: url, headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => done({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

function connectHead(proxyPort: number, target: string): Promise<string> {
  return new Promise((done, reject) => {
    const s = netConnect(proxyPort, "127.0.0.1", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = "";
    s.setEncoding("utf8");
    s.on("data", (c: string) => { buf += c; if (buf.includes("\r\n\r\n")) { done(buf); s.destroy(); } });
    s.on("error", reject);
    setTimeout(() => reject(new Error(`CONNECT ${target} timed out`)), 5000).unref();
  });
}

test("an agent's upload host is refused by the real net-proxy the launcher starts; the upload host sees nothing; a control is reached", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-upload-deny-"));
  // The counting upstream standing in for the agent's upload host.
  const seen: string[] = [];
  const upstream: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { seen.push(`${req.headers.host} ${b}`); res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const up = (upstream.address() as AddressInfo).port;

  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();

  // The launcher's list: a fixed host and the host of a set URL env key (the
  // user's trace collector), as an agent row would name them.
  const table: Record<string, UploadDenyEntry> = {
    "test-agent": { fixed: ["relay.example.invalid"], urlEnv: ["TEST_AGENT_TRACE_URL"] },
  };
  const hosts = uploadDenyHosts("test-agent", { TEST_AGENT_TRACE_URL: `http://trace.upload.test:${up}/api/public/ingestion` }, undefined, table);
  assert.deepEqual(hosts, ["relay.example.invalid", `trace.upload.test:${up}`]);
  // Both names route to the counting upstream, so a deny that failed would
  // reach it.
  const routes = join(tmp, "routes.yaml");
  writeFileSync(routes, ["trace.upload.test", "control.upload.test"].map((h) => `  - host: "${h}"\n    to: "127.0.0.1:${up}"\n`).join("").replace(/^/, "hosts:\n"));

  const plan = {
    target: "claude", argv: ["claude"], scopeId: "upload-deny", tenant: "test", arbiterSock: join(tmp, "arbiter.sock"),
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: tmp, humanCwd: tmp,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: { mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: true, writeMcp: false, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: join(tmp, "human", "h.sock"),
    uploadDenyHosts: hosts,
    mockSitesPath: routes,
  } as unknown as LaunchPlan;

  const savedPort = process.env["MANDU_NET_PROXY_PORT"];
  delete process.env["MANDU_NET_PROXY_PORT"]; // port 0: the port-file handshake
  let stop = (): void => {};
  try {
    const r = await startNetProxy(plan, Layout.dev(REPO), tmp, realDeps);
    stop = r.stop;
    const port = r.netProxy.port;

    // The identity carries the list: the reuse key of a later launch.
    const id = await probeIdentity("127.0.0.1", port);
    assert.deepEqual(id?.denyHosts, hosts);

    // A plain-HTTP trace upload to the listed host:port → 403, nothing reached.
    const denied = await post(port, `http://trace.upload.test:${up}/api/public/ingestion`, JSON.stringify({ batch: [{ output: PAYLOAD }] }));
    assert.equal(denied.status, 403, denied.body);
    assert.match(denied.body, /upload host Mandu denies/);
    assert.ok(!denied.body.includes(PAYLOAD), "the refusal never echoes the upload");
    // A CONNECT to the fixed host → 403 before any dial (no DNS needed).
    assert.match(await connectHead(port, "relay.example.invalid:443"), /^HTTP\/1\.1 403/);
    assert.deepEqual(seen, [], "the upload host saw NOTHING");

    // Control: the same upstream under another spelling is not on the list.
    const ok = await post(port, `http://control.upload.test:${up}/control`, "{}");
    assert.equal(ok.status, 200, ok.body);
    assert.deepEqual(seen, [`control.upload.test:${up} {}`]);
    // The upstream's own loopback address through the proxy: this machine, refused.
    const local = await post(port, `http://127.0.0.1:${up}/control`, "{}");
    assert.equal(local.status, 403, local.body);
    assert.match(local.body, /is this machine/);
    assert.equal(seen.length, 1, "nothing more reached the upstream");
  } finally {
    stop();
    if (savedPort === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = savedPort;
    await server.close();
    upstream.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** The real net-proxy the launcher starts, gated by a real arbiter in
 *  `secrets` mode, with this deny list and these names routed to `up` (a
 *  mock-sites route). */
async function startDenyProxy(tmp: string, hosts: string[], proxyOnly: string[], routed: string[], up: number): Promise<{ port: number; stop: () => Promise<void> }> {
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const routes = join(tmp, "routes.yaml");
  writeFileSync(routes, routed.map((h) => `  - host: "${h}"\n    to: "127.0.0.1:${up}"\n`).join("").replace(/^/, "hosts:\n"));
  const plan = {
    target: "codex", argv: ["codex"], scopeId: "upload-deny-codex", tenant: "test", arbiterSock: join(tmp, "arbiter.sock"),
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: tmp, humanCwd: tmp,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: { mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: true, writeMcp: false, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: join(tmp, "human", "h.sock"),
    uploadDenyHosts: hosts,
    netProxyOnlyDenyHosts: proxyOnly,
    mockSitesPath: routes,
  } as unknown as LaunchPlan;
  const savedPort = process.env["MANDU_NET_PROXY_PORT"];
  delete process.env["MANDU_NET_PROXY_PORT"]; // port 0: the port-file handshake
  try {
    const r = await startNetProxy(plan, Layout.dev(REPO), tmp, realDeps);
    return { port: r.netProxy.port, stop: async () => { r.stop(); await server.close(); } };
  } catch (e) {
    await server.close();
    throw e;
  } finally {
    if (savedPort === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = savedPort;
  }
}

test("codex: the launcher's codex row (Statsig, Sentry, the user's OTLP collectors) is refused by the real net-proxy; chatgpt.com, which the sign-in needs, is reached", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-upload-deny-codex-"));
  const seen: string[] = [];
  const upstream: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { seen.push(`${req.headers.host} ${req.url}`); res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const up = (upstream.address() as AddressInfo).port;
  // The REAL codex row: its fixed hosts, the env's collector, a config.toml
  // layer's `[otel]` exporter endpoint, and its net-proxy-only host.
  const config = { layers: [{ path: join(tmp, "config.toml"), text: `[otel]\nexporter = { otlp-http = { endpoint = "http://otel.config.test:${up}/v1/logs", protocol = "binary" } }\n` }] };
  const hosts = uploadDenyHosts("codex", { OTEL_EXPORTER_OTLP_ENDPOINT: `http://otel.env.test:${up}` }, config);
  const proxyOnly = uploadDenyProxyOnlyHosts("codex");
  for (const h of ["o33249.ingest.us.sentry.io", `otel.env.test:${up}`, `otel.config.test:${up}`]) {
    assert.ok(hosts.includes(h), `${h} is on the codex deny list (${hosts.join(", ")})`);
  }
  assert.deepEqual(proxyOnly, ["ab.chatgpt.com"]);
  assert.ok(![...hosts, ...proxyOnly].some((h) => /(^|\.)chatgpt\.com$/.test(h) && h !== "ab.chatgpt.com"), "chatgpt.com itself is not denied");
  // The connect guard denies by address, and ab.chatgpt.com shares
  // chatgpt.com's: it is left to the net-proxy, by name.
  const guard = uploadDenyGuardSpecs(hosts);
  assert.ok(guard.includes("tcp:o33249.ingest.us.sentry.io:*"), guard.join(", "));
  assert.ok(!guard.some((s) => s.includes("chatgpt.com")), guard.join(", "));

  const proxy = await startDenyProxy(tmp, hosts, proxyOnly, ["otel.config.test", "otel.env.test", "chatgpt.com"], up);
  try {
    // Statsig and Sentry: CONNECT refused before any dial.
    assert.match(await connectHead(proxy.port, "ab.chatgpt.com:443"), /^HTTP\/1\.1 403/);
    assert.match(await connectHead(proxy.port, "o33249.ingest.us.sentry.io:443"), /^HTTP\/1\.1 403/);
    // The user's collectors (config and env): a log export carrying tool
    // output is refused, and the collector sees nothing.
    for (const h of ["otel.config.test", "otel.env.test"]) {
      const r = await post(proxy.port, `http://${h}:${up}/v1/logs`, JSON.stringify({ resourceLogs: [{ body: PAYLOAD }] }));
      assert.equal(r.status, 403, `${h}: ${r.body}`);
      assert.ok(!r.body.includes(PAYLOAD));
    }
    assert.deepEqual(seen, [], "no upload host saw anything");
    // Control: chatgpt.com (the sign-in's account and plugin calls) is reached.
    const ok = await post(proxy.port, `http://chatgpt.com:${up}/backend-api/wham/accounts/check`, "{}");
    assert.equal(ok.status, 200, ok.body);
    assert.deepEqual(seen, [`chatgpt.com:${up} /backend-api/wham/accounts/check`]);
  } finally {
    await proxy.stop();
    upstream.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
