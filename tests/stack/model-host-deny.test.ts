/**
 * model-host-deny e2e — a program in the agent's tree that dials the model
 * vendor itself (a `claude` started by its full path, its base URL removed
 * or pointed at the vendor) is refused at `/v1/messages`, while an account
 * call it makes there directly still passes and the agent's routed model
 * call still reaches the model through Mandu's model proxy (agent-sdks.md
 * §4, "The model-host deny").
 *
 * The REAL components, no agent and no model:
 *   - a real ArbiterServer in `secrets`;
 *   - the REAL net-proxy process the way a `mandu claude` launch starts it
 *     (services/net-proxy.ts `startNetProxy`, real deps), the plan updated as
 *     the manager updates it, and the agent's environment composed by the
 *     launcher (env-compose.ts `composeLaunch`: HTTPS_PROXY, NO_PROXY, the
 *     session CA);
 *   - "the vendor": a loopback TLS capture server with a certificate for
 *     api.anthropic.com. The net-proxy reaches it through a mock-sites host
 *     route; a client that dials the host around the egress proxy reaches it
 *     too (the stand-in's `--connect-to`, standing in for DNS);
 *   - the stand-in for a `claude` started by full path: a script at an
 *     absolute path that follows its environment only (`ANTHROPIC_BASE_URL`,
 *     the proxy variables, NO_PROXY), as Claude Code does, and posts with
 *     curl;
 *   - Mandu's model proxy (the real AnthropicProxy) outside the tree, its
 *     upstream a recorder: the routed call.
 *
 * Red on the code before the deny: the launch kept api.anthropic.com in
 * NO_PROXY, so the stand-in dialed the vendor directly and the capture
 * server received the model call with the secret in clear (and through the
 * egress proxy the host was a blind tunnel).
 *
 * Also held here: the launcher's host list equals the net-proxy's (the two
 * packages build independently).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile, spawnSync } from "node:child_process";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { composeLaunch } from "../../launcher/src/env-compose.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { MODEL_HOST_DENY_HOSTS } from "../../launcher/src/model-host-deny.js";
import { MODEL_HOST_NAMES } from "../../interceptors/net-proxy/src/model-host-paths.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: the deny rides that axis

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const CANARY = "sk-live-MODELHOSTDENY-a1b2c3d4e5f6a7b8c9d0";
const HAS_CURL = spawnSync("curl", ["--version"], { stdio: "ignore" }).status === 0;

/** The stand-in for a `claude` started by its full path: it follows its own
 *  environment, never Mandu's route. NO_PROXY decides whether it dials the
 *  host itself (then `--connect-to` stands in for DNS: the vendor here is
 *  the capture server) or goes through the egress proxy (curl reads
 *  HTTPS_PROXY / NO_PROXY and CURL_CA_BUNDLE itself). Prints the status and
 *  the body. */
const STAND_IN = `#!/bin/sh
path="$1"; data="$2"
base="\${ANTHROPIC_BASE_URL:-https://api.anthropic.com}"
host=$(printf '%s' "$base" | sed -E 's#^[a-z]+://([^/:]+).*#\\1#')
direct=""
IFS=,
for n in $NO_PROXY; do
  case "$host" in "$n"|*".$n") direct=1 ;; esac
done
unset IFS
set --
if [ -n "$direct" ] && [ "$host" = "api.anthropic.com" ]; then set -- --connect-to "api.anthropic.com:443:127.0.0.1:$MDU_TEST_VENDOR_PORT"; fi
if [ -n "$data" ]; then set -- "$@" -X POST -H 'content-type: application/json' --data-binary "$data"; fi
exec curl -sS --max-time 20 -w '\\n%{http_code}' "$@" "$base$path"
`;

/** The vendor: a loopback HTTPS server for api.anthropic.com recording each request. */
async function vendor(dir: string) {
  const ca = ensureCa(join(dir, "vendor-ca"));
  const leaf = leafForHost(ca, "api.anthropic.com");
  const seen: string[] = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push(`${req.method} ${req.url} ${b}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"account":{"uuid":"acct-1"}}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { seen, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

function run(script: string, env: Record<string, string>, path: string, data = ""): Promise<{ status: number; body: string }> {
  return new Promise((done) => {
    execFile(script, [path, data], { env }, (_e, out) => {
      const i = out.lastIndexOf("\n");
      done({ status: Number(out.slice(i + 1).trim()) || 0, body: out.slice(0, i) });
    });
  });
}

test("the launcher's model hosts are the net-proxy's (the packages build independently)", () => {
  assert.deepEqual([...MODEL_HOST_DENY_HOSTS], [...MODEL_HOST_NAMES]);
});

test(
  "a claude started by full path with a hostile environment is refused at /v1/messages; its account call passes; the routed call reaches the model",
  { skip: !opensslAvailable() ? "openssl unavailable" : !HAS_CURL ? "curl is not installed" : false, timeout: 180_000 },
  async () => {
    const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-model-host-deny-")));
    const home = join(tmp, "home");
    const ws = join(home, "proj");
    mkdirSync(ws, { recursive: true });
    const api = await vendor(tmp);
    const routes = join(tmp, "routes.yaml");
    writeFileSync(routes, ["hosts:", "  - host: api.anthropic.com", `    tls_to: 127.0.0.1:${api.port}`, `    tls_ca: ${JSON.stringify(api.caPath)}`, ""].join("\n"));

    const sock = join(tmp, "arbiter.sock");
    mkdirSync(join(tmp, "human"), { mode: 0o700 });
    const server = new ArbiterServer({
      socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"),
      dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
      confidentiality: true, integrity: false, policyPollMs: 0,
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(join(tmp, "human", "h.sock")); await human.connect();

    // Mandu's model proxy, outside the tree; its upstream records the call.
    const upstream = new MockUpstream({ json: { id: "msg_1", type: "message", role: "assistant", content: [{ type: "text", text: "hi" }] } });
    const modelProxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: upstream.fetcher, sessionKey: "model-host-deny", log: () => {} });
    const modelProxyPort = await modelProxy.listen(0);

    const plan = {
      target: "claude", argv: ["claude"], scopeId: "model-host-deny", tenant: "test", arbiterSock: sock,
      arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: ws, humanCwd: ws,
      noContextProxy: true, fsSync: false, basePath: "/usr/bin",
      proxy: { host: "127.0.0.1", port: modelProxyPort }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
      requested: { netProxy: true, execWrap: false }, execWrapCmds: [],
      ullm: { mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary: "claude" }, noScope: true, writeMcp: false, bestEffort: false, replyFilter: false,
      confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
      arbiterHumanSock: join(tmp, "human", "h.sock"), mockSitesPath: routes,
    } as unknown as LaunchPlan;

    const saved = process.env["MANDU_NET_PROXY_PORT"];
    delete process.env["MANDU_NET_PROXY_PORT"];
    const stops: Array<() => void> = [];
    try {
      const runDir = join(tmp, "run");
      mkdirSync(runDir);
      const r = await startNetProxy(plan, Layout.dev(REPO), runDir, { ...realDeps, home });
      stops.push(r.stop);
      // As the manager does (services/manager.ts).
      plan.netProxy = r.netProxy;
      plan.mitmCaCert = r.mitmCaCert;
      plan.mitmCaBundle = r.mitmCaBundle;
      plan.mitmUserTrust = r.mitmUserTrust;
      (plan as { modelHostDeny?: boolean }).modelHostDeny = (r as { modelHostDeny?: boolean }).modelHostDeny === true;
      assert.ok(plan.mitmCaCert, "TLS inspection is on with the confidentiality axis");

      // The agent's environment, as the launch composes it, plus a trust
      // bundle that also holds the vendor's test CA (so a direct dial
      // verifies, as it would against the real host).
      const agentEnv = composeLaunch(plan).env;
      const trust = join(tmp, "trust.pem");
      writeFileSync(trust, `${readFileSync(agentEnv["CURL_CA_BUNDLE"] ?? plan.mitmCaCert!, "utf8")}\n${readFileSync(api.caPath, "utf8")}\n`);
      const standIn = join(tmp, "versions", "2.1.302", "claude");
      mkdirSync(join(standIn, ".."), { recursive: true });
      writeFileSync(standIn, STAND_IN);
      chmodSync(standIn, 0o755);
      const base: Record<string, string> = { ...agentEnv, PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: home, CURL_CA_BUNDLE: trust, MDU_TEST_VENDOR_PORT: String(api.port) };
      assert.match(base["ANTHROPIC_BASE_URL"]!, /^http:\/\/127\.0\.0\.1:/, "the agent itself is routed to the model proxy");

      const body = JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 16, messages: [{ role: "user", content: `the key is ${CANARY}` }] });

      // ── the hostile starts: base URL removed, or pointed at the vendor ──
      const unset = { ...base };
      delete unset["ANTHROPIC_BASE_URL"];
      for (const [name, env] of [["ANTHROPIC_BASE_URL unset", unset], ["ANTHROPIC_BASE_URL at the vendor", { ...base, ANTHROPIC_BASE_URL: "https://api.anthropic.com" }]] as const) {
        const res = await run(standIn, env, "/v1/messages", body);
        assert.equal(res.status, 403, `${name}: CONFIDENTIALITY VIOLATION, the model call was not refused (${res.status}): ${res.body}`);
        assert.match(res.body, /POST \/v1\/messages on model host api\.anthropic\.com is refused/, name);
        assert.ok(!res.body.includes(CANARY), `${name}: the refusal never echoes the request`);
      }
      assert.deepEqual(api.seen.filter((s) => s.includes(CANARY) || s.includes("/v1/messages")), [], `CONFIDENTIALITY VIOLATION: the model call reached the vendor:\n${api.seen.join("\n")}`);

      // ── its account call, made there directly, still passes ──
      const profile = await run(standIn, unset, "/api/oauth/profile");
      assert.equal(profile.status, 200, `the account call is not refused: ${profile.body}`);
      assert.deepEqual(api.seen, ["GET /api/oauth/profile "]);

      // ── the routed call (the agent's own base URL) reaches the model through Mandu's model proxy ──
      const routed = await run(standIn, base, "/v1/messages", JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 16, messages: [{ role: "user", content: "hello" }] }));
      assert.equal(routed.status, 200, `the routed call passes: ${routed.body}`);
      assert.equal(upstream.requests.length, 1, "Mandu's model proxy reached its upstream");
      assert.match(upstream.requests[0]!.path, /^\/v1\/messages/);
      assert.deepEqual(api.seen, ["GET /api/oauth/profile "], "the routed call never touched the egress proxy's leg");

      // The net-proxy's log names each refusal by host, never the body.
      const log = readFileSync(join(runDir, "net-proxy.log"), "utf8");
      assert.match(log, /model host path refused/);
      assert.ok(!log.includes(CANARY), "the proxy's log never carries the body");
    } finally {
      for (const s of stops) s();
      if (saved === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved;
      await modelProxy.close();
      data.close();
      human.close();
      await server.close();
      api.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);
