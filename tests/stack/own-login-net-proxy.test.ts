/**
 * own-login-net-proxy e2e — an AI agent's own login, registered by ANOTHER
 * session, does not trip the egress tripwire in a session that runs that
 * agent; in a session that does not, it still does (secret-discovery.md
 * §1.10 "In the session that runs the agent").
 *
 * A launch that does not run an agent registers that agent's login file
 * (`~/.codex/auth.json` under `mandu claude`, `~/.claude.json` under `mandu
 * codex`), and registration is global and durable: the values stay in the
 * arbiter after that launch. The §4 tripwire scans every request the
 * net-proxy reads for registered values; without the session's own logins
 * (`MANDU_NET_PROXY_SESSION_LOGINS`) it refused a later `mandu codex` its
 * own ChatGPT token refresh to auth.openai.com and its bearer to
 * chatgpt.com, and a later `mandu claude` its MCP server's bearer from
 * `~/.claude.json` (found in review, 2026-10-10).
 *
 * The REAL components, no agent: a real ArbiterServer in `secrets`; the
 * launcher's PRODUCTION secret setup (`applySecretTwins` over
 * `socketSecretArbiter`) for a `mandu claude` and a `mandu codex` launch,
 * which register each other's logins; and, per session, the REAL net-proxy
 * process the way a launch starts it (services/net-proxy.ts
 * `startNetProxy`, real deps, the session's plan and HOME). The service
 * hosts (auth.openai.com, chatgpt.com, api.githubcopilot.com) are names a
 * mock-sites host route sends to a counting loopback upstream, so nothing
 * leaves the machine. Plain HTTP: the tripwire scans the plain leg as it
 * scans a decrypted one.
 *
 * Asserted:
 *   - `mandu codex`'s net-proxy: Codex's refresh token to auth.openai.com
 *     and its access token to chatgpt.com reach the host (200);
 *     `~/.claude.json`'s MCP token to api.githubcopilot.com is refused (403,
 *     the tripwire), nothing reaches the host;
 *   - `mandu claude`'s: the reverse;
 *   - `mandu claude` with MANDU_OTHER_AGENT_LOGINS=raw: Codex started
 *     inside can refresh (200);
 *   - the refusals name the symbol, never the value.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { applySecretTwins, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: registration and the tripwire exist only on this axis

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const REFRESH = "rt_OWNLOGINREFRESH0123456789abcdefABCDEF";
const ACCESS = "eyJhbGciOiJSUzI1NiJ9.OWNLOGINACCESS0123456789abcdef.sig0123456789";
const MCP = "ghp_OWNLOGINMCPTOKEN0123456789abcdefABCD";
const HOSTS = ["auth.openai.com", "chatgpt.com", "api.githubcopilot.com"];

function send(proxyPort: number, url: string, opts: { body?: string; auth?: string }): Promise<{ status: number; body: string }> {
  return new Promise((done, reject) => {
    const u = new URL(url);
    const body = opts.body ?? "";
    const r = httpRequest(
      {
        host: "127.0.0.1", port: proxyPort, method: body ? "POST" : "GET", path: url,
        headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body), ...(opts.auth ? { authorization: `Bearer ${opts.auth}` } : {}) },
      },
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

test("another session's registration of an agent's login refuses that agent nothing in its own session's net-proxy, and still trips in a session that does not run it", { timeout: 180_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-own-login-")));
  const home = join(tmp, "home");
  const ws = join(home, "proj");
  mkdirSync(ws, { recursive: true });
  const put = (rel: string, body: string): void => {
    const p = join(home, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, body, { mode: 0o600 });
  };
  // A ChatGPT-mode Codex login and Claude Code's config with an HTTP MCP server's bearer.
  put(".codex/auth.json", JSON.stringify({ OPENAI_API_KEY: null, tokens: { id_token: ACCESS, access_token: ACCESS, refresh_token: REFRESH, account_id: "acc-1" }, last_refresh: "2026-10-01T00:00:00Z" }, null, 2));
  put(".claude.json", JSON.stringify({ numStartups: 3, mcpServers: { gh: { type: "http", url: "https://api.githubcopilot.com/mcp/", headers: { Authorization: `Bearer ${MCP}` } } } }, null, 2));

  // The counting upstream standing in for the agents' own services.
  const seen: string[] = [];
  const upstream: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { seen.push(`${req.headers.host} ${req.headers.authorization ?? ""} ${b}`); res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const up = (upstream.address() as AddressInfo).port;
  const routes = join(tmp, "routes.yaml");
  writeFileSync(routes, "hosts:\n" + HOSTS.map((h) => `  - host: "${h}"\n    to: "127.0.0.1:${up}"\n`).join(""));

  const sock = join(tmp, "arbiter.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();

  const cli = (binary: string) => ({ mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary });
  const planFor = (target: string, binary: string, scopeId: string): LaunchPlan => ({
    target, argv: [target], scopeId, tenant: "test", arbiterSock: sock,
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: ws, humanCwd: ws,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: cli(binary), noScope: true, writeMcp: true, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: join(tmp, "human", "h.sock"), mockSitesPath: routes,
  } as unknown as LaunchPlan);
  const claudePlan = planFor("claude", "claude", "own-login-claude");
  const codexPlan = planFor("codex", "codex", "own-login-codex");

  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], raw: process.env["MANDU_OTHER_AGENT_LOGINS"] };
  delete process.env["MANDU_NET_PROXY_PORT"]; // port 0: each session its own proxy, as by default
  delete process.env["MANDU_OTHER_AGENT_LOGINS"];
  const stops: Array<() => void> = [];
  let n = 0;
  /** The session's secret setup, as a launch runs it. */
  const secretSetup = async (plan: LaunchPlan): Promise<string[]> => {
    const runDir = join(tmp, `run-${n++}`);
    mkdirSync(runDir);
    const res = await applySecretTwins(plan, runDir, emptyMutation(), {
      arbiter: socketSecretArbiter(sock), commandExists: () => true, usernsOk: () => true, platform: "linux", log: () => {},
      home, workspaceRoots: [ws], onWsl: false, nestingOk: () => true, wrapBwrap: "bwrap", guardServesTwins: true,
      symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }), env: { MANDU_HOME: join(tmp, "mandu-home") }, makeHome: () => {}, accountHome: null,
    });
    return res.confined.map((c) => c.path);
  };
  /** The session's REAL net-proxy, as a launch starts it, for this HOME. */
  const netProxy = async (plan: LaunchPlan): Promise<number> => {
    const runDir = join(tmp, `np-${n++}`);
    mkdirSync(runDir);
    const r = await startNetProxy(plan, Layout.dev(REPO), runDir, { ...realDeps, home });
    stops.push(r.stop);
    return r.netProxy.port;
  };
  try {
    // ── two launches: each registers the OTHER agent's login ──
    assert.deepEqual(await secretSetup(claudePlan), [join(home, ".codex", "auth.json")], "mandu claude confines (and registers) Codex's login");
    assert.deepEqual(await secretSetup(codexPlan), [join(home, ".claude.json")], "mandu codex confines (and registers) ~/.claude.json");

    const codexPort = await netProxy(codexPlan);
    const claudePort = await netProxy(claudePlan);
    const refresh = JSON.stringify({ client_id: "app_x", grant_type: "refresh_token", refresh_token: REFRESH, scope: "openid profile email" });

    // ── mandu codex: its own login goes to its own services ──
    const own1 = await send(codexPort, `http://auth.openai.com:${up}/oauth/token`, { body: refresh });
    assert.equal(own1.status, 200, `Codex's own refresh is not refused in mandu codex: ${own1.body}`);
    const own2 = await send(codexPort, `http://chatgpt.com:${up}/backend-api/wham/usage`, { auth: ACCESS });
    assert.equal(own2.status, 200, `Codex's own bearer to chatgpt.com is not refused: ${own2.body}`);
    // …while Claude Code's MCP token, registered by this very launch, still trips here.
    const other1 = await send(codexPort, `http://api.githubcopilot.com:${up}/mcp/`, { auth: MCP, body: "{}" });
    assert.equal(other1.status, 403, other1.body);
    assert.match(other1.body, /fingerprint tripwire/);
    assert.ok(!other1.body.includes(MCP), "the refusal names the symbol, never the value");

    // ── mandu claude: the reverse ──
    const own3 = await send(claudePort, `http://api.githubcopilot.com:${up}/mcp/`, { auth: MCP, body: "{}" });
    assert.equal(own3.status, 200, `Claude Code's own MCP bearer is not refused in mandu claude: ${own3.body}`);
    const other2 = await send(claudePort, `http://auth.openai.com:${up}/oauth/token`, { body: refresh });
    assert.equal(other2.status, 403, `a session that does not run Codex still trips on Codex's token: ${other2.body}`);
    assert.match(other2.body, /fingerprint tripwire/);
    assert.ok(!other2.body.includes(REFRESH));
    const other3 = await send(claudePort, `http://chatgpt.com:${up}/backend-api/wham/usage`, { auth: ACCESS });
    assert.equal(other3.status, 403, other3.body);

    // ── MANDU_OTHER_AGENT_LOGINS=raw under mandu claude: a nested Codex can refresh ──
    process.env["MANDU_OTHER_AGENT_LOGINS"] = "raw";
    const rawPort = await netProxy({ ...claudePlan, scopeId: "own-login-claude-raw" } as LaunchPlan);
    delete process.env["MANDU_OTHER_AGENT_LOGINS"];
    const nested = await send(rawPort, `http://auth.openai.com:${up}/oauth/token`, { body: refresh });
    assert.equal(nested.status, 200, `the opt-out keeps a nested Codex working: ${nested.body}`);

    // THE ORACLE: exactly the allowed requests reached the hosts, no refused one.
    const reached = seen.map((s) => s.split(" ")[0]!.replace(/:\d+$/, ""));
    assert.deepEqual(reached, ["auth.openai.com", "chatgpt.com", "api.githubcopilot.com", "auth.openai.com"], seen.join("\n"));
  } finally {
    for (const s of stops) s();
    if (saved.port === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved.port;
    if (saved.raw === undefined) delete process.env["MANDU_OTHER_AGENT_LOGINS"]; else process.env["MANDU_OTHER_AGENT_LOGINS"] = saved.raw;
    await server.close();
    upstream.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
