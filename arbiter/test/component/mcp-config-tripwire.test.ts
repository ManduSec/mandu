/**
 * mcp-config-tripwire — the egress tripwire in the session whose agent
 * reads an MCP config (secret-discovery.md §2.10), over the real
 * ArbiterServer and its clients (the launcher's registrations on the human
 * socket, the net-proxy's scans on the data socket).
 *
 * The agent's own MCP configs are registered and left readable: the agent
 * sends its HTTP servers' credentials itself and its stdio servers hold
 * their variables. In that session (the net-proxy's `sessionLogins`, its
 * `mcpConfigs` naming the project `.mcp.json`):
 *   - an HTTP server's Authorization credential is exempt at the host of
 *     its entry's own `url` and trips at any other (narrower than a
 *     login's, which is exempt everywhere);
 *   - a stdio server's variable is exempt everywhere (its config names no
 *     host);
 *   - a tool result's row that holds the raw config (the model's masked
 *     Read, durable) does not refuse those values either, but a longer text
 *     of it (a whole line of the file) still trips;
 *   - the same value registered from another file (a `.env`) keeps that
 *     file's rule;
 *   - a scan that names no session, or a codex session, is as strict as
 *     before.
 * And the guard's question at another program's open (`labelledLevel`):
 * the project `.mcp.json` is gated by its found label (that program reads
 * the twin; the agent's own open is never gated), `~/.claude.json` is not.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON: registration and the tripwire exist only on this axis

const GH = "ghp_MCPTRIPclaudeStdioGitHub0123456789ab";
const LINEAR = "lin_api_MCPTRIPclaudeHttpLinear9z8y7x6w5v";
const BRAVE = "BSAmcpTRIPprojectBraveKey7x9Q2wZ5";
const PROJ = "pk_MCPTRIPprojectHttpBearer0123456789AB";

test("the tripwire in the session whose agent reads an MCP config: its HTTP credential at its own host only, its stdio variable anywhere, a tool result's copy too, another file's copy and other sessions as before", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-mcp-trip-")));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const claudeJson = join(home, ".claude.json");
  const claudeText = `${JSON.stringify({
    numStartups: 2,
    mcpServers: {
      github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: GH } },
      linear: { type: "http", url: "https://mcp.linear.app/mcp", headers: { Authorization: `Bearer ${LINEAR}` } },
    },
  }, null, 2)}\n`;
  writeFileSync(claudeJson, claudeText);
  const mcpJson = join(ws, ".mcp.json");
  writeFileSync(mcpJson, `${JSON.stringify({
    mcpServers: {
      brave: { command: "npx", args: ["-y", "@brave/brave-search-mcp-server"], env: { BRAVE_API_KEY: BRAVE } },
      project: { type: "http", url: "https://mcp.project.test/mcp", headers: { Authorization: `Bearer ${PROJ}` } },
    },
  }, null, 2)}\n`);
  const dotenv = join(ws, "svc", ".env");
  mkdirSync(join(ws, "svc"), { recursive: true });
  writeFileSync(dotenv, `BRAVE_API_KEY=${BRAVE}\n`);

  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  try {
    // The launch's secret setup, as the launcher runs it for `mandu claude`.
    const report = await client.discoverSecretsReport([home, ws], home, { target: "claude", ullmBinary: "claude" });
    const by = new Map(report.files.map((f) => [f.path, f]));
    assert.equal(by.get(claudeJson)?.agentConfig, "claude");
    assert.equal(by.get(mcpJson)?.agentConfig, "claude");
    assert.ok(by.has(dotenv) && by.get(dotenv)?.agentConfig === undefined);
    for (const f of report.files) assert.ok((await human.registerSecret({ path: f.path, home })).symbol, f.path);
    // What the guard asks at the open of a program other than the agent
    // (`labelledLevel`, §1.12): the project's `.mcp.json` is gated by its
    // found label, so such a program reads its twin; `.claude.json` is
    // Claude Code's login, pruned, readable to the agent's whole world.
    assert.equal((await client.labelledLevel({ path: mcpJson })).level, "no-model", "the project .mcp.json is gated at the open");
    assert.equal((await client.labelledLevel({ path: claudeJson })).level, "public", "~/.claude.json: an agent's login, never gated");

    const claudeSession = { home, target: "claude", ullmBinary: "claude", mcpConfigs: [mcpJson] };
    const codexSession = { home, target: "codex", ullmBinary: "codex" };
    const trips = async (where: "header" | "body", text: string, destination: string, sessionLogins?: Record<string, unknown>): Promise<boolean> =>
      (await client.egressFingerprintScan({ surfaces: [{ where, text }], destination, ...(sessionLogins ? { sessionLogins: sessionLogins as never } : {}) })).tripped;

    // ── the agent's own HTTP credentials: at their own hosts only ──
    assert.equal(await trips("header", `Bearer ${LINEAR}`, "mcp.linear.app", claudeSession), false, "~/.claude.json's Linear credential at its server's host");
    assert.equal(await trips("header", `Bearer ${LINEAR}`, "mcp.linear.app:443", claudeSession), false, "any port of it");
    assert.equal(await trips("header", `Bearer ${LINEAR}`, "attacker.example", claudeSession), true, "at another host, even in its own session");
    assert.equal(await trips("header", `Bearer ${PROJ}`, "mcp.project.test", claudeSession), false, ".mcp.json's HTTP credential at its server's host");
    assert.equal(await trips("header", `Bearer ${PROJ}`, "attacker.example", claudeSession), true);
    // ── the stdio servers' variables: anywhere (their config names no host) ──
    assert.equal(await trips("header", `token ${GH}`, "api.github.com", claudeSession), false);
    assert.equal(await trips("body", `{"q":"${GH}"}`, "elsewhere.example", claudeSession), false, "a stdio variable is exempt as a login's token is");
    // …but BRAVE is also another file's value (a `.env`), which keeps its rule.
    assert.equal(await trips("body", `{"key":"${BRAVE}"}`, "api.search.brave.com", claudeSession), true, "the .env's row still trips on the same value");

    // ── other sessions, and no session: as before ──
    for (const v of [`Bearer ${LINEAR}`, `token ${GH}`, `Bearer ${PROJ}`]) {
      assert.equal(await trips("header", v, "mcp.linear.app"), true, `no session: ${v.slice(0, 12)}…`);
      assert.equal(await trips("header", v, "attacker.example", codexSession), true, `a codex session: ${v.slice(0, 12)}…`);
    }
    assert.equal(await trips("header", `token ${GH}`, "api.github.com", { ...claudeSession, home: join(dir, "elsewhere") }), true, "another HOME's config exempts nothing");
    assert.equal(await trips("header", `Bearer ${PROJ}`, "mcp.project.test", { home, target: "claude" }), true, "a session naming no .mcp.json: that file's rows are not its own");

    // ── a tool result's row that holds the raw config (the model's masked Read) ──
    await client.symbolize({ tool: "Read", value: claudeText, origin: claudeJson, callId: "toolu_mcp_read", sessionKey: "s1", confidentiality: "no-model" });
    assert.equal(await trips("header", `token ${GH}`, "api.github.com", claudeSession), false, "the server's own token after the model read the config");
    assert.equal(await trips("header", `Bearer ${LINEAR}`, "mcp.linear.app", claudeSession), false);
    assert.equal(await trips("header", LINEAR, "mcp.linear.app", claudeSession), false, "the credential after its scheme word");
    assert.equal(await trips("header", `Bearer ${LINEAR}`, "attacker.example", claudeSession), true, "still not at another host");
    const line = claudeText.split("\n").find((l) => l.includes(GH))!;
    assert.ok(line.length >= 24);
    assert.equal(await trips("body", line, "api.github.com", claudeSession), true, "a whole line of the file is more than the server's own value: it trips");
    assert.equal(await trips("header", `token ${GH}`, "api.github.com", codexSession), true, "a codex session is refused it");
  } finally {
    client.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
