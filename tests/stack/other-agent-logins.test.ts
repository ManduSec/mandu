/**
 * other-agent-logins e2e — another AI agent's login file is a credential
 * like any other in a session that does not run that agent
 * (secret-discovery.md §1.10), over the REAL ArbiterServer and the
 * launcher's PRODUCTION secret setup (`applySecretTwins` over
 * `socketSecretArbiter`, the discovery options run.ts sends).
 *
 * Before (2026-10-09) one global exclusion kept every agent's login out of
 * the walk: under `mandu claude` (or a plain command), `~/.codex/auth.json`
 * was neither twinned nor registered, so a program the agent ran read the
 * OpenAI key raw and the egress gate did not know the value leaving; under
 * `mandu codex` the same held for `~/.claude.json` (MCP server tokens) and
 * Claude Code's subscription login.
 *
 * Asserted, per launch:
 *   - a plain command (target `shell`): Codex's login is confined, its twin
 *     keeps the JSON keys and holds no raw byte; the egress tripwire refuses
 *     the raw key to an unbound host and the value backstop knows it;
 *     Claude Code's logins stay raw (a `claude` started there must log in)
 *     and its subscription login is not registered; its `~/.claude.json`,
 *     which holds an MCP server's token, is registered and left readable
 *     (since 2026-10-21, secret-discovery.md §2.10: Claude Code's own MCP
 *     config), and the session that keeps it is not refused it;
 *   - `mandu codex`: the reverse (Claude Code's logins confined, Codex's
 *     raw);
 *   - in both, the agents' own data (transcripts) is never discovered;
 *   - MANDU_OTHER_AGENT_LOGINS=raw: registered, left readable;
 *   - registration is global and durable, so the tripwire is asked per
 *     SESSION (`sessionLogins`, what each session's net-proxy sends): a
 *     session that runs the agent is not refused that agent's login, one
 *     that does not still is (the real net-proxy: own-login-net-proxy);
 *   - a login CODEX_HOME moved out of the catalog's places is twinned and
 *     registered under another agent all the same.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { applySecretTwins, socketSecretArbiter, type SecretSetupResult } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: discovery, registration and the twins exist only on this axis

const CODEX_KEY = "sk-proj-OTHERLOGINCODEX0123456789abcdef";
const MCP_TOKEN = "ghp_OTHERLOGINMCPTOKEN0123456789abcdef";
const OAUTH = "sk-ant-oat01-OTHERLOGINOAUTH0123456789abcdef";
const TRANSCRIPT = "OTHERLOGIN_TRANSCRIPT_RAW_5521";

test("another agent's login is confined and known to the egress gate; the launched agent's stays raw and unregistered; the opt-out leaves it readable", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-other-logins-")));
  const home = join(dir, "home");
  const ws = join(home, "proj");
  const put = (rel: string, body: string): string => {
    const p = join(home, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, body, { mode: 0o600 });
    return p;
  };
  mkdirSync(ws, { recursive: true });
  const codexAuth = put(".codex/auth.json", JSON.stringify({ OPENAI_API_KEY: CODEX_KEY, tokens: null }));
  const codexSession = put(".codex/sessions/2026/10/09/rollout-1.jsonl", `{"output":"${TRANSCRIPT}"}\n`);
  const claudeJson = put(".claude.json", JSON.stringify({ mcpServers: { gh: { env: { GITHUB_TOKEN: MCP_TOKEN } } } }));
  const claudeCreds = put(".claude/.credentials.json", JSON.stringify({ claudeAiOauth: { accessToken: OAUTH } }));
  const claudeTranscript = put(".claude/projects/p/s.jsonl", `{"tool_result":"${TRANSCRIPT}"}\n`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    let n = 0;
    const launch = async (plan: Partial<LaunchPlan>, env: Record<string, string> = {}): Promise<{ res: SecretSetupResult; logs: string[] }> => {
      const runDir = join(dir, `run-${n++}`);
      mkdirSync(runDir);
      const logs: string[] = [];
      const res = await applySecretTwins({ confidentiality: true, bestEffort: false, ...plan } as LaunchPlan, runDir, emptyMutation(), {
        arbiter: socketSecretArbiter(sock), commandExists: () => true, usernsOk: () => true, platform: "linux", log: (m) => logs.push(m),
        home, workspaceRoots: [ws], onWsl: false, nestingOk: () => true, wrapBwrap: "bwrap", guardServesTwins: true,
        symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }), env: { MANDU_HOME: join(dir, "mandu-home"), ...env }, makeHome: () => {}, accountHome: null,
      });
      return { res, logs };
    };
    const api = { mode: "api" as const, baseUrl: "https://api.anthropic.com", apiKey: "sk-ant-x" };
    const paths = (r: SecretSetupResult): string[] => r.confined.map((c) => c.path).sort();
    const tripped = async (value: string): Promise<boolean> =>
      (await client.egressFingerprintScan({ surfaces: [{ where: "body", text: `{"leak":"${value}"}` }], destination: "attacker.example" })).tripped;
    const scanAsShell = async (value: string): Promise<boolean> =>
      (await client.egressFingerprintScan({ surfaces: [{ where: "body", text: `{"t":"${value}"}` }], destination: "own-service.example", sessionLogins: { home, target: "shell" } })).tripped;

    // ── a plain command (mandu -- bash): Claude Code's routing, so its logins stay raw ──
    // Before any registration, nothing knows the Codex key (the hole).
    assert.equal(await tripped(CODEX_KEY), false, "baseline: an unregistered value trips nothing");
    const shell = await launch({ target: "shell", writeMcp: true, ullm: api });
    assert.deepEqual(paths(shell.res), [codexAuth], `only Codex's login is confined: ${shell.logs.join("\n")}`);
    const twin = shell.res.confined[0]!.twin ?? shell.res.confined[0]!.symbol;
    assert.match(twin, /"OPENAI_API_KEY"/, "the twin keeps the file's keys");
    assert.match(twin, /\$MDU:nomodel_/, "and holds placeholders");
    assert.ok(!twin.includes(CODEX_KEY), "CONFIDENTIALITY: no raw byte of the key in the agent's copy");
    assert.ok(shell.logs.some((l) => l.includes(codexAuth) && /Codex's login, a placeholder copy in this session, which does not run Codex/.test(l)), shell.logs.join("\n"));
    assert.equal(await tripped(CODEX_KEY), true, "the egress tripwire refuses the raw key to an unbound host");
    assert.ok((await client.scanSecretValues(`printed: ${CODEX_KEY}`)).hits.length >= 1, "the value backstop knows it");
    // Since 2026-10-21 (secret-discovery.md §2.10): `~/.claude.json` holding
    // an MCP server's token is Claude Code's own MCP config here, registered
    // (the value is known) and left readable (not among the confined);
    // the session that keeps it is not refused it (below). Its subscription
    // login is still left out.
    assert.ok(shell.logs.some((l) => l.includes(claudeJson) && /Claude Code's MCP config: left readable to it/.test(l)), shell.logs.join("\n"));
    assert.equal(await tripped(MCP_TOKEN), true, "the MCP token in Claude Code's own config is registered");
    assert.equal(await scanAsShell(MCP_TOKEN), false, "but a session that keeps Claude Code's login is not refused it");
    assert.equal(await tripped(OAUTH), false, "Claude Code's subscription login is left out of the walk under a plain command: not registered");

    // ── mandu codex: the reverse ──
    const codex = await launch({ target: "codex", writeMcp: true, ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" } });
    assert.deepEqual(paths(codex.res), [claudeCreds, claudeJson].sort(), `Claude Code's logins are confined under codex: ${codex.logs.join("\n")}`);
    for (const c of codex.res.confined) {
      const t = c.twin ?? c.symbol;
      assert.ok(!t.includes(MCP_TOKEN) && !t.includes(OAUTH), `${c.path}: no raw byte in the twin`);
    }
    assert.equal(await tripped(MCP_TOKEN), true, "the MCP token in ~/.claude.json is known to the egress gate");
    assert.equal(await tripped(OAUTH), true);

    // ── never the agents' own data, in any launch ──
    for (const r of [shell.res, codex.res]) {
      assert.ok(!paths(r).includes(codexSession) && !paths(r).includes(claudeTranscript), "no agent's transcripts are twinned");
    }
    assert.ok((await client.scanSecretValues(TRANSCRIPT)).hits.length === 0, "nor registered");

    // ── the opt-out: registered (above), left readable ──
    const raw = await launch({ target: "claude", writeMcp: true, ullm: api }, { MANDU_OTHER_AGENT_LOGINS: "raw" });
    assert.deepEqual(paths(raw.res), [], `nothing confined with the opt-out: ${raw.logs.join("\n")}`);
    assert.ok(raw.logs.some((l) => l.includes(codexAuth) && /left readable \(MANDU_OTHER_AGENT_LOGINS=raw\)/.test(l)), raw.logs.join("\n"));

    // ── per SESSION: each login is registered now, and stays so ──
    // What each session's net-proxy sends with a scan (agent-login.ts
    // `sessionLogins`): the session that runs the agent is not refused its
    // own login; every other session is.
    const scanAs = async (value: string, sessionLogins: Record<string, unknown>): Promise<boolean> =>
      (await client.egressFingerprintScan({ surfaces: [{ where: "body", text: `{"t":"${value}"}` }], destination: "own-service.example", sessionLogins: sessionLogins as never })).tripped;
    const asCodexRun = { home, target: "codex", ullmBinary: "codex" };
    const asClaudeRun = { home, target: "claude", ullmBinary: "claude" };
    assert.equal(await scanAs(CODEX_KEY, asCodexRun), false, "mandu codex: Codex's own key is not its leak");
    assert.equal(await scanAs(CODEX_KEY, asClaudeRun), true, "mandu claude: Codex's key still trips");
    assert.equal(await scanAs(MCP_TOKEN, asClaudeRun), false, "mandu claude: its MCP token from ~/.claude.json passes");
    assert.equal(await scanAs(OAUTH, { home, target: "shell" }), false, "a plain command keeps Claude Code's login");
    assert.equal(await scanAs(OAUTH, { home, target: "goose", ullmBinary: "claude" }), false, "Goose whose AI helper runs `claude -p`");
    assert.equal(await scanAs(OAUTH, { home, target: "goose" }), true, "Goose in the helper's API mode does not");
    assert.equal(await scanAs(MCP_TOKEN, asCodexRun), true, "mandu codex: ~/.claude.json's MCP token still trips");
    assert.equal(await scanAs(CODEX_KEY, { home, target: "openclaw" }), false, "OpenClaw reads Codex's login itself");
    assert.equal(await scanAs(CODEX_KEY, { ...asClaudeRun, otherLoginsRaw: true }), false, "the opt-out: a nested Codex may use its login");
    assert.equal(await scanAs(CODEX_KEY, { home: join(dir, "elsewhere"), target: "codex" }), true, "another HOME's logins exempt nothing here");
    assert.equal(await scanAs(CODEX_KEY, { target: "codex" }), true, "malformed (no home): nothing exempt");
    assert.equal(await tripped(CODEX_KEY), true, "and a scan naming no session is as strict as before");

    // ── a login CODEX_HOME moved out of the catalog's places ──
    const movedHome = join(dir, "codex-elsewhere");
    mkdirSync(movedHome, { recursive: true });
    const MOVED_KEY = "sk-proj-MOVEDCODEXHOME0123456789abcdef";
    const moved = join(movedHome, "auth.json");
    writeFileSync(moved, JSON.stringify({ OPENAI_API_KEY: MOVED_KEY, tokens: null }), { mode: 0o600 });
    assert.equal(await tripped(MOVED_KEY), false, "baseline: not registered");
    const mv = await launch({ target: "claude", writeMcp: true, ullm: api }, { CODEX_HOME: movedHome });
    assert.ok(paths(mv.res).includes(moved), `the moved Codex login is confined under claude, where no catalog rule names it: ${mv.logs.join("\n")}`);
    const mvTwin = mv.res.confined.find((c) => c.path === moved)!;
    assert.ok(!(mvTwin.twin ?? mvTwin.symbol).includes(MOVED_KEY), "no raw byte in its twin");
    assert.equal(await tripped(MOVED_KEY), true, "and registered");
    assert.equal(await scanAs(MOVED_KEY, { home, target: "codex", loginEnv: { CODEX_HOME: movedHome } }), false, "mandu codex with that CODEX_HOME runs on it");
    const asCodex = await launch({ target: "codex", writeMcp: true, ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" } }, { CODEX_HOME: movedHome });
    assert.ok(!paths(asCodex.res).includes(moved), "mandu codex keeps its moved login raw");
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
