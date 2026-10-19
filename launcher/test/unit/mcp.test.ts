/**
 * mcp.test — the inspect-mcp config content for cli vs api U-LLM mode, and
 * its location: the SCOPE RUN DIR (delivered by --mcp-config), never the
 * cwd's project-scope .mcp.json (services/mcp.ts header, 2026-09-05).
 */
import { test } from "node:test";
import { Layout } from "../../src/services/layout.js";
import assert from "node:assert/strict";
import { rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writeMcpConfig } from "../../src/services/mcp.js";
import type { LaunchPlan } from "../../src/types.js";
// removed when the test process exits, also when a test fails (test-organization.md §8.5)
import { tmpDir } from "../lib/tmp-dir.js";

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid-2", tenant: "live", arbiterSock: "/run/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/e", cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

test("cli mode: binary hint, base URL = real endpoint, NO api key", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({ cwd: "/w" }), Layout.dev("/repo"), dir);
  assert.equal(p, join(dir, "mcp.json"), "written into the scope run dir, not <cwd>/.mcp.json");
  const j = JSON.parse(readFileSync(p, "utf8"));
  const s = j.mcpServers["mandu-inspect"];
  // node --import <the package-local tsx ESM entry> (layout.ts devTsx), never the tsx binary
  assert.equal(s.command, "node");
  assert.equal(s.args[0], "--import");
  assert.match(s.args[1], /inspect-mcp\/node_modules\/tsx\/dist\/esm\/index\.mjs$/);
  assert.match(s.args[2], /inspect-mcp.*server-main\.ts$/);
  assert.equal(s.env.MANDU_ARBITER_SOCK, "/run/b.sock");
  assert.equal(s.env.MANDU_SCOPE_ID, "sid-2");
  assert.equal(s.env.MANDU_ULLM_MODE, "cli");
  assert.equal(s.env.ANTHROPIC_BASE_URL, "https://api.anthropic.com");
  assert.equal(s.env.MANDU_ULLM_BINARY, "claude");
  assert.equal(s.env.ANTHROPIC_API_KEY, undefined);
  rmSync(dir, { recursive: true, force: true });
});

test("codex U-LLM: the entry names the agent's CODEX_HOME (Codex hands a stdio server no CODEX_HOME); a claude U-LLM never gets one", () => {
  const dir = tmpDir("mcp-");
  const codex = JSON.parse(readFileSync(writeMcpConfig(plan({
    target: "codex", argv: ["codex"],
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex", codexHome: "/runs/x/codex-home" },
  }), Layout.dev("/repo"), dir), "utf8")).mcpServers["mandu-inspect"];
  assert.equal(codex.env.MANDU_ULLM_BINARY, "codex");
  assert.equal(codex.env.CODEX_HOME, "/runs/x/codex-home");
  const claude = JSON.parse(readFileSync(writeMcpConfig(plan({
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude", codexHome: "/runs/x/codex-home" },
  }), Layout.dev("/repo"), dir), "utf8")).mcpServers["mandu-inspect"];
  assert.equal(claude.env.CODEX_HOME, undefined);
  const unset = JSON.parse(readFileSync(writeMcpConfig(plan({
    target: "codex", argv: ["codex"], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" },
  }), Layout.dev("/repo"), dir), "utf8")).mcpServers["mandu-inspect"];
  assert.equal(unset.env.CODEX_HOME, undefined, "no CODEX_HOME in the launcher env: Codex's own default (HOME/.codex)");
  rmSync(dir, { recursive: true, force: true });
});

test("api mode: quarantined key present, no binary hint; model emitted when set", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({ ullm: { mode: "api", baseUrl: "https://api.anthropic.com", apiKey: "sk-q", model: "claude-haiku-4-5" } }), Layout.dev("/repo"), dir);
  const s = JSON.parse(readFileSync(p, "utf8")).mcpServers["mandu-inspect"];
  assert.equal(s.env.ANTHROPIC_API_KEY, "sk-q");
  assert.equal(s.env.MANDU_ULLM_BINARY, undefined);
  assert.equal(s.env.MANDU_ULLM_MODEL, "claude-haiku-4-5");
  rmSync(dir, { recursive: true, force: true });
});

test("forwarder live: base URL is the loopback relay AND the trust pin names it (both env vars)", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude", forwarderUrl: "http://127.0.0.1:8791" },
  }), Layout.dev("/repo"), dir);
  const s = JSON.parse(readFileSync(p, "utf8")).mcpServers["mandu-inspect"];
  // ANTHROPIC_BASE_URL routes the U-LLM through the relay; the pin is what lets
  // inspect-mcp's loopback guard accept EXACTLY that URL and nothing else.
  assert.equal(s.env.ANTHROPIC_BASE_URL, "http://127.0.0.1:8791");
  assert.equal(s.env.MANDU_ULLM_FORWARDER, "http://127.0.0.1:8791");
  rmSync(dir, { recursive: true, force: true });
});

test("no forwarder: no pin env at all (the guard keeps refusing every loopback)", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({}), Layout.dev("/repo"), dir);
  const s = JSON.parse(readFileSync(p, "utf8")).mcpServers["mandu-inspect"];
  assert.equal(s.env.MANDU_ULLM_FORWARDER, undefined);
  assert.equal(s.env.ANTHROPIC_BASE_URL, "https://api.anthropic.com");
  rmSync(dir, { recursive: true, force: true });
});

test("the mandu-policy server rides the same config: socket, session key and project directory only, no U-LLM env; --no-policy-mcp drops it", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({ ullm: { mode: "api", baseUrl: "https://api.anthropic.com", apiKey: "sk-q" }, tenant: "test", cwd: "/av/w", humanCwd: "/home/me/proj" }), Layout.dev("/repo"), dir);
  const servers = JSON.parse(readFileSync(p, "utf8")).mcpServers;
  assert.deepEqual(Object.keys(servers).sort(), ["mandu-inspect", "mandu-policy"]);
  const s = servers["mandu-policy"];
  assert.match(s.args[s.args.length - 1], /policy-mcp.*server-main\.ts$/);
  // MANDU_PROJECT_DIR (2026-10-04): the launch directory a relative path in a
  // proposed edit is read in, in the labels' spelling (humanCwd, not cwd)
  assert.deepEqual(s.env, { MANDU_ARBITER_SOCK: "/run/b.sock", MANDU_SCOPE_ID: "sid-2", MANDU_TENANT: "test", MANDU_PROJECT_DIR: "/home/me/proj" });
  assert.equal(s.env.ANTHROPIC_API_KEY, undefined, "the quarantine key never reaches a server that has no model");
  const off = writeMcpConfig(plan({ writePolicyMcp: false }), Layout.dev("/repo"), dir);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(off, "utf8")).mcpServers), ["mandu-inspect"]);
  rmSync(dir, { recursive: true, force: true });
});

// ── confidentiality-plan-11 D5: inspect-mcp's refusal list of model proxies ──
import { inspectMcpConfigDoc, modelProxyOrigins } from "../../src/services/mcp.js";
import { stateAxes } from "../axes.js";
stateAxes("secrets"); // the refusal list guards local-model routing; the config builder reads no axis

test("modelProxyOrigins: both adopted proxies as http origins, IPv6 bracketed, port 0 left out, deduped", () => {
  assert.equal(modelProxyOrigins({ proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 } }), "http://127.0.0.1:8788,http://127.0.0.1:8789");
  assert.equal(modelProxyOrigins({ proxy: { host: "::1", port: 41000 }, openaiProxy: { host: "127.0.0.1", port: 0 } }), "http://[::1]:41000");
  assert.equal(modelProxyOrigins({ proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 } }), "");
  assert.equal(modelProxyOrigins({}), "");
});

test("the inspect server's env carries MANDU_MODEL_PROXY_URL = the session's model proxy origins (the adopted port), absent when none is live", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({ proxy: { host: "127.0.0.1", port: 43210 }, openaiProxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"), dir);
  const s = JSON.parse(readFileSync(p, "utf8")).mcpServers["mandu-inspect"];
  assert.equal(s.env.MANDU_MODEL_PROXY_URL, "http://127.0.0.1:43210");
  assert.equal(s.env.ANTHROPIC_BASE_URL, "https://api.anthropic.com", "the U-LLM's own base URL is unchanged");
  rmSync(dir, { recursive: true, force: true });
  const none = inspectMcpConfigDoc(plan({ proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"));
  assert.equal(none.mcpServers["mandu-inspect"]!.env["MANDU_MODEL_PROXY_URL"], undefined);
  // A direct-spawn caller without a plan still builds a valid config.
  const bare = inspectMcpConfigDoc({ arbiterSock: "/s", scopeId: "x", ullm: { mode: "cli", baseUrl: "https://api.anthropic.com" } }, Layout.dev("/repo"));
  assert.equal(bare.mcpServers["mandu-inspect"]!.env["MANDU_MODEL_PROXY_URL"], undefined);
});

test("token_env (plan 11 D2): a declared LOCAL endpoint's token rides the inspect-mcp entry with the real value; an outside entry's does not; never over a variable already set", () => {
  const dir = tmpDir("mcp-");
  const p = writeMcpConfig(plan({
    ullm: { mode: "api", baseUrl: "https://api.anthropic.com", apiKey: "sk-q" },
    modelEndpoints: [
      { name: "own", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "OLLAMA_BEARER" },
      { name: "gw", url: "https://gw.example", wire: "anthropic", local: false, tokenEnv: "GW_BEARER" },
      { name: "clash", url: "http://127.0.0.1:4000", wire: "anthropic", local: true, tokenEnv: "ANTHROPIC_API_KEY" },
      { name: "unset", url: "http://127.0.0.1:5000", wire: "openai-chat", model: "m", local: true, tokenEnv: "UNSET_BEARER" },
    ],
    modelTokens: { OLLAMA_BEARER: "tok-real-1", GW_BEARER: "tok-gw", ANTHROPIC_API_KEY: "tok-clash" },
  }), Layout.dev("/repo"), dir);
  const env = JSON.parse(readFileSync(p, "utf8")).mcpServers["mandu-inspect"].env;
  assert.equal(env.OLLAMA_BEARER, "tok-real-1", "the local endpoint's token, unmasked, for the helper alone");
  assert.equal(env.GW_BEARER, undefined, "inspect-mcp never dials an outside entry (D5): its token is not handed over");
  assert.equal(env.ANTHROPIC_API_KEY, "sk-q", "a token_env naming a variable the entry already sets does not replace it");
  assert.equal("UNSET_BEARER" in env, false, "an unset variable is left out");
  rmSync(dir, { recursive: true, force: true });
});

test("plan 12 D3: the declared local endpoints' client keys ride the inspect-mcp entry as MANDU_MODEL_CLIENT_KEYS; none, nothing set", () => {
  const dir = tmpDir("mcp-");
  const keys = { corp: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n" };
  const p = writeMcpConfig(plan({ modelClientKeys: keys }), Layout.dev("/repo"), dir);
  const env = JSON.parse(readFileSync(p, "utf8")).mcpServers["mandu-inspect"].env;
  assert.deepEqual(JSON.parse(env.MANDU_MODEL_CLIENT_KEYS), keys);
  const p2 = writeMcpConfig(plan({ modelClientKeys: {} }), Layout.dev("/repo"), dir);
  assert.equal("MANDU_MODEL_CLIENT_KEYS" in JSON.parse(readFileSync(p2, "utf8")).mcpServers["mandu-inspect"].env, false);
  rmSync(dir, { recursive: true, force: true });
});
