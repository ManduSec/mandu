/**
 * claude-env-key.test — Claude Code's ANTHROPIC_API_KEY put back at the model
 * proxy (agent-sign-in.md §3.8), through the REAL launcher (`main()`), the
 * real arbiter daemon and the autostarted anthropic-proxy, against a scripted
 * upstream on loopback (TLS) that records each request's `x-api-key`. Made-up
 * keys only; no network; no model. No guard (MANDU_NO_KERNEL=1).
 *
 * The agent is a stand-in under `--target claude` (a node script with Claude
 * Code's wire behavior: it sends its ANTHROPIC_API_KEY as `x-api-key` to
 * ANTHROPIC_BASE_URL, and its prompt holds that value, as a model context
 * would hold whatever the agent read). It also plays the inspect server: it
 * reads the U-LLM's entry from the MCP config the launcher wrote and makes
 * the U-LLM's model call with that entry's key and base URL (the loopback
 * forwarder). The oracle:
 *
 *   granted  the agent's environment and the MCP config hold no key, only
 *            placeholders; the upstream receives the REAL key in x-api-key
 *            on the agent's turn (put back by the proxy) and on the U-LLM's
 *            call (put back by the forwarder); no request body carries it;
 *   opt-out  MANDU_AUTH_SUBSTITUTION=0: the variable stays raw, as before,
 *            and the key still reaches the upstream.
 */
import { test, before, after } from "node:test";
import "../lib/private-home.js"; // the Mandu home, npm cache and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { delimiter, join } from "node:path";
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { main } from "../lib/launch-in-dir.js";
import { FAKE_KEY, startStand, type Stand } from "../lib/goose-login-stand.js";
import { stateAxes } from "../axes.js";
import { spawnSync } from "node:child_process";

stateAxes("secrets"); // the shipped default: the variable is masked only with confidentiality on

const SKIP = spawnSync("openssl", ["version"], { encoding: "utf8" }).status !== 0 ? "no openssl (the scripted upstream's certificate)" : false;

/** The stand-in agent: Claude Code's wire for the main turn, the inspect
 *  server's for the U-LLM call. Writes what it saw to argv[2]. */
const AGENT = String.raw`
const fs = require("node:fs");
const out = process.argv[2], mcpPath = process.argv[3];
const key = process.env.ANTHROPIC_API_KEY || "";
async function post(base, apiKey, text) {
  const r = await fetch(base.replace(/\/+$/, "") + "/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01", ...(process.env.ANTHROPIC_CUSTOM_HEADERS ? Object.fromEntries(process.env.ANTHROPIC_CUSTOM_HEADERS.split(";").map((h) => { const i = h.indexOf(":"); return [h.slice(0, i).trim(), h.slice(i + 1).trim()]; })) : {}) },
    body: JSON.stringify({ model: "claude-sonnet-4-5", max_tokens: 16, stream: true, messages: [{ role: "user", content: text }] }),
  });
  await r.text();
  return r.status;
}
(async () => {
  const seen = { envKey: key, baseUrl: process.env.ANTHROPIC_BASE_URL, ullmVar: process.env.MANDU_ULLM_API_KEY ?? null };
  seen.turn = await post(process.env.ANTHROPIC_BASE_URL, key, "my key is " + key);
  let mcp = "";
  try { mcp = fs.readFileSync(mcpPath, "utf8"); } catch {}
  seen.mcp = mcp;
  const inspect = mcp ? JSON.parse(mcp).mcpServers["mandu-inspect"].env : null;
  if (inspect && inspect.MANDU_ULLM_FORWARDER) {
    seen.ullmKey = inspect.ANTHROPIC_API_KEY;
    seen.ullm = await post(inspect.ANTHROPIC_BASE_URL, inspect.ANTHROPIC_API_KEY, "inspect this");
  }
  fs.writeFileSync(out, JSON.stringify(seen));
})().catch((e) => { fs.writeFileSync(out, JSON.stringify({ error: String(e) })); process.exit(1); });
`;

let stand: Stand;
before(async () => { if (!SKIP) stand = await startStand("mdu-claude-key-"); });
after(async () => { await stand?.close(); });

interface Seen { ullmVar?: string | null; envKey: string; baseUrl: string; turn: number; mcp: string; ullmKey?: string; ullm?: number; error?: string }

async function launch(name: string, extraEnv: Record<string, string>): Promise<{ code: number; lines: string[]; seen: Seen }> {
  const home = join(stand.tmp, name);
  mkdirSync(join(home, "work"), { recursive: true });
  const agent = join(stand.tmp, `${name}-agent.cjs`);
  writeFileSync(agent, AGENT);
  const out = join(stand.tmp, `${name}-seen.json`);
  const mcpPath = join(stand.tmp, `${name}-mcp.json`);
  const lines: string[] = [];
  const orig = console.error;
  const savedHome = process.env["HOME"];
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  process.env["HOME"] = home;
  process.env["MANDU_MCP_CONFIG"] = mcpPath;
  try {
    const code = await main(
      // --landlock-net: MANDU_NO_KERNEL drops it, and the U-LLM forwarder
      // (where the U-LLM's key is put back) runs only with it.
      ["--target", "claude", "--no-scope", "--landlock-net", "--", process.execPath, agent, out, mcpPath],
      {
        HOME: home, PATH: process.env["PATH"], PWD: join(home, "work"),
        MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: stand.tmp,
        MANDU_ARBITER_SOCK: stand.sock, MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets", MANDU_VERBOSE: "1",
        MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_FS_SYNC: "0", MANDU_NO_KERNEL: "1",
        // The U-LLM's endpoint: the same scripted upstream, through the forwarder.
        MANDU_ULLM_BASE_URL: stand.upstreamOrigin,
        ANTHROPIC_API_KEY: FAKE_KEY,
        ...extraEnv,
      },
    );
    let seen: Seen;
    try { seen = JSON.parse(readFileSync(out, "utf8")) as Seen; } catch { seen = { error: "the agent wrote nothing" } as Seen; }
    return { code, lines, seen };
  } finally {
    console.error = orig;
    delete process.env["MANDU_MCP_CONFIG"];
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    rmSync(out, { force: true });
  }
}

test("granted: the agent's environment and its MCP config hold placeholders; the upstream gets the real key from the proxy and from the U-LLM forwarder; no body carries it", { skip: SKIP, timeout: 300_000 }, async () => {
  stand.seen.length = 0;
  const { code, lines, seen } = await launch("granted", {});
  assert.equal(code, 0, `${JSON.stringify(seen)}\n${lines.join("\n")}`);
  assert.equal(seen.error, undefined, seen.error);
  assert.match(seen.envKey, /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.ANTHROPIC_API_KEY$/, "the agent's environment holds the placeholder");
  assert.equal(seen.turn, 200, "the agent's turn went through");
  assert.ok(seen.mcp !== "" && !seen.mcp.includes(FAKE_KEY), `the MCP config in the agent's world holds no key: ${seen.mcp}\n${lines.join("\n")}`);
  assert.match(seen.ullmKey ?? "", /^mandu-ullm-key-[0-9a-f]+$/, "the U-LLM's entry holds a stand-in");
  assert.equal(seen.ullm, 200, "the U-LLM's call went through");
  const keyed = stand.seen.filter((q) => q.key === FAKE_KEY);
  assert.ok(keyed.length >= 2, `the upstream got the REAL key on both calls: ${stand.seen.map((q) => `${q.path} ${q.key?.slice(0, 20)}`).join(", ")}`);
  for (const q of stand.seen) {
    assert.ok(!q.body.includes(FAKE_KEY), "INVARIANT: no request body carries the key");
    assert.ok(!q.body.includes("MANDUFAKEgooseLOGIN"), "INVARIANT: not even a piece of it");
  }
  assert.ok(stand.seen.some((q) => q.body.includes(seen.envKey)), "the model's context keeps the placeholder");
  assert.ok(lines.some((l) => /ANTHROPIC_API_KEY is a placeholder in Claude Code's environment/.test(l)), lines.join("\n"));
});

test("opt-out (MANDU_AUTH_SUBSTITUTION=0): the variable stays raw, as before, and the key still reaches the upstream", { skip: SKIP, timeout: 300_000 }, async () => {
  stand.seen.length = 0;
  const { code, lines, seen } = await launch("optout", { MANDU_AUTH_SUBSTITUTION: "0" });
  assert.equal(code, 0, `${JSON.stringify(seen)}\n${lines.join("\n")}`);
  assert.equal(seen.envKey, FAKE_KEY, "raw in the agent's environment (the exemption)");
  assert.equal(seen.turn, 200);
  assert.ok(stand.seen.some((q) => q.key === FAKE_KEY));
  assert.ok(!lines.some((l) => /placeholder in Claude Code's environment/.test(l)));
});

test("MANDU_ULLM_API_KEY (§3.11): never in the agent's environment; the AI helper's entry holds a stand-in and the forwarder puts that key (not ANTHROPIC_API_KEY) back", { skip: SKIP, timeout: 300_000 }, async () => {
  const ULLM_KEY = "sk-ant-api03-MANDUFAKEullmOWNkey0123456789abcdefABCDEF";
  stand.seen.length = 0;
  const { code, lines, seen } = await launch("ullm-own", { MANDU_ULLM_API_KEY: ULLM_KEY });
  assert.equal(code, 0, `${JSON.stringify(seen)}\n${lines.join("\n")}`);
  assert.equal(seen.ullmVar, null, "MANDU_ULLM_API_KEY is not in the agent's environment");
  assert.ok(!seen.mcp.includes(ULLM_KEY) && !seen.mcp.includes(FAKE_KEY), "nor in the helper's entry");
  assert.equal(seen.ullm, 200);
  const ullmCalls = stand.seen.filter((q) => q.body.includes("inspect this"));
  assert.ok(ullmCalls.length === 1 && ullmCalls[0]!.key === ULLM_KEY, "the helper's call carried MANDU_ULLM_API_KEY, put back by the forwarder");
  for (const q of stand.seen) assert.ok(!q.body.includes(ULLM_KEY) && !q.body.includes(FAKE_KEY), "INVARIANT: no body carries a key");
});

/** The claude binary (MANDU_CLAUDE_BIN, else PATH), or null. */
function findClaude(): string | null {
  const pinned = process.env["MANDU_CLAUDE_BIN"];
  if (pinned) return existsSync(pinned) ? pinned : null;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    if (d && existsSync(join(d, "claude"))) return join(d, "claude");
  }
  return null;
}
const CLAUDE = findClaude();

test("the REAL claude (-p): it sends the placeholder it holds, the upstream gets the real key in x-api-key, no request body carries it", { skip: SKIP || (CLAUDE === null ? "no claude binary: set MANDU_CLAUDE_BIN or put claude on PATH" : false), timeout: 300_000 }, async () => {
  stand.seen.length = 0;
  stand.command = null;
  const home = join(stand.tmp, "real");
  mkdirSync(join(home, "work"), { recursive: true });
  const lines: string[] = [];
  const orig = console.error;
  const savedHome = process.env["HOME"];
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  process.env["HOME"] = home;
  let code: number;
  try {
    code = await main(
      ["--target", "claude", "--no-scope", "--no-mcp", "--", CLAUDE!, "-p", "say hi"],
      {
        HOME: home, PATH: process.env["PATH"], PWD: join(home, "work"),
        MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: stand.tmp,
        MANDU_ARBITER_SOCK: stand.sock, MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets", MANDU_VERBOSE: "1",
        MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_FS_SYNC: "0", MANDU_NO_KERNEL: "1",
        CLAUDE_CONFIG_DIR: join(home, ".claude"), DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        ANTHROPIC_MODEL: "claude-sonnet-4-5",
        ANTHROPIC_API_KEY: FAKE_KEY,
      },
    );
  } finally {
    console.error = orig;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
  }
  assert.equal(code, 0, lines.join("\n"));
  const turns = stand.seen.filter((q) => /\/v1\/messages/.test(q.path));
  assert.ok(turns.length >= 1, `claude's turns reached the upstream: ${stand.seen.map((q) => q.path).join(", ")}\n${lines.join("\n")}`);
  for (const q of turns) assert.equal(q.key, FAKE_KEY, `x-api-key is the REAL key, put back by the proxy (${q.key?.slice(0, 24)}…)`);
  for (const q of stand.seen) assert.ok(!q.body.includes(FAKE_KEY) && !q.body.includes("MANDUFAKEgooseLOGIN"), "INVARIANT: no request body carries the key");
  assert.ok(lines.some((l) => /ANTHROPIC_API_KEY is a placeholder in Claude Code's environment/.test(l)), lines.join("\n"));
});
