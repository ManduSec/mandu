/**
 * inspect-ullm-shim.test.ts — under `mandu claude`, inspect_symbol's
 * quarantined `claude -p` (the U-LLM, interceptors/inspect-mcp) runs the
 * real CLI by its path, past the session's `claude` PATH shim, and so keeps
 * its own channel: never the model proxy (launcher/src/types.ts
 * Ullm.binaryPath; docs/design/agents/agent-sdks.md §3.5).
 *
 * WHY. Since the shim (2026-10-18, sdk-route.ts writeClaudeShim) a `claude`
 * started by name anywhere in the session is routed as `mandu claude` is:
 * the launch's ANTHROPIC_BASE_URL (the model proxy) put back in its
 * environment and imposed in its last `--settings`. The inspect server
 * started its U-LLM as `claude`, by name, so the shim re-pointed it at the
 * model proxy: the instrumented T-LLM path the U-LLM must never take
 * (confidentiality.md), and a port the inspect server's network confine
 * refuses (inspect-net-confine.ts), so on Linux every quarantined call hung
 * to its 60 s timeout (the 2026-10-18 nightly: 23 of 23 in the CI guest; the
 * agent then declassified the any-model file instead). Nothing failed
 * before a live drill: no suite ran the inspect server under a real launch.
 *
 * The rig. A stand-in `claude` first on PATH is both sides:
 *   - the agent (`mandu claude -p …`): one Messages request through the
 *     model proxy holding a Read of an any-model file, the scripted model
 *     answers with the symbol it saw; then it starts the `mandu-inspect`
 *     server of its --mcp-config as Claude Code does (the entry's env over
 *     its own) and calls inspect_symbol on that symbol over stdio;
 *   - the U-LLM (`-p … --system-prompt …`): records the executable it runs
 *     as, its base URL and whether a `--settings` reached it, and answers as
 *     `claude -p --output-format json` does.
 * Zero model budget: a scripted model, no agent CLI. Red on the code that
 * spawned the U-LLM by name (its base URL was the model proxy's and the
 * shim's `--settings` reached it).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { startScriptedAnthropic, textTurn } from "../lib/fake-anthropic.js";
import { runLauncher, startHttpsShim, withStack } from "../lib/launcher-live.js";
import { SYMBOL_TOKEN_RE } from "../lib/conf-exfil.js";
import { stateAxes } from "../lib/axes.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";

// This suite STATES its axes (protection-modes.md §4): `secrets`.
stateAxes("secrets");

const READ_ID = "toolu_mdu_ullm_shim_read";
const CONTRACT = "Supply agreement, reference SHIM-ULLM-REF-4417, total 1,250,000.\n";
/** What the stand-in U-LLM answers (re-symbolized on its way back). */
const ULLM_ANSWER = "the reference is SHIM-ULLM-REF-4417";

interface AgentRecord { side: "agent"; base: string; symbol: string | null; binaryPath?: string; ullmBase?: string; result?: unknown; error?: string }
interface UllmRecord { side: "ullm"; self: string; base: string | null; settings: boolean; argv: string[] }

/** The stand-in `claude` (see the header); one JSON line per start in `record`. */
function standInClaude(record: string, contract: string): string {
  return `#!/usr/bin/env node
"use strict";
const fs = require("fs"), http = require("http"), https = require("https"), cp = require("child_process");
const a = process.argv.slice(2);
const rec = (o) => fs.appendFileSync(${JSON.stringify(record)}, JSON.stringify(o) + "\\n");
if (a[0] === "--version") { console.log("2.1.302 (Claude Code)"); process.exit(0); }
if (a.includes("--system-prompt")) {
  // The U-LLM: what it was started as, and with.
  rec({ side: "ullm", self: process.argv[1], base: process.env.ANTHROPIC_BASE_URL ?? null,
    settings: a.some((x) => x === "--settings" || x.startsWith("--settings=")), argv: a });
  process.stdin.resume();
  process.stdin.on("end", () => {
    process.stdout.write(JSON.stringify({ type: "result", is_error: false, result: ${JSON.stringify(ULLM_ANSWER)}, model: "claude-haiku-4-5" }));
    process.exit(0);
  });
} else {
  const cfgAt = a.indexOf("--mcp-config");
  const out = { side: "agent", base: process.env.ANTHROPIC_BASE_URL || "", symbol: null };
  const fail = (e) => { out.error = String(e && e.message || e); rec(out); process.exit(1); };
  const headers = { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": process.env.ANTHROPIC_API_KEY || "x" };
  for (const line of (process.env.ANTHROPIC_CUSTOM_HEADERS || "").split("\\n")) {
    const c = line.indexOf(":");
    if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
  }
  const body = JSON.stringify({
    model: "claude-haiku-4-5", max_tokens: 64, stream: true,
    tools: [{ name: "Read", input_schema: { type: "object" } }, { name: "mcp__mandu-inspect__inspect_symbol", input_schema: { type: "object" } }],
    messages: [
      { role: "user", content: [{ type: "text", text: "What is the contract's reference?" }] },
      { role: "assistant", content: [{ type: "tool_use", id: ${JSON.stringify(READ_ID)}, name: "Read", input: { file_path: ${JSON.stringify(contract)} } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: ${JSON.stringify(READ_ID)}, content: fs.readFileSync(${JSON.stringify(contract)}, "utf8") }] },
    ],
  });
  const u = new URL(out.base.replace(/\\/$/, "") + "/v1/messages");
  const req = (u.protocol === "https:" ? https : http).request(u, { method: "POST", headers }, (res) => {
    let sse = "";
    res.setEncoding("utf8");
    res.on("data", (c) => (sse += c));
    res.on("end", () => {
      let text = "";
      for (const l of sse.split("\\n")) {
        if (!l.startsWith("data:")) continue;
        try { const d = JSON.parse(l.slice(5)); if (d.delta && typeof d.delta.text === "string") text += d.delta.text; } catch {}
      }
      const m = /\\$MDU:[A-Za-z0-9_]+\\[[0-9a-f]+\\]/.exec(text);
      out.symbol = m ? m[0] : null;
      if (!out.symbol) return fail("no symbol in the model's answer: " + text.slice(0, 200));
      inspect();
    });
  });
  req.on("error", fail);
  req.end(body);
  function inspect() {
    if (cfgAt < 0) return fail("no --mcp-config");
    const entry = JSON.parse(fs.readFileSync(a[cfgAt + 1], "utf8")).mcpServers["mandu-inspect"];
    out.binaryPath = entry.env.MANDU_ULLM_BINARY_PATH;
    out.ullmBase = entry.env.ANTHROPIC_BASE_URL;
    // As Claude Code starts a stdio server: the entry's env over its own.
    const srv = cp.spawn(entry.command, entry.args, { env: { ...process.env, ...entry.env }, stdio: ["pipe", "pipe", "inherit"] });
    let buf = "";
    const timer = setTimeout(() => { srv.kill("SIGKILL"); fail("inspect_symbol did not answer in 90 s"); }, 90000);
    srv.stdout.setEncoding("utf8");
    srv.stdout.on("data", (c) => {
      buf += c;
      let i;
      while ((i = buf.indexOf("\\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let msg; try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id === 2) { clearTimeout(timer); out.result = msg.result ?? msg.error; rec(out); srv.kill(); process.exit(0); }
      }
    });
    const send = (o) => srv.stdin.write(JSON.stringify(o) + "\\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "stand-in", version: "0" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "inspect_symbol", arguments: { symbol: out.symbol, instruction: "What is the contract's reference?" } } });
  }
}
`;
}

test(
  "mandu claude: inspect_symbol's quarantined claude -p runs the real CLI by its path, never through the claude shim to the model proxy",
  { timeout: 170_000 },
  async () => {
    // The scripted model answers with the first symbol its request holds.
    const fake = await startScriptedAnthropic({
      script: [{ match: () => true, respond: (req) => textTurn((new RegExp(SYMBOL_TOKEN_RE.source).exec(req.body) ?? ["NO_SYMBOL"])[0]) }],
    });
    try {
      await withStack(async (ctx) => {
        const shim = await startHttpsShim(fake.origin, ctx.tmp);
        try {
          const contract = join(ctx.tmp, "contracts", "supply.md");
          mkdirSync(join(ctx.tmp, "contracts"), { recursive: true });
          writeFileSync(contract, CONTRACT);
          const admin = new ArbiterClient(ctx.adminSock);
          await admin.connect();
          try {
            const r = await admin.setPathLabel({ path: contract, confidentiality: "any-model" });
            assert.equal(r.level, "any-model", JSON.stringify(r));
          } finally {
            admin.close();
          }
          const bin = join(ctx.tmp, "bin");
          mkdirSync(bin, { recursive: true });
          const record = join(ctx.tmp, "claude-starts.jsonl");
          const standIn = join(bin, "claude");
          writeFileSync(standIn, standInClaude(record, contract), { mode: 0o755 });
          // No API key: the U-LLM is the CLI, as on a subscription sign-in
          // (parse.ts ullmCliBinary).
          const env = { ...ctx.launcherEnv(shim.origin, 0), ANTHROPIC_API_KEY: undefined, MANDU_ULLM_API_KEY: undefined };
          const out = await runLauncher(["--no-scope", "--no-reply-filter", "claude", "-p", "go"],
            { ...env, PATH: `${bin}:${process.env["PATH"]}` }, ctx.workspace, 150_000);
          const starts = existsSync(record)
            ? readFileSync(record, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as AgentRecord | UllmRecord)
            : [];
          const why = `launch exit ${out.code}; starts ${JSON.stringify(starts)}\n${out.out.slice(-3000)}`;
          const agent = starts.find((s): s is AgentRecord => s.side === "agent");
          const ullm = starts.filter((s): s is UllmRecord => s.side === "ullm");
          assert.ok(agent, `the stand-in agent ran: ${why}`);
          assert.equal(agent.error, undefined, why);
          assert.ok(agent.symbol, `the Read reached the agent as a symbol: ${why}`);
          // The extraction, and the content-kind classifier beside it.
          assert.ok(ullm.length >= 1, `a quarantined call ran: ${why}`);
          assert.equal(agent.binaryPath, standIn, `the inspect entry names the CLI past the shim: ${why}`);
          for (const u of ullm) {
            // The CLI by its path (the stand-in itself), never the shim.
            assert.equal(u.self, standIn, `the U-LLM ran as the real CLI: ${why}`);
            // Its own channel: never the model proxy, no routing --settings.
            assert.notEqual(u.base, agent.base, `SECURITY: the U-LLM was routed to the model proxy (${agent.base}): ${why}`);
            assert.equal(u.settings, false, `SECURITY: the shim's routing --settings reached the U-LLM: ${why}`);
            if (agent.ullmBase !== undefined && !/^https:\/\/api\.anthropic\.com\/?$/.test(agent.ullmBase)) {
              assert.equal(u.base, agent.ullmBase, `the U-LLM's base URL is its entry's (the forwarder): ${why}`);
            }
          }
          // The answer came back re-symbolized, not raw.
          const result = JSON.stringify(agent.result);
          assert.doesNotMatch(result, /"isError":true/, why);
          assert.doesNotMatch(result, /SHIM-ULLM-REF-4417/, `SECURITY: the U-LLM's raw answer reached the agent: ${why}`);
          assert.match(result, SYMBOL_TOKEN_RE, `the answer is a symbol: ${why}`);
          // Nothing raw reached the model.
          assert.ok(!fake.requests.some((q) => q.body.includes("SHIM-ULLM-REF-4417")),
            "CONFIDENTIALITY VIOLATION: the contract reached the model raw");
        } finally {
          await shim.close();
        }
      }, { mode: "secrets" });
    } finally {
      await fake.close();
    }
  },
);
