/**
 * dashboard-agent-tool-words — an OpenCode session's tool calls read in
 * words on the product's session page, and its secret file reads as a file
 * on *Your secrets*, as a Claude Code session's do (dashboard.md §4.25b,
 * *Every agent's steps read in words*), over the PRODUCTION wiring: a real
 * ArbiterServer in `secrets` with a policy file labelling `vault/**`
 * no-model, a session bound to the `opencode` spec, the REAL anthropic-proxy
 * on its production client (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), new ArbiterClient(humanSock))`), a scripted model
 * making OpenCode 1's calls, and the real DashboardServer over
 * `ArbiterEventSource`, read signed out.
 *
 * Before: the page read a path from Claude Code's `file_path` and `path`
 * only, so OpenCode 1's `read{filePath}` read "Read `a file`", and the
 * labelled file the proxy masked whole as `$MDU:nomodel_read[…]` read
 * "Output of a `read` step that held a secret" on *Your secrets*. The web
 * fetch and search already read in words (the old lists matched in any
 * case); they are pinned here so the table keeps them.
 *
 * Proves, end to end:
 *   - the session page (`/api/home/agent`) words each call: "Opened a web
 *     page on `docs.example.com`", "Searched the web for `acme payments
 *     2026`", "Read `partner-token.md`" (masked before the AI saw it),
 *     "Searched files for `TODO`";
 *   - *Your secrets* names the file: "The file <path>";
 *   - the inspector's trace (`/api/events`) keeps each call as the agent
 *     made it (`read` with its `filePath`);
 *   - PARITY: every exec tool, web fetch and web search on each agent's gate
 *     surface (Claude Code, OpenCode, OpenClaw, Goose) and Codex's recorded
 *     exec tool reads in words, never "Used …"; every path field those
 *     surfaces name for a file read, write, edit or listing is a field the
 *     page reads (tool-family.ts);
 *   - THE ORACLE: the labelled file's value never reaches the model or any
 *     dashboard route.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import {
  CLAUDE_CODE_GATE_SURFACE, GOOSE_GATE_SURFACE, OPENCLAW_GATE_SURFACE, OPENCODE_GATE_SURFACE, type GateSurface,
} from "../../arbiter/policy/tool-gate-surface.js";
import { SCRIPT_EXEC_FUNCTIONS } from "../../interceptors/openai-proxy/src/script-cell.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../interceptors/anthropic-proxy/src/sse-parser.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { actionSentence } from "../../dashboard/src/view-model/agent-page.js";
import { toolFamily } from "../../dashboard/src/view-model/tool-family.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface Part { kind?: string; text: string }
interface StoryStep { kind: string; outcome?: string; sentence?: Part[] }
interface StoryTurn { steps: StoryStep[] }
interface Step { step: string; callId?: string; tool?: string; input?: string | null }
const words = (parts: readonly Part[] | undefined): string => (parts ?? []).map((p) => (p.kind === "masked" ? `[${p.text}]` : p.text)).join("");

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** OpenCode 1.18's `read` rendering of a whole text file (the stack test
 *  opencode-read-value has the capture). */
function rendering(path: string, text: string): string {
  const lines = text.replace(/\n$/, "").split("\n");
  return [`<path>${path}</path>`, "<type>file</type>", "<content>", ...lines.map((l, i) => `${i + 1}: ${l}`), "", `(End of file - total ${lines.length} lines)`, "</content>"].join("\n");
}

test("OpenCode: a session's web fetch, web search, read of a labelled file and file search read in words on the session page, the file by its name on Your secrets; the trace keeps the calls; the file's value reaches neither the model nor the dashboard (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-tool-words-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const vault = join(ws, "vault", "partner-token.md");
  // A per-run value in a no-model file: never a literal.
  const secret = `oc-partner-${randomBytes(16).toString("hex")}`;
  writeFileSync(vault, `Partner API token: ${secret}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `paths:\n  - path: '${ws}/vault/**'\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const data = await open(sock);
  const session = `agent-tool-words-${process.pid}`;
  assert.equal((await data.setSessionSpec({ sessionKey: session, spec: "opencode", requestedBy: "dashboard-agent-tool-words e2e" })).bound, "opencode");
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), log: () => {} });
  const dport = await dashboard.listen(0);
  const get = async (path: string) => {
    const r = await fetch(`http://127.0.0.1:${dport}/api/${path}`);
    const text = await r.text();
    return { status: r.status, text, body: (() => { try { return JSON.parse(text) as Record<string, unknown>; } catch { return {}; } })() };
  };
  let proxy: AnthropicProxy | null = null;
  try {
    // OpenCode 1's wire: `webfetch{url,format}`, `websearch{query}`,
    // `read{filePath}`, `grep{pattern,path}` (the gate surface's capture).
    const calls: Array<{ id: string; name: string; input: Record<string, unknown>; result: string }> = [
      { id: "toolu_fetch", name: "webfetch", input: { url: "https://docs.example.com/guide", format: "markdown" }, result: "# Guide\nUse the partner callback." },
      { id: "toolu_search", name: "websearch", input: { query: "acme payments 2026" }, result: "1. Acme pays on the 30th." },
      { id: "toolu_read", name: "read", input: { filePath: vault }, result: rendering(vault, `Partner API token: ${secret}\n`) },
      { id: "toolu_grep", name: "grep", input: { pattern: "TODO", path: ws }, result: "No files found" },
    ];
    const seen: string[] = [];
    const upstream: UpstreamFetcher = async ({ body }) => {
      seen.push(body.toString("utf8"));
      const c = calls[seen.length - 1];
      const sse = c ? buildToolUseSse({ id: c.id, name: c.name, input: c.input }) : buildTextSse("Done.", { deltas: 1 });
      return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
    };
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, await open(humanSock)), upstream, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const post = async (messages: unknown[]): Promise<ReconstructedToolUse[]> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session },
        body: JSON.stringify({
          model: "claude-sonnet-5", stream: true, max_tokens: 512, messages,
          tools: ["webfetch", "websearch", "read", "grep"].map((name) => ({ name, input_schema: { type: "object" } })),
        }),
      });
      assert.equal(res.status, 200);
      const out: ReconstructedToolUse[] = [];
      const p = new SseToolUseParser((tu) => out.push(tu));
      p.feed(await res.text());
      p.end();
      return out;
    };

    // Each call as the agent receives it, then its result.
    const history: unknown[] = [{ role: "user", content: "Check the partner guide, find Acme's payment day, read the partner token and look for TODOs." }];
    for (const c of calls) {
      const [call] = await post(history);
      assert.equal(call?.id, c.id);
      assert.equal(call!.name, c.name);
      history.push({ role: "assistant", content: [{ type: "tool_use", id: c.id, name: call!.name, input: call!.input }] });
      history.push({ role: "user", content: [{ type: "tool_result", tool_use_id: c.id, content: c.result }] });
    }
    assert.deepEqual(await post(history), []);

    // The inspector's trace keeps each call as the agent made it.
    const ev = await waitFor("the four calls and their results", async () => {
      const r = await get(`events?session=${encodeURIComponent(session)}`);
      const steps = ((r.body["viewModel"] as { dualLanes?: { steps?: Step[] } } | undefined)?.dualLanes?.steps ?? []).filter((s) => s.step === "tool");
      return r.status === 200 && steps.length >= 4 ? r : undefined;
    });
    const cards = ((ev.body["viewModel"] as { dualLanes: { steps: Step[] } }).dualLanes.steps).filter((s) => s.step === "tool");
    assert.deepEqual(cards.map((s) => s.tool), ["webfetch", "websearch", "read", "grep"]);
    assert.deepEqual(JSON.parse(String(cards[2]!.input)), { filePath: vault }, "the trace keeps OpenCode's own field");

    // The product's session page: every call in words.
    const page = await waitFor("the session page's four steps", async () => {
      const r = await get(`home/agent?session=${encodeURIComponent(session)}`);
      const n = ((r.body["story"] ?? []) as StoryTurn[]).flatMap((t) => t.steps).filter((s) => s.kind === "action").length;
      return r.status === 200 && n >= 4 ? r : undefined;
    });
    const steps = ((page.body["story"] ?? []) as StoryTurn[]).flatMap((t) => t.steps).filter((s) => s.kind === "action");
    assert.deepEqual(steps.map((s) => words(s.sentence)), [
      "Opened a web page on docs.example.com",
      "Searched the web for acme payments 2026",
      "Read partner-token.md",
      "Searched files for TODO",
    ]);
    assert.deepEqual(steps.map((s) => s.outcome), ["plain", "plain", "secret", "plain"], "the labelled read was masked before the AI saw it");
    for (const s of steps) assert.doesNotMatch(words(s.sentence), /^Used |a file/, "no step reads as an unknown tool or an unnamed file");

    // Your secrets names the file, as it does for Claude Code's Read.
    const secrets = (page.body["secrets"] ?? {}) as { secrets?: Array<{ what: Part[] }> };
    assert.deepEqual((secrets.secrets ?? []).map((x) => words(x.what)), [`The file ${vault}`]);

    // THE ORACLE: the labelled file's value reaches neither the model nor any route.
    assert.ok(seen.length >= 5, "the model got every turn");
    for (const body of seen) assert.ok(!body.includes(secret), "CONFIDENTIALITY VIOLATION: the model got the labelled file's value");
    for (const text of [ev.text, page.text, (await get("home")).text, (await get("sessions")).text]) {
      assert.ok(!text.includes(secret), "CONFIDENTIALITY VIOLATION: the dashboard served the labelled file's value signed out");
    }
  } finally {
    await proxy?.close().catch(() => {});
    await dashboard.close?.();
    for (const c of clients) c.close();
    await server.close();
  }
});

test("parity: every exec tool, web fetch and web search on each agent's gate surface, and Codex's recorded exec tool, reads in words; every path field the surfaces name for a file read, write, edit or listing is one the page reads (tool-family.ts)", () => {
  const surfaces: Array<[string, Omit<GateSurface, "spec">]> = [
    ["Claude Code", CLAUDE_CODE_GATE_SURFACE], ["OpenCode", OPENCODE_GATE_SURFACE], ["OpenClaw", OPENCLAW_GATE_SURFACE], ["Goose", GOOSE_GATE_SURFACE],
  ];
  const said = (tool: string, input: Record<string, unknown>): string => words(actionSentence({ tool, input: JSON.stringify(input) }).sentence);
  let checked = 0;
  for (const [agent, s] of surfaces) {
    for (const [tool, field] of Object.entries(s.exec)) {
      assert.equal(said(tool, { [field]: "make test" }), "Ran make test", `${agent} ${tool}`);
      checked++;
    }
    for (const [tool, net] of Object.entries(s.net)) {
      if (net.block) continue; // a tool the gate refuses outright is not a web page or a search
      if (net.destination === "url") {
        assert.equal(said(tool, { url: "https://docs.example.com/a" }), "Opened a web page on docs.example.com", `${agent} ${tool}`);
        checked++;
      } else if (net.destination === null && net.symbols === "query") {
        assert.equal(said(tool, { query: "acme" }), "Searched the web for acme", `${agent} ${tool}`);
        checked++;
      }
    }
    for (const [tool, p] of Object.entries(s.paths)) {
      const family = toolFamily(tool);
      if (family !== "read" && family !== "write" && family !== "edit" && family !== "list") continue;
      for (const field of p.fields) {
        assert.match(said(tool, { [field]: "/w/src/notes.md" }), /notes\.md$/, `${agent} ${tool}.${field}: the page names what the call names`);
        checked++;
      }
    }
  }
  for (const tool of SCRIPT_EXEC_FUNCTIONS) {
    assert.equal(said(tool, { cmd: "make test" }), "Ran make test", `Codex ${tool}`);
    checked++;
  }
  assert.ok(checked >= 30, `the parity covers every agent's surface (${checked} checks)`);
});
