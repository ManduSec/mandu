/**
 * after-the-fact-note — confidentiality.md §7.1, "Masked after the fact"
 * (2026-10-05), over the REAL components: a real ArbiterServer in `secrets`
 * with a policy file, the real mandu-policy tool (its own tools/call over
 * `new PolicyArbiterAdapter(new ArbiterClient(sock))`), and the real
 * anthropic-proxy and openai-proxy over HTTP in their production wiring
 * (`new ArbiterClientAdapter(data, human)`), a mock model behind each.
 *
 * The live tour (Claude Code 2.1.289, `secrets`): the user asks what is in
 * deploy/staging.conf (no rule covers it, the Read goes raw), then asks the
 * agent to mark it secret with Mandu's policy tool and read it again. The
 * next request re-sends the history, and the earlier Read's result is masked
 * now (right); with nothing saying why, the model told the user its first
 * answer had been made up and apologised. Replayed exactly:
 *
 *   1. request 1: the Read's result goes to the model raw;
 *   2. the policy tool locks the file (a tightening: applied at once);
 *   3. request 2 (the history + the policy call + a second Read whose result
 *      is Claude Code's "file unchanged" notice): the FIRST Read's result is
 *      a symbol AND the `masked after the fact` note; the second Read's is
 *      Claude Code's notice itself, in clear (it holds no file byte;
 *      confidentiality.md §7.1, "The Read dedup notice"), with no note;
 *   4. THE ORACLE: no byte of the file in any tool_result of request 2, the
 *      note included, nor in the system prompt; with an assistant reply that
 *      did not quote it, not the token anywhere in request 2.
 *
 * The first wording of the note ("reached you in clear in an earlier
 * request") arrived, and Opus 5.5 still apologised (live check 2026-10-05
 * 11:35): it saw a placeholder, then its OWN reply quoting the content (the
 * proxies do not filter assistant text, so that reply is forwarded as
 * written), took the tool result over its reply, and read the note inside
 * the result as a claim it could not check. The second variant replays that
 * live shape, the assistant reply quoting the file, and records exactly what
 * the model receives: the placeholder with the transcript-worded note, its
 * own reply unchanged, and Mandu's system note (the last system block)
 * saying the transcript no longer shows what it read.
 *
 * The Codex half replays the same with `cat deploy/staging.conf`.
 *
 * Across a resume (2026-10-09, tour item 4): the first request runs under
 * one launch; the proxy and the arbiter close; a NEW launch (a fresh proxy,
 * a restarted arbiter over the same mandu.db, a new session key) receives
 * the resumed history after the lock, and still sends the note and Mandu's
 * system note, since the ids are kept by the arbiter (`forwarded_clear`).
 *
 * Two launches at once (2026-10-17): two proxies on one stack, the same
 * resumed history; one masks a result from its first request and holds its
 * id as unknown, the other forwards it in clear later, and the first one's
 * next request carries the line (it re-learns ids through `since`).
 * Unit twins: the proxies' `after-the-fact-note.test.ts` and
 * arbiter/test/unit/forwarded-clear.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { AFTER_THE_FACT_MARKER, AFTER_THE_FACT_SYSTEM_NOTE } from "../../interceptors/anthropic-proxy/src/after-the-fact.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc } from "../../interceptors/policy-mcp/src/mcp-server.js";
import { envDeps } from "../../interceptors/policy-mcp/src/server-main.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const TOKEN = "ghp_FakeTourToken7Q2xW9eR4tY6uI8oP0aS";
const FILE = `[staging]\nhost = "staging.internal.example"\ntoken = "${TOKEN}"\n`;
const FILE_PIECES = [TOKEN, "ghp_FakeTour", "staging.internal.example", "[staging]"];
/** Claude Code's Read rendering of FILE. */
const READ_RENDER = FILE.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
const DEDUP = "Wasted call — file unchanged since your last Read. Refer to that earlier tool_result instead.";
const NOTE_READ = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; it was marked secret after that (a lock or a label, possibly one made later in this conversation), so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this. If you Read this file again while it is unchanged, Claude Code answers with its own \"file unchanged since your last Read\" notice, not the file: that notice points back to this result, which now shows only the symbol.";
const NOTE_PLAIN = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; it was marked secret after that (a lock or a label, possibly one made later in this conversation), so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this.";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/;

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** One launch's arbiter. `home`: an earlier launch's directory, whose
 *  mandu.db, policy file and workspace a new launch reuses (a resume). */
async function stack(session: string, home?: string) {
  const tmp = home ?? mkdtempSync(join(tmpdir(), "mandu-after-fact-"));
  if (!home) dirs.push(tmp);
  const ws = join(tmp, "mandu-try");
  const policyPath = join(tmp, "policy.yaml");
  if (!home) {
    mkdirSync(join(ws, "deploy"), { recursive: true });
    writeFileSync(join(ws, "deploy", "staging.conf"), FILE);
    writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
    mkdirSync(join(tmp, "human"), { mode: 0o700 });
  }
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const policyClient = await open(sock);
  /** The agent's mandu-policy call, as the MCP server runs it. */
  const lock = async (): Promise<string> => {
    const deps = { arbiter: new PolicyArbiterAdapter(policyClient), ...envDeps({ MANDU_SCOPE_ID: session, MANDU_PROJECT_DIR: ws }) };
    const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_propose", arguments: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }], reason: "the user asked" } } }, deps);
    const text = (r!.result as { content: Array<{ text: string }> }).content[0]!.text;
    assert.equal((JSON.parse(text) as { applied?: boolean }).applied, true, `the tightening applies at once: ${text}`);
    return text;
  };
  return {
    tmp, ws, sock, humanSock, open, lock,
    async close() {
      for (const c of clients) c.close();
      await server.close();
    },
  };
}

for (const quoted of [false, true]) test(`Claude Code${quoted ? " (the live shape: its reply quoted the file)" : ""}: the tour's Read, labelled after the fact, comes back masked WITH the after-the-fact note and Mandu's system note; the dedup Read reaches the model as the notice itself, never a symbol; no file byte in any tool result or the system prompt (secrets axes, explicit)`, async () => {
  const session = `after-fact-claude-${quoted ? "q" : "p"}-${process.pid}`;
  const s = await stack(session);
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const path = join(s.ws, "deploy", "staging.conf");
  const send = async (messages: unknown[]): Promise<{ text: string; json: { messages: Array<{ content: unknown }> } }> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    const last = upstream.requests.at(-1)!;
    return { text: last.bodyText, json: last.json() as { messages: Array<{ content: unknown }> } };
  };
  const resultOf = (json: { messages: Array<{ content: unknown }> }, id: string): string => {
    for (const m of json.messages) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
        if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
      }
    }
    throw new Error(`no tool_result ${id}`);
  };
  try {
    const turn1 = [
      { role: "user", content: "What is in deploy/staging.conf?" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_read1", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read1", content: READ_RENDER }] },
    ];
    // 1. nothing labels the file: the Read goes raw (the tour's first answer)
    const r1 = await send(turn1);
    assert.equal(resultOf(r1.json, "toolu_read1"), READ_RENDER, "unlabelled: the Read reaches the model as read");

    // 2. the agent's mandu-policy call locks it
    const policyText = await s.lock();

    // 3. the next request re-sends the history, with the assistant's own
    // earlier answer: describing the file, or (the live shape) quoting it.
    const reply = quoted
      ? `\`deploy/staging.conf\` has three lines:\n\n\`\`\`\n${FILE}\`\`\`\n\nThe token is a GitHub personal access token and nothing protects it. Want me to lock it?`
      : "It holds the staging host and a GitHub personal access token. Want me to lock it?";
    const turn2 = [
      ...turn1,
      { role: "assistant", content: [{ type: "text", text: reply }] },
      { role: "user", content: "Use Mandu's policy tools to mark deploy/staging.conf as a secret hidden from you. Then read it again and tell me what you see." },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_pol", name: "mcp__mandu-policy__mandu_policy_propose", input: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }] } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_pol", content: policyText }] },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_read2", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read2", content: DEDUP }] },
    ];
    const r2 = await send(turn2);
    const first = resultOf(r2.json, "toolu_read1");
    const [symbol, note, ...rest] = first.split("\n\n");
    assert.match(symbol!, SYM_RE, `the earlier Read is masked now: ${first}`);
    assert.equal(note, NOTE_READ, "…and says it was masked after the fact");
    assert.deepEqual(rest, []);
    const second = resultOf(r2.json, "toolu_read2");
    assert.equal(second, DEDUP, `the dedup notice reaches the model as itself, not as a symbol standing for the file: ${second}`);

    // Mandu's system note: the last system block, once
    const system = (r2.json as unknown as { system: Array<{ text: string }> }).system;
    assert.equal(system.at(-1)!.text, AFTER_THE_FACT_SYSTEM_NOTE);
    assert.equal(system.filter((b) => b.text.includes(AFTER_THE_FACT_MARKER)).length, 1);

    // What the model receives for its own earlier reply: unchanged (the
    // proxies filter user text only; confidentiality.md §7.1, the residual).
    const replyFwd = (r2.json.messages[3]!.content as Array<{ type: string; text: string }>)[0]!;
    assert.equal(replyFwd.text, reply, "the assistant's own earlier reply is forwarded as written");

    // 4. THE ORACLE: no byte of the file in any tool_result or the system
    // prompt of request 2 (the notes included); with a reply that did not
    // quote it, nowhere in the request.
    const toolResults = r2.json.messages.flatMap((m) => Array.isArray(m.content) ? (m.content as Array<{ type: string; tool_use_id?: string }>).filter((b) => b.type === "tool_result").map((b) => resultOf(r2.json, b.tool_use_id!)) : []).join("\n");
    const systemText = system.map((b) => b.text).join("\n");
    for (const piece of FILE_PIECES) {
      assert.ok(!toolResults.includes(piece), `a tool result carried file byte(s): ${piece}`);
      assert.ok(!systemText.includes(piece), `the system prompt carried file byte(s): ${piece}`);
      if (!quoted) assert.ok(!r2.text.includes(piece), `the model got file byte(s): ${piece}`);
    }

    // a later request: the same bytes for that result (stable history)
    const r3 = await send([...turn2, { role: "assistant", content: [{ type: "text", text: "Both reads now show a placeholder." }] }, { role: "user", content: "thanks" }]);
    assert.equal(resultOf(r3.json, "toolu_read1"), first);
    const system3 = (r3.json as unknown as { system: Array<{ text: string }> }).system;
    assert.equal(system3.at(-1)!.text, AFTER_THE_FACT_SYSTEM_NOTE, "the system note stays while the result is masked");
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("Codex: the tour's cat output, labelled after the fact, comes back masked with the same note and no output byte (secrets axes, explicit)", async () => {
  const session = `after-fact-codex-${process.pid}`;
  const s = await stack(session);
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const head = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 30\nOutput:\n";
  const turn1 = [
    { type: "message", role: "user", content: [{ type: "input_text", text: "What is in deploy/staging.conf?" }] },
    { type: "function_call", call_id: "c_cat", name: "exec_command", arguments: JSON.stringify({ cmd: "cat deploy/staging.conf", workdir: s.ws }) },
    { type: "function_call_output", call_id: "c_cat", output: `${head}${FILE}` },
  ];
  const send = async (input: unknown[]): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input }),
    });
    assert.equal(res.status, 200, await res.text());
    return upstream.requests.at(-1)!.bodyText;
  };
  const outputOf = (body: string, id: string): string => {
    const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!;
    const o = item["output"];
    return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
  };
  try {
    const b1 = await send(turn1);
    assert.ok(outputOf(b1, "c_cat").includes(TOKEN), "unlabelled: the output reaches the model as printed");

    await s.lock();
    const b2 = await send([
      ...turn1,
      { type: "message", role: "assistant", content: [{ type: "output_text", text: "It holds the staging host and a GitHub token." }] },
      { type: "message", role: "user", content: [{ type: "input_text", text: "Mark deploy/staging.conf as a secret hidden from you, then read it again." }] },
    ]);
    const t = outputOf(b2, "c_cat");
    assert.match(t, /\$MDU:/, t);
    assert.ok(t.endsWith(`\n\n${NOTE_PLAIN}`), t);
    assert.ok(!t.includes("the command names"), "the path-derived line gives way to the after-the-fact one");
    const instructions = String(JSON.parse(b2).instructions);
    assert.ok(instructions.endsWith(`\n\n${AFTER_THE_FACT_SYSTEM_NOTE}`), "Mandu's note closes the instructions");
    for (const piece of FILE_PIECES) assert.ok(!b2.includes(piece), `the model got output byte(s): ${piece}`);
  } finally {
    await proxy.close();
    await s.close();
  }
});

// ── Across a resume (confidentiality.md §7.1, *Across a resume*) ─────────────
// The tour's Read went to the model in clear under one launch; the user
// quits, and `claude --resume` (or `codex resume`) under a NEW launch re-sends
// the history to a new proxy and a restarted arbiter over the same mandu.db.
// The file is locked in the new launch. Before 2026-10-09 the ids lived in
// the first proxy's memory only, so the result came back masked with no note.

test("Claude Code across a resume: launch 1 forwards the Read in clear; a NEW launch (fresh proxy, restarted arbiter, same mandu.db) masks the resumed result WITH the after-the-fact note and Mandu's system note; no file byte in any tool result or the system prompt (secrets axes, explicit)", async () => {
  const s1 = await stack(`after-fact-resume-1-${process.pid}`);
  const path = join(s1.ws, "deploy", "staging.conf");
  const turn1 = [
    { role: "user", content: "What is in deploy/staging.conf?" },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_resume_read1", name: "Read", input: { file_path: path } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_resume_read1", content: READ_RENDER }] },
  ];
  /** One launch's proxy in its production wiring (a data and a human client). */
  const launch = async (s: Awaited<ReturnType<typeof stack>>, session: string) => {
    const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const send = async (messages: unknown[]): Promise<{ text: string; json: { system?: Array<{ text: string }>; messages: Array<{ content: unknown }> } }> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, system: [{ type: "text", text: "You are Claude Code." }], tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
      });
      assert.equal(res.status, 200, await res.text());
      const last = upstream.requests.at(-1)!;
      return { text: last.bodyText, json: last.json() as { system?: Array<{ text: string }>; messages: Array<{ content: unknown }> } };
    };
    return { proxy, send };
  };
  const resultOf = (json: { messages: Array<{ content: unknown }> }, id: string): string => {
    for (const m of json.messages) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
        if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
      }
    }
    throw new Error(`no tool_result ${id}`);
  };

  // launch 1: the Read goes raw; its id (only its id) is recorded
  const l1 = await launch(s1, `after-fact-resume-1-${process.pid}`);
  try {
    assert.equal(resultOf((await l1.send(turn1)).json, "toolu_resume_read1"), READ_RENDER);
  } finally {
    await l1.proxy.close();
    await s1.close();
  }

  // launch 2: a new session key, a new proxy, a restarted arbiter over the same mandu.db
  const session2 = `after-fact-resume-2-${process.pid}`;
  const s2 = await stack(session2, s1.tmp);
  const l2 = await launch(s2, session2);
  try {
    const policyText = await s2.lock();
    const resumed = [
      ...turn1,
      { role: "assistant", content: [{ type: "text", text: "It holds the staging host and a GitHub personal access token." }] },
      { role: "user", content: "Mark deploy/staging.conf as a secret hidden from you, then tell me what you see." },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_resume_pol", name: "mcp__mandu-policy__mandu_policy_propose", input: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }] } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_resume_pol", content: policyText }] },
    ];
    const r = await l2.send(resumed);
    const first = resultOf(r.json, "toolu_resume_read1");
    const [symbol, note, ...rest] = first.split("\n\n");
    assert.match(symbol!, SYM_RE, `the resumed Read is masked: ${first}`);
    assert.equal(note, NOTE_READ, "…and the new launch says it was masked after the fact");
    assert.deepEqual(rest, []);
    const system = r.json.system!;
    assert.equal(system.at(-1)!.text, AFTER_THE_FACT_SYSTEM_NOTE);
    assert.equal(system.filter((b) => b.text.includes(AFTER_THE_FACT_MARKER)).length, 1);
    // THE ORACLE: the reply did not quote the file, so no byte of it anywhere in the request
    for (const piece of FILE_PIECES) assert.ok(!r.text.includes(piece), `the model got file byte(s): ${piece}`);
  } finally {
    await l2.proxy.close();
    await s2.close();
  }
});

test("Codex across a resume: a NEW launch masks the resumed cat output with the after-the-fact note and Mandu's note in the instructions; no output byte (secrets axes, explicit)", async () => {
  const head = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 30\nOutput:\n";
  const launch = async (s: Awaited<ReturnType<typeof stack>>, session: string) => {
    const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
    const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const send = async (input: unknown[]): Promise<string> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": session },
        body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input }),
      });
      assert.equal(res.status, 200, await res.text());
      return upstream.requests.at(-1)!.bodyText;
    };
    return { proxy, send };
  };
  const outputOf = (body: string, id: string): string => {
    const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!;
    const o = item["output"];
    return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
  };
  const s1 = await stack(`after-fact-resume-codex-1-${process.pid}`);
  const turn1 = [
    { type: "message", role: "user", content: [{ type: "input_text", text: "What is in deploy/staging.conf?" }] },
    { type: "function_call", call_id: "c_resume_cat", name: "exec_command", arguments: JSON.stringify({ cmd: "cat deploy/staging.conf", workdir: s1.ws }) },
    { type: "function_call_output", call_id: "c_resume_cat", output: `${head}${FILE}` },
  ];
  const l1 = await launch(s1, `after-fact-resume-codex-1-${process.pid}`);
  try {
    assert.ok(outputOf(await l1.send(turn1), "c_resume_cat").includes(TOKEN), "unlabelled: the output reaches the model as printed");
  } finally {
    await l1.proxy.close();
    await s1.close();
  }
  const session2 = `after-fact-resume-codex-2-${process.pid}`;
  const s2 = await stack(session2, s1.tmp);
  const l2 = await launch(s2, session2);
  try {
    await s2.lock();
    const b = await l2.send([
      ...turn1,
      { type: "message", role: "assistant", content: [{ type: "output_text", text: "It holds the staging host and a GitHub token." }] },
      { type: "message", role: "user", content: [{ type: "input_text", text: "Mark deploy/staging.conf as a secret hidden from you." }] },
    ]);
    const t = outputOf(b, "c_resume_cat");
    assert.match(t, /\$MDU:/, t);
    assert.ok(t.endsWith(`\n\n${NOTE_PLAIN}`), t);
    assert.ok(String(JSON.parse(b).instructions).endsWith(`\n\n${AFTER_THE_FACT_SYSTEM_NOTE}`), "Mandu's note closes the instructions");
    for (const piece of FILE_PIECES) assert.ok(!b.includes(piece), `the model got output byte(s): ${piece}`);
  } finally {
    await l2.proxy.close();
    await s2.close();
  }
});

// ── Two launches at once (confidentiality.md §7.1, 2026-10-17) ───────────────
// Two launches resumed on the same conversation at once, both on the one
// running stack (one arbiter, two proxies, two session keys). The resumed
// Bash call ran under an earlier launch, so no recorder binds it here, and a
// call no recorder binds is masked at the level of what its SESSION read
// raw: launch B's session has read the .env raw, launch A's nothing. So B's
// first request masks the result from the start and holds its id as
// unknown; then A forwards the same result in clear and records it. B's
// NEXT request must carry the after-the-fact line: the conversation's model
// did read it. Before 2026-10-17 B never asked about that id again.

test("two launches at once on one stack: B held a resumed result's id as unknown; A forwards it in clear later; B's next request carries the after-the-fact line and Mandu's system note; no secret byte (secrets axes, explicit)", async () => {
  const s = await stack(`after-fact-two-${process.pid}`);
  const guard = await s.open(s.humanSock);
  const env = join(s.ws, ".env");
  const secret = "sk-two-launches-0123456789abcdef";
  writeFileSync(env, `API_KEY=${secret}\n`);
  const sessionA = `after-fact-two-a-${process.pid}`;
  const sessionB = `after-fact-two-b-${process.pid}`;
  // Launch B's session read the .env raw (a process of B's tree did).
  await guard.recordExecRoot({ procKey: "bash-b0", ancestors: ["agent-b"], argv: ["/bin/bash", "-c", "cat .env"], session: sessionB, callRoot: true });
  await guard.taintProcessSecret({ procKey: "bash-b0", path: env, level: "no-model", app: "cat", session: sessionB });

  const launch = async (session: string) => {
    const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const send = async (messages: unknown[]): Promise<{ text: string; json: { system?: Array<{ text: string }>; messages: Array<{ content: unknown }> } }> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, system: [{ type: "text", text: "You are Claude Code." }], tools: [{ name: "Bash", input_schema: { type: "object" } }], messages }),
      });
      assert.equal(res.status, 200, await res.text());
      const last = upstream.requests.at(-1)!;
      return { text: last.bodyText, json: last.json() as { system?: Array<{ text: string }>; messages: Array<{ content: unknown }> } };
    };
    return { proxy, send };
  };
  const resultOf = (json: { messages: Array<{ content: unknown }> }, id: string): string => {
    for (const m of json.messages) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
        if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
      }
    }
    throw new Error(`no tool_result ${id}`);
  };
  const OUTPUT = "build 4127 passed: 212 tests, 0 failures\n";
  const history = [
    { role: "user", content: "How did the last build go?" },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_two_log", name: "Bash", input: { command: "tail -1 build.log" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_two_log", content: OUTPUT }] },
  ];
  const a = await launch(sessionA);
  const b = await launch(sessionB);
  try {
    // B first: masked at its session's level from the start, no after-the-fact line.
    const b1 = resultOf((await b.send(history)).json, "toolu_two_log");
    assert.match(b1, /^\$MDU:/, b1);
    assert.ok(!b1.includes("masked after the fact"), `nothing says the model read it yet: ${b1}`);

    // A: its session read nothing, so the same result goes to the model in clear (and is recorded).
    assert.equal(resultOf((await a.send(history)).json, "toolu_two_log"), OUTPUT);

    // B again: the same result, masked, now WITH the line and Mandu's system note.
    const r = await b.send([...history, { role: "assistant", content: [{ type: "text", text: "Build 4127 passed." }] }, { role: "user", content: "thanks" }]);
    const again = resultOf(r.json, "toolu_two_log");
    assert.match(again, /^\$MDU:/, again);
    assert.ok(again.includes("[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content;"), `B learns that A forwarded it in clear: ${again}`);
    assert.equal(r.json.system!.at(-1)!.text, AFTER_THE_FACT_SYSTEM_NOTE);
    assert.ok(!r.text.includes(secret), "the secret reaches no model request");
  } finally {
    await a.proxy.close();
    await b.proxy.close();
    await s.close();
  }
});
