/**
 * exec-output-key-listing — plan 10 §11.8, "A key listing"
 * (2026-10-16), over the REAL components: a real ArbiterServer in `secrets`,
 * the real anthropic-proxy and openai-proxy over HTTP in their production
 * wiring (`new ArbiterClientAdapter(data, human)`), a mock model behind each,
 * and the guard's records on the human socket.
 *
 * Found live (demo-api-401-debug, Claude Code + Sonnet): debugging an
 * empty-key 401, the model ran a `sed` that cuts each `.env` line at its `=`,
 * to read the variable NAMES without the values. The program was served the
 * twin, so it printed the keys and nothing else, yet the command names
 * `.env` and the path-derived precaution masked it whole; the model gave up
 * and asked the user. Now:
 *
 *   - Claude Code (Bash) and Codex (exec_command): the key listing reaches
 *     the model as printed, with the `twin:` key-listing note naming the file;
 *   - the same command whose tree read the file RAW stays one symbol (rule
 *     (i)), and so does a listing no guard record answers for, or one out of
 *     the twin's order;
 *   - review of !1604: a listing with whitespace appended (the key's bits as
 *     spaces and tabs, U+00A0/U+2003 blank lines, extra newlines) stays one
 *     symbol, and another project's registered .env with the same keys is
 *     never the file the note names;
 *   - THE ORACLE: the secret value is in no request to the model.
 *
 * Unit twins: arbiter `exec-output-key-listing.test.ts` (unit + component),
 * both proxies' `rewrite-request.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_test_51KeyListingStackE2E0123456789";
const RAW = `# fake values, made up by mandu demo\nSTRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`;
/** What the guard-served program printed (Claude Code's Bash trims the last newline). */
const LISTING = "# fake values, made up by mandu demo\nSTRIPE_SECRET_KEY\nPORT";
const HEAD = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";
const NOTE_CLAUDE = (path: string) => `[mandu:secret] twin: these are the key names in ${path}, and the lines of it that hold no masked value, as you see the file; no masked value is in this output. Read the file (or cat it) to see each masked value as a symbol, and use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.`;
const NOTE_CODEX = (path: string) => `[mandu:secret] twin: these are the key names in ${path}, and the lines of it that hold no masked value, as you see the file; no masked value is in this output. Print the file (cat it) to see each masked value as a symbol, and use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.`;

async function stack(name: string) {
  const tmp = mkdtempSync(join(tmpdir(), `mandu-key-listing-${name}-`));
  const ws = join(tmp, "shop-app");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, RAW);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  return {
    ws, env, sock, humanSock, open, guard,
    /** The guard's record of a clean run: the program opened the file and
     *  was served the twin (no taint), and the call is bound to it. */
    async cleanRun(session: string, procKey: string, callIds: string[]) {
      const d = await guard.decideSecretOpen({ path: env, exe: "/usr/bin/sed", isAgent: false, exeSystem: true, openerEnv: [], procKey, session });
      assert.equal(d.verdict, "twin");
      for (const callId of callIds) await guard.recordCallRoot({ callId, procKey, session });
    },
    /** A run whose program read the file RAW (a listed reader), bound the
     *  way the recorder binds it (plan 13 D9 follow-up): the proxy's record
     *  of the command it relayed, the agent's own shell exec of it as the
     *  call root, the reader its child. */
    async rawRun(session: string, procKey: string, callId: string, command: string, recorder: { recordCallCommand?(r: { callId: string; command: string; sessionKey?: string }): Promise<unknown> }) {
      await recorder.recordCallCommand!({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey, ancestors: ["agent-kl-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
      await guard.processLineage({ childKey: `${procKey}-reader`, parentKey: procKey });
      await guard.taintProcessSecret({ procKey: `${procKey}-reader`, path: env, level: "no-model", app: "sed", session });
    },
    async close() {
      for (const c of clients) c.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

test("Claude Code: `sed` cutting each .env line at `=` reaches the model as the key names with the key-listing note; a raw read, no record or a sorted listing stays one symbol; no secret value reaches the model (secrets axes, explicit)", async () => {
  const s = await stack("claude");
  const session = `key-listing-claude-${process.pid}`;
  const command = `sed 's/=.*//' ${s.env}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const adapter = new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.humanSock));
  const proxy = new AnthropicProxy({ arbiter: adapter, upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const bashCall = async (id: string, cmd: string, output: string): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "The payments call fails with a 401 and an empty key. Which variables does .env set?" },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: cmd } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return String(body.messages[2]!.content[0]!.content);
  };
  try {
    // Another project's .env with the same keys, registered too (review of
    // !1604): the note names the file the command names, never that one.
    const otherEnv = join(s.ws, "..", "other-proj", ".env");
    mkdirSync(join(s.ws, "..", "other-proj"));
    writeFileSync(otherEnv, RAW.replace(KEY, "sk_test_51OtherProjectStackE2E9876543"));
    await s.guard.registerSecret({ path: otherEnv, sessionKey: session });
    const reg = await s.guard.registerSecret({ path: s.env, sessionKey: session });
    assert.ok(typeof reg.twin === "string" && !(reg.twin as string).includes(KEY), JSON.stringify(reg));

    await s.cleanRun(session, "sed-kl-1", ["toolu_kl_1"]);
    const released = await bashCall("toolu_kl_1", command, LISTING);
    assert.equal(released, `${LISTING}\n\n${NOTE_CLAUDE(s.env)}`);

    // Review of !1604, the whitespace channel: the proxy forwards a released
    // result's bytes as received, so whitespace a program appends (the key's
    // bits as space/tab, U+00A0/U+2003 blank lines) must keep the mask.
    const bits = [...Buffer.from(KEY)].flatMap((b) => [...b.toString(2).padStart(8, "0")]);
    const encodings: Array<[string, string]> = [
      ["space/tab after each key line", LISTING.split("\n").map((l, i) => l + bits.slice(i * 16, i * 16 + 16).map((x) => (x === "1" ? "\t" : " ")).join("")).join("\n")],
      ["U+00A0/U+2003 trailing blank lines", `${LISTING}\n${bits.map((x) => (x === "1" ? " " : " ")).join("")}\n`],
      ["extra trailing newlines", `${LISTING}\n\n\n\n`],
      // second review: a Codex-shaped head the program printed itself, the key as digits
      ["a forged exec head", `Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: ${[...Buffer.from(KEY)].map((b) => String(b).padStart(3, "0")).join("")}\nOutput:\n${LISTING}\n`],
      ["a well-formed head on Claude Code", `${HEAD}${LISTING}\n`],
    ];
    for (const [i, [why, out]] of encodings.entries()) {
      await s.cleanRun(session, `sed-kl-ws-${i}`, [`toolu_kl_ws_${i}`]);
      const got = await bashCall(`toolu_kl_ws_${i}`, command, out);
      assert.match(got, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]\n\n\[mandu:secret\] masked: the command names /, why);
      assert.doesNotMatch(got, /STRIPE_SECRET_KEY|twin:|[\t  ]/, why);
      assert.doesNotMatch(got, /Chunk ID|Original token count/, why);
    }

    // a listing no guard record answers for: the text alone is no evidence
    const unrecorded = await bashCall("toolu_kl_norecord", command, LISTING);
    assert.match(unrecorded, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]\n\n\[mandu:secret\] masked: the command names /, unrecorded);
    assert.doesNotMatch(unrecorded, /STRIPE_SECRET_KEY|twin:/);

    // sorted: not the twin's order
    await s.cleanRun(session, "sed-kl-sort", ["toolu_kl_sort"]);
    const sorted = await bashCall("toolu_kl_sort", `${command} | sort`, "# fake values, made up by mandu demo\nPORT\nSTRIPE_SECRET_KEY");
    assert.doesNotMatch(sorted, /STRIPE_SECRET_KEY|twin:/, sorted);

    // the same command whose tree read the file raw: rule (i), one symbol
    await s.rawRun(session, "sed-kl-raw", "toolu_kl_raw", command, adapter);
    const raw = await bashCall("toolu_kl_raw", command, LISTING);
    assert.match(raw, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/, raw);
    assert.doesNotMatch(raw, /STRIPE_SECRET_KEY|twin:/);
    assert.match(raw, /\[mandu:secret\] masked: sed read /, "rule (i): the tree read the file raw");

    // THE ORACLE: the secret value is in no request to the model
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(KEY), "the model got the secret value");
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("Codex: the same listing behind the exec envelope reaches the model with the Codex key-listing note (`cat it`); a raw read stays one symbol; no secret value reaches the model (secrets axes, explicit)", async () => {
  const s = await stack("codex");
  const session = `key-listing-codex-${process.pid}`;
  const command = `sed 's/=.*//' ${s.env}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const adapter = new OpenAiProxyArbiterAdapter(await s.open(s.sock), await s.open(s.humanSock));
  const proxy = new OpenAiProxy({ arbiter: adapter, upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await s.guard.registerSecret({ path: s.env, sessionKey: session });
    assert.ok(typeof reg.twin === "string", JSON.stringify(reg));
    // One call per request, the raw run after the clean one: a call bound
    // by the guard's call-root record alone is answered for its tree only
    // while the session holds no raw read (plan 13 D7).
    const ask = async (id: string): Promise<{ out: string; body: string }> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": session },
        body: JSON.stringify({
          model: "gpt-5.5", stream: true, instructions: "You are Codex.",
          input: [
            { type: "message", role: "user", content: [{ type: "input_text", text: "The payments call fails with a 401 and an empty key. Which variables does .env set?" }] },
            { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd: command, workdir: s.ws }) },
            { type: "function_call_output", call_id: id, output: `${HEAD}${LISTING}\n` },
          ],
        }),
      });
      assert.equal(res.status, 200, await res.text());
      const body = upstream.requests.at(-1)!.bodyText;
      const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!;
      const o = item["output"];
      return { out: typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join(""), body };
    };
    await s.cleanRun(session, "sed-kl-c1", ["call_kl_1"]);
    assert.equal((await ask("call_kl_1")).out, `${HEAD}${LISTING}\n\n\n${NOTE_CODEX(s.env)}`);
    await s.rawRun(session, "sed-kl-craw", "call_kl_raw", command, adapter);
    const raw = (await ask("call_kl_raw")).out;
    assert.match(raw, /\$MDU:nomodel_/, raw);
    assert.doesNotMatch(raw, /STRIPE_SECRET_KEY|twin:/);
    assert.match(raw, /\[mandu:secret\] masked: sed read /, "rule (i): the tree read the file raw");
    // THE ORACLE: the secret value is in no request to the model
    assert.ok(!upstream.requests.map((r) => r.bodyText).join("\n").includes(KEY), "the model got the secret value");
  } finally {
    await proxy.close();
    await s.close();
  }
});
