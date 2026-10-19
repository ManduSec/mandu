/**
 * quoted-payload-binding — plan 13 D7's call-root recorder over the REAL
 * components, for the shell shape of Codex, OpenCode and OpenClaw
 * (`bash -lc '<command>'`) when the command starts and ends with a quote
 * character (plan 13 D8 leftover (5), 2026-10-03).
 *
 *   a real ArbiterServer in `secrets`, the real AnthropicProxy over HTTP in
 *   its production wiring (`new ArbiterClientAdapter(new ArbiterClient(sock),
 *   new ArbiterClient(humanSock))`), a scripted model behind it. One turn,
 *   three Bash calls; the guard's records are written as the guard writes
 *   them, on the human socket:
 *     - a reader call: its shell's `mytool` reads the secret raw, so the
 *       session holds a raw read (an unbound call is then masked whole);
 *     - a clean call whose command is `"printf" '%s\n' "quoted-ok"`: on
 *       master the signature stripped one more quote layer off the shell's
 *       payload, read `printf" '%s\n' "quoted-ok` and matched no call, so
 *       the clean result was masked whole with the D7 note (utility). Now it
 *       binds to its own shell and reaches the model raw;
 *     - a lost call (`rev "$SECRET_FILE"`) whose own shell's
 *       record never arrived, while the agent's child ran a DIFFERENT command:
 *       the same text inside one more pair of quotes (one word, a program of
 *       that name). On master the extra layer was stripped, the lost call
 *       bound `exact` to that clean shell, and the file reversed reached the
 *       model raw. Now a different command never binds: masked.
 *
 * Unit twin: arbiter `exec-signature-quoting.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = `D8Q_STACK_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");
/** The file reversed (`rev`): a form no value scan knows, so only the
 *  binding decides whether it reaches the model. */
const FILE_REV = [...`token=${CANARY}`].reverse().join("");
const READ = "mytool ./x.tx? | od -An -tx1 | tr -d ' \\n'";
const QUOTED = `"printf" '%s\\n' "quoted-ok"`;
// names the file by a variable only (no path-derived precaution): the
// binding alone decides
const LOST = 'rev "$SECRET_FILE"';
const CALLS = [
  { id: "toolu_q_read", command: READ },
  { id: "toolu_q_quoted", command: QUOTED },
  { id: "toolu_q_lost", command: LOST },
];
const OUTPUT: Record<string, string> = {
  toolu_q_read: FILE_HEX,
  toolu_q_quoted: "quoted-ok\n",
  toolu_q_lost: `${FILE_REV}\n`,
};

/** Codex/OpenCode/OpenClaw's shell for one call, as the guard reads its argv. */
const lcShell = (command: string): string[] => ["/bin/bash", "-lc", command];

function toolUseTurn(): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_q_1", role: "assistant", content: [] } });
  CALLS.forEach((c, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: c.id, name: "Bash", input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command: c.command }) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function post(port: number, session: string, messages: unknown[]): Promise<{ status: number; body: string }> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { let b = ""; res.on("data", (c) => (b += String(c))); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b })); });
    r.on("error", reject);
    r.end(body);
  });
}

/** What the model received for one tool_result in one upstream request. */
function resultIn(body: string, id: string): string {
  const msgs = (JSON.parse(body) as { messages: Array<{ content?: unknown }> }).messages;
  for (const m of msgs) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<Record<string, unknown>>) {
      if (b.type !== "tool_result" || b.tool_use_id !== id) continue;
      return typeof b.content === "string" ? b.content : JSON.stringify(b.content);
    }
  }
  throw new Error(`no tool_result ${id} forwarded`);
}

test("D7 over the real stack, bash -lc shells: a command quoted at both ends binds to its own shell (raw when clean); a shell of the same text inside one more quote layer binds no call (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-d8q-stack-"));
  const secret = join(tmp, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect(); // what the guard writes (plan 13 D9)
  const real = new ArbiterClient(sock); await real.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect(); // server-main's second client
  const session = `d8q-stack-${process.pid}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn() : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // 1. The model's turn: three Bash calls, gated by the proxy as they stream.
    const turn = await post(port, session, [{ role: "user", content: "go" }]);
    assert.equal(turn.status, 200);
    for (const c of CALLS) assert.ok(turn.body.includes(c.id), `the agent received ${c.id}`);

    // 2. The agent runs them; the guard reports what it saw.
    // the reader call: its shell → mytool, which reads the file raw
    await guard.recordExecRoot({ procKey: "q-sh-1", ancestors: ["q-agent-0"], argv: lcShell(READ), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "q-mytool-2", ancestors: ["q-sh-1", "q-agent-0"], argv: ["mytool", "./x.txt"], session });
    const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "q-mytool-2", parentKey: "q-sh-1", ancestorKeys: ["q-sh-1", "q-agent-0"], session });
    assert.equal(d.verdict, "raw", d.reason);
    // the quoted call: its own clean shell, the payload exactly the command
    await guard.recordExecRoot({ procKey: "q-sh-3", ancestors: ["q-agent-0"], argv: lcShell(QUOTED), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "q-printf-4", ancestors: ["q-sh-3", "q-agent-0"], argv: ["printf", "%s\\n", "quoted-ok"], session });
    // the lost call: its reader ran, its shell's record never arrived; the
    // agent's child ran another command, the same text in one more quote layer
    await guard.recordExecRoot({ procKey: "q-rev-6", ancestors: ["q-wrap-5", "q-agent-0"], argv: ["rev", "./x.txt"], session });
    await guard.recordExecRoot({ procKey: "q-sh-7", ancestors: ["q-agent-0"], argv: lcShell(`"${LOST}"`), session, callRoot: true });

    // 3. The results go back to the model.
    const history = [
      { role: "user", content: "go" },
      { role: "assistant", content: CALLS.map((c) => ({ type: "tool_use", id: c.id, name: "Bash", input: { command: c.command } })) },
      { role: "user", content: CALLS.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: OUTPUT[c.id] })) },
    ];
    assert.equal((await post(port, session, history)).status, 200);
    const sent = seen[1]!;
    const read = resultIn(sent, "toolu_q_read");
    assert.match(read, /\[mandu:secret\] masked: mytool read .*x\.txt/, `the reader call is masked by its own tree: ${read}`);
    // MASTER: masked whole with "plan 13 D7: Mandu could not tie this Bash call"
    const quoted = resultIn(sent, "toolu_q_quoted");
    assert.ok(quoted.startsWith("quoted-ok"), `a clean call quoted at both ends binds to its own shell and is raw: ${quoted}`);
    // MASTER: bound exact to q-sh-7 (clean) and the file reversed reached the model raw
    const lost = resultIn(sent, "toolu_q_lost");
    assert.ok(!lost.includes(FILE_REV.slice(0, 16)), `CONFIDENTIALITY VIOLATION: a shell of a different command bound the lost call: ${lost}`);
    assert.match(lost, /plan 13 D7: Mandu could not tie this Bash call/, lost);

    // THE ORACLE: no request to the model carried the file, raw or hex.
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
    assert.ok(!wire.includes(FILE_REV.slice(0, 16)), "the file reversed never reached the model");
  } finally {
    await proxy.close();
    guard.close(); real.close(); realHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
