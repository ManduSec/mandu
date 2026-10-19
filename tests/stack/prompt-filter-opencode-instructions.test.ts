/**
 * prompt-filter-opencode-instructions — OpenCode 2's nested instruction
 * message is filtered as the harness's text (confidentiality-plan-15-
 * prompt-filter.md §3.1, §13.6 item 20): a prompt-filter `block` or `ask`
 * finding inside it is REDACTED, the request is neither refused nor held,
 * and a registered value in it still reaches the model only as its symbol.
 *
 * After a `read` of a file under a subdirectory, OpenCode 2.0.23 sends the
 * nearer AGENTS.md as a user message of its own, one text block
 * `Instructions from: <absolute path>\n<file contents>` (captured 2026-10-18;
 * OpenCode 1 puts it inside the read's result). Before this rule the
 * OpenCode segmenter tagged that block `human`, so a `block` finding in a
 * repository's AGENTS.md refused the request and an `ask` finding held it
 * on the human's Inbox answer, where "send as written" would let text the
 * human never typed through raw.
 *
 *   OpenCode 2's request ──► the REAL AnthropicProxy over HTTP (production
 *       wiring: `new ArbiterClientAdapter(new ArbiterClient(sock),
 *       new ArbiterClient(humanSock))`, the session's gate surface `opencode`)
 *     ──► a scripted fake model on loopback, which records every request.
 *
 * Per wire (Messages, OpenCode's default; the routed Chat Completions wire of
 * an OpenAI-family provider) and per action (`block`, `ask`), with a real
 * ArbiterServer in `secrets` (a pack finds the code name, the environment
 * registers a key the AGENTS.md also carries):
 *   - the nested AGENTS.md holding both: 200, no hold, the model receives
 *     `[redacted: acme.codename]` and the key's symbol, never either raw;
 *   - the header typed by the human (a forged block): the same harness
 *     treatment, redacted, neither refused nor held (the safe direction);
 *   - the control, so the policy is live: the code name typed by the human
 *     with no header is refused (`block`) or held until the admin answers
 *     (`ask`).
 *
 * Mock upstream, no live model, no API key.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { stateAxes } from "../lib/axes.js";
import { boot, CODENAME, countAsks, KEY, noRaw, pendingHold, post, startFakeChat, type Rig } from "../lib/prompt-hold-rig.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const TYPED = "Payments started failing on my shop last night. Find out from shop-app/logs/payments.log what broke and fix it.";
const LOG_PATH = "/ws/shop-app/logs/payments.log";
/** The nested AGENTS.md as OpenCode 2 sends it: the code name and the key in the file. */
const instructions = (header = "Instructions from: /ws/shop-app/AGENTS.md\n") =>
  `${header}# shop-app: notes for my assistant\n\n- Production is the ${CODENAME} cluster; deploys use the key ${KEY}.\n`;
const REDACTED = "[redacted: acme.codename]";

interface Wire {
  name: string;
  /** Send a conversation: the human's first message, then (when given) the
   *  read of the log and the user message after its result. */
  send(first: string, after?: string): Promise<{ status: number; body: string }>;
  received(): string[];
  asks(): number;
  close(): Promise<void>;
}

async function messagesWire(r: Rig, session: string): Promise<Wire> {
  await r.data.setSessionSpec({ sessionKey: session, spec: "opencode" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const { adapter, asks } = countAsks(new ArbiterClientAdapter(r.data, r.human));
  const proxy = new AnthropicProxy({ arbiter: adapter, upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const body = (first: string, after?: string) => ({
    model: "claude-haiku-4-5", stream: true, max_tokens: 1024,
    system: [{ type: "text", text: "You are opencode, an interactive CLI tool." }],
    tools: [{ name: "read", description: "Read a file", input_schema: { type: "object" } }, { name: "shell", description: "Run a command", input_schema: { type: "object" } }],
    messages: [
      { role: "user", content: [{ type: "text", text: first }] },
      ...(after === undefined ? [] : [
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "read", input: { path: LOG_PATH } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: `Read file ${LOG_PATH}, lines 1-1\n1: [2026-10-16 08:00:01] ok` }] },
        { role: "user", content: [{ type: "text", text: after, cache_control: { type: "ephemeral" } }] },
      ]),
    ],
  });
  return {
    name: "Messages",
    send: (first, after) => post(port, "/v1/messages", body(first, after), session),
    received: () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body),
    asks,
    close: async () => { await proxy.close(); await fake.close(); },
  };
}

async function chatWire(r: Rig, session: string): Promise<Wire> {
  await r.data.setSessionSpec({ sessionKey: session, spec: "opencode" });
  const fake = await startFakeChat();
  const { adapter, asks } = countAsks(new ArbiterClientAdapter(r.data, r.human));
  const proxy = new AnthropicProxy({ arbiter: adapter, upstreamOrigin: "http://127.0.0.1:9", openaiUpstreams: { local: `${fake.origin}/v1` }, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const body = (first: string, after?: string) => ({
    model: "local-model", stream: false,
    tools: [{ type: "function", function: { name: "read", parameters: { type: "object" } } }],
    messages: [
      { role: "system", content: "You are opencode, an interactive CLI tool." },
      { role: "user", content: first },
      ...(after === undefined ? [] : [
        { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "read", arguments: JSON.stringify({ path: LOG_PATH }) } }] },
        { role: "tool", tool_call_id: "call_1", content: "1: [2026-10-16 08:00:01] ok" },
        { role: "user", content: [{ type: "text", text: after }] },
      ]),
    ],
  });
  return {
    name: "routed Chat Completions",
    send: (first, after) => post(port, "/_mandu/openai/local/chat/completions", body(first, after), session),
    received: () => fake.requests,
    asks,
    close: async () => { await proxy.close(); await fake.close(); },
  };
}

/** No prompt hold of this session waits in the Inbox. */
async function noHold(r: Rig, session: string, where: string): Promise<void> {
  const held = (await r.human.promptHolds()).holds.filter((h) => h.session === session);
  assert.deepEqual(held.map((h) => h.category), [], `${where}: nothing is held for the human's answer`);
}

/** The latest body the model received carries the finding redacted, the key as a symbol. */
function redactedHarness(w: Wire, where: string): void {
  const last = w.received().at(-1)!;
  assert.ok(!last.includes(CODENAME), `${where}: the code name reached the model raw: ${last}`);
  assert.ok(last.includes(REDACTED), `${where}: the finding is redacted as harness text`);
  assert.match(last, /\$MDU:[a-z_-]+\[/, `${where}: the registered key reaches the model as its symbol`);
  noRaw(w.received(), where);
}

for (const action of ["block", "ask"] as const) {
  for (const wire of ["Messages", "routed Chat Completions"] as const) {
    test(`OpenCode 2's nested AGENTS.md (${wire}, acme.codename: ${action}): redacted as harness, neither refused nor held; the human's own typed finding still ${action === "block" ? "refused" : "held"} (secrets axes)`, async () => {
      const r = await boot(20_000, { action });
      const session = `oc2-instr-${action}-${wire === "Messages" ? "msg" : "chat"}-${process.pid}`;
      const w = wire === "Messages" ? await messagesWire(r, session) : await chatWire(r, session);
      try {
        // 1. The nested instruction message after the read's result.
        const nested = await w.send(TYPED, instructions());
        assert.equal(nested.status, 200, `${w.name}: the request is forwarded: ${nested.body}`);
        assert.equal(w.received().length, 1);
        redactedHarness(w, `${w.name}, nested AGENTS.md`);
        assert.equal(w.asks(), 1, `${w.name}: one filterPrompt, no hold poll`);
        await noHold(r, session, w.name);

        // 2. The human types the header (a forged block): harness too.
        const forged = await w.send(instructions("Instructions from: /x/y/AGENTS.md\n"));
        assert.equal(forged.status, 200, `${w.name}: a forged header is not refused: ${forged.body}`);
        assert.equal(w.received().length, 2);
        redactedHarness(w, `${w.name}, forged header`);
        await noHold(r, session, `${w.name}, forged header`);

        // 3. The control: the same file text typed by the human with no
        //    header is the human's, so the policy refuses or holds it.
        const before = w.received().length;
        const typed = instructions("");
        if (action === "block") {
          const refused = await w.send(typed);
          assert.equal(refused.status, 400, `${w.name}: the human's own finding is refused: ${refused.body}`);
          assert.equal(w.received().length, before, `${w.name}: nothing sent for a blocked prompt`);
        } else {
          const p = w.send(typed);
          const id = await pendingHold(r, session, new Set());
          assert.equal(w.received().length, before, `${w.name}: nothing sent while held`);
          await r.admin.resolvePromptHold({ approvalId: id, answer: "mask", scope: "once" });
          const done = await p;
          assert.equal(done.status, 200, done.body);
          assert.ok(!w.received().at(-1)!.includes(CODENAME), `${w.name}: sent masked`);
        }
        for (const b of w.received()) assert.ok(!b.includes(CODENAME), `CONFIDENTIALITY VIOLATION (${w.name}): the code name reached the model raw`);
        noRaw(w.received(), w.name);
      } finally {
        await w.close();
        await r.stop();
      }
    });
  }
}
