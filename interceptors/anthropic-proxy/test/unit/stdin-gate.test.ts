/**
 * stdin-gate (unit) — text OpenClaw's `process` tool types into a background
 * exec session is exec-gated like a command (stdin-gate.ts;
 * supported-agents.md §2.1). The streams are built the way OpenClaw 2026.9.6
 * builds them (bash-tools.ts encodeKeySequence: literal, then hex bytes,
 * then encoded keys).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { encodeKeyToken, gateStdinToolUse, typedStreams, STDIN_GATE_MAX_BYTES } from "../../src/stdin-gate.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const STDIN = { process: "openclaw-process" } as const;
const SYM = "$MDU:bash[a1b2]";

test("typedStreams: write/paste text as written, send-keys as literal + hex bytes + encoded keys; nothing typed → no streams", () => {
  assert.deepEqual(typedStreams("openclaw-process", { action: "write", sessionId: "s1", data: "ls\n" }), [{ field: "data", text: "ls\n" }]);
  assert.deepEqual(typedStreams("openclaw-process", { action: "paste", sessionId: "s1", text: "echo hi" }), [{ field: "text", text: "echo hi" }]);
  // "$" via hex 0x24, then "MDU" literal-equivalent keys: a symbol spelled across the three fields is one stream
  const keys = typedStreams("openclaw-process", { action: "send-keys", literal: "bash -c ", hex: ["0x24", "4d", "zz"], keys: ["D", "U", ":", "b", "Enter"] });
  assert.deepEqual(keys, [{ field: "literal+hex+keys", text: "bash -c $MDU:b\r" }]);
  assert.deepEqual(typedStreams("openclaw-process", { action: "poll", sessionId: "s1" }), []);
  assert.deepEqual(typedStreams("openclaw-process", { action: "submit", sessionId: "s1" }), []);
  assert.deepEqual(typedStreams("openclaw-process", { action: "write", data: "" }), []);
  assert.deepEqual(typedStreams("openclaw-process", "write ls"), []);
});

test("typedStreams: a field that is not text is reported (the gate then refuses the call)", () => {
  assert.equal(typedStreams("openclaw-process", { action: "write", data: 42 }), "data");
  assert.equal(typedStreams("openclaw-process", { action: "send-keys", keys: "Enter" }), "keys");
  assert.equal(typedStreams("openclaw-process", { action: "send-keys", hex: [36] }), "hex");
  assert.equal(typedStreams("openclaw-process", { action: "send-keys", literal: ["ls"] }), "literal");
  assert.deepEqual(typedStreams("openclaw-process", { action: "write", data: null }), []);
});

test("encodeKeyToken: characters, control keys, named keys and unknown tokens as OpenClaw sends them", () => {
  assert.equal(encodeKeyToken("a"), "a");
  assert.equal(encodeKeyToken(" x "), "x");
  assert.equal(encodeKeyToken("^C"), "\x03");
  assert.equal(encodeKeyToken("^?"), "\x7f");
  assert.equal(encodeKeyToken("Enter"), "\r");
  assert.equal(encodeKeyToken("C-m"), "m", "a modified character keeps its character");
  assert.equal(encodeKeyToken("Tab"), "\t");
  assert.equal(encodeKeyToken("Left"), "\x1b");
  assert.equal(encodeKeyToken("F12"), "\x1b");
  assert.equal(encodeKeyToken("rm -rf /"), "rm -rf /", "an unknown token is sent literally");
  assert.equal(encodeKeyToken(""), "");
});

test("gateStdinToolUse: a symbol typed in command position into the shell is BLOCKED by the arbiter's execGate; benign text is allowed; each stream is asked", async () => {
  const arbiter = new MockArbiter({});
  const blocked = await gateStdinToolUse("process", { action: "write", sessionId: "s1", data: `bash -c "${SYM}"\n` }, { stdinTools: STDIN, arbiter, sessionKey: "k" });
  assert.equal(blocked.outcome?.decision, "block");
  assert.equal(arbiter.execGateCalls[0]!.command, `bash -c "${SYM}"\n`);
  assert.equal(arbiter.execGateCalls[0]!.sessionKey, "k", "the watermark session decides (a high session blocks every command)");
  assert.equal(arbiter.execGateCalls[0]!.callId, undefined, "typed text is no process the supervisor will correlate");
  const ok = await gateStdinToolUse("process", { action: "paste", sessionId: "s1", text: "ls -la" }, { stdinTools: STDIN, arbiter, sessionKey: "k" });
  assert.equal(ok.outcome?.decision, "allow");
  // send-keys spelling the symbol across literal / hex / keys is one stream
  const spelled = await gateStdinToolUse("process", { action: "send-keys", literal: `bash -c "$`, keys: ["M", "D", "U", ":bash[a1b2]\"", "Enter"] }, { stdinTools: STDIN, arbiter });
  assert.equal(spelled.outcome?.decision, "block");
});

test("gateStdinToolUse: fail closed — an unreachable arbiter, a malformed field, text past the bound; not a stdin tool → no opinion", async () => {
  const down = await gateStdinToolUse("process", { action: "write", data: "ls" }, { stdinTools: STDIN, arbiter: new MockArbiter({ failExecGate: true }) });
  assert.equal(down.outcome?.decision, "block");
  const bad = await gateStdinToolUse("process", { action: "write", data: { cmd: "ls" } }, { stdinTools: STDIN, arbiter: new MockArbiter({}) });
  assert.equal(bad.outcome?.decision, "block");
  const arbiter = new MockArbiter({});
  const big = await gateStdinToolUse("process", { action: "paste", text: "x".repeat(STDIN_GATE_MAX_BYTES + 1) }, { stdinTools: STDIN, arbiter });
  assert.equal(big.outcome?.decision, "block");
  assert.equal(arbiter.execGateCalls.length, 0, "past the bound nothing is sent to the arbiter");
  assert.equal((await gateStdinToolUse("exec", { data: SYM }, { stdinTools: STDIN, arbiter })).outcome, null);
  assert.equal((await gateStdinToolUse("process", { action: "write", data: SYM }, { stdinTools: {}, arbiter })).outcome, null);
});
