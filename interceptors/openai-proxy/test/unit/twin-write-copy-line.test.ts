/**
 * twin-write-copy-line.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (plan 10 §4.1, "The model is told at the call", 2026-10-27):
 * a Codex exec that writes a protected file (a heredoc into the `.env`)
 * carries the same `copy:` line after its masked line, wherever the arbiter
 * answers `twinWrites`, naming the model's own token; no output byte.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { twinWriteLine } from "../../src/twin-write-note.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const ENV = "orders-app/.env";
const HEREDOC = `cat > ${ENV} << 'EOF'\nORDERHUB_PASSWORD='$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'\nEOF\n`;
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
const COPY = `[mandu:secret] ${twinWriteLine([ENV])}`;

const verdict = (twinWrites: string[]): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model", namedPaths: [ENV], twinWrites,
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(cmd: string, output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Fix the order sync." }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd }) },
      { type: "function_call_output", call_id: "call_1", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("Codex's heredoc into the .env, answered: masked, the masked line, then the same copy: line as the Claude proxy's", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => verdict([ENV]), callTaintFn: () => wire({}) });
  const t = out(await rewriteRequest(exec(HEREDOC, HEADER), { arbiter }));
  assert.match(t, /\[mandu:secret\] masked: the command names a secret file \(orders-app\/\.env\)/);
  assert.ok(t.endsWith(`\n${COPY}`), t);
  assert.ok(!t.includes("Wall time: 0.0123"), "no run fact beyond what R4 forwards");
});

test("no copy: line without the arbiter's answer, nor for a token the command does not hold", async () => {
  const none = new MockArbiter({ classifyFn: () => verdict([]), callTaintFn: () => wire({}) });
  assert.ok(!out(await rewriteRequest(exec(HEREDOC, HEADER), { arbiter: none })).includes("copy:"));
  const foreign = new MockArbiter({ classifyFn: () => verdict(["/elsewhere/.env"]), callTaintFn: () => wire({}) });
  assert.ok(!out(await rewriteRequest(exec(HEREDOC, HEADER), { arbiter: foreign })).includes("copy:"));
});
