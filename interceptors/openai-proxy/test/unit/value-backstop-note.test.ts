/**
 * value-backstop-note.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (confidentiality.md §7.1, "the value-backstop note",
 * 2026-10-17): a Codex exec whose output the arbiter's value backstop raised
 * (a registered secret's value in a log the path rules call public) carries
 * the value-backstop line, byte-identical to the Claude proxy's, and never
 * the path-derived advice, which names a secret file the command does not.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const KEY = "sk_test_NOTEPROBE_2718281828";
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
const LOG = `[08:00:01] check (DEBUG=1)\nDEBUG: Authorization: Bearer ${KEY}\n[08:00:02] ok: HTTP 200\n[20:00:01] warning: STRIPE_KEY is empty\n`;
const NOTE = "[mandu:secret] masked: this output contains the value of a registered secret, so the whole output is withheld from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). It is withheld for that value, not for the file it came from. To read the rest, run a command that prints it with the value left out (for example without the lines that hold it); do not print the value in any other form. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";

const backstopVerdict = (): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock; a registered secret appears verbatim", confidentiality: "no-model",
  raisedBy: "value-backstop",
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(cmd: string, output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "payments broke last night; here is the log" }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd }) },
      { type: "function_call_output", call_id: "call_1", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("the same line as the Claude proxy, and no listed reader's release line beside it", () => {
  const base = { level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "" };
  assert.equal(buildSecretNote({ ...base, valueBackstop: true }), NOTE);
  assert.equal(buildSecretNote({ ...base, files: ["/w/.env"], apps: ["psql"], valueBackstop: true }), NOTE);
});

test("a `cat` of a public log the value backstop raised: masked, the value-backstop note, no path-derived advice, no output byte", async () => {
  const arbiter = new MockArbiter({ classifyFn: backstopVerdict, callTaintFn: () => wire({}) });
  const t = out(await rewriteRequest(exec("cat shop-app/logs/payments.log", `${HEADER}${LOG}`), { arbiter }));
  assert.match(t, /\$MDU:/);
  assert.ok(t.endsWith(`\n\n${NOTE}`), t);
  assert.ok(!t.includes("the command names"), t);
  assert.ok(!t.includes("names no secret file"), t);
  for (const piece of [KEY, "NOTEPROBE", "Authorization", "STRIPE_KEY is empty"]) {
    assert.ok(!t.includes(piece), `output byte(s) reached the model: ${piece}`);
  }
});

test("only the backstop case: a path-derived mask keeps its own note", async () => {
  const path = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model", namedPaths: [".env"] }),
    callTaintFn: () => wire({}),
  });
  const t = out(await rewriteRequest(exec("cat .env", `${HEADER}K=v\n`), { arbiter: path }));
  assert.match(t, /\[mandu:secret\] masked: the command names a secret file \(\.env\)/);
  assert.ok(!t.includes("registered secret"), t);
});
