/**
 * path-derived-note.test.ts — the openai-proxy twin of the anthropic proxy's
 * test (confidentiality.md §7.1, "the path-derived note", 2026-10-05): a
 * Codex exec whose output is masked whole only because the command NAMES a
 * secret path carries the same `[mandu:secret]` line, built from the model's
 * own command; no output byte; only that case.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, pathDerivedPaths, pathDerivedTwinSentence, pathDerivedTwins, rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const TOUR = 'set -a && . ./.env && set +a && curl -sS https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"';
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
const BODY = '{"error":{"message":"Invalid API Key provided: sk_live_****3456","type":"invalid_request_error"}}\n';
const NOTE = "[mandu:secret] masked: the command names a secret file (./.env), so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";

const pathVerdict = (): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model",
  namedPaths: ["./.env", "/home/human/proj/.env"],
});
const publicVerdict = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" });
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(cmd: string, output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "list my Stripe customers" }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd }) },
      { type: "function_call_output", call_id: "call_1", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("the same line and the same path filter as the Claude proxy", () => {
  assert.equal(buildSecretNote({ level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "", pathDerived: { paths: ["./.env"] } }), NOTE);
  assert.deepEqual(pathDerivedPaths(["./.env", "/home/human/proj/.env"], TOUR), ["./.env"]);
});

test("the tour's command under Codex: the masked output ends with the note naming ./.env; no output byte, no translated path", async () => {
  const arbiter = new MockArbiter({ classifyFn: pathVerdict, callTaintFn: () => wire({}) });
  const t = out(await rewriteRequest(exec(TOUR, `${HEADER}${BODY}`), { arbiter }));
  assert.match(t, /\$MDU:/);
  assert.ok(t.endsWith(`\n\n${NOTE}`), t);
  for (const piece of ["Invalid API Key", "sk_live_", "3456", "invalid_request_error"]) {
    assert.ok(!t.includes(piece), `output byte(s) reached the model: ${piece}`);
  }
  assert.ok(!t.includes("/home/human"));
});

test("only the path-derived case: a taint-masked output and a public one get no path-derived line", async () => {
  const tainted = new MockArbiter({ classifyFn: pathVerdict, callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) });
  const a = out(await rewriteRequest(exec("cat ./.env", `${HEADER}${BODY}`), { arbiter: tainted }));
  assert.match(a, /\[mandu:secret\] masked: cat read \/w\/\.env/);
  assert.ok(!a.includes("the command names"), a);
  const pub = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({}) });
  const b = out(await rewriteRequest(exec("ls", `${HEADER}a b\n`), { arbiter: pub }));
  assert.ok(!b.includes("[mandu:secret]"), b);
});

// ── The way to the secret file itself (2026-10-19): the same sentences,
// byte for byte, as the Claude proxy's test pins them.
const LEAD = "[mandu:secret] masked: the command names a secret file (taxes/2025/*), so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file.";
const TAIL = " Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";
const TWIN_SENTENCES: Record<"lines" | "fields" | "whole" | "text", string> = {
  lines: "To use each secret file taxes/2025/* matches itself, read it on its own (a file read of that one file, or `cat` with that file alone): you see each line's label as written and its value as a symbol you can pass to a command (a command that sends it is checked against the file's rules).",
  fields: "To use .env itself, read it on its own (a file read of .env, or `cat .env` alone): you see its keys and layout as written and each secret value as a symbol you can pass to a command (a command that sends it is checked against the file's rules).",
  whole: "To use keys/id.bin itself, read it on its own (a file read of keys/id.bin, or `cat keys/id.bin` alone): you see one symbol that stands for the whole file, which you can pass whole to a command where the file's content belongs (a command that sends it is checked against the file's rules).",
  text: "To read ~/.ssh/config itself, read it on its own (a file read of ~/.ssh/config, or `cat ~/.ssh/config` alone): Mandu read every place in it that can hold a secret and found none, so you see its text.",
};

test("the twin sentences and their filter are the Claude proxy's", () => {
  assert.equal(pathDerivedTwinSentence({ path: "taxes/2025/*", twin: "lines" }), TWIN_SENTENCES.lines);
  assert.equal(pathDerivedTwinSentence({ path: ".env", twin: "fields" }), TWIN_SENTENCES.fields);
  assert.equal(pathDerivedTwinSentence({ path: "keys/id.bin", twin: "whole" }), TWIN_SENTENCES.whole);
  assert.equal(pathDerivedTwinSentence({ path: "~/.ssh/config", twin: "text" }), TWIN_SENTENCES.text);
  assert.deepEqual(pathDerivedTwins([{ path: "taxes/2025/*", twin: "lines" }, { path: "/h/x", twin: "lines" }, { path: ".env", twin: "nope" }], ["taxes/2025/*", ".env"]), [{ path: "taxes/2025/*", twin: "lines" }]);
  const base = { level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "" };
  assert.equal(buildSecretNote({ ...base, pathDerived: { paths: ["taxes/2025/*"], twins: [{ path: "taxes/2025/*", twin: "lines" }] } }), `${LEAD} ${TWIN_SENTENCES.lines}${TAIL}`);
  assert.equal(buildSecretNote({ ...base, pathDerived: { paths: ["taxes/2025/*"] } }), `${LEAD}${TAIL}`);
});

test("a Codex batch cat of a document: masked whole, and the note says how to read the document itself", async () => {
  const cmd = "ls -R taxes/; cat taxes/2025/* 2>/dev/null | head -100";
  const verdict = (): ClassifyResult => ({
    trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model",
    namedPaths: ["taxes/2025/*"], namedTwins: [{ path: "taxes/2025/*", twin: "lines" }],
  });
  const arbiter = new MockArbiter({ classifyFn: verdict, callTaintFn: () => wire({}) });
  const t = out(await rewriteRequest(exec(cmd, `${HEADER}SSN: 934-52-1170\n`), { arbiter }));
  assert.match(t, /\$MDU:/);
  assert.ok(t.endsWith(`\n\n${LEAD} ${TWIN_SENTENCES.lines}${TAIL}`), t);
  assert.ok(!t.includes("934-52-1170"));
});
