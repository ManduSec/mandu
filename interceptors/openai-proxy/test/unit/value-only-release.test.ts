/**
 * value-only-release.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (docs/design/confidentiality/backstop-value-only.md §3): a
 * Codex exec output the arbiter offers as a value-only release goes with
 * each registered value as its symbol, and only when the call's own
 * evidence is clean; else it is masked whole.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { acceptValueOnlyOffer, rewriteRequest, valueOnlyEvidenceClean } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const KEY = "sk_test_VALUEONLY_2718281828";
const SYM = "$MDU:nomodel_Read[1a2b].STRIPE_SECRET_KEY";
const OUT = `Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\nDEBUG: Authorization: Bearer ${KEY}\nok: HTTP 200\n`;
const AT = OUT.indexOf(KEY);
const OFFER = { text: OUT.replace(KEY, SYM), spans: [{ start: AT, end: AT + KEY.length, symbol: SYM }] };

const offered = (valueOnly: unknown): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model",
  raisedBy: "value-backstop", valueOnly: valueOnly as ClassifyResult["valueOnly"],
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "payments broke last night" }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd: "cat shop-app/logs/payments.log" }) },
      { type: "function_call_output", call_id: "call_1", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("the same helpers as the Claude proxy", () => {
  assert.deepEqual(acceptValueOnlyOffer(OUT, { valueOnly: OFFER }), { text: OFFER.text, values: [{ symbol: SYM, value: KEY }] });
  assert.equal(acceptValueOnlyOffer(OUT, { valueOnly: { ...OFFER, text: "x" } }), null);
  assert.equal(valueOnlyEvidenceClean(null), true);
  assert.equal(valueOnlyEvidenceClean({ level: "no-model", files: ["/w/.env"], apps: ["cat"], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: "" }), false);
});

test("a clean exec: the output goes with the key as its symbol; the key is in no byte of the request", async () => {
  const r = await rewriteRequest(exec(OUT), { arbiter: new MockArbiter({ classifyFn: () => offered(OFFER), callTaintFn: () => wire({}) }) });
  assert.equal(out(r), OFFER.text);
  assert.ok(!JSON.stringify(r.request).includes(KEY));
  assert.deepEqual(r.rewrites[0]!.valueOnly, [{ symbol: SYM, value: KEY }]);
});

test("fail closed: a tainted tree, no offer, a malformed offer", async () => {
  for (const [name, o] of [
    ["tainted", { classifyFn: () => offered(OFFER), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) }],
    ["no offer", { classifyFn: () => offered(undefined), callTaintFn: () => wire({}) }],
    ["malformed", { classifyFn: () => offered({ text: OFFER.text, spans: [{ ...OFFER.spans[0], symbol: "x" }] }), callTaintFn: () => wire({}) }],
  ] as const) {
    const r = await rewriteRequest(exec(OUT), { arbiter: new MockArbiter(o as ConstructorParameters<typeof MockArbiter>[0]) });
    const t = out(r);
    assert.ok(!t.includes("ok: HTTP 200"), `${name}: masked whole: ${t}`);
    assert.ok(!t.includes(KEY), name);
    assert.equal(r.rewrites[0]!.valueOnly, undefined, name);
  }
});

test("fail closed (review round 2): a listed reader, a refused open, a path-rule level, integrity distrust, after the fact", async () => {
  const cases: Array<[string, ConstructorParameters<typeof MockArbiter>[0], Record<string, unknown>?]> = [
    ["listed reader", { classifyFn: () => offered(OFFER), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["psql"], rule: "clear" }) }],
    ["refused open", { classifyFn: () => offered(OFFER), callTaintFn: () => wire({ denied: [{ path: "/w/.env", app: "cat", reason: "not a reader" }] }) }],
    ["path-rule level", { classifyFn: () => ({ ...offered(OFFER), raisedBy: undefined }), callTaintFn: () => wire({}) }],
    ["integrity distrust", { classifyFn: () => ({ ...offered(OFFER), trust: "UNTRUSTED", category: "web" }), callTaintFn: () => wire({}) }],
    ["after the fact", { classifyFn: () => offered(OFFER), callTaintFn: () => wire({}) }, { clearResults: { wasClear: () => true, remember: async () => {} } }],
  ];
  for (const [name, o, extra] of cases) {
    const r = await rewriteRequest(exec(OUT), { arbiter: new MockArbiter(o), ...(extra ?? {}) } as Parameters<typeof rewriteRequest>[1]);
    const t = out(r);
    assert.ok(!t.includes("ok: HTTP 200"), `${name}: masked whole: ${t}`);
    assert.ok(!t.includes(KEY), name);
    assert.equal(r.rewrites[0]!.valueOnly, undefined, name);
  }
});

test("fail closed (review round 2): a non-text output (an image part beside the text) is never released in part", async () => {
  const output = [{ type: "input_text", text: OUT }, { type: "input_image", image_url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAE" }];
  const flat = JSON.stringify(output);
  const at = flat.indexOf(KEY);
  const offer = { text: flat.replace(KEY, SYM), spans: [{ start: at, end: at + KEY.length, symbol: SYM }] };
  const req = exec(OUT);
  (req.input as Array<{ type: string; output?: unknown }>)[2]!.output = output;
  const r = await rewriteRequest(req, { arbiter: new MockArbiter({ classifyFn: () => offered(offer), callTaintFn: () => wire({}) }) });
  assert.equal(r.rewrites[0]!.valueOnly, undefined);
  assert.ok(!JSON.stringify(r.request).includes("iVBORw0KGgo"), "no byte of the image");
  assert.ok(!JSON.stringify(r.request).includes(KEY));
});
