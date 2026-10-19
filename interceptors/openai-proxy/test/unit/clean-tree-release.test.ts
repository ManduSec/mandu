/**
 * clean-tree-release.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (docs/design/confidentiality/clean-tree-release.md §2, rules
 * Q1-Q3): a Codex exec output masked only because its command names a
 * registered credential file goes as the arbiter offers it, and only when
 * the call's own evidence is clean; else it is masked whole. The classify
 * names the call by `treeCallId` (R3), never by `callId`.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { acceptPathReleaseOffer, rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const KEY = "sk_test_CLEANTREE_2718281828";
const SYM = "$MDU:nomodel_Read[1a2b].STRIPE_SECRET_KEY";
const HEAD = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
const GIT = `${HEAD}Cannot rewrite branches: You have unstaged changes.\n`;
const LOG_P = `${HEAD}+const stripe = Stripe("${KEY}");\n`;
const AT = LOG_P.indexOf(KEY);
const LOG_OFFER = { text: LOG_P.replace(KEY, SYM), spans: [{ start: AT, end: AT + KEY.length, symbol: SYM }] };

const offered = (o: unknown): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock; the command names a secret path", confidentiality: "no-model",
  namedPaths: [".env"], pathRelease: o as ClassifyResult["pathRelease"],
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function exec(output: string, cmd = "git filter-branch --force --index-filter 'git rm -q --cached --ignore-unmatch .env' -- --all"): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "scrub the key" }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd }) },
      { type: "function_call_output", call_id: "call_1", output },
    ],
  } as unknown as ResponsesRequest;
}
const out = (r: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);

test("the same helper as the Claude proxy", () => {
  assert.deepEqual(acceptPathReleaseOffer(GIT, { pathRelease: { text: GIT, spans: [] } }), { text: GIT, values: [] });
  assert.equal(acceptPathReleaseOffer(GIT, { pathRelease: { text: `${GIT}x`, spans: [] } }), null);
  assert.deepEqual(acceptPathReleaseOffer(LOG_P, { pathRelease: LOG_OFFER }), { text: LOG_OFFER.text, values: [{ symbol: SYM, value: KEY }] });
});

test("released: the output as it is, the classify naming the call by treeCallId", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({}) });
  const r = await rewriteRequest(exec(GIT), { arbiter });
  assert.equal(out(r), GIT);
  const asked = arbiter.classifyCalls.find((c) => c.value === GIT)!;
  assert.equal(asked.treeCallId, "call_1");
  assert.equal((asked as { callId?: string }).callId, undefined, "no callId: its start-directory reading is not taken");
});

test("released with spans: the key as its symbol, in no byte of the request", async () => {
  const r = await rewriteRequest(exec(LOG_P, "git log -p -- src .env"), { arbiter: new MockArbiter({ classifyFn: () => offered(LOG_OFFER), callTaintFn: () => wire({}) }) });
  assert.equal(out(r), LOG_OFFER.text);
  assert.ok(!JSON.stringify(r.request).includes(KEY));
  assert.deepEqual(r.rewrites[0]!.valueOnly, [{ symbol: SYM, value: KEY }]);
});

test("fail closed: a tainted tree, a listed reader, a refused open, a refused connection, a backstop raise, no or a malformed offer", async () => {
  for (const [name, o] of [
    ["tainted", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) }],
    ["listed reader", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["psql"], rule: "clear" }) }],
    ["refused open", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ denied: [{ path: "/w/.env", app: "cat", reason: "x" }] }) }],
    ["refused connection", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ refusedEgress: [{ app: "curl", kind: "tainted" }] }) }],
    ["backstop raise", { classifyFn: () => ({ ...offered({ text: GIT, spans: [] }), raisedBy: "value-backstop" }), callTaintFn: () => wire({}) }],
    ["no offer", { classifyFn: () => offered(undefined), callTaintFn: () => wire({}) }],
    ["malformed", { classifyFn: () => offered({ text: "x", spans: [] }), callTaintFn: () => wire({}) }],
  ] as const) {
    const r = await rewriteRequest(exec(GIT), { arbiter: new MockArbiter(o as ConstructorParameters<typeof MockArbiter>[0]) });
    assert.ok(!out(r).includes("Cannot rewrite"), `${name}: masked whole: ${out(r)}`);
  }
});

test("fail closed: a non-text output part", async () => {
  const req = exec(GIT);
  (req.input as Array<{ type: string; output?: unknown }>)[2]!.output = [{ type: "input_text", text: GIT }, { type: "input_image", image_url: "data:image/png;base64,iVBORw0KGgo=" }];
  const r = await rewriteRequest(req, { arbiter: new MockArbiter({ classifyFn: () => offered({ text: JSON.stringify([{ type: "input_text", text: GIT }]), spans: [] }), callTaintFn: () => wire({}) }) });
  assert.ok(!JSON.stringify(r.request.input).includes("Cannot rewrite"), "masked whole");
});

test("review round 3: a release is not recorded as forwarded in clear, so the next request releases it again", async () => {
  const seen = new Set<string>();
  const clearResults = { wasClear: (id: string) => seen.has(id), remember: async (ids: readonly string[]) => { for (const i of ids) seen.add(i); } };
  const arbiter = new MockArbiter({ classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({}) });
  assert.equal(out(await rewriteRequest(exec(GIT), { arbiter, clearResults } as never)), GIT, "turn 1");
  assert.equal(out(await rewriteRequest(exec(GIT), { arbiter, clearResults } as never)), GIT, "turn 2: the history re-sent");
  assert.equal(seen.has("call_1"), false);
});

test("folder-listing-compound.md: a listing offer gets the listing line; a listing with spans refuses", async () => {
  const OUT = `${HEAD}1  Dentist  reminder\nbank:\nstatement.md\n`;
  const listing = { operands: ["bank"], part: "last" };
  const r = await rewriteRequest(exec(OUT, "tools/mail list; ls bank"), { arbiter: new MockArbiter({ classifyFn: () => offered({ text: OUT, spans: [], listing }), callTaintFn: () => wire({}) }) });
  assert.ok(out(r).startsWith(OUT), out(r));
  assert.ok(out(r).includes("[mandu:secret] listing: the last lines of this output are the names in bank as ls printed them"), out(r));
  const bad = await rewriteRequest(exec(OUT, "tools/mail list; ls bank"), { arbiter: new MockArbiter({ classifyFn: () => offered({ text: OUT, spans: LOG_OFFER.spans, listing }), callTaintFn: () => wire({}) }) });
  assert.ok(!out(bad).includes("Dentist"), "masked whole");
});
