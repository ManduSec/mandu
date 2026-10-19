/**
 * value-only-release.test.ts — the proxy's half of the value backstop's
 * value-only release (docs/design/confidentiality/backstop-value-only.md §3):
 * the arbiter OFFERS a result with each registered value replaced by its
 * symbol; this proxy takes it only when its own evidence says the call read
 * no secret (P2), and only after rebuilding it from its own copy (P3).
 * Every other case masks the result whole, as before.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { acceptValueOnlyOffer, rewriteRequest, valueOnlyEvidenceClean, mustNotSurvive } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const KEY = "sk_test_VALUEONLY_2718281828";
const SYM = "$MDU:nomodel_Read[1a2b].STRIPE_SECRET_KEY";
const LOG = `DEBUG: Authorization: Bearer ${KEY}\n[08:00:02] ok: HTTP 200\n`;
const AT = LOG.indexOf(KEY);
const RELEASED = `DEBUG: Authorization: Bearer ${SYM}\n[08:00:02] ok: HTTP 200\n`;
const OFFER = { text: RELEASED, spans: [{ start: AT, end: AT + KEY.length, symbol: SYM }] };
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

const offered = (o: unknown = OFFER): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock; a registered secret appears verbatim", confidentiality: "no-model",
  raisedBy: "value-backstop", valueOnly: o as ClassifyResult["valueOnly"],
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function call(name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "payments broke last night; here is the log" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  } as MessagesRequest;
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
const CAT = { command: "cat shop-app/logs/payments.log" };

test("acceptValueOnlyOffer: a well-formed offer rebuilt from the proxy's own copy", () => {
  assert.deepEqual(acceptValueOnlyOffer(LOG, { valueOnly: OFFER }), { text: RELEASED, values: [{ symbol: SYM, value: KEY }] });
});

test("acceptValueOnlyOffer: fail closed on every malformed offer", () => {
  const bad: unknown[] = [
    undefined, null, {}, { text: RELEASED }, { text: RELEASED, spans: [] },
    { text: RELEASED.replace("200", "201"), spans: OFFER.spans },                       // text does not rebuild
    { text: RELEASED, spans: [{ ...OFFER.spans[0], end: LOG.length + 1 }] },              // out of bounds
    { text: RELEASED, spans: [{ ...OFFER.spans[0], start: AT + 1 }] },                    // a different span
    { text: RELEASED, spans: [{ ...OFFER.spans[0], symbol: "not a symbol" }] },           // not a token
    { text: RELEASED, spans: [{ ...OFFER.spans[0], symbol: `${SYM} ${KEY}` }] },          // a token with a tail
    { text: RELEASED, spans: [{ ...OFFER.spans[0], start: "6" }] },                       // not a number
    { text: RELEASED, spans: [OFFER.spans[0], OFFER.spans[0]] },                          // overlapping / unsorted
  ];
  for (const o of bad) assert.equal(acceptValueOnlyOffer(LOG, { valueOnly: o }), null, JSON.stringify(o));
  // a replaced value that still occurs in the rebuilt text (the log printed it twice, one span offered)
  const twice = `${LOG}${KEY}\n`;
  assert.equal(acceptValueOnlyOffer(twice, { valueOnly: { text: `${RELEASED}${KEY}\n`, spans: OFFER.spans } }), null);
});

test("valueOnlyEvidenceClean: only a call whose evidence holds no secret read", () => {
  const base = { level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "" };
  assert.equal(valueOnlyEvidenceClean(null), true);
  assert.equal(valueOnlyEvidenceClean(base), true);
  for (const t of [
    { ...base, maskWhole: true }, { ...base, level: "no-model" }, { ...base, files: ["/w/.env"], apps: ["psql"] },
    { ...base, denied: [{ path: "/w/.env", app: "cat", reason: "x" }] }, { ...base, deniedOnly: true }, { ...base, twinOnly: true },
    { ...base, refusedEgress: [{ app: "curl", kind: "tainted" as const }] }, { ...base, blockedExec: [{ app: "sh", kind: "x" }] },
  ]) assert.equal(valueOnlyEvidenceClean(t as never), false, JSON.stringify(t));
});

test("a clean Bash `cat` of the log: the released text, the key as its symbol; the key is the must-not-survive span", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => offered(), callTaintFn: () => wire({}) });
  const out = await rewriteRequest(call("Bash", CAT, LOG), { arbiter });
  assert.equal(text(out), RELEASED);
  assert.ok(!JSON.stringify(out.request).includes(KEY), "THE ORACLE: the key is in no byte of the request");
  const r = out.rewrites[0]!;
  assert.equal(r.symbolized, true);
  assert.deepEqual(r.valueOnly, [{ symbol: SYM, value: KEY }]);
  assert.deepEqual(mustNotSurvive(r), [KEY]);
  assert.equal(r.secretNote, undefined, "no mask note: the result is not masked");
});

test("a Read of the log: the same release (a null taint is the path rule's public verdict)", async () => {
  const rendered = LOG.split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");
  const at = rendered.indexOf(KEY);
  const offer = { text: rendered.replace(KEY, SYM), spans: [{ start: at, end: at + KEY.length, symbol: SYM }] };
  const out = await rewriteRequest(call("Read", { file_path: "/w/logs/payments.log" }, rendered), { arbiter: new MockArbiter({ classifyFn: () => offered(offer) }) });
  assert.equal(text(out), offer.text);
});

test("fail closed: a tainted call, a listed reader's release, a refused open, no or a malformed offer, a path-rule level, after the fact", async () => {
  const cases: Array<[string, ConstructorParameters<typeof MockArbiter>[0]]> = [
    ["tainted tree", { classifyFn: () => offered(), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) }],
    ["listed reader (rule clear)", { classifyFn: () => offered(), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["psql"], rule: "clear" }) }],
    ["refused open", { classifyFn: () => offered(), callTaintFn: () => wire({ denied: [{ path: "/w/.env", app: "cat", reason: "not a reader" }] }) }],
    ["no offer", { classifyFn: () => ({ ...offered(), valueOnly: undefined }), callTaintFn: () => wire({}) }],
    ["a malformed offer", { classifyFn: () => offered({ text: "x", spans: OFFER.spans }), callTaintFn: () => wire({}) }],
    ["raised by a path rule, not the backstop", { classifyFn: () => ({ ...offered(), raisedBy: undefined }), callTaintFn: () => wire({}) }],
  ];
  for (const [name, o] of cases) {
    const out = await rewriteRequest(call("Bash", CAT, LOG), { arbiter: new MockArbiter(o) });
    const t = text(out);
    assert.match(t, SYM_RE, `${name}: masked whole: ${t}`);
    assert.ok(!t.includes("ok: HTTP 200"), `${name}: no byte of the result`);
    assert.ok(!t.includes(KEY), name);
    assert.equal(out.rewrites[0]!.valueOnly, undefined, name);
  }
  // after the fact: the result went in clear before, so it keeps the whole mask and its note
  const arbiter = new MockArbiter({ classifyFn: () => offered(), callTaintFn: () => wire({}) });
  const clearResults = { wasClear: (id: string) => id === "tu_1", remember: async () => {} };
  const t = text(await rewriteRequest(call("Bash", CAT, LOG), { arbiter, clearResults }));
  assert.match(t, SYM_RE);
  assert.ok(!t.includes("ok: HTTP 200"), t);
});

test("fail closed: the integrity axis distrusting the result, and a non-text block", async () => {
  const untrusted = new MockArbiter({ classifyFn: () => ({ ...offered(), trust: "UNTRUSTED", category: "web" }), callTaintFn: () => wire({}) });
  const t = text(await rewriteRequest(call("Bash", CAT, LOG), { arbiter: untrusted }));
  assert.ok(!t.includes("ok: HTTP 200"), t);
  const img: MessagesRequest = {
    model: "claude-test",
    messages: [
      { role: "user", content: "x" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name: "Bash", input: CAT }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content: [{ type: "text", text: LOG }, { type: "image", source: { type: "base64", media_type: "image/png", data: "AAAA" } }] }] },
    ],
  } as MessagesRequest;
  const out = await rewriteRequest(img, { arbiter: new MockArbiter({ classifyFn: () => offered(), callTaintFn: () => wire({}) }) });
  assert.equal(out.rewrites[0]!.valueOnly, undefined);
  assert.ok(!JSON.stringify(out.request).includes("ok: HTTP 200"));
});

test("fail closed (review round 2): the agent received a secret during the call, a twin was matched, a connection was refused", async () => {
  const cases: Array<[string, ConstructorParameters<typeof MockArbiter>[0]]> = [
    ["agent receipt", {
      classifyFn: () => offered(), callTaintFn: () => wire({}),
      agentReceiptTaintFn: (req) => ({ calls: req.calls.map((c) => ({ callId: c.callId, level: "no-model", files: ["/w/.env"], apps: ["mcp-server"] })) }),
    }],
    ["a twin matched", { classifyFn: () => offered(), callTaintFn: () => wire({ twinOf: ["/w/.env"], twinKeys: true } as Partial<CallTaintWire>) }],
    ["a refused connection", { classifyFn: () => offered(), callTaintFn: () => wire({ refusedEgress: [{ app: "curl", kind: "tainted" }] } as Partial<CallTaintWire>) }],
  ];
  for (const [name, o] of cases) {
    const out = await rewriteRequest(call("Bash", CAT, LOG), { arbiter: new MockArbiter(o) });
    const t = text(out);
    assert.ok(!t.includes("ok: HTTP 200"), `${name}: masked whole: ${t}`);
    assert.ok(!t.includes(KEY), name);
    assert.equal(out.rewrites[0]!.valueOnly, undefined, name);
  }
});
