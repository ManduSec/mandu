/**
 * clean-tree-release.test.ts — the proxy's half of the path-derived mask's
 * clean-tree release (docs/design/confidentiality/clean-tree-release.md §2,
 * rules Q1-Q3): the arbiter OFFERS a shell result masked only because its
 * command names a registered credential file; this proxy takes it only when
 * its own evidence says the call read no secret (Q2), and only after
 * rebuilding it from its own copy (Q3). Every other case masks the result
 * whole, as before.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { acceptPathReleaseOffer, rewriteRequest, mustNotSurvive } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const KEY = "sk_test_CLEANTREE_2718281828";
const SYM = "$MDU:nomodel_Read[1a2b].STRIPE_SECRET_KEY";
const GIT = "Cannot rewrite branches: You have unstaged changes.\n";
const LOG_P = `commit 196115d Initial checkout service\n+const stripe = Stripe("${KEY}");\n`;
const AT = LOG_P.indexOf(KEY);
const LOG_OFFER = { text: LOG_P.replace(KEY, SYM), spans: [{ start: AT, end: AT + KEY.length, symbol: SYM }] };
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const FILTER = { command: "git filter-branch --force --index-filter 'git rm -q --cached --ignore-unmatch .env' -- --all 2>&1" };

const offered = (o: unknown): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock; the command names a secret path", confidentiality: "no-model",
  namedPaths: [".env"], pathRelease: o as ClassifyResult["pathRelease"],
});
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function call(name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "scrub the key from storefront's history" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  } as MessagesRequest;
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);

test("acceptPathReleaseOffer: no span is the result exactly; spans rebuild as a value-only release; anything else is null", () => {
  assert.deepEqual(acceptPathReleaseOffer(GIT, { pathRelease: { text: GIT, spans: [] } }), { text: GIT, values: [] });
  assert.deepEqual(acceptPathReleaseOffer(LOG_P, { pathRelease: LOG_OFFER }), { text: LOG_OFFER.text, values: [{ symbol: SYM, value: KEY }] });
  for (const o of [undefined, null, {}, { text: GIT }, { text: `${GIT}x`, spans: [] }, { text: GIT, spans: "x" }]) {
    assert.equal(acceptPathReleaseOffer(GIT, { pathRelease: o }), null, JSON.stringify(o));
  }
  assert.equal(acceptPathReleaseOffer(LOG_P, { pathRelease: { text: "x", spans: LOG_OFFER.spans } }), null, "spans that do not rebuild the text");
  const tok = `${GIT}see $mdu:x\n`;
  assert.equal(acceptPathReleaseOffer(tok, { pathRelease: { text: tok, spans: [] } }), null, "a $MDU text in any case is never released");
});

test("released: git's output naming .env goes as it is, no note, no symbol", async () => {
  const out = await rewriteRequest(call("Bash", FILTER, GIT), { arbiter: new MockArbiter({ classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({}) }) });
  assert.equal(text(out), GIT);
  const r = out.rewrites[0]!;
  assert.equal(r.symbolized, false);
  assert.match(r.reason ?? "", /clean-tree release/);
});

test("released with spans: the key as its symbol; the key is the must-not-survive span", async () => {
  const out = await rewriteRequest(call("Bash", { command: "git log -p -- src .env" }, LOG_P), { arbiter: new MockArbiter({ classifyFn: () => offered(LOG_OFFER), callTaintFn: () => wire({}) }) });
  assert.equal(text(out), LOG_OFFER.text);
  assert.ok(!JSON.stringify(out.request).includes(KEY), "THE ORACLE: the key is in no byte of the request");
  const r = out.rewrites[0]!;
  assert.deepEqual(r.valueOnly, [{ symbol: SYM, value: KEY }]);
  assert.deepEqual(mustNotSurvive(r), [KEY]);
  assert.match(r.reason ?? "", /clean-tree release: 1 registered value/);
});

test("fail closed (Q1, Q2): a tainted tree, a listed reader, a refused open, a matched twin, a refused connection, a blocked command, a backstop raise, a malformed offer, after the fact", async () => {
  const cases: Array<[string, ConstructorParameters<typeof MockArbiter>[0]]> = [
    ["tainted tree", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) }],
    ["listed reader", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["psql"], rule: "clear" }) }],
    ["refused open", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ denied: [{ path: "/w/.env", app: "cat", reason: "x" }] }) }],
    ["refused connection", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ refusedEgress: [{ app: "curl", kind: "tainted" }] }) }],
    ["blocked command", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ blockedExec: [{ app: "sh", kind: "x" }] }) }],
    ["a backstop raise is not this release's", { classifyFn: () => ({ ...offered({ text: GIT, spans: [] }), raisedBy: "value-backstop" }), callTaintFn: () => wire({}) }],
    ["no offer", { classifyFn: () => offered(undefined), callTaintFn: () => wire({}) }],
    ["a malformed offer", { classifyFn: () => offered({ text: "other", spans: [] }), callTaintFn: () => wire({}) }],
    ["unbound session taint", { classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["node"], evidence: "session" }) }],
  ];
  for (const [name, o] of cases) {
    const out = await rewriteRequest(call("Bash", FILTER, GIT), { arbiter: new MockArbiter(o) });
    const t = text(out);
    assert.match(t, SYM_RE, `${name}: masked whole: ${t}`);
    assert.ok(!t.includes("Cannot rewrite"), `${name}: no byte of the result`);
  }
  const arbiter = new MockArbiter({ classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({}) });
  const clearResults = { wasClear: (id: string) => id === "tu_1", remember: async () => {} };
  assert.match(text(await rewriteRequest(call("Bash", FILTER, GIT), { arbiter, clearResults })), SYM_RE, "after the fact keeps the mask");
});

test("fail closed: a non-text block beside the text", async () => {
  const req = call("Bash", FILTER, GIT);
  (req.messages[2]!.content as Array<{ content: unknown }>)[0]!.content = [{ type: "text", text: GIT }, { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } }];
  const out = await rewriteRequest(req, { arbiter: new MockArbiter({ classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({}) }) });
  assert.ok(!JSON.stringify(out.request.messages[2]).includes("Cannot rewrite"), "masked whole");
});

test("review round 3: a release is not recorded as forwarded in clear, so the next request releases it again", async () => {
  const seen = new Set<string>();
  const clearResults = { wasClear: (id: string) => seen.has(id), remember: async (ids: readonly string[]) => { for (const i of ids) seen.add(i); } };
  const arbiter = new MockArbiter({ classifyFn: () => offered({ text: GIT, spans: [] }), callTaintFn: () => wire({}) });
  assert.equal(text(await rewriteRequest(call("Bash", FILTER, GIT), { arbiter, clearResults })), GIT, "turn 1");
  assert.equal(text(await rewriteRequest(call("Bash", FILTER, GIT), { arbiter, clearResults })), GIT, "turn 2: the history re-sent");
  assert.equal(seen.has("tu_1"), false);
});

test("folder-listing-compound.md: a listing offer gets the listing line naming the operands as written; a listing with spans or malformed refuses", async () => {
  const OUT = "1  Dentist  reminder\nbank:\nstatement.md\n\nmail/inbox:\n1.md";
  const cmd = { command: "tools/mail list; ls mail/inbox bank" };
  const listing = { operands: ["mail/inbox", "bank", "/abs/not/in/command"], part: "last" };
  const out = await rewriteRequest(call("Bash", cmd, OUT), { arbiter: new MockArbiter({ classifyFn: () => offered({ text: OUT, spans: [], listing }), callTaintFn: () => wire({}) }) });
  const t = text(out);
  assert.ok(t.startsWith(OUT), t);
  assert.ok(t.includes("[mandu:secret] listing: the last lines of this output are the names in mail/inbox, bank as ls printed them"), t);
  assert.ok(!t.includes("/abs/not/in/command"), "only operands the model's own command holds");
  for (const bad of [
    { text: OUT, spans: LOG_OFFER.spans, listing },
    { text: OUT, spans: [], listing: { operands: [], part: "last" } },
    { text: OUT, spans: [], listing: { operands: ["bank"], part: "middle" } },
    { text: OUT, spans: [], listing: { operands: ["a\nb"], part: "last" } },
    { text: OUT, spans: [], listing: null },
  ]) {
    const r = await rewriteRequest(call("Bash", cmd, OUT), { arbiter: new MockArbiter({ classifyFn: () => offered(bad), callTaintFn: () => wire({}) }) });
    assert.match(text(r), SYM_RE, `masked whole: ${JSON.stringify(bad)}`);
  }
});
