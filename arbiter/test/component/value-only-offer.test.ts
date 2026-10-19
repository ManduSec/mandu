/**
 * value-only-offer.test.ts — the classify op's value-only offer over a real
 * ArbiterServer (docs/design/confidentiality/backstop-value-only.md §2, A1
 * and A6): offered for an old log holding a registered key; not offered
 * with the axis off, for a path-derived result, for a quarantine tool, for
 * a result carrying another registered value's encoded copy (the residue
 * scan reads every row, not only the ones that hit), or a long line of a
 * labelled document (a piece outside every replaced value).
 *
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { INSPECT_TOOL_SPELLINGS } from "../../policy/inspect-tool.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// Made-up values (no real credential).
const KEY = "sk_test_OfferUnit7Qm2Xv9Lk4Tz8Wp3";
const OTHER = "tok_OfferOther0123456789abcdefXYZ";
const DOC_LINE = "The acquisition of Northwind closes in March; keep it quiet.";
const LOG = `[08:00:01] check (DEBUG=1)\nDEBUG: Authorization: Bearer ${KEY}\n[08:00:02] ok: HTTP 200\n`;

async function stack(confidentiality = true, pieceLimits?: { scanChars: number; pieces: number }): Promise<{ c: ArbiterClient; done: () => Promise<void>; ws: string }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-value-only-offer-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "shop-app"), { recursive: true });
  mkdirSync(join(ws, "other"), { recursive: true });
  mkdirSync(join(ws, "memo"), { recursive: true });
  writeFileSync(join(ws, "shop-app", ".env"), `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`);
  writeFileSync(join(ws, "other", ".env"), `OTHER_TOKEN=${OTHER}\n`);
  writeFileSync(join(ws, "memo", "plan.md"), `# Plan\n\n${DOC_LINE}\nNothing else.\n`);
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality, integrity: false, ...(pieceLimits ? { pieceLimits } : {}),
    policyDocument: { version: 1, paths: [
      { path: join(ws, "shop-app", ".env"), level: "no-model", bindings: ["api.stripe.com"] },
      { path: join(ws, "other", ".env"), level: "no-model" },
      { path: join(ws, "memo", "plan.md"), level: "no-model" },
    ] } as never,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  if (confidentiality) {
    for (const p of [join(ws, "shop-app", ".env"), join(ws, "other", ".env"), join(ws, "memo", "plan.md")]) {
      const r = await c.registerSecret({ path: p, home: dir, sessionKey: "vo" });
      assert.ok(r.symbol, `${p}: ${r.reason}`);
    }
  }
  return { c, ws, done: async () => { c.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

type Verdict = { confidentiality?: string; raisedBy?: string; valueOnly?: { text: string; spans: Array<{ start: number; end: number; symbol: string }> } };
const classify = (c: ArbiterClient, value: string, origin = "cat logs/payments.log", tool = "Bash"): Promise<Verdict> =>
  c.classify({ tool, value, boundary: "model_context", origin, params: { command: origin }, sessionKey: "vo", callId: `call_${Math.random().toString(16).slice(2)}` }) as Promise<Verdict>;

test("offered: the log with the key as its own symbol, the level still the raise", async () => {
  const k = await stack();
  try {
    const v = await classify(k.c, LOG);
    assert.equal(v.confidentiality, "no-model");
    assert.equal(v.raisedBy, "value-backstop");
    assert.ok(v.valueOnly, JSON.stringify(v));
    const at = LOG.indexOf(KEY);
    assert.deepEqual(v.valueOnly!.spans.map((s) => [s.start, s.end]), [[at, at + KEY.length]]);
    assert.match(v.valueOnly!.spans[0]!.symbol, /^\$MDU:nomodel_/);
    assert.equal(v.valueOnly!.text, LOG.replace(KEY, v.valueOnly!.spans[0]!.symbol));
  } finally { await k.done(); }
});

test("not offered (A1): a path-derived result, a quarantine tool", async () => {
  const k = await stack();
  try {
    const path = await classify(k.c, `STRIPE_SECRET_KEY=${KEY}\n`, `cat ${join(k.ws, "shop-app", ".env")}`);
    assert.equal(path.raisedBy, undefined);
    assert.equal(path.valueOnly, undefined);
    const q = await classify(k.c, LOG, "inspect", INSPECT_TOOL_SPELLINGS[0]!);
    assert.equal(q.valueOnly, undefined);
  } finally { await k.done(); }
});

test("not offered (A1): the confidentiality axis off", async () => {
  const k = await stack(false);
  try {
    const v = await classify(k.c, LOG);
    assert.equal(v.valueOnly, undefined);
    assert.equal(v.raisedBy, undefined);
  } finally { await k.done(); }
});

test("not offered (A6b): another registered value's encoded copy beside the hit, though that value never hits", async () => {
  const k = await stack();
  try {
    for (const extra of [Buffer.from(OTHER).toString("base64"), [...OTHER].reverse().join(""), OTHER.slice(4, 16)]) {
      const v = await classify(k.c, `${LOG}${extra}\n`);
      assert.equal(v.raisedBy, "value-backstop");
      assert.equal(v.valueOnly, undefined, extra);
    }
  } finally { await k.done(); }
});

test("not offered (A4): a long line of a labelled document beside the key", async () => {
  const k = await stack();
  try {
    const v = await classify(k.c, `${LOG}${DOC_LINE}\n`);
    assert.equal(v.raisedBy, "value-backstop");
    assert.equal(v.valueOnly, undefined);
  } finally { await k.done(); }
});

test("not offered: a registered row whose pieces were cut at the bound (plan 10 §11.18)", async () => {
  // a bound of 1 piece: the rows's pieces are cut, so a piece past the
  // bound is matched by nothing and nothing can be proved
  const k = await stack(true, { scanChars: 16 * 1024 * 1024, pieces: 1 });
  try {
    const v = await classify(k.c, LOG);
    assert.equal(v.raisedBy, "value-backstop");
    assert.equal(v.valueOnly, undefined);
  } finally { await k.done(); }
});

test("still offered (review round 4): an earlier masked one-line command output sharing a word with the log refuses nothing", async () => {
  const k = await stack();
  try {
    await k.c.symbolize({ tool: "Bash", value: "payments: connected to Stripe (test mode)", confidentiality: "no-model", callId: "call_earlier", sessionKey: "vo" });
    const v = await classify(k.c, `${LOG}payments: retried at 09:00\n`);
    assert.equal(v.raisedBy, "value-backstop");
    assert.ok(v.valueOnly, "an ordinary row's words are no fragment of a secret");
  } finally { await k.done(); }
});

test("not offered (A1): a tool whose result is no file read or command output (a subagent's answer, an MCP tool)", async () => {
  const k = await stack();
  try {
    for (const tool of ["subagent", "Task", "mcp__notes__search", "WebFetch", "BashOutput"]) {
      const v = await classify(k.c, LOG, "x", tool);
      assert.equal(v.valueOnly, undefined, tool);
    }
    assert.ok((await classify(k.c, LOG, "cat logs/payments.log", "Read")).valueOnly, "a Read gets it");
  } finally { await k.done(); }
});
