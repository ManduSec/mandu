/**
 * send-without.test — the gate's half of "Send without it"
 * (confidentiality.md §4 "Send without it", 2026-10-17), over the pure `gateRequest` and an
 * in-memory MockArbiter. Mandu-new.
 *
 * A decision carrying `strip` (the human's one-shot answer, spent by the
 * net-proxy's ask) FORWARDS the request with `SEND_WITHOUT_MARKER` where the
 * symbol was: never the value (the symbol is never resolved), never the
 * `$MDU:` token. Pinned in every place a symbol sits: a JSON body (still
 * valid JSON), a form body and the URL's query string (percent-encoded, so
 * they decode to the marker), a header, a Basic credential's pair; the
 * agent's `Content-Length` is set to the new body's length. A symbol in the
 * destination host, or one still denied beside it, blocks the request.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { gateRequest, SEND_WITHOUT_MARKER, SEND_WITHOUT_MARKER_ENCODED, type GateInput } from "../../src/egress.js";
import { MockArbiter, type DesymbolizationDecision } from "../../src/arbiter-client.js";

const SYM = "$MDU:nomodel_Read[ab12cd34]";
const OK_SYM = "$MDU:nomodel_Read[0bee5]";
const SECRET = "db-password-hunter2";
const TOKEN = "ghp_realTokenValue123";

const STRIP: DesymbolizationDecision = { allow: false, requiresApproval: false, strip: true, reason: "the user chose Send without it", ruleRef: { source: "verdict", id: "verdict:egr-1" } };

/** A mock whose decision strips SYM and allows OK_SYM, recording resolves. */
function arbiter(): { a: MockArbiter; resolved: string[] } {
  const a = new MockArbiter({
    values: { [SYM]: SECRET, [OK_SYM]: TOKEN },
    decisionFn: (req) => (req.symbol === SYM ? STRIP : { allow: true, reason: "bound" }),
  });
  const resolved: string[] = [];
  const inner = a.resolve.bind(a);
  a.resolve = async (s: string) => { resolved.push(s); return inner(s); };
  return { a, resolved };
}

function input(a: MockArbiter, over: Partial<GateInput>): GateInput {
  return { method: "POST", destinationHost: "api.github.com", url: "http://api.github.com/repos/o/r/issues", headers: {}, bodyText: "", arbiter: a, ...over };
}

/** No trace of the secret anywhere in the result, and, when forwarded, no
 *  trace of the symbol in the request (a block's withheld list names it). */
function clean(r: Awaited<ReturnType<typeof gateRequest>>): void {
  assert.ok(!JSON.stringify(r).includes(SECRET), "never the raw value");
  if (r.action === "forward") assert.ok(!JSON.stringify(r.rewritten).includes(SYM), "never the symbol");
}

test("a JSON body: the marker in the symbol's place, still valid JSON, Content-Length set, the symbol never resolved", async () => {
  const { a, resolved } = arbiter();
  const body = JSON.stringify({ title: "crash", body: `error: connect failed password=${SYM} at db:5432` });
  const r = await gateRequest(input(a, { headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }, bodyText: body }));
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  clean(r);
  assert.deepEqual(r.sentWithout, [SYM]);
  assert.deepEqual(resolved, [], "a symbol sent without is never resolved");
  const parsed = JSON.parse(r.rewritten!.bodyText) as { body: string };
  assert.equal(parsed.body, `error: connect failed password=${SEND_WITHOUT_MARKER} at db:5432`);
  assert.equal(r.rewritten!.headers["content-length"], String(Buffer.byteLength(r.rewritten!.bodyText)));
  assert.equal(r.sentWithoutView!.bodyText, r.rewritten!.bodyText, "the scanned view is the request");
});

test("the URL's query string and a form body: percent-encoded, decoding to the marker", async () => {
  const { a } = arbiter();
  const r = await gateRequest(input(a, {
    url: `http://api.github.com/search?q=${SYM}&x=1`,
    headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
    bodyText: `title=crash&body=pw%3D${SYM}`,
  }));
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  clean(r);
  const u = new URL(r.rewritten!.url);
  assert.equal(u.searchParams.get("q"), SEND_WITHOUT_MARKER);
  assert.ok(r.rewritten!.url.includes(SEND_WITHOUT_MARKER_ENCODED));
  assert.doesNotMatch(r.rewritten!.url, /\s/, "a URL with no space: sendable");
  assert.equal(new URLSearchParams(r.rewritten!.bodyText).get("body"), `pw=${SEND_WITHOUT_MARKER}`);
});

test("a header and a Basic credential's pair: the plain marker (no quote, no colon, no line break)", async () => {
  const { a } = arbiter();
  const basic = `Basic ${Buffer.from(`user:${SYM}`, "latin1").toString("base64")}`;
  const r = await gateRequest(input(a, { headers: { "x-note": `pw ${SYM}`, authorization: basic } }));
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  clean(r);
  assert.equal(r.rewritten!.headers["x-note"], `pw ${SEND_WITHOUT_MARKER}`);
  const pair = Buffer.from(String(r.rewritten!.headers.authorization).replace(/^Basic /, ""), "base64").toString("latin1");
  assert.equal(pair, `user:${SEND_WITHOUT_MARKER}`);
  assert.doesNotMatch(SEND_WITHOUT_MARKER, /["\\:\r\n]/);
});

test("every occurrence goes: a startup log with the placeholder in a URL and in 24 conninfo lines (demo-c8's) keeps none of them", async () => {
  // the field placeholder a dotenv URL's password stands as, in a log the
  // agent attaches whole: the URL form and libpq's `password=<value> ` form
  const FIELD = `${SYM}.DATABASE_URL.password`;
  const strip = new MockArbiter({ values: { [FIELD]: SECRET }, decisionFn: () => STRIP });
  const resolved: string[] = [];
  const inner = strip.resolve.bind(strip);
  strip.resolve = async (s: string) => { resolved.push(s); return inner(s); };
  const lines = [`[config]   DATABASE_URL=postgres://inventory:${FIELD}@db.inventory.test:5432/inventory`];
  for (let n = 1; n <= 24; n++) lines.push(`[db] attempt ${n}/24: pg connect host=db.inventory.test port=5432 dbname=inventory user=inventory password=${FIELD} sslmode=prefer connect_timeout=5`);
  const body = JSON.stringify({ title: "inventory-api does not start", body: lines.join("\n") });
  const r = await gateRequest(input(strip, { headers: { "content-type": "application/json" }, bodyText: body }));
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  assert.ok(!r.rewritten!.bodyText.includes("$MDU:"), "no placeholder left");
  assert.ok(!r.rewritten!.bodyText.includes(SECRET));
  const got = (JSON.parse(r.rewritten!.bodyText) as { body: string }).body;
  assert.equal(got.split(SEND_WITHOUT_MARKER).length - 1, 25, "the marker in each of the 25 places");
  assert.match(got, /postgres:\/\/inventory:\[hidden by Mandu\]@db\.inventory\.test:5432/);
  assert.match(got, /password=\[hidden by Mandu\] sslmode=prefer/);
  assert.deepEqual(resolved, []);
});

test("beside an allowed symbol: that one is resolved as before, and the view the proxy scans keeps it a token", async () => {
  const { a, resolved } = arbiter();
  const r = await gateRequest(input(a, { headers: { authorization: `token ${OK_SYM}` }, bodyText: `pw=${SYM}` }));
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  clean(r);
  assert.deepEqual(resolved, [OK_SYM]);
  assert.equal(r.rewritten!.headers.authorization, `token ${TOKEN}`);
  assert.equal(r.sentWithoutView!.headers.authorization, `token ${OK_SYM}`, "the scanned view releases nothing");
  assert.equal(r.sentWithoutView!.bodyText, `pw=${SEND_WITHOUT_MARKER}`);
});

test("a strip with allow:true (a pre-check's shape) is still never resolved", async () => {
  const a = new MockArbiter({ values: { [SYM]: SECRET }, decisionFn: () => ({ allow: true, strip: true, reason: "pre-check" }) });
  const r = await gateRequest(input(a, { bodyText: `pw=${SYM}` }));
  assert.equal(r.action, "forward");
  clean(r);
});

test("blocked (fail-closed): a symbol still denied beside it; a symbol in the destination host", async () => {
  const deny = new MockArbiter({
    values: { [SYM]: SECRET, [OK_SYM]: TOKEN },
    decisionFn: (req) => (req.symbol === SYM ? STRIP : { allow: false, requiresApproval: true, reason: "unbound" }),
  });
  const both = await gateRequest(input(deny, { bodyText: `a=${SYM}&b=${OK_SYM}` }));
  assert.equal(both.action, "block");
  clean(both);

  // the host reads as the symbol with a field path: stripped by the same answer
  const hostArb = new MockArbiter({ values: { [SYM]: SECRET }, decisionFn: (req) => (req.symbol.startsWith(SYM) ? STRIP : { allow: true, reason: "x" }) });
  const host = await gateRequest(input(hostArb, { destinationHost: `${SYM}.example`, url: `http://${SYM}.example/`, bodyText: "" }));
  assert.equal(host.action, "block");
  clean(host);
});

test("arbiter unreachable: still a block, as before", async () => {
  const a = new MockArbiter({ values: { [SYM]: SECRET }, failDecision: true });
  const r = await gateRequest(input(a, { bodyText: `pw=${SYM}` }));
  assert.equal(r.action, "block");
  clean(r);
});
