/**
 * egress-hold.test — a held request (confidentiality.md §4, "A held
 * request", 2026-10-17), over the pure `gateRequest` with a hold and an
 * in-memory MockArbiter. Mandu-new.
 *
 * A request whose only obstacle is an unanswered per-symbol card waits for
 * the human's answer, and the answer decides THAT request: Send without it
 * forwards it with the marker in the symbol's place (every encoding the
 * strip handles), Allow once resolves, Block refuses. Fail-closed: the
 * deadline, the arbiter gone mid-hold and the client gone all refuse, and a
 * block that does not wait on a card (a denial, a program holding a secret,
 * an arbiter miss) is never held. An answer the request already got is not
 * asked for again while it waits (a once is spent once), and the queue read
 * paces the re-asks.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  gateRequest, awaitsAnswer, egressHoldMs, heldForEvent, EGRESS_HOLD_MAX_MS, EGRESS_HELD_TIMEOUT,
  SEND_WITHOUT_MARKER, type EgressHold, type GateInput, type GateResult,
} from "../../src/egress.js";
import { MockArbiter, type DesymbolizationDecision, type DesymbolizationRequest } from "../../src/arbiter-client.js";

const SYM = "$MDU:nomodel_Read[ab12cd34]";
const OTHER = "$MDU:nomodel_Read[0bee5]";
const SECRET = "db-password-hunter2-hold";
const TOKEN = "ghp_realTokenValue123hold";

const PENDING = (id = "egr-1"): DesymbolizationDecision => ({ allow: false, requiresApproval: true, reason: "secret unbound", ruleRef: { source: "rule", id: "egress:secret-unbound" }, approvalId: id });
const STRIP: DesymbolizationDecision = { allow: false, requiresApproval: false, strip: true, reason: "the user chose Send without it", ruleRef: { source: "verdict", id: "verdict:egr-1" } };
const DENIED: DesymbolizationDecision = { allow: false, requiresApproval: false, reason: "human-denied", ruleRef: { source: "verdict", id: "verdict:egr-1" } };
const ALLOWED: DesymbolizationDecision = { allow: true, reason: "human-approved", ruleRef: { source: "verdict", id: "verdict:egr-1" } };

/** A fake clock the hold's sleeps advance; `onSleep` runs after each one
 *  (the human answering while the request waits). */
function clock(onSleep?: (n: number) => void): Pick<EgressHold, "sleep" | "now"> & { sleeps: number } {
  let t = 1_000_000;
  const c = {
    sleeps: 0,
    now: () => t,
    sleep: async (ms: number) => { t += ms; c.sleeps++; onSleep?.(c.sleeps); },
  };
  return c;
}

/** A mock whose answer for SYM is `answer()` (read live), recording resolves. */
function arbiter(answer: (req: DesymbolizationRequest) => DesymbolizationDecision, extra: ConstructorParameters<typeof MockArbiter>[0] = {}): { a: MockArbiter; resolved: string[] } {
  const a = new MockArbiter({ values: { [SYM]: SECRET, [OTHER]: TOKEN }, decisionFn: answer, ...extra });
  const resolved: string[] = [];
  const inner = a.resolve.bind(a);
  a.resolve = async (s: string) => { resolved.push(s); return inner(s); };
  return { a, resolved };
}

function input(a: MockArbiter, over: Partial<GateInput> = {}): GateInput {
  const body = JSON.stringify({ title: "inventory-api does not start", body: `could not connect to postgres://inventory:${SYM}@db:5432/inventory` });
  return {
    method: "POST", destinationHost: "tracker.example", url: "https://tracker.example/api/issues",
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }, bodyText: body, arbiter: a, ...over,
  };
}

/** No trace of the secret anywhere in the result; forwarded, no symbol left. */
function clean(r: GateResult): void {
  assert.ok(!JSON.stringify(r).includes(SECRET), "never the raw value");
  if (r.action === "forward") assert.ok(!JSON.stringify(r.rewritten).includes("$MDU:"), "never the symbol");
}

test("the setting: whole ms, capped; absent, empty, zero, negative or not a number is no hold", () => {
  assert.equal(egressHoldMs(undefined), 0);
  assert.equal(egressHoldMs(""), 0);
  assert.equal(egressHoldMs("0"), 0);
  assert.equal(egressHoldMs("-5"), 0);
  assert.equal(egressHoldMs("soon"), 0);
  assert.equal(egressHoldMs("Infinity"), 0);
  assert.equal(egressHoldMs("60000"), 60_000);
  assert.equal(egressHoldMs("1500.7"), 1500);
  assert.equal(egressHoldMs("99999999"), EGRESS_HOLD_MAX_MS);
});

test("awaitsAnswer: only a block whose every withheld symbol is a placeholder with a waiting card", () => {
  const pending = { symbol: SYM, requiresApproval: true, reason: "x", approvalId: "egr-1" };
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [pending] }), true);
  assert.equal(awaitsAnswer({ action: "forward" }), false);
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [] }), false);
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [{ ...pending, requiresApproval: false }] }), false, "a denial is final");
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [{ symbol: SYM, requiresApproval: true, reason: "arbiter unreachable" }] }), false, "no row: an arbiter miss");
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [{ ...pending, symbol: "<secret-taint:1-2→tracker.example>" }] }), false, "a program holding a secret");
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [{ ...pending, symbol: `host-${SYM}` }] }), false, "not a whole placeholder");
  assert.equal(awaitsAnswer({ action: "block", reason: "x", withheld: [pending, { ...pending, symbol: OTHER, requiresApproval: false }] }), false, "one final denial ends it");
});

test("held, then Send without it: THIS request goes with the marker, the symbol never resolved", async () => {
  let answered = false;
  const { a, resolved } = arbiter(() => (answered ? STRIP : PENDING()));
  const c = clock((n) => { if (n === 3) answered = true; });
  const r = await gateRequest(input(a), { ms: 60_000, pollMs: 500, ...c });
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  clean(r);
  assert.deepEqual(r.sentWithout, [SYM]);
  assert.deepEqual(resolved, [], "a symbol sent without is never resolved");
  const parsed = JSON.parse(r.rewritten!.bodyText) as { body: string };
  assert.equal(parsed.body, `could not connect to postgres://inventory:${SEND_WITHOUT_MARKER}@db:5432/inventory`);
  assert.equal(r.rewritten!.headers["content-length"], String(Buffer.byteLength(r.rewritten!.bodyText)));
  assert.equal(r.sentWithoutView!.bodyText, r.rewritten!.bodyText, "the proxy's strict scan reads the request as sent");
  assert.deepEqual(r.held, { ms: 1500, answered: true, cards: [{ approvalId: "egr-1", rule: "egress:secret-unbound" }] });
});

test("held, then Send without it: the URL, a form body, a header and a Basic pair each lose the symbol", async () => {
  let answered = false;
  const { a } = arbiter(() => (answered ? STRIP : PENDING()));
  const basic = `Basic ${Buffer.from(`inventory:${SYM}`, "latin1").toString("base64")}`;
  const r = await gateRequest(input(a, {
    url: `https://tracker.example/api/issues?pw=${SYM}`,
    headers: { "content-type": "application/x-www-form-urlencoded", "x-note": `pw ${SYM}`, authorization: basic },
    bodyText: `title=crash&body=pw%3D${SYM}`,
  }), { ms: 60_000, ...clock(() => { answered = true; }) });
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  clean(r);
  assert.equal(new URL(r.rewritten!.url).searchParams.get("pw"), SEND_WITHOUT_MARKER);
  assert.equal(new URLSearchParams(r.rewritten!.bodyText).get("body"), `pw=${SEND_WITHOUT_MARKER}`);
  assert.equal(r.rewritten!.headers["x-note"], `pw ${SEND_WITHOUT_MARKER}`);
  const pair = Buffer.from(String(r.rewritten!.headers.authorization).replace(/^Basic /, ""), "base64").toString("latin1");
  assert.equal(pair, `inventory:${SEND_WITHOUT_MARKER}`);
});

test("held, then Allow once: the value is put back, as for the request sent again today", async () => {
  let answered = false;
  const { a, resolved } = arbiter(() => (answered ? ALLOWED : PENDING()));
  const r = await gateRequest(input(a), { ms: 60_000, ...clock(() => { answered = true; }) });
  assert.equal(r.action, "forward");
  assert.deepEqual(resolved, [SYM]);
  assert.ok(r.action === "forward" && r.rewritten!.bodyText.includes(SECRET));
});

test("held, then Block: refused at once, the value never resolved", async () => {
  let answered = false;
  const { a, resolved } = arbiter(() => (answered ? DENIED : PENDING()));
  const c = clock(() => { answered = true; });
  const r = await gateRequest(input(a), { ms: 60_000, ...c });
  assert.equal(r.action, "block");
  clean(r);
  assert.deepEqual(resolved, []);
  assert.equal(c.sleeps, 1, "a denial ends the hold");
  assert.deepEqual(r.held, { ms: 500, answered: true, cards: [{ approvalId: "egr-1", rule: "egress:secret-unbound" }] });
});

test("held, then Block: the block names the human's verdict, and the trace keeps the card it waited on and the rule that filed it", async () => {
  // demo-c1 on the defaults (2026-10-19): the held upload refused by the
  // human's Block carried only `verdict:egr-1`; which rule asked the human
  // (an unbound host, not a bound host's one-time approval) was lost.
  let answered = false;
  const { a } = arbiter(() => (answered ? DENIED : PENDING()));
  const r = await gateRequest(input(a), { ms: 60_000, ...clock(() => { answered = true; }) });
  assert.equal(r.action, "block");
  if (r.action !== "block") return;
  assert.equal(r.withheld[0]!.ruleRef?.id, "verdict:egr-1", "the decision is the human's");
  assert.deepEqual(heldForEvent(r.held), [{ approvalId: "egr-1", rule: "egress:secret-unbound" }]);
  assert.ok(!JSON.stringify(heldForEvent(r.held)).includes(SECRET), "ids and rule ids only");
  // two placeholders, two cards, one entry each; a request never held has none
  const two = new MockArbiter({ values: { [SYM]: SECRET, [OTHER]: TOKEN }, decisionFn: (req) => (answered ? DENIED : PENDING(req.symbol === SYM ? "egr-1" : "egr-2")) });
  answered = false;
  const r2 = await gateRequest(input(two, { bodyText: `${SYM} ${OTHER} ${SYM}` }), { ms: 60_000, ...clock(() => { answered = true; }) });
  assert.deepEqual(heldForEvent(r2.held), [{ approvalId: "egr-1", rule: "egress:secret-unbound" }, { approvalId: "egr-2", rule: "egress:secret-unbound" }]);
  assert.equal(heldForEvent(undefined), undefined);
  assert.equal(heldForEvent({ ms: 0, answered: true, cards: [] }), undefined);
});

test("nobody answers: refused at the deadline, the card left waiting, the reason says so", async () => {
  const { a, resolved } = arbiter(() => PENDING());
  const c = clock();
  const r = await gateRequest(input(a), { ms: 3_000, pollMs: 500, ...c });
  assert.equal(r.action, "block");
  if (r.action !== "block") return;
  clean(r);
  assert.deepEqual(resolved, []);
  assert.match(r.reason, new RegExp(EGRESS_HELD_TIMEOUT));
  assert.match(r.reason, /nobody answered/);
  assert.equal(r.withheld[0]!.approvalId, "egr-1", "the card's id rides on the block (the event joins it)");
  assert.deepEqual(r.held, { ms: 3_000, answered: false, cards: [{ approvalId: "egr-1", rule: "egress:secret-unbound" }] });
  assert.ok(a.decisionCalls.length <= 7, `bounded asks (${a.decisionCalls.length})`);
});

test("the arbiter gone mid-hold: refused (fail-closed), nothing resolved", async () => {
  let gone = false;
  const { a, resolved } = arbiter(() => { if (gone) throw new Error("socket closed"); return PENDING(); });
  const r = await gateRequest(input(a), { ms: 60_000, ...clock(() => { gone = true; }) });
  assert.equal(r.action, "block");
  if (r.action !== "block") return;
  clean(r);
  assert.match(r.reason, /arbiter unreachable/);
  assert.deepEqual(resolved, []);
});

test("the client gone mid-hold: refused, nothing sent, even after the answer", async () => {
  let answered = false;
  let gone = false;
  const { a } = arbiter(() => (answered ? STRIP : PENDING()));
  const r = await gateRequest(input(a), { ms: 60_000, aborted: () => gone, ...clock(() => { answered = true; gone = true; }) });
  assert.equal(r.action, "block");
  clean(r);
  assert.match(r.action === "block" ? r.reason : "", /client went away/);
});

test("no hold (absent or 0): the pending card refuses at once, as before", async () => {
  for (const hold of [undefined, { ms: 0 }]) {
    const { a } = arbiter(() => PENDING());
    const c = clock();
    const r = await gateRequest(input(a), hold ? { ...hold, ...c } : undefined);
    assert.equal(r.action, "block");
    assert.equal(c.sleeps, 0);
    assert.equal(a.decisionCalls.length, 1);
    assert.equal(r.held, undefined);
  }
});

test("never held: a denial, an arbiter miss, a program holding a secret", async () => {
  const c = clock();
  const denied = arbiter(() => DENIED);
  assert.equal((await gateRequest(input(denied.a), { ms: 60_000, ...c })).action, "block");
  const miss = new MockArbiter({ failDecision: true });
  assert.equal((await gateRequest(input(miss), { ms: 60_000, ...c })).action, "block");
  const holder = new MockArbiter({
    values: { [SYM]: SECRET },
    decisionFn: () => PENDING(),
    secretTaint: { "10-20": { tainted: true, level: "no-model", files: ["/w/.env"], bindings: [] } },
  });
  const r = await gateRequest(input(holder, { holders: [{ procKey: "10-20", ancestors: [] }] }), { ms: 60_000, ...c });
  assert.equal(r.action, "block");
  assert.equal(c.sleeps, 0, "none of them waited");
});

test("two placeholders: an answer already got is kept while the other waits (a once is spent once)", async () => {
  let answered = false;
  const { a, resolved } = arbiter((req) => (req.symbol === OTHER ? ALLOWED : answered ? STRIP : PENDING()));
  const r = await gateRequest(input(a, { headers: { authorization: `token ${OTHER}` } }), { ms: 60_000, ...clock((n) => { if (n === 2) answered = true; }) });
  assert.equal(r.action, "forward");
  if (r.action !== "forward") return;
  assert.equal(a.decisionCalls.filter((d) => d.symbol === OTHER).length, 1, "the allowed one was asked once");
  assert.deepEqual(resolved, [OTHER]);
  assert.equal(r.rewritten!.headers.authorization, `token ${TOKEN}`);
  assert.ok(!r.rewritten!.bodyText.includes(SECRET) && r.rewritten!.bodyText.includes(SEND_WITHOUT_MARKER));
  assert.equal(r.sentWithoutView!.headers.authorization, `token ${OTHER}`, "the scanned view releases nothing");
});

test("the queue read paces the re-asks: asked again only once the card is answered", async () => {
  let answered = false;
  const { a } = arbiter(() => (answered ? STRIP : PENDING()), { awaitingFn: (ids) => new Set(answered ? [] : ids) });
  const r = await gateRequest(input(a), { ms: 60_000, ...clock((n) => { if (n === 6) answered = true; }) });
  assert.equal(r.action, "forward");
  assert.equal(a.decisionCalls.length, 2, "the first ask and the one after the answer");
  assert.equal(a.awaitingCalls.length, 6);
});

// egress-hold.md "One card per file" (2026-10-19): the arbiter files a
// registered file's placeholders under ONE card and spends a once by the
// request, so every ask of one request carries one id, held re-asks
// included, and another request carries another.
test("one request id on every ask of a request, its held re-asks included; another request, another id; one card's id listed once", async () => {
  let answered = false;
  // both placeholders under one card (the file's), as the arbiter files them
  const { a } = arbiter(() => (answered ? ALLOWED : PENDING("egr-7")), { awaitingFn: (ids) => new Set(answered ? [] : ids) });
  const logged: string[] = [];
  const r = await gateRequest(input(a, { headers: { authorization: `token ${OTHER}` } }), { ms: 60_000, log: (m) => logged.push(m), ...clock((n) => { if (n === 2) answered = true; }) });
  assert.equal(r.action, "forward");
  const ids = new Set(a.decisionCalls.map((d) => d.requestId));
  assert.equal(ids.size, 1, `one id for the request: ${[...ids].join(", ")}`);
  const [id] = [...ids];
  assert.ok(typeof id === "string" && id.length >= 16, "an unguessable id");
  assert.equal(a.decisionCalls.length, 4, "two placeholders asked, then asked again after the answer");
  for (const d of a.decisionCalls) assert.deepEqual([...(d.requestSymbols ?? [])].sort(), [SYM, OTHER].sort(), "every ask names every placeholder of the request");
  assert.deepEqual(a.awaitingCalls.map((c) => c.length), [1, 1], "the one card is read as one id");
  assert.ok(logged[0]!.includes("(egr-7;"), `the card named once: ${logged[0]}`);

  const again = arbiter(() => ALLOWED);
  await gateRequest(input(again.a));
  await gateRequest(input(again.a));
  const two = again.a.decisionCalls.map((d) => d.requestId);
  assert.equal(two.length, 2);
  assert.notEqual(two[0], two[1], "each request its own id");
});

test("a failed queue read just asks (the decision is always the ask's)", async () => {
  let answered = false;
  const { a } = arbiter(() => (answered ? STRIP : PENDING()), { awaitingFn: () => { throw new Error("listing failed"); } });
  const r = await gateRequest(input(a), { ms: 60_000, ...clock((n) => { if (n === 2) answered = true; }) });
  assert.equal(r.action, "forward");
  clean(r);
  assert.equal(a.decisionCalls.length, 3);
});
