/**
 * release — a typed placeholder is put back only into a page whose origin
 * the egress decision allows, inserted by the isolated-world function with
 * the value as an argument; every other outcome refuses and types nothing
 * (devtools-relay.md §3.2; secrets axes, explicit). A placeholder the
 * arbiter does not know is refused too, and the agent told to type it as
 * the page shows it, and so is a lookalike (the placeholder's shape with a
 * code no placeholder has), without asking the arbiter.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { checkTyped, frameOrigin, insertCause, insertRefusal, release, releaseText, unknownMessage, INSERT_FUNCTION, RELEASE_WORLD, UNKNOWN_PLACEHOLDER, LEAVE_IT_OUT, type PageTarget } from "../../src/release.js";
import { MockArbiter } from "../mock-arbiter.js";
import { findLookalikes, findSymbols, wholeLookalike, LOOKALIKE_MAX_CODE } from "../../src/symbols.js";

stateAxes("secrets");

const KEY = "sk_" + "live_51HxQz8Yv3kT9mN2pL4rB6wE";
const SYM = "$MDU:nomodel_STRIPE_KEY[7f3a]";

/** A target whose page is at `url` and whose insert answers `insert`. */
function target(url: string, insert = "ok"): PageTarget & { sent: Array<{ method: string; params: Record<string, unknown> }> } {
  const sent: Array<{ method: string; params: Record<string, unknown> }> = [];
  return {
    sent,
    async send(method, params) {
      sent.push({ method, params });
      if (method === "Page.getFrameTree") return { frameTree: { frame: { id: "F1", url, securityOrigin: url.startsWith("http") ? new URL(url).origin : "://" } } };
      if (method === "Page.createIsolatedWorld") return { executionContextId: 5 };
      if (method === "Runtime.callFunctionOn") return { result: { type: "string", value: insert } };
      return {};
    },
  };
}

test("releaseText: only an input command whose text holds a placeholder", () => {
  assert.equal(releaseText("Input.insertText", { text: `key ${SYM}` }), `key ${SYM}`);
  assert.equal(releaseText("Input.insertText", { text: "plain" }), null);
  assert.equal(releaseText("Input.dispatchKeyEvent", { type: "keyDown", text: SYM }), SYM);
  assert.equal(releaseText("Input.dispatchKeyEvent", { type: "keyUp", text: SYM }), null);
  assert.equal(releaseText("Runtime.evaluate", { expression: SYM }), null, "elsewhere the literal goes as written");
});

test("frameOrigin: the browser's origin of the main frame, http(s) only", () => {
  assert.deepEqual(frameOrigin({ frameTree: { frame: { id: "F1", url: "https://dashboard.stripe.com/apikeys", securityOrigin: "https://dashboard.stripe.com" } } }),
    { frameId: "F1", origin: "https://dashboard.stripe.com", host: "dashboard.stripe.com", scheme: "https" });
  assert.equal(typeof frameOrigin({ frameTree: { frame: { id: "F1", url: "about:blank", securityOrigin: "" } } }), "string");
  assert.equal(typeof frameOrigin({ frameTree: { frame: { id: "F1", url: "data:text/html,x", securityOrigin: "null" } } }), "string");
  assert.equal(typeof frameOrigin({}), "string");
});

test("a bound origin: the value goes in as an argument of the isolated-world insert, never in its source", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const t = target("https://vercel.com/settings/env");
  const out = await release(`STRIPE=${SYM}`, { arbiter: a, target: t, session: "s1" });
  assert.deepEqual(out, { kind: "done", origin: "https://vercel.com" });
  assert.deepEqual(a.decisions[0], { symbol: SYM, boundary: "network", destination: "vercel.com", asCommand: false, scheme: "https", positions: ["body"], sessionKey: "s1" });
  assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree", "Page.createIsolatedWorld", "Runtime.callFunctionOn"]);
  assert.equal(t.sent[1]!.params["worldName"], RELEASE_WORLD);
  const call = t.sent[2]!.params;
  assert.equal(call["functionDeclaration"], INSERT_FUNCTION);
  assert.ok(!INSERT_FUNCTION.includes(KEY));
  assert.deepEqual(call["arguments"], [{ value: "https://vercel.com" }, { value: `STRIPE=${KEY}` }]);
});

test("an unbound origin, an ask, a Send-without-it or a down gate refuse before anything is typed", async () => {
  for (const [name, setup] of [
    ["unbound", (_a: MockArbiter) => {}],
    ["ask", (a: MockArbiter) => a.asks.add(SYM)],
    ["strip", (a: MockArbiter) => a.strips.add(SYM)],
    ["gate down", (a: MockArbiter) => { a.gateDown = true; }],
  ] as const) {
    const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["stripe.com"] }]);
    setup(a);
    const t = target("https://evil.example/form");
    const out = await release(SYM, { arbiter: a, target: t });
    assert.equal(out.kind, "refuse", name);
    assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree"], `${name}: no insert`);
    assert.deepEqual(a.resolved, [], `${name}: never resolved`);
    assert.ok(!JSON.stringify(out).includes(KEY), `${name}: the refusal carries no value`);
  }
});

test("an ask tells the agent the site may not have it: leave it out and go on, ask the person only if they asked for it there", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: [] }]);
  a.asks.add(SYM);
  const out = await release(SYM, { arbiter: a, target: target("https://vercel.com/") });
  assert.equal(out.kind, "refuse");
  assert.equal(
    out.kind === "refuse" ? out.message : "",
    `Mandu: the placeholder was not typed: vercel.com may not have ${SYM} without the person's approval in Mandu; ` +
      "leave it out (name it in plain words if the text needs it, never its placeholder) and go on; " +
      "ask the person only if they asked for it to go there, then type it again",
  );
  assert.equal(LEAVE_IT_OUT, "leave it out (name it in plain words if the text needs it, never its placeholder) and go on");
  assert.deepEqual(out.kind === "refuse" ? out.notice : undefined, { kind: "needs-approval", symbols: [SYM], page: "vercel.com" });
});

test("an unbound site tells the agent to leave it out and go on, the gate's reason kept", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const out = await release(SYM, { arbiter: a, target: target("https://evil.example/") });
  assert.equal(out.kind, "refuse");
  assert.match(out.kind === "refuse" ? out.message : "", /^Mandu: the placeholder was not typed: \$MDU:\S+ may not go to evil\.example \(.+\); leave it out \(name it in plain words if the text needs it, never its placeholder\) and go on$/);
  assert.equal(out.kind === "refuse" ? out.notice?.kind : undefined, "not-allowed");
});

test("a page with no origin is refused without asking the gate", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const out = await release(SYM, { arbiter: a, target: target("about:blank") });
  assert.equal(out.kind, "refuse");
  assert.equal(a.decisions.length, 0);
});

test("the page moving or the focus in a frame refuses after the check", async () => {
  for (const answer of ["origin", "focus", "none", "failed"]) {
    const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
    const out = await release(SYM, { arbiter: a, target: target("https://vercel.com/", answer) });
    assert.equal(out.kind, "refuse", answer);
    assert.notEqual(insertRefusal(answer), null);
  }
  assert.equal(insertRefusal("ok"), null);
});

test("the insert function checks the origin, then the focus, then inserts, in one turn", () => {
  // Run it against a stand-in page: the contract release.ts relies on.
  const run = (origin: string, active: unknown, ok = true) => {
    const inserted: string[] = [];
    const fn = new Function("location", "document", `return (${INSERT_FUNCTION});`);
    const doc = { activeElement: active, body: { tagName: "BODY" }, documentElement: {}, execCommand: (_c: string, _u: boolean, t: string) => { inserted.push(t); return ok; } };
    const answer = (fn({ origin: "https://vercel.com" }, doc) as (o: string, t: string) => string)(origin, "VALUE");
    return { answer, inserted };
  };
  assert.deepEqual(run("https://vercel.com", { tagName: "INPUT" }), { answer: "ok", inserted: ["VALUE"] });
  assert.deepEqual(run("https://evil.example", { tagName: "INPUT" }), { answer: "origin", inserted: [] });
  assert.deepEqual(run("https://vercel.com", { tagName: "IFRAME" }), { answer: "focus", inserted: [] });
  assert.deepEqual(run("https://vercel.com", null), { answer: "none", inserted: [] });
  const inner = { tagName: "INPUT" };
  assert.deepEqual(run("https://vercel.com", { tagName: "X-FIELD", shadowRoot: { activeElement: inner } }), { answer: "ok", inserted: ["VALUE"] });
});

// ── A placeholder that names nothing (devtools-relay.md §3.2) ──────────────

/** The near-miss the live demos' model typed: one hash digit changed. */
const MADE_UP = "$MDU:nomodel_STRIPE_KEY[7f3b]";

test("an unknown placeholder is refused, nothing typed, and the agent is told to type it as the page shows it, with the nearest shown", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const t = target("https://vercel.com/settings/env");
  const asked: string[] = [];
  const out = await release(`STRIPE=${MADE_UP}`, { arbiter: a, target: t, hints: (s) => { asked.push(s); return [SYM]; } });
  assert.equal(out.kind, "refuse");
  if (out.kind !== "refuse") return;
  assert.equal(out.reason, UNKNOWN_PLACEHOLDER, "the trace says unknown placeholder, never released");
  assert.deepEqual(out.unknown, [MADE_UP]);
  assert.match(out.message, /no such placeholder \$MDU:nomodel_STRIPE_KEY\[7f3b\]/);
  assert.match(out.message, /type the placeholder exactly as the page shows it/);
  assert.ok(out.message.includes(`the pages showed ${SYM}`), out.message);
  assert.deepEqual(asked, [MADE_UP], "the hints are asked for the unknown one");
  assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree"], "no isolated world, no insert: the literal never reaches the page");
  assert.ok(!out.message.includes(KEY), "names only");
});

test("an unknown placeholder beside a known, allowed one: the whole command is refused, the known value never inserted", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const t = target("https://vercel.com/settings/env");
  const out = await release(`${SYM} and ${MADE_UP}`, { arbiter: a, target: t });
  assert.equal(out.kind, "refuse");
  assert.deepEqual(out.kind === "refuse" ? out.unknown : null, [MADE_UP]);
  assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree"]);
  assert.ok(!JSON.stringify(out).includes(KEY));
  assert.doesNotMatch(out.kind === "refuse" ? out.message : "", /pages showed/, "no hints, no list");
});

test("an unknown placeholder on an unbound page is still told as unknown; a known one there is still refused for the site", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const unknown = await release(MADE_UP, { arbiter: a, target: target("https://evil.example/form") });
  assert.equal(unknown.kind === "refuse" ? unknown.reason : null, UNKNOWN_PLACEHOLDER);
  const known = await release(SYM, { arbiter: a, target: target("https://evil.example/form") });
  assert.equal(known.kind, "refuse");
  assert.match(known.kind === "refuse" ? known.message : "", /may not go to evil\.example/, "the origin refusal is unchanged");
  assert.equal(known.kind === "refuse" ? known.unknown : "x", undefined);
});

test("the arbiter failing to resolve refuses (fail-closed), not as unknown", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  a.resolveDown = true;
  const t = target("https://vercel.com/");
  for (const sym of [SYM, MADE_UP]) {
    const out = await release(sym, { arbiter: a, target: t });
    assert.equal(out.kind, "refuse", sym);
    assert.match(out.kind === "refuse" ? out.message : "", /could not be read/);
    assert.notEqual(out.kind === "refuse" ? out.reason : null, UNKNOWN_PLACEHOLDER);
  }
  assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree", "Page.getFrameTree"], "nothing inserted");
});

test("hints that throw change nothing but the list", async () => {
  const a = new MockArbiter([]);
  const out = await release(MADE_UP, { arbiter: a, target: target("https://vercel.com/"), hints: () => { throw new Error("x"); } });
  assert.equal(out.kind === "refuse" ? out.reason : null, UNKNOWN_PLACEHOLDER);
});

test("every refusal carries its notice for the model: the kind, the cause, the page's host, names only (§3.4)", async () => {
  const notice = async (setup: (a: MockArbiter) => void, url = "https://evil.example/form", insert = "ok", text = SYM) => {
    const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["stripe.com", "vercel.com"] }]);
    setup(a);
    const out = await release(text, { arbiter: a, target: target(url, insert), hints: () => [SYM] });
    assert.equal(out.kind, "refuse");
    assert.ok(!JSON.stringify(out).includes(KEY), "no value");
    return (out as { notice: unknown }).notice;
  };
  assert.deepEqual(await notice(() => {}), { kind: "not-allowed", page: "evil.example", symbols: [SYM] });
  assert.deepEqual(await notice((a) => a.asks.add(SYM)), { kind: "needs-approval", page: "evil.example", symbols: [SYM] });
  assert.deepEqual(await notice((a) => a.strips.add(SYM)), { kind: "declined", page: "evil.example", symbols: [SYM] });
  assert.deepEqual(await notice((a) => { a.gateDown = true; }), { kind: "failed", cause: "unavailable", page: "evil.example", symbols: [SYM] });
  assert.deepEqual(await notice((a) => { a.resolveDown = true; }, "https://vercel.com/x"), { kind: "failed", cause: "unavailable", page: "vercel.com", symbols: [SYM] });
  assert.deepEqual(await notice(() => {}, "about:blank"), { kind: "failed", cause: "no-page", symbols: [SYM] });
  assert.deepEqual(await notice(() => {}, "https://vercel.com/x", "none"), { kind: "failed", cause: "no-field", page: "vercel.com", symbols: [SYM] });
  assert.deepEqual(await notice(() => {}, "https://vercel.com/x", "origin"), { kind: "failed", cause: "page-moved", page: "vercel.com", symbols: [SYM] });
  const made = "$MDU:nomodel_STRIPE_KEY[7f3b]";
  assert.deepEqual(await notice(() => {}, "https://vercel.com/x", "ok", `${made} ${SYM}`), { kind: "unknown", page: "vercel.com", symbols: [made], shown: [SYM] });
  assert.deepEqual(insertCause("focus"), { message: "the focus is in a frame of another page", cause: "frame" });
  assert.equal(insertCause("ok"), null);
});

test("unknownMessage: one or several, with or without the shown ones", () => {
  assert.equal(unknownMessage([MADE_UP], []), `Mandu: nothing was typed: no such placeholder ${MADE_UP}: type the placeholder exactly as the page shows it, every character`);
  assert.match(unknownMessage([MADE_UP, "$MDU:x[0000]"], [SYM, "$MDU:y[1111]"]), /no such placeholders .*, \$MDU:x\[0000\]: .* \(the pages showed \$MDU:nomodel_STRIPE_KEY\[7f3a\], \$MDU:y\[1111\]\)$/);
});

// ── A lookalike: the placeholder's shape, a code no placeholder has (§3.2) ──

/** What the live expense-report demo's model typed into the card field. */
const UUID_LOOKALIKE = "$MDU:nomodel_Read[e213b2c2-8419-4809-b684-297d264f3319].number";
/** The wallet page's real placeholder. */
const WALLET = "$MDU:nomodel_Read[5958].extract_1";

test("findLookalikes: the placeholder's shape with a code no placeholder has; never a placeholder, never prose", () => {
  for (const look of [
    UUID_LOOKALIKE,
    "$MDU:nomodel_Read[5958-ab]",
    "$MDU:nomodel_Read[7F3A]",
    "$MDU:nomodel_Read[0123456789]",
    "$MDU:nomodel_Read[012]",
    "$MDU:kind[hash]",
    `$MDU:k[${"z".repeat(LOOKALIKE_MAX_CODE)}]`,
  ]) {
    assert.deepEqual(findLookalikes(`pay with ${look} now`), [look], look);
    assert.ok(wholeLookalike(look), look);
    assert.deepEqual(findSymbols(look), [], `${look} is no placeholder`);
  }
  for (const no of [
    SYM, WALLET, `${SYM}.sub`, "$MDU docs", "$MDU:", "$MDU:foo", "$MDU:foo[", "$MDU:k[]", "$MDU:k[ab cd]", "$MDU:1x[abcd]",
    `$MDU:k[${"z".repeat(LOOKALIKE_MAX_CODE + 1)}]`, "plain",
  ]) {
    assert.deepEqual(findLookalikes(no), [], no);
    assert.equal(wholeLookalike(no), false, no);
  }
  assert.deepEqual(findLookalikes(`${UUID_LOOKALIKE} and ${UUID_LOOKALIKE}`), [UUID_LOOKALIKE], "each once");
});

test("releaseText: an input command carrying a lookalike is taken, prose with $MDU is not", () => {
  assert.equal(releaseText("Input.insertText", { text: UUID_LOOKALIKE }), UUID_LOOKALIKE);
  assert.equal(releaseText("Input.dispatchKeyEvent", { type: "char", text: `card ${UUID_LOOKALIKE}` }), `card ${UUID_LOOKALIKE}`);
  for (const text of ["$MDU docs", "$MDU:", "$MDU:foo", "see $MDU:k[ab cd]"]) assert.equal(releaseText("Input.insertText", { text }), null, text);
  assert.equal(releaseText("Runtime.evaluate", { expression: UUID_LOOKALIKE }), null, "elsewhere the literal goes as written");
});

test("a lookalike inserted whole is refused as an unknown placeholder without asking the arbiter: nothing typed, the nearest shown named", async () => {
  for (const look of [UUID_LOOKALIKE, "$MDU:nomodel_Read[5958-ab].extract_1", "$MDU:nomodel_Read[5958A].extract_1", "$MDU:nomodel_Read[595812345].extract_1", "$MDU:nomodel_Read[zz].extract_1"]) {
    const a = new MockArbiter([{ value: KEY, symbol: WALLET, bindings: ["ledgerly.localhost"] }]);
    const t = target("https://ledgerly.localhost/expenses/new");
    const asked: string[] = [];
    const out = await release(`card: ${look}`, { arbiter: a, target: t, hints: (s) => { asked.push(s); return [WALLET]; } });
    assert.equal(out.kind, "refuse", look);
    if (out.kind !== "refuse") continue;
    assert.equal(out.reason, UNKNOWN_PLACEHOLDER, "the trace says unknown placeholder, never released");
    assert.deepEqual(out.unknown, [look]);
    assert.equal(out.message, unknownMessage([look], [WALLET]));
    assert.deepEqual(asked, [look], "the hints are asked for the lookalike");
    assert.deepEqual(a.decisions, [], "no egress decision: a lookalike names nothing");
    assert.deepEqual(a.resolved, [], "no lookup");
    assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree"], "no isolated world, no insert");
    assert.deepEqual(out.notice, { kind: "malformed", symbols: [], page: "ledgerly.localhost", shown: [WALLET] }, "the notice never quotes the lookalike");
    assert.ok(!JSON.stringify(out).includes(KEY), "names only");
  }
});

test("a lookalike beside a known, allowed placeholder: the whole command refused, the known one never asked for nor inserted", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: WALLET, bindings: ["ledgerly.localhost"] }]);
  const t = target("https://ledgerly.localhost/x");
  const out = await release(`${WALLET} ${UUID_LOOKALIKE}`, { arbiter: a, target: t });
  assert.equal(out.kind, "refuse");
  assert.deepEqual(out.kind === "refuse" ? out.unknown : null, [UUID_LOOKALIKE]);
  assert.deepEqual(a.resolved, []);
  assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree"]);
  assert.ok(!JSON.stringify(out).includes(KEY));
});

test("a lookalike on a page Chrome cannot name, or with hints that throw, is still refused as unknown; the notice just names no page", async () => {
  const a = new MockArbiter([]);
  const down: PageTarget = { async send() { throw new Error("gone"); } };
  for (const t of [down, target("about:blank")]) {
    const out = await release(UUID_LOOKALIKE, { arbiter: a, target: t, hints: () => { throw new Error("x"); } });
    assert.equal(out.kind === "refuse" ? out.reason : null, UNKNOWN_PLACEHOLDER);
    assert.deepEqual(out.kind === "refuse" ? out.notice : null, { kind: "malformed", symbols: [] });
  }
});

test("ordinary text with $MDU that is not placeholder-shaped is not the release's: a well-formed placeholder is judged as before", async () => {
  const a = new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["vercel.com"] }]);
  const out = await release(`$MDU docs, $MDU:foo and ${SYM}`, { arbiter: a, target: target("https://vercel.com/") });
  assert.equal(out.kind, "done", "the placeholder released, the prose around it as typed");
  assert.deepEqual(a.decisions.map((d) => d.symbol), [SYM]);
});

test("checkTyped (a key run's placeholder, on the key that closes its code, §3.3): a base the arbiter knows goes on with nothing asked of the gate or the page; one it does not know is refused as unknown with the nearest shown; no answer refuses (fail-closed)", async () => {
  const field = "$MDU:nomodel_Read[5958].CARD_NUMBER";
  const a = new MockArbiter([{ value: KEY, symbol: field, bindings: ["ledgerly.localhost"] }]);
  const t = target("https://ledgerly.localhost/expenses/new");
  // Known through its field row (no row of its own): goes on.
  assert.equal(await checkTyped("$MDU:nomodel_Read[5958]", { arbiter: a, target: t, hints: () => [field] }), null);
  assert.equal(t.sent.length, 0, "a known base asks Chrome nothing");
  assert.deepEqual([a.decisions.length, a.resolved.length], [0, 0], "nor the gate, nor a value");
  assert.deepEqual(a.looked, ["$MDU:nomodel_Read[5958]"]);

  // A hex code no row has (the live demo's made-up `$MDU:web_fetch[8c4f]`).
  const made = "$MDU:web_fetch[8c4f]";
  const out = await checkTyped(made, { arbiter: a, target: t, session: "s1", hints: () => [field] });
  assert.equal(out?.kind, "refuse");
  if (out?.kind !== "refuse") return;
  assert.equal(out.reason, UNKNOWN_PLACEHOLDER);
  assert.deepEqual(out.unknown, [made]);
  assert.equal(out.message, unknownMessage([made], [field]), "the same words as a placeholder that names nothing");
  assert.deepEqual(out.notice, { kind: "unknown", symbols: [made], page: "ledgerly.localhost", shown: [field] });
  assert.deepEqual(t.sent.map((s) => s.method), ["Page.getFrameTree"], "Chrome asked only to name the page");
  assert.deepEqual([a.decisions.length, a.resolved.length], [0, 0]);
  assert.ok(!JSON.stringify(out).includes(KEY), "names only");

  // The arbiter cannot answer: refused, a failure (not unknown), the page still named.
  a.lookupDown = true;
  const down = await checkTyped("$MDU:nomodel_Read[5958]", { arbiter: a, target: t });
  assert.equal(down?.kind, "refuse");
  if (down?.kind !== "refuse") return;
  assert.match(down.message, /^Mandu: the placeholder was not typed: it could not be looked up/);
  assert.deepEqual(down.notice, { kind: "failed", cause: "unavailable", symbols: ["$MDU:nomodel_Read[5958]"], page: "ledgerly.localhost" });
  assert.equal(down.unknown, undefined, "not told as unknown");

  // A page Chrome cannot name: still refused, the notice names no page.
  a.lookupDown = false;
  const gone: PageTarget = { async send() { throw new Error("gone"); } };
  const nameless = await checkTyped(made, { arbiter: a, target: gone, hints: () => { throw new Error("x"); } });
  assert.deepEqual(nameless?.kind === "refuse" ? nameless.notice : null, { kind: "unknown", symbols: [made] });
});
