/**
 * reply-row-reservation (proxy e2e, 2026-09-30) — the REAL AnthropicProxy over
 * HTTP, a fake upstream and the mock arbiter (docs/design/ui/reply-row-reservation.md
 * §3.4, §3.5, §6 "Proxy e2e").
 *
 * The round trip:
 *   turn 1   the agent sends a multi-line `.ssh/config` tool result (`secrets`
 *            shape: integrity off, the result labelled `no-model`); the
 *            provider receives only its symbol T and answers with T alone on a
 *            line; the agent receives an N-row reserve block and NEVER an
 *            original (the proxy does not desymbolize; it learns only N);
 *   turn 2   the agent re-sends its history with the block; the provider
 *            receives T byte-exact in the assistant turn, and no marker and no
 *            `/1:N` anywhere.
 * Plus: a mangled block and a marker in a tool result are stripped (with a
 * `reserve_residual` event), and there is NO expansion with the relay unset or
 * in pipe mode, with an arbiter predating the ops or down, past the
 * symbolShape deadline, with the kill switch, or on the non-streaming path.
 *
 * v2 (§11.3-§11.5), with a relay that reports `wrap: true` and its `cols`:
 * a token inside a sentence reaches the agent as a `T/1:N:W:F` block with the
 * prose around it, a one-line value wider than the terminal reserves its
 * wrapped rows, and turn 2 still reaches the provider byte-exact.
 *
 * The arbiter here is the MOCK at the proxy's `Arbiter` interface; which
 * socket each op rides (both reservation ops on the HUMAN plane, §5.3,
 * §11.5) is the adapter's job, pinned by test/unit/arbiter-client-adapter.test.ts
 * and, over a real ArbiterServer, by the integration parity test
 * (CONTRIBUTING.md, the arbiter-client pattern).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";

import { AnthropicProxy, type ProxyOptions, type UpstreamFetcher } from "../../src/proxy.js";
import type { GateSurface } from "../../src/gate-surface.js";
import type { SessionRelayState } from "../../src/arbiter-client.js";
import { layoutRows } from "../../src/reserve-layout.js";
import { MockArbiter, type MockArbiterOptions } from "../helpers/mock-arbiter.js";
import { sseEvent } from "../helpers/mock-upstream.js";

type Json = Record<string, unknown>;

const SSH_CONFIG = "Host bastion\n  HostName 10.9.8.7\n  User RESERVECANARYUSER\n  IdentityFile ~/.ssh/RESERVECANARYKEY\n";
const VALUE_LINES = SSH_CONFIG.replace(/\n$/, "").split("\n");
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/;
const MARKER_RE = /\$MDU\/[0-9a-f]{4,8}\/\d+|\/1:\d/;
const SESSION = "scope-rr-1";

const SURFACE: GateSurface = {
  spec: "claude-code",
  exec: { Bash: "command" },
  execOutput: { Bash: "command" },
  net: {},
  paths: { Read: { fields: ["file_path"], mode: "read" } },
  dispatch: {},
  refuse: {},
  refuseArgs: {},
  stdin: {},
};

const PTY: SessionRelayState = { mode: "pty", reserve: true, cols: 80, rows: 24, updatedAt: 1 };

/** `secrets` as the arbiter answers it: integrity off (all TRUSTED), the ssh
 *  config read carries its level. The line count comes from the value the
 *  mock minted, exactly as the arbiter's symbolShape would compute it. */
function arbiter(o: { relay?: SessionRelayState | null | "absent"; shapes?: "absent"; extra?: MockArbiterOptions } = {}): MockArbiter {
  let m: MockArbiter;
  const relay = o.relay === undefined ? PTY : o.relay;
  m = new MockArbiter({
    gateSurfaceFn: () => SURFACE,
    classifyFn: (req) => JSON.stringify(req).includes(".ssh")
      ? { trust: "TRUSTED", category: null, reason: "mock: ssh config", confidentiality: "no-model" }
      : { trust: "TRUSTED", category: null, reason: "mock: integrity off" },
    ...(o.shapes === "absent" ? {} : {
      symbolShapeFn: (token: string, layout?: { width: number; first: number; indent?: number }) => {
        const v = m.valueOf.get(token);
        if (v === undefined) return null;
        const lines = v.replace(/\n$/, "").split("\n").length;
        // As the arbiter computes it (§11.5): rows only when a width is asked.
        return layout ? { lines, rows: layoutRows(v, layout.width, layout.first, "ink", layout.indent).length } : { lines };
      },
    }),
    ...(relay === "absent" ? {} : { sessionRelayFn: () => relay }),
    ...(o.extra ?? {}),
  });
  return m;
}

function send(port: number, path: string, body: Json): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": "ev-1" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

function payloads(sse: string): Json[] {
  return sse.split("\n\n").flatMap((e) => {
    const line = e.split("\n").find((l) => l.startsWith("data: "));
    return line ? [JSON.parse(line.slice(6)) as Json] : [];
  });
}
function texts(sse: string): string[] {
  return payloads(sse).flatMap((p) => {
    const d = p["delta"] as Json | undefined;
    return p["type"] === "content_block_delta" && d?.["type"] === "text_delta" ? [d["text"] as string] : [];
  });
}

function textSse(pieces: string[]): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })
    + pieces.map((p) => sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: p } })).join("")
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

const TURN1: Json = {
  model: "claude-opus-4", stream: true, max_tokens: 1024,
  messages: [
    { role: "user", content: "show me my ssh config" },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_cfg", name: "Read", input: { file_path: "/home/u/.ssh/config" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cfg", content: SSH_CONFIG }] },
  ],
};

/** A proxy whose fake model answers with the forwarded symbol alone on a
 *  line, streamed in `deltas` pieces. Records every upstream-bound body. */
async function harness(o: { arb?: MockArbiter; deltas?: number; json?: boolean; proxy?: Partial<ProxyOptions>; reply?: (token: string) => string } = {}) {
  const arb = o.arb ?? arbiter();
  const forwarded: string[] = [];
  const answer = { text: "", token: "" };
  const fetcher: UpstreamFetcher = async ({ body }) => {
    const sent = body.toString("utf8");
    forwarded.push(sent);
    const token = SYMBOL_RE.exec(sent)?.[0] ?? "$MDU:none[0000]";
    answer.token = token;
    answer.text = o.reply
      ? o.reply(token)
      : `Mandu locked it, so I only see a token. Here it is:\n\n${token}\n\nDone.`;
    if (o.json) {
      const msg = { id: "msg_1", type: "message", role: "assistant", content: [{ type: "text", text: answer.text }], stop_reason: "end_turn" };
      return { status: 200, headers: { "content-type": "application/json" }, body: Readable.from([Buffer.from(JSON.stringify(msg))]) };
    }
    const n = o.deltas ?? 5;
    const size = Math.ceil(answer.text.length / n);
    const pieces: string[] = [];
    for (let i = 0; i < answer.text.length; i += size) pieces.push(answer.text.slice(i, i + size));
    const sse = textSse(pieces);
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from((sse.match(/[\s\S]{1,11}/g) ?? []).map((p) => Buffer.from(p))) };
  };
  const proxy = new AnthropicProxy({ arbiter: arb, sessionKey: SESSION, log: () => {}, upstream: fetcher, ...(o.proxy ?? {}) });
  const port = await proxy.listen(0);
  return { arb, proxy, port, forwarded, answer };
}

/** No original value (whole, or any of its lines) in `bytes`. */
function assertNoOriginal(bytes: string, arb: MockArbiter, where: string): void {
  for (const v of arb.valueOf.values()) assert.ok(!bytes.includes(v), `${where}: a whole original leaked`);
  for (const l of VALUE_LINES) assert.ok(!bytes.includes(l.trim()), `${where}: an original line leaked: ${l}`);
  assert.ok(!bytes.includes("RESERVECANARY"), `${where}: the canary leaked`);
}

test("round trip: the agent gets the N-row block and no original; the next request collapses it to T byte-exact", async () => {
  const h = await harness();
  try {
    const r1 = await send(h.port, "/v1/messages", TURN1);
    assert.equal(r1.status, 200, r1.body);
    // Turn 1, upstream-bound: only the symbol.
    assertNoOriginal(h.forwarded[0]!, h.arb, "turn-1 request");
    const T = h.answer.token;
    assert.match(T, /^\$MDU:/);
    // Client-bound: the block, whole in one delta, and no original.
    assertNoOriginal(r1.body, h.arb, "client-bound stream");
    const n = VALUE_LINES.length;
    const block = [`${T}/1:${n}`, ...Array.from({ length: n - 1 }, (_, i) => `$MDU/${/\[([0-9a-f]+)\]/.exec(T)![1]}/${i + 2}`)].join("\n");
    const got = texts(r1.body);
    const agentText = got.join("");
    assert.equal(agentText, h.answer.text.replace(T, block));
    assert.ok(got.some((t) => t.includes(block)), `one delta holds the whole block: ${JSON.stringify(got)}`);
    assert.deepEqual(h.arb.sessionRelayCalls, [SESSION], "the relay is read under MANDU_SESSION_KEY");
    assert.deepEqual(h.arb.symbolShapeCalls, [T]);
    await h.proxy.close();
    // The sniffer recorded the MODEL's text, not the block; a reserve_expand event names T and N.
    const tllm = h.arb.eventsOfKind("tllm_call");
    assert.equal(tllm.length, 1);
    assert.ok(tllm[0]!.output!.symbolized.includes(h.answer.text), tllm[0]!.output!.symbolized);
    assert.doesNotMatch(tllm[0]!.output!.symbolized, MARKER_RE);
    const ex = h.arb.eventsOfKind("reserve_expand") as unknown as Array<Json>;
    assert.equal(ex.length, 1);
    assert.equal(ex[0]!["rows"], n);
    assertNoOriginal(JSON.stringify(h.arb.emittedEvents.filter((e) => e.kind.startsWith("reserve_"))), h.arb, "reserve events");

    // Turn 2: the agent re-sends history holding the block.
    const h2 = await harness({ arb: h.arb });
    try {
      const turn2 = {
        ...TURN1,
        messages: [
          ...(TURN1["messages"] as Json[]),
          { role: "assistant", content: [{ type: "text", text: agentText }] },
          { role: "user", content: "thanks" },
        ],
      };
      const r2 = await send(h2.port, "/v1/messages", turn2);
      assert.equal(r2.status, 200, r2.body);
      const up = h2.forwarded[0]!;
      assert.doesNotMatch(up, MARKER_RE, "no marker and no /1:N reaches the model");
      assertNoOriginal(up, h.arb, "turn-2 request");
      const sentMsgs = (JSON.parse(up) as { messages: Array<{ role: string; content: unknown }> }).messages;
      const asst = sentMsgs.filter((m) => m.role === "assistant").at(-1)!;
      assert.deepEqual(asst.content, [{ type: "text", text: h.answer.text }], "the model's own text, byte for byte");
      assert.equal(h.arb.eventsOfKind("reserve_residual").length, 0, "an exact collapse is not a residual");
    } finally {
      await h2.proxy.close();
    }
  } finally {
    await h.proxy.close();
  }
});

test("a mangled block and a marker in a tool result are stripped; reserve_residual is emitted", async () => {
  const h = await harness();
  try {
    const T = "$MDU:nomodel_Read[464e]";
    const body = {
      model: "claude-opus-4", stream: true, max_tokens: 64,
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: [{ type: "text", text: `x\n${T}/1:4\n$MDU/464e/2\n$MDU/464e/4` }] },
        { role: "user", content: [{ type: "tool_use_placeholder", note: "ignored" }, { type: "text", text: "read my transcript" }] },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_t", name: "Bash", input: { command: "cat t.jsonl" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_t", content: `{"text":"$MDU/464e/2"}\n$MDU/464e/3\n` }] },
      ],
    };
    const r = await send(h.port, "/v1/messages", body);
    assert.equal(r.status, 200, r.body);
    const up = h.forwarded[0]!;
    assert.doesNotMatch(up, MARKER_RE);
    const msgs = (JSON.parse(up) as { messages: Array<{ content: Array<Json> }> }).messages;
    assert.equal(msgs[1]!.content[0]!["text"], `x\n${T}`);
    await h.proxy.close();
    const ev = h.arb.eventsOfKind("reserve_residual") as unknown as Array<Json>;
    assert.equal(ev.length, 1);
    assert.equal(ev[0]!["removed"], 5);
    assert.deepEqual(ev[0]!["where"], ["messages[1].content[0]:assistant_text", "messages[4].content[0]:tool_result"]);
  } finally {
    await h.proxy.close();
  }
});

test("count_tokens gets the same collapse + strip", async () => {
  const h = await harness({ json: true });
  try {
    const T = "$MDU:nomodel_Read[464e]";
    const r = await send(h.port, "/v1/messages/count_tokens", {
      model: "claude-opus-4",
      messages: [{ role: "assistant", content: `${T}/1:2\n$MDU/464e/2` }, { role: "user", content: "$MDU/464e/9 hi" }],
    });
    assert.equal(r.status, 200, r.body);
    const sent = JSON.parse(h.forwarded[0]!) as { messages: Array<{ content: string }> };
    assert.equal(sent.messages[0]!.content, T);
    assert.equal(sent.messages[1]!.content, " hi");
    await h.proxy.close();
    assert.equal(h.arb.eventsOfKind("reserve_residual").length, 1);
  } finally {
    await h.proxy.close();
  }
});

for (const [name, opts] of [
  ["the relay is unset (null)", { arb: () => arbiter({ relay: null }) }],
  ["the relay is in pipe mode", { arb: () => arbiter({ relay: { ...PTY, mode: "pipe" } }) }],
  ["the filter cannot paint blocks (reserve:false)", { arb: () => arbiter({ relay: { ...PTY, reserve: false } }) }],
  ["the arbiter predates the ops", { arb: () => arbiter({ relay: "absent", shapes: "absent" }) }],
  ["symbolShape misses its deadline", { arb: () => arbiter({ extra: { symbolShapeDelayMs: 400 } }), proxy: { replyReserve: { timeoutMs: 40 } } }],
  ["the kill switch is set", { arb: () => arbiter(), proxy: { replyReserve: { enabled: false } } }],
  ["the response is not streamed", { arb: () => arbiter(), json: true }],
] as Array<[string, { arb: () => MockArbiter; proxy?: Partial<ProxyOptions>; json?: boolean }]>) {
  test(`no expansion when ${name}: the token passes byte-identical`, async () => {
    const h = await harness({ arb: opts.arb(), ...(opts.proxy ? { proxy: opts.proxy } : {}), ...(opts.json ? { json: true } : {}) });
    try {
      const r = await send(h.port, "/v1/messages", opts.json ? { ...TURN1, stream: false } : TURN1);
      assert.equal(r.status, 200, r.body);
      const agentText = opts.json
        ? ((JSON.parse(r.body) as { content: Array<{ text: string }> }).content[0]!.text)
        : texts(r.body).join("");
      assert.equal(agentText, h.answer.text);
      assert.doesNotMatch(r.body, MARKER_RE);
      assertNoOriginal(r.body, h.arb, "client-bound");
    } finally {
      await h.proxy.close();
    }
  });
}

test("the arbiter down (sessionRelay throws): no expansion, the reply still flows", async () => {
  const arb = arbiter();
  arb.sessionRelay = async () => { throw new Error("arbiter unreachable"); };
  const h = await harness({ arb });
  try {
    const r = await send(h.port, "/v1/messages", TURN1);
    assert.equal(r.status, 200);
    assert.equal(texts(r.body).join(""), h.answer.text);
  } finally {
    await h.proxy.close();
  }
});

// ── v2: wrapped rows and tokens inside a line (§11.3-§11.5) ─────────────────

const PTY_WRAP: SessionRelayState = { ...PTY, wrap: true };

/** Turn 2 over the same arbiter: the provider gets the model's own text. */
async function assertTurn2Exact(arb: MockArbiter, turn1: Json, agentText: string, modelText: string): Promise<void> {
  const h2 = await harness({ arb });
  try {
    const turn2 = {
      ...turn1,
      messages: [
        ...(turn1["messages"] as Json[]),
        { role: "assistant", content: [{ type: "text", text: agentText }] },
        { role: "user", content: "thanks" },
      ],
    };
    const r2 = await send(h2.port, "/v1/messages", turn2);
    assert.equal(r2.status, 200, r2.body);
    const up = h2.forwarded[0]!;
    assert.doesNotMatch(up, MARKER_RE, "no marker and no head suffix reaches the model");
    assertNoOriginal(up, arb, "turn-2 request");
    const sentMsgs = (JSON.parse(up) as { messages: Array<{ role: string; content: unknown }> }).messages;
    assert.deepEqual(sentMsgs.filter((m) => m.role === "assistant").at(-1)!.content, [{ type: "text", text: modelText }], "the model's own text, byte for byte");
    assert.equal(arb.eventsOfKind("reserve_residual").length, 0, "an exact collapse is not a residual");
  } finally {
    await h2.proxy.close();
  }
}

test("v2 round trip: a token inside a sentence reaches the agent as T/1:N:W:F with the prose around it; turn 2 is byte-exact", async () => {
  const arb = arbiter({ relay: PTY_WRAP });
  const h = await harness({ arb, reply: (t) => `The file is ${t} and that is all.` });
  try {
    const r1 = await send(h.port, "/v1/messages", TURN1);
    assert.equal(r1.status, 200, r1.body);
    assertNoOriginal(h.forwarded[0]!, arb, "turn-1 request");
    assertNoOriginal(r1.body, arb, "client-bound stream");
    const T = h.answer.token;
    const hash = /\[([0-9a-f]+)\]/.exec(T)![1];
    // W = 80 − 2; the prefix "The file is " is 12 columns → F = 66.
    const n = VALUE_LINES.length;
    const block = [`${T}/1:${n}:78:66`, ...Array.from({ length: n - 1 }, (_, i) => `$MDU/${hash}/${i + 2}`)].join("\n");
    const got = texts(r1.body);
    const agentText = got.join("");
    assert.equal(agentText, `The file is ${block} and that is all.`);
    assert.ok(got.some((t) => t.includes(block)), `one delta holds the whole block: ${JSON.stringify(got)}`);
    assert.deepEqual(arb.symbolShapeLayouts, [{ width: 78, first: 66, indent: 2 }],
      "the arbiter is asked for rows at (W, F), the content area at column 2 (§19: TAB stops)");
    await h.proxy.close();
    const ex = arb.eventsOfKind("reserve_expand") as unknown as Array<Json>;
    assert.equal(ex.length, 1);
    assert.deepEqual([ex[0]!["rows"], ex[0]!["W"], ex[0]!["F"], ex[0]!["head"]], [n, 78, 66, "v2"]);
    assertNoOriginal(JSON.stringify(ex), arb, "reserve events");
    const tllm = arb.eventsOfKind("tllm_call");
    assert.doesNotMatch(tllm[0]!.output!.symbolized, MARKER_RE, "the sniffer recorded the model's text");
    await assertTurn2Exact(arb, TURN1, agentText, h.answer.text);
  } finally {
    await h.proxy.close();
  }
});

test("v2: a one-line value wider than the terminal reserves its wrapped rows", async () => {
  const KEY = "sk-RESERVECANARYWRAP-" + "0123456789abcdef".repeat(10); // 181 columns, one line
  const turn: Json = {
    ...TURN1,
    messages: [
      { role: "user", content: "show me my api key" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_cfg", name: "Read", input: { file_path: "/home/u/.ssh/api_key" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cfg", content: KEY }] },
    ],
  };
  const arb = arbiter({ relay: PTY_WRAP });
  const h = await harness({ arb, deltas: 3 });
  try {
    const r1 = await send(h.port, "/v1/messages", turn);
    assert.equal(r1.status, 200, r1.body);
    assert.ok(!h.forwarded[0]!.includes(KEY), "the provider never gets the key");
    assert.ok(!r1.body.includes(KEY) && !r1.body.includes("RESERVECANARYWRAP"), "the agent never gets the key");
    const T = h.answer.token;
    const hash = /\[([0-9a-f]+)\]/.exec(T)![1];
    // Standalone: F = W = 78; 181 columns hard-break into 78 + 78 + 25.
    const block = `${T}/1:3:78:78\n$MDU/${hash}/2\n$MDU/${hash}/3`;
    const agentText = texts(r1.body).join("");
    assert.equal(agentText, h.answer.text.replace(T, block));
    await h.proxy.close();
    await assertTurn2Exact(arb, turn, agentText, h.answer.text);
  } finally {
    await h.proxy.close();
  }
});

test("v2 needs the relay's wrap: without it a mid-line token passes byte-identical (v1)", async () => {
  const h = await harness({ arb: arbiter({ relay: PTY }), reply: (t) => `The file is ${t} and that is all.` });
  try {
    const r = await send(h.port, "/v1/messages", TURN1);
    assert.equal(r.status, 200, r.body);
    assert.equal(texts(r.body).join(""), h.answer.text);
    assert.doesNotMatch(r.body, MARKER_RE);
    assert.deepEqual(h.arb.symbolShapeCalls, [], "v1 asks no shape for a token inside a line");
  } finally {
    await h.proxy.close();
  }
});
