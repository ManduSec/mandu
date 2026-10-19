/**
 * reply-row-reservation (Codex proxy e2e, 2026-09-30) — the REAL OpenAiProxy
 * over HTTP, a fake Responses upstream and the mock arbiter
 * (docs/design/ui/reply-row-reservation.md §3.4, §3.5, §11.7).
 *
 * The round trip:
 *   turn 1   Codex sends a multi-line `.ssh/config` tool output (`secrets`
 *            shape: integrity off, the output labelled `no-model`); the
 *            provider receives only its symbol T and answers with T alone on
 *            a line and T inside a sentence, the token split across deltas;
 *            Codex receives N-row reserve blocks (a v1-width standalone head
 *            and a mid-line `T/1:N:W:F` head) in the deltas AND in every
 *            snapshot (`output_text.done`, `content_part.done`,
 *            `output_item.done`, `response.completed`), and NEVER an original
 *            (the proxy does not desymbolize; it learns only N);
 *   turn 2   Codex re-sends its history with the blocks; the provider
 *            receives T byte-exact in the assistant's output_text, and no
 *            marker and no `/1:N` anywhere (a stray marker in a tool output
 *            is stripped, with a `reserve_residual` event).
 * And no expansion (the client-bound text is the model's) without the human
 * plane's ops, with the relay in pipe mode, with the kill switch, or without
 * a session key.
 *
 * The arbiter here is the MOCK at the proxy's `Arbiter` interface; that both
 * reservation ops ride the HUMAN plane is the adapter's job, pinned by
 * test/unit/arbiter-client-adapter.test.ts and, over a real ArbiterServer, by
 * the integration parity test (CONTRIBUTING.md, the arbiter-client pattern).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";

import { OpenAiProxy, type ProxyOptions, type UpstreamFetcher } from "../../src/proxy.js";
import type { SessionRelayState } from "../../src/arbiter-client.js";
import { layoutRows } from "../../src/reserve-layout.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

type Json = Record<string, unknown>;

const SSH_CONFIG = "Host bastion\n  HostName 10.9.8.7\n  User RESERVECANARYUSER\n  IdentityFile ~/.ssh/RESERVECANARYKEY\n";
const ENVELOPE = "Chunk ID: dc1ae0\nWall time: 0.0 seconds\nProcess exited with code 0\nOutput:\n";
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/;
const MARKER_RE = /\$MDU\/[0-9a-f]{4,8}\/\d+|\/1:\d/;
const SESSION = "scope-rr-codex";

const PTY: SessionRelayState = { mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true, updatedAt: 1 };

/** `secrets` as the arbiter answers it: integrity off (all TRUSTED), the ssh
 *  config read carries its level. The shape comes from the value the mock
 *  minted, as the arbiter's symbolShape computes it (§11.5). */
function arbiter(o: { relay?: SessionRelayState | null; humanPlane?: boolean } = {}): MockArbiter {
  const relay = o.relay === undefined ? PTY : o.relay;
  const human = o.humanPlane !== false;
  const m: MockArbiter = new MockArbiter({
    classifyFn: (req) => JSON.stringify(req).includes(".ssh")
      ? { trust: "TRUSTED", category: null, reason: "mock: ssh config", confidentiality: "no-model" }
      : { trust: "TRUSTED", category: null, reason: "mock: integrity off" },
    ...(human ? {
      symbolShapeFn: (token: string, layout?: { width: number; first: number; indent?: number }) => {
        const v = m.valueOf.get(token);
        if (v === undefined) return null;
        const lines = v.replace(/\n$/, "").split("\n").length;
        return layout ? { lines, rows: layoutRows(v, layout.width, layout.first, "ink", layout.indent).length } : { lines };
      },
      sessionRelayFn: () => relay,
    } : {}),
  });
  return m;
}

const ev = (type: string, seq: number, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: seq, ...data })}\n\n`;

/** The model's answer: T alone on a line, then T inside a sentence. */
const answer = (t: string): string => `Here is your config:\n\n${t}\n\nIn a sentence: the value is ${t} and that is all.`;

/** A Responses stream carrying `text` in deltas cut inside each token. */
function responsesSse(text: string): string {
  const ids = { item_id: "msg_1", output_index: 0, content_index: 0 };
  const msg = { type: "message", id: "msg_1", status: "completed", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] };
  const cuts = [0];
  for (let at = text.indexOf("$MDU:"); at >= 0; at = text.indexOf("$MDU:", at + 1)) cuts.push(at + 7);
  cuts.push(text.length);
  let seq = 0;
  let s = ev("response.created", seq++, { response: { id: "r1", output: [] } });
  s += ev("response.output_item.added", seq++, { output_index: 0, item: { ...msg, status: "in_progress", content: [] } });
  s += ev("response.content_part.added", seq++, { ...ids, part: { type: "output_text", text: "", annotations: [] } });
  for (let i = 0; i + 1 < cuts.length; i++) s += ev("response.output_text.delta", seq++, { ...ids, delta: text.slice(cuts[i], cuts[i + 1]) });
  s += ev("response.output_text.done", seq++, { ...ids, text });
  s += ev("response.content_part.done", seq++, { ...ids, part: { type: "output_text", text, annotations: [] } });
  s += ev("response.output_item.done", seq++, { output_index: 0, item: msg });
  s += ev("response.completed", seq++, { response: { id: "r1", status: "completed", output: [msg] } });
  return s;
}

/** A fake upstream that answers with the symbol it received in the tool
 *  output, and records every body. */
function upstream(): { fetcher: UpstreamFetcher; bodies: string[]; token: () => string } {
  const bodies: string[] = [];
  let token = "";
  const fetcher: UpstreamFetcher = async ({ body }) => {
    const text = body.toString("utf8");
    bodies.push(text);
    const m = SYMBOL_RE.exec(text);
    if (m && !token) token = m[0];
    const sse = responsesSse(answer(token || "no token"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  return { fetcher, bodies, token: () => token };
}

function send(port: number, body: Json): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json", "content-length": String(data.length) } },
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
const deltas = (sse: string): string[] => payloads(sse).filter((p) => p["type"] === "response.output_text.delta").map((p) => p["delta"] as string);
function snapshotTexts(sse: string): string[] {
  const out: string[] = [];
  for (const p of payloads(sse)) {
    if (p["type"] === "response.output_text.done") out.push(p["text"] as string);
    if (p["type"] === "response.content_part.done") out.push((p["part"] as Json)["text"] as string);
    if (p["type"] === "response.output_item.done") out.push((((p["item"] as Json)["content"] as Json[])[0]!)["text"] as string);
    if (p["type"] === "response.completed") out.push(((((p["response"] as Json)["output"] as Json[])[0]!["content"] as Json[])[0]!)["text"] as string);
  }
  return out;
}

const turn1 = (): Json => ({
  model: "gpt-5.5", stream: true, instructions: "You are Codex.",
  input: [
    { type: "message", role: "user", content: [{ type: "input_text", text: "show me my ssh config" }] },
    { type: "function_call", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: "cat ~/.ssh/config" }) },
    { type: "function_call_output", call_id: "c1", output: ENVELOPE + SSH_CONFIG },
  ],
});

async function withProxy<T>(a: MockArbiter, up: ReturnType<typeof upstream>, extra: Partial<ProxyOptions>, fn: (port: number) => Promise<T>): Promise<T> {
  const proxy = new OpenAiProxy({ arbiter: a, upstream: up.fetcher, log: () => {}, sessionKey: SESSION, ...extra });
  const port = await proxy.listen(0);
  try {
    return await fn(port);
  } finally {
    await proxy.close();
  }
}

test("round trip: Codex gets the blocks (deltas and every snapshot) and no original; the provider gets T back byte-exact and no marker", async () => {
  const a = arbiter();
  const up = upstream();
  await withProxy(a, up, {}, async (port) => {
    const r1 = await send(port, turn1());
    assert.equal(r1.status, 200);
    // The provider saw only the symbol.
    assert.doesNotMatch(up.bodies[0]!, /RESERVECANARY/);
    const T = up.token();
    assert.match(T, SYMBOL_RE);
    // Codex: the blocks, whole, in the deltas and every snapshot; no original.
    assert.doesNotMatch(r1.body, /RESERVECANARY/, "no original reaches Codex");
    const text = deltas(r1.body).join("");
    // N = the rows of the value the arbiter holds for T (the whole symbolized
    // output) at W = 78; every value line is narrower than a row.
    const value = a.valueOf.get(T)!;
    assert.ok(value.includes("RESERVECANARYKEY"));
    const n = value.replace(/\n$/, "").split("\n").length;
    const standalone = `${T}/1:${n}:78:78\n$MDU/${/\[([0-9a-f]+)\]/.exec(T)![1]}/2`;
    assert.ok(text.includes(standalone), `a v2 standalone head: ${JSON.stringify(text)}`);
    assert.match(text, /the value is \$MDU:[^\s]+\/1:\d+:78:\d+\n/, "a mid-line v2 head");
    assert.match(text, / and that is all\.$/, "the prose after the mid-line block stays on its row");
    assert.ok(deltas(r1.body).some((d) => d.includes(standalone)), "a block rides in one delta");
    const snaps = snapshotTexts(r1.body);
    assert.equal(snaps.length, 4);
    for (const s of snaps) assert.equal(s, text, "every snapshot carries the text the deltas carried");
    assert.deepEqual(payloads(r1.body).map((p) => p["sequence_number"]), [...Array(payloads(r1.body).length).keys()], "no event invented or dropped");
    // Observability: the expansions, and the tllm_call records the model's own text.
    const expands = a.eventsOfKind("reserve_expand");
    assert.equal(expands.length, 2);
    const tllm = a.eventsOfKind("tllm_call");
    assert.equal(tllm.length, 1);
    assert.equal(tllm[0]!.output!.symbolized, answer(T), "the tllm_call reads the model's answer, not the blocks");

    // Turn 2: Codex re-sends its history with the blocks, and a tool output
    // that read Codex's session file (a stray marker).
    const r2 = await send(port, {
      ...turn1(),
      input: [
        ...(turn1()["input"] as Json[]),
        { type: "message", role: "assistant", id: "msg_1", content: [{ type: "output_text", text, annotations: [] }] },
        { type: "function_call", call_id: "c2", name: "exec_command", arguments: JSON.stringify({ cmd: "tail ~/.codex/sessions/s.jsonl" }) },
        { type: "function_call_output", call_id: "c2", output: `${ENVELOPE}${text.split("\n").slice(0, 5).join("\n")}\n` },
        { type: "message", role: "user", content: [{ type: "input_text", text: "thanks" }] },
      ],
    });
    assert.equal(r2.status, 200);
    const sent = JSON.parse(up.bodies[1]!) as Json;
    const assistant = (sent["input"] as Json[]).find((i) => i["role"] === "assistant")!;
    assert.equal(((assistant["content"] as Json[])[0]!)["text"], answer(T), "the model's own text, byte-exact");
    assert.doesNotMatch(up.bodies[1]!, MARKER_RE, "no marker and no head suffix reaches the provider");
    assert.doesNotMatch(up.bodies[1]!, /RESERVECANARY/);
    const residual = a.eventsOfKind("reserve_residual");
    assert.equal(residual.length, 1);
    assert.ok((residual[0] as unknown as { where: string[] }).where.some((w) => w.includes("function_call_output")));
  });
});

test("no expansion without the human plane's ops, with a pipe relay, with a relay that does not reserve, with the kill switch, or without a session key", async () => {
  const cases: Array<{ label: string; a: MockArbiter; extra: Partial<ProxyOptions> }> = [
    { label: "no human plane", a: arbiter({ humanPlane: false }), extra: {} },
    { label: "relay unset", a: arbiter({ relay: null }), extra: {} },
    { label: "pipe", a: arbiter({ relay: { ...PTY, mode: "pipe" } }), extra: {} },
    { label: "reserve false", a: arbiter({ relay: { ...PTY, reserve: false } }), extra: {} },
    { label: "kill switch", a: arbiter(), extra: { replyReserve: { enabled: false } } },
    { label: "no session key", a: arbiter(), extra: { sessionKey: undefined } },
  ];
  for (const c of cases) {
    const up = upstream();
    await withProxy(c.a, up, c.extra, async (port) => {
      const r = await send(port, turn1());
      assert.equal(r.status, 200, c.label);
      assert.doesNotMatch(r.body, MARKER_RE, `${c.label}: no block`);
      assert.equal(deltas(r.body).join(""), answer(up.token()), `${c.label}: the model's text`);
      for (const s of snapshotTexts(r.body)) assert.equal(s, answer(up.token()), c.label);
      assert.equal(c.a.eventsOfKind("reserve_expand").length, 0, c.label);
    });
  }
});
