/**
 * text-repack (unit) — a `$MDU:` token split across streamed text deltas
 * reaches the agent WHOLE in one delta (src/text-repack.ts). The text is
 * byte-identical, no event is invented or dropped, and an untouched stream
 * relays byte-verbatim.
 *
 * ONE SUITE, TWO COPIES, like the module it tests: this file is copied
 * VERBATIM to interceptors/anthropic-proxy and interceptors/openai-proxy
 * (test/unit/text-repack.test.ts), so the same table of split-token cases
 * runs against each package's repacker in its own suite;
 * tests/stack/text-repack-parity.test.ts fails unless the
 * copies are byte-identical. Change the anthropic-proxy copy and copy it out.
 *
 * "Broken token": any delta that holds part of a token but not all of it.
 * `assertWhole` checks each token occurs in exactly one delta and the text
 * joins to the original, which together rule a broken token out.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ChatTextRepacker, ResponsesTextRepacker, danglingTokenStart, REPACK_HOLD_CAP } from "../../src/text-repack.js";

type Json = Record<string, unknown>;

const TOKEN = "$MDU:exec_command[695b].output";
const ESCAPED = "\\$MDU:web\\_fetch[8c1d]";
const SECRET_TOKEN = "$MDU:nomodel_Read[5e1a]";
const FIELD_TOKEN = "$MDU:inspect[695b].result.items[0].name";
/** Every token shape the table splits: plain, Markdown-escaped, a
 *  confidentiality-marked tag, a deep field path. */
const TOKENS = [TOKEN, ESCAPED, SECRET_TOKEN, FIELD_TOKEN];

/** The data payloads of a relayed stream, in order ([DONE] as a string). */
function payloads(sse: string): Array<Json | string> {
  const out: Array<Json | string> = [];
  for (const ev of sse.split(/\r?\n\r?\n/)) {
    const lines = ev.split(/\r?\n/).filter((l) => l.startsWith("data:"));
    if (lines.length === 0) continue;
    const d = lines.map((l) => l.slice(5).replace(/^ /, "")).join("\n");
    out.push(d === "[DONE]" ? d : (JSON.parse(d) as Json));
  }
  return out;
}
const respTexts = (sse: string): string[] =>
  payloads(sse).flatMap((p) => typeof p !== "string" && p["type"] === "response.output_text.delta" ? [p["delta"] as string] : []);
const chatTexts = (sse: string): string[] =>
  payloads(sse).flatMap((p) => typeof p === "string" ? [] : ((p["choices"] as Json[] | undefined) ?? [])
    .map((c) => (c["delta"] as Json | undefined)?.["content"]).filter((t): t is string => typeof t === "string"));

/** Feed a stream through a repacker in one chunk, or byte by byte. */
function run(r: ResponsesTextRepacker | ChatTextRepacker, sse: string, bytewise = false): string {
  let out = "";
  if (bytewise) for (const c of sse) out += r.feed(c);
  else out += r.feed(sse);
  return out + r.end();
}

/** The deltas join to `full`, and each token rides whole in exactly one. */
function assertWhole(texts: string[], full: string, tokens: string[], at: string): void {
  assert.equal(texts.join(""), full, `text preserved (${at})`);
  for (const tok of tokens) {
    const holders = texts.filter((t) => t.includes(tok));
    assert.equal(holders.length, 1, `${JSON.stringify(tok)} whole in one delta (${at}): ${JSON.stringify(texts)}`);
  }
}

/** Every way to cut `s` into `parts` non-empty pieces (parts ≤ 3). */
function cuts(s: string, parts: 2 | 3): string[][] {
  const out: string[][] = [];
  for (let i = 1; i < s.length; i++) {
    if (parts === 2) { out.push([s.slice(0, i), s.slice(i)]); continue; }
    for (let j = i + 1; j < s.length; j++) out.push([s.slice(0, i), s.slice(i, j), s.slice(j)]);
  }
  return out;
}

const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
let seq = 0;
const text = (delta: string, extra: Json = {}): string =>
  ev("response.output_text.delta", { sequence_number: seq++, item_id: "msg_1", output_index: 0, content_index: 0, delta, ...extra });
const textDone = (full: string): string =>
  ev("response.output_text.done", { sequence_number: seq++, item_id: "msg_1", output_index: 0, content_index: 0, text: full });
const respStream = (pieces: string[], full: string): string => {
  seq = 0;
  return ev("response.output_item.added", { sequence_number: seq++, output_index: 0, item: { type: "message", id: "msg_1", content: [] } })
    + pieces.map((p) => text(p)).join("") + textDone(full)
    + ev("response.completed", { sequence_number: seq++, response: { id: "r1", output: [] } });
};

const chunk = (delta: Json, finish: string | null = null, index = 0): string =>
  `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index, delta, finish_reason: finish }] })}\n\n`;
const DONE = "data: [DONE]\n\n";
const chatStream = (pieces: string[]): string =>
  chunk({ role: "assistant", content: "" }) + pieces.map((p) => chunk({ content: p })).join("") + chunk({}, "stop") + DONE;

// ── danglingTokenStart ────────────────────────────────────────────────────────

test("danglingTokenStart: every growing prefix, an extensible token and a lone escape dangle", () => {
  for (const s of ["x $", "x $M", "x $MD", "x $MDU", "x $MDU:", "x $MDU:exec", "x $MDU:exec_command[69", `x ${TOKEN}`, "x \\$MDU:web\\_fe", "x \\$MDU:web\\", "x \\"]) {
    assert.equal(danglingTokenStart(s), 2, `should dangle at 2: ${JSON.stringify(s)}`);
  }
  for (const s of ["plain prose", "total: $5.00", "$HOME is set", `${TOKEN} times.`, "x $MDX", "C:\\\\"]) {
    assert.equal(danglingTokenStart(s), s.length, `should not dangle: ${JSON.stringify(s)}`);
  }
  assert.equal(danglingTokenStart("$MDU:" + "a".repeat(REPACK_HOLD_CAP)), REPACK_HOLD_CAP + 5, "past the cap it is prose");
});

test("danglingTokenStart: every proper prefix of every token dangles at the token's start", () => {
  for (const tok of TOKENS) {
    for (let k = 1; k <= tok.length; k++) {
      const s = `Ran ${tok.slice(0, k)}`;
      assert.equal(danglingTokenStart(s), 4, `prefix ${JSON.stringify(tok.slice(0, k))}`);
    }
    assert.equal(danglingTokenStart(`Ran ${tok} twice`), `Ran ${tok} twice`.length, "a finished token does not dangle");
  }
});

// ── Responses ─────────────────────────────────────────────────────────────────

test("responses: a token split at EVERY boundary inside it reaches the agent whole; events and sequence numbers kept", () => {
  for (const tok of TOKENS) {
    const full = `Ran ${tok} twice.`;
    for (const [a, b] of cuts(full, 2)) {
      const sse = respStream([a!, b!], full);
      for (const bytewise of [false, true]) {
        const out = run(new ResponsesTextRepacker(), sse, bytewise);
        assertWhole(respTexts(out), full, [tok], `split after ${JSON.stringify(a)}${bytewise ? ", bytewise" : ""}`);
        assert.deepEqual(payloads(out).map((p) => (p as Json)["sequence_number"]), payloads(sse).map((p) => (p as Json)["sequence_number"]));
        assert.match(out, /^event: response\.output_item\.added\n/, "the `event:` line is kept");
      }
    }
  }
});

test("responses: every THREE-way cut and one delta per character still deliver each token whole", () => {
  for (const tok of TOKENS) {
    const full = `Ran ${tok} twice.`;
    for (const pieces of cuts(full, 3)) {
      assertWhole(respTexts(run(new ResponsesTextRepacker(), respStream(pieces, full))), full, [tok], `cut ${JSON.stringify(pieces)}`);
    }
    const sse = respStream([...full], full);
    const out = run(new ResponsesTextRepacker(), sse, true);
    assertWhole(respTexts(out), full, [tok], "one delta per character");
    assert.equal(payloads(out).length, payloads(sse).length, "no event invented or dropped");
  }
});

test("responses: two adjacent tokens split at every boundary are each whole", () => {
  const full = `A ${TOKEN}${SECRET_TOKEN} B`;
  for (const [a, b] of cuts(full, 2)) {
    assertWhole(respTexts(run(new ResponsesTextRepacker(), respStream([a!, b!], full))), full, [TOKEN, SECRET_TOKEN], `split after ${JSON.stringify(a)}`);
  }
});

test("responses: the named boundaries `$`, `$MDU`, `$MDU:` and mid-hash", () => {
  for (const head of ["$", "$MDU", "$MDU:", "$MDU:exec_command[69"]) {
    const out = run(new ResponsesTextRepacker(), text(`see ${head}`) + text(`${TOKEN.slice(head.length)} ok`) + textDone(`see ${TOKEN} ok`));
    assert.deepEqual(respTexts(out), ["see ", `${TOKEN} ok`], `split after ${JSON.stringify(head)}`);
  }
});

test("responses: a token over THREE deltas is rejoined", () => {
  const out = run(new ResponsesTextRepacker(), text("a $M") + text("DU:exec_command[6") + text("95b].output b") + textDone(`a ${TOKEN} b`));
  assert.deepEqual(respTexts(out), ["a ", "", `${TOKEN} b`]);
});

test("responses: nothing token-shaped at a cut relays byte-verbatim; prose `$` only moves", () => {
  const plain = text("total: $5") + text(".00 and $HOME is set") + textDone("total: $5.00 and $HOME is set");
  assert.equal(run(new ResponsesTextRepacker(), plain), plain);
  assert.deepEqual(respTexts(run(new ResponsesTextRepacker(), text("total: $") + text("5.00"))), ["total: ", "$5.00"]);
});

test("responses: a held prefix before `.done`, another part or a tool call goes out whole, in place", () => {
  const done = text("pay $MDU") + textDone("pay $MDU");
  assert.equal(run(new ResponsesTextRepacker(), done), done);
  const part = text("a $MDU") + text(":x[1a2b]", { content_index: 1 });
  assert.equal(run(new ResponsesTextRepacker(), part), part, "another content part is not a continuation");
  const item = text("a $MDU") + text(":x[1a2b]", { item_id: "msg_2", output_index: 1 });
  assert.equal(run(new ResponsesTextRepacker(), item), item, "another output item is not a continuation");
  const call = text("run $MDU:") + ev("response.output_item.added", { output_index: 1, item: { type: "function_call", id: "fc", call_id: "c", name: "shell", arguments: "" } });
  assert.equal(run(new ResponsesTextRepacker(), call), call);
});

test("responses: end() never swallows the held text; comments pass during a hold; logprobs are never re-cut", () => {
  const r = new ResponsesTextRepacker();
  assert.equal(r.feed(text("x $MDU:exe")), "", "the possible token start is held");
  assert.equal(r.feed(": keepalive\n\n"), ": keepalive\n\n");
  assert.deepEqual(respTexts(r.feed(text("c_command[695b].output")) + r.end()), ["x ", TOKEN]);
  const cut = new ResponsesTextRepacker();
  assert.deepEqual(respTexts(cut.feed(text("x $MDU")) + cut.end()), ["x $MDU"]);
  const partial = new ResponsesTextRepacker();
  const held = text("x $MDU");
  const torn = "event: response.output_text.delta\ndata: {\"ty";
  assert.equal(partial.feed(held + torn), "");
  assert.equal(partial.end(), held + torn, "the held event, then a torn trailing frame verbatim");
  const lp = text("a $MDU", { logprobs: [{ token: "a", logprob: 0 }] }) + text(":x[1a2b]");
  assert.equal(run(new ResponsesTextRepacker(), lp), lp);
});

test("responses: CRLF framing is read and a re-cut event keeps its other lines", () => {
  seq = 0;
  const crlf = (s: string): string => s.replace(/\n/g, "\r\n");
  const sse = crlf(`id: 7\n${text("see $MDU:exec_co")}`) + crlf(text("mmand[695b].output ok")) + crlf(textDone(`see ${TOKEN} ok`));
  const out = run(new ResponsesTextRepacker(), sse, true);
  assertWhole(respTexts(out), `see ${TOKEN} ok`, [TOKEN], "CRLF");
  assert.match(out, /^id: 7\nevent: response\.output_text\.delta\ndata: /, "the id: and event: lines ride with the re-cut event");
});

test("responses: a malformed event passes through and ends a hold whole", () => {
  const bad = "event: response.output_text.delta\ndata: {not json\n\n";
  const sse = text("a $MDU") + bad + text(":x[1a2b]");
  assert.equal(run(new ResponsesTextRepacker(), sse), sse);
});

// ── Chat Completions ─────────────────────────────────────────────────────────

test("chat: a token split at EVERY boundary inside it reaches the agent whole, envelope kept", () => {
  for (const tok of TOKENS) {
    const full = `Ran ${tok} twice.`;
    for (const [a, b] of cuts(full, 2)) {
      const sse = chatStream([a!, b!]);
      for (const bytewise of [false, true]) {
        const out = run(new ChatTextRepacker(), sse, bytewise);
        assertWhole(chatTexts(out), full, [tok], `split after ${JSON.stringify(a)}${bytewise ? ", bytewise" : ""}`);
        assert.equal(payloads(out).length, payloads(sse).length, "no event invented or dropped");
        for (const p of payloads(out)) if (typeof p !== "string") { assert.equal(p["id"], "c1"); assert.equal(p["model"], "m"); }
        assert.ok(out.endsWith(DONE));
      }
    }
  }
});

test("chat: every THREE-way cut and one delta per character still deliver each token whole", () => {
  for (const tok of TOKENS) {
    const full = `Ran ${tok} twice.`;
    for (const pieces of cuts(full, 3)) {
      assertWhole(chatTexts(run(new ChatTextRepacker(), chatStream(pieces))), full, [tok], `cut ${JSON.stringify(pieces)}`);
    }
    const sse = chatStream([...full]);
    const out = run(new ChatTextRepacker(), sse, true);
    assertWhole(chatTexts(out), full, [tok], "one delta per character");
    assert.equal(payloads(out).length, payloads(sse).length);
  }
});

test("chat: the named boundaries `$`, `$MDU`, `$MDU:` and mid-hash", () => {
  for (const head of ["$", "$MDU", "$MDU:", "$MDU:exec_command[69"]) {
    const out = run(new ChatTextRepacker(), chunk({ content: `see ${head}` }) + chunk({ content: `${TOKEN.slice(head.length)} ok` }) + chunk({}, "stop") + DONE);
    assert.deepEqual(chatTexts(out), ["see ", `${TOKEN} ok`], `split after ${JSON.stringify(head)}`);
  }
});

test("chat: a stream with nothing token-shaped at a cut relays byte-verbatim; prose `$` only moves", () => {
  const sse = chunk({ role: "assistant", content: "" }) + chunk({ content: "total: $5" }) + chunk({ content: ".00, and $HOME is set" }) + chunk({}, "stop") + DONE;
  assert.equal(run(new ChatTextRepacker(), sse), sse);
  const out = run(new ChatTextRepacker(), chunk({ content: "total: $" }) + chunk({ content: "5.00" }) + chunk({}, "stop") + DONE);
  assert.deepEqual(chatTexts(out), ["total: ", "$5.00"]);
});

test("chat: a held prefix before a finish, a tool call or another choice goes out whole; text in the finishing chunk absorbs the carry", () => {
  const fin = chunk({ content: "pay $MDU" }) + chunk({}, "stop") + DONE;
  assert.equal(run(new ChatTextRepacker(), fin), fin);
  const tc = chunk({ content: "see $MDU:" }) + chunk({ tool_calls: [{ index: 0, id: "c", type: "function", function: { name: "x", arguments: "{}" } }] }) + chunk({}, "tool_calls");
  assert.equal(run(new ChatTextRepacker(), tc), tc, "a tool-call chunk (the rewriter's release) is not text: the order stays");
  const other = chunk({ content: "a $MDU" }) + chunk({ content: ":x" }, null, 1);
  assert.equal(run(new ChatTextRepacker(), other), other, "another choice's text does not continue this one");
  const out = run(new ChatTextRepacker(), chunk({ content: "see $MDU:exe" }) + chunk({ content: "c_command[695b].output" }, "stop") + DONE);
  assert.deepEqual(chatTexts(out), ["see ", TOKEN]);
});

test("chat: end() and a cut stream never swallow the held text; comments pass during a hold", () => {
  const r = new ChatTextRepacker();
  assert.equal(r.feed(chunk({ content: "x $MDU:exe" })), "", "the possible token start is held");
  assert.equal(r.feed(": keepalive\n\n"), ": keepalive\n\n", "a comment passes through while the hold stays open");
  assert.deepEqual(chatTexts(r.feed(chunk({ content: "c_command[695b].output" })) + r.end()), ["x ", TOKEN]);
  const cut = new ChatTextRepacker();
  assert.deepEqual(chatTexts(cut.feed(chunk({ content: "x $MDU" })) + cut.end()), ["x $MDU"]);
});

test("chat: logprobs or several choices are never re-cut", () => {
  const lp = chunk({ content: "a $MDU" }).replace('"finish_reason":null', '"finish_reason":null,"logprobs":{"content":[]}') + chunk({ content: ":x[1a2b]" });
  assert.equal(run(new ChatTextRepacker(), lp), lp);
  const two = `data: ${JSON.stringify({ id: "c1", choices: [{ index: 0, delta: { content: "a $MDU" }, finish_reason: null }, { index: 1, delta: { content: "b" }, finish_reason: null }] })}\n\n` + chunk({ content: ":x[1a2b]" });
  assert.equal(run(new ChatTextRepacker(), two), two);
});
