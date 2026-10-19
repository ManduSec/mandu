/**
 * sse-reserve-expand.test — the Responses reserve expander (Codex) and its
 * eligibility (src/sse-reserve-expand.ts, src/reserve-eligibility.ts;
 * docs/design/ui/reply-row-reservation.md §3.5, §11.3-§11.5, §11.7): standalone
 * and mid-line tokens, a token split at every delta offset (through the text
 * repacker and without it, and SSE frames torn at every byte), the
 * `output_text.done` / `content_part.done` / `output_item.done` /
 * `response.completed` snapshots carrying the same expanded text, the event
 * list and `sequence_number`s untouched, the hold's release rules, a v1
 * relay, and an arbiter that is down, silent or refusing (no rewrite, the
 * stream byte-identical). Pure: no arbiter process, no axes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ResponsesReserveExpander, type ReserveExpansion } from "../../src/sse-reserve-expand.js";
import { ReserveEligibility } from "../../src/reserve-eligibility.js";
import { ResponsesTextRepacker } from "../../src/text-repack.js";
import { collapseText, reserveBlock } from "../../src/reserve-block.js";
import { layoutLines, layoutRows, layoutWidth } from "../../src/reserve-layout.js";
import { suffixBreak } from "../../src/reserve-context.js";

/** Small seeded PRNG (mulberry32), so a failure reproduces. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const T = "$MDU:nomodel_exec_command[464e]";
const T_ESC = "\\$MDU:nomodel\\_exec\\_command[464e]";
const T_FIELD = "$MDU:inspect[695b].result";
const T_LONG1 = "$MDU:anymodel_Read[a1b2c3]";
/** Values by canonical token (what the arbiter would resolve). */
const VALUES = new Map<string, string>([
  [T, "Host bastion\n  HostName 10.9.8.7\n  User git\n  IdentityFile ~/.ssh/key\n"],
  [T_FIELD, "line one\nline two\n"],
  [T_LONG1, "k".repeat(200)], // one line that wraps
]);

type Json = Record<string, unknown>;

// ── a Responses stream ───────────────────────────────────────────────────────

const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;

interface Part { item: string; out: number; parts: string[] }

/** A whole Responses stream: one message item per Part (its text in the
 *  given deltas), every snapshot carrying the model's full text. */
function stream(items: Part[], o: { logprobs?: boolean; doneText?: (full: string) => string } = {}): string {
  let seq = 0;
  let s = ev("response.created", { sequence_number: seq++, response: { id: "r1", output: [] } });
  const msgs: Json[] = [];
  for (const it of items) {
    const full = it.parts.join("");
    const msg = { type: "message", id: it.item, status: "completed", role: "assistant", content: [{ type: "output_text", text: full, annotations: [] }] };
    msgs.push(msg);
    const ids = { item_id: it.item, output_index: it.out, content_index: 0 };
    s += ev("response.output_item.added", { sequence_number: seq++, output_index: it.out, item: { ...msg, status: "in_progress", content: [] } });
    s += ev("response.content_part.added", { sequence_number: seq++, ...ids, part: { type: "output_text", text: "", annotations: [] } });
    for (const p of it.parts) {
      s += ev("response.output_text.delta", { sequence_number: seq++, ...ids, delta: p, ...(o.logprobs ? { logprobs: [{ token: p, logprob: -0.1 }] } : {}) });
    }
    const doneText = o.doneText ? o.doneText(full) : full;
    s += ev("response.output_text.done", { sequence_number: seq++, ...ids, text: doneText });
    s += ev("response.content_part.done", { sequence_number: seq++, ...ids, part: { type: "output_text", text: doneText, annotations: [] } });
    s += ev("response.output_item.done", { sequence_number: seq++, output_index: it.out, item: msg });
  }
  s += ev("response.completed", { sequence_number: seq++, response: { id: "r1", status: "completed", output: msgs } });
  return s;
}
const one = (parts: string[], o?: Parameters<typeof stream>[1]): string => stream([{ item: "msg_1", out: 0, parts }], o);

function events(sse: string): Json[] {
  const out: Json[] = [];
  for (const frame of sse.split(/\n\n/)) {
    const line = frame.split(/\r?\n/).find((l) => l.startsWith("data:"));
    if (line) out.push(JSON.parse(line.slice(5).trim()) as Json);
  }
  return out;
}
function deltaTexts(sse: string, item = "msg_1"): string[] {
  return events(sse).filter((e) => e["type"] === "response.output_text.delta" && e["item_id"] === item).map((e) => e["delta"] as string);
}
/** Every snapshot's text for an item: output_text.done, content_part.done,
 *  output_item.done, response.completed. */
function snapshots(sse: string, item = "msg_1"): string[] {
  const out: string[] = [];
  for (const e of events(sse)) {
    if (e["type"] === "response.output_text.done" && e["item_id"] === item) out.push(e["text"] as string);
    if (e["type"] === "response.content_part.done" && e["item_id"] === item) out.push((e["part"] as Json)["text"] as string);
    if (e["type"] === "response.output_item.done" && (e["item"] as Json)["id"] === item) {
      out.push((((e["item"] as Json)["content"] as Json[])[0]!)["text"] as string);
    }
    if (e["type"] === "response.completed") {
      for (const m of (e["response"] as Json)["output"] as Json[]) {
        if (m["id"] === item) out.push(((m["content"] as Json[])[0]!)["text"] as string);
      }
    }
  }
  return out;
}
const shape = (sse: string): string[] => events(sse).map((e) => `${e["type"]}#${e["sequence_number"]}`);

/** The v1 expander (no layout): lines by canonical token. */
function expanderV1(o: { seen?: ReserveExpansion[]; calls?: string[]; values?: Map<string, string> } = {}): ResponsesReserveExpander {
  const values = o.values ?? VALUES;
  return new ResponsesReserveExpander({
    lines: async (tok) => {
      o.calls?.push(tok);
      const v = values.get(tok);
      return v === undefined ? null : layoutLines(v).length;
    },
    cap: 40,
    onExpand: (e) => o.seen?.push(e),
  });
}

interface ShapeCall { token: string; width: number; first: number }

/** The v2 expander: a relay at `cols` (null: a v1 relay). */
function expanderV2(o: { cols?: number | null; values?: Map<string, string>; seen?: ReserveExpansion[]; calls?: ShapeCall[]; codeSpan?: boolean; withLast?: boolean } = {}): ResponsesReserveExpander {
  const values = o.values ?? VALUES;
  const cols = o.cols === undefined ? 80 : o.cols;
  return new ResponsesReserveExpander({
    lines: async (tok) => {
      const v = values.get(tok);
      return v === undefined ? null : layoutLines(v).length;
    },
    layout: async () => (cols === null ? null : { cols }),
    shape: async (token, width, first) => {
      o.calls?.push({ token, width, first });
      const v = values.get(token);
      if (v === undefined) return null;
      const laid = layoutRows(v, width, first);
      return o.withLast
        ? { lines: layoutLines(v).length, rows: laid.length, last: layoutWidth(laid[laid.length - 1]!.text) }
        : { lines: layoutLines(v).length, rows: laid.length };
    },
    cap: 40,
    onExpand: (e) => o.seen?.push(e),
    ...(o.codeSpan !== undefined ? { codeSpan: o.codeSpan } : {}),
  });
}

async function run(x: ResponsesReserveExpander, chunks: string[]): Promise<string> {
  let out = "";
  for (const c of chunks) out += await x.feed(c);
  return out + (await x.end());
}

/** The text a stream of one part expands to (whole, one delta). */
async function textOf(x: ResponsesReserveExpander, text: string): Promise<string> {
  return deltaTexts(await run(x, [one([text])])).join("");
}

const b2 = (tok: string, n: number, width: number, first: number): string => reserveBlock(tok, n, { width, first });

/** The invariants every expanded stream keeps: the same events with the same
 *  sequence numbers, in order; every snapshot = the deltas' text. */
function assertConsistent(input: string, out: string, label: string, item = "msg_1"): string {
  assert.deepEqual(shape(out), shape(input), `${label}: the upstream's events, in order, sequence numbers untouched`);
  const joined = deltaTexts(out, item).join("");
  for (const s of snapshots(out, item)) assert.equal(s, joined, `${label}: every snapshot carries the deltas' text`);
  return joined;
}

// ── v1 heads ─────────────────────────────────────────────────────────────────

test("v1: a standalone token is expanded in ONE delta; every snapshot carries the same text; collapse restores the model's", async () => {
  const text = `Your config:\n\n${T}\n\nDone.`;
  const seen: ReserveExpansion[] = [];
  const input = one([text]);
  const out = await run(expanderV1({ seen }), [input]);
  const joined = assertConsistent(input, out, "v1");
  assert.equal(joined, `Your config:\n\n${reserveBlock(T, 4)}\n\nDone.`);
  assert.ok(deltaTexts(out).some((t) => t.includes(reserveBlock(T, 4))), "the whole block rides in one delta");
  assert.equal(collapseText(joined), text);
  assert.deepEqual(seen, [{ index: 0, token: T, hash: "464e", rows: 4 }]);
});

test("register (§3.8): every expanded block is recorded before its delta, canonical token, v2 W/F; a rejection is ignored", async () => {
  const order: string[] = [];
  const registered: ReserveExpansion[] = [];
  const x = new ResponsesReserveExpander({
    lines: async () => null,
    layout: async () => ({ cols: 80 }),
    shape: async (token, width, first) => {
      const v = VALUES.get(token);
      return v === undefined ? null : { lines: layoutLines(v).length, rows: layoutRows(v, width, first).length };
    },
    cap: 40,
    register: async (e) => { order.push("register"); registered.push(e); },
    onExpand: () => order.push("expand"),
  });
  const text = `Here:\n${T_ESC}\nThe value is ${T_LONG1} and that is all.`;
  await run(x, [one([text])]);
  assert.deepEqual(order, ["register", "expand", "register", "expand"]);
  assert.deepEqual(registered.map((e) => [e.token, e.hash, e.width !== undefined]), [[T, "464e", true], [T_LONG1, "a1b2c3", true]]);
  const failing = new ResponsesReserveExpander({
    lines: async (tok) => { const v = VALUES.get(tok); return v === undefined ? null : layoutLines(v).length; },
    cap: 40,
    register: async () => { throw new Error("arbiter down"); },
  });
  assert.ok(deltaTexts(await run(failing, [one([`${T}\n`])])).join("").includes(`${T}/1:4`), "still expanded");
});

test("eligibility register: the session's block (and W/F), bounded; absent op or key → nothing", async () => {
  const notes: unknown[] = [];
  const relay = async () => ({ mode: "pty", reserve: true, updatedAt: 1 });
  const e = new ReserveEligibility({ sessionRelay: relay, symbolShape: async () => ({ lines: 4 }), noteReserveBlock: async (a) => { notes.push(a); } }, { enabled: true, sessionKey: "s1" });
  await e.register({ token: T, rows: 4 });
  await e.register({ token: T, rows: 3, width: 78, first: 40 });
  assert.deepEqual(notes, [{ sessionKey: "s1", token: T, n: 4 }, { sessionKey: "s1", token: T, n: 3, width: 78, first: 40 }]);
  // An op that never answers on its own: register must come back while it is
  // still pending (its deadline, not the op, ended the wait). No wall-clock
  // bound: a loaded CI host ran the 30 ms timer past the old 150 ms check
  // (as in anthropic-proxy's copy of this test).
  let settled = false;
  let release = (): void => {};
  const pending = new Promise<void>((r) => { release = () => { settled = true; r(); }; });
  const slow = new ReserveEligibility({ noteReserveBlock: () => pending }, { enabled: true, sessionKey: "s1", timeoutMs: 30 });
  // The deadline's timer is unref'd (it must not hold a proxy open); hold the
  // loop open while the test waits on it.
  const keepAlive = setTimeout(() => {}, 60_000);
  try {
    await slow.register({ token: T, rows: 4 });
  } finally {
    clearTimeout(keepAlive);
  }
  assert.equal(settled, false, "bounded by the deadline: register returned with the op still pending");
  release();
  const none: unknown[] = [];
  await new ReserveEligibility({ noteReserveBlock: async (a) => { none.push(a); } }, { enabled: true }).register({ token: T, rows: 4 });
  assert.deepEqual(none, [], "no session key, nothing recorded");
});

test("v1: a token ending the part is proven alone by output_text.done; a mid-line token is left", async () => {
  assert.equal(await textOf(expanderV1(), `${T}`), reserveBlock(T, 4));
  assert.equal(await textOf(expanderV1(), `${T_ESC}\n`), `${reserveBlock(T_ESC, 4)}\n`, "escaped: the head keeps the model's spelling");
  for (const text of [`see ${T} here`, `${T}.\n`, `${T} \n`, `- ${T}\n`, `${T}\r\n`]) {
    const input = one([text]);
    assert.equal(await run(expanderV1(), [input]), input, `byte-identical: ${JSON.stringify(text)}`);
  }
});

// ── v2 heads ─────────────────────────────────────────────────────────────────

test("v2: a token inside a sentence expands with W:F; the suffix stays after the last row; every snapshot agrees", async () => {
  const seen: ReserveExpansion[] = [];
  const calls: ShapeCall[] = [];
  const text = `The value is ${T} and that is all.`;
  const input = one([text]);
  const out = await run(expanderV2({ seen, calls }), [input]);
  const joined = assertConsistent(input, out, "mid-line");
  // Codex's content indent is 2, as Claude Code's (§11.7): W = 78 at 80 columns.
  const first = 78 - "The value is ".length;
  assert.equal(joined, `The value is ${b2(T, 4, 78, first)} and that is all.`);
  assert.equal(collapseText(joined), text);
  assert.deepEqual(calls, [{ token: T, width: 78, first }]);
  assert.deepEqual(seen, [{ index: 0, token: T, hash: "464e", rows: 4, width: 78, first }]);
});

test("v2: a one-line value that wraps expands (standalone F = W); a value that fits one row does not", async () => {
  assert.equal(await textOf(expanderV2(), `${T_LONG1}\n`), `${b2(T_LONG1, 3, 78, 78)}\n`, "200 columns at W = 78: 3 rows");
  const fits = one([`${T_LONG1}\n`]);
  assert.equal(await run(expanderV2({ cols: 240 }), [fits]), fits, "fits one row at W = 238: byte-identical");
});

test("v2: every split offset (through the repacker, bare, and SSE torn at every byte) gives the same text, the block whole, the snapshots agreeing", async () => {
  const cases = [
    `The value is ${T} and that is all.`,
    `The value is ${T}`,
    `Your config:\n${T}\nafter`,
    `${T}`,
    `Key: **${T}** done.`,
    `field ${T_FIELD}, ok`,
    `Line one\n- item ${T}.\n${T}\nend`,
    `x ${T}y and ${T}$5 then ${T}`,
    `${T_ESC}\n`,
  ];
  for (const text of cases) {
    const expected = await textOf(expanderV2(), text);
    assert.equal(collapseText(expected), text, JSON.stringify(text));
    const blocks = expected.match(/\$MDU:[^\s]*?\/1:[0-9:]+(?:\n\$MDU\/[0-9a-f]+\/[0-9]+)+/g) ?? [];
    const step = Math.max(1, Math.floor(text.length / 9));
    for (let i = 0; i <= text.length; i++) {
      for (let j = i; j <= text.length; j += step) {
        const parts = [text.slice(0, i), text.slice(i, j), text.slice(j)];
        const input = one(parts);
        const rp = new ResponsesTextRepacker();
        const repacked = rp.feed(input) + rp.end();
        const out = await run(expanderV2(), [repacked]);
        const label = `${JSON.stringify(text)} @${i},${j}`;
        assert.equal(assertConsistent(input, out, label), expected, label);
        for (const blk of blocks) {
          assert.ok(deltaTexts(out).some((t) => t.includes(blk)), `${label}: block split: ${JSON.stringify(deltaTexts(out))}`);
        }
        const bare = await run(expanderV2(), [input]);
        assert.equal(assertConsistent(input, bare, `bare ${label}`), expected, `no repacker ${label}`);
      }
    }
    const input = one([text.slice(0, 3), text.slice(3)]);
    const x = expanderV2();
    let out = "";
    for (const ch of input) out += await x.feed(ch);
    out += await x.end();
    assert.equal(assertConsistent(input, out, `bytewise ${JSON.stringify(text)}`), expected);
  }
});

test("v2: a v1 relay (no wrap) gives v1 heads only; a stream with no standalone token is byte-identical", async () => {
  const text = `The value is ${T} and that is all.\n${T}\n`;
  assert.equal(await textOf(expanderV2({ cols: null }), text), `The value is ${T} and that is all.\n${reserveBlock(T, 4)}\n`);
  const mid = one([`The value is ${T}`, ` and that is all.`]);
  assert.equal(await run(expanderV2({ cols: null }), [mid]), mid, "a v1 relay leaves a mid-line token: the stream is byte-identical");
});

test("a held token is released unexpanded, in place, on another event and at the stream end; nothing is invented or dropped", async () => {
  // The part ends without its output_text.done: not proven, never guessed.
  const cut = one([`see ${T}`]).split("event: response.output_text.done")[0]!;
  const out = await run(expanderV2(), [cut]);
  assert.equal(out, cut, "byte-identical: the held delta goes out whole at the end");
  // Another event between the token and the done: released as is.
  const input = one([`see ${T}`]).replace(
    "event: response.output_text.done",
    `event: response.output_text.annotation.added\ndata: ${JSON.stringify({ type: "response.output_text.annotation.added", item_id: "msg_1", output_index: 0, content_index: 0, annotation: {} })}\n\nevent: response.output_text.done`,
  );
  const out2 = await run(expanderV2(), [input]);
  assert.equal(out2, input, "byte-identical");
  // A keepalive comment inside the hold passes through; the token is still decided.
  const withComment = one([`see ${T}`]).replace("event: response.output_text.done", ": keepalive\n\nevent: response.output_text.done");
  const out3 = await run(expanderV2(), [withComment]);
  assert.ok(out3.includes(": keepalive\n\n"));
  assert.equal(deltaTexts(out3).join(""), `see ${b2(T, 4, 78, 74)}`);
});

test("two message items keep their own state, and each snapshot gets its own part's text", async () => {
  const input = stream([
    { item: "msg_1", out: 0, parts: [`first ${T}`, " done"] },
    { item: "msg_2", out: 1, parts: [`${T_FIELD}\n`, "plain"] },
  ]);
  const out = await run(expanderV2(), [input]);
  assert.equal(assertConsistent(input, out, "msg_1", "msg_1"), `first ${b2(T, 4, 78, 72)} done`);
  assert.equal(assertConsistent(input, out, "msg_2", "msg_2"), `${b2(T_FIELD, 2, 78, 78)}\nplain`);
});

test("a part whose deltas carry logprobs is never changed", async () => {
  const input = one([`see ${T}`, " and more"], { logprobs: true });
  assert.equal(await run(expanderV2(), [input]), input);
});

test("a snapshot that does not match the deltas' text is left alone (no rewrite, never guess)", async () => {
  const input = one([`see ${T} x`], { doneText: (f) => `${f}!` });
  const out = await run(expanderV2(), [input]);
  assert.equal(deltaTexts(out).join(""), `see ${b2(T, 4, 78, 74)} x`);
  const ev0 = events(out).find((e) => e["type"] === "response.output_text.done")!;
  assert.equal(ev0["text"], `see ${T} x!`);
  // The item snapshot still matches the deltas: rewritten.
  const item = events(out).find((e) => e["type"] === "response.output_item.done")!;
  assert.equal((((item["item"] as Json)["content"] as Json[])[0]!)["text"], `see ${b2(T, 4, 78, 74)} x`);
});

test("a lookup that rejects, answers null or a non-integer means no expansion: byte-identical", async () => {
  const input = one([`${T}\n`, `see ${T} here`]);
  const bad = [
    async () => { throw new Error("down"); },
    async () => null,
    async () => ({ lines: 2.5, rows: 3.5 }),
  ];
  for (const s of bad) {
    const x = new ResponsesReserveExpander({ lines: async () => { throw new Error("down"); }, layout: async () => ({ cols: 80 }), shape: s as never, cap: 40 });
    assert.equal(await run(x, [input]), input);
  }
  const noLayout = new ResponsesReserveExpander({ lines: async () => null, layout: async () => { throw new Error("down"); }, shape: async () => null, cap: 40 });
  assert.equal(await run(noLayout, [input]), input);
});

test("property: the expander's output always collapses back to the model's text, and every snapshot agrees", async () => {
  const r = rng(0x5eed);
  const pick = <X>(xs: readonly X[]): X => xs[Math.floor(r() * xs.length)]!;
  const toks = [T, T_ESC, T_FIELD, T_LONG1, "$MDU:unknown[beef]"];
  const words = ["the", "key", "**", "`", "(", ")", "[", "]", "|", "#", "> ", "- ", "1. ", "```", "", "é", "🔑", "$5", "\\"];
  const values = new Map(VALUES);
  values.set(T_ESC.replace(/\\/g, ""), VALUES.get(T)!);
  let expanded = 0;
  for (let i = 0; i < 200; i++) {
    const lines: string[] = [];
    const n = 1 + Math.floor(r() * 6);
    for (let k = 0; k < n; k++) {
      const w: string[] = [];
      const m = Math.floor(r() * 6);
      for (let j = 0; j < m; j++) w.push(r() < 0.35 ? pick(["", "**", "\"", "_"]) + pick(toks) + pick(["", ".", ",", "** x", "!", "7", "x"]) : pick(words));
      lines.push(w.join(r() < 0.8 ? " " : ""));
    }
    const text = lines.join("\n");
    const cols = pick([40, 80, 120]);
    const c1 = Math.floor(r() * (text.length + 1));
    const c2 = c1 + Math.floor(r() * (text.length - c1 + 1));
    const input = one([text.slice(0, c1), text.slice(c1, c2), text.slice(c2)]);
    const out = await run(expanderV2({ cols, values }), [input]);
    const joined = assertConsistent(input, out, `case ${i}`);
    if (joined !== text) expanded++;
    assert.equal(collapseText(joined), text, `case ${i}: ${JSON.stringify(text)}`);
    assert.equal(joined, await textOf(expanderV2({ cols, values }), text), `case ${i}: split-invariant`);
  }
  assert.ok(expanded > 60, `the generator must exercise expansion (${expanded})`);
});

// ── with the eligibility (the arbiter's human plane) ─────────────────────────

const PTY = { mode: "pty" as const, reserve: true, cols: 80, rows: 24, wrap: true, updatedAt: 1 };

function eligible(arbiter: ConstructorParameters<typeof ReserveEligibility>[0], enabled = true, sessionKey: string | null = "scope-1"): ReserveEligibility {
  return new ReserveEligibility(arbiter, { enabled, ...(sessionKey ? { sessionKey } : {}), timeoutMs: 50 });
}
function viaEligibility(e: ReserveEligibility): ResponsesReserveExpander {
  return new ResponsesReserveExpander({ lines: e.lines, layout: e.layout, shape: e.shape, cap: 40 });
}
const shapeOf = async (t: string, o?: { width: number; first: number }) => {
  const v = VALUES.get(t);
  if (v === undefined) return null;
  return o ? { lines: layoutLines(v).length, rows: layoutRows(v, o.width, o.first).length } : { lines: layoutLines(v).length };
};

test("eligibility: a PTY relay that reserves and wraps → v2 blocks; the relay is asked on the session key", async () => {
  const keys: string[] = [];
  const e = eligible({ sessionRelay: async (k) => { keys.push(k); return PTY; }, symbolShape: shapeOf });
  assert.equal(e.possible, true);
  assert.equal(await textOf(viaEligibility(e), `The value is ${T} and that is all.`), `The value is ${b2(T, 4, 78, 65)} and that is all.`);
  assert.deepEqual(keys, ["scope-1"]);
});

/** An answer past the eligibility's 50 ms deadline (a wedged arbiter). */
const late = <X>(v: X): Promise<X> => new Promise((r) => setTimeout(() => r(v), 200));

test("eligibility: arbiter down, silent, relay null / pipe / no reserve → no rewrite: the stream is byte-identical", async () => {
  const input = one([`Your config:\n${T}\n`, `The value is ${T} and that is all.`]);
  const arbiters = [
    { sessionRelay: async () => { throw new Error("ECONNREFUSED"); }, symbolShape: shapeOf },
    { sessionRelay: () => late(PTY), symbolShape: shapeOf },
    { sessionRelay: async () => null, symbolShape: shapeOf },
    { sessionRelay: async () => ({ ...PTY, mode: "pipe" as const }), symbolShape: shapeOf },
    { sessionRelay: async () => ({ ...PTY, reserve: false }), symbolShape: shapeOf },
    { sessionRelay: async () => PTY, symbolShape: async () => { throw new Error("ECONNREFUSED"); } },
    { sessionRelay: async () => PTY, symbolShape: (t: string, o?: { width: number; first: number }) => shapeOf(t, o).then(late) },
  ];
  for (const [i, a] of arbiters.entries()) {
    assert.equal(await run(viaEligibility(eligible(a)), [input]), input, `case ${i}`);
  }
  // No human plane (the ops absent), the kill switch, no session key: impossible.
  assert.equal(eligible({}).possible, false);
  assert.equal(eligible({ sessionRelay: async () => PTY, symbolShape: shapeOf }, false).possible, false);
  assert.equal(eligible({ sessionRelay: async () => PTY, symbolShape: shapeOf }, true, null).possible, false);
});

test("span form (§12): off by default (Codex's renderer is not probed), and the grammar when turned on", async () => {
  const text = `The key is \`${T}\`, done.`;
  const out = await run(expanderV2(), [one([text])]);
  assert.equal(deltaTexts(out).join(""), text, "a token in a code span is left alone");
  const on = deltaTexts(await run(expanderV2({ codeSpan: true }), [one([text])])).join("");
  assert.ok(on.includes("`\n`$MDU/464e/2"), on);
  assert.equal(collapseText(on), text);
});

test("§14 break on Codex: the line is held across deltas until it ends; one line break where vanilla wraps; every snapshot agrees", async () => {
  const suffix = " and that is all, and the rest of this sentence runs on.";
  const text = `The value is ${T_LONG1}${suffix}\nDONE`;
  const F = 78 - "The value is ".length;
  const laid = layoutRows(VALUES.get(T_LONG1)!, 78, F);
  const k = suffixBreak({
    suffix, last: layoutWidth(laid[laid.length - 1]!.text), marker: layoutWidth(`$MDU/a1b2c3/${laid.length}`), width: 78, lineTicks: 0,
  })!;
  assert.ok(k !== null, "precondition: the text needs a break");
  const want = `The value is ${reserveBlock(T_LONG1, laid.length, { width: 78, first: F }, false, k)}${suffix.slice(0, k)}\n${suffix.slice(k)}\nDONE`;
  assert.equal(collapseText(want), text);
  for (let i = 1; i < text.length; i += 4) {
    for (const j of [i + 1, i + 9, text.length - 1]) {
      if (j <= i || j >= text.length) continue;
      const input = one([text.slice(0, i), text.slice(i, j), text.slice(j)]);
      const out = await run(expanderV2({ withLast: true }), [input]);
      assert.equal(assertConsistent(input, out, `@${i},${j}`), want, `@${i},${j}`);
    }
  }
});

test("§14 table row on Codex: a token in the first cell is not expanded; the stream keeps its text", async () => {
  const text = `${T} | the ssh config |\n--- | --- |\n`;
  const input = one([`${T} | the`, " ssh config |\n", "--- | --- |\n"]);
  const out = await run(expanderV2({ withLast: true }), [input]);
  assert.equal(assertConsistent(input, out, "table"), text);
});

test("§11.2 indent on Codex: symbolShape gets the content area's column (cols − W), so a TAB's stop is the terminal's", async () => {
  // Nine tabbed cells of 7: 71 columns counted from column 0, 77 from the
  // reply's column 2, past W = 72 at 74 columns. Only the right count
  // reserves the second row the terminal will draw.
  const TABS = "$MDU:nomodel_Read[7ab5]";
  const cells = Array.from({ length: 9 }, () => "abcdefg").join("\t");
  const seen: Array<{ width: number; first: number; indent?: number }> = [];
  const e = eligible({
    sessionRelay: async () => ({ ...PTY, cols: 74 }),
    symbolShape: async (_t: string, o?: { width: number; first: number; indent?: number }) => {
      if (o) seen.push(o);
      return o ? { lines: 1, rows: layoutRows(cells, o.width, o.first, "ink", o.indent).length } : { lines: 1 };
    },
  });
  assert.equal(await textOf(viaEligibility(e), `${TABS}\n`), `${b2(TABS, 2, 72, 72)}\n`);
  assert.deepEqual(seen, [{ width: 72, first: 72, indent: 2 }]);
  assert.equal(layoutRows(cells, 72, 72).length, 1, "counted from the value's own column 0 it would not expand");
});
