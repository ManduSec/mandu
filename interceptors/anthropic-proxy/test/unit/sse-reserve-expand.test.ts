/**
 * sse-reserve-expand.test — the response-side reserve expander and its
 * eligibility (src/sse-reserve-expand.ts; docs/design/ui/reply-row-reservation.md
 * §3.2, §3.5): expansion over deltas split at every offset, the one-line
 * hold, what is never expanded (mid-sentence, thinking, tool_use), the relay
 * and symbolShape gates, and event order. v2 (§11.3-§11.5): tokens inside a
 * line split at every offset, wrapped rows, (W, F) as the arbiter sees them,
 * fences, the v1 fallback (byte-identical), an arbiter without `rows`, the
 * hold's release rules, and the relay's `wrap`/`cols`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SseReserveExpander, ReserveEligibility, type ReserveExpansion } from "../../src/sse-reserve-expand.js";
import { SseTextDeltaRepacker } from "../../src/sse-text-repack.js";
import { collapseText, reserveBlock } from "../../src/reserve-block.js";
import { layoutLines, layoutRows, layoutWidth } from "../../src/reserve-layout.js";
import { suffixBreak } from "../../src/reserve-context.js";
import { sseEvent } from "../helpers/mock-upstream.js";

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

const T = "$MDU:nomodel_Bash[464e]";
const T_ESC = "\\$MDU:nomodel\\_Bash[464e]";
const LINES = new Map([[T, 4]]);

function blockStart(index = 0, type = "text"): string {
  const cb = type === "text" ? { type, text: "" } : type === "thinking" ? { type, thinking: "" } : { type, id: "tu1", name: "Bash", input: {} };
  return sseEvent("content_block_start", { type: "content_block_start", index, content_block: cb });
}
function textDelta(text: string, index = 0): string {
  return sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text } });
}
function blockStop(index = 0): string {
  return sseEvent("content_block_stop", { type: "content_block_stop", index });
}
const MSG_START = sseEvent("message_start", { type: "message_start", message: { id: "m", role: "assistant", content: [] } });
const MSG_STOP = sseEvent("message_stop", { type: "message_stop" });

type Ev = Record<string, unknown>;
function events(sse: string): Ev[] {
  const out: Ev[] = [];
  for (const frame of sse.split(/\n\n/)) {
    const line = frame.split(/\r?\n/).find((l) => l.startsWith("data:"));
    if (line) out.push(JSON.parse(line.slice(5).trim()) as Ev);
  }
  return out;
}
function deltaTexts(sse: string, index = 0): string[] {
  return events(sse)
    .filter((e) => e["type"] === "content_block_delta" && e["index"] === index && (e["delta"] as Ev)["type"] === "text_delta")
    .map((e) => (e["delta"] as Ev)["text"] as string);
}

function expander(lines: Map<string, number> = LINES, cap = 40, seen: ReserveExpansion[] = [], calls: string[] = []): SseReserveExpander {
  return new SseReserveExpander({
    lines: async (tok) => { calls.push(tok); return lines.get(tok) ?? null; },
    cap,
    onExpand: (e) => seen.push(e),
  });
}

async function run(x: SseReserveExpander, chunks: string[]): Promise<string> {
  let out = "";
  for (const c of chunks) out += await x.feed(c);
  return out + x.end();
}

test("a standalone token is expanded into ONE text_delta; the concatenated text collapses back exactly", async () => {
  const text = `Your config:\n\n${T}\n\nDone.`;
  const seen: ReserveExpansion[] = [];
  const out = await run(expander(LINES, 40, seen), [MSG_START, blockStart(), textDelta(text), blockStop(), MSG_STOP]);
  const texts = deltaTexts(out);
  const joined = texts.join("");
  assert.equal(joined, `Your config:\n\n${reserveBlock(T, 4)}\n\nDone.`);
  assert.ok(texts.some((t) => t.includes(reserveBlock(T, 4))), "the whole block rides in one delta");
  assert.equal(collapseText(joined), text);
  assert.deepEqual(seen, [{ index: 0, token: T, hash: "464e", rows: 4 }]);
  assert.deepEqual(events(out).map((e) => e["type"]), ["message_start", "content_block_start", ...texts.map(() => "content_block_delta"), "content_block_stop", "message_stop"]);
});

test("every split offset, through the repacker first: same final text, the block whole in one delta", async () => {
  const cases = [`Here:\n${T}\nafter`, `${T}`, `a\n${T}`, `${T}\n${T}\nx`, `${T_ESC}\n`, `mid ${T} sentence\n${T}`];
  for (const text of cases) {
    const whole = await run(expander(), [blockStart(), textDelta(text), blockStop()]);
    const expected = deltaTexts(whole).join("");
    for (let i = 0; i <= text.length; i++) {
      for (let j = i; j <= text.length; j += Math.max(1, Math.floor(text.length / 7))) {
        const parts = [text.slice(0, i), text.slice(i, j), text.slice(j)];
        const rp = new SseTextDeltaRepacker();
        let sse = rp.feed(blockStart());
        for (const p of parts) sse += rp.feed(textDelta(p));
        sse += rp.feed(blockStop()) + rp.end();
        const out = await run(expander(), [sse]);
        const texts = deltaTexts(out);
        assert.equal(texts.join(""), expected, `${JSON.stringify(text)} @${i},${j}`);
        if (expected.includes("/1:4")) {
          assert.ok(texts.some((t) => t.includes(reserveBlock(T.includes("\\") ? T_ESC : T, 4)) || t.includes(reserveBlock(T_ESC, 4))), `${JSON.stringify(text)} @${i},${j}: block split across deltas: ${JSON.stringify(texts)}`);
        }
        assert.equal(collapseText(texts.join("")), text);
        // Without the repacker (a token torn across deltas): the expander's
        // own line hold reaches the same text.
        const bare = await run(expander(), [blockStart(), ...parts.map((p) => textDelta(p)), blockStop()]);
        assert.equal(deltaTexts(bare).join(""), expected, `no repacker ${JSON.stringify(text)} @${i},${j}`);
      }
    }
    // And fed byte by byte (SSE frames torn at every offset).
    const sse = blockStart() + textDelta(text) + blockStop();
    const x = expander();
    let out = "";
    for (const ch of sse) out += await x.feed(ch);
    out += x.end();
    assert.equal(deltaTexts(out).join(""), expected, `bytewise ${JSON.stringify(text)}`);
  }
});

test("expected expansions for the split cases", async () => {
  const exp = async (text: string) => deltaTexts(await run(expander(), [blockStart(), textDelta(text), blockStop()])).join("");
  assert.equal(await exp(`${T}`), reserveBlock(T, 4), "the token is the whole block: proven at content_block_stop");
  assert.equal(await exp(`${T_ESC}\n`), `${reserveBlock(T_ESC, 4)}\n`, "escaped: the head keeps the model's spelling");
  assert.equal(await exp(`mid ${T} sentence\n${T}`), `mid ${T} sentence\n${reserveBlock(T, 4)}`);
});

test("not expanded: mid-sentence, a trailing char, one-line values, unknown tokens", async () => {
  for (const text of [`see ${T} here`, `${T}.\n`, `${T} \n`, `- ${T}\n`, `${T}\r\n`]) {
    const out = await run(expander(), [blockStart(), textDelta(text), blockStop()]);
    assert.equal(deltaTexts(out).join(""), text, JSON.stringify(text));
  }
  const one = await run(expander(new Map([[T, 1]])), [blockStart(), textDelta(`${T}\n`), blockStop()]);
  assert.equal(deltaTexts(one).join(""), `${T}\n`);
  const unknown = await run(expander(new Map()), [blockStart(), textDelta(`${T}\n`), blockStop()]);
  assert.equal(deltaTexts(unknown).join(""), `${T}\n`);
});

test("an untouched delta relays byte-verbatim, and no lookup is made without a candidate", async () => {
  const calls: string[] = [];
  const x = expander(LINES, 40, [], calls);
  const raw = textDelta("plain prose with $5.00 and a token mid-line $MDU:a[ab12] ok\n");
  const out = await run(x, [blockStart(), raw, blockStop()]);
  assert.ok(out.includes(raw));
  assert.deepEqual(calls, []);
});

test("thinking and tool_use blocks are never expanded", async () => {
  const thinking = sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: `${T}\n` } });
  const json = sseEvent("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command: `${T}\n` }) } });
  // A text_delta on a non-text block index (malformed) is also left alone.
  const stray = textDelta(`${T}\n`, 1);
  const input = [blockStart(0, "thinking"), thinking, blockStop(0), blockStart(1, "tool_use"), json, stray, blockStop(1)];
  const out = await run(expander(), input);
  assert.equal(out, input.join(""));
});

test("a held candidate is released unexpanded on a non-text delta, message_stop and the stream end", async () => {
  const cit = sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "citations_delta", citation: {} } });
  const a = await run(expander(), [blockStart(), textDelta(`x\n${T}`), cit, blockStop()]);
  assert.equal(deltaTexts(a).join(""), `x\n${T}`);
  const types = events(a).map((e) => (e["delta"] as Ev | undefined)?.["type"] ?? e["type"]);
  assert.deepEqual(types, ["content_block_start", "text_delta", "text_delta", "citations_delta", "content_block_stop"], "held text precedes the citation");
  const b = await run(expander(), [blockStart(), textDelta(`x\n${T}`), MSG_STOP]);
  assert.equal(deltaTexts(b).join(""), `x\n${T}`);
  assert.ok(b.indexOf("message_stop") > b.lastIndexOf(T));
  const c = await run(expander(), [blockStart(), textDelta(`x\n${T}`)]);
  assert.equal(deltaTexts(c).join(""), `x\n${T}`);
});

test("per-index holds: interleaved text blocks keep their own state", async () => {
  const out = await run(expander(), [
    blockStart(0), blockStart(1),
    textDelta(`a\n${T}`, 0), textDelta(`b ${T}`, 1), textDelta("\n", 0), textDelta("\n", 1),
    blockStop(0), blockStop(1),
  ]);
  assert.equal(deltaTexts(out, 0).join(""), `a\n${reserveBlock(T, 4)}\n`);
  assert.equal(deltaTexts(out, 1).join(""), `b ${T}\n`);
});

test("a lookup that rejects or answers a non-integer means no expansion", async () => {
  const x = new SseReserveExpander({ lines: async () => { throw new Error("down"); }, cap: 40 });
  const out = await run(x, [blockStart(), textDelta(`${T}\n`), blockStop()]);
  assert.equal(deltaTexts(out).join(""), `${T}\n`);
  const y = new SseReserveExpander({ lines: async () => 2.5, cap: 40 });
  assert.equal(deltaTexts(await run(y, [blockStart(), textDelta(`${T}\n`), blockStop()])).join(""), `${T}\n`);
});

test("the cap bounds N", async () => {
  const out = await run(expander(new Map([[T, 500]]), 3), [blockStart(), textDelta(`${T}\n`), blockStop()]);
  assert.equal(deltaTexts(out).join(""), `${reserveBlock(T, 3)}\n`);
});

// ── the block registry (reply-row-reservation.md §3.8) ────────────────────────

test("register: each expanded block is recorded BEFORE its delta goes out, with the canonical token", async () => {
  const order: string[] = [];
  const registered: ReserveExpansion[] = [];
  const x = new SseReserveExpander({
    lines: async (tok) => LINES.get(tok) ?? null,
    cap: 40,
    register: async (e) => { order.push("register"); registered.push(e); },
    onExpand: () => order.push("expand"),
  });
  const out = await run(x, [MSG_START, blockStart(), textDelta(`See:\n${T_ESC}\n`), blockStop(), MSG_STOP]);
  assert.ok(deltaTexts(out).join("").includes(`${T_ESC}/1:4`), "expanded");
  assert.deepEqual(order, ["register", "expand"], "registered first, then reported");
  assert.equal(registered.length, 1);
  assert.equal(registered[0]!.token, T, "the arbiter gets the canonical token");
  assert.equal(registered[0]!.hash, "464e");
  assert.equal(registered[0]!.rows, 4);
});

test("register: a rejection does not stop the expansion", async () => {
  const x = new SseReserveExpander({
    lines: async (tok) => LINES.get(tok) ?? null,
    cap: 40,
    register: async () => { throw new Error("arbiter down"); },
  });
  const out = await run(x, [MSG_START, blockStart(), textDelta(`${T}\n`), blockStop(), MSG_STOP]);
  assert.equal(deltaTexts(out).join(""), `${reserveBlock(T, 4)}\n`);
});

test("eligibility register: the session's block with N (and W/F for v2), bounded; absent op or key → nothing", async () => {
  const notes: unknown[] = [];
  const base = arb({ relay: () => PTY, shape: () => ({ lines: 4 }) }).arbiter;
  const e = new ReserveEligibility({ ...base, noteReserveBlock: async (a) => { notes.push(a); } }, { enabled: true, sessionKey: "s1" });
  await e.register({ token: T, rows: 4 });
  await e.register({ token: T, rows: 3, width: 78, first: 40 });
  assert.deepEqual(notes, [
    { sessionKey: "s1", token: T, n: 4 },
    { sessionKey: "s1", token: T, n: 3, width: 78, first: 40 },
  ]);
  // An op that never answers on its own: register must come back while it is
  // still pending (its deadline, not the op, ended the wait). No wall-clock
  // bound: a loaded CI guest ran the 30 ms timer past the old 150 ms check.
  let settled = false;
  let release = (): void => {};
  const pending = new Promise<void>((r) => { release = () => { settled = true; r(); }; });
  const slow = new ReserveEligibility({ ...base, noteReserveBlock: () => pending }, { enabled: true, sessionKey: "s1", timeoutMs: 30 });
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
  await new ReserveEligibility(base, { enabled: true, sessionKey: "s1" }).register({ token: T, rows: 4 });
  const noKey: unknown[] = [];
  await new ReserveEligibility({ ...base, noteReserveBlock: async (a) => { noKey.push(a); } }, { enabled: true }).register({ token: T, rows: 4 });
  assert.deepEqual(noKey, []);
});

// ── eligibility ──────────────────────────────────────────────────────────────

type Relay = { mode: "pty" | "pipe" | "passthrough"; reserve: boolean; updatedAt: number } | null;

function arb(o: { relay?: () => Relay | Promise<Relay>; shape?: (t: string) => { lines: number } | null | Promise<{ lines: number } | null> } = {}) {
  const calls = { relay: 0, shape: [] as string[] };
  return {
    calls,
    arbiter: {
      ...(o.relay ? { sessionRelay: async () => { calls.relay++; return o.relay!(); } } : {}),
      ...(o.shape ? { symbolShape: async (t: string) => { calls.shape.push(t); return o.shape!(t); } } : {}),
    },
  };
}
const PTY: Relay = { mode: "pty", reserve: true, updatedAt: 1 };

test("eligibility: PTY relay with reserve → the shape's line count; cached per token", async () => {
  const { arbiter, calls } = arb({ relay: () => PTY, shape: () => ({ lines: 7 }) });
  const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s1" });
  assert.equal(e.possible, true);
  assert.equal(await e.lines(T), 7);
  assert.equal(await e.lines(T), 7);
  assert.deepEqual(calls.shape, [T], "shape cached");
  assert.equal(calls.relay, 1, "relay cached within its TTL");
});

test("eligibility: relay null / pipe / passthrough / reserve:false / error → no expansion", async () => {
  for (const relay of [() => null, () => ({ ...PTY!, mode: "pipe" as const }), () => ({ ...PTY!, mode: "passthrough" as const }), () => ({ ...PTY!, reserve: false }), (): Relay => { throw new Error("down"); }]) {
    const { arbiter, calls } = arb({ relay, shape: () => ({ lines: 7 }) });
    const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s1" });
    assert.equal(await e.lines(T), null);
    assert.deepEqual(calls.shape, [], "no shape asked without a reserving relay");
  }
});

test("eligibility: kill switch, no session key, or an arbiter without the ops → impossible", async () => {
  const full = arb({ relay: () => PTY, shape: () => ({ lines: 7 }) }).arbiter;
  assert.equal(new ReserveEligibility(full, { enabled: false, sessionKey: "s1" }).possible, false);
  assert.equal(await new ReserveEligibility(full, { enabled: false, sessionKey: "s1" }).lines(T), null);
  assert.equal(new ReserveEligibility(full, { enabled: true }).possible, false);
  assert.equal(new ReserveEligibility(arb({ relay: () => PTY }).arbiter, { enabled: true, sessionKey: "s" }).possible, false);
  assert.equal(new ReserveEligibility(arb({ shape: () => ({ lines: 2 }) }).arbiter, { enabled: true, sessionKey: "s" }).possible, false);
});

test("eligibility: a symbolShape past the deadline, null or malformed → null, and is not cached", async () => {
  let slow = true;
  // The slow answer comes only when released, so a deadline timer a loaded
  // CI host runs late still ends the wait first (no wall-clock bound).
  let release = (): void => {};
  const held = new Promise<{ lines: number }>((r) => { release = () => r({ lines: 9 }); });
  const { arbiter, calls } = arb({
    relay: () => PTY,
    shape: (t) => (t === T && slow ? held : t === T ? { lines: 9 } : t.includes("bad") ? ({ lines: "x" } as unknown as { lines: number }) : null),
  });
  const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s1", timeoutMs: 30 });
  // The deadline's timer is unref'd; hold the loop open while the test waits.
  const keepAlive = setTimeout(() => {}, 60_000);
  try {
    assert.equal(await e.lines(T), null, "bounded by the deadline: null while the answer is still pending");
  } finally {
    clearTimeout(keepAlive);
  }
  release();
  slow = false;
  assert.equal(await e.lines(T), 9, "a timeout was not cached");
  assert.equal(await e.lines("$MDU:x[ffff]"), null);
  assert.equal(await e.lines("$MDU:bad[ffff]"), null);
  assert.equal(calls.shape.filter((t) => t === T).length, 2);
});

test("eligibility: the relay answer expires after its TTL; the shape cache is bounded", async () => {
  let now = 0;
  let relay: Relay = PTY;
  const { arbiter, calls } = arb({ relay: () => relay, shape: (t) => ({ lines: t.length }) });
  const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s1", relayTtlMs: 1000, shapeCacheMax: 2, now: () => now });
  assert.ok((await e.lines("$MDU:a[aaaa]")) !== null);
  relay = null;
  now = 999;
  assert.ok((await e.lines("$MDU:a[aaaa]")) !== null, "still cached");
  now = 1000;
  assert.equal(await e.lines("$MDU:a[aaaa]"), null, "re-read after the TTL");
  assert.equal(calls.relay, 2);
  relay = PTY;
  now = 5000;
  await e.lines("$MDU:b[bbbb]");
  await e.lines("$MDU:c[cccc]");
  await e.lines("$MDU:a[aaaa]"); // evicted (oldest) → asked again
  assert.equal(calls.shape.filter((t) => t === "$MDU:a[aaaa]").length, 2);
});

// ── v2 (§11.3-§11.5): wrapped rows, tokens inside a line ─────────────────────

const T_FIELD = "$MDU:inspect[695b].result";
const T_LONG1 = "$MDU:anymodel_Read[a1b2c3]";
/** Values by canonical token (what the arbiter would resolve). */
const VALUES = new Map<string, string>([
  [T, "Host bastion\n  HostName 10.9.8.7\n  User git\n  IdentityFile ~/.ssh/key\n"],
  [T_FIELD, "line one\nline two\n"],
  [T_LONG1, "k".repeat(200)], // one line that wraps
]);

interface ShapeCall { token: string; width: number; first: number; rule?: string }

function expanderV2(o: {
  cols?: number | null;
  values?: Map<string, string>;
  rowsAbsent?: boolean;
  cap?: number;
  seen?: ReserveExpansion[];
  calls?: ShapeCall[];
  lineCalls?: string[];
  codeSpan?: boolean;
  /** Answer `last` too (an arbiter with §14). */
  withLast?: boolean;
  /** The relay's wrap rule (§17). */
  rule?: "terminal";
} = {}): SseReserveExpander {
  const values = o.values ?? VALUES;
  const cols = o.cols === undefined ? 80 : o.cols;
  return new SseReserveExpander({
    lines: async (tok) => {
      o.lineCalls?.push(tok);
      const v = values.get(tok);
      return v === undefined ? null : layoutLines(v).length;
    },
    layout: async () => (cols === null ? null : o.rule ? { cols, rule: o.rule } : { cols }),
    shape: async (token, width, first, rule) => {
      o.calls?.push({ token, width, first, ...(rule !== undefined ? { rule } : {}) });
      const v = values.get(token);
      if (v === undefined) return null;
      const lines = layoutLines(v).length;
      if (o.rowsAbsent) return { lines };
      const laid = layoutRows(v, width, first, rule ?? "ink");
      return o.withLast ? { lines, rows: laid.length, last: layoutWidth(laid[laid.length - 1]!.text) } : { lines, rows: laid.length };
    },
    cap: o.cap ?? 40,
    onExpand: (e) => o.seen?.push(e),
    ...(o.codeSpan !== undefined ? { codeSpan: o.codeSpan } : {}),
  });
}

async function textOf(x: SseReserveExpander, text: string): Promise<string> {
  return deltaTexts(await run(x, [blockStart(), textDelta(text), blockStop()])).join("");
}
const b2 = (tok: string, n: number, width: number, first: number) => reserveBlock(tok, n, { width, first });

test("v2: a token inside a sentence expands with W:F; the suffix stays after the last row; collapse restores it", async () => {
  const seen: ReserveExpansion[] = [];
  const calls: ShapeCall[] = [];
  const text = `The value is ${T} and that is all.`;
  const out = await run(expanderV2({ seen, calls }), [MSG_START, blockStart(), textDelta(text), blockStop(), MSG_STOP]);
  const texts = deltaTexts(out);
  const want = `The value is ${b2(T, 4, 78, 65)} and that is all.`;
  assert.equal(texts.join(""), want);
  assert.ok(texts.some((t) => t.includes(b2(T, 4, 78, 65))), "the block rides in one delta");
  assert.equal(collapseText(want), text);
  assert.deepEqual(calls, [{ token: T, width: 78, first: 65 }]);
  assert.deepEqual(seen, [{ index: 0, token: T, hash: "464e", rows: 4, width: 78, first: 65 }]);
});

test("v2: a one-line value that wraps now expands (standalone F = W); a value that fits one row does not", async () => {
  assert.equal(await textOf(expanderV2(), `${T_LONG1}\n`), `${b2(T_LONG1, 3, 78, 78)}\n`, "200 columns at W = 78: 3 rows");
  assert.equal(await textOf(expanderV2({ cols: 240 }), `${T_LONG1}\n`), `${T_LONG1}\n`, "fits in one row at W = 238: no block");
  assert.equal(await textOf(expanderV2(), `a ${T_LONG1} b`), `a ${b2(T_LONG1, 3, 78, 76)} b`);
});

test("v2: every split offset, mid-line and standalone tokens, suffixes, the block end, a field path", async () => {
  const cases = [
    `The value is ${T} and that is all.`,
    `The value is ${T}`,
    `Key: **${T}** done.`,
    `field ${T_FIELD}, ok`,
    `Line one\n- item ${T}.\n${T}\nend`,
    `"${T_FIELD}"`,
    `x ${T}y and ${T}$5 then ${T}`,
    `a ${T} b ${T} c`,
  ];
  for (const text of cases) {
    const expected = await textOf(expanderV2(), text);
    assert.equal(collapseText(expected), text, JSON.stringify(text));
    const step = Math.max(1, Math.floor(text.length / 9));
    for (let i = 0; i <= text.length; i++) {
      for (let j = i; j <= text.length; j += step) {
        const parts = [text.slice(0, i), text.slice(i, j), text.slice(j)];
        const rp = new SseTextDeltaRepacker();
        let sse = rp.feed(blockStart());
        for (const p of parts) sse += rp.feed(textDelta(p));
        sse += rp.feed(blockStop()) + rp.end();
        const texts = deltaTexts(await run(expanderV2(), [sse]));
        assert.equal(texts.join(""), expected, `${JSON.stringify(text)} @${i},${j}`);
        for (const blk of expected.match(/\$MDU:[^\s]*?\/1:[0-9:]+(?:\n\$MDU\/[0-9a-f]+\/[0-9]+)+/g) ?? []) {
          assert.ok(texts.some((t) => t.includes(blk)), `${JSON.stringify(text)} @${i},${j}: block split: ${JSON.stringify(texts)}`);
        }
        const bare = await run(expanderV2(), [blockStart(), ...parts.map((p) => textDelta(p)), blockStop()]);
        assert.equal(deltaTexts(bare).join(""), expected, `no repacker ${JSON.stringify(text)} @${i},${j}`);
      }
    }
    const sse = blockStart() + textDelta(text) + blockStop();
    const x = expanderV2();
    let out = "";
    for (const ch of sse) out += await x.feed(ch);
    out += x.end();
    assert.equal(deltaTexts(out).join(""), expected, `bytewise ${JSON.stringify(text)}`);
  }
});

test("v2: the expected expansions for the split cases", async () => {
  const exp = (t: string) => textOf(expanderV2(), t);
  assert.equal(await exp(`The value is ${T}`), `The value is ${b2(T, 4, 78, 65)}`, "the token ends the block: the line end follows");
  assert.equal(await exp(`Key: **${T}** done.`), `Key: **${b2(T, 4, 78, 71)}** done.`);
  assert.equal(await exp(`field ${T_FIELD}, ok`), `field ${b2(T_FIELD, 2, 78, 72)}, ok`, "a field path is part of the token");
  assert.equal(
    await exp(`Line one\n- item ${T}.\n${T}\nend`),
    `Line one\n- item ${b2(T, 4, 76, 71)}.\n${b2(T, 4, 76, 76)}\nend`,
    "list indent 2 → W = 76, inherited by the next line",
  );
  assert.equal(await exp(`x ${T}y and ${T}$5 then ${T}`), `x ${T}y and ${T}$5 then ${b2(T, 5, 78, 0)}`,
    "`y` and `$` after: not expanded; the third has other tokens before it → F = 0 (an empty head row: 1 + 4 rows)");
  assert.equal(await exp(`a ${T} b ${T} c`), `a ${b2(T, 4, 78, 76)} b ${T} c`, "one block per line");
});

test("v2: the F = 0 clamp and the head on its own row reach the arbiter as (W, F)", async () => {
  const calls: ShapeCall[] = [];
  const x = expanderV2({ calls });
  const clamp = `${"x".repeat(39)} ${T} end`; // p = 40 → F = 38 < 39 → 0
  const own = `${"x".repeat(49)} ${T} end`; // p = 50: even the narrowest head passes 78
  assert.equal(await textOf(x, `${clamp}\n${own}`), `${"x".repeat(39)} ${b2(T, 5, 78, 0)} end\n${"x".repeat(49)} ${b2(T, 4, 78, 78)} end`);
  assert.deepEqual(calls, [{ token: T, width: 78, first: 0 }, { token: T, width: 78, first: 78 }]);
});

test("v2: fences — a standalone token gets a v1 head, a mid-line token none; after the fence, v2 again", async () => {
  const calls: ShapeCall[] = [];
  const lineCalls: string[] = [];
  const text = "```\n" + `${T}\nsee ${T} here\n` + "```\n" + `${T}\n`;
  assert.equal(
    await textOf(expanderV2({ calls, lineCalls }), text),
    "```\n" + `${reserveBlock(T, 4)}\nsee ${T} here\n` + "```\n" + `${b2(T, 4, 78, 78)}\n`,
  );
  assert.deepEqual(lineCalls, [T]);
  assert.deepEqual(calls, [{ token: T, width: 78, first: 78 }]);
});

test("v2 falls back to v1: a relay without wrap/cols is byte-identical to the v1 expander", async () => {
  const cases = [`Here:\n${T}\nafter`, `mid ${T} sentence\n${T}`, `The value is ${T}.`, `${T_ESC}\n`, `$5 and \\ and ${T}`];
  for (const text of cases) {
    for (const cut of [0, 3, Math.floor(text.length / 2), text.length - 1]) {
      const input = [MSG_START, blockStart(), textDelta(text.slice(0, cut)), textDelta(text.slice(cut)), blockStop(), MSG_STOP];
      const v1 = await run(expander(), input);
      const noWrap = await run(expanderV2({ cols: null, values: new Map([[T, "a\nb\nc\nd"]]) }), input);
      assert.equal(noWrap, v1, `${JSON.stringify(text)} @${cut}`);
    }
  }
});

test("v2 with an arbiter predating rows: standalone → a v1 head by lines; mid-line → none", async () => {
  const x = () => expanderV2({ rowsAbsent: true });
  assert.equal(await textOf(x(), `${T}\n`), `${reserveBlock(T, 4)}\n`);
  assert.equal(await textOf(x(), `The value is ${T}.`), `The value is ${T}.`);
});

test("v2: a held mid-line token is released unexpanded, in order, on a non-text delta, message_stop and the stream end", async () => {
  const cit = sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "citations_delta", citation: {} } });
  const a = await run(expanderV2(), [blockStart(), textDelta(`see ${T}`), cit, textDelta(" ok"), blockStop()]);
  assert.equal(deltaTexts(a).join(""), `see ${T} ok`, "the context moves on; the released token is not expanded later");
  const types = events(a).map((e) => (e["delta"] as Ev | undefined)?.["type"] ?? e["type"]);
  assert.deepEqual(types, ["content_block_start", "text_delta", "text_delta", "citations_delta", "text_delta", "content_block_stop"]);
  const b = await run(expanderV2(), [blockStart(), textDelta(`see ${T}`), MSG_STOP]);
  assert.equal(deltaTexts(b).join(""), `see ${T}`);
  assert.ok(b.indexOf("message_stop") > b.lastIndexOf(T));
  const c = await run(expanderV2(), [blockStart(), textDelta(`see ${T}`)]);
  assert.equal(deltaTexts(c).join(""), `see ${T}`);
});

test("v2: an untouched delta relays byte-verbatim; the relay is asked only once a token may appear", async () => {
  let asked = 0;
  const x = new SseReserveExpander({
    lines: async () => null,
    layout: async () => { asked++; return { cols: 80 }; },
    shape: async () => null,
    cap: 40,
  });
  const raw = textDelta("plain prose, no symbols at all\n");
  const out1 = await x.feed(blockStart() + raw);
  assert.ok(out1.includes(raw));
  assert.equal(asked, 0, "no possible token yet: no relay call");
  const raw2 = textDelta(`the key ${T}. ok\n`);
  const out2 = await x.feed(raw2);
  assert.ok(out2.includes(raw2), "a token the arbiter does not know: the delta is byte-verbatim");
  await x.feed(textDelta(`and ${T}.\n`));
  assert.equal(asked, 1, "the mode is fixed per stream");
});

test("v2 property: the streaming expander's output always collapses back to the model's text", async () => {
  const r = rng(0x77aa);
  const pick = <X>(xs: readonly X[]): X => xs[Math.floor(r() * xs.length)]!;
  const toks = [T, T_ESC, T_FIELD, T_LONG1, "$MDU:unknown[beef]"];
  const words = ["the", "key", "**", "`", "(", ")", "[", "]", "|", "#", "> ", "- ", "1. ", "```", "", "é", "🔑", "$5", "\\"];
  const values = new Map(VALUES);
  values.set(T_ESC.replace(/\\/g, ""), VALUES.get(T)!);
  let expanded = 0;
  for (let i = 0; i < 300; i++) {
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
    const cut1 = Math.floor(r() * (text.length + 1));
    const cut2 = cut1 + Math.floor(r() * (text.length - cut1 + 1));
    const out = await run(expanderV2({ cols, values }), [blockStart(), textDelta(text.slice(0, cut1)), textDelta(text.slice(cut1, cut2)), textDelta(text.slice(cut2)), blockStop()]);
    const joined = deltaTexts(out).join("");
    if (joined !== text) expanded++;
    assert.equal(collapseText(joined), text, `case ${i}: ${JSON.stringify(text)}`);
    assert.equal(joined, await textOf(expanderV2({ cols, values }), text), `case ${i}: split-invariant`);
  }
  assert.ok(expanded > 100, `the generator must exercise expansion (${expanded})`);
});

// ── eligibility, v2 ──────────────────────────────────────────────────────────

type Relay2 = { mode: "pty" | "pipe" | "passthrough"; reserve: boolean; cols?: number; wrap?: boolean; rule?: string; updatedAt: number } | null;
type Opts2 = { width: number; first: number; rule?: "ink" | "terminal" };

function arb2(relay: () => Relay2, shape: (t: string, o?: Opts2) => { lines: number; rows?: number } | null) {
  const calls: Array<[string, Opts2 | undefined]> = [];
  return {
    calls,
    arbiter: {
      sessionRelay: async () => relay(),
      symbolShape: async (t: string, o?: Opts2) => { calls.push([t, o]); return shape(t, o); },
    },
  };
}

test("eligibility v2: layout only for a PTY relay that reserves AND reports wrap with integer cols", async () => {
  const base = { mode: "pty" as const, reserve: true, updatedAt: 1 };
  const layout = async (relay: Relay2) => new ReserveEligibility(arb2(() => relay, () => null).arbiter, { enabled: true, sessionKey: "s" }).layout();
  assert.deepEqual(await layout({ ...base, cols: 80, wrap: true }), { cols: 80 });
  assert.equal(await layout({ ...base, cols: 80 }), null, "a v1 filter (no wrap)");
  assert.equal(await layout({ ...base, cols: 80, wrap: false }), null);
  assert.equal(await layout({ ...base, wrap: true }), null, "no cols");
  assert.equal(await layout({ ...base, cols: 80.5, wrap: true }), null);
  assert.equal(await layout({ ...base, cols: 0, wrap: true }), null);
  assert.equal(await layout({ ...base, reserve: false, cols: 80, wrap: true }), null);
  assert.equal(await layout({ ...base, mode: "pipe", cols: 80, wrap: true }), null);
  assert.equal(await layout(null), null);
});

test("eligibility v2: shape passes {width, first}, caches per (token, width, first), drops malformed rows", async () => {
  const relay: Relay2 = { mode: "pty", reserve: true, cols: 80, wrap: true, updatedAt: 1 };
  const { arbiter, calls } = arb2(() => relay, (t, o) => (t.includes("bad") ? { lines: 2, rows: -1 } : o ? { lines: 2, rows: o.first === 0 ? 4 : 3 } : { lines: 2 }));
  const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s" });
  assert.deepEqual(await e.shape(T, 78, 78), { lines: 2, rows: 3 });
  assert.deepEqual(await e.shape(T, 78, 78), { lines: 2, rows: 3 });
  assert.deepEqual(await e.shape(T, 78, 0), { lines: 2, rows: 4 }, "a different F is a different key");
  assert.deepEqual(await e.shape(T, 76, 76), { lines: 2, rows: 3 });
  assert.equal(await e.lines(T), 2, "the lines-only call is its own entry");
  assert.deepEqual(await e.shape("$MDU:bad[beef]", 78, 78), { lines: 2 }, "malformed rows: as an arbiter without rows");
  assert.deepEqual(calls, [
    [T, { width: 78, first: 78 }], [T, { width: 78, first: 0 }], [T, { width: 76, first: 76 }], [T, undefined],
    ["$MDU:bad[beef]", { width: 78, first: 78 }],
  ]);
  const off = new ReserveEligibility(arb2(() => ({ ...relay!, mode: "pipe" }), () => ({ lines: 2, rows: 3 })).arbiter, { enabled: true, sessionKey: "s" });
  assert.equal(await off.shape(T, 78, 78), null, "no reserving relay: no shape");
});

test("span form (§12): a token that is a whole code span, every split offset; off by default", async () => {
  const text = `The value of API_KEY in \`.env\` is \`${T}\`, and that is all.`;
  const want = `The value of API_KEY in \`.env\` is \`${reserveBlock(T, 4, { width: 78, first: 44 }, true)}\`, and that is all.`;
  const seen: ReserveExpansion[] = [];
  assert.equal(await textOf(expanderV2({ codeSpan: true, seen }), text), want);
  assert.equal(collapseText(want), text);
  assert.deepEqual(seen, [{ index: 0, token: T, hash: "464e", rows: 4, width: 78, first: 44 }]);
  assert.equal(await textOf(expanderV2(), text), text, "codeSpan off (Codex): never inside a span");
  assert.equal(await textOf(expanderV2({ codeSpan: false }), text), text);
  assert.equal(await textOf(expanderV2({ codeSpan: true }), `run \`echo ${T}\` now`), `run \`echo ${T}\` now`, "not the whole span");
  const block = reserveBlock(T, 4, { width: 78, first: 44 }, true);
  for (let i = 0; i <= text.length; i++) {
    const rp = new SseTextDeltaRepacker();
    const sse = rp.feed(blockStart()) + rp.feed(textDelta(text.slice(0, i))) + rp.feed(textDelta(text.slice(i))) + rp.feed(blockStop()) + rp.end();
    const texts = deltaTexts(await run(expanderV2({ codeSpan: true }), [sse]));
    assert.equal(texts.join(""), want, `@${i}`);
    assert.ok(texts.some((t) => t.includes(block)), `@${i}: the block rides in one delta`);
  }
});

// ── §14: the line hold, the break, the table row ─────────────────────────────

test("§14 hold: a line holding a token waits for its end; text before the token goes out at once", async () => {
  const x = expanderV2({ withLast: true });
  let out = await x.feed(MSG_START + blockStart() + textDelta("Intro line.\nThe value is "));
  assert.equal(deltaTexts(out).join(""), "Intro line.\nThe value is ");
  out = await x.feed(textDelta(`${T} and that`));
  assert.equal(deltaTexts(out).join(""), "", "the token and the rest of its line are held");
  out = await x.feed(textDelta(" is all.\nNext line"));
  assert.equal(deltaTexts(out).join(""), `${b2(T, 4, 78, 65)} and that is all.\nNext line`, "released whole at the line end");
  out = await x.feed(blockStop() + MSG_STOP);
  assert.equal(deltaTexts(out).join(""), "");
});

test("§14 break: text after a mid-line block that would clip gets ONE line break where vanilla wraps; collapse removes it", async () => {
  const suffix = " and that is all, and the rest of this sentence runs on.";
  const text = `The value is ${T_LONG1}${suffix}\nDONE`;
  const F = 78 - "The value is ".length;
  const laid = layoutRows(VALUES.get(T_LONG1)!, 78, F);
  const last = layoutWidth(laid[laid.length - 1]!.text);
  const k = suffixBreak({ suffix, last, marker: layoutWidth(`$MDU/a1b2c3/${laid.length}`), width: 78, lineTicks: 0 })!;
  assert.ok(k !== null && k > 1, "precondition: the text needs a break");
  const block = reserveBlock(T_LONG1, laid.length, { width: 78, first: F }, false, k);
  const want = `The value is ${block}${suffix.slice(0, k)}\n${suffix.slice(k)}\nDONE`;
  assert.equal(await textOf(expanderV2({ withLast: true }), text), want);
  assert.equal(collapseText(want), text);
  // The row after the value: its last row, then the text up to the break, fits W.
  assert.ok(last + layoutWidth(suffix.slice(0, k).trimEnd()) <= 78);
  // An arbiter without `last`: no break (the old behavior).
  assert.equal(await textOf(expanderV2(), text), `The value is ${reserveBlock(T_LONG1, laid.length, { width: 78, first: F })}${suffix}\nDONE`);
  // Every split offset, through the repacker: the same text.
  for (let i = 0; i <= text.length; i += 3) {
    const rp = new SseTextDeltaRepacker();
    const sse = rp.feed(blockStart()) + rp.feed(textDelta(text.slice(0, i))) + rp.feed(textDelta(text.slice(i))) + rp.feed(blockStop()) + rp.end();
    assert.equal(deltaTexts(await run(expanderV2({ withLast: true }), [sse])).join(""), want, `@${i}`);
  }
});

test("§14 table row: a token in the first cell (no leading `|`) is not expanded", async () => {
  for (const text of [`${T} | the ssh config |\n--- | --- |\n`, `| ${T} | x |\n`, `key: ${T} | x\n`]) {
    assert.equal(await textOf(expanderV2({ withLast: true }), text), text, JSON.stringify(text));
  }
  assert.equal(await textOf(expanderV2({ withLast: true }), `${T}\n| a | b |\n`), `${b2(T, 4, 78, 78)}\n| a | b |\n`,
    "a table on another line does not stop a standalone token");
});

test("§14 head-only: a value that fits its row but pushes the text after it past the edge gets `T/1:1:W:F:K`", async () => {
  const short = "Q".repeat(94); // fits the head row at 160 columns (F = 145)
  const values = new Map([[T, short]]);
  const suffix = " and that is all, so the rest of this sentence wraps onto the next row.";
  const text = `The value is ${T}${suffix}\nDONE`;
  const F = 158 - "The value is ".length;
  const out = await textOf(expanderV2({ withLast: true, values, cols: 160 }), text);
  const m = /\/1:1:158:(\d+):(\d+)/.exec(out);
  assert.ok(m, `a head-only block: ${out}`);
  assert.equal(Number(m![1]), F);
  const k = Number(m![2]);
  assert.equal(out, `The value is ${T}/1:1:158:${F}:${k}${suffix.slice(0, k)}\n${suffix.slice(k)}\nDONE`);
  assert.ok(13 + 94 + layoutWidth(suffix.slice(0, k).trimEnd()) <= 158, "the value's row, with the text up to the break, fits");
  assert.equal(collapseText(out), text);
  // A short tail fits: the token stays as it is (the one-row splice).
  assert.equal(await textOf(expanderV2({ withLast: true, values, cols: 160 }), `The value is ${T} ok.\n`), `The value is ${T} ok.\n`);
  // No `last` from the arbiter: nothing.
  assert.equal(await textOf(expanderV2({ values, cols: 160 }), text), text);
});

// ── §17: the `terminal` rule (Goose) ─────────────────────────────────────────

/** The Goose lane's values (differential-interactive.md §32). */
const SEGS = (p: string, n: number) => Array.from({ length: n }, (_, i) => `${p}${String(i + 1).padStart(2, "0")}`).join(" ");
const G_WRAP = `DIFFWRAP_A short\nDIFFWRAP_LONG ${SEGS("SEGW", 14)}\nDIFFWRAP_C end\n`;
const G_INLINE = `DIFFINLINE ${SEGS("SEGI", 12)}`;

test("§17 terminal: a standalone value is laid out at the full width by character wrap, and the arbiter is asked so", async () => {
  const calls: ShapeCall[] = [];
  const values = new Map([[T, G_WRAP]]);
  const out = await textOf(expanderV2({ values, rule: "terminal", calls }), `File content follows:\n${T}\nDONE`);
  // 4 rows at W = 80 (ink at 78 is 4 rows too: the count agrees, the break does not).
  assert.equal(out, `File content follows:\n${b2(T, 4, 80, 80)}\nDONE`);
  assert.deepEqual(calls, [{ token: T, width: 80, first: 80, rule: "terminal" }]);
  assert.equal(layoutRows(G_WRAP, 80, 80, "terminal")[1]!.text.endsWith(" SEG"), true, "the row the filter paints breaks mid-word");
});

test("§17 terminal: a mid-line value takes F = 80 − its raw column; the suffix breaks where the row is full; collapse restores it", async () => {
  const values = new Map([[T, G_INLINE]]);
  const suffix = " and that is all, so the rest of this sentence wraps onto the next row.";
  const text = `The value is ${T}${suffix}\nDONE`;
  const laid = layoutRows(G_INLINE, 80, 67, "terminal");
  assert.equal(laid.length, 2);
  const last = layoutWidth(laid[1]!.text);
  const k = 80 - last; // the characters that fill the row, mid-word
  const want = `The value is ${reserveBlock(T, 2, { width: 80, first: 67 }, false, k)}${suffix.slice(0, k)}\n${suffix.slice(k)}\nDONE`;
  assert.equal(await textOf(expanderV2({ values, rule: "terminal", withLast: true }), text), want);
  assert.equal(collapseText(want), text);
  for (let i = 0; i <= text.length; i += 5) {
    const rp = new SseTextDeltaRepacker();
    const sse = rp.feed(blockStart()) + rp.feed(textDelta(text.slice(0, i))) + rp.feed(textDelta(text.slice(i))) + rp.feed(blockStop()) + rp.end();
    assert.equal(deltaTexts(await run(expanderV2({ values, rule: "terminal", withLast: true }), [sse])).join(""), want, `@${i}`);
  }
});

test("§17 terminal: a code span is text — the plain mid-line form, never the span form, even with codeSpan on", async () => {
  const values = new Map([[T, `DIFFSPAN ${SEGS("SEGK", 12)}`]]);
  const text = `The value is \`${T}\`, and that is all.\n`;
  const out = await textOf(expanderV2({ values, rule: "terminal", codeSpan: true, withLast: true }), text);
  assert.equal(out, `The value is \`${reserveBlock(T, 2, { width: 80, first: 66 })}\`, and that is all.\n`);
  assert.ok(!out.includes("`\n`"), "no span separator: Goose would draw its backticks");
  assert.equal(collapseText(out), text);
});

test("§17 terminal: no head-only block — a one-row value's suffix wraps by itself", async () => {
  const values = new Map([[T, "Q".repeat(60)]]);
  const text = `The value is ${T} and that is all, so the rest of this sentence wraps onto the next row.\n`;
  assert.equal(await textOf(expanderV2({ values, rule: "terminal", withLast: true }), text), text);
});

test("§17 eligibility: the relay's rule rides with layout; shape passes it and caches per rule; anything else is ink", async () => {
  const base = { mode: "pty" as const, reserve: true, cols: 80, wrap: true, updatedAt: 1 };
  const layout = async (relay: Relay2) => new ReserveEligibility(arb2(() => relay, () => null).arbiter, { enabled: true, sessionKey: "s" }).layout();
  assert.deepEqual(await layout({ ...base, rule: "terminal" }), { cols: 80, rule: "terminal" });
  assert.deepEqual(await layout({ ...base, rule: "ink" }), { cols: 80 });
  assert.deepEqual(await layout({ ...base, rule: "char" }), { cols: 80 }, "an unknown rule is read as ink");
  assert.equal(await layout({ ...base, wrap: false, rule: "terminal" }), null, "no v2 without wrap, whatever the rule");
  const { arbiter, calls } = arb2(() => ({ ...base, rule: "terminal" }), (_t, o) => (o ? { lines: 1, rows: o.rule === "terminal" ? 2 : 3 } : { lines: 1 }));
  const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s" });
  assert.deepEqual(await e.shape(T, 80, 80, "terminal"), { lines: 1, rows: 2 });
  assert.deepEqual(await e.shape(T, 80, 80, "terminal"), { lines: 1, rows: 2 });
  assert.deepEqual(await e.shape(T, 80, 80), { lines: 1, rows: 3 }, "ink is its own cache entry");
  assert.deepEqual(calls, [[T, { width: 80, first: 80, rule: "terminal" }], [T, { width: 80, first: 80 }]]);
});

// ── §11.2: the TAB stops, the content area's column ──────────────────────────

test("§11.2 indent: the expander asks the arbiter with cols − W (2, 4 in a list item, 0 under the terminal rule)", async () => {
  const TSV = "$MDU:nomodel_Read[7ab5]";
  const tsv = "name\tport\towner\nweb\t8080\talice\n";
  const run1 = async (text: string, rule?: "terminal"): Promise<Array<{ width: number; first: number; indent?: number }>> => {
    const seen: Array<{ width: number; first: number; indent?: number }> = [];
    const x = new SseReserveExpander({
      lines: async () => 2,
      layout: async () => (rule ? { cols: 80, rule } : { cols: 80 }),
      shape: async (_t, width, first, r, indent) => {
        seen.push({ width, first, ...(indent !== undefined ? { indent } : {}) });
        return { lines: 2, rows: layoutRows(tsv, width, first, r ?? "ink", indent).length };
      },
      cap: 40,
    });
    await textOf(x, text);
    return seen;
  };
  assert.deepEqual(await run1(`${TSV}\n`), [{ width: 78, first: 78, indent: 2 }], "a reply's text starts at column 2");
  assert.deepEqual(await run1(`- ${TSV}\n`), [{ width: 76, first: 76, indent: 4 }], "a list item's at column 4");
  assert.deepEqual(await run1(`The table is ${TSV}\n`), [{ width: 78, first: 65, indent: 2 }], "mid-line: the indent is the area's, F places the head");
  assert.deepEqual(await run1(`${TSV}\n`, "terminal"), [{ width: 80, first: 80, indent: 0 }], "Goose prints at column 0");
});

test("§11.2 indent: eligibility passes `indent` to symbolShape only when it moves a stop, and caches per indent", async () => {
  const relay: Relay2 = { mode: "pty", reserve: true, cols: 80, wrap: true, updatedAt: 1 };
  type Opts3 = Opts2 & { indent?: number };
  const calls: Array<[string, Opts3 | undefined]> = [];
  const arbiter = {
    sessionRelay: async () => relay,
    symbolShape: async (t: string, o?: Opts3) => { calls.push([t, o]); return { lines: 2, rows: o?.indent === 2 ? 2 : 3 }; },
  };
  const e = new ReserveEligibility(arbiter, { enabled: true, sessionKey: "s" });
  assert.deepEqual(await e.shape(T, 78, 78, undefined, 2), { lines: 2, rows: 2 });
  assert.deepEqual(await e.shape(T, 78, 78, undefined, 2), { lines: 2, rows: 2 }, "cached");
  assert.deepEqual(await e.shape(T, 78, 78, undefined, 0), { lines: 2, rows: 3 }, "indent 0 is its own entry, sent without the key");
  assert.deepEqual(await e.shape(T, 78, 78), { lines: 2, rows: 3 }, "absent is indent 0: the same entry");
  await e.shape(T, 80, 80, "terminal", 0);
  assert.deepEqual(calls, [
    [T, { width: 78, first: 78, indent: 2 }], [T, { width: 78, first: 78 }], [T, { width: 80, first: 80, rule: "terminal" }],
  ]);
});
