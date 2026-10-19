/**
 * sse-text-repack.test — unit tests for the text_delta token repacker
 * (src/sse-text-repack.ts): a `$MDU:` token must never be split across
 * content_block_delta events, while the concatenated text stays
 * byte-identical and every non-text event relays verbatim, in order.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SseTextDeltaRepacker } from "../../src/sse-text-repack.js";
import { danglingTokenStart, REPACK_HOLD_CAP } from "../../src/text-repack.js";
import { sseEvent } from "../helpers/mock-upstream.js";

const TOKEN = "$MDU:inspect[695b].result";

function textDelta(text: string, index = 0): string {
  return sseEvent("content_block_delta", {
    type: "content_block_delta",
    index,
    delta: { type: "text_delta", text },
  });
}
function blockStart(index = 0): string {
  return sseEvent("content_block_start", {
    type: "content_block_start",
    index,
    content_block: { type: "text", text: "" },
  });
}
function blockStop(index = 0): string {
  return sseEvent("content_block_stop", { type: "content_block_stop", index });
}

/** Parse the text_delta texts (in order) out of a relayed SSE byte string. */
function deltaTexts(sse: string): string[] {
  const texts: string[] = [];
  for (const frame of sse.split(/\n\n/)) {
    const line = frame.split(/\r?\n/).find((l) => l.startsWith("data:"));
    if (!line) continue;
    try {
      const d = JSON.parse(line.slice(5)) as { type?: string; delta?: { type?: string; text?: string } };
      if (d.type === "content_block_delta" && d.delta?.type === "text_delta" && typeof d.delta.text === "string") {
        texts.push(d.delta.text);
      }
    } catch {
      /* non-JSON */
    }
  }
  return texts;
}

// ── danglingTokenStart ────────────────────────────────────────────────────────

test("danglingTokenStart: growing prefixes and complete-but-extensible tokens dangle", () => {
  for (const s of ["x $", "x $M", "x $MD", "x $MDU", "x $MDU:", "x $MDU:insp", "x $MDU:inspect[695b]", `x ${TOKEN}`]) {
    assert.equal(danglingTokenStart(s), 2, `should dangle at 2: ${JSON.stringify(s)}`);
  }
  // Markdown-escaped spelling: the backslash travels with its token.
  assert.equal(danglingTokenStart("x \\$MDU:web\\_fe"), 2);
  assert.equal(danglingTokenStart("x \\$MDU:web\\"), 2, "an escape inside the token keeps the token's start");
  // A lone trailing escape may be the `\` of a `\$MDU:` in the next delta.
  assert.equal(danglingTokenStart("x \\"), 2);
  assert.equal(danglingTokenStart("C:\\\\"), 4, "an escaped backslash is not a token start");
});

test("danglingTokenStart: ordinary text never dangles", () => {
  for (const s of ["plain prose", "total: $5.00", "$HOME is set", `${TOKEN} times on x.io.`, "x $MDX", "x $MX", "x $D"]) {
    assert.equal(danglingTokenStart(s), s.length, `should not dangle: ${JSON.stringify(s)}`);
  }
  // A suffix longer than any real token is prose, not a candidate.
  assert.equal(danglingTokenStart("$MDU:" + "a".repeat(REPACK_HOLD_CAP)), REPACK_HOLD_CAP + "$MDU:".length);
});

// ── repacking ─────────────────────────────────────────────────────────────────

test("the ']'↔'.field' seam split (live leak 1783831380) re-emits the token WHOLE", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(blockStart());
  out += r.feed(textDelta('The word "security" appears $MDU:inspect[695b]'));
  out += r.feed(textDelta(".result times on homepage.example.test."));
  out += r.feed(blockStop());
  const texts = deltaTexts(out);
  assert.equal(texts.join(""), `The word "security" appears ${TOKEN} times on homepage.example.test.`);
  assert.ok(texts.some((t) => t.includes(TOKEN)), "the token arrives whole in one delta");
  for (const t of texts) assert.doesNotMatch(t, /\$MDU:[a-zA-Z0-9_[\].]*$/, `dangling: ${JSON.stringify(t)}`);
});

test("a token split across THREE deltas (mid-hash) reassembles into one delta", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(textDelta("count: $MDU:insp"));
  out += r.feed(textDelta("ect[69"));
  out += r.feed(textDelta("5b].result done"));
  const texts = deltaTexts(out);
  assert.equal(texts.join(""), `count: ${TOKEN} done`);
  assert.ok(texts.some((t) => t.includes(TOKEN)));
});

test("a held suffix flushes as its own text_delta BEFORE the block's stop", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(textDelta(`reply ends with ${TOKEN}`)); // dangles (extensible)
  out += r.feed(blockStop());
  const stopAt = out.indexOf("content_block_stop");
  const tokenAt = out.indexOf(TOKEN);
  assert.ok(tokenAt >= 0 && tokenAt < stopAt, "held token released before the stop event");
  assert.equal(deltaTexts(out).join(""), `reply ends with ${TOKEN}`);
});

test("pings and message_delta relay verbatim while a suffix is held", () => {
  const r = new SseTextDeltaRepacker();
  const ping = sseEvent("ping", { type: "ping" });
  let out = "";
  out += r.feed(textDelta("x $MDU:inspect[695b]"));
  out += r.feed(ping);
  out += r.feed(textDelta(".result y"));
  assert.ok(out.includes(ping), "ping relayed while holding");
  assert.equal(deltaTexts(out).join(""), `x ${TOKEN} y`);
  assert.ok(deltaTexts(out).some((t) => t.includes(TOKEN)));
});

test("ordinary '$'-prose moves across the boundary byte-identically (no token, no loss)", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(textDelta("total: $"));
  out += r.feed(textDelta("5.00 exactly"));
  out += r.feed(blockStop());
  assert.equal(deltaTexts(out).join(""), "total: $5.00 exactly");
});

test("token-free deltas take the byte-verbatim fast path", () => {
  const r = new SseTextDeltaRepacker();
  const stream = blockStart() + textDelta("hello ") + textDelta("world") + blockStop();
  assert.equal(r.feed(stream) + r.end(), stream, "bytes pass through unchanged");
});

test("SSE frames split across feed() chunks reassemble identically", () => {
  const stream =
    blockStart() +
    textDelta("appears $MDU:inspect[695b]") +
    textDelta(".result times") +
    blockStop() +
    sseEvent("message_stop", { type: "message_stop" });
  const whole = new SseTextDeltaRepacker();
  const wholeOut = whole.feed(stream) + whole.end();
  for (const size of [1, 3, 7, 16]) {
    const r = new SseTextDeltaRepacker();
    let out = "";
    for (let i = 0; i < stream.length; i += size) out += r.feed(stream.slice(i, i + size));
    out += r.end();
    assert.equal(out, wholeOut, `chunk=${size} output differs`);
    assert.ok(deltaTexts(out).some((t) => t.includes(TOKEN)));
  }
});

test("message_stop and end() flush held suffixes — bytes are never swallowed", () => {
  const r1 = new SseTextDeltaRepacker();
  let out1 = "";
  out1 += r1.feed(textDelta("tail: $MDU:inspect[695b]"));
  out1 += r1.feed(sseEvent("message_stop", { type: "message_stop" }));
  assert.equal(deltaTexts(out1).join(""), "tail: $MDU:inspect[695b]");
  const stopAt = out1.indexOf("message_stop");
  assert.ok(out1.indexOf("$MDU:") < stopAt, "flushed before message_stop");

  const r2 = new SseTextDeltaRepacker();
  let out2 = "";
  out2 += r2.feed(textDelta("cut: $MDU:in"));
  out2 += r2.feed("event: partial\ndata: {"); // truncated frame
  out2 += r2.end();
  assert.ok(out2.includes("cut: ") && out2.includes("$MDU:in"), "held text released");
  assert.ok(out2.endsWith("event: partial\ndata: {"), "partial trailing frame released verbatim");
});

test("independent blocks hold independently (per-index state)", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(textDelta("a $MDU:inspect[695b]", 0));
  out += r.feed(textDelta("b plain", 1));
  out += r.feed(textDelta(".result c", 0));
  const texts = deltaTexts(out);
  assert.deepEqual(texts, ["a ", "b plain", `${TOKEN} c`], "block 1 relays untouched; block 0 reassembles");
});

test("a Markdown-ESCAPED token split at the seam reassembles", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(textDelta("see \\$MDU:web\\_fetch[a1b2]"));
  out += r.feed(textDelta(".text now"));
  const texts = deltaTexts(out);
  assert.equal(texts.join(""), "see \\$MDU:web\\_fetch[a1b2].text now");
  assert.ok(texts.some((t) => t.includes("\\$MDU:web\\_fetch[a1b2].text")));
});

test("a Markdown-ESCAPED token split between its escape and its `$` reassembles", () => {
  const r = new SseTextDeltaRepacker();
  let out = "";
  out += r.feed(textDelta("see \\"));
  out += r.feed(textDelta("$MDU:web\\_fetch[a1b2] now"));
  out += r.feed(blockStop());
  const texts = deltaTexts(out);
  assert.equal(texts.join(""), "see \\$MDU:web\\_fetch[a1b2] now");
  assert.ok(texts.some((t) => t.includes("\\$MDU:web\\_fetch[a1b2]")), JSON.stringify(texts));
});
