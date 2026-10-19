/**
 * reserve-block.test — unit tests for the reply filter's reserve-block
 * recognizer (src/reserve-block.ts; docs/design/ui/reply-row-reservation.md
 * §3.1, §3.2, §3.6, §3.7): the grammar, the per-row text (line i, the cap
 * row, the no-value head), the session cache, and the relay report. Pure: no
 * arbiter, no pty. Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SYMBOL_TOKEN_RE, couldBeSymbolPrefix } from "../../src/filter.js";
import {
  TOKEN_SOURCE,
  RESERVE_CACHE_MAX,
  RESERVE_MAX_ROWS_DEFAULT,
  ReserveValueCache,
  WRAP_RULE_ENV,
  wrapLayoutKnown,
  wrapRule,
  blockIndent,
  blockRowText,
  findContinuations,
  findHeads,
  formatBlock,
  formatBlockV2,
  moreLinesNote,
  paintLayout,
  parseHeadSuffix,
  reserveEnabled,
  reserveMaxRows,
  reserveRowText,
  sessionRelay,
  tokenHash,
  unknownHeadText,
  valueLines,
} from "../../src/reserve-block.js";
import { layoutRows, linesNotShown } from "../../src/reserve-layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const T = "$MDU:nomodel_Bash[464e]";

test("grammar parity: the recognizer's token source IS the stream filter's SYMBOL_TOKEN_RE", () => {
  assert.equal(TOKEN_SOURCE, SYMBOL_TOKEN_RE.source);
});

test("head row: `T/1:N` with 2 ≤ N ≤ 200; the suffix ends the token grammar", () => {
  const heads = findHeads(`  ${T}/1:5`);
  assert.deepEqual(heads, [{ index: 2, length: T.length + 4, canonical: T, hash: "464e", n: 5 }]);
  assert.equal(findHeads(`${T}/1:200`)[0]?.n, 200);
  // Out of range, or not a head at all: no match.
  for (const s of [`${T}/1:1`, `${T}/1:0`, `${T}/1:201`, `${T}/1:5000`, `${T}/2:5`, `${T} /1:5`, `${T}`]) {
    assert.deepEqual(findHeads(s), [], s);
  }
  // A field path is part of T; the hash is the one in brackets.
  const f = findHeads("$MDU:Read[9b0a].stdout/1:3")[0]!;
  assert.equal(f.canonical, "$MDU:Read[9b0a].stdout");
  assert.equal(f.hash, "9b0a");
  assert.deepEqual(parseHeadSuffix("/1:12\x1b[K"), { n: 12, length: 5 });
  assert.equal(parseHeadSuffix("/1:"), null);
});

test("head row: a Markdown-escaped head is recognized, its canonical token unescaped", () => {
  const h = findHeads("\\$MDU:nomodel\\_Bash[464e]/1:4")[0]!;
  assert.equal(h.canonical, T);
  assert.equal(h.length, "\\$MDU:nomodel\\_Bash[464e]/1:4".length);
  assert.equal(h.n, 4);
});

test("continuation row: `$MDU/<hash>/<i>`, 2 ≤ i ≤ 200; never a token candidate", () => {
  assert.deepEqual(findContinuations("  $MDU/464e/2\x1b[K"), [{ index: 2, length: 11, hash: "464e", i: 2 }]);
  assert.deepEqual(findContinuations("$MDU/464e/1 $MDU/464e/201 $MDU/xyz1/3 $MDU/46/3"), []);
  // Digits of a following word never glue into the index when it is written
  // contiguously (the row's own bytes end at a non-digit).
  assert.equal(findContinuations("$MDU/464e/12x")[0]?.i, 12);
  // No `:` → the candidate-prefix hold never holds a continuation row.
  for (const p of ["$MDU/", "$MDU/464e", "$MDU/464e/", "$MDU/464e/2"]) {
    assert.equal(couldBeSymbolPrefix(p), false, p);
  }
});

test("no leading zeros: `/1:05` and `$MDU/<hash>/02` are not a head or a row (the proxy never emits nor collapses them)", () => {
  for (const s of [`${T}/1:05`, `${T}/1:005`, `${T}/1:020`]) assert.deepEqual(findHeads(s), [], s);
  assert.equal(parseHeadSuffix("/1:05"), null);
  assert.deepEqual(findContinuations("$MDU/464e/02 $MDU/464e/002 $MDU/464e/010"), []);
  // The canonical spellings still match.
  assert.equal(findHeads(`${T}/1:50`)[0]?.n, 50);
  assert.equal(findContinuations("$MDU/464e/10")[0]?.i, 10);
  assert.equal(findContinuations("$MDU/464e/200")[0]?.i, 200);
});

test("candidate hold: a complete token followed by a PARTIAL head suffix still holds (never split into token + `/1:N`)", () => {
  for (const p of [`${T}/`, `${T}/1`, `${T}/1:`, `${T}/1:5`, `${T}/1:12`]) {
    assert.equal(couldBeSymbolPrefix(p), true, p);
  }
  for (const p of [`${T}/2`, `${T}/1:5 `, `${T}/1:1234`, `${T}/x`]) {
    assert.equal(couldBeSymbolPrefix(p), false, p);
  }
});

test("value lines: one trailing newline dropped, CRLF split, a blank line kept", () => {
  assert.deepEqual(valueLines("a\nb\n"), ["a", "b"]);
  assert.deepEqual(valueLines("a\r\n\r\nb"), ["a", "", "b"]);
  assert.deepEqual(valueLines("a\n\n"), ["a", ""]);
});

test("row text: line i; the cap row carries `… +K more lines`, K = lines − (N − 1)", () => {
  const lines = ["l1", "l2", "l3", "l4", "l5", "l6", "l7"];
  assert.equal(reserveRowText(lines, 1, 7), "l1");
  assert.equal(reserveRowText(lines, 7, 7), "l7");
  assert.equal(reserveRowText(lines, 3, 4), "l3");
  assert.equal(reserveRowText(lines, 4, 4), moreLinesNote(4));
  assert.equal(moreLinesNote(4), "… +4 more lines (full value: mandu dashboard)");
  assert.equal(reserveRowText(["a", "b"], 3, 3), "", "a row past the value's end is blank");
  assert.equal(unknownHeadText(T, 5), `${T} (5 lines)`);
});

test("formatBlock mirrors the proxy's emitter: N = min(lines, cap), rows 2..N", () => {
  assert.equal(formatBlock(T, 3), `${T}/1:3\n$MDU/464e/2\n$MDU/464e/3`);
  const capped = formatBlock(T, 50).split("\n");
  assert.equal(capped.length, RESERVE_MAX_ROWS_DEFAULT);
  assert.equal(capped[39], "$MDU/464e/40");
  assert.equal(tokenHash(T), "464e");
});

test("cap and kill switch: MANDU_REPLY_RESERVE_MAX in 2..200 else 40; MANDU_REPLY_RESERVE=0 disables", () => {
  assert.equal(reserveMaxRows({}), 40);
  assert.equal(reserveMaxRows({ MANDU_REPLY_RESERVE_MAX: "12" }), 12);
  for (const v of ["1", "201", "abc", "", "-3", "4.5"]) assert.equal(reserveMaxRows({ MANDU_REPLY_RESERVE_MAX: v }), 40, v);
  assert.equal(reserveEnabled({}), true);
  assert.equal(reserveEnabled({ MANDU_REPLY_RESERVE: "1" }), true);
  assert.equal(reserveEnabled({ MANDU_REPLY_RESERVE: "0" }), false);
});

test("relay report: reserve only for the PTY relay and only without the kill switch; size when known", () => {
  // `wrap: true` rides with `reserve` (this filter paints v2 heads, §11.5).
  assert.deepEqual(sessionRelay("s1", "pty", { cols: 120, rows: 40 }, {}), { sessionKey: "s1", mode: "pty", reserve: true, wrap: true, cols: 120, rows: 40 });
  assert.deepEqual(sessionRelay("s1", "pty", {}, { MANDU_REPLY_RESERVE: "0" }), { sessionKey: "s1", mode: "pty", reserve: false });
  assert.deepEqual(sessionRelay("s1", "pipe", {}, {}), { sessionKey: "s1", mode: "pipe", reserve: false });
  assert.deepEqual(sessionRelay("s1", "passthrough", { cols: undefined }, {}), { sessionKey: "s1", mode: "passthrough", reserve: false });
});

test("value cache: head → value by hash; unknown until set; bounded; one report per value", () => {
  const c = new ReserveValueCache(2);
  assert.equal(c.headFor("464e"), undefined);
  c.noteHead("464e", T, 5);
  assert.deepEqual(c.headFor("464e"), { canonical: T, n: 5, value: null });
  c.setValue(T, "a\nb\n");
  assert.equal(c.headFor("464e")?.value, "a\nb\n");
  assert.equal(c.firstReport(T), true);
  assert.equal(c.firstReport(T), false, "reported once");
  // Bounded: the oldest head is forgotten past the cap.
  c.noteHead("aaaa", "$MDU:x[aaaa]", 2);
  c.noteHead("bbbb", "$MDU:x[bbbb]", 2);
  assert.equal(c.headFor("464e"), undefined);
  assert.ok(c.headFor("bbbb"));
});

// ── v2 heads `T/1:N:W:F` (reply-row-reservation.md §11.2, §11.3) ─────────────

test("v2 head: `T/1:N:W:F` parses N, W and F; findHeads carries them", () => {
  assert.deepEqual(parseHeadSuffix("/1:5:78:40\x1b[K"), { n: 5, length: 10, w: 78, f: 40 });
  assert.deepEqual(parseHeadSuffix("/1:2:78:0"), { n: 2, length: 9, w: 78, f: 0 });
  assert.deepEqual(parseHeadSuffix("/1:200:1000:1000 "), { n: 200, length: 16, w: 1000, f: 1000 });
  const h = findHeads(`The value is ${T}/1:3:78:65`)[0]!;
  assert.deepEqual(h, { index: 13, length: T.length + 10, canonical: T, hash: "464e", n: 3, w: 78, f: 65 });
  // The escaped spelling, as a v2 head.
  assert.equal(findHeads("**\\$MDU:nomodel\\_Bash[464e]/1:3:78:78**")[0]?.w, 78);
  // v1 heads carry no W/F.
  assert.equal(findHeads(`${T}/1:5`)[0]?.w, undefined);
});

test("v2 head: bounds — N 2..200, W 20..1000, F 0 or ⌈W/2⌉..W, no leading zeros, a non-digit after", () => {
  // Legal edges.
  for (const s of ["/1:2:20:10", "/1:2:20:20", "/1:2:21:11", "/1:2:1000:500", "/1:2:78:0"]) {
    assert.ok(parseHeadSuffix(s), s);
  }
  // Out of range or malformed: NOT a head, and never the v1 head `/1:N`.
  for (const s of [
    "/1:1:78:78", "/1:201:78:78", // N
    "/1:5:19:19", "/1:5:1001:1000", "/1:5:0:0", // W
    "/1:5:78:38", "/1:5:21:10", "/1:5:78:79", // F below ⌈W/2⌉ or above W
    "/1:05:78:78", "/1:5:078:78", "/1:5:78:078", "/1:5:78:00", // leading zeros
    "/1:5:78:40000", "/1:5:78", "/1:5:78:", "/1:5:7", // too long / incomplete
  ]) {
    assert.equal(parseHeadSuffix(s), null, s);
    assert.deepEqual(findHeads(`${T}${s}`), [], s);
  }
});

test("v2 before v1: `/1:5:78:40` is ONE v2 head, never v1's `/1:5` beside `:78:40`", () => {
  const h = findHeads(`${T}/1:5:78:40`)[0]!;
  assert.equal(h.length, T.length + "/1:5:78:40".length);
  assert.equal(h.w, 78);
  // A v1 head followed by a colon and a NON-digit stays v1 (not v2-shaped).
  assert.deepEqual(parseHeadSuffix("/1:5: x"), { n: 5, length: 4 });
});

test("candidate hold: a partial v2 suffix is still a candidate (never split into token + `/1:N`)", () => {
  for (const p of [`${T}/1:5:`, `${T}/1:5:7`, `${T}/1:5:78`, `${T}/1:5:78:`, `${T}/1:5:78:4`, `${T}/1:5:78:40`]) {
    assert.equal(couldBeSymbolPrefix(p), true, p);
  }
  for (const p of [`${T}/1:5:78:40 `, `${T}/1:5:78:40000`, `${T}/1:5:x`]) {
    assert.equal(couldBeSymbolPrefix(p), false, p);
  }
});

test("v2 row text: row i of layoutRows(value, W, F); a one-line value wider than W wraps", () => {
  const key = "sk-" + "A".repeat(117); // 120 columns, one line
  assert.equal(layoutRows(key, 78, 78).length, 2);
  const head = { n: 2, w: 78, f: 78 };
  assert.equal(blockRowText(key, 1, head), key.slice(0, 78));
  assert.equal(blockRowText(key, 2, head), key.slice(78));
  // Head row narrower (a prefix before the head): F columns, then W.
  const words = Array.from({ length: 12 }, (_, i) => `word${String(i + 1).padStart(2, "0")}`).join(" ");
  const mid = { n: 4, w: 30, f: 18 };
  assert.equal(blockRowText(words, 1, mid), "word01 word02 ");
  assert.equal(blockRowText(words, 2, mid), "word03 word04 word05 word06 ");
  const laid = layoutRows(words, 30, 18);
  assert.equal(laid.length, 4);
  for (let i = 1; i <= 4; i++) assert.equal(blockRowText(words, i, mid), laid[i - 1]!.text, `row ${i}`);
  // wrap-ansi's rule for a word longer than W: it moves to the next row when
  // that saves a break, so the narrow head row stays empty.
  assert.equal(blockRowText(key, 1, { n: 3, w: 78, f: 40 }), "");
  assert.equal(blockRowText(key, 2, { n: 3, w: 78, f: 40 }), key.slice(0, 78));
  // Word wrap, cleaned rows: a TAB is already spaces (from the line's column 0).
  const prose = "alpha\tbeta " + "word ".repeat(20);
  for (let i = 1; i <= layoutRows(prose, 30, 30).length; i++) {
    const t = blockRowText(prose, i, { n: 9, w: 30, f: 30 });
    assert.ok(!t.includes("\t") && [...t].length <= 30, JSON.stringify(t));
  }
  assert.equal(blockRowText(prose, 1, { n: 9, w: 30, f: 30 }).slice(0, 13), "alpha   beta ");
});

test("v2 row text: F = 0 — the head row is empty, the value starts on row 2", () => {
  const head = { n: 3, w: 40, f: 0 };
  assert.equal(blockRowText("one\ntwo\n", 1, head), "");
  assert.equal(blockRowText("one\ntwo\n", 2, head), "one");
  assert.equal(blockRowText("one\ntwo\n", 3, head), "two");
});

test("v2 cap row: row N shows `… +K more lines`, K = the lines not shown in full on rows 1..N−1", () => {
  // Line 1 wraps over 3 rows at W = 20; lines 2..4 one row each: 6 rows.
  const value = "x".repeat(50) + "\nl2\nl3\nl4\n";
  assert.equal(layoutRows(value, 20, 20).length, 6);
  // N = 4: rows 1..3 hold line 1 in full; K = 3 (l2, l3, l4).
  const n4 = { n: 4, w: 20, f: 20 };
  assert.equal(blockRowText(value, 3, n4), "x".repeat(10));
  assert.equal(blockRowText(value, 4, n4), moreLinesNote(3));
  assert.equal(linesNotShown(layoutRows(value, 20, 20), 3), 3);
  // N = 3: line 1 is cut after two rows, so it counts as not shown: K = 4.
  assert.equal(blockRowText(value, 3, { n: 3, w: 20, f: 20 }), moreLinesNote(4));
  // No cap when the layout fits.
  assert.equal(blockRowText(value, 6, { n: 6, w: 20, f: 20 }), "l4");
});

test("v1 row text through blockRowText is unchanged: line i, cap note K = lines − (N − 1)", () => {
  const lines = "l1\nl2\nl3\nl4\nl5\nl6\nl7\n";
  assert.equal(blockRowText(lines, 1, { n: 7 }), "l1");
  assert.equal(blockRowText(lines, 4, { n: 4 }), moreLinesNote(4));
  // A v1 row is the raw line: its TAB is the writers' job (column-aware).
  assert.equal(blockRowText("a\n\tb\n", 2, { n: 2 }), "\tb");
});

test("value cache: a v2 head's W and F reach its continuation rows", () => {
  const c = new ReserveValueCache();
  c.noteHead("464e", T, 3, 78, 40);
  c.setValue(T, "v");
  assert.deepEqual(c.headFor("464e"), { canonical: T, n: 3, w: 78, f: 40, value: "v" });
  c.noteHead("464e", T, 5); // a later v1 head with the same hash wins, without W/F
  assert.deepEqual(c.headFor("464e"), { canonical: T, n: 5, value: "v" });
});

test("formatBlockV2 mirrors the proxy's v2 expander: N = min(layout rows, cap)", () => {
  const key = "Z".repeat(120);
  assert.equal(formatBlockV2(T, key, 78, 78), `${T}/1:2:78:78\n$MDU/464e/2`);
  assert.equal(formatBlockV2(T, key, 78, 0), `${T}/1:3:78:0\n$MDU/464e/2\n$MDU/464e/3`);
  assert.equal(formatBlockV2(T, "x\n".repeat(90), 40, 40).split("\n").length, RESERVE_MAX_ROWS_DEFAULT);
});

test("relay report: `wrap` is sent only with `reserve: true`", () => {
  assert.equal(sessionRelay("s", "pty", {}, {}).wrap, true);
  assert.equal("wrap" in sessionRelay("s", "pty", {}, { MANDU_REPLY_RESERVE: "0" }), false);
  assert.equal("wrap" in sessionRelay("s", "pipe", {}, {}), false);
});

// ── §13: a resize after the reply ────────────────────────────────────────────

test("paintLayout (§13): narrower → W − d and F − d; same or wider → the block's own; v1 → null", () => {
  const h = { n: 4, w: 78, f: 65, cols: 80 };
  assert.deepEqual(paintLayout(h, 80), { w: 78, f: 65 }, "same width");
  assert.deepEqual(paintLayout(h, 120), { w: 78, f: 65 }, "wider: N rows cannot shrink, the old rows still fit");
  assert.deepEqual(paintLayout(h, 60), { w: 58, f: 45 }, "20 narrower");
  assert.deepEqual(paintLayout({ ...h, f: 78 }, 60), { w: 58, f: 58 }, "a head alone on its row");
  assert.deepEqual(paintLayout({ ...h, f: 0 }, 60), { w: 58, f: 0 }, "F = 0 stays 0");
  assert.deepEqual(paintLayout({ ...h, f: 40 }, 60), { w: 58, f: 0 }, "F − d = 20 < ⌈58/2⌉: the head row goes blank");
  assert.deepEqual(paintLayout(h, 21), { w: 78, f: 65 }, "W − d = 19 < 20: keep the layout (clips)");
  assert.deepEqual(paintLayout({ n: 4, w: 78, f: 65 }, 60), { w: 78, f: 65 }, "the first width unknown: never re-laid out");
  assert.deepEqual(paintLayout(h, null), { w: 78, f: 65 }, "the width now unknown");
  assert.deepEqual(paintLayout(h, 60.5), { w: 78, f: 65 });
  assert.equal(paintLayout({ n: 4, cols: 80 }, 60), null, "v1");
});

test("row text after a narrowing (§13): the value re-laid out at W − d; N rows too few → the cap note on row N", () => {
  const long = `DIFFWRAP_LONG ${Array.from({ length: 14 }, (_, i) => `SEGW${String(i + 1).padStart(2, "0")}`).join(" ")}`;
  const value = `DIFFWRAP_A short\n${long}\nDIFFWRAP_C end`;
  assert.equal(layoutRows(value, 78, 78).length, 4);
  assert.equal(layoutRows(value, 58, 58).length, 4, "precondition: the same N at 58");
  const head = { n: 4, w: 78, f: 78, cols: 80 };
  for (let i = 1; i <= 4; i++) {
    assert.equal(blockRowText(value, i, head, 60), layoutRows(value, 58, 58)[i - 1]!.text, `row ${i} at 60 columns`);
    assert.equal(blockRowText(value, i, head, 80), layoutRows(value, 78, 78)[i - 1]!.text, `row ${i} at 80 columns`);
    assert.equal(blockRowText(value, i, head), layoutRows(value, 78, 78)[i - 1]!.text, `row ${i}, no width given`);
  }
  // Laid out at 160 (the long line fits: N = 3), shown at 60 (4 rows needed).
  const wide = { n: 3, w: 158, f: 158, cols: 160 };
  assert.equal(blockRowText(value, 1, wide, 60), "DIFFWRAP_A short");
  assert.equal(blockRowText(value, 2, wide, 60), layoutRows(value, 58, 58)[1]!.text);
  assert.equal(blockRowText(value, 3, wide, 60), moreLinesNote(2), "the long line cut, and line 3: two lines not shown");
  // v1 heads never change with the width.
  assert.equal(blockRowText("a\nb\n", 2, { n: 2, cols: 80 }, 30), "b");
});

test("TAB stops (§11.2): a v2 row's TAB reaches the terminal's stop from the content area's column, cols − W", () => {
  // The differential capture: 120 columns, W = 118, the reply at column 2.
  const tsv = "name\tport\towner\nweb\t8080\talice\n";
  const head = { n: 2, w: 118, f: 118, cols: 120 };
  assert.equal(blockIndent(head), 2);
  assert.equal(blockRowText(tsv, 1, head, 120), "name  port    owner", "`port` at 2 + 6 = 8, `owner` at 16");
  assert.equal(blockRowText(tsv, 2, head, 120), "web   8080    alice");
  assert.deepEqual([1, 2].map((i) => blockRowText(tsv, i, head, 120)), layoutRows(tsv, 118, 118, "ink", 2).map((r) => r.text),
    "the rows the arbiter counted with the proxy's indent");
  // A list item (indent 4), and a mid-line head 10 columns into its row.
  assert.equal(blockRowText("a\tb", 1, { n: 2, w: 76, f: 76, cols: 80 }, 80), "a   b");
  assert.equal(blockRowText("a\tb\nc", 1, { n: 2, w: 78, f: 68, cols: 80 }, 80), "a   b", "12 + 1 → 16");
  // A narrowing keeps the rows' start column (paintLayout): the same stops.
  assert.equal(blockRowText(tsv, 1, head, 100), "name  port    owner");
  // The width unknown, or a v1 head: stops from the content area's own
  // column 0 (v1 rows go through the writers' frame-safe pass instead).
  assert.equal(blockIndent({ n: 2, w: 118, f: 118 }), 0);
  assert.equal(blockIndent({ n: 2, cols: 120 }), 0);
  assert.equal(blockRowText(tsv, 1, { n: 2, w: 118, f: 118 }), "name    port    owner");
  // The terminal rule: W is the full width, so the indent is 0.
  assert.equal(blockIndent({ n: 2, w: 80, f: 80, cols: 80, rule: "terminal" }), 0);
});

test("value cache (§13): a block keeps the width it was first seen at; a different block takes the width now", () => {
  const c = new ReserveValueCache();
  c.noteHead("464e", T, 4, 78, 78, 80);
  assert.equal(c.headFor("464e")!.cols, 80);
  c.noteHead("464e", T, 4, 78, 78, 60); // the TUI reprints the same head after a resize
  assert.equal(c.headFor("464e")!.cols, 80, "the first sighting's width is kept");
  c.noteHead("464e", T, 3, 58, 58, 60); // a new block with the same hash (a later reply)
  assert.equal(c.headFor("464e")!.cols, 60);
  c.noteHead("abcd", T, 2, 78, 78);
  assert.equal(c.headFor("abcd")!.cols, undefined, "no width known");
  c.noteHead("abcd", T, 2, 78, 78, 0);
  assert.equal(c.headFor("abcd")!.cols, undefined, "a non-positive width is not a width");
});

test("§14 head: `T/1:N:W:F:K` parses N, W, F and the break K; K is part of the head, never left on screen", () => {
  assert.deepEqual(parseHeadSuffix("/1:3:78:65:12\x1b[K"), { n: 3, length: 13, w: 78, f: 65, k: 12 });
  assert.deepEqual(parseHeadSuffix("/1:200:1000:1000:9999 "), { n: 200, length: 21, w: 1000, f: 1000, k: 9999 });
  const h = findHeads(`The value is ${T}/1:3:78:65:5\n`)[0]!;
  assert.equal(h.length, T.length + 12, "the head spans `:5`");
  // K: no leading zero, at most four digits, then neither a digit nor `:`.
  for (const bad of ["/1:3:78:65:0", "/1:3:78:65:05", "/1:3:78:65:12345", "/1:3:78:65:5:1"]) {
    assert.equal(parseHeadSuffix(bad), null, bad);
  }
});

test("§14 head-only head: N = 1 parses only with a break field", () => {
  assert.deepEqual(parseHeadSuffix("/1:1:158:145:5 "), { n: 1, length: 14, w: 158, f: 145, k: 5 });
  assert.equal(parseHeadSuffix("/1:1:158:145 "), null);
  assert.equal(parseHeadSuffix("/1:1 "), null);
  const v = "Q".repeat(60);
  assert.equal(blockRowText(v, 1, { n: 1, w: 158, f: 145 }), v, "row 1 is the whole value");
});

// ── §17: the `terminal` wrap rule (Goose) ────────────────────────────────────

const G_LONG = "DIFFWRAP_LONG " + Array.from({ length: 14 }, (_, i) => `SEGW${String(i + 1).padStart(2, "0")}`).join(" ");
const G_VALUE = `DIFFWRAP_A short\n${G_LONG}\nDIFFWRAP_C end\n`;

test("§17 wrap rule from MANDU_REPLY_WRAP_RULE: `terminal` only when it says so, ink otherwise", () => {
  assert.equal(WRAP_RULE_ENV, "MANDU_REPLY_WRAP_RULE");
  assert.equal(wrapRule({}), "ink");
  assert.equal(wrapRule({ MANDU_REPLY_WRAP_RULE: "terminal" }), "terminal");
  assert.equal(wrapRule({ MANDU_REPLY_WRAP_RULE: " terminal\n" }), "terminal");
  for (const v of ["", "ink", "TERMINAL", "char", "1"]) assert.equal(wrapRule({ MANDU_REPLY_WRAP_RULE: v }), "ink", v);
});

test("§17 relay report: `rule: terminal` rides with `reserve` and `wrap`, never alone; absent for ink", () => {
  const goose = { MANDU_REPLY_WRAP_RULE: "terminal" };
  assert.deepEqual(sessionRelay("s", "pty", { cols: 80, rows: 24 }, goose),
    { sessionKey: "s", mode: "pty", reserve: true, wrap: true, rule: "terminal", cols: 80, rows: 24 });
  assert.equal("rule" in sessionRelay("s", "pty", {}, {}), false, "ink: no rule key (an older arbiter refuses nothing)");
  assert.equal("rule" in sessionRelay("s", "pty", {}, { ...goose, MANDU_REPLY_RESERVE: "0" }), false, "the kill switch");
  assert.equal("rule" in sessionRelay("s", "pipe", {}, goose), false);
});

test("§35 MANDU_REPLY_WRAP_RULE=none (OpenCode): no `wrap` in the relay report, so the proxy sends v1 heads only; painting stays ink", () => {
  const opencode = { MANDU_REPLY_WRAP_RULE: "none" };
  assert.equal(wrapLayoutKnown(opencode), false);
  assert.equal(wrapLayoutKnown({ MANDU_REPLY_WRAP_RULE: " none\n" }), false);
  for (const v of [undefined, "", "ink", "terminal", "NONE"]) assert.equal(wrapLayoutKnown(v === undefined ? {} : { MANDU_REPLY_WRAP_RULE: v }), true, String(v));
  assert.equal(wrapRule(opencode), "ink", "a v2 head that arrives anyway is painted by Ink's rule");
  assert.deepEqual(sessionRelay("s", "pty", { cols: 120, rows: 40 }, opencode),
    { sessionKey: "s", mode: "pty", reserve: true, cols: 120, rows: 40 });
  assert.equal(sessionRelay("s", "pty", {}, { ...opencode, MANDU_REPLY_RESERVE: "0" }).reserve, false, "the kill switch still wins");
});

test("§17 value cache: a terminal-rule cache stamps its rule on every head; the rows break by character at the full width", () => {
  const c = new ReserveValueCache(RESERVE_CACHE_MAX, "terminal");
  assert.equal(c.rule, "terminal");
  c.noteHead("464e", T, 4, 80, 80, 80);
  c.setValue(T, G_VALUE);
  const head = c.headFor("464e")!;
  assert.deepEqual(head, { canonical: T, n: 4, w: 80, f: 80, cols: 80, rule: "terminal", value: G_VALUE });
  assert.deepEqual([1, 2, 3, 4].map((i) => blockRowText(G_VALUE, i, head, 80)), [
    "DIFFWRAP_A short",
    "DIFFWRAP_LONG SEGW01 SEGW02 SEGW03 SEGW04 SEGW05 SEGW06 SEGW07 SEGW08 SEGW09 SEG",
    "W10 SEGW11 SEGW12 SEGW13 SEGW14",
    "DIFFWRAP_C end",
  ], "vanilla Goose's screen (differential-interactive.md §32)");
  // The default cache (every other agent) stamps nothing and paints Ink's rows.
  const ink = new ReserveValueCache();
  ink.noteHead("464e", T, 4, 78, 78);
  assert.equal("rule" in ink.headFor("464e")!, false);
  assert.equal(blockRowText(G_VALUE, 2, ink.headFor("464e")!), layoutRows(G_VALUE, 78, 78)[1]!.text);
  assert.equal(formatBlockV2(T, G_LONG, 80, 80, 40, "terminal"), `${T}/1:2:80:80\n$MDU/464e/2`);
});

test("§17 the memo keys on the rule: one value, one (W, F), two rules, two layouts", () => {
  const head = { n: 2, w: 80, f: 80 };
  const ink = blockRowText(G_LONG, 2, head);
  const term = blockRowText(G_LONG, 2, { ...head, rule: "terminal" });
  assert.equal(ink, "SEGW10 SEGW11 SEGW12 SEGW13 SEGW14");
  assert.equal(term, "W10 SEGW11 SEGW12 SEGW13 SEGW14");
  assert.equal(blockRowText(G_LONG, 2, head), ink, "the ink layout is not served from the terminal entry");
});

test("§17 narrowing (§13) under the terminal rule: re-laid out at W − d by character wrap", () => {
  // 111 columns: 80 + 31 at the old width, 60 + 51 after a 20-column narrowing.
  const rows = [1, 2].map((i) => blockRowText(G_LONG, i, { n: 2, w: 80, f: 80, cols: 80, rule: "terminal" }, 60));
  assert.deepEqual(rows, [G_LONG.slice(0, 60), G_LONG.slice(60)]);
});
