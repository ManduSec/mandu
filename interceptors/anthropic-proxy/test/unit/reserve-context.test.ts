/**
 * reserve-context.test — v2 eligibility for reply row reservation
 * (src/reserve-context.ts; docs/design/ui/reply-row-reservation.md §11.4): the
 * line context (fences, list indent, the prefix), every accept and reject
 * rule for a token inside a line, the content width W from the list indent,
 * and F: the head on the prefix's row, on its own row, the ambiguous zone and
 * the F = 0 clamp. Pure: no arbiter, no axes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { advanceContext, decideReserve, newLineContext, suffixBreak, SUFFIX_BREAK_MAX, terminalColumn, type LineContext, type ReserveDecision } from "../../src/reserve-context.js";

const T = "$MDU:nomodel_Bash[464e]"; // 23 columns
const T_ESC = "\\$MDU:nomodel\\_Bash[464e]";
const LONG = "$MDU:nomodel_Bash[464e].results.first_one"; // 41 columns

/** The context after the model's `text` (the token comes next). */
function ctxAfter(text: string): LineContext {
  const c = newLineContext();
  advanceContext(c, text);
  return c;
}

function decide(text: string, after: string | null, o: { token?: string; cols?: number | null; cap?: number; codeSpan?: boolean; rest?: string } = {}): ReserveDecision {
  return decideReserve({
    ctx: ctxAfter(text), token: o.token ?? T, after, cols: o.cols === undefined ? 80 : o.cols, cap: o.cap ?? 40,
    ...(o.codeSpan !== undefined ? { codeSpan: o.codeSpan } : {}),
    ...(o.rest !== undefined ? { rest: o.rest } : {}),
  });
}
const v2 = (width: number, first: number, standalone = false, span = false): ReserveDecision => ({ kind: "v2", width, first, standalone, span });

test("context: fences toggle on ``` / ~~~ lines (same char, at least as long, nothing after, to close)", () => {
  assert.equal(ctxAfter("a\n```\n").fence?.ch, "`");
  assert.equal(ctxAfter("a\n```sh\ncode\n```\n").fence, null);
  assert.equal(ctxAfter("~~~\nx\n```\n").fence?.ch, "~", "a backtick line does not close a tilde fence");
  assert.equal(ctxAfter("````\nx\n```\n").fence?.n, 4, "a shorter fence does not close");
  assert.equal(ctxAfter("```\nx\n``` not a close\n").fence?.ch, "`");
  assert.equal(ctxAfter("  ```\nx\n  ```\n").fence, null, "indented fences");
  assert.equal(ctxAfter("```\r\nx\r\n```\r\n").fence, null, "CRLF");
  assert.equal(ctxAfter("``` \n").fence?.ch, "`");
  assert.equal(ctxAfter("``\n").fence, null, "two backticks are not a fence");
});

test("context: list indent from the item, inherited by following lines, reset by a blank line", () => {
  assert.equal(ctxAfter("- item\n").listCarry, 2);
  assert.equal(ctxAfter("- item\nmore\n").listCarry, 2, "a continuation line inherits");
  assert.equal(ctxAfter("- item\n\n").listCarry, 0, "a blank line resets");
  assert.equal(ctxAfter("- item\n  \t\n").listCarry, 0, "a whitespace-only line is blank");
  assert.equal(ctxAfter("10) item\n").listCarry, 4);
  assert.equal(ctxAfter("- a\n  - b\n").listCarry, 4, "a nested item");
  assert.equal(ctxAfter("*   wide\n").listCarry, 4);
  assert.equal(ctxAfter("-item\n").listCarry, 0, "no space after the marker: not an item");
  assert.equal(ctxAfter("1234567890. x\n").listCarry, 0, "ten digits: not an item");
  const c = ctxAfter("- a\nb");
  assert.equal(c.line, "b", "the current line so far");
  assert.equal(c.lineExpanded, false);
});

test("standalone: v2 with F = W; W = cols − 2 − list indent", () => {
  assert.deepEqual(decide("", ""), v2(78, 78, true), "the block's only line, at the block end");
  assert.deepEqual(decide("para\n", "\n"), v2(78, 78, true));
  assert.deepEqual(decide("- item\n", "\n"), v2(76, 76, true), "folded into the list item (phase 0 P2)");
  assert.deepEqual(decide("- item\n\n", "\n"), v2(78, 78, true), "after a blank line: no list");
  assert.deepEqual(decide("  - nested\n", "\n"), v2(74, 74, true));
  assert.deepEqual(decide("", "\n", { cols: 160 }), v2(158, 158, true));
});

test("standalone falls back to a v1 head: a v1 relay, a fence, W < 20, W > 1000, a head wider than W", () => {
  assert.deepEqual(decide("", "\n", { cols: null }), { kind: "v1" });
  assert.deepEqual(decide("```\n", "\n"), { kind: "v1" }, "inside a fence: only v1");
  assert.deepEqual(decide("~~~\nx\n", ""), { kind: "v1" });
  assert.deepEqual(decide("```\nx\n```\n", "\n"), v2(78, 78, true), "after the fence closes");
  assert.deepEqual(decide("", "\n", { cols: 21 }), { kind: "v1" }, "W = 19");
  assert.deepEqual(decide("", "\n", { cols: 22 }), { kind: "v1" }, "W = 20, but the head (23 + 11) does not fit");
  assert.deepEqual(decide("", "\n", { cols: 1003 }), { kind: "v1" }, "W = 1001");
  assert.deepEqual(decide("", "\n", { cols: 1002 }), v2(1000, 1000, true));
  // The head bound: 23 + "/1:40:W:W".length. At cols 37, W = 35 ≥ 34: fits.
  assert.deepEqual(decide("", "\n", { cols: 37 }), v2(35, 35, true));
  assert.deepEqual(decide("", "\n", { cols: 35 }), { kind: "v1" }, "W = 33 < 34");
  assert.deepEqual(decide("", "\n", { cols: 35, cap: 9 }), v2(33, 33, true), "a smaller cap narrows the head bound");
});

test("the character after decides: unknown → none; CR is not a standalone line end", () => {
  assert.equal(decide("", null).kind, "none");
  assert.deepEqual(decide("", "\r"), v2(78, 78), "CRLF: a token at the line start, not standalone");
});

test("mid-line: the characters allowed before the token", () => {
  for (const pre of ["The key is ", "key:\t", "**", "_", "\"", "'", ""]) {
    assert.equal(decide(pre, " ").kind, "v2", JSON.stringify(pre));
  }
  for (const pre of ["abc", "(", "-", "/", "$", "\\", "=", "x."]) {
    assert.equal(decide(pre, " ").kind, "none", JSON.stringify(pre));
  }
});

test("mid-line: the characters allowed after the token", () => {
  for (const after of ["", "\n", " ", "\t", "\r", ".", ",", ";", ":", "!", "?", ")", "*", "_", "\"", "'"]) {
    assert.equal(decide("The key is ", after).kind, "v2", JSON.stringify(after));
  }
  for (const after of ["x", "1", "-", "/", "(", "$", "\\", "]", "`", "|"]) {
    assert.equal(decide("The key is ", after).kind, "none", JSON.stringify(after));
  }
});

test("mid-line rejects: heading, blockquote, table row, code span, link text, fence, a block already on the line", () => {
  const no = (pre: string, why: RegExp) => {
    const d = decide(pre, " ");
    assert.equal(d.kind, "none", JSON.stringify(pre));
    assert.match((d as { reason: string }).reason, why, JSON.stringify(pre));
  };
  no("# Key ", /heading/);
  no("   ## Key ", /heading/);
  no("> quoted ", /blockquote/);
  no("  > quoted ", /blockquote/);
  no("| a | ", /table/);
  no("a | ", /table/);
  no("use ` ", /code span/);
  no("`a` and `b ", /code span/);
  no("[see ", /link/);
  no("[a] and [b ", /link/);
  no("```sh ", /fence/);
  const inFence = decideReserve({ ctx: ctxAfter("```\nsee "), token: T, after: " ", cols: 80, cap: 40 });
  assert.equal(inFence.kind, "none");
  const c = ctxAfter("a ");
  c.lineExpanded = true;
  assert.equal(decideReserve({ ctx: c, token: T, after: " ", cols: 80, cap: 40 }).kind, "none");
  // Accepted look-alikes.
  for (const pre of ["    # not a heading ", "`a` and ", "[a](b) ", "a > b "]) {
    assert.equal(decide(pre, " ").kind, "v2", JSON.stringify(pre));
  }
  assert.equal(decide("see ", " ", { cols: null }).kind, "none", "a v1 relay never expands mid-line");
  assert.equal(decide("see ", " ", { cols: 21 }).kind, "none", "W < 20");
  assert.equal(decide("see ", " ", { cols: 1003 }).kind, "none", "W > 1000");
  assert.equal(decide("see ", " ", { cols: 35 }).kind, "none", "the head word does not fit");
});

test("F: the head on the prefix's row → F = W − p; the F = 0 clamp below ⌈W/2⌉", () => {
  // W = 78, head ≤ 23 + 11 = 34 columns.
  assert.deepEqual(decide("The value is ", " "), v2(78, 65));
  assert.deepEqual(decide("", " "), v2(78, 78), "at the line start");
  assert.deepEqual(decide("x".repeat(38) + " ", "."), v2(78, 39), "F = ⌈W/2⌉ is kept");
  assert.deepEqual(decide("x".repeat(39) + " ", "."), v2(78, 0), "F = 38 < 39 → 0 (the value starts on the next row)");
  // A prefix that wraps: p is its last row's width (wrapLine at W).
  const two = "word ".repeat(20); // 100 columns
  assert.deepEqual(decide(two, " "), v2(78, 78 - 25), "rows of 75 (the space before the 16th word stays up) and 25");
});

test("F: the head on its own row → F = W; the ambiguous zone → F = 0", () => {
  // p + narrowest head (23 + "/1:2:78:0" = 32) > 78 → surely its own row.
  assert.deepEqual(decide("x".repeat(46) + " ", " "), v2(78, 78));
  assert.deepEqual(decide("x".repeat(77) + " ", " "), v2(78, 78), "a full row");
  // A long token where the zone is wide: W = 58, head 41 + 9 = 50 .. 41 + 11 = 52.
  const d = (n: number) => decide("x".repeat(n - 1) + " ", " ", { token: LONG, cols: 60 });
  assert.deepEqual(d(6), v2(58, 52), "p + 52 ≤ 58: on the prefix row");
  assert.deepEqual(d(7), v2(58, 0), "p + 50 ≤ 58 < p + 52: ambiguous (N's digits decide) → 0");
  assert.deepEqual(d(8), v2(58, 0));
  assert.deepEqual(d(9), v2(58, 58), "p + 50 > 58: its own row");
});

test("F: glue before the token, Markdown in the prefix, another token, TAB, list items", () => {
  assert.deepEqual(decide("Key: **", " "), v2(78, 78 - 5 - 2), "glue `**` counted at its raw width");
  assert.deepEqual(decide("x".repeat(47) + " **", " "), v2(78, 78 - 2), "own row: F = W − the glue's raw width");
  assert.deepEqual(decide("x".repeat(45) + " **", " "), v2(78, 0), "`**` may render as nothing: own row not proven → 0");
  // Non-plain prefix (Markdown may render it narrower): an upper bound.
  assert.deepEqual(decide("The *big* key is ", " "), v2(78, 78 - 17));
  assert.deepEqual(decide("*" + "x".repeat(45) + "* ", " "), v2(78, 0), "own row cannot be proven → 0");
  assert.deepEqual(decide("  indented ", " "), v2(78, 78 - 11), "leading spaces: upper bound, single row");
  // Another token earlier on the line moves the head (its one-row splice).
  assert.deepEqual(decide(`${T} and `, " "), v2(78, 0));
  // TAB: counted as a full tab stop.
  assert.deepEqual(decide("key:\t", " "), v2(78, 78 - 12));
  // A list item: W from its indent; the marker is not part of the prefix.
  assert.deepEqual(decide("- key: ", " "), v2(76, 76 - 5));
  assert.deepEqual(decide("- ", " "), v2(76, 76));
  assert.deepEqual(decide("10) key: ", "."), v2(74, 74 - 5));
  assert.deepEqual(decide("- item\ncontinued ", " "), v2(76, 76 - 10), "a continuation line inherits the indent");
  // An escaped token: the upper bound uses the escaped width, the lower bound the rendered one.
  assert.deepEqual(decide("The value is ", " ", { token: T_ESC }), v2(78, 65));
});

test("span form (§12): a token that is a whole code span, only with codeSpan", () => {
  const on = { codeSpan: true };
  // The span's own opening backtick is no glue: it never renders.
  assert.deepEqual(decide("The key is `", "`", on), v2(78, 67, false, true), "a plain prefix: exact, as vanilla lays it out");
  // Upper-bound prefix (the `.env` span): p = 34 raw (32 shown) → F = 44,
  // below the 46 columns really free: too small, never too large.
  assert.deepEqual(decide("The value of API_KEY in `.env` is `", "`", on), v2(78, 44, false, true));
  assert.deepEqual(decide("`", "`", on), v2(78, 78, false, true), "the span opens the line");
  assert.deepEqual(decide("- API_KEY: `", "`", on), v2(76, 67, false, true), "a list item: W from its indent");
  assert.deepEqual(decide("**`", "`", on), v2(78, 76, false, true), "bold around the span: `**` is glue");
  const no = (pre: string, after: string, why: RegExp, o: { codeSpan?: boolean } = on) => {
    const d = decide(pre, after, o);
    assert.equal(d.kind, "none", JSON.stringify([pre, after]));
    assert.match((d as { reason: string }).reason, why, JSON.stringify([pre, after]));
  };
  no("is `", "`", /inside a code span$/, {});
  no("is `", "`", /inside a code span$/, { codeSpan: false });
  no("is `", " ", /not all of it/, undefined);
  no("is `", ".", /not all of it/);
  no("is `API_KEY=", "`", /not all of it/, undefined);
  no("is ```", "`", /not all of it/, undefined);
  no("is \\`", "`", /not all of it/, undefined);
  no("# `", "`", /heading/);
  no("> `", "`", /blockquote/);
  no("| a | `", "`", /table/);
  no("[see `", "`", /link/);
  // A span that closed before the token is not this token's span.
  assert.equal(decide("`a` and `", "`", on).kind, "v2");
  assert.equal(decide("`a` ", "`", on).kind, "none", "an even count: not inside a span; `` ` `` after is refused");
  // Standalone and fenced tokens never take the span form.
  assert.deepEqual(decide("", "", on), v2(78, 78, true, false));
  assert.deepEqual(decideReserve({ ctx: ctxAfter("```\n"), token: T, after: "\n", cols: 80, cap: 40, codeSpan: true }), { kind: "v1" });
});

test("§14 table row: a `|` later on the line (the first cell holds the token) → none; the rest unknown → not checked", () => {
  const d = decide("", " ", { rest: " | the deploy key |" });
  assert.equal(d.kind, "none");
  assert.match((d as { reason: string }).reason, /table/);
  assert.equal(decide("key ", " ", { rest: " | x" }).kind, "none");
  assert.equal(decide("", " ", { rest: " and that is all." }).kind, "v2");
  assert.equal(decide("", " ").kind, "v2", "rest not known: the old rule");
  assert.deepEqual(decide("", "", { rest: "" }), v2(78, 78, true), "standalone: an empty rest");
});

test("§14 suffixBreak: none when the text fits; else after the space before the first word that does not", () => {
  const b = (suffix: string, last: number, o: { marker?: number; width?: number; ticks?: number } = {}) =>
    suffixBreak({ suffix, last, marker: o.marker ?? 12, width: o.width ?? 78, lineTicks: o.ticks ?? 0 });
  assert.equal(b(" and that is all.", 20), null, "fits after the last row");
  assert.equal(b("", 78), null, "no text");
  // last 70: " and" → 74, " that" → 79 > 78: break before "that".
  assert.equal(b(" and that is all.", 70), 5);
  assert.equal(" and that is all.".slice(0, 5), " and ");
  // Glue (text touching the value) stays on the value's row.
  assert.equal(b(", and that", 77), 2, "`,` fits at 78; ` and` does not");
  assert.equal(b(".", 78), null, "the glue itself does not fit: vanilla moves the value's last word");
  // The TUI lays the text out after the marker: the wider of the two counts.
  assert.equal(b(" aaaa bbbb", 3, { marker: 12, width: 20 }), 6, "12 + 5 = 17; + 5 = 22 > 20");
  // A word that fits nowhere, spacing wrap-ansi keeps, another token: no break.
  assert.equal(b(" " + "x".repeat(79), 10), null);
  assert.equal(b(" and  that is all, and more words here", 70), null, "double space");
  assert.equal(b(" and\tthat", 76), null, "TAB");
  assert.equal(b(" and $MDU:nomodel_Bash[464e] too", 70), null);
  assert.equal(b(" a b\nc", 77), null, "a line break in the text");
});

test("§14 suffixBreak: never inside a code span or link text, never before text that opens a Markdown block", () => {
  const b = (suffix: string, last: number, ticks = 0) => suffixBreak({ suffix, last, marker: 12, width: 78, lineTicks: ticks });
  assert.equal(b(" `a b` c", 74), null, "the break would fall inside ` `a b` `");
  assert.equal(b("`, and more", 74, 1), 3, "the span form: the closing backtick is the glue");
  assert.equal(b(" [see the docs", 72), null, "inside link text");
  for (const rest of ["- y", "* y", "+ y", "1. y", "2) y", "# y", "> y", "```", "~~~", "<div>", "| y", "===", "---"]) {
    const suffix = ` x ${rest}`;
    assert.equal(b(suffix, 75), null, JSON.stringify(rest));
  }
  assert.equal(b(" x plain", 75), 3, "a plain word may start the row");
  assert.equal(SUFFIX_BREAK_MAX, 9999);
});

// ── §17: the `terminal` rule (Goose prints the reply raw at column 0) ────────

function decideT(text: string, after: string | null, o: { cols?: number | null; rest?: string; token?: string } = {}): ReserveDecision {
  return decideReserve({
    ctx: ctxAfter(text), token: o.token ?? T, after, cols: o.cols === undefined ? 80 : o.cols, cap: 40,
    codeSpan: true, rule: "terminal",
    ...(o.rest !== undefined ? { rest: o.rest } : {}),
  });
}

test("§17 terminalColumn: the terminal's own arithmetic over raw text", () => {
  assert.equal(terminalColumn("", 80), 0);
  assert.equal(terminalColumn("The value is ", 80), 13);
  assert.equal(terminalColumn("x".repeat(85), 80), 5, "autowrap at the full width");
  assert.equal(terminalColumn("x".repeat(79) + "한", 80), 2, "a wide glyph that would straddle the edge moves whole");
  assert.equal(terminalColumn("Tab\t", 80), 8);
  assert.equal(terminalColumn("áb", 80), 2, "a combining mark takes no column");
  assert.equal(terminalColumn("x".repeat(80), 80), null, "a full row: the cursor waits to wrap");
  assert.equal(terminalColumn("a\x1b[1mb", 80), null, "an escape: not plain arithmetic");
  assert.equal(terminalColumn("x".repeat(79) + "\t", 80), 79, "a TAB stops at the last column");
});

test("§17 decide, terminal: W is the full width, no indent of any kind; a standalone token takes F = W, in a fence too", () => {
  assert.deepEqual(decideT("", "\n"), v2(80, 80, true));
  assert.deepEqual(decideT("", ""), v2(80, 80, true));
  assert.deepEqual(decideT("- item\n", "\n"), v2(80, 80, true), "a list carry adds no indent: Goose draws it at column 0");
  assert.deepEqual(decideT("```\n", "\n"), v2(80, 80, true), "a fence is drawn raw: v2, not v1");
  assert.deepEqual(decideT("", "\n", { cols: 19 }), { kind: "v1" }, "below the grammar's width: v1");
  assert.deepEqual(decideT("", "\n", { cols: null }), { kind: "v1" }, "a v1 relay");
});

test("§17 decide, terminal: a mid-line head's F is W minus its raw column (exact: nothing is Markdown)", () => {
  assert.deepEqual(decideT("The value is ", " "), v2(80, 67));
  assert.deepEqual(decideT("- key: ", "\n"), v2(80, 73), "a list marker is text on its row");
  assert.deepEqual(decideT("**Key**: ", "."), v2(80, 71), "asterisks are drawn");
  assert.deepEqual(decideT("    indented: ", ","), v2(80, 66), "leading spaces are drawn");
  assert.deepEqual(decideT("x".repeat(70) + " ", " "), v2(80, 0), "under half a row left: the head row stays blank");
  assert.deepEqual(decideT("x".repeat(85) + " ", " "), v2(80, 74), "the prefix wrapped: its last row counts");
  assert.deepEqual(decideT("x".repeat(79) + " ", " ").kind, "none", "the prefix fills its row to the edge");
  assert.deepEqual(decideT("see $MDU:nomodel_Read[3407] and ", " "), v2(80, 0), "another token on the line");
});

test("§17 decide, terminal: a code span is plain text (backticks are drawn): never the span form", () => {
  assert.deepEqual(decideT("The value is `", "`"), v2(80, 66, false, false));
  assert.deepEqual(decideT("run `echo ", "`"), v2(80, 70), "a token sharing its span with text expands too: the span is text");
  // Under ink the same token takes the span form, F counted without the backtick.
  assert.deepEqual(decide("The value is `", "`", { codeSpan: true }), v2(78, 65, false, true));
});

test("§17 decide, terminal: the structural refusals stay", () => {
  assert.equal(decideT("# Title ", " ").kind, "none");
  assert.equal(decideT("> quoted ", " ").kind, "none");
  assert.equal(decideT("| cell ", " ").kind, "none");
  assert.equal(decideT("", " ", { rest: " | next |" }).kind, "none", "a table row by its rest");
  assert.equal(decideT("[link ", "]").kind, "none");
  assert.equal(decideT("```\nkey ", " ").kind, "none", "mid-line inside a fence");
  assert.equal(decideT("key=", " ").kind, "none", "the character before");
  assert.equal(decideT("key ", "x").kind, "none", "the character after");
  const c = ctxAfter("a ");
  c.lineExpanded = true;
  assert.equal(decideReserve({ ctx: c, token: T, after: " ", cols: 80, cap: 40, rule: "terminal" }).kind, "none", "one block per line");
});

test("§17 suffixBreak, terminal: the break falls where the row is full, mid-word, as the terminal's", () => {
  const b = (suffix: string, last: number, marker = 12) => suffixBreak({ suffix, last, marker, width: 80, lineTicks: 0, rule: "terminal" });
  // fidelity-echo-suffix: the value's last row is 27 columns; vanilla Goose
  // fills the row with the next 53 characters, mid-word if need be.
  const suffix = " and that is all, so the rest of this sentence wraps onto the next row.";
  assert.equal(b(suffix, 27), 53);
  assert.equal(b(suffix, 30), 50, "mid-word");
  assert.equal(b(" short", 27), null, "fits");
  assert.equal(b(" x", 79), 1, "one character fits");
  assert.equal(b(" x", 80), null, "not one character fits: no K = 0");
  assert.equal(b(" 한글", 78), 1, "a wide glyph that would straddle the edge moves whole");
  assert.equal(b(" more text here", 5, 70), 10, "the marker, when wider, is where the text starts on the screen");
  assert.equal(b(" and $MDU:nomodel_Bash[464e] too and more and more and more words", 40), null, "another token");
  assert.equal(b(" a\tb" + "c".repeat(80), 10), null, "a control byte");
  assert.equal(b(" `a b` c" + "d".repeat(80), 10), 68, "backticks are text: a break inside a span is fine (from the marker, 12)");
});
