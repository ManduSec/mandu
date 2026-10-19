/**
 * reserve-layout.test — the wrap rule reserved rows are laid out by
 * (src/reserve-layout.ts; docs/design/ui/reply-row-reservation.md §11.2), pinned
 * against the vanilla Claude Code 2.1.285 screens of the v2 probe (§11.1),
 * and the `terminal` rule against vanilla Goose 1.53.0's (§17.1).
 * Pure. The arbiter's and the proxy's copies are held byte-identical by
 * tests/stack/reserve-layout-parity.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  LAYOUT_RULES,
  cleanLine,
  layoutLines,
  layoutRows,
  layoutWidth,
  linesNotShown,
  wrapLine,
  wrapLineTerminal,
} from "../../src/reserve-layout.js";

const WORDS = Array.from({ length: 30 }, (_, i) => `WRAPW${String(i + 1).padStart(2, "0")}`).join(" ");
const rowsOf = (from: number, to: number): string =>
  Array.from({ length: to - from + 1 }, (_, i) => `WRAPW${String(from + i).padStart(2, "0")}`).join(" ");

test("probe: 30 words wrap at 78 columns, 9 words a row, the break space ends the upper row", () => {
  const rows = wrapLine(WORDS, 78);
  assert.deepEqual(rows.map((r) => r.trimEnd()), [rowsOf(1, 9), rowsOf(10, 18), rowsOf(19, 27), rowsOf(28, 30)]);
  assert.equal(rows[0], rowsOf(1, 9) + " ");
  assert.ok(rows.every((r) => layoutWidth(r) <= 78));
});

test("probe: 158 columns hold 19 words", () => {
  const rows = wrapLine(WORDS, 158);
  assert.equal(rows[0]!.trimEnd(), rowsOf(1, 19));
  assert.equal(rows.length, 2);
});

test("probe: a list item wraps at cols − 4", () => {
  // `- ` + words at indent 2 is the same as the words at width 76 after the marker.
  const rows = wrapLine("- " + WORDS, 76);
  assert.equal(rows[0]!.trimEnd(), "- " + rowsOf(1, 9));
  assert.equal(rows[1]!.trimEnd(), rowsOf(10, 18));
});

test("probe: leading spaces stay on the first row; wrapped rows start at the indent", () => {
  const rows = wrapLine("    HostName " + WORDS, 78);
  assert.equal(rows[0]!.trimEnd(), "    HostName " + rowsOf(1, 8));
  assert.equal(rows[1]!.trimEnd(), rowsOf(9, 17));
  assert.equal(rows[3]!.trimEnd(), rowsOf(27, 30));
});

test("probe: an unbroken word breaks hard at the width (78 + 42)", () => {
  assert.deepEqual(wrapLine("Z".repeat(120), 78), ["Z".repeat(78), "Z".repeat(42)]);
});

test("probe: wide glyphs are two columns (39 syllables on a 78-column row)", () => {
  const rows = wrapLine("한글".repeat(25) + " 끝", 78);
  assert.equal(rows[0], "한글".repeat(19) + "한");
  assert.equal(rows[1], "글한".repeat(5) + "글 끝");
});

test("a line that fits is one row; an empty line is one empty row", () => {
  assert.deepEqual(wrapLine("short", 78), ["short"]);
  assert.deepEqual(wrapLine("", 78), [""]);
  assert.deepEqual(layoutRows("a\n\nb\n", 78).map((r) => r.text), ["a", "", "b"]);
});

test("first-row width: line 1 starts narrower, later rows are full width", () => {
  const rows = wrapLine(WORDS, 78, 40);
  assert.ok(layoutWidth(rows[0]!) <= 40);
  assert.equal(rows[0]!.trimEnd(), rowsOf(1, 5));
  assert.equal(rows[1]!.trimEnd(), rowsOf(6, 14));
});

test("first-row width: a word wider than the first row but not the rest moves down", () => {
  const w = "X".repeat(60);
  assert.deepEqual(wrapLine(w, 78, 40), ["", w]);
});

test("first 0: the head row stays empty and line 1 starts on the next row", () => {
  const rows = layoutRows("alpha\nbeta", 78, 0);
  assert.deepEqual(rows, [{ text: "", line: -1 }, { text: "alpha", line: 0 }, { text: "beta", line: 1 }]);
});

test("layoutRows tags each row with its line; the first width applies to line 1 only", () => {
  const rows = layoutRows(`${WORDS}\n${WORDS}`, 78, 40);
  const line0 = rows.filter((r) => r.line === 0).length;
  const line1 = rows.filter((r) => r.line === 1).length;
  assert.equal(line0, wrapLine(WORDS, 78, 40).length);
  assert.equal(line1, 4);
});

test("cleanLine: escapes and control bytes go; a TAB reaches the next multiple of 8", () => {
  assert.equal(cleanLine("a\x1b[31mb\x1b[0m\x07c"), "abc");
  assert.equal(cleanLine("ab\tc"), "ab      c");
  assert.equal(cleanLine("\tx"), "        x");
  assert.equal(cleanLine("한\tx"), "한      x");
});

/**
 * A reference terminal, independent of cleanLine: print `text` with the
 * cursor at column `col0` of a blank row (a TAB moves the cursor to the next
 * multiple of 8, a glyph takes its width), then read the row back from
 * `col0` (blanks as spaces, trailing ones kept up to the cursor).
 */
function terminalRow(text: string, col0: number): string {
  const cells: string[] = [];
  let x = col0;
  for (const ch of text) {
    if (ch === "\t") {
      x = (Math.floor(x / 8) + 1) * 8;
      continue;
    }
    const w = layoutWidth(ch);
    if (w === 0) {
      cells[x - 1] = (cells[x - 1] ?? " ") + ch;
      continue;
    }
    cells[x] = ch;
    for (let k = 1; k < w; k++) cells[x + k] = "";
    x += w;
  }
  let out = "";
  for (let i = col0; i < x; i++) out += cells[i] ?? " ";
  return out;
}

test("cleanLine with a start column: TAB stops are the terminal's, counted from its column 0", () => {
  assert.equal(cleanLine("ab\tc", 0), "ab      c", "column 0: as before");
  assert.equal(cleanLine("ab\tc", 2), "ab    c", "from column 2 the stop is 8: 4 spaces");
  assert.equal(cleanLine("\tx", 2), "      x");
  assert.equal(cleanLine("\tx", 8), "        x", "on a stop: a full 8");
  assert.equal(cleanLine("\tx", 7), " x", "one column before a stop: 1");
  assert.equal(cleanLine("한\tx", 3), "한   x", "a wide glyph counts 2: 3+2 = 5, 3 to the stop");
  assert.equal(cleanLine("ab\tc", -4), "ab      c", "a negative start counts from 0");
  assert.equal(cleanLine("ab\tc", 2.5), "ab      c", "a fractional start counts from 0");
  assert.equal(cleanLine("abc", 5), "abc", "no TAB: untouched");
  // Against the reference terminal over a seeded corpus, every start column.
  let seed = 1018;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) >>> 0) % n);
  const alphabet = ["a", "b", " ", "\t", "\t", "한", "é", "Z", "́"];
  for (let t = 0; t < 2000; t++) {
    let s = "";
    const len = rnd(40);
    for (let i = 0; i < len; i++) s += alphabet[rnd(alphabet.length)]!;
    if (s.startsWith("́")) s = "a" + s;
    const col0 = rnd(24);
    assert.equal(cleanLine(s, col0), terminalRow(s, col0), `${JSON.stringify(s)} at column ${col0}`);
  }
});

test("vanilla capture (differential-interactive.md §19): a TSV line at the reply's column 2 matches the terminal's stops", () => {
  // Vanilla Claude Code 2.1.292 at 120 columns: `● name  port    owner`,
  // `port` at column 8 and `owner` at 16. The rows are W = 118 wide from
  // column 2 (`indent` 2); before 2026-10-18 they sat 2 columns right.
  const value = "name\tport\towner\nweb\t8080\talice\ndb\t5432\tbob\n";
  const screen = layoutRows(value, 118, 118, "ink", 2).map((r) => `● ${r.text}`);
  assert.deepEqual(screen, ["● name  port    owner", "● web   8080    alice", "● db    5432    bob"]);
  assert.equal(screen[0]!.indexOf("port"), 8);
  assert.equal(screen[0]!.indexOf("owner"), 16);
  assert.deepEqual(layoutRows(value, 118, 118).map((r) => r.text)[0], "name    port    owner", "no indent: the old stops");
});

test("layoutRows with an indent: the head row starts W − F further in, every other line at the indent", () => {
  // A mid-line head 8 columns into a W = 78 row at indent 2: line 1 starts
  // at column 10, so its TAB reaches 16 (5 spaces after `a`); line 2 starts
  // at column 2, its TAB reaches 8.
  assert.deepEqual(layoutRows("a\tb\nc\td", 78, 70, "ink", 2).map((r) => r.text), ["a     b", "c     d"]);
  assert.deepEqual(layoutRows("a\tb\nc\td", 78, 70, "ink", 2).map((r) => r.text),
    [terminalRow("a\tb", 10), terminalRow("c\td", 2)]);
  // F = 0: line 1 starts on its own row, at the indent.
  assert.deepEqual(layoutRows("a\tb", 78, 0, "ink", 4).map((r) => r.text), ["", terminalRow("a\tb", 4)]);
  // The terminal rule: indent 0, a mid-line head at column W − F.
  assert.deepEqual(layoutRows("x\ty", 80, 67, "terminal", 0).map((r) => r.text), [terminalRow("x\ty", 13)]);
  // No indent, or a malformed one, is indent 0 (the content area at the
  // terminal's column 0; the head row still starts W − F in).
  const v = "k\tv\nlonger\tline\t" + WORDS;
  for (const bad of [0, -3, 1.5, Number.NaN]) assert.deepEqual(layoutRows(v, 78, 60, "ink", bad), layoutRows(v, 78, 60));
});

test("with an indent, every single-row line reads as the terminal prints it at its column", () => {
  let seed = 2026;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) >>> 0) % n);
  const alphabet = ["a", "b", "c", " ", "\t", "\t", "한", "Z"];
  for (let t = 0; t < 1000; t++) {
    const lines: string[] = [];
    const count = 1 + rnd(4);
    for (let k = 0; k < count; k++) {
      let s = "";
      const len = rnd(6);
      for (let i = 0; i < len; i++) s += alphabet[rnd(alphabet.length)]!;
      lines.push(s);
    }
    // A trailing empty line is the value's final line break (layoutLines).
    if (lines[lines.length - 1] === "") lines[lines.length - 1] = "z";
    const W = 100 + rnd(80);
    const half = Math.ceil(W / 2);
    const F = rnd(4) === 0 ? 0 : half + rnd(W - half + 1);
    const indent = rnd(12);
    const rule = rnd(2) === 0 ? "ink" : "terminal";
    const rows = layoutRows(lines.join("\n"), W, F, rule, indent);
    for (let k = 0; k < lines.length; k++) {
      const mine = rows.filter((r) => r.line === k);
      assert.equal(mine.length, 1, "precondition: short lines take one row");
      const col0 = indent + (k === 0 && F > 0 ? W - F : 0);
      assert.equal(mine[0]!.text, terminalRow(lines[k]!, col0), `${JSON.stringify(lines[k])} W=${W} F=${F} indent=${indent} ${rule}`);
    }
  }
});

test("layoutLines drops one trailing break and splits on any break", () => {
  assert.deepEqual(layoutLines("a\r\nb\rc\n"), ["a", "b", "c"]);
  assert.deepEqual(layoutLines("a\n\n"), ["a", ""]);
  assert.deepEqual(layoutLines(""), [""]);
});

test("zero-width marks take no column", () => {
  assert.equal(layoutWidth("é"), 1);
  assert.equal(layoutWidth("a​b"), 2);
});

test("linesNotShown counts the lines not complete before the cap row", () => {
  const rows = layoutRows(["one", WORDS, "three", "four"].join("\n"), 78);
  // rows: one | 4 × WORDS | three | four  (7 rows)
  assert.equal(rows.length, 7);
  assert.equal(linesNotShown(rows, 7), 0);
  assert.equal(linesNotShown(rows, 6), 1); // four
  assert.equal(linesNotShown(rows, 3), 3); // WORDS (partial), three, four
  assert.equal(linesNotShown(rows, 1), 3);
});

test("no row is ever wider than its cap, whatever the input", () => {
  let seed = 7;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) >>> 0) % n);
  const alphabet = ["a", "b", " ", " ", "한", "\t", "é", "Z"];
  for (let t = 0; t < 500; t++) {
    let s = "";
    const len = rnd(200);
    for (let i = 0; i < len; i++) s += alphabet[rnd(alphabet.length)]!;
    const W = 20 + rnd(100);
    const F = rnd(3) === 0 ? 0 : Math.ceil(W / 2) + rnd(W - Math.ceil(W / 2) + 1);
    const rows = layoutRows(s, W, F);
    rows.forEach((r, i) => {
      const cap = i === 0 && F > 0 ? F : W;
      assert.ok(layoutWidth(r.text) <= cap, `row ${i} "${r.text}" wider than ${cap} (W=${W}, F=${F})`);
    });
  }
});

// ── the `terminal` rule (reply-row-reservation.md §17): Goose prints its
// reply at column 0 and the terminal's autowrap breaks it ─────────────────

test("terminal rule, probe: Goose 1.53.0's echo of a long line breaks mid-word at the full width", () => {
  // differential-interactive.md §32: the fidelity-echo-wrap screen, vanilla.
  const line = "DIFFWRAP_LONG " + Array.from({ length: 14 }, (_, i) => `SEGW${String(i + 1).padStart(2, "0")}`).join(" ");
  assert.deepEqual(wrapLineTerminal(line, 80), [
    "DIFFWRAP_LONG SEGW01 SEGW02 SEGW03 SEGW04 SEGW05 SEGW06 SEGW07 SEGW08 SEGW09 SEG",
    "W10 SEGW11 SEGW12 SEGW13 SEGW14",
  ]);
  // Ink's rule at cols − 2 moves the whole word: the divergence §17 closes.
  assert.equal(wrapLine(line, 78)[0]!.trimEnd(), "DIFFWRAP_LONG SEGW01 SEGW02 SEGW03 SEGW04 SEGW05 SEGW06 SEGW07 SEGW08 SEGW09");
});

test("terminal rule: the first row is `first` wide, a space at a row's start is kept", () => {
  // "The value is " (13 columns) before the head: F = 67.
  const value = "DIFFINLINE " + Array.from({ length: 12 }, (_, i) => `SEGI${String(i + 1).padStart(2, "0")}`).join(" ");
  const rows = wrapLineTerminal(value, 80, 67);
  assert.equal(rows[0], "DIFFINLINE SEGI01 SEGI02 SEGI03 SEGI04 SEGI05 SEGI06 SEGI07 SEGI08 ");
  assert.equal(layoutWidth(rows[0]!), 67);
  assert.equal(rows[1], "SEGI09 SEGI10 SEGI11 SEGI12");
  assert.deepEqual(wrapLineTerminal("ab cd", 3), ["ab ", "cd"]);
  assert.deepEqual(wrapLineTerminal("abc def", 3), ["abc", " de", "f"]);
});

test("terminal rule: a wide glyph that would straddle the edge moves whole; zero-width marks stay", () => {
  assert.deepEqual(wrapLineTerminal("a" + "한".repeat(3), 6), ["a한한", "한"]);
  assert.deepEqual(wrapLineTerminal("abcdef́g", 6), ["abcdef́", "g"]);
  assert.deepEqual(wrapLineTerminal("", 20), [""]);
  assert.deepEqual(wrapLineTerminal("x".repeat(40), 20), ["x".repeat(20), "x".repeat(20)]);
});

test("terminal rule: layoutRows lays every line out by it, `first` 0 keeps the empty head row", () => {
  const rows = layoutRows("short\n" + "y".repeat(90) + "\nend", 80, 80, "terminal");
  assert.deepEqual(rows.map((r) => [r.text, r.line]), [["short", 0], ["y".repeat(80), 1], ["y".repeat(10), 1], ["end", 2]]);
  assert.deepEqual(layoutRows("ab", 40, 0, "terminal").map((r) => r.text), ["", "ab"]);
  // The default is Ink's: every existing caller is unchanged.
  assert.deepEqual(layoutRows(WORDS, 78), layoutRows(WORDS, 78, 78, "ink"));
  assert.deepEqual(LAYOUT_RULES, ["ink", "terminal"]);
});

test("terminal rule: no row is ever wider than its cap, and the rows rejoin to the line", () => {
  let seed = 11;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) >>> 0) % n);
  const alphabet = ["a", "b", " ", " ", "한", "\t", "é", "Z", "́"];
  for (let t = 0; t < 500; t++) {
    let s = "";
    const len = rnd(200);
    for (let i = 0; i < len; i++) s += alphabet[rnd(alphabet.length)]!;
    const W = 20 + rnd(100);
    const F = rnd(3) === 0 ? 0 : Math.ceil(W / 2) + rnd(W - Math.ceil(W / 2) + 1);
    const rows = layoutRows(s, W, F, "terminal");
    rows.forEach((r, i) => {
      const cap = i === 0 && F > 0 ? F : W;
      assert.ok(layoutWidth(r.text) <= cap, `row ${i} "${r.text}" wider than ${cap} (W=${W}, F=${F})`);
    });
    // Character wrap drops nothing: the rows are the cleaned line, in order
    // (its TAB stops counted from the head's column, W − F in).
    assert.equal(rows.filter((r) => r.line === 0).map((r) => r.text).join(""), cleanLine(s, F > 0 ? W - F : 0));
  }
});
