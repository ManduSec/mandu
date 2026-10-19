/**
 * reserve-fixtures — the reserve-block byte shapes captured by phase 0
 * (docs/design/ui/reply-row-reservation.md §7.1: Claude Code 2.1.285, inline
 * and fullscreen renderers), as unit fixtures for the stream splice
 * (filter.test.ts) and the screen reconciler (screen-reconcile.test.ts).
 * Mandu-new (no reference origin).
 *
 * The block is the one phase 0 drove: `$MDU:nomodel_Bash[464e]` standing for
 * a 5-line ssh config (N = 5). The value is chosen to exercise every per-row
 * rule at once: a line SHORTER than its marker (padded), one LONGER
 * (wrap-off bracketed and clipped), leading indentation (painted), and a
 * TAB (expanded to the tab stop from the row's column).
 */

import * as xtermHeadlessNs from "@xterm/headless";
import { layoutRows } from "../../src/reserve-layout.js";

export const BT = "$MDU:nomodel_Bash[464e]";
export const BV = "Host a\n  HostName a.example.com\n  User git\n\tIdentityFile ~/.ssh/id_a\nHost b\n";
export const BLINES = ["Host a", "  HostName a.example.com", "  User git", "\tIdentityFile ~/.ssh/id_a", "Host b"];
/** Line i (1-based) as a terminal shows it at column `col` (0-based): a TAB
 *  becomes the spaces to the next 8-column stop. */
export function shown(i: number, col = 2): string {
  let c = col;
  let out = "";
  for (const ch of BLINES[i - 1]!) {
    if (ch === "\t") {
      const n = 8 - (c % 8);
      out += " ".repeat(n);
      c += n;
    } else {
      out += ch;
      c += 1;
    }
  }
  return out;
}

/** Phase 0, inline renderer, first paint (contiguous; relative moves; the
 *  head at row 2, rows 3-6 below it, every marker at column 2). */
export const INLINE_FIRST_PAINT =
  `\r\x1b[2B  ${BT}/1:5\x1b[K\r\x1b[1B  $MDU/464e/2\r\x1b[1B  $MDU/464e/3\x1b[K` +
  `\r\x1b[2C\x1b[1B$MDU/464e/4\x1b[K\r\r\n\x1b[3G$MDU/464e/5`;

/** Phase 0, fullscreen renderer, first paint (CR + CUF + CUD per row). */
export const FULLSCREEN_FIRST_PAINT =
  `\x1b[?1049h\x1b[H\r\x1b[2C\x1b[2B${BT}/1:5\r\x1b[2C\x1b[1B$MDU/464e/2\r\x1b[2C\x1b[1B$MDU/464e/3` +
  `\r\x1b[2C\x1b[1B$MDU/464e/4\r\x1b[2C\x1b[1B$MDU/464e/5`;

/** The same first paint inside a fenced code block: the code color around
 *  every row (the fence rows themselves vanish). */
export const FENCED_FIRST_PAINT =
  `\r\x1b[2B  \x1b[38;5;153m${BT}/1:5\x1b[39m\x1b[K\r\x1b[1B  \x1b[38;5;153m$MDU/464e/2\x1b[39m` +
  `\r\x1b[1B  \x1b[38;5;153m$MDU/464e/3\x1b[39m\r\x1b[1B  \x1b[38;5;153m$MDU/464e/4\x1b[39m` +
  `\r\x1b[1B  \x1b[38;5;153m$MDU/464e/5\x1b[39m`;

/** A later RE-LAYOUT frame, cell-diffed (the phase 0 fragment shape
 *  `\r ESC[nC ESC[1B <changed cells>`): a prose row is inserted above the
 *  block, so every row of the block moves down one. From the cursor left at
 *  row 6 by INLINE_FIRST_PAINT, move up to row 1, then write only the cells
 *  that differ from what the TUI believes each row held:
 *    row 2  `  PROBE para` + EL      (was the head)
 *    row 3  `:nomodel_Bash[464e]/1:5` from col 6   (was `$MDU/464e/2`)
 *    row 4  `2` at col 12            (was `…/3`)
 *    row 5  `3` at col 12            (was `…/4`)
 *    row 6  `4` at col 12            (was `…/5`)
 *    row 7  `  $MDU/464e/5`          (new, contiguous)
 *  No byte sequence of rows 3-6 holds a whole marker; only the screen does. */
export const INLINE_RELAYOUT =
  `\x1b[5A\r\x1b[1B  PROBE para\x1b[K\r\x1b[6C\x1b[1B:nomodel_Bash[464e]/1:5` +
  `\r\x1b[12C\x1b[1B2\r\x1b[12C\x1b[1B3\r\x1b[12C\x1b[1B4\r\n  $MDU/464e/5`;

// ── v2 (reply-row-reservation.md §11): wrapped rows, a block inside a line ──
// An 80-column terminal, content indent 2, so W = 78. Synthetic frames in the
// shapes of phase 0's captures (relative moves, EL per row, cell diff).

/** v2 content width at 80 columns. */
export const V2_W = 78;

/** A one-line value WIDER than the terminal: a 120-column API key. At (78,
 *  78) it lays out as 78 + 42 columns (the probe's hard break). */
export const KT = "$MDU:nomodel_Bash[7c1d]";
export const KV = "sk-live-" + "0123456789abcdef".repeat(7);
export const KV_ROWS = layoutRows(KV, V2_W, V2_W).map((r) => r.text);
/** First paint of the key's v2 block, alone on its line (F = W): a prose row,
 *  the head, the continuation, then a closing prose row. */
export const KEY_FIRST_PAINT =
  `\r\n  Your key:\x1b[K\r\n  ${KT}/1:${KV_ROWS.length}:${V2_W}:${V2_W}\x1b[K` +
  `\r\n  $MDU/7c1d/2\x1b[K\r\n  key done\x1b[K`;

/** A value in a SENTENCE: "The value is T and that is all." The prefix takes
 *  13 columns, so F = 78 − 13 = 65; the value is 20 words, laid out 7 / 8 / 5
 *  words (63 / 72 / 44 columns): N = 3. */
export const MT = "$MDU:nomodel_Read[5e2a]";
export const MV = Array.from({ length: 20 }, (_, i) => `secret${String(i + 1).padStart(2, "0")}`).join(" ");
export const MID_PREFIX = "The value is ";
export const MID_SUFFIX = " and that is all.";
export const MID_F = V2_W - MID_PREFIX.length;
export const MID_ROWS = layoutRows(MV, V2_W, MID_F).map((r) => r.text);
export const MID_HEAD = `${MT}/1:${MID_ROWS.length}:${V2_W}:${MID_F}`;
/** First paint (inline renderer): a prose row, then the block with the prefix
 *  before the head on its row and the suffix after the last row's marker.
 *  Rows 1..4; the cursor ends on row 4. */
export const MID_FIRST_PAINT =
  `\r\n  PROBE para\x1b[K\r\n  ${MID_PREFIX}${MID_HEAD}\x1b[K\r\n  $MDU/5e2a/2\x1b[K` +
  `\r\n  $MDU/5e2a/3${MID_SUFFIX}\x1b[K`;
/** A later RE-LAYOUT, cell-diffed: the prose row goes, the block moves UP one
 *  row. From row 4, up to row 1, then only what differs from the TUI's
 *  previous row:
 *    row 1  the head row, whole from column 2 (was `PROBE para`)
 *    row 2  `$MDU/5e2a/2` from column 2 (was the head row)
 *    row 3  `3 and that is all.` from column 12 (was `$MDU/5e2a/2`): a
 *           FRAGMENT — the last row's marker is whole only on the screen
 *    row 4  erased
 *  The cursor ends on row 4, column 0. */
export const MID_RELAYOUT =
  `\x1b[3A\r\x1b[2C${MID_PREFIX}${MID_HEAD}\x1b[K\r\x1b[1B\x1b[2C$MDU/5e2a/2\x1b[K` +
  `\r\x1b[1B\x1b[12C3${MID_SUFFIX}\x1b[K\r\x1b[1B\x1b[K`;
/** What rows 1..3 must read once the block is painted (right-trimmed). */
export const MID_SCREEN = [
  `  ${MID_PREFIX}${MID_ROWS[0]!}`.trimEnd(),
  `  ${MID_ROWS[1]!}`.trimEnd(),
  `  ${MID_ROWS[2]!}${MID_SUFFIX}`,
];

// ── echo-fidelity-long @160x40, the fullscreen renderer (CI 2026-09-30/10-01) ──
// Six per-push pipelines (7752, 7764, 7859, 7875, 7883, 7896) failed F2's raw-
// stream check with `$MDU` (differential-interactive.md §19.1). The wrapped
// side's PTY stream showed the alt-screen renderer re-laying the 33-row block
// out THREE rows up by cell diff, and row 2 going out as
// `ESC[3G $MDU/ ESC[9G 101/3`: the row held `● File content follows:` before,
// whose column 8 is the `c` of "content", the first glyph of the hash, so the
// diff skipped that one cell. Every failing run's hash started with `c` (one in
// sixteen: the flake). The bytes below are pipeline 7896's, with the stream
// filter's splices put back to the markers the TUI wrote (the head padded to
// its 36 columns, each row's value to its `$MDU/c101/<i>`).

export const LONG_HASH = "c101";
export const LONG_TOKEN = `$MDU:nomodel_Read[${LONG_HASH}].content`;
const LONG_WORDS = [
  "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
  "india", "juliett", "kilo", "lima", "mike", "november", "oscar", "papa",
];
const longLine = (n: number, w: string): string => `DIFFLONG_${String(n).padStart(2, "0")} ${w} DL${String(n).padStart(2, "0")}END`;
/** The scenario's 33 value lines (differential-scenarios.ts
 *  PROBE_LONG): 16 anchored lines, a blank one, 16 more. */
export const LONG_LINES = [
  ...LONG_WORDS.map((w, i) => longLine(i + 1, w)),
  "",
  ...LONG_WORDS.map((w, i) => longLine(i + 17, w)),
];
export const LONG_VALUE = LONG_LINES.join("\n") + "\n";
const lm = (i: number): string => `$MDU/${LONG_HASH}/${i}`;
/** The first paint, contiguous: `● File content follows:` on row 2, the head on
 *  row 3, rows 2..33 of the block on rows 4..35 (each row's prefix as
 *  captured: CR + CUD + two spaces, or CR + CUF 2 + CUD). */
export const LONG_FIRST_PAINT =
  `\x1b[H\r\x1b[1B\x1b[38;5;231m●\x1b[39m File content follows:\x1b[K\r\x1b[1B  ${LONG_TOKEN}/1:33\x1b[K` +
  `\r\x1b[1B  ${lm(2)}\x1b[K\r\x1b[2C\x1b[1B${lm(3)}\r\x1b[2C\x1b[1B${lm(4)}\r\x1b[1B  ${lm(5)}\x1b[K` +
  `\r\x1b[2C\x1b[1B${lm(6)}\r\x1b[1B \x1b[3G${lm(7)}\x1b[K\r\x1b[1B  ${lm(8)}` +
  Array.from({ length: 24 }, (_, k) => `\r\x1b[2C\x1b[1B${lm(k + 9)}`).join("") +
  `\r\x1b[1B \x1b[3G${lm(33)}\x1b[K`;
/** The scroll re-layout, cell-diffed: block row i moves from screen row i + 2
 *  to row i - 1. Row 1 is written whole; row 2 (was the prose row) is the
 *  split `$MDU/` CHA `101/3`; row 3 (was the head) from column 7; rows 4..33
 *  only the index digits that differ (`\r ESC[12C ESC[1B 5`). Then the
 *  prose and spinner rows below, and the cursor parked in the input box. */
export const LONG_SCROLL_RELAYOUT =
  `\x1b[40;1H\x1b[38;3H\x1b]0;◑ Claude Code\x07\x1b[H\x1b[3G${lm(2)}` +
  `\r\x1b[1B \x1b[3G$MDU/\x1b[9G${LONG_HASH.slice(1)}/3\x1b[K\r\x1b[6C\x1b[1B/${LONG_HASH}/4\x1b[K` +
  Array.from({ length: 29 }, (_, k) => {
    const was = lm(k + 2);
    const now = lm(k + 5);
    let p = 0;
    while (was[p] === now[p]) p += 1;
    return `\r\x1b[${2 + p}C\x1b[1B${now.slice(p)}`;
  }).join("") +
  `\r\x1b[2C\x1b[1BDIFF_S\x1b[10G_DONE\r\x1b[2C\x1b[1B\x1b[K\r\x1b[1B\x1b[38;5;174m·\x1b[3GCooking… ` +
  `\x1b[38;5;246m(1s · ↓\x1b[20G136 tokens)\x1b[39m\x1b[40;1H\x1b[38;3H`;

/** Render bytes through a fresh headless terminal and return its viewport
 *  rows, right-trimmed (what a human's terminal shows). */
export async function renderScreen(bytes: string, cols = 80, rows = 12): Promise<string[]> {
  const { Terminal } = ((xtermHeadlessNs as { default?: unknown }).default ??
    xtermHeadlessNs) as typeof import("@xterm/headless");
  const term = new Terminal({ cols, rows, allowProposedApi: true, scrollback: 0 });
  await new Promise<void>((r) => term.write(bytes, r));
  const buf = term.buffer.active;
  const out: string[] = [];
  for (let y = 0; y < rows; y++) out.push((buf.getLine(buf.baseY + y)?.translateToString(true) ?? "").trimEnd());
  term.dispose();
  return out;
}
