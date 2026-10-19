/**
 * inline-split-fixtures — a captured INLINE (main screen) cell-diff split of a
 * symbol token, for the screen reconciler's main-screen mask
 * (differential-interactive.md §30).
 *
 * Source: CI pipeline 8633, `fidelity-permission-prompt` on the real-config
 * lane, Claude Code 2.1.273's inline renderer. The Bash tool ran long enough
 * (about 3 s) to show its live output under the `⎿` row that read
 * `Running…`. The token `$MDU:nomodel_Read[5ccd]` has an `n` at the same
 * offset as `Running…`'s `n`, so the renderer's cell diff skipped that cell:
 * `$MDU:` CHA `omodel_Read[5ccd]`. The stream filter never sees a contiguous
 * token, and before the fix the raw token reached the human's terminal and
 * stayed on screen until the tool finished (four CI reds in a day).
 *
 * SPLIT_SETUP reproduces the screen just before that frame (row for row, the
 * header shortened; the renderer writes a NO-BREAK SPACE after `⎿` and `❯`);
 * SPLIT_FRAME is the captured frame, verbatim. The renderer addresses the
 * main screen with moves RELATIVE to its cursor, which SPLIT_SETUP leaves
 * where the capture had it (column 3, row 14).
 */

const NBSP = "\u00a0";
const RULE = "─".repeat(80);

export const SPLIT_TOKEN = "$MDU:nomodel_Read[5ccd]";
export const SPLIT_VALUE = "RC_PROBE_2026_5527";
/** The 0-based viewport row the token is painted on. */
export const SPLIT_ROW = 8;
/** The row's text before the frame, and what the human must see after it. */
export const SPLIT_BEFORE = `  ⎿ ${NBSP}Running…`;
export const SPLIT_AFTER = `  ⎿ ${NBSP}${SPLIT_VALUE}`;

const SETUP_ROWS = [
  " ▐▛███▛█   Claude Code v2.1.273",
  "▝▜██████▀  Haiku 4.5 · API Usage Billing",
  "  ▝▝ ▝▝    ~/workspace",
  "",
  "",
  "❯ DIFF_T1 show notes.md, leave a marker file, and echo the output",
  "",
  "  Bash(cat notes.md; touch diff-marker.txt)",
  SPLIT_BEFORE,
  "",
  "· Channelling… (8s · ↓ 12 tokens)",
  "",
  RULE,
  `❯${NBSP} `,
  RULE,
  "  sl p1/d0 m1 | Haiku 4.5 | workspace | git | +0 -0",
  "  ⏸ manual mode on · ← for agents",
];

/** The screen before the split frame; the cursor ends on row 14 (0-based
 *  13), column 3, as in the capture. Rows end in EL so the 80-column rule
 *  never leaves a pending wrap. */
export const SPLIT_SETUP = SETUP_ROWS.map((r) => `${r}\x1b[K`).join("\r\n") + "\r\x1b[3A\x1b[2C";

/** The captured frame (pipeline 8633, t=18.159 s), verbatim. */
export const SPLIT_FRAME =
  "\x1b[2D\x1b[4B\r\x1b[5C\x1b[9A\x1b[38;5;246m$MDU:\x1b[12Gomodel_Read[5ccd]\r\x1b[5C\x1b[1B(3s)\r\x1b[1B\x1b[39m \x1b[3G   " +
  "\x1b[38;5;246m(ctrl+b to run in background)\r\x1b[2B\x1b[38;5;174m·\x1b[39m \x1b[38;5;180mChannelling…\x1b[38;5;174m " +
  "\x1b[38;5;246m(8s · ↓\x1b[39m \x1b[38;5;246m12 tokens)\x1b[39m\x1b[K\r\x1b[1B\x1b[K\r\x1b[2B\x1b[38;5;246m❯" + NBSP + "\x1b[39m\x1b[7m \x1b[27m\x1b[K" +
  "\r\x1b[1B\x1b[38;5;244m" + RULE + "\x1b[39m\r\r\n\x1b[3G\x1b[38;5;246msl\x1b[6Gp1/d0\x1b[12Gm1\x1b[15G|\x1b[17GHaiku\x1b[23G4.5" +
  "\x1b[27G|\x1b[29Gworkspace\x1b[39G|\x1b[41Ggit\x1b[45G|\x1b[47G+0\x1b[50G-0\x1b[39m\r\r\n\x1b[3G\x1b[38;5;246m⏸\x1b[5Gmanual" +
  "\x1b[12Gmode\x1b[17Gon\x1b[20G·\x1b[22G←\x1b[24Gfor\x1b[28Gagents\x1b[39m\r\r\n\x1b[2C\x1b[4A";
