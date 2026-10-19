/**
 * goose-fixtures — Goose 1.53.0's terminal writes, captured from the reply
 * filter's input during the Goose differential lane (2026-10-06,
 * docs/testing/differential-interactive.md §32): `goose session` at 80x24
 * under `mandu goose`, mode `secrets`, against the scripted model. Each
 * string is one PTY read, byte for byte.
 */

/** The labelled file's value (fidelity-echo-rows' notes.md). */
export const GOOSE_ROWS_VALUE = "DIFFROW_ALPHA one\nDIFFROW_BETA two\n\nDIFFROW_GAMMA three\nDIFFROW_DELTA four";

/** The reply's reserve block, head `T/1:5:78:78`, as Goose writes it: its
 *  Markdown streamer prints the token in two reads and two colors, cut at the
 *  `_` (an emphasis candidate): `$MDU:nomodel` white, then `_shell[9062]…`
 *  magenta, each piece in its own SGR pair. */
export const GOOSE_HEAD_TOKEN = "$MDU:nomodel_shell[9062]";
export const GOOSE_REPLY_READS: readonly string[] = [
  "\x1b[37mFile content follows:\x1b[0m\r\n",
  "\x1b[37m$MDU:nomodel\x1b[0m",
  "\x1b[35m_\x1b[0m\x1b[35mshell[9062]/1:5:78:78\x1b[0m\r\n" +
    "\x1b[35m$MDU/9062/2\x1b[0m\r\n\x1b[35m$MDU/9062/3\x1b[0m\r\n\x1b[35m$MDU/9062/4\x1b[0m\r\n\x1b[35m$MDU/9062/5\x1b[0m\r\n" +
    "\x1b[35mDIFF_S1_DONE\x1b[0m\r\n",
];
/** What vanilla Goose shows for the same reply (the model echoed the file). */
export const GOOSE_REPLY_SCREEN = [
  "File content follows:",
  "DIFFROW_ALPHA one",
  "DIFFROW_BETA two",
  "",
  "DIFFROW_GAMMA three",
  "DIFFROW_DELTA four",
  "DIFF_S1_DONE",
];

/** The shell tool's live row while `cat` runs: a spinner glyph, then the
 *  command's last output line (here the twin token: the file is labelled),
 *  padded with blanks to the terminal width; the next frame repaints the row
 *  with `CR EL`. Then the finished output, four columns in. The first frame
 *  follows a `CR EL` too in the capture's stream. */
export const GOOSE_LIVE_TOKEN = "$MDU:nomodel_Read[18fc]";
const pad = " ".repeat(55);
export const GOOSE_LIVE_READS: readonly string[] = [
  `\r\x1b[2K\x1b[32m⠋\x1b[0m \x1b[2m${GOOSE_LIVE_TOKEN}\x1b[0m${pad}\r\x1b[2K\x1b[32m⠙\x1b[0m \x1b[2m${GOOSE_LIVE_TOKEN}\x1b[0m${pad}`,
  `\r\x1b[2K    \x1b[2m${GOOSE_LIVE_TOKEN}\x1b[0m\r\n`,
];
