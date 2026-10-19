/**
 * filter — the pure user-reply desymbolizing stream core (lift-able logic).
 *
 * Mandu user-reply egress chokepoint (interceptors/reply-filter).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE (CONTRIBUTING.md reuse policy)
 *   The RESOLUTION SEMANTICS are lifted from the reference `message_sending`
 *   hook at
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/index.ts
 *   ("Output resolution: resolve $sym tokens in outbound messages"): before a
 *   reply is delivered to the human, resolve every symbol token to its actual
 *   value — the transcript (the agent's own context) RETAINS the symbols; only
 *   the outbound copy is transformed. Its unescape-before-match step is lifted
 *   byte-for-byte from
 *     arbiter/symbol-table/symbol-format.ts (unescapeSymbols / ESCAPED_SYM_RE,
 *     itself lifted from adfi-openclaw's adfi-symbol-format.ts)
 *   because LLMs frequently Markdown-escape underscores in symbol tokens.
 *   Mandu changes only *where the hook attaches*: OpenClaw resolves inside a
 *   plugin hook on the message object; Mandu has no message object at the OS
 *   level, so the same transform runs over the agent process's STDOUT STREAM
 *   (the user-facing reply channel), chunk-safely. Resolution moves to the
 *   arbiter's deep `desymbolize` op over IPC (the arbiter owns the symbol
 *   table; nested chains collapse server-side — mandu.md §2 "Nested
 *   symbolization and deep resolution").
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * SECURITY POSTURE (deliberately inverted from the enforcement chokepoints):
 *   This is a UTILITY-ONLY surface. The human terminal is HumanView — the
 *   trusted destination that is SUPPOSED to see original data (the same
 *   fidelity promise fs-sync's syncToHuman keeps for on-disk files). Failing
 *   to resolve leaks nothing: the symbol token is opaque by construction. So
 *   on ANY failure (arbiter unreachable, op error) the filter passes the text
 *   through UNCHANGED — fail-closed TOWARD SYMBOLIC, never blocking the
 *   agent's output. Do NOT add approval gating here: gating the human's own
 *   view would break HumanView fidelity, and there is no egress risk to gate.
 *
 * CHUNK SAFETY (default, line-buffered — pipe mode):
 *   Symbols never contain newlines or carriage returns, so text up to the last
 *   line boundary (\n or \r — \r matters for TUI redraws and progress bars) is
 *   always safe to process. The current partial line is HELD until its boundary
 *   arrives; a pathological unbroken line is force-flushed past MAX_TAIL_HOLD
 *   at a cut point that never splits a candidate token.
 *
 * EAGER MODE (opts.eager — the PTY relay):
 *   Line-buffering a TUI stream delays exactly the bytes that must not lag:
 *   the frame's final cursor-control sequences (hide/show cursor, positioning,
 *   DSR queries) and the unterminated bottom line — held 50–250ms per repaint,
 *   the terminal cursor visibly blinks/jumps. Eager mode inverts the posture:
 *   every write EMITS IMMEDIATELY (tokens in it resolved inline), holding back
 *   ONLY a trailing suffix that could still be an in-flight token
 *   (candidateCut — wrap insertions looked through). A normal TUI frame ends
 *   in escapes/prompt text, never token-prefix-shaped, so nothing is held and
 *   display timing is byte-for-byte what the TUI wrote; a held candidate is
 *   drained by the caller's quiet-period flush(false) (which re-holds a
 *   still-in-flight token, bounded — see IDLE-DRAIN RE-HOLD below).
 *
 * AGGRESSIVE WRAP REASSEMBLY (TUI streams):
 *   A TUI that hard-wraps a long token injects INSERTIONS mid-token — \r/\n,
 *   continuation indent, ANSI escape sequences. Tokens are therefore matched
 *   ON A CLEANED VIEW of each span (insertions stripped, with an index map
 *   back to the original bytes) and the resolved value is spliced over the
 *   whole interrupted span; bytes outside token spans are NEVER altered, so
 *   the TUI's own control sequences survive. A token interrupted by SGR
 *   alone (a Markdown streamer restyling it mid-token: Goose 1.53 prints
 *   `$MDU:nomodel` and `_shell[…]` in two colors, differential-interactive.md
 *   §32) is still ONE row: it keeps the single-row splice (a reserve head
 *   suffix after it is part of the unit, the column model registers it), and
 *   its SGR sequences are re-emitted after the value, so the pen ends as the
 *   TUI set it (setRowGeometry). An INCOMPLETE token prefix left
 *   dangling at an emit boundary is pulled back into the held tail so its
 *   continuation (the next wrapped row) can complete it; in eager mode a
 *   COMPLETE token is held too — only until the next non-styling byte — since
 *   its `.field` chain may still be streaming (see candidateCut).
 *   Aggressive-by-design: the token grammar ($MDU:…[hex]) is
 *   distinctive enough that non-symbol text virtually never glues into a
 *   candidate, and a false candidate merely fails the arbiter lookup and
 *   passes through byte-identical (utility-only surface — nothing can leak).
 *   ONE glue shape is real and common, though: a token that ENDS a line
 *   whose next line starts with a word (`KEY = $MDU:…[h].key_id` then
 *   `aws_secret_access_key = …`, or `echo $GITHUB_TOKEN; echo done`). The
 *   `\n` is a genuine line break, but it is also a wrap insertion, so the
 *   cleaned view reads `…key_idaws_secret_access_key` (a name the arbiter
 *   never allocated), and the token stayed raw on the human's terminal while
 *   a quote-terminated `.env` token beside it resolved (release checklist
 *   a3, 2026-09-26: "secrets render differently by source"). LINE-END GLUE
 *   FALLBACK: when a reassembled token does NOT resolve, the filter retries
 *   the shorter complete tokens that end exactly at one of its insertion
 *   boundaries (longest first) and splices only the one that resolves,
 *   leaving the insertion and the next line's word untouched. The full
 *   reassembly is always tried first, so a genuinely wrapped token keeps
 *   resolving as before (confidentiality.md §7, "Secrets on the human's
 *   terminal: one rendering for every source").
 *
 * FRAME-SAFE VALUE RENDERING (eager mode — the width-mismatch fix):
 *   A TUI paints frames with per-word absolute column addressing (CHA) and
 *   relative row moves, computing its erase/repaint regions for the text it
 *   BELIEVES it printed — the short symbol token. Splicing a LONGER value in
 *   its place desynchronizes the terminal from the TUI's cursor arithmetic:
 *   raw \n/\t in the value punch the cursor through rows the TUI owns, and a
 *   value that runs past the right edge wraps onto a physical row the TUI
 *   never counted — stale fragments then persist on the settled screen
 *   (found by the differential harness's first run, 2026-07-17;
 *   docs/testing/differential-interactive.md §10). In eager mode a
 *   substitution must therefore be CURSOR-NEUTRAL:
 *     - the value is rendered as ONE ROW (frameSafeValue: newlines become
 *       " ⏎ ", embedded escapes/C0 stripped; a TAB becomes the SPACES that
 *       reach the next 8-column tab stop when the splice column is known,
 *       one space when it is not, see COLUMN-AWARE TAB EXPANSION below);
 *     - a value longer than the token it replaces is bracketed in
 *       ESC[?7l … ESC[?7h (auto-wrap off), so it CLIPS at the row edge
 *       instead of wrapping — intra-row column drift self-heals at the
 *       TUI's next CHA. (Restore-to-?7h assumes the TUI runs with auto-wrap
 *       on — claude's stream shows no ?7 usage; a TUI that disables wrap
 *       itself would fight the restore, accepted + documented.)
 *   The inherent limit, stated honestly: multi-line values CANNOT be
 *   reflowed into a positioned frame from outside the renderer, unless the
 *   proxy reserved the rows (RESERVED ROWS below) — otherwise the human
 *   sees a clipped single-row rendering under a live TUI (the full value
 *   still reaches HumanView surfaces: pipe mode, fs-sync files, the
 *   dashboard). Pipe mode (linear output, no frames) keeps full-fidelity
 *   multi-line substitution byte-identical to before.
 *
 * RESERVED ROWS (eager mode; docs/design/ui/reply-row-reservation.md §3.7):
 *   For a multi-line token alone on its line, the proxy sends Claude Code an
 *   N-row RESERVE BLOCK instead (reserve-block.ts: a head row `T/1:N`, then
 *   continuation rows `$MDU/<hash>/<i>`), so the renderer lays out N rows
 *   with its own arithmetic. Each marker is a splice unit like a token: the
 *   head resolves T (deep `desymbolize`, cached per session) and paints line
 *   1; a continuation finds the value through the head that announced its
 *   hash and paints line i. Every row is rendered by the SAME frame-safe
 *   rules as a token value — one row, control bytes stripped, a TAB expanded
 *   (column-aware), padded to the marker's width when shorter, wrap-off
 *   bracketed when longer — and the column translation applies unchanged,
 *   row by row; a line's leading spaces are painted. The row past a capped
 *   block's N shows `… +K more lines`. No value (arbiter down, unknown
 *   token, hash never seen): the head reads `T (N lines)`, a continuation
 *   row goes blank; nothing can leak. A head is ONE unit (never T resolved
 *   beside a stray `/1:N`: a partial suffix at a chunk edge is held like a
 *   token prefix); a continuation row has no `:` and is never a candidate.
 *   The stream splices only markers that are CONTIGUOUS on the wire (every
 *   first paint); a re-layout's cell-diff fragments are healed by the screen
 *   reconciler, which takes reserve rows on the main screen too (on the
 *   alternate screen the relay also blanks a fragment's `$MDU` bytes before
 *   they are written, screen-reconcile.ts maskFragments). One
 *   onResolve per head per session, with the whole value. Pipe mode (a
 *   block never expected there) collapses the block to the full value.
 *   V2 (reply-row-reservation.md §11): a head `T/1:N:W:F` announces N ROWS
 *   of reserve-layout.ts layoutRows(value, W, F) (Ink's word wrap), and row i
 *   paints layout row i (already cleaned: no TAB, no escape, so the frame-
 *   safe pass leaves it as is); F = 0 paints the head blank. A v2 block may
 *   sit INSIDE a line: prefix text before the head is left alone, and suffix
 *   text after the last row's marker follows the painted row. When a v2 row
 *   is wider than its marker, its wrap-off bracket stays open while the TUI
 *   keeps printing on the row (printable text, SGR, EL, CHA, CUF, CUB), so
 *   the suffix, shifted right by the splice, CLIPS at the right edge instead
 *   of wrapping. Tokens and v1 rows close the bracket right after the
 *   value, except over the BLANKS a TUI pads the row with when those would
 *   run past the edge (Goose's live tool row pads its token to the width:
 *   the wrapped pad started a row the TUI never counted, and every spinner
 *   frame was left behind as a row; differential-interactive.md §32): the
 *   blanks stay wrap-off and those past the edge are not sent. The column
 *   translation shifts the TUI's later same-row moves as for any splice. In
 *   pipe mode each continuation row is dropped with the line break BEFORE it
 *   (what the proxy inserted), so `T` and its suffix read as the model wrote
 *   them; a line ending in a marker holds its line break until the next
 *   line. A value's width is counted in DISPLAY columns (a wide glyph 2, a
 *   combining mark 0), so a wide row is bracketed, never padded past the edge.
 *   After a resize (§13) the TUI reprints the block at the new width: on a
 *   terminal narrower than when the block's head was first seen, the value
 *   is laid out anew at W − d (reserve-block.ts paintLayout), with the cap
 *   note on row N when the N rows no longer hold it; wider keeps the layout.
 *
 * POST-SPLICE COLUMN TRANSLATION (eager mode — the differential harness's
 * SECOND catch, 2026-07-17, soak run 7):
 *   Frame-safe rendering keeps the CURSOR honest but not the TUI's own
 *   follow-up geometry: after painting its (short) token the TUI re-addresses
 *   the row with math computed for the token's width — observed live as
 *   `CHA token-end` + `EL` (`ESC[19G ESC[K`), which lands INSIDE a longer
 *   spliced value and erases its tail from the settled screen. The filter
 *   therefore keeps a TUI-SPACE column model over everything it emits: each
 *   splice that lengthened a row registers {boundary: token-end column,
 *   delta: value − token width}, and every subsequent same-row absolute
 *   column move (CHA) / relative move (CUF/CUB) crossing a boundary has its
 *   parameter shifted by the accumulated delta — the TUI's erase then lands
 *   AFTER the value, where the TUI's stale-content assumption is actually
 *   true. Row abandonment (CR, LF, any row-moving sequence) clears the row's
 *   registrations; a sequence the model cannot classify BAILS (registrations
 *   dropped, column unknown until the next CR/CHA/CUP re-anchor), degrading
 *   to the pre-translation behavior — never worse. A chunk ending mid-escape
 *   is carried into the next write so a sequence is never scanned (or
 *   translated) in halves. The erase-tail rewrite covers MULTI-splice rows
 *   (erase from the LAST value's real end, cumulative deltas) and the idiom
 *   SPLIT across a PTY read boundary: a trailing complete CHA that could
 *   still pair with an incoming EL is HELD (csiHold, the escCarry pattern
 *   for COMPLETE sequences — a trailing cursor move renders nothing until
 *   more bytes arrive anyway) and drained translated-plain by any flush.
 *   A value SHORTER than its token is PADDED with spaces to the token's
 *   width: the row's geometry then matches the TUI's belief exactly, and
 *   the token's ghost tail (stale glyphs from the previous frame) is
 *   blanked instead of surviving next to the value (the live 2026-07-18
 *   shape: a 15-col Bash token resolving to a 12-col release code). The
 *   pad keeps the TUI's cursor math exact while the frame is written; the
 *   screen reconciler then CLOSES UP the gap on the human's row (screen-
 *   reconcile.ts, differential-interactive.md §31), and the onResolve trace
 *   reports the value without it.
 *   Accepted residuals, chosen small over clever: a partial `\r` repaint
 *   that skips the token region, an erase-tail landing BETWEEN two splices
 *   (plain translation), and wide-glyph (CJK) TEXT painted by the TUI on the
 *   row, whose code-point count under-measures its column width (a value's
 *   own width is measured in display columns since 2026-09-30, so a wide
 *   value is bracketed and its delta registered exactly) — each degrades to
 *   at most today's clip, and only on rows that carried a symbol.
 *
 * CLIP PAST THE EDGE (eager mode, 2026-10-17; differential-interactive.md
 * §36): the translation moves the TUI's later same-row text right by the
 * splice's delta, and on a row whose value is much wider than its token that
 * text lands PAST THE RIGHT EDGE (a 107-column Stripe key for a 41-column
 * token: the next word's `CHA 114` became `CHA 180` on a 120-column
 * terminal). The wrap-off bracket closes right after the value, so that text
 * went out with auto-wrap on and wrapped onto rows the TUI never counted;
 * every relative row move after it landed low, and a later row showed cells
 * from the wrapped run (`connected0totStripe`). When the terminal width is
 * known (opts.cols) and the session's renderer places its rows itself (the
 * Ink wrap rule; not Goose's terminal rule, whose text after a value wraps
 * by itself as vanilla's does, reply-row-reservation.md §17):
 *     - a value goes out cut to the columns its row has left from its real
 *       start (a wide glyph that would straddle the edge is dropped), so the
 *       row's last cell is the glyph that belongs there;
 *     - a printable glyph the TUI places on the row (its TUI column at most
 *       the width) whose REAL column is past the edge is not sent;
 *     - an EL (erase to the row's end) from past the edge is not sent: there
 *       is nothing of the row to erase, and the terminal, whose cursor sits
 *       on the last column, would erase the last cell the row shows;
 *     - a CUF/CUB from past the edge goes out as the CHA to the real column
 *       it means (the terminal's cursor is on the last column, not at the
 *       model's real one).
 *   The row then reads as the screen reconciler's desired(row) clips it
 *   (screen-reconcile.ts: the value in place of its token, the cells after
 *   it shifted right and clipped), so the reconciler finds nothing to fix.
 *   Residual: a TUI that itself writes past its width, leaning on the
 *   terminal's auto-wrap, on a row an Ink-rule session widened, keeps the
 *   old behavior for the glyphs past its width (no Ink renderer does).
 *
 * COLUMN-AWARE TAB EXPANSION (eager mode, 2026-09-20; closes the §19
 * TAB-in-value residual where the column is known):
 *   The vanilla TUI prints a value's TAB raw and the terminal advances to the
 *   next tab stop (every 8 columns, the terminal default), so the tab's width
 *   depends on the COLUMN it lands on. A raw TAB must never be spliced (it
 *   is a cursor jump the TUI did not plan), so the tab is rendered as the
 *   spaces that reach the same stop. The column is NOT known where the value
 *   is rendered (resolveText works on bytes, before the column model runs);
 *   it IS known in applyColumnModel when the scanner reaches the splice
 *   mark, so a tab-carrying value is re-rendered THERE, and only when every
 *   one of these holds (tabSpliceCol): the TUI-space column is anchored
 *   (tuiCol non-null: a CR/CHA/CUP was seen on this row), every glyph counted
 *   since that anchor has a certain width of one column (colExact: no
 *   wide/combining/zero-width glyph, whose code-point count mis-measures the
 *   column), the terminal width is known (opts.cols) and the real column
 *   (TUI column + the deltas of the splices left of it) is inside the row
 *   (a run that overflowed the right edge auto-wrapped onto a row this model
 *   never saw). Anywhere else the ONE-SPACE rendering stays, as the
 *   documented fallback: a filter constructed without a width, a row with no
 *   anchor yet, a row that carried an uncertain-width glyph, and a token the
 *   TUI wrap-SPLIT over two rows (no splice mark, no single-row geometry).
 *   On the alternate screen the screen reconciler (screen-reconcile.ts), which
 *   knows the exact column from its cell model, repaints a fallback row to
 *   the tab-stop form. The observability callback (onResolve) still reports
 *   the one-space form: it fires before the column is known, and it is a
 *   trace, not the screen. Tab stops are assumed to be the default 8; a TUI
 *   that reprograms them (HTS/TBC) is not modeled.
 *
 * IDLE-DRAIN RE-HOLD (eager mode — the SSE-gap raw-leak fix, 2026-07-18):
 *   The model streams a token's base and its `.field` chain in SEPARATE
 *   deltas (a natural BPE/SSE boundary), and under API load the gap between
 *   them can exceed the relay's quiet period. The idle flush() used to drain
 *   the held base unconditionally: the arbiter resolves only the EXACT
 *   allocated name, so a base awaiting its field came back unchanged and was
 *   emitted RAW — the human saw `$MDU:inspect[003d]` (live: pipeline 6414
 *   interactive-inspect-extract, 0 desymbolize events + a raw token in the
 *   terminal stream). flush(final=false) — the relay's quiet-period drain —
 *   now RE-HOLDS a tail that is still a candidate (a complete token the
 *   arbiter does not know yet, or a mid-token prefix), bounded by
 *   IDLE_HOLD_MAX consecutive re-holds (~2s at the relay's cadence) so a
 *   ghost token can never stall the stream; a complete token the arbiter
 *   DOES know resolves and emits on the first idle drain exactly as before.
 *   flush() with no argument stays a FINAL flush: stream end emits
 *   everything, resolved or not — bytes are never lost.
 *   Since the third live hit of this seam (pipeline 6420, 2026-07-19 — a TUI
 *   frame INTERPOSED between base and field, which no hold can bridge), the
 *   ARBITER backstops the whole class: its lookup walk aliases a stranded
 *   base to its one allocated field extension (symbol-format
 *   uniqueFieldExtension), so a bare base that reaches resolution — via the
 *   candidate-breaking frame, or an idle drain outrunning its budget —
 *   resolves instead of emitting raw (see candidateCut's doc for the
 *   residuals + the pinned e2e).
 */

import {
  CONT_ANCHOR,
  HEAD_SUFFIX_MAX,
  ReserveValueCache,
  blockRowText,
  findContinuations,
  parseHeadSuffix,
  tokenHash,
  unknownHeadText,
} from "./reserve-block.js";
import { layoutGlyphWidth, layoutWidth } from "./reserve-layout.js";

// ─────────────────────────────────────────────────────────────────────────────
// Symbol-token helpers — lifted byte-for-byte from
// arbiter/symbol-table/symbol-format.ts (unescapeSymbols + ESCAPED_SYM_RE).
// Kept as a local copy so this package typechecks/runs standalone (the arbiter
// is a sibling package); the grammar is stable and covered by unit tests here.
// ─────────────────────────────────────────────────────────────────────────────

/** Every symbol token spelling (canonical or Markdown-escaped), global.
 *  Exported for the screen reconciler (screen-reconcile.ts), which scans
 *  rendered rows with the same grammar. Reset `lastIndex` before reuse. */
export const SYMBOL_TOKEN_RE =
  /\\?\$MDU:(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9])*\[[0-9a-f]{4,8}\](?:\.(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9[\].])*)*/g;
const ESCAPED_SYM_RE = SYMBOL_TOKEN_RE;

/** Strip Markdown backslash escapes from symbol tokens in a string. Only
 *  touches sequences that look like Mandu symbols — leaves other text alone. */
export function unescapeSymbols(text: string): string {
  ESCAPED_SYM_RE.lastIndex = 0;
  return text.replace(ESCAPED_SYM_RE, (match) => match.replace(/\\/g, ""));
}

/** The placeholders `text` names, unescaped, each once, in order: what the
 *  `desymbolize` event records as the reply's AgentView form (run.ts). Names
 *  only, never the text around them. */
export function placeholderNames(text: string): string[] {
  ESCAPED_SYM_RE.lastIndex = 0;
  return [...new Set([...text.matchAll(ESCAPED_SYM_RE)].map((m) => m[0].replace(/\\/g, "")))];
}

/** Cheap substring pre-check that covers BOTH the canonical and the
 *  Markdown-escaped spellings ($MDU: / \$MDU:) — the `$MDU:` anchor has no
 *  underscores so only its leading `$` can be escaped, leaving the substring
 *  intact. A false positive only costs one IPC round-trip that returns the
 *  text unchanged. */
const CANDIDATE = "$MDU:";

/** True iff `text` may contain a symbol token (either spelling). */
export function mayContainSymbol(text: string): boolean {
  return text.includes(CANDIDATE);
}

/** Literal head of every token (canonical spelling, escapes stripped). */
const TOKEN_HEAD = "$MDU:";
/** Chars that may legally continue a token after its head: tag/hash/field path
 *  (letters, digits, _, [hex], .field[idx]) — see ESCAPED_SYM_RE. */
const TOKEN_CONTINUATION_RE = /^[a-zA-Z0-9_[\].]*$/;
/** A COMPLETE canonical token (ESCAPED_SYM_RE's unescaped alternative,
 *  anchored) — used to decide "resolve now" vs "hold for the wrapped rest". */
const COMPLETE_TOKEN_RE =
  /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_](?:_|[a-zA-Z0-9[\].])*)*$/;
/** COMPLETE_TOKEN_RE's body (anchors dropped), for the reserve-head forms. */
const COMPLETE_TOKEN_BODY = COMPLETE_TOKEN_RE.source.slice(1, -1);
/** A COMPLETE reserve-block head row, v1 `T/1:N` or v2 `T/1:N:W:F`
 *  (reserve-block.ts): resolves now, like a complete token (the digits may
 *  still grow; see candidateCut). */
const COMPLETE_HEAD_RE = new RegExp(`^${COMPLETE_TOKEN_BODY}\\/1:[0-9]{1,3}(?::[0-9]{1,4}:[0-9]{1,4}(?::[0-9]{1,4})?)?$`);
/** A complete token followed by a PARTIAL head suffix (`/`, `/1`, `/1:`,
 *  `/1:N`, and v2's `/1:N:`, `/1:N:W`, `/1:N:W:`, `/1:N:W:F`): still a
 *  candidate, so the head is never split into a resolved token and a stray
 *  suffix at a chunk edge. */
const HEAD_PREFIX_RE = new RegExp(
  `^${COMPLETE_TOKEN_BODY}\\/(?:1(?::[0-9]{0,3}(?::[0-9]{0,4}(?::[0-9]{0,4}(?::[0-9]{0,4})?)?)?)?)?$`,
);
/** True for a candidate that can resolve right now: a complete token or a
 *  complete reserve head. */
function isCompleteCandidate(cleaned: string): boolean {
  return COMPLETE_TOKEN_RE.test(cleaned) || COMPLETE_HEAD_RE.test(cleaned);
}

// ─────────────────────────────────────────────────────────────────────────────
// Insertions — what a terminal/TUI may inject INSIDE a wrapped token. Symbols
// contain none of these, so any of them inside an otherwise token-shaped span
// is a wrap artifact, not content. The set is deliberately NARROW — only what
// a row wrap or styling actually injects mid-word: SGR styling, erase-to-EOL
// (EL, at a wrapped row's end), carriage returns, and newlines with their
// continuation indent. Every OTHER escape — cursor movement (CHA/CUP/CUD…),
// mode toggles (?25l/h), OSC, two-byte Fe — is a WRITE-HEAD MOVE: real
// streams use CHA to position every WORD of a repainted row and pure-control
// frames as heartbeats, so those BREAK a candidate token instead of gluing
// through it. (History: treating ALL ANSI as look-through made heartbeat
// frames invisible to the candidate check, so a symbol-terminal reply stayed
// held all session — live 1783791601-1802875; the emit-complete-NOW patch for
// that then emitted bare bases split at the ']'↔'.field' seam raw — live
// 1783831380-3877123; and CHA look-through glued repainted words into the
// field path. The narrow glue set fixes all three at the root.) A dangling
// PARTIAL escape (chunk-split CSI like `\x1b[5`) matches nothing and so also
// breaks the candidate — its parameter bytes must never strand as "text".
// ─────────────────────────────────────────────────────────────────────────────

const GLUE_ESCAPE = "\\x1b\\[[0-9;:]*[mK]";
const INSERTION_RUN_RE = new RegExp(`(?:${GLUE_ESCAPE}|\\r|\\n[ \\t]*)+`, "g");

/**
 * Strip insertion runs from `text`, keeping an index map back to the original:
 * `map[i]` is the original index of `clean[i]`. Token matching runs on `clean`;
 * splicing runs on the original bytes, so nothing OUTSIDE a token span is ever
 * altered (the TUI's own control sequences survive verbatim).
 */
export function stripInsertions(text: string): { clean: string; map: number[] } {
  INSERTION_RUN_RE.lastIndex = 0;
  let clean = "";
  const map: number[] = [];
  let last = 0;
  for (const m of text.matchAll(INSERTION_RUN_RE)) {
    for (let i = last; i < m.index; i++) map.push(i);
    clean += text.slice(last, m.index);
    last = m.index + m[0].length;
  }
  for (let i = last; i < text.length; i++) map.push(i);
  clean += text.slice(last);
  return { clean, map };
}

/** An SGR sequence (styling only: no cursor move, no cell). */
const SGR_RE = /\x1b\[[0-9;:]*m/g;

/**
 * A token span's row geometry: `inRow` when the token sits on one row (not
 * split at all, or split by SGR sequences alone), and the SGR sequences it
 * carried (`sgr`) when split. A TUI that streams Markdown may restyle a token
 * in the middle (Goose 1.53 prints `$MDU:nomodel` in one color and, from the
 * `_` on, another; differential-interactive.md §32): that token is still one
 * row of cells, so it keeps the single-row splice (a reserve head suffix, the
 * column model). A token split by a line break or an EL stays `split` only.
 * Pure over `text[s.os, s.oe)`; total.
 */
export function setRowGeometry(s: { os: number; oe: number; cs: number; ce: number; split: boolean; inRow: boolean; sgr: string }, text: string): void {
  if (!s.split) {
    s.inRow = true;
    s.sgr = "";
    return;
  }
  const raw = text.slice(s.os, s.oe);
  const sgr = raw.match(SGR_RE) ?? [];
  const inRow = raw.replace(SGR_RE, "").length === s.ce - s.cs;
  s.inRow = inRow;
  s.sgr = inRow ? sgr.join("") : "";
}

/** CSI escape sequences (any final byte) — stripped out of values rendered
 *  into a frame (a value must never carry its own cursor moves). */
const CSI_RE = /\x1b\[[0-9;:?]*[@-~]/g;

/** East Asian Wide / Fullwidth ranges a terminal renders two columns wide.
 *  A deliberate approximation (the emulator's own table is not exposed): the
 *  CJK blocks, Hangul, fullwidth forms and the common emoji planes. (Lives
 *  here, not in screen-reconcile.ts, because frameSafeValue's tab expansion
 *  needs it and screen-reconcile imports this module.) */
const WIDE_RE = /[ᄀ-ᅟ⺀-〾ぁ-㏿㐀-䶿一-鿿ꀀ-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦\u{1f300}-\u{1f64f}\u{1f900}-\u{1f9ff}\u{20000}-\u{2fffd}\u{30000}-\u{3fffd}]/u;

/** Column width of one glyph (code point). */
export function glyphWidth(ch: string): number {
  return WIDE_RE.test(ch) ? 2 : 1;
}

/** Glyphs whose on-screen width a code-point count cannot be trusted for:
 *  wide (two columns), combining marks, zero-width and variation selectors.
 *  A row that carried one no longer has an EXACT column (see colExact). */
const UNCERTAIN_WIDTH_RE = /[\p{M}\u200b-\u200f\u2060\ufe00-\ufe0f]/u;
function hasUncertainWidth(s: string): boolean {
  return /[^\x20-\x7e]/.test(s) && (WIDE_RE.test(s) || UNCERTAIN_WIDTH_RE.test(s));
}

/** Terminal default tab stops: every 8 columns. */
export const TAB_STOP = 8;

/**
 * Render a resolved value CURSOR-NEUTRALLY for splicing into a TUI frame
 * (eager mode — see FRAME-SAFE VALUE RENDERING in the header): one row, no
 * control bytes. Trailing newlines drop (file contents end with one); inner
 * newlines become " ⏎ " so line structure stays readable; embedded escapes
 * and remaining C0 bytes are stripped. A TAB is never emitted raw (it jumps
 * the cursor to a tab stop the TUI didn't plan):
 *   - `startCol` given (the 0-based screen column the value's first glyph
 *     lands on): each tab becomes the spaces that reach the next TAB_STOP
 *     multiple, the column tracked glyph by glyph, which is what the vanilla
 *     terminal shows for the raw tab;
 *   - `startCol` omitted (or not a finite non-negative number): each tab is
 *     ONE space, the documented fallback for a caller that does not know
 *     the column.
 * Total by construction: never throws, whatever the input.
 */
export function frameSafeValue(v: string, startCol?: number): string {
  const flat = v
    .replace(/[\r\n]+$/, "")
    .replace(/\r\n|\r|\n/g, " ⏎ ")
    .replace(CSI_RE, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
  if (!flat.includes("\t")) return flat;
  if (typeof startCol !== "number" || !Number.isFinite(startCol) || startCol < 0) {
    return flat.replace(/\t/g, " ");
  }
  let col = Math.floor(startCol);
  let out = "";
  for (const ch of flat) {
    if (ch === "\t") {
      const n = TAB_STOP - (col % TAB_STOP);
      out += " ".repeat(n);
      col += n;
    } else {
      out += ch;
      col += glyphWidth(ch);
    }
  }
  return out;
}

/**
 * True iff `s` (a string starting at a `$` / `\$`) could be the PREFIX of a
 * symbol token still arriving — i.e. holding it may let a split token
 * reassemble. Insertions (wrap artifacts) and Markdown escapes are looked
 * through. Used by the idle flush and the force-flush cut so neither ever
 * emits half of an in-flight token, while text that merely contains a `$`
 * ("total: $5.00 > ") is never held hostage.
 */
export function couldBeSymbolPrefix(s: string): boolean {
  const t = s.replace(INSERTION_RUN_RE, "").replace(/\\/g, "");
  if (t.length === 0) return false;
  if (t.length <= TOKEN_HEAD.length) return TOKEN_HEAD.startsWith(t);
  if (!t.startsWith(TOKEN_HEAD)) return false; // a `$MDU/…` continuation row never holds
  return TOKEN_CONTINUATION_RE.test(t.slice(TOKEN_HEAD.length)) || HEAD_PREFIX_RE.test(t);
}

/**
 * Index in `s` where an INCOMPLETE in-flight token (possibly already split by
 * wrap insertions) dangles at the very end, or -1. write() pulls this suffix
 * back into the held tail so the next wrapped row can complete it. A COMPLETE
 * token returns -1 — it can resolve right now and must never be delayed (a
 * trailing newline is usually a real line end, not a wrap).
 */
function danglingIncompleteStart(s: string): number {
  const windowFrom = Math.max(0, s.length - SYMBOL_RESERVE * 2);
  let d = s.lastIndexOf("$");
  if (d < windowFrom) return -1;
  if (d > 0 && s[d - 1] === "\\") d -= 1;
  const cleaned = s.slice(d).replace(INSERTION_RUN_RE, "").replace(/\\/g, "");
  if (cleaned.length > SYMBOL_RESERVE) return -1;
  if (!couldBeSymbolPrefix(cleaned)) return -1;
  if (isCompleteCandidate(cleaned)) return -1;
  return d;
}

/**
 * Pipe mode's collapse of a reserve continuation row: the byte range to
 * drop for the marker at [os, oe). The block's rows were inserted after `T`
 * as `\n$MDU/<hash>/<i>` each (§3.1, §11.3), so the collapse drops exactly
 * that: the line break BEFORE the marker, its indent and the marker, which
 * also joins a v2 block's suffix (`$MDU/h/3 and that is all.`) back onto the
 * value's line. When that line break is not in `text` (already emitted by an
 * earlier write, or before `floor`, the end of the previous span): if the
 * marker stands alone on its line (blanks around it, a line break or the text
 * end after) the whole line goes, its line break included; otherwise only the
 * marker.
 */
function rowExtent(text: string, os: number, oe: number, floor: number): [number, number] {
  let a = os;
  while (a > floor && (text[a - 1] === " " || text[a - 1] === "\t")) a -= 1;
  if (a > floor && text[a - 1] === "\n") {
    const nl = a - 1 > floor && text[a - 2] === "\r" ? a - 2 : a - 1;
    return [nl, oe];
  }
  let b = oe;
  while (b < text.length && (text[b] === " " || text[b] === "\t")) b += 1;
  const lineStart = a === 0 || text[a - 1] === "\n";
  if (!lineStart) return [os, oe];
  if (text.startsWith("\r\n", b)) return [a, b + 2];
  if (text[b] === "\n") return [a, b + 1];
  if (b === text.length) return [a, b];
  return [os, oe];
}

/** Auto-wrap off / on (DECAWM): the bracket around a value wider than the
 *  text it replaces (FRAME-SAFE VALUE RENDERING). */
const WRAP_OFF = "\x1b[?7l";
const WRAP_ON = "\x1b[?7h";
/** The escapes that keep the cursor on its row and that the column model
 *  classifies: SGR, EL, CHA, CUF, CUB. A deferred ESC[?7h waits across them. */
const ROW_NEUTRAL_CSI_RE = /^\x1b\[[0-9;:]*[mKGCD]/;

/** Pipe mode: a processable chunk whose last line ends in a reserve-block
 *  marker (a head suffix `/1:N` or `/1:N:W:F`, or a continuation row
 *  `$MDU/<hash>/<i>`), then blanks and ONE line break (group 1). */
const MARKER_LINE_END_RE =
  /(?:\/1:[1-9][0-9]{0,2}(?::[1-9][0-9]{1,3}:(?:0|[1-9][0-9]{0,3})(?::[1-9][0-9]{0,3})?)?|\$MDU\/[0-9a-f]{4,8}\/[1-9][0-9]{0,2})[ \t]*(\r?\n)$/;

// ─────────────────────────────────────────────────────────────────────────────
// The stream filter
// ─────────────────────────────────────────────────────────────────────────────

/** The one arbiter capability the filter needs: deep text desymbolization
 *  (arbiter `desymbolize` op — nested chains collapse to raw server-side). */
export interface ReplyResolver {
  desymbolize(text: string): Promise<string>;
}

/** Max bytes of a partial (newline-less) line held before a forced flush. */
export const MAX_TAIL_HOLD = 4096;
/** Longest escape sequence the column model parses or carries across a chunk
 *  edge; anything longer is no real terminal sequence → emit raw + bail. */
const ESC_CARRY_MAX = 64;
/** Longest suffix ever held back as a possible in-flight token (forced flush
 *  and idle flush). Far above any real symbol length (prefix 4 + tag ≤24 +
 *  [hash] ≤10 + field path, escaped variants included). */
export const SYMBOL_RESERVE = 512;
/** Max consecutive idle-drain re-holds of a still-candidate tail before it
 *  emits raw anyway (see IDLE-DRAIN RE-HOLD in the header). At the relay's
 *  200ms drain cadence this bounds the wait for a token's straggling `.field`
 *  delta (or a ghost token's non-arrival) to ~2s. */
export const IDLE_HOLD_MAX = 10;

export interface ReplyStreamFilterOptions {
  /** Called (best-effort, awaited) whenever resolution CHANGED a span — the
   *  observability seam. Never on the fast path or pass-through. */
  onResolve?: (before: string, after: string) => Promise<void> | void;
  /** Override MAX_TAIL_HOLD (testing). */
  maxTailHold?: number;
  /** EAGER MODE (PTY relay): emit each write immediately, holding only a
   *  possible in-flight token suffix — see the header. Default false:
   *  line-buffered (pipe mode). */
  eager?: boolean;
  /** Terminal width in columns (a number, or a getter so a resize is
   *  followed). Used ONLY to bound the column model for COLUMN-AWARE TAB
   *  EXPANSION (see the header): without a positive width a tab in a value
   *  keeps the one-space fallback. */
  cols?: number | (() => number | undefined);
  /** The session's reserve-block memory (reserve-block.ts), shared with the
   *  screen reconciler so a continuation row the reconciler repaints finds
   *  the value of a head the stream saw. Default: a private instance. */
  reserveCache?: ReserveValueCache;
}

/**
 * Incremental stdout desymbolizer. Feed raw chunks with `write()`; each call
 * returns the (possibly resolved) text that is SAFE to emit now — the current
 * partial line stays held until its newline (or the force-flush cap). Call
 * `flush()` at stream end to drain the held tail.
 */
/** A value spliced into the CURRENT emit (offsets into the emitted string):
 *  the scanner skips the value's bytes (they are ours, not the TUI's) and
 *  registers a column translation when the value widened the row. */
interface SpliceMark {
  start: number;
  end: number;
  /** On-screen width the TUI painted (the token span, wrap artifacts
   *  stripped, Markdown escapes kept — what its cursor math counted). */
  tokenCols: number;
  /** Width of the frame-safe rendering actually on the row now. */
  valueCols: number;
  /** Set ONLY when the raw value carries a TAB: what applyColumnModel needs
   *  to re-render it at the splice column once that column is known (the
   *  value, or the reserved row's line, and the width it pads to). Never
   *  leaves this object except as bytes of the terminal stream. */
  tab?: { value: string; padCols: number };
  /** How long a wrap-off bracketed value keeps auto-wrap off (see
   *  wrapOffPending): `row`, a v2 reserve row (reply-row-reservation.md
   *  §11.3), while the TUI keeps printing on the row; `pad`, a token or a v1
   *  row, only across the BLANKS the TUI pads the row with (Goose's live
   *  tool row pads the token to the width: a wider value pushed that pad
   *  onto a row the TUI never counted, differential-interactive.md §32).
   *  Any other printable byte gets auto-wrap back first. */
  holdWrap?: "row" | "pad";
}

/** One splice unit found in a span of text: a symbol token, a reserve-block
 *  head row (`T/1:N`) or a continuation row (`$MDU/<hash>/<i>`). Offsets:
 *  os/oe into the original bytes, cs/ce into the cleaned view (tokens and
 *  heads only). */
interface Span {
  os: number;
  oe: number;
  cs: number;
  ce: number;
  /** On-screen width the TUI painted (see SpliceMark.tokenCols). */
  cols: number;
  canonical: string;
  split: boolean;
  /** The token sits on ONE row: not split, or split by SGR sequences alone
   *  (a TUI's Markdown streamer restyling mid-token: Goose prints
   *  `$MDU:nomodel` and `_shell[…]` in two colors, differential-interactive.md
   *  §32). Such a span keeps the single-row geometry: it may carry a reserve
   *  head suffix, and it registers its splice with the column model. */
  inRow: boolean;
  /** The SGR sequences the span's original bytes carried inside the token,
   *  re-emitted after the value so the terminal's pen ends as the TUI set it
   *  (an inRow span split by SGR; "" otherwise). */
  sgr: string;
  /** A reserve head: N, and for a v2 head (`/1:N:W:F`) W and F. */
  head?: { n: number; hash: string; suffixLen: number; w?: number | undefined; f?: number | undefined };
  cont?: { hash: string; i: number };
}

export class ReplyStreamFilter {
  private tail = "";
  private readonly maxTailHold: number;
  // ── POST-SPLICE COLUMN TRANSLATION state (eager mode; see header) ──
  /** TUI-space column (1-based) of the emit cursor; null = unknown until the
   *  next CR / CHA / CUP re-anchor. */
  private tuiCol: number | null = null;
  /** True while every glyph counted into tuiCol since its last anchor
   *  (CR/CHA/CUP) had a certain one-column width AND every splice since then
   *  measured exactly: only then is the REAL column trustworthy enough to
   *  place a tab stop (the CHA translation tolerates the drift, a tab stop
   *  does not). */
  private colExact = false;
  /** Widening splices on the CURRENT screen row, boundaries in TUI space. */
  private rowSplices: Array<{ boundary: number; delta: number }> = [];
  /** Marks produced by the LAST resolveText call, consumed by emitEager. */
  private pendingMarks: SpliceMark[] = [];
  /** A trailing incomplete escape sequence carried into the next write so the
   *  scanner never sees (or mis-translates) half a sequence. Never drained on
   *  its own: an escape a dead stream left incomplete renders nothing either
   *  way. Capped — see ESC_CARRY_MAX. */
  private escCarry = "";
  /** A trailing COMPLETE CHA (plus any partial EL after it) held on a
   *  splice-active row so an erase-tail idiom split across a PTY read
   *  boundary reassembles (see the header). Unlike escCarry it renders on its
   *  own (a cursor move), so EVERY flush drains it — translated plainly. At
   *  most one of csiHold/escCarry is non-empty. */
  private csiHold = "";
  /** Consecutive idle-drain re-holds of the current candidate tail (see
   *  IDLE-DRAIN RE-HOLD in the header). Reset by every write. */
  private idleHolds = 0;
  /** Pipe mode: length of a reserve-marker line break held at the tail's
   *  head (see write()); 0 when none. */
  private heldBreak = 0;
  /** Eager mode, within one emit: a widened splice's `ESC[?7h` (auto-wrap
   *  back on) is deferred while the TUI keeps printing on the same row, so
   *  text after the value (a v2 block's suffix, §11.3) clips at the edge
   *  instead of wrapping onto a row the TUI never counted. */
  private wrapOffPending: false | "row" | "pad" = false;
  /** Reserve-block memory (see ReplyStreamFilterOptions.reserveCache). */
  private readonly reserve: ReserveValueCache;

  constructor(
    private readonly resolver: ReplyResolver,
    private readonly opts: ReplyStreamFilterOptions = {},
  ) {
    this.maxTailHold = opts.maxTailHold ?? MAX_TAIL_HOLD;
    this.reserve = opts.reserveCache ?? new ReserveValueCache();
  }

  /** Bytes currently held back (the partial line / candidate tail). */
  get pending(): number {
    return this.tail.length;
  }

  /** Bytes of the child's stream taken in but NOT yet on the wire: the held
   *  candidate tail, plus (eager mode) a carried partial escape or a held
   *  trailing CHA. Always the LAST `held` bytes written, in order (the carry
   *  is the raw end of the emitted part, the tail follows it), so a caller
   *  can hold back the same suffix from anything else it feeds: the screen
   *  reconciler's TUI model (run.ts, screen-reconcile.ts feedTui), which must
   *  describe the moment the human's terminal is at, not a row further on. */
  get held(): number {
    return this.tail.length + this.escCarry.length + this.csiHold.length;
  }

  async write(chunk: string): Promise<string> {
    this.tail += chunk;
    this.idleHolds = 0; // fresh bytes restart the idle-drain re-hold budget
    if (this.opts.eager) return this.writeEager();
    let processable = "";
    // \r counts as a boundary too: symbols contain neither, and TUI redraws /
    // progress bars emit long \r-separated runs with no \n at all.
    let lastNl = Math.max(this.tail.lastIndexOf("\n"), this.tail.lastIndexOf("\r"));
    // The only boundary is a held marker line break (below): keep holding it
    // until the next line is complete, so the next row's collapse sees it.
    // The hold lasts across writes until a later boundary arrives: a next row
    // that trickles in over several writes must still find it.
    if (lastNl >= 0 && lastNl < this.heldBreak) lastNl = -1;
    else this.heldBreak = 0;
    if (lastNl >= 0) {
      processable = this.tail.slice(0, lastNl + 1);
      this.tail = this.tail.slice(lastNl + 1);
    }
    // Wrap-split reassembly: an INCOMPLETE token prefix dangling at the emit
    // boundary (a TUI wrapped mid-token) is pulled back into the held tail so
    // the continuation row can complete it. Complete tokens never come back.
    if (processable !== "") {
      const d = danglingIncompleteStart(processable);
      if (d >= 0) {
        this.tail = processable.slice(d) + this.tail;
        processable = processable.slice(0, d);
      }
    }
    // A line ending in a reserve-block marker (a head, or a continuation
    // row): its line break goes back into the tail, so the NEXT row's
    // collapse (rowExtent) can drop it together with its marker. That is what
    // joins a v2 block's suffix back onto the value's line when the block
    // arrives one line per write (reply-row-reservation.md §11.3). Delays one
    // line break until the next write or the final flush; never text.
    if (processable !== "" && processable.includes("$MDU")) {
      const m = MARKER_LINE_END_RE.exec(processable);
      if (m) {
        const cut = processable.length - m[1]!.length;
        this.tail = processable.slice(cut) + this.tail;
        this.heldBreak = m[1]!.length;
        processable = processable.slice(0, cut);
      }
    }
    // Forced flush for a pathological unbroken line: emit the head, keep a
    // tail cut that never splits a candidate token.
    if (this.tail.length > this.maxTailHold) {
      const cut = this.candidateCut(this.tail);
      processable += this.tail.slice(0, cut);
      this.tail = this.tail.slice(cut);
      this.heldBreak = 0;
    }
    if (processable === "") return "";
    return this.resolveText(processable);
  }

  /** EAGER MODE: emit everything now (tokens resolved inline), hold only a
   *  trailing possible in-flight token. Display bytes — escapes, prompts,
   *  cursor control — are never delayed (the cursor must not blink). */
  private async writeEager(): Promise<string> {
    let cut = this.candidateCut(this.tail);
    // Pathological guard: a "candidate" bloated past any real token by raw
    // insertion bytes (candidateCut caps only the CLEANED length) — stop
    // holding, emit everything.
    if (cut < this.tail.length && this.tail.length - cut > this.maxTailHold) {
      cut = this.tail.length;
    }
    const head = this.tail.slice(0, cut);
    this.tail = this.tail.slice(cut);
    if (head === "") return "";
    return this.emitEager(await this.resolveText(head));
  }

  /** Drain the held tail. `final=true` (stream end) emits everything,
   *  resolved or not. `final=false` is the relay's quiet-period drain: a tail
   *  that is STILL a candidate token (a complete token the arbiter does not
   *  know yet — its `.field` delta may be in flight — or a mid-token prefix)
   *  is RE-HELD, bounded by IDLE_HOLD_MAX; see IDLE-DRAIN RE-HOLD in the
   *  header. A held trailing CHA (csiHold) drains on every flush either way —
   *  it is display bytes, not token bytes. */
  async flush(final = true): Promise<string> {
    const t = this.tail;
    if (!final && this.opts.eager && t !== "" && this.idleHolds < IDLE_HOLD_MAX) {
      const cleaned = t.replace(INSERTION_RUN_RE, "").replace(/\\/g, "");
      if (couldBeSymbolPrefix(cleaned)) {
        if (isCompleteCandidate(cleaned)) {
          // A complete token the arbiter already knows resolves NOW — the
          // proven first-idle-drain behavior for a symbol-terminal reply.
          const resolved = await this.resolveText(t);
          if (resolved !== t) {
            this.tail = "";
            return this.emitEager(resolved, true);
          }
        }
        this.idleHolds += 1;
        return this.csiHold !== "" ? this.emitEager("", true) : "";
      }
    }
    this.tail = "";
    this.heldBreak = 0;
    if (t === "") {
      // Nothing held but possibly a trailing CHA — drain it translated-plain.
      return this.opts.eager && this.csiHold !== "" ? this.emitEager("", true) : "";
    }
    const resolved = await this.resolveText(t);
    return this.opts.eager ? this.emitEager(resolved, true) : resolved;
  }

  /** A cut index that cannot split an IN-FLIGHT symbol: the start of the last
   *  `$` (with its Markdown `\` escape, if any) whose suffix is a
   *  still-growing token — wrap insertions looked through. Only the LAST `$` can
   *  start a still-growing token — tokens never contain `$`, so any earlier
   *  incomplete candidate is permanently dead. A suffix whose CLEANED form is
   *  longer than SYMBOL_RESERVE is longer than any real token → not a
   *  candidate.
   *
   *  A COMPLETE token is HELD too — it is still a valid PREFIX of a longer
   *  one: the field grammar is open-ended, and the model streams
   *  `$MDU:inspect[695b]` and `.result` in SEPARATE deltas (a natural BPE/SSE
   *  boundary; found live: session 1783831380-3877123, both turns). Resolving
   *  the bare base "now" emits it raw — the arbiter only resolves the exact
   *  allocated name (base or base+field), never a base-broadened one — and
   *  the `$`-free `.field` then sails through untouched: the human sees the
   *  full raw token. The hold cannot last: the narrow GLUE set means the very
   *  next non-styling byte — a heartbeat frame's cursor control, a repaint's
   *  CHA, a space — breaks the candidate and everything emits+resolves; a
   *  genuinely quiet stream is drained by the relay's idle flush(false),
   *  which re-holds a STILL-CANDIDATE tail a bounded while (IDLE_HOLD_MAX —
   *  the loaded-SSE base↔field gap, see IDLE-DRAIN RE-HOLD in the header)
   *  before letting it go raw. (That is
   *  what keeps the earlier live regression fixed — 1783791601-1802875, a
   *  symbol-terminal reply + heartbeat frames held all session: heartbeats
   *  now TERMINATE the hold instead of being invisibly stripped.) A row wrap
   *  or heartbeat frame landing EXACTLY between `]` and `.field` still
   *  resolves the base early (a token is one unbroken word — TUIs wrap and
   *  reposition it whole) — that WAS a raw-leak residual until its third
   *  live hit (pipeline 6420, 2026-07-19): the ARBITER's lookup walk now
   *  aliases a stranded base to its one allocated field extension
   *  (symbol-format uniqueFieldExtension), so the early resolve SUCCEEDS
   *  instead of emitting raw — same for an idle drain that outruns its
   *  re-hold budget. The straggling `.field` glyphs then print as a brief
   *  stray beside the spliced value until the next full repaint (which
   *  carries the whole token and resolves exactly) — accepted: glyph noise,
   *  never token bytes. Remaining seam residuals: a delta split MID-hash/tag
   *  (no grammar-complete base to alias; never observed live) and a base
   *  whose extensions are SIBLINGS (.stdout/.stderr — the alias refuses to
   *  guess). Pinned e2e: tests/stack/reply-filter-seam.test.ts. */
  private candidateCut(s: string): number {
    const dollar = s.lastIndexOf("$");
    if (dollar < 0) return s.length;
    // `\$MDU:…` — keep the escaping backslash with its token.
    const start = dollar > 0 && s[dollar - 1] === "\\" ? dollar - 1 : dollar;
    const cleaned = s.slice(start).replace(INSERTION_RUN_RE, "").replace(/\\/g, "");
    if (cleaned.length > SYMBOL_RESERVE) return s.length;
    return couldBeSymbolPrefix(cleaned) ? start : s.length;
  }

  private async resolveText(text: string): Promise<string> {
    if (!text.includes("$")) return text; // fast path: nothing token-shaped
    // Match on the CLEANED view: a token split by wrap insertions (\r/\n +
    // indent, ANSI escapes) is contiguous there; the map points back at the
    // original bytes so splicing never touches text outside token spans.
    const { clean, map } = stripInsertions(text);
    const hasCont = text.includes(CONT_ANCHOR);
    if (!mayContainSymbol(clean) && !hasCont) return text; // fast path: no IPC
    const spans: Span[] = [];
    for (const m of clean.matchAll(ESCAPED_SYM_RE)) {
      const cs = m.index;
      const ce = cs + m[0].length;
      const os = map[cs]!;
      const oe = map[ce - 1]! + 1;
      const s: Span = { os, oe, cs, ce, cols: ce - cs, canonical: m[0].replace(/\\/g, ""), split: oe - os !== ce - cs, inRow: true, sgr: "" };
      setRowGeometry(s, text);
      // RESERVE HEAD ROW (reserve-block.ts): a contiguous token directly
      // followed by `/1:N` is ONE splice unit, never a resolved token beside a
      // stray `/1:N`. The first paint of a head is contiguous (phase 0, §7.1);
      // a wrap-split token keeps the plain-token path. A v2 head (`/1:N:W:F`,
      // §11.3) may follow prefix text on its row: nothing here assumes the
      // head starts its row. A token split by SGR alone is on one row too
      // (inRow): Goose's Markdown streamer restyles it at the `_` (§32).
      if (s.inRow) {
        const suffix = parseHeadSuffix(text.slice(oe, oe + HEAD_SUFFIX_MAX));
        if (suffix) {
          s.head = { n: suffix.n, hash: tokenHash(s.canonical), suffixLen: suffix.length, w: suffix.w, f: suffix.f };
          s.oe += suffix.length;
          s.cols += suffix.length;
        }
      }
      spans.push(s);
    }
    // RESERVE CONTINUATION ROWS: matched on the ORIGINAL bytes (no insertion
    // look-through: a row is written contiguously, and looking through a line
    // break would glue the next line's digits into its index).
    if (hasCont) {
      for (const c of findContinuations(text)) {
        spans.push({ os: c.index, oe: c.index + c.length, cs: -1, ce: -1, cols: c.length, canonical: "", split: false, inRow: true, sgr: "", cont: { hash: c.hash, i: c.i } });
      }
      spans.sort((a, b) => a.os - b.os);
    }
    if (spans.length === 0) return text; // "$MDU:" prose, no full token — no IPC
    const hasReserve = spans.some((s) => s.head !== undefined || s.cont !== undefined);

    // No span was interrupted → the proven whole-text path: ONE deep call,
    // server-side matching (byte-identical to the pre-reassembly behavior).
    // EAGER (TUI) mode never takes it: every substitution must go through the
    // frame-safe per-span renderer below (the arbiter's whole-text response
    // inlines values verbatim, which is exactly the width-mismatch hazard).
    // Nor does a reserve block (the whole-text call would resolve the head's
    // token and leave its `/1:N`).
    if (!this.opts.eager && !hasReserve && !spans.some((s) => s.split)) {
      const candidate = unescapeSymbols(text);
      let resolved: string;
      try {
        resolved = await this.resolver.desymbolize(candidate);
      } catch {
        // Arbiter unreachable → pass through UNCHANGED (symbols stay opaque;
        // utility-only surface — see the SECURITY POSTURE header).
        return text;
      }
      if (resolved === candidate) {
        // Nothing actually resolved → keep the ORIGINAL spelling (do not strip
        // the Markdown escapes of tokens we could not resolve).
        return text;
      }
      await this.emitResolve(text, resolved);
      return resolved;
    }

    // AGGRESSIVE path — at least one token is interrupted by insertions:
    // resolve each reassembled token individually (deep, so nested chains
    // still collapse) and splice the value over the token's WHOLE original
    // span (its wrap artifacts go with it — the value re-wraps naturally).
    // Unknown tokens keep their original bytes, insertions intact.
    const resolvedByToken = new Map<string, string>();
    const lookup = async (tok: string): Promise<string> => {
      let v = resolvedByToken.get(tok);
      if (v === undefined) {
        v = await this.resolver.desymbolize(tok);
        resolvedByToken.set(tok, v);
      }
      return v;
    };
    let arbiterDown = false;
    try {
      for (const s of spans) {
        if (s.head || s.cont) continue; // reserve rows: resolved below
        if ((await lookup(s.canonical)) !== s.canonical || !s.split) continue;
        // LINE-END GLUE FALLBACK (see header): the reassembled token is
        // unknown; a shorter complete token ending at one of its insertion
        // boundaries may be the real one (a line-final token glued to the
        // next line's first word). Longest first; the first that resolves
        // narrows the span, so the insertion and the rest stay verbatim.
        for (let k = s.ce - 1; k > s.cs; k--) {
          if (map[k]! === map[k - 1]! + 1) continue; // no insertion before clean[k]
          const prefix = clean.slice(s.cs, k).replace(/\\/g, "");
          if (!COMPLETE_TOKEN_RE.test(prefix)) continue;
          if ((await lookup(prefix)) === prefix) continue;
          const oe = map[k - 1]! + 1;
          s.oe = oe;
          s.cols = k - s.cs;
          s.canonical = prefix;
          s.split = oe - s.os !== k - s.cs;
          setRowGeometry(s, text);
          break;
        }
      }
    } catch {
      // Arbiter unreachable → unchanged (utility posture). A reserve block
      // still gets its no-value rendering below (blank rows, `(N lines)`).
      if (!hasReserve) return text;
      arbiterDown = true;
    }
    // Reserve heads: the value from the session cache, else one deep call.
    // An unknown or unreachable value stays null (the no-value rendering).
    const headValue = new Map<Span, string | null>();
    for (const s of spans) {
      if (!s.head) continue;
      let v = this.reserve.getValue(s.canonical);
      if (v === undefined && !arbiterDown) {
        try {
          const r = await this.resolver.desymbolize(s.canonical);
          if (r !== s.canonical) {
            v = r;
            this.reserve.setValue(s.canonical, r);
          }
        } catch {
          arbiterDown = true;
        }
      }
      headValue.set(s, v ?? null);
      this.reserve.noteHead(s.head.hash, s.canonical, s.head.n, s.head.w, s.head.f, this.widthCols());
    }
    const eager = this.opts.eager === true;
    let out = "";
    /** `out` without the eager padding (renderValue `pad`): the trace the
     *  onResolve callback reports, what the human reads once the screen
     *  reconciler closed the gap (screen-reconcile.ts CLOSE UP). */
    let trace = "";
    let last = 0;
    let changed = false;
    let tokenChanged = false;
    const marks: SpliceMark[] = [];
    const headReports: Array<[string, string]> = [];
    for (const s of spans) {
      let os = s.os;
      let oe = s.oe;
      let rendered: { bytes: string; cols: number; pad?: number };
      /** The text rendered into the row, when it may carry a TAB. */
      let line: string;
      /** The width a shorter rendering pads to (what the TUI counted). */
      let padCols: number;
      /** A v2 row: text may follow it on its row (SpliceMark.holdWrap). */
      let holdWrap = false;
      if (s.head) {
        holdWrap = s.head.w !== undefined;
        const value = headValue.get(s)!;
        padCols = [...s.canonical].length + s.head.suffixLen;
        if (value === null) {
          line = unknownHeadText(s.canonical, s.head.n);
        } else if (eager) {
          // v1: line 1; v2: row 1 of the layout ("" when F = 0: blank cells),
          // at the width the block was first seen at (§13, a resize).
          line = blockRowText(value, 1, this.reserve.headFor(s.head.hash) ?? s.head, this.widthCols());
        } else {
          // PIPE MODE (a block should never arrive: the proxy expands only
          // for a PTY relay): collapse the block to the full value, which pipe
          // mode prints faithfully. The block's own line break follows.
          line = value.replace(/\r?\n$/, "");
        }
        if (value !== null && this.reserve.firstReport(s.canonical)) headReports.push([s.canonical, value]);
        rendered = this.renderValue(line, padCols);
      } else if (s.cont) {
        const head = this.reserve.headFor(s.cont.hash);
        padCols = s.cols;
        holdWrap = head?.w !== undefined;
        if (!eager) {
          // Pipe mode: the head printed the whole value; drop the row (its
          // indent and line break with it). A hash no head announced is
          // literal text and stays.
          if (!head) continue;
          [os, oe] = rowExtent(text, s.os, s.oe, last);
          line = "";
          rendered = { bytes: "", cols: 0 };
        } else {
          // Unknown value (arbiter down, unknown token, hash never seen):
          // blank spaces of the marker's width — the row carries nothing.
          line = head && head.value !== null ? blockRowText(head.value, s.cont.i, head, this.widthCols()) : "";
          rendered = this.renderValue(line, padCols);
        }
      } else {
        if (arbiterDown) continue;
        const value = resolvedByToken.get(s.canonical)!;
        if (value === s.canonical) continue; // unresolved → original bytes stay
        line = value;
        padCols = [...s.canonical].length;
        rendered = this.renderValue(value, padCols);
        tokenChanged = true;
      }
      if (eager && s.inRow) {
        // A wrap-SPLIT token occupied two physical rows — no single-row
        // geometry to translate; skip registration (pre-translation behavior).
        // A token split by SGR alone is one row (setRowGeometry).
        const start = out.length + (os - last);
        marks.push({
          start,
          end: start + rendered.bytes.length,
          tokenCols: s.cols,
          valueCols: rendered.cols,
          ...(line.includes("\t") ? { tab: { value: line, padCols } } : {}),
          holdWrap: holdWrap ? "row" : "pad",
        });
      }
      // The styling the TUI set inside the token goes out after the value
      // (outside the mark: the column model scans it as the TUI's bytes).
      const sgr = eager ? s.sgr : "";
      out += text.slice(last, os) + rendered.bytes + sgr;
      trace += text.slice(last, os) + (rendered.pad ? rendered.bytes.slice(0, -rendered.pad) : rendered.bytes) + sgr;
      last = oe;
      changed = true;
    }
    if (!changed) return text;
    out += text.slice(last);
    trace += text.slice(last);
    // Handed to emitEager only now — an earlier throw (arbiter unreachable →
    // pass through) must never leave stale marks behind.
    if (eager) this.pendingMarks = marks;
    if (tokenChanged) await this.emitResolve(text, trace);
    // A reserve block is recorded ONCE per value, whole, never per row.
    for (const [token, value] of headReports) await this.emitResolve(token, value);
    return out;
  }

  /** One emitted eager chunk: prepend any carried partial escape / held CHA,
   *  run the column model + translations, hold back a new trailing partial
   *  escape (or idiom-eligible CHA). `drain` (any flush) forbids re-holding a
   *  trailing CHA — a flush must leave nothing behind but the token tail the
   *  caller manages. Any modeling surprise degrades to the untranslated bytes
   *  (utility surface — never worse than the pre-translation behavior). */
  private emitEager(text: string, drain = false): string {
    const marks = this.pendingMarks;
    this.pendingMarks = [];
    if (text === "" && this.escCarry === "" && this.csiHold === "") return "";
    try {
      return this.applyColumnModel(text, marks, drain);
    } catch {
      this.rowSplices = [];
      this.tuiCol = null;
      this.colExact = false;
      this.wrapOffPending = false; // `text` keeps every bracket whole
      const carried = this.csiHold + this.escCarry;
      this.csiHold = "";
      this.escCarry = "";
      return carried + text;
    }
  }

  /** POST-SPLICE COLUMN TRANSLATION (see header): scan the emit in TUI space,
   *  register widening splices, shift same-row CHA/CUF/CUB across them. */
  private applyColumnModel(text: string, marks: SpliceMark[], drain = false): string {
    this.wrapOffPending = false;
    let out = this.scanColumnModel(text, marks, drain);
    // A deferred `ESC[?7h` never outlives its emit: the next write may start
    // anywhere.
    if (this.wrapOffPending) {
      out += WRAP_ON;
      this.wrapOffPending = false;
    }
    return out;
  }

  private scanColumnModel(text: string, marks: SpliceMark[], drain: boolean): string {
    const pre = this.csiHold + this.escCarry; // at most one is ever non-empty
    if (pre !== "") {
      for (const m of marks) {
        m.start += pre.length;
        m.end += pre.length;
      }
      text = pre + text;
      this.csiHold = "";
      this.escCarry = "";
    }
    // Fast path: nothing to translate, nothing registrable, nothing that can
    // move the column model — the overwhelming majority of frames go through
    // untouched. (Any C0/ESC byte, or a live row state, takes the full scan.)
    if (marks.length === 0 && this.rowSplices.length === 0 && !/[\x00-\x1f\x7f]/.test(text)) {
      if (this.tuiCol !== null) {
        this.tuiCol += [...text].length;
        if (hasUncertainWidth(text)) this.colExact = false;
      }
      return text;
    }
    const shiftAt = (n: number) => this.rowSplices.reduce((a, s) => a + (s.boundary <= n ? s.delta : 0), 0);
    const shiftBetween = (lo: number, hi: number) =>
      this.rowSplices.reduce((a, s) => a + (s.boundary > lo && s.boundary <= hi ? s.delta : 0), 0);
    const bailRow = () => {
      this.rowSplices = [];
      this.tuiCol = null;
      this.colExact = false;
    };
    let out = "";
    let i = 0;
    let mk = 0;
    while (i < text.length) {
      // A spliced value: OUR bytes, not the TUI's — register its widening and
      // step the model by the width the TUI BELIEVES it painted (the token).
      if (mk < marks.length && i === marks[mk]!.start) {
        const m = marks[mk]!;
        mk += 1;
        let bytes = text.slice(i, m.end);
        // A pad hold covers blanks only: a value is text, so auto-wrap goes
        // back on before it (a v2 row's hold keeps its old rule).
        if (this.wrapOffPending === "pad") {
          out += WRAP_ON;
          this.wrapOffPending = false;
        }
        if (m.tab) {
          // COLUMN-AWARE TAB EXPANSION (see header): the column is known only
          // here. Unknown → the one-space rendering resolveText produced stays.
          const col0 = this.tabSpliceCol(shiftAt);
          if (col0 !== null) {
            const r = this.renderValue(m.tab.value, m.tab.padCols, col0);
            bytes = r.bytes;
            m.valueCols = r.cols;
          }
        }
        // CLIP PAST THE EDGE (see the header): only the part of a wrap-off
        // value the row can show goes out, so its last cell is the glyph
        // that belongs there (not the value's last glyph, written over and
        // over at the edge), and a value that starts past the edge sends none.
        bytes = this.clipValue(bytes, shiftAt);
        // A value with wide/combining glyphs: its code-point width (the
        // delta registered below) is an estimate, so the row's real column
        // is no longer exact.
        if (hasUncertainWidth(bytes)) this.colExact = false;
        if (this.tuiCol !== null) {
          const delta = m.valueCols - m.tokenCols;
          if (delta > 0) this.rowSplices.push({ boundary: this.tuiCol + m.tokenCols, delta });
          this.tuiCol += m.tokenCols;
        }
        // A wrap-off bracketed value: defer its `ESC[?7h` while the TUI
        // keeps printing on this row (see wrapOffPending), so the text after
        // the value, shifted right by the splice, CLIPS at the edge.
        if (m.holdWrap && bytes.startsWith(WRAP_OFF) && bytes.endsWith(WRAP_ON) &&
          (m.holdWrap === "row" || this.padOverflows(text, m.end, shiftAt))) {
          bytes = bytes.slice(0, -WRAP_ON.length);
          this.wrapOffPending = m.holdWrap;
        }
        out += bytes;
        i = m.end;
        continue;
      }
      const limit = mk < marks.length ? marks[mk]!.start : text.length;
      const ch = text[i]!;
      // Auto-wrap goes back on before anything that can leave the row or
      // that the row model does not classify: every C0 byte, every escape
      // other than SGR / EL / CHA / CUF / CUB. Printable text stays wrap-off.
      if (this.wrapOffPending && (ch < " " || ch === "\x7f")) {
        if (ch !== "\x1b" || !ROW_NEUTRAL_CSI_RE.test(text.slice(i, i + ESC_CARRY_MAX))) {
          out += WRAP_ON;
          this.wrapOffPending = false;
        }
      }
      if (ch === "\x1b") {
        const rest = text.slice(i, i + ESC_CARRY_MAX);
        const intro = text[i + 1];
        // Dispatch on the introducer FIRST: `ESC [` / `ESC ]` are prefixes of
        // longer sequences and must never be consumed as a two-byte escape —
        // an incomplete one at the chunk edge is CARRIED, not half-scanned.
        if (intro === "[") {
          // The ERASE-TAIL idiom, special-cased (both live catches wore it):
          // `CHA(n) EL` with n at/past the LAST splice boundary. Ink's diff
          // SKIPS columns it believes unchanged (the word gap), so its erase
          // can start past the value's real end and leave a stale glyph in
          // between (run 23's trailing `o`). Start the erase at the LAST
          // value's real end instead (cumulative deltas — multi-splice rows
          // included), then restore the TUI's intended (translated) cursor —
          // the real screen ends up exactly as the TUI believes: its content,
          // then blanks. An erase landing BETWEEN two splices keeps plain
          // translation (documented residual — small over clever).
          const eraseTail = /^\x1b\[([0-9]*)G\x1b\[0?K/.exec(rest);
          if (eraseTail && this.rowSplices.length >= 1) {
            const n = eraseTail[1] === "" ? 1 : parseInt(eraseTail[1]!, 10);
            const maxBoundary = Math.max(...this.rowSplices.map((s) => s.boundary));
            if (n >= maxBoundary) {
              const totalDelta = this.rowSplices.reduce((a, s) => a + s.delta, 0);
              const valueEnd = maxBoundary + totalDelta;
              const intended = n + totalDelta;
              // A value that ran past the right edge (clipped, wrap off) leaves
              // nothing after it to erase: the CHA would clamp to the last
              // column and the EL erase the value's last visible glyph (a long
              // reserved row, reply-row-reservation.md §3.7). Skip the erase
              // when the width is known and the value's end is off the row.
              const width = this.widthCols();
              out += width !== null && valueEnd > width
                ? `\x1b[${intended}G`
                : `\x1b[${valueEnd}G\x1b[K` + (intended === valueEnd ? "" : `\x1b[${intended}G`);
              this.tuiCol = n;
              this.colExact = true;
              i += eraseTail[0].length;
              continue;
            }
          }
          // The idiom SPLIT at a PTY read boundary: an idiom-eligible
          // complete CHA at the very end of the emit, followed by nothing
          // but a possible EL prefix — HOLD it so the next read reassembles
          // the pair (a trailing cursor move renders nothing until more
          // bytes arrive anyway; every flush drains it translated-plain).
          if (!drain && this.rowSplices.length >= 1 && mk >= marks.length) {
            const cha = /^\x1b\[([0-9]*)G/.exec(rest);
            if (cha && /^(?:\x1b(?:\[0?)?)?$/.test(text.slice(i + cha[0].length))) {
              const n = cha[1] === "" ? 1 : parseInt(cha[1]!, 10);
              if (n >= Math.max(...this.rowSplices.map((s) => s.boundary))) {
                this.csiHold = text.slice(i);
                return out;
              }
            }
          }
          const csi = /^\x1b\[([0-9;:?]*)([\x40-\x7e])/.exec(rest);
          if (csi) {
            const [seq, params, final] = [csi[0], csi[1]!, csi[2]!];
            out += this.translateCsi(seq, params, final, shiftAt, shiftBetween, bailRow);
            i += seq.length;
            continue;
          }
        } else if (intro === "]") {
          const osc = /^\x1b\][^\x07\x1b]*(\x07|\x1b\\)/.exec(rest);
          if (osc) {
            out += osc[0]; // titles etc. — column-neutral
            i += osc[0].length;
            continue;
          }
        } else if (intro !== undefined) {
          const other = /^\x1b[\x20-\x2f]*[\x30-\x7e]/.exec(rest);
          if (other) {
            bailRow(); // ESC 7/8 save/restore & friends can move the cursor
            out += other[0];
            i += other[0].length;
            continue;
          }
        }
        // Incomplete escape at the chunk edge: carry it (never scan halves).
        if (text.length - i <= ESC_CARRY_MAX) {
          this.escCarry = text.slice(i);
          return out;
        }
        bailRow(); // pathological: an "escape" longer than any real sequence
        out += text.slice(i);
        return out;
      }
      if (ch === "\r") {
        // Full-row repaint follows; its token re-splices and re-registers.
        this.rowSplices = [];
        this.tuiCol = 1;
        this.colExact = true;
        out += ch;
        i += 1;
        continue;
      }
      if (ch === "\n") {
        this.rowSplices = []; // new row, same column
        out += ch;
        i += 1;
        continue;
      }
      if (ch === "\b") {
        if (this.tuiCol !== null) this.tuiCol = Math.max(1, this.tuiCol - 1);
        out += ch;
        i += 1;
        continue;
      }
      if (ch === "\t") {
        bailRow(); // tab stops are terminal state we do not model
        out += ch;
        i += 1;
        continue;
      }
      if (ch < " " || ch === "\x7f") {
        out += ch; // BEL etc. — column-neutral
        i += 1;
        continue;
      }
      // Printable run (up to the next C0/ESC byte or the next mark).
      let j = i;
      while (j < limit && text[j]! >= " " && text[j] !== "\x7f") j += 1;
      let run = text.slice(i, j);
      if (this.wrapOffPending === "pad") {
        // The TUI's pad after a widened token: its blanks stay wrap-off, and
        // the ones past the right edge are not sent at all (the cursor is
        // already at the last column; a blank there would only overwrite the
        // value's last glyph). The first other byte gets auto-wrap back.
        const blanks = /^ */.exec(run)![0].length;
        if (blanks > 0) {
          const width = this.widthCols();
          let keep = blanks;
          if (width !== null && this.tuiCol !== null) {
            const realCol = this.tuiCol + shiftAt(this.tuiCol);
            keep = Math.max(0, Math.min(blanks, width - realCol + 1));
          }
          out += " ".repeat(keep);
          if (this.tuiCol !== null) this.tuiCol += blanks;
          run = run.slice(blanks);
        }
        if (run !== "") {
          out += WRAP_ON;
          this.wrapOffPending = false;
        }
      }
      // CLIP PAST THE EDGE (see the header): a glyph the TUI believes is on
      // this row but a widening splice pushed past the right edge is not
      // sent; with auto-wrap on it would start a row the TUI never counted.
      const sent = this.clipRun(run, shiftAt);
      if (this.tuiCol !== null) this.tuiCol += [...run].length;
      if (hasUncertainWidth(run)) this.colExact = false;
      out += sent;
      i = j;
    }
    return out;
  }

  /** CLIP PAST THE EDGE holds for a renderer that places every row itself
   *  (Ink's rule: Claude Code, Codex, OpenCode). Under the terminal rule
   *  (Goose prints its reply raw and leaves the wrap to the terminal,
   *  reply-row-reservation.md §17) the text after a value wraps by itself,
   *  where vanilla's does, so nothing is clipped there. */
  private get clipsAtEdge(): boolean {
    return this.reserve.rule === "ink";
  }

  /** True when the TUI believes its cursor is on the row (its column is at
   *  most the width) but a widening splice on the row put the REAL column
   *  past the right edge (CLIP PAST THE EDGE in the header). Unknown width
   *  or column: false. */
  private pastEdge(shiftAt: (n: number) => number): boolean {
    if (!this.clipsAtEdge || this.tuiCol === null || this.rowSplices.length === 0) return false;
    const width = this.widthCols();
    return width !== null && this.tuiCol <= width && this.tuiCol + shiftAt(this.tuiCol) > width;
  }

  /** A printable run without the glyphs a widening splice pushed past the
   *  right edge (CLIP PAST THE EDGE). Unknown width or column, no splice on
   *  the row, or a glyph the TUI itself places past its width (a TUI that
   *  leans on auto-wrap: the old behavior): sent as is. */
  private clipRun(run: string, shiftAt: (n: number) => number): string {
    if (!this.clipsAtEdge) return run;
    const width = this.widthCols();
    if (width === null || this.tuiCol === null || this.rowSplices.length === 0) return run;
    let sent = "";
    let c = this.tuiCol;
    for (const g of run) {
      if (!(c <= width && c + shiftAt(c) > width)) sent += g;
      c += 1;
    }
    return sent;
  }

  /** A wrap-off bracketed value (`ESC[?7l` value `ESC[?7h`) cut to the
   *  columns left on the row from its real start (CLIP PAST THE EDGE): a
   *  wide glyph that would straddle the edge is dropped, as a clipping
   *  terminal drops it. Anything else, an unknown width or column, or a
   *  TUI column past the width: as is. */
  private clipValue(bytes: string, shiftAt: (n: number) => number): string {
    if (!this.clipsAtEdge || !bytes.startsWith(WRAP_OFF) || !bytes.endsWith(WRAP_ON)) return bytes;
    const width = this.widthCols();
    if (width === null || this.tuiCol === null || this.tuiCol > width) return bytes;
    const avail = width - (this.tuiCol + shiftAt(this.tuiCol)) + 1;
    const inner = bytes.slice(WRAP_OFF.length, bytes.length - WRAP_ON.length);
    if (layoutWidth(inner) <= avail) return bytes;
    let kept = "";
    let used = 0;
    for (const g of inner) {
      const w = layoutGlyphWidth(g);
      if (used + w > avail) break;
      kept += g;
      used += w;
    }
    return WRAP_OFF + kept + WRAP_ON;
  }

  /** A `pad` hold is taken only where it changes the screen: the blanks the
   *  TUI writes right after the value (SGR looked through) would run past
   *  the right edge, so with auto-wrap on they would start a row the TUI
   *  never counted. Needs the width and the row's column; unknown → false
   *  (the bracket closes right after the value, as before). */
  private padOverflows(text: string, from: number, shiftAt: (n: number) => number): boolean {
    const width = this.widthCols();
    if (width === null || this.tuiCol === null) return false;
    const m = /^(?:\x1b\[[0-9;:]*m)*( +)/.exec(text.slice(from));
    if (!m) return false;
    const realCol = this.tuiCol + shiftAt(this.tuiCol);
    return realCol + m[1]!.length - 1 > width;
  }

  /** Translate one CSI sequence against the row's registered splices. */
  private translateCsi(
    seq: string,
    params: string,
    final: string,
    shiftAt: (n: number) => number,
    shiftBetween: (lo: number, hi: number) => number,
    bailRow: () => void,
  ): string {
    const simpleN = /^[0-9]*$/.test(params) ? (params === "" ? 1 : parseInt(params, 10)) : null;
    switch (final) {
      case "G": {
        // CHA — the observed hazard (`ESC[19G ESC[K` after a widened splice).
        if (simpleN === null) {
          bailRow();
          return seq;
        }
        const shifted = simpleN + shiftAt(simpleN);
        this.tuiCol = simpleN;
        this.colExact = true;
        return shifted === simpleN ? seq : `\x1b[${shifted}G`;
      }
      case "C": // CUF — relative, shift by the boundaries it crosses
      case "D": {
        if (simpleN === null) {
          bailRow();
          return seq;
        }
        if (this.tuiCol === null) return seq; // unknown stays unknown
        const from = this.tuiCol;
        const to = final === "C" ? from + simpleN : Math.max(1, from - simpleN);
        const crossed = final === "C" ? shiftBetween(from, to) : shiftBetween(to, from);
        // Past the edge the terminal's cursor sits on the last column, not
        // at the model's real column: a relative move from there would land
        // short, so the move goes out as the absolute column it means.
        const fromPast = this.pastEdge(shiftAt);
        this.tuiCol = to;
        if (fromPast) return `\x1b[${to + shiftAt(to)}G`;
        return crossed === 0 ? seq : `\x1b[${simpleN + crossed}${final}`;
      }
      case "K": // EL — erases FROM the (already translated) cursor
        // Past the edge there is nothing of the row to erase, and the
        // terminal would erase the last cell the row shows.
        if ((params === "" || params === "0") && this.pastEdge(shiftAt)) return "";
        return seq;
      case "m": // SGR
        return seq;
      case "h":
      case "l":
        if (params.startsWith("?")) return seq; // modes (?7l/?7h, ?25l/h, …)
        bailRow();
        return seq;
      case "H":
      case "f": {
        // CUP — new row; the column half re-anchors the model.
        this.rowSplices = [];
        const m = /^[0-9]*;([0-9]*)$/.exec(params);
        this.tuiCol = params === "" ? 1 : m ? (m[1] === "" ? 1 : parseInt(m[1]!, 10)) : null;
        this.colExact = this.tuiCol !== null;
        return seq;
      }
      case "A":
      case "B":
      case "d": // row moves, column kept
        this.rowSplices = [];
        return seq;
      case "E":
      case "F": // next/prev row, column 1
        this.rowSplices = [];
        this.tuiCol = 1;
        this.colExact = true;
        return seq;
      case "J":
      case "S":
      case "T": // screen-level erase/scroll, column kept
        this.rowSplices = [];
        return seq;
      default:
        bailRow(); // ICH/DCH/ECH shift row content; anything else is unknown
        return seq;
    }
  }

  /** How a resolved value is rendered into the output stream (`cols` is its
   *  on-screen width, consumed by the splice mark; `tokenCols` is the width
   *  of what it replaces: a token, or a reserve-block row marker whose value
   *  is one line of the whole value). Pipe mode: verbatim
   *  (linear output — full fidelity; cols unused). Eager (TUI) mode:
   *  frame-safe single row, and
   *    - LONGER than the token: bracketed in ESC[?7l…?7h so the terminal
   *      clips at the row edge instead of wrapping onto an uncounted
   *      physical row (the §10 fix);
   *    - SHORTER than the token: PADDED with spaces to the token's width —
   *      the row's geometry then matches the TUI's cursor math exactly (no
   *      registration, no translation) and the token's ghost tail (stale
   *      glyphs where the previous frame's bytes ran past the short value)
   *      is blanked (live 2026-07-18: a 15-col Bash token → a 12-col code,
   *      three stale columns beside the value on every such row). The
   *      screen reconciler then CLOSES UP the gap on the human's row (the
   *      cells after the value shift left, the tail is erased;
   *      screen-reconcile.ts), and the onResolve trace reports the value
   *      without the pad (`pad`: how many trailing spaces are padding). */
  private renderValue(value: string, tokenCols: number, startCol?: number): { bytes: string; cols: number; pad?: number } {
    if (!this.opts.eager) return { bytes: value, cols: 0 };
    // `startCol` (0-based real column, from tabSpliceCol) is given only on the
    // column-aware re-render of a tab-carrying value; without it a tab is one
    // space (COLUMN-AWARE TAB EXPANSION in the header).
    const sv = frameSafeValue(value, startCol);
    // DISPLAY columns (a wide glyph is 2, a combining mark 0), not code
    // points: a v2 row (reply-row-reservation.md §11.2) is laid out to fill
    // its row in display columns, and a wide row counted short would be
    // padded past the edge with auto-wrap on.
    const svCols = layoutWidth(sv);
    if (svCols > tokenCols) return { bytes: `${WRAP_OFF}${sv}${WRAP_ON}`, cols: svCols };
    if (svCols < tokenCols) return { bytes: sv + " ".repeat(tokenCols - svCols), cols: tokenCols, pad: tokenCols - svCols };
    return { bytes: sv, cols: svCols };
  }

  /** The 0-based REAL screen column the next splice lands on, or null when
   *  it is not reliably known (the one-space tab fallback then stays). Every
   *  condition is listed in COLUMN-AWARE TAB EXPANSION in the header. */
  private tabSpliceCol(shiftAt: (n: number) => number): number | null {
    if (this.tuiCol === null || !this.colExact) return null;
    const cols = this.widthCols();
    if (cols === null) return null;
    const real = this.tuiCol - 1 + shiftAt(this.tuiCol);
    if (!Number.isFinite(real) || real < 0 || real >= cols) return null;
    return real;
  }

  /** The terminal width (opts.cols) when it is a positive number, else null. */
  private widthCols(): number | null {
    let cols: number | undefined;
    try {
      cols = typeof this.opts.cols === "function" ? this.opts.cols() : this.opts.cols;
    } catch {
      return null;
    }
    return typeof cols === "number" && Number.isFinite(cols) && cols >= 1 ? cols : null;
  }

  /** Best-effort observability callback — never on the output path. */
  private async emitResolve(before: string, after: string): Promise<void> {
    if (!this.opts.onResolve) return;
    try {
      await this.opts.onResolve(before, after);
    } catch {
      // Observability is best-effort, never disturbs the stream.
    }
  }
}
