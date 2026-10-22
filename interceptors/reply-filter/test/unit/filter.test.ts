/**
 * filter.test — unit tests for the pure user-reply desymbolizing stream core
 * (src/filter.ts), driven with an in-memory resolver (no arbiter, no spawn).
 *
 * Covers the chunk-safety contract (a symbol split across chunk boundaries is
 * never emitted half-resolved), the Markdown-escape normalization lifted from
 * the reference `message_sending` hook, the no-symbol fast path (zero resolver
 * calls), and the UTILITY-ONLY failure posture: a resolver error passes text
 * through UNCHANGED (symbols stay opaque — nothing can leak, nothing blocks).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ReplyStreamFilter,
  unescapeSymbols,
  placeholderNames,
  mayContainSymbol,
  couldBeSymbolPrefix,
  stripInsertions,
  setRowGeometry,
  frameSafeValue,
  MAX_TAIL_HOLD,
  SYMBOL_RESERVE,
  IDLE_HOLD_MAX,
  type ReplyResolver,
} from "../../src/filter.js";
import { ReserveValueCache, formatBlock, formatBlockV2, moreLinesNote } from "../../src/reserve-block.js";
import { layoutRows } from "../../src/reserve-layout.js";
import {
  BT,
  BV,
  BLINES,
  shown,
  INLINE_FIRST_PAINT,
  FULLSCREEN_FIRST_PAINT,
  FENCED_FIRST_PAINT,
  KT,
  KV,
  KEY_FIRST_PAINT,
  MT,
  MV,
  MID_F,
  MID_HEAD,
  MID_PREFIX,
  MID_SUFFIX,
  MID_FIRST_PAINT,
  MID_SCREEN,
  renderScreen,
} from "./reserve-fixtures.js";
import {
  GOOSE_HEAD_TOKEN,
  GOOSE_LIVE_READS,
  GOOSE_LIVE_TOKEN,
  GOOSE_REPLY_READS,
  GOOSE_REPLY_SCREEN,
  GOOSE_ROWS_VALUE,
} from "./goose-fixtures.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SYM = "$MDU:Read[9b0a]";
const RAW = "# Project notes\nTODO: ship the proxy.";
// EAGER (TUI) mode renders values FRAME-SAFELY (src/filter.ts header): one
// row (\n → " ⏎ "), and — because RAW is longer than SYM — bracketed in
// ESC[?7l…?7h so the row clips instead of wrapping. Pipe mode keeps RAW
// verbatim (linear output, full fidelity).
const RAW_ONELINE = "# Project notes ⏎ TODO: ship the proxy.";
const RAW_FRAME = `\x1b[?7l${RAW_ONELINE}\x1b[?7h`;

/** In-memory resolver: replaces known tokens, counts calls, optional failure. */
class MockResolver implements ReplyResolver {
  calls: string[] = [];
  fail = false;
  constructor(private readonly table: Record<string, string> = { [SYM]: RAW }) {}
  async desymbolize(text: string): Promise<string> {
    this.calls.push(text);
    if (this.fail) throw new Error("arbiter down");
    let out = text;
    for (const [sym, value] of Object.entries(this.table)) {
      out = out.split(sym).join(value);
    }
    return out;
  }
}

/** Feed chunks through a filter and return everything it emitted. */
async function run(filter: ReplyStreamFilter, chunks: string[]): Promise<string> {
  let out = "";
  for (const c of chunks) out += await filter.write(c);
  out += await filter.flush();
  return out;
}

// ── helpers ───────────────────────────────────────────────────────────────────

test("unescapeSymbols strips Markdown escapes from symbol tokens only", () => {
  // Escaped `$` and escaped tail underscores (the #260 case) are both stripped.
  assert.equal(unescapeSymbols("see \\$MDU:web\\_fetch[a1b2] now"), "see $MDU:web_fetch[a1b2] now");
  // Non-symbol backslashes are untouched.
  assert.equal(unescapeSymbols("a \\_regular\\_ escape"), "a \\_regular\\_ escape");
});

test("mayContainSymbol covers canonical + escaped spellings, cheap negative", () => {
  assert.equal(mayContainSymbol(`x ${SYM} y`), true);
  assert.equal(mayContainSymbol("x \\$MDU:exec[a1b2] y"), true);
  assert.equal(mayContainSymbol("perfectly ordinary output"), false);
});

// ── resolution ────────────────────────────────────────────────────────────────

test("a symbol in a complete line resolves to its raw value", async () => {
  const r = new MockResolver();
  const out = await run(new ReplyStreamFilter(r), [`Summary: ${SYM}\n`]);
  assert.equal(out, `Summary: ${RAW}\n`);
});

test("a symbol SPLIT across chunk boundaries still resolves (never half-emitted)", async () => {
  const r = new MockResolver();
  // Split mid-token, no newline until the end — the tail must be held.
  const text = `The notes say: ${SYM} — done.\n`;
  const cut = text.indexOf("[9b"); // inside the hash
  const out = await run(new ReplyStreamFilter(r), [text.slice(0, cut), text.slice(cut)]);
  assert.equal(out, `The notes say: ${RAW} — done.\n`);
});

test("a Markdown-ESCAPED symbol resolves (reference message_sending unescape step)", async () => {
  const r = new MockResolver();
  const out = await run(new ReplyStreamFilter(r), ["Summary: \\$MDU:Read[9b0a]\n"]);
  assert.equal(out, `Summary: ${RAW}\n`);
});

test("an UNKNOWN symbol passes through with its original spelling (escapes intact)", async () => {
  const r = new MockResolver({}); // knows nothing
  const escaped = "ghost: \\$MDU:exec[ffff]\n";
  const out = await run(new ReplyStreamFilter(r), [escaped]);
  // Nothing resolved → the ORIGINAL text (not the unescaped candidate) is kept.
  assert.equal(out, escaped);
});

test("symbol-free text takes the fast path — the resolver is never called", async () => {
  const r = new MockResolver();
  const out = await run(new ReplyStreamFilter(r), ["hello\n", "plain world\n"]);
  assert.equal(out, "hello\nplain world\n");
  assert.deepEqual(r.calls, []);
});

test("UTILITY POSTURE: a resolver failure passes text through UNCHANGED", async () => {
  const r = new MockResolver();
  r.fail = true;
  const text = `Summary: ${SYM}\n`;
  const out = await run(new ReplyStreamFilter(r), [text]);
  assert.equal(out, text); // symbols stay opaque; the stream is never blocked
});

// ── chunk / hold mechanics ────────────────────────────────────────────────────

test("a partial line is HELD until its newline arrives", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  assert.equal(await f.write("no newline yet"), "");
  assert.equal(await f.write(" …still going"), "");
  assert.equal(await f.write(" — end\n"), "no newline yet …still going — end\n");
  assert.equal(await f.flush(), "");
});

test("complete lines are emitted immediately; only the tail is held", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  const out = await f.write("line one\nline two\npartial");
  assert.equal(out, "line one\nline two\n");
  assert.equal(await f.flush(), "partial");
});

test("a pathological unbroken line force-flushes without splitting a token", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { maxTailHold: 64 });
  const pad = "x".repeat(60);
  // The token starts inside the guarded region of the forced flush.
  let out = await f.write(`${pad}${SYM.slice(0, 12)}`); // "…xxx$MDU:Read[9b0"[cut mid-token]
  out += await f.write(SYM.slice(12) + "\n");
  out += await f.flush();
  assert.equal(out, `${pad}${RAW}\n`);
});

test("a force-flush with a $-free tail emits everything (no needless hold)", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { maxTailHold: 32 });
  const long = "y".repeat(100);
  const out = (await f.write(long)) + (await f.flush());
  assert.equal(out, long);
});

test("exported caps stay sane (reserve protects a full symbol, hold ≥ reserve)", () => {
  assert.ok(SYMBOL_RESERVE >= 128);
  assert.ok(MAX_TAIL_HOLD >= SYMBOL_RESERVE);
});

test("\\r is a boundary too (TUI redraws / progress bars): text up to it is emitted", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  // A carriage-return-separated redraw run with NO newline anywhere.
  const out = await f.write(`step 1\rstep 2 ${SYM}\rpartial`);
  assert.equal(out, `step 1\rstep 2 ${RAW}\r`);
  assert.equal(await f.flush(), "partial");
});

// ── PTY-relay eager mode ──────────────────────────────────────────────────────

test("couldBeSymbolPrefix: token heads (both spellings) hold; ordinary $ text does not", () => {
  // Growing prefixes of a real token — every truncation point.
  for (const p of ["$", "$M", "$MD", "$MDU", "$MDU:", "$MDU:Re", `${SYM}`, `${SYM}.field`]) {
    assert.equal(couldBeSymbolPrefix(p), true, `should hold: ${JSON.stringify(p)}`);
  }
  // Markdown-escaped spellings count too (only the leading `$` and tail `_` escape).
  assert.equal(couldBeSymbolPrefix("\\$MDU"), true);
  assert.equal(couldBeSymbolPrefix("\\$MDU:web\\_fe"), true);
  // Not token-shaped: never held.
  // The RETIRED prefixes (built from parts: the tree-wide sweep forbids their
  // literals) are ordinary `$` text now — never held.
  const retired = ["$", "AOS:"].join("");
  const retiredDv = ["$", "DV:"].join("");
  for (const p of ["", "$5.00 > ", "$HOME", "$MX", "$MDX", "$D", `${SYM} > `, "$MDU:!", retired, `${retired}Read[9b0a]`, retiredDv, `${retiredDv}Read[9b0a]`]) {
    assert.equal(couldBeSymbolPrefix(p), false, `should NOT hold: ${JSON.stringify(p)}`);
  }
});

test("EAGER: a TUI frame tail — cursor control + unterminated prompt — is emitted IMMEDIATELY", async () => {
  // The cursor-blink regression guard: the hide-cursor sequence and the
  // unterminated bottom line must come out of the SAME write, never held for
  // an idle timer.
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  const frame = "line one\nline two\n\x1b[?25l\x1b[2K❯ input box";
  assert.equal(await f.write(frame), frame);
  assert.equal(f.pending, 0);
  assert.deepEqual(r.calls, []); // no token → no IPC either
});

test("EAGER: a newline-less prompt whose $ is NOT a token is emitted immediately", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  assert.equal(await f.write("total: $5.00 > "), "total: $5.00 > ");
  assert.equal(f.pending, 0);
});

test("EAGER: a COMPLETE token followed by prompt text resolves INLINE, no boundary needed", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  assert.equal(await f.write(`reply: ${SYM} > `), `reply: ${RAW_FRAME} > `);
  assert.equal(f.pending, 0);
});

test("EAGER: an in-flight token prefix is held; the token reassembles when data resumes", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  assert.equal(await f.write(`loading ${SYM.slice(0, 10)}`), "loading ");
  assert.equal(f.pending, SYM.slice(0, 10).length); // candidate stays held
  assert.equal(await f.write(`${SYM.slice(10)} done`), `${RAW_FRAME} done`);
  assert.equal(f.pending, 0);
});

test("EAGER: a COMPLETE token ending a write is held ONE step (a .field may still arrive), then resolves", async () => {
  // A complete token is also a valid PREFIX of a longer token (`.field` chain
  // segments may still be streaming — see the ']'↔'.field' seam test below), so
  // the completing write holds it; the very next non-styling write (here: a
  // cursor-control heartbeat) — or the idle-drain flush — resolves it.
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  assert.equal(await f.write(`done: ${SYM}`), "done: ");
  assert.equal(f.pending, SYM.length, "the extensible token is held for a possible .field continuation");
  assert.equal(await f.flush(), RAW_FRAME);
});

test("EAGER: `held` is the suffix of the input not yet on the wire — the candidate tail, a line break looked through, a carried escape", async () => {
  // run.ts holds the same suffix back from the screen reconciler's TUI model
  // (screen-reconcile.ts feedTui), so the model never runs a row ahead of the
  // human's terminal: a reserve head ending a read keeps its line break held.
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  const read1 = `The value is ${SYM}/1:2:78:65\r\n`;
  assert.equal(await f.write(read1), "The value is ");
  assert.equal(f.held, read1.length - "The value is ".length, "the head and its CRLF are held");
  assert.equal(f.held, f.pending);
  const out2 = await f.write("$MDU/d49f/2 end\r\n");
  assert.equal(f.held, 0, "the continuation broke the candidate: everything went out");
  assert.ok(out2.endsWith(" end\r\n") && !out2.includes(SYM), JSON.stringify(out2));
  // A partial escape at the end of a read is carried, not emitted: held too.
  const g = new ReplyStreamFilter(r, { eager: true });
  assert.equal(await g.write("abc\x1b["), "abc");
  assert.equal(g.pending, 0);
  assert.equal(g.held, 2, "the carried `ESC [` is held");
  assert.equal(await g.write("1Adef"), "\x1b[1Adef");
  assert.equal(g.held, 0);
  assert.equal(await g.flush(), "");
  assert.equal(g.held, 0);
});

test("EAGER: a symbol-terminal reply + active heartbeat frames RESOLVES mid-stream (no idle needed)", async () => {
  // The production shape end-to-end: the reply's last visible content is the
  // symbol, followed ONLY by cursor-control 'heartbeat' frames (the TUI's live
  // region keeps repainting, so filter.flush() never fires during the turn).
  // Before the fix the token sat held across every heartbeat and the resolver
  // was NEVER called; now it resolves on the write that completes it.
  const r = new MockResolver();
  const resolved: string[] = [];
  const f = new ReplyStreamFilter(r, { eager: true, onResolve: (_b, a) => void resolved.push(a) });
  const heartbeat = "\x1b[?25l\x1b[H\x1b[63;3H\x1b[?25h"; // pure cursor-control, no text
  let out = "";
  out += await f.write(`The count is \x1b[1m${SYM}\x1b[22m`); // symbol ends the reply text
  out += await f.write(heartbeat);
  out += await f.write(heartbeat);
  // Resolved WITHOUT any flush() — i.e. while the stream is still "live".
  assert.equal(r.calls.length >= 1, true, "the resolver ran during streaming, not only on idle");
  assert.equal(resolved.length, 1, "one resolution fired mid-stream");
  assert.ok(out.includes(RAW_ONELINE), "the human saw the resolved value (frame-safe row)");
  assert.ok(!out.includes("$MDU:"), "the raw symbol was NEVER emitted to the terminal");
});

test("EAGER: a token split at the ']'↔'.field' seam never emits the raw base (live leak 1783831380)", async () => {
  // Live regression (session 1783831380-3877123, 2026-07-12): the model
  // streams `$MDU:inspect[695b]` and `.result` in SEPARATE deltas (a natural
  // BPE/SSE boundary — hit on BOTH turns of the reported session). The bare
  // base matches COMPLETE_TOKEN_RE, and the old resolve-NOW rule emitted it
  // immediately — but the arbiter cannot resolve a base whose symbol was
  // allocated WITH a field (resolveSymbolReference is exact-name + field
  // fallback, never base-broadening), so it passed through raw; `.result`
  // followed, `$`-free, also raw. The human saw the full raw token
  // mid-sentence until a much-later full repaint re-delivered it whole.
  const FIELDED = "$MDU:inspect[695b].result";
  const r = new MockResolver({ [FIELDED]: "6" });
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write('The word "security" appears \x1b[1m$MDU:inspect[695b]');
  out += await f.write(".result\x1b[22m times on homepage.example.test.");
  assert.ok(!out.includes("$MDU:"), "no raw token fragment reached the terminal");
  // The 1-col value pads to the token's width (frame-safe padding): the
  // appended flow text stays at the columns the TUI's cursor math counted.
  assert.ok(out.includes(`6${" ".repeat(FIELDED.length - 1)}\x1b[22m times on`), "the resolved value was delivered mid-stream");
});

test("EAGER: live claude-code frame shapes never leak a raw token at ANY chunk boundary", async () => {
  // Distilled from a live claude-2.1.207 PTY capture (2026-07-12): append-
  // streamed reply text with SGR styling around the token, a pure
  // cursor-control heartbeat frame, and the word-positioned transcript
  // repaint (\x1b[<n>G between words, NO literal spaces). Wherever the PTY
  // read boundaries fall, the raw token must never reach the terminal, the
  // resolved value must, and the positioned words after the token must not
  // be glued into the candidate (display stall / maximal-munch mis-match).
  const FIELDED = "$MDU:inspect[695b].result";
  // The token sits at col 24; the TUI places the next word one gap column
  // past the token's end (and "on" one gap past "times").
  const TIMES = 24 + FIELDED.length + 1;
  const ON = TIMES + "times".length + 1;
  const stream =
    `The word "security" appears \x1b[1m${FIELDED}\x1b[22m times on homepage.example.test.\r\n` +
    "\x1b[?25l\x1b[H\x1b[63;3H\x1b[?25h" + // heartbeat frame
    `\x1b[7GThe\x1b[11Gword\x1b[16Gappears\x1b[24G${FIELDED}\x1b[${TIMES}Gtimes\x1b[${ON}Gon\r\n`;
  for (const size of [1, 2, 3, 5, 7, 11, 16, 33, 64, stream.length]) {
    const r = new MockResolver({ [FIELDED]: "6" });
    const f = new ReplyStreamFilter(r, { eager: true });
    let out = "";
    for (let i = 0; i < stream.length; i += size) out += await f.write(stream.slice(i, i + size));
    out += await f.flush();
    const PADDED = `6${" ".repeat(FIELDED.length - 1)}`; // 1-col value padded to the token's width
    assert.ok(!out.includes("$MDU:"), `chunk=${size}: raw token leaked to the terminal`);
    assert.ok(out.includes(`\x1b[1m${PADDED}\x1b[22m times`), `chunk=${size}: the streamed copy did not resolve`);
    assert.ok(out.includes(`\x1b[24G${PADDED}\x1b[${TIMES}G`), `chunk=${size}: the word-positioned copy did not resolve`);
    assert.ok(out.includes(`\x1b[${TIMES}Gtimes`), `chunk=${size}: positioned words after the token were eaten`);
  }
});

test("EAGER: a wrap-split token (insertions mid-token) still reassembles across writes", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  const cut = SYM.length - 1; // mid-token: everything but the closing ']'
  assert.equal(await f.write(`start ${SYM.slice(0, cut)}\r\n`), "start ");
  assert.equal(await f.write(`  ${SYM.slice(cut)} end\n`), `${RAW_FRAME} end\n`);
});

test("EAGER: a candidate bloated past maxTailHold by raw insertions stops holding", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true, maxTailHold: 64 });
  const bloat = "$MDU:" + "\x1b[0m".repeat(30); // cleaned stays tiny, raw >64
  const out = await f.write(bloat);
  assert.equal(out, bloat); // emitted, not held forever
  assert.equal(f.pending, 0);
});

// ── frame-safe value rendering (eager) — the width-mismatch fix ──────────────
// The differential harness's first catch (differential-interactive.md §10): a
// multi-line / overlong value spliced into a TUI's positioned frame punches
// the cursor through rows the TUI owns. Eager substitutions are therefore
// cursor-neutral: one row, wrap-off-bracketed when longer than the token.

test("frameSafeValue: one row — newlines become ⏎, tabs a space, escapes/C0 stripped, trailing NL drops", () => {
  assert.equal(frameSafeValue("a\nb"), "a ⏎ b");
  assert.equal(frameSafeValue("a\r\nb\rc"), "a ⏎ b ⏎ c");
  assert.equal(frameSafeValue("     1\t# notes\n2\tmore\n"), "     1 # notes ⏎ 2 more");
  assert.equal(frameSafeValue("x\x1b[31mred\x1b[0my"), "xredy");
  assert.equal(frameSafeValue("bell\x07null\x00"), "bellnull");
  assert.equal(frameSafeValue("plain"), "plain");
});

// Geometry of the forensic splice tests below, DERIVED from SYM so the byte
// shapes stay exact whatever the token's spelling: the TUI paints SYM at
// column AT and does its cursor math with the TOKEN's width.
const AT = 3; // ESC[3G — where the token is painted
const TOK_COLS = SYM.length; // the token's width on the row
const BOUNDARY = AT + TOK_COLS; // the TUI's token end (first column after it)
const PROBE = "1 RC_PROBE_2026_5527"; // 20 cols, no newline — splices whole
const DELTA = PROBE.length - TOK_COLS; // how far the splice widens the row
const VALUE_END = AT + PROBE.length; // where the value really ends (BOUNDARY + DELTA)
const GAP = BOUNDARY + 1; // Ink's gap-skip erase column (one past the token end)
const cha = (n: number): string => `\x1b[${n}G`;

/** Two-splice rows `\r${A} ${B}`: A at col 1, one space, then B; both tokens
 *  one width W, both values 20 cols → each splice widens by D. */
function twoSplice(A: string, B: string): { W: number; D: number; bA: number; bB: number } {
  assert.equal(A.length, B.length, "fixture: both tokens share one width");
  const W = A.length;
  const bA = 1 + W; // A's TUI end; B starts one space later
  return { W, D: 20 - W, bA, bB: bA + 1 + W };
}

test("EAGER: a multi-line value NEVER emits raw newlines/tabs into the frame", async () => {
  const r = new MockResolver({ [SYM]: "line1\nline2\tend\n" });
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = (await f.write(`${cha(AT)}${SYM}\x1b[50Gnext`)) + (await f.flush());
  assert.ok(!out.includes("\n"), "no raw newline punched into the positioned frame");
  assert.ok(!out.includes("\t"), "no raw tab column-jump");
  const ROW = "line1 ⏎ line2 end"; // 17 cols
  assert.ok(out.includes(ROW), "value delivered as one readable row");
  // The TUI's own positioning after the token survives TRANSLATED: the value
  // (ROW) widened the row past the token by ROW.length - TOK_COLS, and 50
  // addresses PAST the token end (BOUNDARY), so it shifts by that delta. (The
  // old expectation — 50G verbatim — encoded the second-catch clip: the TUI's
  // stale-width math landing inside the value. See POST-SPLICE COLUMN
  // TRANSLATION in src/filter.ts.)
  assert.ok(
    out.includes(`${cha(50 + ROW.length - TOK_COLS)}next`),
    "the TUI's positioning after the token survives, shifted by the splice delta",
  );
});

// ── post-splice column translation (eager) — the width-delta erase fix ───────
// The differential harness's SECOND catch (2026-07-17, soak run 7; the byte
// shapes below are the live forensics): after painting its token the TUI
// re-addresses the row with math computed for the TOKEN's width; without
// translation its `CHA token-end` + `EL` chops the tail off the longer
// spliced value on the SETTLED screen.

test("EAGER: the forensic shape — TUI's CHA-to-token-end + EL no longer erases the value tail", async () => {
  // Live capture, wrapped side: ESC[3G ?7l <value> ?7h ESC[<end>G ESC[K — the
  // TUI painted the token at col 3 and erases from BOUNDARY (its token end);
  // the 20-col value ends at VALUE_END. BOUNDARY must become
  // BOUNDARY + DELTA = VALUE_END.
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = (await f.write(`${cha(AT)}${SYM}${cha(BOUNDARY)}\x1b[K`)) + (await f.flush());
  assert.ok(out.includes(PROBE), "the full value is on the row");
  assert.ok(out.includes(`${cha(VALUE_END)}\x1b[K`), "the TUI's erase lands AFTER the value, not inside it");
  assert.ok(!out.includes(cha(BOUNDARY)), "the stale-width CHA target was rewritten");
});

test("EAGER: the gap-skip erase (run 23) — EL starts at the value's END, no stale glyph survives", async () => {
  // Second forensic shape: Ink's diff renderer skips the word-gap column it
  // believes unchanged and erases from ONE PAST the token end (GAP).
  // Plain translation (GAP → GAP + DELTA) would leave real col VALUE_END
  // unerased — a stale glyph from the previous frame survives there (the
  // trailing `o`). The erase-tail idiom instead erases from the value's real
  // end and then restores the TUI's intended translated cursor.
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = (await f.write(`${cha(AT)}${SYM}${cha(GAP)}\x1b[K`)) + (await f.flush());
  assert.ok(out.includes(`${cha(VALUE_END)}\x1b[K${cha(GAP + DELTA)}`), "erase from the value end, then the translated cursor");
  assert.ok(!out.includes(`${cha(GAP + DELTA)}\x1b[K`), "the naively translated erase (leaving a stale gap col) is gone");
});

test("EAGER: a CHA at/before the splice start is NOT shifted (row-interior repaint)", async () => {
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = (await f.write(`${cha(AT)}${SYM}\x1b[2Gx`)) + (await f.flush());
  assert.ok(out.includes("\x1b[2Gx"), "addressing before the splice keeps the TUI's own target");
});

test("EAGER: row abandonment clears translations — same CHA on the NEXT row is untouched", async () => {
  const r = new MockResolver({ [SYM]: PROBE });
  for (const abandon of ["\n", "\r", "\x1b[1B", "\x1b[5;1H", "\x1b[2Fdown"]) {
    const f = new ReplyStreamFilter(r, { eager: true });
    const out = (await f.write(`${cha(AT)}${SYM}${abandon}${cha(BOUNDARY)}tail`)) + (await f.flush());
    assert.ok(
      out.includes(`${cha(BOUNDARY)}tail`),
      `after ${JSON.stringify(abandon)} the new row's CHA is the TUI's own again`,
    );
  }
});

test("EAGER: two widened splices on one row shift a later CHA by the CUMULATIVE delta", async () => {
  const A = "$MDU:Read[9b0a]";
  const B = "$MDU:exec[1f2e]";
  const r = new MockResolver({ [A]: "AAAAAAAAAAAAAAAAAAAA", [B]: "BBBBBBBBBBBBBBBBBBBB" }); // 20 cols each
  const f = new ReplyStreamFilter(r, { eager: true });
  // col 1: A (token W, value 20, ΔD) then B one space later (ΔD): a CHA to 40
  // (past both boundaries bA and bB) shifts by 2·D.
  const { D, bB } = twoSplice(A, B);
  assert.ok(40 > bB, "fixture: the CHA addresses past both tokens");
  const out = (await f.write(`\r${A} ${B}${cha(40)}end`)) + (await f.flush());
  assert.ok(out.includes(`${cha(40 + 2 * D)}end`), "both deltas apply to a CHA past both boundaries");
});

test("EAGER: a CSI split across the chunk edge is carried whole — never scanned in halves", async () => {
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  const seq = cha(BOUNDARY);
  let out = "";
  out += await f.write(`${cha(AT)}${SYM}${seq.slice(0, 3)}`); // ends mid-CSI: "\x1b[1…"
  out += await f.write(`${seq.slice(3)}\x1b[K`);
  out += await f.flush();
  assert.ok(out.includes(`${cha(VALUE_END)}\x1b[K`), "the reassembled CHA is translated exactly once");
  assert.ok(!out.includes(seq), "no half-scanned sequence slipped through raw");
});

// ── a value wider than the rest of its row (2026-10-17) ──────────────────────
// A real Stripe secret key is 107 columns; its 41-column token sat mid-row in
// a Claude Code reply. The translation moved the TUI's `CHA 114` for the next
// word to 180 on a 120-column terminal, and the text after the value went out
// with auto-wrap back on: it wrapped onto rows the TUI never counted, and
// every relative row move after it landed low (a later row read
// `connected0totStripe`). The text the splice pushes past the right edge is
// CLIPPED: not sent, as the screen reconciler's clip rule paints it.

/** The live shape, at 72 columns: a token mid-row with words after it placed
 *  by CHA, then rows reached by relative moves. */
const WIDE_KEY = "$MDU:nomodel_Read[aad5].STRIPE_SECRET_KEY";
const WIDE_VALUE = `wide-value-${"0123456789".repeat(10)}`; // 111 columns
const WIDE_FRAME =
  `\r●${cha(3)}Found${cha(9)}the${cha(13)}key${cha(17)}(${WIDE_KEY})${cha(61)}and${cha(65)}got` +
  `\r\x1b[2C\x1b[1BHTTP${cha(8)}200.` +
  `\r\x1b[2C\x1b[2Bpayments:${cha(13)}connected${cha(23)}to${cha(26)}Stripe${cha(33)}(test${cha(39)}mode)`;
const WIDE_SCREEN = [
  `● Found the key (${WIDE_VALUE}`.slice(0, 72),
  "  HTTP 200.",
  "",
  "  payments: connected to Stripe (test mode)",
  "",
  "",
];

test("EAGER wide value: the text after it clips at the right edge — no row the TUI never counted, later rows intact", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [WIDE_KEY]: WIDE_VALUE }), { eager: true, cols: 72 });
  const out = await run(f, [WIDE_FRAME]);
  assert.deepEqual(await renderScreen(out, 72, 6), WIDE_SCREEN);
  // The value is cut where the row ends (its last cell is the 72nd column's
  // glyph, not the value's last one written over and over).
  assert.ok(!out.includes(WIDE_VALUE), "only the part of the value the row shows goes out");
  assert.ok(!/[)]|and|got/.test(out.slice(out.indexOf(WIDE_VALUE.slice(0, 20)), out.indexOf("HTTP"))), JSON.stringify(out));
  // Every chunk size: the clip does not depend on where a read ends.
  for (const size of [1, 7, 40]) {
    const g = new ReplyStreamFilter(new MockResolver({ [WIDE_KEY]: WIDE_VALUE }), { eager: true, cols: 72 });
    const parts: string[] = [];
    for (let i = 0; i < WIDE_FRAME.length; i += size) parts.push(WIDE_FRAME.slice(i, i + size));
    assert.deepEqual(await renderScreen(await run(g, parts), 72, 6), WIDE_SCREEN, `reads of ${size}`);
  }
});

test("EAGER wide value: words the value pushes past the edge clip even when the value itself fits", async () => {
  // A 50-column value from column 17 ends at 66: `(…)` fits, `and got`
  // (shifted 9 columns right) runs past 72.
  const value = "v".repeat(50);
  const f = new ReplyStreamFilter(new MockResolver({ [WIDE_KEY]: value }), { eager: true, cols: 72 });
  const rows = await renderScreen(await run(f, [WIDE_FRAME]), 72, 6);
  assert.deepEqual(rows, [`● Found the key (${value}) and got`.slice(0, 72), ...WIDE_SCREEN.slice(1)]);
});

test("EAGER wide value: past the edge, an EL erases nothing and a relative move lands at its real column", async () => {
  const A = "$MDU:Read[9b0a]"; // 15 columns
  const value = "0123456789abcdefghijklmnopqrstu"; // 31: from column 1 past a 20-column row
  // EL at a column past the edge: the terminal would erase the last visible cell.
  let f = new ReplyStreamFilter(new MockResolver({ [A]: value }), { eager: true, cols: 20 });
  let out = await run(f, [`\r${A}abcd\x1b[K\r\n`]);
  assert.equal((await renderScreen(out, 20, 2))[0], value.slice(0, 20));
  // CUB from past the edge: the terminal's cursor sits on the last column,
  // not at the model's real column; the move back to column 5 (inside the
  // value: a TUI overwriting its own token cells) lands on column 5.
  f = new ReplyStreamFilter(new MockResolver({ [A]: value }), { eager: true, cols: 20 });
  out = await run(f, [`\r${A}abcd\x1b[15DX\r\n`]);
  assert.equal((await renderScreen(out, 20, 2))[0], `${value.slice(0, 4)}X${value.slice(5, 20)}`);
  // Unknown width: nothing is clipped (bytes as before).
  f = new ReplyStreamFilter(new MockResolver({ [A]: value }), { eager: true });
  out = await run(f, [`\r${A}abcd\x1b[K`]);
  assert.equal(out, `\r\x1b[?7l${value}\x1b[?7habcd\x1b[K`);
});

test("EAGER wide value, the terminal wrap rule (Goose, §17): the text after a value wraps by itself, bytes as before", async () => {
  // Goose prints its reply raw and the terminal wraps it: nothing places the
  // text after the value on the row, so it is not clipped.
  const A = "$MDU:Read[9b0a]";
  const value = "0123456789abcdefghijklmnopqrstu";
  const f = new ReplyStreamFilter(new MockResolver({ [A]: value }), {
    eager: true, cols: 20, reserveCache: new ReserveValueCache(undefined, "terminal"),
  });
  const out = await run(f, [`\r${A}, and the rest of it\r\n`]);
  assert.equal(out, `\r\x1b[?7l${value}\x1b[?7h, and the rest of it\r\n`);
});

// ── the two residual splice shapes (TODO 2026-07-18), closed ─────────────────
// Shape 1: the erase-tail idiom SPLIT across a PTY read boundary. A trailing
// idiom-eligible complete CHA on a splice-active row is HELD (csiHold) so the
// EL arriving in the next read reassembles the pair; every flush drains the
// hold translated-plain. Shape 2: multi-splice rows — the erase-tail rewrite
// generalizes to cumulative deltas (erase from the LAST value's real end).

test("EAGER: the erase-tail idiom SPLIT at a PTY read boundary still rewrites (CHA | EL)", async () => {
  // Same forensic geometry as run 23 (BOUNDARY, DELTA, gap-skip CHA GAP)
  // but the pair arrives in separate reads: `…ESC[<GAP>G` ‖ `ESC[K`.
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write(`${cha(AT)}${SYM}${cha(GAP)}`);
  out += await f.write("\x1b[K");
  out += await f.flush();
  assert.ok(out.includes(`${cha(VALUE_END)}\x1b[K${cha(GAP + DELTA)}`), "the reassembled idiom erases from the value end, then restores the translated cursor");
  assert.ok(!out.includes(`${cha(GAP + DELTA)}\x1b[K`), "the naively translated erase (stale gap col) is gone");
  assert.ok(!out.includes(cha(GAP)), "the stale-width CHA never reached the terminal raw");
});

test("EAGER: the split idiom with n == boundary (no gap skip) erases from the value end", async () => {
  const r = new MockResolver({ [SYM]: PROBE }); // intended BOUNDARY + DELTA == VALUE_END
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write(`${cha(AT)}${SYM}${cha(BOUNDARY)}`);
  out += await f.write("\x1b[K");
  out += await f.flush();
  assert.ok(out.includes(`${cha(VALUE_END)}\x1b[K`), "erase lands after the value");
  assert.ok(!out.includes(`${cha(VALUE_END)}\x1b[K${cha(VALUE_END)}`), "no redundant cursor restore when intended == valueEnd");
});

test("EAGER: the split idiom survives a MID-EL read boundary (ESC | [K, [ | K, [0 | K)", async () => {
  for (const [head, rest] of [
    ["\x1b", "[K"],
    ["\x1b[", "K"],
    ["\x1b[0", "K"],
  ] as const) {
    const r = new MockResolver({ [SYM]: PROBE });
    const f = new ReplyStreamFilter(r, { eager: true });
    let out = "";
    out += await f.write(`${cha(AT)}${SYM}${cha(GAP)}${head}`);
    out += await f.write(rest);
    out += await f.flush();
    assert.ok(out.includes(cha(VALUE_END)), `split ${JSON.stringify(head)}‖${JSON.stringify(rest)}: erase starts at the value end`);
    assert.ok(!out.includes(cha(GAP)), `split ${JSON.stringify(head)}‖${JSON.stringify(rest)}: stale-width CHA rewritten`);
  }
});

test("EAGER: flush drains a held trailing CHA translated-plain (stream end mid-idiom)", async () => {
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = (await f.write(`${cha(AT)}${SYM}${cha(GAP)}`)) + (await f.flush());
  assert.ok(out.endsWith(cha(GAP + DELTA)), "the held CHA emits shifted by the splice delta — never lost");
});

test("EAGER: a non-EL follow-up releases the held CHA plainly (no idiom rewrite)", async () => {
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write(`${cha(AT)}${SYM}${cha(GAP)}`);
  out += await f.write("\x1b[2Kx"); // EL(2) — whole-line erase, not the idiom tail
  out += await f.flush();
  assert.ok(out.includes(`${cha(GAP + DELTA)}\x1b[2Kx`), "plain translation: CHA shifted, follow-up untouched");
});

test("EAGER: a CHA on a splice-FREE row is never held (no display delay off splice rows)", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = await f.write("plain frame\x1b[19G");
  assert.ok(out.endsWith("\x1b[19G"), "the trailing CHA emits immediately — nothing to pair against");
});

test("EAGER: multi-splice row — the trailing erase rewrites against the LAST value's end", async () => {
  const A = "$MDU:Read[9b0a]"; // at col 1 → boundary bA
  const B = "$MDU:exec[1f2e]"; // at TUI col bA + 1 → boundary bB
  const r = new MockResolver({ [A]: "AAAAAAAAAAAAAAAAAAAA", [B]: "BBBBBBBBBBBBBBBBBBBB" }); // 20 cols → ΔD each
  const f = new ReplyStreamFilter(r, { eager: true });
  const { D, bB } = twoSplice(A, B);
  // Gap-skip erase after BOTH tokens (bB + 1 ≥ boundary bB): the last value
  // really ends at bB + 2·D; the TUI intends its cursor at bB + 1 + 2·D.
  const out = (await f.write(`\r${A} ${B}${cha(bB + 1)}\x1b[K`)) + (await f.flush());
  assert.ok(out.includes(`${cha(bB + 2 * D)}\x1b[K${cha(bB + 1 + 2 * D)}`), "erase from the LAST value's real end, cumulative deltas");
  assert.ok(!out.includes(cha(bB + 1)), "the stale-width CHA was rewritten");
});

test("EAGER: multi-splice row + SPLIT idiom (CHA | EL) still rewrites cumulatively", async () => {
  const A = "$MDU:Read[9b0a]";
  const B = "$MDU:exec[1f2e]";
  const r = new MockResolver({ [A]: "AAAAAAAAAAAAAAAAAAAA", [B]: "BBBBBBBBBBBBBBBBBBBB" });
  const f = new ReplyStreamFilter(r, { eager: true });
  const { D, bB } = twoSplice(A, B);
  let out = "";
  out += await f.write(`\r${A} ${B}${cha(bB + 1)}`);
  out += await f.write("\x1b[K");
  out += await f.flush();
  assert.ok(out.includes(`${cha(bB + 2 * D)}\x1b[K${cha(bB + 1 + 2 * D)}`), "the split pair reassembles and rewrites against both deltas");
});

test("EAGER: an erase BETWEEN two splices keeps plain translation (documented residual)", async () => {
  const A = "$MDU:Read[9b0a]"; // boundary bA, ΔD
  const B = "$MDU:exec[1f2e]"; // boundary bB, ΔD
  const r = new MockResolver({ [A]: "AAAAAAAAAAAAAAAAAAAA", [B]: "BBBBBBBBBBBBBBBBBBBB" });
  const f = new ReplyStreamFilter(r, { eager: true });
  const { D, bA, bB } = twoSplice(A, B);
  // n: past A's boundary but inside B's span — no erase-tail rewrite; plain
  // CHA translation shifts by A's delta only.
  const n = bA + 4;
  assert.ok(n > bA + 1 && n < bB, "fixture: n lands inside B's TUI span");
  const out = (await f.write(`\r${A} ${B}${cha(n)}\x1b[K`)) + (await f.flush());
  assert.ok(out.includes(`${cha(n + D)}\x1b[K`), "plain translation: shifted by the crossed boundary only");
});

// ── IDLE-DRAIN RE-HOLD (the loaded-SSE base↔field gap; live 6414 leak) ───────

test("EAGER: idle flush(false) RE-HOLDS a complete-but-unresolvable base awaiting its field", async () => {
  // Live shape (pipeline 6414, interactive-inspect-extract): the reply is
  // exactly `$MDU:inspect[003d].result`, streamed as base ‖ (>200ms) ‖ field.
  // The old unconditional idle drain emitted the bare base raw.
  const FIELDED = "$MDU:inspect[003d].result";
  const r = new MockResolver({ [FIELDED]: "SA-2026-0777" });
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write("advisory:$MDU:inspect[003d]");
  out += await f.flush(false); // the relay's quiet-period drain fires mid-gap
  assert.ok(!out.includes("$MDU:"), "the unresolvable base is re-held, not emitted raw");
  out += await f.write(".result\n");
  out += await f.flush();
  assert.ok(out.includes("SA-2026-0777"), "the reassembled token resolved for the human");
  assert.ok(!out.includes("$MDU:"), "no raw token fragment ever reached the terminal");
});

test("EAGER: idle flush(false) still resolves a KNOWN complete token immediately", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write(`reply: ${SYM}`);
  out += await f.flush(false);
  assert.ok(out.includes(RAW_ONELINE), "a resolvable symbol-terminal reply drains on the first idle flush");
  assert.equal(f.pending, 0);
});

test("EAGER: idle flush(false) re-holds a MID-TOKEN prefix too (SSE gap inside the token)", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = "";
  out += await f.write("The code is $MDU:Read[9b");
  out += await f.flush(false);
  assert.ok(!out.includes("$MDU:"), "the dangling prefix is re-held across the idle drain");
  out += await f.write("0a] done\n");
  out += await f.flush();
  assert.ok(out.includes(RAW_ONELINE), "the token reassembled and resolved");
});

test("EAGER: the idle re-hold is BOUNDED — a ghost token emits raw after IDLE_HOLD_MAX drains", async () => {
  const r = new MockResolver({}); // knows nothing — the base never resolves
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = await f.write("ghost: $MDU:exec[ffff]");
  for (let i = 0; i < IDLE_HOLD_MAX; i++) {
    out += await f.flush(false);
    assert.equal(out.includes("$MDU:"), false, `re-hold ${i + 1}/${IDLE_HOLD_MAX} keeps waiting`);
  }
  out += await f.flush(false); // budget exhausted → emit raw (never lose bytes)
  assert.ok(out.includes("$MDU:exec[ffff]"), "a ghost token cannot stall the stream forever");
  assert.equal(f.pending, 0);
});

test("EAGER: a FINAL flush emits a held candidate immediately (stream end loses nothing)", async () => {
  const r = new MockResolver({});
  const f = new ReplyStreamFilter(r, { eager: true });
  const out = (await f.write("tail: $MDU:exec[ffff]")) + (await f.flush());
  assert.ok(out.includes("$MDU:exec[ffff]"), "final flush never re-holds");
  assert.equal(f.pending, 0);
});

test("EAGER: new data resets the idle re-hold budget", async () => {
  const FIELDED = "$MDU:inspect[003d].result";
  const r = new MockResolver({ [FIELDED]: "SA-2026-0777" });
  const f = new ReplyStreamFilter(r, { eager: true });
  let out = await f.write("id: $MDU:inspect[003d]");
  for (let i = 0; i < IDLE_HOLD_MAX - 1; i++) out += await f.flush(false);
  out += await f.write(""); // a data event (even empty) restarts the budget
  for (let i = 0; i < IDLE_HOLD_MAX - 1; i++) out += await f.flush(false);
  assert.ok(!out.includes("$MDU:"), "the budget restarted — still holding");
  out += await f.write(".result\n");
  out += await f.flush();
  assert.ok(out.includes("SA-2026-0777"), "and the straggler field still completes the token");
});

test("EAGER: an unmodellable sequence BAILS to passthrough — no translation, no corruption", async () => {
  const r = new MockResolver({ [SYM]: PROBE });
  const f = new ReplyStreamFilter(r, { eager: true });
  // ESC 7 (save cursor) is not modeled → registrations drop; the CHA (at the
  // token end — translated without the bail) stays raw.
  const out = (await f.write(`${cha(AT)}${SYM}\x1b7${cha(BOUNDARY)}x`)) + (await f.flush());
  assert.ok(out.includes(`${cha(BOUNDARY)}x`), "after a bail the TUI's bytes pass through untouched");
});

test("EAGER: a value SHORTER than its token PADS to the token's width — geometry exact, nothing registers", async () => {
  // Live 2026-07-18 (pipeline 6414, all three reply-filter-live runs): every
  // splice was NARROWING (15-col Bash token → 12-col release code). A bare
  // short splice leaves the token's ghost tail — stale glyphs from the
  // previous frame — beside the value, and every later same-row CHA lands
  // right of the real text. Padding to the token's width blanks the ghost
  // tail and makes the TUI's cursor math exact with NO registration: the
  // following CHA+EL pass through untranslated.
  const LONG_SYM = "$MDU:Bash[a1b2].stdout";
  const r = new MockResolver({ [LONG_SYM]: "6" });
  const f = new ReplyStreamFilter(r, { eager: true });
  const erase = cha(AT + LONG_SYM.length + 1); // gap-skip erase past the token end
  const out = (await f.write(`${cha(AT)}${LONG_SYM}${erase}\x1b[K done`)) + (await f.flush());
  assert.equal(
    out,
    `${cha(AT)}6${" ".repeat(LONG_SYM.length - 1)}${erase}\x1b[K done`,
    "padded to token width; no brackets, no translation",
  );
});

test("EAGER: a value LONGER than its token is wrap-off-bracketed; a SHORTER one pads, never brackets", async () => {
  const LONG_SYM = "$MDU:Bash[a1b2].stdout";
  const r = new MockResolver({ [SYM]: RAW, [LONG_SYM]: "6" });
  const f = new ReplyStreamFilter(r, { eager: true });
  const longOut = (await f.write(`x ${SYM} y`)) + (await f.flush());
  assert.ok(longOut.includes(`\x1b[?7l${RAW_ONELINE}\x1b[?7h`), "overlong value clips instead of wrapping");
  const f2 = new ReplyStreamFilter(r, { eager: true });
  const shortOut = (await f2.write(`n = ${LONG_SYM} ok`)) + (await f2.flush());
  assert.equal(shortOut, `n = 6${" ".repeat(LONG_SYM.length - 1)} ok`, "short value: padded splice, no brackets");
});

// ── column-aware TAB expansion (differential-interactive.md §19 residual) ────

test("frameSafeValue(startCol): a tab becomes the spaces to the next 8-column stop, tracked glyph by glyph", () => {
  assert.equal(frameSafeValue("a\tb", 0), "a" + " ".repeat(7) + "b");
  assert.equal(frameSafeValue("a\tb", 2), "a" + " ".repeat(5) + "b"); // a@2, tab@3 → 8
  assert.equal(frameSafeValue("\tx", 8), " ".repeat(8) + "x", "a tab AT a stop advances a full stop");
  assert.equal(frameSafeValue("\t\tx", 7), " " + " ".repeat(8) + "x");
  assert.equal(frameSafeValue("     1\t# notes\n2\tmore\n", 2), "     1" + " ".repeat(8) + "# notes ⏎ 2" + " ".repeat(5) + "more");
  // A wide glyph counts two columns toward the stop; stripped bytes count none.
  assert.equal(frameSafeValue("日\tx", 0), "日" + " ".repeat(6) + "x");
  assert.equal(frameSafeValue("a\x1b[31m\x07\tb", 0), "a" + " ".repeat(7) + "b");
  assert.ok(!frameSafeValue("a\tb\tc", 5).includes("\t"), "a raw TAB never survives");
});

test("frameSafeValue: an absent or odd startCol keeps the ONE-SPACE fallback and never throws", () => {
  for (const bad of [undefined, NaN, Infinity, -1, -Infinity, "3" as unknown as number, null as unknown as number]) {
    assert.equal(frameSafeValue("a\tb", bad), "a b", `startCol=${String(bad)}`);
  }
  assert.equal(frameSafeValue("a\tb", 2.9), "a" + " ".repeat(5) + "b", "a fractional column floors");
  assert.equal(frameSafeValue("", 3), "");
  assert.equal(frameSafeValue("\t".repeat(3), 1e9).length, 8 * 3 - (1e9 % 8));
});

test("EAGER tab: the column is KNOWN (anchor + width) → the splice carries the tab-stop expansion and the erase-tail lands after it", async () => {
  const TAB_SYM = "$MDU:Read[7ab1]";
  const r = new MockResolver({ [TAB_SYM]: "k\tvalue-longer-than-token" });
  const f = new ReplyStreamFilter(r, { eager: true, cols: 80 });
  // CHA 3 → 0-based column 2: k@2, tab@3 → stop 8 = 5 spaces.
  const tokenEnd = 3 + TAB_SYM.length;
  const out = (await f.write(`\x1b[3G${TAB_SYM}${cha(tokenEnd)}\x1b[K`)) + (await f.flush());
  const rendered = "k" + " ".repeat(5) + "value-longer-than-token";
  // Value 29 cols: the TUI's erase at its token end moves to the value's real
  // end (3 + 29 = 32), with no restore since the CHA sat exactly at the end.
  assert.equal(out, `\x1b[3G\x1b[?7l${rendered}\x1b[?7h\x1b[32G\x1b[K`);
  assert.ok(!out.includes("\t"));
});

test("frameSafeValue(startCol, origin): the stops count from screen column `origin` (§19.7); a value left of it from its own start", () => {
  assert.equal(frameSafeValue("a\tb", 2, 2), "a" + " ".repeat(7) + "b", "a@0 of the text, its TAB to 8");
  // The live sentence capture (differential-interactive.md §19): `The value
  // is ` puts the value at column 15; Claude Code puts `port` at 2 + 32.
  assert.equal(frameSafeValue("DIFFTAB_HOST\tport", 15, 2), "DIFFTAB_HOST" + " ".repeat(7) + "port");
  assert.equal(frameSafeValue("DIFFTAB_HOST\tport", 15), "DIFFTAB_HOST" + " ".repeat(5) + "port", "origin 0: the screen's stops");
  assert.equal(frameSafeValue("a\tb", 0, 2), "a" + " ".repeat(7) + "b", "left of the origin: from its own start");
  for (const bad of [NaN, -3, Infinity, -Infinity]) assert.equal(frameSafeValue("a\tb", 2, bad), "a" + " ".repeat(5) + "b", String(bad));
  assert.equal(frameSafeValue("a\tb", undefined, 2), "a b", "no column: the one-space fallback still");
});

test("EAGER tab, content origin (§19.7): the splice counts the stops from the reply's text column, as Claude Code does", async () => {
  const TAB_SYM = "$MDU:Read[7ab1]";
  const r = new MockResolver({ [TAB_SYM]: "k\tvalue-longer-than-token" });
  const reserveCache = new ReserveValueCache(undefined, "ink", "content");
  const f = new ReplyStreamFilter(r, { eager: true, cols: 80, reserveCache });
  // CHA 3 → 0-based column 2, the text's column 0: k@0, its TAB to 8 = 7 spaces.
  const tokenEnd = 3 + TAB_SYM.length;
  const out = (await f.write(`\x1b[3G${TAB_SYM}${cha(tokenEnd)}\x1b[K`)) + (await f.flush());
  const rendered = "k" + " ".repeat(7) + "value-longer-than-token";
  assert.equal(out, `\x1b[3G\x1b[?7l${rendered}\x1b[?7h\x1b[34G\x1b[K`);
});

test("EAGER tab: a second value on the row expands from its REAL column (the first splice's widening counted)", async () => {
  const A = "$MDU:Read[aaaa]";
  const B = "$MDU:Read[bbbb]";
  const r = new MockResolver({ [A]: "0123456789abcdefghij", [B]: "x\ty" }); // A: W → 20 cols (+20-W)
  const f = new ReplyStreamFilter(r, { eager: true, cols: 120 });
  const out = (await f.write(`\r${A} ${B}!`)) + (await f.flush());
  // TUI space: B starts at 0-based col W + 1; real = W + 1 + (20 - W) = 21 → x@21, tab@22 → 24 = 2 spaces.
  const bRendered = "x  y";
  assert.equal(out, `\r\x1b[?7l0123456789abcdefghij\x1b[?7h ${bRendered}${" ".repeat(B.length - bRendered.length)}!`);
});

test("EAGER tab FALLBACK: no width, no anchor, an uncertain-width glyph, or a column past the edge → one space", async () => {
  const TAB_SYM = "$MDU:Read[7ab1]";
  const table = { [TAB_SYM]: "k\tv" };
  const oneSpace = "k v" + " ".repeat(TAB_SYM.length - 3); // padded to the token's width
  // (1) no terminal width given.
  let f = new ReplyStreamFilter(new MockResolver(table), { eager: true });
  assert.equal((await f.write(`\x1b[3G${TAB_SYM} `)) + (await f.flush()), `\x1b[3G${oneSpace} `);
  // (2) width given but the row was never anchored (no CR/CHA/CUP yet).
  f = new ReplyStreamFilter(new MockResolver(table), { eager: true, cols: 80 });
  assert.equal((await f.write(`say ${TAB_SYM} `)) + (await f.flush()), `say ${oneSpace} `);
  // (3) a wide glyph since the anchor: the code-point column is not exact.
  f = new ReplyStreamFilter(new MockResolver(table), { eager: true, cols: 80 });
  assert.equal((await f.write(`\r日本 ${TAB_SYM} `)) + (await f.flush()), `\r日本 ${oneSpace} `);
  //     ... and a fresh anchor restores it (CHA 9 → column 8, a stop: k@8, tab@9 → 16).
  const anchored = `k${" ".repeat(7)}v`;
  assert.equal(
    (await f.write(`\x1b[9G${TAB_SYM} `)) + (await f.flush()),
    `\x1b[9G${anchored}${" ".repeat(TAB_SYM.length - anchored.length)} `,
  );
  // (4) the modeled column is past the right edge (the run auto-wrapped).
  f = new ReplyStreamFilter(new MockResolver(table), { eager: true, cols: 10 });
  assert.equal((await f.write(`\r0123456789ab ${TAB_SYM} `)) + (await f.flush()), `\r0123456789ab ${oneSpace} `);
  // (5) a width getter that throws or returns junk degrades, never throws.
  f = new ReplyStreamFilter(new MockResolver(table), { eager: true, cols: () => { throw new Error("no tty"); } });
  assert.equal((await f.write(`\r${TAB_SYM} `)) + (await f.flush()), `\r${oneSpace} `);
  f = new ReplyStreamFilter(new MockResolver(table), { eager: true, cols: () => undefined });
  assert.equal((await f.write(`\r${TAB_SYM} `)) + (await f.flush()), `\r${oneSpace} `);
});

test("EAGER tab FALLBACK: a wrap-SPLIT token (two physical rows, no splice mark) keeps one space", async () => {
  const TAB_SYM = "$MDU:Read[7ab1]";
  const f = new ReplyStreamFilter(new MockResolver({ [TAB_SYM]: "k\tv" }), { eager: true, cols: 80 });
  const out = (await f.write(`\r$MDU:Read\r\n  [7ab1] `)) + (await f.flush());
  assert.ok(out.includes("k v"), JSON.stringify(out));
  assert.ok(!out.includes("\t"));
});

test("PIPE mode keeps a value's raw TAB verbatim (linear output, the terminal expands it)", async () => {
  const TAB_SYM = "$MDU:Read[7ab1]";
  const out = await run(new ReplyStreamFilter(new MockResolver({ [TAB_SYM]: "k\tv" }), { cols: 80 }), [`\r${TAB_SYM}\n`]);
  assert.equal(out, "\rk\tv\n");
});

test("PIPE mode is untouched by the frame-safe fix: multi-line values stay verbatim", async () => {
  const r = new MockResolver();
  const out = await run(new ReplyStreamFilter(r), [`Summary: ${SYM}\n`]);
  assert.equal(out, `Summary: ${RAW}\n`); // raw \n kept — linear output, full fidelity
});

// ── aggressive wrap reassembly (insertions inside tokens) ────────────────────

test("stripInsertions removes wrap artifacts and maps back to original indices", () => {
  const text = "ab\r\n  cd\x1b[0mef";
  const { clean, map } = stripInsertions(text);
  assert.equal(clean, "abcdef");
  // Each clean char points at its original byte.
  assert.equal(text[map[0]!], "a");
  assert.equal(text[map[2]!], "c");
  assert.equal(text[map[4]!], "e");
  assert.equal(map.length, clean.length);
});

test("a token hard-wrapped by \\r\\n + continuation indent resolves (span spliced)", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  const cut = SYM.length - 1; // mid-token: everything but the closing ']'
  const wrapped = `${SYM.slice(0, cut)}\r\n  ${SYM.slice(cut)}`;
  const out = (await f.write(`A ${wrapped} B\n`)) + (await f.flush());
  assert.equal(out, `A ${RAW} B\n`);
});

test("a token interrupted by ANSI escapes resolves; escapes OUTSIDE the token survive", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  const wrapped = `${SYM.slice(0, 12)}\x1b[0m\x1b[2K${SYM.slice(12)}`;
  const out = (await f.write(`\x1b[1mbold\x1b[0m ${wrapped}!\n`)) + (await f.flush());
  // The bytes outside the token span are byte-identical; the interrupted
  // token span (escapes included) is replaced by the resolved value.
  assert.equal(out, `\x1b[1mbold\x1b[0m ${RAW}!\n`);
});

test("an INCOMPLETE token prefix at a wrap boundary is pulled back and reassembles across writes", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  // First write ends mid-token AT a newline (the TUI wrapped the row): the
  // text before the token flushes, the dangling prefix is held.
  const cut = SYM.length - 1; // mid-token: everything but the closing ']'
  const out1 = await f.write(`start ${SYM.slice(0, cut)}\r\n`);
  assert.equal(out1, "start ");
  // The continuation row completes the token.
  const out2 = await f.write(`  ${SYM.slice(cut)} done\n`);
  assert.equal(out2, `${RAW} done\n`);
});

test("a COMPLETE token at a line end is never delayed by the pull-back", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  assert.equal(await f.write(`Summary: ${SYM}\n`), `Summary: ${RAW}\n`);
  assert.equal(f.pending, 0);
});

test("an UNKNOWN wrapped token passes through byte-identical (insertions intact)", async () => {
  const r = new MockResolver({}); // knows nothing
  const f = new ReplyStreamFilter(r);
  const wrapped = "ghost $MDU:ex\r\n  ec[ffff] end\n";
  const out = (await f.write(wrapped)) + (await f.flush());
  assert.equal(out, wrapped);
});

test("mixed span: a contiguous and a wrapped token both resolve in one pass", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  const wrapped = `${SYM.slice(0, 12)}\n  ${SYM.slice(12)}`;
  const out = (await f.write(`x ${SYM} y ${wrapped} z\n`)) + (await f.flush());
  assert.equal(out, `x ${RAW} y ${RAW} z\n`);
});

test("Markdown-ESCAPED token split by a wrap still resolves", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  const escaped = "\\$MDU:Read[9b0a]";
  const wrapped = `${escaped.slice(0, 10)}\r\n  ${escaped.slice(10)}`;
  const out = (await f.write(`see ${wrapped} now\n`)) + (await f.flush());
  assert.equal(out, `see ${RAW} now\n`);
});

test("prose with $ around newlines is NOT glued into a candidate (resolver untouched)", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r);
  const text = "price $5\nmore text\nand $HOME too\n";
  const out = (await f.write(text)) + (await f.flush());
  assert.equal(out, text);
  assert.deepEqual(r.calls, []);
});

test("couldBeSymbolPrefix looks through insertions", () => {
  assert.equal(couldBeSymbolPrefix("$MDU:\r\n  Read"), true);
  assert.equal(couldBeSymbolPrefix("$MDU:Re\x1b[0mad"), true);
  assert.equal(couldBeSymbolPrefix("$5.00\r\n"), false);
});

// ── observability seam ────────────────────────────────────────────────────────

test("onResolve fires exactly when resolution changed a span, with before/after", async () => {
  const r = new MockResolver();
  const seen: Array<[string, string]> = [];
  const f = new ReplyStreamFilter(r, {
    onResolve: (before, after) => {
      seen.push([before, after]);
    },
  });
  await f.write("plain line\n"); // fast path → no callback
  await f.write(`ghost $MDU:exec[ffff]\n`); // unknown → unchanged → no callback
  await f.write(`real ${SYM}\n`); // resolved → callback
  assert.equal(seen.length, 1);
  assert.equal(seen[0]![0], `real ${SYM}\n`);
  assert.equal(seen[0]![1], `real ${RAW}\n`);
});

test("an onResolve failure never disturbs the output stream", async () => {
  const r = new MockResolver();
  const f = new ReplyStreamFilter(r, {
    onResolve: () => {
      throw new Error("emit exploded");
    },
  });
  const out = (await f.write(`x ${SYM}\n`)) + (await f.flush());
  assert.equal(out, `x ${RAW}\n`);
});

// ── line-end glue fallback (release checklist a3, 2026-09-26) ────────────────
// A token that ENDS a line glues to the next line's first word in the cleaned
// view (`\n` is also a wrap insertion). The arbiter resolves only allocated
// names, so the glued name used to stay raw: `.env` values (quote-terminated)
// resolved while `~/.aws/credentials` (INI, line-final) and an env-masked
// `GITHUB_TOKEN` (line-final, another line after it) stayed `$MDU:` tokens.
// ExactResolver behaves like the arbiter (exact names only); the substring
// MockResolver above would "resolve" a glued name and hide the bug.

const ENV_SYM = "$MDU:nomodel_Read[4274].API_KEY";
const AWS_ID = "$MDU:nomodel_Read[8a7e].default.aws_access_key_id";
const AWS_KEY = "$MDU:nomodel_Read[8a7e].default.aws_secret_access_key";
const GH = "$MDU:nomodel_Env[0925].GITHUB_TOKEN";
const SECRETS: Record<string, string> = {
  [ENV_SYM]: "sk-test-abcdef1234567890",
  [AWS_ID]: "AKIAIOSFODNN7EXAMPLE",
  [AWS_KEY]: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  [GH]: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
};

class ExactResolver implements ReplyResolver {
  calls: string[] = [];
  constructor(private readonly table: Record<string, string>) {}
  async desymbolize(text: string): Promise<string> {
    this.calls.push(text);
    return text.replace(
      /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]*)*/g,
      (tok) => this.table[tok] ?? tok,
    );
  }
}

/** What `cat .env; cat ~/.aws/credentials; echo "GH=$GITHUB_TOKEN"; echo done`
 *  prints inside the agent's world (twins + env mask), and what the human
 *  must see: every secret source rendered the same way, as its original. */
const AGENT_SIDE =
  `API_KEY='${ENV_SYM}'\n[default]\naws_access_key_id = ${AWS_ID}\n` +
  `aws_secret_access_key = ${AWS_KEY}\nGH=${GH}\ndone\n`;
const HUMAN_SIDE =
  `API_KEY='${SECRETS[ENV_SYM]}'\n[default]\naws_access_key_id = ${SECRETS[AWS_ID]}\n` +
  `aws_secret_access_key = ${SECRETS[AWS_KEY]}\nGH=${SECRETS[GH]}\ndone\n`;

test("line-end glue: .env, ~/.aws/credentials and an env-masked var all resolve alike (pipe mode, one chunk)", async () => {
  const out = await run(new ReplyStreamFilter(new ExactResolver(SECRETS)), [AGENT_SIDE]);
  assert.equal(out, HUMAN_SIDE);
});

test("line-end glue: the same output resolves alike in EAGER (PTY) mode and line-by-line chunking", async () => {
  const lines = AGENT_SIDE.split(/(?<=\n)/);
  assert.equal(await run(new ReplyStreamFilter(new ExactResolver(SECRETS)), lines), HUMAN_SIDE);
  // EAGER renders frame-safely: a shorter value is space-padded to the
  // token's width, a longer one is bracketed in ESC[?7l…?7h. Strip exactly
  // that framing; the text underneath must be the pipe-mode result.
  const unframe = (s: string) => s.replace(/\x1b\[\?7[lh]/g, "").replace(/ +(?=['\n])/g, "");
  for (const chunks of [[AGENT_SIDE], lines]) {
    const out = await run(new ReplyStreamFilter(new ExactResolver(SECRETS), { eager: true }), chunks);
    assert.ok(!out.includes("$MDU:"), out);
    assert.equal(unframe(out), HUMAN_SIDE);
  }
});

test("line-end glue: the next line's word, the CRLF and the indent survive verbatim", async () => {
  const f = new ReplyStreamFilter(new ExactResolver(SECRETS));
  const out = (await f.write(`token: ${GH}\r\n  next_word here\n`)) + (await f.flush());
  assert.equal(out, `token: ${SECRETS[GH]}\r\n  next_word here\n`);
});

test("line-end glue: the FULL reassembly wins over a shorter prefix (a genuinely wrapped token)", async () => {
  // Both `.a` and `.ab` exist: a TUI wrapping `.ab` as `.a` / `b` must still
  // resolve `.ab`. The fallback only runs when the full token is unknown.
  const table = { "$MDU:x[abcd].a": "SHORT", "$MDU:x[abcd].ab": "LONG" };
  const f = new ReplyStreamFilter(new ExactResolver(table));
  const out = (await f.write("v=$MDU:x[abcd].a\r\n  b end\n")) + (await f.flush());
  assert.equal(out, "v=LONG end\n");
});

test("line-end glue: an unknown token with no resolvable prefix stays byte-identical", async () => {
  const f = new ReplyStreamFilter(new ExactResolver(SECRETS));
  const text = "ghost $MDU:nomodel_Env[ffff].NOPE\nnext line\n";
  const out = (await f.write(text)) + (await f.flush());
  assert.equal(out, text);
});

test("line-end glue: an arbiter failure during the prefix retry passes the text through unchanged", async () => {
  let n = 0;
  const flaky: ReplyResolver = {
    async desymbolize(t: string) {
      n += 1;
      if (n > 1) throw new Error("arbiter down"); // full lookup answers, the retry fails
      return t;
    },
  };
  const f = new ReplyStreamFilter(flaky);
  const text = `GH=${GH}\ndone\n`;
  const out = (await f.write(text)) + (await f.flush());
  assert.equal(out, text);
});

// ── reserve blocks: the stream splice (reply-row-reservation.md §3.7) ─────────
// The proxy sends Claude Code an N-row reserve block in place of a multi-line
// token alone on its line; the stream splice paints line i of the value into
// the i-th row wherever a marker is CONTIGUOUS on the wire (the first paint,
// phase 0 §7.1). Fixtures: test/unit/reserve-fixtures.ts.

/** Rows 2..6 (0-based) of a rendered screen: where the fixtures paint the block. */
const blockRows = (rows: string[], top = 2) => rows.slice(top, top + 5);
const wantRows = (indent = "  ") => [1, 2, 3, 4, 5].map((i) => indent + shown(i, indent.length));

test("RESERVE: inline first paint — every reserved row shows its line (pad, clip, indent, TAB)", async () => {
  const r = new MockResolver({ [BT]: BV });
  const f = new ReplyStreamFilter(r, { eager: true, cols: 80 });
  const out = await run(f, [INLINE_FIRST_PAINT]);
  assert.deepEqual(blockRows(await renderScreen(out)), wantRows());
  assert.ok(!out.includes("$MDU"), "no marker and no token reaches the human's terminal");
  assert.ok(!out.includes("⏎"), "a reserved row never renders the one-row ⏎ form");
  assert.ok(!out.includes("\t"), "a TAB is never spliced raw");
  // The longer lines are wrap-off bracketed; the shorter ones are padded.
  assert.ok(out.includes(`\x1b[?7l${BLINES[1]}\x1b[?7h`), "line 2 clips at the edge instead of wrapping");
  assert.ok(out.includes(`${BLINES[2]} `), "line 3 is padded to its marker's width");
  assert.deepEqual(r.calls, [BT], "one resolution for the whole block");
});

test("RESERVE: fullscreen first paint and a fenced block paint the same rows", async () => {
  for (const [name, bytes] of [["fullscreen", FULLSCREEN_FIRST_PAINT], ["fenced", FENCED_FIRST_PAINT]] as const) {
    const f = new ReplyStreamFilter(new MockResolver({ [BT]: BV }), { eager: true, cols: 80 });
    const out = await run(f, [bytes]);
    assert.deepEqual(blockRows(await renderScreen(out)), wantRows(), name);
    assert.ok(!out.includes("$MDU"), name);
  }
});

test("RESERVE: a head is ONE unit — never a resolved token beside a stray `/1:N`", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: BV }), { eager: true, cols: 80 });
  const out = await run(f, [`\r  ${BT}/1:5\x1b[K`]);
  assert.ok(!out.includes("/1:5"), out);
  assert.ok(!out.includes("⏎"), "the token is not rendered as the whole one-row value");
  assert.equal((await renderScreen(out))[0], "  Host a");
});

test("RESERVE: a Markdown-escaped head is recognized and spliced like the canonical one", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: BV }), { eager: true, cols: 80 });
  const out = await run(f, ["\r  \\$MDU:nomodel\\_Bash[464e]/1:5\x1b[K\r\n  $MDU/464e/2"]);
  const rows = await renderScreen(out);
  assert.equal(rows[0], "  Host a");
  assert.equal(rows[1], `  ${BLINES[1]}`);
});

test("RESERVE: arbiter DOWN — the head keeps its token with `(N lines)`, continuation rows go blank", async () => {
  const r = new MockResolver({ [BT]: BV });
  r.fail = true;
  const f = new ReplyStreamFilter(r, { eager: true, cols: 80 });
  const out = await run(f, [INLINE_FIRST_PAINT]);
  const rows = blockRows(await renderScreen(out));
  assert.deepEqual(rows, [`  ${BT} (5 lines)`, "", "", "", ""]);
  assert.ok(!out.includes("$MDU/"), "no continuation marker is left on screen");
  // An UNKNOWN token (the arbiter answers, but not with a value) renders alike.
  const unknown = await run(new ReplyStreamFilter(new MockResolver({}), { eager: true, cols: 80 }), [INLINE_FIRST_PAINT]);
  assert.deepEqual(blockRows(await renderScreen(unknown)), rows);
});

test("RESERVE: a continuation whose hash no head announced is painted blank (it carries nothing)", async () => {
  const r = new MockResolver({});
  const f = new ReplyStreamFilter(r, { eager: true, cols: 80 });
  const out = await run(f, ["\rabc $MDU/beef/3 xyz"]);
  assert.equal((await renderScreen(out))[0], "abc             xyz");
  assert.deepEqual(r.calls, [], "a continuation never asks the arbiter");
});

test("RESERVE: the cap row — a value longer than N shows `… +K more lines` in row N", async () => {
  const seven = "l1\nl2\nl3\nl4\nl5\nl6\nl7\n";
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: seven }), { eager: true, cols: 80 });
  const block = formatBlock(BT, 7, 4).split("\n").map((row) => `\r\n  ${row}`).join("");
  const rows = await renderScreen(await run(f, [block]));
  assert.deepEqual(rows.slice(1, 5), ["  l1", "  l2", "  l3", `  ${moreLinesNote(4)}`]);
});

test("RESERVE: a shorter line pads to its marker's width — the old marker's ghost tail is blanked", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: "first\nok\n" }), { eager: true, cols: 80 });
  // The row already holds the marker from an earlier paint (no EL follows).
  const out = await run(f, [`\r  ${BT}/1:2\r\n  $MDU/464e/2`]);
  const rows = await renderScreen(`\r\n  $MDU/464e/2\x1b[H` + out);
  assert.equal(rows[1], "  ok", "no `/464e/2` tail survives beside the short line");
  assert.ok(out.includes("ok" + " ".repeat("$MDU/464e/2".length - 2)));
});

test("RESERVE: a longer line clips with ?7l/?7h and the TUI's erase lands after it (column translation)", async () => {
  const long = "x".repeat(60);
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: `h\n${long}\n` }), { eager: true, cols: 40 });
  // The TUI erases the row's tail from the marker's end: CHA + EL.
  const out = await run(f, [`\r  ${BT}/1:2\x1b[K\r\n  $MDU/464e/2\x1b[14G\x1b[K\r\nnext`]);
  // Only the 38 columns the row has left go out (CLIP PAST THE EDGE).
  assert.ok(out.includes(`\x1b[?7l${long.slice(0, 38)}\x1b[?7h`), JSON.stringify(out));
  const rows = await renderScreen(out, 40, 4);
  assert.equal(rows[1], `  ${long}`.slice(0, 40), "clipped at the edge, not erased by the TUI's EL");
  assert.equal(rows[2], "next", "no wrap onto the next row");
});

test("RESERVE: the value cache — a repainted head never asks again; continuations never ask", async () => {
  const r = new MockResolver({ [BT]: BV });
  const f = new ReplyStreamFilter(r, { eager: true, cols: 80 });
  await run(f, [INLINE_FIRST_PAINT]);
  await run(f, [INLINE_FIRST_PAINT]);
  assert.deepEqual(r.calls, [BT], "one round-trip per head value per session");
  // A shared cache (the screen reconciler's) serves a fresh filter too.
  const cache = new ReserveValueCache();
  const a = new ReplyStreamFilter(r, { eager: true, reserveCache: cache });
  await run(a, [`\r${BT}/1:5\r\n`]);
  const b = new ReplyStreamFilter(new MockResolver({}), { eager: true, cols: 80, reserveCache: cache });
  const rows = await renderScreen(await run(b, ["\r$MDU/464e/3"]));
  assert.equal(rows[0], "  User git");
});

test("RESERVE: observability — ONE onResolve per head, with the whole value; none per row", async () => {
  const seen: Array<[string, string]> = [];
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: BV }), {
    eager: true,
    cols: 80,
    onResolve: (b, a) => { seen.push([b, a]); },
  });
  await run(f, [INLINE_FIRST_PAINT]);
  await run(f, [INLINE_FIRST_PAINT]); // a repaint of the same block
  assert.deepEqual(seen, [[BT, BV]]);
});

test("RESERVE: a head split at a chunk edge (`T` | `/1:5`, `T/` | …, `T/1:` | `5`) is held, never half-resolved", async () => {
  const whole = `\r  ${BT}/1:5\x1b[K\r\n  $MDU/464e/2\x1b[K`;
  for (const cut of [`\r  ${BT}`.length, `\r  ${BT}/`.length, `\r  ${BT}/1:`.length]) {
    const g = new ReplyStreamFilter(new MockResolver({ [BT]: BV }), { eager: true, cols: 80 });
    const first = await g.write(whole.slice(0, cut));
    assert.ok(!first.includes("Host") && !first.includes("$MDU"), `held at cut ${cut}: ${JSON.stringify(first)}`);
    const out = first + (await g.write(whole.slice(cut))) + (await g.flush());
    const rows = await renderScreen(out);
    assert.deepEqual(rows.slice(0, 2), ["  Host a", `  ${BLINES[1]}`], `cut ${cut}`);
  }
  // A complete head ending a quiet stream resolves on the FIRST idle drain.
  const f = new ReplyStreamFilter(new MockResolver({ [BT]: BV }), { eager: true, cols: 80 });
  assert.equal(await f.write(`\r${BT}/1:5`), "\r");
  const drained = await f.flush(false);
  assert.ok(drained.includes("Host a"), JSON.stringify(drained));
});

test("RESERVE, PIPE mode: a block (never expected there) collapses to the FULL value", async () => {
  const text = `Here it is:\n\n${formatBlock(BT, 5)}\n\nDone.\n`;
  const want = `Here it is:\n\n${BV}\nDone.\n`;
  assert.equal(await run(new ReplyStreamFilter(new MockResolver({ [BT]: BV })), [text]), want);
  // Line by line (a continuation arriving in a later write than its head).
  const lines = text.split(/(?<=\n)/);
  assert.equal(await run(new ReplyStreamFilter(new MockResolver({ [BT]: BV })), lines), want);
  // A capped block still prints the whole value.
  const long = Array.from({ length: 50 }, (_, i) => `row ${i + 1}`).join("\n") + "\n";
  const capped = await run(new ReplyStreamFilter(new MockResolver({ [BT]: long })), [`${formatBlock(BT, 50)}\n`]);
  assert.equal(capped, long);
  // Arbiter down: the token and its line count, no marker rows.
  const r = new MockResolver({ [BT]: BV });
  r.fail = true;
  assert.equal(await run(new ReplyStreamFilter(r), [text]), `Here it is:\n\n${BT} (5 lines)\n\nDone.\n`);
});

test("RESERVE, PIPE mode: literal `$MDU/<hex>/<n>` text with no announcing head stays byte-identical", async () => {
  const text = "see $MDU/beef/3 in the transcript\n";
  assert.equal(await run(new ReplyStreamFilter(new MockResolver({})), [text]), text);
});

// ── v2 blocks: wrapped rows and a block inside a line (reply-row-reservation.md §11) ──

const V2_TABLE = { [KT]: KV, [MT]: MV };

test("RESERVE v2: a one-line value wider than the terminal fills its reserved rows (78 + 42), no clip", async () => {
  const f = new ReplyStreamFilter(new MockResolver(V2_TABLE), { eager: true, cols: 80 });
  const out = await run(f, [KEY_FIRST_PAINT]);
  const rows = await renderScreen(out);
  assert.deepEqual(rows.slice(1, 5), ["  Your key:", `  ${KV.slice(0, 78)}`, `  ${KV.slice(78)}`, "  key done"]);
  assert.ok(!out.includes("$MDU") && !out.includes("/1:2:78:78"), "no marker, no head suffix on the wire");
});

test("RESERVE v2: a head AFTER prefix text paints row 1 after the prefix; the last row's SUFFIX follows its text", async () => {
  const f = new ReplyStreamFilter(new MockResolver(V2_TABLE), { eager: true, cols: 80 });
  const out = await run(f, [MID_FIRST_PAINT]);
  const rows = await renderScreen(out);
  assert.equal(rows[1], "  PROBE para");
  assert.deepEqual(rows.slice(2, 5), MID_SCREEN, `screen was:\n${rows.join("\n")}`);
  assert.ok(!out.includes("$MDU"));
});

test("RESERVE v2: a head split at a chunk edge inside `/1:N:W:F` is held, never half-resolved", async () => {
  const whole = `\r  ${MID_PREFIX}${MID_HEAD}\x1b[K`;
  for (const part of ["/1:3", "/1:3:", "/1:3:78", "/1:3:78:", "/1:3:78:6"]) {
    const cut = `\r  ${MID_PREFIX}${MT}${part}`.length;
    const g = new ReplyStreamFilter(new MockResolver(V2_TABLE), { eager: true, cols: 80 });
    const first = await g.write(whole.slice(0, cut));
    assert.ok(!first.includes("secret") && !first.includes("$MDU"), `held at ${part}: ${JSON.stringify(first)}`);
    const out = first + (await g.write(whole.slice(cut))) + (await g.flush());
    assert.equal((await renderScreen(out))[0], MID_SCREEN[0], part);
  }
});

test("RESERVE v2: the suffix after a long last row CLIPS at the right edge, never wraps onto the next row", async () => {
  // 22 words: rows of 7 / 8 / 7 words; the last row is 62 columns, so
  // `  ` + 62 + the 17-column suffix is one column too wide.
  const value = Array.from({ length: 22 }, (_, i) => `secret${String(i + 1).padStart(2, "0")}`).join(" ");
  const f = new ReplyStreamFilter(new MockResolver({ [MT]: value }), { eager: true, cols: 80 });
  const head = `${MT}/1:3:78:${MID_F}`;
  const out = await run(f, [
    `\r  ${MID_PREFIX}${head}\x1b[K\r\n  $MDU/5e2a/2\x1b[K\r\n  $MDU/5e2a/3${MID_SUFFIX}\x1b[K\r\n  next`,
  ]);
  const rows = await renderScreen(out, 80, 6);
  const last = `  ${"secret16 secret17 secret18 secret19 secret20 secret21 secret22"}`;
  assert.equal(rows[2]!.length, 80, rows[2]);
  assert.ok(rows[2]!.startsWith(last + " and that is al"), rows[2]);
  assert.equal(rows[3], "  next", "the suffix never wraps onto the row below");
  // The wrap-off bracket closes before the row is left.
  assert.ok(/\x1b\[\?7h\r\n {2}next$/.test(out), JSON.stringify(out.slice(-40)));
});

test("RESERVE v2: a shorter last row pads to its marker, and the suffix lands where the TUI put it", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [MT]: "alpha beta\nz" }), { eager: true, cols: 80 });
  const out = await run(f, [`\r  x ${MT}/1:2:78:76\x1b[K\r\n  $MDU/5e2a/2 done.\x1b[K`]);
  const rows = await renderScreen(out);
  assert.equal(rows[0], "  x alpha beta");
  assert.equal(rows[1], `  z${" ".repeat("$MDU/5e2a/2".length - 1)} done.`, "ghost-tail rule: the marker's cells go blank");
});

test("RESERVE v2: F = 0 — the head row keeps its prefix and paints no value; the value starts on row 2", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [MT]: "one\ntwo\n" }), { eager: true, cols: 80 });
  const out = await run(f, [`\r  - a long list item prefix: ${MT}/1:3:78:0\x1b[K\r\n    $MDU/5e2a/2\r\n    $MDU/5e2a/3`]);
  const rows = await renderScreen(out);
  assert.deepEqual(rows.slice(0, 3), ["  - a long list item prefix:", "    one", "    two"]);
});

test("RESERVE v2: the cap row carries `… +K more lines`, K counted over laid-out rows", async () => {
  const value = "x".repeat(50) + "\nl2\nl3\nl4\n"; // 6 rows at W = 20
  const f = new ReplyStreamFilter(new MockResolver({ [MT]: value }), { eager: true, cols: 80 });
  const out = await run(f, [`\r  ${MT}/1:4:20:20\r\n  $MDU/5e2a/2\r\n  $MDU/5e2a/3\r\n  $MDU/5e2a/4`]);
  const rows = await renderScreen(out);
  assert.deepEqual(rows.slice(0, 4), ["  " + "x".repeat(20), "  " + "x".repeat(20), "  " + "x".repeat(10), `  ${moreLinesNote(3)}`]);
});

test("RESERVE v2: an out-of-range v2 suffix is not a head — the token resolves alone, never as v1 `/1:N`", async () => {
  const f = new ReplyStreamFilter(new MockResolver({ [MT]: "v" }), { eager: true, cols: 80 });
  const out = await run(f, [`\r${MT}/1:3:78:10 `]);
  assert.equal((await renderScreen(out))[0], `v${" ".repeat(MT.length - 1)}/1:3:78:10`);
});

test("RESERVE v2, PIPE mode: a block inside a line collapses to the sentence as the model wrote it", async () => {
  const block = `${MID_PREFIX}${MID_HEAD}\n$MDU/5e2a/2\n$MDU/5e2a/3${MID_SUFFIX}\n`;
  const want = `${MID_PREFIX}${MV}${MID_SUFFIX}\n`;
  assert.equal(await run(new ReplyStreamFilter(new MockResolver(V2_TABLE)), [block]), want);
  // One line per write (a continuation arriving after its head).
  const lines = block.split(/(?<=\n)/);
  assert.equal(await run(new ReplyStreamFilter(new MockResolver(V2_TABLE)), lines), want);
  // Split mid-line too, and with CRLF line breaks.
  const crlf = block.replace(/\n/g, "\r\n");
  const cuts = [crlf.slice(0, 20), crlf.slice(20, 70), crlf.slice(70, 95), crlf.slice(95)];
  assert.equal(await run(new ReplyStreamFilter(new MockResolver(V2_TABLE)), cuts), want.replace(/\n$/, "\r\n"));
  // Every chunk size, down to one byte a write: the held line break before a
  // row survives the writes that bring that row in (a hold lost after one
  // write emitted it, and the human saw an extra blank line).
  for (let size = 1; size <= 12; size++) {
    const parts: string[] = [];
    for (let i = 0; i < block.length; i += size) parts.push(block.slice(i, i + size));
    assert.equal(await run(new ReplyStreamFilter(new MockResolver(V2_TABLE)), parts), want, `chunk size ${size}`);
  }
  // A v2 head alone on its line: the value, then the text after the block.
  const alone = `Key:\n${formatBlockV2(KT, KV, 78, 78)}\nDone.\n`;
  assert.equal(await run(new ReplyStreamFilter(new MockResolver(V2_TABLE)), [alone]), `Key:\n${KV}\nDone.\n`);
  // Arbiter down: `T (N lines)` and the suffix, no marker rows.
  const r = new MockResolver(V2_TABLE);
  r.fail = true;
  assert.equal(await run(new ReplyStreamFilter(r), [block]), `${MID_PREFIX}${MT} (3 lines)${MID_SUFFIX}\n`);
});

test("RESERVE §13: the TUI reprints a v2 block after the terminal narrowed — the filter re-lays the value out at the new width", async () => {
  const long = `DIFFWRAP_LONG ${Array.from({ length: 14 }, (_, i) => `SEGW${String(i + 1).padStart(2, "0")}`).join(" ")}`;
  const value = `DIFFWRAP_A short\n${long}\nDIFFWRAP_C end\n`;
  const paint = `\r  ${BT}/1:4:78:78\x1b[K\r\n  $MDU/464e/2\x1b[K\r\n  $MDU/464e/3\x1b[K\r\n  $MDU/464e/4\x1b[K`;
  let cols = 80;
  const r = new MockResolver({ [BT]: value });
  const f = new ReplyStreamFilter(r, { eager: true, cols: () => cols });
  const first = await run(f, [paint]);
  const at80 = layoutRows(value, 78, 78).map((x) => `  ${x.text}`.trimEnd());
  assert.deepEqual((await renderScreen(first, 80)).slice(0, 4), at80);
  // SIGWINCH: the TUI clears and reprints its transcript at 60 columns.
  cols = 60;
  const again = await run(f, [`\x1b[2J\x1b[H${paint}`]);
  const at60 = layoutRows(value, 58, 58).map((x) => `  ${x.text}`.trimEnd());
  assert.notDeepEqual(at60, at80, "precondition: the layout differs");
  assert.deepEqual((await renderScreen(again, 60)).slice(0, 4), at60);
  // Wider again: the block keeps its first layout (its rows fit).
  cols = 120;
  const wider = await run(f, [`\x1b[2J\x1b[H${paint}`]);
  assert.deepEqual((await renderScreen(wider, 120)).slice(0, 4), at80);
});

test("RESERVE §14: a head with a break field `:K` paints like its plain v2 head; `:K` never reaches the screen, even split at a chunk edge", async () => {
  const withK = MID_FIRST_PAINT.replace(MID_HEAD, `${MID_HEAD}:7`);
  assert.notEqual(withK, MID_FIRST_PAINT);
  const out = await run(new ReplyStreamFilter(new MockResolver(V2_TABLE), { eager: true, cols: 80 }), [withK]);
  assert.deepEqual((await renderScreen(out)).slice(2, 5), MID_SCREEN);
  assert.ok(!out.includes(":7"), "the break field is part of the head");
  const at = withK.indexOf(`${MID_HEAD}:7`) + MID_HEAD.length;
  for (const cut of [at, at + 1, at + 2]) {
    const g = new ReplyStreamFilter(new MockResolver(V2_TABLE), { eager: true, cols: 80 });
    const o = await run(g, [withK.slice(0, cut), withK.slice(cut)]);
    assert.deepEqual((await renderScreen(o)).slice(2, 5), MID_SCREEN, `cut @${cut - at}`);
  }
});

test("RESERVE §14: a head-only block paints the value in its row; the text after it, broken by the proxy, follows", async () => {
  const v = "Q".repeat(40);
  const head = `${BT}/1:1:78:65:5`;
  const paint = `\r  The value is ${head} and \x1b[K\r\n  that is all.\x1b[K`;
  const out = await run(new ReplyStreamFilter(new MockResolver({ [BT]: v }), { eager: true, cols: 80 }), [paint]);
  const rows = await renderScreen(out);
  assert.deepEqual(rows.slice(0, 2), [`  The value is ${v} and`, "  that is all."]);
  assert.ok(!out.includes("/1:1") && !out.includes("$MDU"));
});

// ── Goose 1.53 (docs/testing/differential-interactive.md §32) ────────────────

test("GOOSE §32: setRowGeometry — a token split by SGR alone is one row (its SGR kept); a line break or an EL splits it", () => {
  const sgrSplit = "\x1b[37m$MDU:nomodel\x1b[0m\x1b[35m_shell[9062]";
  const a = { os: 5, oe: sgrSplit.length, cs: 0, ce: GOOSE_HEAD_TOKEN.length, split: true, inRow: false, sgr: "x" };
  setRowGeometry(a, sgrSplit);
  assert.deepEqual([a.inRow, a.sgr], [true, "\x1b[0m\x1b[35m"]);
  const wrapSplit = "$MDU:nomodel\r\n  _shell[9062]";
  const b = { os: 0, oe: wrapSplit.length, cs: 0, ce: GOOSE_HEAD_TOKEN.length, split: true, inRow: true, sgr: "x" };
  setRowGeometry(b, wrapSplit);
  assert.deepEqual([b.inRow, b.sgr], [false, ""]);
  const elSplit = "$MDU:nomodel\x1b[K_shell[9062]";
  const c = { os: 0, oe: elSplit.length, cs: 0, ce: GOOSE_HEAD_TOKEN.length, split: true, inRow: true, sgr: "x" };
  setRowGeometry(c, elSplit);
  assert.equal(c.inRow, false, "an EL is not styling: the token keeps the split path");
  const whole = { os: 0, oe: GOOSE_HEAD_TOKEN.length, cs: 0, ce: GOOSE_HEAD_TOKEN.length, split: false, inRow: false, sgr: "x" };
  setRowGeometry(whole, GOOSE_HEAD_TOKEN);
  assert.deepEqual([whole.inRow, whole.sgr], [true, ""]);
});

test("GOOSE §32: a reserve head its Markdown streamer restyled at the `_` paints as a block — no `/1:N:W:F` on screen, no extra row", async () => {
  // Before the fix the SGR inside the token made it a wrap-SPLIT span: T
  // resolved as a plain token (one ⏎ row, clipped) and `/1:5:78:78` stayed,
  // wrapping onto a row the TUI never counted; the rows below were blank.
  for (const reads of [GOOSE_REPLY_READS, [GOOSE_REPLY_READS.join("")]]) {
    const f = new ReplyStreamFilter(new MockResolver({ [GOOSE_HEAD_TOKEN]: GOOSE_ROWS_VALUE }), { eager: true, cols: 80 });
    const out = await run(f, [...reads]);
    assert.ok(!out.includes("/1:5") && !out.includes("$MDU"), JSON.stringify(out));
    assert.deepEqual((await renderScreen(out, 80, 10)).slice(0, GOOSE_REPLY_SCREEN.length + 1), [...GOOSE_REPLY_SCREEN, ""]);
    // The styling Goose set inside the token follows the value: the pen ends
    // as the TUI left it.
    assert.match(out, /DIFFROW_ALPHA one *\x1b\[0m\x1b\[35m\x1b\[0m\x1b\[35m\x1b\[0m\r\n/);
  }
});

test("GOOSE §32: the live tool row's pad after a widened token stays on its row — no ghost spinner row", async () => {
  // Goose pads its live row to the width after the token; the value is far
  // wider, so before the fix the pad (written after `ESC[?7h`) wrapped onto
  // a new row, the next frame's `CR EL` cleared only that one, and every
  // spinner frame stayed on the screen as its own row.
  // Goose runs under the terminal wrap rule (§17), as the launcher sets it.
  const f = new ReplyStreamFilter(new MockResolver({ [GOOSE_LIVE_TOKEN]: GOOSE_ROWS_VALUE }), {
    eager: true, cols: 80, reserveCache: new ReserveValueCache(undefined, "terminal"),
  });
  const out = await run(f, [...GOOSE_LIVE_READS]);
  const row = `    ${frameSafeValue(GOOSE_ROWS_VALUE)}`;
  // wrap off: the row clips, its last cell holding the value's last glyph
  const clipped = row.length > 80 ? row.slice(0, 79) + row.slice(-1) : row;
  assert.deepEqual(await renderScreen(out, 80, 4), [clipped, "", "", ""]);
  assert.ok(!out.includes("$MDU"));
});

test("GOOSE §32: a pad that fits the row, or a row of unknown width, keeps the bracket closed right after the value (bytes as before)", async () => {
  const value = "x".repeat(GOOSE_LIVE_TOKEN.length + 5);
  const f = new ReplyStreamFilter(new MockResolver({ [GOOSE_LIVE_TOKEN]: value }), { eager: true, cols: 80 });
  const out = await run(f, [`\r\x1b[2K${GOOSE_LIVE_TOKEN}\x1b[0m${" ".repeat(10)}\r\n`]);
  assert.ok(out.includes(`\x1b[?7l${value}\x1b[?7h\x1b[0m${" ".repeat(10)}\r\n`), JSON.stringify(out));
  const g = new ReplyStreamFilter(new MockResolver({ [GOOSE_LIVE_TOKEN]: value }), { eager: true });
  const out2 = await run(g, [`\r\x1b[2K${GOOSE_LIVE_TOKEN}\x1b[0m${" ".repeat(70)}\r\n`]);
  assert.ok(out2.includes(`\x1b[?7l${value}\x1b[?7h\x1b[0m${" ".repeat(70)}\r\n`), JSON.stringify(out2));
});

// ── §17: the terminal wrap rule (reply-row-reservation.md §17) ───────────────
// Goose prints the model's text raw at column 0; vanilla's screen is that
// text with the value in place of the token, wrapped by the terminal. The
// block below is what the proxy sends under the rule, printed as Goose
// prints it (CRLF line ends); the filter paints it with a terminal-rule cache.

const G_TOKEN = "$MDU:nomodel_shell[5d1e]";
const G_HASH = "5d1e";
const segs = (p: string, n: number) => Array.from({ length: n }, (_, i) => `${p}${String(i + 1).padStart(2, "0")}`).join(" ");
const G_WRAP_VALUE = `DIFFWRAP_A short\nDIFFWRAP_LONG ${segs("SEGW", 14)}\nDIFFWRAP_C end\n`;
const G_INLINE_VALUE = `DIFFINLINE ${segs("SEGI", 12)}`;
const gooseFilter = (values: Record<string, string>, rule: "ink" | "terminal" = "terminal") =>
  new ReplyStreamFilter(new MockResolver(values), { eager: true, cols: 80, reserveCache: new ReserveValueCache(undefined, rule) });
/** Goose's printing of the model's text: raw, LF as CRLF. */
const goosePrint = (text: string) => text.replace(/\n/g, "\r\n");

test("§17 GOOSE: a standalone terminal-rule block paints vanilla Goose's screen — the long line broken mid-word at column 80", async () => {
  const block = formatBlockV2(G_TOKEN, G_WRAP_VALUE, 80, 80, 40, "terminal");
  assert.equal(block.split("\n").length, 4);
  const out = await run(gooseFilter({ [G_TOKEN]: G_WRAP_VALUE }), [goosePrint(`File content follows:\n${block}\nDIFF_S1_DONE\n`)]);
  const vanilla = await renderScreen(goosePrint(`File content follows:\n${G_WRAP_VALUE}DIFF_S1_DONE\n`), 80, 8);
  const screen = await renderScreen(out, 80, 8);
  assert.deepEqual(screen, vanilla);
  assert.equal(screen[2], `DIFFWRAP_LONG ${segs("SEGW", 9)} SEG`);
  assert.ok(!out.includes("$MDU"));
});

test("§17 GOOSE: a mid-line block with the proxy's exact break paints vanilla's screen, the sentence wrapped mid-word", async () => {
  const suffix = " and that is all, so the rest of this sentence wraps onto the next row.";
  const F = 80 - "The value is ".length;
  const rows = layoutRows(G_INLINE_VALUE, 80, F, "terminal");
  const k = 80 - rows[rows.length - 1]!.text.length;
  const head = `${G_TOKEN}/1:${rows.length}:80:${F}:${k}`;
  const wire = `The value is ${head}\n$MDU/${G_HASH}/2${suffix.slice(0, k)}\n${suffix.slice(k)}\nDONE\n`;
  const out = await run(gooseFilter({ [G_TOKEN]: G_INLINE_VALUE }), [goosePrint(wire)]);
  const vanilla = await renderScreen(goosePrint(`The value is ${G_INLINE_VALUE}${suffix}\nDONE\n`), 80, 6);
  assert.deepEqual(await renderScreen(out, 80, 6), vanilla);
});

test("§17 GOOSE: the same block painted by Ink's rule breaks a word early — the divergence the rule closes", async () => {
  const block = formatBlockV2(G_TOKEN, G_WRAP_VALUE, 80, 80, 40, "terminal");
  const out = await run(gooseFilter({ [G_TOKEN]: G_WRAP_VALUE }, "ink"), [goosePrint(`File content follows:\n${block}\nDIFF_S1_DONE\n`)]);
  const screen = await renderScreen(out, 80, 8);
  assert.equal(screen[2], `DIFFWRAP_LONG ${segs("SEGW", 9)}`);
  assert.equal(screen[3], segs("SEGW", 14).slice("SEGW01 ".length * 9));
});

// The `desymbolize` event's AgentView form (run.ts desymbolizeEvent): the
// placeholders a reply named, never the text around them. A terminal write
// or a json-mode record can carry text the model never saw (a tool's output
// as the agent process got it, the human's prompt before the prompt filter);
// the dashboard's signed-out projection keeps every `symbolized` (§6).
test("placeholderNames: the names a text holds, unescaped, each once, in order — nothing else", () => {
  const frame = "  ⎿  API_KEY=sk-live-the-model-never-saw\n> my password is hunter2\nSaved \\$MDU:Read\\_env[ab12] and $MDU:Bash[cd34].text, again $MDU:Read_env[ab12]\n";
  assert.deepEqual(placeholderNames(frame), ["$MDU:Read_env[ab12]", "$MDU:Bash[cd34].text"]);
  assert.ok(!placeholderNames(frame).join(" ").includes("sk-live") && !placeholderNames(frame).join(" ").includes("hunter2"));
  assert.deepEqual(placeholderNames("no placeholder here"), []);
});
