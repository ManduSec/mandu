/**
 * screen-reconcile.test — unit tests for the fullscreen-aware screen-cell
 * reconciler (src/screen-reconcile.ts), driven with an in-memory resolver and
 * the two headless terminal models — no arbiter, no pty, no spawn.
 *
 * The shapes come from the 2026-09-05 real-config catch (differential-
 * interactive.md §17): Claude Code's alt-screen renderer paints with cell-diff
 * repaints, so a symbol token reaches the wire in PIECES around cursor moves
 * (`$MDU:Read[d49` → CHA → `]`) that the stream filter cannot glue. Each test
 * feeds the TUI's raw bytes to the TUI model, the (unresolved) bytes to the
 * human model as the stream filter would have passed them, and asserts on
 * what the human's screen shows after reconcile().
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ScreenReconciler, concealedCandidates, concealedSpelling, glyphWidth, softWrapJoin, splitFragments, type ScreenReconcilerOptions,
} from "../../src/screen-reconcile.js";
import { ReplyStreamFilter, frameSafeValue, type ReplyResolver } from "../../src/filter.js";
import { ReserveValueCache, moreLinesNote } from "../../src/reserve-block.js";
import { layoutRows } from "../../src/reserve-layout.js";
import {
  BT,
  BV,
  shown,
  INLINE_FIRST_PAINT,
  INLINE_RELAYOUT,
  FULLSCREEN_FIRST_PAINT,
  KT,
  KV,
  KV_ROWS,
  LONG_FIRST_PAINT,
  LONG_LINES,
  LONG_SCROLL_RELAYOUT,
  LONG_TOKEN,
  LONG_VALUE,
  V2_W,
  KEY_FIRST_PAINT,
  MT,
  MV,
  MID_F,
  MID_HEAD,
  MID_PREFIX,
  MID_SUFFIX,
  MID_FIRST_PAINT,
  MID_ROWS,
  MID_RELAYOUT,
  MID_SCREEN,
  renderScreen,
} from "./reserve-fixtures.js";
import {
  SPLIT_AFTER,
  SPLIT_BEFORE,
  SPLIT_FRAME,
  SPLIT_ROW,
  SPLIT_SETUP,
  SPLIT_TOKEN,
  SPLIT_VALUE,
} from "./inline-split-fixtures.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SYM = "$MDU:Read[d49f]";
const RAW = "TODO: ship the proxy.";
const ALT_ON = "\x1b[?1049h";
const ALT_OFF = "\x1b[?1049l";
const cup = (row: number, col: number) => `\x1b[${row};${col}H`;
const cha = (col: number) => `\x1b[${col}G`;
/** Offset in SYM of the hash's LAST glyph (`f`) — the cell a cell-diff
 *  repaint skips when the previous frame already holds that glyph there. */
const SKIP = SYM.indexOf("]") - 1;

/** The two frames of a cell-diff split with the token painted at column
 *  `col`: frame 1 is a spinner row whose cell under the token's `f` already
 *  holds an `f`; frame 2 paints the token up to that cell, jumps the cursor
 *  over it (CHA), and writes the closing `]`. */
function splitFrames(row: number, col: number): [string, string] {
  assert.equal(SYM[SKIP], "f", "fixture: the skipped cell is the hash's f");
  const frame1 = cup(row, col) + "Reading the".padEnd(SKIP) + "f...";
  const frame2 = cup(row, col) + SYM.slice(0, SKIP) + cha(col + SKIP + 1) + "]" + "\x1b[K";
  return [frame1, frame2];
}

class MockResolver implements ReplyResolver {
  calls: string[] = [];
  fail = false;
  constructor(private readonly table: Record<string, string> = { [SYM]: RAW }) {}
  async desymbolize(text: string): Promise<string> {
    this.calls.push(text);
    if (this.fail) throw new Error("arbiter down");
    return this.table[text] ?? text;
  }
}

/** Feed the same bytes to both models (what a pass-through stream does). */
function both(r: ScreenReconciler, bytes: string): void {
  r.feedTui(bytes);
  r.feedHuman(bytes);
}

function make(opts: { cols?: number; rows?: number; table?: Record<string, string> } = {}) {
  const resolver = new MockResolver(opts.table);
  const r = new ScreenReconciler(resolver, { cols: opts.cols ?? 40, rows: opts.rows ?? 6, unknownRetryMs: 50 });
  return { r, resolver };
}

// ── the catch: a cell-diff split token ──────────────────────────────────────

test("cell-diff split: a token assembled only on screen resolves in place; cursor restored", async () => {
  const { r, resolver } = make();
  const [frame1, frame2] = splitFrames(3, 3);
  // Frame 1: a spinner row whose column under the token's `f` happens to
  // hold the `f` the token's hash needs (the TUI's diff will skip that cell
  // next frame).
  both(r, ALT_ON + frame1);
  // Frame 2: the reply row — the token minus the cell the TUI believes is
  // already right, then the cursor parked in the input box.
  both(r, frame2 + cup(6, 3));
  assert.deepEqual((await r.tuiLines())[2], `  ${SYM}`);
  const repaint = await r.reconcile();
  assert.notEqual(repaint, "", "the split token needs a repaint");
  const human = await r.humanLines();
  assert.equal(human[2], `  ${RAW}`, "the value replaced the token on the human's row");
  assert.ok(!human.join("\n").includes("$MDU:"), "no token left on the human's screen");
  assert.ok(repaint.endsWith(cup(6, 3)), "the cursor goes back where the TUI believes it is");
  assert.deepEqual(resolver.calls, [SYM], "one round-trip per distinct token");
  // Idempotent: a second pass finds the row already right.
  assert.equal(await r.reconcile(), "");
  r.dispose();
});

test("main screen, nothing masked: a token row stays the stream's (no repaint)", async () => {
  // Without maskFragments (a stream that passed the bytes as they were), a
  // main-screen token row is not the reconciler's: only a mask pass (§30)
  // or a reserve row brings it in.
  const { r } = make();
  const [frame1, frame2] = splitFrames(2, 1);
  both(r, frame1);
  both(r, frame2);
  assert.equal(r.fullscreen, false);
  assert.equal(await r.reconcile(), "");
  assert.equal((await r.humanLines())[1], SYM, "left as the stream passed it");
  r.dispose();
});

test("already right: a row the stream splice resolved compares equal, no repaint", async () => {
  const { r } = make();
  r.feedTui(ALT_ON + cup(2, 1) + `see ${SYM} now`);
  // What the stream filter emitted for that chunk: the frame-safe splice
  // (value longer than the token → ESC[?7l…?7h) with the rest of the row.
  r.feedHuman(ALT_ON + cup(2, 1) + `see \x1b[?7l${RAW}\x1b[?7h now`);
  assert.equal(await r.reconcile(), "");
  assert.equal((await r.humanLines())[1], `see ${RAW} now`);
  r.dispose();
});

test("overrun of an earlier frame's cells: the row's tail shifts right and clips at the edge", async () => {
  const { r } = make({ cols: 30 });
  // Frame 1 painted the row's tail; frame 2 writes only the token cells (the
  // diff), so the stream's splice would overwrite ` and more` with value bytes.
  const frame1 = "x: " + " ".repeat(SYM.length) + " and more";
  both(r, ALT_ON + cup(1, 1) + frame1);
  r.feedTui(cup(1, 4) + SYM);
  r.feedHuman(cup(1, 4) + `\x1b[?7l${RAW}\x1b[?7h`);
  // The value overwrote the token cells AND the start of ` and more`; only
  // frame 1's cells past the value's end survive beside it.
  const smeared = "x: " + RAW + frame1.slice("x: ".length + RAW.length);
  assert.ok(smeared.length > "x: ".length + RAW.length, "fixture: frame 1's tail runs past the value");
  assert.equal((await r.humanLines())[0], smeared, "the stream splice alone leaves a smeared tail");
  const repaint = await r.reconcile();
  assert.notEqual(repaint, "");
  assert.equal((await r.humanLines())[0], "x: TODO: ship the proxy. and m", "tail shifted right, clipped at 30 columns");
  r.dispose();
});

test("shorter value closes up: the cells after the token shift left, the tail is erased (no inner padding)", async () => {
  const { r } = make({ table: { [SYM]: "ok" } });
  both(r, ALT_ON + cup(1, 1) + `[${SYM}] and more` + cup(6, 3));
  const repaint = await r.reconcile();
  assert.equal((await r.humanLines())[0], "[ok] and more");
  assert.ok(repaint.includes("\x1b[K"), "the row's old tail is erased, no ghost glyphs");
  assert.ok(repaint.endsWith(cup(6, 3)), "the cursor goes back where the TUI believes it is");
  assert.equal(await r.reconcile(), "", "converged");
  r.dispose();
});

test("token gone: when the TUI rewrites the row, our value cells do not linger", async () => {
  const { r } = make();
  both(r, ALT_ON + cup(1, 1) + `A ${SYM}`);
  await r.reconcile();
  assert.equal((await r.humanLines())[0], `A ${RAW}`);
  // The TUI now believes the row reads "A done." — its diff rewrote only
  // the cells that differ from ITS model (the token), leaving the cells
  // beyond "done." untouched, where our value's tail still sits.
  both(r, cup(1, 3) + "done." + "\x1b[K");
  await r.reconcile();
  assert.equal((await r.humanLines())[0], "A done.", "owned row reconciled back to the TUI's content");
  assert.equal(await r.reconcile(), "", "and released");
  r.dispose();
});

test("unknown token: no repaint, one query, retried only after the backoff", async () => {
  const { r, resolver } = make({ table: {} });
  both(r, ALT_ON + cup(1, 1) + SYM);
  assert.equal(await r.reconcile(1000), "");
  assert.equal(await r.reconcile(1010), "");
  assert.equal(resolver.calls.length, 1, "the backoff holds the second ask");
  assert.equal(await r.reconcile(1100), "");
  assert.equal(resolver.calls.length, 2, "re-asked after unknownRetryMs");
  assert.equal((await r.humanLines())[0], SYM, "opaque token stays — nothing leaks");
  r.dispose();
});

test("arbiter unreachable: no repaint, screen untouched (utility posture)", async () => {
  const { r, resolver } = make();
  resolver.fail = true;
  both(r, ALT_ON + cup(1, 1) + SYM);
  assert.equal(await r.reconcile(), "");
  assert.equal((await r.humanLines())[0], SYM);
  r.dispose();
});

test("markdown-escaped spelling on screen resolves through the canonical token", async () => {
  const { r, resolver } = make();
  both(r, ALT_ON + cup(1, 1) + "\\$MDU:Read[d49f]");
  await r.reconcile();
  assert.deepEqual(resolver.calls, [SYM]);
  assert.equal((await r.humanLines())[0], RAW);
  r.dispose();
});

test("multi-line value renders as one row (frame-safe)", async () => {
  const { r } = make({ table: { [SYM]: "# notes\nline two\n" } });
  both(r, ALT_ON + cup(2, 1) + SYM);
  await r.reconcile();
  assert.equal((await r.humanLines())[1], "# notes ⏎ line two");
  r.dispose();
});

test("wide glyphs before the token keep the column arithmetic honest", async () => {
  const { r } = make();
  both(r, ALT_ON + cup(1, 1) + `中文 ${SYM} 末`);
  await r.reconcile();
  const line = (await r.humanLines())[0];
  assert.equal(line, `中文 ${RAW} 末`);
  assert.equal(glyphWidth("中"), 2);
  assert.equal(glyphWidth("a"), 1);
  r.dispose();
});

test("resize reflows both models and forgets owned rows", async () => {
  const { r } = make({ cols: 40, rows: 6 });
  both(r, ALT_ON + cup(1, 1) + SYM);
  await r.reconcile();
  await r.resize(60, 10);
  // A fresh full repaint at the new size (what a TUI does on SIGWINCH).
  both(r, "\x1b[2J" + cup(1, 1) + SYM);
  await r.reconcile();
  const human = await r.humanLines();
  assert.equal(human.length, 10);
  assert.equal(human[0], RAW);
  r.dispose();
});

// ── a TAB in the value (differential-interactive.md §19 residual) ────────────

test("tab in the value: expanded to the next 8-column stop from the value's exact screen column", async () => {
  const { r } = make({ table: { [SYM]: "k\tv" } });
  both(r, ALT_ON + cup(2, 3) + SYM + " tail");
  await r.reconcile();
  // Value at 0-based column 2: k@2, tab@3 → stop 8 (5 spaces), v@8; the
  // value is narrower than the token, so " tail" closes up behind it (no pad).
  const want = "  k" + " ".repeat(5) + "v" + " tail";
  assert.equal((await r.humanLines())[1], want);
  // Exactly what a vanilla terminal shows for the raw value at that column.
  const vanilla = new ScreenReconciler(new MockResolver({}), { cols: 40, rows: 6 });
  both(vanilla, ALT_ON + cup(2, 3) + "k\tv");
  assert.equal((await vanilla.humanLines())[1], want.slice(0, 9));
  vanilla.dispose();
  r.dispose();
});

test("tab in the value, content origin (§19.7): the stops count from the TUI's text column, as Claude Code's renderer expands them", async () => {
  const reserveCache = new ReserveValueCache(undefined, "ink", "content");
  const r = new ScreenReconciler(new MockResolver({ [SYM]: "k\tv" }), { cols: 40, rows: 6, unknownRetryMs: 50, reserveCache });
  both(r, ALT_ON + cup(2, 3) + SYM + " tail");
  await r.reconcile();
  // Value at column 2, the text's column 0: k@0, its TAB to 8 (7 spaces), v@10.
  assert.equal((await r.humanLines())[1], "  k" + " ".repeat(7) + "v" + " tail");
  r.dispose();
});

test("tab in the value: a row the stream filter spliced with its ONE-SPACE fallback is repainted to the tab-stop form", async () => {
  const { r } = make({ table: { [SYM]: "k\tv" } });
  r.feedTui(ALT_ON + cup(2, 3) + SYM);
  r.feedHuman(ALT_ON + cup(2, 3) + "k v" + " ".repeat(SYM.length - 3)); // the stream's fallback splice
  const out = await r.reconcile();
  assert.notEqual(out, "");
  assert.ok(!out.includes("\t"), "a repaint never carries a raw TAB");
  assert.equal((await r.humanLines())[1], "  k" + " ".repeat(5) + "v");
  assert.equal(await r.reconcile(), "", "converged: no second repaint");
  r.dispose();
});

test("tab in the value: the column is the value's REAL one (an earlier wider value shifts it); a tab at the edge clips", async () => {
  const A = "$MDU:Read[aaaa]";
  const B = "$MDU:Read[bbbb]";
  const { r } = make({ cols: 60, table: { [A]: "0123456789abcdefghij", [B]: "x\ty" } });
  both(r, ALT_ON + cup(1, 1) + `${A} ${B}`);
  await r.reconcile();
  // A widens A.length → 20; B's value starts at column A.length + 1 + (20 - A.length) = 21: x@21, tab@22 → 24.
  assert.equal((await r.humanLines())[0], "0123456789abcdefghij x  y");
  r.dispose();
  const edge = make({ cols: 20, table: { [SYM]: "abcdefghijklmnopq\tz" } });
  both(edge.r, ALT_ON + cup(1, 1) + SYM);
  await edge.r.reconcile();
  assert.equal((await edge.r.humanLines())[0], "abcdefghijklmnopq", "tab spaces + z clip at the right edge");
  edge.r.dispose();
});

test("leaving the alternate screen clears ownership; the main screen is left alone", async () => {
  const { r } = make();
  both(r, ALT_ON + cup(1, 1) + SYM);
  await r.reconcile();
  both(r, ALT_OFF + `main ${SYM}\r\n`);
  assert.equal(await r.reconcile(), "");
  assert.equal(r.fullscreen, false);
  r.dispose();
});

test("onResolve fires once per token a repaint resolved", async () => {
  const seen: Array<[string, string]> = [];
  const r = new ScreenReconciler(new MockResolver(), {
    cols: 40, rows: 4, onResolve: (b, a) => { seen.push([b, a]); },
  });
  both(r, ALT_ON + cup(1, 1) + SYM + cup(2, 1) + SYM);
  await r.reconcile();
  assert.deepEqual(seen, [[SYM, RAW], [SYM, RAW]]);
  assert.equal(r.repaints, 1, "one repaint write covers both rows");
  r.dispose();
});

// ── reserve blocks: the reconciler on BOTH screens (reply-row-reservation.md §3.7) ──
// Phase 0 (§7.1) found that a re-layout frame repaints marker rows by CELL
// DIFF on the main screen too: only the changed cells go out (`\r ESC[12C
// ESC[1B 3`), so the stream alone cannot paint them. The reconciler takes
// reserve rows on the main screen (tokens there stay stream-only). These
// tests run the REAL pair — the stream filter's output feeds the human model,
// the reconciler's repaints follow — as run.ts wires them.

/** The stream filter and the reconciler over one shared reserve cache, as
 *  run.ts wires them; `wire` is every byte the human's terminal received. */
function relay(
  table: Record<string, string>,
  opts: { cols?: number; rows?: number; blockLookup?: ScreenReconcilerOptions["blockLookup"] } = {},
) {
  const cols = opts.cols ?? 80;
  const rows = opts.rows ?? 12;
  const resolver = new MockResolver(table);
  const reserveCache = new ReserveValueCache();
  const filter = new ReplyStreamFilter(resolver, { eager: true, cols, reserveCache });
  const r = new ScreenReconciler(resolver, {
    cols, rows, unknownRetryMs: 50, reserveCache,
    ...(opts.blockLookup ? { blockLookup: opts.blockLookup } : {}),
  });
  let wire = "";
  const deliver = async (filtered: string): Promise<string> => {
    // run.ts writeOutput: the alt-screen mask, then the terminal, then the reconcile.
    const out = await r.maskFragments(filtered);
    r.feedHuman(out);
    const rep = await r.reconcile();
    wire += out + rep;
    return rep;
  };
  return {
    r,
    resolver,
    /** One PTY read: the stream filter, the TUI model (minus what the filter
     *  still holds), then the reconcile. */
    async step(bytes: string): Promise<string> {
      const out = await filter.write(bytes);
      r.feedTui(bytes, filter.held);
      return deliver(out);
    },
    async end(): Promise<string> {
      const out = await filter.flush();
      r.feedTui("", filter.held);
      return deliver(out);
    },
    wire: () => wire,
  };
}

/** Rows `top..top+4` of the human screen. */
async function block(r: ScreenReconciler, top: number): Promise<string[]> {
  return (await r.humanLines()).slice(top, top + 5);
}
const lines5 = [1, 2, 3, 4, 5].map((i) => "  " + shown(i));

test("RESERVE main screen: the first paint is the stream's; the reconciler has nothing to add", async () => {
  const p = relay({ [BT]: BV });
  assert.equal(await p.step(INLINE_FIRST_PAINT), "", "a contiguous first paint needs no repaint");
  assert.equal(p.r.fullscreen, false);
  assert.deepEqual(await block(p.r, 2), lines5);
  p.r.dispose();
});

test("RESERVE main screen: a cell-diff RE-LAYOUT frame (fragments only) is healed — row i reads line i", async () => {
  const p = relay({ [BT]: BV });
  await p.step(INLINE_FIRST_PAINT);
  const rep = await p.step(INLINE_RELAYOUT);
  assert.notEqual(rep, "", "the fragments need a repaint");
  const human = await p.r.humanLines();
  assert.equal(human[2], "  PROBE para");
  assert.deepEqual(human.slice(3, 8), lines5, `screen was:\n${human.join("\n")}`);
  assert.ok(!human.join("\n").includes("$MDU") && !human.join("\n").includes("464e"), "no marker or fragment left");
  // The main screen is addressed RELATIVELY (it does not start at the real
  // terminal's top-left) — never an absolute CUP.
  assert.doesNotMatch(rep, /\x1b\[\d+;\d+H/);
  assert.equal(await p.r.reconcile(), "", "converged: no second repaint");
  // The whole wire, rendered on a terminal that ALREADY held three lines of
  // shell output (the relay does not start at row 0): the block lands three
  // rows lower, every row still line i.
  const real = await renderScreen("$ ls\r\nnotes.txt\r\n$ claude\r\n" + p.wire(), 80, 16);
  assert.equal(real[5], "  PROBE para");
  assert.deepEqual(real.slice(6, 11), lines5, `real terminal was:\n${real.join("\n")}`);
  p.r.dispose();
});

test("main screen: a token the stream spliced whole stays the stream's (no mask, no repaint)", async () => {
  const p = relay({ [SYM]: RAW });
  assert.equal(await p.step(`\r\nsee ${SYM}\x1b[16Gnow\r\n`), "", "a contiguous token needs no repaint");
  assert.ok((await p.r.humanLines())[1]!.startsWith(`see ${RAW.slice(0, 11)}`), "the stream spliced the value");
  assert.doesNotMatch(p.wire(), /\$MDU/);
  p.r.dispose();
});

// ── the main screen's split fragment (differential-interactive.md §30) ──────
// Claude Code 2.1.273's INLINE renderer diffs cells too: a frame that paints a
// token over a row whose cell at the same offset already holds the token's
// glyph skips that cell. The stream sees `$MDU:` CHA `omodel_…`, never a
// whole token. maskFragments blanks the cut-off fragment on the wire and the
// reconcile that follows paints the value, as on the alternate screen.

test("main screen: a cell-diff SPLIT token is masked on the wire and repainted with its value", async () => {
  const p = relay({ [SYM]: RAW });
  const [frame1, frame2] = splitFrames(2, 1);
  await p.step(frame1);
  const rep = await p.step(frame2);
  assert.notEqual(rep, "", "the split token needs a repaint");
  assert.equal((await p.r.humanLines())[1], RAW);
  assert.doesNotMatch(p.wire(), /\$MDU/, "no symbol byte on the wire, not even the split prefix");
  assert.doesNotMatch(rep, /\x1b\[\d+;\d+H/, "the main screen is addressed relatively");
  assert.equal(await p.r.reconcile(), "", "converged");
  p.r.dispose();
});

test("main screen: the CI capture (claude 2.1.273, `$MDU:` CHA `omodel_Read[5ccd]` over `Running…`)", async () => {
  const p = relay({ [SPLIT_TOKEN]: SPLIT_VALUE }, { rows: 24 });
  assert.equal(await p.step(SPLIT_SETUP), "");
  assert.equal((await p.r.humanLines())[SPLIT_ROW], SPLIT_BEFORE);
  await p.step(SPLIT_FRAME);
  assert.equal((await p.r.tuiLines())[SPLIT_ROW], `  ⎿ \u00a0${SPLIT_TOKEN}`, "fixture: the TUI believes the token is whole");
  const human = await p.r.humanLines();
  assert.equal(human[SPLIT_ROW], SPLIT_AFTER, `screen was:\n${human.join("\n")}`);
  assert.equal(human[SPLIT_ROW + 1], "     (3s)", "the rows the frame painted after the token are intact");
  assert.doesNotMatch(p.wire(), /\$MDU/, "no symbol byte on the wire");
  // The whole wire on a terminal that already held a shell prompt above the
  // relay: the row is right there too (relative addressing).
  const real = await renderScreen("$ mandu claude\r\n" + p.wire(), 80, 25);
  assert.equal(real[SPLIT_ROW + 1], SPLIT_AFTER, `real terminal was:\n${real.join("\n")}`);
  p.r.dispose();
});

test("main screen: the CI capture split at EVERY read boundary never puts `$MDU` on the wire and ends right", async () => {
  for (let cut = 1; cut < SPLIT_FRAME.length; cut++) {
    const p = relay({ [SPLIT_TOKEN]: SPLIT_VALUE }, { rows: 24 });
    await p.step(SPLIT_SETUP);
    await p.step(SPLIT_FRAME.slice(0, cut));
    await p.step(SPLIT_FRAME.slice(cut));
    await p.end();
    await p.r.reconcile();
    assert.doesNotMatch(p.wire(), /\$MDU/, `cut at ${cut}: ${JSON.stringify(SPLIT_FRAME.slice(0, cut))}`);
    const real = await renderScreen(p.wire(), 80, 24);
    assert.equal(real[SPLIT_ROW], SPLIT_AFTER, `cut at ${cut}: real terminal was:\n${real.join("\n")}`);
    p.r.dispose();
  }
});

test("main screen: a split fragment that stays unresolvable gets the TUI's cells back, never left blank", async () => {
  const unknown = "$MDU:Read[dead]";
  const p = relay({});
  const skip = unknown.indexOf("]") - 1; // the `d` before `]`
  await p.step(`\r\n${"Reading the".padEnd(skip)}d...`);
  await p.step(`\r${unknown.slice(0, skip)}\x1b[${skip + 2}G]\x1b[K`);
  assert.doesNotMatch(p.wire(), /\$MDU/, "the fragment went out blank");
  // One reconcile later (the next write or the relay's idle drain) the
  // TUI's own cells come back: the opaque token, as the stream would show it.
  assert.ok(p.r.restorePending, "a restore pass is pending (the idle drain re-arms on it)");
  await p.r.reconcile();
  assert.equal((await p.r.humanLines())[1], unknown);
  assert.equal(p.r.restorePending, false);
  p.r.dispose();
});

test("main screen: prose about the grammar cut by a CHA is restored too", async () => {
  const p = relay({});
  await p.step("\r\nthe\x1b[5G$MDU:\x1b[11Gprefix\r\n");
  await p.r.reconcile();
  assert.equal((await p.r.humanLines())[1], "the $MDU: prefix");
  p.r.dispose();
});

test("splitFragments: only an incomplete run cut off by an escape is blanked", () => {
  const cha = "\x1b[12G";
  assert.equal(splitFragments(`$MDU:${cha}omodel`), `     ${cha}omodel`, "a bare prefix");
  assert.equal(splitFragments(`$MDU:Read[d49\x1b[39m${cha}f]`), `             \x1b[39m${cha}f]`, "styling looked through");
  assert.equal(splitFragments(`\\$MDU:Re${cha}`), `        ${cha}`, "the Markdown-escaped spelling");
  assert.equal(splitFragments(`$MDU/464e/${cha}5`), `          ${cha}5`, "a continuation marker's fragment");
  assert.equal(splitFragments(`${SYM}${cha}now`), `${SYM}${cha}now`, "a whole token (unknown to the arbiter) stays");
  assert.equal(splitFragments(`${SYM}.key${cha}`), `${SYM}.key${cha}`, "a whole token with its field stays");
  assert.equal(splitFragments(`$MDU/464e/3${cha}`), `$MDU/464e/3${cha}`, "a whole continuation marker stays");
  assert.equal(splitFragments(`${SYM}/1:5${cha}`), `${SYM}/1:5${cha}`, "a whole reserve head stays");
  assert.equal(splitFragments("$MDU: prefix\r\n"), "$MDU: prefix\r\n", "not cut by an escape: the stream's");
  assert.equal(splitFragments("$MDU:\x1b[K\r\n"), "$MDU:\x1b[K\r\n", "an erase at the row's end is glue, not a cut");
});

test("RESERVE main screen: scrolling — owned rows follow their lines; a scroll never triggers a wrong repaint", async () => {
  const nine = Array.from({ length: 9 }, (_, i) => `l${i + 1}`).join("\n") + "\n";
  const p = relay({ [BT]: nine }, { cols: 40, rows: 6 });
  let paint = `\r\n  ${BT}/1:9`;
  for (let i = 2; i <= 9; i++) paint += `\r\n  $MDU/464e/${i}`;
  await p.step(paint); // 10 rows on a 6-row screen: the top scrolls away
  assert.deepEqual(await p.r.humanLines(), ["  l4", "  l5", "  l6", "  l7", "  l8", "  l9"]);
  // A re-layout shifts the block up one row, by cell diff: one digit per row.
  let relayout = "\x1b[5A";
  for (let k = 0; k < 5; k++) relayout += `\r\x1b[12C${k > 0 ? "\x1b[1B" : ""}${5 + k}`;
  relayout += "\r\x1b[1B\x1b[K";
  assert.notEqual(await p.step(relayout), "");
  assert.deepEqual(await p.r.humanLines(), ["  l5", "  l6", "  l7", "  l8", "  l9", ""]);
  // A line feed at the bottom scrolls both models: the painted rows move up
  // with their lines and still compare equal — no repaint.
  assert.equal(await p.step("\r\n"), "");
  assert.deepEqual(await p.r.humanLines(), ["  l6", "  l7", "  l8", "  l9", "", ""]);
  p.r.dispose();
});

test("RESERVE main screen: a first paint split at EVERY offset still ends with row i = line i", async () => {
  for (let cut = 1; cut < INLINE_FIRST_PAINT.length; cut++) {
    const p = relay({ [BT]: BV });
    await p.step(INLINE_FIRST_PAINT.slice(0, cut));
    await p.step(INLINE_FIRST_PAINT.slice(cut));
    await p.end();
    assert.deepEqual(await block(p.r, 2), lines5, `cut at ${cut}: ${JSON.stringify(INLINE_FIRST_PAINT.slice(0, cut))}`);
    const real = await renderScreen(p.wire());
    assert.deepEqual(real.slice(0, 8), ["", "", ...lines5, ""], `wire, cut at ${cut}: no row above or below the block touched`);
    p.r.dispose();
  }
});

test("RESERVE alternate screen: first paint and a cell-diff re-layout both end with row i = line i", async () => {
  const p = relay({ [BT]: BV });
  await p.step(FULLSCREEN_FIRST_PAINT);
  assert.equal(p.r.fullscreen, true);
  assert.deepEqual(await block(p.r, 2), lines5);
  // Re-layout by cell diff: the block moves down one row (absolute CUPs, as a
  // fullscreen renderer addresses rows).
  const relayout =
    `${cup(3, 1)}  PROBE para\x1b[K${cup(4, 7)}:nomodel_Bash[464e]/1:5${cup(5, 13)}2${cup(6, 13)}3${cup(7, 13)}4` +
    `${cup(8, 1)}  $MDU/464e/5${cup(12, 3)}`;
  const rep = await p.step(relayout);
  assert.notEqual(rep, "");
  const human = await p.r.humanLines();
  assert.equal(human[2], "  PROBE para");
  assert.deepEqual(human.slice(3, 8), lines5, `screen was:\n${human.join("\n")}`);
  assert.ok(rep.endsWith(cup(12, 3)), "the cursor goes back where the TUI believes it is");
  p.r.dispose();
});

test("RESERVE alternate screen: a row the STREAM painted, later cell-diffed to prose, loses the value's tail", async () => {
  // echo-fidelity-long @160x40 (reply-row-reservation.md §3.7): the stream
  // paints a value row right, so the reconciler never repaints it; a later
  // re-layout writes prose of the MARKER's width over it with no EL (the TUI
  // believes the row held `$MDU/464e/4`). The value's tail must not survive.
  const p = relay({ [BT]: BV });
  assert.equal(await p.step(FULLSCREEN_FIRST_PAINT), "", "the stream's first paint is already right");
  assert.equal((await p.r.humanLines())[5], "  " + shown(4));
  const prose = "PROBE_DONE!"; // as wide as `$MDU/464e/4`
  assert.equal(prose.length, "$MDU/464e/4".length);
  assert.notEqual(await p.step(`${cup(6, 3)}${prose}${cup(12, 3)}`), "", "the ghost tail needs a repaint");
  const human = await p.r.humanLines();
  assert.equal(human[5], `  ${prose}`, `screen was:\n${human.join("\n")}`);
  assert.deepEqual(human.slice(2, 5), [1, 2, 3].map((i) => "  " + shown(i)), "the rows above are untouched");
  assert.equal(await p.r.reconcile(), "", "converged");
  p.r.dispose();
});

// ── echo-fidelity-long @160x40: the `$MDU/` CHA `101/3` split (CI, 6 pipelines) ──
// The captured scroll re-layout (reserve-fixtures.ts LONG_SCROLL_RELAYOUT):
// the cell diff writes `$MDU/`, jumps over the `c` the row already held and
// writes `101/3`. The stream cannot splice that, and used to pass the `$MDU/`
// through raw; the reconciler healed the screen a moment later, but the
// symbol bytes had reached the human's terminal (F2's raw-stream check).

const LONG_ROWS = LONG_LINES.slice(1).map((l) => `  ${l}`.trimEnd()); // block rows 2..33

test("RESERVE alternate screen, echo-fidelity-long @160x40: the captured `$MDU/` CHA split never reaches the wire; row i reads line i", async () => {
  const p = relay({ [LONG_TOKEN]: LONG_VALUE }, { cols: 160, rows: 40 });
  assert.equal(await p.step(`${ALT_ON}\x1b[2J${LONG_FIRST_PAINT}`), "", "the contiguous first paint is the stream's");
  assert.deepEqual((await p.r.humanLines()).slice(2, 35), LONG_LINES.map((l) => `  ${l}`.trimEnd()));
  assert.ok(!p.wire().includes("$MDU"), "first paint: no symbol byte on the wire");
  const rep = await p.step(LONG_SCROLL_RELAYOUT);
  assert.notEqual(rep, "", "the fragments need a repaint");
  const wire = p.wire();
  assert.equal(wire.match(/\$MDU[:\w[\].]*/)?.[0] ?? null, null, "no `$MDU` byte ever reached the human's terminal stream (F2)");
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(0, 32), LONG_ROWS, `screen was:\n${human.join("\n")}`);
  assert.equal(human[32], "  DIFF_S1_DONE", "the prose row cell-diffed over a value row keeps no tail");
  assert.ok(rep.endsWith(cup(38, 3)), "the cursor goes back where the TUI believes it is");
  assert.equal(await p.r.reconcile(), "", "converged");
  // The whole wire on a fresh terminal: the same screen.
  const real = await renderScreen(wire, 160, 40);
  assert.deepEqual(real.slice(0, 33), [...LONG_ROWS, "  DIFF_S1_DONE"], `real terminal was:\n${real.join("\n")}`);
  p.r.dispose();
});

test("RESERVE alternate screen, echo-fidelity-long @160x40: the same frames split at every read boundary around the fragment", async () => {
  const at = LONG_SCROLL_RELAYOUT.indexOf("$MDU/\x1b[9G");
  for (let cut = at - 40; cut <= at + 60; cut++) {
    const p = relay({ [LONG_TOKEN]: LONG_VALUE }, { cols: 160, rows: 40 });
    await p.step(`${ALT_ON}\x1b[2J${LONG_FIRST_PAINT}`);
    await p.step(LONG_SCROLL_RELAYOUT.slice(0, cut));
    await p.step(LONG_SCROLL_RELAYOUT.slice(cut));
    await p.end();
    const where = `cut at ${cut}: ${JSON.stringify(LONG_SCROLL_RELAYOUT.slice(Math.max(0, cut - 8), cut))}`;
    assert.equal(p.wire().match(/\$MDU[:\w[\].]*/)?.[0] ?? null, null, `${where}: no \`$MDU\` on the wire`);
    assert.deepEqual((await p.r.humanLines()).slice(0, 32), LONG_ROWS, where);
    p.r.dispose();
  }
});

test("RESERVE alternate screen: a first paint split at EVERY offset puts no `$MDU` on the wire and ends with row i = line i", async () => {
  // A read boundary inside `$MDU/464e/3` used to send the head of the marker
  // raw (a continuation is never held as a candidate); now it is masked and
  // the next read's reconcile paints the row.
  for (let cut = 1; cut < FULLSCREEN_FIRST_PAINT.length; cut++) {
    const p = relay({ [BT]: BV });
    await p.step(FULLSCREEN_FIRST_PAINT.slice(0, cut));
    await p.step(FULLSCREEN_FIRST_PAINT.slice(cut));
    await p.end();
    const where = `cut at ${cut}: ${JSON.stringify(FULLSCREEN_FIRST_PAINT.slice(0, cut))}`;
    assert.ok(!p.wire().includes("$MDU"), `${where}: no symbol byte on the wire`);
    assert.deepEqual(await block(p.r, 2), lines5, where);
    p.r.dispose();
  }
});

test("alternate screen: a split PLAIN token's stream fragment is masked, then the reconciler paints the value", async () => {
  const p = relay({ [SYM]: RAW });
  const [frame1, frame2] = splitFrames(3, 3);
  await p.step(ALT_ON + frame1);
  await p.step(frame2 + cup(6, 3));
  assert.ok(!p.wire().includes("$MDU"), `no token prefix on the wire: ${JSON.stringify(p.wire())}`);
  assert.equal((await p.r.humanLines())[2], `  ${RAW}`);
  p.r.dispose();
});

test("alternate screen: `$MDU` text that is no token (prose) is masked by the stream, then restored from the TUI's row", async () => {
  // A reply that talks ABOUT the grammar: `$MDU:` with no tag/hash, and a
  // continuation-looking `$MDU/<hash>/<i>`. Nothing resolves; the human must
  // still end up seeing exactly what the TUI painted.
  const prose = "symbols look like $MDU:Tag[hash] or $MDU/<hash>/<i>";
  const p = relay({});
  await p.step(`${ALT_ON}${cup(2, 1)}${prose}${cup(6, 1)}`);
  assert.ok(!p.wire().includes("$MDU"), "the stream's write is masked");
  // The restore waits one reconcile (the next write, or the relay's idle drain).
  const rep = await p.r.reconcile();
  assert.ok(rep.endsWith(cup(6, 1)), "restored, the cursor put back");
  assert.equal((await p.r.humanLines())[1], prose, "the human sees the prose the TUI painted");
  assert.equal(await p.r.reconcile(), "", "converged");
  // A token the arbiter does not know stays an opaque token (never blank).
  const q = relay({});
  await q.step(`${ALT_ON}${cup(2, 1)}see ${SYM} here${cup(6, 1)}`);
  await q.step(cup(6, 2)); // the next write
  assert.equal((await q.r.humanLines())[1], `see ${SYM} here`);
  assert.equal(await q.r.reconcile(), "", "converged");
  p.r.dispose();
  q.r.dispose();
});

test("alternate screen: an unknown token pushed past the right edge by a wider value is restored clipped, then left alone (no blank/restore cycle)", async () => {
  const UNK = "$MDU:Read[beef]"; // the arbiter does not know it
  const p = relay({ [SYM]: RAW }, { cols: 40, rows: 6 });
  await p.step(`${ALT_ON}${cup(2, 1)}${SYM} abcdef ${UNK}${cup(6, 1)}`);
  assert.equal(p.r.restorePending, true, "the masked token waits for its restore pass");
  const passes: string[] = [];
  for (let k = 0; k < 4; k++) passes.push(await p.r.reconcile(Date.now() + 1000 * (k + 1)));
  const want = `${RAW} abcdef ${UNK}`.slice(0, 40);
  assert.equal((await p.r.humanLines())[1], want, `passes: ${JSON.stringify(passes)}`);
  assert.deepEqual(passes.slice(-2), ["", ""], "converged");
  assert.equal(p.r.restorePending, false);
  p.r.dispose();
});

test("alternate screen: a value far wider than the rest of its row clips; no cell of it lands on a later row (the 107-column Stripe key, 2026-10-17)", async () => {
  // Claude Code's fullscreen reply, as captured live at 120 columns and cut
  // to 72: a 41-column token mid-row, the words after it placed by CHA, the
  // rows below reached by relative moves (`CR CUF CUD`). The stream used to
  // send the words the splice pushed past the edge with auto-wrap on: they
  // wrapped onto rows the TUI never counted, every later row landed low,
  // and the reconciler (which takes token rows only) left the human reading
  // `connected0totStripe`.
  const KEY = "$MDU:nomodel_Read[aad5].STRIPE_SECRET_KEY";
  const VALUE = `wide-value-${"0123456789".repeat(10)}`; // 111 columns
  const p = relay({ [KEY]: VALUE }, { cols: 72, rows: 8 });
  const frame =
    `${ALT_ON}${cup(2, 1)}●${cha(3)}Found${cha(9)}the${cha(13)}key${cha(17)}(${KEY})${cha(61)}and${cha(65)}got` +
    `\r\x1b[2C\x1b[1BHTTP${cha(8)}200.` +
    `\r\x1b[2C\x1b[2Bpayments:${cha(13)}connected${cha(23)}to${cha(26)}Stripe${cha(33)}(test${cha(39)}mode)` +
    `${cup(8, 3)}`;
  await p.step(frame);
  for (let k = 0; k < 3; k++) await p.r.reconcile(Date.now() + 1000 * (k + 1));
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 6), [
    `● Found the key (${VALUE}`.slice(0, 72),
    "  HTTP 200.",
    "",
    "  payments: connected to Stripe (test mode)",
    "",
  ], `screen was:\n${human.join("\n")}`);
  assert.ok(!human.join("\n").includes("$MDU"), "no symbol byte on the human's screen");
  assert.equal(await p.r.reconcile(Date.now() + 10_000), "", "converged");
  p.r.dispose();
});

test("main screen: prose and whole tokens go out byte-for-byte (only a cut-off fragment is masked, §30)", async () => {
  const p = relay({});
  const prose = "symbols look like $MDU:Tag[hash] or $MDU/<hash>/<i>";
  await p.step(`${prose}\r\n`);
  assert.ok(p.wire().includes(prose), "byte-for-byte on the main screen");
  p.r.dispose();
});

// A fullscreen renderer showing only the TAIL of a block taller than its
// viewport (echo-fidelity-long @80x24, reply-row-reservation.md §3.8): rows
// 3..5 of the block at screen rows 1..3, the head never painted.
const TAIL_ONLY = `\x1b[?1049h${cup(2, 3)}$MDU/464e/3${cup(3, 3)}$MDU/464e/4${cup(4, 3)}$MDU/464e/5${cup(8, 3)}`;

test("RESERVE headless block: without the arbiter's record the rows stay blank (the old fail-safe)", async () => {
  const p = relay({ [BT]: BV });
  await p.step(TAIL_ONLY);
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 4), ["", "", ""], `screen was:\n${human.join("\n")}`);
  assert.ok(!human.join("\n").includes("464e"), "no marker shown");
  p.r.dispose();
});

test("RESERVE headless block: the arbiter's record (§3.8) lays out rows 3..5 as lines 3..5", async () => {
  const asked: string[] = [];
  const p = relay({ [BT]: BV }, { blockLookup: async (h) => { asked.push(h); return h === "464e" ? { token: BT, n: 5 } : null; } });
  await p.step(TAIL_ONLY);
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 4), [3, 4, 5].map((i) => "  " + shown(i)), `screen was:\n${human.join("\n")}`);
  assert.deepEqual(asked, ["464e"], "asked once; the head is remembered for the other rows");
  assert.equal(await p.r.reconcile(), "", "converged");
  p.r.dispose();
});

test("RESERVE headless block: an unknown hash is asked again only after the backoff; a throw counts as unknown", async () => {
  let known = false;
  let calls = 0;
  const p = relay({ [BT]: BV }, {
    blockLookup: async () => {
      calls++;
      if (calls === 1) throw new Error("arbiter down");
      return known ? { token: BT, n: 5 } : null;
    },
  });
  await p.step(TAIL_ONLY);
  assert.equal(calls, 1);
  await p.r.reconcile();
  assert.equal(calls, 1, "within the backoff: not asked again");
  await new Promise((r) => setTimeout(r, 60));
  await p.r.reconcile();
  assert.equal(calls, 2, "after the backoff: asked again");
  known = true;
  await new Promise((r) => setTimeout(r, 60));
  await p.r.reconcile();
  assert.deepEqual((await p.r.humanLines()).slice(1, 4), [3, 4, 5].map((i) => "  " + shown(i)));
  p.r.dispose();
});

test("RESERVE headless v2 block: the record's W/F lay the rows out as the proxy sized them", async () => {
  // The 120-column key at W = 78: row 2 of its layout is the 42-column tail.
  const p = relay({ [KT]: KV }, {
    blockLookup: async () => ({ token: KT, n: KV_ROWS.length, width: V2_W, first: V2_W }),
  });
  await p.step(`\x1b[?1049h${cup(2, 3)}$MDU/7c1d/2${cup(8, 3)}`);
  assert.equal((await p.r.humanLines())[1], `  ${KV_ROWS[1]}`);
  p.r.dispose();
});

test("RESERVE: arbiter down — both writers agree on `T (N lines)` + blank rows; no repaint loop", async () => {
  const p = relay({ [BT]: BV });
  p.resolver.fail = true;
  await p.step(INLINE_FIRST_PAINT);
  await p.step(INLINE_RELAYOUT);
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(3, 8), [`  ${BT} (5 lines)`, "", "", "", ""], `screen was:\n${human.join("\n")}`);
  assert.equal(await p.r.reconcile(), "", "converged");
  p.r.dispose();
});

test("RESERVE: the reconciler reports a head ONCE, with the whole value, never per row", async () => {
  const seen: Array<[string, string]> = [];
  const r = new ScreenReconciler(new MockResolver({ [BT]: BV }), {
    cols: 80, rows: 12, onResolve: (b, a) => { seen.push([b, a]); },
  });
  // The human's terminal got the same cursor moves but none of the marker
  // text (as if the stream had missed every row): every row needs a repaint,
  // twice, and the head is reported once.
  const movesOnly = INLINE_FIRST_PAINT.replace(/\\?\$MDU[^\r\x1b]*/g, "");
  for (let pass = 0; pass < 2; pass++) {
    r.feedTui("\x1b[2J\x1b[H" + INLINE_FIRST_PAINT);
    r.feedHuman("\x1b[2J\x1b[H" + movesOnly);
    assert.notEqual(await r.reconcile(), "");
  }
  assert.deepEqual(seen, [[BT, BV]]);
  assert.deepEqual((await r.humanLines()).slice(2, 7), lines5);
  r.dispose();
});

// ── v2 blocks inside a line (reply-row-reservation.md §11.3) ─────────────────
// A head after prefix text on its row, a last row's marker before suffix
// text: the reconciler replaces ONLY the marker cells with the row's text and
// keeps the cells around them, shifting and clipping the suffix at the edge.

const V2 = { [KT]: KV, [MT]: MV };

test("RESERVE v2 main screen: a mid-line block's cell-diff re-layout (the suffix row a FRAGMENT) is healed", async () => {
  const p = relay(V2);
  assert.equal(await p.step(MID_FIRST_PAINT), "", "a contiguous first paint is the stream's alone");
  assert.deepEqual((await p.r.humanLines()).slice(2, 5), MID_SCREEN);
  const rep = await p.step(MID_RELAYOUT);
  assert.notEqual(rep, "", "the fragment `3 and that is all.` needs a repaint");
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 5), [...MID_SCREEN, ""], `screen was:\n${human.join("\n")}`);
  assert.ok(!human.join("\n").includes("$MDU") && !human.join("\n").includes("5e2a"), "no marker or fragment left");
  assert.doesNotMatch(rep, /\x1b\[\d+;\d+H/, "main screen: relative addressing only");
  assert.equal(await p.r.reconcile(), "", "converged");
  // The whole wire on a terminal that already held shell output above.
  const real = await renderScreen("$ ls\r\nnotes.txt\r\n$ claude\r\n" + p.wire(), 80, 16);
  assert.deepEqual(real.slice(4, 8), [...MID_SCREEN, ""], `real terminal was:\n${real.join("\n")}`);
  p.r.dispose();
});

test("RESERVE v2 main screen: the mid-line first paint split at EVERY offset still ends with the sentence intact", async () => {
  for (let cut = 1; cut < MID_FIRST_PAINT.length; cut++) {
    const p = relay(V2);
    await p.step(MID_FIRST_PAINT.slice(0, cut));
    await p.step(MID_FIRST_PAINT.slice(cut));
    await p.end();
    assert.deepEqual((await p.r.humanLines()).slice(0, 6), ["", "  PROBE para", ...MID_SCREEN, ""], `cut at ${cut}`);
    // Every row, the prose row ABOVE the head included: a repaint aimed at the
    // head while the stream still held it once landed one row up (below).
    assert.deepEqual((await renderScreen(p.wire())).slice(0, 6), ["", "  PROBE para", ...MID_SCREEN, ""], `wire, cut at ${cut}`);
    p.r.dispose();
  }
});

// The CI flake of 2026-09-30 (tests/stack reply-row-reservation, 7 of
// ~80 runs): a PTY read that ends right after the head row's line break. The
// stream filter holds `T/1:N:W:F` + CRLF as a possible in-flight token, so the
// terminal's cursor is still on the head row, after the prefix. The TUI model
// used to take the whole read, so its cursor was one row BELOW, and the
// reconciler's relative repaint of the head row (CUU 1) landed on the row
// above it (at the top of the screen: clamped onto the head row itself), then
// moved the terminal's cursor down a row before the stream's held head was
// written: the prefix was overwritten, or every later row shifted by one.
// The TUI model now takes only what the filter has let through.
test("RESERVE v2 main screen: a read that ends after the head row (the head held) never repaints a row the terminal has not reached", async () => {
  const paint = `${MID_PREFIX}${MID_HEAD}\r\n$MDU/5e2a/2\r\n$MDU/5e2a/3${MID_SUFFIX}\r\n\r\nDONE\r\n`;
  const want = [
    `${MID_PREFIX}${MID_ROWS[0]!}`.trimEnd(),
    MID_ROWS[1]!.trimEnd(),
    `${MID_ROWS[2]!}${MID_SUFFIX}`,
    "",
    "DONE",
    "",
  ];
  const headCut = paint.indexOf("\r\n") + 2;
  for (let cut = 1; cut < paint.length; cut++) {
    const p = relay(V2);
    const rep = await p.step(paint.slice(0, cut));
    if (cut === headCut) {
      assert.equal(rep, "", "the head is still held: nothing on the terminal to repaint yet");
      assert.deepEqual((await p.r.tuiLines()).slice(0, 2), [MID_PREFIX.trimEnd(), ""], "the TUI model waits with the terminal");
    }
    await p.step(paint.slice(cut));
    await p.end();
    const at = `cut at ${cut}: ${JSON.stringify(paint.slice(0, cut))}`;
    assert.deepEqual((await p.r.humanLines()).slice(0, 6), want, at);
    // The block at the top of the screen (the e2e's shape) …
    assert.deepEqual((await renderScreen(p.wire())).slice(0, 6), want, `wire, ${at}`);
    // … and below shell output, which no repaint may touch.
    const real = await renderScreen("$ ls\r\nnotes.txt\r\n$ claude\r\n" + p.wire(), 80, 16);
    assert.deepEqual(real.slice(0, 9), ["$ ls", "notes.txt", "$ claude", ...want], `real terminal, ${at}`);
    p.r.dispose();
  }
});

test("RESERVE v2 alternate screen: prefix and suffix cells survive a cell-diff re-layout", async () => {
  const p = relay(V2);
  const first =
    ALT_ON + cup(2, 1) + "  PROBE para" + cup(3, 3) + MID_PREFIX + MID_HEAD + cup(4, 3) + "$MDU/5e2a/2" +
    cup(5, 3) + "$MDU/5e2a/3" + MID_SUFFIX;
  await p.step(first);
  assert.equal(p.r.fullscreen, true);
  assert.deepEqual((await p.r.humanLines()).slice(2, 5), MID_SCREEN);
  const relayout =
    cup(2, 3) + MID_PREFIX + MID_HEAD + "\x1b[K" + cup(3, 3) + "$MDU/5e2a/2\x1b[K" + cup(4, 13) + "3" + MID_SUFFIX +
    "\x1b[K" + cup(5, 1) + "\x1b[K" + cup(12, 3);
  const rep = await p.step(relayout);
  assert.notEqual(rep, "");
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 5), [...MID_SCREEN, ""], `screen was:\n${human.join("\n")}`);
  assert.ok(rep.endsWith(cup(12, 3)), "the cursor goes back where the TUI believes it is");
  p.r.dispose();
});

test("RESERVE v2: the reconciler alone (the stream missed every marker) keeps prefix and suffix, clips at the edge", async () => {
  // 22 words: the last row is 62 columns, so the suffix runs one column past
  // the edge and clips there.
  const value = Array.from({ length: 22 }, (_, i) => `secret${String(i + 1).padStart(2, "0")}`).join(" ");
  const r = new ScreenReconciler(new MockResolver({ [MT]: value }), { cols: 80, rows: 8 });
  const paint = `\r  ${MID_PREFIX}${MT}/1:3:78:${MID_F}\x1b[K\r\n  $MDU/5e2a/2\x1b[K\r\n  $MDU/5e2a/3${MID_SUFFIX}\x1b[K\r\n  next`;
  r.feedTui(paint);
  // The human's terminal got the text around the markers, not the markers.
  r.feedHuman(paint.replace(/\$MDU[:/][^\s\x1b]*/g, ""));
  assert.notEqual(await r.reconcile(), "");
  const human = await r.humanLines();
  assert.equal(human[0], `  ${MID_PREFIX}secret01 secret02 secret03 secret04 secret05 secret06 secret07`);
  assert.equal(human[2], ("  secret16 secret17 secret18 secret19 secret20 secret21 secret22" + MID_SUFFIX).slice(0, 80));
  assert.equal(human[3], "  next", "the row below is untouched");
  assert.equal(await r.reconcile(), "", "converged");
  r.dispose();
});

test("RESERVE v2 main screen: a one-line value wider than the terminal — both writers agree on 78 + 42", async () => {
  const p = relay(V2);
  await p.step(KEY_FIRST_PAINT);
  assert.deepEqual((await p.r.humanLines()).slice(1, 5), ["  Your key:", `  ${KV.slice(0, 78)}`, `  ${KV.slice(78)}`, "  key done"]);
  assert.equal(await p.r.reconcile(), "", "nothing for the reconciler to add");
  p.r.dispose();
});

test("RESERVE §13: after a resize the reconciler lays a v2 block out at the narrower width (and the cap note when N rows are too few)", async () => {
  const r = new ScreenReconciler(new MockResolver({ [KT]: KV }), { cols: 80, rows: 12 });
  const paint = cup(1, 3) + `${KT}/1:${KV_ROWS.length}:${V2_W}:${V2_W}` + cup(2, 3) + "$MDU/7c1d/2";
  const moves = cup(1, 3) + cup(2, 3); // the human's terminal got no marker text: the reconciler paints every row
  r.feedTui("\x1b[?1049h" + paint);
  r.feedHuman("\x1b[?1049h" + moves);
  await r.reconcile();
  assert.deepEqual((await r.humanLines()).slice(0, 2), KV_ROWS.map((t) => `  ${t}`));
  await r.resize(60, 12);
  r.feedTui("\x1b[2J" + paint);
  r.feedHuman("\x1b[2J" + moves);
  await r.reconcile();
  // The 120-column key at W = 58 takes three rows; two were reserved.
  assert.equal(layoutRows(KV, 58, 58).length, 3);
  assert.deepEqual((await r.humanLines()).slice(0, 2), [`  ${layoutRows(KV, 58, 58)[0]!.text}`, `  ${moreLinesNote(1)}`]);
  r.dispose();
});

test("feedTui(bytes, held): the last `held` bytes wait until a later call releases them, in order", async () => {
  const r = new ScreenReconciler(new MockResolver(), { cols: 20, rows: 3 });
  r.feedTui("abc\r\nde", 4); // `\r\nde` is still the stream filter's
  assert.deepEqual(await r.tuiLines(), ["abc", "", ""], "only what the filter let through");
  r.feedTui("f", 2); // `\r\nd` released; `ef` still held
  assert.deepEqual(await r.tuiLines(), ["abc", "d", ""]);
  r.feedTui("", 0);
  assert.deepEqual(await r.tuiLines(), ["abc", "def", ""], "nothing lost or doubled");
  r.feedTui("gh"); // held defaults to 0: the whole write
  assert.deepEqual(await r.tuiLines(), ["abc", "defgh", ""]);
  r.dispose();
});

// ── OpenCode's renderer: the concealed token and the punctuation wrap ────────
// (differential-interactive.md §35). Live drill conf-quarantine-any-model
// (2026-10-10, OpenCode 1.18.13, 120x40, truecolor): the reply ended
// `… 30 days. $MDU:anymodel_inspect[a1c6].result` and the human saw
// `… 30 days. $MDU:anymodel_inspecta1c6.result/1:3:  1:   118:118` and the
// value's last line only. Two shapes of OpenCode's: (1) its final Markdown
// render draws `[a1c6]` as a link, brackets hidden (truecolor only), so no
// row holds the token's grammar; (2) a word that does not fit its row is
// broken at its punctuation (`$MDU:` / `nomodel_read[…]`), not moved whole.
// The frames below are OpenCode's, shaped as the lane captured them
// (CUP-addressed cell diffs on the alternate screen, 24-bit SGR).

/** OpenCode's text pen (truecolor) and its link pen (cyan, underlined). */
const OC_TEXT = "\x1b[38;2;238;238;238m\x1b[48;2;10;10;10m";
const OC_LINK = "\x1b[38;2;86;182;194m\x1b[48;2;10;10;10m\x1b[4m";
const OC_RESET = "\x1b[0m";
/** A contract's two terms, a blank line between them (the U-LLM's answer). */
const TERMS_TOKEN = "$MDU:nomodel_read[0155]";
const TERMS_VALUE = "DIFFTERM_PAY 4,200,000 USD\n\nDIFFTERM_NOTICE 90 days";
const SENTENCE = "The contract terms are below, quoted in full here for you:";

test("concealedSpelling / concealedCandidates (§35): the brackets gone, every tag/hash split the grammar allows", () => {
  assert.equal(concealedSpelling("$MDU:nomodel_read[80f1]"), "$MDU:nomodel_read80f1");
  assert.equal(concealedSpelling("$MDU:anymodel_inspect[a1c6].result"), "$MDU:anymodel_inspecta1c6.result");
  assert.equal(concealedSpelling("\\$MDU:nomodel\\_read[80f1]"), "$MDU:nomodel_read80f1", "a Markdown escape renders away too");
  assert.deepEqual(concealedCandidates("$MDU:nomodel_read80f1").map((c) => c.canonical), [
    "$MDU:nomodel_read[80f1]", "$MDU:nomodel_rea[d80f1]", "$MDU:nomodel_re[ad80f1]", "$MDU:nomodel_r[ead80f1]",
  ]);
  // A field path: with it (the longer spelling) and without it.
  const field = concealedCandidates("$MDU:anymodel_inspecta1c6.result");
  assert.deepEqual(field.slice(0, 2), [
    { canonical: "$MDU:anymodel_inspect[a1c6].result", length: "$MDU:anymodel_inspecta1c6.result".length },
    { canonical: "$MDU:anymodel_inspect[a1c6]", length: "$MDU:anymodel_inspecta1c6".length },
  ]);
  for (const run of ["$MDU:", "$MDU:abc", "$MDU:read[80f1]", "$MDU:\\_x80f1", "prose"]) {
    assert.deepEqual(concealedCandidates(run), [], run);
  }
});

test("softWrapJoin (§35): a token or reserve head OpenCode broke at its punctuation joins across the two rows", () => {
  // The lane's shape: `$MDU:` ends the sentence's row, the rest starts the next.
  const upper = `     ${SENTENCE} $MDU:`;
  const j = softWrapJoin(upper, "     nomodel_read[0155]");
  assert.ok(j);
  assert.equal(j.index, upper.length - 5);
  assert.deepEqual([j.upperLength, j.lowerIndex, j.lowerLength], [5, 5, "nomodel_read[0155]".length]);
  assert.equal(j.unit.canonical, TERMS_TOKEN);
  // The live head: broken after `/1:` (a reserve head's suffix spans the break).
  const head = softWrapJoin("     30 days. $MDU:anymodel_inspect[a1c6].result/1:", "     3:118:118");
  assert.equal(head?.unit.canonical, "$MDU:anymodel_inspect[a1c6].result");
  assert.deepEqual([head?.unit.suffix?.n, head?.unit.suffix?.w, head?.unit.suffix?.f, head?.lowerLength], [3, 118, 118, "3:118:118".length]);
  // A whole token at the row's end whose head suffix is on the next row.
  const suffixOnly = softWrapJoin(`     see ${TERMS_TOKEN}`, "     /1:3");
  assert.deepEqual([suffixOnly?.unit.suffix?.n, suffixOnly?.lowerLength], [3, 4]);
  // Concealed on both rows: joined only through a matcher that knows it.
  const known = (rest: string) => (rest.startsWith("$MDU:nomodel_read0155") ? { canonical: TERMS_TOKEN, length: 21 } : null);
  assert.equal(softWrapJoin(upper, "     nomodel_read0155", known)?.unit.canonical, TERMS_TOKEN);
  assert.equal(softWrapJoin(upper, "     nomodel_read0155"), null, "never guessed across a row break");
  // Not a split: the upper row holds the whole token; prose follows.
  assert.equal(softWrapJoin(`     see ${TERMS_TOKEN}`, "     and that is all"), null);
  // A continuation marker row is its own unit, not a lead.
  assert.equal(softWrapJoin(`     see ${TERMS_TOKEN}/1:2`, "     $MDU/0155/2"), null);
  // A fragment the next row does not complete: no unit.
  assert.equal(softWrapJoin(upper, "     nomodel_read[01"), null);
  assert.equal(softWrapJoin("     plain prose", "     nomodel_read[0155]"), null);
});

test("OpenCode §35: a token split at its punctuation is painted where its second piece starts — one ⏎ row, no fragment on either row", async () => {
  const p = relay({ [TERMS_TOKEN]: TERMS_VALUE }, { cols: 80, rows: 12 });
  await p.step(ALT_ON + cup(2, 6) + OC_TEXT + SENTENCE + OC_RESET + cup(10, 6));
  // The streaming render: ` $MDU:` fits the row, the rest goes to the next.
  await p.step(cup(2, 64) + OC_TEXT + " $MDU:" + OC_RESET + cup(3, 6) + OC_TEXT + "nomodel_read[0155]" + OC_RESET
    + cup(4, 6) + OC_TEXT + "DIFF_S1_DONE" + OC_RESET + cup(10, 6));
  const want = [`     ${SENTENCE}`, `     ${frameSafeValue(TERMS_VALUE)}`, "     DIFF_S1_DONE"];
  assert.deepEqual((await p.r.humanLines()).slice(1, 4), want);
  // The final Markdown render: `[0155]` drawn as a link, brackets hidden
  // (a cell diff of the hash and the two cells it frees).
  await p.step(cup(3, 18) + OC_LINK + "0155" + OC_RESET + cup(3, 22) + OC_TEXT + "  " + OC_RESET + cup(10, 6));
  assert.deepEqual((await p.r.tuiLines()).slice(1, 3), [`     ${SENTENCE} $MDU:`, "     nomodel_read0155"], "fixture: the TUI's belief");
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 4), want, `screen was:\n${human.join("\n")}`);
  assert.ok(!/MDU|nomodel|0155/.test(human.join("\n")), "no token fragment on the human's screen");
  assert.doesNotMatch(p.wire(), /\$MDU/, "no symbol byte reached the terminal");
  assert.equal(await p.r.reconcile(), "", "converged");
  p.r.dispose();
});

test("OpenCode §35: a token drawn concealed is resolved — after the bracketed form, and from a re-render that never showed it", async () => {
  // (a) the live shape: the streaming render paints the token, the final
  // Markdown render hides its brackets.
  const p = relay({ "$MDU:nomodel_read[80f1]": "RC_PROBE_2026_5527" }, { cols: 80, rows: 8 });
  await p.step(ALT_ON + cup(2, 6) + OC_TEXT + "$MDU:nomodel_read[80f1]" + OC_RESET + cup(7, 6));
  assert.equal((await p.r.humanLines())[1], "     RC_PROBE_2026_5527");
  await p.step(cup(2, 23) + OC_LINK + "80f1" + OC_RESET + cup(2, 27) + OC_TEXT + "  " + OC_RESET + cup(7, 6));
  assert.equal((await p.r.tuiLines())[1], "     $MDU:nomodel_read80f1", "fixture: the TUI's belief");
  assert.equal((await p.r.humanLines())[1], "     RC_PROBE_2026_5527", "the concealed token keeps its value");
  assert.doesNotMatch(p.wire(), /\$MDU/);
  p.r.dispose();
  // (b) a transcript OpenCode re-rendered (a resumed session): the concealed
  // spelling is all the screen ever held. Each tag/hash split is asked; the
  // one the arbiter knows is painted.
  const q = relay({ "$MDU:nomodel_read[80f1]": "RC_PROBE_2026_5527" }, { cols: 80, rows: 8 });
  await q.step(ALT_ON + cup(2, 6) + OC_TEXT + "$MDU:nomodel_read" + OC_RESET + OC_LINK + "80f1" + OC_RESET + " ok" + cup(7, 6));
  assert.equal((await q.r.humanLines())[1], "     RC_PROBE_2026_5527 ok");
  assert.ok(q.resolver.calls.includes("$MDU:nomodel_read[80f1]"));
  assert.doesNotMatch(q.wire(), /\$MDU/);
  q.r.dispose();
});

test("OpenCode §35: a concealed spelling two known tokens share is never painted (ambiguous), and an unknown one stays the TUI's", async () => {
  // `$MDU:tag[b1234]` and `$MDU:tagb[1234]` both read `$MDU:tagb1234` concealed.
  const p = relay({ "$MDU:tag[b1234]": "VALUE_ONE", "$MDU:tagb[1234]": "VALUE_TWO" }, { cols: 60, rows: 6 });
  await p.step(ALT_ON + cup(2, 6) + "$MDU:tagb1234 end" + cup(5, 1));
  await p.step(""); // the restore pass
  const human = (await p.r.humanLines()).join("\n");
  assert.ok(!human.includes("VALUE_ONE") && !human.includes("VALUE_TWO"), `never guessed between two values:\n${human}`);
  assert.equal((await p.r.humanLines())[1], "     $MDU:tagb1234 end", "the TUI's cells, opaque");
  p.r.dispose();
  const q = relay({}, { cols: 60, rows: 6 });
  await q.step(ALT_ON + cup(2, 6) + "$MDU:nomodel_read80f1" + cup(5, 1));
  await q.step("");
  assert.equal((await q.r.humanLines())[1], "     $MDU:nomodel_read80f1", "an unknown token stays opaque");
  q.r.dispose();
});

test("OpenCode §35: the live head shape — a reserve head broken after `/1:`, concealed later — paints the block, no suffix junk", async () => {
  const T = "$MDU:anymodel_inspect[a1c6].result";
  const V = "Payment amount: 4,200,000 USD\n\nTermination notice period: 90 days";
  const W = 45;
  const rows = layoutRows(V, W, W).map((r) => r.text);
  assert.equal(rows.length, 3, "fixture: three rows at W = 45");
  const p = relay({ [T]: V }, { cols: 50, rows: 10 });
  await p.step(ALT_ON + cup(2, 6) + OC_TEXT + "Done. " + T + "/1:" + OC_RESET + cup(3, 6) + OC_TEXT + `3:${W}:${W}` + OC_RESET
    + cup(4, 6) + OC_TEXT + "$MDU/a1c6/2" + OC_RESET + cup(5, 6) + OC_TEXT + "$MDU/a1c6/3" + OC_RESET + cup(9, 6));
  const want = ["     Done.", `     ${rows[0]}`, "", `     ${rows[2]}`];
  assert.deepEqual((await p.r.humanLines()).slice(1, 5), want);
  // The final render conceals the brackets and re-wraps the head one cell on.
  await p.step(cup(2, 12) + OC_TEXT + "$MDU:anymodel_inspect" + OC_RESET + OC_LINK + "a1c6" + OC_RESET + OC_TEXT + ".result/1:3:" + OC_RESET
    + "\x1b[K" + cup(3, 6) + OC_TEXT + `${W}:${W}` + OC_RESET + "\x1b[K" + cup(9, 6));
  assert.deepEqual((await p.r.tuiLines()).slice(1, 3), ["     Done. $MDU:anymodel_inspecta1c6.result/1:3:", `     ${W}:${W}`], "fixture");
  const human = await p.r.humanLines();
  assert.deepEqual(human.slice(1, 5), want, `screen was:\n${human.join("\n")}`);
  assert.ok(!/MDU|a1c6|\/1:|45:45/.test(human.join("\n")), "no head, suffix or marker fragment");
  p.r.dispose();
});
