/**
 * screen-closeup.test — the reconciler's CLOSE UP rule (screen-reconcile.ts,
 * 2026-10-05): a value NARROWER than its token is never padded inside the
 * human's line. The stream filter pads it to the token's width (the TUI's
 * cursor math, filter.ts renderValue); the reconcile that follows shifts the
 * cells after the value left and erases the row's tail.
 *
 * The shapes come from the first-session tour (Claude Code 2.1.289, PTY
 * relay): `.env` holds `STRIPE_KEY=sk_live_fake_123456`, the model holds the
 * longer `$MDU:nomodel_Read[5c6e].STRIPE_KEY`, and the human read
 * `STRIPE_KEY='sk_live_fake_123456               '` — a key that looked
 * corrupted. The frames below are the TUI bytes the reply filter recorded in
 * its desymbolize events (the value is the tour's fake key).
 *
 * Each test runs the REAL pair, as run.ts wires them: the stream filter's
 * output (masked) feeds the human model, the reconcile's repaint follows,
 * and `wire` is every byte the human's terminal received.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ScreenReconciler } from "../../src/screen-reconcile.js";
import { ReplyStreamFilter, type ReplyResolver } from "../../src/filter.js";
import { renderScreen } from "./reserve-fixtures.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const TOKEN = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
const VALUE = "sk_live_fake_123456";
const ALT_ON = "\x1b[?1049h";
const cup = (row: number, col: number) => `\x1b[${row};${col}H`;
const cha = (col: number) => `\x1b[${col}G`;

/** The tour's reply frame (fullscreen renderer, 160×50): the two `.env` lines
 *  quoted back, at row 26, column 3. */
const TOUR_FRAME =
  `\x1b[H\r\x1b[2C\x1b[25B\x1b[38;5;153mSTRIPE_KEY='${TOKEN}'\r\x1b[2C\x1b[1BDEBUG=1\x1b[39m\x1b[48;1H\x1b[45;3H`;
/** The tour's tool row: the Bash call shown live under `Running…`. */
const TOUR_CURL =
  "\x1b[H\r\x1b[35B\x1b[38;5;246m \x1b[3G\x1b[39mRunning\x1b[11G\x1b[1m1\x1b[13G\x1b[22mshell\x1b[19Gcommand…\r\x1b[1B" +
  `\x1b[38;5;246m  ⎿  $ curl -sS https://api.stripe.com/v1/customers -u '${TOKEN}:' -d limit=100 -G\x1b[39m\x1b[48;1H\x1b[45;3H`;

class MockResolver implements ReplyResolver {
  calls: string[] = [];
  fail = false;
  constructor(private readonly table: Record<string, string>) {}
  async desymbolize(text: string): Promise<string> {
    this.calls.push(text);
    if (this.fail) throw new Error("arbiter down");
    let out = text;
    for (const [k, v] of Object.entries(this.table)) out = out.split(k).join(v);
    return out;
  }
}

function relay(table: Record<string, string>, opts: { cols?: number; rows?: number } = {}) {
  const cols = opts.cols ?? 80;
  const rows = opts.rows ?? 12;
  const resolver = new MockResolver(table);
  const streamTrace: Array<[string, string]> = [];
  const screenTrace: Array<[string, string]> = [];
  const filter = new ReplyStreamFilter(resolver, {
    eager: true,
    cols,
    onResolve: (b, a) => { streamTrace.push([b, a]); },
  });
  const r = new ScreenReconciler(resolver, {
    cols, rows, unknownRetryMs: 50,
    onResolve: (b, a) => { screenTrace.push([b, a]); },
  });
  let wire = "";
  const deliver = async (filtered: string): Promise<string> => {
    const out = await r.maskFragments(filtered);
    r.feedHuman(out);
    const rep = await r.reconcile();
    wire += out + rep;
    return rep;
  };
  return {
    r,
    resolver,
    streamTrace,
    screenTrace,
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

// ── the tour's captures ─────────────────────────────────────────────────────

test("tour capture, alternate screen: `STRIPE_KEY='sk_live_…'` reads with no inner padding", async () => {
  const p = relay({ [TOKEN]: VALUE }, { cols: 160, rows: 50 });
  await p.step(ALT_ON);
  const rep = await p.step(TOUR_FRAME);
  await p.end();
  assert.notEqual(rep, "", "the stream's padded splice is closed up by a repaint");
  const human = await p.r.humanLines();
  assert.equal(human[25], `  STRIPE_KEY='${VALUE}'`, `screen was:\n${human.join("\n")}`);
  assert.equal(human[26], "  DEBUG=1", "the next row is untouched");
  assert.ok(rep.endsWith(cup(45, 3)), "the cursor goes back where the TUI believes it is");
  assert.equal(await p.r.reconcile(), "", "converged: no second repaint");
  // What a real terminal shows for the whole wire.
  const real = await renderScreen(p.wire(), 160, 50);
  assert.equal(real[25], `  STRIPE_KEY='${VALUE}'`);
  assert.doesNotMatch(p.wire(), /\$MDU/, "no symbol byte on the wire");
  p.r.dispose();
});

test("tour capture, alternate screen: the live tool row `-u 'sk_live_…:'` closes up too", async () => {
  const p = relay({ [TOKEN]: VALUE }, { cols: 160, rows: 50 });
  await p.step(ALT_ON);
  await p.step(TOUR_CURL);
  const human = await p.r.humanLines();
  assert.equal(
    human[36],
    `  ⎿  $ curl -sS https://api.stripe.com/v1/customers -u '${VALUE}:' -d limit=100 -G`,
    `screen was:\n${human.join("\n")}`,
  );
  p.r.dispose();
});

test("the stream's trace (onResolve) reports the value without the pad; a close-up repaint reports nothing new", async () => {
  const p = relay({ [TOKEN]: VALUE }, { cols: 160, rows: 50 });
  await p.step(ALT_ON);
  await p.step(TOUR_FRAME);
  assert.equal(p.streamTrace.length, 1, "the stream reported its splice");
  assert.ok(p.streamTrace[0]![1].includes(`STRIPE_KEY='${VALUE}'`), `trace: ${JSON.stringify(p.streamTrace[0]![1])}`);
  assert.doesNotMatch(p.streamTrace[0]![1], new RegExp(`${VALUE} +'`), "no pad in the trace");
  assert.equal(p.screenTrace.length, 0, "the close-up is not a second resolution");
  p.r.dispose();
});

test("tour capture, MAIN screen (inline renderer): the row closes up with relative moves", async () => {
  const p = relay({ [TOKEN]: VALUE });
  const frame = `\r\n● Here are the lines:\r\n  STRIPE_KEY='${TOKEN}'\r\n  DEBUG=1\r\n\r\n> `;
  const rep = await p.step(frame);
  assert.equal(p.r.fullscreen, false);
  assert.notEqual(rep, "");
  assert.doesNotMatch(rep, /\x1b\[\d+;\d+H/, "the main screen is addressed relatively");
  const human = await p.r.humanLines();
  assert.equal(human[2], `  STRIPE_KEY='${VALUE}'`, `screen was:\n${human.join("\n")}`);
  assert.equal(human[3], "  DEBUG=1");
  assert.equal(await p.r.reconcile(), "", "converged");
  // On a terminal that already held a shell prompt above the relay.
  const real = await renderScreen("$ mandu claude\r\n" + p.wire(), 80, 13);
  assert.equal(real[3], `  STRIPE_KEY='${VALUE}'`, `real terminal was:\n${real.join("\n")}`);
  assert.equal(real[4], "  DEBUG=1");
  p.r.dispose();
});

// ── the shapes around it ────────────────────────────────────────────────────

test("mid-sentence, the renderer addressing each word with CHA: no gap before the next word", async () => {
  // `STRIPE_KEY = <token>. Mandu locks this value…`, Ink's per-word CHA at
  // the TUI's columns (the second tour reply showed ~30 spaces there).
  const p = relay({ [TOKEN]: VALUE }, { cols: 120 });
  await p.step(ALT_ON);
  const lead = "  STRIPE_KEY = ";
  const c0 = lead.length + TOKEN.length + 1; // 0-based column after `.`
  await p.step(`${cup(2, 1)}${lead}${TOKEN}.${cha(c0 + 2)}Mandu${cha(c0 + 8)}locks${cha(c0 + 14)}this${cup(10, 3)}`);
  const human = await p.r.humanLines();
  assert.equal(human[1], `  STRIPE_KEY = ${VALUE}. Mandu locks this`, `screen was:\n${human.join("\n")}`);
  assert.equal(await p.r.reconcile(), "");
  p.r.dispose();
});

test("two tokens on a row, both narrower: each closes up, the text between and after keeps its spacing", async () => {
  const A = "$MDU:nomodel_Read[aaaa].USER";
  const B = "$MDU:nomodel_Read[bbbb].PASS";
  const p = relay({ [A]: "bob", [B]: "hunter2" });
  await p.step(ALT_ON);
  await p.step(`${cup(1, 1)}user=${A} pass=${B} ok`);
  assert.equal((await p.r.humanLines())[0], "user=bob pass=hunter2 ok");
  p.r.dispose();
});

test("a narrower and a WIDER token on one row (alternate screen): close up, then shift right and clip", async () => {
  const S = "$MDU:Read[aaaa]";
  const L = "$MDU:Read[bbbb]";
  const long = "0123456789abcdefghijklmnop"; // 26 > 15
  const p = relay({ [S]: "ok", [L]: long }, { cols: 40 });
  await p.step(ALT_ON);
  await p.step(`${cup(1, 1)}${S} ${L} tail end`);
  // 2 + 1 + 26 + " tail end" = 38 columns: fits after the close-up.
  assert.equal((await p.r.humanLines())[0], `ok ${long} tail end`);
  p.r.dispose();
});

test("main screen: a row with a WIDER token too stays the stream's (its wrap-off splice, unchanged)", async () => {
  const S = "$MDU:Read[aaaa]";
  const L = "$MDU:Read[bbbb]";
  const long = "0123456789abcdefghijklmnop";
  const p = relay({ [S]: "ok", [L]: long }, { cols: 60 });
  const rep = await p.step(`\r\n${S} ${L} end\r\n`);
  assert.equal(rep, "", "no repaint: the main screen's widening path is the stream's alone");
  assert.equal((await p.r.humanLines())[1], `ok${" ".repeat(S.length - 2)} ${long} end`);
  p.r.dispose();
});

test("main screen: a value as wide as its token needs nothing (no repaint)", async () => {
  const T = "$MDU:Read[cccc]";
  const p = relay({ [T]: "x".repeat(T.length) });
  assert.equal(await p.step(`\r\nk=${T}!\r\n`), "");
  assert.equal((await p.r.humanLines())[1], `k=${"x".repeat(T.length)}!`);
  p.r.dispose();
});

test("wide (CJK) glyphs: a CJK value closes up by its display width; CJK text before the token keeps the columns", async () => {
  const T = "$MDU:Read[dddd]";
  const p = relay({ [T]: "秘密値" }, { cols: 40 }); // 6 columns < 15
  await p.step(ALT_ON);
  await p.step(`${cup(1, 1)}鍵: '${T}' 終`);
  assert.equal((await p.r.humanLines())[0], "鍵: '秘密値' 終");
  assert.equal(await p.r.reconcile(), "");
  p.r.dispose();
});

test("a later cell diff at the TUI's columns (the reply still streaming) converges to the closed-up row", async () => {
  // Frame 1 ends on the token; frame 2 appends `'` and a word where the TUI
  // believes the token ends (its own column), as Ink's diff does.
  const p = relay({ [TOKEN]: VALUE });
  await p.step(ALT_ON);
  await p.step(`${cup(3, 3)}STRIPE_KEY='${TOKEN}${cup(10, 3)}`);
  assert.equal((await p.r.humanLines())[2], `  STRIPE_KEY='${VALUE}`);
  const end = 2 + "STRIPE_KEY='".length + TOKEN.length; // 0-based column after the token
  await p.step(`${cup(3, end + 1)}' is the key${cup(10, 3)}`);
  const human = await p.r.humanLines();
  assert.equal(human[2], `  STRIPE_KEY='${VALUE}' is the key`, `screen was:\n${human.join("\n")}`);
  assert.equal(await p.r.reconcile(), "", "converged");
  // The TUI rewrites the row to prose: the owned row follows it, no value
  // glyph lingers past the new text.
  await p.step(`${cup(3, 3)}done.\x1b[K${cup(10, 3)}`);
  assert.equal((await p.r.humanLines())[2], "  done.");
  p.r.dispose();
});

test("a token split across a cell-diff repaint (the §19 shape) resolves and closes up", async () => {
  // Frame 1: a spinner whose cell under the hash's last glyph holds it;
  // frame 2: the token minus that cell (CHA over it), then `'` and more.
  const skip = TOKEN.indexOf("]") - 1;
  const p = relay({ [TOKEN]: VALUE });
  await p.step(ALT_ON);
  await p.step(`${cup(2, 1)}${"Reading the".padEnd(skip)}${TOKEN[skip]}...`);
  await p.step(`${cup(2, 1)}${TOKEN.slice(0, skip)}${cha(skip + 2)}${TOKEN.slice(skip + 1)}' next\x1b[K${cup(10, 3)}`);
  await p.end();
  const human = await p.r.humanLines();
  assert.equal(human[1], `${VALUE}' next`, `screen was:\n${human.join("\n")}`);
  assert.doesNotMatch(p.wire(), /\$MDU/, "no symbol byte on the wire");
  p.r.dispose();
});

test("arbiter down: nothing to close up — the token stays opaque, no repaint (utility posture)", async () => {
  const p = relay({ [TOKEN]: VALUE });
  p.resolver.fail = true;
  await p.step(ALT_ON);
  await p.step(`${cup(1, 1)}KEY='${TOKEN}'`);
  // The alternate screen masks the run on the wire and restores the TUI's
  // own cells one reconcile later: the token, never a value.
  await p.end();
  await p.r.reconcile();
  assert.equal((await p.r.humanLines())[0], `KEY='${TOKEN}'`);
  assert.ok(!p.wire().includes(VALUE), "no value can appear without the arbiter");
  p.r.dispose();
});

test("main screen, arbiter down: the stream's raw bytes stand, no repaint", async () => {
  const p = relay({ [TOKEN]: VALUE });
  p.resolver.fail = true;
  assert.equal(await p.step(`\r\nKEY='${TOKEN}'\r\n`), "");
  assert.equal((await p.r.humanLines())[1], `KEY='${TOKEN}'`);
  p.r.dispose();
});

test("main screen under a scroll region (Codex's history insert): the close-up waits until the region is reset", async () => {
  const p = relay({ [TOKEN]: VALUE });
  // The row lands while the TUI holds DECSTBM 1..4 (a partial region).
  assert.equal(await p.step(`\x1b[1;4r\x1b[2;1HKEY='${TOKEN}' end`), "", "no relative repaint inside a region");
  assert.equal((await p.r.humanLines())[1], `KEY='${VALUE}${" ".repeat(TOKEN.length - VALUE.length)}' end`, "the stream's padded form, for now");
  // The region is reset and the cursor parked: the next reconcile closes up.
  await p.step("\x1b[r\x1b[10;1H");
  assert.equal((await p.r.humanLines())[1], `KEY='${VALUE}' end`);
  const real = await renderScreen(p.wire(), 80, 12);
  assert.equal(real[1], `KEY='${VALUE}' end`);
  p.r.dispose();
});
