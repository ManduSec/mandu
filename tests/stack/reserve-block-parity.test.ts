/**
 * reserve-block-parity.test.ts — ONE reserve-block grammar in two packages
 * (docs/design/ui/reply-row-reservation.md §3.1, §3.4, §3.7, §12 the span form,
 * §14 the break field).
 *
 * The proxy (interceptors/anthropic-proxy/src/reserve-block.ts) EMITS a
 * reserve block in place of a multi-line token alone on its line and
 * collapses it on the next request; the reply filter
 * (interceptors/reply-filter/src/reserve-block.ts + the stream filter)
 * RECOGNIZES it and paints each row. The two packages are independent roots,
 * so the grammar is a local copy in each. A drift would let the proxy hand
 * Claude Code a block the filter paints raw (the human sees `$MDU/…` rows),
 * or a pipe-mode filter print something else than the value the model named.
 * This file drives both packages' exports with one generated table:
 *   - tokens the arbiter really mints (symbol-format.ts `generate`: every
 *     level marker, fields, a canonical-encoded field), their Markdown-escaped
 *     spellings, and hashes of 4 to 8 hex digits;
 *   - value line counts 2..40 and past 40, caps 2..200;
 *   - the proxy's expandText / reserveBlock output is recognized by the
 *     filter's findHeads / findContinuations as EXACTLY the head and rows
 *     2..N, with the token's hash, each row's index and N;
 *   - the filter's PIPE-mode rendering of a block equals the value the
 *     proxy's collapse names (collapse, then the token's value);
 *   - the token grammar is one regex source in the proxy, the filter's
 *     recognizer and the filter's stream scanner, and they accept the same
 *     lines over a seeded corpus.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stateAxes } from "../lib/axes.js";
import * as proxy from "../../interceptors/anthropic-proxy/src/reserve-block.js";
import * as filterBlock from "../../interceptors/reply-filter/src/reserve-block.js";
import { layoutRows } from "../../interceptors/reply-filter/src/reserve-layout.js";
import { ReplyStreamFilter, SYMBOL_TOKEN_RE } from "../../interceptors/reply-filter/src/filter.js";
import { MDU_SYM_FORMAT } from "../../arbiter/symbol-table/symbol-format.js";

stateAxes("secrets"); // the grammar reads no axis; a secret's multi-line value is what it reserves rows for

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (p: string): string => readFileSync(join(ROOT, p), "utf8");

// ── the generated table ──────────────────────────────────────────────────────

/** A Markdown writer's spelling: `$` and every `_` backslash-escaped. */
const mdEscape = (t: string): string => t.replace(/\$/g, "\\$").replace(/_/g, "\\_");

const HASHES = ["464e", "0c3d9", "a1b2c3", "0badc0d", "0c3d9e2f"];
const MINTED: string[] = HASHES.flatMap((hash) => [
  MDU_SYM_FORMAT.generate({ tool: "Bash", hash, level: "no-model" }),
  MDU_SYM_FORMAT.generate({ tool: "Read", hash, level: "local-model", field: "DB_PASSWORD" }),
  MDU_SYM_FORMAT.generate({ tool: "Bash", hash, level: "any-model", field: "stdout" }),
  MDU_SYM_FORMAT.generate({ tool: "mcp__github__get_file", hash, field: "api-key" }),
  MDU_SYM_FORMAT.generate({ tool: "exec_command", hash }),
]);
/** A field path with an index and a nested field (the grammar's `[`, `]`, `.`). */
const HAND = ["$MDU:nomodel_Read[5e1a].items[0].key", "$MDU:inspect[8c1d].result"];
const CANONICAL = [...MINTED, ...HAND];
/** Every spelling the proxy may see in the model's text. */
const TOKENS = [...CANONICAL, ...CANONICAL.map(mdEscape), ...CANONICAL.map((t) => t.replace(/^\$/, "\\$"))];

const canonicalOf = (t: string): string => t.replace(/\\/g, "");
const hashOf = (t: string): string => /\[([0-9a-f]{4,8})\]/.exec(canonicalOf(t))![1]!;

/** A multi-line value of `n` lines (indent, a blank line and a TAB inside). */
function valueOf(n: number, trailingNl: boolean): string {
  const lines = Array.from({ length: n }, (_, i) =>
    i === 1 && n > 2 ? "" : i % 3 === 0 ? `  HostName host-${i}.example\tport ${i}` : `line ${i + 1} of ${n}`);
  return lines.join("\n") + (trailingNl ? "\n" : "");
}

const COUNTS = [2, 3, 5, 7, 12, 23, 39, 40, 41, 57, 120, 199, 200, 201, 250];
const CAPS = [2, 3, 8, 24, 40, 41, 100, 199, 200];

/** The rows the proxy reserves, as the grammar pins them. */
const expectedRows = (lines: number, cap: number): number => Math.min(lines, cap, 200);

// ── recognition: what the proxy emits, the filter reads back exactly ─────────

function assertRecognized(text: string, token: string, n: number, blockStart: number, at: string): void {
  const heads = filterBlock.findHeads(text);
  assert.equal(heads.length, 1, `${at}: one head: ${JSON.stringify(heads)}`);
  const h = heads[0]!;
  assert.equal(h.index, blockStart, `${at}: the head starts the block`);
  assert.equal(h.length, token.length + `/1:${n}`.length, `${at}: the head spans T/1:N`);
  assert.equal(h.canonical, canonicalOf(token), `${at}: canonical token`);
  assert.equal(h.hash, hashOf(token), `${at}: hash`);
  assert.equal(h.n, n, `${at}: N`);
  const conts = filterBlock.findContinuations(text);
  assert.equal(conts.length, n - 1, `${at}: N-1 continuation rows`);
  const rowLines = text.slice(blockStart).split("\n").slice(1, n);
  let offset = blockStart + token.length + `/1:${n}`.length;
  conts.forEach((c, k) => {
    offset += 1; // the `\n`
    assert.equal(c.i, k + 2, `${at}: row index`);
    assert.equal(c.hash, hashOf(token), `${at}: row hash`);
    assert.equal(c.index, offset, `${at}: row ${k + 2} offset`);
    assert.equal(c.length, rowLines[k]!.length, `${at}: row ${k + 2} spans its whole line`);
    offset += c.length;
  });
}

test("every token × line count × cap: the proxy's block is recognized by the filter as exactly head + rows 2..N", () => {
  let checked = 0;
  for (const token of TOKENS) {
    for (const lines of COUNTS) {
      for (const cap of CAPS) {
        const n = expectedRows(lines, cap);
        const block = proxy.reserveBlock(token, n);
        // The filter's own emitter mirror agrees byte for byte.
        assert.equal(filterBlock.formatBlock(token, lines, Math.min(cap, 200)), block, `formatBlock(${token}, ${lines}, ${cap})`);
        // expandText in context: prose above and below, the token alone on its line.
        const before = "Here is the file:\n\n";
        const text = `${before}${token}\n\nDONE`;
        const shapes = new Map([[canonicalOf(token), lines]]);
        const expanded = proxy.expandText(text, shapes, cap);
        assert.equal(expanded, `${before}${block}\n\nDONE`, `expandText(${token}, ${lines}, ${cap})`);
        assertRecognized(expanded, token, n, before.length, `${token} lines=${lines} cap=${cap}`);
        // Block edges: the token opening and closing the text.
        assertRecognized(proxy.expandText(token, shapes, cap), token, n, 0, `${token} alone`);
        // The proxy collapses its own block back to the token, byte for byte.
        assert.equal(proxy.collapseText(expanded), text, `collapse(expand(t)) === t for ${token}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 1000, `the table is not trivially small (${checked})`);
});

test("the cap row: N = min(lines, cap); a capped block's last row carries the `+K more lines` note on the filter side", () => {
  for (const token of CANONICAL) {
    for (const lines of COUNTS) {
      for (const cap of CAPS) {
        const n = expectedRows(lines, cap);
        const value = valueOf(lines, true);
        const vl = filterBlock.valueLines(value);
        assert.equal(vl.length, lines, "the filter counts lines as the proxy's symbolShape does (one trailing newline dropped)");
        const head = filterBlock.findHeads(proxy.reserveBlock(token, n))[0]!;
        const rows = Array.from({ length: head.n }, (_, k) => filterBlock.reserveRowText(vl, k + 1, head.n));
        if (lines > n) {
          assert.deepEqual(rows.slice(0, n - 1), vl.slice(0, n - 1));
          assert.equal(rows[n - 1], filterBlock.moreLinesNote(lines - (n - 1)));
        } else {
          assert.deepEqual(rows, vl);
        }
      }
    }
  }
});

test("a one-line value, an unknown token or a token inside a sentence: no block, and the filter sees no head or row", () => {
  for (const token of TOKENS) {
    for (const [text, shapes] of [
      [`a\n${token}\nb`, new Map([[canonicalOf(token), 1]])],
      [`a\n${token}\nb`, new Map<string, number>()],
      [`see ${token}\nb`, new Map([[canonicalOf(token), 5]])],
      [`a\n${token} here`, new Map([[canonicalOf(token), 5]])],
      [`a\n${token}.`, new Map([[canonicalOf(token), 5]])],
    ] as Array<[string, Map<string, number>]>) {
      const out = proxy.expandText(text, shapes, 40);
      assert.equal(out, text, `no expansion for ${JSON.stringify(text)}`);
      assert.deepEqual(filterBlock.findHeads(out), []);
      assert.deepEqual(filterBlock.findContinuations(out), []);
    }
  }
});

// ── pipe mode: the filter's collapse of a block = the proxy's collapse ───────

/** A resolver over a fixed table: every whole token the grammar finds is
 *  looked up by its EXACT name (the arbiter never resolves a name it did not
 *  allocate, so a field token glued to the next line's word stays unknown). */
function resolverOver(values: Map<string, string>): { desymbolize(text: string): Promise<string> } {
  const re = new RegExp(filterBlock.TOKEN_SOURCE, "g");
  return {
    async desymbolize(text: string): Promise<string> {
      return text.replace(re, (m) => values.get(m.replace(/\\/g, "")) ?? m);
    },
  };
}

async function pipeRender(text: string, values: Map<string, string>, chunks: number): Promise<string> {
  const f = new ReplyStreamFilter(resolverOver(values));
  const size = Math.max(1, Math.ceil(text.length / chunks));
  let out = "";
  for (let i = 0; i < text.length; i += size) out += await f.write(text.slice(i, i + size));
  return out + (await f.flush());
}

test("PIPE mode: the filter's rendering of a block is the value the proxy's collapse names (every token, capped too)", async () => {
  for (const token of TOKENS) {
    for (const lines of [2, 5, 23, 40, 57]) {
      for (const trailingNl of [false, true]) {
        const value = valueOf(lines, trailingNl);
        const values = new Map([[canonicalOf(token), value]]);
        const text = `Here is the file:\n\n${token}\n\nDONE\n`;
        const expanded = proxy.expandText(text, new Map([[canonicalOf(token), lines]]), 40);
        assert.notEqual(expanded, text, "precondition: expanded");
        const collapsed = proxy.collapseText(expanded);
        assert.equal(collapsed, text);
        // What the collapse names, as the block's own rows count it: the
        // value with its one trailing newline dropped (the block's line break
        // follows it). The whole value, even past the cap.
        const want = collapsed.split(token).join(value.replace(/\n$/, ""));
        for (const chunks of [1, 3, 17]) {
          const got = await pipeRender(expanded, values, chunks);
          assert.equal(got, want, `pipe render of ${token} (${lines} lines, trailing NL ${trailingNl}, ${chunks} chunks)`);
          assert.ok(!got.includes("$MDU"), "no marker or token left for the human");
        }
        if (!trailingNl) {
          // A value without a trailing newline: byte-identical to piping the
          // collapsed text (today's rendering of the bare token).
          assert.equal(await pipeRender(expanded, values, 1), await pipeRender(collapsed, values, 1));
        }
      }
    }
  }
});

test("PIPE mode without the value: the filter shows the token and the count, never a row marker or a guess", async () => {
  const token = CANONICAL[0]!;
  const expanded = proxy.expandText(`x\n${token}\ny\n`, new Map([[token, 4]]), 40);
  const got = await pipeRender(expanded, new Map(), 1);
  assert.equal(got, `x\n${filterBlock.unknownHeadText(token, 4)}\ny\n`);
});

// ── one token grammar ────────────────────────────────────────────────────────

test("the token grammar is ONE regex source: the proxy's TOKEN_SRC, the filter's TOKEN_SOURCE and SYMBOL_TOKEN_RE", () => {
  const src = read("interceptors/anthropic-proxy/src/reserve-block.ts");
  const m = /^const TOKEN_SRC =\s*String\.raw`([^`]+)`;$/m.exec(src);
  assert.ok(m, "the proxy declares TOKEN_SRC as a String.raw literal");
  assert.equal(m[1], filterBlock.TOKEN_SOURCE, "proxy TOKEN_SRC === reply-filter TOKEN_SOURCE");
  assert.equal(SYMBOL_TOKEN_RE.source, filterBlock.TOKEN_SOURCE, "reply-filter SYMBOL_TOKEN_RE === TOKEN_SOURCE");
  // The continuation-row and head-suffix shapes, as each side spells them.
  assert.match(src, /const MARKER_ANY_RE = \/\\\$MDU\\\/\[0-9a-f\]\{4,8\}\\\/\[0-9\]\+\/g;/);
  assert.equal(filterBlock.CONT_RE.source, String.raw`\$MDU\/([0-9a-f]{4,8})\/([1-9][0-9]{0,2})(?![0-9])`);
  // The limits and the cap parse agree.
  assert.equal(proxy.RESERVE_MAX_LIMIT, filterBlock.RESERVE_ROWS_LIMIT);
  assert.equal(proxy.RESERVE_MAX_ROWS, filterBlock.RESERVE_MAX_ROWS_DEFAULT);
  for (const raw of [undefined, "", "0", "1", "2", "40", "41", "200", "201", " 7 ", "x", "-3", "4.5", "0040"]) {
    assert.equal(proxy.parseReserveMax(raw), filterBlock.reserveMaxRows({ MANDU_REPLY_RESERVE_MAX: raw }), `cap parse of ${JSON.stringify(raw)}`);
  }
  for (const raw of [undefined, "", "0", "1", "no"]) {
    assert.equal(proxy.reserveEnabled(raw), filterBlock.reserveEnabled({ MANDU_REPLY_RESERVE: raw }), `kill switch parse of ${JSON.stringify(raw)}`);
  }
});

test("a non-canonical block (leading zeros, a wrong hash or index, N out of range): the proxy does not collapse it, the filter does not see that head or row", () => {
  const T = CANONICAL[0]!;
  const h = hashOf(T);
  const cases: Array<[string, { heads: number; rows: number }]> = [
    [`${T}/1:03\n$MDU/${h}/2\n$MDU/${h}/3`, { heads: 0, rows: 2 }],
    [`${T}/1:3\n$MDU/${h}/02\n$MDU/${h}/3`, { heads: 1, rows: 1 }],
    [`${T}/1:3\n$MDU/${h}/2\n$MDU/${h}/03`, { heads: 1, rows: 1 }],
    [`${T}/1:3\n$MDU/${h}/3\n$MDU/${h}/2`, { heads: 1, rows: 2 }],
    [`${T}/1:3\n$MDU/beef/2\n$MDU/beef/3`, { heads: 1, rows: 2 }],
    [`${T}/1:1`, { heads: 0, rows: 0 }],
    [`${T}/1:201\n$MDU/${h}/2`, { heads: 0, rows: 1 }],
  ];
  for (const [text, want] of cases) {
    assert.equal(proxy.collapseText(text), text, `the proxy leaves ${JSON.stringify(text)} for the strip`);
    assert.equal(filterBlock.findHeads(text).length, want.heads, `filter heads in ${JSON.stringify(text)}`);
    assert.equal(filterBlock.findContinuations(text).length, want.rows, `filter rows in ${JSON.stringify(text)}`);
    // And the strip leaves no fragment the filter would still read as one.
    const stripped = proxy.stripResiduals(text).text;
    assert.deepEqual(filterBlock.findHeads(stripped), [], `no head survives the strip: ${JSON.stringify(stripped)}`);
    assert.deepEqual(filterBlock.findContinuations(stripped), [], `no row survives the strip: ${JSON.stringify(stripped)}`);
  }
});

test("the proxy (a line alone) and the filter (anchored TOKEN_SOURCE) accept the same lines over a seeded corpus", () => {
  const anchored = new RegExp(`^${filterBlock.TOKEN_SOURCE}$`);
  const alphabet = ["$", "M", "D", "U", ":", "\\", "_", "[", "]", ".", "a", "Z", "0", "9", "f", "/", "1"];
  let seed = 0x5eed0b1;
  const rand = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const corpus: string[] = [...TOKENS, ...TOKENS.map((t) => t + "/1:3"), ...TOKENS.map((t) => t.slice(0, -1))];
  for (let i = 0; i < 20000; i++) {
    // Half the corpus starts from a real token prefix, so the grammar's
    // interesting region is actually reached.
    let s = rand(2) === 0 ? "$MDU:" : TOKENS[rand(TOKENS.length)]!.slice(0, rand(12));
    const len = rand(16);
    for (let j = 0; j < len; j++) s += alphabet[rand(alphabet.length)];
    corpus.push(s);
  }
  let accepted = 0;
  for (const line of corpus) {
    if (line.includes("\n")) continue;
    const p = proxy.standaloneTokens(line).length === 1;
    const f = anchored.test(line);
    assert.equal(p, f, `the two grammars disagree on ${JSON.stringify(line)}`);
    if (p) accepted++;
  }
  assert.ok(accepted > TOKENS.length, `the corpus reaches accepted tokens beyond the seeds (${accepted})`);
});

// ── v2: the width-carrying head and blocks inside a line (§11.3) ─────────────

test("v2 heads: every layout the proxy may emit, the filter reads back with the same N, W and F", () => {
  let seed = 0x11a2;
  const rand = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  for (let k = 0; k < 3000; k++) {
    const T = TOKENS[rand(TOKENS.length)]!;
    const W = proxy.RESERVE_MIN_WIDTH + rand(proxy.RESERVE_MAX_WIDTH - proxy.RESERVE_MIN_WIDTH + 1);
    const half = Math.ceil(W / 2);
    const F = rand(4) === 0 ? 0 : half + rand(W - half + 1);
    assert.ok(proxy.validLayout(W, F));
    const n = 2 + rand(proxy.RESERVE_MAX_LIMIT - 1);
    const block = proxy.reserveBlock(T, n, { width: W, first: F });
    const heads = filterBlock.findHeads(block);
    assert.equal(heads.length, 1, block.slice(0, 80));
    assert.deepEqual([heads[0]!.n, heads[0]!.w, heads[0]!.f], [n, W, F]);
    assert.equal(filterBlock.findContinuations(block).length, n - 1);
    // Inside a line: prefix and suffix around it collapse back byte-exact.
    const text = `pre ${T}${block.slice(T.length)} tail.`;
    assert.equal(proxy.collapseText(text), `pre ${T} tail.`);    // The span form (§12): the same head and rows, each row its own code
    // span; the filter reads them alike, the proxy collapses to the span.
    const span = proxy.reserveBlock(T, n, { width: W, first: F }, true);
    const sh = filterBlock.findHeads(span);
    assert.equal(sh.length, 1, span.slice(0, 80));
    assert.deepEqual([sh[0]!.n, sh[0]!.w, sh[0]!.f], [n, W, F]);
    assert.equal(filterBlock.findContinuations(span).length, n - 1);
    assert.equal(proxy.collapseText(`pre \`${span}\`, tail.`), `pre \`${T}\`, tail.`);
    // §14: a head with a break field reads the same; the break goes on collapse.
    const K = 1 + rand(9999);
    const brk = proxy.reserveBlock(T, n, { width: W, first: F }, false, K);
    const bh = filterBlock.findHeads(brk);
    assert.equal(bh.length, 1, brk.slice(0, 80));
    assert.deepEqual([bh[0]!.n, bh[0]!.w, bh[0]!.f], [n, W, F]);
    assert.equal(bh[0]!.length, brk.indexOf("\n"), "the head spans `:K`");
    const tail = "x".repeat(K);
    assert.equal(proxy.collapseText(`pre ${brk}${tail}\nrest`), `pre ${T}${tail}rest`);    // A head-only block (N = 1, §14): the filter reads it, the proxy collapses it.
    const one = proxy.reserveBlock(T, 1, { width: W, first: F === 0 ? W : F }, false, K);
    const oh = filterBlock.findHeads(one);
    assert.equal(oh.length, 1, one);
    assert.equal(oh[0]!.n, 1);
    assert.equal(proxy.collapseText(`pre ${one}${tail}\nrest`), `pre ${T}${tail}rest`);
  }
  // A layout the proxy refuses is not a head on the filter either.
  const T = CANONICAL[0]!;
  for (const [W, F] of [[19, 19], [1001, 1001], [80, 1], [80, 39], [80, 81]] as const) {
    assert.equal(proxy.validLayout(W, F), false, `${W}:${F}`);
    assert.deepEqual(filterBlock.findHeads(`${T}/1:3:${W}:${F}\n$MDU/${hashOf(T)}/2`), [], `${W}:${F}`);
  }
});

test("v2 PIPE mode: a block inside a sentence reads as the sentence the model wrote, the value in place of T", async () => {
  const T = CANONICAL[0]!;
  const value = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho";
  const W = 40;
  const F = 27;
  const n = layoutRows(value, W, F).length;
  assert.ok(n >= 2, "precondition: the value wraps");
  const text = `The value is ${T} and that is all.\n`;
  const expanded = text.replace(T, proxy.reserveBlock(T, n, { width: W, first: F }));
  assert.equal(proxy.collapseText(expanded), text);
  for (const chunks of [1, 3, 17, expanded.length]) {
    const got = await pipeRender(expanded, new Map([[T, value]]), chunks);
    assert.equal(got, `The value is ${value} and that is all.\n`, `${chunks} chunks`);
  }
});
