/**
 * reserve-block.test — the reply row reservation grammar (src/reserve-block.ts;
 * docs/design/ui/reply-row-reservation.md §3.1, §3.2 item 4, §3.4): the block
 * shape, which tokens stand alone, the collapse(expand(t)) === t property over
 * generated text, and the residual strip; v2 (§11.3): the `T/1:N:W:F` head,
 * blocks inside a line, and the property over mid-line tokens, suffixes, list
 * items and fences.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  RESERVE_MAX_ROWS,
  RESERVE_MAX_LIMIT,
  applyExpansions,
  canonicalToken,
  findTokens,
  reserveHeadSuffix,
  validLayout,
  type TokenExpansion,
  collapseText,
  collapseTextCounted,
  expandText,
  parseReserveMax,
  reserveBlock,
  reserveEnabled,
  reserveRows,
  standaloneTokens,
  stripResiduals,
  tokenHash,
} from "../../src/reserve-block.js";

const T = "$MDU:nomodel_Bash[464e]";
const T_ESC = "\\$MDU:nomodel\\_Bash[464e]";
const T_FIELD = "$MDU:inspect[695b].result";
const T2 = "$MDU:anymodel_Read[a1b2c3]";

test("the block: head T/1:N, then rows $MDU/<hash>/2..N, one per line", () => {
  assert.equal(reserveBlock(T, 3), `${T}/1:3\n$MDU/464e/2\n$MDU/464e/3`);
  assert.equal(reserveBlock(T_ESC, 2), `${T_ESC}/1:2\n$MDU/464e/2`, "the head keeps the escaped spelling; the hash is unescaped");
  assert.equal(reserveBlock(T_FIELD, 2), `${T_FIELD}/1:2\n$MDU/695b/2`);
  assert.equal(tokenHash("$MDU:x[abcd].__mdu_split[3]"), "abcd", "the base hash, not a field index");
  assert.equal(canonicalToken(T_ESC), T);
});

test("cap: MANDU_REPLY_RESERVE_MAX is an integer 2..200, else 40; the kill switch is exactly 0", () => {
  assert.equal(RESERVE_MAX_ROWS, 40);
  assert.equal(parseReserveMax(undefined), 40);
  assert.equal(parseReserveMax("2"), 2);
  assert.equal(parseReserveMax("200"), 200);
  for (const bad of ["1", "0", "201", "-3", "4.5", "abc", "", " ", "1e2"]) assert.equal(parseReserveMax(bad), 40, bad);
  assert.equal(reserveEnabled(undefined), true);
  assert.equal(reserveEnabled("1"), true);
  assert.equal(reserveEnabled("0"), false);
  assert.equal(reserveEnabled(" 0 "), false);
  assert.equal(reserveRows(5, 40), 5);
  assert.equal(reserveRows(99, 40), 40);
  assert.equal(reserveRows(1, 40), 0, "a one-line value is not expanded");
  assert.equal(reserveRows(2.5, 40), 0);
  assert.equal(reserveRows(5, 1), 0, "a cap below 2 never expands");
  assert.equal(reserveRows(500, 999), RESERVE_MAX_LIMIT);
});

test("standalone: line and block edges, escaped tokens, field paths; mid-sentence tokens are not", () => {
  const at = (text: string, edges?: Parameters<typeof standaloneTokens>[1]) => standaloneTokens(text, edges).map((c) => c.token);
  assert.deepEqual(at(T), [T], "the whole text");
  assert.deepEqual(at(`intro:\n${T}\nafter`), [T]);
  assert.deepEqual(at(`${T}\n`), [T]);
  assert.deepEqual(at(`a\n${T_ESC}\nb`), [T_ESC], "Markdown-escaped");
  assert.deepEqual(at(`a\n${T_FIELD}`), [T_FIELD], "field path, at the block end");
  assert.deepEqual(at(`see ${T} here`), []);
  assert.deepEqual(at(`see ${T}\nx`), [], "not at a line start");
  assert.deepEqual(at(`${T}.\nx`), [], "a sentence dot after the base is not the token");
  assert.deepEqual(at(`${T} \nx`), [], "a trailing space");
  assert.deepEqual(at(`${T}\r\nx`), [], "CRLF: the next char is \\r, not \\n");
  assert.deepEqual(at(`- ${T}\n`), [], "a list item");
  assert.deepEqual(at(`${T}${T2}\n`), [], "two tokens on one line");
  assert.deepEqual(at(`${T}\n${T2}`), [T, T2], "adjacent standalone tokens");
  assert.deepEqual(at(T, { lineStart: false }), [], "a region that does not start a line");
  assert.deepEqual(at(`x\n${T}`, { textEnd: false }), [], "a region whose end is not the block end");
  assert.deepEqual(at(`x\n${T}\n`, { textEnd: false }), [T]);
  const c = standaloneTokens(`ab\n${T_ESC}\n`)[0]!;
  assert.deepEqual([c.start, c.end, c.canonical, c.hash], [3, 3 + T_ESC.length, T, "464e"]);
});

test("expand: only standalone tokens with ≥ 2 lines, N = min(lines, cap)", () => {
  const shapes = new Map([[T, 3], [T2, 1], [T_FIELD, 100]]);
  assert.equal(expandText(`Here:\n${T}\nDone.`, shapes, 40), `Here:\n${T}/1:3\n$MDU/464e/2\n$MDU/464e/3\nDone.`);
  assert.equal(expandText(`see ${T} here`, shapes, 40), `see ${T} here`, "mid-sentence: untouched");
  assert.equal(expandText(`${T2}\n`, shapes, 40), `${T2}\n`, "one line: untouched");
  assert.equal(expandText(`${T_ESC}`, shapes, 40), reserveBlock(T_ESC, 3), "escaped: looked up by canonical spelling");
  const capped = expandText(T_FIELD, shapes, 4);
  assert.equal(capped, `${T_FIELD}/1:4\n$MDU/695b/2\n$MDU/695b/3\n$MDU/695b/4`);
  assert.equal(expandText(`${"$MDU:unknown[ffff]"}\n`, shapes, 40), "$MDU:unknown[ffff]\n", "unknown shape: untouched");
});

test("collapse: a well-formed block → T; anything else is left alone", () => {
  const block = reserveBlock(T, 4);
  assert.equal(collapseText(block), T);
  assert.equal(collapseText(`pre\n${block}\npost`), `pre\n${T}\npost`);
  assert.deepEqual(collapseTextCounted(`${block}\n${reserveBlock(T2, 2)}`), { text: `${T}\n${T2}`, collapsed: 2 });
  const malformed = [
    `${T}/1:4\n$MDU/464e/2\n$MDU/464e/3`, // a row missing
    `${T}/1:3\n$MDU/464e/2\n$MDU/464e/4`, // wrong index
    `${T}/1:2\n$MDU/beef/2`, // wrong hash
    `${T}/1:2\n $MDU/464e/2`, // indented row
    `${T}/1:1`, // N < 2
    `${T}/1:02\n$MDU/464e/2`, // leading zero
    `${T}/1:2\n$MDU/464e/23`, // the last row runs on into a digit
    `${T}/1:2:80\n$MDU/464e/2`, // a truncated v2 head
    `${T}/1:2\r\n$MDU/464e/2`, // CRLF: rows are joined by \n only
    `${T}/1:${RESERVE_MAX_LIMIT + 1}`,
  ];
  for (const m of malformed) assert.equal(collapseText(m), m, JSON.stringify(m));
  // v2 (§11.3): a block collapses wherever it stands — a head after prefix
  // text, a last row followed by suffix text that is not a digit.
  assert.equal(collapseText(`x ${T}/1:2\n$MDU/464e/2`), `x ${T}`, "head after prefix text");
  assert.equal(collapseText(`${T}/1:2\n$MDU/464e/2x`), `${T}x`, "suffix after the last row");
  // A block followed by an extra row: the block collapses, the row is left for the strip.
  assert.equal(collapseText(`${reserveBlock(T, 2)}\n$MDU/464e/3`), `${T}\n$MDU/464e/3`);
});

// ── the property: collapse(expand(t)) === t over generated text ──────────────

/** Small seeded PRNG (mulberry32), so a failure reproduces. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const TOKENS = [T, T_ESC, T_FIELD, T2, "$MDU:localmodel_Read[0a1b].stdout", "\\$MDU:web\\_fetch[beef].text.most\\_mentioned", "$MDU:Grep[cafe01]"];
const WORDS = ["the", "file", "Host", "a", "  HostName", "10.0.0.1", "$5.00", "total: $", "/1:3", "#", "- item", "```", "`code`", "\\", "é", "🔑", "[x]", ".", "MDU", "$MDU", "$MDU:"];

function genText(r: () => number): string {
  const lines: string[] = [];
  const n = 1 + Math.floor(r() * 8);
  for (let i = 0; i < n; i++) {
    const kind = r();
    if (kind < 0.3) lines.push(TOKENS[Math.floor(r() * TOKENS.length)]!); // standalone
    else if (kind < 0.4) lines.push("");
    else {
      const w: string[] = [];
      const k = 1 + Math.floor(r() * 6);
      for (let j = 0; j < k; j++) {
        w.push(r() < 0.25 ? TOKENS[Math.floor(r() * TOKENS.length)]! : WORDS[Math.floor(r() * WORDS.length)]!);
      }
      lines.push(w.join(r() < 0.5 ? " " : ""));
    }
  }
  const eol = r() < 0.2 ? "\r\n" : "\n";
  let t = lines.join(eol);
  if (r() < 0.3) t += eol;
  return t;
}

test("property: collapse(expand(t)) === t byte for byte (2000 generated texts, varied shapes and caps)", () => {
  const r = rng(0x5eed);
  let expandedSome = 0;
  for (let i = 0; i < 2000; i++) {
    const t = genText(r);
    const shapes = new Map<string, number>();
    for (const tok of TOKENS) if (r() < 0.8) shapes.set(canonicalToken(tok), Math.floor(r() * 60));
    const cap = [2, 3, 40, 200][Math.floor(r() * 4)]!;
    const e = expandText(t, shapes, cap);
    if (e !== t) expandedSome++;
    assert.equal(collapseText(e), t, `seed case ${i}: ${JSON.stringify(t)}`);
    // …and the strip never touches a text holding no fragment of its own.
    if (!/\/1:\d|\$MDU\/[0-9a-f]{4,8}\/\d/.test(t)) assert.equal(stripResiduals(t).text, t);
  }
  assert.ok(expandedSome > 500, `the generator must exercise expansion (${expandedSome})`);
});

test("property holds on hand-picked edges: block start/end, adjacent tokens, CRLF, lone escape", () => {
  const shapes = new Map([[T, 3], [T2, 2], [T_FIELD, 5]]);
  for (const t of [
    T, `${T}\n`, `\n${T}`, `${T}\n${T2}`, `${T}\n\n${T2}\n`, `${T}\r\n${T2}`, `a\r\n${T}\r\n`,
    `${T_ESC}\n${T_FIELD}`, `\\\n${T}`, `x\n${T}\n${T}\n${T}`, "", "\n", "no tokens at all",
  ]) {
    assert.equal(collapseText(expandText(t, shapes, 40)), t, JSON.stringify(t));
  }
});

// ── residual strip ───────────────────────────────────────────────────────────

test("strip: head suffixes and continuation markers, whole lines with their line break", () => {
  assert.deepEqual(stripResiduals(`${T}/1:3`), { text: T, removed: 1 });
  assert.deepEqual(stripResiduals(`${T_ESC}/1:12 and more`), { text: `${T_ESC} and more`, removed: 1 });
  assert.deepEqual(stripResiduals(`a\n$MDU/464e/2\nb`), { text: "a\nb", removed: 1 });
  assert.deepEqual(stripResiduals(`$MDU/464e/2\nb`), { text: "b", removed: 1 }, "at the text start: the following break goes");
  assert.deepEqual(stripResiduals(`$MDU/464e/2\n$MDU/464e/3\nb`), { text: "b", removed: 2 });
  assert.deepEqual(stripResiduals(`a\n$MDU/464e/2`), { text: "a", removed: 1 });
  assert.deepEqual(stripResiduals(`a\r\n$MDU/464e/2\r\nb`), { text: "a\r\nb", removed: 1 }, "CRLF");
  assert.deepEqual(stripResiduals(`x $MDU/464e/7 y`), { text: "x  y", removed: 1 }, "inline");
  assert.deepEqual(stripResiduals(`$MDU/464e/2`), { text: "", removed: 1 });
  // A mangled block (a row lost) strips to the bare token.
  assert.deepEqual(stripResiduals(`${T}/1:4\n$MDU/464e/2\n$MDU/464e/4`), { text: T, removed: 3 });
  // Not a fragment: tokens, `$MDU` prose, other slashes, 9 hex digits.
  for (const clean of [T, `${T}/2:3`, "cost $MDU/x/2", "$MDU/abcdef012/3", "a/1:3", `${T}\n$MDU:x[ab12]`]) {
    assert.deepEqual(stripResiduals(clean), { text: clean, removed: 0 }, clean);
  }
});

// ── v2 (§11.3) ───────────────────────────────────────────────────────────────

test("v2 head: T/1:N:W:F with the same rows; W 20..1000, F 0 or ⌈W/2⌉..W", () => {
  assert.equal(reserveBlock(T, 3, { width: 78, first: 40 }), `${T}/1:3:78:40\n$MDU/464e/2\n$MDU/464e/3`);
  assert.equal(reserveBlock(T, 2, { width: 78, first: 0 }), `${T}/1:2:78:0\n$MDU/464e/2`);
  assert.equal(reserveHeadSuffix(5), "/1:5");
  assert.equal(reserveHeadSuffix(5, { width: 20, first: 10 }), "/1:5:20:10");
  for (const [w, f] of [[20, 0], [20, 10], [20, 20], [21, 11], [1000, 500], [1000, 1000], [78, 39]] as const) {
    assert.equal(validLayout(w, f), true, `${w}:${f}`);
  }
  for (const [w, f] of [[19, 0], [1001, 1001], [20, 9], [21, 10], [20, 21], [78, 38], [78.5, 40], [78, 40.5], [78, -1]] as const) {
    assert.equal(validLayout(w, f), false, `${w}:${f}`);
  }
});

test("findTokens: every occurrence, greedy with its field path, escapes kept", () => {
  assert.deepEqual(findTokens(`a ${T}. b **${T_ESC}** ${T_FIELD}.x!`).map((m) => m.token), [T, T_ESC, `${T_FIELD}.x`]);
  const [m] = findTokens(`ab ${T}`);
  assert.deepEqual([m!.start, m!.end], [3, 3 + T.length]);
  assert.deepEqual(findTokens("no tokens, $5 and $MDU/464e/2"), []);
});

test("v2 collapse: mid-line blocks with prefix and suffix, several on a line, v1 and v2 mixed", () => {
  const b = (tok: string, n: number, w?: number, f?: number) => reserveBlock(tok, n, w === undefined ? undefined : { width: w, first: f! });
  assert.equal(collapseText(`The value is ${b(T, 3, 78, 65)} and that is all.`), `The value is ${T} and that is all.`);
  assert.equal(collapseText(`- key: ${b(T, 2, 76, 0)}`), `- key: ${T}`);
  assert.equal(collapseText(`**${b(T, 3, 78, 78)}** done.`), `**${T}** done.`);
  assert.equal(collapseText(`"${b(T_ESC, 2, 78, 70)}", ${b(T2, 4, 78, 50)})`), `"${T_ESC}", ${T2})`);
  assert.equal(collapseText(`${b(T_FIELD, 2, 20, 10)}.`), `${T_FIELD}.`);
  assert.deepEqual(collapseTextCounted(`${b(T, 2)}\n${b(T2, 3, 100, 100)} x`), { text: `${T}\n${T2} x`, collapsed: 2 });
  // Any digits are accepted in W and F (the strip would remove them anyway).
  assert.equal(collapseText(`${T}/1:2:0:0\n$MDU/464e/2`), T);
});

test("v2 strip: `:W:F` goes with `/1:N`; a marker after a break goes with the break, suffix text or not", () => {
  assert.deepEqual(stripResiduals(`${T}/1:3:78:40`), { text: T, removed: 1 });
  assert.deepEqual(stripResiduals(`${T}/1:3:78`), { text: T, removed: 1 }, "a truncated v2 head");
  assert.deepEqual(stripResiduals(`see ${T_ESC}/1:3:78:0 now`), { text: `see ${T_ESC} now`, removed: 1 });
  // A mangled mid-line block (N says 4, three rows) degrades to readable text.
  assert.deepEqual(
    stripResiduals(`The value is ${T}/1:4:78:65\n$MDU/464e/2\n$MDU/464e/3 and that is all.`),
    { text: `The value is ${T} and that is all.`, removed: 3 },
  );
  assert.deepEqual(stripResiduals(`pre ${T}\n$MDU/464e/2 tail`), { text: `pre ${T} tail`, removed: 1 }, "suffix residue");
  assert.deepEqual(stripResiduals(`a\r\n$MDU/464e/2, b`), { text: "a, b", removed: 1 }, "CRLF before a suffixed marker");
  assert.deepEqual(stripResiduals(`$MDU/464e/2 tail`), { text: " tail", removed: 1 }, "at the text start with suffix: the marker alone");
  assert.deepEqual(stripResiduals(`x\n$MDU/464e/2x`), { text: "xx", removed: 1 });
  for (const clean of [`${T}/1:`, `${T}:78:40`, `${T} /1:3`]) {
    assert.deepEqual(stripResiduals(clean), { text: clean, removed: 0 }, clean);
  }
});

// The v2 property: any token occurrence not followed by a digit, expanded
// with a v1 or a v2 head (what the expander may emit), collapses back.

const WORDS_V2 = [...WORDS, ",", ")", "**", "_", "\"", "'", "!", "?", ";", ":", "and", "is", "(", "*", "12", "|", "#"];
const SUFFIXES = ["", ".", ",", " and more", "** done.", ")", "\"", "'s", "!", "?", ":", ";", "_", " 42", "/1:3", "7", "`", "`, and"];

function genTextV2(r: () => number): string {
  const pick = <X>(xs: readonly X[]): X => xs[Math.floor(r() * xs.length)]!;
  const lines: string[] = [];
  const n = 1 + Math.floor(r() * 9);
  for (let i = 0; i < n; i++) {
    const kind = r();
    if (kind < 0.12) lines.push(pick(TOKENS));
    else if (kind < 0.2) lines.push("");
    else if (kind < 0.28) lines.push(pick(["```", "~~~", "```sh", "  ```"]));
    else {
      const lead = kind < 0.45 ? pick(["- ", "* ", "1. ", "  - ", "10) ", "> ", "# ", "| "]) : "";
      const w: string[] = [];
      const k = 1 + Math.floor(r() * 7);
      for (let j = 0; j < k; j++) {
        if (r() < 0.3) w.push(pick(["", "**", "_", "\"", "'", "(", "`"]) + pick(TOKENS) + pick(SUFFIXES));
        else w.push(pick(WORDS_V2));
      }
      lines.push(lead + w.join(r() < 0.8 ? " " : ""));
    }
  }
  const eol = r() < 0.15 ? "\r\n" : "\n";
  let t = lines.join(eol);
  if (r() < 0.3) t += eol;
  return t;
}

test("property v2: collapse(applyExpansions(t)) === t (2000 generated texts: mid-line tokens, suffixes, list items, fences)", () => {
  const r = rng(0xb10c2);
  let expandedSome = 0;
  let midLine = 0;
  let spanForm = 0;
  let breaks = 0;
  for (let i = 0; i < 2000; i++) {
    const t = genTextV2(r);
    const exps: TokenExpansion[] = [];
    let lastEnd = 0;
    for (const m of findTokens(t)) {
      if (/[0-9]/.test(t[m.end] ?? "")) continue; // never expanded (the suffix never starts with a digit)
      if (r() < 0.25) continue;
      const rows = 2 + Math.floor(r() * 45);
      const width = 20 + Math.floor(r() * 981);
      const first = r() < 0.3 ? 0 : Math.ceil(width / 2) + Math.floor(r() * (width - Math.ceil(width / 2) + 1));
      const layout = r() < 0.7 ? { layout: { width, first } } : {};
      // The span form (§12), on any v2 token: collapse must not depend on
      // the backticks around it.
      const span = "layout" in layout && r() < 0.3;
      // §14: a break K characters on, within the token's line.
      const nl = t.indexOf("\n", m.end);
      const lineLeft = (nl < 0 ? t.length : nl) - m.end;
      const brk = "layout" in layout && lineLeft >= 1 && r() < 0.4 ? 1 + Math.floor(r() * lineLeft) : undefined;
      if (exps.length > 0 && m.start < lastEnd) continue; // after an earlier break on the line
      exps.push({ start: m.start, end: m.end, token: m.token, rows, ...layout, ...(span ? { span } : {}), ...(brk !== undefined ? { brk } : {}) });
      lastEnd = m.end + (brk ?? 0);
      if (m.start > 0 && t[m.start - 1] !== "\n") midLine++;
      if (span) spanForm++;
      if (brk !== undefined) breaks++;
    }
    const e = applyExpansions(t, exps);
    if (e !== t) expandedSome++;
    assert.equal(collapseText(e), t, `seed case ${i}: ${JSON.stringify(t)}`);
    assert.equal(collapseTextCounted(e).collapsed, exps.length, `seed case ${i}: every block collapses`);
    if (!/\/1:\d|\$MDU\/[0-9a-f]{4,8}\/\d/.test(t)) assert.equal(stripResiduals(t).text, t);
  }
  assert.ok(expandedSome > 1000, `the generator must exercise expansion (${expandedSome})`);
  assert.ok(midLine > 1000, `the generator must exercise mid-line blocks (${midLine})`);
  assert.ok(spanForm > 300, `the generator must exercise the span form (${spanForm})`);
  assert.ok(breaks > 300, `the generator must exercise §14 breaks (${breaks})`);
});

test("span form (§12): each row its own code span; collapse restores the model's span; the strip keeps it readable", () => {
  const L = { width: 78, first: 43 };
  assert.equal(reserveBlock(T, 3, L, true), `${T}/1:3:78:43\`\n\`$MDU/464e/2\`\n\`$MDU/464e/3`);
  assert.equal(reserveBlock(T, 3, L, false), reserveBlock(T, 3, L), "span off: the plain form");
  const model = `The value of API_KEY in \`.env\` is \`${T}\`, and that is all.`;
  const at = model.indexOf(T);
  const wire = applyExpansions(model, [{ start: at, end: at + T.length, token: T, rows: 3, layout: L, span: true }]);
  assert.equal(wire, `The value of API_KEY in \`.env\` is \`${T}/1:3:78:43\`\n\`$MDU/464e/2\`\n\`$MDU/464e/3\`, and that is all.`);
  assert.deepEqual(collapseTextCounted(wire), { text: model, collapsed: 1 });
  // A list item, an escaped token, and a plain block on the same text.
  const two = `- key: \`${reserveBlock(T_ESC, 2, { width: 76, first: 66 }, true)}\`\n${reserveBlock(T2, 2)}`;
  assert.deepEqual(collapseTextCounted(two), { text: `- key: \`${T_ESC}\`\n${T2}`, collapsed: 2 });
  // One separator per block: a block that mixes the forms is not well formed.
  const mixed = `\`${T}/1:3:78:43\`\n\`$MDU/464e/2\n$MDU/464e/3\``;
  assert.equal(collapseTextCounted(mixed).collapsed, 0);
  assert.deepEqual(stripResiduals(mixed), { text: `\`${T}\``, removed: 3 });
  // Mangled span blocks strip to the model's span.
  assert.deepEqual(
    stripResiduals(`is \`${T}/1:4:78:43\`\n\`$MDU/464e/2\`\n\`$MDU/464e/3\`, and`),
    { text: `is \`${T}\`, and`, removed: 3 },
  );
  assert.deepEqual(stripResiduals(`\`$MDU/464e/2\` x`), { text: "`` x", removed: 1 }, "a lone span marker goes alone");
});

test("§14 break: head `T/1:N:W:F:K`; the `\\n` K characters after the block goes with it on collapse", () => {
  const L = { width: 78, first: 65 };
  assert.equal(reserveBlock(T, 2, L, false, 5), `${T}/1:2:78:65:5\n$MDU/464e/2`);
  assert.equal(reserveHeadSuffix(2, L, 5), "/1:2:78:65:5");
  assert.equal(reserveHeadSuffix(2, undefined, 5), "/1:2", "a v1 head carries no break");
  const model = `The value is ${T} and that is all.\nnext`;
  const at = model.indexOf(T);
  const wire = applyExpansions(model, [{ start: at, end: at + T.length, token: T, rows: 2, layout: L, brk: 5 }]);
  assert.equal(wire, `The value is ${T}/1:2:78:65:5\n$MDU/464e/2 and \nthat is all.\nnext`);
  assert.deepEqual(collapseTextCounted(wire), { text: model, collapsed: 1 });
  // The span form carries a break the same way.
  const span = applyExpansions(`is \`${T}\`, and more`, [{ start: 4, end: 4 + T.length, token: T, rows: 2, layout: L, span: true, brk: 3 }]);
  assert.equal(span, `is \`${T}/1:2:78:65:3\`\n\`$MDU/464e/2\`, \nand more`);
  assert.equal(collapseText(span), `is \`${T}\`, and more`);
  // Not well formed: no \n at K, a \n before K, or the text ends first.
  for (const bad of [
    `${T}/1:2:78:65:3\n$MDU/464e/2 abcd`,
    `${T}/1:2:78:65:3\n$MDU/464e/2 a\nb\n`,
    `${T}/1:2:78:65:9\n$MDU/464e/2 ab`,
  ]) {
    assert.equal(collapseTextCounted(bad).collapsed, 0, JSON.stringify(bad));
  }
  // The strip takes `:K` with the head suffix; the inserted \n cannot be told apart and stays.
  assert.deepEqual(stripResiduals(`${T}/1:3:78:65:5`), { text: T, removed: 1 });
});

test("§14 head-only block: `T/1:1:W:F:K` (no rows) collapses with its break; N = 1 without a break is no block", () => {
  const L = { width: 158, first: 145 };
  assert.equal(reserveBlock(T, 1, L, false, 4), `${T}/1:1:158:145:4`);
  const model = `The value is ${T} and that is all, so on.\nnext`;
  const at = model.indexOf(T);
  const wire = applyExpansions(model, [{ start: at, end: at + T.length, token: T, rows: 1, layout: L, brk: 5 }]);
  assert.equal(wire, `The value is ${T}/1:1:158:145:5 and \nthat is all, so on.\nnext`);
  assert.deepEqual(collapseTextCounted(wire), { text: model, collapsed: 1 });
  // The span form, head only: the model's closing backtick follows the head.
  const span = `is \`${T}/1:1:158:145:3\`, \nand more`;
  assert.equal(collapseText(span), `is \`${T}\`, and more`);
  for (const bad of [`${T}/1:1:158:145 and\nmore`, `${T}/1:1\nmore`, `${T}/1:1:158:145:9 ab\ncd`]) {
    assert.equal(collapseTextCounted(bad).collapsed, 0, JSON.stringify(bad));
  }
});
