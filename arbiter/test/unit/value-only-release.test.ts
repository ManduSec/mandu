/**
 * value-only-release.test.ts — the value backstop's value-only release
 * (docs/design/confidentiality/backstop-value-only.md §2): the plan
 * (`planValueOnly`, rules A2-A5) and the residue scan (`ResidueScanner`,
 * rule A6b), one test per fail-closed case the note lists.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ResidueScanner, VALUE_ONLY_MAX_CHARS, applySpans, dumpColumns, dumpSkeleton, encodedForms, odCharForm, planValueOnly, publicPrefixLength, replaceableValue, residueCheckText, wellFormedSpans,
  type ValueOnlyOccurrence, type ValueOnlyRow,
} from "../../policy/value-only-release.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";

const KEY = "sk_test_MANDUDEMO_2718281828";
const SYM = "$MDU:nomodel_Read[1a2b].STRIPE_SECRET_KEY";
const LOG = `DEBUG: Authorization: Bearer ${KEY}\n[08:00:02] ok: HTTP 200\n`;

function rows(...r: Array<[string, string, ConfidentialityLevel?]>): (s: string) => ValueOnlyRow | undefined {
  const m = new Map(r.map(([sym, value, level], i) => [sym, { value, level: level ?? "no-model", order: i }]));
  return (s) => m.get(s);
}
/** Every occurrence of `value` in `text` as a whole-value hit of `symbol`. */
function occ(text: string, value: string, symbol: string, how: "value" | "line" = "value"): ValueOnlyOccurrence[] {
  const out: ValueOnlyOccurrence[] = [];
  for (let i = text.indexOf(value); i !== -1; i = text.indexOf(value, i + 1)) out.push({ symbol, how, start: i, end: i + value.length });
  return out;
}

test("a log line holding a registered key: the key becomes its symbol, every other byte stays", () => {
  const p = planValueOnly(LOG, occ(LOG, KEY, SYM), rows([SYM, KEY]));
  assert.ok(p.ok, JSON.stringify(p));
  assert.equal(p.text, `DEBUG: Authorization: Bearer ${SYM}\n[08:00:02] ok: HTTP 200\n`);
  assert.deepEqual(p.spans, [{ start: LOG.indexOf(KEY), end: LOG.indexOf(KEY) + KEY.length, symbol: SYM }]);
  assert.ok(!p.text.includes(KEY));
});

test("every occurrence is replaced, in order", () => {
  const text = `${KEY} and ${KEY}\n`;
  const p = planValueOnly(text, occ(text, KEY, SYM), rows([SYM, KEY]));
  assert.ok(p.ok);
  assert.equal(p.text, `${SYM} and ${SYM}\n`);
});

test("fail closed: a result too long", () => {
  const text = `${KEY}${"x".repeat(VALUE_ONLY_MAX_CHARS)}`;
  assert.deepEqual(planValueOnly(text, occ(text, KEY, SYM), rows([SYM, KEY])), { ok: false, why: "result too long" });
});

test("fail closed: any $MDU token in the result (any case), even a forged one", () => {
  for (const extra of ["$MDU:nomodel_Read[1a2b]", "$mdu:x", "see $MDU"]) {
    const text = `${LOG}${extra}\n`;
    const p = planValueOnly(text, occ(text, KEY, SYM), rows([SYM, KEY]));
    assert.equal(p.ok, false, extra);
  }
});

test("fail closed: no whole value to replace (only a piece hit)", () => {
  const line = `export STRIPE_SECRET_KEY=${KEY}`;
  const text = `${line}\n`;
  const p = planValueOnly(text, occ(text, line, "$MDU:nomodel_Read[9999]", "line"), rows(["$MDU:nomodel_Read[9999]", `${line}\nPORT=1\n`]));
  assert.deepEqual(p, { ok: false, why: "no whole value to replace" });
});

test("fail closed: a multi-line value, a short value, a low-entropy value", () => {
  const doc = "line one of the secret memo\nline two";
  const t1 = `x ${doc} y`;
  assert.equal(planValueOnly(t1, occ(t1, doc, "$MDU:nomodel_Read[0001]"), rows(["$MDU:nomodel_Read[0001]", doc])).ok, false);
  const short = "Ab3$xY9!q";
  const t2 = `pw=${short}`;
  assert.equal(planValueOnly(t2, occ(t2, short, "$MDU:nomodel_x[0002]"), rows(["$MDU:nomodel_x[0002]", short])).ok, false);
  const flat = "aaaaaaaaaaaaaaaaaaaa";
  const t3 = `v=${flat}`;
  assert.equal(planValueOnly(t3, occ(t3, flat, "$MDU:nomodel_x[0003]"), rows(["$MDU:nomodel_x[0003]", flat])).ok, false);
  assert.equal(replaceableValue(KEY), true);
  assert.equal(replaceableValue(`${KEY}\n`), false);
  assert.equal(replaceableValue(`${KEY}\u2028`), false);
});

test("fail closed: an occurrence that does not locate the row's value exactly, or out of bounds, or of a row that is gone", () => {
  const bad: ValueOnlyOccurrence = { symbol: SYM, how: "value", start: 0, end: KEY.length };
  assert.deepEqual(planValueOnly(LOG, [bad], rows([SYM, KEY])), { ok: false, why: "an occurrence not located exactly" });
  assert.equal(planValueOnly(LOG, [{ ...bad, start: 5, end: LOG.length + 3 }], rows([SYM, KEY])).ok, false);
  assert.equal(planValueOnly(LOG, occ(LOG, KEY, SYM), rows()).ok, false);
});

test("fail closed: two different values that overlap", () => {
  const a = "sk_test_MANDUDEMO_27";
  const b = "MANDUDEMO_2718281828";
  const text = `Bearer ${KEY}`;
  const o = [...occ(text, a, "$MDU:nomodel_x[000a]"), ...occ(text, b, "$MDU:nomodel_x[000b]")];
  assert.deepEqual(planValueOnly(text, o, rows(["$MDU:nomodel_x[000a]", a], ["$MDU:nomodel_x[000b]", b])), { ok: false, why: "overlapping values" });
});

test("one span held by two rows: the strictest row's symbol, then the first in the map's order", () => {
  const o = [...occ(LOG, KEY, "$MDU:anymodel_x[00a1]"), ...occ(LOG, KEY, "$MDU:nomodel_x[00b2]")];
  const p = planValueOnly(LOG, o, rows(["$MDU:anymodel_x[00a1]", KEY, "any-model"], ["$MDU:nomodel_x[00b2]", KEY, "no-model"]));
  assert.ok(p.ok);
  assert.equal(p.spans[0]!.symbol, "$MDU:nomodel_x[00b2]");
  const q = planValueOnly(LOG, [...occ(LOG, KEY, "$MDU:nomodel_x[00c3]"), ...occ(LOG, KEY, "$MDU:nomodel_x[00d4]")],
    rows(["$MDU:nomodel_x[00c3]", KEY], ["$MDU:nomodel_x[00d4]", KEY]));
  assert.ok(q.ok);
  assert.equal(q.spans[0]!.symbol, "$MDU:nomodel_x[00c3]");
});

test("a piece of a secret (a file row's credential span) inside a replaced value is covered; one outside is fail-closed", () => {
  const fileRow = "$MDU:nomodel_Read[f11e]";
  const inside = [...occ(LOG, KEY, SYM), ...occ(LOG, KEY, fileRow, "line")];
  assert.ok(planValueOnly(LOG, inside, rows([SYM, KEY], [fileRow, `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`])).ok);
  const line = "DEBUG: Authorization: Bearer";
  const outside = [...occ(LOG, KEY, SYM), ...occ(LOG, line, fileRow, "line")];
  assert.deepEqual(planValueOnly(LOG, outside, rows([SYM, KEY], [fileRow, `${line}\n`])), { ok: false, why: "a piece of a secret outside every replaced value" });
});

test("applySpans, residueCheckText and wellFormedSpans", () => {
  const spans = [{ start: 2, end: 4, symbol: "$MDU:nomodel_x[00aa]" }];
  assert.equal(applySpans("abCDef", spans), "ab$MDU:nomodel_x[00aa]ef");
  assert.equal(residueCheckText("abCDef", spans), "ab\u0000ef");
  assert.equal(wellFormedSpans(6, spans), true);
  assert.equal(wellFormedSpans(3, spans), false, "out of bounds");
  assert.equal(wellFormedSpans(6, []), false, "empty");
  assert.equal(wellFormedSpans(6, [{ ...spans[0]!, symbol: "$MDU:nomodel_x[00aa] tail" }]), false, "not one whole token");
  assert.equal(wellFormedSpans(6, [spans[0]!, { start: 3, end: 5, symbol: spans[0]!.symbol }]), false, "overlap");
});

// ── the residue scan (A6b) ────────────────────────────────────────────────

const scanner = new ResidueScanner([KEY, "short", "Garden-Lamp-MANDUDEMO-6180"]);
const b64 = (s: string): string => Buffer.from(s).toString("base64");
const rot13 = (s: string): string => s.replace(/[a-z]/gi, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); });

test("residue: a clean text (the replaced log) is clean; a NUL cut joins no fragment", () => {
  assert.equal(scanner.find(residueCheckText(LOG, [{ start: LOG.indexOf(KEY), end: LOG.indexOf(KEY) + KEY.length, symbol: SYM }])), null);
  assert.equal(scanner.find("sk_test\u0000_MANDU"), null);
});

test("residue: every encoded form the scan knows is found", () => {
  const cases: Array<[string, string]> = [
    ["verbatim", `x ${KEY} y`],
    ["base64 at offset 0", b64(KEY)],
    ["base64 at offset 1", b64(`a${KEY}`)],
    ["base64 at offset 2", b64(`ab${KEY}`)],
    ["base64 inside a larger stream", b64(`{"token":"${KEY}","n":1}`)],
    ["url-safe base64", b64(`ab${KEY}`).replace(/\+/g, "-").replace(/\//g, "_")],
    ["hex", Buffer.from(KEY).toString("hex")],
    ["HEX", Buffer.from(KEY).toString("hex").toUpperCase()],
    ["percent-encoded", encodeURIComponent("Garden-Lamp-MANDUDEMO-6180 ") + "%2F"],
    ["reversed", [...KEY].reverse().join("")],
    ["rot13", rot13(KEY)],
  ];
  for (const [name, text] of cases) assert.notEqual(scanner.find(text), null, name);
  const json = new ResidueScanner(['pa"ss\\word-9f8e7d6c5b']);
  assert.equal(json.find(JSON.stringify({ p: 'pa"ss\\word-9f8e7d6c5b' })), "encoded", "JSON-escaped");
  const pct = new ResidueScanner(["key/with+chars=9f8e7d6c"]);
  assert.equal(pct.find(`?k=${encodeURIComponent("key/with+chars=9f8e7d6c")}`), "encoded", "percent-encoded");
  assert.equal(pct.find(`?k=${encodeURIComponent("key/with+chars=9f8e7d6c").replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())}`), "encoded", "percent-encoded, lower-case digits");
  assert.ok(encodedForms(KEY).every((f) => f.length >= 8));
});

test("residue: a value spread across lines, spaced out, case changed, or reversed and spread", () => {
  // split by blanks alone: found as the verbatim form once blanks are squeezed out
  assert.notEqual(scanner.find(`${KEY.slice(0, 10)}\n${KEY.slice(10)}`), null);
  assert.notEqual(scanner.find([...KEY].join(" ")), null);
  assert.equal(scanner.find([...KEY].join("|")), "spread");
  assert.equal(scanner.find(KEY.toUpperCase().split("").join("\n")), "spread");
  assert.equal(scanner.find([...KEY].reverse().join(".")), "spread");
});

test("residue: a fragment of 8 characters (a prefix, a suffix, any chunk, any case) is found; 7 is not", () => {
  assert.equal(scanner.find(`prefix: ${KEY.slice(0, 10)} only`), "fragment", "a prefix past the public format prefix");
  assert.equal(scanner.find("Invalid API Key provided: sk_test_****1828"), null, "the public format prefix alone is no fragment (review round 4)");
  assert.equal(scanner.find(`suffix: ${KEY.slice(-8)} only`), "fragment");
  assert.equal(scanner.find(`chunk: ${KEY.slice(9, 17)} only`), "fragment");
  assert.equal(scanner.find(`chunk: ${KEY.slice(9, 17).toUpperCase()} only`), "fragment");
  assert.equal(scanner.find(`seven: ${KEY.slice(10, 17)} only`), null);
  assert.equal(scanner.find("short short"), null, "a row under the residue floor is not scanned");
});

test("residue (review round 2): base64 and hex wrapped at a fixed width, as base64, openssl and xxd -p print them", () => {
  const long = `sk_live_${"Q7k2Xr9Lm4Tz8Vb3Pw6".repeat(5)}`;
  const s = new ResidueScanner([long]);
  const wrap = (t: string, w: number): string => t.match(new RegExp(`.{1,${w}}`, "g"))!.join("\n");
  const b = Buffer.from(long).toString("base64");
  assert.equal(s.find(wrap(b, 76)), "encoded", "base64 at 76");
  assert.equal(s.find(wrap(b, 64)), "encoded", "openssl base64 at 64");
  assert.notEqual(s.find(wrap(Buffer.from(long).toString("hex"), 60)), null, "xxd -p at 60");
  assert.equal(s.find(wrap(Buffer.from(`ab${long}`).toString("base64"), 76).replace(/\n/g, "\r\n")), "encoded", "base64 at offset 2, CRLF");
});

test("residue (review round 3): byte dumps and numbered folds of the key, as od, xxd, printf and cat -n print them", () => {
  const bytes = [...Buffer.from(KEY)];
  const rowsOf = (per: number, cell: (b: number) => string, off: (i: number) => string): string => {
    const out: string[] = [];
    for (let i = 0; i < bytes.length; i += per) out.push(`${off(i)} ${bytes.slice(i, i + per).map(cell).join(" ")}`);
    return out.join("\n");
  };
  const octOff = (i: number): string => i.toString(8).padStart(7, "0");
  const cases: Array<[string, string]> = [
    ["od -c", rowsOf(16, (b) => `   ${String.fromCharCode(b)}`, octOff)],
    ["od -tx1", rowsOf(16, (b) => b.toString(16).padStart(2, "0"), octOff)],
    ["od -b", rowsOf(16, (b) => b.toString(8).padStart(3, "0"), octOff)],
    ["xxd -i", `unsigned char k[] = {\n  ${bytes.map((b) => `0x${b.toString(16).padStart(2, "0")}`).join(", ")}\n};`],
    ["printf \\x", bytes.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")],
    ["octal escapes", bytes.map((b) => `\\${b.toString(8).padStart(3, "0")}`).join("")],
    ["aa:bb hex", bytes.map((b) => b.toString(16).padStart(2, "0")).join(":")],
    ["fold -w 4 | cat -n", KEY.match(/.{1,4}/g)!.map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n")],
    ["fold -w 7 | cat -n", KEY.match(/.{1,7}/g)!.map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n")],
    ["wrapped base64 in a JSON string", JSON.stringify({ blob: Buffer.from(`ab${KEY}`).toString("base64").match(/.{1,12}/g)!.join("\n") })],
    ["a hex fragment of 8 bytes", Buffer.from(KEY.slice(5, 13)).toString("hex")],
  ];
  for (const [name, text] of cases) assert.notEqual(scanner.find(text), null, name);
});

test("fail closed (review round 2): a stricter row's piece inside a replaced span, and a value glued to text the symbol would absorb", () => {
  const file = "$MDU:nomodel_Read[f11f]";
  const o = [...occ(LOG, KEY, "$MDU:anymodel_x[0a0a]"), ...occ(LOG, KEY, file, "line")];
  assert.deepEqual(planValueOnly(LOG, o, rows(["$MDU:anymodel_x[0a0a]", KEY, "any-model"], [file, `K=${KEY}\nP=1\n`, "no-model"])),
    { ok: false, why: "a stricter row's piece inside a replaced value" });
  for (const after of ["_old", "x", ".json", "[0]"]) {
    const text = `token ${KEY}${after} end`;
    assert.deepEqual(planValueOnly(text, occ(text, KEY, SYM), rows([SYM, KEY])), { ok: false, why: "a value glued to text the symbol would absorb" }, after);
  }
  for (const after of [".", ". next", "\n", " ", "\"", "'", ",", ")"]) {
    const text = `token ${KEY}${after}`;
    assert.ok(planValueOnly(text, occ(text, KEY, SYM), rows([SYM, KEY])).ok, JSON.stringify(after));
  }
});

test("residue: a copy in look-alike or padded characters (full-width, zero-width inside), and hex in mixed case", () => {
  const fullWidth = [...KEY].map((c) => /[A-Za-z0-9]/.test(c) ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c).join("");
  assert.notEqual(scanner.find(`a ${fullWidth} b`), null, "full-width");
  const zw = `${KEY.slice(0, 6)}\u200b${KEY.slice(6, 14)}\u2060${KEY.slice(14)}`;
  assert.notEqual(scanner.find(zw), null, "zero-width inside");
  const hex = [...Buffer.from(KEY).toString("hex")].map((c, i) => (i % 2 ? c.toUpperCase() : c)).join("");
  assert.equal(scanner.find(hex), "encoded", "mixed-case hex");
});

test("review round 4: the dump helpers (gutters, escaped backslashes, od -c's octal for other bytes, a hex dump's two columns)", () => {
  assert.equal(dumpSkeleton("     1→abcd\n     2→efgh"), "abcdefgh", "an arrow gutter");
  assert.equal(dumpSkeleton("1:abcd\n2:efgh"), "abcdefgh", "a grep -n gutter");
  assert.equal(dumpSkeleton("a\\\\nb"), "a\\\\nb", "an escaped backslash keeps its n");
  assert.equal(odCharForm("abé"), "ab303251");
  assert.deepEqual(dumpColumns("00000000: 6162 6364  abcd\n00000004: 6566 6768  efgh"), { hex: "6162636465666768", ascii: "abcdefgh" });
  assert.equal(publicPrefixLength("sk_live_abc"), 8);
  assert.equal(publicPrefixLength("plainvalue"), 0);
});

test("review round 4: fragments only of the values passed for them; every value still whole in every form", () => {
  const word = "payments: connected to Stripe";
  const s = new ResidueScanner([KEY, word], [KEY]);
  assert.equal(s.find("payments retried"), null, "an ordinary row's words are no fragment");
  assert.notEqual(s.find(`x ${word} y`), null, "but the row whole is still found");
  assert.equal(s.find(KEY.slice(9, 17)), "fragment");
});
