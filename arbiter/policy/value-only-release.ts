/**
 * value-only-release — the value backstop's value-only release
 * (docs/design/confidentiality/backstop-value-only.md). Mandu-new (no
 * reference origin).
 *
 * The value backstop (classify, plan 10 §2.2) raises a result the path rules
 * call public when a registered secret's value is in it, and the proxy then
 * masks the WHOLE result: an old log whose debug lines printed a labelled
 * `.env`'s key reached the model as one symbol, and the model could not read
 * the log at all. This module plans the narrower release: each occurrence of
 * a registered single-line value becomes that value's own symbol, the rest of
 * the text stays, and the release is offered only when it provably carries no
 * registered value in any form this module knows how to look for. Anything
 * it cannot prove clean is refused, and the caller masks the result whole as
 * before.
 *
 * PURE: no I/O, no symbol table. The arbiter (ipc/server.ts
 * `valueOnlyOffer`) feeds it the counted occurrences and the rows; the model
 * proxies take the offer only when their own evidence says the call read no
 * secret (rewrite-request.ts, the value-only path).
 */
import { MDU_SYM_FORMAT } from "../symbol-table/symbol-format.js";
import { confidentialityRank, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { entropy } from "./secret-detectors.js";
import { ValueMatcher } from "../prompt-filter/value-matcher.js";

/** A value shorter than this is never replaced in place: the result is
 *  masked whole (a short value is easy to recover from its context). */
export const VALUE_ONLY_MIN_LEN = 12;
/** Nor a value under this Shannon entropy (bits per character): a
 *  low-entropy value (`password1234`) is a word the text may repeat in
 *  pieces the scan cannot tell from prose. */
export const VALUE_ONLY_MIN_ENTROPY = 3.0;
/** A result longer than this is masked whole: the residue scan is linear,
 *  but its cost is paid on the arbiter's one event loop. */
export const VALUE_ONLY_MAX_CHARS = 256 * 1024;
/** The residue scan looks for every secret row of this length or more. */
export const RESIDUE_MIN_LEN = 8;
/** A piece of a secret value of this many characters is a fragment of it. */
export const RESIDUE_FRAGMENT_LEN = 8;

/** One occurrence the value backstop counts (a live secret row's value or
 *  piece, `RegisteredValueIndex.occurrences` filtered by the row's level). */
export interface ValueOnlyOccurrence {
  symbol: string;
  how: "value" | "line";
  start: number;
  end: number;
}

/** A row as the plan needs it: its value, its level, its place in the
 *  symbol map's order (the tie-break between rows that hold one value). */
export interface ValueOnlyRow {
  value: string;
  level: ConfidentialityLevel;
  order: number;
}

/** One replaced span of the original text, [start, end), and its symbol. */
export interface ValueOnlySpan {
  start: number;
  end: number;
  symbol: string;
}

export type ValueOnlyPlan =
  | { ok: true; text: string; spans: ValueOnlySpan[] }
  | { ok: false; why: string };

const MDU_ANY_RE = /\$MDU/i;
const LINE_BREAK_RE = /[\r\n\u2028\u2029]/;

/** True when `value` may be replaced in place: one line, long enough, and
 *  not low-entropy. */
export function replaceableValue(value: string): boolean {
  return !LINE_BREAK_RE.test(value) && value.length >= VALUE_ONLY_MIN_LEN && entropy(value) >= VALUE_ONLY_MIN_ENTROPY;
}

/** `text` with each span replaced by `with(span)`; spans sorted, disjoint. */
export function applySpans(text: string, spans: readonly ValueOnlySpan[], with_: (s: ValueOnlySpan) => string = (s) => s.symbol): string {
  let out = "";
  let at = 0;
  for (const s of spans) {
    out += text.slice(at, s.start) + with_(s);
    at = s.end;
  }
  return out + text.slice(at);
}

/** The text the residue scan reads: the original with each replaced span
 *  cut out and a NUL in its place (never the symbol: its letters are no
 *  secret, and a NUL joins no fragment across the cut). */
export function residueCheckText(text: string, spans: readonly ValueOnlySpan[]): string {
  return applySpans(text, spans, () => "\u0000");
}

/** Are `spans` well-formed over a text of `length`: sorted, disjoint, in
 *  bounds, each non-empty, each symbol one whole `$MDU` token? The proxies
 *  check an offer with the same rule before they rebuild it. */
export function wellFormedSpans(length: number, spans: readonly ValueOnlySpan[]): boolean {
  let at = 0;
  for (const s of spans) {
    if (!Number.isInteger(s.start) || !Number.isInteger(s.end) || s.start < at || s.end <= s.start || s.end > length) return false;
    if (typeof s.symbol !== "string" || !isWholeSymbol(s.symbol)) return false;
    at = s.end;
  }
  return spans.length > 0;
}

function isWholeSymbol(s: string): boolean {
  const re = new RegExp(MDU_SYM_FORMAT.pattern.source, "g");
  const m = re.exec(s);
  return m !== null && m.index === 0 && m[0] === s;
}

/**
 * Plan the release (design note §2, rules A2–A5): `occurrences` are the
 * counted occurrences in `text`; `rowOf` reads each row. Refuses (`ok:
 * false`) a text too long, a text holding any `$MDU`, a text with no
 * whole-value occurrence, a whole-value occurrence of a row that is not
 * replaceable (`replaceableValue`: multi-line, short, low-entropy), two
 * distinct occurrences that overlap, and a piece occurrence (a long line, a
 * credential span, a bare token of a registered file) not inside a replaced
 * span. Identical spans of two rows take the strictest row (then the first in
 * the map's order). Does NOT run the residue checks: the caller does, on the
 * planned text (`ResidueScanner`, and the backstop's own rescan).
 */
export function planValueOnly(
  text: string,
  occurrences: readonly ValueOnlyOccurrence[],
  rowOf: (symbol: string) => ValueOnlyRow | undefined,
): ValueOnlyPlan {
  if (text.length > VALUE_ONLY_MAX_CHARS) return { ok: false, why: "result too long" };
  if (MDU_ANY_RE.test(text)) return { ok: false, why: "the result holds a $MDU token" };
  const bySpan = new Map<string, { start: number; end: number; symbol: string; row: ValueOnlyRow }>();
  const pieces: ValueOnlyOccurrence[] = [];
  for (const o of occurrences) {
    if (!(o.end > o.start && o.start >= 0 && o.end <= text.length)) return { ok: false, why: "an occurrence out of bounds" };
    const row = rowOf(o.symbol);
    if (row === undefined) return { ok: false, why: "an occurrence of a row that is gone" };
    if (o.how !== "value") { pieces.push(o); continue; }
    if (text.slice(o.start, o.end) !== row.value) return { ok: false, why: "an occurrence not located exactly" };
    if (!replaceableValue(row.value)) return { ok: false, why: "a value that is multi-line, short or low-entropy" };
    const key = `${o.start}:${o.end}`;
    const cur = bySpan.get(key);
    if (cur === undefined
      || confidentialityRank(row.level) > confidentialityRank(cur.row.level)
      || (confidentialityRank(row.level) === confidentialityRank(cur.row.level) && row.order < cur.row.order)) {
      bySpan.set(key, { start: o.start, end: o.end, symbol: o.symbol, row });
    }
  }
  if (bySpan.size === 0) return { ok: false, why: "no whole value to replace" };
  const spans = [...bySpan.values()].sort((a, b) => a.start - b.start || a.end - b.end);
  for (let i = 1; i < spans.length; i++) {
    if (spans[i]!.start < spans[i - 1]!.end) return { ok: false, why: "overlapping values" };
  }
  for (const p of pieces) {
    const cover = spans.find((s) => s.start <= p.start && p.end <= s.end);
    if (cover === undefined) return { ok: false, why: "a piece of a secret outside every replaced value" };
    // The span takes its own row's symbol; a stricter row's piece inside it
    // would stand at a lower level than its own: refused.
    const pr = rowOf(p.symbol)!;
    if (confidentialityRank(pr.level) > confidentialityRank(cover.row.level)) return { ok: false, why: "a stricter row's piece inside a replaced value" };
  }
  for (const s of spans) {
    // A symbol's grammar runs on over `_`, letters, digits, brackets, and a
    // dot followed by one of those: text glued to the value would be read
    // as part of the symbol, which then names nothing (a usability guard).
    const next = text.slice(s.end, s.end + 2);
    if (/^[A-Za-z0-9_[\]]/.test(next) || /^\.[A-Za-z0-9_[\]]/.test(next)) return { ok: false, why: "a value glued to text the symbol would absorb" };
  }
  const out = spans.map((s) => ({ start: s.start, end: s.end, symbol: s.symbol }));
  return { ok: true, text: applySpans(text, out), spans: out };
}

const rot13 = (s: string): string => s.replace(/[a-z]/gi, (c) => {
  const b = c <= "Z" ? 65 : 97;
  return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
});
const alnumUpper = (s: string): string => s.replace(/[^A-Za-z0-9]/g, "").toUpperCase();

/**
 * The encoded forms of `value` the residue scan looks for (design note §2,
 * A6): the value itself; its base64 at each of the three byte alignments
 * (the core that does not depend on the neighbours), standard and URL-safe;
 * hex, lower and upper case; percent-encoded (lower and upper hex digits);
 * JSON-escaped; reversed; rot13. Only forms of `RESIDUE_MIN_LEN` or more.
 */
export function encodedForms(value: string): string[] {
  const out = new Set<string>([value]);
  for (let pad = 0; pad < 3; pad++) {
    const b64 = Buffer.from("x".repeat(pad) + value, "utf8").toString("base64").replace(/=+$/, "");
    const lead = pad === 0 ? 0 : pad + 1;
    const tail = (pad + Buffer.byteLength(value)) % 3 === 0 ? 0 : 1;
    const core = b64.slice(lead, b64.length - tail);
    out.add(core);
    out.add(core.replace(/\+/g, "-").replace(/\//g, "_"));
  }
  const hex = Buffer.from(value, "utf8").toString("hex");
  out.add(hex);
  out.add(hex.toUpperCase());
  const pct = encodeURIComponent(value);
  out.add(pct);
  out.add(pct.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  out.add(JSON.stringify(value).slice(1, -1));
  out.add([...value].reverse().join(""));
  out.add(rot13(value));
  return [...out].filter((f) => f.length >= RESIDUE_MIN_LEN);
}

/** Every blank and line break (a NUL cut stays). */
const BLANKS_RE = /[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/g;

/** Each line's leading offset or line-number column: a hex or decimal
 *  offset (`od`, `hexdump`, `xxd`) before a blank, a bar or the line's end,
 *  or a line number before a tab, `:`, `→`, `|` or `-` (`cat -n`, a Read's
 *  gutter, `grep -n`, `nl`) or a blank. */
const GUTTER_RE = /^[ \t]*(?:[0-9a-fA-F]{4,}:?(?=[ \t|]|$)|\d+(?:[\t:\u2192|-]|(?=[ ]|$)))/;

/** Literal `\n`, `\r`, `\t` escapes, but not the second half of an escaped
 *  backslash (`\\n` is a backslash and an `n`). */
const unescapeBreaks = (t: string): string => t.replace(/\\(\\|[nrt])/g, (m, c: string) => (c === "\\" ? m : ""));

/**
 * The text a byte dump leaves once its scaffolding is taken out (review
 * rounds 3 and 4): each line's offset or line-number column (`GUTTER_RE`);
 * literal `\n` `\r` `\t` escapes (a wrapped value inside a JSON string); the
 * `\x`, `0x` and `\u00` of C, `xxd -i` and JSON escapes; the backslash of an
 * octal escape; and every blank, comma, colon and bar. `od -c`, `od -tx1`,
 * `xxd -i`, `printf '\x..'`, `aa:bb` hex and a numbered fold all come out
 * as the value, its hex, its octal or its `od -c` form, unbroken.
 */
export function dumpSkeleton(text: string): string {
  return unescapeBreaks(text
    .split(/\r\n|\r|\n/)
    .map((l) => l.replace(GUTTER_RE, ""))
    .join(""))
    .replace(/\\x|0x|\\u00/gi, "")
    .replace(/\\(?=[0-7]{3})/g, "")
    .replace(/[\s,:|]+/g, "");
}

/**
 * The two columns of a hex dump with an ASCII column (`xxd`, `hexdump -C`),
 * each joined across its lines (review round 4): a value that straddles two
 * rows is split in both, so neither column alone holds 8 bytes of it on one
 * line. `hex` is each line's leading run of hex groups after its offset,
 * `ascii` the rest of the line, with `hexdump -C`'s bars taken off.
 */
export function dumpColumns(text: string): { hex: string; ascii: string } {
  const hex: string[] = [];
  const ascii: string[] = [];
  for (const raw of text.split(/\r\n|\r|\n/)) {
    const off = /^[ \t]*[0-9a-fA-F]{4,}(:?)(?=[ \t])/.exec(raw);
    const l = off ? raw.slice(off[0].length) : raw;
    // `xxd` (an offset with a colon) parts its groups by one blank and its
    // ASCII column by two; `hexdump -C` puts two blanks mid-row and bars
    // round its ASCII column
    // groups of up to 16 hex digits (`xxd -g8`)
    const m = (off?.[1] === ":" ? /^(?: [0-9a-fA-F]{2,16}(?= |$))+/ : /^(?: {1,2}[0-9a-fA-F]{2,16}(?= |$))+/).exec(l);
    if (m === null) continue;
    hex.push(m[0].replace(/[ \t]+/g, ""));
    ascii.push(l.slice(m[0].length).trim().replace(/^\||\|$/g, ""));
  }
  return { hex: hex.join(""), ascii: ascii.join("") };
}

/** The bytes of `value` as three-digit octal, run together (`od -b`, octal escapes). */
export function octalForm(value: string): string {
  return [...Buffer.from(value, "utf8")].map((b) => b.toString(8).padStart(3, "0")).join("");
}

/** The bytes of `value` as `od -c` prints them, scaffolding out (review
 *  round 4): a printable ASCII byte as itself (a blank, `,`, `:` and `|`
 *  dropped, as `dumpSkeleton` drops them; `\` as `\\`), every other byte as
 *  three-digit octal. Equal to the value for an ASCII value. */
export function odCharForm(value: string): string {
  return [...Buffer.from(value, "utf8")].map((b) => {
    if (b === 0x5c) return "\\\\";
    if (b > 0x20 && b < 0x7f) return /[,:|]/.test(String.fromCharCode(b)) ? "" : String.fromCharCode(b);
    // a blank, and the tab, line feed and carriage return `od -c` prints as
    // escapes the skeleton takes out, leave nothing
    if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) return "";
    return b.toString(8).padStart(3, "0");
  }).join("");
}

/** The public format prefix a credential of a known kind starts with (its
 *  first characters say only which kind it is): `sk_test_`, `rk_live_`,
 *  `whsec_`, `github_pat_`, `glpat-`, `xoxb-`, `AKIA` and the like. A
 *  fragment wholly inside it is no piece of the secret (review round 4: a
 *  Stripe error naming `sk_test_****1828` refused every release). */
export function publicPrefixLength(value: string): number {
  const m = /^(?:[spr]k_(?:test|live)_|whsec_|github_pat_|gh[pousr]_|glpat-|xox[abposr]-|AKIA|ASIA|npm_|pypi-|hf_|sk-(?:ant-|proj-)?)/.exec(value);
  return m ? m[0].length : 0;
}

/**
 * The residue scan over a set of secret values (design note §2, A6b): does a
 * text hold any of them in an encoded form (`encodedForms`; hex, octal and
 * the `od -c` form in any case), spread (its letters and digits in order
 * with only other characters, no letter or digit, between them; case
 * folded, forwards or reversed), or, for the `fragmentValues` only, as a
 * fragment of `RESIDUE_FRAGMENT_LEN` characters, case folded (a prefix
 * past its public format prefix, a suffix, any chunk), or a fragment of its
 * hex of the same many bytes? Each check reads several views of the text:
 * as it is; with every blank and line break taken out; that once more with
 * literal `\n` escapes out; a byte dump's skeleton (`dumpSkeleton`); and a
 * hex dump's hex and ASCII columns (`dumpColumns`); and each view once more
 * folded (NFKC, format characters removed). Built once per value set; each
 * scan is linear in the text.
 */
export class ResidueScanner {
  private readonly forms: ValueMatcher;
  /** Hex, octal and the `od -c` form in any mix of cases: matched on the lower-cased view. */
  private readonly numForms: ValueMatcher;
  private readonly spread: ValueMatcher;
  private readonly grams = new Set<string>();
  /** 8-byte fragments of each value's hex (16 hex digits, lower case). */
  private readonly hexGrams = new Set<string>();

  /** `values`: every value, looked for whole in every form. `fragmentValues`
   *  (default: all of them): the values also looked for spread and in
   *  fragments. */
  constructor(values: readonly string[], fragmentValues: readonly string[] = values) {
    const forms: string[] = [];
    const nums: string[] = [];
    const spread: string[] = [];
    for (const v of values) {
      if (v.length < RESIDUE_MIN_LEN) continue;
      for (const f of encodedForms(v)) forms.push(f);
      nums.push(Buffer.from(v, "utf8").toString("hex"), octalForm(v), odCharForm(v).toLowerCase());
    }
    for (const v of fragmentValues) {
      if (v.length < RESIDUE_MIN_LEN) continue;
      const hex = Buffer.from(v, "utf8").toString("hex");
      for (let i = 0; i + 2 * RESIDUE_FRAGMENT_LEN <= hex.length; i += 2) this.hexGrams.add(hex.slice(i, i + 2 * RESIDUE_FRAGMENT_LEN));
      const a = alnumUpper(v);
      if (a.length >= RESIDUE_MIN_LEN) { spread.push(a, [...a].reverse().join("")); }
      // Fragments case-folded: a chunk of a key given out in another case is
      // the same chunk. None wholly inside the public format prefix.
      const lower = v.toLowerCase();
      const skip = publicPrefixLength(v);
      for (let i = 0; i + RESIDUE_FRAGMENT_LEN <= lower.length; i++) {
        if (i + RESIDUE_FRAGMENT_LEN <= skip) continue;
        this.grams.add(lower.slice(i, i + RESIDUE_FRAGMENT_LEN));
      }
    }
    this.forms = new ValueMatcher(forms);
    this.numForms = new ValueMatcher(nums.filter((n) => n.length >= RESIDUE_MIN_LEN));
    this.spread = new ValueMatcher(spread);
  }

  /** The first kind of residue found in `text`, or null when it is clean. */
  find(text: string): "encoded" | "spread" | "fragment" | null {
    const folded = text.normalize("NFKC").replace(/\p{Cf}/gu, "");
    const views = new Set<string>();
    for (const t of [text, folded]) {
      views.add(t);
      const squeezed = t.replace(BLANKS_RE, "");
      views.add(squeezed);
      // a value wrapped inside a JSON or C string: its literal \n escapes out
      views.add(unescapeBreaks(squeezed));
      views.add(dumpSkeleton(t));
      const cols = dumpColumns(t);
      if (cols.hex !== "") { views.add(cols.hex); views.add(cols.ascii); }
    }
    for (const v of views) {
      const found = this.scan(v);
      if (found !== null) return found;
    }
    return null;
  }

  private scan(text: string): "encoded" | "spread" | "fragment" | null {
    if (this.forms.matched(text).size > 0) return "encoded";
    const lower = text.toLowerCase();
    if (this.numForms.matched(lower).size > 0) return "encoded";
    if (this.spread.matched(alnumUpper(text)).size > 0) return "spread";
    for (let i = 0; i + RESIDUE_FRAGMENT_LEN <= lower.length; i++) {
      if (this.grams.has(lower.slice(i, i + RESIDUE_FRAGMENT_LEN))) return "fragment";
    }
    const w = 2 * RESIDUE_FRAGMENT_LEN;
    for (let i = 0; i + w <= lower.length; i++) {
      if (this.hexGrams.has(lower.slice(i, i + w))) return "fragment";
    }
    return null;
  }
}
