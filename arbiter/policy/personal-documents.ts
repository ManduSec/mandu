/**
 * personal-documents — the content tier's PERSONAL DOCUMENTS (2026-10-19,
 * docs/design/confidentiality/secret-discovery.md §2.7): a text document the
 * launch walk READ and found to be a bank or card statement, a payslip, a tax
 * return, a lab report, an identity document or a note of household codes is
 * labelled `no-model`, bound nowhere, as a config file holding a credential is
 * (found-labels.ts). Pure: which files are read, what decides, and the twin.
 *
 * ── THE GAP ─────────────────────────────────────────────────────────────────
 *
 * The catalog decides by path, and the content tier of 2026-10-19 reads only
 * JSON, YAML and TOML config files. A bank statement in `bank/`, a blood-test
 * report in `health/`, a tax return's text export or a note of the house's
 * alarm code matched nothing, so it was public: on a fresh install the model
 * read every line of it and an upload went anywhere with no card (the
 * `secrets-defaults` battery of 2026-10-18: demo-scam-email's statement and
 * demo-local-health-summary's report reached the cloud model; the dog-sitter
 * note and the tax return were missed the same way).
 *
 * ── THE RULE ────────────────────────────────────────────────────────────────
 *
 * The walk reads each CANDIDATE (`documentProbeCandidate`: a `.md`,
 * `.markdown`, `.txt`, `.text`, `.csv` or `.tsv` file of at most
 * DOCUMENT_PROBE_MAX_BYTES, or since §2.8 a `.pdf`, `.docx`, `.docm`,
 * `.xlsx`, `.xlsm`, `.odt` or `.ods` file of at most
 * DOCUMENT_FILE_PROBE_MAX_BYTES whose text document-text.ts extracts and
 * this module decides the same way; in a workspace, or in HOME's `Documents`,
 * `Desktop` or `Downloads`; never a project's README, changelog, licence or
 * agent notes, never in a test, fixture, example, docs, source or vendored
 * tree, never in a dot-directory, and never inside a software project below
 * the walk root, `inSoftwareProject`) and asks `personalDocumentKind`. Each
 * kind needs SEVERAL independent signals at once, each specific on its own,
 * so a developer's notes, sample data and documentation stay readable:
 *
 *   bank-statement     an account identifier (a mod-97-valid IBAN, a
 *                      Luhn-valid card number, a masked card `**** 1234`, or
 *                      a value with 4+ digits under an account, sort-code,
 *                      routing or card label) AND two statement terms
 *                      (`statement`, `closing balance`, `available balance`,
 *                      `minimum payment`, …) AND money amounts on 3+ lines;
 *   payslip            a payslip term (`payslip`, `pay stub`, `gross pay`,
 *                      `net pay`, `earnings statement`) AND three payroll
 *                      terms in all AND money amounts on 3+ lines AND an
 *                      `Employee:` (or name, staff or payroll number) line;
 *   tax-return         a taxpayer number (an SSN or ITIN of a valid shape,
 *                      never a known example; a UK NI number; a value with
 *                      9+ digits under a tax-id label) AND two tax-return
 *                      terms (`tax return`, `adjusted gross income`, `filing
 *                      status`, `total tax`, `Form 1040`, …) AND an amount;
 *   lab-report         a patient line (`Patient:`, `MRN`, `NHS number`, or a
 *                      name AND a date of birth) AND 3+ results with a lab
 *                      unit (`mmol/L`, `g/L`, `x10^9/L`, `mU/L`, …) AND 2+
 *                      reference ranges (`(120-160)`, `(below 3.0)`);
 *   identity-document  a passport machine-readable zone, or a passport,
 *                      licence or ID number line AND a date of birth AND an
 *                      issuing, expiry or nationality line; or an SSN (valid
 *                      shape) or NI number under its own label;
 *   house-codes        2+ `Label: value` lines whose label names a door,
 *                      gate, garage, keypad, alarm, lockbox or safe code (a
 *                      value with 4+ digits) or a Wi-Fi password (8+
 *                      characters, no stand-in).
 *
 * ── THE TWIN (DOCUMENT_TWIN_EXTRACT) ────────────────────────────────────────
 *
 * The file is registered with the twin of a `paths[].extract` regex Mandu
 * writes itself: on each line the leading Markdown markers (`#`, `-`, `>`,
 * `|`) and a short `Label:` stay as written, and the REST of the line is one
 * placeholder; a line with no label is a placeholder whole; a blank line or a
 * rule (`---`, `|---|`) stays. So the model reads which line is the account,
 * the SSN or the alarm code and can put each placeholder where a task needs
 * it (a form field, a text, an upload), and reads no value; the reply filter
 * shows the human the originals. The rule is a real regex (one capturing
 * group, linear: no lazy quantifier, a bounded label), so it is valid
 * `extract:` for a human's own label too.
 *
 * ── A PERSON'S NAME (documentNameField) ─────────────────────────────────────
 *
 * The holder's, patient's or employee's NAME is a placeholder in the twin
 * like every other value (with the results of a lab report it is the
 * sensitive part), but it is no fingerprint of the value backstop or the
 * egress tripwire (2026-10-19, secret-discovery.md §2.7 "A person's name"):
 * as one it masked every mail, log and page that mentions the user, which
 * is most of them. The twin's renderer marks such a span (secret-extract.ts
 * `SecretSpan.name`); the registry still mints its field row, and the value
 * index leaves it out (registry.ts `documentNameRows`).
 *
 * Mandu-new (no reference origin).
 */

import { DOCUMENT_FILE_EXT_RE, DOCUMENT_FILE_LIMITS } from "./document-text.js";

// ── Which files the walk reads ──────────────────────────────────────────────

/** A document's size cap: a statement, a report or a note is small; a
 *  larger text is a dataset or a log (its twin would be thousands of
 *  placeholders). */
export const DOCUMENT_PROBE_MAX_BYTES = 64 * 1024;
/** How many documents one walk reads at most, and how many bytes in all
 *  (their own budget: a HOME full of notes must not crowd out the config
 *  files, found-labels.ts CONTENT_PROBE_MAX_FILES). */
export const DOCUMENT_PROBE_MAX_FILES = 512;
export const DOCUMENT_PROBE_MAX_TOTAL = 8 * 1024 * 1024;

/** The text-document extensions read. */
const DOCUMENT_EXT_RE = /\.(?:md|markdown|txt|text|csv|tsv)$/i;

/** The PDF and Office documents read (2026-10-19, §2.8): their text is
 *  extracted first (document-text.ts) and decided as a text document's. */
export { DOCUMENT_FILE_EXT_RE };

/** A PDF or Office document's own caps: its bytes at most (the
 *  extraction's, document-text.ts DOCUMENT_FILE_LIMITS.fileMax), how many
 *  one walk extracts at most and how many bytes in all (their own budget:
 *  a Downloads folder of manuals must not crowd out the text documents).
 *  A verdict is remembered by the file's size, time and inode for the
 *  arbiter's lifetime (secret-discovery.ts), so a launch re-reads only what
 *  changed. */
export const DOCUMENT_FILE_PROBE_MAX_BYTES = DOCUMENT_FILE_LIMITS.fileMax;
export const DOCUMENT_FILE_PROBE_MAX_FILES = 128;
export const DOCUMENT_FILE_PROBE_MAX_TOTAL = 64 * 1024 * 1024;

/** A template by name (found-labels.ts TEMPLATE_NAME_RE's twin). */
const TEMPLATE_NAME_RE = /[._-](example|sample|template|dist|tmpl)([._-]|$)/i;

/** A project's own documents and an agent's notes by name: never a person's
 *  statement, and the most numerous `.md` and `.txt` files there are. */
const PROJECT_DOC_NAME_RE = /^(?:readme|changelog|changes|history|news|contributing|contributors|license|licence|copying|notice|authors|maintainers|security|code_of_conduct|code-of-conduct|support|governance|agents|claude|gemini|copilot-instructions|conventions|todo|roadmap|release[-_ ]?notes|requirements(?:[-_.][^/]*)?|constraints|robots|humans|cmakelists|llms(?:-full)?|third[-_]party[-_]notices)(?:\.[a-z0-9]+)+$/i;

/** Directory names whose files are test data, examples, documentation,
 *  source or vendored code: never a person's own document (found-labels.ts
 *  NOT_CONFIG_DIRS, and the trees of a code base). Matched below the walk
 *  root. */
const NOT_DOCUMENT_DIRS: ReadonlySet<string> = new Set([
  "test", "tests", "__tests__", "spec", "specs", "e2e", "testing", "testdata", "test-data", "test_data",
  "fixture", "fixtures", "__fixtures__", "mock", "mocks", "__mocks__", "cassettes", "recordings",
  "snapshots", "__snapshots__", "example", "examples", "sample", "samples", "doc", "docs", "documentation",
  "src", "lib", "vendor", "third_party", "third-party", "node_modules", "site-packages", "seed", "seeds",
  "locales", "locale", "i18n", "l10n", "templates", "testfiles", "benchmark", "benchmarks", "dist", "build", "target",
  "design", "rfc", "rfcs", "adr", "adrs", "eval", "evals",
]);

/** HOME's folders a person keeps documents in (the XDG user directories'
 *  default names): the only part of HOME the document tier reads, unless a
 *  launch names a folder as its workspace. */
const HOME_DOCUMENT_DIRS: ReadonlySet<string> = new Set(["Documents", "Desktop", "Downloads"]);

/** The files that make a directory a software project's root: a document
 *  below one is the project's (its notes, its sample data), not a person's. */
export const PROJECT_MARKERS: readonly string[] = [
  "package.json", "Cargo.toml", "pyproject.toml", "setup.py", "setup.cfg", "go.mod", "pom.xml", "build.gradle",
  "build.gradle.kts", "Gemfile", "composer.json", "mix.exs", "CMakeLists.txt", "Makefile", "deno.json", "pubspec.yaml",
  "Package.swift", "stack.yaml", "dune-project", "build.sbt",
];

/**
 * Does the walk read this file for the document tier? `rel`: the path's
 * segments below its walk root (the basename last); `tier` as
 * found-labels.ts `contentProbeCandidate`. The project test
 * (`inSoftwareProject`) is the walk's, over the directories. Pure.
 */
export function documentProbeCandidate(rel: readonly string[], tier: "workspace" | "home"): boolean {
  if (rel.length === 0) return false;
  const base = rel[rel.length - 1]!;
  if (!(DOCUMENT_EXT_RE.test(base) || DOCUMENT_FILE_EXT_RE.test(base)) || TEMPLATE_NAME_RE.test(base) || PROJECT_DOC_NAME_RE.test(base) || base.startsWith(".")) return false;
  const dirs = rel.slice(0, -1);
  for (const d of dirs) {
    if (d.startsWith(".") || NOT_DOCUMENT_DIRS.has(d.toLowerCase())) return false;
  }
  if (tier === "home") return dirs.length >= 1 && HOME_DOCUMENT_DIRS.has(dirs[0]!);
  return true;
}

/**
 * Is a file whose directories below the walk root are `dirs` (absolute,
 * outermost first) inside a software project? `listing(dir)` lists a
 * directory's names (the walk caches it). The walk root itself is never
 * asked: a workspace may be a repository, and a person's folder of
 * documents with a `Makefile` in it is still theirs. Pure but for `listing`.
 */
export function inSoftwareProject(dirs: readonly string[], listing: (dir: string) => ReadonlySet<string>): boolean {
  for (const d of dirs) {
    const names = listing(d);
    if (PROJECT_MARKERS.some((m) => names.has(m))) return true;
  }
  return false;
}

// ── The twin ────────────────────────────────────────────────────────────────

/** A letter or a digit, in a regex with no `u` flag: any character but
 *  ASCII controls, blanks and punctuation (a non-ASCII letter counts). */
const WORDISH = String.raw`[^\x00-\x2F\x3A-\x40\x5B-\x60\x7B-\x7F]`;

/**
 * The document twin's `extract:` regex (flags `gm`, secret-extract.ts
 * `extractByRegex`): per line, the leading Markdown markers and blanks, then
 * an optional label (a letter, at most 48 characters with no colon, then a
 * colon and a blank) stay; group 1, from the first non-blank character to
 * the last, is the placeholder. A line with no letter or digit (a blank
 * line, `---`, `|---|---|`) has no group and stays; a group always holds a
 * letter or digit, since the twin replaces every other copy of a value in
 * the file (secret-extract.ts `twinNeedles`) and a value of `-` would eat
 * every hyphen. Linear: the lookahead at the line's start fails a line with
 * no letter or digit before the markers could backtrack, and every other
 * quantifier is greedy or bounded.
 */
export const DOCUMENT_TWIN_EXTRACT = String.raw`^(?=[^\n]*${WORDISH})[ \t>*+#|-]*(?:[A-Za-z][^:\n]{0,47}:[ \t]+)?(?=[^\n]*${WORDISH})(\S(?:[^\n]*\S)?)`;

// ── A person's name ─────────────────────────────────────────────────────────

/** Labels whose value is a person's name (normalized: lower case, one blank
 *  between words, no emphasis): the holder of an account or a policy, a
 *  patient, an employee, a taxpayer, a member, whom a document is for. */
const NAME_FIELD_LABEL_RE = new RegExp("^(?:" + [
  String.raw`(?:(?:primary|joint|secondary|account|card|policy) )?(?:account ?|card ?|policy ?)?holders?(?: name)?`,
  String.raw`(?:(?:full|first|last|given|family|middle|legal|preferred|patient|employee|customer|client|member|taxpayer|spouse|insured|holder|cardholder|account holder|policyholder)(?:'s)? )?names?`,
  String.raw`surname|forenames?|name of (?:patient|employee|taxpayer|insured|holder|account holder|member|customer|client)`,
  String.raw`patient|employee|taxpayer|spouse|dependent|dependant|prepared for|issued to|statement for|insured(?: person| party)?`,
  String.raw`member|subscriber|customer|client|beneficiary|payee|recipient|guarantor|bill(?:ed)? to|attn|attention`,
  String.raw`(?:ordering |referring |requesting )?(?:physician|doctor|clinician|consultant)|requested by|referred by|gp`,
].join("|") + ")$");

/** Labels whose value is a secret of its own whatever its shape (a
 *  passphrase of capitalized words, a security answer that is a name). */
const SECRETISH_LABEL_RE = /pass|\bpin\b|code|combo|combination|answer|secret|security|maiden|\bkey\b|token|hint|memorable|login|user|wi-?fi|wireless|network|ssid|address|street|account|iban|card|number|\bno\b|\bid\b|ssn|nino|mrn/;

/** One word of a person's name: letters, with initials, hyphens and
 *  apostrophes (`J.`, `Demo-Rivera`, `O'Neil`), a comma after it allowed;
 *  `&` or `and` between two names. */
const NAME_WORD_RE = /^(?:&|and|\p{L}[\p{L}.'’-]*,?)$/u;

/** One capitalized word of a name by its shape: an initial (`J.`) or a
 *  capital and lower-case letters, hyphenated parts allowed. */
const SHAPE_WORD_RE = /^\p{Lu}(?:\.?|[\p{Ll}'’]+(?:-\p{Lu}?[\p{Ll}'’]+)*)$/u;

/**
 * Is the value of one line of a personal document's twin a person's NAME
 * (module header, "A person's name")? `label`: the line's label as written
 * (`Holder`, `**Patient name**`), or null for a line with none; `value`:
 * the span's text. A name label (`Holder`, `Name`, `Account holder`,
 * `Patient`, `Employee`, `Taxpayer`, `Prepared for`, `Insured`, `Member`,
 * …) and a value of 1 to 6 words of letters; or no label, or one that names
 * no secret, and a value of 2 to 4 capitalized words. Never a value with a
 * digit (an account number, a date of birth, `Alex Demo (MRN 1234)`), and
 * never under a label that names a secret (a password, a code, a security
 * answer, an address, a number). Pure.
 */
export function documentNameField(label: string | null, value: string): boolean {
  const v = value.trim();
  if (v === "" || v.length > 64 || /\d/.test(v)) return false;
  const l = label === null ? null : normLabel(label);
  const words = v.split(/\s+/);
  if (l !== null && NAME_FIELD_LABEL_RE.test(l)) return words.length <= 6 && words.every((w) => NAME_WORD_RE.test(w)) && /\p{L}/u.test(words[0]!);
  if (l !== null && SECRETISH_LABEL_RE.test(l)) return false;
  return words.length >= 2 && words.length <= 4 && words.every((w) => SHAPE_WORD_RE.test(w)) && /\p{Ll}/u.test(v);
}

/** The label of the twin line whose placeholder starts at `start` in
 *  `content` (DOCUMENT_TWIN_EXTRACT's optional label: after the line's
 *  Markdown markers, before the colon), or null for a line with none. */
export function documentLineLabel(content: string, start: number): string | null {
  const lineStart = content.lastIndexOf("\n", start - 1) + 1;
  const m = /^[ \t>*+#|-]*([A-Za-z][^:\n]{0,47}):[ \t]+$/.exec(content.slice(lineStart, start));
  return m ? m[1]! : null;
}

// ── What decides ────────────────────────────────────────────────────────────

/** What a found document is (the found row's field; `mandu why`'s words). */
export type DocumentKind = "bank-statement" | "payslip" | "tax-return" | "lab-report" | "identity-document" | "house-codes";

/** Each kind in plain words. */
export const DOCUMENT_KIND_WORDS: Readonly<Record<DocumentKind, string>> = {
  "bank-statement": "a bank or card statement",
  "payslip": "a payslip",
  "tax-return": "a tax return",
  "lab-report": "a medical lab report",
  "identity-document": "an identity document",
  "house-codes": "household codes",
};

/** One `Label: value` pair of a line, or of a two-cell table row. */
interface Pair { label: string; value: string }

const LABEL_LINE_RE = /^[ \t>*+#-]*(?:\*\*|__)?([A-Za-z][^:\n]{0,47}?)(?:\*\*|__)?[ \t]*:(?:\*\*|__)?[ \t]+(\S[^\n]*)$/;

/** A label as compared: lower case, one blank between words, no emphasis. */
function normLabel(s: string): string {
  return s.replace(/[*_`]/g, "").replace(/\s+/g, " ").trim().toLowerCase();
}

/** A value as compared: no emphasis, quotes or backticks around it. */
function normValue(s: string): string {
  return s.trim().replace(/^[*_`"']+|[*_`"']+$/g, "").trim();
}

/** The `Label: value` pairs of a text's lines (and `| label | value |`
 *  rows). Pure, linear. */
function pairsOf(lines: readonly string[]): Pair[] {
  const out: Pair[] = [];
  for (const line of lines) {
    if (line.length > 4096) continue;
    const m = LABEL_LINE_RE.exec(line);
    if (m) { out.push({ label: normLabel(m[1]!), value: normValue(m[2]!) }); continue; }
    if (line.includes("|")) {
      const cells = line.split("|").map((c) => c.trim()).filter((c) => c !== "");
      if (cells.length >= 2 && /^[A-Za-z*_]/.test(cells[0]!) && cells[0]!.length <= 48 && !/^-+$/.test(cells[1]!)) {
        out.push({ label: normLabel(cells[0]!), value: normValue(cells[1]!) });
      }
    }
  }
  return out;
}

/** The distinct terms of `re` (global, case-insensitive) in `text`,
 *  lower case, blanks collapsed. */
function termsIn(text: string, re: RegExp): Set<string> {
  const out = new Set<string>();
  for (const m of text.matchAll(re)) out.add(m[0].toLowerCase().replace(/[\s-]+/g, " "));
  return out;
}

const digitsIn = (s: string): number => (s.match(/\d/g) ?? []).length;

/** A money amount: a number with exactly two decimals, thousands grouped
 *  or not, a sign or currency sign before it allowed (a CSV's comma too);
 *  never a piece of a version number or a longer number. */
const AMOUNT_RE = /(?:^|[^\w.])[-+(]?(?:[$€£¥]|USD|EUR|GBP)?\s?\d{1,3}(?:[,.' ]\d{3})*[.,]\d{2}(?![\d.,]*\d)/;

/** How many lines carry a money amount. Only lines of at most 512
 *  characters are read (a statement's line is short): AMOUNT_RE backtracks
 *  over a long run of grouped digits (`1,000,000,…`), quadratic in the
 *  line, and a planted document must not stall the launch walk. */
function amountLines(lines: readonly string[]): number {
  let n = 0;
  for (const l of lines) if (l.length <= 512 && AMOUNT_RE.test(l)) n++;
  return n;
}

// Bank and card statements.

const STATEMENT_TERMS_RE = /\b(?:statement|closing balance|opening balance|available balance|current balance|new balance|previous balance|ending balance|beginning balance|balance (?:brought|carried) forward|account summary|minimum payment|payment due|credit limit|direct debit|standing order)\b/gi;
const ACCOUNT_LABEL_RE = /^(?:(?:bank |checking |savings |current |card |credit card |debit card )?account(?: number| no\.?| #)?|acct(?: no\.?| number)?|a\/c(?: no\.?)?|sort code|routing(?: number| no\.?)?|aba(?: number| routing number)?|bsb(?: number)?|iban|card(?: number| no\.?)?|account holder number)$/;
/** Account and card numbers the documentation of every payments API
 *  prints: an example, never a person's. */
const EXAMPLE_ACCOUNT_NUMBERS: ReadonlySet<string> = new Set([
  "GB82WEST12345698765432", "GB29NWBK60161331926819", "DE89370400440532013000", "FR1420041010050500013M02606", "NL91ABNA0417164300",
  "4111111111111111", "4242424242424242", "4012888888881881", "5555555555554444", "5105105105105100", "378282246310005",
  "371449635398431", "6011111111111117", "6011000990139424", "3530111333300000", "4000056655665556", "4000000000000002",
]);

/** Is `s` (no blanks) a valid IBAN: country, check digits, 11 to 30 more,
 *  mod 97 equal to 1? */
export function ibanValid(s: string): boolean {
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s) || EXAMPLE_ACCOUNT_NUMBERS.has(s)) return false;
  const r = s.slice(4) + s.slice(0, 4);
  let mod = 0;
  for (const c of r) {
    const v = c >= "A" && c <= "Z" ? String(c.charCodeAt(0) - 55) : c;
    for (const d of v) mod = (mod * 10 + Number(d)) % 97;
  }
  return mod === 1;
}

/** Is `digits` a Luhn-valid card number (13 to 19 digits, not one digit
 *  repeated, never a documented test card)? */
export function cardNumberValid(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits) || /^(\d)\1+$/.test(digits) || EXAMPLE_ACCOUNT_NUMBERS.has(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

const IBAN_CANDIDATE_RE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g;
const CARD_CANDIDATE_RE = /\b\d(?:[ -]?\d){12,18}\b/g;
const MASKED_CARD_RE = /(?:\*{2,}|[xX•]{4})[ -]?\d{4}\b|\bending (?:in )?\d{4}\b/;

/** Does the text hold an account identifier (the bank-statement rule)? */
function accountIdentifier(text: string, pairs: readonly Pair[]): boolean {
  for (const m of text.matchAll(IBAN_CANDIDATE_RE)) if (ibanValid(m[0].replace(/ /g, ""))) return true;
  for (const m of text.matchAll(CARD_CANDIDATE_RE)) if (cardNumberValid(m[0].replace(/[ -]/g, ""))) return true;
  if (MASKED_CARD_RE.test(text)) return true;
  return pairs.some((p) => ACCOUNT_LABEL_RE.test(p.label) && digitsIn(p.value) >= 4 && !EXAMPLE_ACCOUNT_NUMBERS.has(p.value.replace(/[ -]/g, "")));
}

// Payslips.

const PAYSLIP_CORE_RE = /\b(?:pay ?slip|pay ?stub|earnings statement|gross pay|net pay)\b/gi;
/** A payslip names its employee: a developer's notes on a payroll feature
 *  use the same words and amounts, but no `Employee:` line. */
const EMPLOYEE_LABEL_RE = /^(?:employee(?: name| id| no\.?| number)?|name|staff (?:id|no\.?|number)|payroll (?:id|no\.?|number))$/;
const PAYROLL_TERMS_RE =/\b(?:pay ?slip|pay ?stub|earnings statement|gross pay|net pay|gross earnings|net earnings|pay period|pay date|year[- ]to[- ]date|ytd|deductions|tax withheld|federal withholding|state withholding|paye|national insurance|social security tax|medicare|employee (?:id|no\.?|number)|employer|overtime|pension contribution)\b/gi;

// Tax returns and taxpayer numbers.

const TAX_TERMS_RE = /\b(?:tax return|income tax|adjusted gross income|agi|taxable income|filing status|total tax|tax due|tax owed|amount (?:you )?owe|balance due|refund|withholding|form 1040|1040|w-2|1099|schedule [a-e]|self assessment|hmrc|estimated tax payments?|total payments|tax year|exemptions?)\b/gi;
const SSN_RE = /\b(\d{3})-(\d{2})-(\d{4})\b/g;
/** SSNs printed as examples (the Woolworths wallet card, documentation). */
const EXAMPLE_SSNS: ReadonlySet<string> = new Set(["123-45-6789", "078-05-1120", "219-09-9999", "987-65-4321", "457-55-5462"]);
const SSN_LABEL_RE = /^(?:ssn|social security(?: number| no\.?| #)?|soc\.? sec\.?(?: no\.?)?|itin|tin|taxpayer id(?:entification)?(?: number| no\.?)?|tax id(?: number| no\.?)?|ein)$/;
const NINO_LABEL_RE = /^(?:national insurance(?: number| no\.?)?|ni (?:number|no\.?)|nino)$/;
const NINO_RE = /^(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]$/i;
const UTR_LABEL_RE = /^(?:utr|unique taxpayer reference)(?: number| no\.?)?$/;

/** Is `ddd-dd-dddd` an SSN or ITIN of a valid shape (never area 000 or
 *  666, group 00 or serial 0000; a 9xx area only in the ITIN groups), and
 *  no documented example or one digit repeated? */
export function ssnShapeValid(s: string): boolean {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(s);
  if (!m || EXAMPLE_SSNS.has(s) || /^(\d)\1\1-\1\1-\1\1\1\1$/.test(s)) return false;
  const [area, group, serial] = [m[1]!, m[2]!, m[3]!];
  if (area === "000" || area === "666" || group === "00" || serial === "0000") return false;
  if (area.startsWith("9")) {
    const g = Number(group);
    return (g >= 50 && g <= 65) || (g >= 70 && g <= 88) || (g >= 90 && g <= 92) || g >= 94;
  }
  return true;
}

/** A taxpayer number: a valid SSN or ITIN anywhere, an NI number or UTR
 *  under its label, or 9+ digits under a tax-id label. */
function taxpayerNumber(text: string, pairs: readonly Pair[]): boolean {
  for (const m of text.matchAll(SSN_RE)) if (ssnShapeValid(m[0])) return true;
  return pairs.some((p) =>
    (NINO_LABEL_RE.test(p.label) && NINO_RE.test(p.value)) ||
    (UTR_LABEL_RE.test(p.label) && /^\d{5} ?\d{5}$/.test(p.value)) ||
    (SSN_LABEL_RE.test(p.label) && taxIdValue(p.value)));
}

/** The first word of a tax-id line's value: an SSN or ITIN of a valid
 *  shape, or another number of 9+ digits (an EIN, a TIN). */
function taxIdValue(value: string): boolean {
  const tok = value.split(/\s+/)[0]!.replace(/[.,;]$/, "");
  if (/^\d{3}-\d{2}-\d{4}$/.test(tok)) return ssnShapeValid(tok);
  return digitsIn(tok) >= 9 && /^[\d -]+$/.test(tok) && !/^(\d)\1+$/.test(tok.replace(/\D/g, ""));
}

/** An SSN or NI number under its own label (the identity rule). */
function labelledIdentityNumber(pairs: readonly Pair[]): boolean {
  return pairs.some((p) =>
    (SSN_LABEL_RE.test(p.label) && !/^(?:ein|tin)$/.test(p.label) && ssnShapeValid(p.value.slice(0, 11)) && /^\d{3}-\d{2}-\d{4}\b/.test(p.value)) ||
    (NINO_LABEL_RE.test(p.label) && NINO_RE.test(p.value)));
}

// Lab reports.

const PATIENT_LABEL_RE = /^(?:patient(?: name| id| number)?|name of patient|mrn|medical record(?: number| no\.?)|nhs (?:number|no\.?)|hospital (?:number|no\.?)|chi (?:number|no\.?))$/;
const DOB_LABEL_RE = /^(?:date of birth|d\.?o\.?b\.?|birth ?date|born)$/;
const NAME_LABEL_RE = /^(?:name|full name|surname|given names?)$/;
const LAB_RESULT_RE = /(?:^|[\s:(])\d+(?:[.,]\d+)?\s*(?:x\s?10\^?\d+\/l|10\^?\d+\/l|mmol\/l|mmol\/mol|[uµμ]mol\/l|nmol\/l|pmol\/l|mg\/dl|mg\/l|g\/l|g\/dl|[uµμ]g\/l|[uµμ]g\/dl|ng\/ml|ng\/dl|pg\/ml|[mu]?iu\/m?l|m?u\/l|meq\/l|fl|cells\/[uµμ]l|mm\/hr?|ml\/min(?:\/1\.73\s?m2)?)(?![a-z])/i;
const REF_RANGE_RE = /\(\s*(?:\d+(?:[.,]\d+)?\s*[-–]\s*\d+(?:[.,]\d+)?|(?:below|above|under|over|less than|more than|<|>|≤|≥)\s*\d+(?:[.,]\d+)?)[^)\n]{0,40}\)|\b(?:ref(?:erence)?\.? (?:range|interval)|normal range)\b/i;

// Identity documents.

const ID_NUMBER_LABEL_RE = /^(?:passport(?: number| no\.?)?|document (?:number|no\.?)|driver'?s? licen[cs]e(?: number| no\.?)?|driving licen[cs]e(?: number| no\.?)?|licen[cs]e (?:number|no\.?)|national id(?:entity)?(?: card)?(?: number| no\.?)?|id (?:card )?(?:number|no\.?))$/;
const ID_DETAIL_LABEL_RE = /^(?:nationality|place of birth|date of (?:expiry|issue)|expiry date|expiration date|expires|issue date|issued|issuing (?:country|authority|state)|authority|sex)$/;
const MRZ_LINE_RE = /^[A-Z0-9<]{44}$/;

/** A passport's machine-readable zone: two lines of 44, the first `P<`. */
function passportMrz(lines: readonly string[]): boolean {
  for (let i = 0; i + 1 < lines.length; i++) {
    const a = lines[i]!.trim();
    if (/^P[A-Z<][A-Z<]{3}/.test(a) && MRZ_LINE_RE.test(a) && MRZ_LINE_RE.test(lines[i + 1]!.trim())) return true;
  }
  return false;
}

// Household codes.

const HOUSE_CODE_LABEL_RE = /\b(?:(?:front|back|side|main|entry|garage|gate|building|lobby|door|alarm|keypad|lock ?box|key ?safe|padlock|safe|storage|shed|disarm)(?: door)?(?: keypad)? (?:code|pin|combination|combo)|(?:front|back|side|main|garage|gate|building|door) (?:door )?keypad|alarm(?: system)?(?: code| pin)?|lock ?box|key ?safe)$/;
const WIFI_PASSWORD_LABEL_RE = /\b(?:wi-?fi|wireless|wlan|network|wpa2?)(?: network)? (?:password|passphrase|key|pass)$/;

/** Is `p` a household-code line: a code with 4+ digits under a door, gate,
 *  alarm or safe label, or a Wi-Fi password of 8+ characters? */
function houseCodeLine(p: Pair): boolean {
  const v = p.value.split(/\s+\(|\s+[-–]\s+/)[0]!.trim();
  if (v === "" || /[<>{}$]/.test(v)) return false;
  if (HOUSE_CODE_LABEL_RE.test(p.label)) return digitsIn(v) >= 4 && !/^(?:0000|1234|12345|123456|1111|9999)$/.test(v.replace(/\D/g, ""));
  if (WIFI_PASSWORD_LABEL_RE.test(p.label)) return v.length >= 8 && !/\s/.test(v) && !isWordStandIn(v);
  return false;
}

/** A stand-in a note writes for a password it does not give. */
function isWordStandIn(v: string): boolean {
  return /^(?:x+|\*+|\.+|[-_]+|n\/?a|none|tbd|tba|unknown|changeme|change[-_ ]?me|password\d*|your[-_ ]?\w*|my[-_ ]?\w*|example\w*|placeholder|redacted|hidden|secret)$/i.test(v) || /^<.*>$/.test(v) || /^\[.*\]$/.test(v);
}

/**
 * What personal document `text` (the content of the file at `path`) is, or
 * null. Several independent signals per kind (module header). Pure; linear
 * in the text (each regex is bounded or greedy, each line at most 4 KiB is
 * read for pairs and amounts).
 */
export function personalDocumentKind(path: string, text: string): DocumentKind | null {
  if (!(DOCUMENT_EXT_RE.test(path) || DOCUMENT_FILE_EXT_RE.test(path)) || text.length === 0 || text.length > DOCUMENT_PROBE_MAX_BYTES * 4) return null;
  const lines = text.split(/\r?\n/);
  const pairs = pairsOf(lines);
  const amounts = amountLines(lines);

  const labels = new Set(pairs.map((p) => p.label));
  const has = (re: RegExp): boolean => [...labels].some((l) => re.test(l));

  if (has(PATIENT_LABEL_RE) || (has(NAME_LABEL_RE) && has(DOB_LABEL_RE))) {
    let results = 0;
    let ranges = 0;
    for (const l of lines) {
      if (l.length > 4096) continue;
      if (LAB_RESULT_RE.test(l)) results++;
      if (REF_RANGE_RE.test(l)) ranges++;
    }
    if (results >= 3 && ranges >= 2) return "lab-report";
  }
  if (passportMrz(lines) || (has(ID_NUMBER_LABEL_RE) && pairs.some((p) => ID_NUMBER_LABEL_RE.test(p.label) && digitsIn(p.value) >= 4 && /^[A-Z0-9 -]{6,20}$/i.test(p.value)) && has(DOB_LABEL_RE) && has(ID_DETAIL_LABEL_RE))) {
    return "identity-document";
  }
  if (taxpayerNumber(text, pairs) && termsIn(text, TAX_TERMS_RE).size >= 2 && amounts >= 1) return "tax-return";
  if (termsIn(text, PAYSLIP_CORE_RE).size >= 1 && termsIn(text, PAYROLL_TERMS_RE).size >= 3 && amounts >= 3 && has(EMPLOYEE_LABEL_RE)) return "payslip";
  if (amounts >= 3 && termsIn(text, STATEMENT_TERMS_RE).size >= 2 && accountIdentifier(text, pairs)) return "bank-statement";
  if (labelledIdentityNumber(pairs)) return "identity-document";
  if (pairs.filter(houseCodeLine).length >= 2) return "house-codes";
  return null;
}
