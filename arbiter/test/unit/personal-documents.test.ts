/**
 * personal-documents — the content tier's personal documents
 * (secret-discovery.md §2.7, 2026-10-19): which text files the launch walk
 * reads, which it takes for a statement, a payslip, a tax return, a lab
 * report, an identity document or household codes (positive and negative
 * tables, the negatives a developer's and a person's ordinary documents),
 * the document twin, how the found label composes with a human's, the
 * store's kind, the walk, and a person's name (a placeholder in the twin,
 * no fingerprint of the value index).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import Database from "../../db/sqlite.js";
import {
  DOCUMENT_TWIN_EXTRACT, cardNumberValid, documentNameField, documentProbeCandidate, ibanValid, inSoftwareProject, personalDocumentKind, ssnShapeValid,
  type DocumentKind,
} from "../../policy/personal-documents.js";
import { documentNameRows, registerSecret, registeredFileTwin } from "../../secret-registry/registry.js";
import { loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import { valueFingerprints } from "../../policy/egress-fingerprint.js";
import { FoundLabelStore } from "../../policy/found-labels.js";
import { composedLabel, foundLabel, type LabelSnapshot } from "../../policy/label-lookup.js";
import { DOCUMENT_RULE, pathConfidentiality } from "../../policy/secret-catalog.js";
import { discoverSecretsReport } from "../../policy/secret-discovery.js";
import { extractSecretSpans, renderStructuredTwin } from "../../policy/secret-extract.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import type { PathLabel } from "../../policy/path-labels.js";

const lines = (...l: string[]): string => `${l.join("\n")}\n`;

/** Two valid account numbers no documentation prints (mod 97, Luhn). */
const IBAN = "DE44500105175407324931";
const CARD = "4532015112830366";

// ── the documents Mandu takes ───────────────────────────────────────────────

const POSITIVE: ReadonlyArray<[string, DocumentKind, string]> = [
  ["bank/statement-2026-09.md", "bank-statement", lines(
    "# Maple Bank - statement, September 2026", "", "Account: 0042-118833 (current)", "Holder: Alex Demo", "",
    "2026-09-01  +3,200.00  Salary", "2026-09-03  -1,250.00  Rent", "2026-09-12     -84.10  Groceries", "Closing balance: 4,512.37")],
  ["finance/girokonto-oktober.txt", "bank-statement", lines(
    "Kontoauszug / Account statement 10/2026", `IBAN: ${IBAN.replace(/(.{4})/g, "$1 ").trim()}`,
    "Opening balance: 1.204,55 EUR", "03.10. Miete -850,00", "07.10. Supermarkt -63,20", "Closing balance: 2.391,35 EUR")],
  ["Downloads/transactions.csv", "bank-statement", lines(
    "Date,Description,Amount,Balance", `# card ${CARD}`, "2026-10-01,Coffee,-4.50,812.10", "2026-10-02,Refund,+20.00,832.10",
    "2026-10-03,Rent,-700.00,132.10", "statement end; available balance 132.10")],
  ["cards/visa-oct.md", "bank-statement", lines(
    "Visa card ending in 4821 - statement", "New balance: $1,284.19", "Minimum payment: $35.00", "Payment due: 2026-11-21",
    "- 10/02 Grocer  $82.10")],
  ["work/payslip-2026-09.txt", "payslip", lines(
    "PAYSLIP - Northwind Ltd", "Employee: Alex Demo", "Pay period: 2026-09-01 to 2026-09-30",
    "Gross pay: 4,250.00", "Income tax: 812.40", "National Insurance: 341.22", "Net pay: 3,096.38")],
  ["taxes/2025/return-summary.txt", "tax-return", lines(
    "TaxPal export - 2025 state income tax return, summary", "", "Name: Alex Demo Rivera", "SSN: 934-52-1170",
    "Filing status: Single", "Adjusted gross income (AGI): 68,452.31", "Total tax: 9,187.46", "Total payments: 8,240.19")],
  ["taxes/self-assessment-2025.md", "tax-return", lines(
    "# Self Assessment 2024-25", "UTR: 12345 67890", "National Insurance number: QQ 12 34 56 C",
    "Total income: 41,200.00", "Tax due: 6,104.20", "HMRC payment reference below.")],
  ["health/lab-results.md", "lab-report", lines(
    "# Blood test results - Northgate Community Clinic", "Patient: Rosalind Achterberg-Quist", "Date of birth: 1979-03-14", "",
    "Haemoglobin: 128 g/L (120-160)", "Ferritin: 9 ug/L (15-150)", "LDL cholesterol: 5.4 mmol/L (below 3.0)", "TSH: 2.1 mU/L (0.4-4.0)")],
  ["medical/cbc.txt", "lab-report", lines(
    "MRN: 00418822", "| Test | Result | Ref range |", "|---|---|---|", "| WBC | 6.1 x10^9/L | 4.0-11.0 |",
    "| Glucose | 98 mg/dL | (70-99) |", "| Creatinine | 0.9 mg/dL | (0.6-1.2) |")],
  ["scans/passport.txt", "identity-document", lines(
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10")],
  ["id/licence.md", "identity-document", lines(
    "Driver's licence number: D1234-56789-01234", "Date of birth: 1985-02-11", "Expiry date: 2031-02-11", "Issuing state: Ohio")],
  ["family/mom.md", "identity-document", lines("# Mom", "Social Security number: 512-73-4419", "Doctor: Dr. Lee")],
  ["home/house-codes.md", "house-codes", lines(
    "# House codes", "", "Address: 27 Alder Lane, Brookfield", "Front door keypad: 40917233", "Alarm code: 73160482",
    "Wi-Fi network: AlderLane-Home", "Wi-Fi password: Willow-Otter-MANDUDEMO-2291")],
  ["notes/cabin.md", "house-codes", lines(
    "| What | Code |", "|---|---|", "| Gate code | 4471 9921 |", "| Lockbox | 3318 |", "| WiFi password | pinecone-Harbor-77 |")],
];

// ── what stays readable: a developer's and a person's ordinary documents ────

const NEGATIVE: ReadonlyArray<[string, string, string]> = [
  ["a payments API's notes: documented test cards and example IBANs", "notes/payments.md", lines(
    "# Statement export", "The statement endpoint returns the closing balance and the available balance.",
    "Test card: 4242 4242 4242 4242, or 4111 1111 1111 1111", "IBAN: GB82 WEST 1234 5698 7654 32", "Amounts: 10.00, 250.00, 1,000.00")],
  ["a budget with amounts and no account", "budget.md", lines(
    "# October budget", "- Rent: 1,250.00", "- Groceries: 320.00", "- Savings: 400.00", "Statement day is the 3rd; closing balance target 2,000.00")],
  ["meeting notes with times and a budget line", "meetings/2026-10-02.md", lines(
    "# Planning", "Attendees: Kim, Sam", "Start: 9:30", "Budget: $12,000.00 approved", "Next: review on 2026-10-09")],
  ["a nutrition log: units, no patient", "health/food-log.md", lines(
    "# Glucose log", "Mon: 5.4 mmol/L (3.9-5.5)", "Tue: 6.1 mmol/L (3.9-5.5)", "Wed: 5.0 mmol/L (3.9-5.5)")],
  ["an article about cholesterol", "reading/cholesterol.md", lines(
    "LDL above 3.0 mmol/L is high (below 3.0 is the target).", "Total cholesterol: 5.0 mmol/L (below 5.0)", "HDL: 1.0 mmol/L (above 1.0)",
    "Name: the article's author")],
  ["a setup guide with stand-ins and the default code", "guides/router.md", lines(
    "Wi-Fi password: <your password>", "Door code: 1234", "Alarm code: (set by installer)")],
  ["one Wi-Fi password alone (one signal)", "guest.md", lines("# Guests", "Wi-Fi password: Harbor-Pine-2291x")],
  ["an invoice: tax and totals, no taxpayer number", "invoices/2026-014.md", lines(
    "Invoice 2026-014", "Subtotal: 1,000.00", "Tax: 200.00", "Total: 1,200.00", "Payment due: 2026-11-01")],
  ["the documented example SSN", "hr/ssn-format.txt", lines(
    "SSN: 123-45-6789 is the example; tax return forms ask for it", "Total tax: 1,000.00", "adjusted gross income")],
  ["an invalid SSN shape", "x.txt", lines("SSN: 000-12-3456", "tax return", "filing status", "Total tax: 10.00")],
  ["a developer's payroll feature notes (no employee line)", "notes/payroll.md", lines(
    "Payslip export: gross pay, net pay, pay period, deductions", "Example totals: 1,234.56 / 987.65 / 246.91")],
  ["sales data", "sales.csv", lines("region,quarter,amount", "north,Q1,410", "south,Q1,275", "west,Q1,520")],
  ["a recipe", "recipes/soup.md", lines("# Soup", "Stock: 2 fl oz", "Salt: 1 tsp", "Simmer: 40 min")],
  ["a changelog-style list of versions", "notes/releases.txt", lines("v1.2.30 fixed", "v1.10.00 statement export", "balance 1.20.00")],
  ["contacts", "contacts.md", lines("# Contacts", "- Kim Alvarez (dog sitter): +1 555-0142", "- Brookfield Animal Clinic: +1 555-0177")],
  ["a CV: a name and a date of birth, no results", "cv.md", lines("Name: Alex Demo", "Date of birth: 1985-02-11", "Nationality: Utopian", "Skills: TypeScript")],
];

test("personalDocumentKind: each kind on its own signals (positive table)", () => {
  for (const [path, kind, text] of POSITIVE) assert.equal(personalDocumentKind(path, text), kind, `${path} is ${kind}`);
});

test("personalDocumentKind: ordinary documents stay readable (negative table)", () => {
  for (const [why, path, text] of NEGATIVE) assert.equal(personalDocumentKind(path, text), null, `${why} (${path})`);
  // a document format the tier does not read
  assert.equal(personalDocumentKind("bank/statement.doc", POSITIVE[0]![2]), null);
  // a PDF or Office document is decided on its extracted text (§2.8)
  assert.equal(personalDocumentKind("bank/statement.pdf", POSITIVE[0]![2]), "bank-statement");
});

test("personalDocumentKind is fast on a planted worst case (a launch walk reads up to 512 of them)", () => {
  const long = (unit: string): string => unit.repeat(Math.ceil(4000 / unit.length)).slice(0, 4000);
  const doc = [
    `Patient: x`, `Account: 1234`, long("1,000"), long("( 1111"), long("1 mmol/L (1-"), long("Alarm code: 1"), long("4532 "), long("DE44 5001 "),
    long("statement closing balance "), long("x".repeat(47) + ": "), long("123-45-"),
  ].join("\n").repeat(2).slice(0, 64 * 1024);
  const t0 = Date.now();
  personalDocumentKind("x.md", doc);
  assert.ok(Date.now() - t0 < 500, `took ${Date.now() - t0} ms`);
});

test("the account and taxpayer number checks: mod 97, Luhn, the SSN and ITIN shapes, never a documented example", () => {
  assert.ok(ibanValid(IBAN));
  assert.ok(!ibanValid("DE45500105175407324931"), "a wrong check digit");
  assert.ok(!ibanValid("GB82WEST12345698765432"), "the documented example");
  assert.ok(cardNumberValid(CARD));
  assert.ok(!cardNumberValid("4532015112830367"), "fails Luhn");
  assert.ok(!cardNumberValid("4242424242424242") && !cardNumberValid("4111111111111111"), "test cards");
  assert.ok(!cardNumberValid("0000000000000000"), "one digit repeated");
  for (const s of ["512-73-4419", "934-52-1170", "900-70-1234"]) assert.ok(ssnShapeValid(s), s);
  for (const s of ["000-12-3456", "666-12-3456", "512-00-3456", "512-73-0000", "123-45-6789", "078-05-1120", "900-12-3456", "111-11-1111"]) {
    assert.ok(!ssnShapeValid(s), s);
  }
});

// ── which files the walk reads ──────────────────────────────────────────────

test("documentProbeCandidate: text documents of a workspace and of HOME's document folders; never a project's docs, test data or a dot-folder", () => {
  const ws = (p: string): boolean => documentProbeCandidate(p.split("/"), "workspace");
  const home = (p: string): boolean => documentProbeCandidate(p.split("/"), "home");
  for (const p of ["bank/statement-2026-09.md", "notes.txt", "taxes/2025/return-summary.txt", "export.csv", "x.tsv", "a.markdown", "b.text", "bank/statement.pdf", "bank/statement.docx", "x.xlsx", "y.odt", "z.ods"]) assert.ok(ws(p), p);
  for (const p of [
    "README.md", "docs/README.md", "CHANGELOG.md", "LICENSE.txt", "CONTRIBUTING.md", "AGENTS.md", "CLAUDE.md", "requirements.txt", "requirements-dev.txt",
    "robots.txt", "CMakeLists.txt", "llms.txt",
    "docs/statement.md", "test/fixtures/statement.md", "examples/payslip.txt", "src/data/x.csv", "vendor/x/notes.md", "seeds/accounts.csv",
    ".github/notes.md", ".obsidian/x.md", ".notes.md", "statement.example.md", "payslip.template.txt",
    "bank/statement.doc", "bank/statement.xls", "deck.pptx", "app.json",
  ]) {
    assert.ok(!ws(p), `${p} is not read`);
  }
  for (const p of ["Documents/bank/statement.md", "Desktop/codes.txt", "Downloads/transactions.csv"]) assert.ok(home(p), p);
  for (const p of ["notes.md", "projects/x/notes.md", ".config/x/notes.md", "Music/list.txt"]) assert.ok(!home(p), `${p} is not read in HOME`);
});

test("inSoftwareProject: a directory below the root with a build manifest makes its documents the project's", () => {
  const listings: Record<string, string[]> = { "/w/app": ["package.json", "src"], "/w/app/data": ["x.csv"], "/w/bank": ["s.md"], "/w/paper": ["Makefile"] };
  const listing = (d: string): ReadonlySet<string> => new Set(listings[d] ?? []);
  assert.ok(inSoftwareProject(["/w/app", "/w/app/data"], listing));
  assert.ok(inSoftwareProject(["/w/paper"], listing));
  assert.ok(!inSoftwareProject(["/w/bank"], listing));
  assert.ok(!inSoftwareProject([], listing), "the walk root itself is never asked");
});

// ── the twin ────────────────────────────────────────────────────────────────

test("the document twin: labels and Markdown stay, every value is a placeholder; a valid extract regex, linear", () => {
  const text = POSITIVE.find(([p]) => p === "home/house-codes.md")![2] + "\n---\n|---|---|\n| Gate | 4471 |\nThe alarm panel is just inside the door.\r\n";
  const x = extractSecretSpans("home/house-codes.md", text, { extract: DOCUMENT_TWIN_EXTRACT });
  assert.equal(x.shape, "extract");
  const twin = renderStructuredTwin(text, x.spans, (s) => `<${s.key}>`);
  for (const kept of ["# <", "Front door keypad: <", "Alarm code: <", "Wi-Fi password: <", "\n---\n", "|---|---|", "| <"]) assert.ok(twin.includes(kept), `the twin keeps ${JSON.stringify(kept)}:\n${twin}`);
  for (const value of ["40917233", "73160482", "Willow-Otter-MANDUDEMO-2291", "27 Alder Lane", "House codes", "4471", "alarm panel"]) {
    assert.ok(!twin.includes(value), `the twin hides ${value}:\n${twin}`);
  }
  assert.ok(twin.endsWith(">\r\n"), "a CRLF line keeps its CR outside the placeholder");
  // `paths[].extract` takes it as a human's own rule too (one capturing group)
  assert.deepEqual(validatePolicyDocument({ version: 1, paths: [{ path: "~/notes/codes.md", level: "no-model", extract: DOCUMENT_TWIN_EXTRACT }] }), []);
  // linear: a long line of blanks and a long label-less line
  const t0 = Date.now();
  extractSecretSpans("x.md", `a${" ".repeat(60_000)}b\n${"x:".repeat(30_000)}\n`, { extract: DOCUMENT_TWIN_EXTRACT });
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
});

// ── how a found document composes ───────────────────────────────────────────

const human = (path: string, confidentiality: PathLabel["confidentiality"], extra: Partial<PathLabel> = {}): PathLabel =>
  ({ path, confidentiality, bindings: [], recursive: false, createdAt: 0, updatedAt: 0, ...extra } as unknown as PathLabel);
const snap = (o: { human?: PathLabel[]; docs?: string[]; creds?: string[] }): LabelSnapshot => ({
  human: new Map((o.human ?? []).map((l) => [l.path, l])),
  derived: new Map(),
  clientKeys: [],
  found: new Map([...(o.docs ?? []).map((p) => [p, { path: p, kind: "document" }] as const), ...(o.creds ?? []).map((p) => [p, { path: p }] as const)]),
});

test("a found document is no-model, bound nowhere, rule content:personal-document, with the document twin; a human label decides and keeps the twin", () => {
  const f = "/home/u/ws/bank/statement.md";
  const lookup = (s: LabelSnapshot) => (p: string) => composedLabel(p, s);
  assert.deepEqual(foundLabel(f, snap({ docs: [f] })), { level: "no-model", bindings: [], via: f, origin: "found", extract: DOCUMENT_TWIN_EXTRACT });
  assert.deepEqual(pathConfidentiality(f, "/home/u", lookup(snap({ docs: [f] }))), { level: "no-model", bindings: [], rule: DOCUMENT_RULE, extract: DOCUMENT_TWIN_EXTRACT });
  // a credential's found row has no twin rule of its own (its shape's)
  assert.equal(foundLabel(f, snap({ creds: [f] }))!.extract, undefined);
  // the human's Always on an upload writes an exact rule with the host: it
  // decides the level and bindings, and the twin stays the document's
  const bound = pathConfidentiality(f, "/home/u", lookup(snap({ docs: [f], human: [human(f, "no-model", { bindings: ["parktax.test"] } as Partial<PathLabel>)] })));
  assert.deepEqual([bound.level, bound.bindings, bound.rule, bound.extract], ["no-model", ["parktax.test"], `label:${f}`, DOCUMENT_TWIN_EXTRACT]);
  // a human rule's own extract wins; a public label has no twin
  const own = pathConfidentiality(f, "/home/u", lookup(snap({ docs: [f], human: [human(f, "no-model", { extract: "Account: (\\S+)" })] })));
  assert.equal(own.extract, "Account: (\\S+)");
  const pub = pathConfidentiality(f, "/home/u", lookup(snap({ docs: [f], human: [human(f, "public")] })));
  assert.deepEqual([pub.level, pub.extract], ["public", undefined]);
  // a file the content tier never found keeps the human's whole-file twin
  assert.equal(pathConfidentiality("/home/u/ws/bank/other.md", "/home/u", lookup(snap({ docs: [f], human: [human("/home/u/ws/bank/other.md", "no-model")] }))).extract, undefined);
});

test("FoundLabelStore: a document's kind is kept across a reopen, and a table of the first content tier gains the column", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-found-docs-"));
  const db = join(dir, "symbols.sqlite");
  try {
    // the 2026-10-19 schema, before `kind`
    const old = new Database(db);
    old.exec("CREATE TABLE found_labels (path TEXT PRIMARY KEY, field TEXT NOT NULL DEFAULT '', found_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)");
    old.prepare("INSERT INTO found_labels VALUES (?, ?, ?, ?)").run("/w/accounts/power.yaml", "password", 1, 1);
    old.close();
    const a = new FoundLabelStore({ dbPath: db });
    assert.equal(a.map().get("/w/accounts/power.yaml")!.kind, undefined, "an old row is a credential's");
    const g = a.generation();
    a.add("/w/bank/statement.md", "bank-statement", undefined, "document");
    assert.ok(a.generation() > g);
    const g2 = a.generation();
    a.add("/w/bank/statement.md", "bank-statement", undefined, "document");
    assert.equal(a.generation(), g2, "the same verdict changes nothing");
    a.close();
    const b = new FoundLabelStore({ dbPath: db });
    assert.deepEqual(b.map().get("/w/bank/statement.md"), { ...b.map().get("/w/bank/statement.md")!, field: "bank-statement", kind: "document" });
    // the same file read later as a credential's config takes the new kind
    b.add("/w/bank/statement.md", "password");
    assert.equal(b.map().get("/w/bank/statement.md")!.kind, undefined);
    b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the walk ────────────────────────────────────────────────────────────────

test("the walk reads the documents, lists a personal document (rule content:personal-document, kind document), never a value; skips a project's and HOME's other folders", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-docs-walk-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "everything");
  const put = (p: string, text: string): void => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); };
  const doc = (p: string) => POSITIVE.find(([q]) => q === p)![2];
  try {
    put(join(ws, "bank/statement-2026-09.md"), doc("bank/statement-2026-09.md"));
    put(join(ws, "health/lab-results.md"), doc("health/lab-results.md"));
    put(join(ws, "notes/meeting.md"), NEGATIVE[2]![2]);
    // a software project below the root: its sample statement is its own
    put(join(ws, "bank-app/package.json"), "{}\n");
    put(join(ws, "bank-app/samples-data/statement.md"), doc("bank/statement-2026-09.md"));
    put(join(ws, "docs/statement.md"), doc("bank/statement-2026-09.md"));
    put(join(ws, "README.md"), doc("home/house-codes.md"));
    // the workspace root itself may be a repository
    put(join(ws, "Makefile"), "all:\n");
    // HOME: its document folders only
    put(join(home, "Documents/taxes/return-summary.txt"), doc("taxes/2025/return-summary.txt"));
    put(join(home, "old/house-codes.md"), doc("home/house-codes.md"));
    const r = discoverSecretsReport([home, ws], home);
    const text = JSON.stringify(r);
    for (const v of ["0042-118833", "Rosalind", "934-52-1170", "40917233"]) assert.ok(!text.includes(v), `never a value (${v})`);
    const listed = new Map(r.files.map((f) => [f.path, f.rule]));
    assert.equal(listed.get(join(ws, "bank/statement-2026-09.md")), DOCUMENT_RULE);
    assert.equal(listed.get(join(ws, "health/lab-results.md")), DOCUMENT_RULE);
    assert.equal(listed.get(join(home, "Documents/taxes/return-summary.txt")), DOCUMENT_RULE);
    for (const p of [join(ws, "notes/meeting.md"), join(ws, "bank-app/samples-data/statement.md"), join(ws, "docs/statement.md"), join(ws, "README.md"), join(home, "old/house-codes.md")]) {
      assert.ok(!listed.has(p), `${p} is not listed`);
    }
    assert.deepEqual(
      r.found!.filter((f) => f.kind === "document").map((f) => [f.path, f.field]).sort(),
      [[join(home, "Documents/taxes/return-summary.txt"), "tax-return"], [join(ws, "bank/statement-2026-09.md"), "bank-statement"], [join(ws, "health/lab-results.md"), "lab-report"]].sort(),
    );
    assert.ok(r.documents!.read >= 4 && r.documents!.capped === 0, JSON.stringify(r.documents));
    // names only, on request: no document read either
    const names = discoverSecretsReport([home, ws], home, undefined, { contentTier: false });
    assert.ok(!names.files.some((f) => f.rule === DOCUMENT_RULE));
    // read again with the statement's values gone: its label is cleared
    const stmt = join(ws, "bank/statement-2026-09.md");
    writeFileSync(stmt, "# Notes on banks\nI should open a savings account.\n");
    const s: LabelSnapshot = { human: new Map(), derived: new Map(), clientKeys: [], found: new Map([[stmt, { path: stmt, kind: "document" }]]) };
    const again = discoverSecretsReport([home, ws], home, (p) => composedLabel(p, s), { foundPaths: [stmt] });
    assert.ok(again.cleared!.includes(stmt), JSON.stringify(again.cleared));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── a person's name: a placeholder in the twin, no fingerprint (2026-10-19) ──

test("documentNameField: a name under a name label, or a name's shape under no label; never a value with a digit or under a secret's label", () => {
  const yes: ReadonlyArray<[string | null, string]> = [
    ["Holder", "Alex Demo"], ["Account holder", "Alex Demo"], ["Name", "Alex Demo Rivera"], ["**Patient name**", "Rosalind Achterberg-Quist"],
    ["Patient", "Rosalind Achterberg-Quist"], ["Employee", "Alex Demo"], ["Taxpayer", "O'Neil, Kim"], ["Prepared for", "Alex & Sam Demo"],
    ["Insured", "Alex J. Demo"], ["Member", "Alex"], ["Cardholder name", "ALEX DEMO"], ["Spouse's name", "Sam Demo"], ["Requesting physician", "Dr. Ana Ruiz"],
    [null, "Alex Demo"], [null, "Rosalind Achterberg-Quist"], ["Filed by", "Alex J. Demo"],
  ];
  for (const [label, value] of yes) assert.equal(documentNameField(label, value), true, `${label}: ${value}`);
  const no: ReadonlyArray<[string | null, string]> = [
    // an identifier, an amount, a date: a digit
    ["Account", "0042-118833 (current)"], ["Holder", "Alex Demo (MRN 4412)"], ["Date of birth", "1979-03-14"], ["Closing balance", "4,512.37"],
    ["Name", "Alex Demo, 27 Alder Lane"],
    // a secret's label, whatever the value's shape
    ["Wi-Fi password", "Correct Horse Battery Staple"], ["Mother's maiden name", "Kim Alvarez"], ["Security answer", "Fluffy Smith"],
    ["Address", "Alder Lane"], ["User name", "Alex Demo"], ["Wi-Fi network", "Alder Home"],
    // not a name's shape: one word, lower case, all capitals, a sentence, a heading with a dash
    [null, "Groceries"], [null, "alex demo"], [null, "PAYSLIP"], [null, "The alarm panel is just inside the door."],
    [null, "Blood test results - Northgate Community Clinic"], ["Filing status", "Single"], ["Note", "Call Alex Demo after five"],
    // too long for a name under a name label
    ["Name", "one two three four five six seven"],
  ];
  for (const [label, value] of no) assert.equal(documentNameField(label, value), false, `${label}: ${value}`);
});

test("the document twin marks the names (SecretSpan.name) and nothing else; a human's own extract marks none", () => {
  const names = (rel: string, extract = DOCUMENT_TWIN_EXTRACT): string[] =>
    extractSecretSpans(rel, POSITIVE.find(([p]) => p === rel)![2], { extract }).spans.filter((s) => s.name).map((s) => s.value);
  assert.deepEqual(names("bank/statement-2026-09.md"), ["Alex Demo"]);
  assert.deepEqual(names("work/payslip-2026-09.txt"), ["Alex Demo"]);
  assert.deepEqual(names("taxes/2025/return-summary.txt"), ["Alex Demo Rivera"]);
  assert.deepEqual(names("health/lab-results.md"), ["Rosalind Achterberg-Quist"]);
  assert.deepEqual(names("home/house-codes.md"), [], "a house note's codes, network and Wi-Fi password are no names");
  assert.deepEqual(names("bank/statement-2026-09.md", ":[ \\t]*(.+)"), [], "a human's own extract: every value a fingerprint, as before");
});

test("a found document's name rows: minted and a placeholder in the twin, left out of the value index and the file's line pieces; the account number stays a fingerprint", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-doc-names-"));
  try {
    const f = join(dir, "statement.md");
    const NAME = "Alexandra Demonstration-Smith"; // a name line of 24+ characters: a line piece before
    const ACCT = "0042-118833-77";
    writeFileSync(f, lines("# Maple Bank - statement, September 2026", "", `Account: ${ACCT}`, `Account holder: ${NAME}`, "",
      "2026-09-01  +3,200.00  Salary", "2026-09-03  -1,250.00  Rent", "2026-09-12     -84.10  Groceries", "Closing balance: 4,512.37"));
    const lookup = (p: string) => composedLabel(p, snap({ docs: [f] }));
    const db = join(dir, "symbols.sqlite");
    const map = loadSymbolMap(db);
    const r = registerSecret(map, { path: f, resolveLabel: lookup }, db);
    assert.ok(r.symbol && typeof r.twin === "string", r.reason);
    assert.match(r.twin, /^Account holder: \$MDU:\S+$/m, "the name is a placeholder in the twin");
    assert.ok(!r.twin.includes(NAME));
    const nameRows = documentNameRows(map, { resolveLabel: lookup });
    assert.deepEqual([...nameRows].map((n) => map.symbols.get(n)!.value), [NAME], "the name's field row, and only it");
    const twin = registeredFileTwin(map, r.symbol, { resolveLabel: lookup })!;
    assert.deepEqual([twin.names, twin.nameLines], [[NAME], [`Account holder: ${NAME}`]]);
    assert.ok(!valueFingerprints(map.symbols.get(r.symbol)!.value, 0, { bareTokens: true, twin }).includes(`Account holder: ${NAME}`), "its line is no piece of the file's row");
    const index = new RegisteredValueIndex();
    index.sync(map, undefined, 0, (name, e) => (e.field === null && e.call_id === null ? registeredFileTwin(map, name, { resolveLabel: lookup }) : null), undefined, (name) => nameRows.has(name));
    assert.deepEqual(index.occurrences(`> On Monday, ${NAME} wrote:\n> Account holder: ${NAME}\n`), [], "a mail quoting the holder: no registered value");
    assert.ok(index.occurrences(`ref ${ACCT}`).length > 0, "the account number is a fingerprint");
    assert.ok(index.occurrences("Closing balance: 4,512.37").length > 0, "the balance is one");
    // under a human's own extract the name is a fingerprint, as before
    const own = (p: string) => (p === f ? { level: "no-model" as const, bindings: [], via: f, extract: ":[ \\t]*(.+)" } : null);
    const map2 = loadSymbolMap(join(dir, "own.sqlite"));
    const r2 = registerSecret(map2, { path: f, resolveLabel: own }, join(dir, "own.sqlite"));
    assert.ok(r2.symbol, r2.reason);
    assert.equal(documentNameRows(map2, { resolveLabel: own }).size, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
