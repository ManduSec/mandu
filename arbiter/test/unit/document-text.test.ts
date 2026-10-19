/**
 * document-text — the content tier's PDF and Office reader
 * (secret-discovery.md §2.8; arbiter/policy/document-text.ts, pdf-text.ts,
 * document-twin-pdf.ts), over fixtures built at run time
 * (test/helpers/document-fixtures.ts) and three small PDFs a real producer
 * wrote (test/fixtures/documents: Ghostscript's pdfwrite from PostScript,
 * then MuPDF's AES-256 R6 encryption with an owner password only, and with
 * a user password). Every value in them is invented.
 *
 * Pins:
 *   - the formats by extension, and the row rendering (`Label: value`, or
 *     cells joined by ` | `);
 *   - PDF: a statement laid out in columns reads as labelled lines and
 *     table rows, with a simple font (Helvetica, WinAnsi) or a composite one
 *     (Identity-H, ToUnicode), `TJ` kerning as word spaces, compressed or
 *     not, in an object stream, encrypted with the empty user password
 *     (RC4 128, AES-128, AES-256 R6), a form's filled-in fields; a file that
 *     needs a password is `encrypted`; a scan is `no-text`; garbage is
 *     `unreadable`; 300 byte flips never throw;
 *   - the twin PDF: ASCII, deterministic, a valid PDF whose text is the
 *     twin's lines (placeholders and labels), `?` for what WinAnsi lacks,
 *     page breaks, a smaller size for a long line;
 *   - Word (a table's rows, deleted text not read), Excel (money and date
 *     formats, phonetic runs not read), ODF text and spreadsheet (spaces,
 *     tables, notes not read), an encrypted ODF and an OOXML container, a
 *     zip bomb;
 *   - each format's statement is a personal document (personal-documents.ts),
 *     and the walk finds them, remembers its verdict, and leaves a scan, a
 *     password-protected file and a project's sample alone;
 *   - the registry twins a found PDF as a PDF of its document twin and an
 *     Office document as its text, with no value in either.
 *
 * No privilege, no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { DOCUMENT_FILE_LIMITS, documentFormatOf, extractDocumentText, renderRow, showNumber, type DocumentTextRead } from "../../policy/document-text.js";
import { renderTwinPdf } from "../../policy/document-twin-pdf.js";
import { DOCUMENT_BLOCK_MAX_BASE64, documentBlockText } from "../../policy/document-blocks.js";
import { personalDocumentKind, documentProbeCandidate } from "../../policy/personal-documents.js";
import { discoverSecretsReport, documentFileVerdict } from "../../policy/secret-discovery.js";
import { DOCUMENT_RULE } from "../../policy/secret-catalog.js";
import { foundLabel, type LabelSnapshot } from "../../policy/label-lookup.js";
import { FoundLabelStore } from "../../policy/found-labels.js";
import { registerSecret } from "../../secret-registry/registry.js";
import { loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { buildZip } from "../helpers/office-zip.js";
import {
  buildDocxDocument, buildOdsDocument, buildOdtDocument, buildPdf, buildXlsxDocument, statementPdfItems, type PdfOptions,
} from "../helpers/document-fixtures.js";
import { blankNormalLines, structuredTwinExecOutputPath } from "../../policy/claude-code-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "documents");
const ACCOUNT = "0042-118833-77";
const HOLDER = "Alex Demo";
const CLOSING = "4,512.37";

const text = (r: DocumentTextRead): string => {
  assert.equal(r.kind, "text", JSON.stringify(r));
  return (r as { text: string }).text;
};

/** The lines a statement's PDF reads as. */
const STATEMENT_LINES = [
  "Maple Bank - Statement, September 2026",
  `Account number: ${ACCOUNT}`,
  `Account holder: ${HOLDER}`,
  "Date | Description | Amount | Balance",
  "2026-09-01 | Salary ACME Ltd | +3,200.00 | 4,646.47",
  "2026-09-03 | Rent | -1,250.00 | 3,396.47",
  "2026-09-12 | Groceries | -84.10 | 3,312.37",
  "Opening balance: 1,446.47",
  `Closing balance: ${CLOSING}`,
];

const statementPdf = (o: PdfOptions = {}): Buffer => buildPdf([statementPdfItems({ account: ACCOUNT, holder: HOLDER, closing: CLOSING })], o);

test("formats by extension, any case; legacy and other formats are not read", () => {
  assert.equal(documentFormatOf("/a/Statement.PDF"), "pdf");
  assert.equal(documentFormatOf("x.docx"), "docx");
  assert.equal(documentFormatOf("x.docm"), "docx");
  assert.equal(documentFormatOf("x.xlsx"), "xlsx");
  assert.equal(documentFormatOf("x.xlsm"), "xlsx");
  assert.equal(documentFormatOf("x.odt"), "odt");
  assert.equal(documentFormatOf("x.ods"), "ods");
  for (const p of ["x.doc", "x.xls", "x.pptx", "x.odp", "x.rtf", "x.pdf.txt", "pdf", "x."]) assert.equal(documentFormatOf(p), null, p);
});

test("a row: two cells with a label read `Label: value`; any other row joins its cells", () => {
  assert.equal(renderRow(["Account number", ACCOUNT]), `Account number: ${ACCOUNT}`);
  assert.equal(renderRow(["Closing balance:", " 4,512.37 "]), "Closing balance: 4,512.37");
  assert.equal(renderRow(["2026-09-01", "Rent", "-1,250.00"]), "2026-09-01 | Rent | -1,250.00");
  assert.equal(renderRow(["2026-09-01", "Rent"]), "2026-09-01 | Rent");
  assert.equal(renderRow(["", "only", ""]), "only");
  assert.equal(renderRow(["", ""]), "");
  assert.equal(renderRow(["a: b", "c"]), "a: b | c");
});

test("numbers as their cell format shows them", () => {
  assert.equal(showNumber("4512.37", { kind: "money", grouped: true, decimals: 2 }), "4,512.37");
  assert.equal(showNumber("-1250", { kind: "money", grouped: true, decimals: 2 }), "-1,250.00");
  assert.equal(showNumber("84.1", { kind: "plain" }), "84.10");
  assert.equal(showNumber("1250", { kind: "plain" }), "1250");
  assert.equal(showNumber("0.30000000000000004", { kind: "plain" }), "0.30");
  assert.equal(showNumber("3312.37", { kind: "plain" }), "3,312.37");
  assert.equal(showNumber("3.14159", { kind: "plain" }), "3.14159");
  assert.equal(showNumber("46266", { kind: "date" }), "2026-09-01");
  assert.equal(showNumber("abc", { kind: "money", grouped: true, decimals: 2 }), "abc");
});

test("PDF: a statement in columns reads as labelled lines and table rows, in every encoding a producer uses", () => {
  const variants: Array<[string, PdfOptions]> = [
    ["simple font, compressed", {}],
    ["uncompressed", { compress: false }],
    ["composite font with ToUnicode", { type0: true }],
    ["TJ kerning", { tj: true }],
    ["composite font, TJ", { type0: true, tj: true }],
    ["object stream", { objStm: true }],
    ["RC4 128, empty user password", { encrypt: "rc4" }],
    ["AES-128, empty user password", { encrypt: "aes" }],
    ["AES-128 and an object stream", { encrypt: "aes", objStm: true }],
  ];
  for (const [what, o] of variants) {
    const t = text(extractDocumentText(statementPdf(o), "pdf"));
    assert.deepEqual(t.split("\n"), STATEMENT_LINES, `${what}:\n${t}`);
    assert.equal(personalDocumentKind("/w/statement.pdf", t), "bank-statement", what);
  }
});

test("PDF: a file a real producer wrote (Ghostscript), and MuPDF's AES-256 R6 with an owner password only", () => {
  for (const f of ["statement-ghostscript.pdf", "statement-aes256-r6.pdf"]) {
    const t = text(extractDocumentText(readFileSync(join(FIXTURES, f)), "pdf"));
    assert.ok(t.includes(`Account number: ${ACCOUNT}`), `${f}:\n${t}`);
    assert.ok(t.includes("IBAN: GB33 BUKB 2020 1555 5555 55"), f);
    assert.ok(t.includes("2026-09-03 | Rent | -1,250.00 | 3,396.47"), f);
    assert.equal(personalDocumentKind(`/w/${f}`, t), "bank-statement", f);
  }
});

test("PDF: a password is never guessed, a scan has no text, garbage is unreadable, and a flipped byte never throws", () => {
  assert.deepEqual(extractDocumentText(readFileSync(join(FIXTURES, "statement-user-password.pdf")), "pdf"), { kind: "encrypted" });
  assert.deepEqual(extractDocumentText(statementPdf({ encrypt: "password" }), "pdf"), { kind: "encrypted" });
  assert.deepEqual(extractDocumentText(buildPdf([[]], { scanned: true }), "pdf"), { kind: "no-text" });
  assert.equal(extractDocumentText(Buffer.from("hello, not a pdf"), "pdf").kind, "unreadable");
  const base = statementPdf();
  let seed = 7;
  const rnd = (): number => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  for (let i = 0; i < 300; i++) {
    const b = Buffer.from(base);
    for (let k = 0; k < 1 + (i % 5); k++) b[rnd() % b.length] = rnd() & 255;
    const r = extractDocumentText(i % 7 === 0 ? b.subarray(0, rnd() % b.length) : b, "pdf");
    assert.ok(["text", "no-text", "unreadable", "encrypted", "too-long"].includes(r.kind));
  }
});

test("PDF: a form's filled-in fields are read after the pages, named by their description", () => {
  const pdf = buildPdf([[{ x: 50, y: 700, text: "Form 1040 - U.S. Individual Income Tax Return 2025" }, { x: 50, y: 680, text: "Filing status: Single" }]],
    { fields: [{ tu: "Your social security number", v: "934-52-1170" }, { tu: "Adjusted gross income", v: "68,452.31" }] });
  const t = text(extractDocumentText(pdf, "pdf"));
  assert.ok(t.includes("Your social security number: 934-52-1170"), t);
  assert.ok(t.includes("Adjusted gross income: 68,452.31"), t);
  assert.equal(personalDocumentKind("/w/f1040.pdf", t), "tax-return");
  // encrypted strings too
  const enc = text(extractDocumentText(buildPdf([[{ x: 50, y: 700, text: "Form 1040 - U.S. Individual Income Tax Return 2025" }]], { encrypt: "rc4", fields: [{ tu: "Your social security number", v: "934-52-1170" }] }), "pdf"));
  assert.ok(enc.includes("Your social security number: 934-52-1170"), enc);
});

test("PDF: the text is capped (too-long), and so is the number of pages", () => {
  const items = Array.from({ length: 60 }, (_, i) => ({ x: 50, y: 760 - 12 * i, text: `Line ${i} ${"x".repeat(80)}` }));
  assert.deepEqual(extractDocumentText(buildPdf([items, items, items]), "pdf", { textMax: 4096 }), { kind: "too-long" });
});

test("the twin PDF: ASCII, deterministic, a PDF whose text is the twin's lines", () => {
  const twin = [
    "# Maple Bank (statement) \\ September", "", "Account number: $MDU:nomodel_Read[a1b2].extract_2", "Holder: $MDU:nomodel_Read[a1b2].extract_3",
    "Café: 3,00 € — 한국", "$MDU:nomodel_Read[a1b2].extract_4",
  ].join("\n");
  const pdf = renderTwinPdf(twin);
  assert.equal(pdf, renderTwinPdf(twin), "the same text renders the same bytes");
  assert.ok(pdf.startsWith("%PDF-1.4\n"));
  assert.ok(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(pdf), "ASCII only");
  assert.ok(!pdf.includes("한국"));
  const t = text(extractDocumentText(Buffer.from(pdf, "latin1"), "pdf"));
  assert.deepEqual(t.split("\n"), [
    "# Maple Bank (statement) \\ September", "Account number: $MDU:nomodel_Read[a1b2].extract_2", "Holder: $MDU:nomodel_Read[a1b2].extract_3",
    "Café: 3,00 € — ??", "$MDU:nomodel_Read[a1b2].extract_4",
  ]);
  // page breaks, and a long line set small enough to fit
  const many = Array.from({ length: 200 }, (_, i) => `Line ${i}: $MDU:nomodel_Read[a1b2].extract_${i + 1}`).join("\n");
  const long = renderTwinPdf(many);
  assert.ok((long.match(/\/Type \/Page /g) ?? []).length >= 3);
  const lt = text(extractDocumentText(Buffer.from(long, "latin1"), "pdf")).split("\n").filter((l) => l !== "");
  assert.equal(lt.length, 200);
  assert.equal(lt[199], "Line 199: $MDU:nomodel_Read[a1b2].extract_200");
  const wide = renderTwinPdf(`Note: ${"$MDU:nomodel_Read[a1b2].extract_9 ".repeat(8)}`);
  assert.match(wide, /\/F1 4 Tf/);
});

test("Word: paragraphs and a table's rows; deleted text is not text", () => {
  const docx = buildDocxDocument([
    "PAYSLIP - Northwind Ltd",
    [["Employee", "Alex Demo"], ["Pay period", "2026-09-01 to 2026-09-30"], ["Gross pay", "4,250.00"], ["Income tax", "812.40"],
      ["National Insurance", "341.22"], ["Net pay", "3,096.38"]],
    "Thank you & regards",
  ]);
  const t = text(extractDocumentText(docx, "docx"));
  assert.deepEqual(t.split("\n"), [
    "PAYSLIP - Northwind Ltd", "Employee: Alex Demo", "Pay period: 2026-09-01 to 2026-09-30", "Gross pay: 4,250.00", "Income tax: 812.40",
    "National Insurance: 341.22", "Net pay: 3,096.38", "Thank you & regards",
  ]);
  assert.equal(personalDocumentKind("/w/payslip.docx", t), "payslip");
});

test("Excel: rows as lines, money and dates as their formats show them, phonetic runs not read", () => {
  const xlsx = buildXlsxDocument([
    ["Maple Bank - account statement"], ["Account number", ACCOUNT], ["Account holder", HOLDER], [],
    ["Date", "Description", "Amount", "Balance"],
    [{ n: 46266, fmt: "date" }, "Salary", { n: 3200, fmt: "money" }, { n: 4646.47, fmt: "money" }],
    [{ n: 46268, fmt: "date" }, "Rent", { n: -1250, fmt: "money" }, { n: 3396.47, fmt: "money" }],
    [{ n: 46277, fmt: "date" }, "Groceries", { n: -84.1 }, { n: 3312.37 }],
    ["Closing balance", { n: 4512.37, fmt: "money" }],
  ]);
  const t = text(extractDocumentText(xlsx, "xlsx"));
  assert.deepEqual(t.split("\n"), [
    "Maple Bank - account statement", `Account number: ${ACCOUNT}`, `Account holder: ${HOLDER}`, "", "Date | Description | Amount | Balance",
    "2026-09-01 | Salary | 3,200.00 | 4,646.47", "2026-09-03 | Rent | -1,250.00 | 3,396.47", "2026-09-12 | Groceries | -84.10 | 3,312.37",
    `Closing balance: ${CLOSING}`,
  ]);
  assert.ok(!t.includes("PHONETIC"));
  assert.equal(personalDocumentKind("/w/transactions.xlsx", t), "bank-statement");
});

test("ODF: a text document's paragraphs, spaces and tables, a spreadsheet's rows; notes are not text", () => {
  const odt = buildOdtDocument([
    "Blood test results - Northgate Community Clinic", "Patient: Rosalind  Achterberg-Quist", "Date of birth: 1979-03-14",
    [["Haemoglobin", "128 g/L (120-160)"], ["Ferritin", "9 ug/L (15-150)"], ["LDL cholesterol", "5.4 mmol/L (below 3.0)"], ["TSH", "2.1 mU/L (0.4-4.0)"]],
  ]);
  const t = text(extractDocumentText(odt, "odt"));
  assert.deepEqual(t.split("\n"), [
    "Blood test results - Northgate Community Clinic", "Patient: Rosalind  Achterberg-Quist", "Date of birth: 1979-03-14",
    "Haemoglobin: 128 g/L (120-160)", "Ferritin: 9 ug/L (15-150)", "LDL cholesterol: 5.4 mmol/L (below 3.0)", "TSH: 2.1 mU/L (0.4-4.0)", "", "kept",
  ]);
  assert.equal(personalDocumentKind("/w/results.odt", t), "lab-report");
  const ods = buildOdsDocument([["Statement - Maple Bank"], ["Account number", ACCOUNT], ["Date", "Amount"], ["2026-09-01", "+3,200.00"],
    ["2026-09-03", "-1,250.00"], ["Opening balance", "1,446.47"], ["Closing balance", CLOSING]]);
  const s = text(extractDocumentText(ods, "ods"));
  assert.ok(s.includes(`Account number: ${ACCOUNT}`) && s.includes("2026-09-03 | -1,250.00"), s);
  assert.equal(personalDocumentKind("/w/stmt.ods", s), "bank-statement");
});

test("refused: an encrypted ODF, an OOXML encryption container (or a legacy file renamed), a zip bomb, a missing part, not a zip", () => {
  assert.deepEqual(extractDocumentText(buildOdtDocument(["x"], { encrypted: true }), "odt"), { kind: "encrypted" });
  const cfb = Buffer.alloc(1024);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(cfb);
  assert.deepEqual(extractDocumentText(cfb, "docx"), { kind: "encrypted" });
  const bomb = buildZip([{ name: "word/document.xml", data: Buffer.alloc(DOCUMENT_FILE_LIMITS.partOutMax + 1024, 0x20) }]);
  assert.equal(extractDocumentText(bomb, "docx").kind, "unreadable");
  assert.equal(extractDocumentText(buildZip([{ name: "x.xml", data: "<a/>" }]), "docx").kind, "unreadable");
  assert.equal(extractDocumentText(Buffer.from("PK not really"), "xlsx").kind, "unreadable");
  const docx = buildDocxDocument(["hello"]);
  for (let i = 0; i < docx.length; i += 7) assert.ok(["text", "no-text", "unreadable", "encrypted", "too-long"].includes(extractDocumentText(docx.subarray(0, i), "docx").kind));
});

test("the walk's candidates include PDF and Office documents, by the same rules as text documents", () => {
  for (const rel of [["bank", "statement.pdf"], ["Payslip-2026-09.docx"], ["money", "transactions.xlsx"], ["health", "results.odt"], ["stmt.ods"]]) {
    assert.ok(documentProbeCandidate(rel, "workspace"), rel.join("/"));
  }
  assert.ok(documentProbeCandidate(["Downloads", "statement.pdf"], "home"));
  assert.ok(!documentProbeCandidate(["Library", "statement.pdf"], "home"));
  assert.ok(!documentProbeCandidate(["docs", "manual.pdf"], "workspace"));
  assert.ok(!documentProbeCandidate(["statement.doc"], "workspace"));
  assert.ok(!documentProbeCandidate(["statement-template.docx"], "workspace"));
  assert.deepEqual(documentFileVerdict("/w/x.pdf", { kind: "no-text" }), "clean");
  assert.deepEqual(documentFileVerdict("/w/x.pdf", { kind: "encrypted" }), "unread");
  assert.deepEqual(documentFileVerdict("/w/x.pdf", { kind: "text", text: "hello world, nothing personal here" }), "clean");
});

function scratch(): { dir: string; home: string; ws: string; write(rel: string, b: Buffer | string): string } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-doc-files-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "papers");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  return {
    dir, home, ws,
    write(rel, b) { const p = join(ws, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, b); return p; },
  };
}

test("the walk finds a statement PDF, a payslip, a spreadsheet statement and a lab report, and leaves a scan, a locked file and a project's sample alone", () => {
  const s = scratch();
  try {
    const at = {
      pdf: s.write("bank/statement-2026-09.pdf", statementPdf()),
      docx: s.write("work/payslip.docx", buildDocxDocument(["PAYSLIP - Northwind Ltd", [["Employee", HOLDER], ["Pay period", "2026-09"], ["Gross pay", "4,250.00"], ["Income tax", "812.40"], ["Net pay", "3,096.38"]]])),
      xlsx: s.write("bank/transactions.xlsx", buildXlsxDocument([["Statement"], ["Account number", ACCOUNT], ["Date", "Amount"], ["2026-09-01", { n: 3200.5 }], ["2026-09-02", { n: -12.25 }], ["Closing balance", { n: 4512.37 }]])),
      odt: s.write("health/results.odt", buildOdtDocument(["Patient: Rosalind Achterberg-Quist", "Date of birth: 1979-03-14", "Haemoglobin: 128 g/L (120-160)", "Ferritin: 9 ug/L (15-150)", "TSH: 2.1 mU/L (0.4-4.0)"])),
      scan: s.write("bank/scan.pdf", buildPdf([[]], { scanned: true })),
      locked: s.write("bank/locked.pdf", statementPdf({ encrypt: "password" })),
      sample: s.write("bank-app/sample/statement.pdf", statementPdf()),
    };
    s.write("bank-app/package.json", "{}\n");
    const report = discoverSecretsReport([s.home, s.ws], s.home);
    const found = new Map((report.found ?? []).map((f) => [f.path, f]));
    for (const [k, kind] of [["pdf", "bank-statement"], ["docx", "payslip"], ["xlsx", "bank-statement"], ["odt", "lab-report"]] as const) {
      assert.deepEqual(found.get(at[k]), { path: at[k], field: kind, kind: "document" }, k);
      assert.equal(report.files.find((f) => f.path === at[k])?.rule, DOCUMENT_RULE, k);
    }
    for (const k of ["scan", "locked", "sample"] as const) assert.ok(!found.has(at[k]) && !report.files.some((f) => f.path === at[k]), k);
    assert.ok(!JSON.stringify(report).includes(ACCOUNT), "the walk answers paths and kinds, never a value");
    // the verdicts are remembered: a second walk answers the same
    const again = discoverSecretsReport([s.home, s.ws], s.home);
    assert.deepEqual((again.found ?? []).map((f) => f.path).sort(), [...found.keys()].sort());
  } finally {
    rmSync(s.dir, { recursive: true, force: true });
  }
});

test("the registry twins a found PDF as a PDF of its document twin, an Office document as its text: labels kept, no value", () => {
  const s = scratch();
  const store = new FoundLabelStore({ dbPath: join(s.dir, "symbols.sqlite") });
  try {
    const pdf = s.write("bank/statement.pdf", statementPdf({ type0: true }));
    const docx = s.write("work/payslip.docx", buildDocxDocument(["PAYSLIP", [["Employee", HOLDER], ["Account number", ACCOUNT], ["Net pay", "3,096.38"]]]));
    store.add(pdf, "bank-statement", s.home, "document");
    store.add(docx, "payslip", s.home, "document");
    const snapshot: LabelSnapshot = { human: new Map(), derived: new Map(), clientKeys: [], found: store.map() };
    const resolveLabel = (p: string) => foundLabel(p, snapshot);
    const map = loadSymbolMap(join(s.dir, "symbols.sqlite"));
    const r = registerSecret(map, { path: pdf, home: s.home, resolveLabel }, join(s.dir, "symbols.sqlite"));
    assert.ok(r.symbol && typeof r.twin === "string", r.reason);
    assert.ok(r.twin!.startsWith("%PDF-"), "a PDF's twin is a PDF");
    assert.ok(!r.twin!.includes(ACCOUNT) && !r.twin!.includes(CLOSING), "no value in the twin PDF");
    const twinText = text(extractDocumentText(Buffer.from(r.twin!, "latin1"), "pdf"));
    assert.match(twinText, /^Account number: \$MDU:nomodel_Read\[[^\]]+\]\.extract_\d+$/m);
    assert.match(twinText, /^Closing balance: \$MDU:nomodel_Read/m);
    const field = [...map.symbols.values()].find((e) => e.origin === pdf && e.value === ACCOUNT);
    assert.ok(field, "the account number is a registered value (the backstop masks it anywhere)");
    const base = [...map.symbols.values()].find((e) => e.origin === pdf && e.field === null);
    assert.ok(base && base.value.includes(`Account number: ${ACCOUNT}`), "the base row is the document's text");
    const d = registerSecret(map, { path: docx, home: s.home, resolveLabel }, join(s.dir, "symbols.sqlite"));
    assert.ok(d.twin && !d.twin.startsWith("PK") && /^Account number: \$MDU:/m.test(d.twin) && !d.twin.includes(ACCOUNT), d.twin);
    // re-registering the unchanged file reuses the same names
    assert.equal(registerSecret(map, { path: pdf, home: s.home, resolveLabel }, join(s.dir, "symbols.sqlite")).twin, r.twin);
  } finally {
    store.close();
    rmSync(s.dir, { recursive: true, force: true });
  }
});

test("a PDF tool's rendering of a PDF document's twin is the twin when only its blanks differ; any other byte, or another file's twin, is not", () => {
  const twinText = ["Maple Bank - Statement, September 2026", "Account number: $MDU:nomodel_Read[a1b2].extract_2", "Closing balance: $MDU:nomodel_Read[a1b2].extract_9"].join("\n");
  const twinFor = (path: string) => (tok: string) => (tok.startsWith("$MDU:nomodel_Read[a1b2]") ? { path, text: twinText, secrets: ["4,512.37"] } : null);
  const pdf = twinFor("/w/bank/statement.pdf");
  // exactly the twin, and pdftotext's renderings of it
  assert.equal(structuredTwinExecOutputPath(twinText, pdf), "/w/bank/statement.pdf");
  assert.equal(structuredTwinExecOutputPath(`${twinText}\n\f`, pdf), "/w/bank/statement.pdf");
  assert.equal(structuredTwinExecOutputPath(twinText.replace(/: /g, ":     ").split("\n").join("\n\n"), pdf), "/w/bank/statement.pdf");
  assert.equal(blankNormalLines("  a \t b\f\n\n c  "), "a b\nc");
  // a byte that is not the twin's, a value, lines out of order: no release
  assert.equal(structuredTwinExecOutputPath(`${twinText}\nx`, pdf), null);
  assert.equal(structuredTwinExecOutputPath(twinText.replace("Closing balance:", "Closing balance: 4,512.37"), pdf), null);
  assert.equal(structuredTwinExecOutputPath(twinText.split("\n").reverse().join("\n"), pdf), null);
  // another format's twin is matched exactly, as before
  assert.equal(structuredTwinExecOutputPath(`${twinText}\n\f`, twinFor("/w/work/payslip.docx")), null);
  assert.equal(structuredTwinExecOutputPath(twinText, twinFor("/w/work/payslip.docx")), "/w/work/payslip.docx");
});

test("a PDF document block's text: the twin's text for the twin or the document as registered, else the text layer; null when there is none", () => {
  const raw = statementPdf();
  const base = text(extractDocumentText(raw, "pdf"));
  const twinText = base.replace(/^(Account number|Account holder|Closing balance): .*$/gm, "$1: $MDU:nomodel_Read[a1b2].extract_1");
  const twin = { path: "/w/bank/statement.pdf", text: twinText, base };
  const b64 = (b: Buffer | string): string => (typeof b === "string" ? Buffer.from(b, "latin1") : b).toString("base64");
  assert.deepEqual(documentBlockText(b64(renderTwinPdf(twinText)), "application/pdf", twin), { text: twinText, twinOf: twin.path, reason: "the twin of a personal document, as the guard serves it" });
  assert.deepEqual(documentBlockText(b64(raw), "application/pdf", twin), { text: twinText, twinOf: twin.path, reason: "a personal document as registered: its twin's text" });
  // another PDF at that path (changed since), or no registered twin: its text, for the classify to judge
  const other = buildPdf([statementPdfItems({ account: "0099-554433-21", holder: HOLDER, closing: "9,999.99" })]);
  assert.ok(documentBlockText(b64(other), "application/pdf", twin).text!.includes("0099-554433-21"));
  assert.equal(documentBlockText(b64(raw), "application/pdf", null).text, base);
  // none: not a PDF, a scan, a password, garbage, not base64, too large
  assert.equal(documentBlockText(b64(raw), "image/png", twin).text, null);
  assert.equal(documentBlockText(b64(buildPdf([[]], { scanned: true })), "application/pdf", null).text, null);
  assert.equal(documentBlockText(b64(statementPdf({ encrypt: "password" })), "application/pdf", null).text, null);
  assert.equal(documentBlockText(b64("hello"), "application/pdf", null).text, null);
  assert.equal(documentBlockText("%%%not base64%%%", "application/pdf", null).text, null);
  assert.equal(documentBlockText("A".repeat(DOCUMENT_BLOCK_MAX_BASE64 + 4), "application/pdf", null).text, null);
  assert.equal(documentBlockText(42, "application/pdf", null).text, null);
});
