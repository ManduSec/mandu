/**
 * content-tier-document-files — the content tier's personal documents kept
 * as PDF and Office files, end to end (secret-discovery.md §2.8): a bank
 * statement PDF, a payslip `.docx`, a statement `.xlsx` and a lab report
 * `.odt` are found with no label of the human's, twinned (the PDF as a PDF
 * of its document twin, an Office document as its text), and reach the
 * model only as labels and placeholders, through the shell commands an
 * agent runs on them (`pdftotext`, `unzip -p`, a script that names no
 * file) and through Claude Code's `Read` of the PDF.
 *
 * The gap it closes: the content tier of 2026-10-19 read `.md`, `.txt` and
 * `.csv` only, so the same statement as a PDF (as banks send them) was
 * public: `pdftotext statement.pdf -` showed the model every value and an
 * upload went anywhere with no card.
 *
 * Real ArbiterServer, the launch's secret setup as the launcher does it
 * (`discoverSecretsReport`, `registerSecret` per file), and the PRODUCTION
 * proxy wiring (`new ArbiterClientAdapter(new ArbiterClient(sock))`) in
 * front of a mock upstream: what the upstream receives is what the model
 * would. No guard here (no kernel): a program's output is what it prints
 * from the RAW file, the worst case of an unconfined session.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { inflateRawSync } from "node:zlib";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { extractDocumentText } from "../../arbiter/policy/document-text.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import {
  buildDocxDocument, buildOdtDocument, buildPdf, buildXlsxDocument, statementPdfItems,
} from "../../arbiter/test/helpers/document-fixtures.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const ACCOUNT = "0042-118833-77";
const IBAN = "DE44 5001 0517 5407 3249 31";
const CLOSING = "4,512.37";
const EMPLOYEE_NO = "EMP-0048817";
const NET_PAY = "3,096.38";
const PATIENT = "Rosalind Achterberg-Quist";
const LDL = "5.4 mmol/L (below 3.0)";

/** The workspace: four personal documents, and what must stay readable. */
function files(): Record<string, Buffer> {
  return {
    "bank/statement-2026-09.pdf": buildPdf([statementPdfItems({ account: ACCOUNT, holder: "Alex Demo", iban: IBAN, closing: CLOSING })], { type0: true }),
    "work/payslip-2026-09.docx": buildDocxDocument(["PAYSLIP - Northwind Ltd", [["Employee", "Alex Demo"], ["Employee number", EMPLOYEE_NO],
      ["Pay period", "2026-09-01 to 2026-09-30"], ["Gross pay", "4,250.00"], ["Income tax", "812.40"], ["National Insurance", "341.22"], ["Net pay", NET_PAY]]]),
    "bank/transactions.xlsx": buildXlsxDocument([["Maple Bank - account statement"], ["Account number", ACCOUNT], ["Date", "Description", "Amount"],
      [{ n: 46266, fmt: "date" }, "Salary", { n: 3200, fmt: "money" }], [{ n: 46268, fmt: "date" }, "Rent", { n: -1250, fmt: "money" }],
      [{ n: 46277, fmt: "date" }, "Groceries", { n: -84.1, fmt: "money" }], ["Closing balance", { n: 4512.37, fmt: "money" }]]),
    "health/results.odt": buildOdtDocument(["Blood test results - Northgate Community Clinic", `Patient: ${PATIENT}`, "Date of birth: 1979-03-14",
      [["Haemoglobin", "128 g/L (120-160)"], ["Ferritin", "9 ug/L (15-150)"], ["LDL cholesterol", LDL], ["TSH", "2.1 mU/L (0.4-4.0)"]]]),
    // a software project's sample statement, a scan: not documents of the user's it can read
    "bank-app/package.json": Buffer.from("{}\n"),
    "bank-app/samples/statement.pdf": buildPdf([statementPdfItems({ account: ACCOUNT, holder: "Sample", closing: "1.00" })]),
    "scans/receipt.pdf": buildPdf([[]], { scanned: true }),
  };
}

const DOCS: ReadonlyArray<{ rel: string; kind: string; values: string[]; kept: string[] }> = [
  { rel: "bank/statement-2026-09.pdf", kind: "bank-statement", values: [ACCOUNT, IBAN, CLOSING, "+3,200.00 | 4,646.47"], kept: ["Account number: $MDU:", "Closing balance: $MDU:"] },
  { rel: "work/payslip-2026-09.docx", kind: "payslip", values: [EMPLOYEE_NO, NET_PAY, "4,250.00"], kept: ["Employee number: $MDU:", "Net pay: $MDU:"] },
  { rel: "bank/transactions.xlsx", kind: "bank-statement", values: [ACCOUNT, CLOSING, "-1,250.00"], kept: ["Account number: $MDU:", "Closing balance: $MDU:"] },
  { rel: "health/results.odt", kind: "lab-report", values: [PATIENT, LDL, "1979-03-14"], kept: ["Patient: $MDU:", "LDL cholesterol: $MDU:"] },
];

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function turn(input: { file_path: string } | { command: string }, content: unknown, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "go through my papers and take care of what needs doing" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "file_path" in input ? "Read" : "Bash", input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

/** Claude Code's Read result for a PDF (2.1.x): a header, then the file as
 *  a base64 document block. */
function claudePdfRead(path: string, bytes: Buffer): unknown[] {
  return [
    { type: "text", text: `PDF file read: ${path} (${bytes.length} B)` },
    { type: "document", source: { type: "base64", media_type: "application/pdf", data: bytes.toString("base64") } },
  ];
}

/** What `unzip -p x.docx word/document.xml` prints. */
function docxXml(bytes: Buffer): string {
  // the entry is the archive's second (buildZip writes no data descriptor)
  const at = bytes.indexOf(Buffer.from("word/document.xml"));
  const lh = at - 30;
  const comp = bytes.readUInt32LE(lh + 18);
  const start = at + bytes.readUInt16LE(lh + 26) + bytes.readUInt16LE(lh + 28);
  return inflateRawSync(bytes.subarray(start, start + comp)).toString("utf8");
}

test("a statement PDF, a payslip .docx, a statement .xlsx and a lab report .odt are found, twinned, and reach the model only as labels and placeholders (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-content-docfiles-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "papers");
  mkdirSync(home, { recursive: true });
  const fx = files();
  for (const [rel, b] of Object.entries(fx)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), b);
  }
  const at = (rel: string): string => join(ws, rel);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const real = new ArbiterClient(join(dir, "arbiter.sock"));
  await real.connect();
  // the guard reports on the human socket (plan 13 D9); the proxy's second client
  const guard = new ArbiterClient(join(dir, "human", "h.sock"));
  await guard.connect();
  const realHuman = new ArbiterClient(join(dir, "human", "h.sock"));
  await realHuman.connect();
  const sessionKey = `content-docfiles-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "content-docfiles e2e" })).bound, "claude-code");

    // The launch's secret setup (launcher/src/secret-setup.ts).
    const report = await real.discoverSecretsReport([home, ws], home);
    const allValues = DOCS.flatMap((d) => d.values);
    assert.ok(!allValues.some((v) => JSON.stringify(report).includes(v)), "the walk answers paths and kinds, never a value");
    const found = new Map((report.found ?? []).map((f) => [f.path, f.field]));
    for (const d of DOCS) assert.equal(found.get(at(d.rel)), d.kind, `the content tier read ${d.rel}`);
    for (const rel of ["bank-app/samples/statement.pdf", "scans/receipt.pdf"]) assert.ok(!report.files.some((f) => f.path === at(rel)), `${rel} is left alone`);
    const twins = new Map<string, string>();
    for (const f of report.files) {
      const r = await real.registerSecret({ path: f.path, home });
      assert.ok(r.symbol, `${f.path}: ${r.reason}`);
      if (typeof r.twin === "string") twins.set(f.path, r.twin);
    }

    const forwarded = async (input: { file_path: string } | { command: string }, content: unknown, id = `tu_${n++}`): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), turn(input, content, id), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      return Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
    };
    const inBody = (sent: string, v: string): boolean => sent.includes(JSON.stringify(v).slice(1, -1));

    for (const d of DOCS) {
      const path = at(d.rel);
      assert.deepEqual(await real.pathLevel(path), { level: "no-model", bindings: [], axis: true, rule: "content:personal-document" }, d.rel);
      const raw = fx[d.rel]!;
      const rawText = (extractDocumentText(raw, d.rel.endsWith(".pdf") ? "pdf" : d.rel.endsWith(".docx") ? "docx" : d.rel.endsWith(".xlsx") ? "xlsx" : "odt") as { text: string }).text;
      // the copy programs read: the labels as written, every value a placeholder
      const twin = twins.get(path)!;
      assert.ok(twin, `${d.rel}: a structured twin`);
      const twinText = d.rel.endsWith(".pdf") ? (extractDocumentText(Buffer.from(twin, "latin1"), "pdf") as { text: string }).text : twin;
      if (d.rel.endsWith(".pdf")) assert.ok(twin.startsWith("%PDF-"), "a PDF's twin is a PDF");
      for (const v of d.values) assert.ok(!twin.includes(v) && !twinText.includes(v), `${d.rel}: the twin hides ${v}:\n${twinText}`);
      for (const k of d.kept) assert.ok(twinText.includes(k), `${d.rel}: the twin keeps ${k}:\n${twinText}`);

      // what reaches the model from the RAW file: a command that names it
      // (`pdftotext`, `unzip -p`), one that does not (a script over the
      // folder), the text with another layout (pdftotext -layout's blanks)
      const cases: Array<[{ command: string } | { file_path: string }, unknown]> = [
        [{ command: `pdftotext '${d.rel}' - 2>/dev/null || python3 -c 'import sys; print(open(sys.argv[1], "rb").read())' '${d.rel}'` }, rawText],
        [{ command: "python3 summarize_folder.py" }, rawText],
        [{ command: "python3 summarize_folder.py --layout" }, rawText.replace(/: /g, ":        ").replace(/ \| /g, "     ")],
      ];
      if (d.rel.endsWith(".docx")) cases.push([{ command: `unzip -p ${d.rel} word/document.xml` }, docxXml(raw)], [{ command: "for f in work/*; do unzip -p \"$f\" word/document.xml; done" }, docxXml(raw)]);
      // Claude Code's Read of the raw PDF (no guard served the twin)
      if (d.rel.endsWith(".pdf")) cases.push([{ file_path: path }, claudePdfRead(path, raw)]);
      for (const [input, content] of cases) {
        const sent = await forwarded(input, content);
        for (const v of d.values) {
          assert.ok(!inBody(sent, v), `CONFIDENTIALITY VIOLATION: ${d.rel}'s ${v} reached the model through ${JSON.stringify(input)}:\n${sent.slice(0, 2500)}`);
        }
        assert.ok(!sent.includes(raw.toString("base64").slice(0, 200)), `CONFIDENTIALITY VIOLATION: ${d.rel}'s bytes reached the model`);
        assert.match(sent, /\$MDU:nomodel_/, `${d.rel}: the model sees placeholders:\n${sent.slice(0, 2500)}`);
      }

      // the twin, read by a program the guard served it to (a confined
      // session: no reader list, so `pdftotext` and `cat` get the twin): the
      // model reads which line is which, and no value
      const exe = d.rel.endsWith(".pdf") ? "/usr/bin/pdftotext" : "/usr/bin/cat";
      const procKey = `reader-${n}`;
      const open = await guard.decideSecretOpen({ path, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey, session: sessionKey });
      assert.equal(open.verdict, "twin", `${d.rel}: the guard serves ${exe} the twin`);
      const id = `tu_twin_${n++}`;
      await guard.recordCallRoot({ callId: id, procKey, session: sessionKey });
      const viaTwin = await forwarded({ command: d.rel.endsWith(".pdf") ? `pdftotext ${d.rel} -` : `cat ${d.rel}` }, twinText, id);
      for (const v of d.values) assert.ok(!inBody(viaTwin, v), `CONFIDENTIALITY VIOLATION: ${d.rel}'s ${v} reached the model through its twin`);
      for (const k of d.kept) assert.ok(viaTwin.includes(k.replace("$MDU:", "")) && viaTwin.includes(k), `${d.rel}: the model reads ${k} through the twin:\n${viaTwin.slice(0, 2000)}`);
      if (d.rel.endsWith(".pdf")) {
        // pdftotext's own rendering of the twin (a blank line, a form feed
        // at the page's end, -layout's columns): still the twin's labels
        const procKey2 = `reader-${n}`;
        await guard.decideSecretOpen({ path, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey: procKey2, session: sessionKey });
        const id2 = `tu_twin_${n++}`;
        await guard.recordCallRoot({ callId: id2, procKey: procKey2, session: sessionKey });
        const layout = await forwarded({ command: `pdftotext -layout ${d.rel} -` }, `${twinText.replace(/: /g, ":   ")}\n\n\f`, id2);
        for (const k of d.kept) assert.ok(layout.includes(k.replace(": ", ":   ")), `${d.rel}: pdftotext -layout's rendering of the twin is read: ${k}:\n${layout.slice(0, 2000)}`);
      }
    }

    // Claude Code's Read of a PDF (a document block, §2.8 "A document
    // block"): the model reads the twin's labels and placeholders, whether
    // the guard served the twin PDF or no guard did (the raw file as
    // registered); never the block, never a value
    const stmtPath = at("bank/statement-2026-09.pdf");
    const stmtVals = DOCS[0]!.values;
    const resultOf = (sent: string): string => {
      const msgs = (JSON.parse(sent) as { messages: Array<{ content: unknown }> }).messages;
      return JSON.stringify(msgs[msgs.length - 1]!.content);
    };
    for (const [what, bytes] of [["the twin PDF", Buffer.from(twins.get(stmtPath)!, "latin1")], ["the raw PDF", fx["bank/statement-2026-09.pdf"]!]] as const) {
      const sent = await forwarded({ file_path: stmtPath }, claudePdfRead(stmtPath, bytes));
      const res = resultOf(sent);
      for (const v of stmtVals) assert.ok(!inBody(sent, v), `CONFIDENTIALITY VIOLATION: ${what}'s ${v} reached the model through Read`);
      assert.ok(!sent.includes(bytes.toString("base64").slice(0, 120)), `${what}: the document block never reaches the model`);
      assert.match(res, /Account number: \$MDU:nomodel_Read\[/, `${what}: the model reads the twin's labels:\n${res.slice(0, 1500)}`);
      assert.match(res, /Closing balance: \$MDU:nomodel_Read\[/, what);
    }
    // the statement replaced by another one (not as registered): the label masks it whole
    const other = buildPdf([statementPdfItems({ account: "0099-554433-21", holder: "Alex Demo", closing: "9,999.99" })]);
    const sentOther = await forwarded({ file_path: stmtPath }, claudePdfRead(stmtPath, other));
    assert.ok(!inBody(sentOther, "0099-554433-21") && !inBody(sentOther, "9,999.99"), "CONFIDENTIALITY VIOLATION: a changed statement reached the model");
    assert.doesNotMatch(resultOf(sentOther), /Account number/, "masked whole");
    // a scan: no text, masked whole as before
    const scanPath = at("scans/receipt.pdf");
    const sentScan = await forwarded({ file_path: scanPath }, claudePdfRead(scanPath, fx["scans/receipt.pdf"]!));
    assert.match(resultOf(sentScan), /"content":\[\{"type":"text","text":"\$MDU:[A-Za-z_]+\[[0-9a-f]+\]"\}\]/, `a scan stays one placeholder:\n${resultOf(sentScan).slice(0, 400)}`);
    // a PDF that is no personal document: the model reads its text (before, one placeholder)
    const manual = buildPdf([[{ x: 50, y: 700, text: "Router quick start" }, { x: 50, y: 680, text: "Press the reset button for ten seconds to restore the defaults." }]]);
    const manualPath = at("manuals/router.pdf");
    const sentManual = await forwarded({ file_path: manualPath }, claudePdfRead(manualPath, manual));
    assert.ok(resultOf(sentManual).includes("Press the reset button for ten seconds"), `a public PDF's text reaches the model:\n${resultOf(sentManual).slice(0, 400)}`);

    // each value is a registered one: the backstop knows it, and its
    // placeholder asks before it leaves, at any host
    for (const v of [ACCOUNT, EMPLOYEE_NO, "1979-03-14"]) {
      const hits = (await real.scanSecretValues(`debug: ${v}\n`)).hits;
      assert.ok(hits.length > 0, `the value backstop knows ${v}`);
      for (const host of ["parktax.test", "ledgerly.test"]) {
        const dd = await real.desymbolizationDecision({ symbol: hits[0]!.symbol, boundary: "network", destination: host });
        assert.equal(dd.allow, false, dd.reason);
        assert.equal(dd.requiresApproval, true, dd.reason);
      }
      const trip = await real.egressFingerprintScan({ surfaces: [{ where: "body", text: `ref ${v}` }], destination: "ledgerly.test" });
      assert.equal(trip.tripped, true, `${v} trips the egress tripwire`);
    }
    // the whole statement's upload asks too (its base placeholder)
    const stmt = await real.registerSecret({ path: at("bank/statement-2026-09.pdf"), home });
    const up = await real.desymbolizationDecision({ symbol: stmt.symbol!, boundary: "network", destination: "parktax.test" });
    assert.equal(up.allow, false, up.reason);
    assert.equal(up.requiresApproval, true, up.reason);
    // the raw file on disk is untouched: a program the human allows reads it
    assert.deepEqual(readFileSync(at("bank/statement-2026-09.pdf")), fx["bank/statement-2026-09.pdf"]);
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    guard.close();
    realHuman.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
