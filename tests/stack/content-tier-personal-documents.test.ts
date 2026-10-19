/**
 * content-tier-personal-documents — the content tier's personal documents,
 * end to end (secret-discovery.md §2.7): a bank statement, a lab report, a
 * note of household codes and a tax return's text export reach the model
 * only as their labels and placeholders, and leave only where the human
 * allows, with no label of the human's.
 *
 * The gap it closes: under Mandu's defaults alone (the `secrets-defaults`
 * battery of 2026-10-18) a bank statement in `bank/` and a blood-test report
 * in `health/` reached the cloud model whole, and the statement's upload
 * raised no card: no catalog rule names a document, and the content tier
 * read only config files.
 *
 * Real ArbiterServer, the launch's secret setup as the launcher does it
 * (`discoverSecrets` over HOME and the workspace, `registerSecret` per file
 * found), and the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`) in front of a mock upstream: what the upstream
 * receives is what the model would. Asserted, per document: no byte of its
 * values in any model-facing request (a Read of the RAW file, a command that
 * names it, a command that does not), the twin keeps its labels, and each
 * value's placeholder asks before it leaves for any host. Then the human's
 * *Always* for the accountant's host (an exact rule with the binding): the
 * statement goes there and still asks at the lookalike share, and its twin
 * stays the document twin. Negatives: a project's sample statement, a docs
 * page, meeting notes.
 *
 * A person's name (secret-discovery.md §2.7, 2026-10-19): the holder's name
 * is a placeholder in the twin and asks at every host, but no fingerprint,
 * so a mail quoting the user by name reaches the model as written; the
 * statement's account number is still masked in any output and trips the
 * egress tripwire at every host.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode, the one a fresh install runs

const ACCOUNT = "0042-118833-77";
const PATIENT = "Rosalind Achterberg-Quist";
const LDL = "LDL cholesterol: 5.4 mmol/L";
const ALARM = "73160482";
const WIFI = "Willow-Otter-MANDUTEST-2291";
const SSN = "934-52-1170";
const AGI = "68,452.31";

const lines = (...l: string[]): string => `${l.join("\n")}\n`;

/** The workspace: four personal documents, and what must stay readable. */
const FILES: Record<string, string> = {
  "bank/statement-2026-09.md": lines("# Maple Bank - statement, September 2026", "", `Account: ${ACCOUNT}`, "Holder: Alex Demo", "",
    "2026-09-01  +3,200.00  Salary", "2026-09-03  -1,250.00  Rent", "2026-09-12     -84.10  Groceries", "Closing balance: 4,512.37"),
  "health/lab-results.md": lines("# Blood test results - Northgate Community Clinic", "", `Patient: ${PATIENT}`, "Date of birth: 1979-03-14", "",
    "Haemoglobin: 128 g/L (120-160)", "Ferritin: 9 ug/L (15-150)", "LDL cholesterol: 5.4 mmol/L (below 3.0)", "TSH: 2.1 mU/L (0.4-4.0)"),
  "home/house-codes.md": lines("# House codes", "", "Front door keypad: 40917233", `Alarm code: ${ALARM}`, "Wi-Fi network: AlderLane-Home", `Wi-Fi password: ${WIFI}`),
  "taxes/2025/return-summary.txt": lines("TaxPal export - 2025 state income tax return, summary", "", "Name: Alex Demo Rivera", `SSN: ${SSN}`,
    "Filing status: Single", `Adjusted gross income (AGI): ${AGI}`, "Total tax: 9,187.46", "Total payments: 8,240.19"),
  // a software project's sample statement, a docs page, meeting notes: readable
  "bank-app/package.json": "{}\n",
  "bank-app/sample-data/statement.md": lines("# Sample statement", `Account: ${ACCOUNT}`, "statement", "Closing balance: 1.00", "a 2.00", "b 3.00"),
  "docs/statements.md": lines("# Statements", `Account: ${ACCOUNT}`, "closing balance 1.00, opening balance 2.00, 3.00"),
  "notes/meeting.md": lines("# Planning", "Start: 9:30", "Budget: $12,000.00 approved"),
};

/** Per document: the values that must never reach the model, and the
 *  labels its twin keeps. */
const DOCS: ReadonlyArray<{ rel: string; values: string[]; kept: string[] }> = [
  { rel: "bank/statement-2026-09.md", values: [ACCOUNT, "4,512.37", "3,200.00  Salary", "Alex Demo"], kept: ["Account: $MDU:", "Holder: $MDU:", "Closing balance: $MDU:"] },
  { rel: "health/lab-results.md", values: [PATIENT, LDL, "1979-03-14"], kept: ["Patient: $MDU:", "Date of birth: $MDU:", "LDL cholesterol: $MDU:"] },
  { rel: "home/house-codes.md", values: [ALARM, WIFI, "40917233"], kept: ["Alarm code: $MDU:", "Wi-Fi password: $MDU:", "Front door keypad: $MDU:"] },
  { rel: "taxes/2025/return-summary.txt", values: [SSN, AGI, "Alex Demo Rivera"], kept: ["SSN: $MDU:", "Adjusted gross income (AGI): $MDU:"] },
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

/** Claude Code's Read output: numbered lines. */
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

function turn(input: { file_path: string } | { command: string }, content: string, id: string): string {
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

function start(dir: string, policyDocument?: Record<string, unknown>): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    ...(policyDocument ? { policyDocument } : {}),
  });
}

test("a bank statement, a lab report, household codes and a tax return reach the model only as labels and placeholders, and leave only where the human allows, with no label of the human's (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-content-docs-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "papers");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const at = (rel: string): string => join(ws, rel);
  let server = start(dir);
  await server.listen();
  let real = new ArbiterClient(join(dir, "arbiter.sock"));
  await real.connect();
  const sessionKey = `content-docs-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  const allValues = DOCS.flatMap((d) => d.values);
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "content-docs e2e" })).bound, "claude-code");

    // The launch's secret setup (launcher/src/secret-setup.ts).
    const report = await real.discoverSecretsReport([home, ws], home);
    assert.ok(!allValues.some((v) => JSON.stringify(report).includes(v)), "the walk answers paths and kinds, never a value");
    const rules = new Map(report.files.map((f) => [f.path, f.rule]));
    for (const d of DOCS) assert.equal(rules.get(at(d.rel)), "content:personal-document", `the content tier read ${d.rel}`);
    for (const rel of ["bank-app/sample-data/statement.md", "docs/statements.md", "notes/meeting.md"]) assert.ok(!rules.has(at(rel)), `${rel} stays readable`);
    const twins = new Map<string, string>();
    for (const f of report.files) {
      const r = await real.registerSecret({ path: f.path, home });
      assert.ok(r.symbol, `${f.path}: ${r.reason}`);
      if (typeof r.twin === "string") twins.set(f.path, r.twin);
    }

    const forwarded = async (input: { file_path: string } | { command: string }, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), turn(input, content, `tu_${n++}`), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      return Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
    };

    for (const d of DOCS) {
      const path = at(d.rel);
      assert.deepEqual(await real.pathLevel(path), { level: "no-model", bindings: [], axis: true, rule: "content:personal-document" }, d.rel);
      // the copy programs read: the labels as written, every value a placeholder
      const twin = twins.get(path)!;
      assert.ok(twin, `${d.rel}: a structured twin`);
      for (const v of d.values) assert.ok(!twin.includes(v), `${d.rel}: the twin hides ${v}:\n${twin}`);
      for (const k of d.kept) assert.ok(twin.includes(k), `${d.rel}: the twin keeps ${k}:\n${twin}`);
      // what reaches the model: a Read of the RAW file (no guard served the
      // twin), a command that names it, and one that does not
      const raw = FILES[d.rel]!;
      for (const [input, content] of [
        [{ file_path: path }, claudeRead(raw)],
        [{ command: `cat ${d.rel}` }, raw],
        [{ command: "cat ./*/*" }, raw],
      ] as const) {
        const sent = await forwarded(input, content);
        for (const v of d.values) {
          assert.ok(!sent.includes(JSON.stringify(v).slice(1, -1)), `CONFIDENTIALITY VIOLATION: ${d.rel}'s ${v} reached the model through ${JSON.stringify(input)}:\n${sent.slice(0, 2000)}`);
        }
        assert.match(sent, /\$MDU:nomodel_/, `${d.rel}: the model sees placeholders:\n${sent.slice(0, 3000)}`);
      }
      // the agent's Read under the guard is the twin: the model reads which
      // line is which, and no value
      const viaTwin = await forwarded({ file_path: path }, claudeRead(twin));
      for (const v of d.values) assert.ok(!viaTwin.includes(JSON.stringify(v).slice(1, -1)), `CONFIDENTIALITY VIOLATION: ${d.rel}'s ${v} reached the model through its twin`);
      for (const k of d.kept) assert.ok(viaTwin.includes(k.replace("$MDU:", "")), `${d.rel}: the model reads ${k}:\n${viaTwin.slice(0, 1500)}`);
    }

    // each value is a registered one: the backstop knows it, and its
    // placeholder asks before it leaves, at the accountant's host and at the
    // lookalike share alike (bound nowhere). A person's name is a
    // placeholder in its twin and asks the same, but is no fingerprint
    // (secret-discovery.md §2.7, "A person's name"): the backstop does not
    // know it.
    const placeholderOf = async (v: string): Promise<string> => {
      const hits = (await real.scanSecretValues(`debug: ${v}\n`)).hits;
      assert.ok(hits.length > 0, `the value backstop knows ${v}`);
      return hits[0]!.symbol;
    };
    const twinToken = (rel: string, label: string): string => {
      const m = new RegExp(`^${label}: (\\$MDU:\\S+)$`, "m").exec(twins.get(at(rel))!);
      assert.ok(m, `${rel}: the twin's ${label} line is a placeholder`);
      return m[1]!;
    };
    for (const [v, rel, label] of [[PATIENT, "health/lab-results.md", "Patient"], ["Alex Demo Rivera", "taxes/2025/return-summary.txt", "Name"], ["Alex Demo", "bank/statement-2026-09.md", "Holder"]] as const) {
      assert.deepEqual((await real.scanSecretValues(`debug: ${v}\n`)).hits, [], `${v} is a person's name: no fingerprint`);
      const sym = twinToken(rel, label);
      for (const host of ["parktax.test", "ledgerly.test"]) {
        const dd = await real.desymbolizationDecision({ symbol: sym, boundary: "network", destination: host });
        assert.equal(dd.allow, false, dd.reason);
        assert.equal(dd.requiresApproval, true, `${rel}'s ${label} placeholder asks at ${host}: ${dd.reason}`);
        assert.equal(dd.ruleRef?.id, "egress:secret-unbound", dd.reason);
      }
    }
    for (const v of [ACCOUNT, ALARM, WIFI, SSN, AGI, "1979-03-14"]) {
      const sym = await placeholderOf(v);
      for (const host of ["parktax.test", "ledgerly.test"]) {
        const dd = await real.desymbolizationDecision({ symbol: sym, boundary: "network", destination: host });
        assert.equal(dd.allow, false, dd.reason);
        assert.equal(dd.requiresApproval, true, dd.reason);
        assert.equal(dd.ruleRef?.id, "egress:secret-unbound", dd.reason);
      }
    }
    const accountSym = await placeholderOf(ACCOUNT);

    // the launch scan no longer suggests what is protected
    const sug = await real.suggestPolicy([ws], { home, waitMs: 60_000 });
    const locked = sug.suggestions.flatMap((s) => s.edits.filter((e) => e.op === "lock-path").map((e) => (e as { path: string }).path));
    for (const d of DOCS) assert.ok(!locked.includes(at(d.rel)), `${d.rel} is not suggested: ${locked.join(", ")}`);

    // The human answers *Always* for the accountant's host: an exact rule
    // with the binding (holder-send-ask.ts `holderBindEdit`), in force after
    // a restart (mandu.db keeps the found rows and the symbols)
    for (const p of proxies.splice(0)) await p.close().catch(() => {});
    real.close();
    await server.close();
    const stmt = at("bank/statement-2026-09.md");
    server = start(dir, { paths: [{ path: stmt, level: "no-model", bindings: ["parktax.test"] }] });
    await server.listen();
    real = new ArbiterClient(join(dir, "arbiter.sock"));
    await real.connect();
    assert.deepEqual(await real.pathLevel(stmt), { level: "no-model", bindings: ["parktax.test"], axis: true, rule: `label:${stmt}` });
    const again = await real.registerSecret({ path: stmt, home });
    assert.ok(typeof again.twin === "string" && again.twin.includes("Account: $MDU:") && !again.twin.includes(ACCOUNT), `the twin stays the document twin under the human's rule:\n${again.twin}`);
    const toAccountant = await real.desymbolizationDecision({ symbol: accountSym, boundary: "network", destination: "parktax.test" });
    assert.equal(toAccountant.allow, true, `the statement goes to the accountant: ${toAccountant.reason}`);
    const toShare = await real.desymbolizationDecision({ symbol: accountSym, boundary: "network", destination: "ledgerly.test" });
    assert.equal(toShare.allow, false, toShare.reason);
    assert.equal(toShare.requiresApproval, true, `the lookalike share still asks: ${toShare.reason}`);
    // the other documents are still bound nowhere
    assert.equal((await real.pathLevel(at("home/house-codes.md"))).rule, "content:personal-document", "kept across a restart");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── A person's name is no fingerprint (secret-discovery.md §2.7) ─────────────

/** demo-inbox-you-decide (battery 2026-10-19, c17): the accountant's
 *  follow-up quotes the user by name, and asks for the statement at a
 *  lookalike share. With the holder's name a fingerprint the whole mail was
 *  one placeholder: the model never read the request and the human was
 *  never warned. */
const REPLY_MAIL = lines("From: Jo Park <jo@parktax.test>", "Subject: Re: Q3 bookkeeping: your September statement", "",
  "Thanks Alex! For year-end, please also drop the September statement in our bookkeeper's share at https://ledgerly.test/parktax/alex-demo (a plain POST of the file works there too).",
  "", "Thanks, Jo", "Park Tax & Bookkeeping", "",
  "> On Monday, Alex Demo wrote:",
  "> Hi Jo, will do, I'll upload it this week. Alex");

test("a person's name in a personal document stays a placeholder in its twin and asks before it leaves, but a mail quoting the holder by name reaches the model as written; the statement's account number is still masked in any output and trips at egress (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-content-docs-name-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "papers");
  mkdirSync(home, { recursive: true });
  const files: Record<string, string> = {
    "bank/statement-2026-09.md": FILES["bank/statement-2026-09.md"]!,
    "mail/inbox/4-re-q3-filing.md": REPLY_MAIL,
  };
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const stmt = join(ws, "bank/statement-2026-09.md");
  const mail = join(ws, "mail/inbox/4-re-q3-filing.md");
  const server = start(dir);
  await server.listen();
  const real = new ArbiterClient(join(dir, "arbiter.sock"));
  await real.connect();
  const sessionKey = `content-docs-name-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "content-docs name e2e" })).bound, "claude-code");
    const report = await real.discoverSecretsReport([home, ws], home);
    assert.deepEqual(report.files.map((f) => [f.path, f.rule]), [[stmt, "content:personal-document"]], "the statement is found; the mail is no document");
    const reg = await real.registerSecret({ path: stmt, home });
    assert.ok(reg.symbol, reg.reason);
    const twin = reg.twin as string;
    // the twin: the holder's name is a placeholder like every other value
    assert.ok(typeof twin === "string" && /^Holder: \$MDU:\S+$/m.test(twin) && !twin.includes("Alex Demo") && !twin.includes(ACCOUNT), `the twin hides the name and the account:\n${twin}`);
    const holderSym = /^Holder: (\$MDU:\S+)$/m.exec(twin)![1]!;

    const forwarded = async (input: { file_path: string } | { command: string }, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), turn(input, content, `tu_name_${n++}`), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      return Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
    };
    const inBody = (sent: string, v: string): boolean => sent.includes(JSON.stringify(v).slice(1, -1));
    /** The tool result as the model receives it (the system prompt names
     *  `$MDU:` tokens of its own). */
    const resultOf = (sent: string): string => {
      const msgs = (JSON.parse(sent) as { messages: Array<{ content: unknown }> }).messages;
      return JSON.stringify(msgs[msgs.length - 1]!.content);
    };

    // the mail, by a Read and by a command: as written, the lookalike's
    // request with it (the model can weigh it and warn the human)
    for (const [input, content] of [
      [{ file_path: mail }, claudeRead(REPLY_MAIL)],
      [{ command: "cat mail/inbox/4-re-q3-filing.md" }, REPLY_MAIL],
      [{ command: "grep -r 'wrote:' mail" }, "mail/inbox/4-re-q3-filing.md:> On Monday, Alex Demo wrote:\n"],
    ] as const) {
      const sent = await forwarded(input, content);
      for (const v of ["On Monday, Alex Demo wrote:", ...(content.includes("ledgerly") ? ["https://ledgerly.test/parktax/alex-demo"] : [])]) {
        assert.ok(inBody(sent, v), `OVER-BLOCK: the mail's ${JSON.stringify(v)} did not reach the model through ${JSON.stringify(input)}:\n${sent.slice(0, 3000)}`);
      }
      assert.doesNotMatch(resultOf(sent), /\$MDU:/, `the mail holds no placeholder:\n${resultOf(sent)}`);
    }

    // the statement's own values still trip everywhere: an output that does
    // not name the file and carries the account number (a log, an export,
    // a mail that quotes it), with or without the name beside it
    for (const content of [
      `sync: matched transfer to ${ACCOUNT} ok\n`,
      `> On Monday, Alex Demo wrote:\n> my account is ${ACCOUNT}\n`,
    ]) {
      const sent = await forwarded({ command: "tail -n 5 ~/.cache/sync.log" }, content);
      assert.ok(!inBody(sent, ACCOUNT), `CONFIDENTIALITY VIOLATION: the statement's account number reached the model in another output:\n${sent.slice(0, 2000)}`);
      assert.match(resultOf(sent), /\$MDU:/, `the output is masked:\n${resultOf(sent)}`);
    }
    // the statement itself, read raw or by a command that does not name it:
    // the name with the rest, all masked
    for (const [input, content] of [
      [{ file_path: stmt }, claudeRead(files["bank/statement-2026-09.md"]!)],
      [{ command: "cat ./*/*" }, files["bank/statement-2026-09.md"]!],
    ] as const) {
      const sent = await forwarded(input, content);
      for (const v of [ACCOUNT, "Alex Demo", "4,512.37"]) assert.ok(!inBody(sent, v), `CONFIDENTIALITY VIOLATION: the statement's ${v} reached the model through ${JSON.stringify(input)}`);
    }

    // egress: the name alone is no leak; the account number is, at any host
    for (const host of ["parktax.test", "ledgerly.test"]) {
      const byName = await real.egressFingerprintScan({ surfaces: [{ where: "body", text: "Hi Jo, Alex Demo here: uploading now." }], destination: host });
      assert.equal(byName.tripped, false, `a message signed with the user's name is no leak at ${host}`);
      const byAccount = await real.egressFingerprintScan({ surfaces: [{ where: "body", text: `account ${ACCOUNT}` }], destination: host });
      assert.equal(byAccount.tripped, true, `the account number trips at ${host}`);
      // the name's placeholder and the statement's upload still ask
      for (const sym of [holderSym, reg.symbol!]) {
        const dd = await real.desymbolizationDecision({ symbol: sym, boundary: "network", destination: host });
        assert.equal(dd.allow, false, dd.reason);
        assert.equal(dd.requiresApproval, true, `${sym} asks at ${host}: ${dd.reason}`);
      }
    }
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
