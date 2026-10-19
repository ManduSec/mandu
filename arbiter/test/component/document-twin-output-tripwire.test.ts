/**
 * document-twin-output-tripwire.test.ts — a twin line in a masked output is
 * no fingerprint of that output's row (plan 10 §11.8, "A twin line is no
 * piece of an output that prints it", 2026-10-19), over the real IPC.
 *
 * The live case (demo-c17 `demo-inbox-you-decide`, secrets-defaults, takes
 * m1r2 and m1r3 of 2026-10-19): the bank statement is a personal document
 * (content tier, `content:personal-document`) whose twin keeps each line's
 * label and makes each value a placeholder. Claude Code read it in ONE
 * command with other files (`cat bank/statement-2026-09.md; cat
 * contacts.md`): the guard served the twin, the command names a secret file,
 * so the whole output was masked as a new row whose long lines (`Account:
 * $MDU:…`, the twin's own lines) were each a fingerprint. Then `curl
 * --data-binary @bank/statement-2026-09.md https://parktax.test/…` sent the
 * twin; every placeholder's card was answered Allow once; and the egress
 * tripwire refused the request on those lines ("there is nothing to approve
 * for it"), the upload the human had just allowed.
 *
 * Now a line of a registered file's twin, holding none of that file's secret
 * texts, is no piece of an output row whose value carries that file's
 * placeholders: the agent is shown it in the twin anyway. Every raw value
 * and the output's other lines still hit.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const ACCOUNT = "DEMO-ACCT-000123";
const lines = (...l: string[]): string => `${l.join("\n")}\n`;
const STATEMENT = lines("# Maple Bank (maplebank.test) - statement, September 2026", "", `Account: ${ACCOUNT} (test data)`, "Holder: Alex Demo", "",
  "2026-09-01  +3,200.00  Salary", "2026-09-03  -1,250.00  Rent", "2026-09-12     -84.10  Groceries", "Closing balance: 4,512.37");
const CONTACTS = lines("# Contacts", "", "- Kim Alvarez (dog sitter): +1 555-0142", "- Sam Reyes (next door, has a spare key): +1 555-0163");

async function rig(t: { after: (fn: () => Promise<void> | void) => void }) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-doc-twin-trip-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "inbox");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries({ "bank/statement-2026-09.md": STATEMENT, "contacts.md": CONTACTS })) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  t.after(async () => {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  });
  // The launch's secret setup (launcher/src/secret-setup.ts).
  const report = await c.discoverSecretsReport([home, ws], home);
  const stmt = join(ws, "bank/statement-2026-09.md");
  assert.equal(new Map(report.files.map((f) => [f.path, f.rule])).get(stmt), "content:personal-document", JSON.stringify(report.files));
  const reg = await c.registerSecret({ path: stmt, home });
  const twin = reg.twin as string;
  assert.ok(typeof twin === "string" && twin.includes("Account: $MDU:") && !twin.includes(ACCOUNT), twin);
  return { c, ws, stmt, twin };
}

test("a masked output that printed a document's twin beside another file: the twin may still leave (each placeholder asks), the raw values may not", async (t) => {
  const { c, twin } = await rig(t);
  // The batched read, masked whole by the path rule: a new row holding the
  // twin and the contacts.
  const row = await c.symbolizeFull({
    tool: "Bash", value: `${twin}${CONTACTS}`, origin: "cat bank/statement-2026-09.md; cat contacts.md",
    sessionKey: "dt", callId: "toolu_batched_cat", confidentiality: "no-model",
  });
  assert.ok(row.symbol && row.confidentiality === "no-model", JSON.stringify(row));

  // The upload of the twin (curl --data-binary @file): no tripwire hit. Each
  // placeholder in it is judged by the per-symbol gate on its own row.
  const up = await c.egressFingerprintScan({ surfaces: [{ where: "body", text: twin }], destination: "parktax.test" });
  assert.deepEqual(up.hits, [], `the twin is no fingerprint of the masked output: ${JSON.stringify(up.hits)}`);
  assert.equal(up.tripped, false);
  // ... nor a hit for the value backstop
  assert.deepEqual((await c.scanSecretValues(twin)).hits, [], "the twin passes the value backstop");

  // INVARIANT: every raw value still trips, and so does the output's own
  // non-twin line (the contacts were masked with it, and stay a piece).
  for (const raw of [STATEMENT, `Account: ${ACCOUNT} (test data)`, "Closing balance: 4,512.37 and more"]) {
    const r = await c.egressFingerprintScan({ surfaces: [{ where: "body", text: raw }], destination: "parktax.test" });
    assert.equal(r.tripped, true, `CONFIDENTIALITY: ${JSON.stringify(raw)} must trip`);
  }
  const contactLine = await c.egressFingerprintScan({ surfaces: [{ where: "body", text: "- Sam Reyes (next door, has a spare key): +1 555-0163" }], destination: "parktax.test" });
  assert.ok(contactLine.hits.some((h) => h.symbol === row.symbol), `the output's other lines stay pieces of its row: ${JSON.stringify(contactLine.hits)}`);
  // the whole masked output too
  const whole = await c.egressFingerprintScan({ surfaces: [{ where: "body", text: `${twin}${CONTACTS}` }], destination: "parktax.test" });
  assert.ok(whole.hits.some((h) => h.symbol === row.symbol), "the output as a whole still hits its row");
});

test("a line that is not the twin's (a raw value beside its placeholder) stays a piece of the output's row", async (t) => {
  const { c, twin } = await rig(t);
  const tampered = twin.replace(/^(Account: \$MDU:\S+)/m, `$1 ${ACCOUNT}`);
  assert.notEqual(tampered, twin);
  const row = await c.symbolizeFull({ tool: "Bash", value: tampered, origin: "cat x", sessionKey: "dt", callId: "toolu_tampered", confidentiality: "no-model" });
  const line = tampered.split("\n").find((l) => l.startsWith("Account:"))!;
  const hit = await c.egressFingerprintScan({ surfaces: [{ where: "body", text: `prefix ${line} suffix` }], destination: "parktax.test" });
  assert.ok(hit.hits.some((h) => h.symbol === row.symbol), `CONFIDENTIALITY: a line the twin does not carry stays a piece: ${JSON.stringify(hit.hits)}`);
  // and the twin's own lines are still no piece of it
  const up = await c.egressFingerprintScan({ surfaces: [{ where: "body", text: twin }], destination: "parktax.test" });
  assert.ok(!up.hits.some((h) => h.symbol === row.symbol), JSON.stringify(up.hits));
});
