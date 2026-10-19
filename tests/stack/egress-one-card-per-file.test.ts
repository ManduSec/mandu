/**
 * egress-one-card-per-file — one Approvals card per file and host, across
 * the real components (egress-hold.md "One card per file", 2026-10-19).
 * Mandu-new.
 *
 * The live case it pins (demo-c17 `demo-inbox-you-decide`, secrets-defaults,
 * takes m1r2 and m1r3 of 2026-10-19): the model read the bank statement in
 * one command with other files (`cat bank/statement-2026-09.md; cat
 * contacts.md`, masked whole), then uploaded it with `curl --data-binary
 * @bank/statement-2026-09.md https://parktax.test/…`. The guard served the
 * personal document's twin, one placeholder per line, so the held request
 * raised SEVEN cards for parktax.test at once; the human answered each Allow
 * once, and the request was still refused: the egress tripwire matched the
 * twin's own lines, which the masked batched read had made fingerprints.
 *
 * No mocks on the path: a real ArbiterServer in `secrets` with data, human
 * and admin sockets, the launch's secret setup (the content tier labels the
 * statement and a note of house codes as personal documents and registers
 * their twins); the net-proxy in its `server-main.ts` wiring with a hold;
 * the dashboard's production approvals adapter for the human's answers; a
 * recording HTTP sink.
 *
 *   F1  the upload of the statement's twin, after the masked batched read,
 *       is held on ONE card naming the file; Allow once sends it with every
 *       value filled in (the sink receives the statement as it is on disk);
 *   F2  the once is spent by that request: the same upload again is held on
 *       the same card, and nobody answering refuses it, nothing sent;
 *   F3  two files in one request are two cards; the statement's Allow once
 *       alone leaves the request waiting on the codes' card and, unanswered,
 *       refused with nothing sent; both answered, it goes with both;
 *   F4  Block on the file's card refuses the request, nothing sent, no
 *       value in the refusal;
 *   F5  the per-line placeholders of the file never reach another host on
 *       that answer: another host is held on a card of its own.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { EGRESS_HELD_TIMEOUT } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode, the one a fresh install runs

const SESSION = "sess-one-card";
const HOLD_MS = 3_000;
const lines = (...l: string[]): string => `${l.join("\n")}\n`;
const STATEMENT = lines("# Maple Bank (maplebank.test) - statement, September 2026", "", "Account: DEMO-ACCT-000123 (test data)", "Holder: Alex Demo", "",
  "2026-09-01  +3,200.00  Salary", "2026-09-03  -1,250.00  Rent", "2026-09-12     -84.10  Groceries", "Closing balance: 4,512.37");
const CODES = lines("# House codes", "", "Front door keypad: 40917233", "Alarm code: 73160482", "Wi-Fi network: AlderLane-Home", "Wi-Fi password: Willow-Otter-MANDUTEST-2291");
const CONTACTS = lines("# Contacts", "", "- Kim Alvarez (dog sitter): +1 555-0142", "- Sam Reyes (next door, has a spare key): +1 555-0163");
/** Values that must never leave without the human's answer for their file. */
const STATEMENT_VALUES = ["DEMO-ACCT-000123", "4,512.37", "Alex Demo"];
const CODE_VALUES = ["73160482", "Willow-Otter-MANDUTEST-2291", "40917233"];

interface Received { headers: IncomingHttpHeaders; body: string; host: string }

function post(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "application/octet-stream", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-one-card-"));
  const home = join(tmp, "home");
  const ws = join(tmp, "work", "inbox");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries({ "bank/statement-2026-09.md": STATEMENT, "home/house-codes.md": CODES, "contacts.md": CONTACTS })) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath, dbPath: join(tmp, "symbols.sqlite"), adminSocketPath: adminSock, humanSocketPath: humanSockIn(tmp),
    eventDir: join(tmp, "events"), adminPolicyDir: null, packDir: null, log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await arbiter.listen();

  const received: Received[] = [];
  const sink = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString("utf8"), host: String(req.headers.host ?? "") });
      res.writeHead(201, { "content-type": "application/json" });
      res.end("{\"uploaded\":true}");
    });
  });
  sink.listen(0, "127.0.0.1");
  await once(sink, "listening");
  const port = (sink.address() as AddressInfo).port;

  // The net-proxy's production wiring, held as MANDU_EGRESS_HOLD_MS would.
  const netData = new ArbiterClient(socketPath);
  await netData.connect();
  const netHuman = new ArbiterClient(humanSockIn(tmp));
  const proxy = new NetProxy({ arbiter: new ArbiterClientAdapter(netData, netHuman), sessionId: SESSION, allowThisMachine: true, log: () => {}, egressHoldMs: HOLD_MS });
  const proxyPort = await proxy.listen(0);

  const dash = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(dash, "the dashboard's adapter connects");
  const human = new ArbiterClient(humanSockIn(tmp));
  await human.connect();

  // The launch's secret setup: the content tier finds both documents, and
  // the registry serves their twins (what the guard gives every program).
  const report = await human.discoverSecretsReport([home, ws], home);
  const twins = new Map<string, string>();
  for (const rel of ["bank/statement-2026-09.md", "home/house-codes.md"]) {
    const path = join(ws, rel);
    assert.equal(new Map(report.files.map((f) => [f.path, f.rule])).get(path), "content:personal-document", rel);
    const reg = await human.registerSecret({ path, home });
    assert.ok(typeof reg.twin === "string" && reg.twin.includes("$MDU:"), JSON.stringify(reg));
    twins.set(rel, reg.twin as string);
  }
  return {
    proxyPort, received, port, dash: dash!, human, ws,
    statementTwin: twins.get("bank/statement-2026-09.md")!, codesTwin: twins.get("home/house-codes.md")!,
    async close() {
      await proxy.close();
      netData.close(); netHuman.close(); human.close(); dash!.close();
      await arbiter.close();
      sink.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

type Stack = Awaited<ReturnType<typeof stack>>;

/** The file a card names (the arbiter's read-time `source`). */
const originOf = (c: unknown): string | null | undefined => (c as { source?: { origin?: string | null } | null }).source?.origin;
/** How many of the file's values a card's answer covers (`fileValues`). */
const fileValuesOf = (c: unknown): number | undefined => (c as { fileValues?: number }).fileValues;

/** The pending cards for `host`, once the held request filed `n` of them. */
async function cardsFor(s: Stack, host: string, n: number) {
  for (let i = 0; i < 150; i++) {
    const cards = (await s.dash.arbiter.egressApprovals("pending")).filter((a) => a.destination === host);
    if (cards.length >= n) {
      await sleep(150); // a straggler would show now
      return (await s.dash.arbiter.egressApprovals("pending")).filter((a) => a.destination === host);
    }
    await sleep(20);
  }
  throw new Error(`no ${n} card(s) for ${host}`);
}

const placeholders = (twin: string): number => new Set(twin.match(/\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g) ?? []).size;

function noValues(text: string, values: readonly string[], what: string): void {
  for (const v of values) assert.ok(!text.includes(v), `CONFIDENTIALITY VIOLATION: ${v} in ${what}:\n${text.slice(0, 1500)}`);
}

test("a document's upload is ONE card for the file; Allow once sends it whole, once; Block, another file and another host each keep their own answer (secrets axes)", async () => {
  const s = await stack();
  try {
    const host = `127.0.0.1:${s.port}`;
    const url = `http://${host}/clients/alex-demo/upload`;
    assert.ok(placeholders(s.statementTwin) >= 5, `the statement's twin has a placeholder per line:\n${s.statementTwin}`);

    // The batched read before the upload, masked whole by the path rule: its
    // row holds the twin's lines (the live take's `$MDU:nomodel_Bash[…]`).
    const batched = await s.human.symbolizeFull({
      tool: "Bash", value: `${s.statementTwin}${CONTACTS}`, origin: "cat bank/statement-2026-09.md; cat contacts.md",
      sessionKey: SESSION, callId: "toolu_batched_read", confidentiality: "no-model",
    });
    assert.equal(batched.confidentiality, "no-model");

    // F1: held on ONE card naming the file; Allow once sends it whole
    let settled = false;
    const sending = post(s.proxyPort, url, s.statementTwin).finally(() => { settled = true; });
    const cards = await cardsFor(s, host, 1);
    assert.equal(cards.length, 1, `one card for the file, not one per placeholder: ${JSON.stringify(cards.map((c) => c.symbol))}`);
    const card = cards[0]!;
    assert.equal(originOf(card), join(s.ws, "bank/statement-2026-09.md"), "the card names the statement");
    assert.equal(fileValuesOf(card), placeholders(s.statementTwin), "and says how many of its values the answer covers");
    assert.equal(settled, false, "held while the card waits");
    assert.equal(s.received.length, 0, "nothing on the wire while held");
    await s.dash.arbiter.resolveEgressApproval(card.id, true, "once");
    const sent = await sending;
    assert.equal(sent.status, 201, `the allowed upload went out (no tripwire on the twin's own lines): ${sent.body}`);
    assert.equal(s.received.length, 1);
    assert.equal(s.received[0]!.body, STATEMENT, "the accountant receives the statement as it is on disk");

    // F2: the once is spent by that request; nobody answering refuses the next
    const t0 = Date.now();
    const unanswered = await post(s.proxyPort, url, s.statementTwin);
    assert.equal(unanswered.status, 403, unanswered.body);
    assert.ok(Date.now() - t0 >= HOLD_MS - 300, "held until the deadline");
    assert.ok(unanswered.body.includes(EGRESS_HELD_TIMEOUT), unanswered.body);
    noValues(unanswered.body, STATEMENT_VALUES, "the refusal");
    assert.equal(s.received.length, 1, "a spent once sends nothing more");
    const left = (await s.dash.arbiter.egressApprovals("pending")).filter((a) => a.destination === host);
    assert.deepEqual(left.map((a) => a.id), [card.id], "the same one card asks again");

    // F3: two files in one request, two cards; one answer is not enough
    const both = `${s.statementTwin}\n${s.codesTwin}`;
    const t1 = Date.now();
    const half = post(s.proxyPort, url, both);
    const two = await cardsFor(s, host, 2);
    assert.equal(two.length, 2, `one card per file: ${JSON.stringify(two.map((c) => c.symbol))}`);
    const codesCard = two.find((c) => originOf(c) === join(s.ws, "home/house-codes.md"))!;
    const stmtCard = two.find((c) => originOf(c) === join(s.ws, "bank/statement-2026-09.md"))!;
    assert.ok(codesCard && stmtCard, JSON.stringify(two.map(originOf)));
    await s.dash.arbiter.resolveEgressApproval(stmtCard.id, true, "once");
    const halfDone = await half;
    assert.equal(halfDone.status, 403, `the codes' card unanswered: refused: ${halfDone.body}`);
    assert.ok(Date.now() - t1 >= HOLD_MS - 300, "it waited for the codes' card");
    noValues(halfDone.body, [...STATEMENT_VALUES, ...CODE_VALUES], "the refusal");
    assert.equal(s.received.length, 1, "CONFIDENTIALITY: nothing sent on half the answers");
    const whole = post(s.proxyPort, url, both);
    const two2 = await cardsFor(s, host, 2);
    for (const c of two2) await s.dash.arbiter.resolveEgressApproval(c.id, true, "once");
    const wholeDone = await whole;
    assert.equal(wholeDone.status, 201, wholeDone.body);
    assert.equal(s.received.length, 2);
    assert.equal(s.received[1]!.body, `${STATEMENT}\n${CODES}`, "both files answered: both go whole");

    // F4: Block refuses, nothing sent, no value in the refusal
    const blocking = post(s.proxyPort, url, s.codesTwin);
    const [blockCard] = await cardsFor(s, host, 1);
    await s.dash.arbiter.resolveEgressApproval(blockCard!.id, false);
    const blocked = await blocking;
    assert.equal(blocked.status, 403, blocked.body);
    noValues(blocked.body, CODE_VALUES, "the refusal");
    assert.equal(s.received.length, 2, "Block: nothing sent");
    const blockedAgain = await post(s.proxyPort, url, s.codesTwin);
    assert.equal(blockedAgain.status, 403, "Block stands for every placeholder of the file");
    assert.equal(s.received.length, 2);

    // F5: another host is a card of its own; the statement's answers at the
    // first host carry nothing there
    const other = `localhost:${s.port}`;
    const elsewhere = post(s.proxyPort, `http://${other}/parktax/alex-demo`, s.statementTwin);
    const otherCards = await cardsFor(s, other, 1);
    assert.equal(otherCards.length, 1, "one card at the other host");
    const refusedElsewhere = await elsewhere;
    assert.equal(refusedElsewhere.status, 403, refusedElsewhere.body);
    assert.equal(s.received.length, 2, "CONFIDENTIALITY: nothing reached the other host");
    for (const r of s.received) assert.equal(r.host, host);
  } finally {
    await s.close();
  }
});
