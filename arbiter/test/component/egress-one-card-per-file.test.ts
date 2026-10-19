/**
 * egress-one-card-per-file.test.ts — one Approvals card per FILE and host
 * (egress-hold.md "One card per file", 2026-10-19), over the real IPC.
 *
 * The live case (demo-c17 `demo-inbox-you-decide`, takes m1r2 and m1r3 of
 * 2026-10-19): one upload of the bank statement's document twin carried its
 * seven per-line placeholders, and the arbiter filed SEVEN cards for
 * parktax.test at once. Now a registered file's placeholders file one card
 * (the file's base symbol × the host); the human's answer decides all of
 * them; a *once* is spent by the request that asked (its `requestId`), not
 * by its first placeholder, and the next request asks again.
 *
 * Asserted: one card for N placeholders; Allow once covers every
 * placeholder of THAT request and no other request; without a request id a
 * once covers one ask (as before); Block refuses every placeholder; a
 * second file is a second card; another host is another card; the data
 * socket spends nothing; a placeholder's own standing answer still wins; the
 * value itself never rides an answer for another file.
 *
 * Mandu-new test. A real ArbiterServer on temp sockets, the real clients.
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

const lines = (...l: string[]): string => `${l.join("\n")}\n`;
const FILES: Record<string, string> = {
  "bank/statement-2026-09.md": lines("# Maple Bank (maplebank.test) - statement, September 2026", "", "Account: DEMO-ACCT-000123 (test data)", "Holder: Alex Demo", "",
    "2026-09-01  +3,200.00  Salary", "2026-09-03  -1,250.00  Rent", "2026-09-12     -84.10  Groceries", "Closing balance: 4,512.37"),
  "home/house-codes.md": lines("# House codes", "", "Front door keypad: 40917233", "Alarm code: 73160482", "Wi-Fi network: AlderLane-Home", "Wi-Fi password: Willow-Otter-MANDUTEST-2291"),
};

const PH_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;

async function rig(t: { after: (fn: () => Promise<void> | void) => void }) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-one-card-"));
  const home = join(dir, "home-dir");
  const ws = join(dir, "work", "papers");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await s.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  await human.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  await admin.connect();
  const data = new ArbiterClient(join(dir, "a.sock"));
  await data.connect();
  t.after(async () => {
    human.close(); admin.close(); data.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const report = await human.discoverSecretsReport([home, ws], home);
  const twins = new Map<string, { path: string; twin: string; placeholders: string[]; base: string }>();
  for (const rel of Object.keys(FILES)) {
    const path = join(ws, rel);
    assert.equal(new Map(report.files.map((f) => [f.path, f.rule])).get(path), "content:personal-document", rel);
    const reg = await human.registerSecret({ path, home });
    const twin = reg.twin as string;
    const placeholders = [...new Set(twin.match(PH_RE) ?? [])];
    assert.ok(placeholders.length >= 4, `${rel}: per-line placeholders: ${twin}`);
    const base = placeholders[0]!.slice(0, placeholders[0]!.indexOf("].") + 1);
    assert.ok(placeholders.every((p) => p.startsWith(`${base}.`)), `one registration: ${placeholders.join(" ")}`);
    twins.set(rel, { path, twin, placeholders, base });
  }
  /** One ask of a request: its id, and every placeholder it carries (the
   *  net-proxy sends both). */
  const ask = (symbol: string, destination: string, requestId?: string, all?: string[], via: ArbiterClient = human) =>
    via.desymbolizationDecision({ symbol, boundary: "network", destination, asCommand: false, scheme: "https", positions: ["body"], ...(requestId ? { requestId } : {}), ...(all ? { requestSymbols: all } : {}) });
  const pending = async (destination: string) => (await admin.egressApprovals("pending")).filter((a) => a.destination === destination);
  return { human, admin, data, twins, ask, pending, stmt: twins.get("bank/statement-2026-09.md")!, codes: twins.get("home/house-codes.md")! };
}

test("one upload of a document's placeholders files ONE card; Allow once covers every placeholder of that request, and the next request asks again", async (t) => {
  const { admin, ask, pending, stmt } = await rig(t);
  // The request's first pass: every placeholder asks; one card
  const ids = new Set<string>();
  for (const p of stmt.placeholders) {
    const d = await ask(p, "parktax.test", "req-1", stmt.placeholders);
    assert.equal(d.allow, false, d.reason);
    assert.equal(d.allow === false && d.requiresApproval, true, d.reason);
    ids.add((d as { approvalId?: string }).approvalId!);
  }
  assert.equal(ids.size, 1, `one card for ${stmt.placeholders.length} placeholders: ${[...ids].join(", ")}`);
  const cards = await pending("parktax.test");
  assert.equal(cards.length, 1, JSON.stringify(cards));
  const card = cards[0]!;
  assert.equal(card.symbol, stmt.base, "the card is the file's");
  assert.equal(card.source?.origin, stmt.path, "and names the file");
  assert.equal(card.count, stmt.placeholders.length);
  assert.equal(card.stripOffered, true, "it takes Send without it");

  // Allow once: every placeholder of THAT request is allowed
  await admin.resolveEgressApproval(card.id, true, "once");
  for (const p of stmt.placeholders) {
    const d = await ask(p, "parktax.test", "req-1", stmt.placeholders);
    assert.equal(d.allow, true, `${p}: ${d.reason}`);
  }
  // SECURITY: the once is spent by req-1. Another request asks again, on
  // the same card, and gets nothing.
  const next = await ask(stmt.placeholders[0]!, "parktax.test", "req-2", stmt.placeholders);
  assert.equal(next.allow, false, `CONFIDENTIALITY: a spent once released ${stmt.placeholders[0]} to another request: ${next.reason}`);
  assert.equal((next as { approvalId?: string }).approvalId, card.id, "the same card asks again");
  for (const p of stmt.placeholders.slice(1)) assert.equal((await ask(p, "parktax.test", "req-2", stmt.placeholders)).allow, false, p);
  for (const p of stmt.placeholders) assert.equal((await ask(p, "parktax.test", "req-1", stmt.placeholders)).allow, false, `${p}: the card asks again, so req-1's spent once is gone too`);
  const again = await pending("parktax.test");
  assert.equal(again.length, 1, "still one card");
  assert.equal(again[0]!.status, "pending");
});

test("Block on the file's card refuses every placeholder; another file and another host are cards of their own", async (t) => {
  const { admin, ask, pending, stmt, codes } = await rig(t);
  // two files in one request: two cards
  const both = [...stmt.placeholders, ...codes.placeholders];
  const seen = new Set<string>();
  for (const p of [...stmt.placeholders, ...codes.placeholders]) seen.add((await ask(p, "parktax.test", "req-a", both) as { approvalId?: string }).approvalId!);
  assert.equal(seen.size, 2, "one card per file");
  const cards = await pending("parktax.test");
  assert.deepEqual(cards.map((c) => c.symbol).sort(), [stmt.base, codes.base].sort());
  const stmtCard = cards.find((c) => c.symbol === stmt.base)!;
  const codesCard = cards.find((c) => c.symbol === codes.base)!;

  // Allow once for the statement only: its placeholders go, the codes' do not
  await admin.resolveEgressApproval(stmtCard.id, true, "once");
  for (const p of stmt.placeholders) assert.equal((await ask(p, "parktax.test", "req-a", both)).allow, true, p);
  for (const p of codes.placeholders) {
    const d = await ask(p, "parktax.test", "req-a", both);
    assert.equal(d.allow, false, `CONFIDENTIALITY: ${p} rode the statement's answer: ${d.reason}`);
  }

  // Block for the codes: every one of its placeholders is refused, with no
  // further card
  await admin.resolveEgressApproval(codesCard.id, false);
  for (const p of codes.placeholders) {
    const d = await ask(p, "parktax.test", "req-b", codes.placeholders);
    assert.equal(d.allow, false, p);
    assert.equal(d.allow === false && d.requiresApproval, false, `Block is final: ${d.reason}`);
  }

  // another host: a card of its own, the statement's answer at parktax.test
  // carries nothing there
  const elsewhere = await ask(stmt.placeholders[0]!, "ledgerly.test", "req-a", stmt.placeholders);
  assert.equal(elsewhere.allow, false, elsewhere.reason);
  const l = await pending("ledgerly.test");
  assert.equal(l.length, 1);
  assert.equal(l[0]!.symbol, stmt.base);
});

test("without a request id a once covers one ask; the data socket spends nothing; a placeholder's own answer still wins; Always stands for the file", async (t) => {
  const { admin, ask, data, pending, stmt } = await rig(t);
  const [p1, p2] = stmt.placeholders;
  await ask(p1!, "parktax.test", undefined, stmt.placeholders);
  const card = (await pending("parktax.test"))[0]!;
  await admin.resolveEgressApproval(card.id, true, "once");
  // the data socket reads the once without spending it, and is no grant
  const viaData = await ask(p1!, "parktax.test", "req-x", stmt.placeholders, data);
  assert.equal(viaData.allow, false, `the data socket is never granted a once: ${viaData.reason}`);
  // no request id: the first ask spends it, the second asks again
  assert.equal((await ask(p1!, "parktax.test", undefined, stmt.placeholders)).allow, true);
  assert.equal((await ask(p2!, "parktax.test", undefined, stmt.placeholders)).allow, false, "spent by one ask");

  // Always on the file's card: every placeholder, every request, at that host
  const again = (await pending("parktax.test"))[0]!;
  await admin.resolveEgressApproval(again.id, true, "always");
  for (const r of ["req-1", "req-2"]) for (const p of stmt.placeholders) assert.equal((await ask(p, "parktax.test", r, stmt.placeholders)).allow, true, `${r} ${p}`);
  assert.equal((await ask(p1!, "ledgerly.test", "req-3", stmt.placeholders)).allow, false, "only at that host");
});

test("a lone placeholder keeps its own card (it names its key); the file's answer still covers it; a sentence's period never makes a second card", async (t) => {
  const { admin, ask, pending, stmt } = await rig(t);
  const [p1, p2] = stmt.placeholders;
  // one placeholder of the file in the request: its own card, as before
  const lone = await ask(p1!, "parktax.test", "req-1", [p1!]);
  assert.equal(lone.allow, false);
  let cards = await pending("parktax.test");
  assert.deepEqual(cards.map((c) => c.symbol), [p1], "a lone placeholder's card is its own");
  // the same placeholder spelled with a sentence's period: the same card
  const dotted = await ask(`${p1}.`, "parktax.test", "req-2", [`${p1}.`]);
  assert.equal((dotted as { approvalId?: string }).approvalId, cards[0]!.id, "`X.` and `X` are one card");
  // both spellings in one request are still ONE placeholder: its own card
  const twice = await ask(p1!, "parktax.test", "req-2b", [`${p1}.`, p1!]);
  assert.equal((twice as { approvalId?: string }).approvalId, cards[0]!.id, "two spellings of one placeholder are not two of the file's");
  // two of the file's placeholders, one spelled with a period: the file's card
  const a = await ask(`${p1}.`, "parktax.test", "req-3", [`${p1}.`, p2!]);
  const b = await ask(p2!, "parktax.test", "req-3", [`${p1}.`, p2!]);
  const fileCard = (a as { approvalId?: string }).approvalId;
  assert.equal((b as { approvalId?: string }).approvalId, fileCard, "both on the file's card");
  cards = await pending("parktax.test");
  assert.equal(cards.find((c) => c.id === fileCard)?.symbol, stmt.base);
  // Always on the file's card covers a lone placeholder of it later
  await admin.resolveEgressApproval(fileCard!, true, "always");
  assert.equal((await ask(p2!, "parktax.test", "req-4", [p2!])).allow, true, "the file's answer covers a lone placeholder");
  // ... but a lone placeholder's own Block still wins over it
  await admin.resolveEgressApproval(cards.find((c) => c.symbol === p1)!.id, false);
  const blocked = await ask(p1!, "parktax.test", "req-5", [p1!]);
  assert.equal(blocked.allow, false, "the placeholder's own answer wins");
});
