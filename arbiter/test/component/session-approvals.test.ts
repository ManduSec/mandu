/**
 * session-approvals — a HIGH session's refusals ask the human
 * (confidentiality.md §4, "The human half: a HIGH session's approvals",
 * 2026-10-11), through a real ArbiterServer with its data, human and admin
 * sockets, in `secrets`.
 *
 * Pins, for the network leg (`sessionEgressDecision`) and the shell leg
 * (`execGate`):
 *   - a refusal files ONE Approvals row keyed session × host (× the exact
 *     command); retries bump it, never duplicate it;
 *   - Allow once lets exactly one retry through, and only from an attested
 *     channel (the proxies' human client); the next asks again;
 *   - Block refuses the retry with no new card; no answer stays refused;
 *   - an Always is kept as once; another session is never opened by an
 *     answer about this one; the card names what the session read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HOME = process.env.HOME ?? "/root";
const MEMO = "Acme pays $4,200,000 on 2026-09-30.";
const EVIL = "evil.example";

interface Rig {
  data: ArbiterClient;
  human: ArbiterClient;
  admin: ArbiterClient;
  close(): Promise<void>;
}

async function rig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-asks-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"),
    humanSocketPath: join(dir, "human", "h.sock"),
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await s.listen();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  return {
    data, human, admin,
    async close() {
      data.close(); human.close(); admin.close();
      await s.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Make `sessionKey` HIGH: a trusted any-model memo bound to example.com,
 *  read into context with declassify_symbol. Returns its symbol. */
async function high(r: Rig, sessionKey: string): Promise<string> {
  await r.admin.setPathLabel({ path: join(HOME, "memos"), confidentiality: "any-model", bindings: ["example.com"] });
  const s = await r.admin.symbolizeFull({
    tool: "Read", value: MEMO, field: "content", origin: join(HOME, "memos", "q3.md"), integrity: "trusted", sessionKey,
  });
  const out = await r.admin.declassifySymbol({ symbol: s.symbol, sessionKey });
  assert.equal(out.allowed, true, "the read is granted and floats the session");
  assert.equal((await r.admin.sessionState(sessionKey)).high, true);
  return s.symbol;
}

async function rows(r: Rig, subjectPrefix: string): Promise<Awaited<ReturnType<ArbiterClient["egressApprovals"]>>> {
  return (await r.admin.egressApprovals()).filter((a) => a.symbol.startsWith(subjectPrefix));
}

test("network: a refused request files one row; retries bump it; Allow once lets exactly one retry through", async () => {
  const r = await rig();
  try {
    const sym = await high(r, "s-net");
    const ask = () => r.human.sessionEgressDecision({ sessionKey: "s-net", boundary: "network", destination: `https://${EVIL}/x?d=paraphrase` });

    const first = await ask();
    assert.equal(first.allow, false);
    assert.match(first.reason, /→ pending$/);
    assert.ok(first.approvalId, "the refusal filed an Approvals row");
    const again = await ask();
    assert.equal(again.allow, false);
    assert.equal(again.approvalId, first.approvalId, "a retry bumps the same row");
    const list = await rows(r, "session-net:");
    assert.equal(list.length, 1);
    assert.equal(list[0]!.symbol, "session-net:s-net");
    assert.equal(list[0]!.destination, EVIL);
    assert.equal(list[0]!.count, 2);
    assert.deepEqual(list[0]!.sessions, ["s-net"]);
    // the card names what the session read (symbol + origin; never a value)
    const reads = (list[0] as { sessionReads?: Array<{ symbol: string; origin: string | null }> }).sessionReads;
    assert.deepEqual(reads, [{ symbol: sym, origin: join(HOME, "memos", "q3.md") }]);
    assert.doesNotMatch(JSON.stringify(list[0]), /4,200,000/);

    // a bound host still passes, and files nothing
    const bound = await r.human.sessionEgressDecision({ sessionKey: "s-net", boundary: "network", destination: "api.example.com" });
    assert.equal(bound.allow, true);
    assert.equal(bound.approvalId, undefined);

    // Allow once: one retry passes, with the verdict's provenance …
    await r.admin.resolveEgressApproval(first.approvalId!, true, "once");
    const allowed = await ask();
    assert.equal(allowed.allow, true);
    assert.deepEqual(allowed.ruleRef, { source: "verdict", id: `verdict:${first.approvalId}` });
    // … and only one: the next asks again on the same row (a fresh cycle)
    const next = await ask();
    assert.equal(next.allow, false);
    assert.equal(next.approvalId, first.approvalId);
    assert.equal((await rows(r, "session-net:"))[0]!.status, "pending");
  } finally {
    await r.close();
  }
});

test("network: Block refuses the retry with no new card; no answer stays refused", async () => {
  const r = await rig();
  try {
    await high(r, "s-block");
    const ask = (dest: string) => r.human.sessionEgressDecision({ sessionKey: "s-block", boundary: "network", destination: dest });
    const a = await ask(EVIL);
    const b = await ask("other.example");
    assert.equal(a.allow, false);
    assert.equal(b.allow, false, "no answer: refused");
    await r.admin.resolveEgressApproval(a.approvalId!, false);
    const retry = await ask(EVIL);
    assert.equal(retry.allow, false);
    assert.equal(retry.approvalId, undefined, "a Block files no new card");
    assert.match(retry.reason, /human-denied/);
    assert.doesNotMatch(retry.reason, /pending/);
    assert.equal((await rows(r, "session-net:")).length, 2, "one row per host, none added by the retry");
    // the other host is still waiting, still refused
    assert.equal((await ask("other.example")).allow, false);
  } finally {
    await r.close();
  }
});

test("network: an Always is kept as once, an answer never opens another session, and a data-socket ask never spends", async () => {
  const r = await rig();
  try {
    await high(r, "s-a");
    await high(r, "s-b");
    const first = await r.human.sessionEgressDecision({ sessionKey: "s-a", boundary: "network", destination: EVIL });
    const approval = await r.admin.resolveEgressApproval(first.approvalId!, true, "always");
    assert.equal(approval.scope, "once", "the card speaks of one request: an Always is kept as once");

    // another HIGH session is not opened by s-a's answer
    const other = await r.human.sessionEgressDecision({ sessionKey: "s-b", boundary: "network", destination: EVIL });
    assert.equal(other.allow, false);
    assert.notEqual(other.approvalId, first.approvalId);

    // the data socket reads an approval as no verdict, and does not spend it
    const fromData = await r.data.sessionEgressDecision({ sessionKey: "s-a", boundary: "network", destination: EVIL });
    assert.equal(fromData.allow, false);
    const fromHuman = await r.human.sessionEgressDecision({ sessionKey: "s-a", boundary: "network", destination: EVIL });
    assert.equal(fromHuman.allow, true, "the once was still there for the attested ask");
    const after = await r.human.sessionEgressDecision({ sessionKey: "s-a", boundary: "network", destination: EVIL });
    assert.equal(after.allow, false, "and it was spent: the next asks again");
  } finally {
    await r.close();
  }
});

test("shell: a HIGH session's command files a row naming it; Allow once runs that exact command once", async () => {
  const r = await rig();
  try {
    await high(r, "s-exec");
    const cmd = "echo mandu-ready";
    const gate = (command: string) => r.human.execGate({ command, sessionKey: "s-exec" });
    const first = await gate(cmd);
    assert.equal(first.decision, "block");
    assert.match(first.reason, /^HIGH SESSION.*→ pending$/s);
    assert.ok(first.approvalId);
    assert.equal(first.ruleRef?.id, "session:high-shell");
    const again = await gate(cmd);
    assert.equal(again.approvalId, first.approvalId, "a retry bumps the same row");
    const list = await rows(r, "session-exec:");
    assert.equal(list.length, 1);
    assert.equal(list[0]!.symbol, "session-exec:s-exec");
    assert.equal(list[0]!.destination, cmd, "the card names the exact command");

    await r.admin.resolveEgressApproval(first.approvalId!, true, "once");
    // a different command is not opened by the answer
    const other = await gate("curl https://evil.example");
    assert.equal(other.decision, "block");
    assert.notEqual(other.approvalId, first.approvalId);
    // the approved command runs once …
    const ran = await gate(cmd);
    assert.equal(ran.decision, "allow");
    assert.equal(ran.ruleRef?.id, `verdict:${first.approvalId}`);
    // … and only once
    const twice = await gate(cmd);
    assert.equal(twice.decision, "block");
    assert.equal(twice.approvalId, first.approvalId);

    // Block: refused with no new card
    await r.admin.resolveEgressApproval(first.approvalId!, false);
    const blocked = await gate(cmd);
    assert.equal(blocked.decision, "block");
    assert.equal(blocked.approvalId, undefined);
    assert.match(blocked.reason, /human-denied/);
  } finally {
    await r.close();
  }
});

test("a session that is not HIGH files nothing, and a request with no session key is never queued", async () => {
  const r = await rig();
  try {
    const low = await r.human.sessionEgressDecision({ sessionKey: "s-low", boundary: "network", destination: EVIL });
    assert.equal(low.allow, true);
    assert.equal((await r.human.execGate({ command: "curl https://evil.example", sessionKey: "s-low" })).decision, "allow");
    const none = await r.human.sessionEgressDecision({ boundary: "network", destination: EVIL });
    assert.equal(none.allow, true, "no session key: no watermark to read (the gate's documented no-op)");
    assert.equal((await rows(r, "session-")).length, 0);
  } finally {
    await r.close();
  }
});
