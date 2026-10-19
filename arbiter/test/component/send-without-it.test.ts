/**
 * send-without-it — the arbiter's half of "Send without it"
 * (confidentiality.md §4 "Send without it", 2026-10-17). Mandu-new.
 *
 * A real ArbiterServer in `secrets` with data, human and admin sockets:
 *
 *   S1  a secret's symbol asked at an unbound host files a card the listing
 *       marks `stripOffered`;
 *   S2  the answer (`approve: false, strip: true`) is stored as a once
 *       denial carrying `strip`; with `approve: true` it is refused;
 *   S3  the data socket (the agent's programs) reads a plain denial, no
 *       `strip`, and does not spend it; a pre-check reads it unspent and is
 *       told the call may go on (nothing released); the net-proxy's ask on
 *       the human socket gets the denial WITH `strip` and spends it;
 *   S4  the next ask is a fresh question (one-shot);
 *   S5  a HIGH session's network card (`session-net:`, content-agnostic:
 *       the request may hold the raw value) is not offered it, and the
 *       answer is REFUSED there (fail-closed), its row left as it was (the
 *       other non-symbol cards: send-without.test.ts, over the pure rule).
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

const HOST = "api.github.com";
const SESSION = "s-send-without";
const HOME = "/home/send-without-test";

interface Rig {
  data: ArbiterClient;
  human: ArbiterClient;
  admin: ArbiterClient;
  close(): Promise<void>;
}

async function rig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-send-without-"));
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

type Row = Awaited<ReturnType<ArbiterClient["egressApprovals"]>>[number];
const rowOf = async (r: Rig, id: string): Promise<Row> => (await r.admin.egressApprovals()).find((a) => a.id === id)!;

test("Send without it: offered on a secret's card, stored as a once denial with strip, spent only by the send's own ask, then asks again", async () => {
  const r = await rig();
  try {
    const symbol = await r.data.symbolize({ tool: "Read", field: "content", value: "db-password-hunter2-xyz", confidentiality: "secret" });
    const ask = (via: ArbiterClient, extra: Record<string, unknown> = {}) =>
      via.desymbolizationDecision({ symbol, boundary: "network", destination: HOST, sessionKey: SESSION, ...extra });

    // S1
    const first = await ask(r.human);
    assert.equal(first.allow, false);
    const approvalId = (first as { approvalId?: string }).approvalId!;
    assert.ok(approvalId);
    assert.equal((await rowOf(r, approvalId)).stripOffered, true, "the listing marks the card");

    // S2
    await assert.rejects(r.admin.resolveEgressApproval(approvalId, true, "once", { strip: true }), /not an allow/);
    assert.equal((await rowOf(r, approvalId)).status, "pending", "a refused answer changes nothing");
    const answered = await r.admin.resolveEgressApproval(approvalId, false, undefined, { strip: true });
    assert.equal(answered.status, "denied");
    assert.equal(answered.scope, "once");
    assert.equal(answered.strip, true);
    assert.equal((await rowOf(r, approvalId)).stripOffered, undefined, "an answered card is not offered it");

    // S3: the data socket reads a plain denial and spends nothing
    const agent = await ask(r.data);
    assert.equal(agent.allow, false);
    assert.equal(agent.reason, "human-denied");
    assert.equal((agent as { strip?: true }).strip, undefined, "the agent's programs are never told to strip");
    assert.equal((await rowOf(r, approvalId)).consumedAt, null);
    // a pre-check reads it unspent: the call goes on to the send, nothing released
    const pre = await ask(r.human, { preflight: true });
    assert.equal(pre.allow, true);
    assert.equal((pre as { strip?: true }).strip, true);
    assert.equal((await rowOf(r, approvalId)).consumedAt, null, "a pre-check does not spend it");
    // the send's own ask spends it
    const send = await ask(r.human);
    assert.equal(send.allow, false, "the value is never released");
    assert.equal((send as { strip?: true }).strip, true, "the net-proxy is told to send it without the secret");
    assert.equal((send as { requiresApproval: boolean }).requiresApproval, false);
    assert.deepEqual(send.ruleRef, { source: "verdict", id: `verdict:${approvalId}` });
    assert.notEqual((await rowOf(r, approvalId)).consumedAt, null, "spent");

    // S4
    const next = await ask(r.human);
    assert.equal(next.allow, false);
    assert.equal((next as { strip?: true }).strip, undefined);
    assert.equal((next as { approvalId?: string }).approvalId, approvalId, "the same card asks again");
    const fresh = await rowOf(r, approvalId);
    assert.equal(fresh.status, "pending");
    assert.equal(fresh.strip, undefined);
    assert.equal(fresh.stripOffered, true);
  } finally {
    await r.close();
  }
});

test("Send without it is refused on a content-agnostic card (a HIGH session's request): fail-closed, the row unchanged", async () => {
  const r = await rig();
  try {
    // A HIGH session: a trusted any-model memo bound to example.com, read into context.
    await r.admin.setPathLabel({ path: join(HOME, "memos"), confidentiality: "any-model", bindings: ["example.com"] });
    const memo = await r.admin.symbolizeFull({
      tool: "Read", value: "Q3 revenue 4,200,000", field: "content", origin: join(HOME, "memos", "q3.md"), integrity: "trusted", sessionKey: "s-high",
    });
    assert.equal((await r.admin.declassifySymbol({ symbol: memo.symbol, sessionKey: "s-high" })).allowed, true);
    const held = await r.human.sessionEgressDecision({ sessionKey: "s-high", boundary: "network", destination: "https://evil.example/x?d=paraphrase" });
    assert.equal(held.allow, false);
    const sessionCard = await rowOf(r, held.approvalId!);
    assert.equal(sessionCard.symbol, "session-net:s-high");
    assert.equal(sessionCard.stripOffered, undefined, "never offered on a session's request");
    await assert.rejects(
      r.admin.resolveEgressApproval(held.approvalId!, false, "once", { strip: true }),
      /cannot be answered Send without it/,
    );
    const after = await rowOf(r, held.approvalId!);
    assert.equal(after.status, "pending", "the refused answer changed nothing");
    assert.equal(after.strip, undefined);

  } finally {
    await r.close();
  }
});
