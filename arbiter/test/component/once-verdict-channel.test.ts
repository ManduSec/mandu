/**
 * once-verdict-channel — a human's *Allow once* is spent only by the gate it
 * was given to (confidentiality plan 13 §3 D9, "who may spend a human
 * verdict"; arbiter-human-plane.md §10).
 *
 * The gates that consult a prior verdict (`desymbolizationDecision`,
 * `fsPathDecision`, `escalateExec`) answer every client, the data socket the
 * agent's processes reach included. Before this fix a data-socket ask SPENT
 * an unspent *once* (`consumeOnce`) for whoever asked first: an injected agent
 * could spend every *Allow once* the human gave, so the real send, asked on
 * the human socket by the net-proxy, found it spent and asked the human
 * again (approval fatigue, pushing the human toward *Always*).
 *
 * Now, from the data socket, an unspent *once* is read and never spent: a
 * once DENIAL still answers (a denial is anyone's to read, and fail-closed),
 * a once APPROVAL is no verdict (the law decides, which queues; the row stays
 * armed). A standing (*always*) verdict answers every channel, as before.
 * `declassifySymbol` keeps spending from the data socket: its caller, the
 * quarantined inspect child, lives in the agent's tree by design
 * (`rung3-completes.test.ts` pins that a data-socket read spends its once).
 *
 * A real ArbiterServer in `secrets`, with data, human and admin sockets.
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

const EVIL = "evil.example";
const SESSION = "s-once-channel";

interface Rig {
  data: ArbiterClient;
  human: ArbiterClient;
  admin: ArbiterClient;
  close(): Promise<void>;
}

async function rig(prefix: string): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
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

/** A secret symbol, queued at EVIL by the gate's own (human-socket) ask. */
async function queuedSend(r: Rig, value: string): Promise<{ symbol: string; approvalId: string }> {
  const symbol = await r.data.symbolize({ tool: "WebFetch", field: "text", value, confidentiality: "secret" });
  const first = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
  assert.equal(first.allow, false);
  const approvalId = (first as { approvalId?: string }).approvalId;
  assert.ok(approvalId, "the gate's ask queues a row");
  return { symbol, approvalId };
}

const rowOf = async (r: Rig, id: string) => (await r.admin.egressApprovals()).find((a) => a.id === id)!;

test("network: a data-socket ask neither spends nor is granted the human's Allow once; the gate's ask on the human socket is", async () => {
  const r = await rig("mandu-once-net-");
  try {
    const { symbol, approvalId } = await queuedSend(r, "once-net-secret-value");
    await r.admin.resolveEgressApproval(approvalId, true, "once");

    // The agent's ask on the data socket: no verdict for it (the law decides:
    // the secret is unbound at EVIL, so it asks), and the once stays armed.
    const agent = await r.data.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(agent.allow, false, "a data-socket ask is not granted the human's once");
    assert.equal((agent as { requiresApproval?: boolean }).requiresApproval, true);
    const armed = await rowOf(r, approvalId);
    assert.equal(armed.status, "approved", "the human's answer is not reset to a question");
    assert.equal(armed.scope, "once");
    assert.equal(armed.consumedAt, null, "the data-socket ask did not spend the once");

    // The gate's ask on the human socket: the one use the human granted.
    const use = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(use.allow, true, "the gate gets the use the human granted");
    assert.deepEqual(use.ruleRef, { source: "verdict", id: `verdict:${approvalId}` });
    assert.notEqual((await rowOf(r, approvalId)).consumedAt, null, "spent by the gate");

    // Then the same row asks again, on either channel.
    const again = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(again.allow, false, "spent: exactly one use");
    assert.equal((again as { approvalId?: string }).approvalId, approvalId);
    assert.equal((await rowOf(r, approvalId)).status, "pending");
  } finally {
    await r.close();
  }
});

test("network control: with no data-socket ask, the human socket's ask spends the once (one use, then asks again)", async () => {
  const r = await rig("mandu-once-net-ctl-");
  try {
    const { symbol, approvalId } = await queuedSend(r, "once-net-control-value");
    await r.admin.resolveEgressApproval(approvalId, true, "once");
    const use = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(use.allow, true);
    const again = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(again.allow, false);
  } finally {
    await r.close();
  }
});

test("network: a once DENIAL answers a data-socket ask without being spent; the gate then spends it; an Always answers every channel", async () => {
  const r = await rig("mandu-once-deny-");
  try {
    const { symbol, approvalId } = await queuedSend(r, "once-deny-secret-value");
    await r.admin.resolveEgressApproval(approvalId, false, "once");
    const agent = await r.data.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(agent.allow, false);
    assert.equal(agent.reason, "human-denied", "a denial is read from any channel (fail-closed)");
    assert.equal((await rowOf(r, approvalId)).consumedAt, null, "and not spent by it");
    const gate = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
    assert.equal(gate.reason, "human-denied");
    assert.notEqual((await rowOf(r, approvalId)).consumedAt, null, "the gate spends it");

    // A standing verdict is not spent by anyone and answers every channel.
    const s2 = await queuedSend(r, "always-secret-value");
    await r.admin.resolveEgressApproval(s2.approvalId, true, "always");
    for (const c of [r.data, r.human, r.data]) {
      const d = await c.desymbolizationDecision({ symbol: s2.symbol, boundary: "network", destination: EVIL, sessionKey: SESSION });
      assert.equal(d.allow, true, "an Always answers every channel");
    }
  } finally {
    await r.close();
  }
});

test("files: a data-socket fsPathDecision does not spend the human's Allow once; the proxy's gate on the human socket does", async () => {
  const r = await rig("mandu-once-fs-");
  try {
    const req = { tool: "Read", path: "/opt/once-channel/notes.txt", mode: "read" as const, workspaceRoots: [], sessionKey: SESSION };
    const first = await r.human.fsPathDecision(req);
    assert.equal(first.allow, false);
    const approvalId = (first as { approvalId?: string }).approvalId!;
    assert.ok(approvalId);
    await r.admin.resolveEgressApproval(approvalId, true, "once");

    const agent = await r.data.fsPathDecision(req);
    assert.equal(agent.allow, false, "a data-socket ask is not granted the human's once");
    assert.equal((await rowOf(r, approvalId)).consumedAt, null, "nor does it spend it");

    assert.equal((await r.human.fsPathDecision(req)).allow, true, "the gate's one use");
    assert.equal((await r.human.fsPathDecision(req)).allow, false, "then it asks again");
  } finally {
    await r.close();
  }
});

test("exec escalation: a data-socket escalateExec is not granted (nor spends) an Allow once", async () => {
  const r = await rig("mandu-once-exec-");
  try {
    const args = { argv: ["curl", "https://example.com"], resource: "network" as const, sessionKey: SESSION };
    const first = await r.human.escalateExec(args);
    assert.equal(first.shell, "AgentShell");
    const approvalId = first.approvalId!;
    assert.ok(approvalId);
    await r.admin.resolveEgressApproval(approvalId, true, "once");

    const agent = await r.data.escalateExec(args);
    assert.equal(agent.shell, "AgentShell", "fail-safe: the data socket does not escalate on a once");
    assert.equal((await rowOf(r, approvalId)).consumedAt, null);

    assert.equal((await r.human.escalateExec(args)).shell, "HumanShell", "the attested ask's one use");
    assert.equal((await r.human.escalateExec(args)).shell, "AgentShell", "then it asks again");
  } finally {
    await r.close();
  }
});

test("preflight (the model proxy's tool_use pre-check): on the human socket it reads an Allow once unspent and spends a once denial; from the data socket it is granted nothing", async () => {
  const r = await rig("mandu-once-preflight-");
  try {
    const { symbol, approvalId } = await queuedSend(r, "once-preflight-secret-value");
    await r.admin.resolveEgressApproval(approvalId, true, "once");
    const ask = { symbol, boundary: "network" as const, destination: EVIL, sessionKey: SESSION, preflight: true };
    for (let i = 0; i < 2; i++) {
      const pre = await r.human.desymbolizationDecision(ask);
      assert.equal(pre.allow, true, "the pre-check reads the human's once");
    }
    assert.equal((await r.data.desymbolizationDecision(ask)).allow, false, "a data-socket pre-check is granted nothing");
    assert.equal((await rowOf(r, approvalId)).consumedAt, null, "no pre-check spent it");
    // The real send (no preflight) spends it, once.
    assert.equal((await r.human.desymbolizationDecision({ ...ask, preflight: false })).allow, true);
    assert.equal((await r.human.desymbolizationDecision(ask)).allow, false, "spent: the pre-check asks again");

    // A once denial is spent by the pre-check that enacts it.
    const d = await queuedSend(r, "once-preflight-denied-value");
    await r.admin.resolveEgressApproval(d.approvalId, false, "once");
    const denied = await r.human.desymbolizationDecision({ symbol: d.symbol, boundary: "network", destination: EVIL, sessionKey: SESSION, preflight: true });
    assert.equal(denied.reason, "human-denied");
    assert.notEqual((await rowOf(r, d.approvalId)).consumedAt, null, "the refusal it enacted spends it");
  } finally {
    await r.close();
  }
});
