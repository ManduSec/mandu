/**
 * egress-hold-send-without — a held request answered "Send without it"
 * across the real components (confidentiality.md §4, "A held request",
 * 2026-10-17). Mandu-new.
 *
 * No mocks on the path: a real ArbiterServer in `secrets` with data, human
 * and admin sockets; the net-proxy in its `server-main.ts` wiring
 * (`new ArbiterClientAdapter(new ArbiterClient(dataSock), new
 * ArbiterClient(humanSock))`) with a hold (`egressHoldMs`, what
 * MANDU_EGRESS_HOLD_MS sets) and its own forwarder; the dashboard's
 * production approvals adapter for the human's answers; and a recording
 * HTTP sink on loopback that sees the bytes the proxy put on the wire.
 *
 *   H1  "open an issue with the full error": the POST carrying a secret's
 *       placeholder to a host it is not bound to is HELD (no answer to the
 *       client, nothing on the wire) and files one card that takes Send
 *       without it;
 *   H2  the human answers Send without it while it waits: the SAME request
 *       reaches the sink with the marker where the placeholder was, without
 *       the value and without the placeholder, as valid JSON; the client
 *       gets the sink's answer; the answer is spent; the queue read paced
 *       the hold (the row was asked once, not once per poll);
 *   H3  nobody answers: refused at the deadline, nothing on the wire, the
 *       card still waiting;
 *   H4  the human answers Block while it waits: refused, nothing sent;
 *   H5  the arbiter gone while it waits: refused (fail-closed), nothing sent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { SEND_WITHOUT_MARKER, EGRESS_HELD_TIMEOUT } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = "sess-egress-hold";
const VALUE = "pg-pass-Hq42-held-send-without";
const VALUE2 = "pg-pass-Zz07-held-arbiter-gone";
const HOLD_MS = 4_000;

interface Received { headers: IncomingHttpHeaders; body: string }

function post(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
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
  const tmp = mkdtempSync(join(tmpdir(), "mandu-egress-hold-"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: adminSock,
    humanSocketPath: humanSockIn(tmp),
    eventDir: join(tmp, "events"),
    adminPolicyDir: null,
    packDir: null,
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await arbiter.listen();

  const received: Received[] = [];
  const sink = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(201, { "content-type": "application/json" });
      res.end("{\"number\":7}");
    });
  });
  sink.listen(0, "127.0.0.1");
  await once(sink, "listening");
  const sinkHost = `127.0.0.1:${(sink.address() as AddressInfo).port}`;

  // The net-proxy's production wiring, held as MANDU_EGRESS_HOLD_MS would.
  const netData = new ArbiterClient(socketPath);
  await netData.connect();
  const netHuman = new ArbiterClient(humanSockIn(tmp));
  // the trace's reader (the dashboard's human socket)
  const reader = new ArbiterClient(humanSockIn(tmp));
  await reader.connect();
  const proxy = new NetProxy({ arbiter: new ArbiterClientAdapter(netData, netHuman), sessionId: SESSION, allowThisMachine: true, log: () => {}, egressHoldMs: HOLD_MS });
  const proxyPort = await proxy.listen(0);

  const dash = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(dash, "the dashboard's adapter connects");
  const agent = new ArbiterClient(socketPath);
  await agent.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  let arbiterUp = true;
  return {
    proxyPort, received, sinkHost, dash: dash!, agent, admin, reader,
    async stopArbiter() { arbiterUp = false; agent.close(); admin.close(); reader.close(); dash!.close(); await arbiter.close(); },
    async close() {
      await proxy.close();
      netData.close(); netHuman.close();
      if (arbiterUp) { agent.close(); admin.close(); reader.close(); dash!.close(); await arbiter.close(); }
      sink.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** The pending card for `symbol`, once the held request has filed it. */
async function cardFor(s: Awaited<ReturnType<typeof stack>>, symbol: string) {
  for (let i = 0; i < 100; i++) {
    const card = (await s.dash.arbiter.egressApprovals("pending")).find((a) => a.symbol === symbol);
    if (card) return card;
    await sleep(20);
  }
  throw new Error(`no card for ${symbol}`);
}

test("a held request answered Send without it goes out with the marker; nobody answering, Block, and the arbiter gone each refuse it with nothing sent", async () => {
  const s = await stack();
  try {
    const symbol = await s.agent.symbolize({ tool: "Read", field: "content", value: VALUE, confidentiality: "secret", sessionKey: SESSION });
    const url = `http://${s.sinkHost}/api/issues`;
    const issue = JSON.stringify({
      title: "inventory-api does not start",
      body: `inventory-api: could not connect to the database at postgres://inventory:${symbol}@db.inventory.test:5432/inventory: connection refused`,
    });

    // H1: held while the card waits
    let settled = false;
    const sending = post(s.proxyPort, url, issue).finally(() => { settled = true; });
    const card = await cardFor(s, symbol);
    assert.equal(card.stripOffered, true, "the card takes Send without it");
    await sleep(600);
    assert.equal(settled, false, "the client is still waiting");
    assert.equal(s.received.length, 0, "nothing on the wire while held");

    // H2: answered while it waits; the same request goes
    await s.dash.arbiter.resolveEgressApproval(card.id, false, "once", { strip: true });
    const sent = await sending;
    assert.equal(sent.status, 201, sent.body);
    assert.equal(sent.body, "{\"number\":7}", "the client gets the tracker's answer");
    assert.equal(s.received.length, 1, "exactly one request on the wire");
    const wire = s.received[0]!;
    assert.ok(!wire.body.includes(VALUE), "the raw value never left");
    assert.ok(!wire.body.includes("$MDU:"), "nor the placeholder");
    assert.ok(!JSON.stringify(wire.headers).includes(VALUE) && !JSON.stringify(wire.headers).includes("$MDU:"));
    const parsed = JSON.parse(wire.body) as { title: string; body: string };
    assert.equal(parsed.body, `inventory-api: could not connect to the database at postgres://inventory:${SEND_WITHOUT_MARKER}@db.inventory.test:5432/inventory: connection refused`);
    assert.equal(wire.headers["content-length"], String(Buffer.byteLength(wire.body)));
    const spent = (await s.admin.egressApprovals()).find((a) => a.id === card.id)!;
    assert.notEqual(spent.consumedAt, null, "spent by the held request");
    assert.equal(spent.count, 1, "the queue read paced the hold: one ask filed the card, none per poll");

    // H3: the next send is held again (one-shot) and nobody answers
    const t0 = Date.now();
    const unanswered = await post(s.proxyPort, url, issue);
    assert.equal(unanswered.status, 403, unanswered.body);
    assert.ok(Date.now() - t0 >= HOLD_MS - 200, "held until the deadline");
    assert.ok(unanswered.body.includes(EGRESS_HELD_TIMEOUT));
    assert.ok(!unanswered.body.includes(VALUE));
    assert.equal(s.received.length, 1, "nothing more on the wire");
    assert.equal((await s.admin.egressApprovals()).find((a) => a.id === card.id)!.status, "pending", "the card still waits");

    // H4: Block while it waits
    // (the card still waits from H3: answer only once THIS request asked it,
    // so the Block lands while the request is held)
    const askedBefore = (await s.admin.egressApprovals()).find((a) => a.id === card.id)!.count;
    const blocking = post(s.proxyPort, url, issue);
    const again = await cardFor(s, symbol);
    for (let i = 0; i < 100 && (await s.admin.egressApprovals()).find((a) => a.id === again.id)!.count === askedBefore; i++) await sleep(20);
    await s.dash.arbiter.resolveEgressApproval(again.id, false);
    const blocked = await blocking;
    assert.equal(blocked.status, 403, blocked.body);
    assert.ok(!blocked.body.includes(VALUE));
    assert.equal(s.received.length, 1, "Block: nothing sent");
    // The trace: the refusal is decided by the human's verdict, and it keeps
    // the card it waited on with the rule that filed it (egress-hold.md,
    // "The trace"; a drill grading `net_blocked` + `rule` reads it, demo-c1
    // on the defaults, 2026-10-19).
    type NetEv = { kind: string; action?: string; policy?: { ruleRef?: { id?: string } }; heldFor?: Array<{ approvalId: string; rule?: string }> };
    let byVerdict: NetEv | undefined;
    let unansweredEv: NetEv | undefined;
    for (let i = 0; i < 100 && !byVerdict; i++) {
      const evs = (await s.reader.events(SESSION)) as unknown as NetEv[];
      const blocks = evs.filter((e) => e.kind === "net_action" && e.action === "blocked");
      byVerdict = blocks.find((e) => e.policy?.ruleRef?.id === `verdict:${again.id}`);
      unansweredEv = blocks.find((e) => e.policy?.ruleRef?.id?.startsWith("egress:") === true);
      if (!byVerdict) await sleep(20);
    }
    assert.ok(byVerdict, "the Block's refusal names the human's verdict");
    const askedBy = unansweredEv?.policy?.ruleRef?.id;
    assert.ok(askedBy, "the unanswered hold's refusal names the rule that asked");
    assert.deepEqual(unansweredEv!.heldFor, [{ approvalId: card.id, rule: askedBy }]);
    assert.deepEqual(byVerdict!.heldFor, [{ approvalId: again.id, rule: askedBy }], "the Block keeps the card and the rule that filed it");
    assert.ok(!JSON.stringify(byVerdict).includes(VALUE), "no value in the trace");

    // H5: the arbiter gone while it waits
    const symbol2 = await s.agent.symbolize({ tool: "Read", field: "content", value: VALUE2, confidentiality: "secret", sessionKey: SESSION });
    const issue2 = JSON.stringify({ title: "again", body: `password=${symbol2}` });
    const orphan = post(s.proxyPort, url, issue2);
    await cardFor(s, symbol2);
    await s.stopArbiter();
    const gone = await orphan;
    assert.equal(gone.status, 403, gone.body);
    assert.ok(!gone.body.includes(VALUE2));
    assert.equal(s.received.length, 1, "the arbiter gone: nothing sent");
  } finally {
    await s.close();
  }
});
