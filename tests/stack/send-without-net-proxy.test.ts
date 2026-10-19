/**
 * send-without-net-proxy — "Send without it" across the real components
 * (confidentiality.md §4 "Send without it", dashboard.md §4.34, 2026-10-17). Mandu-new.
 *
 * No mocks on the path: a real ArbiterServer in `secrets` with data, human
 * and admin sockets; the net-proxy wired as `net-proxy/src/server-main.ts`
 * wires it (`new ArbiterClientAdapter(new ArbiterClient(dataSock), new
 * ArbiterClient(humanSock))`) with its own forwarder; the dashboard's
 * production approvals adapter (`makeApprovalsArbiter`, the human's answer
 * on the admin channel: the parity half for its forwarded `strip`); and a
 * recording HTTP sink on loopback that sees the bytes the proxy put on the
 * wire.
 *
 *   S1  "open an issue with the full error": a JSON body carrying a secret's
 *       symbol to a host it is not bound to is held (403, nothing on the
 *       wire) and files a card the listing marks `stripOffered`;
 *   S2  the human answers Send without it through the dashboard adapter;
 *       a program of the agent asking on the data socket is told nothing
 *       and spends nothing;
 *   S3  the agent sends again: the sink receives the request with the
 *       marker where the symbol was, WITHOUT the raw value and WITHOUT the
 *       symbol, as valid JSON with a Content-Length that is its length;
 *   S4  one-shot: the next send is held again;
 *   S5  a HIGH session's network card (content-agnostic: its request may
 *       hold the raw value) refuses the answer through the same adapter,
 *       and nothing changes;
 *   S6  the arbiter gone: the send is blocked (fail-closed), nothing sent.
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
import { SEND_WITHOUT_MARKER } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = "sess-send-without";
const VALUE = "pg-pass-Zq81-send-without-secret";

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

async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-send-without-"));
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

  // The recording sink: the bytes on the wire.
  const received: Received[] = [];
  const sink = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(201, { "content-type": "application/json" });
      res.end("{\"number\":1}");
    });
  });
  sink.listen(0, "127.0.0.1");
  await once(sink, "listening");
  const sinkHost = `127.0.0.1:${(sink.address() as AddressInfo).port}`;

  // The net-proxy's production wiring, with its own forwarder.
  const netData = new ArbiterClient(socketPath);
  await netData.connect();
  const netHuman = new ArbiterClient(humanSockIn(tmp));
  const proxy = new NetProxy({ arbiter: new ArbiterClientAdapter(netData, netHuman), sessionId: SESSION, allowThisMachine: true, log: () => {} });
  const proxyPort = await proxy.listen(0);

  // The dashboard's production approvals adapter (reads on the data socket,
  // the human's answer on the admin channel).
  const dash = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(dash, "the dashboard's adapter connects");
  // A program of the agent: the data socket is all it reaches.
  const agent = new ArbiterClient(socketPath);
  await agent.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const human = new ArbiterClient(humanSockIn(tmp));
  await human.connect();
  let arbiterUp = true;
  return {
    proxyPort, received, sinkHost, dash: dash!, agent, admin, human,
    async stopArbiter() { arbiterUp = false; agent.close(); admin.close(); human.close(); dash!.close(); await arbiter.close(); },
    async close() {
      await proxy.close();
      netData.close(); netHuman.close();
      if (arbiterUp) { agent.close(); admin.close(); human.close(); dash!.close(); await arbiter.close(); }
      sink.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

test("Send without it: the next request reaches the sink with the marker, without the value or the symbol; one-shot; a session's card refuses it; the arbiter gone blocks", async () => {
  const s = await stack();
  try {
    const symbol = await s.agent.symbolize({ tool: "Read", field: "content", value: VALUE, confidentiality: "secret", sessionKey: SESSION });
    const url = `http://${s.sinkHost}/repos/acme/app/issues`;
    const issue = JSON.stringify({ title: "Deploy fails", body: `Error: password authentication failed for user "app" (password=${symbol}) at db.internal:5432` });

    // S1
    const held = await post(s.proxyPort, url, issue);
    assert.equal(held.status, 403, held.body);
    assert.ok(!held.body.includes(VALUE));
    assert.equal(s.received.length, 0, "nothing on the wire");
    const card = (await s.dash.arbiter.egressApprovals("pending")).find((a) => a.symbol === symbol);
    assert.ok(card, "the held send filed a card");
    assert.equal(card!.stripOffered, true, "the card takes Send without it");

    // S2
    const answered = await s.dash.arbiter.resolveEgressApproval(card!.id, false, "once", { strip: true });
    assert.equal(answered.status, "denied", "never an approval: the value is not released");
    assert.equal(answered.scope, "once");
    assert.equal(answered.strip, true);
    const d = await s.agent.desymbolizationDecision({ symbol, boundary: "network", destination: s.sinkHost, sessionKey: SESSION });
    assert.equal(d.allow, false);
    assert.equal((d as { strip?: true }).strip, undefined, "the agent's programs are not told to strip");
    assert.equal((await s.admin.egressApprovals()).find((a) => a.id === card!.id)!.consumedAt, null, "nor do they spend it");

    // S3
    const sent = await post(s.proxyPort, url, issue);
    assert.equal(sent.status, 201, sent.body);
    assert.equal(s.received.length, 1, "exactly one request on the wire");
    const wire = s.received[0]!;
    assert.ok(!wire.body.includes(VALUE), "the raw value never left");
    assert.ok(!wire.body.includes("$MDU:"), "nor the symbol");
    assert.ok(!JSON.stringify(wire.headers).includes(VALUE) && !JSON.stringify(wire.headers).includes("$MDU:"));
    const parsed = JSON.parse(wire.body) as { title: string; body: string };
    assert.equal(parsed.body, `Error: password authentication failed for user "app" (password=${SEND_WITHOUT_MARKER}) at db.internal:5432`);
    assert.equal(parsed.title, "Deploy fails");
    assert.equal(wire.headers["content-length"], String(Buffer.byteLength(wire.body)), "Content-Length is the body's");
    assert.notEqual((await s.admin.egressApprovals()).find((a) => a.id === card!.id)!.consumedAt, null, "spent by the send");

    // S4
    const again = await post(s.proxyPort, url, issue);
    assert.equal(again.status, 403, again.body);
    assert.equal(s.received.length, 1, "one answer, one request");
    const requeued = (await s.admin.egressApprovals()).find((a) => a.id === card!.id)!;
    assert.equal(requeued.status, "pending");
    assert.equal(requeued.strip, undefined);

    // S5: a HIGH session's network card (content-agnostic)
    const HOME = "/home/send-without-stack";
    await s.admin.setPathLabel({ path: join(HOME, "memos"), confidentiality: "any-model", bindings: ["example.com"] });
    const memo = await s.admin.symbolizeFull({ tool: "Read", value: "Q3 revenue 4,200,000", field: "content", origin: join(HOME, "memos", "q3.md"), integrity: "trusted", sessionKey: "s-high" });
    assert.equal((await s.admin.declassifySymbol({ symbol: memo.symbol, sessionKey: "s-high" })).allowed, true);
    const asked = await s.human.sessionEgressDecision({ sessionKey: "s-high", boundary: "network", destination: "https://evil.example/x" });
    assert.ok(asked.approvalId);
    const sessionCard = (await s.dash.arbiter.egressApprovals("pending")).find((a) => a.id === asked.approvalId)!;
    assert.equal(sessionCard.symbol, "session-net:s-high");
    assert.equal(sessionCard.stripOffered, undefined, "not offered on a content-agnostic card");
    await assert.rejects(s.dash.arbiter.resolveEgressApproval(asked.approvalId!, false, "once", { strip: true }), /cannot be answered Send without it/);
    const unchanged = (await s.admin.egressApprovals()).find((a) => a.id === asked.approvalId)!;
    assert.equal(unchanged.status, "pending");
    assert.equal(unchanged.strip, undefined);

    // S6: the arbiter gone → blocked, nothing sent
    await s.stopArbiter();
    const gone = await post(s.proxyPort, url, issue);
    assert.equal(gone.status, 403, gone.body);
    assert.ok(!gone.body.includes(VALUE));
    assert.equal(s.received.length, 1, "nothing more on the wire");
  } finally {
    await s.close();
  }
});
