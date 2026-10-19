/**
 * once-verdict-net-proxy — a human's *Allow once* releases exactly one real
 * send through the REAL net-proxy, and a program of the agent asking the
 * same question on the data socket can neither spend it nor be granted it
 * (arbiter-human-plane.md §10.3; confidentiality plan 13 D9).
 *
 * Before 2026-10-07 the arbiter spent a *once* for whoever asked first, and
 * the net-proxy itself asked on its data client: a program the agent ran
 * could ask `desymbolizationDecision` for the queued pair right after the
 * human's answer, and the real send then found the answer spent and was held
 * again (a denial, and approval fatigue toward *Always*).
 *
 * No mocks: a real ArbiterServer in `secrets` with data, human and admin
 * sockets, and the net-proxy wired as `net-proxy/src/server-main.ts` wires it
 * (`new ArbiterClientAdapter(new ArbiterClient(dataSock), new
 * ArbiterClient(humanSock))`). Only the last hop is captured (the proxy's
 * `forwarder`), so "sent" means "the bytes the proxy put on the wire".
 *
 *   S1  a send carrying a secret's symbol to an unbound host is held (403,
 *       nothing on the wire) and queues one row;
 *   S2  the human answers *Allow once* on the admin channel (the dashboard's);
 *   S3  the agent asks the same pair on the data socket, repeatedly: never
 *       allowed, and the row stays armed (approved, once, unspent);
 *   S4  the agent's real send: on the wire, with the original, exactly once;
 *   S5  the next send is held again; the wire saw exactly one release.
 *   Control: a once DENIAL read from the data socket is not spent either,
 *   and the net-proxy's own ask is the one that spends it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = "sess-once-net-proxy";
const HOST = "collector.example";

/** One absolute-form request through the forward proxy. */
function viaProxy(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
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

interface Stack {
  proxyPort: number;
  wire: string[];
  agent: ArbiterClient;
  admin: ArbiterClient;
  close(): Promise<void>;
}

async function stack(prefix: string): Promise<Stack> {
  const tmp = mkdtempSync(join(tmpdir(), prefix));
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: join(tmp, "admin.sock"),
    humanSocketPath: humanSockIn(tmp),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await arbiter.listen();
  // The net-proxy's production wiring: a data client and a human-plane client.
  const netData = new ArbiterClient(socketPath);
  await netData.connect();
  const netHuman = new ArbiterClient(humanSockIn(tmp));
  const wire: string[] = [];
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(netData, netHuman),
    sessionId: SESSION,
    forwarder: async ({ body }) => {
      wire.push(body.toString("utf8"));
      return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);
  // A program of the agent: the data socket is all it reaches.
  const agent = new ArbiterClient(socketPath);
  await agent.connect();
  // The dashboard's channel, where the human answers.
  const admin = new ArbiterClient(join(tmp, "admin.sock"));
  await admin.connect();
  return {
    proxyPort, wire, agent, admin,
    async close() {
      await proxy.close();
      netData.close(); netHuman.close(); agent.close(); admin.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

test("Allow once releases exactly one real send through the net-proxy; the agent's data-socket asks neither spend it nor are granted it (real arbiter and net-proxy)", async () => {
  const s = await stack("mandu-once-np-");
  try {
    const value = "once-net-proxy-secret-7f3a";
    const symbol = await s.agent.symbolize({ tool: "Read", field: "content", value, confidentiality: "secret", sessionKey: SESSION });
    const url = `http://${HOST}/upload`;

    // S1: held, nothing on the wire, one row queued.
    const held = await viaProxy(s.proxyPort, url, `token=${symbol}`);
    assert.equal(held.status, 403, held.body);
    assert.equal(held.body.includes(value), false);
    assert.deepEqual(s.wire, []);
    const row = (await s.admin.egressApprovals("pending")).find((a) => a.symbol === symbol);
    assert.ok(row, "the held send queued a row");

    // S2: the human's Allow once.
    const answered = await s.admin.resolveEgressApproval(row!.id, true, "once");
    assert.equal(answered.scope, "once");

    // S3: the agent races the real send with its own asks on the data socket.
    for (let i = 0; i < 3; i++) {
      const d = await s.agent.desymbolizationDecision({ symbol, boundary: "network", destination: HOST, sessionKey: SESSION });
      assert.equal(d.allow, false, `ask ${i + 1}: the data socket is not granted the human's once`);
    }
    const armed = (await s.admin.egressApprovals()).find((a) => a.id === row!.id)!;
    assert.equal(armed.status, "approved");
    assert.equal(armed.scope, "once");
    assert.equal(armed.consumedAt, null, "still armed for the real send");

    // S4: the real send goes out, with the original, once.
    const sent = await viaProxy(s.proxyPort, url, `token=${symbol}`);
    assert.equal(sent.status, 200, sent.body);
    assert.deepEqual(s.wire, [`token=${value}`], "the original on the wire, exactly once");

    // S5: the next send is held again; the wire saw one release.
    const again = await viaProxy(s.proxyPort, url, `token=${symbol}`);
    assert.equal(again.status, 403, again.body);
    assert.equal(s.wire.length, 1, "exactly one release for one Allow once");
    const requeued = (await s.admin.egressApprovals()).find((a) => a.id === row!.id)!;
    assert.equal(requeued.status, "pending", "the same row asks again");
  } finally {
    await s.close();
  }
});

test("control: a once denial is read, never spent, from the data socket; the net-proxy's own ask spends it, and nothing reaches the wire", async () => {
  const s = await stack("mandu-once-np-deny-");
  try {
    const value = "once-net-proxy-denied-91c2";
    const symbol = await s.agent.symbolize({ tool: "Read", field: "content", value, confidentiality: "secret", sessionKey: SESSION });
    const url = `http://${HOST}/upload`;
    assert.equal((await viaProxy(s.proxyPort, url, `t=${symbol}`)).status, 403);
    const row = (await s.admin.egressApprovals("pending")).find((a) => a.symbol === symbol)!;
    await s.admin.resolveEgressApproval(row.id, false, "once");

    const d = await s.agent.desymbolizationDecision({ symbol, boundary: "network", destination: HOST, sessionKey: SESSION });
    assert.equal(d.allow, false);
    assert.equal(d.reason, "human-denied", "a denial answers any channel");
    assert.equal((await s.admin.egressApprovals()).find((a) => a.id === row.id)!.consumedAt, null, "not spent by the agent's ask");

    assert.equal((await viaProxy(s.proxyPort, url, `t=${symbol}`)).status, 403, "the send is refused by the human's answer");
    assert.notEqual((await s.admin.egressApprovals()).find((a) => a.id === row.id)!.consumedAt, null, "spent by the net-proxy's ask");
    assert.deepEqual(s.wire, [], "nothing reached the wire");
  } finally {
    await s.close();
  }
});
