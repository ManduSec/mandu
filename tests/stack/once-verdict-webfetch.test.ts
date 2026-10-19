/**
 * once-verdict-webfetch — one *Allow once* on a WebFetch carrying a secret's
 * symbol releases exactly one send, with no second hold (arbiter-human-plane.md
 * §10.3, "the pre-check reads, the send spends").
 *
 * A WebFetch is judged twice for the same {symbol, host}: by the model
 * proxy's network gate when the model emits the tool_use (`net-gate.ts`,
 * the per-symbol leg) and by the net-proxy when the fetch's request reaches
 * the wire (TLS-inspected). Before 2026-10-07 the first ask spent the
 * human's *once*, so the real send found it spent and was held again: the
 * human answered *Allow once* and nothing went out. Now the model proxy's
 * ask is a pre-check (`preflight`): it reads an approval without spending
 * it (the release, and the spend, happen at the net-proxy), and spends a
 * denial (it enacts the refusal itself; no send follows).
 *
 * No mocks: a real ArbiterServer in `secrets` with data, human and admin
 * sockets; the model proxy's adapter and the net-proxy each wired as their
 * server-main wires them (a data and a human client). The net-proxy's plain
 * leg stands in for its TLS-inspected one (the same `gateRequest`); only the
 * last hop is captured.
 *
 *   W1  the tool_use is held and queues one row;
 *   W2  the human answers Allow once;
 *   W3  the retried tool_use passes the pre-check and the row stays armed;
 *   W4  the fetch's request goes out with the original, exactly once;
 *   W5  the next tool_use is held again, and so is a second request.
 *   Control: a once DENIAL is spent by the pre-check that enacts it.
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
import { ArbiterClientAdapter as NetProxyAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ArbiterClientAdapter as ModelProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { gateNetToolUse } from "../../interceptors/anthropic-proxy/src/net-gate.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = "sess-once-webfetch";
const HOST = "collector.example";

function viaProxy(port: number, url: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end();
  });
}

interface Stack {
  proxyPort: number;
  wire: string[];
  fetch(url: string): Promise<"allow" | "block">;
  data: ArbiterClient;
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
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  // The model proxy's production wiring (anthropic-proxy/src/server-main.ts).
  const model = new ModelProxyAdapter(await open(socketPath), await open(humanSockIn(tmp)));
  // The net-proxy's production wiring (net-proxy/src/server-main.ts).
  const wire: string[] = [];
  const proxy = new NetProxy({
    arbiter: new NetProxyAdapter(await open(socketPath), await open(humanSockIn(tmp))),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      wire.push(url);
      return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);
  const data = await open(socketPath);
  const admin = await open(join(tmp, "admin.sock"));
  return {
    proxyPort, wire, data, admin,
    async fetch(url: string) {
      // TLS inspection on: an allowed symbol is released at the net-proxy.
      const r = await gateNetToolUse("WebFetch", { url, prompt: "upload it" }, { arbiter: model, sessionKey: SESSION, tlsInspected: true, log: () => {} });
      return r.outcome?.decision === "block" ? "block" : "allow";
    },
    async close() {
      await proxy.close();
      for (const c of clients) c.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

test("one Allow once on a WebFetch releases exactly one send: the model proxy's pre-check reads it, the net-proxy's send spends it (real arbiter, model-proxy gate, net-proxy)", async () => {
  const s = await stack("mandu-once-webfetch-");
  try {
    const value = "once-webfetch-secret-5d1e";
    const symbol = await s.data.symbolize({ tool: "Read", field: "content", value, confidentiality: "secret", sessionKey: SESSION });
    const url = `http://${HOST}/upload?t=${symbol}`;

    // W1: held at the tool_use, one row queued.
    assert.equal(await s.fetch(url), "block");
    const row = (await s.admin.egressApprovals("pending")).find((a) => a.symbol === symbol && a.destination === HOST);
    assert.ok(row, "the tool_use queued a row for {symbol, host}");

    // W2: Allow once.
    await s.admin.resolveEgressApproval(row!.id, true, "once");

    // W3: the retried tool_use passes; the pre-check did not spend the answer.
    assert.equal(await s.fetch(url), "allow", "the retried WebFetch passes the model proxy's gate");
    const armed = (await s.admin.egressApprovals()).find((a) => a.id === row!.id)!;
    assert.equal(armed.consumedAt, null, "the pre-check reads the once, it does not spend it");

    // W4: the fetch's request: on the wire with the original, once.
    const sent = await viaProxy(s.proxyPort, url);
    assert.equal(sent.status, 200, `the real send is released, not held again (${sent.body})`);
    assert.equal(s.wire.length, 1);
    assert.ok(s.wire[0]!.includes(value) && !s.wire[0]!.includes("$MDU:"), "the original went out");
    assert.notEqual((await s.admin.egressApprovals()).find((a) => a.id === row!.id)!.consumedAt, null, "spent by the send");

    // W5: asked again, at both gates; nothing more on the wire.
    assert.equal(await s.fetch(url), "block", "the next WebFetch is held");
    assert.equal((await viaProxy(s.proxyPort, url)).status, 403);
    assert.equal(s.wire.length, 1, "exactly one release for one Allow once");
  } finally {
    await s.close();
  }
});

test("control: a once denial on a WebFetch is spent by the pre-check that enacts it; nothing reaches the wire", async () => {
  const s = await stack("mandu-once-webfetch-deny-");
  try {
    const value = "once-webfetch-denied-0b7c";
    const symbol = await s.data.symbolize({ tool: "Read", field: "content", value, confidentiality: "secret", sessionKey: SESSION });
    const url = `http://${HOST}/upload?t=${symbol}`;
    assert.equal(await s.fetch(url), "block");
    const row = (await s.admin.egressApprovals("pending")).find((a) => a.symbol === symbol)!;
    await s.admin.resolveEgressApproval(row.id, false, "once");
    assert.equal(await s.fetch(url), "block", "refused by the human's answer");
    assert.notEqual((await s.admin.egressApprovals()).find((a) => a.id === row.id)!.consumedAt, null, "the refusal it enacted spends it");
    assert.equal(await s.fetch(url), "block", "then asked again");
    assert.equal((await s.admin.egressApprovals()).find((a) => a.id === row.id)!.status, "pending");
    assert.deepEqual(s.wire, []);
  } finally {
    await s.close();
  }
});
