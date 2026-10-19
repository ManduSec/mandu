/**
 * tls-endpoint-wiring.test.ts — plan 12 D3 on real wires, PRODUCTION wiring:
 * a real ArbiterServer holding a `models:` entry with `tls:`, the launcher's
 * own reader of that list (`readModelEndpoints`) and its client-key hand-off
 * (`localModelClientKeys` → MANDU_MODEL_CLIENT_KEYS), inspect-mcp's adapter
 * over the real client (`new ArbiterClientAdapter(new ArbiterClient(sock))`)
 * and the production endpoint factory, against an https stand-in model that
 * requires a client certificate and is signed by a private CA.
 *
 *   - with the entry's tls (CA, the server's pin, the client pair), the
 *     local-model document reaches that wire only, the answer returns as
 *     `$MDU:localmodel_`, and no raw byte comes back;
 *   - the same entry with a pin of an unrelated key: refused, and the
 *     server's application sees no request;
 * (The masked-key case, where the helper reads the key file's twin in the
 * agent's world and refuses, is inspect-mcp's endpoint-tls e2e: here the file
 * is readable, as it is when confinement is off.)
 *
 * Certificates are minted per run with openssl (self-SKIP without it).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter as InspectArbiterAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";
import { localModelClientKeys, readModelEndpoints } from "../../launcher/src/model-endpoints.js";
import { mintTlsFixtures } from "../../arbiter/test/helpers/tls-fixtures.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

const fx = mintTlsFixtures();
const CONTRACT = "Board minutes: acquire Initech for 18M. TLS_WIRING_CANARY";

async function mtlsModel(): Promise<{ url: string; bodies: string[]; close: () => Promise<void> }> {
  const bodies: string[] = [];
  const server: Server = createServer({ cert: fx!.serverCertPem, key: fx!.serverKeyPem, requestCert: true, rejectUnauthorized: true, ca: [fx!.clientCaCertPem] }, (req, res) => {
    let b = "";
    req.on("data", (d) => { b += d; });
    req.on("end", () => {
      bodies.push(b);
      const text = b.includes("quarantined content classifier") ? "substantive" : "An 18M acquisition.";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "q", choices: [{ message: { role: "assistant", content: text } }] }));
    });
  });
  server.on("tlsClientError", () => {});
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `https://127.0.0.1:${(server.address() as AddressInfo).port}/v1`, bodies, close: () => new Promise<void>((r) => server.close(() => r())) };
}

async function withArbiter(url: string, pin: string, fn: (sock: string, minter: ArbiterClient) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-tls-wiring-"));
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      models: [{ name: "corp", url, wire: "openai-chat", model: "q", local: true,
        tls: { ca_file: fx!.caCert, pin_sha256: [pin], client_cert: fx!.clientCert, client_key: fx!.clientKey } }],
      paths: [{ path: "/h/notes/minutes.md", level: "local-model" }],
    },
  });
  await arbiter.listen();
  const minter = new ArbiterClient(sock);
  await minter.connect();
  try { await fn(sock, minter); } finally {
    minter.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

async function inspectVia(sock: string, symbol: string, env: Record<string, string>) {
  const client = new ArbiterClient(sock);
  await client.connect();
  const outside = new MockUllm({ reply: "the default must not run" });
  try {
    const out = await inspectSymbol({ arbiter: new InspectArbiterAdapter(client), ullm: outside, sessionId: "tls-wiring", endpointUllm: createEndpointUllmFactory(env) }, { symbol, instruction: "Summarize." });
    return { out, outside };
  } finally { client.close(); }
}

test("production wiring: the tls entry reaches the helper with its checks; the key through the launcher's hand-off", { skip: fx === null ? "openssl is not on PATH" : false }, async () => {
  const model = await mtlsModel();
  try {
    await withArbiter(model.url, fx!.serverPin, async (sock, minter) => {
      const read = await readModelEndpoints(sock);
      assert.equal(read.status, "ok");
      assert.deepEqual(read.endpoints[0]!.tls, { caFile: fx!.caCert, pinSha256: [fx!.serverPin], clientCert: fx!.clientCert, clientKey: fx!.clientKey });
      const keys = localModelClientKeys(read.endpoints);
      assert.deepEqual(Object.keys(keys), ["corp"]);
      const minutes = await minter.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: "/h/notes/minutes.md" });

      const { out, outside } = await inspectVia(sock, minutes.symbol, { MANDU_MODEL_CLIENT_KEYS: JSON.stringify(keys) });
      assert.equal(out.ok, true, (out as { error?: string }).error);
      if (out.ok) assert.match(out.resultSymbol, /^\$MDU:localmodel_/);
      assert.ok(!JSON.stringify(out).includes("TLS_WIRING_CANARY"));
      assert.ok(model.bodies.some((b) => b.includes("TLS_WIRING_CANARY")));
      assert.equal(outside.calls.length, 0);
    });
    const before = model.bodies.length;
    await withArbiter(model.url, fx!.otherPin, async (sock, minter) => {
      const keys = localModelClientKeys((await readModelEndpoints(sock)).endpoints);
      const minutes = await minter.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: "/h/notes/minutes.md" });
      const { out } = await inspectVia(sock, minutes.symbol, { MANDU_MODEL_CLIENT_KEYS: JSON.stringify(keys) });
      assert.equal(out.ok, false, "a pin of an unrelated key: refused");
      assert.equal(model.bodies.length, before, "the server's application saw no request");
    });
  } finally {
    await model.close();
    fx?.cleanup();
  }
});
