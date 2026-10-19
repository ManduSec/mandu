/**
 * endpoint-tls e2e (plan 12 D3): the helper against a real https model server
 * with a private CA, through the PRODUCTION endpoint factory
 * (`createEndpointUllmFactory`) and `inspectSymbol`.
 *
 * The oracle for every refusal: the call fails, the default helper sees
 * nothing, and the model server's application sees ZERO requests (the
 * refusal happens in the TLS handshake, before any byte of the document is
 * handed to it). The cases:
 *   - no `ca_file` (the server's CA is unknown): refused;  `ca_file`: served;
 *   - a pin of an unrelated key: refused;  the server's (or its CA's) pin: served;
 *   - a server that requires a client certificate, without `client_cert`:
 *     refused;  with it (the key's bytes from MANDU_MODEL_CLIENT_KEYS, as the
 *     launcher hands them): served;
 *   - a `client_key` whose bytes are not a key (the masked twin a helper
 *     reads in the agent's world): refused before any connection;
 *   - plan 12 D4, a `perimeter` on the entry (the arbiter attaches it to a
 *     local entry on another machine): an address outside it, literal or
 *     resolved from a name, is refused with zero requests; inside is served,
 *     with the name kept for the host-name check.
 *
 * Certificates are minted per run with openssl (self-SKIP without it).
 * Axes: the mock arbiter plays confidentiality ON; this package reads none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";

import { inspectSymbol, type InspectSymbolDeps } from "../../src/inspect-symbol.js";
import { createEndpointUllmFactory } from "../../src/ullm-config.js";
import type { ModelEndpoint } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUllm } from "../helpers/mock-ullm.js";
import { mintTlsFixtures } from "../helpers/tls-fixtures.js";

const fx = mintTlsFixtures();
const skip = fx === null ? "openssl is not on PATH" : false;
process.on("exit", () => fx?.cleanup());

const LOCAL = "$MDU:localmodel_Read[7157]";
const NOTES = "TLS-CANARY: the Q4 layoff list is Kim, Park, Lee.";

interface Wire { url: string; bodies: string[]; close: () => Promise<void> }

async function httpsModel(opts: { mtls?: boolean } = {}): Promise<Wire> {
  const bodies: string[] = [];
  const server: Server = createServer({
    cert: fx!.serverCertPem, key: fx!.serverKeyPem,
    ...(opts.mtls ? { requestCert: true, rejectUnauthorized: true, ca: [fx!.clientCaCertPem] } : {}),
  }, (req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(`${req.method} ${req.url}\n${body}`);
      const text = body.includes("quarantined content classifier") ? "substantive" : "tls-summary";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "qwen", choices: [{ message: { role: "assistant", content: text } }] }));
    });
  });
  server.on("tlsClientError", () => { /* a refused handshake: expected in the refusal legs */ });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `https://127.0.0.1:${(server.address() as AddressInfo).port}/v1`,
    bodies,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

async function run(endpoint: ModelEndpoint, env: Record<string, string | undefined> = {}) {
  const arbiter = new MockArbiter().seed(LOCAL, NOTES).declareEndpoints([endpoint]);
  const def = new MockUllm({ reply: "the default must not run" });
  const deps: InspectSymbolDeps = {
    arbiter, ullm: def, sessionId: "tls-12", now: () => new Date("2026-09-28T00:00:00Z"), genId: () => "evt-1",
    endpointUllm: createEndpointUllmFactory({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "5000", ...env }),
  };
  const res = await inspectSymbol(deps, { symbol: LOCAL, instruction: "Summarize." });
  return { res, def, arbiter };
}

const entry = (url: string, tls: ModelEndpoint["tls"]): ModelEndpoint => ({ name: "corp", url, wire: "openai-chat", model: "qwen", local: true, ...(tls ? { tls } : {}) });

test("the CA: unknown to the default store → refused, zero requests; tls.ca_file → served", { skip }, async () => {
  const w = await httpsModel();
  try {
    const bare = await run(entry(w.url, undefined));
    assert.equal(bare.res.ok, false);
    assert.equal(w.bodies.length, 0, "no request reached the server");
    assert.equal(bare.def.calls.length, 0);

    const ok = await run(entry(w.url, { caFile: fx!.caCert }));
    assert.equal(ok.res.ok, true, (ok.res as { error?: string }).error);
    assert.ok(w.bodies.some((b) => b.includes("TLS-CANARY")), "the document reached the declared model");
  } finally { await w.close(); }
});

test("pins: an unrelated key → refused before the request, the error says why; the server's or its CA's pin → served", { skip }, async () => {
  const w = await httpsModel();
  try {
    const wrong = await run(entry(w.url, { caFile: fx!.caCert, pinSha256: [fx!.otherPin] }));
    assert.equal(wrong.res.ok, false);
    assert.equal(w.bodies.length, 0, "zero requests on a pin mismatch");
    if (!wrong.res.ok) assert.ok(!wrong.res.error.includes("TLS-CANARY"));
    for (const pin of [fx!.serverPin, fx!.caPin]) {
      const ok = await run(entry(w.url, { caFile: fx!.caCert, pinSha256: [fx!.otherPin, pin] }));
      assert.equal(ok.res.ok, true, (ok.res as { error?: string }).error);
    }
  } finally { await w.close(); }
});

test("mutual TLS: without client_cert → refused, zero requests; with it (key bytes from the launcher) → served; masked key bytes → refused before connecting", { skip }, async () => {
  const w = await httpsModel({ mtls: true });
  try {
    const none = await run(entry(w.url, { caFile: fx!.caCert }));
    assert.equal(none.res.ok, false);
    assert.equal(w.bodies.length, 0, "the server's application saw nothing");

    const tls = { caFile: fx!.caCert, clientCert: fx!.clientCert, clientKey: "/masked/in/this/world.key" };
    const ok = await run(entry(w.url, tls), { MANDU_MODEL_CLIENT_KEYS: JSON.stringify({ corp: fx!.clientKeyPem }) });
    assert.equal(ok.res.ok, true, (ok.res as { error?: string }).error);
    assert.equal(w.bodies.filter((b) => b.includes("TLS-CANARY")).length, 1);

    const masked = await run(entry(w.url, tls), { MANDU_MODEL_CLIENT_KEYS: JSON.stringify({ corp: "$MDU:nomodel_secret[1a2b]\n" }) });
    assert.equal(masked.res.ok, false);
    if (!masked.res.ok) assert.match(masked.res.error, /client_key: the key's bytes are not a PEM private key here/);
    assert.equal(w.bodies.filter((b) => b.includes("TLS-CANARY")).length, 1, "no second request");
  } finally { await w.close(); }
});

test("tls on a plain http url is refused before any resolve (a belt for an arbiter older than the load rule)", { skip }, async () => {
  const r = await run(entry("http://127.0.0.1:9/v1", { caFile: fx!.caCert }));
  assert.equal(r.res.ok, false);
  if (!r.res.ok) assert.match(r.res.error, /tls settings but a plain http url/);
  assert.deepEqual(r.arbiter.resolveRequests, [], "nothing was resolved");
});

test("perimeter: a literal address outside → refused, zero requests; a name whose answer is outside → refused, zero requests; inside (by literal and by name) → served", { skip }, async () => {
  const w = await httpsModel();
  try {
    const port = new URL(w.url).port;
    const tls = { caFile: fx!.caCert };
    const outLit = await run({ ...entry(w.url, tls), perimeter: ["10.0.0.0/8"] });
    assert.equal(outLit.res.ok, false);
    if (!outLit.res.ok) assert.match(outLit.res.error, /127\.0\.0\.1 is outside perimeter\.networks/);
    // `localhost` resolves (hosts file) to loopback only, outside 10.0.0.0/8.
    const outName = await run({ ...entry(`https://localhost:${port}/v1`, tls), perimeter: ["10.0.0.0/8"] });
    assert.equal(outName.res.ok, false);
    if (!outName.res.ok) assert.match(outName.res.error, /localhost resolves to (127\.0\.0\.1|::1), outside perimeter\.networks/);
    assert.equal(w.bodies.length, 0, "no request reached the server");
    assert.equal(outLit.def.calls.length + outName.def.calls.length, 0, "the default helper never ran");

    const inLit = await run({ ...entry(w.url, tls), perimeter: ["127.0.0.0/8"] });
    assert.equal(inLit.res.ok, true, (inLit.res as { error?: string }).error);
    const inName = await run({ ...entry(`https://localhost:${port}/v1`, tls), perimeter: ["127.0.0.0/8", "::1/128"] });
    assert.equal(inName.res.ok, true, (inName.res as { error?: string }).error);
    assert.equal(w.bodies.filter((b) => b.includes("TLS-CANARY")).length, 2);
  } finally { await w.close(); }
});
