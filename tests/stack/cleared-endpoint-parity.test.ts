/**
 * cleared-endpoint-parity.test.ts — plan 11's invariant on real wires, with
 * the PRODUCTION wiring of inspect-mcp's adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(sock))`, no test bridge) and the
 * production endpoint factory (`createEndpointUllmFactory`), over a real
 * ArbiterServer (docs/design/confidentiality/model-endpoints.md §1
 * §4, D4 "What the arbiter can and cannot verify").
 *
 * Three model servers listen on loopback: `own` (declared `local: true`, an
 * OpenAI-chat server as Ollama speaks), `gateway` (declared, NOT local, an
 * Anthropic Messages server), and the default helper (a recording client).
 * A local-model document's bytes must appear on `own`'s wire and on no other;
 * the helper's answer must come back as `$MDU:localmodel_`; an any-model
 * document still goes to the default helper; and the arbiter itself refuses a
 * local-model read named for `gateway`, so a caller that named the wrong
 * endpoint gets nothing.
 *
 * Parity rule (CONTRIBUTING.md): the mock arbiter proves the package, only this
 * proves the wiring. A forwarding gap in the adapter (the `modelEndpoints` op
 * or the `endpoint` field on resolve) fails here and nowhere else.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
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
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

const CONTRACT = "Board minutes: acquire Initech for 18M. PARITY_LOCAL_CANARY";
const MEMO = "Release notes draft. PARITY_ANY_CANARY";
const SUMMARY = "An 18M acquisition. PARITY_SUMMARY_CANARY";

interface Wire { url: string; bodies: string[]; close: () => Promise<void> }

async function modelServer(kind: "openai" | "anthropic"): Promise<Wire> {
  const bodies: string[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(`${req.method} ${req.url}\n${body}`);
      const text = body.includes("quarantined content classifier") ? "substantive" : SUMMARY;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(kind === "openai"
        ? { model: "llama3.2", choices: [{ message: { role: "assistant", content: text } }] }
        : { model: "gw", content: [{ type: "text", text }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    bodies,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

test("production wiring: local-model bytes reach only the declared local model; any-model goes to the default helper; the arbiter refuses a non-local endpoint", async () => {
  const own = await modelServer("openai");
  const gateway = await modelServer("anthropic");
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cleared-parity-"));
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      models: [
        { name: "own", url: own.url, wire: "openai-chat", model: "llama3.2", local: true },
        { name: "gateway", url: gateway.url, wire: "anthropic" },
      ],
      paths: [
        { path: "/h/notes/minutes.md", level: "local-model" },
        { path: "/h/notes/memo.md", level: "any-model" },
      ],
    },
  });
  await arbiter.listen();
  const minter = new ArbiterClient(sock);
  await minter.connect();
  // THE production wiring: the adapter over the real client, nothing between.
  const inspectClient = new ArbiterClient(sock);
  await inspectClient.connect();
  const adapter = new InspectArbiterAdapter(inspectClient);
  const outside = new MockUllm({ reply: SUMMARY, model: "claude-haiku-mock" });
  const deps = { arbiter: adapter, ullm: outside, sessionId: "parity-11", endpointUllm: createEndpointUllmFactory({}) };
  try {
    const minutes = await minter.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: "/h/notes/minutes.md" });
    assert.match(minutes.symbol, /^\$MDU:localmodel_Read\[/);

    const out = await inspectSymbol(deps, { symbol: minutes.symbol, instruction: "Summarize." });
    assert.equal(out.ok, true, `routed to the declared local model (${(out as { error?: string }).error ?? ""})`);
    if (!out.ok) return;
    assert.match(out.resultSymbol, /^\$MDU:localmodel_/, "the answer inherits local-model");
    assert.ok(own.bodies.some((b) => b.includes("PARITY_LOCAL_CANARY")), "the local model's wire carries the document");
    assert.ok(own.bodies.every((b) => b.startsWith("POST /v1/chat/completions")), "on the OpenAI-chat path");
    assert.equal(gateway.bodies.length, 0, "the declared non-local endpoint received nothing");
    assert.equal(outside.calls.length, 0, "the default helper received nothing");

    // The arbiter's own check, independent of inspect-mcp's routing: a
    // local-model read named for the non-local endpoint resolves to nothing.
    const real = new ArbiterClient(sock);
    await real.connect();
    assert.equal(await real.resolve(minutes.symbol, { deep: true, endpoint: "gateway" }), null);
    assert.equal(await real.resolve(minutes.symbol, { deep: true, endpoint: "own" }), CONTRACT);
    real.close();

    // An any-model document is unchanged: the default helper, no endpoint.
    const memo = await minter.symbolizeFull({ tool: "Read", value: MEMO, field: "content", origin: "/h/notes/memo.md" });
    const before = own.bodies.length;
    const out2 = await inspectSymbol(deps, { symbol: memo.symbol, instruction: "Summarize." });
    assert.equal(out2.ok, true);
    assert.ok(outside.calls.some((c) => c.user.includes("PARITY_ANY_CANARY")), "any-model goes to the default helper");
    assert.equal(own.bodies.length, before, "and not to the local model");
    assert.ok(own.bodies.concat(gateway.bodies).every((b) => !b.includes("PARITY_ANY_CANARY")));
  } finally {
    inspectClient.close();
    minter.close();
    await arbiter.close();
    await own.close();
    await gateway.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
