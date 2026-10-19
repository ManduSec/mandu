/**
 * plain-http-local-endpoint.test.ts — plan 12 D2 on real wires
 * (docs/design/confidentiality/model-endpoints.md §2).
 *
 * A `local: true` model on another machine receives local-model files, so
 * plain http would carry them across the network in the clear. The rule: a
 * policy file with such an entry is refused at load unless the entry says
 * `allow_plain_http: true`; the helper refuses such an entry per call before
 * any resolve unless the arbiter's wire list carries `allowPlainHttp`.
 *
 * The stand-in model listens on one of THIS machine's non-loopback addresses
 * (a docker bridge, the LAN address), so its URL has `network` placement
 * while the test needs no second machine (self-SKIP when the host has no
 * such address). Wiring is PRODUCTION: a real ArbiterServer, inspect-mcp's
 * adapter over the real client (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`) and the production endpoint factory.
 *
 * Legs:
 *   1. file-backed arbiter, entry with the opt-out: `allowPlainHttp` rides
 *      the modelEndpoints op, the document reaches that wire only, and the
 *      answer comes back as `$MDU:localmodel_`;
 *   2. a hot edit that drops the opt-out is refused at reload: the file on
 *      disk reports the plain-http problem (the law in force is kept, as for
 *      every refused reload);
 *   3. an arbiter that serves the entry WITHOUT the opt-out (an in-memory
 *      document, the shape an arbiter older than the rule serves): the
 *      helper refuses, and zero bytes reach the wire.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { networkInterfaces } from "node:os";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
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

const CONTRACT = "Board minutes: acquire Initech for 18M. PLAIN_HTTP_CANARY";
const SUMMARY = "An 18M acquisition. PLAIN_HTTP_SUMMARY";

/** One non-loopback IPv4 address of this machine, or null. */
function networkAddress(): string | null {
  for (const ifs of Object.values(networkInterfaces())) {
    for (const i of ifs ?? []) if (!i.internal && i.family === "IPv4") return i.address;
  }
  return null;
}

interface Wire { url: string; bodies: string[]; close: () => Promise<void> }

async function openAiChatServer(host: string): Promise<Wire> {
  const bodies: string[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(`${req.method} ${req.url}\n${body}`);
      const text = body.includes("quarantined content classifier") ? "substantive" : SUMMARY;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "qwen", choices: [{ message: { role: "assistant", content: text } }] }));
    });
  });
  await new Promise<void>((r, j) => { server.once("error", j); server.listen(0, host, r); });
  return {
    url: `http://${host}:${(server.address() as AddressInfo).port}`,
    bodies,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

const law = (url: string, optOut: boolean): string =>
  "version: 1\n" +
  "models:\n" +
  `  - name: lab\n    url: ${url}\n    wire: openai-chat\n    model: qwen\n    local: true\n` +
  (optOut ? "    allow_plain_http: true\n" : "") +
  "paths:\n  - path: /h/notes/minutes.md\n    level: local-model\n";

async function waitFor(pred: () => Promise<boolean>, ms: number, what: string): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await pred())) {
    if (Date.now() > deadline) assert.fail(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

const HOST = networkAddress();

test("plan 12 D2: the opt-out reaches the helper through the production wiring; dropping it is refused at reload", { skip: HOST === null ? "no non-loopback IPv4 address on this host" : false }, async () => {
  const lab = await openAiChatServer(HOST!);
  const tmp = mkdtempSync(join(tmpdir(), "mandu-plain-http-"));
  const file = join(tmp, "policy.yaml");
  writeFileSync(file, law(lab.url, true));
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
    policyPath: file, policyPollMs: 40,
  });
  await arbiter.listen();
  const minter = new ArbiterClient(sock);
  await minter.connect();
  const inspectClient = new ArbiterClient(sock);
  await inspectClient.connect();
  const adapter = new InspectArbiterAdapter(inspectClient);
  const outside = new MockUllm({ reply: "the default must not run", model: "claude-haiku-mock" });
  const deps = { arbiter: adapter, ullm: outside, sessionId: "plain-http-12", endpointUllm: createEndpointUllmFactory({}) };
  try {
    // 1. The opt-out on the wire, and the bytes on the named wire only.
    const listed = await adapter.modelEndpoints();
    assert.deepEqual(listed.map((e) => [e.name, e.local, e.allowPlainHttp ?? false]), [["lab", true, true]]);
    const minutes = await minter.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: "/h/notes/minutes.md" });
    assert.match(minutes.symbol, /^\$MDU:localmodel_Read\[/);
    const out = await inspectSymbol(deps, { symbol: minutes.symbol, instruction: "Summarize." });
    assert.equal(out.ok, true, `routed to the declared model (${(out as { error?: string }).error ?? ""})`);
    if (!out.ok) return;
    assert.match(out.resultSymbol, /^\$MDU:localmodel_/, "the answer inherits local-model");
    assert.ok(!JSON.stringify(out).includes("PLAIN_HTTP_CANARY"), "no raw byte back to the caller");
    assert.ok(lab.bodies.some((b) => b.includes("PLAIN_HTTP_CANARY")), "the opted-in wire carries the document");
    assert.equal(outside.calls.length, 0, "the default helper received nothing");

    // 2. Dropping the opt-out: the reload is refused, and the file names why.
    writeFileSync(file, law(lab.url, false));
    const t = new Date(Date.now() + 5_000);
    utimesSync(file, t, t);
    const raw = arbiter["policyDocs"].readRaw() as { problems: string[] };
    assert.match(raw.problems.join("\n"), /models\[0\]\.url: 'lab' is on another machine and would receive local-model files in the clear/);
    await waitFor(async () => {
      const s = arbiter["policyDocs"].status;
      return !s.valid && s.problems.join("\n").includes("in the clear");
    }, 10_000, "the refused reload was never reported");
    assert.deepEqual((await adapter.modelEndpoints()).map((e) => e.allowPlainHttp ?? false), [true], "the law in force is kept");
  } finally {
    inspectClient.close();
    minter.close();
    await arbiter.close();
    await lab.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("plan 12 D2: an arbiter serving the entry without the opt-out: the helper refuses and zero bytes reach the wire", { skip: HOST === null ? "no non-loopback IPv4 address on this host" : false }, async () => {
  const lab = await openAiChatServer(HOST!);
  const tmp = mkdtempSync(join(tmpdir(), "mandu-plain-http-old-"));
  const sock = join(tmp, "arbiter.sock");
  // An in-memory document is not validated: the shape an arbiter older than
  // the load rule serves.
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      models: [{ name: "lab", url: lab.url, wire: "openai-chat", model: "qwen", local: true }],
      paths: [{ path: "/h/notes/minutes.md", level: "local-model" }],
    },
  });
  await arbiter.listen();
  const minter = new ArbiterClient(sock);
  await minter.connect();
  const inspectClient = new ArbiterClient(sock);
  await inspectClient.connect();
  const adapter = new InspectArbiterAdapter(inspectClient);
  const outside = new MockUllm({ reply: "the default must not run", model: "claude-haiku-mock" });
  const deps = { arbiter: adapter, ullm: outside, sessionId: "plain-http-12-old", endpointUllm: createEndpointUllmFactory({}) };
  try {
    const minutes = await minter.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: "/h/notes/minutes.md" });
    const out = await inspectSymbol(deps, { symbol: minutes.symbol, instruction: "Summarize." });
    assert.equal(out.ok, false);
    if (!out.ok) {
      assert.match(out.error, /your declared model 'lab' is unusable: .*plain http on another machine/);
      assert.ok(!out.error.includes("PLAIN_HTTP_CANARY"));
    }
    assert.deepEqual(lab.bodies, [], "zero bytes reached the wire");
    assert.equal(outside.calls.length, 0, "the call never moved to another model");
  } finally {
    inspectClient.close();
    minter.close();
    await arbiter.close();
    await lab.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
