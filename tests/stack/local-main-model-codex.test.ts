/**
 * e2e — plan 11 §7.2: Codex's declared local main model across the real
 * components, in PRODUCTION wiring. The launcher's own `bindSessionUpstream`
 * records each session's main model on a real ArbiterServer; the real
 * openai-proxy (`new ArbiterClientAdapter(new ArbiterClient(sock))`, as its
 * server-main builds it) forwards Codex's Responses request to a declared
 * `wire: openai-chat` model over a real HTTP socket, with the launcher's
 * settings for such a model (the entry's url is the base URL,
 * `upstreamIsBaseUrl`; it is `local: true`, `upstreamLocal`).
 *
 * What it pins:
 *   - ingress still masks for a LOCAL main model: the labeled document read
 *     through exec_command reaches it only as a symbol;
 *   - the handling prompt each Codex session receives says whether
 *     `declassify_symbol` opens the level (the proxy names the session);
 *   - Codex's `/v1/responses` reaches `<base>/responses` at the declared base;
 *   - a cloud-backed model name is refused before anything is sent;
 *   - with an EXTERNAL main model (the default vendor, or a declared
 *     `wire: openai-chat` entry that is not `local: true`) the document
 *     reaches the vendor only as `$MDU:localmodel_…` and rung 3 refuses it in
 *     that session; an undeclared MANDU_OPENAI_BASE_URL selects no entry, so
 *     the session binds the default vendor and stays external.
 * The Claude Code analogue is local-main-model.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { buildTextSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { bindSessionUpstream, readModelEndpoints, selectTllmEndpoint } from "../../launcher/src/model-endpoints.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const BODY = "Board minutes: the Acme deal closes at $4,200,000. CODEX_MAIN_MODEL_CANARY";
const CANARY = "CODEX_MAIN_MODEL_CANARY";

interface Captured { path: string; body: string }

/** An OpenAI-compatible server at base `/v1`: records every request, answers one text turn. */
async function modelServer(): Promise<{ origin: string; seen: Captured[]; connections: () => number; close: () => Promise<void> }> {
  const seen: Captured[] = [];
  let connections = 0;
  const srv: Server = createServer((req, res) => {
    let b = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push({ path: req.url ?? "", body: b });
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("ok"));
    });
  });
  srv.on("connection", () => { connections++; });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  return { origin, seen, connections: () => connections, close: () => new Promise<void>((r) => srv.close(() => r())) };
}

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** Codex read the labeled document through exec_command. */
function readTurn(path: string, model = "gpt-oss:20b"): string {
  return JSON.stringify({
    model,
    stream: true,
    instructions: "You are Codex.",
    tools: [{ type: "function", name: "exec_command" }, { type: "function", name: "mcp__mandu-inspect__inspect_symbol" }],
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Summarize the board minutes." }] },
      { type: "function_call", call_id: "call_mm1", name: "exec_command", arguments: JSON.stringify({ cmd: `cat ${path}` }) },
      { type: "function_call_output", call_id: "call_mm1", output: BODY },
    ],
  });
}

const instructionsOf = (body: string): string => String((JSON.parse(body) as { instructions?: unknown }).instructions ?? "");

test("Codex with a declared local main model: masked at ingress, the prompt names rung 3 per session, the base URL maps, a cloud model is refused", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-main-model-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  const minutes = join(home, "notes", "minutes.md");
  writeFileSync(minutes, BODY + "\n");
  const mine = await modelServer();
  const base = `${mine.origin}/v1`;
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
    policyDocument: {
      version: 1,
      models: [{ name: "mine", url: base, wire: "openai-chat", local: true }],
      paths: [{ path: minutes, level: "local-model" }],
    } as never,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const proxies: OpenAiProxy[] = [];
  try {
    // The launcher's own calls, before any service starts (run.ts).
    const bLocal = await bindSessionUpstream(socketPath, "cx-local", "mine");
    assert.equal(bLocal.status, "ok", JSON.stringify(bLocal));
    assert.equal(bLocal.location, "local");
    assert.equal((await bindSessionUpstream(socketPath, "cx-vendor", null)).location, "external");

    const proxyFor = async (sessionKey: string, local: boolean): Promise<number> => {
      const c = new ArbiterClient(socketPath);
      await c.connect();
      clients.push(c);
      const p = new OpenAiProxy({
        arbiter: new ProxyAdapter(c), upstreamOrigin: base, upstreamIsBaseUrl: true, upstreamLocal: local, sessionKey, log: () => {},
      });
      proxies.push(p);
      return p.listen(0);
    };

    const localPort = await proxyFor("cx-local", true);
    const r = await post(localPort, readTurn(minutes));
    assert.equal(r.status, 200, r.body);
    assert.equal(mine.seen.length, 1);
    assert.equal(mine.seen[0]!.path, "/v1/responses", "Codex's /v1 maps onto the declared base, not doubled");
    const localBody = mine.seen[0]!.body;
    assert.ok(!localBody.includes(CANARY), "ingress masks for a local main model too");
    assert.match(localBody, /\$MDU:[a-z]+_[A-Za-z_]+\[[0-9a-f]+\]/, "the document reached the model as a symbol");
    assert.match(instructionsOf(localBody), /`declassify_symbol` works for this level here/);

    const vendorPort = await proxyFor("cx-vendor", false);
    assert.equal((await post(vendorPort, readTurn(minutes))).status, 200);
    const vendorBody = mine.seen[1]!.body;
    assert.ok(!vendorBody.includes(CANARY));
    assert.match(instructionsOf(vendorBody), /`declassify_symbol` is refused\*\* for this level/);

    // A cloud-backed model at the local main model: nothing sent.
    const before = mine.connections();
    const cloud = await post(localPort, readTurn(minutes, "gpt-oss:120b-cloud"));
    assert.equal(cloud.status, 400, cloud.body);
    assert.equal(mine.seen.length, 2, "no request reached the model server");
    assert.equal(mine.connections(), before, "not even a connection");
  } finally {
    for (const p of proxies) await p.close();
    for (const c of clients) c.close();
    await arbiter.close();
    await mine.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("Codex with an EXTERNAL main model: the local-model file reaches the vendor only as $MDU:localmodel_ and rung 3 refuses it; an undeclared openai-chat URL stays external", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-external-main-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  const minutes = join(home, "notes", "minutes.md");
  writeFileSync(minutes, BODY + "\n");
  const vendor = await modelServer(); // the default vendor's wire (origin semantics)
  const gateway = await modelServer(); // a declared outside model (base-URL semantics)
  const gatewayBase = `${gateway.origin}/v1`;
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
    policyDocument: {
      version: 1,
      models: [{ name: "gateway", url: gatewayBase, wire: "openai-chat", local: false }],
      paths: [{ path: minutes, level: "local-model" }],
    } as never,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const proxies: OpenAiProxy[] = [];
  try {
    const c = new ArbiterClient(socketPath);
    await c.connect();
    clients.push(c);

    // The launcher's selection over the law the arbiter serves (run.ts).
    const read = await readModelEndpoints(socketPath);
    assert.equal(read.status, "ok");
    const undeclared = "http://127.0.0.1:18080/v1";
    assert.equal(selectTllmEndpoint(undeclared, read.endpoints, "openai"), null, "an undeclared URL selects no entry");
    const matched = selectTllmEndpoint(gatewayBase, read.endpoints, "openai");
    assert.equal(matched?.name, "gateway");
    assert.equal(matched?.local, false);

    // Bindings exactly as the launcher makes them: the default vendor and the
    // undeclared URL bind null, the declared outside model binds its name.
    assert.equal((await bindSessionUpstream(socketPath, "cx-default", null)).location, "external");
    assert.equal((await bindSessionUpstream(socketPath, "cx-undeclared", null)).location, "external");
    assert.equal((await bindSessionUpstream(socketPath, "cx-gateway", matched!.name)).location, "external");

    const assertLevelRefused = async (sessionKey: string): Promise<void> => {
      const trusted = await c.symbolizeFull({ tool: "Read", value: BODY, field: "content", origin: minutes, integrity: "trusted", sessionKey });
      assert.match(trusted.symbol, /^\$MDU:localmodel_/);
      const t = await c.declassifySymbol({ symbol: trusted.symbol, sessionKey });
      assert.equal(t.allowed, false, `${sessionKey}: rung 3 refuses a trusted local-model datum`);
      assert.equal(t.requiresApproval, false, `${sessionKey}: no approval opens it`);
      assert.equal(t.value ?? null, null);
      assert.match(t.reason, /local-model data is readable only by the user's own model/, sessionKey);
    };

    const proxyFor = async (sessionKey: string, upstreamOrigin: string, baseUrl: boolean): Promise<number> => {
      const pc = new ArbiterClient(socketPath);
      await pc.connect();
      clients.push(pc);
      const p = new OpenAiProxy({
        arbiter: new ProxyAdapter(pc), upstreamOrigin, upstreamIsBaseUrl: baseUrl, upstreamLocal: false, sessionKey, log: () => {},
      });
      proxies.push(p);
      return p.listen(0);
    };

    for (const [sessionKey, wire, port] of [
      ["cx-default", vendor, await proxyFor("cx-default", vendor.origin, false)],
      ["cx-gateway", gateway, await proxyFor("cx-gateway", gatewayBase, true)],
    ] as const) {
      const r = await post(port, readTurn(minutes));
      assert.equal(r.status, 200, `${sessionKey}: ${r.body}`);
      const seen = wire.seen.at(-1)!;
      assert.equal(seen.path, "/v1/responses", sessionKey);
      assert.ok(!seen.body.includes(CANARY), `${sessionKey}: the document never reaches the outside model`);
      // The tool result as it reached the model (the handling prompt quotes example tokens).
      const output = (JSON.parse(seen.body) as { input: Array<{ type: string; output?: unknown }> }).input
        .filter((i) => i.type === "function_call_output").map((i) => JSON.stringify(i.output)).join("\n");
      assert.ok(!output.includes(CANARY), sessionKey);
      const sym = /\$MDU:localmodel_[A-Za-z0-9_]+\[[0-9a-f]+\](?:\.[A-Za-z_][A-Za-z0-9_]*)*/.exec(output)?.[0];
      assert.ok(sym, `${sessionKey}: the document reached the model as $MDU:localmodel_ (${output.slice(0, 300)})`);
      assert.match(instructionsOf(seen.body), /`declassify_symbol` is refused\*\* for this level/, `${sessionKey}: the strict prompt`);
      const d = await c.declassifySymbol({ symbol: sym, sessionKey });
      assert.equal(d.allowed, false, `${sessionKey}: rung 3 refuses the ingress symbol`);
      assert.equal(d.value ?? null, null, `${sessionKey}: no bytes come back`);
      // The ingress symbol is untrusted, so integrity may answer first; a
      // TRUSTED copy isolates the level: refused because the main model is
      // outside, not because of where the bytes came from.
      await assertLevelRefused(sessionKey);
    }

    // The undeclared URL: the proxy is skipped in that shape (a WARNING at
    // launch, guarantees.md), so what stays is the binding: rung 3 refuses the
    // same datum there too.
    await assertLevelRefused("cx-undeclared");
    assert.equal(vendor.seen.length + gateway.seen.length, 2, "one request per proxied session, nothing else");
  } finally {
    for (const p of proxies) await p.close();
    for (const cl of clients) cl.close();
    await arbiter.close();
    await vendor.close();
    await gateway.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
