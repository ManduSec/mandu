/**
 * perimeter-scenario.fixture — the client side of the perimeter-netns e2e
 * (confidentiality plan 12 D4), run on "this machine" of tests/lib/netns.ts
 * while the model stand-in runs on the peer. Prints ONE JSON line: what each
 * leg saw. The test asserts on it and on the peer's request log.
 *
 * For each declared name (the hosts file gives each its answer):
 *   corp   → 10.77.0.2                 (inside perimeter.networks)
 *   drift  → 203.0.113.9               (outside)
 *   mixed  → 10.77.0.2 and 203.0.113.9 (one outside: every address counts)
 * a real ArbiterServer is started with that name as the only local model,
 * and three clients meet it, with the production wiring:
 *   - the launch check: `readModelEndpoints` + `assertLocalEndpoints` with the
 *     system resolver;
 *   - the helper: `new ArbiterClientAdapter(new ArbiterClient(sock))` +
 *     `createEndpointUllmFactory` + `inspectSymbol` on a local-model document;
 *   - the main model: an AnthropicProxy whose upstream is that name, with the
 *     perimeter the launcher hands it (MANDU_UPSTREAM_TLS → upstreamTlsFromEnv).
 *
 * env: FX_CA (the CA's PEM path), MODEL_LOG, MODEL_PORT, PERIMETER (CIDR);
 * for the live leg (tests/env/network-model.test.ts): LEGS (names, comma
 * separated), MODEL_NAME (the model to request), NO_PROXY_LEG=1 (a real
 * Ollama has no Anthropic Messages wire), ANSWER=1 (resolve the helper's
 * answer as the declared model may read it, to show a real model wrote it),
 * MANDU_ULLM_ENDPOINT_TIMEOUT_MS (a real model on a small GPU is slow).
 * PROVENANCE: NEW Mandu test code.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { upstreamTlsFromEnv } from "../../interceptors/anthropic-proxy/src/upstream-tls.js";
import { MockArbiter } from "../../interceptors/anthropic-proxy/test/helpers/mock-arbiter.js";
import { assertLocalEndpoints, readModelEndpoints } from "../../launcher/src/model-endpoints.js";

const CA = process.env["FX_CA"]!;
const LOG = process.env["MODEL_LOG"]!;
const PORT = process.env["MODEL_PORT"]!;
const PERIMETER = process.env["PERIMETER"]!;
const CANARY = (name: string): string => `NETNS_CANARY_${name.toUpperCase()}: the Q4 layoff list is Kim, Park, Lee.`;

const logLines = (): number => { try { return readFileSync(LOG, "utf8").split("\n").filter(Boolean).length; } catch { return 0; } };

function post(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(JSON.stringify({ model: "claude-opus-4", stream: true, messages: [{ role: "user", content: "hi" }] }));
  });
}

interface Leg {
  launch: string;
  helper: { ok: boolean; error?: string; resultSymbol?: string };
  helperRequests: number;
  proxyStatus: number;
  proxyRequests: number;
  endpoint: unknown;
  answer?: string | null;
}

async function leg(name: string): Promise<Leg> {
  const host = `${name}.corp.example`;
  const url = `https://${host}:${PORT}/v1`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-perimeter-"));
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      perimeter: { networks: [PERIMETER], domains: ["corp.example"] },
      models: [{ name, url, wire: "openai-chat", model: process.env["MODEL_NAME"] ?? "qwen", local: true, tls: { ca_file: CA } }],
      paths: [{ path: "/h/notes/minutes.md", level: "local-model" }],
    },
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const client = async (): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  try {
    // 1. The launch check, with the system resolver (the hosts file).
    const read = await readModelEndpoints(sock);
    let launch = "ok";
    try { await assertLocalEndpoints(read, [], { localAddresses: () => [] }); } catch (e) { launch = (e as Error).message; }

    // 2. The helper, production wiring.
    const minter = await client();
    const doc = await minter.symbolizeFull({ tool: "Read", value: CANARY(name), field: "content", origin: "/h/notes/minutes.md" });
    const adapter = new ArbiterClientAdapter(await client());
    const before = logLines();
    const out = await inspectSymbol(
      { arbiter: adapter, ullm: new MockUllm({ reply: "the default helper must not run" }), sessionId: `perimeter-${name}`, endpointUllm: createEndpointUllmFactory({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: process.env["MANDU_ULLM_ENDPOINT_TIMEOUT_MS"] ?? "8000" }) },
      { symbol: doc.symbol, instruction: "Summarize." },
    );
    const helperRequests = logLines() - before;

    // The answer, as the declared model may read it (the live leg).
    const answer = process.env["ANSWER"] === "1" && out.ok ? await minter.resolve(out.resultSymbol, { deep: true, endpoint: name }) : undefined;
    // 3. The main model through the proxy, with what the launcher hands it.
    const entry = read.endpoints.find((e) => e.name === name);
    if (process.env["NO_PROXY_LEG"] === "1") {
      return { launch, helper: out.ok ? { ok: true, resultSymbol: out.resultSymbol } : { ok: false, error: out.error }, helperRequests, proxyStatus: 0, proxyRequests: 0, endpoint: entry ?? null, ...(answer !== undefined ? { answer } : {}) };
    }
    const upstream = upstreamTlsFromEnv(JSON.stringify({ ...(entry?.tls ?? {}), ...(entry?.perimeter ? { perimeter: entry.perimeter } : {}) }));
    const proxy = new AnthropicProxy({ arbiter: new MockArbiter(), upstreamOrigin: `https://${host}:${PORT}`, log: () => {}, retry: { maxAttempts: 1 }, ...upstream });
    const port = await proxy.listen(0);
    const before2 = logLines();
    let proxyStatus = 0;
    try { proxyStatus = await post(port); } finally { await proxy.close(); }
    return {
      launch,
      helper: out.ok ? { ok: true, resultSymbol: out.resultSymbol } : { ok: false, error: out.error },
      helperRequests,
      proxyStatus,
      proxyRequests: logLines() - before2,
      endpoint: entry ?? null,
    };
  } finally {
    for (const c of clients) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

const result: Record<string, Leg> = {};
for (const name of (process.env["LEGS"] ?? "corp,drift,mixed").split(",")) result[name] = await leg(name);
process.stdout.write(JSON.stringify(result) + "\n");
process.exit(0);
