/**
 * stdio-server fixture: the inspect_symbol MCP server over stdio with the
 * PRODUCTION U-LLM wiring (the default AnthropicUllmClient and the production
 * declared-endpoint factory `createEndpointUllmFactory(process.env)`), and the
 * in-memory MockArbiter standing in for the arbiter daemon. The real-arbiter
 * version of this wiring is the integration parity e2e
 * (tests/stack/cleared-endpoint-parity.test.ts).
 *
 * Env (set by the e2e):
 *   E2E_DEFAULT_URL    : the external mock (served as the default U-LLM, pinned
 *                        as the forwarder so the loopback guard admits it)
 *   E2E_ENDPOINTS      : JSON ModelEndpoint[] the mock arbiter declares
 *   E2E_SEED           : JSON { [symbol]: value }
 *   E2E_EVENTS         : file the emitted events are appended to (NDJSON)
 */
import { appendFileSync } from "node:fs";
import { runStdioServer } from "../../../src/mcp-server.js";
import { AnthropicUllmClient } from "../../../src/ullm-client.js";
import { createEndpointUllmFactory } from "../../../src/ullm-config.js";
import type { ManduEvent } from "../../../src/event-model.js";
import type { SymbolizeArgs } from "../../../src/arbiter-client.js";
import { MockArbiter } from "../../helpers/mock-arbiter.js";

class FixtureArbiter extends MockArbiter {
  async emit(event: ManduEvent): Promise<{ seq: number }> {
    const r = await super.emit(event);
    appendFileSync(process.env.E2E_EVENTS!, JSON.stringify(event) + "\n");
    return r;
  }
  async symbolizeDerived(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
    return this.symbolize(args);
  }
}

const arbiter = new FixtureArbiter().declareEndpoints(JSON.parse(process.env.E2E_ENDPOINTS ?? "[]"));
for (const [sym, value] of Object.entries(JSON.parse(process.env.E2E_SEED ?? "{}") as Record<string, string>)) {
  arbiter.seed(sym, value);
}

const defaultUrl = process.env.E2E_DEFAULT_URL!;
process.env.MANDU_ULLM_FORWARDER = defaultUrl;

runStdioServer({
  arbiter,
  ullm: new AnthropicUllmClient({ apiKey: "sk-test", baseUrl: defaultUrl, forwarderUrl: defaultUrl }),
  sessionId: "e2e",
  triageCache: new Map(),
  endpointUllm: createEndpointUllmFactory(process.env),
});
