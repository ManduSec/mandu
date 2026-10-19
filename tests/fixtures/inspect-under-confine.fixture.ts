/**
 * inspect-under-confine.fixture — one `inspect_symbol` call in its own
 * process, so the endpoint-added-mid-session e2e can run it under the
 * launcher's inspect-mcp network confine (a process-wide Landlock ruleset)
 * without confining the test runner.
 *
 * Production wiring: inspect-mcp's adapter over the real arbiter client and
 * the production endpoint factory. The default U-LLM is a recording client;
 * its call count is reported so the parent can assert nothing fell back to it.
 *
 * Input:  MANDU_ARBITER_SOCK, INSPECT_SYMBOL (env).
 * Output: one JSON line on stdout: {ok, error?, resultSymbol?, defaultCalls}.
 *
 * Mandu (tests/). NEW code, no reference origin. Named
 * *.fixture.ts so the `stack/*.test.ts` glob never picks it up.
 */
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";

const sock = process.env["MANDU_ARBITER_SOCK"];
const symbol = process.env["INSPECT_SYMBOL"];
if (!sock || !symbol) {
  process.stderr.write("inspect-under-confine: MANDU_ARBITER_SOCK and INSPECT_SYMBOL are required\n");
  process.exit(2);
}

const client = new ArbiterClient(sock);
await client.connect();
const outside = new MockUllm({ reply: "default helper answer", model: "claude-haiku-mock" });
try {
  const out = await inspectSymbol(
    { arbiter: new ArbiterClientAdapter(client), ullm: outside, sessionId: "late-endpoint", endpointUllm: createEndpointUllmFactory({}) },
    { symbol, instruction: "Summarize." },
  );
  process.stdout.write(JSON.stringify({
    ok: out.ok,
    ...(out.ok ? { resultSymbol: out.resultSymbol } : { error: out.error }),
    defaultCalls: outside.calls.length,
  }) + "\n");
} finally {
  client.close();
}
