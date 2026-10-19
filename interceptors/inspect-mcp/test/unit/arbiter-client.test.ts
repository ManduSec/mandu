/**
 * arbiter-client unit tests — the ArbiterClientAdapter over the real-IPC seam.
 *
 * Mandu M4 (interceptors/inspect-mcp). The adapter is thin, but its ONE
 * substantive decision is load-bearing for utility: `resolve` must request a
 * DEEP (fixpoint) resolution from the arbiter, because under the dual view a
 * symbol's value can itself be a symbol (the fs-sync AgentView twin Read →
 * proxy re-symbolization stack). A shallow resolve hands the quarantined
 * U-LLM a literal `$MDU:*` placeholder — every "summarize this file"
 * then degrades to describing the token (the 2026-07 claude-e2e
 * trusted-and-untrusted symptom).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ArbiterClientAdapter, type RealArbiterClient, type SymbolizeArgs } from "../../src/arbiter-client.js";
import { inspectSymbol } from "../../src/inspect-symbol.js";
import { MockUllm } from "../helpers/mock-ullm.js";

/** Recording fake of the real arbiter IPC client seam. */
class FakeRealClient implements RealArbiterClient {
  resolveCalls: Array<{ symbol: string; opts?: { deep?: boolean; endpoint?: string } }> = [];
  symbolizeCalls: SymbolizeArgs[] = [];
  async connect(): Promise<void> {}
  async resolve(symbol: string, opts?: { deep?: boolean; endpoint?: string }): Promise<string | null> {
    this.resolveCalls.push({ symbol, ...(opts ? { opts } : {}) });
    return "raw value";
  }
  async symbolize(args: SymbolizeArgs): Promise<string> {
    this.symbolizeCalls.push(args);
    return "$MDU:inspect[abcd]";
  }
  async emit(_event: unknown): Promise<number> {
    return 1;
  }
  close(): void {}
}

test("adapter resolve requests DEEP resolution (quarantine sees raw content, never a nested placeholder)", async () => {
  const fake = new FakeRealClient();
  const adapter = new ArbiterClientAdapter(fake);

  assert.equal(await adapter.resolve("$MDU:Read[9b0a]"), "raw value");
  assert.deepEqual(fake.resolveCalls, [
    { symbol: "$MDU:Read[9b0a]", opts: { deep: true } },
  ]);
});


test("single-input inspection through the real adapter requests server-side source inheritance", async () => {
  const calls: Array<SymbolizeArgs & { sourceSymbols: string[] }> = [];
  class DerivedClient extends FakeRealClient {
    async symbolizeDerived(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
      calls.push(args);
      return "$MDU:inspect[abcd]";
    }
  }
  const fake = new DerivedClient();
  const result = await inspectSymbol({ arbiter: new ArbiterClientAdapter(fake), ullm: new MockUllm({ reply: "PRIVATE_DERIVED_MARKER" }) }, {
    symbol: "$MDU:Read[9b0a]", instruction: "derive the artifact",
  });
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].sourceSymbols, ["$MDU:Read[9b0a]"]);
  assert.equal(calls[0].value, "PRIVATE_DERIVED_MARKER");
  assert.equal(fake.symbolizeCalls.length, 0);
  assert.ok(!JSON.stringify(result).includes("PRIVATE_DERIVED_MARKER"));
});

test("single-input adapter version skew refuses without a legacy symbolization fallback", async () => {
  class OldServerClient extends FakeRealClient {
    async symbolizeDerived(_args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
      throw new Error("unknown op: symbolizeDerived");
    }
  }
  // The missing client method and an older daemon refusing the new operation
  // must both retain the source-inheritance boundary.
  for (const fake of [new FakeRealClient(), new OldServerClient()]) {
    const result = await inspectSymbol({ arbiter: new ArbiterClientAdapter(fake), ullm: new MockUllm({ reply: "PRIVATE_DERIVED_MARKER" }) }, {
      symbol: "$MDU:Read[9b0a]", instruction: "derive the artifact",
    });
    assert.equal(result.ok, false);
    if (result.ok) continue;
    assert.match(result.error, /re-symbolization failed, refusing/);
    assert.equal(fake.symbolizeCalls.length, 0);
    assert.ok(!JSON.stringify(result).includes("PRIVATE_DERIVED_MARKER"));
    assert.ok(!JSON.stringify(result).includes("raw value"));
  }
});


test("adapter resolve forwards a named endpoint (Plan 11 D4) and stays byte-for-byte {deep:true} without one", async () => {
  const fake = new FakeRealClient();
  const adapter = new ArbiterClientAdapter(fake);
  await adapter.resolve("$MDU:localmodel_Read[1]", { endpoint: "ollama" });
  await adapter.resolve("$MDU:Read[2]");
  await adapter.resolve("$MDU:Read[3]", {});
  assert.deepEqual(fake.resolveCalls, [
    { symbol: "$MDU:localmodel_Read[1]", opts: { deep: true, endpoint: "ollama" } },
    { symbol: "$MDU:Read[2]", opts: { deep: true } },
    { symbol: "$MDU:Read[3]", opts: { deep: true } },
  ]);
});

test("adapter modelEndpoints: forwarded when the client has the op, throws (fail closed) when it lacks it", async () => {
  const eps = [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat" as const, model: "llama3.2", local: true }];
  class WithEndpoints extends FakeRealClient {
    async modelEndpoints() { return eps; }
  }
  assert.deepEqual(await new ArbiterClientAdapter(new WithEndpoints()).modelEndpoints(), eps);
  await assert.rejects(new ArbiterClientAdapter(new FakeRealClient()).modelEndpoints(), /upgrade required/);
});
