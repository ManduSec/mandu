/**
 * register tests — the synchronous registrar against a FAKE OpenClaw api.
 *
 * Mandu (interceptors/openclaw-inspect-plugin). No OpenClaw installed, no
 * network, no arbiter daemon. The load-bearing assertions:
 *
 *   - registration is SYNCHRONOUS and NON-optional (the loader ignores async
 *     registration; an optional tool is silently allowlist-filtered).
 *   - misconfiguration FAILS LOUDLY at register time (missing arbiter sock,
 *     no U-LLM transport, loopback-proxy base URL).
 *   - the arbiter connection is LAZY (never dialed at register), refusals are
 *     fail-closed and not trusted-shaped, and a failed connect is retried on
 *     the next call rather than bricking the tool.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { registerInspectPlugin, type RegisterOptions } from "../../src/register.js";
import type {
  OpenClawPluginApiLike,
  PluginAgentTool,
  PluginToolFactory,
  PluginToolOptions,
} from "../../src/openclaw-api.js";
import { MockArbiter } from "../../../inspect-mcp/test/helpers/mock-arbiter.js";
import { MockUllm } from "../../../inspect-mcp/test/helpers/mock-ullm.js";
import {
  SYMBOL_ONLY_RE,
  isPureSymbolicInspectResult,
  flattenLikeProxy,
} from "../helpers/trusted-shape.js";

const SOCK = "/tmp/mandu-test/arbiter.sock";
const SYM = "$MDU:web_fetch[a1b2]";
const RAW = "raw untrusted page";

interface Registered {
  tool: PluginAgentTool | PluginToolFactory;
  opts: PluginToolOptions | undefined;
}

function makeFakeApi(pluginConfig?: Record<string, unknown>): {
  api: OpenClawPluginApiLike;
  registered: Registered[];
  logs: string[];
} {
  const registered: Registered[] = [];
  const logs: string[] = [];
  const api: OpenClawPluginApiLike = {
    id: "mandu-inspect",
    pluginConfig,
    logger: {
      info: (m) => logs.push(`info:${m}`),
      warn: (m) => logs.push(`warn:${m}`),
      error: (m) => logs.push(`error:${m}`),
    },
    registerTool: (tool, opts) => registered.push({ tool, opts }),
  };
  return { api, registered, logs };
}

/** Baseline options: cli transport reported available, injected mocks. */
function baseOpts(arbiter: MockArbiter, ullm: MockUllm, over: Partial<RegisterOptions> = {}): RegisterOptions {
  return {
    env: {},
    cliAvailable: () => true,
    connectArbiter: async () => arbiter,
    buildUllm: () => ullm,
    ...over,
  };
}

const CFG = { arbiterSock: SOCK, ullmMode: "cli", ullmBinary: "claude" };

/** Resolve the registered factory into the tool object. */
function resolveTool(registered: Registered[], ctx: Record<string, unknown> = {}, name = "inspect_symbol"): PluginAgentTool {
  assert.equal(registered.length, 2, "two registerTool calls expected: inspect_symbol, declassify_symbol");
  const entry = registered[name === "inspect_symbol" ? 0 : 1]!;
  assert.equal(typeof entry.tool, "function", "registered as a factory");
  const tool = (entry.tool as PluginToolFactory)(ctx);
  assert.ok(tool && !Array.isArray(tool));
  return tool as PluginAgentTool;
}

// ── Registration contract ────────────────────────────────────────────────────

test("registers two NON-optional factories (inspect_symbol, declassify_symbol), synchronously", () => {
  const { api, registered } = makeFakeApi(CFG);
  const ret = registerInspectPlugin(
    api,
    baseOpts(new MockArbiter(), new MockUllm()),
  ) as unknown;
  // Synchronous: no promise comes back (the loader would ignore one).
  assert.equal(ret, undefined);
  assert.equal(registered.length, 2);
  // NON-optional: no options at all — never `optional: true` (the allowlist
  // filter would silently drop the tool under a tools.profile config).
  assert.equal(registered[0]!.opts, undefined);
  assert.equal(registered[1]!.opts, undefined);
  assert.equal(resolveTool(registered, {}, "declassify_symbol").name, "declassify_symbol");
});

test("the factory yields the inspect_symbol tool with the reused schema", () => {
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(api, baseOpts(new MockArbiter(), new MockUllm()));
  const tool = resolveTool(registered);
  assert.equal(tool.name, "inspect_symbol");
  assert.equal(tool.label, "Inspect Symbol");
  assert.ok(tool.description.includes("$MDU:"));
  assert.deepEqual([...(tool.parameters.required ?? [])], ["instruction"]);
});

test("both tools are direct-only: OpenClaw 2026.9.x's Tool Search must not catalog them away from their bare names", () => {
  // Cataloged, a call by name fails "Tool inspect_symbol not found" on
  // 2026.9.6 / 2026.9.9 (agent-e2e-harness.md §8.6).
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(api, baseOpts(new MockArbiter(), new MockUllm()));
  assert.equal(resolveTool(registered).catalogMode, "direct-only");
  assert.equal(resolveTool(registered, {}, "declassify_symbol").catalogMode, "direct-only");
});

test("end-to-end through the registrar: success is pure-symbolic", async () => {
  const arbiter = new MockArbiter().seed(SYM, RAW);
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(api, baseOpts(arbiter, new MockUllm({ reply: "derived" })));
  const tool = resolveTool(registered);
  const res = await tool.execute("c1", { symbol: SYM, instruction: "summarize" });
  assert.match(res.content[0]!.text, SYMBOL_ONLY_RE);
  assert.equal(isPureSymbolicInspectResult(flattenLikeProxy(res)), true);
});

// ── Fail-loud misconfiguration at register time ──────────────────────────────

test("FAIL LOUD: no arbiter socket anywhere → register throws", () => {
  const { api } = makeFakeApi({});
  assert.throws(
    () => registerInspectPlugin(api, baseOpts(new MockArbiter(), new MockUllm())),
    /MANDU_ARBITER_SOCK/,
  );
});

test("FAIL LOUD: no U-LLM transport (no key, no CLI) → register throws", () => {
  const { api } = makeFakeApi({ arbiterSock: SOCK });
  assert.throws(
    () =>
      registerInspectPlugin(
        api,
        baseOpts(new MockArbiter(), new MockUllm(), { cliAvailable: () => false }),
      ),
    /fail closed/,
  );
});

test("FAIL CLOSED: a loopback (instrumented-proxy) U-LLM base URL → register throws", () => {
  const { api } = makeFakeApi({ ...CFG, ullmBaseUrl: "http://127.0.0.1:8788" });
  assert.throws(
    () => registerInspectPlugin(api, baseOpts(new MockArbiter(), new MockUllm())),
    /loopback/,
  );
});

test("the ONE sanctioned loopback: the pinned forwarder base URL is accepted", () => {
  const { api, registered } = makeFakeApi({
    ...CFG,
    ullmBaseUrl: "http://127.0.0.1:9317",
    ullmForwarder: "http://127.0.0.1:9317",
  });
  registerInspectPlugin(api, baseOpts(new MockArbiter(), new MockUllm()));
  assert.equal(registered.length, 2);
});

// ── Lazy arbiter connection ──────────────────────────────────────────────────

test("the arbiter is NOT dialed at register time (lazy first-use)", () => {
  let dials = 0;
  const { api } = makeFakeApi(CFG);
  registerInspectPlugin(
    api,
    baseOpts(new MockArbiter(), new MockUllm(), {
      connectArbiter: async () => {
        dials += 1;
        return new MockArbiter();
      },
    }),
  );
  assert.equal(dials, 0);
});

test("connect failure → fail-closed refusal; the NEXT call retries and succeeds", async () => {
  const arbiter = new MockArbiter().seed(SYM, RAW);
  let dials = 0;
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(
    api,
    baseOpts(arbiter, new MockUllm({ reply: "derived" }), {
      connectArbiter: async () => {
        dials += 1;
        if (dials === 1) throw new Error("ECONNREFUSED");
        return arbiter;
      },
    }),
  );
  const tool = resolveTool(registered);

  const first = await tool.execute("c1", { symbol: SYM, instruction: "summarize" });
  assert.match(first.content[0]!.text, /arbiter unavailable, refusing/);
  assert.equal(isPureSymbolicInspectResult(flattenLikeProxy(first)), false);

  const second = await tool.execute("c2", { symbol: SYM, instruction: "summarize" });
  assert.equal(isPureSymbolicInspectResult(flattenLikeProxy(second)), true);
  assert.equal(dials, 2);
});

test("a healthy connection is memoized — one dial across many calls", async () => {
  const arbiter = new MockArbiter().seed(SYM, RAW);
  let dials = 0;
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(
    api,
    baseOpts(arbiter, new MockUllm({ reply: "derived" }), {
      connectArbiter: async () => {
        dials += 1;
        return arbiter;
      },
    }),
  );
  const tool = resolveTool(registered);
  await tool.execute("c1", { symbol: SYM, instruction: "summarize" });
  await tool.execute("c2", { symbol: SYM, instruction: "extract" });
  assert.equal(dials, 1);
});

// ── Scope / session threading + the shared triage cache ──────────────────────

test("configured scopeId wins as the arbiter session key", async () => {
  const arbiter = new MockArbiter().seed(SYM, RAW);
  const { api, registered } = makeFakeApi({ ...CFG, scopeId: "scope-cfg" });
  registerInspectPlugin(api, baseOpts(arbiter, new MockUllm({ reply: "derived" })));
  const tool = resolveTool(registered, { sessionKey: "oc-session-1" });
  await tool.execute("c1", { symbol: SYM, instruction: "summarize" });
  assert.equal(arbiter.symbolizeCalls[0]!.sessionKey, "scope-cfg");
});

test("without a scopeId the OpenClaw sessionKey threads through", async () => {
  const arbiter = new MockArbiter().seed(SYM, RAW);
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(api, baseOpts(arbiter, new MockUllm({ reply: "derived" })));
  const tool = resolveTool(registered, { sessionKey: "oc-session-1" });
  await tool.execute("c1", { symbol: SYM, instruction: "summarize" });
  assert.equal(arbiter.symbolizeCalls[0]!.sessionKey, "oc-session-1");
});

test("ONE triage cache per registration: tools from different sessions share it", async () => {
  const arbiter = new MockArbiter().seed(SYM, RAW);
  const ullm = new MockUllm({ reply: "derived" });
  const { api, registered } = makeFakeApi(CFG);
  registerInspectPlugin(api, baseOpts(arbiter, ullm));
  const toolA = resolveTool(registered, { sessionKey: "session-a" });
  const toolB = (registered[0]!.tool as PluginToolFactory)({ sessionKey: "session-b" }) as PluginAgentTool;
  await toolA.execute("c1", { symbol: SYM, instruction: "summarize" });
  await toolB.execute("c2", { symbol: SYM, instruction: "extract" });
  assert.equal(ullm.mainCalls.length, 2);
  assert.equal(ullm.triageCalls.length, 1);
});
