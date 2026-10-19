/**
 * harness — the Mandu conformance micro-runner + the real-component stack
 * builder.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE
 *   The runner (`test` / `testAsync` / `summary` / `header` + the ANSI palette)
 *   mirrors the ergonomics of
 *     DualView (adfi-openclaw) test/helpers.ts
 *   (`test(name, fn)` + a `summary()` that returns {passed, failed}, with the
 *   same ✓/✗ + bold-cyan section header style). The deterministic stack builder
 *   `buildStack(opts)` is the Mandu analog of adfi's `buildMockApi(opts)`: a
 *   single call that constructs a fully-wired, offline system under test and
 *   returns handles to drive + observe it.
 *
 *   Where adfi's `buildMockApi` registers the in-process plugin against a mock
 *   OpenClaw `api`, Mandu's components are SEPARATE processes/packages wired
 *   over a Unix-socket IPC. So `buildStack` boots a REAL `ArbiterServer` on a temp
 *   socket/db/eventDir and the chosen REAL ingress proxy (AnthropicProxy for Claude,
 *   OpenAiProxy for Codex) pointed at a MOCK upstream — the exact in-process
 *   wiring proven in tests/stack/full-stack.test.ts, generalized so any
 *   scenario can drive it. NO API key, NO network: the proxies' upstream is the
 *   anthropic-proxy mock-upstream fetcher.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";

// ── REAL components under test (imported across package boundaries) ───────────
import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";

import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";

import { OpenAiProxy } from "../../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../../interceptors/openai-proxy/src/arbiter-client.js";

import { ArbiterEventSource } from "../../../dashboard/src/event-source.js";
import type { ManduEvent } from "../../../dashboard/src/event-model.js";

import { inspectSymbol, type InspectSymbolResult } from "../../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter as InspectArbiterAdapter } from "../../../interceptors/inspect-mcp/src/arbiter-client.js";
import { MockUllm } from "../../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";

import { MockUpstream, buildToolUseSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";

import type {
  ClassifyRequest,
  DesymbolizationRequest,
} from "../../../arbiter/policy/policy-interface.js";
import type { ExecShell } from "../../../arbiter/policy/exec-classify.js";

// ─────────────────────────────────────────────────────────────────────────────
// ANSI palette — matches adfi-openclaw/test/helpers.ts + unit_policy.ts.
// ─────────────────────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

// ─────────────────────────────────────────────────────────────────────────────
// The micro test runner (mirrors adfi test/helpers.ts `test` / `summary`).
// ─────────────────────────────────────────────────────────────────────────────
let _passed = 0;
let _failed = 0;

export function resetCounters(): void {
  _passed = 0;
  _failed = 0;
}

/** Print a bold-cyan section header (adfi unit-suite style). */
export function header(text: string): void {
  console.log(`\n${C.bold}${C.cyan}${text}${C.reset}`);
}

/** A single synchronous test case. ✓ / ✗ with the error message indented. */
export function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ${C.green}✓${C.reset} ${name}`);
    _passed++;
  } catch (err) {
    console.error(`  ${C.red}✗ ${name}${C.reset}`);
    console.error(`    ${C.dim}${(err as Error).message}${C.reset}`);
    _failed++;
  }
}

/** An async test case (used by the scenario runner). */
export async function testAsync(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ${C.green}✓${C.reset} ${name}`);
    _passed++;
  } catch (err) {
    console.error(`  ${C.red}✗ ${name}${C.reset}`);
    console.error(`    ${C.dim}${(err as Error).message}${C.reset}`);
    _failed++;
  }
}

/** Record a one-line result computed elsewhere (used by the DSL evaluator). */
export function record(label: string, passed: boolean, reason: string): void {
  if (passed) {
    console.log(`    ${C.green}✓${C.reset} ${label} ${C.dim}— ${reason}${C.reset}`);
    _passed++;
  } else {
    console.error(`    ${C.red}✗ ${label}${C.reset}`);
    console.error(`      ${C.dim}${reason}${C.reset}`);
    _failed++;
  }
}

export function summary(): { passed: number; failed: number } {
  return { passed: _passed, failed: _failed };
}

/** adfi-style summary print + process exit code (non-zero on any failure). Also
 * prints a node:test-style TAP footer (`# tests/pass/fail`) so the repo's
 * scripts/test-all.sh can extract a compact count line. */
export function printSummaryAndExit(): never {
  const { passed, failed } = summary();
  const total = passed + failed;
  console.log(
    `\n${C.bold}${"═".repeat(60)}${C.reset}\n` +
      `  ${failed === 0 ? C.green : C.red}${C.bold}${passed}/${total} passed, ${failed} failed${C.reset}\n` +
      `${C.bold}${"═".repeat(60)}${C.reset}\n`,
  );
  printTapFooter(passed, failed);
  process.exit(failed === 0 ? 0 : 1);
}

/** Emit a node:test-style TAP footer that scripts/test-all.sh can grep. */
export function printTapFooter(passed: number, failed: number): void {
  console.log(`# tests ${passed + failed}`);
  console.log(`# pass ${passed}`);
  console.log(`# fail ${failed}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// buildStack — the deterministic real-component system under test.
// ─────────────────────────────────────────────────────────────────────────────

/** Which ingress proxy to boot for a scenario. */
export type Target = "claude" | "codex";

export interface BuildStackOptions {
  /** Which ingress proxy to wire: AnthropicProxy ("claude") or OpenAiProxy ("codex"). */
  target: Target;
  /** Stable session id threaded through the proxy + read back from the arbiter. */
  sessionId?: string;
  /** Optional canned U-LLM reply for the inspect_symbol (U-LLM) path. */
  ullmReply?: string;
}

/** Args for one ingress drive (one tool result re-entering T-LLM's context). */
export interface DriveIngressArgs {
  /** Logical tool name (e.g. "Read", "WebFetch", "Bash" for claude; the Codex
   *  function name e.g. "exec_command" for codex). Drives the arbiter's policy. */
  tool: string;
  /** The raw (untrusted or trusted) value the tool returned. */
  value: string;
  /** Tool-call input params, e.g. { file_path, url, command }. Supplies the
   *  origin hint the arbiter keys trust off. */
  input?: Record<string, unknown>;
}

/** What one ingress drive observed at the proxy egress (forwarded model request). */
export interface DriveIngressResult {
  /** HTTP status the proxy returned (200 forwarded; 5xx fail-closed). */
  status: number;
  /** The body bytes the proxy FORWARDED upstream (decoded UTF-8). The §9 oracle
   *  surface: it must carry no raw untrusted byte, only $MDU:* tokens. */
  forwarded: string;
  /** The minted symbol that replaced the value (null if not symbolized). */
  symbol: string | null;
}

/** The U-LLM (inspect_symbol) drive result + the mock U-LLM's recorded calls. */
export interface DriveUllmResult {
  result: InspectSymbolResult;
  /** The user message(s) the quarantined model received (for leak assertions). */
  ullmUserMessages: string[];
}

/** A narrow arbiter facade for the policy assertions. */
export interface StackArbiter {
  classify(req: ClassifyRequest): Promise<{ trust: "TRUSTED" | "UNTRUSTED"; reason: string }>;
  resolve(symbol: string): Promise<string | null>;
  desymbolizationDecision(
    req: DesymbolizationRequest,
  ): Promise<{ allow: boolean; requiresApproval?: boolean; reason: string }>;
  classifyExec(args: {
    argv: string[];
    cwd?: string;
    needsNetwork?: boolean;
    needsOriginalFs?: boolean;
    params?: Record<string, unknown>;
  }): Promise<{ shell: ExecShell; identifier: string | null; reason: string }>;
}

export interface Stack {
  /** Drive ONE tool result through the ingress proxy; capture the forwarded body. */
  driveIngress(args: DriveIngressArgs): Promise<DriveIngressResult>;
  /** Drive the inspect_symbol (cooperative U-LLM) path against a minted symbol. */
  driveUllm(symbol: string, instruction: string): Promise<DriveUllmResult>;
  /** Read persisted ManduEvents for this stack's session via the dashboard
   *  ArbiterEventSource (polled until `predicate` holds, then returned). */
  events(predicate?: (events: ManduEvent[]) => boolean, timeoutMs?: number): Promise<ManduEvent[]>;
  /** The narrow arbiter facade for resolve / desymbolizationDecision / classify(Exec). */
  arbiter: StackArbiter;
  /** The scenario's session id. */
  sessionId: string;
  /** The minted symbols seen so far, in drive order (convenience for scenarios). */
  mintedSymbols: string[];
  /** Tear down the proxy, arbiter, clients, and temp dirs. */
  dispose(): Promise<void>;
}

/** The canonical $MDU:* token shape (mirrors arbiter symbol-format).
 * GLOBAL so we can enumerate EVERY symbol in a forwarded body — the body also
 * contains EXAMPLE symbols baked into the injected handling prompt (e.g.
 * "$MDU:web_fetch[a1b2].text"), so the first match is NOT necessarily the
 * real minted one; we pick the one the arbiter can resolve. */
const SYMBOL_RE_G = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;

/**
 * The integration glue the full-stack test documents: the anthropic-proxy adapter
 * wants an `emit(event) => {seq}`, while the real arbiter IPC client resolves to
 * the bare `seq` number. Bridge it (the proxy ignores the result anyway).
 */
function modelProxyRealClient(client: ArbiterClient): ConstructorParameters<typeof AnthropicProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    recordToolCall: (args) => client.recordToolCall(args),
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    scanSecretValues: (text) => client.scanSecretValues(text),
    // the prompt filter (confidentiality-plan-15 §3.2), as the real client has it
    filterPrompt: (args: Parameters<ArbiterClient["filterPrompt"]>[0]) => client.filterPrompt(args),
    close: () => client.close(),
  };
}

/** Same bridge for the OpenAI proxy adapter (no recordToolCall on that surface). */
function openAiProxyRealClient(client: ArbiterClient): ConstructorParameters<typeof OpenAiProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    close: () => client.close(),
  };
}

/** POST a body to the proxy on `port`, collecting the full (streamed) response. */
function postTo(
  port: number,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path,
        headers: { "content-type": "application/json", ...headers },
      },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Boot a offline, fully-wired Mandu stack and return handles. Mirrors
 * adfi's `buildMockApi`: one call yields the whole system under test, ready to
 * drive + observe, and a `dispose()` that cleans up everything.
 */
export async function buildStack(opts: BuildStackOptions): Promise<Stack> {
  const sessionId = opts.sessionId ?? `conf_${Math.random().toString(36).slice(2, 10)}`;

  // ── 1. A real arbiter on a temp socket + temp event dir + temp symbol DB ──────
  const tmp = mkdtempSync(join(tmpdir(), "mandu-conf-"));
  const socketPath = join(tmp, "arbiter.sock");
  // The human plane (docs/design/architecture/arbiter-human-plane.md): the ops that return
  // originals (shallow resolve, desymbolize, events/subscribe) are served only
  // here, so the harness's own read-backs and the dashboard source ride it.
  const humanSocketPath = join(tmp, "human", "h.sock");
  const eventDir = join(tmp, "events");
  const dbPath = join(tmp, "symbols.sqlite");

  const arbiter = new ArbiterServer({
    // The conformance corpus is the paper's defense: integrity ON, confidentiality
    // OFF, STATED (protection-modes.md §4), never the built-in default.
    socketPath, humanSocketPath, dbPath, eventDir, integrity: true, confidentiality: false, log: () => {},
  });
  await arbiter.listen();

  // The proxy's adapter wraps a REAL arbiter IPC client; a second client serves
  // the test's own arbiter reads (resolve / desymbolizationDecision / classify).
  const proxyClient = new ArbiterClient(socketPath);
  await proxyClient.connect();
  const readClient = new ArbiterClient(socketPath);
  await readClient.connect();
  // …and a human-plane client for the reads that return ORIGINALS (the
  // round-trip authority's shallow resolve), as the dashboard reads them.
  const humanClient = new ArbiterClient(humanSocketPath);
  await humanClient.connect();

  // The dashboard's arbiter-backed event source (events over the human socket).
  const source = new ArbiterEventSource({ socketPath, humanSocketPath });

  // A benign canned tool_use response so each proxy exchange completes cleanly.
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_done", name: "TodoWrite", input: { todos: [] } }),
  });

  // ── 2. The chosen REAL ingress proxy, pointed at the arbiter + mock upstream ──
  let port: number;
  let proxy: AnthropicProxy | OpenAiProxy;
  let ingressPath: string;
  let buildIngressBody: (args: DriveIngressArgs) => string;

  if (opts.target === "claude") {
    const mp = new AnthropicProxy({
      arbiter: new AnthropicProxyArbiterAdapter(modelProxyRealClient(proxyClient)),
      upstream: upstream.fetcher,
      log: () => {},
    });
    port = await mp.listen(0);
    proxy = mp;
    ingressPath = "/v1/messages";
    buildIngressBody = (args) => buildMessagesBody(args);
  } else {
    const op = new OpenAiProxy({
      arbiter: new OpenAiProxyArbiterAdapter(openAiProxyRealClient(proxyClient)),
      upstream: upstream.fetcher,
      log: () => {},
    });
    port = await op.listen(0);
    proxy = op;
    ingressPath = "/v1/responses";
    buildIngressBody = (args) => buildResponsesBody(args);
  }

  const mintedSymbols: string[] = [];

  const driveIngress = async (args: DriveIngressArgs): Promise<DriveIngressResult> => {
    const before = upstream.requests.length;
    const body = buildIngressBody(args);
    const res = await postTo(port, ingressPath, { "x-mandu-session-id": sessionId }, body);
    const forwarded =
      upstream.requests.length > before ? upstream.requests[upstream.requests.length - 1]!.bodyText : "";
    // The forwarded body carries BOTH the injected handling prompt's EXAMPLE
    // symbols and the real minted one. Pick the symbol the arbiter can actually
    // resolve — that is the one that replaced this tool result. (De-dupe; skip
    // the example tokens, which are not in the table.)
    let symbol: string | null = null;
    const seen = new Set<string>();
    for (const m of forwarded.matchAll(SYMBOL_RE_G)) {
      const candidate = m[0];
      if (seen.has(candidate)) continue;
      seen.add(candidate);
      if ((await humanClient.resolve(candidate)) !== null) {
        symbol = candidate;
        break;
      }
    }
    if (symbol) mintedSymbols.push(symbol);
    return { status: res.status, forwarded, symbol };
  };

  const driveUllm = async (symbol: string, instruction: string): Promise<DriveUllmResult> => {
    const ullm = new MockUllm({ reply: opts.ullmReply ?? "QUARANTINED_RESULT", model: "claude-haiku-mock" });
    const inspectArbiter = new InspectArbiterAdapter({
      connect: () => readClient.connect(),
      // Forward the options: the adapter asks for the DEEP (level-gated,
      // data-plane) resolve; dropping them made it a shallow one, which the
      // data socket refuses (arbiter-human-plane.md).
      resolve: (sym, o) => readClient.resolve(sym, o),
      symbolize: (a) => readClient.symbolize(a),
      // Multi-input inspection (2026-09-11) made the adapter ALWAYS take the
      // derived branch, which throws when the underlying client lacks this op
      // — CT-09 had failed silently ("Arbiter lacks multi-source derivation")
      // since then (found 2026-09-18 by the repo-wide run).
      symbolizeDerived: (a) => readClient.symbolizeDerived(a),
      emit: (event) => readClient.emit(event as never),
      close: () => readClient.close(),
    });
    const result = await inspectSymbol({ arbiter: inspectArbiter, ullm, sessionId }, { symbol, instruction });
    return { result, ullmUserMessages: ullm.calls.map((c) => c.user) };
  };

  const events = async (
    predicate?: (events: ManduEvent[]) => boolean,
    timeoutMs = 5000,
  ): Promise<ManduEvent[]> => {
    const deadline = Date.now() + timeoutMs;
    let last: ManduEvent[] = [];
    while (Date.now() < deadline) {
      last = await source.readEvents(sessionId);
      if (!predicate || predicate(last)) return last;
      await new Promise((r) => setTimeout(r, 25));
    }
    return last;
  };

  const arbiterFacade: StackArbiter = {
    classify: async (req) => {
      const r = await readClient.classify(req);
      return { trust: r.trust, reason: r.reason };
    },
    resolve: (symbol) => humanClient.resolve(symbol),
    desymbolizationDecision: async (req) => {
      const d = await readClient.desymbolizationDecision(req);
      return d.allow
        ? { allow: true, reason: d.reason }
        : { allow: false, requiresApproval: d.requiresApproval, reason: d.reason };
    },
    classifyExec: async (a) => {
      const d = await readClient.classifyExec(a);
      return { shell: d.shell, identifier: d.identifier, reason: d.reason };
    },
  };

  const dispose = async (): Promise<void> => {
    await proxy.close();
    proxyClient.close();
    readClient.close();
    humanClient.close();
    source.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  };

  return {
    driveIngress,
    driveUllm,
    events,
    arbiter: arbiterFacade,
    sessionId,
    mintedSymbols,
    dispose,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Request body builders for the two ingress wire formats.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A Messages request with ONE tool_result carrying `args.value`, correlated to a
 * prior assistant tool_use so the proxy recovers {tool, input} (and the origin
 * hint). This is exactly the shape Claude Code POSTs after a tool runs.
 */
function buildMessagesBody(args: DriveIngressArgs): string {
  const input = args.input ?? {};
  return JSON.stringify({
    model: "claude-opus-4",
    stream: true,
    system: "You are Claude Code.",
    messages: [
      { role: "user", content: "Do the task." },
      {
        role: "assistant",
        content: [
          { type: "text", text: `Calling ${args.tool}.` },
          { type: "tool_use", id: "toolu_1", name: args.tool, input },
        ],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "toolu_1", content: args.value }],
      },
    ],
  });
}

/**
 * A Responses request with ONE function_call_output carrying `args.value`,
 * correlated to a prior function_call so the proxy recovers {name, arguments}.
 * This is the shape the Codex CLI POSTs to {base_url}/responses.
 */
function buildResponsesBody(args: DriveIngressArgs): string {
  const argObj = args.input ?? {};
  return JSON.stringify({
    model: "gpt-5-codex",
    stream: true,
    instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: "Do the task." },
      {
        type: "function_call",
        call_id: "call_1",
        name: args.tool,
        arguments: JSON.stringify(argObj),
      },
      {
        type: "function_call_output",
        call_id: "call_1",
        output: args.value,
      },
    ],
  });
}
