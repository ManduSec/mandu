/**
 * server-main — deployment entrypoint for the inspect_symbol MCP stdio server.
 *
 * Mandu M4 cooperative U-LLM path (interceptors/inspect-mcp). Claude Code
 * launches this as an stdio MCP server (see README). It wires:
 *   - the REAL arbiter IPC client (arbiter/ipc/client.ts) via ArbiterClientAdapter,
 *     pointed at MANDU_ARBITER_SOCK — for resolve / symbolize / emit.
 *   - the REAL quarantined U-LLM. Two transports, selected by MANDU_ULLM_MODE:
 *       * "api" — AnthropicUllmClient: a DIRECT Anthropic Messages API call
 *                 (requires ANTHROPIC_API_KEY).
 *       * "cli" — CliUllmClient: a fresh `claude -p` (or `codex exec`) subprocess
 *                 that REUSES the user's logged-in Claude Code auth — NO separate
 *                 key — in a separate session/process, clean cwd, NO tools.
 *       * "auto" (default) — key present → api; else a CLI binary on PATH → cli;
 *                 else fail closed.
 *   Either way the U-LLM is deliberately NOT routed through the Mandu model-API
 *   MITM proxy (the U-LLM is a separate quarantined channel).
 *
 * This file is I/O wiring only — never imported by tests; the PURE selection
 * logic lives in `selectUllmConfig` (unit-tested in test/unit/server-main.test.ts).
 * The arbiter package is a sibling owned by another sub-agent, so we import its
 * client lazily and structurally; if it is absent at runtime the server exits
 * with a clear error (fail-closed: no arbiter → no symbol table → refuse to run).
 *
 * Env:
 *   MANDU_ARBITER_SOCK   — arbiter Unix socket path (required).
 *   MANDU_ULLM_MODE     — "auto" (default) | "api" | "cli".
 *   ANTHROPIC_API_KEY     — key for the api-mode U-LLM call (required for "api").
 *   ANTHROPIC_BASE_URL    — U-LLM endpoint (optional; default api.anthropic.com).
 *                           MUST be the real endpoint, NOT the Mandu proxy —
 *                           the ONE exception is the launcher's pinned verbatim
 *                           forwarder (below).
 *   MANDU_ULLM_FORWARDER — the launcher's loopback→api.anthropic.com verbatim
 *                           relay URL (optional). The single loopback base URL
 *                           the guard accepts; set by the launcher alongside
 *                           ANTHROPIC_BASE_URL so the U-LLM works under the
 *                           whole-agent TCP confine (exec-routing.md §7.1).
 *   MANDU_ULLM_BINARY   — cli-mode binary hint: "claude" | "codex" | "auto".
 *   MANDU_ULLM_BINARY_PATH — that CLI's absolute path (optional), which the
 *                           launcher resolves past the session's `claude`
 *                           PATH shim: by name, the shim would route the
 *                           quarantined `claude -p` to the model proxy.
 *   MANDU_ULLM_MODEL    — quarantined model id (optional).
 *   MANDU_SCOPE_ID      — the Mandu session (scope) id: symbolize, events, and
 *                           the session a declassify_symbol release is
 *                           watermarked on. Optional for inspect_symbol
 *                           (falls back to "inspect-mcp"); REQUIRED for
 *                           declassify_symbol, which refuses without it.
 *   MANDU_MODEL_PROXY_URL: the model proxy's address(es), comma-separated
 *                           (optional). Plan 11 D5: a declared model endpoint
 *                           whose origin equals one of these (or the forwarder)
 *                           is refused. Never a declaration: the endpoint list
 *                           itself comes from the arbiter (policy.yaml `models:`).
 */

import { isEntrypoint } from "./entrypoint.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "./arbiter-client.js";
import { runStdioServer } from "./mcp-server.js";
import { scopeSessionId, type InspectSymbolDeps } from "./inspect-symbol.js";
import {
  selectUllmConfig,
  buildUllmClient,
  createEndpointUllmFactory,
  isOnPath,
  type UllmConfig,
} from "./ullm-config.js";

// Canonical process title (runtime-instances.md §7): ps/pgrep-visible identity.
// This import-time side effect is WHY the pure selection logic lives in
// ullm-config.ts: embedding hosts (the OpenClaw plugin) import that module and
// never this one, so they keep their own process identity.
process.title = "mandu-inspect-mcp";

// The PURE U-LLM transport selection was extracted to ./ullm-config.ts
// (side-effect-free, importable by embedding hosts such as
// interceptors/openclaw-inspect-plugin). Re-exported here so existing
// importers (test/unit/server-main.test.ts) keep working unchanged.
export {
  selectUllmConfig,
  buildUllmClient,
  isOnPath,
  type UllmConfig,
  type UllmEnv,
  type UllmMode,
} from "./ullm-config.js";

async function main(): Promise<void> {
  const sockPath = process.env.MANDU_ARBITER_SOCK;
  if (!sockPath) {
    fail("MANDU_ARBITER_SOCK is not set — cannot reach the arbiter (fail closed).");
  }

  // Resolve the U-LLM transport (api vs cli) before touching the arbiter so a
  // misconfiguration fails closed early with a clear message.
  let config: UllmConfig;
  try {
    config = selectUllmConfig(process.env, isOnPath);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  const client = await loadArbiterClient(sockPath!);
  await client.connect();
  const arbiter = new ArbiterClientAdapter(client);

  const ullm = buildUllmClient(config!);
  logSelectedMode(config!);

  const deps: InspectSymbolDeps = {
    arbiter,
    ullm,
    // The launcher's scope, else the fallback, which inspect_symbol accepts
    // and declassify_symbol refuses (inspect-symbol.ts INSPECT_FALLBACK_SESSION).
    sessionId: scopeSessionId(process.env),
    // One map per server process = per session: repeated inspects of the same
    // symbol pay one content_kind triage call (symbol-quality.md §4.2).
    triageCache: new Map(),
    // Plan 11 D5: the client for a declared `local: true` endpoint, built per
    // call from the arbiter's list; the env gives only the forbidden
    // addresses (forwarder, model proxy) and the entry's named token.
    endpointUllm: createEndpointUllmFactory(process.env),
  };

  runStdioServer(deps);
  // The stdio loop keeps the process alive via stdin; clean up on close.
  process.stdin.on("close", () => client.close());
}

function logSelectedMode(config: UllmConfig): void {
  if (config.mode === "cli") {
    process.stderr.write(
      `[inspect-mcp] U-LLM mode=cli (fresh \`claude -p\` subprocess, reuses Claude Code auth, no key) ` +
        `binary=${config.binary} model=${config.model ?? "default"} base=${config.baseUrl ?? "https://api.anthropic.com"}\n`,
    );
  } else {
    process.stderr.write(
      `[inspect-mcp] U-LLM mode=api (direct Anthropic Messages API) ` +
        `model=${config.model ?? "default"} base=${config.baseUrl ?? "https://api.anthropic.com"}\n`,
    );
  }
}

/**
 * Dynamically import the real arbiter IPC client. Kept out of the static import
 * graph so this package builds without the sibling arbiter present.
 */
async function loadArbiterClient(sockPath: string): Promise<RealArbiterClient> {
  // Resolved relative to this package at runtime: arbiter/ipc/client.ts.
  const mod = (await import(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    "../../../arbiter/ipc/client.js" as any
  )) as { ArbiterClient: new (sock: string) => RealArbiterClient };
  return new mod.ArbiterClient(sockPath);
}

function fail(message: string): never {
  process.stderr.write(`[inspect-mcp] ${message}\n`);
  process.exit(1);
}

/**
 * Run main() ONLY when this module is the process entrypoint — NOT when it is
 * imported (e.g. by the unit tests that exercise the pure `selectUllmConfig` /
 * `buildUllmClient` exports). Without this guard, importing the module would
 * spawn the server and `process.exit(1)` for lack of a arbiter socket. The
 * check is realpath-aware (src/entrypoint.ts): a symlinked spelling of this
 * file (darwin's /tmp → /private/tmp) still starts the server.
 */
if (isEntrypoint(import.meta.url, process.argv[1])) {
  main().catch((err) => {
    process.stderr.write(`[inspect-mcp] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
