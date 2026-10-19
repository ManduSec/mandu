/**
 * register — the synchronous OpenClaw plugin registrar.
 *
 * Mandu U-LLM channel for OpenClaw (interceptors/openclaw-inspect-plugin).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE (a REVERSE lift — Mandu code into an OpenClaw plugin shape):
 *   - The register(api) → api.registerTool((ctx) => tool) SCAFFOLD is lifted
 *     from the reference plugin's registration block,
 *       https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/index.ts
 *     (the `createInspectSymbolTool` registerTool call) — MINUS its
 *     `{ optional: true }`: an optional tool is silently filtered unless the
 *     effective tool allowlist names it (openclaw-src/src/plugins/tools.ts
 *     isOptionalToolAllowed), which under the harness's `tools.profile`
 *     config would drop the tool with no error. Registration here is
 *     NON-optional so the tool always reaches the model's tools[].
 *   - The DEPENDENCY WIRING (real arbiter IPC client via ArbiterClientAdapter,
 *     UllmClient via selectUllmConfig/buildUllmClient, one triageCache per
 *     process) mirrors interceptors/inspect-mcp/src/server-main.ts `main()`.
 *     What changed: server-main is a process entrypoint that can await
 *     connect() before serving and process.exit(1) on misconfiguration; an
 *     OpenClaw registrar MUST be synchronous (a returned promise is ignored
 *     with a warning — openclaw-src/src/plugins/loader.ts), so config
 *     resolution + U-LLM selection stay synchronous-and-throwing here (a
 *     throw fails the plugin load LOUDLY), while the arbiter connect becomes
 *     lazy-on-first-call with a fail-closed refusal (inspect-tool.ts).
 * ─────────────────────────────────────────────────────────────────────────────
 */

import {
  ArbiterClientAdapter,
  type Arbiter,
  type RealArbiterClient,
} from "../../inspect-mcp/src/arbiter-client.js";
import {
  selectUllmConfig,
  buildUllmClient,
  createEndpointUllmFactory,
  isOnPath,
  type UllmConfig,
} from "../../inspect-mcp/src/ullm-config.js";
import type { UllmClient } from "../../inspect-mcp/src/ullm-client.js";
import type { ContentKind } from "../../inspect-mcp/src/inspect-symbol.js";
import { resolvePluginConfig } from "./plugin-config.js";
import { createInspectSymbolPluginTool, INSPECT_TOOL_NAME } from "./inspect-tool.js";
import { createDeclassifySymbolPluginTool, DECLASSIFY_TOOL_NAME } from "./declassify-tool.js";
import type { OpenClawPluginApiLike } from "./openclaw-api.js";

/** Injectable seams (tests). Production callers pass nothing. */
export interface RegisterOptions {
  /** Environment for config fallbacks. Default: process.env. */
  env?: NodeJS.ProcessEnv;
  /** PATH probe for cli-mode selection. Default: inspect-mcp's isOnPath. */
  cliAvailable?: (binary: "claude" | "codex") => boolean;
  /** Async arbiter factory. Default: dynamic-import the real IPC client
   * (arbiter/ipc/client.ts), connect, wrap in ArbiterClientAdapter. */
  connectArbiter?: (sockPath: string) => Promise<Arbiter>;
  /** UllmClient factory from the selected config. Default: buildUllmClient. */
  buildUllm?: (config: UllmConfig) => UllmClient;
}

/**
 * Register the inspect_symbol and declassify_symbol tools on an OpenClaw
 * plugin api. SYNCHRONOUS by
 * contract (see header). Throws — failing the plugin load loudly — when the
 * arbiter socket is unconfigured or no U-LLM transport is available: a run
 * that cannot inspect must say so at load time, never register a tool that
 * silently has no arbiter behind it.
 */
export function registerInspectPlugin(
  api: OpenClawPluginApiLike,
  opts: RegisterOptions = {},
): void {
  const env = opts.env ?? process.env;

  // 1. Config — throws on a missing arbiter socket (fail loud, fail closed).
  const cfg = resolvePluginConfig(api.pluginConfig, env);

  // 2. U-LLM transport — the SAME fail-closed selection the MCP entrypoint
  // runs (api needs a key, cli needs a binary on PATH, auto tries both), with
  // assertNonProxyBaseUrl's loopback refusal inside. Throws on no transport.
  const ullmConfig = selectUllmConfig(cfg.ullmEnv, opts.cliAvailable ?? isOnPath);
  const ullm = (opts.buildUllm ?? buildUllmClient)(ullmConfig);

  // 3. Lazy, memoized arbiter connection (registration must not await). A
  // failed connect clears the memo so a later call can retry — one transient
  // outage must not brick the tool for the gateway's whole lifetime — and the
  // in-flight call that hit it REFUSES fail-closed (inspect-tool.ts).
  const connect = opts.connectArbiter ?? connectRealArbiter;
  let arbiterPromise: Promise<Arbiter> | null = null;
  const getArbiter = (): Promise<Arbiter> => {
    if (arbiterPromise === null) {
      arbiterPromise = connect(cfg.arbiterSock).catch((err: unknown) => {
        arbiterPromise = null;
        throw err;
      });
    }
    return arbiterPromise;
  };

  // 4. One triage-verdict cache per plugin registration (= per gateway
  // process). Keyed by symbol token — tokens are unique, so sharing the map
  // across OpenClaw sessions only saves duplicate triage calls, exactly as
  // the per-process map does in server-main (symbol-quality.md §4.2).
  const triageCache = new Map<string, ContentKind>();

  // 4b. Plan 11 D5: the client for a declared `local: true` model endpoint
  // (the list itself comes from the arbiter per call). Forbidden addresses:
  // the U-LLM forwarder pin and the HOST's ANTHROPIC_BASE_URL, which in a
  // wrapped run is the model proxy (see plugin-config.ts header).
  const endpointUllm = createEndpointUllmFactory(
    { ...env, MANDU_ULLM_FORWARDER: cfg.ullmEnv.MANDU_ULLM_FORWARDER },
    [env.ANTHROPIC_BASE_URL],
  );

  // 5. Register NON-optional (no options object at all — see the header).
  // The factory runs per tool resolution; the session/scope key threads the
  // configured scopeId first (matching the proxy's scope for the run), then
  // OpenClaw's own sessionKey, then a fixed fallback.
  api.registerTool((ctx) =>
    createInspectSymbolPluginTool(async () => ({
      arbiter: await getArbiter(),
      ullm,
      sessionId: cfg.scopeId ?? ctx?.sessionKey ?? "openclaw-inspect",
      triageCache,
      endpointUllm,
    })),
  );

  // 6. declassify_symbol (rung 3, agent-e2e-harness.md §8.5): the same lazy
  // arbiter, NON-optional like inspect_symbol. Its session is the configured
  // Mandu scope ONLY: the arbiter raises the watermark on the session the call
  // names and the model proxy gates the launcher's scope, so a release under
  // OpenClaw's own session key (or a fixed fallback) would leave the gated
  // session clean while the model holds the secret. No scope → the call
  // refuses (declassify-tool.ts), fail closed.
  api.registerTool(() =>
    createDeclassifySymbolPluginTool(async () => {
      if (cfg.scopeId === undefined) {
        throw new Error(
          "no Mandu scope configured (plugins.entries.mandu-inspect.config.scopeId or env MANDU_SCOPE_ID); " +
            "a release that cannot be watermarked on the gated session cannot be confined",
        );
      }
      return { arbiter: await getArbiter(), sessionId: cfg.scopeId };
    }),
  );

  api.logger.info(
    `[mandu-inspect] ${INSPECT_TOOL_NAME} + ${DECLASSIFY_TOOL_NAME} registered (ullm=${ullmConfig.mode}` +
      `${ullmConfig.mode === "cli" ? ` binary=${ullmConfig.binary}` : ""}` +
      `, arbiter=${cfg.arbiterSock})`,
  );
}

/**
 * Default arbiter factory: dynamically import the REAL arbiter IPC client
 * (arbiter/ipc/client.ts — the arbiter is the single owner of the symbol
 * table; interceptors never open the DB), connect, and adapt it to the narrow
 * `Arbiter` interface via inspect-mcp's ArbiterClientAdapter (which also
 * makes resolve() DEEP — the quarantined U-LLM must see full original data).
 * Kept out of the static import graph so this package typechecks standalone,
 * mirroring server-main.ts `loadArbiterClient`.
 */
async function connectRealArbiter(sockPath: string): Promise<Arbiter> {
  const mod = (await import(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    "../../../arbiter/ipc/client.js" as any
  )) as { ArbiterClient: new (sock: string) => RealArbiterClient };
  const client = new mod.ArbiterClient(sockPath);
  await client.connect();
  // A GUEST MUST NOT CHANGE ITS HOST'S LIFECYCLE. This client lives inside the
  // OpenClaw process, and an open socket is a live libuv handle: without this,
  // `openclaw agent --local` completed its turn, printed its result, and then
  // hung forever waiting on our connection (found 2026-08-06 — the run only
  // ended when the harness SIGKILLed the process group at its wall clock). The
  // connection stays fully usable; unref only stops it COUNTING toward keeping
  // the loop alive. See ArbiterClient.unref.
  client.unref?.();
  return new ArbiterClientAdapter(client);
}
