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
import { attachmentSession } from "./attachment-session.js";
import { HookArbiterAdapter, NO_RELEASE, type HookArbiter, type RealHookArbiterClient, type ReplyReleaser } from "./hook-arbiter.js";
import { registerAttachmentHooks } from "./hooks.js";
import { compileTamperPolicy, type TamperContext } from "./tamper-policy.js";
import { registerSandboxTier, type SandboxTierConfig, type SandboxTierDeps } from "./sandbox/backend.js";
import { homedir } from "node:os";
import { join } from "node:path";

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
  /** Async arbiter factory for the attachment hooks. Default: the same real
   *  IPC connection as the tools, behind HookArbiterAdapter. */
  connectHookArbiter?: (sockPath: string) => Promise<HookArbiter>;
  /** The reply release (hook-arbiter.ts). Default NO_RELEASE: no arbiter op
   *  decides a chat destination yet, so every placeholder stays. */
  releaser?: ReplyReleaser;
  /** How long the reply hook waits on the arbiter (hooks.ts default 3 s). */
  replyTimeoutMs?: number;
  /** Registers the confined-commands tier (sandbox/backend.ts). Default: the real one. */
  registerSandbox?: (tier: SandboxTierConfig, deps: SandboxTierDeps) => unknown;
}

/** The tamper policy's paths, from the plugin config and the Gateway's own
 *  environment (tamper-policy.ts). Exported for the tests. */
export function tamperContextFrom(
  cfg: { arbiterSock: string; manduPaths: readonly string[] },
  env: NodeJS.ProcessEnv,
): TamperContext {
  const home = env["HOME"] || homedir();
  const stateDir = env["OPENCLAW_STATE_DIR"] || join(home, ".openclaw");
  const manduPaths = new Set<string>([
    env["MANDU_HOME"] || join(home, ".mandu"),
    ...(env["MANDU_RUNTIME_DIR"] ? [env["MANDU_RUNTIME_DIR"]] : []),
    ...(env["XDG_RUNTIME_DIR"] ? [join(env["XDG_RUNTIME_DIR"], "mandu")] : []),
    ...cfg.manduPaths,
    cfg.arbiterSock,
  ]);
  return {
    home,
    manduPaths: [...manduPaths].filter((p) => p.startsWith("/")),
    openclawConfigPath: env["OPENCLAW_CONFIG_PATH"] || join(stateDir, "openclaw.json"),
    openclawStateDir: stateDir,
  };
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

  // An attachment's session is `openclaw:<agentId>` unless the installer
  // named it (it writes the same string as the proxy's session).
  const scopeId = cfg.scopeId ?? (cfg.attachment ? attachmentSession(cfg.agentId) : undefined);

  // 3. Lazy, memoized arbiter connection (registration must not await). A
  // failed connect clears the memo so a later call can retry — one transient
  // outage must not brick the tool for the gateway's whole lifetime — and the
  // in-flight call that hit it REFUSES fail-closed (inspect-tool.ts). The
  // tools and the hooks share ONE real connection (the data socket).
  let rawPromise: Promise<RealArbiterClient & RealHookArbiterClient> | null = null;
  const getRaw = (): Promise<RealArbiterClient & RealHookArbiterClient> => {
    if (rawPromise === null) {
      rawPromise = connectRealClient(cfg.arbiterSock).catch((err: unknown) => {
        rawPromise = null;
        throw err;
      });
    }
    return rawPromise;
  };
  const memo = <T>(connect: () => Promise<T>): (() => Promise<T>) => {
    let p: Promise<T> | null = null;
    return () => {
      if (p === null) {
        p = connect().catch((err: unknown) => {
          p = null;
          throw err;
        });
      }
      return p;
    };
  };
  const getArbiter = memo<Arbiter>(() =>
    opts.connectArbiter ? opts.connectArbiter(cfg.arbiterSock) : getRaw().then((c) => new ArbiterClientAdapter(c)));

  // 2b. The attachment hooks FIRST (openclaw-plugin.md §3.5, §3.6): they
  // need no U-LLM, and a Gateway that cannot inspect must still refuse a
  // tamper call and still check its replies.
  if (cfg.attachment) {
    const getHookArbiter = memo<HookArbiter>(() =>
      opts.connectHookArbiter ? opts.connectHookArbiter(cfg.arbiterSock) : getRaw().then((c) => new HookArbiterAdapter(c)));
    registerAttachmentHooks(api, {
      policy: compileTamperPolicy(tamperContextFrom(cfg, env)),
      agentId: cfg.agentId,
      getArbiter: getHookArbiter,
      releaser: opts.releaser ?? NO_RELEASE,
      logger: api.logger,
      ...(opts.replyTimeoutMs !== undefined ? { arbiterTimeoutMs: opts.replyTimeoutMs } : {}),
    });
  }

  // 2c. The confined-commands tier (openclaw-plugin.md §10): OpenClaw's
  // `mandu` sandbox backend. Its SDK seam is imported after this registrar
  // returns; a release without it leaves the hooks and tools as they are.
  if (cfg.attachment && cfg.sandbox) {
    (opts.registerSandbox ?? registerSandboxTier)(cfg.sandbox, { env, arbiterSock: cfg.arbiterSock, logger: api.logger });
  }

  // 2. U-LLM transport — the SAME fail-closed selection the MCP entrypoint
  // runs (api needs a key, cli needs a binary on PATH, auto tries both), with
  // assertNonProxyBaseUrl's loopback refusal inside. Throws on no transport.
  // In an attachment a missing transport drops inspect_symbol (logged as an
  // error) rather than the whole plugin: the hooks above must stay.
  let ullmConfig: UllmConfig | null = null;
  let ullm: UllmClient | null = null;
  try {
    ullmConfig = selectUllmConfig(cfg.ullmEnv, opts.cliAvailable ?? isOnPath);
    ullm = (opts.buildUllm ?? buildUllmClient)(ullmConfig);
  } catch (err) {
    if (!cfg.attachment) throw err;
    api.logger.error(`[mandu-inspect] ${INSPECT_TOOL_NAME} not registered: ${err instanceof Error ? err.message : String(err)}`);
  }

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
  if (ullm !== null) {
    const client = ullm;
    api.registerTool((ctx) =>
      createInspectSymbolPluginTool(async () => ({
        arbiter: await getArbiter(),
        ullm: client,
        sessionId: scopeId ?? ctx?.sessionKey ?? "openclaw-inspect",
        triageCache,
        endpointUllm,
      })),
    );
  }

  // 6. declassify_symbol (rung 3, agent-e2e-harness.md §8.5): the same lazy
  // arbiter, NON-optional like inspect_symbol. Its session is the configured
  // Mandu scope ONLY: the arbiter raises the watermark on the session the call
  // names and the model proxy gates the launcher's scope, so a release under
  // OpenClaw's own session key (or a fixed fallback) would leave the gated
  // session clean while the model holds the secret. No scope → the call
  // refuses (declassify-tool.ts), fail closed.
  api.registerTool(() =>
    createDeclassifySymbolPluginTool(async () => {
      if (scopeId === undefined) {
        throw new Error(
          "no Mandu scope configured (plugins.entries.mandu-inspect.config.scopeId or env MANDU_SCOPE_ID); " +
            "a release that cannot be watermarked on the gated session cannot be confined",
        );
      }
      return { arbiter: await getArbiter(), sessionId: scopeId };
    }),
  );

  const facts = [
    ...(ullmConfig !== null ? [`ullm=${ullmConfig.mode}${ullmConfig.mode === "cli" ? ` binary=${ullmConfig.binary}` : ""}`] : []),
    `arbiter=${cfg.arbiterSock}`,
    ...(cfg.attachment ? [`attached as ${scopeId}`] : []),
    ...(cfg.attachment && cfg.sandbox ? ["sandbox backend mandu"] : []),
  ];
  api.logger.info(
    `[mandu-inspect] ${ullmConfig !== null ? `${INSPECT_TOOL_NAME} + ` : ""}${DECLASSIFY_TOOL_NAME} registered (${facts.join(", ")})`,
  );
}

/**
 * Default arbiter connection: dynamically import the REAL arbiter IPC client
 * (arbiter/ipc/client.ts — the arbiter is the single owner of the symbol
 * table; interceptors never open the DB), connect, and adapt it to the narrow
 * `Arbiter` interface via inspect-mcp's ArbiterClientAdapter (which also
 * makes resolve() DEEP — the quarantined U-LLM must see full original data).
 * Kept out of the static import graph so this package typechecks standalone,
 * mirroring server-main.ts `loadArbiterClient`.
 */
async function connectRealClient(sockPath: string): Promise<RealArbiterClient & RealHookArbiterClient> {
  const mod = (await import(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    "../../../arbiter/ipc/client.js" as any
  )) as { ArbiterClient: new (sock: string) => RealArbiterClient & RealHookArbiterClient };
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
  return client;
}
