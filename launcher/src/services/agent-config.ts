/**
 * services/agent-config — per-run config-file routing for the CONFIG-ROUTED
 * targets (openclaw / opencode).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from tests/lib/agent-provision.ts
 *   (buildOpenclawConfig / buildOpencodeConfig — the §2.4 probe-verified
 *   provisioning facts) and services/mcp.ts (the inspect-mcp server entry).
 *   The harness builds a HERMETIC config (throwaway HOME, dummy key, forced
 *   model/provider); this module builds a WRAP config for the user's real
 *   agent instead, and the differences are deliberate:
 *     - the user's own config is READ and deep-merged UNDER our routing
 *       override (their model choice, credentials, and settings survive);
 *     - no dummy key is injected — the agent authenticates exactly as it
 *       would unwrapped (its own auth store / env key), and the context proxy
 *       relays credentials verbatim;
 *     - opencode routing overrides the BUILT-IN `anthropic` provider's
 *       options (baseURL/headers) rather than minting a custom provider, so
 *       the user's `anthropic/<model>` selection keeps working. PROBE-VERIFIED
 *       2026-08-06 in the CI container (opencode 1.18.13): both the title side
 *       call and the agentic call landed on the override URL carrying our
 *       session header, model choice preserved.
 *
 * WHY THIS EXISTS: openclaw and opencode take their base URL from CONFIG
 * FILES and ignore ANTHROPIC_BASE_URL (agent-e2e-harness.md §2.1/§2.2), so
 * the claude-style env delta defends nothing for them. For these targets the
 * emitted file IS the model-context chokepoint wiring — which is why the
 * manager treats a write failure as a HARD fail-closed abort (no
 * --best-effort override): without the file the agent launches fully
 * functional and fully unprotected, the one degradation that cannot be seen.
 *
 * PURE decision / thin enactment, like the rest of services/: the doc
 * builders and merge are pure and unit-tested; writeAgentConfig does the
 * single file write (safe-file.ts publishFile).
 */
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync } from "node:fs";
import {
  findOpencodeProjectCode, OPENCODE_CODE_DIRS, opencodeProjectCodeAllowed, opencodeProjectCodeNotice, opencodeStartDirs, userOpencodeDirs, withoutPlugins,
} from "../opencode-project-code.js";
import {
  addOpencodeSchema, findOpencodeGlobalCode, opencodeGlobalCodeAllowed, opencodeGlobalCodeNotice, OPENCODE_PURE_ENV,
  opencodeV1Pure, opencodeV1ProjectPluginsNotice,
} from "../opencode-global-code.js";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { AgentUserConfig, OpenAiRoute, OpencodeAuthTypes, OpencodeV2Input } from "../agent-model-route.js";
import { opencodeGeneration, opencodePolicyFence, type OpencodeGeneration, type OpencodeLayer } from "../opencode-config.js";
import { compareAgentVersions, parseAgentVersion } from "../agent-versions.js";
import type { LaunchPlan } from "../types.js";
import type { Layout } from "./layout.js";
import { parseJson5 } from "./json5.js";
import { IncludeError, resolveOpenclawIncludes } from "./openclaw-include.js";
import { openclawRunsLocally } from "../openclaw-argv.js";
import { MANDU_POLICY_SERVER, inspectMcpConfigDoc, policyMcpServerEntry } from "./mcp.js";
import { inspectCallBoundMs } from "../ullm-timeout.js";
import { publishFile } from "../safe-file.js";

/** The env var each config-routed agent reads its config path from. */
export const AGENT_CONFIG_ENV_VAR = {
  openclaw: "OPENCLAW_CONFIG_PATH",
  opencode: "OPENCODE_CONFIG",
} as const;

export type ConfigRoutedTarget = keyof typeof AGENT_CONFIG_ENV_VAR;

export function isConfigRouted(target: LaunchPlan["target"]): target is ConfigRoutedTarget {
  return target === "openclaw" || target === "opencode";
}

type Json = Record<string, unknown>;

/**
 * Deep-merge `ours` over `user`: objects recurse, everything else (scalars,
 * arrays) is replaced by ours. The user's keys we do not set all survive —
 * including their provider credentials next to our baseUrl override.
 */
export function mergeConfig(user: Json, ours: Json): Json {
  const out: Json = { ...user };
  for (const [k, v] of Object.entries(ours)) {
    const prev = out[k];
    if (
      v !== null && typeof v === "object" && !Array.isArray(v) &&
      prev !== null && typeof prev === "object" && !Array.isArray(prev)
    ) {
      out[k] = mergeConfig(prev as Json, v as Json);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** The narrow plan slice the builders need (structurally satisfied by a
 *  LaunchPlan whose proxy port is final — call AFTER the context proxy is up). */
export interface AgentConfigInput {
  target: ConfigRoutedTarget;
  scopeId: string;
  batchId?: string | undefined;
  /** Tenant stamp (policy-surface.md §2.7), delivered as `x-mandu-tenant`. */
  tenant: "live" | "test";
  /** The anthropic-proxy endpoint (both targets speak Anthropic Messages). */
  proxyUrl: string;
  /** Mount the U-LLM inspect channel (plan.writeMcp; --no-mcp drops it). */
  inspect: boolean;
  /** Mount the mandu-policy server too (plan.writePolicyMcp; absent = on).
   *  Rides the inspect mount: --no-mcp drops both. */
  policy?: boolean;
  /** The OpenAI-family providers routed through the proxy (plan.openaiRoutes). */
  openaiRoutes?: readonly OpenAiRoute[];
  /** OpenCode only: the config spelling the launched OpenCode reads
   *  (opencode-config.ts opencodeGeneration; absent = 1). */
  opencodeGeneration?: OpencodeGeneration;
}

/** Where a routed OpenAI-family provider points: the proxy's per-provider
 *  prefix (anthropic-proxy route.ts OPENAI_ROUTE_PREFIX). The agent appends
 *  `/chat/completions` or `/responses`. */
export function openaiRouteBaseUrl(proxyUrl: string, id: string): string {
  return `${proxyUrl}/_mandu/openai/${encodeURIComponent(id)}`;
}

/** The session/batch headers both agents deliver per request. Unlike claude's
 *  ONE-header packing, both config formats take a real header map. */
function sessionHeaders(input: AgentConfigInput): Record<string, string> {
  return {
    "x-mandu-session-id": input.scopeId,
    ...(input.batchId ? { "x-mandu-batch-id": input.batchId } : {}),
    "x-mandu-tenant": input.tenant,
  };
}

/** Repo-root resolution for the openclaw plugin package (dev layout only —
 *  the plugin is raw .ts jiti-loaded by OpenClaw from the source tree). */
export function openclawPluginDir(layout: Layout): string {
  return join(layout.repoRoot, "interceptors", "openclaw-inspect-plugin");
}

/**
 * The per-model fields of a user's `models.providers.anthropic.models` entry
 * that DESCRIBE a model (OpenClaw's ModelDefinitionSchema). Everything else is
 * dropped, because OpenClaw lets a model entry carry its own `baseUrl`, `api`
 * and `headers`, and those win over the provider's (probe-verified on 2026.6.35
 * and 2026.7.1: an entry's `baseUrl` received the turn): an entry with its own
 * `baseUrl` would send that model's traffic around the proxy, with tool results
 * unmasked. An allowlist, so a routing field added by a later OpenClaw is
 * dropped too.
 */
const OPENCLAW_MODEL_METADATA_KEYS = new Set([
  "id", "name", "reasoning", "input", "cost", "contextWindow", "contextTokens", "maxTokens",
  "params", "compat", "mediaInput", "thinkingLevelMap",
]);

/**
 * Why the user's entries must survive (os-test-matrix.md §10.14.1, probe-
 * verified 2026-09-27 on OpenClaw 2026.3.12, 2026.6.35, 2026.7.1 and 2026.9.6
 * against a scripted model, with and without the override): a model OUTSIDE
 * OpenClaw's own catalog (2026.7.1 no longer lists `claude-sonnet-4-5`) runs
 * only if the user lists it here with its limits. Unwrapped, OpenClaw answers
 * "Unknown model" for such an id; under the override it resolves the id but
 * without limits, and 2026.7.1 fails every turn "Anthropic Messages transport
 * requires a positive maxTokens value". A listed entry fixes both. Catalog
 * models need no entry, and the launcher adds none: an entry replaces the
 * catalog's metadata (reasoning, image input, cost), which changed the request
 * (2026.3.12 dropped extended thinking), so the launcher does not keep a model
 * table of its own.
 *
 * Returns the cleaned entries plus a note per dropped routing field.
 */
export function openclawUserAnthropicModels(user: Json): { models: Json[]; dropped: string[] } {
  return openclawUserProviderModels(user, "anthropic");
}

/** The same cleaning for any routed provider's `models` list: a model entry's
 *  own `baseUrl` / `api` / `headers` would send that model around the proxy. */
export function openclawUserProviderModels(user: Json, provider: string): { models: Json[]; dropped: string[] } {
  const models = (user["models"] as Json | undefined)?.["providers"] as Json | undefined;
  const list = (models?.[provider] as Json | undefined)?.["models"];
  if (!Array.isArray(list)) return { models: [], dropped: [] };
  const out: Json[] = [];
  const dropped: string[] = [];
  for (const entry of list) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) continue;
    const e = entry as Json;
    const kept: Json = {};
    for (const [k, v] of Object.entries(e)) {
      if (OPENCLAW_MODEL_METADATA_KEYS.has(k)) kept[k] = v;
      else dropped.push(`${typeof e["id"] === "string" ? e["id"] : "?"}.${k}`);
    }
    out.push(kept);
  }
  return { models: out, dropped };
}

/**
 * The OpenClaw routing override (agent-provision.ts buildOpenclawConfig,
 * wrap-mode): models.mode "merge" keeps the built-in catalog and the user's
 * model choice; only where requests GO (+ our headers) is overridden. The
 * U-LLM channel mounts as the in-process plugin (OpenClaw has no MCP client
 * — agent-e2e-harness.md §8), configured from the same Ullm facts .mcp.json
 * would carry; `tools.alsoAllow` lifts the plugin tool past the profile
 * allowlist (probe-verified fact, see the harness builder).
 */
export function buildOpenclawWrapDoc(
  input: AgentConfigInput,
  plan: Pick<LaunchPlan, "arbiterSock" | "scopeId" | "ullm">,
  pluginDir: string | undefined,
  userModels: readonly Json[] = [],
  routedModels: Readonly<Record<string, readonly Json[]>> = {},
): Json {
  const plugins: Json = pluginDir !== undefined
    ? {
        plugins: {
          load: { paths: [pluginDir] },
          entries: {
            "mandu-inspect": {
              enabled: true,
              config: {
                arbiterSock: plan.arbiterSock,
                scopeId: plan.scopeId,
                ullmMode: plan.ullm.mode,
                ullmBinary: plan.ullm.binary ?? "claude",
                ...(plan.ullm.model ? { ullmModel: plan.ullm.model } : {}),
                ...(plan.ullm.mode === "api" && plan.ullm.apiKey
                  ? { ullmApiKey: plan.ullm.apiKey }
                  : {}),
                // The quarantine's endpoint rides DEDICATED keys, never the
                // agent env's ANTHROPIC_BASE_URL (which composeLaunch does not
                // set for this target anyway — the plugin's quarantined child
                // inherits the AGENT environment, so a proxy-pointing base URL
                // there would poison the U-LLM channel).
                ullmBaseUrl: plan.ullm.forwarderUrl ?? plan.ullm.baseUrl,
                ...(plan.ullm.forwarderUrl
                  ? { ullmForwarder: plan.ullm.forwarderUrl }
                  : {}),
              },
            },
          },
        },
        // Both plugin tools (openclaw-inspect-plugin): inspect_symbol and its
        // rung-3 sibling declassify_symbol (agent-e2e-harness.md §8.5).
        tools: { alsoAllow: ["inspect_symbol", "declassify_symbol"] },
      }
    : {};
  return {
    ...plugins,
    models: {
      mode: "merge",
      providers: {
        anthropic: {
          baseUrl: input.proxyUrl,
          // `api` stays named: without it OpenClaw 2026.6.35 infers
          // `openai-completions` and POSTs /chat/completions to the proxy.
          api: "anthropic-messages",
          headers: sessionHeaders(input),
          // The user's own model entries for this provider, cleaned of
          // anything that routes (openclawUserAnthropicModels), else []: the
          // key must be present (2026.3.12 rejects a provider without it), and
          // an array REPLACES the user's in mergeConfig, so writing a bare []
          // over a user's list deleted the models they had added.
          models: [...userModels],
        },
        // Each routed OpenAI-family provider (agent-model-route.ts): the same
        // override, at the proxy's per-provider prefix, with the api pinned
        // (the proxy reads exactly that wire) and the user's model entries
        // cleaned of anything that routes.
        ...Object.fromEntries((input.openaiRoutes ?? []).map((r) => [r.id, {
          baseUrl: openaiRouteBaseUrl(input.proxyUrl, r.id),
          api: r.api,
          headers: sessionHeaders(input),
          models: [...(routedModels[r.id] ?? [])],
        }])),
      },
    },
  };
}

/**
 * The OpenCode routing override: the BUILT-IN `anthropic` provider's options
 * (see the header for why not a custom provider). The U-LLM channel is the
 * same inspect-mcp stdio server .mcp.json registers for claude, in OpenCode's
 * config spelling (`type:"local"`, `environment`, a cold-start-safe timeout —
 * agent-provision.ts buildOpencodeConfig's probe-verified facts).
 */
export function buildOpencodeWrapDoc(
  input: AgentConfigInput,
  plan: Pick<LaunchPlan, "arbiterSock" | "scopeId" | "ullm"> & Partial<Pick<LaunchPlan, "inspectMcpWrap" | "netProxy" | "noProxyExtra" | "modelHostDeny" | "modelEndpoints" | "modelTokens" | "modelClientKeys" | "humanCwd" | "ullmEndpointTimeoutMs">>,
  layout: Layout,
): Json {
  const local = (server: { command: string; args: string[]; env: Record<string, string> }, timeout = OPENCODE_MCP_TIMEOUT_MS): Json => ({
    type: "local",
    command: [server.command, ...server.args],
    enabled: true,
    timeout,
    environment: server.env,
  });
  // OpenCode 2 (supported-agents.md §2.3 part 5): the V2 spelling,
  // `mcp.servers.<name>`, with `codemode: false`. A 2.x MCP server defaults to
  // code mode, where its tools exist only inside `execute`, which Mandu
  // denies and refuses, so the inspect channel would be unreachable; and the
  // V1 spelling has no `codemode` field (2.0.23 drops it when normalizing).
  // The V1 `timeout` normalizes to {catalog, execution}; `startup` covers the
  // same cold start.
  const server = (s: { command: string; args: string[]; env: Record<string, string> }, timeout = OPENCODE_MCP_TIMEOUT_MS): Json =>
    input.opencodeGeneration === 2 ? opencodeV2McpServer(s, timeout) : local(s, timeout);
  const servers: Json = input.inspect
    ? {
        // inspect_symbol's call limit follows the U-LLM timeout the entry
        // carries (opencodeInspectTimeoutMs; model-endpoints.md §1.9).
        "mandu-inspect": server(inspectMcpConfigDoc(plan, layout).mcpServers["mandu-inspect"]!, opencodeInspectTimeoutMs(plan.ullmEndpointTimeoutMs)),
        // The policy agent surface (policy-surface.md §8.5.1), same server
        // the claude MCP config registers; --no-policy-mcp drops it alone.
        ...(input.policy !== false ? { [MANDU_POLICY_SERVER]: server(policyMcpServerEntry(plan, layout)) } : {}),
      }
    : {};
  const mcp: Json = !input.inspect ? {} : input.opencodeGeneration === 2 ? { mcp: { servers } } : { mcp: servers };
  const routes = input.openaiRoutes ?? [];
  return {
    ...mcp,
    // OpenCode 2 (supported-agents.md §2.3 part 4): the same fence in its
    // own spelling. `enabled_providers` below normalizes to the same rules,
    // but a user's `experimental.policies` merged into this doc would come
    // AFTER them in it and win; this array replaces the user's.
    // Code mode off as well (defense in depth: the proxy refuses `execute`
    // on the wire, §2.3 part 3): with `execute` denied, 2.x offers neither
    // the tool nor its catalog. Permission rules take the NORMAL precedence
    // (the last match wins and the inline layer comes last; measured on
    // 2.0.23: a project or global allow did not bring it back), but an
    // agent's own `permissions` allow does; withOpencodeV2Routing appends
    // this rule after the user's own in the same document.
    ...(input.opencodeGeneration === 2
      ? {
          experimental: { policies: opencodePolicyFence(["anthropic", ...routes.map((r) => r.id)]) },
          permissions: [OPENCODE_DENY_EXECUTE],
        }
      : {}),
    // Only the routed providers may load (agent-model-route.ts): `-m
    // google/…`, a configured unrouted model or a project config's custom
    // provider would otherwise go straight to that provider with tool results
    // unmasked. Probe-verified on 1.18.13 and 1.18.32: a fenced provider's
    // model fails before any request.
    enabled_providers: ["anthropic", ...routes.map((r) => r.id)],
    provider: {
      anthropic: {
        options: {
          baseURL: `${input.proxyUrl}/v1`,
          headers: sessionHeaders(input),
        },
      },
      // A routed OpenAI-family provider: its options.baseURL (which OpenCode
      // prefers over every model's own API URL) at the proxy's per-provider
      // prefix. Any wire its models speak lands there, and the proxy gates
      // Chat Completions and the Responses API and refuses the rest.
      ...Object.fromEntries(routes.map((r) => [r.id, {
        options: { baseURL: openaiRouteBaseUrl(input.proxyUrl, r.id), headers: sessionHeaders(input) },
      }])),
    },
  };
}

/**
 * The OPENCODE_CONFIG_CONTENT value: the routing keys of `ours` (the fence and
 * the anthropic provider's endpoint) merged OVER the user's own
 * OPENCODE_CONFIG_CONTENT, if any. WHY (probe-verified 2026-09-27, OpenCode
 * 1.18.13 and 1.18.32): OpenCode ranks a project's `opencode.json` /
 * `.opencode/opencode.json` ABOVE the OPENCODE_CONFIG file, so a repository's
 * own config re-pointed `provider.anthropic.options.baseURL` and every turn
 * left through it, around the proxy. OPENCODE_CONFIG_CONTENT outranks the
 * project config (a project that re-enables `openai` and a custom provider
 * stayed fenced). A user value that is not a JSON object is dropped with a
 * warning (the safe direction: routing kept, their inline settings lost).
 * Unless `opts.globalCode` (the global opt-in, or confidentiality off), the
 * user's `plugin` / `plugins` are dropped from it (§2.3 item 12).
 */
export function opencodeRoutingContent(
  ours: Json,
  userContent: string | undefined,
  warn: (msg: string) => void,
  opts: { globalCode?: boolean } = {},
): string {
  let theirs: Json = {};
  if (userContent !== undefined && userContent.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(userContent);
      // The user's inline plugin list is their own code (§2.3 item 12,
      // opencode-global-code.ts): dropped unless it may run.
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) theirs = opts.globalCode === true ? parsed as Json : withoutPlugins(parsed as Json).doc;
      else warn("agent-config: OPENCODE_CONFIG_CONTENT is not a JSON object — replaced by the Mandu routing keys");
    } catch {
      warn("agent-config: could not parse OPENCODE_CONFIG_CONTENT — replaced by the Mandu routing keys");
    }
  }
  const provider = ((ours["provider"] as Json | undefined) ?? {}) as Json;
  const routing: Json = { enabled_providers: ours["enabled_providers"], provider };
  if (ours["experimental"] !== undefined) routing["experimental"] = ours["experimental"];
  if (ours["permissions"] !== undefined) routing["permissions"] = ours["permissions"];
  return JSON.stringify(mergeConfig(theirs, withOpencodeV2Routing(theirs, routing)));
}

/** The MCP server timeout of an OpenCode launch, in ms (cold-start-safe). */
export const OPENCODE_MCP_TIMEOUT_MS = 30_000;

/** mandu-inspect's timeout in an OpenCode launch: the cold-start-safe 30 s,
 *  raised to the longest inspect_symbol call (ullm-timeout.ts
 *  `inspectCallBoundMs`) when the entry carries a U-LLM timeout (the user's,
 *  or the local default with a `local: true` model declared). OpenCode's
 *  timeout bounds each tool call too ("MCP error -32001: Request timed out",
 *  the blood-test demo on OpenCode, 2026-10-17). Pure. */
export function opencodeInspectTimeoutMs(ullmEndpointTimeoutMs: number | undefined): number {
  return ullmEndpointTimeoutMs === undefined ? OPENCODE_MCP_TIMEOUT_MS : Math.max(OPENCODE_MCP_TIMEOUT_MS, inspectCallBoundMs(ullmEndpointTimeoutMs));
}

/** One stdio MCP server in OpenCode 2's spelling (`mcp.servers.<name>`,
 *  schema `Mcp.LocalConfig` of 2.0.23), its tools offered as direct tools
 *  (`codemode: false`): the model then sees `<server>_<tool>`, the spelling
 *  inspect-tool.ts recognizes. Pure. */
export function opencodeV2McpServer(server: { command: string; args: string[]; env: Record<string, string> }, execution = OPENCODE_MCP_TIMEOUT_MS): Json {
  return {
    type: "local",
    command: [server.command, ...server.args],
    environment: server.env,
    codemode: false,
    timeout: { startup: OPENCODE_MCP_TIMEOUT_MS, catalog: OPENCODE_MCP_TIMEOUT_MS, execution },
  };
}

/** OpenCode 2's code mode, denied for a 2.x launch (`permissions` rule). */
export const OPENCODE_DENY_EXECUTE = { action: "execute", resource: "*", effect: "deny" } as const;

/**
 * OpenCode 2 reads `provider.<id>` (V1) and `providers.<id>` (V2) in one
 * document, and the V2 entry REPLACES the V1 one whole (probe-verified
 * 2026-10-05 on 2.0.23, `opencode debug config`). So a user doc with its own
 * `providers.anthropic` would drop the routing Mandu writes as
 * `provider.anthropic` from that layer: an OPENCODE_CONFIG_CONTENT of
 * `{"providers":{"anthropic":{"settings":{"baseURL":…}}}}` sent every turn
 * to that URL, around the proxy. For each routed provider the user's doc
 * spells in V2, the routing is written in V2 as well (base URL and session
 * headers merged over theirs); a provider they spell in V1 only keeps the V1
 * routing, so their V1 settings (an apiKey) are not dropped. OpenCode 1
 * rejects `providers`, and a 1.x user doc never has it. Mandu's permission
 * rules (the `execute` deny) are appended to the user's own `permissions`
 * array rather than replacing it: their rules (a deny of their own) keep
 * applying, and Mandu's, last, win.
 */
export function withOpencodeV2Routing(user: Json, ours: Json): Json {
  if (Array.isArray(ours["permissions"]) && Array.isArray(user["permissions"])) {
    ours = { ...ours, permissions: [...user["permissions"], ...ours["permissions"]] };
  }
  const v1 = isJsonObj(ours["provider"]) ? ours["provider"] : {};
  const theirsV2 = isJsonObj(user["providers"]) ? user["providers"] : {};
  const v2: Json = {};
  for (const [id, entry] of Object.entries(v1)) {
    if (!isJsonObj(theirsV2[id]) || !isJsonObj(entry) || !isJsonObj(entry["options"])) continue;
    const { baseURL, headers } = entry["options"];
    v2[id] = { settings: { baseURL }, ...(headers !== undefined ? { headers } : {}) };
  }
  return Object.keys(v2).length > 0 ? { ...ours, providers: v2 } : ours;
}

/**
 * The OpenClaw runtime fence: `agents.defaults.models` (OpenClaw's model
 * allowlist for `/model` and session overrides) narrowed to the anthropic
 * provider, on the MERGED doc so a user's own non-anthropic entries are
 * dropped too (mergeConfig keeps keys ours does not set). The launch-time
 * refusal (agent-model-route.ts) covers what the config and argv name; this
 * covers a switch mid-session. Probe-verified 2026-09-27: 2026.6.35 and
 * 2026.7.1 refuse `--model openai/gpt-5.5` ("is not allowed for agent
 * main") and run an allowed model instead of a non-anthropic primary;
 * 2026.9.6 refuses the override; 2026.3.12 does not enforce the allowlist
 * and runs normally with it. The user's anthropic entries (aliases, params)
 * are kept.
 */
export function fenceOpenclawModelAllowlist(merged: Json, routed: readonly string[] = []): Json {
  const agents = (merged["agents"] !== null && typeof merged["agents"] === "object" && !Array.isArray(merged["agents"])
    ? merged["agents"] : {}) as Json;
  const defaults = (agents["defaults"] !== null && typeof agents["defaults"] === "object" && !Array.isArray(agents["defaults"])
    ? agents["defaults"] : {}) as Json;
  const userAllow = (defaults["models"] !== null && typeof defaults["models"] === "object" && !Array.isArray(defaults["models"])
    ? defaults["models"] : {}) as Json;
  // The routed providers: anthropic, and each OpenAI-family provider the
  // launch routes (agent-model-route.ts).
  const providers = ["anthropic", ...routed];
  const allow: Json = Object.fromEntries(providers.map((p) => [`${p}/*`, {}]));
  for (const [ref, entry] of Object.entries(userAllow)) {
    const lower = ref.toLowerCase();
    if (providers.some((p) => lower.startsWith(`${p.toLowerCase()}/`))) allow[ref] = entry;
  }
  return { ...merged, agents: { ...agents, defaults: { ...defaults, models: allow } } };
}

/**
 * Which memory-search keys an OpenClaw release accepts. OpenClaw rejects a
 * config with a key its release does not know ("Unrecognized key"), so the
 * embeddings switch must be written in the release's own spelling:
 *   - "memory.search": `memory.search` (2026.8.1 and later; the per-agent
 *     override is `agents.entries.<id>.memory.search`);
 *   - "memorySearch": `agents.defaults.memorySearch` with `provider: "none"`
 *     (2026.6.35 through 2026.7.x; verified on 2026.6.35 and 2026.7.1);
 *   - "slot": the memory plugin slot set to "none", for everything else: a
 *     release before 2026.6.35 (2026.3.12's provider enum has no "none"), a
 *     version the launch could not read (a wrapper under --target), or a
 *     prerelease of a boundary release. Every release from 2026.3.12 to
 *     2026.9.6 accepts `plugins.slots.memory: "none"`, which unloads the
 *     memory tools.
 * Verified 2026-09-27 with `openclaw config validate` on 2026.3.12, 6.35,
 * 7.1, 8.2, 9.1 and 9.6, and by the schema marker in the 2026.4.1, 5.2, 6.1,
 * 7.33, 7.35 and 8.1 packages (7.35 is the last `memorySearch` release).
 */
export type OpenclawMemoryShape = "memory.search" | "memorySearch" | "slot";

export function openclawMemoryShape(version: string | null | undefined): OpenclawMemoryShape {
  const v = parseAgentVersion(version ?? null);
  if (v === null) return "slot";
  const NEW = parseAgentVersion("2026.8.1")!;
  const NONE = parseAgentVersion("2026.6.35")!;
  // A prerelease of a boundary release may have either shape.
  const sameTriple = (b: typeof v): boolean => b.parts.every((n, i) => n === v.parts[i]);
  if (v.prerelease !== null && (sameTriple(NEW) || sameTriple(NONE))) return "slot";
  if (compareAgentVersions(v, NEW) >= 0) return "memory.search";
  if (compareAgentVersions(v, NONE) >= 0) return "memorySearch";
  return "slot";
}

/** Embedding providers that keep the text on this machine. */
const LOCAL_EMBEDDINGS = new Set(["local"]);
/** The memory plugins whose embeddings the fence below controls. */
const FENCED_MEMORY_SLOTS = new Set(["memory-core", "none"]);

function isJsonObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * The OpenClaw embeddings fence: memory search runs on keywords only.
 *
 * WHY (probe-verified 2026-09-27 on 2026.3.12, 6.35, 7.1, 8.2 and 9.6 with a
 * URL-logging stand-in): OpenClaw's memory search embeds the memory files
 * (`MEMORY.md`, `memory/*.md`) and each query through its embedding provider,
 * OpenAI by default, straight to that provider: two of the stand-in's
 * `/v1/embeddings` requests carried the memory text verbatim. Mandu routes
 * only the Anthropic model provider, so that text left around Mandu, with
 * nothing masked. With the provider set to "none" the same run made no
 * embeddings request and `memory_search` still answered from its keyword
 * index; with the memory slot set to "none" the memory tools are gone and
 * nothing is sent.
 *
 * On the MERGED doc, so a user's own setting at any level is overridden:
 * every memory-search object (top-level `memory.search`, legacy top-level
 * and per-agent `memorySearch`, per-agent `memory.search`) gets
 * `provider: "none"` and `fallback: "none"`, except an explicit "local"
 * provider (embeddings computed on this machine), which is kept. Legacy
 * `memorySearch` objects are fenced in the new shape too: OpenClaw's startup
 * migration would carry their provider to `memory.search`. A memory plugin
 * other than memory-core (memory-lancedb embeds through its own config) has
 * its slot set to "none". Pure; returns the lines to print.
 */
export function fenceOpenclawMemorySearch(
  merged: Json,
  version: string | null | undefined,
): { doc: Json; warnings: string[]; notes: string[] } {
  const shape = openclawMemoryShape(version);
  const warnings: string[] = [];
  const notes: string[] = [];
  const overridden = new Set<string>();
  const doc = structuredClone(merged);

  const plugins = isJsonObj(doc["plugins"]) ? doc["plugins"] : {};
  const slots = isJsonObj(plugins["slots"]) ? plugins["slots"] : {};
  const slot = slots["memory"];
  const setSlotNone = (): void => {
    doc["plugins"] = { ...plugins, slots: { ...slots, memory: "none" } };
  };

  if (typeof slot === "string" && !FENCED_MEMORY_SLOTS.has(slot)) {
    setSlotNone();
    warnings.push(
      `the OpenClaw memory plugin "${slot}" is off under Mandu: its embeddings would send your memory text to its ` +
      "provider directly, around Mandu. Run openclaw without mandu to use it.",
    );
    return { doc, warnings, notes };
  }
  if (slot === "none") return { doc, warnings, notes };

  const fence = (o: Json): void => {
    const p = o["provider"];
    if (typeof p === "string" && LOCAL_EMBEDDINGS.has(p)) {
      if (typeof o["fallback"] === "string" && o["fallback"] !== "none") overridden.add(`fallback ${o["fallback"]}`);
      o["fallback"] = "none";
      return;
    }
    if (typeof p === "string" && p !== "none" && p !== "auto") overridden.add(p);
    if (typeof o["fallback"] === "string" && o["fallback"] !== "none") overridden.add(`fallback ${o["fallback"]}`);
    if (shape === "slot") return;
    o["provider"] = "none";
    o["fallback"] = "none";
  };
  // Every memory-search object under `node`: a `memorySearch` value, or the
  // `search` value of a `memory` object.
  const walk = (node: unknown, key: string, parentKey: string): void => {
    if (Array.isArray(node)) { for (const n of node) walk(n, "[]", key); return; }
    if (!isJsonObj(node)) return;
    if (key === "memorySearch" || (key === "search" && parentKey === "memory")) fence(node);
    for (const [k, v] of Object.entries(node)) walk(v, k, key);
  };
  if (isJsonObj(doc["memory"]) && isJsonObj(doc["memory"]["search"])) fence(doc["memory"]["search"]);
  if (isJsonObj(doc["memorySearch"])) fence(doc["memorySearch"]);
  walk(doc["agents"], "agents", "");

  if (shape === "memory.search") {
    const memory = isJsonObj(doc["memory"]) ? doc["memory"] : {};
    const search = isJsonObj(memory["search"]) ? memory["search"] : {};
    if (!isJsonObj(memory["search"])) { search["provider"] = "none"; search["fallback"] = "none"; }
    doc["memory"] = { ...memory, search };
  } else if (shape === "memorySearch") {
    const agents = isJsonObj(doc["agents"]) ? doc["agents"] : {};
    const defaults = isJsonObj(agents["defaults"]) ? agents["defaults"] : {};
    const ms = isJsonObj(defaults["memorySearch"]) ? defaults["memorySearch"] : {};
    if (!isJsonObj(defaults["memorySearch"])) { ms["provider"] = "none"; ms["fallback"] = "none"; }
    doc["agents"] = { ...agents, defaults: { ...defaults, memorySearch: ms } };
  } else {
    setSlotNone();
    warnings.push(
      `OpenClaw's memory tools are off under Mandu for OpenClaw ${version ?? "(version not read)"}: memory search would ` +
      "send your memory text to its embedding provider directly, around Mandu, and Mandu can switch only the " +
      "embeddings off on OpenClaw 2026.6.35 and later.",
    );
    return { doc, warnings, notes };
  }
  if (overridden.size > 0) {
    warnings.push(
      `OpenClaw memory search runs on keywords only under Mandu: your embedding setting (${[...overridden].join(", ")}) ` +
      "would send your memory text to that provider directly, around Mandu. Run openclaw without mandu to use it.",
    );
  } else {
    notes.push("OpenClaw memory search runs on keywords only (embeddings off: they would send memory text around Mandu)");
  }
  return { doc, warnings, notes };
}

/** The exec hosts that run on this machine, inside the session's box
 *  (OpenClaw's own spelling, lowercased and trimmed as it reads them).
 *  "sandbox" runs in OpenClaw's Docker sandbox, listed in
 *  supported-agents.md §2.1 as outside the claim, not a paired device. */
const LOCAL_EXEC_HOSTS = new Set(["auto", "sandbox", "gateway"]);

/**
 * The OpenClaw exec-host fence (supported-agents.md §2.1): `tools.exec.host:
 * "node"` sends every `exec` that names no host to a paired device, outside
 * Mandu's box (read from OpenClaw 2026.9.6 exec-defaults.ts: a call's own
 * host, else the session's, else the agent's `tools.exec.host`, else the
 * global one, else "auto"). The proxy refuses a call that names such a host
 * (the refuseArgs table), but cannot see this default. On the MERGED doc,
 * every `tools.exec.host` (the global one, and each agent's under `agents`)
 * that is not a local host is removed, so the default ("auto": the sandbox if
 * one is on, else this machine) applies. A session's own `/exec host=node`
 * setting lives in OpenClaw's session store, not in this file (listed in
 * supported-agents.md §4). Pure; returns the lines to print.
 */
export function fenceOpenclawExecHost(merged: Json): { doc: Json; warnings: string[] } {
  const doc = structuredClone(merged);
  const removed: string[] = [];
  const fence = (tools: unknown, where: string): void => {
    if (!isJsonObj(tools) || !isJsonObj(tools["exec"])) return;
    const exec = tools["exec"];
    const host = exec["host"];
    if (host === undefined) return;
    const norm = typeof host === "string" ? host.trim().toLowerCase() : "";
    if (norm === "" || LOCAL_EXEC_HOSTS.has(norm)) return;
    delete exec["host"];
    removed.push(`${where}.tools.exec.host "${String(host)}"`);
  };
  fence(doc["tools"], "");
  const walk = (node: unknown, where: string): void => {
    if (Array.isArray(node)) { node.forEach((n, i) => walk(n, `${where}[${i}]`)); return; }
    if (!isJsonObj(node)) return;
    for (const [k, v] of Object.entries(node)) {
      if (k === "tools") fence(v, where);
      else walk(v, where ? `${where}.${k}` : k);
    }
  };
  walk(doc["agents"], "agents");
  const warnings = removed.length > 0
    ? [`OpenClaw runs commands on this machine under Mandu: ${removed.map((r) => r.replace(/^\./, "")).join(", ")} would send them to a paired device, outside Mandu's sandbox, so it is not used for this run.`]
    : [];
  return { doc, warnings };
}

/** The first OpenClaw release whose config schema has `tools.codeMode`
 *  (read from the published packages: 2026.5.12 has none, 2026.5.18 has the
 *  global and the per-agent key; no release lies between). Earlier releases
 *  reject the unknown key. */
const OPENCLAW_CODE_MODE_SINCE = "2026.5.18";

/** Does this OpenClaw release accept `tools.codeMode`? A version the launch
 *  could not read, or a prerelease of the boundary release, does not say. */
export function openclawHasCodeModeKey(version: string | null | undefined): boolean {
  const v = parseAgentVersion(version ?? null);
  if (v === null) return false;
  const since = parseAgentVersion(OPENCLAW_CODE_MODE_SINCE)!;
  if (v.prerelease !== null && since.parts.every((n, i) => n === v.parts[i])) return false;
  return compareAgentVersions(v, since) >= 0;
}

/** The first OpenClaw release whose config has `tools.web.fetch.
 *  useTrustedEnvProxy` (read from the published packages: 2026.5.2 has none,
 *  2026.5.3 has it). */
const OPENCLAW_WEB_FETCH_ENV_PROXY_SINCE = "2026.5.3";
/** The first OpenClaw release whose managed proxy (`proxy.proxyUrl`) leaves
 *  loopback traffic direct (proxy-lifecycle.ts `managedLoopbackBypassPolicy`,
 *  2026.9.6; 2026.9.5 has none). Before it the managed proxy sends the model
 *  call to the loopback context proxy through the forward proxy too
 *  (measured on 2026.7.1-2: a CONNECT to 127.0.0.1), so it is not used. */
const OPENCLAW_MANAGED_PROXY_SINCE = "2026.9.6";

/** Whether `version` is `since` or later. An unreadable version, or a
 *  prerelease of the boundary release, does not say. */
function openclawAtLeast(version: string | null | undefined, since: string): boolean {
  const v = parseAgentVersion(version ?? null);
  if (v === null) return false;
  const at = parseAgentVersion(since)!;
  if (v.prerelease !== null && at.parts.every((n, i) => n === v.parts[i])) return false;
  return compareAgentVersions(v, at) >= 0;
}

/**
 * The OpenClaw web-egress fence (supported-agents.md §2.1, 2026-10-09).
 * OpenClaw fetches over its own SSRF guard, which resolves the host itself
 * and connects DIRECTLY in its default "strict" mode: `web_fetch` and the
 * URL references the media tools load (image, view_image, pdf, …) ignore
 * HTTPS_PROXY, so under Mandu they bypassed the net-proxy (its egress gate,
 * TLS inspection and verbatim-secret tripwire) and left through the kernel
 * rungs' any-host :443. Measured with a fake model and a logging proxy, no
 * Mandu: 2026.7.1-2 and 2026.9.9 send web_fetch direct; with
 * `tools.web.fetch.useTrustedEnvProxy` both send it to the proxy; with the
 * managed proxy (`proxy.proxyUrl`) 2026.9.9 sends it to the proxy and keeps
 * the loopback model call direct, while 2026.7.1-2 sends the model call to
 * the proxy too. What rides the environment already (web_search's provider
 * endpoints, MCP HTTP servers: `useEnvProxy`) is untouched.
 *
 * With a net-proxy (`netProxyUrl`), per release:
 *   - 2026.9.6 and later: the managed proxy, pointed at the net-proxy
 *     (`proxy: {enabled, proxyUrl, loopbackMode: "gateway-only"}`): every
 *     strict fetch of the process goes through it, loopback stays direct;
 *     and `useTrustedEnvProxy` too.
 *   - 2026.5.3 to 2026.9.5: `useTrustedEnvProxy` (web_fetch). The media
 *     tools' URL references still connect direct; the model-context gate
 *     judges them (tool-gate-surface.ts `alsoDestinations`).
 *   - older, or a version the launch cannot read: `web_fetch` is denied
 *     (`tools.deny`, merged with the user's), since nothing routes it.
 * The user's own `proxy` and `useTrustedEnvProxy` settings are replaced for
 * this run, with a note. No net-proxy (the rung off): nothing to route to,
 * the doc is returned unchanged. Pure.
 */
export function fenceOpenclawWebEgress(
  merged: Json,
  version: string | null | undefined,
  netProxyUrl: string | undefined,
): { doc: Json; warnings: string[]; notes: string[] } {
  if (netProxyUrl === undefined) return { doc: merged, warnings: [], notes: [] };
  const doc = structuredClone(merged);
  const warnings: string[] = [];
  const notes: string[] = [];
  const tools = isJsonObj(doc["tools"]) ? doc["tools"] : (doc["tools"] = {});
  if (openclawAtLeast(version, OPENCLAW_WEB_FETCH_ENV_PROXY_SINCE)) {
    const web = isJsonObj(tools["web"]) ? tools["web"] : (tools["web"] = {});
    const fetch = isJsonObj(web["fetch"]) ? web["fetch"] : (web["fetch"] = {});
    if (fetch["useTrustedEnvProxy"] === false) notes.push("OpenClaw's web_fetch goes through Mandu's network proxy for this session (your tools.web.fetch.useTrustedEnvProxy: false applies without Mandu).");
    fetch["useTrustedEnvProxy"] = true;
    if (openclawAtLeast(version, OPENCLAW_MANAGED_PROXY_SINCE)) {
      const own = isJsonObj(doc["proxy"]) ? doc["proxy"] : undefined;
      if (own && (typeof own["proxyUrl"] === "string" || own["enabled"] !== undefined)) {
        warnings.push("your OpenClaw proxy setting is replaced for this session: OpenClaw's own web requests go through Mandu's network proxy, which reaches the network directly (your proxy applies without Mandu).");
      }
      doc["proxy"] = { enabled: true, proxyUrl: netProxyUrl, loopbackMode: "gateway-only" };
    }
  } else {
    const deny = Array.isArray(tools["deny"]) ? tools["deny"].filter((t): t is string => typeof t === "string") : [];
    if (!deny.includes("web_fetch")) tools["deny"] = [...deny, "web_fetch"];
    const v = parseAgentVersion(version ?? null);
    warnings.push(
      `OpenClaw's web_fetch is off under Mandu on ${v ? `OpenClaw ${v.raw}` : "an OpenClaw release Mandu cannot read"}: before 2026.5.3 it connects to the web itself, around Mandu's network proxy. Update OpenClaw to use it, or fetch with curl through the shell.`,
    );
  }
  return { doc, warnings, notes };
}

/**
 * The OpenClaw Code Mode fence (supported-agents.md §2.1, decided 2026-10-09).
 * Code Mode replaces the model's tools with `exec{code}` and `wait{runId}`:
 * the model writes JavaScript that calls the tools inside OpenClaw, where no
 * wire gate reads which tool gets which input (§5.3.4 refuses code mode for
 * every agent). The proxy refuses both on the wire (tool-gate-surface.ts);
 * this keeps OpenClaw from offering them at all. Read from 2026.9.9
 * code-mode-state.ts: the setting is `tools.codeMode` (an absent one means
 * "auto" from 2026.9.x: on for models whose catalog entry is flagged
 * preferred, Claude Opus 5 and GPT-5.5 among them), overridden per agent by
 * `agents.list[].tools.codeMode`, and per model by `agents.defaults.models.
 * <ref>.codeMode` and `agents.list[].models.<ref>.codeMode`.
 *
 * On the MERGED doc: every `codeMode` the user set, at any of those levels,
 * becomes `false` (a key the user wrote is one their release accepts), with
 * a WARNING when it would have turned Code Mode on; and where the release
 * accepts the key (openclawHasCodeModeKey) the global `tools.codeMode: false`
 * is written too, so 2026.9.x's "auto" never applies. Pure.
 */
export function fenceOpenclawCodeMode(merged: Json, version: string | null | undefined): { doc: Json; warnings: string[] } {
  const doc = structuredClone(merged);
  const enabling: string[] = [];
  const turnsOn = (v: unknown): boolean =>
    v === true || v === "auto" || (isJsonObj(v) && (v["enabled"] === true || v["enabled"] === "auto"));
  const fence = (holder: Json, where: string): void => {
    if (!Object.prototype.hasOwnProperty.call(holder, "codeMode")) return;
    if (turnsOn(holder["codeMode"])) enabling.push(`${where}.codeMode`);
    holder["codeMode"] = false;
  };
  if (isJsonObj(doc["tools"])) fence(doc["tools"], "tools");
  const walk = (node: unknown, where: string): void => {
    if (Array.isArray(node)) { node.forEach((n, i) => walk(n, `${where}[${i}]`)); return; }
    if (!isJsonObj(node)) return;
    fence(node, where);
    for (const [k, v] of Object.entries(node)) walk(v, `${where}.${k}`);
  };
  walk(doc["agents"], "agents");
  if (openclawHasCodeModeKey(version)) {
    const tools = isJsonObj(doc["tools"]) ? doc["tools"] : (doc["tools"] = {});
    (tools as Json)["codeMode"] = false;
  }
  const warnings = enabling.length > 0
    ? [`OpenClaw Code Mode is off under Mandu: its JavaScript calls tools inside OpenClaw, where Mandu cannot check them, so ${enabling.join(", ")} is not used for this run.`]
    : [];
  return { doc, warnings };
}

/**
 * The OpenClaw workspace pin (supported-agents.md §5.5 item 5; decided 2026-09-29).
 * OpenClaw's workspace is the default cwd of its file tools and the folder
 * whose AGENTS.md, SOUL.md, USER.md, MEMORY.md, … it loads into the model's
 * context every session. Unset, it is `~/.openclaw/workspace`: outside the
 * project, and under the frozen integrity axis outside the AgentView twin.
 * For the shapes whose agent loop runs in this launch (`chat`, `terminal`,
 * `tui --local`, `agent --local`: openclaw-argv.ts openclawRunsLocally) it is
 * pinned to the agent's working directory, the launch directory (under
 * `secrets`, the directory the human launched from; under the frozen
 * integrity axis, its AgentView twin). The whole-agent secret-twins wrap is a
 * mask over the same paths (`--dev-bind / /` plus a bind per secret), so the
 * path is the same inside it, and a labelled file OpenClaw loads from there
 * reaches it as the twin: the same ingress as Claude Code's CLAUDE.md.
 *
 * `skipBootstrap: true` goes with it: OpenClaw (2026.6.35 workspace.ts
 * `ensureAgentWorkspace`) otherwise writes its seven persona files (AGENTS.md,
 * SOUL.md, TOOLS.md, IDENTITY.md, USER.md, HEARTBEAT.md, BOOTSTRAP.md) and a
 * workspace state file into a workspace that lacks them, i.e. into the
 * user's project. A project's own AGENTS.md is still read.
 *
 * On the MERGED doc: the user's own `agents.defaults.workspace` and each
 * `agents.list[].workspace` are replaced for this run (their file is not
 * touched) and named in a note. A non-default agent with no workspace of its
 * own gets `<launch dir>/<id>` by OpenClaw's rule. Every other shape (the
 * Gateway, a wrapper) keeps the user's setting. Pure.
 */
export function fenceOpenclawWorkspace(
  merged: Json,
  argv: readonly string[],
  cwd: string,
): { doc: Json; notes: string[] } {
  if (!openclawRunsLocally(argv)) return { doc: merged, notes: [] };
  const doc = structuredClone(merged);
  const agents = isJsonObj(doc["agents"]) ? doc["agents"] : {};
  const defaults = isJsonObj(agents["defaults"]) ? agents["defaults"] : {};
  const replaced: string[] = [];
  // A relative workspace resolves against the launch CWD (OpenClaw's
  // resolveUserPath), so `.` already names it: nothing replaced, no note.
  const sameDir = (ws: string): boolean => !ws.trim().startsWith("~") && resolve(cwd, ws.trim()) === resolve(cwd);
  const own = defaults["workspace"];
  if (typeof own === "string" && own.trim() !== "" && !sameDir(own)) replaced.push(`agents.defaults.workspace "${own}"`);
  const list = Array.isArray(agents["list"]) ? agents["list"] : undefined;
  const newList = list?.map((entry, i) => {
    if (!isJsonObj(entry) || entry["workspace"] === undefined) return entry;
    const ws = entry["workspace"];
    if (typeof ws !== "string" || !sameDir(ws)) replaced.push(`agents.list[${typeof entry["id"] === "string" ? entry["id"] : i}].workspace "${String(ws)}"`);
    return { ...entry, workspace: cwd };
  });
  doc["agents"] = {
    ...agents,
    defaults: { ...defaults, workspace: cwd, skipBootstrap: true },
    ...(newList !== undefined ? { list: newList } : {}),
  };
  const notes = [`OpenClaw works in ${cwd} for this session (its workspace, without its starter files).`];
  if (replaced.length > 0) notes.push(`your ${replaced.join(", ")} applies when you run OpenClaw without Mandu.`);
  return { doc, notes };
}

/**
 * OpenCode's sign-in type per provider, from its auth store
 * (`$XDG_DATA_HOME/opencode/auth.json`, default ~/.local/share): "api",
 * "oauth" or "wellknown". The model check refuses routing OpenAI when it is
 * "oauth" (agent-model-route.ts opencodeProviderVerdict). A missing or
 * unreadable file is {} (no sign-in known).
 */
export function readOpencodeAuthTypes(
  env: Record<string, string | undefined> = process.env,
  home = homedir(),
): OpencodeAuthTypes {
  const path = join(env["XDG_DATA_HOME"] || join(home, ".local", "share"), "opencode", "auth.json");
  try {
    const v: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!isJsonObj(v)) return {};
    const out: Record<string, string> = {};
    for (const [id, entry] of Object.entries(v)) if (isJsonObj(entry) && typeof entry["type"] === "string") out[id] = entry["type"];
    return out;
  } catch {
    return {};
  }
}

/** A truthy OpenCode env flag. Only the plain spellings count, so a value the
 *  launcher reads differently from OpenCode makes it read MORE layers. */
function envFlag(v: string | undefined): boolean {
  return v !== undefined && /^(1|true)$/i.test(v.trim());
}

/** OpenCode 2's config file names, in the order it lists them. */
const OPENCODE_CONFIG_NAMES = ["opencode.json", "opencode.jsonc"] as const;

function realOrSelf(p: string): string {
  try { return realpathSync(p); } catch { return resolve(p); }
}

/**
 * Every config layer OpenCode 2 reads for a session started in `dirs`
 * (opencode-config.ts; probe-verified 2026-10-05 on 2.0.23 with `opencode
 * debug config`), lowest first:
 *   - the global config dir: `$OPENCODE_CONFIG_DIR`, else
 *     `$XDG_CONFIG_HOME/opencode` (`~/.config/opencode`): `opencode.json`,
 *     `opencode.jsonc`;
 *   - the user's `OPENCODE_CONFIG` file;
 *   - the project files of each start directory AND EVERY ANCESTOR up to `/`
 *     (OpenCode 2 does not stop at the repository root): `opencode.json(c)`
 *     from the outermost down, then `.opencode/opencode.json(c)` likewise.
 *     Skipped when `OPENCODE_DISABLE_PROJECT_CONFIG` (or
 *     `OPENCODE_CONFIG_PROJECT_DISABLE`) is set, and for a start directory
 *     that is the global config dir, as OpenCode 2 does;
 *   - the user's `OPENCODE_CONFIG_CONTENT` (one that does not parse as a
 *     JSON object is replaced by Mandu's routing, so OpenCode never sees it).
 * A file that does not parse is listed in `unreadable`: the model check
 * refuses it rather than guess what OpenCode 2 makes of it. With several
 * start directories (the launch cwd and a directory argument) every one's
 * project files are read: reading more layers only makes the check stricter.
 */
export function readOpencodeConfigLayers(
  env: Record<string, string | undefined>,
  dirs: readonly string[],
  home = homedir(),
): OpencodeV2Input {
  const layers: OpencodeLayer[] = [];
  const unreadable: Array<{ path: string; reason: string }> = [];
  const seen = new Set<string>();
  const add = (kind: OpencodeLayer["kind"], path: string): void => {
    const real = realOrSelf(path);
    if (seen.has(real)) return;
    let isFile = false;
    try { isFile = statSync(path).isFile(); } catch { return; }
    if (!isFile) return;
    seen.add(real);
    try {
      layers.push({ kind, path, doc: parseAgentConfigText(readFileSync(path, "utf8")) });
    } catch (e) {
      unreadable.push({ path, reason: e instanceof Error ? e.message : String(e) });
    }
  };
  const globalDir = env["OPENCODE_CONFIG_DIR"] || join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "opencode");
  for (const n of OPENCODE_CONFIG_NAMES) add("global", join(globalDir, n));
  if (env["OPENCODE_CONFIG"]) add("file", resolve(env["OPENCODE_CONFIG"]));
  const noProject = envFlag(env["OPENCODE_CONFIG_PROJECT_DISABLE"] ?? env["OPENCODE_DISABLE_PROJECT_CONFIG"]);
  if (!noProject) {
    const globalReal = realOrSelf(globalDir);
    for (const start of dirs) {
      if (realOrSelf(start) === globalReal) continue;
      const chain: string[] = [];
      for (let d = resolve(start); ; d = dirname(d)) { chain.unshift(d); if (dirname(d) === d) break; }
      for (const d of chain) for (const n of OPENCODE_CONFIG_NAMES) add("project", join(d, n));
      for (const d of chain) for (const n of OPENCODE_CONFIG_NAMES) add("project", join(d, ".opencode", n));
    }
  }
  const content = env["OPENCODE_CONFIG_CONTENT"];
  if (content !== undefined && content.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(content);
      if (isJsonObj(parsed)) layers.push({ kind: "inline", path: "OPENCODE_CONFIG_CONTENT", doc: parsed });
    } catch { /* replaced by Mandu's routing (opencodeRoutingContent) */ }
  }
  return { layers, unreadable };
}

/**
 * The OpenCode 2 input of the launch-time model check, or undefined for an
 * OpenCode 1 launch (which reads only its own config, userConfigPath). The
 * start directories: the launch cwd, and the directory argument of the bare
 * `opencode <dir>` form when it names one.
 */
export function opencodeV2Input(
  argv: readonly string[],
  version: string | null | undefined,
  env: Record<string, string | undefined>,
  cwd: string,
  home = homedir(),
): OpencodeV2Input | undefined {
  if (opencodeGeneration(argv[0], version) !== 2) return undefined;
  const dirs = [cwd];
  const first = argv[1];
  if (first !== undefined && !first.startsWith("-")) {
    try { if (statSync(resolve(cwd, first)).isDirectory()) dirs.push(resolve(cwd, first)); } catch { /* not a directory */ }
  }
  return readOpencodeConfigLayers(env, dirs, home);
}

// ─── OpenCode 2: no config layer the session can change (§2.3 item 8) ────────

/** The launcher-owned directory a 2.x launch hands OpenCode as its config
 *  dir, inside the scope run dir (write-protected for the agent's tree,
 *  run.ts / opencodeWriteProtect). */
export const OPENCODE_CONFIG_DIR_NAME = "opencode-config";
/** The run file inside it (OPENCODE_CONFIG): not a name OpenCode reads as a
 *  config document of the directory itself. */
export const OPENCODE_RUN_FILE = "mandu-run.json";

export function opencodeConfigDirOf(scopeRunDir: string): string {
  return join(scopeRunDir, OPENCODE_CONFIG_DIR_NAME);
}

/**
 * The env that keeps every OpenCode 2 config layer out of the session's
 * reach. WHY (measured 2026-10-05 on 2.0.23, launcher test
 * component/opencode-v2-config.test.ts): 2.x reloads its config files during
 * a session, through its file watcher (a project, `.opencode`, ancestor or
 * global `opencode.json` written mid-turn, even a NEW one, applied to the
 * next model request) and through its API's `POST /api/location/reload`,
 * which any process of the user can call with the private server's password
 * (in that server's /proc environ). A model endpoint written then took the
 * next request, tool result included, around the proxy. So:
 *   - OPENCODE_DISABLE_FILEWATCHER (and its alias): no reload on a write;
 *   - OPENCODE_DISABLE_PROJECT_CONFIG (and its alias): no project layer at
 *     all, at launch or on a reload; the launcher merged the checked project
 *     documents into the run file instead (opencodeV2UserDoc);
 *   - OPENCODE_CONFIG_DIR at the launcher's own directory: no global layer
 *     the session can write; the user's global documents are merged into the
 *     run file, and the rest of their global and project `.opencode`
 *     directories is linked in (buildOpencodeConfigDir);
 *   - OPENCODE_CONFIG at the run file in that directory.
 * Left: the inline OPENCODE_CONFIG_CONTENT (fixed for the process) and the
 * launcher's directory, which the whole-agent guard keeps the agent's tree
 * from writing (a deny entry, opencodeWriteProtect). OpenCode 1 does not
 * reload (measured on 1.18.13) and is not given any of this.
 */
export function opencodeLockdownEnv(configDir: string): Record<string, string> {
  return {
    OPENCODE_CONFIG_DIR: configDir,
    OPENCODE_DISABLE_PROJECT_CONFIG: "1",
    OPENCODE_CONFIG_PROJECT_DISABLE: "1",
    OPENCODE_DISABLE_FILEWATCHER: "1",
    OPENCODE_FILEWATCHER_DISABLE: "1",
  };
}

/** The guard's deny entry for a 2.x launch's config directory: a write into
 *  it (a new `opencode.json` included) is refused like Mandu's own files. */
export function opencodeWriteProtect(scopeRunDir: string): { path: string; answer: "deny"; label: string } {
  return { path: opencodeConfigDirOf(scopeRunDir), answer: "deny", label: "Mandu's own files" };
}

/**
 * The user's OpenCode 2 configuration as one document: every file layer
 * OpenCode 2 would have read for `cwd` (readOpencodeConfigLayers: the global
 * dir, OPENCODE_CONFIG, every ancestor's project files), merged lowest first.
 * The inline layer stays in OPENCODE_CONFIG_CONTENT. The launch-time check
 * (opencodeV2ModelPlan) read the same layers and refused what would route
 * around the proxy; a file that does not parse was refused there and is
 * skipped here with a warning.
 */
export function opencodeV2UserDoc(
  env: Record<string, string | undefined>,
  cwd: string,
  warn: (msg: string) => void,
  home = homedir(),
  opts: { projectCode?: boolean; globalCode?: boolean } = {},
): Json {
  const read = readOpencodeConfigLayers(env, [cwd], home);
  for (const u of read.unreadable) warn(`agent-config: could not parse ${u.path} (${u.reason}) — not carried into this run`);
  // `~/.opencode` is the user's own, though OpenCode 2 reads it as an
  // ancestor's project directory.
  const userDirs = new Set(userOpencodeDirs(env, home).map(realOrSelf));
  let doc: Json = {};
  for (const l of read.layers) {
    if (l.kind === "inline") continue;
    // A plugin list is code: a project's runs only with the project opt-out
    // (§2.3 item 11, opencode-project-code.ts), the user's own (the global
    // documents, OPENCODE_CONFIG, ~/.opencode's) only with the global opt-in
    // (§2.3 item 12, opencode-global-code.ts).
    const own = l.kind === "global" || l.kind === "file" || userDirs.has(realOrSelf(dirname(l.path)));
    const runs = own ? opts.globalCode === true : opts.projectCode === true;
    doc = mergeConfig(doc, runs ? l.doc : withoutPlugins(l.doc).doc);
  }
  return doc;
}

/** Files of a `.opencode` directory that are not linked into the launcher's
 *  directory: the config documents (merged into the run file), the
 *  instructions (composed), and a project's package files (the global
 *  directory's own `node_modules` serve its plugins). */
const OPENCODE_DIR_SKIP = new Set(["opencode.json", "opencode.jsonc", "AGENTS.md"]);
const OPENCODE_PROJECT_SKIP = new Set([...OPENCODE_DIR_SKIP, "node_modules", "package.json", "package-lock.json", "bun.lock", "bun.lockb", ".gitignore"]);
/** A project's `.opencode` without its code directories (plugins, custom
 *  tools): §2.3 item 11, opencode-project-code.ts. */
const OPENCODE_PROJECT_CODE_SKIP = new Set([...OPENCODE_PROJECT_SKIP, ...OPENCODE_CODE_DIRS]);
/** The global directory without its code directories: §2.3 item 12,
 *  opencode-global-code.ts. */
const OPENCODE_GLOBAL_CODE_SKIP = new Set([...OPENCODE_DIR_SKIP, ...OPENCODE_CODE_DIRS]);

/** The project directories OpenCode 2 reads `.opencode` from (every
 *  ancestor of `cwd`, outermost first) and AGENTS.md from (`cwd` up to the
 *  repository root, outermost first). */
function projectChain(cwd: string): { dotDirs: string[]; agentsMd: string[] } {
  const chain: string[] = [];
  for (let d = resolve(cwd); ; d = dirname(d)) { chain.unshift(d); if (dirname(d) === d) break; }
  const gitRoot = [...chain].reverse().find((d) => existsSync(join(d, ".git")));
  const inRepo = gitRoot === undefined ? [resolve(cwd)] : chain.slice(chain.indexOf(gitRoot));
  return { dotDirs: chain.map((d) => join(d, ".opencode")), agentsMd: inRepo.map((d) => join(d, "AGENTS.md")) };
}

function isDir(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

/** Link `src`'s entries into `dest` (lowest source first, a later one
 *  replacing an entry of the same name): a top-level directory becomes a
 *  real directory of links to its entries, so the global and every project
 *  `.opencode` can each add agents, commands or skills. */
function linkEntries(src: string, dest: string, skip: ReadonlySet<string>, whole: ReadonlySet<string>): void {
  let names: string[];
  try { names = readdirSync(src); } catch { return; }
  const link = (target: string, at: string): void => {
    try { if (lstatSync(at)) rmSync(at, { recursive: true, force: true }); } catch { /* absent */ }
    symlinkSync(target, at);
  };
  for (const name of names) {
    if (skip.has(name)) continue;
    const from = join(src, name), at = join(dest, name);
    if (isDir(from) && !whole.has(name)) {
      try { if (lstatSync(at).isSymbolicLink()) rmSync(at, { force: true }); } catch { /* absent */ }
      mkdirSync(at, { recursive: true });
      let kids: string[] = [];
      try { kids = readdirSync(from); } catch { /* unreadable */ }
      for (const k of kids) link(join(from, k), join(at, k));
    } else {
      link(from, at);
    }
  }
}

/**
 * Build the launcher's OpenCode 2 config directory (OPENCODE_CONFIG_DIR): the
 * user's global config directory and every project `.opencode` linked in
 * (agents, commands, skills, plugins, themes: measured, a linked agent loads
 * and runs), minus the config documents, which are merged into the run file;
 * and one AGENTS.md composed of the global one and the project's (cwd up to
 * the repository root), which OpenCode 2 no longer reads from the project
 * with project config off (measured; the `instructions` key did not bring it
 * back). A snapshot: a change to the user's files during the session applies
 * to the next launch. Links point into the user's own directories, which the
 * agent can write; what they can hold is not a config document (an agent's
 * `request.settings.baseURL` or `options.baseURL` in its markdown did not
 * move a request, measured). A project's `plugin`, `plugins`, `tool` and
 * `tools` directories are NOT linked (unless `opts.projectCode`: the opt-out,
 * or confidentiality off): a plugin runs inside OpenCode and writes the
 * model request itself, past every check (§2.3 item 11,
 * opencode-project-code.ts). Nor are the user's own (the global dir,
 * `~/.opencode`) unless `opts.globalCode` (the global opt-in, or
 * confidentiality off; §2.3 item 12, opencode-global-code.ts).
 */
export function buildOpencodeConfigDir(
  dir: string,
  env: Record<string, string | undefined>,
  cwd: string,
  warn: (msg: string) => void,
  home = homedir(),
  opts: { projectCode?: boolean; globalCode?: boolean } = {},
): void {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const globalDir = env["OPENCODE_CONFIG_DIR"] || join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "opencode");
  const { dotDirs, agentsMd } = projectChain(cwd);
  // A project's `.opencode` plugins and tools are left out unless the
  // project opt-out runs them (§2.3 item 11); the user's own (the global dir,
  // `~/.opencode`) unless the global opt-in does (§2.3 item 12).
  const userDirs = new Set(userOpencodeDirs(env, home).map(realOrSelf));
  const globalCode = opts.globalCode === true;
  try {
    if (resolve(globalDir) !== resolve(dir)) linkEntries(globalDir, dir, globalCode ? OPENCODE_DIR_SKIP : OPENCODE_GLOBAL_CODE_SKIP, new Set(["node_modules"]));
    for (const d of dotDirs) {
      if (realOrSelf(d) === realOrSelf(globalDir)) continue;
      const runs = userDirs.has(realOrSelf(d)) ? globalCode : opts.projectCode === true;
      linkEntries(d, dir, runs ? OPENCODE_PROJECT_SKIP : OPENCODE_PROJECT_CODE_SKIP, new Set());
    }
  } catch (e) {
    warn(`agent-config: could not link your OpenCode agents, commands or skills into this run (${e instanceof Error ? e.message : String(e)})`);
  }
  const parts: string[] = [];
  for (const f of [join(globalDir, "AGENTS.md"), ...agentsMd]) {
    try { if (statSync(f).isFile()) parts.push(readFileSync(f, "utf8").trimEnd()); } catch { /* absent */ }
  }
  if (parts.length > 0) publishFile(join(dir, "AGENTS.md"), parts.join("\n\n") + "\n");
}

/** Where the USER's own config lives — the agent's own resolution order, env
 *  override first (openclaw-src config/paths.ts resolveCanonicalConfigPath;
 *  opencode's global config path). */
export function userConfigPath(
  target: ConfigRoutedTarget,
  env: Record<string, string | undefined>,
  home = homedir(),
): string {
  if (target === "openclaw") {
    return (
      env["OPENCLAW_CONFIG_PATH"] ||
      join(env["OPENCLAW_STATE_DIR"] || join(home, ".openclaw"), "openclaw.json")
    );
  }
  return (
    env["OPENCODE_CONFIG"] ||
    join(env["XDG_CONFIG_HOME"] || join(home, ".config"), "opencode", "opencode.json")
  );
}

/**
 * Parse an agent's own config file: JSON5 (json5.ts), which OpenClaw's
 * `openclaw.json` is and OpenCode's JSONC is a subset of. Throws on a file
 * that is not a JSON5 object.
 */
export function parseAgentConfigText(text: string): Json {
  const parsed = parseJson5(text);
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Json;
  throw new Error("not a JSON object");
}

/**
 * Read and parse the agent's own config file at `path`. OpenClaw's `$include`
 * directives are resolved here (services/openclaw-include.ts), so every
 * reader (the model check, the allowlist, the memory fence) sees the config
 * OpenClaw would run, and the per-run config Mandu writes carries it
 * resolved. Throws on a file that does not parse or an include OpenClaw
 * would refuse; the message names the include.
 */
export function readAgentConfigFile(
  target: ConfigRoutedTarget,
  path: string,
  env: Record<string, string | undefined> = process.env,
): Json {
  const doc = parseAgentConfigText(readFileSync(path, "utf8"));
  if (target !== "openclaw") return doc;
  try {
    return resolveOpenclawIncludes(doc, path, { env }) as Json;
  } catch (e) {
    if (e instanceof IncludeError) {
      throw new Error(e.includePath === path ? e.message : `$include "${e.includePath}": ${e.message}`);
    }
    throw e;
  }
}

/**
 * Read the agent's own config the way writeAgentConfig does (JSON5 at
 * userConfigPath, `$include` resolved), for the launch-time model check
 * (agent-model-route.ts).
 */
export function readAgentUserConfig(
  target: ConfigRoutedTarget,
  env: Record<string, string | undefined> = process.env,
): AgentUserConfig {
  const path = userConfigPath(target, env);
  if (!existsSync(path)) return { kind: "absent" };
  try {
    return { kind: "ok", path, doc: readAgentConfigFile(target, path, env) };
  } catch (e) {
    return { kind: "unreadable", path, reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Write the per-run agent config: user config (best-effort read) deep-merged
 * under our routing override, into `<scopeRunDir>/<target>.json`.
 *
 * The user config is read with OpenClaw's `$include` resolved
 * (readAgentConfigFile), and the file written carries the resolved settings
 * with no `$include` left: a relative include would not resolve from the
 * scope run dir, and the run then uses exactly the config the model check
 * read.
 *
 * Read/parse failure of the USER config degrades to ours-only with a loud
 * warning — the SAFE direction (protection intact, user convenience lost;
 * the file is read as JSON5, and for OpenClaw the launch-time model check has
 * already refused a file that does not parse). A WRITE
 * failure must abort the launch instead: the caller (manager) marks it
 * failClosedFatal — no file, no chokepoint.
 */
export function writeAgentConfig(
  plan: LaunchPlan,
  layout: Layout,
  scopeRunDir: string,
  warn: (msg: string) => void,
  env: Record<string, string | undefined> = process.env,
): { envVar: string; path: string; env?: Record<string, string> } {
  if (!isConfigRouted(plan.target)) {
    throw new Error(`agent-config: target '${plan.target}' is not config-routed`);
  }
  const target = plan.target;
  const input: AgentConfigInput = {
    target,
    scopeId: plan.scopeId,
    batchId: plan.batchId,
    tenant: plan.tenant,
    proxyUrl: `http://${plan.proxy.host}:${plan.proxy.port}`,
    inspect: plan.writeMcp,
    ...(plan.writePolicyMcp === false ? { policy: false } : {}),
    ...(plan.openaiRoutes && plan.openaiRoutes.length > 0 ? { openaiRoutes: plan.openaiRoutes } : {}),
    ...(target === "opencode" && opencodeGeneration(plan.argv[0], plan.agentVersion) === 2 ? { opencodeGeneration: 2 as const } : {}),
  };

  let user: Json = {};
  const userPath = userConfigPath(target, env);
  // A project's OpenCode plugins and custom tools run only with the opt-out
  // or with confidentiality off (supported-agents.md §2.3 item 11), the
  // user's own only with the global opt-in or confidentiality off (§2.3 item
  // 12): an unknown axis counts as ON. What OpenCode 1 cannot leave out (a
  // custom tool) is refused at launch (run.ts).
  const confOff = plan.effectiveAxes?.confidentiality === false;
  const projectCode = opencodeProjectCodeAllowed(env) || confOff;
  const globalCode = opencodeGlobalCodeAllowed(env) || confOff;
  const home = env["HOME"] || homedir();
  let pure = false;
  if (target === "opencode") {
    const gen = input.opencodeGeneration === 2 ? 2 : 1;
    if (!globalCode) {
      const left = findOpencodeGlobalCode(gen, env, home);
      if (left.length > 0) warn(opencodeGlobalCodeNotice(left));
    }
    // OpenCode 1: no plugin runs with its own switch on (opencode-global-code.ts).
    pure = gen === 1 && opencodeV1Pure(projectCode, globalCode);
    if (pure) {
      const left = findOpencodeProjectCode(opencodeStartDirs(plan.argv, plan.cwd), 1, env, home).filter((f) => f.kind !== "tool");
      if (left.length > 0) warn(opencodeV1ProjectPluginsNotice(left));
    }
    // OpenCode 1 loads the user's documents itself (and adds `$schema` to
    // each that lacks one): the launcher makes that edit first, outside the
    // guard, so the write-protect hold on those files (an OpenCode setting)
    // does not stop OpenCode's start. Only with an explicit HOME (never the
    // process's own when a caller passes none) and where the guard holds
    // (not mode `off`).
    if (gen === 1 && !confOff && env["HOME"]) for (const p of addOpencodeSchema(env, env["HOME"])) warn(`agent-config: added OpenCode's "$schema" key to ${p} (OpenCode 1 adds it at its start)`);
  }
  if (input.opencodeGeneration === 2) {
    // OpenCode 2 reads no config file of the user's under Mandu (the
    // lockdown below): every layer it would have read is merged here, in its
    // order, under the routing (supported-agents.md §2.3 item 8).
    user = opencodeV2UserDoc(env, plan.cwd, warn, home, { projectCode, globalCode });
    if (!projectCode) {
      const left = findOpencodeProjectCode([plan.cwd], 2, env, home);
      if (left.length > 0) warn(opencodeProjectCodeNotice(left));
    }
  } else if (existsSync(userPath)) {
    try {
      user = readAgentConfigFile(target, userPath, env);
      // OpenCode 1's run file carries the user's document: without its
      // plugin list unless the user's own may run (§2.3 item 12).
      if (target === "opencode" && !globalCode) user = withoutPlugins(user).doc;
    } catch (e) {
      warn(
        `agent-config: could not parse ${userPath} (${e instanceof Error ? e.message : String(e)}) — ` +
        `using the Mandu routing config alone (your ${target} settings are NOT carried into this run)`,
      );
    }
  }

  let ours: Json;
  if (target === "openclaw") {
    let pluginDir: string | undefined = plan.writeMcp ? openclawPluginDir(layout) : undefined;
    if (pluginDir !== undefined && !existsSync(pluginDir)) {
      // Utility-class degrade, same posture as a missing .mcp.json: the
      // inspect channel just does not mount; the §9 invariant does not
      // depend on it (symbols stay opaque without it).
      warn(
        `agent-config: openclaw inspect plugin not found at ${pluginDir} — launching WITHOUT the U-LLM inspect channel`,
      );
      pluginDir = undefined;
    }
    const userModels = openclawUserAnthropicModels(user);
    if (userModels.dropped.length > 0) {
      warn(
        `agent-config: WARNING: ignoring ${userModels.dropped.join(", ")} in your OpenClaw anthropic models. A ` +
        "model's own endpoint settings would send its traffic around Mandu; every Anthropic model goes through Mandu's proxy.",
      );
    }
    const routedModels: Record<string, Json[]> = {};
    for (const r of input.openaiRoutes ?? []) {
      const m = openclawUserProviderModels(user, r.id);
      if (m.dropped.length > 0) {
        warn(
          `agent-config: WARNING: ignoring ${m.dropped.join(", ")} in your OpenClaw ${r.id} models. A model's own ` +
          `endpoint settings would send its traffic around Mandu; every ${r.id} model goes through Mandu's proxy.`,
        );
      }
      routedModels[r.id] = m.models;
    }
    ours = buildOpenclawWrapDoc(input, plan, pluginDir, userModels.models, routedModels);
  } else {
    ours = buildOpencodeWrapDoc(input, plan, layout);
  }

  // Own the dir: with every other service opted out nothing else has created
  // the scope run dir yet, and this write is fail-closed — it must not depend
  // on a sibling service's side effect.
  mkdirSync(scopeRunDir, { recursive: true });
  let path = join(scopeRunDir, `${target}.json`);
  let lockdown: Record<string, string> = {};
  if (input.opencodeGeneration === 2) {
    const dir = opencodeConfigDirOf(scopeRunDir);
    buildOpencodeConfigDir(dir, env, plan.cwd, warn, home, { projectCode, globalCode });
    path = join(dir, OPENCODE_RUN_FILE);
    lockdown = opencodeLockdownEnv(dir);
  }
  // OpenCode 2: the routing in V2 spelling too where the user's doc uses it
  // (withOpencodeV2Routing). Under the lockdown the run file and the inline
  // content are the only documents OpenCode 2 reads, so the fence is the
  // lowest provider rule there is.
  const merged = mergeConfig(user, input.opencodeGeneration === 2 ? withOpencodeV2Routing(user, ours) : ours);
  let out = merged;
  if (target === "openclaw") {
    const execHost = fenceOpenclawExecHost(fenceOpenclawModelAllowlist(merged, (plan.openaiRoutes ?? []).map((r) => r.id)));
    for (const w of execHost.warnings) warn(`agent-config: WARNING: ${w}`);
    const codeMode = fenceOpenclawCodeMode(execHost.doc, plan.agentVersion);
    for (const w of codeMode.warnings) warn(`agent-config: WARNING: ${w}`);
    const webEgress = fenceOpenclawWebEgress(
      codeMode.doc, plan.agentVersion,
      plan.netProxy ? `http://${plan.netProxy.host}:${plan.netProxy.port}` : undefined,
    );
    for (const w of webEgress.warnings) warn(`agent-config: WARNING: ${w}`);
    for (const n of webEgress.notes) warn(`agent-config: ${n}`);
    const memory = fenceOpenclawMemorySearch(webEgress.doc, plan.agentVersion);
    for (const w of memory.warnings) warn(`agent-config: WARNING: ${w}`);
    for (const n of memory.notes) warn(`agent-config: ${n}`);
    const workspace = fenceOpenclawWorkspace(memory.doc, plan.argv, plan.cwd);
    for (const n of workspace.notes) warn(`agent-config: ${n}`);
    out = workspace.doc;
  }
  // Never through a link planted in the scope dir (safe-file.ts).
  publishFile(path, JSON.stringify(out, null, 2) + "\n");
  if (target === "opencode") {
    return {
      envVar: AGENT_CONFIG_ENV_VAR[target],
      path,
      env: {
        ...lockdown,
        OPENCODE_CONFIG_CONTENT: opencodeRoutingContent(ours, env["OPENCODE_CONFIG_CONTENT"], warn, { globalCode }),
        ...(pure ? { [OPENCODE_PURE_ENV]: "1" } : {}),
      },
    };
  }
  return { envVar: AGENT_CONFIG_ENV_VAR[target], path };
}
