/**
 * services/mcp — emit .mcp.json registering the inspect-mcp (U-LLM) server.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh MCP block (L1044-1115). The env's
 *   ANTHROPIC_BASE_URL is the REAL Anthropic endpoint (the U-LLM must NOT go
 *   through the instrumented proxy); cli mode passes a binary hint and emits NO
 *   ANTHROPIC_API_KEY (child reuses the user's login); api mode emits the
 *   quarantined key. Written to <scope run dir>/mcp.json (MANDU_MCP_CONFIG
 *   overrides the path) and handed to claude as `--mcp-config <path>`
 *   (env-compose.ts) — NOT dropped into <cwd>/.mcp.json as a project-scope
 *   file. Found live 2026-09-05: a project .mcp.json is an UNTRUSTED server to
 *   Claude Code at its default permission posture, so every launch opened
 *   "New MCP server found in this project: mandu-inspect" with the default
 *   answer "Continue without using this MCP server" — the dialog ate the
 *   human's first keystrokes and, on Enter, silently removed the U-LLM
 *   `inspect_symbol` tool from the session (only bypassPermissions skipped
 *   it, which is why every harness stayed green). An explicit --mcp-config
 *   file is loaded without that dialog, and nothing is left behind in the
 *   user's workspace (the old file was litter every non-Mandu `claude` in
 *   that cwd kept loading, dead forwarder port and all).
 */
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import type { LaunchPlan, Ullm } from "../types.js";
import type { ModelEndpoint } from "../model-endpoints.js";
import { inspectNoProxy, wrapServerCommand } from "../inspect-net-confine.js";
import type { Layout } from "./layout.js";
import { sessionNoProxy } from "./net-proxy.js";
import { publishFile } from "../safe-file.js";
import { ULLM_ENDPOINT_TIMEOUT_ENV } from "../ullm-timeout.js";

/** The narrow slice of a LaunchPlan the .mcp.json needs. LaunchPlan satisfies it
 *  structurally, so `writeMcpConfig(plan)` passes `plan` straight through; other
 *  callers (e.g. the integration live e2e, which spawns `claude` itself rather
 *  than via the launcher) can build the SAME config without a full plan. */
export interface InspectMcpInput {
  arbiterSock: string;
  scopeId: string;
  ullm: Ullm;
  /** Tenant stamp for the events the inspect child emits (policy-surface-
   *  redesign.md §2.7). Optional so direct-spawn callers predating tenancy
   *  still build a valid config (their events stay unstamped). */
  tenant?: "live" | "test";
  /** The session's model proxies (LaunchPlan.proxy / openaiProxy, the ADOPTED
   *  ports). Their origins reach inspect-mcp as MANDU_MODEL_PROXY_URL, its
   *  refusal list for declared model endpoints (confidentiality-plan-11 D5).
   *  Optional so direct-spawn callers still build a valid config. */
  proxy?: { host: string; port: number };
  openaiProxy?: { host: string; port: number };
  /** The inspect-mcp network confine's wrap argv (LaunchPlan.inspectMcpWrap,
   *  inspect-net-confine.ts): prefixed to the server command. Absent = the
   *  command as today. */
  inspectMcpWrap?: string[];
  /** For the confined server's NO_PROXY (inspect-net-confine.ts
   *  `inspectNoProxy`): the session's net-proxy, MANDU_MODEL_HOSTS and the
   *  declared endpoints. Optional; only read when `inspectMcpWrap` is set. */
  netProxy?: { host: string; port: number };
  noProxyExtra?: string[];
  /** The model-host deny (LaunchPlan.modelHostDeny): the model hosts stay
   *  out of the server's NO_PROXY, as out of the session's. */
  modelHostDeny?: boolean;
  modelEndpoints?: ModelEndpoint[];
  /** The declared local endpoints' tokens by variable name (LaunchPlan.
   *  modelTokens). Optional; only `local: true` entries' variables are read. */
  modelTokens?: Record<string, string>;
  /** Plan 12 D3: the declared local endpoints' client keys, entry name → PEM
   *  (LaunchPlan.modelClientKeys). */
  modelClientKeys?: Record<string, string>;
  /** The per-call endpoint timeout (LaunchPlan.ullmEndpointTimeoutMs),
   *  written as MANDU_ULLM_ENDPOINT_TIMEOUT_MS. The entry must carry it:
   *  Codex hands a stdio server only the entry's env (model-endpoints.md
   *  §1.9). Absent = none (inspect-mcp's 60 s). */
  ullmEndpointTimeoutMs?: number;
}

/** MANDU_MODEL_PROXY_URL: the comma-separated origins of the session's model
 *  proxies (confidentiality-plan-11 D5). inspect-mcp never sends to a declared
 *  endpoint at one of these addresses: they relay to an outside model, and
 *  inspect-mcp cannot see the proxy's address otherwise (its own
 *  ANTHROPIC_BASE_URL is the U-LLM's, set below). Port 0 = never adopted (no
 *  proxy this session): left out. Empty string when neither is live. Pure. */
export function modelProxyOrigins(input: Pick<InspectMcpInput, "proxy" | "openaiProxy">): string {
  const out: string[] = [];
  for (const p of [input.proxy, input.openaiProxy]) {
    if (!p || p.port <= 0) continue;
    const host = p.host.includes(":") && !p.host.startsWith("[") ? `[${p.host}]` : p.host;
    const origin = `http://${host}:${p.port}`;
    if (!out.includes(origin)) out.push(origin);
  }
  return out.join(",");
}

/** Build the `.mcp.json` document registering the inspect-mcp (U-LLM) server
 *  Claude Code exposes as `mcp__mandu-inspect__inspect_symbol`. Single source
 *  of truth for the entry, shared by the launcher and any direct-spawn caller. */
export function inspectMcpConfigDoc(input: InspectMcpInput, layout: Layout): {
  mcpServers: Record<string, { command: string; args: string[]; env: Record<string, string> }>;
} {
  // The launcher does NOT spawn inspect-mcp — the agent does, from this config.
  // The layout gives dev (`tsx server-main.ts`) vs installed (`node
  // dist/inspect-mcp.mjs` + MANDU_ARBITER_CLIENT_MODULE) command/args/env.
  const { command, args, env: layoutEnv } = layout.inspectMcp();

  const env: Record<string, string> = {
    ...layoutEnv,
    MANDU_ARBITER_SOCK: input.arbiterSock,
    MANDU_SCOPE_ID: input.scopeId,
    ...(input.tenant ? { MANDU_TENANT: input.tenant } : {}),
    MANDU_ULLM_MODE: input.ullm.mode,
    ANTHROPIC_BASE_URL: input.ullm.baseUrl,
  };
  if (input.ullm.forwarderUrl) {
    // The loopback U-LLM forwarder is live: route the U-LLM through it instead
    // of a direct :443 dial (exec-routing.md §7.1 — the relay runs outside the
    // landlock-net wrap and forwards VERBATIM to the real endpoint). The
    // MANDU_ULLM_FORWARDER pin is what inspect-mcp's loopback guard trusts:
    // it names exactly this relay, so every OTHER loopback base URL (above all
    // the instrumented anthropic-proxy) stays refused fail-closed.
    env["ANTHROPIC_BASE_URL"] = input.ullm.forwarderUrl;
    env["MANDU_ULLM_FORWARDER"] = input.ullm.forwarderUrl;
  }
  // A declared local endpoint's token (policy.yaml `token_env`, plan 11 D2):
  // the real value from the launcher's environment. The agent's environment,
  // which Claude Code hands to this server, carries the variable masked, so
  // the entry's own env must name it. Never over a variable set above.
  for (const e of input.modelEndpoints ?? []) {
    if (!e.local || e.tokenEnv === undefined || e.tokenEnv in env) continue;
    const token = input.modelTokens?.[e.tokenEnv];
    if (token !== undefined && token !== "") env[e.tokenEnv] = token;
  }
  // Plan 12 D3: a declared endpoint's client key, as the launcher read it
  // (the key file is masked in the agent's world, where this server runs).
  const keys = input.modelClientKeys ?? {};
  if (Object.keys(keys).length > 0) env["MANDU_MODEL_CLIENT_KEYS"] = JSON.stringify(keys);
  const proxies = modelProxyOrigins(input);
  if (proxies !== "") env["MANDU_MODEL_PROXY_URL"] = proxies;
  if (input.ullm.model) env["MANDU_ULLM_MODEL"] = input.ullm.model;
  if (input.ullmEndpointTimeoutMs !== undefined) env[ULLM_ENDPOINT_TIMEOUT_ENV] = String(input.ullmEndpointTimeoutMs);
  if (input.ullm.mode === "cli") env["MANDU_ULLM_BINARY"] = input.ullm.binary ?? "claude";
  // The quarantined `codex exec` signs in from the agent's CODEX_HOME, which
  // Codex does not pass to a stdio MCP server on its own.
  if (input.ullm.mode === "cli" && input.ullm.binary === "codex" && input.ullm.codexHome) env["CODEX_HOME"] = input.ullm.codexHome;
  else if (input.ullm.apiKey) env["ANTHROPIC_API_KEY"] = input.ullm.apiKey;

  // A declared model on another machine is dialed directly, never through the
  // egress proxy (Node honors HTTP(S)_PROXY under NODE_USE_ENV_PROXY,
  // env-compose.ts). Under the network confine (inspect-net-confine.ts, plan
  // 11 §8 item 5) the proxy's port is not even reachable; without it the
  // request would reach the proxy, which would decrypt the local-model bytes
  // and dial the model with its own trust store instead of the entry's tls
  // checks (plan 12 D3). So always, whenever the session has a net-proxy.
  const wrap = input.inspectMcpWrap;
  const noProxy = inspectNoProxy(
    sessionNoProxy({ netProxy: input.netProxy, noProxyExtra: input.noProxyExtra ?? [], ...(input.modelHostDeny === true ? { modelHostDeny: true } : {}) }),
    input.modelEndpoints ?? [],
  );
  if (noProxy !== null) { env["NO_PROXY"] = noProxy; env["no_proxy"] = noProxy; }

  return { mcpServers: { "mandu-inspect": wrapServerCommand({ command, args, env }, wrap) } };
}

/** The server name and tool basenames of the policy agent surface
 *  (policy-surface.md §8.5.1). The arbiter's trust gate keys on exactly
 *  these (arbiter/policy/policy-tool.ts). */
export const MANDU_POLICY_SERVER = "mandu-policy";
/** The policy tools the launcher pre-allows in Claude Code: all three. Reading
 *  and testing change nothing; a proposal either tightens (applied, undoable
 *  from History) or waits for the user in Approvals, so a Claude Code prompt
 *  on top would gate the same act twice (policy-surface.md §8.9). */
export const POLICY_PREALLOWED_TOOLS = ["mandu_policy_read", "mandu_policy_test", "mandu_policy_propose"] as const;

/** The mandu-policy server entry: a data-plane arbiter client with no model
 *  of its own, so it needs only the socket, the session key and the project
 *  directory. Shared by the launcher and direct-spawn callers (the live
 *  harness), like the inspect entry. `humanCwd` (the launch directory, the
 *  spelling the labels are keyed in) becomes MANDU_PROJECT_DIR: a relative
 *  path in a proposed edit is read there (policy-surface.md §8.5.1). */
export function policyMcpServerEntry(
  input: Pick<InspectMcpInput, "arbiterSock" | "scopeId" | "tenant"> & { humanCwd?: string },
  layout: Layout,
): { command: string; args: string[]; env: Record<string, string> } {
  const { command, args, env: layoutEnv } = layout.policyMcp();
  return {
    command,
    args,
    env: {
      ...layoutEnv,
      MANDU_ARBITER_SOCK: input.arbiterSock,
      MANDU_SCOPE_ID: input.scopeId,
      ...(input.tenant ? { MANDU_TENANT: input.tenant } : {}),
      ...(input.humanCwd && input.humanCwd.startsWith("/") ? { MANDU_PROJECT_DIR: input.humanCwd } : {}),
    },
  };
}

/** The whole MCP config the launcher writes: inspect always (the file exists
 *  only when --no-mcp is absent), policy unless --no-policy-mcp. */
export function mcpConfigDoc(
  plan: InspectMcpInput & { writePolicyMcp?: boolean; humanCwd?: string },
  layout: Layout,
): { mcpServers: Record<string, { command: string; args: string[]; env: Record<string, string> }> } {
  const doc = inspectMcpConfigDoc(plan, layout);
  if (plan.writePolicyMcp !== false) doc.mcpServers[MANDU_POLICY_SERVER] = policyMcpServerEntry(plan, layout);
  return doc;
}

export function writeMcpConfig(plan: LaunchPlan, layout: Layout, scopeRunDir: string): string {
  const path = process.env["MANDU_MCP_CONFIG"] || join(scopeRunDir, "mcp.json");
  // Own the dir, as the agent-config step does: with every other service
  // opted out nothing else has created the scope run dir yet.
  mkdirSync(dirname(path), { recursive: true });
  // Never through a link planted in the scope dir (safe-file.ts); a path the
  // user named (MANDU_MCP_CONFIG) may sit in a folder they linked.
  publishFile(path, JSON.stringify(mcpConfigDoc(plan, layout), null, 2) + "\n", { dirMayBeLink: !!process.env["MANDU_MCP_CONFIG"] });
  return path;
}
