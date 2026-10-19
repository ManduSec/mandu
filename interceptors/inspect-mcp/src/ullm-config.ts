/**
 * ullm-config — PURE U-LLM transport selection (api vs cli), side-effect-free.
 *
 * Mandu M4 cooperative U-LLM path (interceptors/inspect-mcp).
 *
 * PROVENANCE: extracted VERBATIM from src/server-main.ts (2026-08-06) —
 * `selectUllmConfig`, `buildUllmClient`, the env slice + config types, and the
 * `isOnPath` probe. server-main.ts re-exports everything here, so its existing
 * importers (test/unit/server-main.test.ts) are unchanged. The move exists
 * because server-main is an ENTRYPOINT module: it sets
 * `process.title = "mandu-inspect-mcp"` at import time, which is correct for
 * the standalone MCP stdio server but wrong for any host that embeds this
 * package's logic in ITS OWN process — concretely the OpenClaw plugin port
 * (interceptors/openclaw-inspect-plugin), which runs inside the OpenClaw
 * gateway and must not rename it out from under runtime-instances discovery.
 * This module has NO side effects and NO I/O beyond the injectable PATH probe.
 *
 * Selection contract (unchanged):
 *   - "api": requires ANTHROPIC_API_KEY (throws with a clear message if absent).
 *   - "cli": no key needed; needs a usable CLI binary on PATH (the probe is
 *            injected so the selection is testable without a real claude).
 *   - "auto": key present → api; else a CLI binary present → cli; else fail
 *            closed.
 * Every path with a base URL runs assertNonProxyBaseUrl — the loopback
 * (instrumented-proxy) refusal, with the launcher-pinned forwarder as the one
 * sanctioned exception — BEFORE a client is built.
 */

import { spawnSync } from "node:child_process";
import {
  AnthropicUllmClient,
  CliUllmClient,
  OpenAiChatUllmClient,
  assertDeclaredEndpointUrl,
  assertNonProxyBaseUrl,
  sanctionedEndpointOrigins,
  type EndpointGuard,
  type UllmCliBinary,
  type UllmClient,
} from "./ullm-client.js";
import type { ModelEndpoint } from "./arbiter-client.js";
import { asTlsConfig, hasTlsConfig, loadTlsMaterial, tlsFetch } from "./endpoint-tls.js";

export type UllmMode = "auto" | "api" | "cli";

/** The relevant slice of the environment for U-LLM client selection. */
export interface UllmEnv {
  MANDU_ULLM_MODE?: string;
  ANTHROPIC_API_KEY?: string;
  ANTHROPIC_BASE_URL?: string;
  MANDU_ULLM_FORWARDER?: string;
  MANDU_ULLM_BINARY?: string;
  MANDU_ULLM_MODEL?: string;
  /** Plan 11 D5: the model proxy's address(es), comma-separated, when the
   *  launcher pins them. NOT a declaration of anything: only the set of
   *  addresses a declared endpoint may never equal. */
  MANDU_MODEL_PROXY_URL?: string;
}

/** What `selectUllmConfig` resolves: which client to build + its options. */
export type UllmConfig =
  | {
      mode: "api";
      apiKey: string;
      baseUrl?: string;
      forwarderUrl?: string;
      model?: string;
    }
  | {
      mode: "cli";
      binary: UllmCliBinary;
      baseUrl?: string;
      forwarderUrl?: string;
      model?: string;
    };

/**
 * PURE selection logic (unit-tested). Decides api vs cli without side effects.
 * Throws (fail-closed) when neither a key nor a usable CLI binary is available.
 */
export function selectUllmConfig(
  env: UllmEnv,
  cliAvailable: (binary: "claude" | "codex") => boolean,
): UllmConfig {
  const rawMode = (env.MANDU_ULLM_MODE ?? "auto").trim().toLowerCase();
  const mode: UllmMode =
    rawMode === "api" || rawMode === "cli" || rawMode === "auto" ? (rawMode as UllmMode) : "auto";

  const apiKey = (env.ANTHROPIC_API_KEY ?? "").trim();
  const baseUrl = env.ANTHROPIC_BASE_URL || undefined;
  const forwarderUrl = env.MANDU_ULLM_FORWARDER || undefined;
  const model = env.MANDU_ULLM_MODEL || undefined;
  const binary = normalizeBinary(env.MANDU_ULLM_BINARY);

  if (mode === "api") {
    if (!apiKey) {
      throw new Error(
        "MANDU_ULLM_MODE=api but ANTHROPIC_API_KEY is not set — cannot make the quarantined U-LLM call (fail closed).",
      );
    }
    // SECURITY: the api-mode client POSTs directly to baseUrl. Refuse a loopback
    // (the Mandu anthropic-proxy) so untrusted data never loops back through
    // T-LLM — the launcher-pinned forwarder is the one sanctioned exception.
    if (baseUrl) assertNonProxyBaseUrl(baseUrl, forwarderUrl);
    return { mode: "api", apiKey, baseUrl, forwarderUrl, model };
  }

  if (mode === "cli") {
    const resolved = resolveProbeBinary(binary, model);
    if (!cliAvailable(resolved)) {
      throw new Error(
        `MANDU_ULLM_MODE=cli but the '${resolved}' CLI is not on PATH — cannot run the quarantined U-LLM subprocess (fail closed).`,
      );
    }
    // SECURITY: cli mode forwards baseUrl into the child's ANTHROPIC_BASE_URL
    // (CliUllmClient.buildChildEnv) — the same loopback refusal applies, or a
    // loopback-proxy base would route the quarantined child through T-LLM's
    // instrumented path.
    if (baseUrl) assertNonProxyBaseUrl(baseUrl, forwarderUrl);
    return { mode: "cli", binary, baseUrl, forwarderUrl, model };
  }

  // auto: prefer an explicit key (api), else a CLI binary (cli), else fail closed.
  if (apiKey) {
    // SECURITY: same loopback refusal as explicit api mode (direct HTTP path).
    if (baseUrl) assertNonProxyBaseUrl(baseUrl, forwarderUrl);
    return { mode: "api", apiKey, baseUrl, forwarderUrl, model };
  }
  const resolved = resolveProbeBinary(binary, model);
  if (baseUrl) assertNonProxyBaseUrl(baseUrl, forwarderUrl);
  if (cliAvailable(resolved)) {
    return { mode: "cli", binary, baseUrl, forwarderUrl, model };
  }
  // Try the other binary as a last resort (e.g. binary hint was claude but only
  // codex is installed, or vice versa) before giving up.
  const alt: "claude" | "codex" = resolved === "claude" ? "codex" : "claude";
  if (cliAvailable(alt)) {
    return { mode: "cli", binary: alt, baseUrl, forwarderUrl, model };
  }
  throw new Error(
    "no ANTHROPIC_API_KEY and no claude/codex CLI on PATH — the quarantined U-LLM cannot run (fail closed). " +
      "Log in to Claude Code (so `claude` is on PATH) or set ANTHROPIC_API_KEY.",
  );
}

function normalizeBinary(raw: string | undefined): UllmCliBinary {
  const v = (raw ?? "").trim().toLowerCase();
  return v === "claude" || v === "codex" ? v : "auto";
}

/** Map a binary hint to the concrete binary to PROBE for ("auto" → from model). */
function resolveProbeBinary(binary: UllmCliBinary, model: string | undefined): "claude" | "codex" {
  if (binary === "claude" || binary === "codex") return binary;
  const m = model ?? "";
  const isOpenAi = m.startsWith("openai/") || m.startsWith("gpt-") || m.startsWith("o");
  return isOpenAi ? "codex" : "claude";
}

/** Build the concrete UllmClient from a resolved config. */
export function buildUllmClient(config: UllmConfig): UllmClient {
  if (config.mode === "api") {
    return new AnthropicUllmClient({
      apiKey: config.apiKey,
      baseUrl: config.baseUrl,
      forwarderUrl: config.forwarderUrl,
      model: config.model,
    });
  }
  return new CliUllmClient({
    binary: config.binary,
    baseUrl: config.baseUrl,
    model: config.model,
    ...(config.forwarderUrl ? { forwarderUrl: config.forwarderUrl } : {}),
  });
}

/** Probe whether a binary is resolvable on PATH (cross-platform via `which`/`where`).
 *  The default `cliAvailable` probe for production callers; tests inject fakes. */
export function isOnPath(binary: "claude" | "codex"): boolean {
  try {
    const probe = process.platform === "win32" ? "where" : "which";
    const r = spawnSync(probe, [binary], { stdio: "ignore" });
    return r.status === 0;
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Declared model endpoints (Plan 11 D5). The ENDPOINT LIST comes from the
// arbiter's `modelEndpoints` op (policy.yaml `models:`), never from env. The
// env contributes only (a) the forbidden addresses (forwarder, model proxy)
// and (b) the token named by an entry's `tokenEnv`.
// ─────────────────────────────────────────────────────────────────────────────

/** The forbidden-address guard this process can know from its env. */
export function endpointGuardFromEnv(
  env: { MANDU_ULLM_FORWARDER?: string; MANDU_MODEL_PROXY_URL?: string },
  extraProxyUrls: ReadonlyArray<string | undefined> = [],
): EndpointGuard {
  const proxyUrls = [
    ...(env.MANDU_MODEL_PROXY_URL ?? "").split(","),
    ...extraProxyUrls,
  ].map((u) => (u ?? "").trim()).filter((u) => u !== "");
  return { forwarderUrl: env.MANDU_ULLM_FORWARDER || undefined, proxyUrls };
}

/** Builds the quarantined client for one declared endpoint. `all` is the
 *  full list the arbiter returned (the loopback guard's sanctioned set). */
export type EndpointUllmFactory = (endpoint: ModelEndpoint, all: readonly ModelEndpoint[]) => UllmClient;

/**
 * Build the U-LLM client for a declared endpoint. Throws (the caller refuses
 * the inspect, before any resolve) when the URL is unusable or is the proxy's
 * or the forwarder's address, when the wire is unknown, or when an
 * `openai-chat` entry names no model.
 *   - `anthropic`:   the Anthropic client pointed at the endpoint's url; the
 *                    `tokenEnv` value (if any) rides as `x-api-key`.
 *   - `openai-chat`: OpenAiChatUllmClient; the token rides as a bearer.
 */
export function buildEndpointUllmClient(
  endpoint: ModelEndpoint,
  all: readonly ModelEndpoint[],
  guard: EndpointGuard,
  env: Record<string, string | undefined>,
): UllmClient {
  const url = endpointApiBase(assertDeclaredEndpointUrl(endpoint.name, endpoint.url, guard, { allowPlainHttp: endpoint.allowPlainHttp === true }));
  const sanctionedOrigins = sanctionedEndpointOrigins(all, guard);
  const token = endpoint.tokenEnv ? (env[endpoint.tokenEnv] ?? "").trim() || undefined : undefined;
  const timeoutMs = endpointTimeoutMs(env);
  const fetchImpl = endpointFetch(endpoint, env);
  if (endpoint.wire === "openai-chat") {
    return new OpenAiChatUllmClient({
      baseUrl: url,
      model: endpoint.model ?? "",
      token,
      sanctionedOrigins,
      forwarderUrl: guard.forwarderUrl,
      timeoutMs,
      ...(fetchImpl ? { fetchImpl } : {}),
    });
  }
  if (endpoint.wire === "anthropic" || endpoint.wire === undefined) {
    return new AnthropicUllmClient({
      apiKey: token ?? "",
      requireApiKey: false,
      errorDetail: false,
      requireContent: true,
      timeoutMs,
      baseUrl: url,
      // No forwarder pin: a declared endpoint is addressed directly (D2).
      sanctionedOrigins,
      model: endpoint.model,
      ...(fetchImpl ? { fetchImpl } : {}),
    });
  }
  throw new Error(`declared model endpoint '${endpoint.name}' has an unknown wire (fail closed)`);
}

/**
 * Plan 12 D3 and D4: the fetch for an entry that says `tls:` or carries a
 * `perimeter`, or undefined (the default fetch). The checks (the entry's CA,
 * its pins, its client certificate; every resolved address inside the
 * perimeter) run on every connection, before a byte is sent; a refusal is a
 * failed call like any other and never moves to another model. The client
 * key's bytes come from `MANDU_MODEL_CLIENT_KEYS` (a JSON map, entry name →
 * PEM, set by the launcher: the key FILE is masked in the agent's world, where
 * this process runs). Throws (the caller refuses the endpoint) when the
 * config is malformed, identity checks are asked of a plain http url, or a
 * file cannot be used.
 */
export function endpointFetch(endpoint: ModelEndpoint, env: Record<string, string | undefined>): typeof fetch | undefined {
  if (endpoint.tls === undefined && endpoint.perimeter === undefined) return undefined;
  const cfg = asTlsConfig({ ...(endpoint.tls ?? {}), ...(endpoint.perimeter !== undefined ? { perimeter: endpoint.perimeter } : {}) });
  if (cfg === null) throw new Error(`declared model endpoint '${endpoint.name}' has a tls or perimeter setting this helper cannot read (fail closed)`);
  if (!hasTlsConfig(cfg)) return undefined;
  const identity = !!cfg.caFile || (cfg.pinSha256?.length ?? 0) > 0 || !!cfg.clientCert || !!cfg.clientKey;
  if (identity && new URL(endpoint.url.trim()).protocol !== "https:") {
    throw new Error(`declared model endpoint '${endpoint.name}' has tls settings but a plain http url (fail closed)`);
  }
  let keyPem: string | undefined;
  if (cfg.clientKey) {
    try { keyPem = (JSON.parse(env.MANDU_MODEL_CLIENT_KEYS ?? "{}") as Record<string, unknown>)[endpoint.name] as string | undefined; } catch { keyPem = undefined; }
    if (typeof keyPem !== "string") keyPem = undefined;
  }
  try {
    return tlsFetch(loadTlsMaterial(cfg, keyPem !== undefined ? { keyPem } : {}));
  } catch (e) {
    throw new Error(`declared model endpoint '${endpoint.name}': ${(e as Error).message} (fail closed)`);
  }
}

/**
 * The base a declared endpoint's client adds its API path to: the entry's
 * url without trailing slashes and without ONE trailing `/v1` segment. The
 * clients add `/v1/chat/completions` or `/v1/messages` themselves, and an
 * OpenAI base URL ends in `/v1` by convention (the url a Codex main model is
 * declared with, plan 11 §7.2), so one entry can serve both Codex and the
 * helper; `…/v1/v1/…` is never a real route. Only the path changes, never the
 * origin the guard checked. Pure.
 */
export function endpointApiBase(url: string): string {
  return url.replace(/\/+$/, "").replace(/\/v1$/, "");
}

/**
 * The per-call timeout for a declared endpoint's client, from
 * `MANDU_ULLM_ENDPOINT_TIMEOUT_MS` (a positive integer of milliseconds, at
 * most ten minutes). undefined = the client's default (60 s). A local model
 * on a CPU can need longer; a test needs shorter. A timeout is a refusal
 * like any other failure: the call never moves to another model.
 */
export function endpointTimeoutMs(env: Record<string, string | undefined>): number | undefined {
  const raw = (env.MANDU_ULLM_ENDPOINT_TIMEOUT_MS ?? "").trim();
  if (!/^[1-9][0-9]{0,6}$/.test(raw)) return undefined;
  const ms = Number(raw);
  return ms <= 600_000 ? ms : undefined;
}

/** The production factory: guard + tokens from `env`. */
export function createEndpointUllmFactory(
  env: Record<string, string | undefined>,
  extraProxyUrls: ReadonlyArray<string | undefined> = [],
): EndpointUllmFactory {
  const guard = endpointGuardFromEnv(env, extraProxyUrls);
  return (endpoint, all) => buildEndpointUllmClient(endpoint, all, guard, env);
}
