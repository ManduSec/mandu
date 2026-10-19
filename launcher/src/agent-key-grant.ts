/**
 * agent-key-grant — the launch's half of putting an agent's own key back at
 * the model proxy (agent-sign-in.md §3).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * Two forms: Goose's key file (below) and, since 2026-10-11, Claude Code's
 * `ANTHROPIC_API_KEY` in the environment (`registerClaudeKeyGrant`, §3.8:
 * the grant names the variable, and the env-var mask then masks it).
 *
 * Under `mandu goose`, Goose reads its provider key from
 * `<config>/goose/secrets.yaml`. With a grant, the file is twinned like any
 * catalog secret (Goose reads and sends the key's placeholder) and the model
 * proxy puts the real key back in the auth header of the request it forwards
 * to the provider this launch routes. The launcher is what knows that
 * provider's host, so it tells the arbiter (`registerAuthGrant`, a HUMAN-PLANE
 * op) which field authenticates to which host, BEFORE the secret setup:
 *
 *   - `ANTHROPIC_API_KEY` → the anthropic upstream's host, when the session
 *     or its subagents use anthropic through the proxy;
 *   - `OPENAI_API_KEY` → the openai route's host, when they use openai.
 *
 * Goose's Chat Completions providers (2026-10-11, agent-sign-in.md §3.10;
 * goose-route.ts GOOSE_COMPAT_PROVIDERS, supported-agents.md §5.6.4): each
 * one's key field goes to its own API host (openrouter.ai, api.x.ai,
 * api.router.tetrate.ai) or this machine's loopback (LiteLLM is a server the
 * user runs, so loopback only); Ollama takes no key and asks for nothing.
 * The same providers' key VARIABLES (and ANTHROPIC_API_KEY / OPENAI_API_KEY)
 * in Goose's environment get an env grant each (`gooseEnvKeyGrantPlans`)
 * and are then masked, as Claude Code's is (§3.8).
 *
 * A host is granted only where the model proxy is the only thing that puts a
 * value back: the provider's own API host over https (`api.anthropic.com`,
 * `api.openai.com`: the net-proxy never releases into a model host, and the
 * agent reaches them directly) or this machine's loopback (a local model
 * server; a launched net-proxy refuses this machine). All or nothing: when a
 * routed provider's host is anything else, when anthropic turns skip the
 * proxy, or when the grant cannot be recorded, no field is granted and the
 * file keeps the agent's-own-key-file posture (agent-login.ts
 * `agentOwnCredentialFiles`, supported-agents.md §5.6.1): Goose reads it raw,
 * as before, so a launch never twins a key Goose then cannot use.
 * `MANDU_AUTH_SUBSTITUTION=0` keeps that posture on purpose.
 */
import { gooseSecretsFile } from "./agent-login.js";
import { GOOSE_DEFAULT_ROUTING, gooseCompatSpec, gooseRoutedKeyVars, type GooseRouting, type GooseRoutedProvider } from "./goose-route.js";
import { isLoopbackHost } from "./model-endpoints.js";
import type { LaunchPlan } from "./types.js";

/** The launcher env switch that keeps the agent's-own-key-file posture. */
export const AUTH_SUBSTITUTION_ENV = "MANDU_AUTH_SUBSTITUTION";

/** Each routed provider's key field in Goose's secrets.yaml and its own API
 *  host (goose 1.53.0 `ANTHROPIC_HOST` / `OPENAI_HOST` defaults). */
const GOOSE_KEY: Record<"anthropic" | "openai", { field: string; vendorHost: string; defaultUpstream: string }> = {
  anthropic: { field: "ANTHROPIC_API_KEY", vendorHost: "api.anthropic.com", defaultUpstream: "https://api.anthropic.com" },
  openai: { field: "OPENAI_API_KEY", vendorHost: "api.openai.com", defaultUpstream: "https://api.openai.com" },
};

/** The own API host of each Chat Completions provider that takes a key
 *  (goose-route.ts GOOSE_COMPAT_PROVIDERS' defaults, goose 1.53.0); null:
 *  none, so only this machine's loopback is grantable (LiteLLM is a proxy
 *  server the user runs). */
const GOOSE_COMPAT_VENDOR: Readonly<Record<string, string | null>> = {
  openrouter: "openrouter.ai",
  xai: "api.x.ai",
  tetrate: "api.router.tetrate.ai",
  litellm: null,
};

/** A provider's own API host, or null (loopback only). */
function vendorHostOf(provider: string): string | null {
  if (provider === "anthropic" || provider === "openai") return GOOSE_KEY[provider].vendorHost;
  return GOOSE_COMPAT_VENDOR[provider] ?? null;
}

export interface AuthGrantWire { field: string; host: string; https: boolean }

export type KeyGrantPlan =
  | { grant: { path: string; grants: AuthGrantWire[] } }
  | { none: string };

export type KeyGrantLaunch = Pick<LaunchPlan, "target" | "gooseRouting" | "anthropicBaseUrl" | "tllmEndpoint" | "noContextProxy" | "effectiveAxes" | "confidentiality">;

type Env = Record<string, string | undefined>;

/** The grantable host of one upstream URL, or why not. Pure. */
export function grantableHost(provider: GooseRoutedProvider, upstream: string): { host: string; https: boolean } | { why: string } {
  let u: URL;
  try {
    u = new URL(upstream);
  } catch {
    return { why: `the ${provider} upstream is not a URL` };
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const https = u.protocol === "https:";
  if (u.protocol !== "https:" && u.protocol !== "http:") return { why: `the ${provider} upstream is not http(s)` };
  // Loopback as the arbiter accepts it (auth-grants.ts isLoopbackGrantHost):
  // the host is granted as written, which is what the proxy will dial.
  if (isLoopbackHost(host) && (host === "localhost" || host === "::1" || /^127\.\d+\.\d+\.\d+$/.test(host))) return { host, https };
  const vendor = vendorHostOf(provider);
  if (vendor !== null && host === vendor && https) return { host, https };
  return { why: vendor !== null
    ? `the ${provider} upstream ${u.host} is neither ${vendor} nor this machine`
    : `the ${provider} upstream ${u.host} is not this machine` };
}

/**
 * Where one routed Goose provider's key would be put back: its key field or
 * variable, and the grantable host of the upstream the proxy sends it to;
 * `null` for a provider that takes no key (Ollama); or why not. Pure.
 */
export function gooseProviderKeyHost(
  p: GooseRoutedProvider,
  routing: GooseRouting,
  plan: Pick<KeyGrantLaunch, "anthropicBaseUrl" | "tllmEndpoint">,
  processEnv: Env,
): { field: string; host: string; https: boolean } | null | { why: string } {
  let upstream: string;
  let field: string;
  if (p === "anthropic") {
    if (plan.anthropicBaseUrl) return { why: "anthropic turns go to the user's own host, around the model proxy" };
    upstream = plan.tllmEndpoint?.upstream ?? processEnv["MANDU_UPSTREAM"] ?? GOOSE_KEY.anthropic.defaultUpstream;
    field = GOOSE_KEY.anthropic.field;
  } else if (p === "openai") {
    const o = routing.openai;
    if (!o) return { why: "the openai route has no upstream" };
    upstream = o.upstream;
    field = GOOSE_KEY.openai.field;
  } else {
    const spec = gooseCompatSpec(p);
    if (!spec) return { why: `the ${p} provider is not routed` };
    if (spec.keyVar === null) return null;
    const c = (routing.compat ?? []).find((e) => e.provider === p);
    if (!c) return { why: `the ${p} route has no upstream` };
    upstream = c.upstream;
    field = spec.keyVar;
  }
  const g = grantableHost(p, upstream);
  return "why" in g ? g : { field, host: g.host, https: g.https };
}

/**
 * Which fields of Goose's secrets.yaml this launch grants, and to which host,
 * or why none. `env` is the launch environment (HOME, XDG_CONFIG_HOME,
 * GOOSE_PATH_ROOT and the opt-out); `processEnv` the launcher's own, whose
 * `MANDU_UPSTREAM` the model proxy inherits (services/context-proxy.ts). Pure.
 */
export function gooseKeyGrantPlan(plan: KeyGrantLaunch, env: Env, processEnv: Env, platform?: string): KeyGrantPlan {
  if (plan.target !== "goose") return { none: "not a Goose launch" };
  // macOS read-blocks a confined file (the Seatbelt profile has no twin), so
  // a granted secrets.yaml would be unreadable to Goose itself (§3.10). The
  // key variables' env grants need no twin and stay on every platform.
  if (platform !== undefined && platform !== "linux") return { none: "a confined file is read-blocked on this platform" };
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return { none: "the confidentiality axis is off" };
  if (env[AUTH_SUBSTITUTION_ENV] === "0" || processEnv[AUTH_SUBSTITUTION_ENV] === "0") return { none: `${AUTH_SUBSTITUTION_ENV}=0` };
  if (plan.noContextProxy) return { none: "no model proxy runs" };
  const routing = plan.gooseRouting ?? GOOSE_DEFAULT_ROUTING;
  const providers = [...new Set<GooseRoutedProvider>([routing.provider, routing.subagentProvider])];
  const grants: AuthGrantWire[] = [];
  for (const p of providers) {
    const k = gooseProviderKeyHost(p, routing, plan, processEnv);
    if (k === null) continue; // Ollama: no key to put back
    if ("why" in k) return { none: k.why };
    if (!grants.some((g) => g.field === k.field)) grants.push(k);
  }
  if (grants.length === 0) return { none: "no routed provider takes a key" };
  return { grant: { path: gooseSecretsFile(env), grants } };
}

/**
 * The env grants of a `mandu goose` launch (§3.10): each routed provider's
 * key VARIABLE that is set in the launch environment, to that provider's
 * host. Per variable (each authenticates one provider): a provider whose
 * host is not grantable leaves its variable raw, as before. The same
 * switches as the file's. Pure.
 */
export function gooseEnvKeyGrantPlans(plan: KeyGrantLaunch & Pick<LaunchPlan, "envSecrets">, env: Env, processEnv: Env): Array<{ env: string; grants: AuthGrantWire[] }> {
  if (plan.target !== "goose") return [];
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return [];
  if (env[AUTH_SUBSTITUTION_ENV] === "0" || processEnv[AUTH_SUBSTITUTION_ENV] === "0") return [];
  if (plan.noContextProxy || plan.envSecrets === false) return [];
  const routing = plan.gooseRouting ?? GOOSE_DEFAULT_ROUTING;
  const out: Array<{ env: string; grants: AuthGrantWire[] }> = [];
  for (const p of new Set<GooseRoutedProvider>([routing.provider, routing.subagentProvider])) {
    const k = gooseProviderKeyHost(p, routing, plan, processEnv);
    if (k === null || "why" in k) continue;
    if ((env[k.field] ?? "") === "" || out.some((g) => g.env === k.field)) continue;
    out.push({ env: k.field, grants: [k] });
  }
  return out;
}

export interface KeyGrantDeps {
  /** One request on a socket (secret-setup.ts `ndjsonCall`). */
  call: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  log: (m: string) => void;
  fileExists: (path: string) => boolean;
  /** The launcher's pid: the arbiter keeps the grant across its own restart
   *  while this process lives (agent-sign-in.md §3.2 item 4). */
  pid?: number;
  /** The host platform (`linux`, `darwin`): the file is granted on Linux
   *  only, where a confined file is twinned rather than read-blocked. */
  platform?: string;
}

export interface KeyGrantOutcome {
  /** The file is twinned and its key put back at the proxy. */
  granted: boolean;
  /** The key file, when granted. */
  path?: string;
  /** The granted hosts, when granted (for the launch line). */
  hosts?: string[];
  /** Why not, when not. */
  why?: string;
}

/**
 * Plan and record this launch's grant (human plane). Never throws: any
 * failure answers `granted: false`, and the caller keeps the agent's own key
 * file readable (the §5.6.1 posture). A failure to record on a reachable
 * human plane prints one WARNING line; a launch that grants nothing prints
 * nothing.
 */
export async function registerAgentKeyGrant(
  plan: KeyGrantLaunch & Pick<LaunchPlan, "arbiterHumanSock">,
  env: Env,
  processEnv: Env,
  deps: KeyGrantDeps,
): Promise<KeyGrantOutcome> {
  const p = gooseKeyGrantPlan(plan, env, processEnv, deps.platform);
  if ("none" in p) return { granted: false, why: p.none };
  const { path, grants } = p.grant;
  if (!deps.fileExists(path)) return { granted: false, why: "no secrets.yaml" };
  const tail = `Goose reads ${path} raw this session (its own key file, supported-agents.md §5.6.1)`;
  if (!plan.arbiterHumanSock) {
    deps.log(`WARNING: mandu: the protection service reported no human-plane socket; ${tail}`);
    return { granted: false, why: "no human plane" };
  }
  try {
    const r = (await deps.call(plan.arbiterHumanSock, "registerAuthGrant", { path, grants, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) })) as { granted?: unknown } | null;
    if (r === null || typeof r !== "object" || r.granted !== grants.length) {
      deps.log(`WARNING: mandu: the protection service did not record the key's host; ${tail}`);
      return { granted: false, why: "not recorded" };
    }
  } catch (e) {
    deps.log(`WARNING: mandu: could not record the key's host (${e instanceof Error ? e.message : String(e)}); ${tail}`);
    return { granted: false, why: "failed" };
  }
  return { granted: true, path, hosts: grants.map((g) => g.host) };
}

// ── Claude Code's key in the environment (agent-sign-in.md §3.8) ────────────

/** The variable Claude Code reads its API key from (sent as `x-api-key`). */
export const CLAUDE_KEY_VAR = "ANTHROPIC_API_KEY";

export type EnvKeyGrantPlan =
  | { grant: { env: string; grants: AuthGrantWire[] } }
  | { none: string };

export type EnvKeyGrantLaunch = KeyGrantLaunch & Pick<LaunchPlan, "envSecrets">;

/**
 * Whether this launch puts Claude Code's `ANTHROPIC_API_KEY` back at the model
 * proxy, and to which host, or why not. The same host rule as Goose's
 * (`grantableHost`): the anthropic upstream the proxy forwards to must be
 * `api.anthropic.com` over https or this machine's loopback. Only the API
 * key: the subscription's sign-in (`~/.claude/.credentials.json`, the
 * `CLAUDE_CODE_OAUTH_TOKEN` variable) and `ANTHROPIC_AUTH_TOKEN` are left as
 * they are (§1, §3.6). Pure.
 */
export function claudeKeyGrantPlan(plan: EnvKeyGrantLaunch, env: Env, processEnv: Env): EnvKeyGrantPlan {
  if (plan.target !== "claude") return { none: "not a Claude Code launch" };
  if ((env[CLAUDE_KEY_VAR] ?? "") === "") return { none: `no ${CLAUDE_KEY_VAR}` };
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return { none: "the confidentiality axis is off" };
  if (env[AUTH_SUBSTITUTION_ENV] === "0" || processEnv[AUTH_SUBSTITUTION_ENV] === "0") return { none: `${AUTH_SUBSTITUTION_ENV}=0` };
  if (plan.envSecrets === false) return { none: "--no-env-secrets" };
  if (plan.noContextProxy) return { none: "no model proxy runs" };
  if (plan.anthropicBaseUrl) return { none: "Claude Code's turns go to the user's own host, around the model proxy" };
  const upstream = plan.tllmEndpoint?.upstream ?? processEnv["MANDU_UPSTREAM"] ?? GOOSE_KEY.anthropic.defaultUpstream;
  const g = grantableHost("anthropic", upstream);
  if ("why" in g) return { none: g.why };
  return { grant: { env: CLAUDE_KEY_VAR, grants: [{ field: CLAUDE_KEY_VAR, host: g.host, https: g.https }] } };
}

export interface EnvKeyGrantDeps {
  call: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  log: (m: string) => void;
  pid?: number;
}

export interface EnvKeyGrantOutcome {
  /** The variable is masked for the agent and its key put back at the proxy. */
  granted: boolean;
  /** The variable, when granted. */
  name?: string;
  hosts?: string[];
  why?: string;
}

/**
 * Plan and record the grant of Claude Code's key variable (human plane).
 * Never throws: any failure answers `granted: false` and the variable stays
 * raw in the agent's environment (the exemption, plan 10 §11.4), so Claude
 * Code keeps a key it can use. A failure to record on a reachable human plane
 * prints one WARNING line.
 */
export async function registerClaudeKeyGrant(
  plan: EnvKeyGrantLaunch & Pick<LaunchPlan, "arbiterHumanSock">,
  env: Env,
  processEnv: Env,
  deps: EnvKeyGrantDeps,
): Promise<EnvKeyGrantOutcome> {
  const p = claudeKeyGrantPlan(plan, env, processEnv);
  if ("none" in p) return { granted: false, why: p.none };
  const { env: name, grants } = p.grant;
  const tail = `${name} stays in Claude Code's environment as it is this session`;
  if (!plan.arbiterHumanSock) {
    deps.log(`WARNING: mandu: the protection service reported no human-plane socket; ${tail}`);
    return { granted: false, why: "no human plane" };
  }
  try {
    const r = (await deps.call(plan.arbiterHumanSock, "registerAuthGrant", { env: name, grants, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) })) as { granted?: unknown } | null;
    if (r === null || typeof r !== "object" || r.granted !== grants.length) {
      deps.log(`WARNING: mandu: the protection service did not record the key's host; ${tail}`);
      return { granted: false, why: "not recorded" };
    }
  } catch (e) {
    deps.log(`WARNING: mandu: could not record the key's host (${e instanceof Error ? e.message : String(e)}); ${tail}`);
    return { granted: false, why: "failed" };
  }
  return { granted: true, name, hosts: grants.map((g) => g.host) };
}

// ── Codex's saved key (agent-sign-in.md §3.9) ───────────────────────────────

/** The field of Codex's `auth.json` that holds a saved key
 *  (`codex login --with-api-key`). */
export const CODEX_KEY_FIELD = "OPENAI_API_KEY";

/** Codex's `auth.json` for this launch: `$CODEX_HOME/auth.json` when
 *  CODEX_HOME is an absolute path, else `~/.codex/auth.json`. Pure. */
export function codexAuthFile(env: Env): string {
  const home = env["HOME"] ?? "";
  const codexHome = (env["CODEX_HOME"] ?? "").startsWith("/") ? env["CODEX_HOME"]! : `${home.replace(/\/+$/, "")}/.codex`;
  return `${codexHome.replace(/\/+$/, "")}/auth.json`;
}

/** The saved key of an `auth.json` in API-key mode, or why not: a ChatGPT
 *  sign-in (`tokens` present) is refreshed by Codex itself and cannot be
 *  put back (§3.6). Never throws; never logs the value. Pure. */
export function codexSavedKey(text: string | null): { key: string } | { why: string } {
  if (text === null) return { why: "no auth.json" };
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return { why: "auth.json is not JSON" }; }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return { why: "auth.json is not an object" };
  const d = doc as Record<string, unknown>;
  if (d["tokens"] !== undefined && d["tokens"] !== null) return { why: "auth.json holds a ChatGPT sign-in, which Codex refreshes itself" };
  const k = d[CODEX_KEY_FIELD];
  if (typeof k !== "string" || k.trim() === "") return { why: "auth.json holds no saved key" };
  if (!/^[\x21-\x7e]+$/.test(k)) return { why: "the saved key is not a header-safe token" };
  return { key: k };
}

export type CodexKeyGrantLaunch = KeyGrantLaunch & Pick<LaunchPlan, "argv" | "codexAuth" | "openaiBaseUrl" | "writeMcp" | "ullm">;

/**
 * Whether this `mandu codex` launch puts Codex's saved key back at the
 * openai-proxy, and to which host, or why not. Codex sends the key it reads
 * from `auth.json` as `Bearer` only with the sign-in provider (no key
 * variable, `codexAuth: "sign-in"`, §2.2); the openai-proxy sends a request
 * without a ChatGPT account header to its API origin, which must be
 * `api.openai.com` over https or this machine's loopback (§3.2 item 3).
 * Linux only: on macOS a confined file is read-blocked, not twinned, so
 * Codex could not read its login at all. The quarantined `codex exec` (the
 * AI helper on Codex) reads the same file, so it needs the forwarder that
 * puts the key back for it too. Pure over `readFile`.
 */
export function codexKeyGrantPlan(
  plan: CodexKeyGrantLaunch,
  env: Env,
  processEnv: Env,
  platform: string,
  readFile: (path: string) => string | null,
): { grant: { path: string; grants: AuthGrantWire[] }; key: string } | { none: string } {
  if (plan.target !== "codex" || (plan.argv[0] ?? "").split("/").pop() !== "codex") return { none: "not a Codex launch" };
  if (platform !== "linux") return { none: "a confined file is read-blocked on this platform" };
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return { none: "the confidentiality axis is off" };
  if (env[AUTH_SUBSTITUTION_ENV] === "0" || processEnv[AUTH_SUBSTITUTION_ENV] === "0") return { none: `${AUTH_SUBSTITUTION_ENV}=0` };
  if (plan.noContextProxy) return { none: "no model proxy runs" };
  if (plan.codexAuth !== "sign-in") return { none: "Codex authenticates with a key variable this launch" };
  if (plan.openaiBaseUrl) return { none: "Codex's turns go to the user's own host, around the model proxy" };
  if (plan.writeMcp !== false && plan.ullm?.mode === "cli" && plan.ullm.binary === "codex" && !plan.ullm.forwarderUrl) {
    return { none: "the AI helper's codex exec reads the same login and no forwarder runs to put the key back for it" };
  }
  const upstream = plan.tllmEndpoint?.upstream ?? processEnv["MANDU_UPSTREAM"] ?? GOOSE_KEY.openai.defaultUpstream;
  const g = grantableHost("openai", upstream);
  if ("why" in g) return { none: g.why };
  const path = codexAuthFile(env);
  const saved = codexSavedKey(readFile(path));
  if ("why" in saved) return { none: saved.why };
  return { grant: { path, grants: [{ field: CODEX_KEY_FIELD, host: g.host, https: g.https }] }, key: saved.key };
}

export interface CodexKeyGrantOutcome {
  granted: boolean;
  path?: string;
  hosts?: string[];
  /** The saved key (granted only): the U-LLM forwarder puts it back for
   *  the quarantined `codex exec`. Never logged. */
  key?: string;
  why?: string;
}

/** Plan and record the grant of Codex's saved key (human plane). Never
 *  throws: any failure answers `granted: false` and `auth.json` stays
 *  Codex's own raw login, as before. */
export async function registerCodexKeyGrant(
  plan: CodexKeyGrantLaunch & Pick<LaunchPlan, "arbiterHumanSock">,
  env: Env,
  processEnv: Env,
  deps: EnvKeyGrantDeps & { platform: string; readFile: (path: string) => string | null },
): Promise<CodexKeyGrantOutcome> {
  const p = codexKeyGrantPlan(plan, env, processEnv, deps.platform, deps.readFile);
  if ("none" in p) return { granted: false, why: p.none };
  const { path, grants } = p.grant;
  const tail = `Codex reads ${path} raw this session`;
  if (!plan.arbiterHumanSock) {
    deps.log(`WARNING: mandu: the protection service reported no human-plane socket; ${tail}`);
    return { granted: false, why: "no human plane" };
  }
  try {
    const r = (await deps.call(plan.arbiterHumanSock, "registerAuthGrant", { path, grants, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) })) as { granted?: unknown } | null;
    if (r === null || typeof r !== "object" || r.granted !== grants.length) {
      deps.log(`WARNING: mandu: the protection service did not record the key's host; ${tail}`);
      return { granted: false, why: "not recorded" };
    }
  } catch (e) {
    deps.log(`WARNING: mandu: could not record the key's host (${e instanceof Error ? e.message : String(e)}); ${tail}`);
    return { granted: false, why: "failed" };
  }
  return { granted: true, path, hosts: grants.map((g) => g.host), key: p.key };
}

/** The placeholder a structured twin of `auth.json` holds for the saved
 *  key, or null (not a JSON twin, no such field, not a placeholder). Pure. */
export function codexTwinPlaceholder(twin: string | undefined): string | null {
  if (twin === undefined) return null;
  try {
    const v = (JSON.parse(twin) as Record<string, unknown>)[CODEX_KEY_FIELD];
    return typeof v === "string" && /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]\.[A-Za-z_][A-Za-z0-9_]*$/.test(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * Record a `mandu goose` launch's env grants (human plane), one per key
 * variable (`gooseEnvKeyGrantPlans`). Never throws: a variable whose grant
 * is not recorded stays raw in Goose's environment, as before, and says so
 * once. Answers the variables granted, for the env-var mask (`agentKeys`).
 */
export async function registerGooseEnvKeyGrants(
  plan: KeyGrantLaunch & Pick<LaunchPlan, "envSecrets" | "arbiterHumanSock">,
  env: Env,
  processEnv: Env,
  deps: EnvKeyGrantDeps,
): Promise<Array<{ name: string; hosts: string[] }>> {
  return registerEnvKeyGrantPlans(gooseEnvKeyGrantPlans(plan, env, processEnv), "Goose", plan.arbiterHumanSock, deps);
}

/** Record env grants (human plane), one per variable. Never throws: a
 *  variable whose grant is not recorded stays raw in the agent's
 *  environment, as before, and says so once. Answers the variables
 *  granted, for the env-var mask (`agentKeys`). */
async function registerEnvKeyGrantPlans(
  plans: ReadonlyArray<{ env: string; grants: AuthGrantWire[] }>,
  agent: string,
  humanSock: string | null | undefined,
  deps: EnvKeyGrantDeps,
): Promise<Array<{ name: string; hosts: string[] }>> {
  if (plans.length === 0) return [];
  if (!humanSock) {
    deps.log(`WARNING: mandu: the protection service reported no human-plane socket; ${plans.map((p) => p.env).join(", ")} stay in ${agent}'s environment as they are this session`);
    return [];
  }
  const out: Array<{ name: string; hosts: string[] }> = [];
  for (const p of plans) {
    try {
      const r = (await deps.call(humanSock, "registerAuthGrant", { env: p.env, grants: p.grants, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) })) as { granted?: unknown } | null;
      if (r !== null && typeof r === "object" && r.granted === p.grants.length) {
        out.push({ name: p.env, hosts: p.grants.map((g) => g.host) });
        continue;
      }
      deps.log(`WARNING: mandu: the protection service did not record the key's host; ${p.env} stays in ${agent}'s environment as it is this session`);
    } catch (e) {
      deps.log(`WARNING: mandu: could not record the key's host (${e instanceof Error ? e.message : String(e)}); ${p.env} stays in ${agent}'s environment as it is this session`);
    }
  }
  return out;
}

// ── Codex's key variables (agent-sign-in.md §3.11) ──────────────────────────

/** The variables Codex reads an API key from (parse.ts `openaiEnvKey`). */
export const CODEX_KEY_VARS = ["OPENAI_API_KEY", "CODEX_API_KEY"] as const;

/**
 * The env grants of a `mandu codex` launch whose Codex authenticates with a
 * key variable (`codexAuth: "key"`, the provider's `env_key`, §2.2): each of
 * `OPENAI_API_KEY` / `CODEX_API_KEY` that is set, to the openai-proxy's API
 * origin (`api.openai.com` over https, or loopback: §3.2 item 3's rule).
 * The openai-proxy puts the key back as `Bearer` toward that origin only,
 * never on a ChatGPT sign-in's request. Any platform: a variable needs no
 * twin. Pure.
 */
export function codexEnvKeyGrantPlans(
  plan: KeyGrantLaunch & Pick<LaunchPlan, "argv" | "codexAuth" | "openaiBaseUrl" | "envSecrets">,
  env: Env,
  processEnv: Env,
): Array<{ env: string; grants: AuthGrantWire[] }> {
  if (plan.target !== "codex" || (plan.argv[0] ?? "").split("/").pop() !== "codex") return [];
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return [];
  if (env[AUTH_SUBSTITUTION_ENV] === "0" || processEnv[AUTH_SUBSTITUTION_ENV] === "0") return [];
  if (plan.noContextProxy || plan.envSecrets === false) return [];
  if (plan.codexAuth !== "key" || plan.openaiBaseUrl) return [];
  const upstream = plan.tllmEndpoint?.upstream ?? processEnv["MANDU_UPSTREAM"] ?? GOOSE_KEY.openai.defaultUpstream;
  const g = grantableHost("openai", upstream);
  if ("why" in g) return [];
  return CODEX_KEY_VARS.filter((v) => (env[v] ?? "") !== "").map((v) => ({ env: v, grants: [{ field: v, host: g.host, https: g.https }] }));
}

/** Record a `mandu codex` launch's env grants (`codexEnvKeyGrantPlans`). */
export async function registerCodexEnvKeyGrants(
  plan: KeyGrantLaunch & Pick<LaunchPlan, "argv" | "codexAuth" | "openaiBaseUrl" | "envSecrets" | "arbiterHumanSock">,
  env: Env,
  processEnv: Env,
  deps: EnvKeyGrantDeps,
): Promise<Array<{ name: string; hosts: string[] }>> {
  return registerEnvKeyGrantPlans(codexEnvKeyGrantPlans(plan, env, processEnv), "Codex", plan.arbiterHumanSock, deps);
}

// ── Model services no Mandu model proxy fronts (agent-sign-in.md §3.12) ────

/**
 * Key variables of model services that a program in the session calls
 * directly (jev-ultrafast's TypeSafe decision model and its OpenRouter text
 * helper, devtools-relay.md §6), each to its provider's own API host. The
 * variable is masked by its name (`*_API_KEY`) as before; the grant binds its
 * row to that host, so the egress proxy puts the key back in a request to
 * that host only, over TLS inspection, and asks anywhere else. No model
 * proxy is involved: these wires are not ones Mandu's proxies read (a
 * request carrying a registered value verbatim is still refused by the
 * egress proxy's tripwire).
 */
export const PROVIDER_KEY_HOSTS: Readonly<Record<string, string>> = Object.freeze({
  TYPESAFE_API_KEY: "api.typesafe.ai",
  OPENROUTER_API_KEY: "openrouter.ai",
});

/**
 * The provider-key grants of a launch: each `PROVIDER_KEY_HOSTS` variable
 * set in the launch environment, to its host over https. Not under `mandu
 * goose` for a provider Goose routes (that variable is Goose's own key, with
 * its own grant, §3.10). The same switches as the other env grants. Pure.
 */
export function providerKeyGrantPlans(plan: EnvKeyGrantLaunch, env: Env, processEnv: Env): Array<{ env: string; grants: AuthGrantWire[] }> {
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return [];
  if (env[AUTH_SUBSTITUTION_ENV] === "0" || processEnv[AUTH_SUBSTITUTION_ENV] === "0") return [];
  if (plan.envSecrets === false) return [];
  const goose = new Set(plan.target === "goose" ? gooseRoutedKeyVars(plan.gooseRouting) : []);
  return Object.entries(PROVIDER_KEY_HOSTS)
    .filter(([name]) => (env[name] ?? "").trim() !== "" && !goose.has(name))
    .map(([name, host]) => ({ env: name, grants: [{ field: name, host, https: true }] }));
}

/**
 * Record the provider-key grants (human plane). Never throws: a variable
 * whose grant is not recorded is still masked, only unbound, so a request
 * carrying it is held for approval; one WARNING line says so. Answers the
 * variables bound, for the launch line.
 */
export async function registerProviderKeyGrants(
  plan: EnvKeyGrantLaunch & Pick<LaunchPlan, "arbiterHumanSock">,
  env: Env,
  processEnv: Env,
  deps: EnvKeyGrantDeps,
): Promise<Array<{ name: string; hosts: string[] }>> {
  const plans = providerKeyGrantPlans(plan, env, processEnv);
  if (plans.length === 0) return [];
  const unbound = (names: string, why: string): void =>
    deps.log(`WARNING: mandu: ${names} not bound to ${names.includes(",") ? "their hosts" : "its host"} (${why}); masked as any key, so a request carrying it waits for your approval`);
  if (!plan.arbiterHumanSock) {
    unbound(plans.map((p) => p.env).join(", "), "the protection service reported no human-plane socket");
    return [];
  }
  const out: Array<{ name: string; hosts: string[] }> = [];
  for (const p of plans) {
    try {
      const r = (await deps.call(plan.arbiterHumanSock, "registerAuthGrant", { env: p.env, grants: p.grants, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) })) as { granted?: unknown } | null;
      if (r !== null && typeof r === "object" && r.granted === p.grants.length) {
        out.push({ name: p.env, hosts: p.grants.map((g) => g.host) });
        continue;
      }
      unbound(p.env, "not recorded");
    } catch (e) {
      unbound(p.env, e instanceof Error ? e.message : String(e));
    }
  }
  return out;
}

// ── Mandu's own credentials, kept out of the agent's world (§3.11) ──────────

/**
 * Variables of the launcher's environment the agent's process tree never
 * needs: `MANDU_ULLM_API_KEY`, the AI helper's key. The launcher reads it
 * (parse.ts) and hands the helper what it needs through the helper's own
 * entry: the forwarder's stand-in, or the key where no forwarder runs
 * (services/mcp.ts, OpenClaw's plugin config). Being `MANDU_*` routing, the
 * env-var mask exempts it, so until 2026-10-11 it reached the agent raw.
 */
export const LAUNCHER_ONLY_ENV: readonly string[] = ["MANDU_ULLM_API_KEY"];

/** `env` without the launcher-only variables. Pure. */
export function withoutLauncherOnlyEnv<T extends Record<string, string | undefined>>(env: T): T {
  if (!LAUNCHER_ONLY_ENV.some((k) => k in env)) return env;
  const out = { ...env };
  for (const k of LAUNCHER_ONLY_ENV) delete out[k];
  return out;
}
