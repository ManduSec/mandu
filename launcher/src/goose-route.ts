/**
 * goose-route — how `mandu goose` routes Goose's model traffic, and what it
 * forces off (supported-agents.md §5.6, §5.3.4).
 *
 * ROUTING BY ENV (goose 1.53.0, crates/goose/src/config/base.rs): an env var
 * named as an uppercase config key outranks `config.yaml`, so the launch env
 * alone points Goose at the session's model proxy. Two built-in providers
 * are ROUTED:
 *   - `anthropic`: `ANTHROPIC_HOST=<proxy>` (Goose appends `v1/messages`).
 *   - `openai` (2026-10-06): `OPENAI_HOST=<proxy>/_mandu/openai/openai` and
 *     `OPENAI_BASE_PATH` pinned. Goose's openai provider (goose-providers
 *     openai.rs, captured against a scripted upstream) picks the wire PER
 *     MODEL on its default base path `v1/chat/completions`: the Responses API
 *     (`v1/responses`) for gpt-5 / gpt-6 / o-series names, Chat Completions
 *     otherwise; a custom base path pins one wire (a path containing
 *     `responses` the Responses API, one containing `chat/completions`
 *     Chat). The proxy reads both (anthropic-proxy openai-wire.ts, the
 *     same gates as the Messages wire) and forwards to the user's own
 *     endpoint, resolved here as Goose resolves it (gooseOpenAiEndpoint):
 *     env OPENAI_HOST, then OPENAI_BASE_URL (env, then config; a trailing
 *     `/v1` moves into the path), then the config's OPENAI_HOST, then
 *     https://api.openai.com; the base path is OPENAI_BASE_PATH (env, then
 *     config) or the default. The launch keeps the wire choice exactly: the
 *     default path stays `v1/chat/completions` (the upstream is the host, the
 *     proxy accepts one `/v1` before the operation), and a custom path's
 *     prefix moves into the upstream (`openai/v1/chat/completions` becomes
 *     upstream `<host>/openai/v1`, base path `chat/completions`). OPENAI_HOST
 *     is set even when openai is not used: a mid-session `/model --provider
 *     openai` then reaches the proxy, which refuses a provider the launch
 *     did not route, instead of api.openai.com.
 * Five more built-in providers speak Chat Completions to a host taken from
 * an env key, and are ROUTED the same way (2026-10-07, supported-agents.md
 * §5.6.4; GOOSE_COMPAT_PROVIDERS, gooseCompatEndpoint): `litellm`
 * (LITELLM_HOST + LITELLM_BASE_PATH), `openrouter` (OPENROUTER_HOST,
 * `api/v1/chat/completions`), `ollama` (OLLAMA_HOST, `v1/chat/completions`),
 * `xai` (XAI_HOST, `chat/completions`) and `tetrate` (TETRATE_HOST,
 * `v1/chat/completions`). Each key is pinned at
 * `<proxy>/_mandu/openai/<provider>` whether or not the launch routes it, so
 * a switch to one the launch did not route reaches the proxy, which refuses
 * a route it was not given (403, nothing sent); the one the launch routes
 * goes to the proxy as MANDU_OPENAI_UPSTREAMS with the user's own endpoint,
 * resolved as Goose resolves it. Ollama's client also reads a tool call the
 * model WRITES in its text (`<function=name>…`, goose-provider-types
 * formats/ollama.rs), which no wire gate sees: its route is marked
 * `textCalls`, and the proxy ends a response whose text carries that
 * markup (openai-sse.ts).
 * Goose sends its own `agent-session-id` header only, so the session is the
 * per-launch proxy's key (as for Codex), and no header env is needed.
 *
 * THE PROVIDER CHECK (gooseRoutePlan). Goose's main provider is, in order,
 * `--provider` on `session` / `run`, env GOOSE_PROVIDER, then the config's;
 * a subagent's (summon.rs resolve_provider) a recipe's settings, env
 * GOOSE_SUBAGENT_PROVIDER, the `delegate` call's `provider`, the config's,
 * then the session's. The launch pins both env keys to the provider it
 * resolved (`anthropic` when none is named), which outranks the config and
 * the call (the call's field is refused on the wire as well,
 * tool-gate-surface.ts), and refuses a launch whose argv, env or config
 * names a provider it does not route, or an openai endpoint the proxy
 * cannot reach (a query string, plain http off this machine, a base path
 * that is neither wire), rather than silently switching the user's provider.
 * A declarative provider (`<config dir>/custom_providers/*.json`, which
 * carries its own base URL) named `anthropic` or `openai` is refused too.
 * NOT ROUTED: every declarative provider (Goose's 48 bundled ones, such as
 * groq, mistral and deepseek, and the user's own custom_providers): its base
 * URL is in its definition (11 of the bundled ones take it from an env key,
 * `${LMSTUDIO_HOST}/v1/…`; the other 37 are literal), and its wire is not
 * one the launch maps onto the proxy; and every built-in provider with its
 * own wire (google, bedrock, gcp_vertex_ai, databricks, ollama, …). They are
 * FENCED instead (below): a launch that names one is refused, and a switch
 * to one mid-session sends nothing. A recipe's
 * settings outrank the env: `run --recipe` is read before the launch and
 * gets `--provider <routed>` pinned, which outranks the recipe
 * (goose-recipe.ts, given the provider resolved here); a recipe as a
 * `delegate` source is refused on the wire. `review` passes its `--provider`
 * to every `goose run` child, so it is checked here like `run`'s.
 * gooseProviderVerdict is the per-name rule, for any other place that reads
 * a provider name. The main provider is read in Goose's order: `--provider`,
 * env GOOSE_PROVIDER, the config's `active_provider` (what `goose configure`
 * writes), then its GOOSE_PROVIDER.
 *
 * THE PROVIDER FENCE (2026-10-07, supported-agents.md §5.6.3). The launch
 * check covers what Goose starts on; an interactive `/model --provider
 * <name>` builds another provider MID-SESSION (and a nested `goose run
 * --provider <name>` at its start), reading that provider's endpoint keys
 * env first at that moment. So the launch env also points every endpoint
 * key of every provider it does not route where nothing is sent
 * (GOOSE_PROVIDER_FENCE: the proxy's refusal route, a `.invalid` host, a CLI
 * path that cannot exist), the user's own declarative providers' `${VAR}`
 * keys likewise (gooseCustomProviderFence), and the network layer denies the
 * hosts no key can move (GOOSE_PROVIDER_HOSTS at the net-proxy; a user's
 * declarative provider's literal host at both layers, upload-deny.ts). A
 * declarative provider the launch can fence neither way (a host built from
 * a variable mid-URL, or api.anthropic.com / api.openai.com itself) refuses
 * the launch.
 *
 * WHAT THE LAUNCH FORCES OFF (gooseForcedEnv), each a channel that would carry
 * conversation data, original tool output included, past the model proxy:
 *   - PostHog usage telemetry (opt-in): GOOSE_TELEMETRY_OFF=1 and
 *     GOOSE_TELEMETRY_ENABLED=false;
 *   - Langfuse traces of every LLM call: on only when LANGFUSE_PUBLIC_KEY and
 *     LANGFUSE_SECRET_KEY (or their LANGFUSE_INIT_PROJECT_ forms) are both
 *     set; Goose reads the first form and falls back to the second only when
 *     the first is UNSET, so all four are set EMPTY (an empty key turns the
 *     observer off; tracing/langfuse_layer.rs);
 *   - OTLP traces, metrics and logs: OTEL_SDK_DISABLED=true (checked before
 *     any endpoint, otel/otlp.rs);
 *   - the prompt and command classifiers (they post the conversation to an
 *     endpoint): SECURITY_PROMPT_CLASSIFIER_ENABLED=false,
 *     SECURITY_COMMAND_CLASSIFIER_ENABLED=false and the command one's
 *     _OVERRIDE;
 *   - the toolshim (a second model at OLLAMA_HOST): GOOSE_TOOLSHIM=false;
 *   - the experimental state-machine agent loop: GOOSE_STATE_MACHINE=false
 *     (read from the env only, agents/state_machine/mod.rs). With it on, an
 *     ACP `session/load` of a session with a pending tool confirmation starts
 *     a turn ON LOAD (acp/server/load_session.rs), on the provider saved with
 *     the session, before the ACP relay has seen that provider or any
 *     `session/prompt` it gates (goose-acp-relay.ts); and the tool surface
 *     Mandu's gates were captured on is the default loop's.
 * The network layer denies the fixed upload hosts and any configured
 * endpoint as well (upload-deny.ts), and `goose session export --nostr` is
 * refused at launch (goose-argv.ts).
 *
 * Pure except readGooseConfig (reads the config file and the custom
 * providers directory); unit-tested in test/unit/goose-route.test.ts and
 * goose-provider-fence.test.ts.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { routableUpstream, type OpenAiRoute } from "./agent-model-route.js";
import { gooseFlagValues, gooseValueFlags, readGooseArgv } from "./goose-argv.js";

/** The anthropic provider: Goose's default under Mandu when none is named. */
export const GOOSE_ROUTED_PROVIDER = "anthropic";

/** Goose's built-in Chat Completions providers with an env host, routed
 *  through the proxy's OpenAI route of the same id (module header). */
export type GooseCompatProvider = "litellm" | "openrouter" | "ollama" | "xai" | "tetrate";

/** Goose's built-in providers the launch routes through the model proxy. */
export type GooseRoutedProvider = "anthropic" | "openai" | GooseCompatProvider;

/** One Chat Completions provider as goose 1.53.0 builds it (goose
 *  providers/litellm.rs, openrouter_def.rs, ollama_def.rs, xai.rs,
 *  tetrate.rs; read from the source and captured against a scripted
 *  upstream). */
export interface GooseCompatSpec {
  provider: GooseCompatProvider;
  /** the env / config key Goose reads the host from (`Config::get_param`) */
  hostKey: string;
  /** Goose's default host when the key is unset */
  defaultHost: string;
  /** the request path Goose joins to the host (litellm: LITELLM_BASE_PATH's default) */
  path: string;
  /** the key variable of its API key; null when it takes none */
  keyVar: string | null;
}

export const GOOSE_COMPAT_PROVIDERS: readonly GooseCompatSpec[] = [
  // LITELLM_BASE_PATH (env, then config) replaces the path; an empty key
  // sends no Authorization at all
  { provider: "litellm", hostKey: "LITELLM_HOST", defaultHost: "http://localhost:4000", path: "v1/chat/completions", keyVar: "LITELLM_API_KEY" },
  { provider: "openrouter", hostKey: "OPENROUTER_HOST", defaultHost: "https://openrouter.ai", path: "api/v1/chat/completions", keyVar: "OPENROUTER_API_KEY" },
  // a host with no scheme gets http://, a bare loopback name port 11434
  { provider: "ollama", hostKey: "OLLAMA_HOST", defaultHost: "localhost", path: "v1/chat/completions", keyVar: null },
  { provider: "xai", hostKey: "XAI_HOST", defaultHost: "https://api.x.ai/v1", path: "chat/completions", keyVar: "XAI_API_KEY" },
  { provider: "tetrate", hostKey: "TETRATE_HOST", defaultHost: "https://api.router.tetrate.ai", path: "v1/chat/completions", keyVar: "TETRATE_API_KEY" },
];

export const GOOSE_ROUTED_PROVIDERS: readonly GooseRoutedProvider[] = ["anthropic", "openai", ...GOOSE_COMPAT_PROVIDERS.map((c) => c.provider)];

/** The spec of a Chat Completions provider, or undefined. */
export function gooseCompatSpec(provider: string): GooseCompatSpec | undefined {
  return GOOSE_COMPAT_PROVIDERS.find((c) => c.provider === provider);
}

/** LITELLM_BASE_PATH's default (litellm.rs). */
export const GOOSE_LITELLM_DEFAULT_BASE_PATH = "v1/chat/completions";

/** A Chat Completions provider's endpoint as the proxy reaches it
 *  (gooseCompatEndpoint). */
export interface GooseCompatEndpoint {
  provider: GooseCompatProvider;
  /** where the proxy sends the gated request: `<upstream><path Goose sent>` */
  upstream: string;
  /** litellm only: LITELLM_BASE_PATH as the launch pins it */
  basePath?: string;
}

/** The proxy route id (`/_mandu/openai/<id>`) of Goose's openai provider. */
export const GOOSE_OPENAI_ROUTE_ID = "openai";

/** Goose's openai default base path, on which it picks the wire per model. */
export const GOOSE_OPENAI_DEFAULT_BASE_PATH = "v1/chat/completions";

/** Goose's openai endpoint as the proxy reaches it (gooseOpenAiEndpoint). */
export interface GooseOpenAiEndpoint {
  /** where the proxy sends the gated request: `<upstream><path Goose sent>` */
  upstream: string;
  /** OPENAI_BASE_PATH as the launch pins it (relative, no leading slash) */
  basePath: string;
  /** `per-model` on the default path; else the one wire the path pins */
  wire: "per-model" | "chat" | "responses";
}

/** What the launch routes for one Goose session (gooseRoutePlan). */
export interface GooseRouting {
  /** GOOSE_PROVIDER as the launch pins it */
  provider: GooseRoutedProvider;
  /** GOOSE_SUBAGENT_PROVIDER as the launch pins it */
  subagentProvider: GooseRoutedProvider;
  /** the openai endpoint, when the session or its subagents use openai */
  openai: GooseOpenAiEndpoint | null;
  /** the Chat Completions providers' endpoints the session or its subagents
   *  use (GOOSE_COMPAT_PROVIDERS); absent when none */
  compat?: GooseCompatEndpoint[];
  /** the user's declarative providers' `${VAR}` host keys, fenced like
   *  GOOSE_PROVIDER_FENCE (gooseRoutePlan) */
  fencedVars?: GooseFence[];
}

/** A launch that names no provider: anthropic, as before 2026-10-06. */
export const GOOSE_DEFAULT_ROUTING: GooseRouting = { provider: "anthropic", subagentProvider: "anthropic", openai: null };

/** The OpenAI route the context proxy serves for this routing (its upstream
 *  goes to the proxy as MANDU_OPENAI_UPSTREAMS), or none. `api` records the
 *  wire the path pins; on the default path Goose picks per model and the
 *  proxy reads both. */
export function gooseOpenAiRoutes(routing: GooseRouting | undefined): OpenAiRoute[] {
  const out: OpenAiRoute[] = [];
  const o = routing?.openai;
  if (o) out.push({ id: GOOSE_OPENAI_ROUTE_ID, api: o.wire === "responses" ? "openai-responses" : "openai-completions", upstream: o.upstream });
  // The Chat Completions providers; Ollama's client also runs a tool call
  // written in the model's text, so its route says so (module header).
  for (const c of routing?.compat ?? []) {
    out.push({ id: c.provider, api: "openai-completions", upstream: c.upstream, ...(c.provider === "ollama" ? { textCalls: true } : {}) });
  }
  return out;
}

/** The key variables of the Chat Completions providers this launch routes
 *  (OPENROUTER_API_KEY, …): the agent's own model credential, which the
 *  launch leaves unmasked in its environment as the arbiter leaves
 *  ANTHROPIC_API_KEY and OPENAI_API_KEY (secret-setup.ts applyEnvSecrets;
 *  secret-extract.ts envSecretExempt). Masked, Goose would send the
 *  placeholder as its key and every turn would fail authentication; the key
 *  is used at the model proxy, which relays it to the provider it belongs
 *  to. A variable the launch granted (agent-sign-in.md §3.10,
 *  agent-key-grant.ts `gooseEnvKeyGrantPlans`) is masked after all: the
 *  model proxy puts the key back (secret-setup.ts `agentKeys`). Pure. */
export function gooseRoutedKeyVars(routing: GooseRouting | undefined): string[] {
  return (routing?.compat ?? []).flatMap((c) => {
    const k = gooseCompatSpec(c.provider)?.keyVar;
    return k ? [k] : [];
  });
}

/** Where a Chat Completions provider's host key points under the launch:
 *  the proxy's route of the provider's own id. Pure. */
export function gooseCompatUrl(proxyUrl: string, provider: GooseCompatProvider): string {
  return `${proxyUrl.replace(/\/+$/, "")}/_mandu/openai/${provider}`;
}

/** How one fenced key is spelled so that Goose sends nothing anywhere. */
export type GooseFenceForm =
  /** a base URL: the proxy's refusal route (gooseRefusalUrl) */
  | "url"
  /** a bare host name Goose puts after `https://`: GOOSE_REFUSED_HOST */
  | "hostname"
  /** a location Goose builds `https://<location>-aiplatform…` from */
  | "location"
  /** a CLI Goose spawns: GOOSE_REFUSED_COMMAND, which cannot exist */
  | "command";

/** One endpoint key of a provider the launch does not route. */
export interface GooseFence {
  key: string;
  /** Goose's provider name (the refusal route's id names it) */
  provider: string;
  form: GooseFenceForm;
}

/**
 * THE PROVIDER FENCE (supported-agents.md §5.6.3): every endpoint key of a
 * goose 1.53.0 provider Mandu does not route. Goose reads each with
 * `Config::get_param` (env first, then config.yaml) when it BUILDS the
 * provider, which an interactive `/model --provider <name>` does mid-session
 * (goose-cli session/mod.rs handle_model -> providers::create) and a nested
 * `goose run --provider <name>` does at its start, both with the launch env.
 * The launch points each key where nothing is sent: a base URL at the
 * proxy's refusal route (`<proxy>/_mandu/openai/goose-unrouted-<provider>`,
 * which the proxy answers 403 without dialing anything, route.ts
 * classifyOpenAiRoute: the id is never routed), a host name at a `.invalid`
 * name (RFC 6761: never resolves), a CLI path at one that cannot exist.
 * Pinned by reading 1.53.0's providers; the hosts with no key are denied at
 * the net-proxy instead (upload-deny.ts goose `proxyOnly`).
 */
export const GOOSE_PROVIDER_FENCE: readonly GooseFence[] = [
  // built-in providers with an env host (goose providers/*.rs); the five
  // Chat Completions ones (GOOSE_COMPAT_PROVIDERS) are pinned at their proxy
  // route instead (gooseForcedEnv), which refuses one the launch did not route
  { key: "GOOGLE_HOST", provider: "google", form: "url" },
  { key: "AVIAN_HOST", provider: "avian", form: "url" },
  { key: "GONDOLA_HOST", provider: "gondola", form: "url" },
  { key: "HF_HOST", provider: "huggingface", form: "url" },
  { key: "MUSE_CODE_HOST", provider: "muse_code", form: "url" },
  { key: "MUSE_CODE_AUTH_HOST", provider: "muse_code", form: "url" },
  { key: "DATABRICKS_HOST", provider: "databricks", form: "url" },
  { key: "AZURE_OPENAI_ENDPOINT", provider: "azure_openai", form: "url" },
  { key: "AZURE_FOUNDRY_ENDPOINT", provider: "azure_foundry", form: "url" },
  // Snowflake appends `.snowflakecomputing.com` to a host without it and
  // refuses a URL that is not https: the http refusal URL fails there.
  { key: "SNOWFLAKE_HOST", provider: "snowflake", form: "url" },
  { key: "GITHUB_COPILOT_HOST", provider: "github_copilot", form: "hostname" },
  { key: "GITHUB_COPILOT_TOKEN_URL", provider: "github_copilot", form: "url" },
  { key: "GCP_LOCATION", provider: "gcp_vertex_ai", form: "location" },
  // the AWS SDK's per-service endpoint (aws-config 1.12, env first)
  { key: "AWS_ENDPOINT_URL_BEDROCK_RUNTIME", provider: "aws_bedrock", form: "url" },
  { key: "AWS_ENDPOINT_URL_SAGEMAKER_RUNTIME", provider: "sagemaker_tgi", form: "url" },
  // the bundled declarative providers whose base_url is `${VAR}…`
  // (goose-providers declarative/definitions/*.json)
  { key: "ATOMIC_CHAT_HOST", provider: "atomic_chat", form: "url" },
  { key: "ASTRON_BASE_URL", provider: "iflytek_astron", form: "url" },
  { key: "LLAMA_SWAP_HOST", provider: "llama_swap", form: "url" },
  { key: "LMSTUDIO_HOST", provider: "lmstudio", form: "url" },
  { key: "LYNKR_HOST", provider: "lynkr", form: "url" },
  { key: "MOONSHOT_BASE_URL", provider: "moonshot", form: "url" },
  { key: "OMLX_HOST", provider: "omlx", form: "url" },
  { key: "ROUTSTR_HOST", provider: "routstr", form: "url" },
  { key: "TANZU_AI_ENDPOINT", provider: "tanzu_ai", form: "url" },
  { key: "ZAI_BASE_URL", provider: "zai", form: "url" },
  { key: "ZHIPU_BASE_URL", provider: "zhipu", form: "url" },
  // providers that spawn another agent's CLI, which dials its own vendor
  // (claude_code and gemini_cli are refused by Goose on a switch, since they
  // keep their own context; fenced anyway for a launch-time build)
  { key: "CODEX_COMMAND", provider: "codex", form: "command" },
  { key: "CURSOR_AGENT_COMMAND", provider: "cursor_agent", form: "command" },
  { key: "CLAUDE_CODE_COMMAND", provider: "claude_code", form: "command" },
  { key: "GEMINI_CLI_COMMAND", provider: "gemini_cli", form: "command" },
];

/** AWS commercial and GovCloud regions (2026-10), for Bedrock's per-region
 *  hosts below. */
const AWS_REGIONS: readonly string[] = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ca-west-1", "mx-central-1",
  "sa-east-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1",
  "eu-south-1", "eu-south-2", "il-central-1", "me-south-1", "me-central-1", "af-south-1",
  "ap-east-1", "ap-east-2", "ap-south-1", "ap-south-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
  "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7",
  "us-gov-east-1", "us-gov-west-1",
];

/**
 * The model API hosts of goose 1.53.0's providers Mandu does not route,
 * denied at the net-proxy only (upload-deny.ts goose `proxyOnly`, which says
 * why not at the guard). The second fence beside GOOSE_PROVIDER_FENCE: it
 * covers the providers with no endpoint key (the bundled declarative ones
 * with a literal base_url, chatgpt_codex, gemini_oauth, kimicode, nanogpt,
 * the Bedrock mantle endpoint) and the default hosts of the fenced ones (a
 * nested `goose` started with the fence keys overridden). Goose's HTTP
 * client honours HTTPS_PROXY (goose-providers api_client.rs, the default
 * transport). Never api.anthropic.com or api.openai.com (Mandu's own model
 * traffic; GOOSE_UNDENIABLE_HOSTS), nor a loopback default (the user's
 * local servers; their keys are fenced).
 */
export const GOOSE_PROVIDER_HOSTS: readonly string[] = [
  // bundled declarative providers, literal base_url
  "api.aimlapi.com", "dashscope-intl.aliyuncs.com", "inference.celeris.ai", "api.cerebras.ai",
  "api.deepseek.com", "api.empiriolabs.ai", "api.eurouter.ai", "api.fireworks.ai", "api.friendli.ai",
  "futurmix.ai", "api.groq.com", "spark-api-open.xf-yun.com", "api.inceptionlabs.ai", "api.meta.ai",
  "api.minimax.io", "api.mistral.ai", "cloud-api.near.ai", "api.novita.ai", "integrate.api.nvidia.com",
  "ollama.com", "opencode.ai", "api.opper.ai", "api.orcarouter.ai", "oai.endpoints.kepler.ai.cloud.ovh.net",
  "api.perplexity.ai", "router.pleum.ai", "api.sakana.ai", "ai.salad.cloud", "api.saygm.com",
  "api.scaleway.ai", "api.tensorix.ai", "api.together.xyz", "api.trustedrouter.com", "api.venice.ai",
  "ai-gateway.vercel.sh", "api.z.ai",
  // the remote defaults of the bundled declarative `${VAR}` providers
  "maas-token-api.cn-huabei-1.xf-yun.com", "maas-coding-api.cn-huabei-1.xf-yun.com", "api.moonshot.cn",
  "api.moonshot.ai", "open.bigmodel.cn", "api.routstr.com",
  // built-in providers with a fixed host (no endpoint key)
  "chatgpt.com", "cloudcode-pa.googleapis.com", "api.kimi.com", "nano-gpt.com",
  // the default hosts of the fenced built-in providers, and of the routed
  // Chat Completions ones (the agent reaches those only through the model
  // proxy, which dials from outside the agent's network)
  "openrouter.ai", "api.router.tetrate.ai", "api.x.ai", "generativelanguage.googleapis.com",
  "api.avian.io", "api.gondola-ai.com", "router.huggingface.co", "api.githubcopilot.com",
  ".githubcopilot.com", "aiplatform.googleapis.com",
  // Bedrock: the runtime (the AWS SDK) and the mantle endpoint (reqwest),
  // per region
  ...AWS_REGIONS.flatMap((r) => [`bedrock-runtime.${r}.amazonaws.com`, `bedrock-runtime-fips.${r}.amazonaws.com`, `bedrock-mantle.${r}.api.aws`]),
];

/** The host name a fenced `hostname` key gets: `.invalid` never resolves. */
export const GOOSE_REFUSED_HOST = "goose-provider-not-routed-by-mandu.invalid";

/** The CLI path a fenced `command` key gets: under /dev/null, so it cannot
 *  exist, and absolute, so no PATH search can find a planted one. */
export const GOOSE_REFUSED_COMMAND = "/dev/null/goose-provider-not-routed-by-mandu";

/** The proxy route id prefix of an unrouted provider (never a routed id). */
export const GOOSE_UNROUTED_ROUTE_PREFIX = "goose-unrouted-";

/** The refusal URL for an unrouted provider: under the proxy's OpenAI route
 *  prefix with an id the launch never routes, so the proxy answers 403 and
 *  sends nothing, whatever path Goose appends. Pure. */
export function gooseRefusalUrl(proxyUrl: string, provider: string): string {
  const id = `${GOOSE_UNROUTED_ROUTE_PREFIX}${provider}`.replace(/[^A-Za-z0-9._-]/g, "_");
  return `${proxyUrl.replace(/\/+$/, "")}/_mandu/openai/${id}`;
}

/** One fence value. Pure. */
export function gooseFenceValue(fence: Pick<GooseFence, "provider" | "form">, proxyUrl: string): string {
  switch (fence.form) {
    case "url": return gooseRefusalUrl(proxyUrl, fence.provider);
    case "hostname": return GOOSE_REFUSED_HOST;
    // `https://<location>-aiplatform.googleapis.com` becomes a host under
    // `.invalid` and a path (gcpvertexai.rs build_host_url)
    case "location": return `${GOOSE_REFUSED_HOST}/`;
    case "command": return GOOSE_REFUSED_COMMAND;
  }
}

/** The fence env (GOOSE_PROVIDER_FENCE, then the user's own declarative
 *  providers' `${VAR}` hosts, gooseRoutePlan `fencedVars`). Pure. */
export function gooseFenceEnv(proxyUrl: string, fencedVars: readonly GooseFence[] = []): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of [...GOOSE_PROVIDER_FENCE, ...fencedVars]) {
    if (!(f.key in out)) out[f.key] = gooseFenceValue(f, proxyUrl);
  }
  return out;
}

/** The env the launch sets for a Goose agent (env-compose.ts).
 *  `anthropicHost` is ANTHROPIC_HOST (the proxy, or the user's own
 *  undeclared endpoint, parse.ts); `proxyUrl` is the proxy, where the
 *  openai route and the refusal routes live. */
export function gooseForcedEnv(
  anthropicHost: string,
  proxyUrl: string = anthropicHost,
  routing: GooseRouting = GOOSE_DEFAULT_ROUTING,
): Record<string, string> {
  return {
    // The provider fence first: the keys below (the routed providers'
    // hosts) are Mandu's own and are never fenced.
    ...gooseFenceEnv(proxyUrl, routing.fencedVars ?? []),
    GOOSE_PROVIDER: routing.provider,
    GOOSE_SUBAGENT_PROVIDER: routing.subagentProvider,
    ANTHROPIC_HOST: anthropicHost,
    // Set whether or not openai is used: a mid-session `/model --provider
    // openai` then reaches the proxy, which refuses an unrouted provider.
    OPENAI_HOST: `${proxyUrl.replace(/\/+$/, "")}/_mandu/openai/${GOOSE_OPENAI_ROUTE_ID}`,
    OPENAI_BASE_PATH: routing.openai?.basePath ?? GOOSE_OPENAI_DEFAULT_BASE_PATH,
    // The Chat Completions providers, each at its own proxy route, routed
    // or not: a switch to one the launch did not route is refused there.
    ...Object.fromEntries(GOOSE_COMPAT_PROVIDERS.map((c) => [c.hostKey, gooseCompatUrl(proxyUrl, c.provider)])),
    LITELLM_BASE_PATH: routing.compat?.find((c) => c.provider === "litellm")?.basePath ?? GOOSE_LITELLM_DEFAULT_BASE_PATH,
    GOOSE_TELEMETRY_OFF: "1",
    GOOSE_TELEMETRY_ENABLED: "false",
    LANGFUSE_PUBLIC_KEY: "",
    LANGFUSE_SECRET_KEY: "",
    LANGFUSE_INIT_PROJECT_PUBLIC_KEY: "",
    LANGFUSE_INIT_PROJECT_SECRET_KEY: "",
    OTEL_SDK_DISABLED: "true",
    SECURITY_PROMPT_CLASSIFIER_ENABLED: "false",
    SECURITY_COMMAND_CLASSIFIER_ENABLED: "false",
    SECURITY_COMMAND_CLASSIFIER_ENABLED_OVERRIDE: "false",
    GOOSE_TOOLSHIM: "false",
    GOOSE_STATE_MACHINE: "false",
  };
}

/** A user's ANTHROPIC_HOST as a base-URL override, or undefined when it is
 *  unset or names Goose's own default (`https://api.anthropic.com`, with or
 *  without a trailing slash): that is no endpoint of the user's own. Pure. */
export function gooseHostOverride(host: string | undefined): string | undefined {
  const h = host?.trim();
  if (!h) return undefined;
  return /^https:\/\/api\.anthropic\.com\/?$/i.test(h) ? undefined : h;
}

/** Goose's config directory (goose 1.53.0 config/paths.rs): an absolute
 *  GOOSE_PATH_ROOT's `config`, else the XDG config dir's `goose`. */
export function gooseConfigDir(env: Record<string, string | undefined>): string {
  const root = env["GOOSE_PATH_ROOT"];
  if (root && isAbsolute(root)) return join(root, "config");
  const xdg = env["XDG_CONFIG_HOME"];
  return join(xdg && isAbsolute(xdg) ? xdg : join(env["HOME"] || homedir(), ".config"), "goose");
}

/** The top-level scalar keys of a Goose `config.yaml` (Goose writes it flat:
 *  `KEY: value`). Nested maps and lists are skipped; quotes are stripped.
 *  Pure. */
export function gooseConfigScalars(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    let v = m[2]!.replace(/\s+#.*$/, "");
    if (v === "" || v === "|" || v === ">") continue;
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    out[m[1]!] = v;
  }
  return out;
}

/** What the launch reads of the user's Goose config. */
export interface GooseConfig {
  path: string;
  /** null when the file is absent */
  values: Record<string, string> | null;
  /** declarative providers (custom_providers/*.json) by file, their names
   *  (`name` and `id`, one entry each) and base URL as written */
  customProviders: Array<{ file: string; name: string; baseUrl?: string; engine?: string }>;
}

/** Read the user's Goose config and declarative providers. Never throws: an
 *  unreadable file reads as absent values (the env pins outrank it anyway). */
export function readGooseConfig(env: Record<string, string | undefined>): GooseConfig {
  const dir = gooseConfigDir(env);
  const path = join(dir, "config.yaml");
  let values: Record<string, string> | null = null;
  try {
    if (existsSync(path)) values = gooseConfigScalars(readFileSync(path, "utf8"));
  } catch { values = null; }
  const customProviders: GooseConfig["customProviders"] = [];
  try {
    const cdir = join(dir, "custom_providers");
    if (existsSync(cdir)) {
      for (const f of readdirSync(cdir)) {
        if (!f.endsWith(".json")) continue;
        try {
          const doc = JSON.parse(readFileSync(join(cdir, f), "utf8")) as Record<string, unknown>;
          const baseUrl = typeof doc["base_url"] === "string" ? { baseUrl: doc["base_url"] as string } : {};
          const engine = typeof doc["engine"] === "string" ? { engine: doc["engine"] as string } : {};
          for (const k of ["name", "id"]) if (typeof doc[k] === "string") customProviders.push({ file: f, name: doc[k] as string, ...baseUrl, ...engine });
        } catch { /* not a provider file Goose could load either */ }
      }
    }
  } catch { /* unreadable dir */ }
  return { path, values, customProviders };
}

/** A value as Goose would read it: env (set and non-empty) wins over the
 *  config. Returns the value and where it came from. */
function gooseParam(
  key: string,
  env: Record<string, string | undefined>,
  cfg: GooseConfig | null,
): { value: string; where: string } | null {
  const e = env[key];
  if (e !== undefined && e.trim() !== "") return { value: e.trim(), where: `the environment's ${key}` };
  const c = cfg?.values?.[key];
  if (c !== undefined && c.trim() !== "") return { value: c.trim(), where: `${key} in ${cfg?.path ?? "the Goose config"}` };
  return null;
}

/** Goose's ensure_url_scheme (goose-providers openai.rs): a URL with no
 *  scheme is http for a loopback name, https otherwise. */
function withScheme(raw: string): string {
  if (raw.includes("://")) return raw;
  const hostPart = raw.split(/[/?]/)[0] ?? raw;
  const bare = hostPart.startsWith("[") ? (hostPart.slice(1).split("]")[0] ?? "") : (hostPart.split(":")[0] ?? "");
  return `${["localhost", "127.0.0.1", "0.0.0.0", "::1"].includes(bare) ? "http" : "https"}://${raw}`;
}

/** scheme://[user[:pass]@]host[:port] of a URL. */
function originWithCredentials(u: URL): string {
  const cred = u.username ? `${u.username}${u.password ? `:${u.password}` : ""}@` : "";
  return `${u.protocol}//${cred}${u.host}`;
}

/**
 * Goose's openai endpoint, resolved the way goose 1.53.0 resolves it
 * (openai_def.rs resolve_base_url): env OPENAI_HOST; else OPENAI_BASE_URL
 * (env, then config: a trailing `/v1` moves into the default path, query
 * parameters ride every request); else the config's OPENAI_HOST; else
 * https://api.openai.com. The base path is OPENAI_BASE_PATH (env only after
 * an OPENAI_BASE_URL, env then config otherwise), else `v1/chat/completions`
 * (`chat/completions` after an OPENAI_BASE_URL without `/v1`). Returned as
 * the proxy's upstream and the base path the launch pins, keeping Goose's
 * wire choice (module header), or why the proxy cannot carry it. Pure.
 */
export function gooseOpenAiEndpoint(
  env: Record<string, string | undefined>,
  cfg: GooseConfig | null,
): GooseOpenAiEndpoint | { why: string } {
  let host: string;
  let hostWhere: string;
  let basePath: { value: string; where: string } | null;
  const envHost = env["OPENAI_HOST"];
  const baseUrl = gooseParam("OPENAI_BASE_URL", env, cfg);
  if (envHost !== undefined && envHost.trim() !== "") {
    host = envHost.trim();
    hostWhere = "the environment's OPENAI_HOST";
    basePath = gooseParam("OPENAI_BASE_PATH", env, cfg);
  } else if (baseUrl !== null) {
    let u: URL;
    try { u = new URL(withScheme(baseUrl.value)); } catch { return { why: `${baseUrl.where} (\`${baseUrl.value}\`) is not a URL` }; }
    if (u.search !== "") {
      return { why: `${baseUrl.where} carries query parameters (\`${u.search}\`), which Mandu's model proxy does not add to the requests it forwards` };
    }
    const path = u.pathname.replace(/\/+$/, "");
    const hasV1 = path === "" || path === "/v1" || path.endsWith("/v1");
    host = `${originWithCredentials(u)}${hasV1 ? path.replace(/\/v1$/, "") : path}`;
    hostWhere = baseUrl.where;
    const envBp = env["OPENAI_BASE_PATH"];
    basePath = envBp !== undefined && envBp.trim() !== ""
      ? { value: envBp.trim(), where: "the environment's OPENAI_BASE_PATH" }
      : { value: hasV1 ? GOOSE_OPENAI_DEFAULT_BASE_PATH : "chat/completions", where: `${baseUrl.where} (Goose's path for it)` };
  } else {
    const c = gooseParam("OPENAI_HOST", {}, cfg);
    host = c?.value ?? "https://api.openai.com";
    hostWhere = c?.where ?? "Goose's default openai host";
    basePath = gooseParam("OPENAI_BASE_PATH", env, cfg);
  }
  const bpRaw = basePath?.value ?? GOOSE_OPENAI_DEFAULT_BASE_PATH;
  // An absolute base path replaces the host's own path (Url::join).
  let base = host;
  if (bpRaw.startsWith("/")) {
    try { base = originWithCredentials(new URL(host)); } catch { /* refused below */ }
  }
  const bp = bpRaw.replace(/^\/+/, "").replace(/\/+$/, "");
  const lower = bp.toLowerCase();
  let wire: GooseOpenAiEndpoint["wire"];
  let prefix: string;
  let pinned: string;
  if (lower === GOOSE_OPENAI_DEFAULT_BASE_PATH) {
    wire = "per-model"; prefix = ""; pinned = GOOSE_OPENAI_DEFAULT_BASE_PATH;
  } else if (lower === "responses" || lower.endsWith("/responses")) {
    wire = "responses"; prefix = bp.slice(0, bp.length - "responses".length); pinned = "responses";
  } else if (lower === "chat/completions" || lower.endsWith("/chat/completions")) {
    wire = "chat"; prefix = bp.slice(0, bp.length - "chat/completions".length); pinned = "chat/completions";
  } else {
    const where = basePath?.where ?? "OPENAI_BASE_PATH";
    return { why: `${where} (\`${bpRaw}\`) ends in neither \`chat/completions\` nor \`responses\`, the two OpenAI wires Mandu's model proxy reads` };
  }
  const trimmedPrefix = prefix.replace(/\/+$/, "");
  const upstream = routableUpstream(`${base.replace(/\/+$/, "")}${trimmedPrefix ? `/${trimmedPrefix}` : ""}`);
  if (upstream === null) {
    return {
      why: `${hostWhere} (\`${host}\`) is not an endpoint Mandu's model proxy forwards to: it must be https, or plain http only to a ` +
        "literal loopback address (127.0.0.1 or ::1), with no credentials or query in the URL",
    };
  }
  return { upstream, basePath: pinned, wire };
}

/** Ollama's base URL as goose 1.53.0 builds it (ollama_def.rs from_env): a
 *  host without `http://` / `https://` gets `http://`, and a bare loopback
 *  name with no port gets 11434. Null when it does not parse. */
function ollamaBase(host: string): string | null {
  const hasScheme = host.startsWith("http://") || host.startsWith("https://");
  let u: URL;
  try { u = new URL(hasScheme ? host : `http://${host}`); } catch { return null; }
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1";
  if (u.port === "" && !host.includes(":") && !hasScheme && isLocal) u.port = "11434";
  return u.href;
}

/** A plain-http `localhost` endpoint as 127.0.0.1: the proxy dials plain
 *  http only to a literal loopback address (agent-model-route.ts
 *  routableUpstream), and LiteLLM's and Ollama's defaults name `localhost`. */
function loopbackLiteral(url: string): string {
  try {
    const u = new URL(url);
    if (u.protocol === "http:" && u.hostname.toLowerCase() === "localhost") {
      u.hostname = "127.0.0.1";
      return u.href;
    }
  } catch { /* refused by the caller */ }
  return url;
}

/**
 * A Chat Completions provider's endpoint (GOOSE_COMPAT_PROVIDERS), resolved
 * the way goose 1.53.0 resolves it: the host key (env, then config), else
 * Goose's default; Ollama's host normalized as Goose does (ollamaBase);
 * LiteLLM's LITELLM_BASE_PATH (env, then config, default
 * `v1/chat/completions`) must end in `chat/completions`, and a prefix before
 * that moves into the upstream (pinned `chat/completions`; the default path
 * stays as is, the proxy accepting one `/v1` before the operation). The
 * upstream must be one the proxy forwards to (https, or plain http to a
 * loopback address; `localhost` is read as 127.0.0.1). Pure.
 */
export function gooseCompatEndpoint(
  spec: GooseCompatSpec,
  env: Record<string, string | undefined>,
  cfg: GooseConfig | null,
): GooseCompatEndpoint | { why: string } {
  const h = gooseParam(spec.hostKey, env, cfg);
  const raw = h?.value ?? spec.defaultHost;
  const where = h?.where ?? `Goose's default ${spec.provider} host`;
  const notReachable = {
    why: `${where} (\`${raw}\`) is not an endpoint Mandu's model proxy forwards to: it must be https, or plain http only to a ` +
      "loopback address (127.0.0.1, ::1 or localhost), with no credentials or query in the URL",
  };
  const normalized = spec.provider === "ollama" ? ollamaBase(raw) : raw;
  if (normalized === null) return notReachable;
  let host = loopbackLiteral(normalized);
  let basePath: string | undefined;
  let prefix = "";
  if (spec.provider === "litellm") {
    const bp = gooseParam("LITELLM_BASE_PATH", env, cfg);
    const bpRaw = bp?.value ?? GOOSE_LITELLM_DEFAULT_BASE_PATH;
    const t = bpRaw.replace(/^\/+/, "").replace(/\/+$/, "");
    const lower = t.toLowerCase();
    if (lower === GOOSE_LITELLM_DEFAULT_BASE_PATH) {
      basePath = GOOSE_LITELLM_DEFAULT_BASE_PATH;
    } else if (lower === "chat/completions" || lower.endsWith("/chat/completions")) {
      prefix = t.slice(0, t.length - "chat/completions".length).replace(/\/+$/, "");
      basePath = "chat/completions";
    } else {
      return { why: `${bp?.where ?? "LITELLM_BASE_PATH"} (\`${bpRaw}\`) does not end in \`chat/completions\`, the wire Mandu's model proxy reads for litellm` };
    }
    // An absolute base path replaces the host's own path (Url::join).
    if (bpRaw.startsWith("/")) {
      try { const u = new URL(host); host = `${u.protocol}//${u.host}`; } catch { /* refused below */ }
    }
  }
  const upstream = routableUpstream(`${host.replace(/\/+$/, "")}${prefix ? `/${prefix}` : ""}`);
  if (upstream === null) return notReachable;
  return { provider: spec.provider, upstream, ...(basePath !== undefined ? { basePath } : {}) };
}

/** One provider name under Mandu: routed (with the openai endpoint when it
 *  is openai, a Chat Completions provider's endpoint when it is one of
 *  GOOSE_COMPAT_PROVIDERS), or refused with why. For every place that reads
 *  a Goose provider name (the launch check below; a recipe's settings). Pure. */
export function gooseProviderVerdict(
  name: string,
  env: Record<string, string | undefined>,
  cfg: GooseConfig | null,
): { routed: GooseRoutedProvider; openai: GooseOpenAiEndpoint | null; compat?: GooseCompatEndpoint } | { why: string; unrouted?: true } {
  const p = name.trim().toLowerCase();
  if (p === "anthropic") return { routed: "anthropic", openai: null };
  if (p === "openai") {
    const ep = gooseOpenAiEndpoint(env, cfg);
    return "why" in ep ? { why: ep.why } : { routed: "openai", openai: ep };
  }
  const spec = gooseCompatSpec(p);
  if (spec) {
    const ep = gooseCompatEndpoint(spec, env, cfg);
    return "why" in ep ? { why: ep.why } : { routed: spec.provider, openai: null, compat: ep };
  }
  return { why: `Mandu does not route the provider \`${name.trim()}\``, unrouted: true };
}

/** Hosts a declarative provider may not point at: the session's own model
 *  traffic (and Mandu's U-LLM) dials them, so the network layer cannot deny
 *  them for the agent, and NO_PROXY sends them around the net-proxy. */
export const GOOSE_UNDENIABLE_HOSTS: readonly string[] = ["api.anthropic.com", "api.openai.com"];

/** Env names a declarative provider's `${VAR}` may not be fenced through:
 *  Mandu's own routing keys are already at the proxy (a provider built on
 *  them goes through it); the rest would break the agent if repointed. */
const GOOSE_ROUTED_HOST_KEYS = new Set(["ANTHROPIC_HOST", "OPENAI_HOST", ...GOOSE_COMPAT_PROVIDERS.map((c) => c.hostKey)]);
const UNFENCEABLE_VAR_RE = /^(?:PATH|HOME|USER|LOGNAME|SHELL|PWD|TMPDIR|TERM|LANG|MANDU_.*|GOOSE_.*|XDG_.*|LC_.*|NODE_.*|HTTPS?_PROXY|NO_PROXY|ALL_PROXY)$/i;

/** What the launch does about the user's own declarative providers
 *  (`<config dir>/custom_providers/*.json`, readGooseConfig), any name, since
 *  a `/model --provider <name>` switch builds one mid-session:
 *  - a base URL that starts with `${VAR}`: VAR is fenced (fencedVars; Goose
 *    resolves it env first, declarative_providers.rs expand_env_vars),
 *    unless VAR is a routed provider's host key (ANTHROPIC_HOST,
 *    OPENAI_HOST, OLLAMA_HOST, …: already at the proxy, whose routes gate
 *    what they were given and refuse the rest); an `ollama`-engine provider
 *    (whose client runs tool calls written in the model's text) on any such
 *    key but OLLAMA_HOST is refused, since only the ollama route checks that
 *    text;
 *  - a literal base URL: its host is denied at the connect guard and the
 *    net-proxy (`hosts`, upload-deny.ts goose `fromConfig`);
 *  - refused (`problems`): a host built from a variable later in the URL, a
 *    variable the launch cannot repoint, an unparseable URL, or a host the
 *    network layer may not deny (GOOSE_UNDENIABLE_HOSTS). Pure. */
export function gooseCustomProviderFence(cfg: GooseConfig | null): { fencedVars: GooseFence[]; hosts: string[]; problems: string[] } {
  const fencedVars: GooseFence[] = [];
  const hosts: string[] = [];
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const c of cfg?.customProviders ?? []) {
    const raw = c.baseUrl?.trim();
    if (!raw || seen.has(c.file)) continue;
    seen.add(c.file);
    const where = `the declarative provider custom_providers/${c.file} (\`${c.name}\`)`;
    const lead = /^\$\{([^}]*)\}/.exec(raw);
    if (lead) {
      const v = lead[1]!;
      if (GOOSE_ROUTED_HOST_KEYS.has(v)) {
        // Goose's ollama engine runs a tool call the model writes in its
        // text; only the ollama route checks the text for one (openai-sse.ts).
        if (/^\s*ollama(?:_compatible)?\s*$/i.test(c.engine ?? "") && v !== "OLLAMA_HOST") {
          problems.push(`${where} is an ollama-engine provider on \${${v}}: Goose runs the tool calls its model writes as text, which Mandu's model proxy checks only on the ollama route (OLLAMA_HOST)`);
        }
        continue;
      }
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(v) || UNFENCEABLE_VAR_RE.test(v)) {
        problems.push(`${where} takes its endpoint from \${${v}}, which Mandu cannot point away from the provider`);
        continue;
      }
      if (!fencedVars.some((f) => f.key === v)) fencedVars.push({ key: v, provider: `custom_${c.name}`, form: "url" });
      continue;
    }
    let u: URL;
    try {
      if (raw.includes("${")) throw new Error("template");
      u = new URL(withScheme(raw));
    } catch {
      problems.push(`${where} has a base URL (\`${raw}\`) whose host Mandu cannot read, so it cannot deny it`);
      continue;
    }
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (GOOSE_UNDENIABLE_HOSTS.includes(host)) {
      problems.push(`${where} dials ${host} directly, which Mandu cannot deny to the session (its own model traffic goes there)`);
      continue;
    }
    const h = host.includes(":") ? `[${host}]` : host;
    hosts.push(u.port ? `${h}:${u.port}` : h);
  }
  return { fencedVars, hosts, problems };
}

/** The routing for a Goose launch, or the refusal for one whose model
 *  traffic Mandu would not route. Pure. */
export function gooseRoutePlan(
  argv: readonly string[],
  env: Record<string, string | undefined>,
  cfg: GooseConfig | null,
): { refusal: string | null; routing: GooseRouting } {
  const g = readGooseArgv(argv);
  const bad: string[] = [];
  let openai: GooseOpenAiEndpoint | null = null;
  const compatEps = new Map<GooseRoutedProvider, GooseCompatEndpoint>();
  /** The routed provider `provider` names, or null when it is refused. */
  const check = (provider: string, where: string): GooseRoutedProvider | null => {
    const v = gooseProviderVerdict(provider, env, cfg);
    if ("why" in v) {
      bad.push(v.unrouted ? `${where} names the provider \`${provider.trim()}\`` : `${where} names the provider \`${provider.trim()}\`, but ${v.why}`);
      return null;
    }
    if (v.openai) openai = v.openai;
    if (v.compat) compatEps.set(v.compat.provider, v.compat);
    return v.routed;
  };
  /** A key's value, env first (set and non-empty), then the config (its
   *  `before` keys first, then the key itself). */
  const named = (key: string, before: readonly string[] = []): { value: string; where: string } | null => {
    const fromEnv = env[key];
    if (fromEnv !== undefined && fromEnv !== "") return fromEnv.trim() === "" ? null : { value: fromEnv, where: `the environment's ${key}` };
    for (const k of [...before, key]) {
      const c = cfg?.values?.[k];
      if (c !== undefined && c.trim() !== "") return { value: c, where: `${k} in ${cfg?.path ?? "the Goose config"}` };
    }
    return null;
  };
  // The main provider: `--provider` (the last one counts), env, config.
  let main: GooseRoutedProvider | null = null;
  let mainFromArgv = false;
  // `review` hands its `--provider` to every `goose run` child it starts
  // (goose 1.53.0 commands/review/orchestrator.rs); a check's frontmatter
  // names a model only, never a provider (checks/mod.rs CheckFrontmatter).
  if (g && (g.command === "session" || g.command === "run" || g.command === "review")) {
    for (const p of gooseFlagValues(g.rest, "--provider", gooseValueFlags(g.command))) {
      if (p.trim() === "") continue;
      mainFromArgv = true;
      main = check(p, "--provider");
    }
  }
  // Goose 1.53.0's order (config/providers.rs get_active_provider): env
  // GOOSE_PROVIDER, then the config's `active_provider` (what `goose
  // configure` writes since the structured `providers:` block), then its
  // legacy GOOSE_PROVIDER.
  const envMain = named("GOOSE_PROVIDER", ["active_provider"]);
  const mainFromEnv = envMain !== null ? check(envMain.value, envMain.where) : null;
  if (!mainFromArgv) main = mainFromEnv;
  const provider: GooseRoutedProvider = main ?? GOOSE_ROUTED_PROVIDER;
  const sub = named("GOOSE_SUBAGENT_PROVIDER");
  const subagentProvider: GooseRoutedProvider = (sub !== null ? check(sub.value, sub.where) : null) ?? provider;
  // A declarative provider named like a routed one would be built in its
  // place, with its own endpoint: refused for anthropic and openai always
  // (their routes are always live), for a Chat Completions one when this
  // launch uses it (otherwise the fence below covers the file).
  const used = new Set<string>(["anthropic", "openai", provider, subagentProvider]);
  for (const c of cfg?.customProviders ?? []) {
    if (used.has(c.name.toLowerCase())) {
      bad.push(`the declarative provider custom_providers/${c.file} is named \`${c.name}\` and carries its own endpoint`);
    }
  }
  // The user's own declarative providers, any name: a `/model --provider`
  // switch builds one mid-session (the fence, supported-agents.md §5.6.3).
  const custom = gooseCustomProviderFence(cfg);
  bad.push(...custom.problems);
  const fence = custom.fencedVars.length > 0 ? { fencedVars: custom.fencedVars } : {};
  const compat = [...new Set([provider, subagentProvider])].flatMap((p) => {
    const ep = compatEps.get(p);
    return ep ? [ep] : [];
  });
  const routing: GooseRouting = {
    provider, subagentProvider,
    openai: provider === "openai" || subagentProvider === "openai" ? openai : null,
    ...(compat.length > 0 ? { compat } : {}),
    ...fence,
  };
  // A wrapper (--target goose) is vouched for: never refused; it gets the
  // routing its env and config name where Mandu routes that, else anthropic.
  if (!g) return { refusal: null, routing: bad.length === 0 ? routing : { ...GOOSE_DEFAULT_ROUTING, ...fence } };
  if (bad.length === 0) return { refusal: null, routing };
  return {
    refusal:
      `mandu: refusing to launch goose: ${bad.join("; ")}. Mandu routes Goose's built-in ${GOOSE_ROUTED_SPELLED} providers ` +
      "through its model proxy; any other provider, or an endpoint the proxy cannot reach, would send the session's tool " +
      "output to its model around Mandu. Use one of those providers (GOOSE_PROVIDER, `--provider`, or " +
      "`goose configure`), or run goose without `mandu`.",
    routing: GOOSE_DEFAULT_ROUTING,
  };
}

/** The routed providers as a refusal names them. */
export const GOOSE_ROUTED_SPELLED = `${GOOSE_ROUTED_PROVIDERS.slice(0, -1).join(", ")} and ${GOOSE_ROUTED_PROVIDERS.at(-1)!}`;

/** The refusal alone (gooseRoutePlan), or null. Pure. */
export function gooseProviderRefusal(
  argv: readonly string[],
  env: Record<string, string | undefined>,
  cfg: GooseConfig | null,
): string | null {
  return gooseRoutePlan(argv, env, cfg).refusal;
}

/** The refusal for a Goose launch on a provider with a proxy route (openai,
 *  a Chat Completions one) whose anthropic side (session or subagents)
 *  keeps the user's own undeclared ANTHROPIC_HOST: that override skips the
 *  model proxy, where that route lives (run.ts). Pure. */
export function gooseOpenAiNeedsProxy(anthropicHost: string, provider = "openai"): string {
  return (
    `mandu: refusing to launch goose: its ${provider} provider goes through Mandu's model proxy, and your ANTHROPIC_HOST ` +
    `(${anthropicHost}), which this launch also uses for the anthropic provider, skips that proxy. Unset ANTHROPIC_HOST, ` +
    "declare it in policy.yaml `models:` (the proxy then stays in front of it), or use one provider for the session and its subagents."
  );
}

/**
 * Does this goose argv RESUME a saved session? `session` / `run` with `-r` /
 * `--resume` (alone or in a short-flag cluster such as `-rs`); `--fork`,
 * `--edit` and `--history` require it. A flag's value is never read as one
 * (gooseValueFlags). Over-reading a cluster only adds the pin below. Pure.
 */
export function gooseResumes(argv: readonly string[]): boolean {
  const g = readGooseArgv(argv);
  if (!g || (g.command !== "session" && g.command !== "run")) return false;
  const values = gooseValueFlags(g.command);
  for (let k = 0; k < g.rest.length; k++) {
    const a = g.rest[k]!;
    if (a === "--") break;
    if (values.has(a)) { k++; continue; }
    if (a === "--resume" || a.startsWith("--resume=")) return true;
    if (/^-[A-Za-z]+$/.test(a) && a.includes("r")) return true;
  }
  return false;
}

/**
 * RESUMED SESSIONS (goose 1.53.0 goose-cli session/builder.rs
 * resolve_provider_and_model; supported-agents.md §5.6): a resumed
 * session's provider is `--provider`, then the provider SAVED with the
 * session, then a recipe's, then env GOOSE_PROVIDER and the config. The
 * saved one outranks the env routing, so a session started outside Mandu on
 * a provider Mandu does not route (captured: a declarative provider at a
 * counting upstream) dialed that provider under `mandu goose run --resume`,
 * its history and the raw tool output in it included. The launch pins
 * `--provider <routed>` right after the subcommand on every resume shape
 * the user gave no `--provider` (a `--provider` the user gave is checked by
 * gooseRoutePlan), which outranks the saved provider. The model then comes
 * from GOOSE_MODEL, the config, or the routed provider's default: the saved
 * model is kept only when the saved provider is the routed one. Pure.
 */
export function gooseResumePin(argv: readonly string[], routed: GooseRoutedProvider): string[] {
  const g = readGooseArgv(argv);
  if (!g || !gooseResumes(argv)) return [...argv];
  if (gooseFlagValues(g.rest, "--provider", gooseValueFlags(g.command)).some((p) => p.trim() !== "")) return [...argv];
  const out = [...argv];
  out.splice(g.subIndex + 1, 0, "--provider", routed);
  return out;
}
