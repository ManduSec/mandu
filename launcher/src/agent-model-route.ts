/**
 * agent-model-route — the launch refuses a config-routed agent (openclaw /
 * opencode) whose model would not go through Mandu's model proxy
 * (docs/design/testing/agent-e2e-harness.md §9, "Only Anthropic models are routed" and
 * "Other providers through the model proxy").
 *
 * WHY (probe-verified 2026-09-27, OpenClaw 2026.7.1 and OpenCode 1.18.13 /
 * 1.18.32, a URL-logging stand-in model): the routing override
 * (services/agent-config.ts) points only the agent's ANTHROPIC provider at the
 * anthropic-proxy. A model from any other provider went straight to that
 * provider:
 *   - OpenClaw's built-in default is `openai/gpt-5.5` on 2026.6 and later
 *     (`anthropic/claude-opus-4-6` on 2026.3.12). `mandu openclaw agent
 *     --local` with no model configured sent its turn to
 *     https://api.openai.com/v1/responses under the default posture: the
 *     whole-agent connect guard admits any :443 host, and NO_PROXY lists
 *     api.openai.com.
 *   - `mandu --mode full openclaw …` with `openai/gpt-5.5` and `mandu --mode
 *     full opencode run -m openai/gpt-5 …` sent a file's untrusted text to the
 *     model RAW (`function_call_output: "# notes\nIPIMARKER…"`), while the
 *     banner said "untrusted text masked". In `secrets` mode a registered
 *     credential file still reached the model as its twin (the file layer
 *     does not depend on the route).
 * The same class as the Codex `exec -c` bypass (codex-argv.ts).
 *
 * The rule, pure and unit-tested (test/unit/agent-model-route.test.ts):
 *   - every model reference the agent can run from its own config (primary,
 *     fallbacks, per-agent and sub-agent models) and from argv (`--model`)
 *     must name a provider Mandu routes; any other provider is refused
 *     before anything launches, naming where the reference came from and
 *     why its provider is not routed. Routed providers (2026-09-28,
 *     agent-e2e-harness.md §9 "Other providers through the model proxy"):
 *       * `anthropic`, as before;
 *       * an OpenAI-family provider (`openaiRouteFor*` below): OpenClaw's
 *         built-in `openai` (the Responses API at api.openai.com) and any
 *         `models.providers.<id>` that names its `baseUrl` and an `api` of
 *         `openai-completions` or `openai-responses`; OpenCode's built-in
 *         `openai` and any `provider.<id>` with the `@ai-sdk/openai` or
 *         `@ai-sdk/openai-compatible` package and a base URL. The launcher
 *         points each at the session's model proxy (agent-config.ts), which
 *         reads that wire with the SAME gates (anthropic-proxy
 *         openai-wire.ts) and forwards to the provider's own URL. OpenCode
 *         signed in to OpenAI with a ChatGPT account is refused: that login
 *         rewrites Chat Completions requests to chatgpt.com whatever the
 *         base URL (read from OpenCode 1.18.32);
 *   - OpenClaw with NO model configured is refused: its built-in default
 *     depends on the release (openai on 2026.6+), so the launcher cannot
 *     vouch for it;
 *   - an OpenClaw config the launcher cannot read is refused: the launch
 *     would drop it, and OpenClaw would fall back to that built-in default.
 *     It is read as JSON5 (services/json5.ts), as OpenClaw reads it, with
 *     its `$include` files resolved the way OpenClaw resolves them
 *     (services/openclaw-include.ts), so the models in included files are
 *     checked like the rest; an include OpenClaw would refuse (outside the
 *     config directory, a cycle, a missing file) makes the config
 *     unreadable, and a `$include` still present in the doc handed here (a
 *     reader that skipped the resolver) is refused;
 *   - OpenClaw's Active Memory plugin runs its own recall model over the
 *     conversation (`plugins.entries.active-memory.config.model` and
 *     `.modelFallback`): those references must name the anthropic provider
 *     as well;
 *   - OpenCode with no model configured is NOT refused: the routing override
 *     also fences OpenCode to the anthropic provider (`enabled_providers`,
 *     delivered in OPENCODE_CONFIG_CONTENT, which outranks a project config),
 *     so its own default is provably routed.
 * These are the clear-message layer; the runtime fences in agent-config.ts
 * (OpenCode `enabled_providers`, OpenClaw's `agents.defaults.models`
 * allowlist) hold the line for a mid-session `/model` switch.
 *
 * OpenCode 2 (opencodeV2ModelPlan below; supported-agents.md §2.3 part 4)
 * reads its own spelling (`providers` with `package` and `settings.baseURL`,
 * `agents.<n>.model` with a `#variant`, `experimental.policies`; V1 keys
 * normalized, opencode-config.ts) from EVERY config layer, and two of its
 * rules are not fenced by the routing Mandu writes: the provider rule of the
 * LOWEST layer wins (so the global config can re-admit a provider), and a
 * model's own endpoint beats its provider's base URL (from any layer). The
 * 2.x check reads every layer and refuses both, besides the unrouted models.
 *
 * An argv the launcher cannot read as the agent (a wrapper script under
 * `--target`) is not checked: `--target` is the user vouching for the
 * wrapper, the contract parse.ts applies to every wrapper target.
 */
import { basename } from "node:path";
import { readOpenclawArgv } from "./openclaw-argv.js";
import {
  normalizeOpencodeDoc, opencodePackageName,
  type OcNormalized, type OcProvider, type OpencodeLayer,
} from "./opencode-config.js";

type Json = Record<string, unknown>;

/** The two OpenAI wires the model proxy reads (anthropic-proxy openai-wire.ts). */
export type OpenAiApi = "openai-responses" | "openai-completions";

/** One OpenAI-family provider routed through the session's model proxy. */
export interface OpenAiRoute {
  /** The agent's provider id (also the proxy path segment). */
  id: string;
  api: OpenAiApi;
  /** The provider's own base URL, where the proxy sends the gated request. */
  upstream: string;
  /** The agent runs a tool call the model WRITES in its text on this route
   *  (Goose's ollama provider, `<function=name>…`): the proxy ends a
   *  response whose text carries that markup (MANDU_OPENAI_TEXT_CALLS,
   *  anthropic-proxy openai-sse.ts). */
  textCalls?: boolean;
}

/** OpenAI's API base, the built-in `openai` provider's in both agents. */
export const OPENAI_API_BASE = "https://api.openai.com/v1";

const OPENAI_APIS: ReadonlySet<string> = new Set<OpenAiApi>(["openai-responses", "openai-completions"]);

/** A provider id the proxy path and MANDU_OPENAI_UPSTREAMS accept. */
const ROUTABLE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** How one provider's models are reached under Mandu. */
export type ProviderVerdict =
  | { kind: "anthropic" }
  | { kind: "route"; route: OpenAiRoute }
  | { kind: "refuse"; why: string };

/**
 * A base URL the proxy may send to: https anywhere, plain http only to a
 * literal loopback address (the proxy's fetcher enforces the same rule per
 * request; refusing here gives the reason before anything starts). No query,
 * fragment or credentials. Returns the URL without a trailing slash, or null.
 */
export function routableUpstream(url: unknown): string | null {
  if (typeof url !== "string" || url.trim() === "") return null;
  let u: URL;
  try { u = new URL(url.trim()); } catch { return null; }
  if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") return null;
  if (u.protocol === "http:") {
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (host !== "::1" && !/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return null;
  } else if (u.protocol !== "https:") {
    return null;
  }
  return url.trim().replace(/\/+$/, "");
}

/** OpenClaw: how provider `p` is reached (its `models.providers` entry, else built-in). */
export function openclawProviderVerdict(p: string, doc: Json): ProviderVerdict {
  if (p === ROUTED_PROVIDER) return { kind: "anthropic" };
  const models = isObj(doc["models"]) ? doc["models"] : {};
  const providers = isObj(models["providers"]) ? models["providers"] : {};
  const entry = isObj(providers[p]) ? providers[p] : undefined;
  if (!ROUTABLE_ID_RE.test(p)) return { kind: "refuse", why: "its provider id is not a plain name" };
  if (entry === undefined) {
    if (p === "openai") return { kind: "route", route: { id: p, api: "openai-responses", upstream: OPENAI_API_BASE } };
    return { kind: "refuse", why: `Mandu routes an OpenAI-compatible provider only when models.providers.${p} names its baseUrl and api ("openai-completions" or "openai-responses")` };
  }
  const api = entry["api"];
  if (api === undefined && p !== "openai") {
    return { kind: "refuse", why: `models.providers.${p} names no api, and Mandu routes only "openai-completions" and "openai-responses"` };
  }
  const apiName = typeof api === "string" ? api : "openai-responses";
  if (!OPENAI_APIS.has(apiName)) return { kind: "refuse", why: `models.providers.${p} uses api "${String(api)}", which Mandu does not route` };
  const base = entry["baseUrl"] === undefined && p === "openai" ? OPENAI_API_BASE : routableUpstream(entry["baseUrl"]);
  if (base === null) {
    return { kind: "refuse", why: `models.providers.${p}.baseUrl is missing or not a URL Mandu sends to (https, or http to 127.0.0.1)` };
  }
  return { kind: "route", route: { id: p, api: apiName as OpenAiApi, upstream: base } };
}

/** The OpenCode auth types by provider (its auth.json: "api", "oauth", "wellknown"). */
export type OpencodeAuthTypes = Readonly<Record<string, string>>;

/** OpenCode: how provider `p` is reached (its `provider` entry, else built-in). */
export function opencodeProviderVerdict(p: string, doc: Json, auth: OpencodeAuthTypes = {}): ProviderVerdict {
  if (p === ROUTED_PROVIDER) return { kind: "anthropic" };
  if (!ROUTABLE_ID_RE.test(p)) return { kind: "refuse", why: "its provider id is not a plain name" };
  const providers = isObj(doc["provider"]) ? doc["provider"] : {};
  const entry = isObj(providers[p]) ? providers[p] : undefined;
  const npm = entry && typeof entry["npm"] === "string" ? entry["npm"] : p === "openai" ? "@ai-sdk/openai" : undefined;
  if (npm !== "@ai-sdk/openai" && npm !== "@ai-sdk/openai-compatible") {
    return {
      kind: "refuse",
      why: entry === undefined
        ? `Mandu routes an OpenAI-compatible provider only when provider.${p} names the @ai-sdk/openai-compatible package and options.baseURL`
        : `provider.${p} uses ${npm === undefined ? "no npm package" : `the ${npm} package`}, which Mandu does not route`,
    };
  }
  if (auth[p] === "oauth" && p === "openai") {
    return {
      kind: "refuse",
      why: "OpenCode is signed in to OpenAI with a ChatGPT account, and that login sends requests to chatgpt.com whatever the base URL; sign in with an API key (`opencode auth login`) to use it under Mandu",
    };
  }
  const options = entry && isObj(entry["options"]) ? entry["options"] : {};
  const raw = options["baseURL"] ?? entry?.["api"] ?? (p === "openai" ? OPENAI_API_BASE : undefined);
  const base = routableUpstream(raw);
  if (base === null) {
    return { kind: "refuse", why: `provider.${p} has no base URL Mandu sends to (options.baseURL: https, or http to 127.0.0.1)` };
  }
  return { kind: "route", route: { id: p, api: npm === "@ai-sdk/openai" ? "openai-responses" : "openai-completions", upstream: base } };
}

/** What the launcher read of the agent's own config file. */
export type AgentUserConfig =
  | { kind: "absent" }
  | { kind: "unreadable"; path: string; reason: string }
  | { kind: "ok"; path: string; doc: Json };

export interface ModelRef {
  ref: string;
  /** where it came from, e.g. "agents.defaults.model.primary" or "--model" */
  where: string;
}

const HELP_OR_VERSION = new Set(["-h", "--help", "-V", "-v", "--version"]);
const ROUTED_PROVIDER = "anthropic";
/** The OpenCode commands: `opencode` (both generations) and `opencode2` (2.x only). */
const OPENCODE_BINS: ReadonlySet<string> = new Set(["opencode", "opencode2"]);

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The value of `--model X` / `--model=X` (and `-m X` / `-mX` when `short`)
 *  before any `--`; the last one wins, as in both agents' parsers. */
function flagValue(args: readonly string[], short: boolean): string | undefined {
  let v: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") break;
    if (a === "--model" || (short && a === "-m")) v = args[++i];
    else if (a.startsWith("--model=")) v = a.slice("--model=".length);
    else if (short && a.startsWith("-m") && a.length > 2 && !a.startsWith("--")) v = a.slice(2);
  }
  return v;
}

/** A `model` value: a "provider/model" string, or `{ primary, fallbacks }`. */
function refsOfModelValue(v: unknown, where: string, out: ModelRef[]): void {
  if (typeof v === "string") { if (v.trim() !== "") out.push({ ref: v.trim(), where }); return; }
  if (!isObj(v)) return;
  if (typeof v["primary"] === "string" && v["primary"].trim() !== "") out.push({ ref: v["primary"].trim(), where: `${where}.primary` });
  if (Array.isArray(v["fallbacks"])) {
    v["fallbacks"].forEach((f, i) => { if (typeof f === "string" && f.trim() !== "") out.push({ ref: f.trim(), where: `${where}.fallbacks[${i}]` }); });
  }
}

/**
 * Every value under a key named exactly `model` in `node`, recursively
 * (per-agent, sub-agent, heartbeat, compaction models all use that key).
 * Keys with other names (`imageModel`, `imageGenerationModel`, the
 * `models` allowlist) are not conversation models and are skipped, and so is
 * `memorySearch` (its `model` is an embedding model id; its provider is a
 * separate key). Compaction and memory-flush models DO read the conversation.
 */
function collectModelKeys(node: unknown, where: string, out: ModelRef[]): void {
  if (Array.isArray(node)) { node.forEach((n, i) => collectModelKeys(n, `${where}[${i}]`, out)); return; }
  if (!isObj(node)) return;
  for (const [k, v] of Object.entries(node)) {
    const at = where ? `${where}.${k}` : k;
    if (k === "model") refsOfModelValue(v, at, out);
    else if (k !== "models" && k !== "memorySearch") collectModelKeys(v, at, out);
  }
}

/** The provider a reference names, resolving an OpenClaw alias through
 *  `agents.defaults.models` (`{ "anthropic/claude-sonnet-4-6": { alias: "sonnet" } }`). */
function providerOf(ref: string, aliases: Json | undefined): string | null {
  if (ref.includes("/")) return ref.slice(0, ref.indexOf("/")).trim().toLowerCase();
  for (const [full, entry] of Object.entries(aliases ?? {})) {
    if (isObj(entry) && entry["alias"] === ref && full.includes("/")) return full.slice(0, full.indexOf("/")).trim().toLowerCase();
  }
  return null;
}

/** The first `$include` key in `node`, as a dotted path, or null. OpenClaw
 *  splices the named files in at load time (its "split config" feature);
 *  readAgentUserConfig resolves them first, so one left here was not read. */
function includePath(node: unknown, where: string): string | null {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) { const p = includePath(node[i], `${where}[${i}]`); if (p) return p; }
    return null;
  }
  if (!isObj(node)) return null;
  for (const [k, v] of Object.entries(node)) {
    const at = where ? `${where}.${k}` : k;
    if (k === "$include") return at;
    const p = includePath(v, at);
    if (p) return p;
  }
  return null;
}

/** Active Memory's recall model references (they read the conversation). */
function activeMemoryRefs(doc: Json, out: ModelRef[]): void {
  const plugins = isObj(doc["plugins"]) ? doc["plugins"] : {};
  const entries = isObj(plugins["entries"]) ? plugins["entries"] : {};
  const am = isObj(entries["active-memory"]) ? entries["active-memory"] : {};
  const cfg = isObj(am["config"]) ? am["config"] : {};
  for (const k of ["model", "modelFallback"]) {
    const v = cfg[k];
    if (typeof v === "string" && v.trim() !== "") out.push({ ref: v.trim(), where: `plugins.entries.active-memory.config.${k}` });
  }
}

type Judged = ModelRef & { provider: string | null; verdict: ProviderVerdict };

/** The routed-provider hint of a refusal, in the config spelling the agent reads. */
const OPENCODE1_HINT = "an OpenAI-compatible provider declared with the @ai-sdk/openai-compatible package and options.baseURL";
const OPENCODE2_HINT = "an OpenAI-compatible provider declared with the aisdk:@ai-sdk/openai-compatible package and settings.baseURL";

function refuseLines(agent: string, bad: readonly Judged[], hint?: string): string {
  const shown = bad.slice(0, 4).map((b) => `${b.ref} (${b.where})`).join(", ");
  const more = bad.length > 4 ? ` and ${bad.length - 4} more` : "";
  const whys = [...new Set(bad.slice(0, 4).map((b) => b.verdict.kind === "refuse" ? b.verdict.why : ""))].filter((w) => w !== "");
  const configHint = hint ?? (agent === "openclaw"
    ? "an OpenAI-compatible provider declared in models.providers with its baseUrl and api \"openai-completions\" or \"openai-responses\""
    : OPENCODE1_HINT);
  return (
    `mandu: refusing to launch ${agent} with model ${shown}${more}: ` +
    (whys.length > 0 ? `${whys.join("; ")}. ` : "") +
    `Mandu protects ${agent} by routing its model provider through Mandu's model proxy, and a model it does not ` +
    "route would receive tool results unmasked. Choose an anthropic/… or openai/… model, or " + configHint +
    (bad.some((b) => b.provider === null) ? "; write a bare model id as <provider>/<id>" : "") +
    `, or run ${agent} without mandu.`
  );
}

function judge(refs: readonly ModelRef[], aliases: Json | undefined, verdictOf: (p: string) => ProviderVerdict): Judged[] {
  return refs.map((r) => {
    const provider = providerOf(r.ref, aliases);
    const verdict: ProviderVerdict = provider === null
      ? { kind: "refuse", why: "" }
      : verdictOf(provider);
    return { ...r, provider, verdict };
  });
}

/** The unique routes the judged references need, in first-seen order. */
function routesOf(judged: readonly Judged[]): OpenAiRoute[] {
  const out = new Map<string, OpenAiRoute>();
  for (const j of judged) if (j.verdict.kind === "route" && !out.has(j.verdict.route.id)) out.set(j.verdict.route.id, j.verdict.route);
  return [...out.values()];
}

/** The launch-time model decision: a refusal, or the OpenAI-family
 *  providers to route (empty when every model is Anthropic). */
export interface ModelPlan {
  refusal: string | null;
  routes: OpenAiRoute[];
}

/** OpenClaw: the refusal message, or null when every model it can run is routed. */
export function openclawModelRefusal(argv: readonly string[], cfg: AgentUserConfig): string | null {
  return openclawModelPlan(argv, cfg).refusal;
}

const NONE: ModelPlan = { refusal: null, routes: [] };
const refused = (refusal: string): ModelPlan => ({ refusal, routes: [] });

/** OpenClaw: the refusal, or the OpenAI-family providers to route. */
export function openclawModelPlan(argv: readonly string[], cfg: AgentUserConfig): ModelPlan {
  const oc = readOpenclawArgv(argv);
  if (!oc) return NONE; // a wrapper: --target vouches for it
  if ([...oc.globals, oc.sub, ...oc.rest].some((a) => HELP_OR_VERSION.has(a)) || oc.sub === "help") return NONE;
  if (cfg.kind === "unreadable") {
    return refused(
      `mandu: refusing to launch openclaw: could not read ${cfg.path} (${cfg.reason}). The launch would run without ` +
      "your settings, and OpenClaw would fall back to its built-in model, which Mandu cannot vouch for. Fix the " +
      "file (Mandu reads it as JSON5 and resolves its $include files, as OpenClaw does), or run openclaw without mandu."
    );
  }
  const doc = cfg.kind === "ok" ? cfg.doc : {};
  const include = cfg.kind === "ok" ? includePath(doc, "") : null;
  if (include !== null) {
    return refused(
      `mandu: refusing to launch openclaw: ${cfg.kind === "ok" ? cfg.path : "its config"} uses $include (${include}), ` +
      "and Mandu checks every model your config can run before the launch but did not read the included files, so " +
      "a model there could go around Mandu's model proxy. Put the included settings into the file itself, or run " +
      "openclaw without mandu."
    );
  }
  const agents = isObj(doc["agents"]) ? doc["agents"] : {};
  const defaults = isObj(agents["defaults"]) ? agents["defaults"] : {};
  const aliases = isObj(defaults["models"]) ? defaults["models"] : undefined;
  // `-m` is --message for OpenClaw: only the long flag names a model.
  const cli = oc.sub === "agent" ? flagValue(oc.rest, false) : undefined;

  const refs: ModelRef[] = [];
  collectModelKeys(agents, "agents", refs);
  activeMemoryRefs(doc, refs);
  // Which primary this run starts on: --model, else the selected agent's own
  // model, else agents.defaults.model. With --model, the configured primaries
  // of the selected agent and the defaults do not run (fallbacks still do).
  const list = Array.isArray(agents["list"]) ? agents["list"].filter(isObj) : [];
  const agentFlag = oc.sub === "agent" ? (() => {
    for (let i = 0; i < oc.rest.length; i++) {
      const a = oc.rest[i]!;
      if (a === "--agent") return oc.rest[i + 1];
      if (a.startsWith("--agent=")) return a.slice("--agent=".length);
    }
    return undefined;
  })() : undefined;
  const selectedIdx = agentFlag !== undefined
    ? list.findIndex((e) => e["id"] === agentFlag)
    : Math.max(list.findIndex((e) => e["default"] === true), list.length > 0 ? 0 : -1);
  const primaryOf = (m: unknown): string | undefined =>
    typeof m === "string" ? m : isObj(m) && typeof m["primary"] === "string" ? m["primary"] : undefined;
  const selected = selectedIdx >= 0 ? list[selectedIdx] : undefined;
  const primary = cli ?? primaryOf(selected?.["model"]) ?? primaryOf(defaults["model"]);

  let effective = refs;
  if (cli !== undefined) {
    const skip = new Set(["agents.defaults.model", "agents.defaults.model.primary"]);
    if (selectedIdx >= 0) { skip.add(`agents.list[${selectedIdx}].model`); skip.add(`agents.list[${selectedIdx}].model.primary`); }
    effective = [...refs.filter((r) => !skip.has(r.where)), { ref: cli, where: "--model" }];
  }
  const judged = judge(effective, aliases, (p) => openclawProviderVerdict(p, doc));
  const bad = judged.filter((j) => j.verdict.kind === "refuse");
  if (bad.length > 0) return refused(refuseLines("openclaw", bad));
  if (primary === undefined || primary.trim() === "") {
    return refused(
      "mandu: refusing to launch openclaw with no model configured: OpenClaw would run its built-in default model, " +
      "which depends on the release (anthropic on 2026.3, openai on 2026.6 and later), so Mandu cannot vouch for " +
      "where it sends tool results. Set one, e.g. `openclaw config set agents.defaults.model.primary " +
      "anthropic/claude-sonnet-4-6`, or pass --model to `openclaw agent`."
    );
  }
  return { refusal: null, routes: routesOf(judged) };
}

/** OpenCode: the refusal message, or null. An unset model is fine here: the
 *  routing override fences OpenCode to the routed providers. */
export function opencodeModelRefusal(argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}): string | null {
  return opencodeModelPlan(argv, cfg, auth).refusal;
}

/** OpenCode: the refusal, or the OpenAI-family providers to route. */
export function opencodeModelPlan(argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}): ModelPlan {
  if (argv.length === 0 || !OPENCODE_BINS.has(basename(argv[0]!))) return NONE; // a wrapper
  const args = argv.slice(1);
  if (args.some((a) => HELP_OR_VERSION.has(a))) return NONE;
  const refs: ModelRef[] = [];
  if (cfg.kind === "ok") {
    const d = cfg.doc;
    if (typeof d["model"] === "string") refs.push({ ref: d["model"], where: `model in ${cfg.path}` });
    if (typeof d["small_model"] === "string") refs.push({ ref: d["small_model"], where: `small_model in ${cfg.path}` });
    for (const key of ["agent", "mode"]) {
      const sect = d[key];
      if (!isObj(sect)) continue;
      for (const [name, a] of Object.entries(sect)) {
        if (isObj(a) && typeof a["model"] === "string") refs.push({ ref: a["model"], where: `${key}.${name}.model in ${cfg.path}` });
      }
    }
  }
  const cli = flagValue(args, true);
  if (cli !== undefined) {
    // The flag replaces the configured main model for this run.
    const i = refs.findIndex((r) => r.where.startsWith("model in "));
    if (i >= 0) refs.splice(i, 1);
    refs.push({ ref: cli, where: "--model" });
  }
  const doc = cfg.kind === "ok" ? cfg.doc : {};
  const judged = judge(refs, undefined, (p) => opencodeProviderVerdict(p, doc, auth));
  const bad = judged.filter((j) => j.verdict.kind === "refuse");
  return bad.length > 0 ? refused(refuseLines("opencode", bad)) : { refusal: null, routes: routesOf(judged) };
}

// ─── OpenCode 2 (supported-agents.md §2.3 part 4) ────────────────────────────

/** What the launcher read of every config layer OpenCode 2 will read
 *  (services/agent-config.ts readOpencodeConfigLayers), lowest first. */
export interface OpencodeV2Input {
  layers: readonly OpencodeLayer[];
  /** Files OpenCode 2 would read that the launcher could not parse. */
  unreadable: ReadonlyArray<{ path: string; reason: string }>;
}

/** The npm packages Mandu routes, and the wire each speaks. */
const OPENAI_PACKAGES: Readonly<Record<string, OpenAiApi>> = {
  "@ai-sdk/openai": "openai-responses",
  "@ai-sdk/openai-compatible": "openai-completions",
};

/** One provider's endpoint settings merged across the layers (each field
 *  from the highest layer that sets it, as OpenCode 2 merges them). */
export type OpencodeV2Providers = Readonly<Record<string, OcProvider>>;

function mergeV2Providers(layers: ReadonlyArray<OcNormalized>): Record<string, OcProvider> {
  const out: Record<string, OcProvider> = {};
  for (const n of layers) for (const [id, e] of Object.entries(n.providers)) out[id] = { ...out[id], ...e };
  return out;
}

/** OpenCode 2: how provider `p` is reached (its merged `providers` entry, else built-in). */
export function opencodeV2ProviderVerdict(p: string, providers: OpencodeV2Providers, auth: OpencodeAuthTypes = {}): ProviderVerdict {
  if (p === ROUTED_PROVIDER) return { kind: "anthropic" };
  if (!ROUTABLE_ID_RE.test(p)) return { kind: "refuse", why: "its provider id is not a plain name" };
  const entry = providers[p];
  if (entry?.canonical !== undefined) {
    return { kind: "refuse", why: `providers.${p}.canonical makes it a copy of another provider, which Mandu does not route` };
  }
  const pkg = opencodePackageName(entry?.package) ?? (p === "openai" ? "@ai-sdk/openai" : undefined);
  const api = pkg === undefined ? undefined : OPENAI_PACKAGES[pkg];
  if (api === undefined) {
    return {
      kind: "refuse",
      why: entry?.package === undefined
        ? `Mandu routes an OpenAI-compatible provider only when providers.${p} names the aisdk:@ai-sdk/openai-compatible package and settings.baseURL`
        : `providers.${p} uses the ${entry.package} package, which Mandu does not route`,
    };
  }
  if (auth[p] === "oauth" && p === "openai") {
    return {
      kind: "refuse",
      why: "OpenCode is signed in to OpenAI with a ChatGPT account, and that login sends requests to chatgpt.com whatever the base URL; sign in with an API key (`opencode auth login`) to use it under Mandu",
    };
  }
  const base = routableUpstream(entry?.baseURL ?? (p === "openai" ? OPENAI_API_BASE : undefined));
  if (base === null) {
    return { kind: "refuse", why: `providers.${p} has no base URL Mandu sends to (settings.baseURL: https, or http to 127.0.0.1)` };
  }
  return { kind: "route", route: { id: p, api, upstream: base } };
}

/** The anthropic package a config may name (the provider's own SDK). */
const ANTHROPIC_PACKAGES: ReadonlySet<string> = new Set(["@ai-sdk/anthropic"]);

/**
 * OpenCode 2: the refusal, or the OpenAI-family providers to route. Reads
 * EVERY config layer OpenCode 2 reads (the global config dir, the
 * OPENCODE_CONFIG file, every project file from `/` down to the start
 * directory, OPENCODE_CONFIG_CONTENT), in both spellings (opencode-config.ts).
 * Refuses, before anything starts:
 *   - a layer it could not read (it could hold any of the below);
 *   - a model the session can run (`model` or `-m`, each `agents.<n>.model`
 *     with its `#variant`, each `commands.<n>.model`; V1 `small_model`,
 *     `agent`, `mode`, `command`), from the highest layer that sets it, on a
 *     provider Mandu does not route: the clear-message layer, as for 1.x
 *     (the policy fence holds the line at run time);
 *   - a model-level endpoint on a routed provider (a model's or variant's
 *     own base URL or package; V1 `options.baseURL`, `provider.api`,
 *     `provider.npm`, `variants.<v>.baseURL`), in ANY layer: OpenCode 2
 *     sends that model's requests there, around the provider's base URL that
 *     Mandu points at its proxy. So is a `package` or `canonical` on the
 *     anthropic provider (another SDK may read its endpoint from other
 *     settings).
 * A re-pointed provider base URL (either spelling, any layer) is not
 * refused: the routing Mandu writes in OPENCODE_CONFIG_CONTENT outranks it,
 * in both spellings (agent-config.ts opencodeRoutingContent). Nor is a
 * provider the user's config admits (`enabled_providers`, an
 * `experimental.policies` allow): OpenCode 2 lets the LOWEST layer's provider
 * rule win, which once let the global config re-admit a provider, but under
 * Mandu OpenCode 2 reads no file of the user's (agent-config.ts
 * opencodeLockdownEnv): every layer is merged into the run file, whose fence
 * replaces the user's rules (supported-agents.md §2.3 item 8).
 */
export function opencodeV2ModelPlan(argv: readonly string[], input: OpencodeV2Input, auth: OpencodeAuthTypes = {}): ModelPlan {
  if (argv.length === 0 || !OPENCODE_BINS.has(basename(argv[0]!))) return NONE; // a wrapper
  const args = argv.slice(1);
  if (args.some((a) => HELP_OR_VERSION.has(a))) return NONE;
  if (input.unreadable.length > 0) {
    const u = input.unreadable[0]!;
    return refused(
      `mandu: refusing to launch opencode: could not read ${u.path} (${u.reason}). OpenCode 2 reads it, and Mandu ` +
      "checks every config layer for a model or endpoint that would go around Mandu's model proxy before the launch. " +
      "Fix the file (Mandu reads it as JSONC), or run opencode without mandu."
    );
  }
  const norm = input.layers.map((layer) => ({ layer, n: normalizeOpencodeDoc(layer.doc) }));
  const at = (where: string, layer: OpencodeLayer): string => `${where} in ${layer.path}`;

  // The models the session can run, each from the highest layer that sets it.
  let main: ModelRef | undefined;
  const named = new Map<string, ModelRef>();
  for (const { layer, n } of norm) {
    if (n.model) main = { ref: n.model.ref, where: at(n.model.where, layer) };
    for (const [name, r] of Object.entries(n.agents)) named.set(`agents.${name}`, { ref: r.ref, where: at(r.where, layer) });
    for (const [name, r] of Object.entries(n.commands)) named.set(`commands.${name}`, { ref: r.ref, where: at(r.where, layer) });
  }
  const cli = flagValue(args, true);
  const refs: ModelRef[] = [];
  if (cli !== undefined) refs.push({ ref: cli, where: "--model" }); // replaces the main model for the run
  else if (main) refs.push(main);
  refs.push(...named.values());

  const providers = mergeV2Providers(norm.map((x) => x.n));
  const verdictOf = (p: string): ProviderVerdict => opencodeV2ProviderVerdict(p, providers, auth);
  const judged = judge(refs, undefined, verdictOf);
  const bad = judged.filter((j) => j.verdict.kind === "refuse");
  if (bad.length > 0) return refused(refuseLines("opencode", bad, OPENCODE2_HINT));

  const routes = routesOf(judged);
  const routed = new Set([ROUTED_PROVIDER, ...routes.map((r) => r.id)]);

  // A routed provider's model with its own endpoint, or another SDK for anthropic.
  for (const { layer, n } of norm) {
    const key = n.endpointKeys.find((k) => routed.has(k.provider.toLowerCase()));
    if (key) {
      return refused(
        `mandu: refusing to launch opencode: ${at(key.where, layer)} gives one ${key.provider} model its own ` +
        "endpoint. OpenCode 2 sends that model's requests there instead of to the provider's base URL, which Mandu " +
        "points at its model proxy, so they would leave with tool results unmasked. Remove the key (Mandu routes " +
        `every ${key.provider} model through its proxy), or run opencode without mandu.`
      );
    }
    const a = n.providers[ROUTED_PROVIDER];
    const pkg = opencodePackageName(a?.package);
    if (a && ((pkg !== undefined && !ANTHROPIC_PACKAGES.has(pkg)) || a.canonical !== undefined)) {
      const which = a.canonical !== undefined ? "canonical" : a.spelling === "providers" ? "package" : "npm";
      return refused(
        `mandu: refusing to launch opencode: ${at(`${a.spelling}.anthropic.${which}`, layer)} makes the anthropic ` +
        "provider speak through another SDK, which may take its endpoint from other settings than the base URL " +
        "Mandu points at its model proxy. Remove it, or run opencode without mandu."
      );
    }
  }
  return { refusal: null, routes };
}

/** The refusal for any target (null for the targets this module does not own). */
export function agentModelRefusal(
  target: string, argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}, opencodeV2?: OpencodeV2Input,
): string | null {
  return agentModelPlan(target, argv, cfg, auth, opencodeV2).refusal;
}

/** The model plan for any target (nothing to route for the targets this
 *  module does not own). `opencodeV2` is given for an OpenCode 2 launch
 *  (opencode-config.ts opencodeGeneration): its layers replace `cfg`. */
export function agentModelPlan(
  target: string, argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}, opencodeV2?: OpencodeV2Input,
): ModelPlan {
  if (target === "openclaw") return openclawModelPlan(argv, cfg);
  if (target === "opencode") return opencodeV2 ? opencodeV2ModelPlan(argv, opencodeV2, auth) : opencodeModelPlan(argv, cfg, auth);
  return NONE;
}
