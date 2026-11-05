/**
 * openclaw-providers — Route 1 of `mandu openclaw install`
 * (docs/design/agents/openclaw-plugin.md §8.1): which providers of the user's
 * OpenClaw config the session's service proxy can read, where each one's
 * calls must go on to, and what its entry held before the install wrote its
 * route. Mandu-new (no reference origin); the per-provider rule is the
 * wrapper's (agent-model-route.ts openclawProviderVerdict), widened to the
 * Anthropic wire at an address of the provider's own. Pure: nothing here reads
 * the environment or the filesystem.
 *
 * THE PROVIDERS CONSIDERED: the two built-ins every OpenClaw has
 * (`anthropic`, `openai`), every `models.providers.<id>` of the config with
 * its includes resolved, and every provider a configured model names
 * (agents' models, fallbacks, Active Memory's), so a catalog provider the
 * config only names a model of (`google/…`) is not missed.
 *
 * EACH ONE IS
 *   - ROUTED when the proxy reads its wire (`api`: `anthropic-messages`,
 *     `openai-completions`, `openai-responses`, `google-generative-ai`
 *     (Gemini, since 2026-10-25), `ollama` (Ollama's native chat API,
 *     since 2026-10-26: the built-in `ollama` and `ollama-cloud` providers
 *     too), `azure-openai-responses` or `openai-chatgpt-responses` (Azure
 *     OpenAI and a ChatGPT sign-in, the Responses wire, since 2026-10-26:
 *     model-wires.md §9); a built-in's own when it names none) and its address is one the proxy sends to (https, or plain
 *     http to a literal loopback address; no user, password, query or
 *     fragment: base URLs only, never a credential). The proxy forwards it to
 *     that address, `upstream`, with the provider's own keys and headers as
 *     OpenClaw sends them; null `upstream` is a built-in's own address (the
 *     service's environment may set it). An Anthropic-wire provider rides
 *     the proxy's one Messages route, so every Anthropic-wire provider of a
 *     session must name one address (the `anthropic` provider's): a second
 *     one cannot be routed yet (a per-provider Messages route in the proxy,
 *     not built).
 *   - or one Mandu CANNOT ROUTE, with why: a wire it cannot read (Vertex AI,
 *     the Gemini CLI login, Bedrock, …: the seam the wire readers extend,
 *     PROVIDER_WIRES), GitHub Copilot (OpenClaw sends its calls to the
 *     endpoint its sign-in answers with, whatever the baseUrl), no `api`,
 *     no `baseUrl`, an address it does not send to, a catalog provider not
 *     declared in `models.providers`, a second Anthropic address. Install
 *     refuses unless the user names each such provider in
 *     `--leave-unprotected`: then it is LEFT AS IS (its calls never cross
 *     Mandu) and recorded as such. `hard` marks one no flag can leave (it
 *     points at a Mandu proxy already, with no record of its own address:
 *     left, it would fail every call).
 *
 * A PROVIDER ALREADY ROUTED (its `baseUrl` a loopback URL beside Mandu's
 * session header): its record from the earlier install (`prior`) keeps its
 * address and its original entry, so a second install changes nothing; an
 * Anthropic route from before Route 1, which no record names, is Anthropic's
 * own (that install refused any other). A route LOST since (the provider's
 * `baseUrl` changed after the install, by the user or by one of the agent's
 * programs): the record's address is kept, not the new one, and `kept` says
 * so (openclaw-plugin.md §3.6: a second install takes a lost route back;
 * uninstall, then install, adopts a new address on purpose).
 */
import {
  AZURE_ENDPOINT_ENV, CHATGPT_BACKEND_BASE, GEMINI_API_BASE, NODE_HAS_ZSTD, OLLAMA_BUILTIN_BASES, OPENAI_API_BASE, azureRouteProblem,
  chatgptZstdProblem, isOpenrouterId, ollamaUpstreamOf, openclawConfigAzureEnv, openclawModelRefs, openclawOpenrouterId, openclawOpenrouterKey,
  openclawOpenrouterReach, openclawOpenrouterUnlisted, routableUpstream, wireUpstream,
} from "./agent-model-route.js";
import { openclawRouteIgnoredWhy } from "./openclaw-model-refs.js";
import {
  configAt,
  configProviderIds,
  endpointWords,
  isLoopbackUrl,
  PROVIDER_ID_RE,
  PROVIDER_WIRES,
  recordableUrlProblem,
  SESSION_HEADER,
  type DeclaredProvider,
  type ProviderOriginal,
  type ProviderWire,
} from "./attachment-contract.js";

type Json = Record<string, unknown>;

/** A provider Mandu cannot route, and why. */
export interface UnroutableProvider {
  id: string;
  why: string;
  /** Where the config names a model of it (e.g. `agents.defaults.model.primary`). */
  refs: string[];
  /** No flag can leave it as it is (see the header). */
  hard?: true;
}

/** The plan for a config's providers. */
export interface ProviderPlan {
  routed: DeclaredProvider[];
  cannot: UnroutableProvider[];
  /** Providers whose address changed since the install recorded it: the
   *  recorded one is kept. */
  kept: Array<{ id: string; now: string | null; recorded: string | null }>;
}

/** Why Route 1 does not route Vertex AI (openclaw-plugin.md §8.1, "Vertex
 *  AI"). */
export const VERTEX_ROUTE1_WHY =
  "OpenClaw 2026.3.x (the Mandu plugin's oldest supported release) sends Vertex AI calls to Google's own host whatever the provider's baseUrl, " +
  "and the install cannot tell which OpenClaw your Gateway runs; `mandu openclaw` routes it on OpenClaw 2026.7.1 and later";

/** The wire a built-in provider speaks when its entry names none. */
const BUILTIN_WIRE: Readonly<Record<string, ProviderWire>> = {
  anthropic: "anthropic-messages", openai: "openai-responses", google: "google-generative-ai", ollama: "ollama", "ollama-cloud": "ollama",
};

/** Anthropic's own endpoint, spelled out (the proxy's default upstream). */
export function isAnthropicDefault(v: unknown): boolean {
  return typeof v === "string" && /^https:\/\/api\.anthropic\.com(?:\/v1)?\/?$/.test(v.trim());
}

/** A wire's name for people. */
export function wireWords(w: ProviderWire): string {
  return w === "anthropic-messages" ? "Anthropic Messages" : w === "openai-completions" ? "OpenAI Chat Completions"
    : w === "google-generative-ai" ? "Google Gemini" : w === "ollama" ? "Ollama" : w === "azure-openai-responses" ? "Azure OpenAI Responses"
    : w === "openai-chatgpt-responses" ? "OpenAI Responses (ChatGPT sign-in)" : "OpenAI Responses";
}

function obj(v: unknown): Json | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined;
}

/** A provider entry that names Mandu's route: a loopback `baseUrl` beside
 *  Mandu's session header (what install writes). */
export function isMandusRoute(entry: Json | undefined): boolean {
  const h = obj(entry?.["headers"])?.[SESSION_HEADER];
  return entry !== undefined && isLoopbackUrl(entry["baseUrl"]) && typeof h === "string" && h.startsWith("openclaw:");
}

/** What the main file's entry for `id` holds now (before the install). */
function originalOf(raw: Json, id: string): ProviderOriginal {
  const e = obj(configAt(raw, "models", "providers", id));
  return {
    existed: e !== undefined,
    ...(typeof e?.["baseUrl"] === "string" ? { baseUrl: e["baseUrl"] as string } : {}),
    ...(typeof e?.["api"] === "string" ? { api: e["api"] as string } : {}),
    headers: obj(e?.["headers"]) !== undefined,
    ...(e !== undefined ? { models: Array.isArray(e["models"]) } : {}),
  };
}

/** The original of an Anthropic route installed before Route 1 (no record):
 *  what that uninstall would have left, read off the entry (no baseUrl; its
 *  headers only if any is not Mandu's; the entry only if it holds more than
 *  install wrote). */
function legacyAnthropicOriginal(raw: Json): ProviderOriginal {
  const e = obj(configAt(raw, "models", "providers", "anthropic")) ?? {};
  const headers = obj(e["headers"]) ?? {};
  const ownHeaders = Object.keys(headers).some((k) => !k.toLowerCase().startsWith("x-mandu-"));
  const models = e["models"];
  const onlyOurs = Object.keys(e).every((k) => k === "baseUrl" || k === "api" || k === "headers" || k === "models") &&
    !ownHeaders && (models === undefined || (Array.isArray(models) && models.length === 0));
  return { existed: !onlyOurs, ...(!onlyOurs && typeof e["api"] === "string" ? { api: e["api"] as string } : {}), headers: ownHeaders };
}

/** The address an upstream names, for comparing two (null: the built-in's). */
function sameAddress(a: string | null, b: string | null): boolean {
  const n = (v: string | null): string => (v === null ? "" : v.replace(/\/+$/, ""));
  return n(a) === n(b);
}

/**
 * Classify every provider of an OpenClaw config (`effective`: includes
 * resolved; `raw`: the main file, whose entries uninstall restores). `prior`:
 * the providers the session's declaration recorded at an earlier install.
 * Pure.
 */
export function planProviders(
  effective: Json, raw: Json, prior: readonly DeclaredProvider[] = [], priorFence: readonly string[] = [],
  opts: PlanOptions = {},
): ProviderPlan {
  // The model allowlist's keys name models too: each one is selectable
  // mid-session (`/model`, the `session_status` tool, `sessions_spawn`), so
  // its provider is judged like a configured model's. The keys an earlier
  // install wrote (`priorFence`, the declaration's) are Mandu's fence, not
  // the user's choice: planModelFence decides them again.
  const user = withoutAllowKeys(effective, priorFence);
  const allowRefs = Object.keys(obj(configAt(user, "agents", "defaults", "models")) ?? {})
    .filter((k) => k.indexOf("/") > 0)
    .map((k) => ({ provider: k.slice(0, k.indexOf("/")).trim().toLowerCase(), where: `agents.defaults.models["${k}"]` }));
  const refs = [...openclawModelRefs(effective), ...allowRefs];
  const refsOf = (id: string): string[] => refs.filter((r) => r.provider === id.toLowerCase()).map((r) => r.where);
  const ids = [...configProviderIds(effective)];
  for (const r of refs) if (r.provider !== null && !ids.some((id) => id.toLowerCase() === r.provider)) ids.push(r.provider);

  const routed: DeclaredProvider[] = [];
  const cannot: UnroutableProvider[] = [];
  const kept: ProviderPlan["kept"] = [];
  const no = (id: string, why: string, hard = false): void => {
    cannot.push({ id, why, refs: refsOf(id), ...(hard ? { hard: true as const } : {}) });
  };

  for (const id of ids) {
    const entry = obj(configAt(effective, "models", "providers", id));
    const before = prior.find((p) => p.id === id);
    if (!PROVIDER_ID_RE.test(id)) { no(id, "its provider id is not a plain name"); continue; }
    // A provider whose calls go where OpenClaw decides at run time (GitHub
    // Copilot, openclaw-model-refs.ts): no route holds. One an earlier
    // install routed keeps Mandu's address in its baseUrl: uninstall puts
    // its own back from the record, so it cannot be left as it is.
    const ignored = openclawRouteIgnoredWhy(id);
    if (ignored !== null) {
      if (isMandusRoute(entry)) no(id, `${ignored}; an earlier install routed it: run mandu openclaw uninstall (it puts the provider's own address back), then install again`, true);
      else no(id, ignored);
      continue;
    }
    // Vertex AI (model-wires.md §4.1): the wrapper routes OpenClaw's
    // google-vertex provider on a release that takes the route, but OpenClaw
    // 2026.3.x, inside the plugin's floor, sends Vertex calls to Google
    // whatever the baseUrl, and install cannot tell which release the
    // Gateway runs.
    if (id.toLowerCase() === "google-vertex" || entry?.["api"] === "google-vertex") { no(id, VERTEX_ROUTE1_WHY); continue; }
    if (isMandusRoute(entry)) {
      if (before !== undefined) routed.push(before);
      else if (id === "anthropic") routed.push({ id, wire: "anthropic-messages", upstream: null, original: legacyAnthropicOriginal(raw) });
      else no(id, "it already points at a Mandu proxy, and the Mandu service has no record of its own address; put its baseUrl back (the install's backup has it), then install again", true);
      continue;
    }
    const builtin = BUILTIN_WIRE[id];
    if (entry === undefined && builtin === undefined) {
      no(id, `it is not declared in models.providers; Mandu routes a provider declared there with its baseUrl and api (${PROVIDER_WIRES.map((w) => `"${w}"`).join(", ")})`);
      continue;
    }
    const api = entry?.["api"] ?? builtin;
    if (api === undefined) { no(id, `models.providers.${id} names no api, and Mandu reads only ${PROVIDER_WIRES.map((w) => `"${w}"`).join(", ")}`); continue; }
    if (typeof api !== "string" || !(PROVIDER_WIRES as readonly string[]).includes(api)) {
      no(id, `it uses api ${JSON.stringify(api)}, a wire Mandu's proxy cannot read yet`);
      continue;
    }
    const wire = api as ProviderWire;
    const base = entry?.["baseUrl"];
    let upstream: string | null;
    if (base === undefined && wire === "openai-chatgpt-responses" && id === "openai") {
      // The built-in openai provider on its ChatGPT sign-in: the backend's
      // own base (OpenClaw's default), recorded, never null.
      upstream = CHATGPT_BACKEND_BASE;
    } else if (base === undefined) {
      if (builtin === undefined || wire === "azure-openai-responses" || wire === "openai-chatgpt-responses") { no(id, `models.providers.${id} names no baseUrl`); continue; }
      upstream = null;
    } else if (id === "anthropic" && wire === "anthropic-messages" && isAnthropicDefault(base)) {
      upstream = null;
    } else {
      const text = typeof base === "string" ? base : "";
      const credential = text !== "" ? recordableUrlProblem(text) : "is not a URL";
      const u = credential === null ? routableUpstream(text) : null;
      if (u === null) {
        no(id, credential !== null && credential !== "is not a URL" && credential !== "is not http(s)"
          ? `its baseUrl ${credential}; Mandu records base URLs only, never a credential (move the key to apiKey or headers)`
          : `its baseUrl (${text === "" ? "not a string" : endpointWords(text)}) is not an address Mandu's proxy sends to (https, or plain http to a literal loopback address such as 127.0.0.1)`);
        continue;
      }
      if (wire === "azure-openai-responses") {
        const problem = azureRouteProblem(u);
        if (problem !== null) { no(id, problem); continue; }
      }
      // Where OpenClaw would itself have sent the path the route is given:
      // an Ollama base without its `/v1` (OpenClaw joins `/api/chat`);
      // Azure's normalized base, the ChatGPT `/codex` base (model-wires.md §9).
      upstream = wire === "anthropic-messages" ? u : wire === "ollama" ? ollamaUpstreamOf(u) : wireUpstream(wire, u);
    }
    if (wire === "azure-openai-responses") {
      // OpenClaw's Azure client reads its endpoint from these variables
      // BEFORE the provider's baseUrl (model-wires.md §9.1): where install
      // can see one set, every Azure call would go there, around the route.
      const set = [...openclawConfigAzureEnv(effective), ...(opts.azureEndpointEnv ?? [])];
      if (set.length > 0) {
        no(id, `OpenClaw's Azure OpenAI client sends every Azure call to ${set.join(", ")} instead of the provider's baseUrl, around Mandu's proxy; ` +
          `unset ${AZURE_ENDPOINT_ENV.join(" and ")} where the Gateway runs (models.providers.${id}.baseUrl names the endpoint), then restart it`);
        continue;
      }
      if (opts.azureEndpointUnverified !== undefined) {
        no(id, `Mandu cannot verify that the Gateway leaves ${AZURE_ENDPOINT_ENV.join(" and ")} unset (${opts.azureEndpointUnverified}), ` +
          "and OpenClaw's Azure OpenAI client sends every Azure call there when one is set, around Mandu's proxy");
        continue;
      }
    }
    if (before !== undefined && before.wire === wire && !sameAddress(before.upstream, upstream)) {
      // The address changed after the install: keep the recorded one.
      kept.push({ id, now: upstream, recorded: before.upstream });
      routed.push(before);
      continue;
    }
    routed.push({ id, wire, upstream, original: before?.original ?? originalOf(raw, id) });
  }

  // OpenClaw's openrouter bypass (agent-model-route.ts; supported-agents.md
  // §2.1, found by the plugin lane): OpenClaw 2026.3.12 and 2026.3.13 send an
  // openrouter model that neither their catalog nor
  // `models.providers.openrouter.models` knows straight to
  // https://openrouter.ai/api/v1 WHATEVER the provider's baseUrl, around the
  // proxy (2026.3.22 and later honour the baseUrl). Mandu cannot read
  // OpenClaw's catalog, nor know which OpenClaw the Gateway runs (it may
  // change after the install), so every openrouter model the config can run
  // (its configured models and its allowlist's openrouter keys) must be
  // listed there, under OpenClaw's own id (`openrouter/<id>` for an id with
  // no `/`), and an openrouter wildcard in the allowlist (the literal model
  // `*` on those releases) is refused.
  const or = routed.findIndex((p) => p.id === "openrouter");
  if (or >= 0) {
    const { missing, wildcards } = openclawOpenrouterUnlisted(user);
    if (missing.length > 0 || wildcards.length > 0) {
      routed.splice(or, 1);
      const parts = [
        ...(missing.length > 0 ? [`list ${missing.map((m) => `"${m.id}"`).join(", ")} in models.providers.openrouter.models (as {"id": …})`] : []),
        ...(wildcards.length > 0 ? [`replace ${wildcards.map((w) => `"${w}"`).join(", ")} in agents.defaults.models with the openrouter models you use, listed there too (before 2026.3.22 OpenClaw reads it as the model "*")`] : []),
      ];
      no("openrouter", `OpenClaw before 2026.3.22 sends a model of its built-in openrouter provider that its own catalog and models.providers.openrouter.models do not list straight to openrouter.ai, whatever the provider's baseUrl; ${parts.join("; and ")}`);
    }
  }

  // The built-in openai on a ChatGPT sign-in sends zstd bodies: refused on
  // a Node.js without zstd, said here rather than as refused turns.
  const zi = routed.findIndex((p) => p.id === "openai" && p.wire === "openai-chatgpt-responses");
  if (zi >= 0) {
    const why = chatgptZstdProblem([{ id: "openai", api: "openai-chatgpt-responses" }], opts.hasZstd ?? NODE_HAS_ZSTD);
    if (why !== null) { routed.splice(zi, 1); no("openai", why); }
  }

  // One Messages upstream per session: the `anthropic` provider's address.
  const messages = routed.filter((p) => p.wire === "anthropic-messages");
  const lead = messages.find((p) => p.id === "anthropic") ?? messages[0];
  const out: DeclaredProvider[] = [];
  for (const p of routed) {
    if (p.wire === "anthropic-messages" && lead !== undefined && p !== lead && !sameAddress(p.upstream, lead.upstream)) {
      no(p.id, `it is a second Anthropic Messages endpoint (${p.upstream !== null ? endpointWords(p.upstream) : "Anthropic's"}) beside ${lead.id}'s ` +
        `(${lead.upstream !== null ? endpointWords(lead.upstream) : "Anthropic's"}), and the service proxy forwards one Messages endpoint per session`);
      continue;
    }
    out.push(p);
  }
  return { routed: out, cannot, kept };
}

/** What install sees beyond the config (openclaw-install-command.ts). */
export interface PlanOptions {
  /** Where one of AZURE_ENDPOINT_ENV is set for the Gateway, as install can
   *  see it (its own environment, the running Gateway's, its systemd unit,
   *  OpenClaw's dotenv files): each as `<name> (<where>)`. The config's own
   *  `env` block is read here. */
  azureEndpointEnv?: readonly string[];
  /** Whether the Node.js running Mandu's model proxy has zstd (default:
   *  this one's, NODE_HAS_ZSTD): without it the built-in openai on a
   *  ChatGPT sign-in is refused (model-wires.md §9.3). */
  hasZstd?: boolean;
  /** Why the running Gateway's environment could not be read: an Azure
   *  provider is then refused (not verified, model-wires.md §9.1). */
  azureEndpointUnverified?: string;
}

/** `doc` with the model allowlist keys `keys` left out (a copy where it
 *  changes). Pure. */
function withoutAllowKeys(doc: Json, keys: readonly string[]): Json {
  const allow = obj(configAt(doc, "agents", "defaults", "models"));
  if (allow === undefined || !keys.some((k) => k in allow)) return doc;
  const kept = Object.fromEntries(Object.entries(allow).filter(([k]) => !keys.includes(k)));
  const agents = obj(doc["agents"])!;
  return { ...doc, agents: { ...agents, defaults: { ...obj(agents["defaults"])!, models: kept } } };
}

/** What install does to OpenClaw's model allowlist (`agents.defaults.models`). */
export interface ModelFencePlan {
  /** Keys to add, each as `{}`. */
  write: string[];
  /** Keys an earlier install added that the fence no longer holds. */
  remove: string[];
  /** The keys Mandu holds in the allowlist after the install (the
   *  declaration's `allowlist`, which uninstall removes). */
  record: string[];
}

/**
 * The model fence of `mandu openclaw install` (openclaw-plugin.md §8.1, "The
 * model fence"; decided 2026-10-25). OpenClaw lets a session switch its model
 * mid-session (`/model`, the `session_status` tool, `sessions_spawn`, cron)
 * to any model when `agents.defaults.models` is empty, and to the models it
 * names otherwise (measured on 2026.3.12: `sessions.patch`, which
 * `sessions_spawn` and cron use, accepts any model with no allowlist; with
 * one, an unlisted model is refused "is not allowed"). A switch to a provider
 * Mandu does not route goes around the proxy, and on OpenClaw before 2026.3.22
 * a switch to an openrouter model OpenClaw does not know goes to openrouter.ai
 * whatever the route. So when the user keeps no allowlist of their own the
 * install writes one: `<provider>/*` for each provider it routes and each the
 * user left unprotected, the openrouter models `models.providers.openrouter.
 * models` lists by their exact key (no wildcard: before 2026.3.22 an
 * allowlist key is exact and `openrouter/*` is the model `*`), and every
 * model the config names of those providers by its exact key (so a release
 * that reads keys exactly can still switch among them). A user's own
 * allowlist is left as it is (planProviders judged its keys: each one's
 * provider routed or left, each openrouter key listed). `priorFence`: the
 * keys an earlier install recorded; `drop`: keys a second install takes back
 * out (fenceKeysToReclaim). Pure.
 */
export function planModelFence(
  effective: Json, plan: Pick<ProviderPlan, "routed" | "cannot">, priorFence: readonly string[] = [], drop: readonly string[] = [],
): ModelFencePlan {
  // `drop`: keys a second install takes back out (fenceKeysToReclaim); the
  // fence is planned as if they were gone, and they are removed.
  const all = Object.keys(obj(configAt(effective, "agents", "defaults", "models")) ?? {});
  const dropped = all.filter((k) => drop.includes(k));
  const fence0 = planFenceOver(effective, all.filter((k) => !drop.includes(k)), plan, priorFence);
  return { write: fence0.write, remove: [...fence0.remove, ...dropped], record: fence0.record };
}

/**
 * The keys a second install takes back out of the model allowlist
 * (openclaw-plugin.md §3.6, "The model fence"; decided 2026-10-25): on a
 * config a FENCED install wrote (the declaration records its `allowlist`),
 * each key added since that lets a model switch go around Mandu: a key of a
 * provider the plan does not route and the user does not leave (now, by
 * `--leave-unprotected`, or at the earlier install), and while openrouter is
 * declared, an openrouter wildcard or an openrouter key whose model
 * `models.providers.openrouter.models` does not list. Install refuses each
 * such key, so on a fenced config it was added after the install, as a
 * changed route is (`kept` above): adopting one on purpose takes naming its
 * provider in `--leave-unprotected`, or listing the openrouter model. Keys
 * the install itself recorded (`priorFence`) are planModelFence's. Pure.
 */
export function fenceKeysToReclaim(effective: Json, plan: Pick<ProviderPlan, "routed">, leave: readonly string[], priorFence: readonly string[]): string[] {
  const lower = (v: string): string => v.trim().toLowerCase();
  const kept = new Set(leave.map(lower));
  const routed = new Set(plan.routed.map((p) => lower(p.id)));
  const providers = obj(configAt(effective, "models", "providers")) ?? {};
  const openrouterDeclared = Object.keys(providers).some((k) => isOpenrouterId(k));
  const listed = openclawOpenrouterReach(effective).listed;
  const out: string[] = [];
  for (const k of Object.keys(obj(configAt(effective, "agents", "defaults", "models")) ?? {})) {
    if (priorFence.includes(k)) continue;
    const slash = k.indexOf("/");
    if (slash <= 0) continue;
    const p = lower(k.slice(0, slash));
    if (kept.has(p)) continue;
    if (isOpenrouterId(p) && openrouterDeclared) {
      const model = k.slice(slash + 1);
      if (model.includes("*") || !listed.has(openclawOpenrouterId(model))) out.push(k);
      continue;
    }
    if (!routed.has(p)) out.push(k);
  }
  return out;
}

function planFenceOver(effective: Json, current: readonly string[], plan: Pick<ProviderPlan, "routed" | "cannot">, priorFence: readonly string[]): ModelFencePlan {
  const ours = current.filter((k) => priorFence.includes(k));
  const theirs = current.filter((k) => !priorFence.includes(k));
  if (theirs.length > 0 && ours.length === 0) return { write: [], remove: [], record: [] };
  const fence = new Set<string>();
  const covered = new Set<string>();
  for (const p of plan.routed) {
    covered.add(p.id.toLowerCase());
    if (isOpenrouterId(p.id)) {
      for (const id of openclawOpenrouterReach(effective).listed) fence.add(openclawOpenrouterKey(id));
    } else {
      fence.add(`${p.id}/*`);
    }
  }
  for (const c of plan.cannot) { covered.add(c.id.toLowerCase()); fence.add(`${c.id}/*`); }
  for (const r of openclawModelRefs(effective)) {
    if (r.full === null || r.provider === null || !covered.has(r.provider)) continue;
    const model = r.full.slice(r.full.indexOf("/") + 1);
    fence.add(isOpenrouterId(r.provider) && plan.routed.some((p) => isOpenrouterId(p.id)) ? openclawOpenrouterKey(openclawOpenrouterId(model)) : r.full);
  }
  const write = [...fence].filter((k) => !current.includes(k));
  const remove = ours.filter((k) => !fence.has(k));
  const record = [...ours.filter((k) => fence.has(k)), ...write];
  return { write, remove, record };
}

/** The built-in address an upstream of null stands for. */
export function builtinAddress(p: Pick<DeclaredProvider, "id" | "wire">): string {
  return p.wire === "anthropic-messages" ? "https://api.anthropic.com" : p.wire === "google-generative-ai" ? GEMINI_API_BASE
    : p.wire === "ollama" ? OLLAMA_BUILTIN_BASES[p.id] ?? OLLAMA_BUILTIN_BASES["ollama"]!
    : p.wire === "openai-chatgpt-responses" ? CHATGPT_BACKEND_BASE : OPENAI_API_BASE;
}
