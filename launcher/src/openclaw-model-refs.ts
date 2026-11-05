/**
 * openclaw-model-refs — the models an OpenClaw config names, and OpenClaw's
 * openrouter bypass (docs/design/agents/openclaw-plugin.md §8.1, "The model
 * fence"; supported-agents.md §2.1, "The openrouter bypass"). Mandu-new (no
 * reference origin); moved out of agent-model-route.ts, which re-exports it,
 * so the service's route check (attachment-contract.ts) judges the model
 * fence by the same reading the install and the wrapper use.
 *
 * One module, byte-identical in two packages (each stays standalone): the
 * launcher and the dashboard (beside its copy of attachment-contract.ts).
 * The source is launcher/src/openclaw-model-refs.ts: change it, then run
 * `node scripts/copies/module-copies.mjs generate`. Pure: no imports, nothing
 * here reads the environment or the filesystem.
 */

type Json = Record<string, unknown>;

export interface ModelRef {
  ref: string;
  /** where it came from, e.g. "agents.defaults.model.primary" or "--model" */
  where: string;
}

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** A `model` value: a "provider/model" string, or `{ primary, fallbacks }`. */
export function refsOfModelValue(v: unknown, where: string, out: ModelRef[]): void {
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
export function collectModelKeys(node: unknown, where: string, out: ModelRef[]): void {
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
export function providerOf(ref: string, aliases: Json | undefined): string | null {
  if (ref.includes("/")) return ref.slice(0, ref.indexOf("/")).trim().toLowerCase();
  for (const [full, entry] of Object.entries(aliases ?? {})) {
    if (isObj(entry) && entry["alias"] === ref && full.includes("/")) return full.slice(0, full.indexOf("/")).trim().toLowerCase();
  }
  return null;
}

/** Active Memory's recall model references (they read the conversation). */
export function activeMemoryRefs(doc: Json, out: ModelRef[]): void {
  const plugins = isObj(doc["plugins"]) ? doc["plugins"] : {};
  const entries = isObj(plugins["entries"]) ? plugins["entries"] : {};
  const am = isObj(entries["active-memory"]) ? entries["active-memory"] : {};
  const cfg = isObj(am["config"]) ? am["config"] : {};
  for (const k of ["model", "modelFallback"]) {
    const v = cfg[k];
    if (typeof v === "string" && v.trim() !== "") out.push({ ref: v.trim(), where: `plugins.entries.active-memory.config.${k}` });
  }
}

/** OpenClaw: every model reference its config names (every agent's models,
 *  fallbacks included, and Active Memory's), each with the provider it
 *  names (null: a bare id no alias resolves). `mandu openclaw install`
 *  (openclaw-providers.ts) routes or reports each of their providers. Pure. */
export function openclawModelRefs(doc: Json): Array<ModelRef & { provider: string | null; full: string | null }> {
  const agents = isObj(doc["agents"]) ? doc["agents"] : {};
  const defaults = isObj(agents["defaults"]) ? agents["defaults"] : {};
  const aliases = isObj(defaults["models"]) ? defaults["models"] : undefined;
  const refs: ModelRef[] = [];
  collectModelKeys(agents, "agents", refs);
  activeMemoryRefs(doc, refs);
  // `full`: the `<provider>/<model>` the reference stands for (an alias resolved).
  const fullOf = (ref: string): string | null => {
    if (ref.includes("/")) return ref;
    for (const [full, entry] of Object.entries(aliases ?? {})) if (isObj(entry) && entry["alias"] === ref && full.includes("/")) return full;
    return null;
  };
  return refs.map((r) => ({ ...r, provider: providerOf(r.ref, aliases), full: fullOf(r.ref) }));
}

// ─── OpenClaw's openrouter bypass (supported-agents.md §2.1, "The openrouter
//     bypass"; openclaw-plugin.md §8.1) ─────────────────────────────────────
//
// OpenClaw 2026.3.12 and 2026.3.13 resolve an `openrouter` model that is
// neither in their catalog nor in `models.providers.openrouter.models` to a
// model of their own making whose baseUrl is `https://openrouter.ai/api/v1`,
// WHATEVER the provider's `baseUrl` says (resolveModelWithRegistry, read from
// the published packages, and measured on 2026.3.12: the turn went to
// openrouter.ai, not to the routed provider). From 2026.3.22 the openrouter
// provider plugin builds that model and the provider's `baseUrl` is applied
// over it (applyConfiguredProviderOverrides), measured on 2026.9.9. So on the
// old releases every openrouter model the config can run must be one the
// provider's `models` list names (an inline model carries the provider's
// baseUrl), and the model allowlist must name no openrouter model that is not
// listed: before 2026.3.22 an allowlist key is exact (`openrouter/*` is the
// model `*`), and an allowlisted model is selectable mid-session (`/model`,
// the `session_status` tool, `sessions_spawn`, cron).

/** The first OpenClaw release that sends an openrouter model it does not
 *  know to the provider's own `baseUrl` (2026.3.13 is the last that does
 *  not; no release lies between). */
export const OPENCLAW_OPENROUTER_BASEURL_SINCE = "2026.3.22";

// OpenClaw's GitHub Copilot provider ignores its baseUrl (openclaw-plugin.md
// §8.1, "GitHub Copilot"; read from the published releases 2026-10-26).
// OpenClaw's bundled github-copilot plugin trades the GitHub token for the
// Copilot endpoint at run time (its `prepareRuntimeAuth`: the `proxy-ep` of
// the token from api.github.com/copilot_internal/v2/token through 2026.7,
// the `endpoints.api` of api.github.com/copilot_internal/user since 2026.9)
// and sets that address on the model OVER the configured one, on every
// release from 2026.3.22 to 2026.10.7. A route Mandu writes into the
// provider's baseUrl would be dropped and the conversation sent straight to
// *.githubcopilot.com. 2026.3.12 and 2026.3.13 trade only the key, but
// Mandu cannot tell which release the Gateway runs, so the provider is
// refused on every release, by the wrapper and by `mandu openclaw install`.

/** The first OpenClaw release whose github-copilot provider sets the
 *  address its Copilot sign-in answers with over the provider's baseUrl. */
export const OPENCLAW_COPILOT_BASEURL_IGNORED_SINCE = "2026.3.22";

/** Why OpenClaw provider `id` cannot be routed whatever its baseUrl says
 *  (its calls go where OpenClaw decides at run time), or null. By OpenClaw's
 *  own id comparison (lower case). */
export function openclawRouteIgnoredWhy(id: string): string | null {
  if (id.trim().toLowerCase() !== "github-copilot") return null;
  return "OpenClaw sends GitHub Copilot's model calls to the endpoint its Copilot sign-in answers with " +
    "(a *.githubcopilot.com host), whatever the provider's baseUrl (every release since " +
    `${OPENCLAW_COPILOT_BASEURL_IGNORED_SINCE}), so a route through Mandu's model proxy would not hold`;
}

/** Is `id` OpenClaw's openrouter provider (its ids are lowercased)? */
export function isOpenrouterId(id: string): boolean {
  return id.trim().toLowerCase() === "openrouter";
}

/** OpenClaw's model id for the model part of an `openrouter/…` reference
 *  (its normalizeProviderModelId: an id with no `/` gains `openrouter/`). */
export function openclawOpenrouterId(model: string): string {
  const m = model.trim();
  return m.includes("/") ? m : `openrouter/${m}`;
}

/** The allowlist key OpenClaw reads for an openrouter model id (its
 *  modelKey: an id that already starts with `openrouter/` is its own key). */
export function openclawOpenrouterKey(id: string): string {
  return id.toLowerCase().startsWith("openrouter/") ? id : `openrouter/${id}`;
}

/** What an OpenClaw config lets run on its openrouter provider. */
export interface OpenrouterReach {
  /** Every openrouter model id it can run, with where it is named. */
  ids: Array<{ id: string; where: string }>;
  /** Allowlist keys whose model part holds `*` (a wildcard from 2026.3.22,
   *  the literal model `*` before). */
  wildcards: string[];
  /** The ids `models.providers.openrouter.models` lists. */
  listed: Set<string>;
}

/** The openrouter models an OpenClaw config can run: its configured
 *  references (every agent's models, fallbacks, Active Memory's; aliases
 *  resolved), the openrouter keys of its model allowlist
 *  (`agents.defaults.models`), and `extra` (a `--model` of the argv). Pure. */
export function openclawOpenrouterReach(doc: Json, extra: readonly ModelRef[] = []): OpenrouterReach {
  const ids: OpenrouterReach["ids"] = [];
  const wildcards: string[] = [];
  const agents = isObj(doc["agents"]) ? doc["agents"] : {};
  const defaults = isObj(agents["defaults"]) ? agents["defaults"] : {};
  const aliases = isObj(defaults["models"]) ? defaults["models"] : undefined;
  const fullOf = (ref: string): string | null => {
    if (ref.includes("/")) return ref;
    for (const [full, entry] of Object.entries(aliases ?? {})) if (isObj(entry) && entry["alias"] === ref && full.includes("/")) return full;
    return null;
  };
  for (const r of [...openclawModelRefs(doc), ...extra]) {
    const full = fullOf(r.ref);
    if (full === null || !isOpenrouterId(full.slice(0, full.indexOf("/")))) continue;
    ids.push({ id: openclawOpenrouterId(full.slice(full.indexOf("/") + 1)), where: r.where });
  }
  for (const key of Object.keys(aliases ?? {})) {
    const slash = key.indexOf("/");
    if (slash <= 0 || !isOpenrouterId(key.slice(0, slash))) continue;
    const model = key.slice(slash + 1);
    if (model.includes("*")) wildcards.push(key);
    else if (model.trim() !== "") ids.push({ id: openclawOpenrouterId(model), where: `agents.defaults.models["${key}"]` });
  }
  const models = isObj(doc["models"]) ? doc["models"] : {};
  const providers = isObj(models["providers"]) ? models["providers"] : {};
  const listed = new Set<string>();
  for (const [k, entry] of Object.entries(providers)) {
    if (!isOpenrouterId(k) || !isObj(entry) || !Array.isArray(entry["models"])) continue;
    for (const m of entry["models"]) if (isObj(m) && typeof m["id"] === "string") listed.add(m["id"]);
  }
  return { ids, wildcards, listed };
}

/** The openrouter models of a config OpenClaw before 2026.3.22 would send to
 *  openrouter.ai whatever the route: the ids it can run that the provider's
 *  `models` list does not name (once each, first place named), and the
 *  allowlist's wildcard keys. Pure. */
export function openclawOpenrouterUnlisted(doc: Json, extra: readonly ModelRef[] = []): { missing: Array<{ id: string; where: string }>; wildcards: string[] } {
  const reach = openclawOpenrouterReach(doc, extra);
  const seen = new Set<string>();
  const missing = reach.ids.filter((x) => !reach.listed.has(x.id) && !seen.has(x.id) && (seen.add(x.id), true));
  return { missing, wildcards: reach.wildcards };
}
