/**
 * openclaw-attach — the pure half of `mandu openclaw install|uninstall` and
 * of its `mandu doctor` check (docs/design/agents/openclaw-plugin.md §3.2,
 * §3.3, §8). Mandu-new (no reference origin). Nothing here reads the
 * environment or the filesystem; openclaw-install-command.ts does the I/O.
 *
 * WHAT INSTALL WRITES into the user's `openclaw.json` (the main file only;
 * its `$include` files are left as they are):
 *   - `plugins.load.paths` gains the plugin's directory, `plugins.entries.
 *     mandu-inspect` is enabled with the attachment config (`attachment:
 *     true`, the agent, its session as `scopeId`, the arbiter socket the
 *     service proxy uses, Mandu's own paths for the tamper policy), and
 *     `plugins.allow` names it when the user keeps an allowlist;
 *   - `tools.alsoAllow` gains the plugin's two tools (as the per-run config
 *     does, services/agent-config.ts buildOpenclawWrapDoc);
 *   - every provider Route 1 routes (openclaw-providers.ts; openclaw-plugin.md
 *     §8.1) points at the service proxy of that agent's session: its
 *     `baseUrl` (the proxy for the Anthropic wire, the proxy's
 *     `/_mandu/openai/<id>` route for an OpenAI wire, its `/_mandu/google/<id>`
 *     route for the Gemini wire, its `/_mandu/ollama/<id>` route for Ollama's
 *     native chat API), its `api` pinned to
 *     the wire the proxy reads, and the session headers merged into its own;
 *     its key (`apiKey`, an auth profile) and its other headers stay as they
 *     are, and its model entries keep only the fields that describe a model
 *     (an entry's own baseUrl would go around the proxy). Without a provider
 *     list (the facts of a caller before Route 1), `anthropic` alone;
 *   - the model fence, when the caller gives one (openclaw-providers.ts
 *     planModelFence; openclaw-plugin.md §8.1): keys added to OpenClaw's
 *     model allowlist (`agents.defaults.models`, each `{}`), and keys an
 *     earlier install added that the fence no longer holds, removed.
 * Nothing that needs `hooks.allowConversationAccess` is granted.
 *
 * WHAT UNINSTALL PUTS BACK: each routed provider's entry exactly as the
 * declaration recorded it before the install (its `baseUrl`, its `api`, its
 * `headers` object, or no entry at all), so a config install then uninstall
 * went through is the user's own again, key for key (dropped model fields
 * excepted: the backup keeps them). An Anthropic route from before Route 1,
 * which no record names, is undone by the old rule. The model fence's keys
 * (the declaration's `allowlist`) are removed, and the allowlist with them
 * when nothing else is left in it; a key the user added since stays.
 *
 * THE SERVICE URL CONTRACT (attachment-contract.ts; `mandu serve` writes it
 * and this reads it):
 *   `<runtime>/attachments/<session>/anthropic-proxy.port`
 * holds the decimal port of the session's model proxy and a newline, in a
 * regular file this user owns that no one else can write, in a directory the
 * service creates 0700. It is written atomically once the proxy listens on
 * 127.0.0.1, and removed when it stops. The proxy answers `GET
 * /_mandu/identity` with `{mandu: true, service: "anthropic-proxy",
 * sessionKey: <session>, arbiterSock}`; install adopts the port only when the
 * identity matches (another program on the port, or another session's proxy,
 * is refused). The service keeps a session's port across restarts when it
 * is free, so the route install wrote stays valid; when it cannot, the
 * doctor check reports the route stale.
 */

import {
  ATTACH_PLUGIN_ID,
  configAt as at,
  isLoopbackUrl,
  isOurLoadPath,
  MODEL_METADATA_KEYS,
  normalizeAgentId,
  providerRouteUrl,
  SESSION_HEADER,
  TENANT_HEADER,
  type DeclaredProvider,
} from "./attachment-contract.js";

type Json = Record<string, unknown>;

/** The plugin's tools, lifted past the tool profile (tools.alsoAllow). */
export const ATTACH_TOOLS: readonly string[] = ["inspect_symbol", "declassify_symbol"];

// ── The session and the service URL contract (attachment-contract.ts, the
//    module the proxy pool shares; re-exported here for this module's callers)

export {
  ATTACH_PLUGIN_ID,
  PLUGIN_DIR_NAME,
  SESSION_HEADER,
  TENANT_HEADER,
  attachedSession,
  attachState,
  endpointWords,
  isLoopbackUrl,
  looksAttached,
  modelsAround,
  providerRouteUrl,
  routeVerdict,
  type DeclaredProvider,
  unreadableRouteVerdict,
  ROUTE_FIX,
  type AttachState,
  type RouteProblem,
  type RouteVerdict,
  ANTHROPIC_PROXY_PORT_FILE,
  ATTACHMENTS_DIR,
  anthropicProxyPortFile,
  attachmentDir,
  attachmentSession,
  identityProblem,
  normalizeAgentId,
  parsePortFile,
  portFileProblem,
  serviceProxyUrl,
  type ServiceIdentity,
} from "./attachment-contract.js";

// ── Reading a config (the state readers live in attachment-contract.ts) ─────

function obj(v: unknown): Json | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

// ── Install / uninstall plans ────────────────────────────────────────────────

/** What install writes, all decided by the caller. */
export interface AttachFacts {
  pluginDir: string;
  agentId: string;
  session: string;
  proxyUrl: string;
  arbiterSock: string;
  manduPaths: readonly string[];
  /** The providers to route (Route 1, openclaw-providers.ts planProviders);
   *  absent: `anthropic` alone. */
  providers?: ReadonlyArray<Pick<DeclaredProvider, "id" | "wire">>;
  /** The model fence (openclaw-providers.ts planModelFence): the
   *  `agents.defaults.models` keys to add (each `{}`) and the ones an
   *  earlier install added that go; absent: the allowlist is not touched. */
  fence?: { write: readonly string[]; remove: readonly string[] };
}

/** Why install must not touch this config, or null. `effective` is the doc
 *  with its includes resolved (what OpenClaw runs). `reclaim`: Mandu was
 *  installed in this config before (its marks are in it, or the service
 *  recorded it), so a Mandu plugin denied or an Anthropic route pointed
 *  elsewhere is a route LOST since (openclaw-plugin.md §3.6), which a second
 *  install takes back, not a choice of the user's it would override. Plugins
 *  switched off as a whole stay a refusal: turning them on would load every
 *  other plugin too. */
export function installRefusal(effective: Json, o: { reclaim?: boolean } = {}): string | null {
  if (at(effective, "plugins", "enabled") === false) {
    return "your OpenClaw config turns plugins off (plugins.enabled: false), so the Mandu plugin would never load" +
      (o.reclaim === true ? "; set plugins.enabled back to true (or remove it), then run mandu openclaw install again" : "");
  }
  if (o.reclaim === true) return null;
  if (strings(at(effective, "plugins", "deny")).includes(ATTACH_PLUGIN_ID)) {
    return `your OpenClaw config denies the Mandu plugin (plugins.deny names ${ATTACH_PLUGIN_ID})`;
  }
  // A provider's own endpoint is no refusal since Route 1: the proxy
  // forwards each routed provider to its own address (openclaw-providers.ts).
  return null;
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function ensureObj(parent: Json, key: string): Json {
  const cur = obj(parent[key]);
  if (cur) return cur;
  const fresh: Json = {};
  parent[key] = fresh;
  return fresh;
}

/** The new main-file doc for install, and the model fields it dropped. Pure;
 *  idempotent (planning over its own output changes nothing). `reclaim`
 *  (installRefusal's): a `plugins.deny` entry naming the plugin goes too. */
export function planInstall(raw: Json, f: AttachFacts, o: { reclaim?: boolean } = {}): { doc: Json; dropped: string[] } {
  const doc = clone(raw);
  const plugins = ensureObj(doc, "plugins");
  if (o.reclaim === true && Array.isArray(plugins["deny"])) {
    plugins["deny"] = (plugins["deny"] as unknown[]).filter((x) => x !== ATTACH_PLUGIN_ID);
  }
  const load = ensureObj(plugins, "load");
  const paths = Array.isArray(load["paths"]) ? load["paths"] as unknown[] : [];
  if (!paths.includes(f.pluginDir)) paths.push(f.pluginDir);
  load["paths"] = paths;
  const entries = ensureObj(plugins, "entries");
  const entry = ensureObj(entries, ATTACH_PLUGIN_ID);
  entry["enabled"] = true;
  entry["config"] = {
    ...(obj(entry["config"]) ?? {}),
    arbiterSock: f.arbiterSock,
    scopeId: f.session,
    attachment: true,
    agentId: normalizeAgentId(f.agentId),
    manduPaths: [...f.manduPaths],
  };
  if (Array.isArray(plugins["allow"]) && !(plugins["allow"] as unknown[]).includes(ATTACH_PLUGIN_ID)) {
    (plugins["allow"] as unknown[]).push(ATTACH_PLUGIN_ID);
  }

  const tools = ensureObj(doc, "tools");
  const also = Array.isArray(tools["alsoAllow"]) ? tools["alsoAllow"] as unknown[] : [];
  for (const t of ATTACH_TOOLS) if (!also.includes(t)) also.push(t);
  tools["alsoAllow"] = also;

  const providers = ensureObj(ensureObj(doc, "models"), "providers");
  const dropped: string[] = [];
  const routed: ReadonlyArray<Pick<DeclaredProvider, "id" | "wire">> = f.providers ?? [{ id: "anthropic", wire: "anthropic-messages" }];
  for (const p of routed) {
    const entry = ensureObj(providers, p.id);
    entry["baseUrl"] = providerRouteUrl(f.proxyUrl, p);
    // The wire the proxy reads, named (OpenClaw infers `openai-completions`
    // for a provider without one, and the built-ins' own wire is this).
    entry["api"] = p.wire;
    entry["headers"] = { ...(obj(entry["headers"]) ?? {}), [SESSION_HEADER]: f.session, [TENANT_HEADER]: "live" };
    const list = Array.isArray(entry["models"]) ? entry["models"] as unknown[] : [];
    // `models` must be present (2026.3.12 rejects a provider without it).
    entry["models"] = list.map((e) => {
      const m = obj(e);
      if (!m) return e;
      const kept: Json = {};
      for (const [k, v] of Object.entries(m)) {
        if (MODEL_METADATA_KEYS.has(k)) kept[k] = v;
        else dropped.push(`${p.id === "anthropic" ? "" : `${p.id}/`}${typeof m["id"] === "string" ? m["id"] : "?"}.${k}`);
      }
      return kept;
    });
  }
  if (f.fence !== undefined && (f.fence.write.length > 0 || f.fence.remove.length > 0)) {
    const allow = ensureObj(ensureObj(ensureObj(doc, "agents"), "defaults"), "models");
    for (const k of f.fence.remove) delete allow[k];
    for (const k of f.fence.write) if (!(k in allow)) allow[k] = {};
    dropEmptyAllowlist(doc);
  }
  return { doc, dropped };
}

/** `agents.defaults.models` gone when empty, and the objects that held only it. */
function dropEmptyAllowlist(doc: Json): void {
  const agents = obj(doc["agents"]);
  const defaults = obj(agents?.["defaults"]);
  const allow = obj(defaults?.["models"]);
  if (!agents || !defaults || !allow || Object.keys(allow).length > 0) return;
  delete defaults["models"];
  if (Object.keys(defaults).length === 0) delete agents["defaults"];
  if (Object.keys(agents).length === 0) delete doc["agents"];
}

/** Remove `id`'s provider entry and the objects that held only it. */
function dropProvider(doc: Json, id: string): void {
  const providers = obj(at(doc, "models", "providers"));
  if (!providers) return;
  delete providers[id];
  const models = obj(doc["models"])!;
  if (Object.keys(providers).length === 0) delete models["providers"];
  if (Object.keys(models).length === 0) delete doc["models"];
}

/** Put a routed provider's entry back as the record says it was. A route
 *  that is no longer Mandu's (the user moved it since) keeps its address;
 *  Mandu's headers go either way. */
function restoreProvider(doc: Json, p: DeclaredProvider): void {
  const entry = obj(at(doc, "models", "providers", p.id));
  if (!entry) return;
  const headers = obj(entry["headers"]);
  const ours = isLoopbackUrl(entry["baseUrl"]) && typeof headers?.[SESSION_HEADER] === "string";
  if (headers) {
    for (const k of Object.keys(headers)) if (k.toLowerCase().startsWith("x-mandu-")) delete headers[k];
    if (Object.keys(headers).length === 0 && !p.original.headers) delete entry["headers"];
  }
  if (!ours) return;
  if (p.original.baseUrl !== undefined) entry["baseUrl"] = p.original.baseUrl;
  else delete entry["baseUrl"];
  if (p.original.api !== undefined) entry["api"] = p.original.api;
  else if (entry["api"] === p.wire) delete entry["api"];
  if (p.original.models === false && Array.isArray(entry["models"]) && (entry["models"] as unknown[]).length === 0) delete entry["models"];
  if (!p.original.existed) {
    const models = entry["models"];
    if (Object.keys(entry).every((k) => k === "models") && (models === undefined || (Array.isArray(models) && models.length === 0))) dropProvider(doc, p.id);
  }
}

/** The new main-file doc for uninstall: what install added, recognized as
 *  Mandu's, removed; everything else left. `providers`: the routes the
 *  session's declaration recorded (Route 1), each put back exactly; without
 *  them, the Anthropic route goes by the rule before Route 1, and another
 *  provider still pointing at a Mandu route loses Mandu's headers but keeps
 *  that address (no record says what it was): `unrestored` names it. Pure. */
export function planUninstall(raw: Json, pluginDir?: string, providers?: readonly DeclaredProvider[], fence?: readonly string[]): { doc: Json; changed: boolean; unrestored: string[] } {
  const doc = clone(raw);
  // The model fence's keys the install added (the declaration's `allowlist`).
  const allow = obj(at(doc, "agents", "defaults", "models"));
  if (allow && fence && fence.length > 0) {
    for (const k of fence) delete allow[k];
    dropEmptyAllowlist(doc);
  }
  const plugins = obj(doc["plugins"]);
  if (plugins) {
    const entries = obj(plugins["entries"]);
    if (entries) {
      delete entries[ATTACH_PLUGIN_ID];
      if (Object.keys(entries).length === 0) delete plugins["entries"];
    }
    const load = obj(plugins["load"]);
    if (load && Array.isArray(load["paths"])) {
      load["paths"] = (load["paths"] as unknown[]).filter((p) => !isOurLoadPath(p, pluginDir));
      if ((load["paths"] as unknown[]).length === 0) delete load["paths"];
      if (Object.keys(load).length === 0) delete plugins["load"];
    }
    if (Array.isArray(plugins["allow"])) plugins["allow"] = (plugins["allow"] as unknown[]).filter((x) => x !== ATTACH_PLUGIN_ID);
    if (Object.keys(plugins).length === 0) delete doc["plugins"];
  }
  const tools = obj(doc["tools"]);
  if (tools && Array.isArray(tools["alsoAllow"])) {
    tools["alsoAllow"] = (tools["alsoAllow"] as unknown[]).filter((t) => !ATTACH_TOOLS.includes(t as string));
    if ((tools["alsoAllow"] as unknown[]).length === 0) delete tools["alsoAllow"];
    if (Object.keys(tools).length === 0) delete doc["tools"];
  }
  const unrestored: string[] = [];
  const recorded = new Set((providers ?? []).map((p) => p.id));
  for (const p of providers ?? []) restoreProvider(doc, p);
  for (const [id, e] of Object.entries(obj(at(doc, "models", "providers")) ?? {})) {
    const entry = obj(e);
    const h = obj(entry?.["headers"]);
    if (!entry || !h || recorded.has(id) || id === "anthropic" || h[SESSION_HEADER] === undefined) continue;
    for (const k of Object.keys(h)) if (k.toLowerCase().startsWith("x-mandu-")) delete h[k];
    if (Object.keys(h).length === 0) delete entry["headers"];
    if (isLoopbackUrl(entry["baseUrl"])) unrestored.push(id);
  }
  const anthropic = recorded.has("anthropic") ? undefined : obj(at(doc, "models", "providers", "anthropic"));
  const headers = obj(anthropic?.["headers"]);
  if (anthropic && headers && headers[SESSION_HEADER] !== undefined) {
    for (const k of Object.keys(headers)) if (k.toLowerCase().startsWith("x-mandu-")) delete headers[k];
    if (Object.keys(headers).length === 0) delete anthropic["headers"];
    if (isLoopbackUrl(anthropic["baseUrl"])) delete anthropic["baseUrl"];
    // What is left of a provider install made from nothing (OpenClaw's own
    // onboarding writes no `models` key): `{api, models: []}` goes, and the
    // objects that held only it, so the file is the user's again.
    const left = Object.keys(anthropic);
    if (left.every((k) => k === "api" || k === "models") && anthropic["api"] === "anthropic-messages" &&
        Array.isArray(anthropic["models"]) && (anthropic["models"] as unknown[]).length === 0) {
      dropProvider(doc, "anthropic");
    }
  }
  return { doc, changed: JSON.stringify(doc) !== JSON.stringify(raw), unrestored };
}
