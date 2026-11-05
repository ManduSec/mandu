/**
 * attachment-contract — what `mandu serve`'s proxy pool and its readers
 * agree on (docs/design/agents/openclaw-plugin.md §3.2, §8): the session of
 * an OpenClaw agent, the service URL contract (the port file and the
 * identity it must answer with), and the declared-attachments file that
 * names the sessions the pool runs a proxy for. Mandu-new (no reference
 * origin). Pure: nothing here reads the environment or the filesystem.
 *
 * One module, byte-identical in two packages (each stays standalone): the
 * launcher (`mandu serve attach|status`, `mandu openclaw install`, the doctor,
 * `mandu reap`) and the dashboard (the pool runs in the service's main
 * process, dashboard/src/supervisor/attachment-pool.ts). The source is
 * launcher/src/attachment-contract.ts: change it, then run
 * `node scripts/copies/module-copies.mjs generate`.
 *
 * THE SERVICE URL CONTRACT (the pool writes, the installer and the doctor read):
 *   `<runtime>/attachments/<session>/anthropic-proxy.port`
 * holds the decimal port of the session's model proxy and a newline, in a
 * regular file this user owns that no one else can write, in a directory the
 * service creates 0700. It is written atomically once the proxy listens on
 * 127.0.0.1, answers as this session's and the session is registered with
 * the arbiter, and removed when it stops. The proxy answers `GET
 * /_mandu/identity` with `{mandu: true, service: "anthropic-proxy",
 * sessionKey: <session>, arbiterSock}`.
 *
 * THE DECLARED ATTACHMENTS (`serve-attachments` in the path table,
 * `<mandu home>/state/serve-attachments.json`): `{version: 2, attachments:
 * [{kind: "openclaw-plugin", agent, session, port, config?, providers?,
 * unprotected?, allowlist?}]}` (version 1, without the last three, is read
 * too). `providers`
 * (Route 1, openclaw-plugin.md §8.1) are the OpenClaw providers `mandu openclaw
 * install` routed through the session's proxy: each one's wire, the address
 * the proxy forwards it to (null: the provider's built-in address) and what
 * its entry held before the install (for uninstall); base URLs only, never a
 * credential (a URL with a user, a password, a query or a fragment makes the
 * whole entry unusable, so the session is not served). `unprotected` names
 * the providers the user chose to leave as they are. `allowlist` names the
 * keys of OpenClaw's model allowlist (`agents.defaults.models`) the install
 * added, the model fence (openclaw-plugin.md §8.1), which uninstall removes;
 * model references only, never a value. An empty `allowlist` records that the
 * install found the user's own allowlist and left it as the fence; absent, no
 * install recorded a fence (one before it). `sandbox` (openclaw-plugin.md
 * §10) records the confined-commands tier: what `mandu openclaw install
 * --sandbox` replaced in the config (`original`), which uninstall puts back.
 * `mandu serve attach
 * openclaw` and `mandu openclaw install` add an entry, `detach` and
 * `uninstall` remove it; the pool reads it every few seconds. The session is
 * derived from the agent (a stored session that disagrees is ignored); the
 * port is the stable one the pool asks for (null: any free port); `config`,
 * when present, is the OpenClaw config `mandu openclaw install` wrote the
 * route into (absolute), which the pool's route check reads.
 *
 * THE ROUTE CHECK (openclaw-plugin.md §3.6, §8): what an OpenClaw config
 * says about an attachment (`attachState`: the plugin, the Anthropic route,
 * every other routed provider's route and a provider added since (Route 1,
 * given the declared routes), the model entries around them, and the model
 * fence: what OpenClaw's model allowlist lets a model switch reach, against
 * the declaration's `allowlist`) and whether it still routes through the
 * session's service proxy (`routeVerdict`). The doctor check and the pool's
 * timer check decide by these same two functions; the config is read by
 * services/openclaw-config-read.ts, shared the same way, and the models it
 * names by openclaw-model-refs.ts (copied beside this module).
 */

import { isOpenrouterId, openclawModelRefs, openclawOpenrouterReach, openclawRouteIgnoredWhy } from "./openclaw-model-refs.js";

// ── The session (mirrors interceptors/openclaw-inspect-plugin/src/
//    attachment-session.ts; tests/stack/openclaw-attach-session-parity holds
//    the two equal) ─────────────────────────────────────────────────────────

const VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i;

/** OpenClaw's agent id, canonical (its packages/normalization-core agent-id.ts). */
export function normalizeAgentId(value: string | null | undefined): string {
  const trimmed = (value ?? "").trim();
  const lower = trimmed.toLowerCase();
  if (VALID_ID_RE.test(trimmed)) return lower;
  const id = lower.replace(/[^a-z0-9_-]+/g, "-").replace(/^-+/, "").replace(/-+$/, "").slice(0, 64);
  return id === "" ? "main" : id;
}

/** The attachment session of an OpenClaw agent: `openclaw:<agentId>`. */
export function attachmentSession(agentId: string | null | undefined): string {
  return `openclaw:${normalizeAgentId(agentId)}`;
}

// ── The service URL contract ─────────────────────────────────────────────────

export const ATTACHMENTS_DIR = "attachments";
export const ANTHROPIC_PROXY_PORT_FILE = "anthropic-proxy.port";
/** The pool's own record, in a session's directory (who serves it:
 *  `{pid, proxyPid, session, startedAt}`) and in the attachments directory
 *  itself (a pool runs: `{pid, startedAt}`), which `mandu reap` and `mandu
 *  openclaw install` read: the pid is the service's main process. */
export const POOL_RECORD_FILE = "pool.json";
/** The modes the pool creates the directories and the port file with. */
export const ATTACHMENT_DIR_MODE = 0o700;
export const PORT_FILE_MODE = 0o600;

/** `<runtime>/attachments` (every session's directory is in it). */
export function attachmentsRoot(runtimeBase: string): string {
  return `${runtimeBase.replace(/\/+$/, "")}/${ATTACHMENTS_DIR}`;
}

/** `<runtime>/attachments/<session>` (a session id has no `/`). */
export function attachmentDir(runtimeBase: string, session: string): string {
  return `${attachmentsRoot(runtimeBase)}/${session}`;
}

/** The running pool's record: `<runtime>/attachments/pool.json`. */
export function poolMarkerFile(runtimeBase: string): string {
  return `${attachmentsRoot(runtimeBase)}/${POOL_RECORD_FILE}`;
}

/** The pid a pool record names, or null when it names none. Pure. */
export function poolRecordPid(text: string): number | null {
  try {
    const o = JSON.parse(text) as { pid?: unknown };
    return typeof o.pid === "number" && Number.isInteger(o.pid) && o.pid > 1 ? o.pid : null;
  } catch {
    return null;
  }
}

/** The port file of a session's model proxy. */
export function anthropicProxyPortFile(runtimeBase: string, session: string): string {
  return `${attachmentDir(runtimeBase, session)}/${ANTHROPIC_PROXY_PORT_FILE}`;
}

/** The port file's text for `port`. */
export function portFileText(port: number): string {
  return `${port}\n`;
}

/** The port in a port file's text, or null: digits only (one trailing
 *  newline allowed), 1..65535. */
export function parsePortFile(text: string): number | null {
  const m = /^([0-9]{1,5})\n?$/.exec(text);
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 1 && n <= 65535 ? n : null;
}

/** The URL the provider route names for a service proxy port. */
export function serviceProxyUrl(port: number): string {
  return `http://127.0.0.1:${port}`;
}

/** Why a port file may not be trusted, or null: a regular file this user
 *  owns that neither the group nor others can write. */
export function portFileProblem(st: { isFile: boolean; uid: number; mode: number }, uid: number | undefined): string | null {
  if (!st.isFile) return "is not a regular file";
  if (uid !== undefined && st.uid !== uid) return `is not yours (owner uid ${st.uid})`;
  if ((st.mode & 0o022) !== 0) return `can be written by others (mode ${(st.mode & 0o777).toString(8)})`;
  return null;
}

/** What a proxy's `/_mandu/identity` said (launcher/src/services/primitives.ts ProxyIdentity, subset). */
export interface ServiceIdentity {
  mandu?: boolean;
  service?: string;
  sessionKey?: string;
  arbiterSock?: string;
}

/** Why a listening proxy is not this session's service proxy, or null. */
export function identityProblem(id: ServiceIdentity | null, session: string): string | null {
  if (id === null) return "nothing answered as a Mandu proxy";
  if (id.mandu !== true) return "a non-Mandu server answers on that port";
  if (id.service !== "anthropic-proxy") return `the server on that port is Mandu's ${id.service ?? "unknown service"}, not its model proxy`;
  if (id.sessionKey !== session) return `the proxy on that port is session ${id.sessionKey ?? "(none)"}, not ${session}`;
  if (typeof id.arbiterSock !== "string" || !id.arbiterSock.startsWith("/")) return "the proxy names no arbiter socket";
  return null;
}

// ── The declared attachments ────────────────────────────────────────────────

export const DECLARED_VERSION = 2;
/** The versions `parseDeclared` reads (1: before Route 1, no providers). */
export const DECLARED_VERSIONS_READ: readonly number[] = [1, 2];
/** The kinds the pool knows (confinement-posture.ts AttachmentGap). */
export const DECLARED_KINDS = ["openclaw-plugin"] as const;
export type DeclaredKind = (typeof DECLARED_KINDS)[number];

// ── The routed providers (Route 1, openclaw-plugin.md §8.1) ─────────────────

/** The provider wires the session's proxy reads: the Anthropic Messages API
 *  (its `/v1/messages`), the two OpenAI wires (its per-provider routes under
 *  `/_mandu/openai/<id>`, anthropic-proxy route.ts), Google's Gemini API
 *  (its per-provider routes under `/_mandu/google/<id>`, model-wires.md §4;
 *  since 2026-10-25), Ollama's native chat API (`/_mandu/ollama/<id>`,
 *  model-wires.md "The Ollama wire"; since 2026-10-26), and OpenClaw's Azure
 *  OpenAI and ChatGPT sign-in apis, the Responses wire under
 *  `/_mandu/openai/<id>` with their own paths and key header (model-wires.md
 *  "OpenClaw's Azure OpenAI and ChatGPT sign-in apis"; since 2026-10-26). A
 *  wire Mandu cannot read (Bedrock's, Vertex AI's) is not one of them: the
 *  seam a new reader extends. */
export const PROVIDER_WIRES = ["anthropic-messages", "openai-completions", "openai-responses", "google-generative-ai", "ollama", "azure-openai-responses", "openai-chatgpt-responses"] as const;
export type ProviderWire = (typeof PROVIDER_WIRES)[number];

/** The prefix of the proxy's per-provider OpenAI routes (anthropic-proxy
 *  route.ts OPENAI_ROUTE_PREFIX). */
export const OPENAI_ROUTE_PREFIX = "/_mandu/openai/";

/** The prefix of the proxy's per-provider Gemini routes (anthropic-proxy
 *  route.ts GOOGLE_ROUTE_PREFIX). */
export const GOOGLE_ROUTE_PREFIX = "/_mandu/google/";

/** The built-in `google` provider's own address (agent-model-route.ts
 *  GEMINI_API_BASE), where a null upstream of it goes unless the service's
 *  environment says otherwise (MANDU_GOOGLE_UPSTREAMS). */
export const GEMINI_BUILTIN_BASE = "https://generativelanguage.googleapis.com/v1beta";

/** Whether a wire is Gemini's (served under GOOGLE_ROUTE_PREFIX, its upstream
 *  in MANDU_GOOGLE_UPSTREAMS). Pure. */
export function isGoogleWire(w: ProviderWire): boolean {
  return w === "google-generative-ai";
}

/** The prefix of the proxy's per-provider Ollama routes (anthropic-proxy
 *  route.ts OLLAMA_ROUTE_PREFIX). */
export const OLLAMA_ROUTE_PREFIX = "/_mandu/ollama/";

/** OpenClaw's built-in Ollama providers' own addresses (agent-model-route.ts
 *  OLLAMA_BUILTIN_BASES), where a null upstream of one goes unless the
 *  service's environment says otherwise (MANDU_OLLAMA_UPSTREAMS). */
export const OLLAMA_BUILTIN_BASES: Readonly<Record<string, string>> = {
  ollama: "http://127.0.0.1:11434",
  "ollama-cloud": "https://ollama.com",
};

/** Whether a wire is Ollama's native chat API (served under
 *  OLLAMA_ROUTE_PREFIX, its upstream in MANDU_OLLAMA_UPSTREAMS). Pure. */
export function isOllamaWire(w: ProviderWire): boolean {
  return w === "ollama";
}

/** The built-in `openai` provider's own address (agent-model-route.ts
 *  OPENAI_API_BASE), where a null upstream of it goes unless the service's
 *  environment says otherwise. */
export const OPENAI_BUILTIN_BASE = "https://api.openai.com/v1";

/** A provider id the proxy's routes and MANDU_OPENAI_UPSTREAMS /
 *  MANDU_GOOGLE_UPSTREAMS accept. */
export const PROVIDER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** What a provider's entry in the main config file held before the install
 *  wrote its route (uninstall puts exactly this back): whether the entry
 *  existed, its own `baseUrl` and `api` (absent: not in the main file),
 *  whether it had a `headers` object, and whether it had a `models` list
 *  (install adds an empty one: 2026.3.12 rejects a provider without it;
 *  absent: kept). */
export interface ProviderOriginal {
  existed: boolean;
  baseUrl?: string;
  api?: string;
  headers: boolean;
  models?: boolean;
}

/** One provider routed through the session's proxy. */
export interface DeclaredProvider {
  /** The OpenClaw provider id (`models.providers.<id>`, or a built-in). */
  id: string;
  wire: ProviderWire;
  /** Where the proxy sends this provider's calls: its own base URL, or null
   *  for the provider's built-in address (Anthropic's, OpenAI's), which the
   *  service's own environment may set (MANDU_UPSTREAM, MANDU_OPENAI_UPSTREAMS,
   *  MANDU_GOOGLE_UPSTREAMS). */
  upstream: string | null;
  original: ProviderOriginal;
}

/** Why a URL may not be recorded (credentials, a query or a fragment, not
 *  http(s)), or null. Pure. */
export function recordableUrlProblem(v: string): string | null {
  let u: URL;
  try { u = new URL(v.trim()); } catch { return "is not a URL"; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "is not http(s)";
  if (u.username !== "" || u.password !== "") return "carries a user or password";
  if (u.search !== "" || u.hash !== "") return "carries a query or fragment";
  return null;
}

/** The URL a provider's `baseUrl` names to reach the session's proxy: the
 *  proxy itself for the Anthropic wire, its per-provider route for an
 *  OpenAI, a Gemini or an Ollama wire. Pure. */
export function providerRouteUrl(serviceUrl: string, p: Pick<DeclaredProvider, "id" | "wire">): string {
  const base = serviceUrl.replace(/\/+$/, "");
  if (p.wire === "anthropic-messages") return base;
  const prefix = isGoogleWire(p.wire) ? GOOGLE_ROUTE_PREFIX : isOllamaWire(p.wire) ? OLLAMA_ROUTE_PREFIX : OPENAI_ROUTE_PREFIX;
  return `${base}${prefix}${encodeURIComponent(p.id)}`;
}

/** What decides how the proxy forwards (id, wire, upstream), stable: the
 *  pool restarts a session's proxy when it changes, and records it beside
 *  the proxy it started, so `mandu openclaw install` waits for a proxy that
 *  forwards each provider where the declaration says. Pure. */
export function providersKey(list: readonly DeclaredProvider[] | undefined): string {
  if (list === undefined) return "";
  return JSON.stringify([...list].map((p) => [p.id, p.wire, p.upstream]).sort((a, b) => String(a[0]).localeCompare(String(b[0]))));
}

/** The providers key a session's pool record names ("" when none). Pure. */
export function poolRecordProvidersKey(text: string): string | null {
  try {
    const v = (JSON.parse(text) as { providers?: unknown }).providers;
    return typeof v === "string" ? v : null;
  } catch {
    return null;
  }
}

function parseProvider(v: unknown): DeclaredProvider | string {
  const x = v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  if (x === null) return "a provider is not an object";
  const id = x["id"];
  if (typeof id !== "string" || !PROVIDER_ID_RE.test(id)) return `provider id ${JSON.stringify(id)} is not a plain name`;
  if (!(PROVIDER_WIRES as readonly unknown[]).includes(x["wire"])) return `provider ${id}: unknown wire ${JSON.stringify(x["wire"])}`;
  const up = x["upstream"];
  if (up !== null && typeof up !== "string") return `provider ${id}: upstream is not a URL or null`;
  if (typeof up === "string") {
    const why = recordableUrlProblem(up);
    if (why !== null) return `provider ${id}: its upstream ${why}`;
  }
  const o = x["original"] !== null && typeof x["original"] === "object" && !Array.isArray(x["original"]) ? (x["original"] as Record<string, unknown>) : null;
  if (o === null || typeof o["existed"] !== "boolean" || typeof o["headers"] !== "boolean") return `provider ${id}: no original entry record`;
  if (o["baseUrl"] !== undefined) {
    if (typeof o["baseUrl"] !== "string") return `provider ${id}: its original baseUrl is not a string`;
    const why = recordableUrlProblem(o["baseUrl"]);
    if (why !== null) return `provider ${id}: its original baseUrl ${why}`;
  }
  if (o["api"] !== undefined && typeof o["api"] !== "string") return `provider ${id}: its original api is not a string`;
  if (o["models"] !== undefined && typeof o["models"] !== "boolean") return `provider ${id}: its original models flag is not a boolean`;
  return {
    id,
    wire: x["wire"] as ProviderWire,
    upstream: up as string | null,
    original: {
      existed: o["existed"],
      ...(typeof o["baseUrl"] === "string" ? { baseUrl: o["baseUrl"] } : {}),
      ...(typeof o["api"] === "string" ? { api: o["api"] } : {}),
      headers: o["headers"],
      ...(typeof o["models"] === "boolean" ? { models: o["models"] } : {}),
    },
  };
}

/** The providers and the unprotected ids of a declared entry, or why the
 *  entry is unusable (a provider that is not one exactly, or one named
 *  twice: the session is not served rather than half-routed). Pure. */
function parseRoutes(x: Record<string, unknown>): { providers?: DeclaredProvider[]; unprotected?: string[]; allowlist?: string[] } | string {
  const out: { providers?: DeclaredProvider[]; unprotected?: string[]; allowlist?: string[] } = {};
  if (x["providers"] !== undefined) {
    if (!Array.isArray(x["providers"])) return "providers is not a list";
    const list: DeclaredProvider[] = [];
    for (const p of x["providers"] as unknown[]) {
      const r = parseProvider(p);
      if (typeof r === "string") return r;
      if (list.some((q) => q.id === r.id)) return `provider ${r.id} is named twice`;
      list.push(r);
    }
    out.providers = list;
  }
  if (x["unprotected"] !== undefined) {
    if (!Array.isArray(x["unprotected"]) || !(x["unprotected"] as unknown[]).every((s) => typeof s === "string" && PROVIDER_ID_RE.test(s))) {
      return "unprotected is not a list of provider ids";
    }
    out.unprotected = [...(x["unprotected"] as string[])];
  }
  if (x["allowlist"] !== undefined) {
    if (!Array.isArray(x["allowlist"]) || !(x["allowlist"] as unknown[]).every((s) => typeof s === "string" && ALLOWLIST_KEY_RE.test(s))) {
      return "allowlist is not a list of model references";
    }
    out.allowlist = [...(x["allowlist"] as string[])];
  }
  return out;
}

/** One session the pool runs a proxy for. */
export interface DeclaredAttachment {
  kind: DeclaredKind;
  /** The OpenClaw agent id, normalized. */
  agent: string;
  /** `openclaw:<agent>`, derived from `agent`. */
  session: string;
  /** The stable port the pool asks for (null: any free one). */
  port: number | null;
  /** The OpenClaw config `mandu openclaw install` wrote this session's route
   *  into (absolute); absent until an install did. Its presence ARMS the
   *  pool's route check: a route lost from it is said loudly at once. */
  config?: string;
  /** The providers routed through this session's proxy (Route 1); absent
   *  before an install recorded them (`mandu serve attach`, a version 1
   *  file): the proxy then forwards as the service's environment says, and
   *  the route check judges the Anthropic route alone. */
  providers?: DeclaredProvider[];
  /** The providers the user chose to leave as they are (`mandu openclaw
   *  install --leave-unprotected`): their calls do not cross Mandu. */
  unprotected?: string[];
  /** The keys of OpenClaw's model allowlist (`agents.defaults.models`) the
   *  install added (the model fence, openclaw-plugin.md §8.1); uninstall
   *  removes them. Empty: the user's own allowlist was the fence. Absent: no
   *  install recorded a fence. The route check judges the fence against it. */
  allowlist?: string[];
  /** The confined-commands tier (`mandu openclaw install --sandbox`,
   *  openclaw-plugin.md §10): what the install replaced, for uninstall. Its
   *  presence arms the route check's tier problems. */
  sandbox?: DeclaredSandbox;
}

/** A model allowlist key the declared file may record: `<provider>/<model>`
 *  (`*` allowed), a model reference, never a value. */
export const ALLOWLIST_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9._:*@+\/-]{1,200}$/;

/** The lowest port the declared file may name (an unprivileged one). */
export const MIN_DECLARED_PORT = 1024;

function validPort(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= MIN_DECLARED_PORT && v <= 65535;
}

/** The declared file's entries and what was wrong with it (a missing file
 *  is none, no problem). An entry that is not one exactly is skipped and
 *  named; two entries for one session keep the first. Pure. */
export function parseDeclared(text: string | null): { attachments: DeclaredAttachment[]; problems: string[] } {
  if (text === null || text.trim() === "") return { attachments: [], problems: [] };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { attachments: [], problems: [`not JSON (${(e as Error).message})`] };
  }
  const o = doc !== null && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : null;
  if (o === null) return { attachments: [], problems: ["not a JSON object"] };
  if (!DECLARED_VERSIONS_READ.includes(o["version"] as number)) return { attachments: [], problems: [`version ${JSON.stringify(o["version"])} is not ${DECLARED_VERSIONS_READ.join(" or ")}`] };
  const list = Array.isArray(o["attachments"]) ? (o["attachments"] as unknown[]) : null;
  if (list === null) return { attachments: [], problems: ["no attachments list"] };
  const out: DeclaredAttachment[] = [];
  const problems: string[] = [];
  const seen = new Set<string>();
  list.forEach((e, i) => {
    const x = e !== null && typeof e === "object" && !Array.isArray(e) ? (e as Record<string, unknown>) : null;
    if (x === null) { problems.push(`entry ${i} is not an object`); return; }
    if (!(DECLARED_KINDS as readonly unknown[]).includes(x["kind"])) { problems.push(`entry ${i}: unknown kind ${JSON.stringify(x["kind"])}`); return; }
    if (typeof x["agent"] !== "string" || x["agent"].trim() === "") { problems.push(`entry ${i}: no agent`); return; }
    const agent = normalizeAgentId(x["agent"]);
    const session = attachmentSession(agent);
    if (x["port"] !== undefined && x["port"] !== null && !validPort(x["port"])) {
      problems.push(`entry ${i} (${session}): port ${JSON.stringify(x["port"])} is not ${MIN_DECLARED_PORT}..65535; any free port is used`);
    }
    if (seen.has(session)) { problems.push(`entry ${i}: ${session} is declared twice; the first counts`); return; }
    seen.add(session);
    const config = typeof x["config"] === "string" && x["config"].startsWith("/") && !x["config"].includes("\0") ? x["config"] : undefined;
    if (x["config"] !== undefined && config === undefined) problems.push(`entry ${i} (${session}): config ${JSON.stringify(x["config"])} is not an absolute path; the service's own is checked`);
    const routes = parseRoutes(x);
    if (typeof routes === "string") { problems.push(`entry ${i} (${session}): ${routes}; not served until mandu openclaw install records it again`); return; }
    let sandbox: DeclaredSandbox | undefined;
    if (x["sandbox"] !== undefined) {
      const s = parseDeclaredSandbox(x["sandbox"]);
      if (typeof s === "string") problems.push(`entry ${i} (${session}): ${s}; uninstall removes Mandu's sandbox values only`);
      else sandbox = s;
    }
    out.push({ kind: x["kind"] as DeclaredKind, agent, session, port: validPort(x["port"]) ? x["port"] : null, ...(config !== undefined ? { config } : {}), ...routes, ...(sandbox !== undefined ? { sandbox } : {}) });
  });
  return { attachments: out, problems };
}

/** The declared file's text for `list`. Pure. */
export function renderDeclared(list: readonly DeclaredAttachment[]): string {
  return JSON.stringify({
    version: DECLARED_VERSION,
    attachments: list.map((a) => ({
      kind: a.kind, agent: a.agent, session: a.session, port: a.port,
      ...(a.config !== undefined ? { config: a.config } : {}),
      ...(a.providers !== undefined ? { providers: a.providers } : {}),
      ...(a.unprotected !== undefined ? { unprotected: a.unprotected } : {}),
      ...(a.allowlist !== undefined ? { allowlist: a.allowlist } : {}),
      ...(a.sandbox !== undefined ? { sandbox: a.sandbox } : {}),
    })),
  }, null, 2) + "\n";
}

/** The routes an install records (Route 1): the providers routed and the
 *  ones left unprotected. */
export interface DeclaredRoutes {
  providers: DeclaredProvider[];
  unprotected: string[];
  /** The model allowlist keys the install added (empty: the user's own
   *  allowlist is the fence; absent: none recorded). */
  allowlist?: string[];
}

/** `list` with the agent's session declared: an entry already there keeps
 *  its port unless `port` names another, its config unless `config` names
 *  one, and its routes unless `routes` gives them; a new one takes all
 *  three. Pure. */
export function declareAttachment(
  list: readonly DeclaredAttachment[],
  agentId: string,
  port: number | null,
  config?: string,
  routes?: DeclaredRoutes,
): { list: DeclaredAttachment[]; entry: DeclaredAttachment; changed: boolean } {
  const agent = normalizeAgentId(agentId);
  const session = attachmentSession(agent);
  const i = list.findIndex((a) => a.session === session);
  const withRoutes = (e: DeclaredAttachment): DeclaredAttachment => {
    if (routes === undefined) return e;
    const same = e.providers !== undefined && JSON.stringify(e.providers) === JSON.stringify(routes.providers) &&
      JSON.stringify(e.unprotected ?? []) === JSON.stringify(routes.unprotected) &&
      JSON.stringify(e.allowlist ?? null) === JSON.stringify(routes.allowlist ?? null);
    if (same) return e;
    const { unprotected: _dropped, allowlist: _gone, ...rest } = e;
    return {
      ...rest, providers: routes.providers,
      ...(routes.unprotected.length > 0 ? { unprotected: routes.unprotected } : {}),
      // Kept when empty: the user's own allowlist is the fence, and the
      // route check judges its removal too.
      ...(routes.allowlist !== undefined ? { allowlist: routes.allowlist } : {}),
    };
  };
  if (i >= 0) {
    const cur = list[i]!;
    let entry: DeclaredAttachment = port === null || port === cur.port ? cur : { ...cur, port };
    if (config !== undefined && config !== entry.config) entry = { ...entry, config };
    entry = withRoutes(entry);
    const next = [...list];
    next[i] = entry;
    return { list: next, entry, changed: entry !== cur };
  }
  const entry: DeclaredAttachment = withRoutes({ kind: "openclaw-plugin", agent, session, port, ...(config !== undefined ? { config } : {}) });
  return { list: [...list, entry], entry, changed: true };
}

/** `list` with the session's entry put back as `entry` was (null: the
 *  session undeclared): an install that refuses after it declared new routes
 *  restores the old ones. Pure. */
export function restoreDeclared(list: readonly DeclaredAttachment[], session: string, entry: DeclaredAttachment | null): DeclaredAttachment[] {
  if (entry === null) return list.filter((a) => a.session !== session);
  const i = list.findIndex((a) => a.session === session);
  if (i < 0) return [...list, entry];
  const next = [...list];
  next[i] = entry;
  return next;
}

/** `list` without `session`. Pure. */
export function undeclareAttachment(list: readonly DeclaredAttachment[], session: string): { list: DeclaredAttachment[]; removed: DeclaredAttachment | null } {
  const removed = list.find((a) => a.session === session) ?? null;
  return { list: list.filter((a) => a.session !== session), removed };
}

// ── What an OpenClaw config says about an attachment (moved here from
//    openclaw-attach.ts, which re-exports it, so the pool decides by it too) ─

type Json = Record<string, unknown>;

/** The plugin's id (openclaw.plugin.json; the per-run config uses it too). */
export const ATTACH_PLUGIN_ID = "mandu-inspect";
/** The plugin directory's name (a load path ending in it is Mandu's). */
export const PLUGIN_DIR_NAME = "openclaw-inspect-plugin";
export const SESSION_HEADER = "x-mandu-session-id";
export const TENANT_HEADER = "x-mandu-tenant";

function obj(v: unknown): Json | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined;
}

/** `doc` at `keys`, or undefined. */
export function configAt(doc: Json, ...keys: string[]): unknown {
  let cur: unknown = doc;
  for (const k of keys) {
    const o = obj(cur);
    if (o === undefined) return undefined;
    cur = o[k];
  }
  return cur;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function sameUrl(a: unknown, b: string): boolean {
  return typeof a === "string" && a.trim().replace(/\/+$/, "") === b.replace(/\/+$/, "");
}

/** A loopback http URL (what a Mandu proxy route looks like). */
export function isLoopbackUrl(v: unknown): boolean {
  if (typeof v !== "string") return false;
  try {
    const u = new URL(v.trim());
    const h = u.hostname.replace(/^\[|\]$/g, "");
    return u.protocol === "http:" && (h === "localhost" || h === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h));
  } catch {
    return false;
  }
}

/** The fields of a model entry that describe a model (agent-config.ts
 *  OPENCLAW_MODEL_METADATA_KEYS; anything else, e.g. its own baseUrl, api or
 *  headers, routes and is dropped). */
export const MODEL_METADATA_KEYS: ReadonlySet<string> = new Set([
  "id", "name", "reasoning", "input", "cost", "contextWindow", "contextTokens", "maxTokens",
  "params", "compat", "mediaInput", "thinkingLevelMap",
]);

/** The routing fields of the model entries of providers `ids` in `doc`
 *  (default: anthropic's): `<model id>.<key>`, prefixed `<provider>/` for a
 *  provider other than anthropic. */
export function modelsAround(doc: Json, ids: readonly string[] = ["anthropic"]): string[] {
  const out: string[] = [];
  for (const pid of ids) {
    const list = configAt(doc, "models", "providers", pid, "models");
    for (const e of Array.isArray(list) ? list as unknown[] : []) {
      const m = obj(e);
      if (!m) continue;
      const name = `${pid === "anthropic" ? "" : `${pid}/`}${typeof m["id"] === "string" ? m["id"] : "?"}`;
      for (const k of Object.keys(m)) if (!MODEL_METADATA_KEYS.has(k)) out.push(`${name}.${k}`);
    }
  }
  return out;
}

/** The providers a config names in `models.providers`, plus the two
 *  built-ins every OpenClaw has (`anthropic`, `openai`). Pure. */
export function configProviderIds(doc: Json): string[] {
  const providers = obj(configAt(doc, "models", "providers")) ?? {};
  return [...new Set(["anthropic", "openai", ...Object.keys(providers)])];
}

/** Where one routed provider's calls go, as a config says. */
export interface ProviderRouteState {
  id: string;
  wire: ProviderWire;
  /** Its `baseUrl` names its route at the service proxy, another endpoint,
   *  or none (its built-in address, directly). */
  route: "service" | "other" | "none";
  routeUrl?: string;
  /** OpenClaw sends this provider's calls where it decides at run time,
   *  whatever its route (GitHub Copilot, openclaw-model-refs.ts): why. */
  ignored?: string;
}

/** A load path that names the plugin directory (`pluginDir`, or any path
 *  ending in its folder name). */
export function isOurLoadPath(p: unknown, pluginDir: string | undefined): boolean {
  if (typeof p !== "string") return false;
  const t = p.replace(/\/+$/, "");
  return (pluginDir !== undefined && t === pluginDir.replace(/\/+$/, "")) || t.endsWith(`/${PLUGIN_DIR_NAME}`);
}

export interface AttachState {
  /** The plugin entry: enabled (and not switched off by plugins.enabled /
   *  deny / an allowlist without it), disabled, or absent. */
  plugin: "enabled" | "disabled" | "absent";
  /** The entry's config says `attachment: true`. */
  attachment: boolean;
  /** A load path names the plugin directory. */
  loadPath: boolean;
  /** Where Anthropic calls go: the given service URL, elsewhere, or nowhere
   *  set (Anthropic directly). */
  route: "service" | "other" | "none";
  routeUrl?: string;
  /** The session the route's header names, if any. */
  routeSession?: string;
  /** Model entries with their own routing fields (`<id>.<key>`). */
  modelsAround: string[];
  /** The user granted the plugin conversation access (not needed; noted). */
  conversationAccess: boolean;
  /** Route 1 (given the declared routes): whether the Anthropic route is
   *  checked (false when the user left `anthropic` unprotected), each other
   *  routed provider's route, and the providers the config names that are
   *  neither routed nor left unprotected (added since the install). */
  checkAnthropic?: boolean;
  providerRoutes?: ProviderRouteState[];
  unrouted?: string[];
  /** The model fence (given the declared routes): what OpenClaw's model
   *  allowlist and the models the config names let a model switch reach
   *  around Mandu (`modelFenceHoles`). */
  fenceHoles?: FenceHole[];
  /** Where OpenClaw's Azure endpoint variables are set for this config's
   *  Gateway (GatewayEnvFacts; the config's own `env` block included), as
   *  the caller could read them; absent: not read. Judged only while an
   *  Azure OpenAI provider is routed. */
  gatewayEnv?: GatewayEnvFacts;
}

/**
 * What the Gateway's environment says about OpenClaw's Azure endpoint
 * variables (AZURE_OPENAI_BASE_URL, AZURE_OPENAI_RESOURCE_NAME), which its
 * Azure OpenAI client reads BEFORE the provider's `baseUrl`
 * (model-wires.md §9.1; services/openclaw-gateway-env.ts reads them): `set`
 * names each one and where (`<NAME> (<where>)`, never a value); `verified`
 * false when a running Gateway's environment could not be read (`why`).
 */
export interface GatewayEnvFacts {
  verified: boolean;
  why?: string;
  set: string[];
}

/** The Azure endpoint variables a config's own `env` block sets
 *  (`env.vars.<name>` or `env.<name>`; OpenClaw applies it where the
 *  environment leaves the variable unset), as `<NAME> (<where>)`. Pure. */
export function configAzureEndpointEnv(doc: Json): string[] {
  const env = obj(doc["env"]) ?? {};
  const vars = obj(env["vars"]) ?? {};
  const out: string[] = [];
  for (const name of ["AZURE_OPENAI_BASE_URL", "AZURE_OPENAI_RESOURCE_NAME"]) {
    for (const [where, map] of [["env.vars", vars], ["env", env]] as const) {
      const hit = Object.entries(map).find(([k, v]) => k.toUpperCase() === name && typeof v === "string" && v.trim() !== "");
      if (hit) { out.push(`${name} (${where}.${hit[0]} in the OpenClaw config)`); break; }
    }
  }
  return out;
}

/** The routes a declared session records (DeclaredAttachment), as the
 *  route check reads them. */
export interface RoutesToCheck {
  providers?: readonly DeclaredProvider[];
  unprotected?: readonly string[];
  /** The model fence the install recorded (the declaration's `allowlist`):
   *  the keys it added; empty, the user's own allowlist was the fence;
   *  absent, no install recorded one (its removal is then not judged). */
  allowlist?: readonly string[];
}

/** A hole in the model fence (openclaw-plugin.md §3.6, §8.1): a way a model
 *  switch (`/model`, the `session_status` tool, a subagent's model, cron)
 *  or a configured model reaches a model whose calls do not cross Mandu.
 *   - `fence-gone`: the allowlist the install fenced with is gone (Mandu's
 *     keys, `names`; or the user's own, `names` empty): OpenClaw then takes
 *     any model, on every release.
 *   - `fence-unrouted`: allowlist keys (`names`) of a provider Mandu neither
 *     routes nor was told to leave: a switch to it goes around the proxy, on
 *     every release.
 *   - `openrouter-wildcard`: an openrouter wildcard key (`names`) while
 *     openrouter is routed: before 2026.3.22 it is the literal model `*`, a
 *     model OpenClaw does not know, which it sends to openrouter.ai.
 *   - `openrouter-unlisted`: openrouter models the allowlist or the config
 *     names (`names`, OpenClaw's ids) that `models.providers.openrouter.
 *     models` does not list, while openrouter is routed: before 2026.3.22
 *     OpenClaw sends each one straight to openrouter.ai, whatever the route. */
export interface FenceHole {
  kind: "fence-gone" | "fence-unrouted" | "openrouter-wildcard" | "openrouter-unlisted";
  names: string[];
}

/** Read an effective config's attachment state. `serviceUrl` is the session's
 *  service proxy (null when it is not running: any route then counts as
 *  `other` unless none is set). `routes`: the session's declared routes
 *  (Route 1); without providers in them (an install before Route 1, or none
 *  yet), the Anthropic route alone is judged. Pure. */
export function attachState(effective: Json, opts: { pluginDir?: string; serviceUrl: string | null; routes?: RoutesToCheck; gatewayEnv?: GatewayEnvFacts }): AttachState {
  const entry = obj(configAt(effective, "plugins", "entries", ATTACH_PLUGIN_ID));
  const allow = configAt(effective, "plugins", "allow");
  const off = configAt(effective, "plugins", "enabled") === false
    || strings(configAt(effective, "plugins", "deny")).includes(ATTACH_PLUGIN_ID)
    || (Array.isArray(allow) && !strings(allow).includes(ATTACH_PLUGIN_ID));
  const plugin = entry === undefined ? "absent" : entry["enabled"] === false || off ? "disabled" : "enabled";
  const base = configAt(effective, "models", "providers", "anthropic", "baseUrl");
  const headers = obj(configAt(effective, "models", "providers", "anthropic", "headers"));
  const route = base === undefined ? "none" : opts.serviceUrl !== null && sameUrl(base, opts.serviceUrl) ? "service" : "other";
  const routeSession = typeof headers?.[SESSION_HEADER] === "string" ? headers[SESSION_HEADER] as string : undefined;
  return {
    plugin,
    attachment: obj(entry?.["config"])?.["attachment"] === true,
    loadPath: strings(configAt(effective, "plugins", "load", "paths")).some((p) => isOurLoadPath(p, opts.pluginDir)),
    route,
    ...(typeof base === "string" ? { routeUrl: base } : {}),
    ...(routeSession !== undefined ? { routeSession } : {}),
    modelsAround: modelsAround(effective, routedIds(opts.routes)),
    conversationAccess: obj(entry?.["hooks"])?.["allowConversationAccess"] === true,
    ...providerRouteFacts(effective, opts.serviceUrl, opts.routes),
    ...gatewayEnvFact(effective, opts.gatewayEnv),
  };
}

/** The Gateway environment facts with the config's own `env` block added;
 *  a caller that read none gets them not verified (an Azure route then
 *  says so). */
function gatewayEnvFact(effective: Json, facts: GatewayEnvFacts | undefined): Pick<AttachState, "gatewayEnv"> {
  const own = configAzureEndpointEnv(effective);
  const read = facts ?? { verified: false, why: "the Gateway's environment was not read", set: [] };
  return { gatewayEnv: { ...read, set: [...own, ...read.set.filter((x) => !own.includes(x))] } };
}

/** The providers whose model entries must not carry their own endpoint:
 *  the declared ones (anthropic alone before Route 1). */
function routedIds(routes: RoutesToCheck | undefined): string[] {
  return routes?.providers !== undefined ? routes.providers.map((p) => p.id) : ["anthropic"];
}

function providerRouteFacts(effective: Json, serviceUrl: string | null, routes: RoutesToCheck | undefined): Pick<AttachState, "checkAnthropic" | "providerRoutes" | "unrouted" | "fenceHoles"> {
  const declared = routes?.providers;
  if (declared === undefined) return {};
  const left = new Set(routes?.unprotected ?? []);
  const providerRoutes: ProviderRouteState[] = declared.filter((p) => p.id !== "anthropic").map((p) => {
    const base = configAt(effective, "models", "providers", p.id, "baseUrl");
    const route = base === undefined ? "none" : serviceUrl !== null && sameUrl(base, providerRouteUrl(serviceUrl, p)) ? "service" : "other";
    // A provider an earlier install routed whose route OpenClaw never
    // honours (GitHub Copilot): its calls go around Mandu.
    const ignored = openclawRouteIgnoredWhy(p.id);
    return { id: p.id, wire: p.wire, route, ...(typeof base === "string" ? { routeUrl: base } : {}), ...(ignored !== null ? { ignored } : {}) };
  });
  // A provider the config names that is neither routed nor left: one in
  // models.providers (or a built-in), or one a configured model names (a
  // catalog provider: `agents.defaults.model.primary: "mistral/…"`).
  const same = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();
  const named = [...configProviderIds(effective)];
  for (const r of openclawModelRefs(effective)) if (r.provider !== null && !named.some((id) => same(id, r.provider!))) named.push(r.provider);
  const unrouted = named.filter((id) => !declared.some((p) => same(p.id, id)) && ![...left].some((l) => same(l, id)));
  return { checkAnthropic: declared.some((p) => p.id === "anthropic"), providerRoutes, unrouted, fenceHoles: modelFenceHoles(effective, { ...routes, providers: declared }) };
}

/** The keys of a config's model allowlist (`agents.defaults.models`). Pure. */
export function allowlistKeys(doc: Json): string[] {
  return Object.keys(obj(configAt(doc, "agents", "defaults", "models")) ?? {});
}

/**
 * The holes in a config's model fence, given the declared routes (FenceHole;
 * openclaw-plugin.md §3.6, "The model fence"). Mandu cannot tell which
 * OpenClaw the Gateway runs (it may change with no edit to the file), so the
 * openrouter shapes count on every release, as install refuses them. A key
 * Mandu recorded that is gone while others stay narrows the fence: no hole.
 * Without declared providers (an install before Route 1) nothing is judged.
 * Pure.
 */
export function modelFenceHoles(effective: Json, routes: RoutesToCheck): FenceHole[] {
  const declared = routes.providers;
  if (declared === undefined) return [];
  const lower = (v: string): string => v.trim().toLowerCase();
  const routed = new Set(declared.map((p) => lower(p.id)));
  const left = new Set((routes.unprotected ?? []).map(lower));
  const keys = allowlistKeys(effective);
  const holes: FenceHole[] = [];
  if (keys.length === 0 && routes.allowlist !== undefined) holes.push({ kind: "fence-gone", names: [...routes.allowlist] });
  const unrouted = keys.filter((k) => {
    const slash = k.indexOf("/");
    if (slash <= 0) return false;
    const p = lower(k.slice(0, slash));
    return !routed.has(p) && !left.has(p);
  });
  if (unrouted.length > 0) holes.push({ kind: "fence-unrouted", names: unrouted });
  if ([...routed].some((p) => isOpenrouterId(p))) {
    const reach = openclawOpenrouterReach(effective);
    if (reach.wildcards.length > 0) holes.push({ kind: "openrouter-wildcard", names: reach.wildcards });
    const missing: string[] = [];
    for (const x of reach.ids) if (!reach.listed.has(x.id) && !missing.includes(x.id)) missing.push(x.id);
    if (missing.length > 0) holes.push({ kind: "openrouter-unlisted", names: missing });
  }
  return holes;
}

/** True when a config shows any sign of an attachment (the doctor's row
 *  appears only then). Pure. */
export function looksAttached(s: AttachState): boolean {
  return s.plugin !== "absent" || (s.routeSession !== undefined && (s.routeSession.startsWith("openclaw:")));
}

/** The session a config is attached as: the route header, else the plugin
 *  config's agent. Pure. */
export function attachedSession(effective: Json): string | null {
  const h = obj(configAt(effective, "models", "providers", "anthropic", "headers"))?.[SESSION_HEADER];
  if (typeof h === "string" && h.startsWith("openclaw:")) return h;
  const cfg = obj(configAt(effective, "plugins", "entries", ATTACH_PLUGIN_ID, "config"));
  if (typeof cfg?.["scopeId"] === "string") return cfg["scopeId"] as string;
  if (typeof cfg?.["agentId"] === "string") return attachmentSession(cfg["agentId"] as string);
  return null;
}

// ── The route verdict (openclaw-plugin.md §3.6) ─────────────────────────────

/** What keeps a config from routing an attachment through Mandu. */
export type RouteProblemCode =
  /** The config cannot be read or parsed, or is gone. */
  | "unreadable"
  /** The plugin entry is not in it. */
  | "plugin-absent"
  /** The plugin is switched off (its entry, plugins.enabled, deny, allow). */
  | "plugin-disabled"
  /** The plugin is not in attachment mode, or no load path names it. */
  | "plugin-not-attached"
  /** No Anthropic route: calls go to Anthropic directly. */
  | "route-direct"
  /** The Anthropic route names another endpoint. */
  | "route-elsewhere"
  /** Model entries carry their own endpoint, around the route. */
  | "model-bypass"
  /** The model fence has a hole: a model switch, or a model the config
   *  names, reaches a model around the route (FenceHole). */
  | "model-fence"
  /** A route Mandu cannot verify: the Gateway's environment, which can
   *  send a routed provider's calls elsewhere (Azure OpenAI's endpoint
   *  variables), could not be read. Counts as lost (fail closed). */
  | "route-unverified";

export const ROUTE_PROBLEM_CODES: readonly RouteProblemCode[] = [
  "unreadable", "plugin-absent", "plugin-disabled", "plugin-not-attached", "route-direct", "route-elsewhere", "model-bypass", "model-fence", "route-unverified",
];

/** One problem: its code and what it means, in a sentence the doctor, `mandu
 *  serve status` and the dashboard show as they are. */
export interface RouteProblem {
  code: RouteProblemCode;
  detail: string;
}

/** A config's verdict: it routes through the proxy with the plugin loaded,
 *  or what is lost. `lost.modelContext`: model calls may go around the proxy
 *  (or the config cannot say); `lost.policy`: the plugin's tool-call policy
 *  and reply check are not loaded. */
export interface RouteVerdict {
  routed: boolean;
  problems: RouteProblem[];
  lost: { modelContext: boolean; policy: boolean };
}

/** The fix for a lost route, in the order it must run: the install writes
 *  the route again, and a Gateway reads its config only when it starts. */
export const ROUTE_FIX = "mandu openclaw install, then openclaw gateway restart";

/** An endpoint as the problem names it: scheme, host and port only (a URL's
 *  user, path and query stay out of every surface). Pure. */
export function endpointWords(v: string): string {
  try {
    const u = new URL(v.trim());
    return `${u.protocol}//${u.host}`;
  } catch {
    return "an endpoint that is not a URL";
  }
}

/** The verdict over an attachment state; `serviceUrl` as given to
 *  `attachState` (the expected route, for the words). Pure. */
export function routeVerdict(s: AttachState, serviceUrl: string | null = null): RouteVerdict {
  const problems: RouteProblem[] = [];
  if (s.plugin === "absent") problems.push({ code: "plugin-absent", detail: "the Mandu plugin is not in the config" });
  else if (s.plugin === "disabled") problems.push({ code: "plugin-disabled", detail: "the Mandu plugin is disabled (its entry, plugins.enabled, plugins.deny or plugins.allow)" });
  else if (!s.loadPath) problems.push({ code: "plugin-not-attached", detail: "the Mandu plugin has no load path to its folder" });
  else if (!s.attachment) problems.push({ code: "plugin-not-attached", detail: "the Mandu plugin is not in attachment mode" });
  if (s.checkAnthropic === false) { /* left unprotected by the user's choice */ }
  else if (s.route === "none") problems.push({ code: "route-direct", detail: "Anthropic calls go to Anthropic directly, not through Mandu" });
  else if (s.route === "other") {
    problems.push({
      code: "route-elsewhere",
      detail: `Anthropic calls go to ${s.routeUrl !== undefined ? endpointWords(s.routeUrl) : "another endpoint"}, not Mandu's service proxy${serviceUrl !== null ? ` (${serviceUrl})` : ""}`,
    });
  }
  // Route 1: every other routed provider, and any provider added since.
  for (const p of s.providerRoutes ?? []) {
    if (p.ignored !== undefined) problems.push({ code: "route-direct", detail: `calls of provider ${p.id} go around Mandu whatever its route: ${p.ignored}` });
    else if (p.route === "none") problems.push({ code: "route-direct", detail: `calls of provider ${p.id} go to its own endpoint directly, not through Mandu` });
    else if (p.route === "other") {
      problems.push({
        code: "route-elsewhere",
        detail: `calls of provider ${p.id} go to ${p.routeUrl !== undefined ? endpointWords(p.routeUrl) : "another endpoint"}, not Mandu's service proxy` +
          (serviceUrl !== null ? ` (${providerRouteUrl(serviceUrl, p)})` : ""),
      });
    }
  }
  // Azure OpenAI (model-wires.md §9.1): OpenClaw's Azure client sends every
  // Azure call to AZURE_OPENAI_BASE_URL / AZURE_OPENAI_RESOURCE_NAME when the
  // Gateway's environment sets one, whatever the provider's route.
  const azure = (s.providerRoutes ?? []).filter((p) => p.wire === "azure-openai-responses" && p.route === "service" && p.ignored === undefined);
  if (azure.length > 0) {
    const ids = azure.map((p) => p.id).join(", ");
    const env = s.gatewayEnv;
    if (env !== undefined && env.set.length > 0) {
      problems.push({
        code: "route-direct",
        detail: `calls of Azure OpenAI provider${azure.length === 1 ? "" : "s"} ${ids} go to ${env.set.join(", ")} instead of the route: ` +
          "OpenClaw's Azure client reads that variable before the provider's baseUrl, so they go around Mandu (unset it where the Gateway runs, then restart it)",
      });
    } else if (env === undefined || !env.verified) {
      problems.push({
        code: "route-unverified",
        detail: `the route of Azure OpenAI provider${azure.length === 1 ? "" : "s"} ${ids} is not verified: ` +
          `${env?.why ?? "the Gateway's environment was not read"}, and OpenClaw's Azure client sends every Azure call to ` +
          "AZURE_OPENAI_BASE_URL or AZURE_OPENAI_RESOURCE_NAME when it is set, around Mandu",
      });
    }
  }
  if ((s.unrouted ?? []).length > 0) {
    const ids = s.unrouted!;
    problems.push({
      code: "route-direct",
      detail: `provider${ids.length === 1 ? "" : "s"} ${ids.join(", ")} ${ids.length === 1 ? "is" : "are"} not routed through Mandu (added after the install), so ${ids.length === 1 ? "its" : "their"} calls go around it`,
    });
  }
  if (s.modelsAround.length > 0) problems.push({ code: "model-bypass", detail: `model entries with their own endpoint go around the proxy: ${s.modelsAround.join(", ")}` });
  // The model fence: each hole loses the model context (openclaw-plugin.md
  // §3.6, "The model fence"): one switch away from a model around Mandu.
  for (const h of s.fenceHoles ?? []) problems.push({ code: "model-fence", detail: fenceHoleWords(h) });
  return { routed: problems.length === 0, problems, lost: routeLostOf(problems) };
}

/** At most three names, then how many more. */
function someNames(names: readonly string[]): string {
  return names.slice(0, 3).join(", ") + (names.length > 3 ? ` and ${names.length - 3} more` : "");
}

/** A fence hole in a sentence: model references and config keys only (no
 *  path, no port, never a value). Pure. */
export function fenceHoleWords(h: FenceHole): string {
  const bypass = "OpenClaw before 2026.3.22 sends an openrouter model that its catalog and models.providers.openrouter.models do not list straight to openrouter.ai, whatever the route";
  switch (h.kind) {
    case "fence-gone":
      return `the model allowlist (agents.defaults.models) ${h.names.length > 0 ? "Mandu wrote at the install" : "your config kept at the install"} is gone, ` +
        "so a model switch (/model, a subagent's model) can reach any model, around Mandu";
    case "fence-unrouted": {
      const ids = [...new Set(h.names.map((k) => k.slice(0, k.indexOf("/"))))];
      return `the model allowlist (agents.defaults.models) names ${someNames(h.names)}, so a model switch can reach ` +
        `provider${ids.length === 1 ? "" : "s"} ${someNames(ids)}, which Mandu does not route (added after the install)`;
    }
    case "openrouter-wildcard":
      return `the model allowlist (agents.defaults.models) names ${someNames(h.names)}, which OpenClaw before 2026.3.22 reads as the model "*": ${bypass}`;
    case "openrouter-unlisted":
      return `openrouter model${h.names.length === 1 ? "" : "s"} ${someNames(h.names)} ${h.names.length === 1 ? "is" : "are"} named by the config or its model allowlist ` +
        `but not listed in models.providers.openrouter.models: ${bypass}`;
  }
}

/** What a set of problems loses: the model context (a route around the
 *  proxy, or a config that cannot say), the plugin's policy (a plugin not
 *  loaded, or a config that cannot say). Pure. */
export function routeLostOf(problems: readonly RouteProblem[]): RouteVerdict["lost"] {
  const has = (...codes: RouteProblemCode[]): boolean => problems.some((p) => codes.includes(p.code));
  return {
    modelContext: has("unreadable", "route-direct", "route-elsewhere", "model-bypass", "model-fence", "route-unverified"),
    policy: has("unreadable", "plugin-absent", "plugin-disabled", "plugin-not-attached"),
  };
}

/** The verdict when the config cannot be read: nothing it says can be
 *  checked, so everything it carries counts as lost (fail closed). Pure. */
export function unreadableRouteVerdict(why: string): RouteVerdict {
  return { routed: false, problems: [{ code: "unreadable", detail: why }], lost: { modelContext: true, policy: true } };
}

/** What the pool says of a session's route: `routed`; `lost` (said loudly);
 *  or `pending`, a route not seen yet on a session no install armed (a
 *  `mandu serve attach` before `mandu openclaw install`). */
export type RouteState = "routed" | "lost" | "pending";

/** The route record the pool keeps in the session's pool record, which
 *  `mandu serve status` and `mandu doctor` read. */
export interface RouteRecord {
  state: RouteState;
  problems: RouteProblem[];
  /** The config checked (absolute). */
  config: string;
  /** When the state began, and when the config was last read (ISO). */
  since: string;
  checkedAt: string;
}

/** The state a verdict puts a session in: lost only once armed (an install
 *  recorded its config, or the pool saw it routed). Pure. */
export function routeStateOf(v: RouteVerdict, armed: boolean): RouteState {
  return v.routed ? "routed" : armed ? "lost" : "pending";
}

/** The route record in a pool record's text, or null (none, or not one). Pure. */
export function parseRouteRecord(text: string): RouteRecord | null {
  let r: unknown;
  try { r = (JSON.parse(text) as { route?: unknown }).route; } catch { return null; }
  const o = obj(r);
  if (!o || (o["state"] !== "routed" && o["state"] !== "lost" && o["state"] !== "pending")) return null;
  if (typeof o["config"] !== "string" || typeof o["since"] !== "string" || typeof o["checkedAt"] !== "string") return null;
  const problems = (Array.isArray(o["problems"]) ? o["problems"] as unknown[] : []).flatMap((p): RouteProblem[] => {
    const x = obj(p);
    return x && (ROUTE_PROBLEM_CODES as readonly unknown[]).includes(x["code"]) && typeof x["detail"] === "string"
      ? [{ code: x["code"] as RouteProblemCode, detail: x["detail"] }]
      : [];
  });
  return { state: o["state"], problems, config: o["config"], since: o["since"], checkedAt: o["checkedAt"] };
}

// ── The confined-commands tier (openclaw-plugin.md §10): what the install
//    records, what the plugin reports, what the doctor and the pool judge ─

/** The sandbox backend id the plugin registers and the install names. */
export const SANDBOX_BACKEND_ID = "mandu";

/** What the sandbox tool gate must let through so chat, web and plugin
 *  tools keep working under the tier (`tools.sandbox.tools.alsoAllow`). */
export const SANDBOX_ALSO_ALLOW: readonly string[] = ["message", "group:web", "group:plugins"];

/** The plugin's status file, in the session's folder of the runtime base. */
export const SANDBOX_STATUS_FILE = "openclaw-sandbox.json";

/** How old the plugin's status may be and still count (it writes every 30 s). */
export const SANDBOX_STATUS_FRESH_MS = 120_000;

/** `<runtime>/attachments/<session>/openclaw-sandbox.json`. */
export function sandboxStatusFile(runtimeBase: string, session: string): string {
  return `${attachmentDir(runtimeBase, session)}/${SANDBOX_STATUS_FILE}`;
}

/** What `mandu openclaw install --sandbox` found in place of each value it
 *  wrote (null: absent), which uninstall puts back. */
export interface SandboxOriginal {
  /** `agents.defaults.sandbox`, whole. */
  sandbox: Json | null;
  /** `tools.sandbox.tools.alsoAllow`. */
  alsoAllow: unknown[] | null;
  /** `tools.elevated`, whole. */
  elevated: Json | null;
  /** `tools.exec.host`. */
  execHost: string | null;
}

/** The declaration's `sandbox`: the tier is installed for this session. */
export interface DeclaredSandbox {
  original: SandboxOriginal;
}

/** The declaration's `sandbox` value, or why it is unusable (the entry then
 *  keeps no tier record: uninstall removes Mandu's values only). Pure. */
export function parseDeclaredSandbox(v: unknown): DeclaredSandbox | string {
  const o = obj(v);
  const orig = obj(o?.["original"]);
  if (!o || !orig) return "sandbox is not a {original} record";
  const objOrNull = (x: unknown): Json | null | undefined => (x === null ? null : obj(x) ?? undefined);
  const sandbox = objOrNull(orig["sandbox"]);
  const elevated = objOrNull(orig["elevated"]);
  const alsoAllow = orig["alsoAllow"] === null ? null : Array.isArray(orig["alsoAllow"]) ? orig["alsoAllow"] as unknown[] : undefined;
  const execHost = orig["execHost"] === null ? null : typeof orig["execHost"] === "string" ? orig["execHost"] : undefined;
  if (sandbox === undefined || elevated === undefined || alsoAllow === undefined || execHost === undefined) return "sandbox.original is not the shape install records";
  return { original: { sandbox, alsoAllow, elevated, execHost } };
}

/** `list` with the session's tier record set (null: removed). Pure. */
export function withDeclaredSandbox(list: readonly DeclaredAttachment[], session: string, sandbox: DeclaredSandbox | null): { list: DeclaredAttachment[]; changed: boolean } {
  const i = list.findIndex((a) => a.session === session);
  if (i < 0) return { list: [...list], changed: false };
  const cur = list[i]!;
  if (JSON.stringify(cur.sandbox ?? null) === JSON.stringify(sandbox)) return { list: [...list], changed: false };
  const { sandbox: _old, ...rest } = cur;
  const next = [...list];
  next[i] = sandbox === null ? rest : { ...rest, sandbox };
  return { list: next, changed: true };
}

/** What the plugin records about OpenClaw's `mandu` backend (the plugin's
 *  sandbox/backend.ts SandboxStatus; a claim from the Gateway). */
export interface SandboxStatusRecord {
  pid?: number;
  checkedAt: string;
  sdk: boolean;
  registered: boolean;
  /** Whether OpenClaw's `mandu` factory is the plugin's (null: cannot tell). */
  ours: boolean | null;
  error?: string;
}

/** The plugin's status record: null unless it parses, its writer lives and
 *  it is fresh. Pure over its inputs. */
export function parseSandboxStatus(text: string | null, now: number, pidAlive: (pid: number) => boolean): SandboxStatusRecord | null {
  if (text === null) return null;
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return null; }
  const o = obj(doc);
  if (!o || o["version"] !== 1 || typeof o["checkedAt"] !== "string") return null;
  const at = Date.parse(o["checkedAt"]);
  if (!Number.isFinite(at) || now - at > SANDBOX_STATUS_FRESH_MS) return null;
  if (typeof o["pid"] === "number" && !pidAlive(o["pid"])) return null;
  return {
    ...(typeof o["pid"] === "number" ? { pid: o["pid"] } : {}),
    checkedAt: o["checkedAt"],
    sdk: o["sdk"] === true,
    registered: o["registered"] === true,
    ours: o["ours"] === true ? true : o["ours"] === false ? false : null,
    ...(typeof o["error"] === "string" ? { error: o["error"] } : {}),
  };
}

/** An agent's own entry in `agents.list` or `agents.entries` (OpenClaw's two
 *  roster forms), by its normalized id. Pure. */
export function openclawAgentEntry(doc: Json, agentId: string): Json | null {
  const agents = obj(doc["agents"]) ?? {};
  if (Array.isArray(agents["list"])) {
    for (const e of agents["list"] as unknown[]) {
      const x = obj(e);
      if (x && typeof x["id"] === "string" && normalizeAgentId(x["id"]) === agentId) return x;
    }
  }
  for (const [k, e] of Object.entries(obj(agents["entries"]) ?? {})) {
    const x = obj(e);
    if (x && normalizeAgentId(typeof x["id"] === "string" ? x["id"] : k) === agentId) return x;
  }
  return null;
}

export const SANDBOX_PROBLEM_KINDS = [
  "sandbox-mode", "sandbox-backend", "workspace-access", "exec-host", "elevated", "backend-replaced", "backend-missing", "tools-blocked",
] as const;
export type SandboxProblemKind = (typeof SANDBOX_PROBLEM_KINDS)[number];

/** One way the tier is not what the install wrote. */
export interface SandboxProblem {
  kind: SandboxProblemKind;
  /** What a person reads. */
  words: string;
  /** `unconfined`: a command may now run outside the box (or none runs);
   *  `utility`: a tool is missing, nothing runs outside. */
  severity: "unconfined" | "utility";
}

/**
 * The tier's problems in an effective config (includes resolved) for the
 * attached agent, and in the plugin's status (null: none, or too old to
 * count). Empty: the tier holds as the install wrote it. The doctor, the
 * install's post-check and the pool's route check decide by this. Pure.
 */
export function sandboxTierProblems(effective: Json, agentId: string, status: SandboxStatusRecord | null): SandboxProblem[] {
  const out: SandboxProblem[] = [];
  const defaults = obj(configAt(effective, "agents", "defaults")) ?? {};
  const entry = openclawAgentEntry(effective, agentId);
  const sb: Json = { ...(obj(defaults["sandbox"]) ?? {}), ...(obj(entry?.["sandbox"]) ?? {}) };
  if (sb["mode"] !== "all") {
    out.push({ kind: "sandbox-mode", severity: "unconfined", words: `the sandbox mode is ${JSON.stringify(sb["mode"] ?? "off")}, not "all": ${sb["mode"] === "non-main" ? "the main chat's commands run" : "commands run"} on the Gateway's host, outside Mandu's box` });
  }
  if (sb["backend"] !== SANDBOX_BACKEND_ID) {
    out.push({ kind: "sandbox-backend", severity: "unconfined", words: `the sandbox backend is ${JSON.stringify(sb["backend"] ?? "docker")}, not "${SANDBOX_BACKEND_ID}": commands do not run in Mandu's box` });
  }
  if (sb["workspaceAccess"] !== "rw") {
    out.push({ kind: "workspace-access", severity: "utility", words: `the sandbox workspace access is ${JSON.stringify(sb["workspaceAccess"] ?? "none")}, not "rw": Mandu's box refuses every command` });
  }
  const toolsOf = (o: Json | null): Json => obj(o?.["tools"]) ?? {};
  const pick = (key: string, field: string): unknown =>
    [toolsOf(entry), toolsOf(effective)].map((t) => obj(t[key])?.[field]).find((v) => v !== undefined);
  const host = pick("exec", "host");
  if (host === "gateway" || host === "node") {
    out.push({ kind: "exec-host", severity: "unconfined", words: `tools.exec.host is "${String(host)}": commands run on ${host === "node" ? "a paired node" : "the Gateway's host"}, outside Mandu's box` });
  }
  if (pick("elevated", "enabled") !== false) {
    out.push({ kind: "elevated", severity: "unconfined", words: "elevated exec is not switched off (tools.elevated.enabled): `/elevated on` runs a command outside Mandu's box" });
  }
  const sbTools = obj(configAt(effective, "tools", "sandbox", "tools")) ?? {};
  const also = Array.isArray(sbTools["alsoAllow"]) ? sbTools["alsoAllow"] as unknown[] : [];
  const missing = SANDBOX_ALSO_ALLOW.filter((t) => !also.includes(t));
  if (missing.length > 0 && !Array.isArray(sbTools["allow"])) {
    out.push({ kind: "tools-blocked", severity: "utility", words: `the sandbox tool gate blocks ${missing.join(", ")} (tools.sandbox.tools.alsoAllow): the agent may go quiet on its chat` });
  }
  if (status !== null) {
    if (status.ours === false) {
      out.push({ kind: "backend-replaced", severity: "unconfined", words: `another plugin registered the sandbox backend "${SANDBOX_BACKEND_ID}" after Mandu's: commands may run outside Mandu's box` });
    } else if (!status.registered) {
      out.push({ kind: "backend-missing", severity: "unconfined", words: `the Gateway's Mandu plugin could not register the sandbox backend${status.error ? ` (${status.error})` : ""}: OpenClaw runs no command` });
    }
  }
  return out;
}

/** The fix for a lost tier, everywhere it is said. */
export const SANDBOX_FIX = "mandu openclaw install --sandbox, then openclaw gateway restart";

/** What the pool's route check found about the tier (the pool record's
 *  `sandbox`): `held`, or `lost` when a command may run outside the box. */
export interface SandboxRecord {
  state: "held" | "lost";
  problems: SandboxProblem[];
  checkedAt: string;
}

/** The tier's record from the pool's check over `effective` and the plugin's
 *  status. Pure. */
export function sandboxRecordOf(effective: Json, agentId: string, status: SandboxStatusRecord | null, now: string): SandboxRecord {
  const problems = sandboxTierProblems(effective, agentId, status);
  return { state: problems.some((p) => p.severity === "unconfined") ? "lost" : "held", problems, checkedAt: now };
}

/** The tier record in a pool record's text, or null. Pure. */
export function parseSandboxRecord(text: string): SandboxRecord | null {
  let r: unknown;
  try { r = (JSON.parse(text) as { sandbox?: unknown }).sandbox; } catch { return null; }
  const o = obj(r);
  if (!o || (o["state"] !== "held" && o["state"] !== "lost") || typeof o["checkedAt"] !== "string") return null;
  const problems = (Array.isArray(o["problems"]) ? o["problems"] as unknown[] : []).flatMap((p): SandboxProblem[] => {
    const x = obj(p);
    return x && (SANDBOX_PROBLEM_KINDS as readonly unknown[]).includes(x["kind"]) && typeof x["words"] === "string" && (x["severity"] === "unconfined" || x["severity"] === "utility")
      ? [{ kind: x["kind"] as SandboxProblemKind, words: x["words"], severity: x["severity"] }]
      : [];
  });
  return { state: o["state"], problems, checkedAt: o["checkedAt"] };
}

/** The lines a lost tier gets in `mandu serve status` and `mandu doctor`
 *  (empty unless lost). Pure. */
export function sandboxLostLines(session: string, rec: SandboxRecord | null): string[] {
  if (rec?.state !== "lost") return [];
  return [
    `${session}: commands may run outside Mandu's box: ${rec.problems.filter((p) => p.severity === "unconfined").map((p) => p.words).join("; ")}`,
    `fix: ${SANDBOX_FIX}`,
  ];
}
