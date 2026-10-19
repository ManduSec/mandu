/**
 * model-endpoints — the launcher's side of policy.yaml `models:` (the
 * operator's own model endpoints; model-endpoints.md §1
 * D2, D5, D6).
 *
 * The arbiter owns the law: it validates `models:` and answers the data-socket
 * op `{op:"modelEndpoints"}` → `{endpoints:[{name,url,wire,model?,local,tokenEnv?}]}`.
 * The launcher reads that answer once per launch (and `mandu doctor` once per
 * run) and uses it for three things:
 *
 *   1. the network confine (D5): a declared `local: true` endpoint's port joins
 *      the agent world's allowed TCP set (landlock-net.ts) and its host:port
 *      joins the connect-guard's allow set (net-guard.ts), the way the U-LLM
 *      forwarder's port does, because `inspect-mcp` (spawned by the agent,
 *      inside that world) dials it directly;
 *   2. the launch refusal (D2): a `local: true` entry whose address is the
 *      model proxy's or the U-LLM forwarder's would send `local-model` bytes to
 *      an EXTERNAL model through the one door the level exists to keep shut, so
 *      the launch refuses (`localEndpointConflicts`);
 *   3. the doctor rows (D6, doctor.ts);
 *   4. the cloud-model rule (plan 11 §8 item 3): `isCloudBackedModel`, mirrored
 *      from the arbiter, refuses a launch whose `local: true` entry names a
 *      cloud-backed model (a belt for an arbiter older than the rule, which
 *      refuses such a file at load) and tells the model proxy when its
 *      upstream is a declared LOCAL model (`MANDU_UPSTREAM_LOCAL`), so it
 *      refuses a request for a cloud model there.
 *
 * Everything here but `readModelEndpoints` is pure and unit-tested with no
 * socket, no DNS and no network.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { connect, isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { networkInterfaces } from "node:os";
import { readFileSync } from "node:fs";
import { asTlsConfig, hasTlsConfig, inNetworks, type EndpointTlsConfig } from "./endpoint-tls.js";

export type ModelWire = "anthropic" | "openai-chat";

/** One declared endpoint, as the arbiter's `modelEndpoints` op reports it. */
export interface ModelEndpoint {
  name: string;
  url: string;
  wire: ModelWire;
  model?: string;
  /** Operator-declared, never inferred from the address (D2). */
  local: boolean;
  /** The env var holding a bearer token for this endpoint (policy.yaml `token_env`). */
  tokenEnv?: string;
  /** policy.yaml `helper: true`: the quarantined helper's model (only when true). */
  helper?: true;
  /** policy.yaml `allow_plain_http: true` (plan 12 D2, only when true): the
   *  helper may reach this entry over plain http on another machine. */
  allowPlainHttp?: true;
  /** policy.yaml `tls:` (plan 12 D3), compiled: absolute paths and pins. */
  tls?: EndpointTlsConfig;
  /** policy.yaml `perimeter.networks` (plan 12 D4), attached by the arbiter
   *  to a `local: true` entry on another machine: every address must be
   *  inside one of these CIDRs (checked at launch and at every connection). */
  perimeter?: readonly string[];
  /** The host is under one of `perimeter.domains` (plan 12 D4): words only. */
  orgDomain?: true;
  /** Plan 12 D5: the administrator's file that set this entry. */
  adminFile?: string;
  /** Plan 12 D5: set by the administrator and locked. */
  locked?: true;
}

const NAME_RE = /^[A-Za-z0-9_.-]+$/;
const ENV_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Accept one endpoint from the wire, or null. The arbiter validated the file;
 *  the launcher re-checks the shape because the url feeds a kernel-side allow
 *  set (stay strict, the same stance as net-guard-law.ts `isGuardSpec`). */
export function asModelEndpoint(x: unknown): ModelEndpoint | null {
  if (x === null || typeof x !== "object") return null;
  const r = x as Record<string, unknown>;
  if (typeof r["name"] !== "string" || !NAME_RE.test(r["name"])) return null;
  if (typeof r["url"] !== "string" || parseOrigin(r["url"]) === null) return null;
  const wire = r["wire"] === undefined ? "anthropic" : r["wire"];
  if (wire !== "anthropic" && wire !== "openai-chat") return null;
  if (r["local"] !== undefined && typeof r["local"] !== "boolean") return null;
  if (r["model"] !== undefined && (typeof r["model"] !== "string" || r["model"] === "")) return null;
  if (r["tokenEnv"] !== undefined && (typeof r["tokenEnv"] !== "string" || !ENV_RE.test(r["tokenEnv"]))) return null;
  if (r["helper"] !== undefined && typeof r["helper"] !== "boolean") return null;
  if (r["allowPlainHttp"] !== undefined && typeof r["allowPlainHttp"] !== "boolean") return null;
  // Plan 12 D3: a tls setting the launcher cannot read drops the entry (and a
  // dropped `local: true` entry refuses the launch, assertLocalEndpoints).
  const tls = r["tls"] === undefined ? null : asTlsConfig(r["tls"]);
  if (r["tls"] !== undefined && tls === null) return null;
  // Plan 12 D4: likewise a perimeter the launcher cannot read.
  const perimeter = r["perimeter"] === undefined ? undefined : asTlsConfig({ perimeter: r["perimeter"] })?.perimeter;
  if (r["perimeter"] !== undefined && perimeter === undefined) return null;
  if (r["orgDomain"] !== undefined && typeof r["orgDomain"] !== "boolean") return null;
  if (r["adminFile"] !== undefined && (typeof r["adminFile"] !== "string" || !r["adminFile"].startsWith("/"))) return null;
  if (r["locked"] !== undefined && typeof r["locked"] !== "boolean") return null;
  return {
    name: r["name"],
    url: r["url"],
    wire,
    ...(typeof r["model"] === "string" ? { model: r["model"] } : {}),
    local: r["local"] === true,
    ...(typeof r["tokenEnv"] === "string" ? { tokenEnv: r["tokenEnv"] } : {}),
    ...(r["helper"] === true && r["local"] === true ? { helper: true as const } : {}),
    ...(r["allowPlainHttp"] === true ? { allowPlainHttp: true as const } : {}),
    ...(tls !== null && hasTlsConfig(tls) ? { tls } : {}),
    ...(perimeter !== undefined ? { perimeter } : {}),
    ...(r["orgDomain"] === true ? { orgDomain: true as const } : {}),
    ...(typeof r["adminFile"] === "string" ? { adminFile: r["adminFile"] } : {}),
    ...(r["locked"] === true && typeof r["adminFile"] === "string" ? { locked: true as const } : {}),
  };
}

/**
 * The client keys inspect-mcp needs for the declared `local: true` endpoints
 * that name one (policy.yaml `tls.client_key`, plan 12 D3), read by the
 * LAUNCHER, outside the agent's world: inside it the key file is masked (the
 * arbiter's secret discovery twins it), and the helper runs there. Entry
 * name → PEM. An unreadable file is left out, so the helper refuses that
 * endpoint (it cannot build the client certificate). Outside entries get
 * nothing: inspect-mcp never dials one. The same residue as `token_env`
 * (plan 11 §7 "D2, token_env"): a program in the agent's world that can read
 * the helper's config can read the key.
 */
export function localModelClientKeys(
  endpoints: readonly ModelEndpoint[],
  read: (p: string) => string = (p) => readFileSync(p, "utf8"),
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of endpoints) {
    const p = e.tls?.clientKey;
    if (!e.local || p === undefined) continue;
    try { out[e.name] = read(p); } catch { /* left out: the helper refuses the endpoint */ }
  }
  return out;
}

/**
 * The name of the entry the quarantined helper uses: the `local: true` entry
 * marked `helper: true`, else the first `local: true` entry; null when none
 * is local. MIRROR of interceptors/inspect-mcp/src/inspect-symbol.ts
 * `helperEndpoint` (the launcher never imports inspect-mcp); the doctor row
 * and the dashboard name the same entry the helper dials. Pure.
 */
export function helperEndpointName(endpoints: readonly ModelEndpoint[]): string | null {
  return helperEndpointEntry(endpoints)?.name ?? null;
}

/** The entry itself ({@link helperEndpointName}'s rule); undefined when none
 *  is local. Pure. */
export function helperEndpointEntry(endpoints: readonly ModelEndpoint[]): ModelEndpoint | undefined {
  return endpoints.find((e) => e.local && e.helper === true) ?? endpoints.find((e) => e.local);
}

/**
 * The base an API path is added to: the url without trailing slashes and
 * without ONE trailing `/v1` (an OpenAI base URL ends in it by convention,
 * and the path added starts with `/v1`). MIRROR of
 * interceptors/inspect-mcp/src/ullm-config.ts `endpointApiBase`. Pure.
 */
export function endpointApiBase(url: string): string {
  return url.replace(/\/+$/, "").replace(/\/v1$/, "");
}

/**
 * The bearer tokens inspect-mcp needs for the declared `local: true`
 * endpoints, read from the LAUNCHER's environment (policy.yaml `token_env`
 * names the variable; the value never goes in the file). The agent's own
 * environment carries the variable masked (the arbiter registers every
 * declared model token as a secret), and Claude Code hands its environment to
 * the MCP server, so without this the helper would send the placeholder.
 * External entries get nothing: inspect-mcp never dials one (D5). An unset or
 * empty variable is left out, so the endpoint answers 401 and the helper
 * refuses, the same as with no token. Pure.
 */
export function localModelTokens(
  endpoints: readonly ModelEndpoint[],
  env: Record<string, string | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of endpoints) {
    if (!e.local || e.tokenEnv === undefined) continue;
    const v = env[e.tokenEnv];
    if (v !== undefined && v !== "") out[e.tokenEnv] = v;
  }
  return out;
}

/**
 * Is a model NAME one the server runs on someone else's machine? Ollama
 * serves cloud-backed models (`gpt-oss:120b-cloud`, `glm-4.6:cloud`, …)
 * through the same loopback API as its own, so a declared `local: true`
 * endpoint can still relay the bytes to the vendor (plan 11 §8 item 3).
 * True when the tag (after the last `:`, when that part holds no `/`) has
 * `cloud` as a `-` / `_` / `.` separated word, or the model's own name (last
 * `/` segment before the tag) ends in that word; case-insensitive, a trailing
 * `@<digest>` ignored. Words, not substrings (`wordcloud` is not). A name
 * without the word is not proven local: a server can alias any name.
 *
 * MIRROR of arbiter/policy/cloud-model.ts (the launcher never imports the
 * arbiter), interceptors/anthropic-proxy/src/cloud-model.ts and
 * interceptors/openai-proxy/src/cloud-model.ts; the four are
 * pinned to one table by tests/stack/cloud-model-parity.test.ts.
 * Change them together. Pure.
 */
export function isCloudBackedModel(name: string): boolean {
  let s = name.trim().toLowerCase();
  const at = s.indexOf("@");
  if (at >= 0) s = s.slice(0, at);
  if (s === "") return false;
  const colon = s.lastIndexOf(":");
  const hasTag = colon >= 0 && !s.slice(colon + 1).includes("/");
  const tag = hasTag ? s.slice(colon + 1) : "";
  const base = hasTag ? s.slice(0, colon) : s;
  if (tag.split(/[-_.]/).includes("cloud")) return true;
  const own = base.slice(base.lastIndexOf("/") + 1);
  const words = own.split(/[-_.]/);
  return words[words.length - 1] === "cloud";
}

/** A normalized network address: lowercase scheme, host without brackets
 *  (IPv4 shorthand / hex already canonicalized by the WHATWG URL parser, an
 *  IPv4-mapped IPv6 host unwrapped to its IPv4 form), explicit port. */
export interface Origin {
  scheme: "http" | "https";
  host: string;
  port: number;
}

/** Parse an endpoint url into its origin, or null when it is not an http(s)
 *  url with a host. A missing port is the scheme's default (80 / 443). */
export function parseOrigin(url: string): Origin | null {
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  const scheme = u.protocol === "http:" ? "http" : u.protocol === "https:" ? "https" : null;
  if (scheme === null || u.hostname === "") return null;
  const port = u.port === "" ? (scheme === "https" ? 443 : 80) : Number(u.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { scheme, host: normalizeHost(u.hostname), port };
}

/** Lowercase, strip IPv6 brackets and a trailing dot, unwrap `::ffff:a.b.c.d`
 *  (the URL parser prints it as `::ffff:7f00:1`). */
export function normalizeHost(host: string): string {
  let h = host.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (mapped) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (dotted) return dotted[1]!;
  return h;
}

function ipv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) ? o : null;
}

/** Hosts that reach THIS machine's loopback listeners. Deliberately wide,
 *  because a match here is a refusal (fail-closed): `localhost` and any
 *  `*.localhost` (RFC 6761), the whole 127.0.0.0/8 (Debian maps the machine's
 *  own hostname to 127.0.1.1), `::1`, and the unspecified addresses 0.0.0.0
 *  and `::`, which a Linux connect(2) delivers to the local host. */
export function isLoopbackHost(host: string): boolean {
  const h = normalizeHost(host);
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return true;
  const v4 = ipv4(h);
  return v4 !== null && (v4[0] === 127 || v4.every((n) => n === 0));
}

/** Where a declared endpoint sits (plan 12 D1): `host` when its host is a
 *  loopback spelling ({@link isLoopbackHost}), else `network`, where the
 *  transport rules must prove the destination; null for an unusable url.
 *  MIRROR of arbiter/policy/model-placement.ts `endpointPlacement` and
 *  interceptors/inspect-mcp/src/ullm-client.ts; pinned together by
 *  tests/stack/model-placement-parity.test.ts. Pure. */
export function endpointPlacement(url: string): "host" | "network" | null {
  const o = parseOrigin(url);
  if (o === null) return null;
  return isLoopbackHost(o.host) ? "host" : "network";
}

/** Plan 12 D2: does a `local: true` entry send local-model files across a
 *  network in the clear (plain http, `network` placement)? Pure. */
export function isPlainHttpLocal(e: ModelEndpoint): boolean {
  return e.local && parseOrigin(e.url)?.scheme === "http" && endpointPlacement(e.url) === "network";
}

/** The launch warnings for `local: true` entries the operator opted into
 *  plain http for (plan 12 D2: never quiet). Each starts with `WARNING` so the
 *  compact launch display prints it. Pure. */
export function plainHttpWarnings(endpoints: readonly ModelEndpoint[]): string[] {
  return endpoints
    .filter((e) => isPlainHttpLocal(e) && e.allowPlainHttp === true)
    .map((e) =>
      `WARNING: mandu: models: ${e.name} (${e.url}) is plain http on another machine; files labeled local-model ` +
        "that the helper sends there cross the network unencrypted (allow_plain_http: true in policy.yaml). " +
        "Use https or a loopback tunnel (ssh -L) to close this",
    );
}

/** The launch refusal for a `local: true` entry on another machine over plain
 *  http without the opt-out (plan 12 D2). An arbiter with the rule refuses
 *  such a file at load, so this fires only under an older one. */
export class PlainHttpLocalModelError extends Error {
  constructor(readonly endpoints: readonly ModelEndpoint[]) {
    const lines = endpoints.map((e) => `  - models: ${e.name} (${e.url})`);
    super(
      "mandu: refusing to launch: policy.yaml declares a model on another machine as `local: true` over plain http:\n" +
        lines.join("\n") + "\n" +
        "  Files labeled local-model would cross the network unencrypted. Use https, reach it through a loopback " +
        "tunnel (ssh -L), or add allow_plain_http: true to the entry to accept that, then launch again.",
    );
    this.name = "PlainHttpLocalModelError";
  }
}

/** Plan 12 D4: the launch refusal for a `local: true` endpoint whose name
 *  resolves outside `perimeter.networks` (or to nothing at all). */
export class PerimeterLocalModelError extends Error {
  constructor(readonly outside: ReadonlyArray<{ endpoint: ModelEndpoint; address: string | null }>) {
    const lines = outside.map(({ endpoint: e, address }) =>
      `  - models: ${e.name} (${e.url}) ${address === null ? "does not resolve here" : `resolves to ${address}`}`);
    super(
      "mandu: refusing to launch: policy.yaml declares a model as `local: true` at an address outside perimeter.networks:\n" +
        lines.join("\n") + "\n" +
        "  Files labeled local-model would leave your organization's networks. Fix the name or its DNS record, or list its " +
        "network under perimeter.networks if it is yours, then launch again.",
    );
    this.name = "PerimeterLocalModelError";
  }
}

/**
 * Plan 12 D4, pure: the endpoints with a perimeter whose addresses are not
 * all inside it. `resolved` maps a name to its addresses (a literal address
 * is its own answer); an empty answer is outside (it cannot be checked).
 */
export function perimeterViolations(
  endpoints: readonly ModelEndpoint[],
  resolved: ReadonlyMap<string, readonly string[]>,
): Array<{ endpoint: ModelEndpoint; address: string | null }> {
  const out: Array<{ endpoint: ModelEndpoint; address: string | null }> = [];
  for (const e of endpoints) {
    if (!e.local || !e.perimeter || e.perimeter.length === 0) continue;
    const o = parseOrigin(e.url);
    if (o === null) continue;
    const addrs = isIP(o.host) !== 0 ? [o.host] : [...(resolved.get(o.host) ?? [])];
    const bad = addrs.find((a) => !inNetworks(a, e.perimeter!));
    if (addrs.length === 0 || bad !== undefined) out.push({ endpoint: e, address: bad ?? null });
  }
  return out;
}

/** The kind of host an endpoint names, for the doctor's hint (D6). */
export type HostClass = "loopback" | "link-local" | "private" | "public" | "name";

export function hostClass(host: string): HostClass {
  const h = normalizeHost(host);
  if (isLoopbackHost(h)) return "loopback";
  const v4 = ipv4(h);
  if (v4 !== null) {
    const [a, b] = v4 as [number, number, number, number];
    if (a === 169 && b === 254) return "link-local";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
    return "public";
  }
  if (h.includes(":")) {
    if (/^fe[89ab][0-9a-f]:/.test(h)) return "link-local";
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return "private"; // unique local fc00::/7
    return "public";
  }
  return "name";
}

/** Where a `network` endpoint's addresses are (plan 12 D6), the worst case
 *  over every address its host resolves to: `public` when any is public;
 *  `unresolved` when there is none; `loopback` when all are loopback;
 *  otherwise `private` (RFC 1918, ULA, link-local, mixed with loopback).
 *  MIRROR of dashboard/src/model-probe.ts `addressReach`; the probe parity
 *  test pins them. Pure. */
export type AddressReach = "loopback" | "private" | "public" | "unresolved";

export function addressReach(addresses: readonly string[]): AddressReach {
  if (addresses.length === 0) return "unresolved";
  const classes = addresses.map(hostClass);
  if (classes.some((c) => c === "public" || c === "name")) return "public";
  if (classes.every((c) => c === "loopback")) return "loopback";
  return "private";
}

/** An address the launch reserves: a declared `local: true` endpoint must
 *  never be one of these (D2). */
export interface ReservedAddress {
  /** What it is, for the refusal message ("the model proxy (anthropic-proxy)"). */
  role: string;
  host: string;
  port: number;
}

/** Do two addresses reach the same listener? Same port, and the same host
 *  after normalization, where every loopback spelling is one host; a
 *  reserved address bound to the unspecified address (0.0.0.0 / ::) also
 *  answers on every address of this machine (`localAddresses`). The scheme is
 *  NOT compared: `https://127.0.0.1:8788` dials the same socket as `http://…`.
 *  `resolved` maps a host name to the addresses it resolved to (the caller's
 *  DNS lookup; a name is compared by those addresses as well as by itself). */
export function sameAddress(
  candidate: { host: string; port: number },
  reserved: { host: string; port: number },
  opts: { localAddresses?: readonly string[]; resolved?: ReadonlyMap<string, readonly string[]> } = {},
): boolean {
  if (candidate.port !== reserved.port) return false;
  const c = normalizeHost(candidate.host);
  const r = normalizeHost(reserved.host);
  const spellings = [c, ...(opts.resolved?.get(c) ?? []).map(normalizeHost)];
  const local = new Set((opts.localAddresses ?? []).map(normalizeHost));
  const rUnspecified = r === "0.0.0.0" || r === "::";
  return spellings.some((h) =>
    h === r ||
    (isLoopbackHost(h) && isLoopbackHost(r)) ||
    (rUnspecified && local.has(h)),
  );
}

export interface EndpointConflict {
  endpoint: ModelEndpoint;
  reserved: ReservedAddress;
}

/** Every declared `local: true` endpoint whose address is a reserved one (the
 *  model proxy, the U-LLM forwarder). Pure; the caller refuses on any. An
 *  endpoint that is not `local` is never a conflict: it is external either
 *  way, and external is what those two addresses are. */
export function localEndpointConflicts(
  endpoints: readonly ModelEndpoint[],
  reserved: readonly ReservedAddress[],
  opts: { localAddresses?: readonly string[]; resolved?: ReadonlyMap<string, readonly string[]> } = {},
): EndpointConflict[] {
  const out: EndpointConflict[] = [];
  for (const endpoint of endpoints) {
    if (!endpoint.local) continue;
    const o = parseOrigin(endpoint.url);
    if (o === null) continue; // asModelEndpoint already dropped it
    for (const r of reserved) {
      if (r.port > 0 && sameAddress(o, r, opts)) out.push({ endpoint, reserved: r });
    }
  }
  return out;
}

/** The launch refusal (D2). Names each entry, the address it collides with,
 *  why that is refused, and the fix. */
export class ModelEndpointConflictError extends Error {
  constructor(readonly conflicts: readonly EndpointConflict[]) {
    const lines = conflicts.map((c) =>
      `  - models: ${c.endpoint.name} (${c.endpoint.url}) is ${c.reserved.role} at ${c.reserved.host}:${c.reserved.port}`,
    );
    super(
      "mandu: refusing to launch: policy.yaml declares a model as `local: true` at an address that relays to an outside model:\n" +
        lines.join("\n") + "\n" +
        "  Files labeled local-model would be sent to that outside model. Point the entry's url at your own model server " +
        "(for example http://127.0.0.1:11434 for Ollama), or remove `local: true`, then launch again.",
    );
    this.name = "ModelEndpointConflictError";
  }
}

/** The launch refusal for a `local: true` entry naming a cloud-backed model
 *  (plan 11 §8 item 3, {@link isCloudBackedModel}). */
export class CloudLocalModelError extends Error {
  constructor(readonly endpoints: readonly ModelEndpoint[]) {
    const lines = endpoints.map((e) => `  - models: ${e.name} (model ${e.model ?? ""}, ${e.url})`);
    super(
      "mandu: refusing to launch: policy.yaml declares a cloud model as `local: true`:\n" +
        lines.join("\n") + "\n" +
        "  That model runs on the vendor's servers, so files labeled local-model would leave your trust boundary " +
        "(the models you or your organization run). Name a model that runs on your own servers, or remove `local: true`, then launch again.",
    );
    this.name = "CloudLocalModelError";
  }
}

/** The addresses a launch reserves, from the plan's live services: both model
 *  proxies (the target's is the T-LLM's door; the other wire's, when a port is
 *  configured, relays to an outside vendor just the same) and the U-LLM
 *  forwarder (a verbatim relay to Anthropic). Port 0 = never adopted (the
 *  kernel-assigned default with no service, or an explicit base-URL override
 *  that skips the proxy): nothing to reserve. */
export function reservedAddresses(plan: {
  proxy: { host: string; port: number };
  openaiProxy: { host: string; port: number };
  ullmForwarder?: { host: string; port: number };
}): ReservedAddress[] {
  const out: ReservedAddress[] = [];
  if (plan.proxy.port > 0) out.push({ role: "the model proxy (anthropic-proxy)", ...plan.proxy });
  if (plan.openaiProxy.port > 0) out.push({ role: "the model proxy (openai-proxy)", ...plan.openaiProxy });
  if (plan.ullmForwarder && plan.ullmForwarder.port > 0) out.push({ role: "the U-LLM forwarder", ...plan.ullmForwarder });
  return out;
}

/**
 * The network-confine additions for the declared endpoints (D5): the port of
 * the ONE entry the quarantined helper dials ({@link helperEndpointEntry}),
 * nothing for any other entry.
 *
 * Why only that entry:
 *   - `inspect-mcp` routes a `local-model` call to the helper's entry (the
 *     `local: true` entry marked `helper: true`, else the first `local: true`
 *     one) or to the DEFAULT U-LLM (D5 "Selection"). No other declared entry
 *     is dialed by anything inside the agent's world (a declared MAIN model
 *     is dialed by the model proxy, which runs outside it), so there is no
 *     traffic to admit; least privilege opens only the helper's (2026-09-29;
 *     it used to open every `local: true` entry). Moving the helper to
 *     another entry mid-session is refused by the confine (fail closed) until
 *     a relaunch, as adding an entry mid-session already was.
 *   - an external declared endpoint is an outside host like any other and
 *     must pass the same egress rules as any host (the permissive :443
 *     fallback in the default posture; `destinations: connect: allow` under
 *     strict/curated). Admitting it here would make `models:` a second way to
 *     open egress that bypasses the reachability law, which is exactly what
 *     `destinations:` exists to own.
 * The helper's entry is added whatever its host (loopback, a LAN GPU box):
 * the operator named that exact destination as their own model, and the
 * guard pins the rule to that host (loopback hosts to the loopback set, as
 * the service ports are), never to `*`.
 */
export function helperEndpointPorts(endpoints: readonly ModelEndpoint[]): number[] {
  const e = helperEndpointEntry(endpoints);
  const o = e ? parseOrigin(e.url) : null;
  return o === null ? [] : [o.port];
}

const LOOPBACK_GUARD_HOSTS = ["127.0.0.0/8", "[::1]"] as const;

/** Connect-guard specs for the helper's entry (see
 *  {@link helperEndpointPorts} for why only that one). A loopback host
 *  becomes the loopback pair (the guard matches addresses, and `localhost`
 *  resolves to either family); any other host is pinned as written. */
export function helperEndpointGuardSpecs(endpoints: readonly ModelEndpoint[]): string[] {
  const e = helperEndpointEntry(endpoints);
  const o = e ? parseOrigin(e.url) : null;
  if (o === null) return [];
  if (isLoopbackHost(o.host)) return LOOPBACK_GUARD_HOSTS.map((h) => `tcp:${h}:${o.port}`);
  return [`tcp:${o.host.includes(":") ? `[${o.host}]` : o.host}:${o.port}`];
}

/** What the read learned. `unsupported` = the arbiter answered but does not
 *  know the op (a pre-plan-11 arbiter, which has no `models:` registry, so
 *  nothing is declared); `unavailable` = no usable answer (timeout, transport
 *  error, malformed reply). */
export interface ModelEndpointsRead {
  status: "ok" | "unsupported" | "unavailable";
  endpoints: ModelEndpoint[];
  /** Entries the launcher could not accept (bad shape), by name when it has one. */
  dropped: string[];
  /** The dropped entries that said `local: true`: the refusal cannot check
   *  them, so the launch refuses (fail-closed; `assertLocalEndpoints`). */
  droppedLocal?: string[];
  /** Plan 12 D5: the administrator's layer in force, when there is one. */
  admin?: { files: string[]; locked: boolean; conflicts: string[]; refused: string[] };
}

/** Ask the arbiter for the declared endpoints (the law in force). Never
 *  throws. Raw NDJSON, the same pattern as net-guard-law.ts: the launcher
 *  keeps no arbiter-client dependency. */
export function readModelEndpoints(sock: string, timeoutMs = 3000): Promise<ModelEndpointsRead> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: ModelEndpointsRead): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { s.destroy(); } catch { /* already gone */ }
      resolve(v);
    };
    const unavailable: ModelEndpointsRead = { status: "unavailable", endpoints: [], dropped: [] };
    const timer = setTimeout(() => finish(unavailable), timeoutMs);
    const s = connect(sock);
    let buf = "";
    s.setEncoding("utf8");
    s.once("connect", () => s.write(JSON.stringify({ id: "model-endpoints", op: "modelEndpoints" }) + "\n"));
    s.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; error?: unknown; result?: { endpoints?: unknown } };
        if (resp.ok !== true) {
          const unknownOp = typeof resp.error === "string" && /unknown op/i.test(resp.error);
          return finish(unknownOp ? { status: "unsupported", endpoints: [], dropped: [] } : unavailable);
        }
        if (!Array.isArray(resp.result?.endpoints)) return finish(unavailable);
        const endpoints: ModelEndpoint[] = [];
        const dropped: string[] = [];
        const droppedLocal: string[] = [];
        for (const raw of resp.result.endpoints) {
          const e = asModelEndpoint(raw);
          if (e === null) {
            const r = (raw ?? {}) as { name?: unknown; local?: unknown };
            const n = typeof r.name === "string" ? r.name : "(unnamed)";
            dropped.push(n);
            if (r.local === true) droppedLocal.push(n);
          } else if (!endpoints.some((x) => x.name === e.name)) {
            endpoints.push(e);
          }
        }
        const a = (resp.result as { admin?: { files?: unknown; locked?: unknown; conflicts?: unknown; refused?: unknown } }).admin;
        const lines = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
        const admin = a && Array.isArray(a.files) && a.files.every((f) => typeof f === "string")
          ? { admin: { files: a.files as string[], locked: a.locked === true, conflicts: lines(a.conflicts), refused: lines(a.refused) } }
          : {};
        finish({ status: "ok", endpoints, dropped, ...(droppedLocal.length > 0 ? { droppedLocal } : {}), ...admin });
      } catch {
        finish(unavailable);
      }
    });
    s.once("error", () => finish(unavailable));
  });
}

/** Injectable I/O for {@link assertLocalEndpoints}. */
export interface LocalEndpointCheckDeps {
  /** Resolve a host name to its addresses ([] on failure). Default: the
   *  system resolver (getaddrinfo, so /etc/hosts counts), 2 s bound. */
  lookup?: (name: string) => Promise<string[]>;
  /** This machine's interface addresses. Default: os.networkInterfaces(). */
  localAddresses?: () => string[];
  log?: (msg: string) => void;
}

/** The system resolver, 2 s bound, [] on failure (getaddrinfo, so
 *  /etc/hosts counts). Used by the launch refusal and by doctor. */
export async function systemLookup(name: string): Promise<string[]> {
  const bounded = new Promise<string[]>((res) => setTimeout(() => res([]), 2000).unref());
  const answer = lookup(name, { all: true }).then((as) => as.map((a) => a.address), () => []);
  return Promise.race([answer, bounded]);
}

function systemLocalAddresses(): string[] {
  return Object.values(networkInterfaces()).flatMap((ifs) => (ifs ?? []).map((i) => i.address));
}

/**
 * The launch warning for a user-set ANTHROPIC_BASE_URL that names no declared
 * model (plan 11 §8 row 2, the maintainer's choice 2026-09-27: warn, keep
 * today's skip). Mandu's model proxy is then not in front of that model, so
 * nothing the proxy masks is masked for that session. `known` is false when the
 * protection service could not list the declared models. Starts with
 * `WARNING` so the compact launch display prints it (launch-banner.ts
 * isAttentionNote). Pure.
 */
export function undeclaredBaseUrlWarning(baseUrl: string, known: boolean, agentWire: "anthropic" | "openai" = "anthropic"): string {
  const knob = agentWire === "openai" ? "MANDU_OPENAI_BASE_URL" : "ANTHROPIC_BASE_URL";
  const wire = agentWire === "openai" ? "openai-chat" : "anthropic";
  return (
    `WARNING: mandu: Mandu's model proxy is skipped because ${knob} (${baseUrl}) is not declared in policy.yaml models:` +
    (known ? "" : " (the protection service could not say which models are declared)") +
    `, so the model reads file contents and tool results unprotected. Declare it under models: with wire: ${wire} ` +
    "(and local: true if it is your own model) to keep protection on"
  );
}

/**
 * The launch-time half of D2: refuse (throw {@link ModelEndpointConflictError})
 * when a declared `local: true` endpoint is a reserved address. Called by
 * run.ts once the services are up (a port-0 proxy / forwarder has its real
 * port only then). A host name in a local entry is resolved first, so a name
 * that points at this machine (its own hostname, a hosts-file alias) cannot
 * slip past the string compare. A dropped `local: true` entry refuses too:
 * the launcher cannot check what it could not parse.
 *
 * `read.status !== "ok"` checks nothing: an arbiter without the op has no
 * `models:` registry, and a mute one leaves `inspect-mcp`'s own refusal of
 * the proxy and forwarder addresses (D5) as the belt; the network confine
 * then admits no endpoint (tighter). The caller logs that case.
 */
export async function assertLocalEndpoints(
  read: ModelEndpointsRead,
  reserved: readonly ReservedAddress[],
  deps: LocalEndpointCheckDeps = {},
): Promise<void> {
  if (read.status !== "ok") return;
  if (read.droppedLocal && read.droppedLocal.length > 0) {
    throw new Error(
      `mandu: refusing to launch: policy.yaml models: ${read.droppedLocal.join(", ")} ${read.droppedLocal.length === 1 ? "is" : "are"} ` +
        "declared `local: true` but the launcher cannot read the entry (its url must be an http(s) address with a host). " +
        "Fix the entry in policy.yaml, then launch again.",
    );
  }
  // Plan 11 §8 item 3: an arbiter with the rule refuses such a file at load,
  // so this fires only under an older one; the launch refuses either way.
  const cloud = read.endpoints.filter((e) => e.local && e.model !== undefined && isCloudBackedModel(e.model));
  if (cloud.length > 0) throw new CloudLocalModelError(cloud);
  const resolveName = deps.lookup ?? systemLookup;
  const resolved = new Map<string, string[]>();
  for (const e of read.endpoints) {
    if (!e.local) continue;
    const o = parseOrigin(e.url);
    if (o === null || isIP(o.host) !== 0 || isLoopbackHost(o.host) || resolved.has(o.host)) continue;
    resolved.set(o.host, await resolveName(o.host));
  }
  const conflicts = localEndpointConflicts(read.endpoints, reserved, {
    resolved,
    localAddresses: (deps.localAddresses ?? systemLocalAddresses)(),
  });
  if (conflicts.length > 0) throw new ModelEndpointConflictError(conflicts);
  // Plan 12 D2, the same belt as the cloud rule: an older arbiter serves a
  // plain-http remote local entry the new one refuses at load (the helper
  // refuses it per call too). After the conflicts, which are the worse news.
  const plain = read.endpoints.filter((e) => isPlainHttpLocal(e) && e.allowPlainHttp !== true);
  if (plain.length > 0) throw new PlainHttpLocalModelError(plain);
  // Plan 12 D4: the operator hears about an address outside the perimeter
  // now, not when a task fails. The same names, resolved once above.
  const outside = perimeterViolations(read.endpoints, resolved);
  if (outside.length > 0) throw new PerimeterLocalModelError(outside);
}

// ── The main model as a declared endpoint (plan 11 §5, phase 3) ─────────────
//
// A user-set ANTHROPIC_BASE_URL used to make the launcher SKIP the model proxy
// ("the user brings their own endpoint"), so a Claude Code pointed at its own
// model ran with no symbolization at all. Phase 3 keeps the proxy in front of
// a base URL the operator DECLARED under policy.yaml `models:` (the proxy's
// upstream becomes that entry), and records the entry's name with the arbiter
// as the session's main model, which is what lets rung 3 (`declassify_symbol`)
// treat the main model as local when the entry says `local: true`
// (model-endpoints.md §1.7.1 phase 3).
//
// The entry's wire must be the agent's: a Claude Code (or any Anthropic-wire
// target) base URL matches only `wire: anthropic` entries, since the
// anthropic-proxy speaks the Messages wire. Codex's base URL
// (MANDU_OPENAI_BASE_URL, the model_provider base_url it would have used)
// matches only `wire: openai-chat` entries: an OpenAI-compatible server
// (Ollama, vLLM, LM Studio) serves Chat Completions and Responses under one
// base URL, and the openai-proxy forwards Codex's Responses requests to it
// (plan 11 §7.2). Anything else binds `endpoint: null` (an outside model).

/** The comparable form of a base URL: scheme, normalized host, explicit port,
 *  pathname without trailing slashes ("/" ≡ ""). null for anything that is
 *  not a plain http(s) url, INCLUDING one with a query or fragment: a base
 *  URL carrying either is not something Claude Code appends paths to cleanly,
 *  so it never counts as the declared entry (no match = today's behavior). */
function comparableBaseUrl(url: string): string | null {
  const o = parseOrigin(url);
  if (o === null) return null;
  const u = new URL(url); // parseOrigin accepted it, so this parses
  if (u.search !== "" || u.hash !== "" || url.includes("?") || url.includes("#")) return null;
  if (u.username !== "" || u.password !== "") return null;
  const path = u.pathname.replace(/\/+$/, "");
  return `${o.scheme}://${o.host.includes(":") ? `[${o.host}]` : o.host}:${o.port}${path}`;
}

/**
 * The declared entry a user-set ANTHROPIC_BASE_URL names, or null: the FIRST
 * `wire: anthropic` entry whose url equals the base URL after normalization
 * (scheme, host via {@link normalizeHost}, explicit default port, trailing
 * slashes). Pure. First wins, matching the arbiter's order (the file's order).
 * No DNS: `http://my-box:8080` and `http://10.0.0.5:8080` are different
 * spellings and do not match each other; the operator declares the URL they
 * actually export.
 */
export function selectTllmEndpoint(
  baseUrl: string,
  endpoints: readonly ModelEndpoint[],
  agentWire: "anthropic" | "openai" = "anthropic",
): ModelEndpoint | null {
  const want = comparableBaseUrl(baseUrl);
  if (want === null) return null;
  const entryWire: ModelWire = agentWire === "openai" ? "openai-chat" : "anthropic";
  for (const e of endpoints) {
    if (e.wire !== entryWire) continue; // the proxy speaks only the agent's own wire (see above)
    if (comparableBaseUrl(e.url) === want) return e;
  }
  return null;
}

/** The launch refusal for a declared main model the proxy cannot reach
 *  safely: plain http to another machine. */
export class TllmUpstreamError extends Error {
  constructor(readonly url: string, knob = "ANTHROPIC_BASE_URL") {
    super(
      `mandu: refusing to launch: your main model ${url} (${knob}, declared in policy.yaml models:) ` +
        "is plain http on another machine, and Mandu's model proxy sends the conversation over plain http only " +
        "to this machine (127.0.0.1, ::1 or localhost). Put the model behind https, or run it on this machine, " +
        "then launch again.",
    );
    this.name = "TllmUpstreamError";
  }
}

/**
 * The anthropic-proxy's `MANDU_UPSTREAM` for a declared main model: origin +
 * path without a trailing slash. Pure.
 *
 * `localhost` and `*.localhost` are rewritten to the literal `127.0.0.1`: the
 * proxy talks plain http only to a LITERAL loopback address
 * (interceptors/anthropic-proxy/src/proxy.ts `upstreamTransport`), and dialing
 * the literal is strictly safer than resolving a name (a hosts-file entry
 * cannot redirect the conversation). Plain http to any other host THROWS
 * {@link TllmUpstreamError} and the launch refuses (fail-closed): the proxy
 * would refuse every request anyway, and the conversation must never cross a
 * network in the clear.
 */
export function tllmUpstream(url: string, knob = "ANTHROPIC_BASE_URL"): string {
  const u = new URL(url);
  let host = normalizeHost(u.hostname);
  if (host === "localhost" || host.endsWith(".localhost")) host = "127.0.0.1";
  if (u.protocol === "http:") {
    const v4 = ipv4(host);
    const literalLoopback = host === "::1" || (v4 !== null && v4[0] === 127);
    if (!literalLoopback) throw new TllmUpstreamError(url, knob);
  } else if (u.protocol !== "https:") {
    throw new TllmUpstreamError(url, knob);
  }
  const port = u.port === "" ? "" : `:${u.port}`;
  const shownHost = host.includes(":") ? `[${host}]` : host;
  return `${u.protocol}//${shownHost}${port}${u.pathname.replace(/\/+$/, "")}`;
}

/** What the arbiter said to {@link bindSessionUpstream}. `unsupported` = an
 *  arbiter older than phase 3 (no such op); `refused` = the arbiter answered
 *  with a refusal (bind-once, or the session already carried traffic);
 *  `unavailable` = no usable answer (timeout, transport error, malformed). */
export interface SessionUpstreamBind {
  status: "ok" | "unsupported" | "refused" | "unavailable";
  /** Where the arbiter places the bound entry, on `ok`. */
  location?: "local" | "external";
  /** The arbiter's refusal text, or what went wrong. */
  error?: string;
  /** exec-routing.md §8.5.3: the session's clean reporter is claimable
   *  (asked for with `cleanReporter`, and this was the fresh bind). */
  cleanReporter?: boolean;
}

/**
 * Record the session's main model with the arbiter (`setSessionUpstream`):
 * the declared entry's name, or null for the agent's default vendor. Never
 * throws; raw NDJSON like {@link readModelEndpoints}.
 *
 * run.ts calls it for EVERY launch, before any service starts. The binding is
 * bind-once and refused once the session has carried traffic, so the first
 * binding must be the launcher's: that is what stops a process inside the
 * agent from claiming a local main model for its own session.
 */
export function bindSessionUpstream(
  sock: string,
  sessionKey: string,
  endpoint: string | null,
  timeoutMs = 3000,
  /** Ask for the guard-hosted clean box's reporter (clean-host.ts). */
  cleanReporter = false,
): Promise<SessionUpstreamBind> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: SessionUpstreamBind): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { s.destroy(); } catch { /* already gone */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish({ status: "unavailable", error: "no answer" }), timeoutMs);
    const s = connect(sock);
    let buf = "";
    s.setEncoding("utf8");
    s.once("connect", () => s.write(JSON.stringify({
      id: "session-upstream", op: "setSessionUpstream", sessionKey, endpoint, requestedBy: "launcher",
      ...(cleanReporter ? { cleanReporter: true } : {}),
    }) + "\n"));
    s.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: unknown; error?: unknown; result?: { location?: unknown; cleanReporter?: unknown } };
        if (resp.ok !== true) {
          const error = typeof resp.error === "string" ? resp.error : "";
          if (/unknown op/i.test(error)) return finish({ status: "unsupported", error });
          return finish(error !== "" ? { status: "refused", error } : { status: "unavailable", error: "malformed reply" });
        }
        const location = resp.result?.location;
        if (location !== "local" && location !== "external") return finish({ status: "unavailable", error: "malformed reply" });
        finish({ status: "ok", location, ...(resp.result?.cleanReporter === true ? { cleanReporter: true } : {}) });
      } catch {
        finish({ status: "unavailable", error: "malformed reply" });
      }
    });
    s.once("error", (e) => finish({ status: "unavailable", error: e.message }));
  });
}
