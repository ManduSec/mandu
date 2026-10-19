/**
 * model-probe — "Test connection" for one declared model (policy.yaml
 * `models:`, confidentiality plan 11 D6; dashboard.md §4.25l).
 *
 * Provenance: the decision logic MIRRORS `mandu doctor`'s model rows
 * (launcher/src/doctor.ts `gatherModels`, `modelRows`, `realProbeTcp`,
 * `realListModels`) and the launcher's host rules (launcher/src/model-endpoints.ts
 * `normalizeHost`, `isLoopbackHost`, `hostClass`, `isCloudBackedModel`). The
 * dashboard package cannot import the launcher (its tsc rootDir is the
 * package), so the pieces are copied here and pinned to the launcher's by
 * tests/stack/model-probe-parity.test.ts (one case table run
 * through doctor's `gatherModels` and through `probeModelEndpoint`) and by
 * cloud-model-parity.test.ts. Change them together.
 *
 * What a probe does, as doctor does it: a short TCP connect to the entry's
 * host and port; when it connects, GET {url}/v1/models for an openai-chat
 * entry that names a model (is it loaded?) and for every `local: true` entry
 * (does the server also offer cloud-backed models?). The entry's own bearer
 * token rides along when its `token_env` variable is set in THIS process's
 * environment; the token is never returned, and no result string carries it.
 * Plan 12 D6: a `local: true` entry on another machine is graded by where its
 * address really is (a name is resolved), with a hint when it is public or
 * does not resolve, and plain http to another machine is a failure (refused,
 * or accepted by the entry's `allow_plain_http`, still graded bad). Everything
 * but the I/O deps is pure.
 */
import { connect, isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { endpointPlacement } from "./view-model/model-endpoints.js";
import { inNetworks, loadTlsMaterial, probeTls, type EndpointTlsConfig, type TlsMaterial } from "./endpoint-tls.js";

/** Both the connect and the listing give up after this long. */
export const PROBE_TIMEOUT_MS = 3000;

export type HostClass = "loopback" | "link-local" | "private" | "public" | "name";

/** Lowercase, strip IPv6 brackets and a trailing dot, unwrap `::ffff:a.b.c.d`. */
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

export function isLoopbackHost(host: string): boolean {
  const h = normalizeHost(host);
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return true;
  const v4 = ipv4(h);
  return v4 !== null && (v4[0] === 127 || v4.every((n) => n === 0));
}

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
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return "private";
    return "public";
  }
  return "name";
}

/** The host of an http(s) url and its port (the scheme's default when absent), or null. */
export function originOf(url: string): { host: string; port: number } | null {
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  const scheme = u.protocol === "http:" ? "http" : u.protocol === "https:" ? "https" : null;
  if (scheme === null || u.hostname === "") return null;
  const port = u.port === "" ? (scheme === "https" ? 443 : 80) : Number(u.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: normalizeHost(u.hostname), port };
}

/** Where a network endpoint's addresses are, the worst case over all of them
 *  (plan 12 D6). MIRROR of launcher/src/model-endpoints.ts `addressReach`;
 *  model-probe-parity.test.ts pins them. Pure. */
export type AddressReach = "loopback" | "private" | "public" | "unresolved";

export function addressReach(addresses: readonly string[]): AddressReach {
  if (addresses.length === 0) return "unresolved";
  const classes = addresses.map(hostClass);
  if (classes.some((c) => c === "public" || c === "name")) return "public";
  if (classes.every((c) => c === "loopback")) return "loopback";
  return "private";
}

/** The configured TLS checks in words. MIRROR of launcher/src/doctor.ts
 *  `tlsChecksWords`. Pure. */
export function tlsChecksWords(t: EndpointTlsConfig | undefined): string[] {
  if (!t) return [];
  return [
    ...(t.caFile ? ["your CA"] : []),
    ...(t.pinSha256 && t.pinSha256.length > 0 ? ["a pinned key"] : []),
    ...(t.clientCert ? ["a client certificate"] : []),
  ];
}

/** A `local: true` entry at this url deserves the "is it really yours?"
 *  hint: its host is not a loopback, link-local or private address (or the
 *  url does not parse). The Approvals card (policy-proposals.ts) and the probe
 *  share it. */
export function needsHostHint(url: string): boolean {
  const o = originOf(url);
  if (o === null) return true;
  const c = hostClass(o.host);
  return c === "public" || c === "name";
}

/** MIRROR of the cloud-model rule (arbiter/policy/cloud-model.ts and three
 *  more copies; cloud-model-parity.test.ts pins all of them to one table). */
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

/** Ollama lists `llama3.2:latest` for a model pulled as `llama3.2`. */
export function modelListedIn(ids: readonly string[], model: string): boolean {
  const bare = (m: string): string => m.replace(/:latest$/, "");
  return ids.some((id) => id === model || bare(id) === bare(model));
}

/** One declared entry, defaults applied (the arbiter's ModelEndpoint shape). */
/**
 * The base `/v1/models` is added to: the url without trailing slashes and
 * without ONE trailing `/v1` (an OpenAI base URL ends in it by convention).
 * MIRROR of launcher/src/model-endpoints.ts and
 * interceptors/inspect-mcp/src/ullm-config.ts `endpointApiBase`. Pure.
 */
export function endpointApiBase(url: string): string {
  return url.replace(/\/+$/, "").replace(/\/v1$/, "");
}

export interface ProbeEntry {
  name: string;
  url: string;
  wire: "anthropic" | "openai-chat";
  model?: string;
  local: boolean;
  tokenEnv?: string;
  /** policy.yaml `allow_plain_http: true` (plan 12 D2). */
  allowPlainHttp?: boolean;
  /** policy.yaml `tls:` (plan 12 D3), absolute paths. */
  tls?: EndpointTlsConfig;
  /** policy.yaml `perimeter.networks` (plan 12 D4), when it applies to this
   *  entry (`local: true`, on another machine). */
  perimeter?: readonly string[];
  /** The host is under `perimeter.domains` (words only). */
  orgDomain?: boolean;
}

export interface ProbeDeps {
  probeTcp(host: string, port: number): Promise<boolean>;
  /** Resolve a host name (plan 12 D6); [] when it does not resolve. Optional:
   *  without it a name is not resolved and no address hint is given. */
  lookupHost?(name: string): Promise<string[]>;
  /** One TLS handshake with the entry's checks (plan 12 D3). Optional:
   *  without it no TLS line is given. */
  probeTls?(host: string, port: number, m: TlsMaterial): Promise<{ ok: true } | { ok: false; reason: string }>;
  /** GET {url}/v1/models → the listed ids, or null when it could not be read. */
  listModels(url: string, token: string | undefined): Promise<string[] | null>;
  env: Record<string, string | undefined>;
}

/** One line of the answer, in the product page's words. */
export interface ProbeLine {
  tone: "ok" | "bad" | "note";
  text: string;
}

export interface ProbeResult {
  name: string;
  /** The facts, as doctor gathers them (the parity test compares these). */
  host: string | null;
  port: number | null;
  hostClass: HostClass | null;
  reachable: boolean | null;
  modelListed: boolean | null;
  cloudListed: string[];
  /** Plan 12 D1/D6: `host` | `network`; for a network entry the addresses
   *  its host resolved to and where they are (absent when not resolved). */
  placement: "host" | "network" | null;
  addresses?: string[];
  reach?: AddressReach;
  /** Plan 12 D2: a `local: true` entry over plain http to another machine. */
  plainHttp?: "allowed" | "refused";
  /** Plan 12 D3/D6: the handshake with the entry's checks (doctor's fact). */
  tls?: { checks: string[]; ok: boolean; reason?: string };
  /** Plan 12 D4: the perimeter against the addresses (doctor's fact). */
  perimeter?: { networks: string[]; ok: boolean; outside?: string | null };
  /** Nothing is wrong: it connected and, when checked, the model is listed. */
  ok: boolean;
  lines: ProbeLine[];
}

/** Probe one entry the way `mandu doctor` does. Never throws. */
export async function probeModelEndpoint(e: ProbeEntry, deps: ProbeDeps): Promise<ProbeResult> {
  const o = originOf(e.url);
  const lines: ProbeLine[] = [];
  if (o === null) {
    return {
      name: e.name, host: null, port: null, hostClass: null, reachable: null, modelListed: null, cloudListed: [], placement: null, ok: false,
      lines: [{ tone: "bad", text: "The address is not a web address Mandu can connect to. Fix it and save again." }],
    };
  }
  const where = `${o.host.includes(":") ? `[${o.host}]` : o.host}:${o.port}`;
  const placement = endpointPlacement(e.url) ?? "network";
  let place: { addresses: string[]; reach: AddressReach } | null = null;
  if (placement === "network") {
    let addresses: string[] | null = null;
    if (isIP(o.host) !== 0) addresses = [o.host];
    else if (deps.lookupHost) { try { addresses = await deps.lookupHost(o.host); } catch { addresses = []; } }
    if (addresses !== null) place = { addresses, reach: addressReach(addresses) };
  }
  let plainHttp: "allowed" | "refused" | undefined;
  if (e.local && placement === "network" && new URL(e.url).protocol === "http:") plainHttp = e.allowPlainHttp === true ? "allowed" : "refused";
  // Plan 12 D4: the perimeter against those addresses, as doctor and the launch check.
  let perimeterFact: ProbeResult["perimeter"] | undefined;
  if (e.local && placement === "network" && e.perimeter && place !== null) {
    const bad = place.addresses.find((a) => !inNetworks(a, e.perimeter!));
    const inside = place.addresses.length > 0 && bad === undefined;
    perimeterFact = { networks: [...e.perimeter], ok: inside, ...(inside ? {} : { outside: bad ?? null }) };
  }
  let reachable: boolean | null = null;
  try { reachable = await deps.probeTcp(o.host, o.port); } catch { reachable = false; }
  let tlsFact: ProbeResult["tls"] | undefined;
  if (reachable === true && new URL(e.url).protocol === "https:" && deps.probeTls && perimeterFact?.ok !== false && (e.tls !== undefined || (e.local && placement === "network"))) {
    const checks = tlsChecksWords(e.tls);
    try {
      const r = await deps.probeTls(o.host, o.port, e.tls ? loadTlsMaterial(e.tls) : {});
      tlsFact = r.ok ? { checks, ok: true } : { checks, ok: false, reason: r.reason };
    } catch (err) {
      tlsFact = { checks, ok: false, reason: (err as Error).message };
    }
  }
  let modelListed: boolean | null = null;
  let cloudListed: string[] = [];
  const wantListed = e.wire === "openai-chat" && e.model !== undefined;
  const token = e.tokenEnv ? deps.env[e.tokenEnv] : undefined;
  if (reachable === true && (wantListed || e.local)) {
    let ids: string[] | null = null;
    try { ids = await deps.listModels(e.url, token || undefined); } catch { ids = null; }
    if (wantListed) modelListed = ids === null ? null : modelListedIn(ids, e.model!);
    if (e.local && ids !== null) cloudListed = ids.filter(isCloudBackedModel);
  }

  // A name with no address here: the connection could not even start, so
  // "start the model server" would send the person the wrong way.
  const unresolved = place !== null && place.reach === "unresolved" && isIP(o.host) === 0;
  if (!reachable) {
    lines.push({
      tone: "bad",
      text: unresolved
        ? `Could not connect to ${where}: ${o.host} does not resolve here. Check the address, or connect to the network it is on.`
        : `Could not connect to ${where}. Start the model server, or fix the address.`,
    });
  } else {
    lines.push({ tone: "ok", text: `Connected to ${where}.` });
    if (modelListed === true) lines.push({ tone: "ok", text: `${e.model} is loaded on the server.` });
    else if (modelListed === false) {
      lines.push({ tone: "bad", text: `${e.model} is not in the server's model list (${endpointApiBase(e.url)}/v1/models). Load it on the server (for Ollama: ollama pull ${e.model}).` });
    } else if (wantListed) {
      lines.push({ tone: "note", text: `The server's model list could not be read, so Mandu could not check that ${e.model} is loaded.` });
    }
  }
  if (e.tokenEnv && !token && reachable === true && (wantListed || e.local)) {
    lines.push({ tone: "note", text: `${e.tokenEnv} is not set where the dashboard runs, so the model list was asked for without a key.` });
  }
  const hc = hostClass(o.host);
  // Plan 12 D4: the perimeter, as doctor gives it.
  if (perimeterFact?.ok === true) {
    lines.push({ tone: "ok", text: `Every address (${place!.addresses.slice(0, 3).join(", ")}) is inside your organization's networks.` });
  } else if (perimeterFact?.ok === false) {
    lines.push({
      tone: "bad",
      text: (perimeterFact.outside
        ? `${perimeterFact.outside === o.host ? `${o.host} is` : `${o.host} resolves to ${perimeterFact.outside}, which is`} outside your organization's networks (${perimeterFact.networks.join(", ")}).`
        : `Mandu cannot check that ${o.host} is inside your organization's networks until it resolves.`) +
        " Mandu sends nothing to it, and a launch refuses it.",
    });
  }
  // Plan 12 D6: graded by where the address really is, as doctor does. With
  // a perimeter the line above says it; without one, a note.
  if (e.local && place !== null && place.reach === "public" && perimeterFact === undefined) {
    const shown = place.addresses.filter((a) => hostClass(a) === "public").slice(0, 3).join(", ");
    lines.push({
      tone: "note",
      text: (isIP(o.host) !== 0 ? `${o.host} is a public address.` : `${o.host} resolves to a public address (${shown}).`) +
        " If it is your organization's private-link endpoint, list its network under perimeter: networks in policy.yaml; otherwise make sure your organization controls that server." +
        " Mandu makes sure the data goes to the address you gave, not what that server does with it next.",
    });
  } else if (e.local && place !== null && place.reach === "unresolved" && perimeterFact === undefined) {
    lines.push({ tone: "note", text: `${o.host} does not resolve here. Check the address.` });
  }
  // Plan 12 D3/D6: the TLS facts, as doctor gives them.
  if (tlsFact?.ok === true) {
    lines.push({ tone: "ok", text: `TLS checked${tlsFact.checks.length > 0 ? ` with ${tlsFact.checks.join(", ")}` : " with the system's trusted CAs"}.` });
  } else if (tlsFact?.ok === false) {
    lines.push({ tone: "bad", text: `TLS refused: ${tlsFact.reason ?? "unknown"}. Nothing is sent to this model until it passes.` });
  }
  // Plan 12 D2: never quiet, graded bad like doctor's row.
  if (plainHttp === "allowed") {
    lines.push({ tone: "bad", text: `Not encrypted: files marked "Your own AI only" cross the network in the clear to ${where}. Use an https address to fix this.` });
  } else if (plainHttp === "refused") {
    lines.push({ tone: "bad", text: `This is a plain http address on another computer, so Mandu will not send files marked "Your own AI only" to it. Use an https address.` });
  }
  if (e.local && e.model !== undefined && isCloudBackedModel(e.model)) {
    lines.push({ tone: "bad", text: `${e.model} runs on the vendor's computers, so it cannot be your own model. Choose a model that runs on your machine.` });
  }
  if (cloudListed.length > 0) {
    const shown = cloudListed.slice(0, 5).join(", ") + (cloudListed.length > 5 ? ` and ${cloudListed.length - 5} more` : "");
    lines.push({ tone: "note", text: `This server also offers models that run on the vendor's computers (${shown}). Never choose one of them here or as your main model.` });
  }
  const ok = reachable === true && modelListed !== false && !(e.local && e.model !== undefined && isCloudBackedModel(e.model)) && plainHttp === undefined && tlsFact?.ok !== false && perimeterFact?.ok !== false;
  return {
    name: e.name, host: o.host, port: o.port, hostClass: hc, reachable, modelListed, cloudListed, placement,
    ...(place !== null ? place : {}), ...(plainHttp ? { plainHttp } : {}), ...(tlsFact ? { tls: tlsFact } : {}),
    ...(perimeterFact ? { perimeter: perimeterFact } : {}), ok, lines,
  };
}

// ── the real I/O (short timeouts; nothing is kept) ──────────────────────────

export function realProbeTcp(host: string, port: number, timeoutMs = PROBE_TIMEOUT_MS): Promise<boolean> {
  return new Promise((res) => {
    const c = connect({ host, port });
    const done = (ok: boolean): void => { clearTimeout(t); c.destroy(); res(ok); };
    const t = setTimeout(() => done(false), timeoutMs);
    c.once("connect", () => done(true));
    c.once("error", () => done(false));
  });
}

export async function realListModels(url: string, token: string | undefined, timeoutMs = PROBE_TIMEOUT_MS): Promise<string[] | null> {
  try {
    const r = await fetch(`${endpointApiBase(url)}/v1/models`, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
      ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}),
    });
    if (!r.ok) return null;
    const body = (await r.json()) as { data?: Array<{ id?: unknown }> };
    return Array.isArray(body.data) ? body.data.map((d) => d.id).filter((id): id is string => typeof id === "string") : null;
  } catch {
    return null;
  }
}

/** The system resolver, bounded like the probe, [] on failure. */
export async function realLookupHost(name: string): Promise<string[]> {
  const bounded = new Promise<string[]>((res) => setTimeout(() => res([]), PROBE_TIMEOUT_MS).unref());
  const answer = lookup(name, { all: true }).then((as) => as.map((a) => a.address), () => []);
  return Promise.race([answer, bounded]);
}

export function realProbeDeps(env: Record<string, string | undefined> = process.env): ProbeDeps {
  return { probeTcp: (h, p) => realProbeTcp(h, p), listModels: (u, t) => realListModels(u, t), lookupHost: realLookupHost, probeTls: (h, p, m) => probeTls(h, p, m), env };
}
