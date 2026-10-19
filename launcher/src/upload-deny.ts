/**
 * upload-deny — the hosts an agent would upload its own transcript, trace or
 * telemetry to, denied at the network layer for that agent's launch
 * (supported-agents.md §5.3.4, rule 1: "Transcript and trace uploads").
 *
 * The agent process holds original tool output, so a session or trace upload
 * of its own would carry data off the machine past the model proxy. Each
 * agent build (1) forces the agent's off switch in the launch env, (2) lists
 * the upload hosts here, and (3) ships an e2e test. This module is (2): PURE,
 * a table keyed by launcher target. run.ts puts the answer on the plan
 * (`LaunchPlan.uploadDenyHosts`), and two layers enforce it:
 *   - the connect guard: one `--deny tcp:<host>:<port|*>` per entry
 *     (`uploadDenyGuardSpecs`; mandu-net-guard checks deny rules before any
 *     allow, so they beat the `tcp:*:443` fallback);
 *   - the net-proxy: `MANDU_NET_PROXY_DENY_HOSTS` (services/net-proxy.ts),
 *     which refuses a CONNECT or plain-HTTP request to the host with 403
 *     before dialing (the guard sees only the proxy's loopback port for
 *     proxied traffic, so the proxy must refuse it itself).
 *
 * Entry syntax: `host` (every port) or `host:port`; a leading `.` (`.example`)
 * also matches every subdomain at the net-proxy (the guard resolves names, so
 * there it denies the apex only). An entry that does not parse as a host is
 * dropped: a bad spec would make the guard refuse to start the agent.
 *
 * Mandu-new (no reference origin).
 *
 * Since 2026-10-07 the table also carries an agent's MODEL hosts that the
 * launch does not route (Goose's other providers, supported-agents.md
 * §5.6.3): a provider switch mid-session would send the conversation there
 * past the model proxy, the same harm as an upload. Most of those are
 * `proxyOnly` (the net-proxy, by name).
 */
import { GOOSE_PROVIDER_HOSTS, gooseCustomProviderFence, type GooseConfig } from "./goose-route.js";

/** How one agent's upload hosts are computed. */
export interface UploadDenyEntry {
  /** Hosts the agent always uploads to when its switch is on (fixed, e.g. a
   *  vendor's telemetry endpoint). */
  fixed: readonly string[];
  /** Env keys holding a URL whose host the agent uploads to (a user-configured
   *  trace collector): the host of each set key is denied too. */
  urlEnv?: readonly string[];
  /** Extra hosts from the agent's own config, when the caller read it. */
  fromConfig?: (config: unknown) => string[];
  /** Hosts denied at the net-proxy ONLY (by name; `.suffix` entries match
   *  every subdomain there), never handed to the connect guard: a long list
   *  of vendor API hosts, many behind shared CDN addresses. The guard
   *  resolves each deny name on every connect (cached 30 s) and matches by
   *  address, so such a list would slow every connect and could refuse an
   *  unrelated site that shares an address. For hosts the agent reaches
   *  through HTTPS_PROXY (the net-proxy is on by default, and fail-closed). */
  proxyOnly?: readonly string[];
}

/**
 * The table, keyed by launcher target (`LaunchPlan.target`). Empty until an
 * agent build adds its row; the shape, for a hypothetical agent:
 *
 *   example: {
 *     fixed: ["telemetry.example.com", ".traces.example.net"],
 *     urlEnv: ["EXAMPLE_TRACE_URL"],
 *   }
 */
export const UPLOAD_DENY: Readonly<Record<string, UploadDenyEntry>> = {
  // Goose 1.53.0 (supported-agents.md §5.6; the switches are forced off in
  // the launch env, goose-route.ts gooseForcedEnv): PostHog usage telemetry,
  // the public Nostr relays `goose session export --nostr` publishes a
  // session to (the subcommand is refused at launch too), and the Langfuse /
  // OTLP collectors the user's env or config names.
  goose: {
    fixed: ["us.i.posthog.com", "relay.damus.io", "relay.primal.net", "nos.lol", "relay.nostr.band"],
    urlEnv: [
      "LANGFUSE_URL", "LANGFUSE_BASE_URL", "LANGFUSE_HOST",
      "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
      "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
      "SECURITY_PROMPT_CLASSIFIER_ENDPOINT", "SECURITY_COMMAND_CLASSIFIER_ENDPOINT",
    ],
    // config.yaml's own collector and classifier endpoints (Goose promotes
    // `otel_exporter_otlp_endpoint` into the env; the classifier keys are
    // read as config params)
    fromConfig: (config: unknown) => {
      const values = (config as { values?: Record<string, string> | null } | null)?.values ?? {};
      return [
        ...hostsFromUrlEnv(values, [
          "otel_exporter_otlp_endpoint", "OTEL_EXPORTER_OTLP_ENDPOINT",
          "SECURITY_PROMPT_CLASSIFIER_ENDPOINT", "SECURITY_COMMAND_CLASSIFIER_ENDPOINT",
          "LANGFUSE_URL", "LANGFUSE_BASE_URL", "LANGFUSE_HOST",
        ]),
        // the user's own declarative providers' literal hosts (§5.6.3): a
        // few, and a loopback one is reached around the net-proxy (NO_PROXY),
        // so both layers
        ...gooseCustomProviderFence(config as GooseConfig | null).hosts,
      ];
    },
    // the model hosts of the providers the launch does not route (§5.6.3)
    proxyOnly: GOOSE_PROVIDER_HOSTS,
  },
  // Codex (codex-cli 0.160.0 source, checked against 0.136.0; supported-
  // agents.md §5.5; the switches are forced off on every command level,
  // codex-argv.ts CODEX_UPLOADS_OFF): the Statsig metrics endpoint, the
  // Sentry project the feedback report uploads the session to, the OTLP
  // collectors the env names, and from the user's config.toml layers the
  // `[otel]` exporters' endpoints and the realtime (voice) base URLs, which
  // would carry the conversation past the model proxy. chatgpt.com is NOT
  // listed: the ChatGPT sign-in, plugins and account calls need it (§5.5).
  codex: {
    fixed: ["o33249.ingest.us.sentry.io"],
    // ab.chatgpt.com resolves to chatgpt.com's own Cloudflare addresses
    // (checked 2026-10-07): an address deny would cut the sign-in off.
    proxyOnly: ["ab.chatgpt.com"],
    urlEnv: [
      "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
      "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    ],
    fromConfig: (config: unknown) => {
      const layers = (config as { layers?: ReadonlyArray<{ text?: unknown }> } | null)?.layers ?? [];
      const urls = layers.flatMap((l) => (typeof l?.text === "string" ? codexConfigUploadUrls(l.text) : []));
      return hostsFromUrlEnv(Object.fromEntries(urls.map((u, i) => [String(i), u])), urls.map((_, i) => String(i)));
    },
  },
};

/** The target's hosts denied at the net-proxy ONLY (`proxyOnly`),
 *  normalized; empty for a target with no row. Pure. */
export function uploadDenyProxyOnlyHosts(
  target: string,
  table: Readonly<Record<string, UploadDenyEntry>> = UPLOAD_DENY,
): string[] {
  const entry = Object.prototype.hasOwnProperty.call(table, target) ? table[target]! : undefined;
  return normalizeDenyHosts(entry?.proxyOnly ?? []);
}

/** Everything the net-proxy denies for a launch: both lists, de-duplicated.
 *  Pure. */
export function netProxyDenyHosts(plan: { uploadDenyHosts?: readonly string[]; netProxyOnlyDenyHosts?: readonly string[] }): string[] {
  return normalizeDenyHosts([...(plan.uploadDenyHosts ?? []), ...(plan.netProxyOnlyDenyHosts ?? [])]);
}

/** Config keys of Codex's whose URL takes data past the model proxy, outside
 *  the `[otel]` tables (realtime voice: core/src/realtime_conversation.rs). */
const CODEX_URL_KEYS = ["experimental_realtime_ws_base_url", "experimental_realtime_webrtc_call_base_url"];

/**
 * The upload URLs one Codex config.toml names: every `endpoint` string inside
 * an OpenTelemetry setting (a `[otel…]` table, or a dotted `otel.` key with
 * an inline table: `exporter = { otlp-http = { endpoint = "…" } }`), and the
 * realtime base URLs (CODEX_URL_KEYS). A line scan, conservative: a profile
 * or table it cannot place still counts, since a denied host costs the
 * session only that host. Pure.
 */
export function codexConfigUploadUrls(text: string): string[] {
  const out: string[] = [];
  let header: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (line === "") continue;
    const h = /^\[\[?\s*([^\]]+?)\s*\]\]?$/.exec(line);
    if (h) { header = h[1]!.split(".").map((p) => p.trim().replace(/^["']|["']$/g, "")); continue; }
    const key = /^([A-Za-z0-9_."'-]+)\s*=/.exec(line)?.[1]?.split(".").map((p) => p.replace(/^["']|["']$/g, "")) ?? [];
    const path = [...header, ...key];
    if (path.includes("otel")) {
      for (const m of line.matchAll(/\bendpoint["']?\s*=\s*["']([^"']+)["']/g)) out.push(m[1]!);
    }
    const last = key[key.length - 1];
    if (last !== undefined && CODEX_URL_KEYS.includes(last)) {
      const v = /=\s*["']([^"']+)["']/.exec(line)?.[1];
      if (v) out.push(v);
    }
  }
  return out;
}

/** The host (and port, when the URL names one) of each URL-valued env key that
 *  is set, as deny entries (`host` or `host:port`). An unparseable value is
 *  skipped: it names no host the agent could reach either. */
export function hostsFromUrlEnv(env: Record<string, string | undefined>, keys: readonly string[]): string[] {
  const out: string[] = [];
  for (const k of keys) {
    const v = env[k]?.trim();
    if (!v) continue;
    let u: URL;
    try {
      u = new URL(v.includes("://") ? v : `http://${v}`);
    } catch {
      continue;
    }
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (!host) continue;
    out.push(u.port ? `${host.includes(":") ? `[${host}]` : host}:${u.port}` : (host.includes(":") ? `[${host}]` : host));
  }
  return out;
}

/** A deny entry split into its parts, or null when it is not a host. */
export function parseDenyEntry(entry: string): { host: string; port: number | null; suffix: boolean } | null {
  let s = entry.trim().toLowerCase();
  if (!s) return null;
  const suffix = s.startsWith(".");
  if (suffix) s = s.slice(1);
  let host: string;
  let port: number | null = null;
  const v6 = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/.exec(s);
  if (v6) {
    host = v6[1]!;
    if (v6[2] !== undefined) port = Number(v6[2]);
  } else {
    const m = /^([a-z0-9._-]+)(?::(\d{1,5}))?$/.exec(s);
    if (!m) return null;
    host = m[1]!.replace(/\.$/, "");
    if (m[2] !== undefined) port = Number(m[2]);
  }
  if (!host || host.startsWith(".") || host.includes("..")) return null;
  if (port !== null && (port < 1 || port > 65535)) return null;
  if (suffix && v6) return null;
  return { host, port, suffix };
}

/** The upload hosts to deny for this launch: the target's fixed hosts, the
 *  hosts of its URL env keys that are set, and its config's, normalized and
 *  de-duplicated. Empty for a target with no row. Pure. */
export function uploadDenyHosts(
  target: string,
  env: Record<string, string | undefined>,
  config?: unknown,
  table: Readonly<Record<string, UploadDenyEntry>> = UPLOAD_DENY,
): string[] {
  const entry = Object.prototype.hasOwnProperty.call(table, target) ? table[target]! : undefined;
  if (!entry) return [];
  return normalizeDenyHosts([
    ...entry.fixed,
    ...hostsFromUrlEnv(env, entry.urlEnv ?? []),
    ...(entry.fromConfig && config !== undefined ? entry.fromConfig(config) : []),
  ]);
}

/** Normalize, validate and de-duplicate a list of deny entries. Pure. */
export function normalizeDenyHosts(entries: readonly string[]): string[] {
  const out: string[] = [];
  for (const e of entries) {
    const p = parseDenyEntry(e);
    if (!p) continue;
    const h = p.host.includes(":") ? `[${p.host}]` : p.host;
    const s = `${p.suffix ? "." : ""}${h}${p.port !== null ? `:${p.port}` : ""}`;
    if (!out.includes(s)) out.push(s);
  }
  return out;
}

/** The connect guard's `--deny` specs for a deny list: `tcp:<host>:<port|*>`
 *  (a `.suffix` entry denies its apex: the guard resolves names, it cannot
 *  match every subdomain). Pure. */
export function uploadDenyGuardSpecs(hosts: readonly string[]): string[] {
  const out: string[] = [];
  for (const e of hosts) {
    const p = parseDenyEntry(e);
    if (!p) continue;
    const h = p.host.includes(":") ? `[${p.host}]` : p.host;
    const s = `tcp:${h}:${p.port ?? "*"}`;
    if (!out.includes(s)) out.push(s);
  }
  return out;
}

/** The net-proxy's env variable carrying the deny list (comma-separated). */
export const NET_PROXY_DENY_HOSTS_ENV = "MANDU_NET_PROXY_DENY_HOSTS";
