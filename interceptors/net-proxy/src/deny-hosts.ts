/**
 * deny-hosts — the agent's upload hosts this proxy refuses (supported-agents.md
 * §5.3.4 rule 1, "Transcript and trace uploads").
 *
 * The agent process holds original tool output, so its own transcript, trace
 * or telemetry upload would carry data off the machine past the model proxy.
 * The launcher lists the hosts per agent (launcher/src/upload-deny.ts) and
 * hands them here in `MANDU_NET_PROXY_DENY_HOSTS`; the connect guard gets the
 * same list as `--deny` rules, except the model hosts of providers the launch
 * does not route (Goose's, supported-agents.md §5.6.3), which only this proxy
 * denies (upload-deny.ts `proxyOnly`). The guard sees only this proxy's loopback port
 * for proxied traffic, so this proxy must refuse a listed host itself: a
 * CONNECT or plain-HTTP request to it is answered 403 before anything is
 * dialed, in every mode. The refusal names the host, never the payload.
 *
 * Entry syntax (a TWIN of launcher upload-deny.ts `parseDenyEntry`; the
 * packages build independently, KEEP IN SYNC): `host` (every port) or
 * `host:port`, compared case-insensitively with a trailing dot dropped; a
 * leading `.` (`.example.net`) also matches every subdomain; an IPv6 literal
 * is bracketed (`[2001:db8::1]:443`). An entry that does not parse is
 * ignored.
 *
 * Mandu-new (no reference origin).
 */

/** The variable carrying the list (comma-separated). */
export const DENY_HOSTS_ENV = "MANDU_NET_PROXY_DENY_HOSTS";

export interface DenyHostRule {
  /** Lowercase, no brackets, no trailing dot. */
  host: string;
  /** null = every port. */
  port: number | null;
  /** The entry began with `.`: subdomains match too. */
  suffix: boolean;
}

/** One entry, or null when it is not a host. Pure. */
export function parseDenyHost(entry: string): DenyHostRule | null {
  let s = entry.trim().toLowerCase();
  if (!s) return null;
  const suffix = s.startsWith(".");
  if (suffix) s = s.slice(1);
  let host: string;
  let port: number | null = null;
  const v6 = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/.exec(s);
  if (v6) {
    if (suffix) return null;
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
  return { host, port, suffix };
}

/** The rules of a comma-separated list (the env value). Pure. */
export function parseDenyHosts(raw: string | undefined): DenyHostRule[] {
  if (!raw) return [];
  return raw.split(",").map(parseDenyHost).filter((r): r is DenyHostRule => r !== null);
}

/** The rule `host:port` falls under, or null. `host` as the client wrote it
 *  (a CONNECT target's or a URL's host; brackets and a trailing dot are
 *  dropped, case ignored). Pure. */
export function deniedHost(host: string, port: number, rules: readonly DenyHostRule[]): DenyHostRule | null {
  if (rules.length === 0) return null;
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!h) return null;
  for (const r of rules) {
    if (r.port !== null && r.port !== port) continue;
    if (h === r.host || (r.suffix && h.endsWith(`.${r.host}`))) return r;
  }
  return null;
}

/** The refusal message: names the destination, never the request. */
export function denyHostReason(host: string): string {
  return `destination ${host} is an upload host Mandu denies for this agent, or the model host of a provider Mandu does not route for it (a transcript, trace or telemetry upload, or a request to that model, would carry data past the model proxy)`;
}

/** The list as the launcher passed it, normalized, for the identity endpoint. */
export function denyHostsForIdentity(rules: readonly DenyHostRule[]): string[] {
  return rules.map((r) => `${r.suffix ? "." : ""}${r.host.includes(":") ? `[${r.host}]` : r.host}${r.port !== null ? `:${r.port}` : ""}`);
}
