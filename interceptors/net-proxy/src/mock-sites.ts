/**
 * mock-sites — an OFFLINE web mock for the egress proxy.
 *
 * Mandu-new. Realizes Mandu's per-URL fixture interception
 * (adfi-openclaw/test/common/placeholders.yaml: url → fixture file) at Mandu's
 * NETWORK chokepoint. When the proxy is configured with a mock-sites YAML and an
 * outbound request URL matches a configured site, the proxy serves the canned
 * response AS the upstream response — instead of forwarding to the real internet —
 * so a REAL Claude Code agent can run a deterministic fetch→write→read loop while
 * the response STILL flows through the proxy's ingress symbolization (the defense
 * is exercised, the network is not touched).
 *
 * Config shape (YAML):
 *   sites:
 *     - url: "http://example.com/setup-guide"   # matched scheme+host+path (+query)
 *       status: 200                              # optional, default 200
 *       content_type: "text/html"               # optional, default text/html
 *       body: "<h1>…</h1>"                       # inline body, OR:
 *       body_file: "setup-guide.html"           # file relative to the YAML's dir
 *       then_body: "<h1>…</h1>"                  # optional: `body` serves the FIRST
 *       then_status: 200                         #   request only; from the second
 *                                                #   request on, then_body/then_status
 *                                                #   are served (a transient-failure
 *                                                #   fixture for retry scenarios,
 *                                                #   e.g. symbol-quality.md §4.6)
 *   hosts:                                       # optional: a per-host catch-all
 *     - host: "httpbin.org"                      # every URL on this host no site matched
 *       to: "127.0.0.1:41234"                    # plaintext HTTP is forwarded here
 *       tls_to: "127.0.0.1:41235"                # a CONNECT is tunneled here (MITM off) or
 *                                                #   its gated requests re-originated here (MITM on)
 *       tls_ca: "replay-ca.pem"                  # the CA the re-origination verifies tls_to's
 *                                                #   certificate against (relative to the YAML)
 *     - host: "*"                                # every other host (never a model host)
 *       to: "127.0.0.1:41234"
 *
 * A host route (2026-10-01, the replay runner's network fixture,
 * test-reorganization.md §6.7 and docs/testing/differential-interactive.md
 * §28) sends what the egress gate let out to a LOOPBACK test listener instead
 * of the internet, so a replay of a drill that names a real host
 * (`httpbin.org`, `example.com`) never leaves the machine and the listener
 * records the bytes that got through. Only a loopback address is accepted
 * (127.0.0.0/8, ::1, localhost). The gate runs first, unchanged; a route
 * changes only where an allowed request is dialed. Under MITM the body gate
 * still runs on the terminated request and only the re-origination dials the
 * route, over TLS that is still verified (against `tls_ca`, for the host's
 * name); without MITM the blind tunnel is pointed at it.
 *
 * This module is observability/test infrastructure, NOT on the security path: a
 * mocked response is treated EXACTLY like a real upstream response (classified +
 * symbolized by the proxy), so mocking cannot weaken the symbolization invariant.
 */

import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { isIP } from "node:net";
import yaml from "js-yaml";

/** A canned upstream response — structurally a proxy `ForwardedResponse`, so it
 *  plugs straight into the forward path where the real upstream would go. */
export interface MockResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

interface SiteConfig {
  url: string;
  status?: number;
  content_type?: string;
  body?: string;
  body_file?: string;
  /** Serve `body` for the FIRST request only; this from the second onward. */
  then_body?: string;
  then_status?: number;
}

/** A site entry: the first-response mock plus (optionally) the response every
 *  LATER request gets. `served` flips on the first match — per-instance state,
 *  which is per-scenario in the live suites (a fresh MockSites per run). */
interface SiteEntry {
  first: MockResponse;
  rest?: MockResponse;
  served: boolean;
}

/** Canonicalize a URL for matching: lowercase scheme+host, drop a single trailing
 *  slash (so `/x` and `/x/` match), drop the fragment, keep path + query. An
 *  unparseable string is matched literally. */
function normalizeUrl(u: string): string {
  try {
    const url = new URL(u);
    let path = url.pathname;
    if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
    return `${url.protocol.toLowerCase()}//${url.host.toLowerCase()}${path}${url.search}`;
  } catch {
    return u;
  }
}

/** A loopback address a host route dials. */
export interface MockDial {
  host: string;
  port: number;
}

/** A host's catch-all route: where its plaintext HTTP and its CONNECTs go;
 *  `tls.ca` is the PEM the MITM re-origination verifies the listener with. */
export interface MockRoute {
  http?: MockDial;
  tls?: MockDial & { ca?: string };
}

interface HostConfig {
  host?: unknown;
  to?: unknown;
  tls_to?: unknown;
  tls_ca?: unknown;
}

/** A route target: `127.0.0.1:<port>`, `[::1]:<port>` or `localhost:<port>`.
 *  Anything else throws (a route never points off the machine). */
export function parseLoopbackDial(v: unknown, where: string): MockDial {
  if (typeof v !== "string") throw new Error(`mock-sites: ${where} must be a "<loopback host>:<port>" string`);
  const m = /^(?:\[(::1)\]|(localhost|127(?:\.\d{1,3}){3})):(\d{1,5})$/.exec(v.trim());
  if (!m) throw new Error(`mock-sites: ${where} ${JSON.stringify(v)} is not a loopback address with a port (127.0.0.0/8, [::1] or localhost)`);
  const host = m[1] ?? m[2]!;
  if (host.startsWith("127.") && host.split(".").some((o) => Number(o) > 255)) {
    throw new Error(`mock-sites: ${where} ${JSON.stringify(v)} is not an IPv4 address`);
  }
  const port = Number(m[3]);
  if (!(port >= 1 && port <= 65535)) throw new Error(`mock-sites: ${where} ${JSON.stringify(v)} has no valid port`);
  return { host, port };
}

/** A host as matched: lower case, no trailing dot, no port, no brackets; an
 *  IPv6 address in its canonical text (`2001:DB8:0::1` → `2001:db8::1`). */
export function normalizeHost(h: string): string {
  let s = h.trim().toLowerCase();
  if (s.startsWith("[")) s = s.slice(1, s.indexOf("]") > 0 ? s.indexOf("]") : undefined);
  else if (/^[^:]+:\d+$/.test(s)) s = s.slice(0, s.lastIndexOf(":"));
  if (isIP(s) === 6 && !s.includes("%")) {
    try {
      return new URL(`http://[${s}]/`).hostname.slice(1, -1);
    } catch {
      /* as written */
    }
  }
  return s.replace(/\.$/, "");
}

export class MockSites {
  private constructor(
    private readonly map: Map<string, SiteEntry>,
    private readonly routes: Map<string, MockRoute> = new Map(),
  ) {}

  /** Number of configured sites. */
  get size(): number {
    return this.map.size;
  }

  /** Number of configured host routes. */
  get routeCount(): number {
    return this.routes.size;
  }

  /** Build from a YAML string. `body_file` paths resolve relative to `baseDir`
   *  (default cwd). Throws (fail loud) on a site missing url / body+body_file. */
  static fromYaml(yamlText: string, baseDir: string = process.cwd()): MockSites {
    const doc = (yaml.load(yamlText) ?? {}) as { sites?: SiteConfig[]; hosts?: unknown };
    const sites = Array.isArray(doc.sites) ? doc.sites : [];
    const map = new Map<string, SiteEntry>();
    for (const s of sites) {
      if (!s || typeof s.url !== "string" || s.url === "") {
        throw new Error("mock-sites: each site needs a non-empty 'url'");
      }
      let body: Buffer;
      if (typeof s.body === "string") {
        body = Buffer.from(s.body, "utf8");
      } else if (typeof s.body_file === "string") {
        const p = isAbsolute(s.body_file) ? s.body_file : join(baseDir, s.body_file);
        body = readFileSync(p);
      } else {
        throw new Error(`mock-sites: site '${s.url}' needs a 'body' or 'body_file'`);
      }
      const status = typeof s.status === "number" ? s.status : 200;
      const contentType = s.content_type ?? "text/html; charset=utf-8";
      const first: MockResponse = { status, headers: { "content-type": contentType }, body };
      let rest: MockResponse | undefined;
      if (typeof s.then_body === "string") {
        rest = {
          status: typeof s.then_status === "number" ? s.then_status : 200,
          headers: { "content-type": contentType },
          body: Buffer.from(s.then_body, "utf8"),
        };
      }
      map.set(normalizeUrl(s.url), { first, rest, served: false });
    }
    const hosts = doc.hosts;
    const routes = new Map<string, MockRoute>();
    if (hosts !== undefined && hosts !== null) {
      if (!Array.isArray(hosts)) throw new Error("mock-sites: 'hosts' must be a list");
      for (const h of hosts as HostConfig[]) {
        if (!h || typeof h.host !== "string" || h.host.trim() === "") throw new Error("mock-sites: each host route needs a non-empty 'host'");
        const name = normalizeHost(h.host);
        if (h.to === undefined && h.tls_to === undefined) throw new Error(`mock-sites: host route '${name}' needs 'to' or 'tls_to'`);
        if (routes.has(name)) throw new Error(`mock-sites: host route '${name}' is listed twice`);
        if (h.tls_ca !== undefined && (typeof h.tls_ca !== "string" || h.tls_to === undefined)) {
          throw new Error(`mock-sites: host route '${name}' tls_ca must be a file path, beside a tls_to`);
        }
        const ca = typeof h.tls_ca === "string" ? readFileSync(isAbsolute(h.tls_ca) ? h.tls_ca : join(baseDir, h.tls_ca), "utf8") : undefined;
        routes.set(name, {
          ...(h.to !== undefined ? { http: parseLoopbackDial(h.to, `host route '${name}' to`) } : {}),
          ...(h.tls_to !== undefined ? { tls: { ...parseLoopbackDial(h.tls_to, `host route '${name}' tls_to`), ...(ca !== undefined ? { ca } : {}) } } : {}),
        });
      }
    }
    return new MockSites(map, routes);
  }

  /** Build from a YAML file; `body_file` paths resolve relative to the file's dir. */
  static fromFile(path: string): MockSites {
    return MockSites.fromYaml(readFileSync(path, "utf8"), dirname(path));
  }

  /** The canned response for `absoluteUrl`, or null if no site matches. The Buffer
   *  is shared (callers must not mutate it). For a site with `then_body`, the
   *  FIRST match serves `body` and every later match serves `then_body` — the
   *  transient-failure fixture retry scenarios need (per-instance state; the
   *  live suites build one MockSites per scenario run). */
  match(absoluteUrl: string): MockResponse | null {
    const entry = this.map.get(normalizeUrl(absoluteUrl));
    if (!entry) return null;
    if (entry.rest && entry.served) return entry.rest;
    entry.served = true;
    return entry.first;
  }

  /** Whether a site serves `absoluteUrl` (no side effect: `match` advances a
   *  `then_body` site, this does not). */
  has(absoluteUrl: string): boolean {
    return this.map.has(normalizeUrl(absoluteUrl));
  }

  /** The catch-all route of `host` (`host` or `host:port`, any case): its
   *  own, else the `*` route, else null. An exact site (match) is served
   *  before a route is consulted. A model host is never routed by `*`
   *  (`routeOf`), and only under the model-host deny at all. */
  route(host: string): MockRoute | null {
    return this.routes.get(normalizeHost(host)) ?? this.routes.get("*") ?? null;
  }

  /** The route naming `host` itself, never the `*` one: a model host that
   *  the proxy gates under the model-host deny (proxy.ts) is routed only by
   *  a route that names it. */
  routeOf(host: string): MockRoute | null {
    return this.routes.get(normalizeHost(host)) ?? null;
  }
}
