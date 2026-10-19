/**
 * server/read-gate — which dashboard READS may carry a real value, and the
 * Host check that runs before every route (dashboard.md §6, "Reads and the
 * admin session"). Mandu-new (no reference origin).
 *
 * WHY. A GET reaches the dashboard from any process on this host: the
 * source-IP gate admits loopback, and loopback is also the path a program the
 * agent runs would take. Until 2026-10-05 every read was open, so such a
 * program could read the raw tool output, the reply the human saw and the
 * HumanView files, every secret value in them. Now a read that can carry a
 * value needs the ADMIN SESSION (the cookie a one-time sign-in link sets, a
 * password session, Basic-auth credentials, or an authenticating front), and
 * without it the dashboard serves what the AI saw and nothing else.
 *
 * THE TABLE. Every GET under `/api/` is listed in {@link READ_ROUTES} with
 * its access:
 *   - `open`: metadata only (ids, names, paths, counts, rules, statuses);
 *   - `projection`: served to everyone, its values only to the admin session
 *     (the route itself takes `values` and leaves them out otherwise);
 *   - `admin`: nothing to show without the session (a log, a run's output,
 *     a recorded run's files): 403 before the route runs.
 * A GET under `/api/` that no entry names is `admin` (fail closed), so a new
 * route cannot slip in open: a unit test walks server.ts for every route and
 * fails on one the table does not name (read-gate.test.ts).
 *
 * THE VIEWER. `values` is the admin session AND a same-origin request: the
 * `X-Mandu-Control` header (what a fetch from the pages sends, as every
 * mutating route needs) or `Sec-Fetch-Site: same-origin | none` (what a
 * browser sends on its own, the only way an EventSource can say it).
 *
 * THE HOST CHECK (DNS rebinding). A web page the human opens could rebind
 * its own name to 127.0.0.1 and read the dashboard as the same origin. The
 * `Host` header is the one thing such a page cannot choose, so every request
 * must name a loopback host at the bound port, or a name the operator
 * configured (DASHBOARD_ALLOW_HOSTS, DASHBOARD_SERVER_NAMES), before any
 * route runs.
 */

import { type IncomingHttpHeaders } from "node:http";
import { networkInterfaces } from "node:os";

export type ReadAccess = "open" | "projection" | "admin";

export interface ReadRoute {
  /** The exact path, or a pattern over it (after the base path is stripped). */
  path: string | RegExp;
  access: ReadAccess;
  /** Why this access: what the route serves. */
  why: string;
}

/**
 * Every GET under `/api/` the product's server answers (an extension
 * brings its own rows: the inspector's are INSPECTOR_READ_ROUTES). Keep it
 * in step with server.ts (read-gate.test.ts checks both ways). Order matters only where patterns
 * overlap: the first match wins.
 */
export const READ_ROUTES: readonly ReadRoute[] = [
  // ── sessions and their records ──
  { path: "/api/sessions", access: "open", why: "the session list: ids, agents, times, counts; no event payload" },
  { path: "/api/events", access: "projection", why: "a session's events: originals, symbol values and HumanView files only with the session" },
  { path: "/api/stream", access: "projection", why: "a session's live events, projected like /api/events" },
  { path: "/api/home", access: "open", why: "the product home: counts, asks (names and destinations), agents" },
  { path: "/api/home/agent", access: "projection", why: "the product's per-agent page: originals only with the session" },
  { path: "/api/home/history", access: "open", why: "the product's History page: every session's agent, prompt label, times and counts (as /api/sessions and /api/home); no event payload" },
  { path: "/api/home/answered", access: "open", why: "Approvals' earlier answers past the newest 20: the asks' names and destinations, as /api/home carries the newest 20" },
  { path: "/api/home/original", access: "admin", why: "one step's whole original behind its mask: a value" },
  { path: "/api/data-locations", access: "open", why: "where Mandu keeps its files (stat only)" },
  { path: "/api/tenants", access: "open", why: "the tenant names" },
  // ── rules and decisions ──
  { path: "/api/policy/panel", access: "open", why: "posture, the approval queue (names, paths, destinations), rule catalog" },
  { path: "/api/policy/by-who", access: "open", why: "the rules read per program, host and AI: paths, names and hosts, never a value" },
  { path: "/api/policy/rules/source", access: "open", why: "a rule's lines of policy.yaml (rules, never a value)" },
  { path: "/api/policy/rules/origins", access: "open", why: "who put each rule there" },
  { path: "/api/policy/proposals", access: "open", why: "rule changes the agent asked for; a pattern only with the session (adminRead)" },
  { path: "/api/policy/changes", access: "open", why: "rule-change history; a pattern only with the session (adminRead)" },
  { path: "/api/policy/prompt-filters", access: "admin", why: "prompt-filter exceptions may hold the person's words" },
  { path: "/api/policy/sensitivity-labels", access: "admin", why: "what the last scan found" },
  { path: "/api/prompt-filters/holds", access: "admin", why: "the found text of a held message" },
  { path: "/api/files/list", access: "admin", why: "the file browser: names the person's files" },
  { path: "/api/files/why", access: "admin", why: "the file browser's answer for one file" },
  { path: "/api/suggestions", access: "admin", why: "paths where keys were found" },
  { path: "/api/secrets", access: "open", why: "registered secret names and labelled paths; never a value" },
  { path: "/api/egress/approvals", access: "open", why: "the approval queue: names, destinations, statuses" },
  { path: "/api/config/axes", access: "open", why: "the protection mode in config.toml" },
  // ── the control plane ──
  { path: "/api/control/summary", access: "open", why: "the services' state in one line" },
];

/** The entry naming `urlPath`, or null when none does. `routes`: the
 *  table, the product's (READ_ROUTES) and each extension's rows after it
 *  (server/extension.ts `readRoutes`). */
export function readRouteOf(urlPath: string, routes: readonly ReadRoute[] = READ_ROUTES): ReadRoute | null {
  for (const r of routes) {
    if (typeof r.path === "string" ? r.path === urlPath : r.path.test(urlPath)) return r;
  }
  return null;
}

/** The access of a GET under `/api/` (`urlPath` without the query). A path
 *  no entry names is `admin`: a new route is gated until it is listed. */
export function readAccessOf(urlPath: string, routes: readonly ReadRoute[] = READ_ROUTES): ReadAccess {
  return readRouteOf(urlPath, routes)?.access ?? "admin";
}

/** Whether a request came from a page of this dashboard rather than another
 *  site: the CSRF header a fetch from our pages sends, or the browser's own
 *  `Sec-Fetch-Site` saying same-origin (or a navigation the person typed).
 *  A client without either (curl, a test) holds the cookie only if the person
 *  gave it to it, so the cookie decides; such a client sends the header. */
export function sameOriginRead(headers: IncomingHttpHeaders): boolean {
  if (headers["x-mandu-control"] !== undefined) return true;
  const site = headers["sec-fetch-site"];
  return site === "same-origin" || site === "none";
}

// ── the Host check ───────────────────────────────────────────────────────────

/** Split a Host header into a lower-cased name and its port (null when the
 *  header names none). `[::1]:4500` → `::1`, 4500. Null for a malformed one. */
export function parseHostHeader(host: string | undefined): { name: string; port: number | null } | null {
  if (host === undefined) return null;
  const h = host.trim().toLowerCase();
  if (h === "") return null;
  let name: string;
  let rest: string;
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    if (end < 0) return null;
    name = h.slice(1, end);
    rest = h.slice(end + 1);
  } else {
    const i = h.lastIndexOf(":");
    if (i >= 0 && h.indexOf(":") === i) {
      name = h.slice(0, i);
      rest = h.slice(i);
    } else if (i >= 0) {
      return null; // a bare IPv6 literal without brackets is not a Host
    } else {
      name = h;
      rest = "";
    }
  }
  if (name === "" || !/^[a-z0-9.\-_:]+$/.test(name)) return null;
  if (rest === "") return { name, port: null };
  if (!/^:[0-9]{1,5}$/.test(rest)) return null;
  const port = Number(rest.slice(1));
  return port > 0 && port < 65536 ? { name, port } : null;
}

/** A loopback name or address: `localhost`, 127.0.0.0/8, ::1. */
export function isLoopbackName(name: string): boolean {
  return name === "localhost" || name === "::1" || /^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(name);
}

/**
 * Whether a request's Host names this dashboard. Allowed: a loopback name
 * at the bound port (no port only when bound to 80), the bound address or
 * one of this host's own interface addresses at that port (an address is
 * never a rebound name: a page reached by IP has that IP as its origin), or
 * an operator-configured name at any port (`name`) or one port
 * (`name:port`). Everything else, a missing Host included, is refused: that
 * is a page that rebound its own name to this host.
 */
export function hostAllowed(
  hostHeader: string | undefined,
  boundPort: number | null,
  boundAddress: string | null,
  extraNames: readonly string[],
  hostAddresses: ReadonlySet<string> = new Set(),
): boolean {
  const h = parseHostHeader(hostHeader);
  if (!h) return false;
  const port = h.port ?? 80;
  for (const raw of extraNames) {
    const e = parseHostHeader(raw);
    if (!e) continue;
    if (e.name === h.name && (e.port === null || e.port === port)) return true;
  }
  // Before listen() there is no bound port: nothing is served then anyway.
  if (boundPort === null) return false;
  if (port !== boundPort) return false;
  if (isLoopbackName(h.name)) return true;
  if (hostAddresses.has(h.name)) return true;
  const bound = (boundAddress ?? "").toLowerCase();
  return bound !== "" && bound !== "0.0.0.0" && bound !== "::" && h.name === bound;
}

/** This host's interface addresses, lower-cased (the Host check's own
 *  addresses). */
export function interfaceAddresses(): Set<string> {
  const out = new Set<string>();
  for (const list of Object.values(networkInterfaces())) {
    for (const i of list ?? []) out.add(i.address.toLowerCase().replace(/%.*$/, ""));
  }
  return out;
}
