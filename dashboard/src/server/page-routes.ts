/**
 * server/page-routes — the dashboard's page URL table (dashboard.md §4.25v,
 * "URL scheme"). Both front-ends route by PATH (History API, one index.html
 * per front-end); this module decides, for a GET/HEAD path already stripped
 * of the base path, whether it is a page of the product (`/`) or of the
 * developer view (`/dev/`, §4.32), and maps the retired query-string page
 * URLs (`/?page=inbox&ask=…`, `/dev/?area=…&session=…`) and a renamed page's
 * old path (`/dev/status`, `/dev/policy`, `/dev/inbox`) to their path form
 * so a bookmark keeps working through a 302.
 *
 * Pure: no I/O, no server state. The client builds the same URLs
 * (public/js/home.js `routeHref`, dev/js/pages.js `devHref`); the
 * component test two-front-ends.test.ts walks every route the client builds
 * through the real server.
 */

/** The product's page paths. A `<seg>` is ONE non-empty path segment, a
 *  well-formed percent-encoding (the client writes it with
 *  encodeURIComponent). Anything else is not a page: it falls through to the
 *  static files, which answer 404. */
const PRODUCT_FIXED = new Set(["/", "/index.html", "/approvals", "/rules", "/settings", "/history", "/scan"]);
const PRODUCT_PARAM = ["/approvals/", "/agents/"];

/** The developer view's pages (dev/js/pages.js PAGES, dashboard.md §4.32):
 *  one nav row, six pages. Sessions, Drills and Tests list sessions and take
 *  a session segment; Drills and Tests also have sub-pages, whose names are
 *  reserved (`/dev/tests/ci` is the CI page, never a session called "ci"). */
export const INSPECTOR_PAGES = ["sessions", "drills", "tests", "approvals", "rules", "settings"] as const;
export const INSPECTOR_SESSION_PAGES = ["sessions", "drills", "tests"] as const;
export const INSPECTOR_SUBPAGES: Readonly<Record<string, readonly string[]>> = { drills: ["matrix", "agents", "comparison", "videos"], tests: ["suites", "coverage", "vm", "ci"] };
/** Renamed pages: old key → new (dev/js/pages.js PAGE_ALIASES). Approvals was
 *  Inbox until 2026-10-02; Status became Sessions and Policy became Rules on
 *  2026-10-03 (the one-nav redesign, §4.32). Each old path and `?area=` value
 *  is a 302 to the new one. */
export const INSPECTOR_PAGE_ALIASES: Readonly<Record<string, (typeof INSPECTOR_PAGES)[number]>> = {
  status: "sessions",
  policy: "rules",
  inbox: "approvals",
};
const own = (o: object, k: string | null): k is string => k !== null && Object.prototype.hasOwnProperty.call(o, k);
const canonicalPage = (a: string | null): string | null => (own(INSPECTOR_PAGE_ALIASES, a) ? INSPECTOR_PAGE_ALIASES[a]! : a);
const INSPECTOR_FIXED = new Set([
  "/dev/",
  "/dev/index.html",
  ...INSPECTOR_PAGES.map((p) => `/dev/${p}`),
  ...Object.entries(INSPECTOR_SUBPAGES).flatMap(([p, subs]) => subs.map((s) => `/dev/${p}/${s}`)),
]);
const INSPECTOR_PARAM = INSPECTOR_SESSION_PAGES.map((p) => `/dev/${p}/`);

/** One path segment: non-empty, no `/`, and a percent-encoding that decodes. */
function validSegment(seg: string): boolean {
  if (seg === "" || seg.includes("/")) return false;
  try {
    decodeURIComponent(seg);
    return true;
  } catch {
    return false;
  }
}

function matches(urlPath: string, fixed: Set<string>, param: string[]): boolean {
  if (fixed.has(urlPath)) return true;
  return param.some((p) => urlPath.startsWith(p) && validSegment(urlPath.slice(p.length)));
}

/** Which front-end's index.html serves this (base-stripped) path, if any. */
export function pageFor(urlPath: string): "product" | "inspector" | null {
  if (matches(urlPath, PRODUCT_FIXED, PRODUCT_PARAM)) return "product";
  if (matches(urlPath, INSPECTOR_FIXED, INSPECTOR_PARAM)) return "inspector";
  return null;
}

const enc = encodeURIComponent;

/** The query left after the route's own keys move into the path. */
function rest(q: URLSearchParams, drop: string[]): URLSearchParams {
  const out = new URLSearchParams();
  for (const [k, v] of q) if (!drop.includes(k)) out.append(k, v);
  return out;
}
const withQuery = (path: string, q: URLSearchParams): string => {
  const s = q.toString();
  return s ? `${path}?${s}` : path;
};

/**
 * The path form of a retired page URL, or null when the URL is not one
 * (already a current path URL, or carries none of the retired keys). Paths
 * are base-stripped in and out; the caller prefixes the base path.
 *
 *   /?page=inbox[&ask=A]               → /approvals[/A]
 *   /?page=rules | settings            → /rules | /settings
 *   /?page=agent&session=S[&ask=A]     → /agents/S[?ask=A]
 *   /?page=home | agent (no session) | unknown → /
 *   /dev/?session=S                    → /dev/sessions/S
 *   /dev/?area=status[&session=S]      → /dev/sessions | /dev/sessions/S
 *   /dev/?area=X[&session=S]           → /dev/X[?session=S]   (X another page)
 *   /dev/?area=policy | inbox [&…]     → /dev/rules | /dev/approvals [?session=S]
 *   /dev/?area=unknown[&session=S]     → as area=status (what the inspector did)
 *   /dev/status | policy | inbox[?…]   → /dev/sessions | rules | approvals[?…]
 *
 * A session URL for a drill, replay or test session (/dev/sessions/<id>)
 * stays a page here: the server does not look sessions up to route. The
 * client moves it to /dev/drills/<id> or /dev/tests/<id> once the session
 * list says which group the session is in (app.js followSessionPage).
 *
 * Every other query key (e.g. `tenant`) rides along unchanged.
 */
export function legacyRedirect(url: string): string | null {
  const qi = url.indexOf("?");
  const path = qi < 0 ? url : url.slice(0, qi);
  const query = qi < 0 ? "" : url.slice(qi + 1);
  // A renamed page's old path: the new path, the query as it was.
  if (path.startsWith("/dev/")) {
    const seg = path.slice("/dev/".length);
    if (own(INSPECTOR_PAGE_ALIASES, seg)) {
      const renamed = INSPECTOR_PAGE_ALIASES[seg];
      return query ? `/dev/${renamed}?${query}` : `/dev/${renamed}`;
    }
  }
  if (qi < 0) return null;
  const q = new URLSearchParams(query);
  if ((path === "/" || path === "/index.html") && q.has("page")) {
    const page = q.get("page");
    const ask = q.get("ask");
    const session = q.get("session");
    const left = rest(q, ["page", "ask", "session"]);
    if (page === "inbox" || page === "approvals") return withQuery(ask ? `/approvals/${enc(ask)}` : "/approvals", left);
    if (page === "rules" || page === "settings") return withQuery(`/${page}`, left);
    if (page === "agent" && session) {
      if (ask) left.set("ask", ask);
      return withQuery(`/agents/${enc(session)}`, left);
    }
    return withQuery("/", left);
  }
  if ((path === "/dev" || path === "/dev/" || path === "/dev/index.html") && (q.has("area") || q.has("session"))) {
    const page = canonicalPage(q.get("area") || null);
    const session = q.get("session");
    const left = rest(q, ["area", "session"]);
    if (page !== null && page !== "sessions" && (INSPECTOR_PAGES as readonly string[]).includes(page)) {
      if (session) left.set("session", session);
      return withQuery(`/dev/${page}`, left);
    }
    // No area (the persisted page applies), status, or an unknown area (the
    // inspector fell back to Status): the session, or the Sessions page.
    if (session) return withQuery(`/dev/sessions/${enc(session)}`, left);
    return withQuery(page === null ? "/dev/" : "/dev/sessions", left);
  }
  return null;
}
