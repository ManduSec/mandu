/**
 * server/options — the DashboardServer's constructor options and the tenant
 * surface types (moved out of server.ts, which re-exports them; the pre-split
 * public API is unchanged). Types only: no runtime code lives here.
 */

import { type EventSource } from "../event-source.js";
import { type Supervisor } from "../supervisor/supervisor.js";
import { type DashboardSelfStatus } from "../self-status.js";
import { type ProbeDeps } from "../model-probe.js";
import { type AssistantModel } from "../policy-assistant.js";
import { type ApprovalsArbiter } from "./approval-routes.js";
import { type SecretsArbiter } from "./secrets-routes.js";
import { type PostureArbiter } from "./arbiter-surfaces.js";
import { type ConfigAuditArbiter } from "./config-axes-routes.js";
import { type PolicyDocArbiter } from "./policy-doc-routes.js";
import { type DashboardExtension } from "./extension.js";
import { type AccountFile } from "../account.js";

export interface DashboardServerOptions {
  source: EventSource;
  /** The PRODUCT front-end (dashboard.md §4.25), served at `/`: index.html +
   *  app.css + js/. Defaults to ../public. */
  publicDir?: string;
  /** The front-ends beyond the product (server/extension.ts, §4.25ac), each
   *  owning its mount: the developer view at `/dev/` where the build carries
   *  it (server-main loads it, extension-loader.ts). Default none: the
   *  product only. */
  extensions?: DashboardExtension[];
  /** Reverse-proxy URL prefix (e.g. "/mandu"), no trailing slash. */
  basePath?: string;
  /**
   * Control plane: the process supervisor for arbiter + Track-A proxies. When
   * provided, the `/api/control/*` routes are enabled; when undefined those
   * routes answer 404 `{error:"control plane disabled"}`. The dashboard reaps
   * the supervised children on close() (Supervisor.close: shutdownAll, and
   * no spawn after it).
   */
  supervisor?: Supervisor;
  /**
   * Egress-approval queue: the narrow arbiter surface backing the interactive
   * `/api/egress/approvals*` routes. When provided, those routes list pending
   * approvals and apply approve/deny verdicts; when undefined they answer 404
   * `{error:"arbiter not connected"}`. Injected by server-main when
   * MANDU_ARBITER_SOCK is set; the tests pass an in-memory fake.
   */
  approvalsArbiter?: ApprovalsArbiter;
  /** Arbiter surface for the confidentiality panel (`GET /api/secrets` — the
   *  standing release surface, confidentiality.md §6). Absent → 404. */
  secretsArbiter?: SecretsArbiter;
  /** Arbiter surface for the Protection drawer's egress pause/resume
   *  (`POST /api/policy/posture`, dashboard.md §4.19). Absent → 404
   *  "arbiter not connected", exactly like the approvals/secrets surfaces. */
  postureArbiter?: PostureArbiter;
  /** Arbiter surface for the §4.19 config_change audit trail (emit on an
   *  applied axis write + the GET-side who/when attribution). UNLIKE the
   *  surfaces above, absence degrades nothing but the audit: the config
   *  routes answer in full without it (best-effort observability, never on
   *  the act's path). */
  auditArbiter?: ConfigAuditArbiter;
  /** Arbiter surface for the policy DOCUMENT routes (`/api/policy/document`,
   *  `/api/policy/rules`, `/api/policy/export-labels`; policy-surface.md
   *  §2.1 stage 5a). Absent → 404 "arbiter not connected". Writes ride the
   *  admin channel (server-main); an adopted arbiter answers 503. */
  policyDocArbiter?: PolicyDocArbiter;
  /** TEST SEAM for "Describe what you want" (policy-surface.md §8.5.2):
   *  the quarantined model factory. Default: inspect-mcp's U-LLM selector
   *  (api / cli, never the proxy); no channel ⇒ the route answers 503. */
  assistantModel?: () => Promise<AssistantModel>;
  /** TEST SEAM for Settings › Models "Test connection" (dashboard.md §4.25l):
   *  the TCP connect and the model listing. Default: real sockets, 3 s. */
  modelProbeDeps?: ProbeDeps;
  /**
   * TEST SEAM for the /api/config/axes routes: the env the config-path
   * resolution reads (`<MANDU_HOME or ~/.mandu>/config.toml` — the
   * launcher's rule, see src/config-axes.ts), and that `/api/home` and
   * `/api/data-locations` (MANDU_HOME / HOME, src/data-locations.ts) read.
   * Default: process.env.
   */
  configEnv?: Record<string, string | undefined>;
  /**
   * Is Mandu running at all (mandu-running.ts `manduNotRunning`)? Asked by
   * Home when the live tenant's session list cannot be read, so a computer
   * where nothing of Mandu's runs (the person only ran `mandu scan`) reads
   * "Protection is off: no agent runs with Mandu." rather than "Not
   * connected." (dashboard.md §4.25, the verdict ladder). server-main
   * passes the probe over its arbiter socket, runtime base and event store.
   * Absent: never asked, so an unreadable list is "Not connected.".
   */
  manduNotRunning?: () => { everRan: boolean } | null;
  /**
   * Source-IP allowlist for NON-loopback clients (server-main resolves
   * DASHBOARD_ALLOW_HOSTS to this). Loopback is always allowed; any other
   * client address must appear here or the request is answered 403 — so a
   * non-loopback bind without an allowlist FAILS CLOSED (nothing remote gets
   * in). Entries are IP literals; IPv4-mapped IPv6 forms are normalized.
   */
  allowedClientIps?: string[];
  /**
   * Host names this dashboard answers to besides loopback at its bound port
   * (the Host check, dashboard.md §6: a web page that rebinds its own name
   * to this host is refused before any route). `name` admits any port,
   * `name:port` one. server-main sets it from DASHBOARD_ALLOW_HOSTS and
   * DASHBOARD_SERVER_NAMES (the name a front or tunnel forwards).
   */
  allowedHosts?: string[];
  /**
   * TEST SEAM: the admin token (policy-surface.md §2.6). Its cookie
   * ({@link DashboardServer.adminCookie}, also set by
   * `<basePath>/login?token=<adminToken>`) is an admin session. A person
   * signs in with the dashboard account (`account`); the token is for
   * tests: a server built without an account takes the cookie, and one
   * with an account only when `pinnedAdminToken` says the token was pinned.
   * Defaults to a random per-boot token nobody is told.
   */
  adminToken?: string;
  /**
   * TEST SEAM: the admin token was pinned (server-main: DASHBOARD_ADMIN_TOKEN,
   * which the suites set). Its cookie and its `/login?token=` then pass the
   * sign-in gate. Off by default; a deployment never sets it (the token is
   * in the dashboard's environment, which a same-uid process can read).
   */
  pinnedAdminToken?: boolean;
  /**
   * Trust an authenticating reverse proxy: a NON-loopback client that already
   * passed the source-IP allowlist (the OAuth front) counts as an admin session
   * without the cookie. Loopback clients — the agent's path — always need it.
   * Off by default; server-main sets it from DASHBOARD_TRUST_FRONT=1.
   */
  trustFront?: boolean;
  /**
   * A username and password held in memory (dashboard.md §6.z): the sign-in
   * gate's credentials while no dashboard account file exists. EVERY
   * request past the Host check needs a sign-in session (the sign-in page,
   * `POST <base>/login`) or the pair as an `Authorization: Basic` header;
   * anything else gets the sign-in page or a 401, never a
   * `WWW-Authenticate` challenge. Either IS the admin session. server-main
   * sets it from DASHBOARD_BASIC_AUTH="user:password" only when the pair
   * could not be moved into the account file (a home that cannot hold it);
   * tests set it directly.
   */
  basicAuth?: { user: string; password: string };
  /**
   * The Mandu dashboard account (account.ts; dashboard.md §6.z): the
   * path table's `dashboard-account` file, holding a username and a scrypt
   * hash. With it set, EVERY request past the Host check needs a
   * sign-in session (the sign-in page, `POST <base>/login`) or the account's
   * credentials in an `Authorization: Basic` header; anything else gets the
   * sign-in page (a browser navigation) or a 401, with no `WWW-Authenticate`
   * (no native prompt). A file that is there but cannot be used (wrong
   * owner or mode, a link, not a record) signs nobody in. Read per request,
   * so `mandu dashboard --set-password` applies at once. No file yet: FAIL
   * CLOSED, the page says "no account yet" and how to make one, and nothing
   * else is served. The account wins over `basicAuth` (which then only
   * stands in while no file exists). server-main always passes it; a test
   * that passes none gets a server with no sign-in gate.
   */
  account?: AccountFile;
  /** TEST SEAM: the clock of the sign-in sessions and the throttle. */
  signInClock?: () => number;
  /**
   * TEST SEAM: the folder `~` means on the product pages: the Rules page's
   * file browser (dashboard.md §4.25m), the paths in an agent page's Your
   * secrets (§4.25b), and every other path the pages show, served with the
   * page as its `home-dir` (§4.34 "`~` is the dashboard's home"). Production
   * leaves it unset: the dashboard runs as the person, and `os.homedir()` is
   * their HOME.
   */
  fileBrowserHome?: string;
  /**
   * TEST SEAM: how long `POST /api/suggestions/scan` waits for the scan
   * before it answers "still scanning" (dashboard.md §4.25r). Production
   * leaves it unset (SCAN_WAIT_MS); the scan goes on either way.
   */
  suggestScanWaitMs?: number;
  /**
   * Plan 14 §14.6, §14.11 (dashboard.md §4.25t): is the Suggested view's
   * model picker offered? Default: MANDU_EXPERIMENTAL_POLICY_MODEL=1 in this
   * process's environment. TEST SEAM for the routes' tests.
   */
  policyModelOffered?: boolean;
  /**
   * TEST SEAM: pin the per-process secret the session cookie is derived from
   * (`sha256((password || adminToken) + sessionSecret)`), so a suite can
   * precompute the admin cookie once for every server it starts. Production
   * never sets it — the secret is random per boot.
   */
  sessionSecret?: string;
  /**
   * The TEST tenant (policy-surface.md §2.7 1c): a second event source
   * + arbiter surfaces over the test-tenant arbiter. Every request is served for
   * ONE tenant — `?tenant=` wins, else the `mandu_tenant` cookie, else live —
   * so the sidebar, trace, Approvals, Policy, secrets and posture all follow the
   * chosen tenant with no per-route plumbing in the page. Absent → the
   * dashboard advertises the live tenant alone (`GET /api/tenants`), an
   * explicit `?tenant=test` answers 404, and a stale test cookie falls back to
   * live rather than blanking the page.
   */
  testTenant?: TenantSurfaces;
  log?: (msg: string) => void;
}

/** Which of the two stores a request is served from (§2.7). */
export type Tenant = "live" | "test";

/** The per-tenant surfaces: one event source + the arbiter-backed surfaces the
 *  routes late-bind (set-once, like the live ones). */
export interface TenantSurfaces {
  source: EventSource;
  approvalsArbiter?: ApprovalsArbiter;
  secretsArbiter?: SecretsArbiter;
  postureArbiter?: PostureArbiter;
  auditArbiter?: ConfigAuditArbiter;
  policyDocArbiter?: PolicyDocArbiter;
}

export interface TenantState {
  source: EventSource;
  approvalsArbiter?: ApprovalsArbiter;
  secretsArbiter?: SecretsArbiter;
  postureArbiter?: PostureArbiter;
  auditArbiter?: ConfigAuditArbiter;
  policyDocArbiter?: PolicyDocArbiter;
}

/**
 * The dashboard's self-control surface (self-status.ts backs status(); server-
 * main backs restart()). Narrow on purpose — the route layer only ever reads a
 * status snapshot and pulls the restart trigger.
 */
export interface DashboardSelfControl {
  status(): DashboardSelfStatus;
  restart(): void;
}
