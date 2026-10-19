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
import { type SignInTickets } from "../sign-in.js";
import { type DashboardExtension } from "./extension.js";

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
  /** Basic-Auth password; empty/undefined disables auth. */
  password?: string;
  /** Reverse-proxy URL prefix (e.g. "/mandu"), no trailing slash. */
  basePath?: string;
  /**
   * Control plane: the process supervisor for arbiter + Track-A proxies. When
   * provided, the `/api/control/*` routes are enabled; when undefined those
   * routes answer 404 `{error:"control plane disabled"}`. The dashboard reaps
   * the supervised children on close() (shutdownAll).
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
   * ADMIN SESSION for mutating routes without DASHBOARD_PASSWORD
   * (policy-surface.md §2.6). Every POST/DELETE needs a browser
   * session, established by a one-time sign-in link (`signInTickets`, the
   * default way) or by opening `<basePath>/login?token=<adminToken>` once
   * — the link server-main prints when its stderr is a terminal. The token lives in
   * this process and the browser cookie only (never on disk), so a same-uid
   * agent process cannot read it the way it could read a file or /proc
   * environ. A read that can carry a value needs it too (server/read-gate.ts,
   * dashboard.md §6). Defaults to a random per-boot token;
   * tests pass a fixed one and send {@link DashboardServer.adminCookie}.
   * With a password set, the password session IS the admin session.
   */
  adminToken?: string;
  /**
   * The one-time sign-in tickets (sign-in.ts; policy-surface.md §2.6
   * "Signing in"): minted over the human-plane sign-in socket, redeemed by
   * `GET <basePath>/login?ticket=…`. TEST SEAM (a clock, a fixed ticket);
   * production leaves it unset and the server keeps its own.
   */
  signInTickets?: SignInTickets;
  /**
   * Trust an authenticating reverse proxy: a NON-loopback client that already
   * passed the source-IP allowlist (the OAuth front) counts as an admin session
   * without the cookie. Loopback clients — the agent's path — always need it.
   * Off by default; server-main sets it from DASHBOARD_TRUST_FRONT=1.
   */
  trustFront?: boolean;
  /**
   * HTTP Basic auth (RFC 7617) for a front that speaks only HTTP, such as a
   * tunnel (dashboard.md §6.z). When set, EVERY request past the source-IP gate must carry a valid
   * `Authorization: Basic` header or is answered 401 with a challenge (no
   * login page, no app detail). Valid credentials ARE the admin session
   * (the browser resends them on every same-origin fetch/EventSource), so the
   * dashboard is fully usable through the tunnel without the cookie. A
   * same-host process the agent runs cannot present them: they live in this
   * process (and the operator's browser), never on disk. server-main sets it
   * from DASHBOARD_BASIC_AUTH="user:password".
   */
  basicAuth?: { user: string; password: string };
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
