/**
 * server — the Mandu dashboard HTTP server (static UI + REST + SSE).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   The static-serving, cookie-session Basic-Auth (DASHBOARD_PASSWORD), and
 *   base-path handling are ADAPTED from
 *     https://github.com/compsec-snu/dualview/blob/main/dashboard/server.ts
 *   Adaptation (dashboard.md §5 reuse table): the reference scans OpenClaw
 *   `log-sessions/` dirs; this server instead reads the canonical ManduEvent
 *   stream through an `EventSource` (FileEventSource now, ArbiterEventSource in
 *   Wave 3), exposes REST `/api/sessions` + `/api/events`, and adds an SSE
 *   `/api/stream` endpoint (NEW; §3.1) — an upgrade over the reference's
 *   setInterval polling. The observability surface is READ-ONLY.
 *
 * MUTATING ROUTES: the trace itself is read-only, but the dashboard has since
 * grown the surfaces where a HUMAN decides — the egress-approval verdicts
 * (/api/egress/approvals/<id>/{approve,deny}), the service control plane
 * (/api/control/*), the agent/test runners, and the confidentiality LABELING act
 * (/api/secrets/label, confidentiality.md §6). EVERY one of them is gated by
 * `requireCsrf`: a human decision must come from this page, not from a
 * cross-origin page forging a request at a dashboard the user has open.
 *
 * Security posture (dashboard.md §6): the dashboard reveals symbol→original, so
 * it binds to loopback by default (server-main, since 2026-09-25) and sits
 * behind optional DASHBOARD_PASSWORD / DASHBOARD_BASIC_AUTH auth. It must never
 * be reachable by the monitored agent or an untrusted network. When bound wider
 * than loopback (server-main's DASHBOARD_HOST, e.g. to sit behind a trusted
 * reverse proxy — which server-main refuses without an authenticator), a
 * FAIL-CLOSED source-IP gate admits only loopback plus the explicit
 * {@link DashboardServerOptions.allowedClientIps} allowlist (empty by default)
 * — every other client is answered 403 before any route (even /login) runs.
 *
 * READS (2026-10-05, dashboard.md §6, server/read-gate.ts): a GET under
 * /api/ that can carry a real value needs the admin session too. Loopback is
 * also where a program the agent runs comes from, so a read without the
 * session gets what the AI saw (the signed-out projection) or a 403. Every
 * request must name this dashboard in its Host header (DNS rebinding).
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { json, readBody, requireCsrf } from "./server/http-util.js";
import { isDevPagePath, redirectTo, serveDevAbsent, serveIndex, serveStatic } from "./server/static-routes.js";
import { type DashboardExtension, type ExtensionHost, type SessionRuns, extensionFor } from "./server/extension.js";
import { legacyRedirect, pageFor } from "./server/page-routes.js";
import { apiHome, apiHomeAgent, apiHomeAnswered, apiHomeHistory, apiHomeOriginal, HomeFacts, readFirstLookup, recentWorkspaces } from "./server/home-routes.js";
import { labelTimesArbiter, type LabelTimesArbiter } from "./server/label-times.js";
import { getSuggestions, postApply as postSuggestionApply, postDismiss as postSuggestionDismiss, postModelPreview, postModelSend, postScan as postSuggestionScan, type SuggestionRouteDeps } from "./server/suggestion-routes.js";
import { buildDataLocations, homeOf } from "./data-locations.js";
import { apiSessions, apiPolicyPanel, apiEvents, apiStream } from "./server/api-routes.js";

// Re-exported so importers keep reading it from server.js (the
// pre-decomposition public API).
export { DEFAULT_EVENT_LIMIT } from "./server/api-routes.js";
import { getFileList, getFileWhy, postFileImpact, postFileLabels, postMovePageRules } from "./server/file-browser-routes.js";
import { isServiceId, controlDisabled, controlAction } from "./server/control-service-routes.js";
import {
  arbiterDisabled,
  forgetApproval,
  alwaysSource,
  listApprovals,
  resolveApproval,
  type ApprovalsArbiter,
} from "./server/approval-routes.js";
import { type WarmResult } from "./server/cache-warmup.js";

// Re-exported so importers keep reading the egress-approval surface from
// server.js (the pre-decomposition public API).
export type { EgressApproval, ApprovalStatus, ApprovalsArbiter } from "./server/approval-routes.js";
import { type PostureArbiter } from "./server/arbiter-surfaces.js";
import { postExportLabels, type PolicyDocArbiter } from "./server/policy-doc-routes.js";
export type { PolicyDocArbiter, PolicyDocumentView, PolicyFileStatusRow, MintRuleInput, TestFlowInput } from "./server/policy-doc-routes.js";
import { getChanges, getProposals, getRuleOrigins, postProposalVerdict, postUndoChange } from "./server/policy-proposal-routes.js";
import { postApply, postSuggest, postTry } from "./server/policy-assistant-routes.js";
import { getRuleSource, postRuleChange } from "./server/rule-action-routes.js";
import { postModelChange, postModelTest } from "./server/model-routes.js";
import { getPromptHolds, getPromptSettings, postPromptHoldAnswer, postPromptLetThrough, postPromptReveal, postPromptSettingsChange } from "./server/prompt-filter-routes.js";
import { postSecretReveal } from "./server/secret-reveal-routes.js";
import { getSensitivityLabels, postSensitivityLabelChange } from "./server/sensitivity-label-routes.js";
import { realProbeDeps, type ProbeDeps } from "./model-probe.js";
import { productionAssistantModel, type AssistantModel } from "./policy-assistant.js";
export type { PolicyProposalArbiter } from "./server/policy-proposal-routes.js";
export type { PostureArbiter, PostureChangeResult } from "./server/arbiter-surfaces.js";
import { getConfigAxes, postConfigAxes, type ConfigAuditArbiter } from "./server/config-axes-routes.js";
export type { ConfigAuditArbiter, AxesStateWithAudit, AxisChangeAudit } from "./server/config-axes-routes.js";
import { getSecrets, setSecretLabel, type SecretsArbiter } from "./server/secrets-routes.js";
import { apiPolicyByWho } from "./server/by-who-routes.js";
export type {
  RegisteredSecret,
  ConfidentialityState,
  SecretsArbiter,
  PathLabelWire,
  PathLabelResult,
} from "./server/secrets-routes.js";
import { type EventSource } from "./event-source.js";
import { type Supervisor } from "./supervisor/supervisor.js";
import { buildServiceSummary } from "./view-model/service-summary.js";

export type { DashboardServerOptions, Tenant, TenantSurfaces, DashboardSelfControl } from "./server/options.js";
import { type DashboardServerOptions, type Tenant, type TenantState, type DashboardSelfControl } from "./server/options.js";
import { SignInTickets, SIGN_IN_REMEDY } from "./sign-in.js";
import { requestedTenant, isArbiterUnreachable, unreachableBody } from "./server/tenant.js";
import { hostAllowed, interfaceAddresses, readAccessOf, sameOriginRead, READ_ROUTES, type ReadRoute } from "./server/read-gate.js";

/** The 403 body every mutating route answers without an admin session. */
export const ADMIN_SESSION_REQUIRED =
  `admin session required — ${SIGN_IN_REMEDY} (each link works once), ` +
  "or sign in with DASHBOARD_PASSWORD where one is set; without it the dashboard shows only what the AI saw";

/** Where the two front-ends live (dashboard.md §4.25). From source the server
 *  is dashboard/src/server.ts, so they are `../public` and `../dev`. In the
 *  installed bundle it is launcher/dist/dashboard.mjs and the bundler copied
 *  them to `./dashboard/public` and `./dashboard/dev` beside it. The first
 *  candidate holding an index.html wins; none → the source path, whose
 *  missing index.html the static route reports. */
export function resolveStaticDir(here: string, name: "public" | "dev", exists: (p: string) => boolean = existsSync): string {
  // A checkout's build (launcher/dist, packaging.md §5.1) serves the
  // checkout's own front-ends, never the copies its last build took: the
  // build record covers the bundles' inputs, not these files.
  const checkout = isCheckoutBuildDir(here, exists) ? [join(here, "..", "..", "dashboard", name)] : [];
  const candidates = [join(here, "..", name), ...checkout, join(here, "dashboard", name)];
  return candidates.find((d) => exists(join(d, "index.html"))) ?? candidates[0]!;
}

/** Is `dir` a source checkout's own build (`launcher/dist` beside
 *  `launcher/src/run.ts`) rather than an installed package's `dist/` (which
 *  ships no src/)? Mirrors launcher/src/services/layout.ts `isCheckoutBuild`. */
export function isCheckoutBuildDir(dir: string, exists: (p: string) => boolean = existsSync): boolean {
  return basename(dir) === "dist" && exists(join(dir, "..", "src", "run.ts"));
}
const HERE = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_PUBLIC_DIR = resolveStaticDir(HERE, "public");

/** Normalize a socket address for allowlist comparison: Node reports IPv4
 *  clients on a dual-stack listener as IPv4-mapped IPv6 ("::ffff:1.2.3.4") —
 *  compare the embedded IPv4 form. */
function normalizeClientIp(addr: string): string {
  const low = addr.toLowerCase();
  return low.startsWith("::ffff:") ? low.slice("::ffff:".length) : low;
}

/** Loopback peer (v4, v6, or v4-mapped v6) — the path a same-host process the
 *  agent runs would take; never trusted as "the front" (see trustFront). */
function isLoopbackAddress(addr: string | undefined): boolean {
  if (!addr) return false;
  const a = normalizeClientIp(addr);
  return a === "::1" || a.startsWith("127.");
}

/**
 * Decide whether a client socket may reach the dashboard at all (dashboard.md
 * §6: the dashboard reveals symbol→original, so reachability is allowlist-only).
 * Loopback is always allowed — the historical localhost-only posture; any other
 * source address must be explicitly allowlisted (e.g. the trusted reverse
 * proxy's IP). FAIL-CLOSED: a missing/unknown address is denied. Exported for
 * the unit tests.
 */
export function clientAllowed(
  remoteAddress: string | undefined,
  allowedIps: ReadonlySet<string>,
): boolean {
  if (!remoteAddress) return false;
  const ip = normalizeClientIp(remoteAddress);
  if (ip === "::1" || ip.startsWith("127.")) return true;
  return allowedIps.has(ip);
}

export class DashboardServer {
  private readonly source: EventSource;
  private readonly publicDir: string;
  /** The front-ends beyond the product (§4.25ac), each owning its mount. */
  private readonly extensions: readonly DashboardExtension[];
  /** The read gate's table: the product's rows, then each extension's. */
  private readonly readRoutes: readonly ReadRoute[];
  /** Does this build serve the developer view? The product's words point
   *  to the detailed trace only then (§4.25ad). */
  private get hasDev(): boolean {
    return this.extensions.some((x) => x.name === "inspector");
  }
  /** Per-tenant home-facts caches (home-routes.ts), keyed by the tenant's source. */
  private readonly homeFacts = new WeakMap<EventSource, HomeFacts>();
  private readonly password: string;
  private readonly basePath: string;
  private readonly supervisor?: Supervisor;
  /** MUTABLE (the one exception): a supervised cold boot cannot connect these
   * at construction — the supervisor's own arbiter does not exist yet — so
   * server-main late-binds them via attachArbiterSurfaces() once autostart
   * brings the arbiter up. Every route already handles the undefined window
   * (404 "arbiter not connected"). */
  private approvalsArbiter?: ApprovalsArbiter;
  private secretsArbiter?: SecretsArbiter;
  private postureArbiter?: PostureArbiter;
  private auditArbiter?: ConfigAuditArbiter;
  private policyDocArbiter?: PolicyDocArbiter;
  private readonly assistantModel: () => Promise<AssistantModel>;
  private readonly modelProbeDeps: ProbeDeps;
  private readonly configEnv: Record<string, string | undefined>;
  private readonly allowedClientIps: ReadonlySet<string>;
  /** Host names besides loopback at the bound port (read-gate.ts hostAllowed). */
  private readonly allowedHosts: readonly string[];
  /** The bound port and address, once listening (the Host check needs them). */
  private boundPort: number | null = null;
  private boundAddress: string | null = null;
  /** This host's interface addresses, read when listening (hostAllowed). */
  private hostAddresses: ReadonlySet<string> = new Set();
  private readonly sessionSecret: string;
  private readonly adminToken: string;
  /** One-time sign-in tickets (sign-in.ts): minted over the human-plane
   *  sign-in socket, redeemed by `GET /login?ticket=`. */
  private readonly signInTickets: SignInTickets;
  private readonly trustFront: boolean;
  /** What `~` means in the file browser (dashboard.md §4.25m). */
  private readonly fileBrowserHome?: string;
  /** How long the Suggested view's Scan waits before "still scanning" (§4.25r). */
  private readonly suggestScanWaitMs?: number;
  private readonly policyModelOffered?: boolean;
  private readonly basicAuth?: { user: string; password: string };
  /** The test tenant's surfaces (§2.7 1c); undefined = live only. Mutable
   *  fields for the same set-once late-bind the live surfaces get. */
  private readonly testTenant?: TenantState;
  private readonly log: (msg: string) => void;
  private readonly http: Server;

  constructor(opts: DashboardServerOptions) {
    this.source = opts.source;
    this.publicDir = opts.publicDir ?? DEFAULT_PUBLIC_DIR;
    this.extensions = opts.extensions ?? [];
    this.readRoutes = [...READ_ROUTES, ...this.extensions.flatMap((x) => x.readRoutes ?? [])];
    this.password = opts.password ?? "";
    this.adminToken = opts.adminToken ?? randomBytes(16).toString("hex");
    this.signInTickets = opts.signInTickets ?? new SignInTickets();
    this.sessionSecret = opts.sessionSecret ?? randomBytes(32).toString("hex");
    this.trustFront = opts.trustFront ?? false;
    this.fileBrowserHome = opts.fileBrowserHome;
    this.suggestScanWaitMs = opts.suggestScanWaitMs;
    this.policyModelOffered = opts.policyModelOffered;
    this.basicAuth = opts.basicAuth;
    this.basePath = (opts.basePath ?? "").replace(/\/+$/, "");
    this.supervisor = opts.supervisor;
    this.approvalsArbiter = opts.approvalsArbiter;
    this.secretsArbiter = opts.secretsArbiter;
    this.postureArbiter = opts.postureArbiter;
    this.auditArbiter = opts.auditArbiter;
    this.policyDocArbiter = opts.policyDocArbiter;
    this.assistantModel = opts.assistantModel ?? productionAssistantModel();
    this.modelProbeDeps = opts.modelProbeDeps ?? realProbeDeps();
    this.configEnv = opts.configEnv ?? process.env;
    this.allowedClientIps = new Set((opts.allowedClientIps ?? []).map(normalizeClientIp));
    this.allowedHosts = opts.allowedHosts ?? [];
    this.testTenant = opts.testTenant
      ? { ...opts.testTenant }
      : undefined;
    this.log = opts.log ?? ((m) => console.error(`[dashboard] ${m}`));
    const host: ExtensionHost = {
      log: this.log,
      liveSource: this.source,
      supervisor: this.supervisor,
      configEnv: this.configEnv,
      requireAdminRead: (req, res, urlPath) => this.requireAdminRead(req, res, urlPath),
      hasAdminSession: (req) => this.hasAdminSession(req),
    };
    for (const x of this.extensions) x.attach?.(host);
    this.http = createServer((req, res) => {
      void this.handle(req, res).catch((err: unknown) => {
        this.log(`handler error: ${(err as Error).message}`);
        if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Internal error");
      });
    });
  }

  /** Late-bind the arbiter-backed surfaces (approvals + secrets + posture)
   * after a supervised cold boot: the constructor-time connect fails when the
   * supervisor has not spawned the arbiter yet (the boot ordering is
   * inherent — autostart runs after listen()). Set-once: an already-connected
   * surface is never replaced or downgraded to undefined. */
  attachArbiterSurfaces(
    approvals?: ApprovalsArbiter,
    secrets?: SecretsArbiter,
    posture?: PostureArbiter,
    audit?: ConfigAuditArbiter,
    tenant: Tenant = "live",
  ): void {
    if (tenant === "test") {
      const t = this.testTenant;
      if (!t) return; // no test tenant configured — nothing to bind to
      if (approvals && !t.approvalsArbiter) t.approvalsArbiter = approvals;
      if (secrets && !t.secretsArbiter) t.secretsArbiter = secrets;
      if (posture && !t.postureArbiter) t.postureArbiter = posture;
      if (audit && !t.auditArbiter) t.auditArbiter = audit;
      return;
    }
    if (approvals && !this.approvalsArbiter) this.approvalsArbiter = approvals;
    if (secrets && !this.secretsArbiter) this.secretsArbiter = secrets;
    if (posture && !this.postureArbiter) this.postureArbiter = posture;
    if (audit && !this.auditArbiter) this.auditArbiter = audit;
  }

  /** Late-bind the policy-document surface (stage 5a), set-once per tenant. */
  attachPolicyDocSurface(surface: PolicyDocArbiter | undefined, tenant: Tenant = "live"): void {
    if (!surface) return;
    if (tenant === "test") {
      if (this.testTenant && !this.testTenant.policyDocArbiter) this.testTenant.policyDocArbiter = surface;
      return;
    }
    if (!this.policyDocArbiter) this.policyDocArbiter = surface;
  }

  /** The tenants this dashboard serves. */
  tenants(): Tenant[] {
    return this.testTenant ? ["live", "test"] : ["live"];
  }

  /** The runs whose sessions are not the person's own (the extensions':
   *  the inspector's test and drill runs; none in a product-only build). */
  private sessionRuns(): SessionRuns {
    const testRuns: SessionRuns["testRuns"] = [];
    const watchRuns: SessionRuns["watchRuns"] = [];
    for (const x of this.extensions) {
      const r = x.sessionRuns?.();
      if (r) {
        testRuns.push(...r.testRuns);
        watchRuns.push(...r.watchRuns);
      }
    }
    return { testRuns, watchRuns };
  }

  /** The tenant's home-facts cache (home-routes.ts), made on first use: the
   *  product home, the Suggested view's folders and the policy panel's
   *  waiting cards (`readFirstLookup`) share it. */
  private homeFactsFor(source: EventSource): HomeFacts {
    let facts = this.homeFacts.get(source);
    if (!facts) {
      // The label times on the files a session read (label-times.ts), read
      // through the tenant's surfaces as they stand at each request (they
      // are late-bound with the arbiter, `attachArbiterSurfaces`).
      const labels = (): LabelTimesArbiter | undefined => {
        const t = source === this.source ? this.liveState() : this.testTenant?.source === source ? this.testTenant : undefined;
        return t ? labelTimesArbiter(t.secretsArbiter, t.policyDocArbiter) : undefined;
      };
      facts = new HomeFacts(source, this.fileBrowserHome, labels);
      this.homeFacts.set(source, facts);
    }
    return facts;
  }

  private liveState(): TenantState {
    return {
      source: this.source,
      approvalsArbiter: this.approvalsArbiter,
      secretsArbiter: this.secretsArbiter,
      postureArbiter: this.postureArbiter,
      auditArbiter: this.auditArbiter,
      policyDocArbiter: this.policyDocArbiter,
    };
  }

  /** Listen on host:port. Returns the bound port (handy when port=0). The
   *  persisted listing cache is loaded first (bounded, synchronous); the
   *  warm-up starts in the background once listening (dashboard.md §4.30). */
  listen(port: number, host = "127.0.0.1"): Promise<number> {
    for (const x of this.extensions) x.start?.();
    return new Promise((resolve, reject) => {
      this.http.once("error", reject);
      this.http.listen(port, host, () => {
        this.http.off("error", reject);
        const addr = this.http.address();
        const bound = typeof addr === "object" && addr ? addr.port : port;
        this.boundPort = bound;
        this.boundAddress = typeof addr === "object" && addr ? addr.address : host;
        try {
          this.hostAddresses = interfaceAddresses();
        } catch {
          this.hostAddresses = new Set();
        }
        this.log(`listening on http://${host}:${bound}${this.basePath}`);
        for (const x of this.extensions) x.listening?.();
        resolve(bound);
      });
    });
  }

  /** The extensions' boot warm-ups (the inspector's, dashboard.md §4.30),
   *  started once; a test awaits them. */
  async warmup(): Promise<WarmResult[]> {
    const runs = await Promise.all(this.extensions.map((x) => x.warmup?.() ?? []));
    return runs.flat();
  }

  async close(): Promise<void> {
    for (const x of this.extensions) {
      try {
        await x.close?.();
      } catch (err) {
        this.log(`${x.name} close error: ${(err as Error).message}`);
      }
    }
    this.testTenant?.source.close();
    // Reap the control-plane children we own before tearing the server down, so
    // a dashboard exit/SIGTERM never orphans the arbiter, the proxies, or any
    // in-flight agent run.
    if (this.supervisor) {
      try {
        await this.supervisor.shutdownAll();
      } catch (err) {
        this.log(`supervisor shutdown error: ${(err as Error).message}`);
      }
    }
    this.source.close();
    await new Promise<void>((resolve) => this.http.close(() => resolve()));
  }

  // ── auth helpers (adapted from reference server.ts) ─────────────────────────

  /** The session cookie value: derived from the password when one is set,
   *  else from the per-boot admin token — one cookie, two ways to earn it. */
  private token(): string {
    return createHash("sha256").update((this.password || this.adminToken) + this.sessionSecret).digest("hex");
  }

  private hasSessionCookie(req: IncomingMessage): boolean {
    const cookie = req.headers.cookie ?? "";
    for (const part of cookie.split(";")) {
      const [k, ...v] = part.trim().split("=");
      if (k === "mandu_session" && v.join("=") === this.token()) return true;
    }
    return false;
  }

  private isAuthed(req: IncomingMessage): boolean {
    if (!this.password) return true;
    return this.hasSessionCookie(req);
  }

  /** `Authorization: Basic base64(user:password)` matches the configured pair.
   *  Constant-time on the decoded bytes; a missing/garbled header is false. */
  private basicAuthOk(req: IncomingMessage): boolean {
    if (!this.basicAuth) return false;
    const header = req.headers.authorization ?? "";
    const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/.exec(header);
    if (!m) return false;
    const got = Buffer.from(m[1]!, "base64");
    const want = Buffer.from(`${this.basicAuth.user}:${this.basicAuth.password}`);
    return got.length === want.length && timingSafeEqual(got, want);
  }

  private challengeBasicAuth(res: ServerResponse): void {
    res.writeHead(401, {
      "WWW-Authenticate": 'Basic realm="Mandu dashboard", charset="UTF-8"',
      "Content-Type": "text/plain",
      "Cache-Control": "no-store",
    });
    res.end("Unauthorized");
  }

  /** Mutating verbs need an ADMIN SESSION (see DashboardServerOptions.adminToken). */
  private static isMutating(req: IncomingMessage): boolean {
    const m = (req.method ?? "GET").toUpperCase();
    return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
  }

  /**
   * The gate on a GET that serves human-plane text (an organization's
   * patterns, a held message, the person's own exceptions, the policy file):
   * the CSRF header AND the admin session, as a mutating verb needs. A GET
   * is open to any same-host process (the agent's too); the session cookie
   * is what tells the human's browser from it. False once refused (the 403
   * is answered here).
   */
  /** Whether a read may carry what `requireAdminRead` guards, for a listing
   *  that is served to every reader but hides that part otherwise (History
   *  and the rule-change cards hide a prompt exception's pattern, plan 15
   *  §13.7 item 4). The same two checks; nothing is answered here. */
  private adminRead(req: IncomingMessage): boolean {
    return req.headers["x-mandu-control"] !== undefined && this.hasAdminSession(req);
  }

  private requireAdminRead(req: IncomingMessage, res: ServerResponse, urlPath: string): boolean {
    if (!requireCsrf(req, res)) return false;
    if (this.hasAdminSession(req)) return true;
    this.log(`denied GET ${urlPath}: no admin session (${req.socket.remoteAddress ?? "<no address>"})`);
    json(res, 403, { error: ADMIN_SESSION_REQUIRED });
    return false;
  }

  private hasAdminSession(req: IncomingMessage): boolean {
    if (this.hasSessionCookie(req)) return true; // password session or token session
    if (this.basicAuthOk(req)) return true; // the Basic-auth front: credentials ARE the session
    if (this.trustFront && !isLoopbackAddress(req.socket.remoteAddress)) return true; // came through the front
    return false;
  }

  /** Whether this read may carry a real value (read-gate.ts, dashboard.md
   *  §6): the admin session, from a page of this dashboard (the CSRF header
   *  or the browser's same-origin `Sec-Fetch-Site`). Without it a read gets
   *  what the AI saw. */
  private valueRead(req: IncomingMessage): boolean {
    return this.hasAdminSession(req) && sameOriginRead(req.headers);
  }

  /** The Cookie header value a client needs for mutating routes and for the
   *  reads that carry values (tests, or a script the operator runs by hand;
   *  such a read also sends `X-Mandu-Control`). */
  adminCookie(): string {
    return `mandu_session=${this.token()}`;
  }

  /** The one-time login path that sets that cookie in a browser. */
  adminLoginPath(): string {
    return `${this.basePath}/login?token=${this.adminToken}`;
  }

  /** How a human signs in to this dashboard (sign-in.ts SignInDeps.mode):
   *  its Basic-auth credentials, its password, or a one-time ticket. */
  signInMode(): "tickets" | "password" | "basic-auth" {
    if (this.basicAuth) return "basic-auth";
    if (this.password) return "password";
    return "tickets";
  }

  /** Mint a one-time sign-in ticket and answer its login path. Called only
   *  by the human-plane sign-in socket (server-main.ts serveSignInChannel),
   *  which decides first whether a link may be handed out at all. */
  mintSignInPath(): { path: string; expiresAt: number } {
    const { ticket, expiresAt } = this.signInTickets.mint();
    return { path: `${this.basePath}/login?ticket=${ticket}`, expiresAt };
  }

  /** The page for a sign-in that did not happen (no password configured):
   *  what to run, never a form that invites guessing. */
  private signInHelpPage(headline: string): string {
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Mandu Dashboard — Sign in</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.login{background:#161b22;padding:2rem;border-radius:8px;max-width:30rem;border:1px solid #30363d;line-height:1.5}
code{background:#0d1117;padding:.1rem .3rem;border-radius:4px}
a{color:#58a6ff}</style></head><body>
<div class="login"><h1>Mandu Dashboard</h1>
<p>${headline}</p>
<p>To sign in, run <code>mandu dashboard</code> in your own terminal and open the sign-in link it prints.
Each link works once. A Mandu launch prints one too, on its dashboard line.</p>
<p>You can still look around without signing in: <a href="${this.basePath}/">open the dashboard</a>.</p>
</div></body></html>`;
  }

  private loginPage(): string {
    const bp = this.basePath;
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Mandu Dashboard — Login</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.login{background:#161b22;padding:2rem;border-radius:8px;width:320px;border:1px solid #30363d}
.login input{width:100%;padding:.6rem;margin-bottom:1rem;border:1px solid #30363d;border-radius:4px;
background:#0d1117;color:#e6edf3;box-sizing:border-box}
.login button{width:100%;padding:.6rem;background:#3fb950;color:#0d1117;border:none;border-radius:4px;
font-weight:600;cursor:pointer}</style></head><body>
<form class="login" method="POST" action="${bp}/login">
<h1>Mandu Dashboard</h1>
<input type="password" name="password" placeholder="Password" autofocus required>
<button type="submit">Log in</button></form></body></html>`;
  }

  // ── request dispatch ────────────────────────────────────────────────────────

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Source-IP gate (fail-closed; dashboard.md §6). FIRST — before /login and
    // every route — so a non-allowlisted client learns nothing about the app.
    if (!clientAllowed(req.socket.remoteAddress, this.allowedClientIps)) {
      this.log(`denied client ${req.socket.remoteAddress ?? "<no address>"} (not loopback/allowlisted)`);
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Forbidden");
      return;
    }

    // Host check (DNS rebinding, read-gate.ts) — SECOND, before every route:
    // a page that rebound its own name to this host names that name here,
    // the one header it cannot choose. 421: this server is not that host.
    if (!hostAllowed(req.headers.host, this.boundPort, this.boundAddress, this.allowedHosts, this.hostAddresses)) {
      this.log(`refused Host ${JSON.stringify(req.headers.host ?? null)} from ${req.socket.remoteAddress ?? "<no address>"} (not a name of this dashboard; DASHBOARD_SERVER_NAMES adds one)`);
      res.writeHead(421, { "Content-Type": "text/plain", "Cache-Control": "no-store" });
      res.end("Misdirected Request: this dashboard does not answer to that host name");
      return;
    }

    // HTTP Basic auth (basicAuth option) — THIRD, still before every route:
    // a client without the credentials learns nothing but the challenge.
    if (this.basicAuth && !this.basicAuthOk(req)) {
      if (req.headers.authorization) {
        this.log(`rejected Basic-auth credentials from ${req.socket.remoteAddress ?? "<no address>"}`);
      }
      this.challengeBasicAuth(res);
      return;
    }

    const rawUrl = req.url ?? "";
    const url = stripBasePath(rawUrl, this.basePath);
    const urlPath = url.split("?")[0]!;

    // Login (always accessible)
    if (urlPath === "/login" && req.method === "GET") {
      const query = new URLSearchParams(url.split("?")[1] ?? "");
      // Ticket login (sign-in.ts, policy-surface.md §2.6 "Signing in"): a
      // one-time link minted over the human-plane sign-in socket. Spent on
      // first use; a used, expired or guessed ticket signs nobody in. A
      // browser that already holds the session is just let in (an old launch
      // line still opens the dashboard).
      const ticket = query.get("ticket");
      if (ticket !== null) {
        if (!this.password && !this.basicAuth && this.signInTickets.redeem(ticket)) {
          this.log(`signed in with a one-time link (${req.socket.remoteAddress ?? "<no address>"})`);
          res.writeHead(302, {
            "Set-Cookie": `mandu_session=${this.token()}; Path=${this.basePath || "/"}; HttpOnly; SameSite=Strict`,
            Location: `${this.basePath}/`,
            "Cache-Control": "no-store",
          });
          res.end();
          return;
        }
        if (this.hasAdminSession(req)) {
          res.writeHead(302, { Location: `${this.basePath}/`, "Cache-Control": "no-store" });
          res.end();
          return;
        }
        this.log(`rejected a sign-in link (used, expired or unknown) from ${req.socket.remoteAddress ?? "<no address>"}`);
        if (this.password) {
          res.writeHead(302, { Location: `${this.basePath}/login` });
          res.end();
          return;
        }
        res.writeHead(403, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
        res.end(this.signInHelpPage("This sign-in link was already used, or it has expired."));
        return;
      }
      // Token login (no password configured): the admin link server-main
      // printed. A wrong token is a plain 403 — no page that invites guessing.
      const token = query.get("token");
      if (token !== null) {
        if (!this.password && token === this.adminToken) {
          res.writeHead(302, {
            "Set-Cookie": `mandu_session=${this.token()}; Path=${this.basePath || "/"}; HttpOnly; SameSite=Strict`,
            Location: `${this.basePath}/`,
          });
          res.end();
          return;
        }
        this.log(`rejected admin-link login from ${req.socket.remoteAddress ?? "<no address>"}`);
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end("Forbidden");
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      // No password: there is no form to fill, only a link to get.
      res.end(this.password ? this.loginPage() : this.signInHelpPage(this.hasAdminSession(req) ? "This browser is signed in." : "This browser is not signed in."));
      return;
    }
    if (urlPath === "/login" && req.method === "POST") {
      const body = await readBody(req);
      const password = new URLSearchParams(body).get("password") ?? "";
      if (this.password && password === this.password) {
        res.writeHead(302, {
          "Set-Cookie": `mandu_session=${this.token()}; Path=${this.basePath || "/"}; HttpOnly; SameSite=Strict`,
          Location: `${this.basePath}/`,
        });
      } else {
        res.writeHead(302, { Location: `${this.basePath}/login` });
      }
      res.end();
      return;
    }
    if (urlPath === "/logout") {
      res.writeHead(302, {
        "Set-Cookie": `mandu_session=; Path=${this.basePath || "/"}; HttpOnly; Max-Age=0`,
        Location: `${this.basePath}/login`,
      });
      res.end();
      return;
    }

    if (!this.isAuthed(req)) {
      res.writeHead(302, { Location: `${this.basePath}/login` });
      res.end();
      return;
    }

    // Admin session for every mutating verb (policy-surface.md §2.6):
    // the source-IP allowlist and CSRF header cannot tell the human's browser
    // from a same-host process the agent runs — the token cookie can, because
    // the token is never written anywhere that process can read.
    if (DashboardServer.isMutating(req)) {
      // CSRF first (the cheaper, older gate; a missing header is answered as it
      // always was), then the admin session.
      if (!requireCsrf(req, res)) return;
      if (!this.hasAdminSession(req)) {
        this.log(`denied ${req.method} ${urlPath}: no admin session (${req.socket.remoteAddress ?? "<no address>"})`);
        json(res, 403, { error: ADMIN_SESSION_REQUIRED });
        return;
      }
    }

    // The read gate (read-gate.ts, dashboard.md §6): a GET under /api/ that
    // can carry a real value needs the admin session as a mutating verb
    // does. `admin` routes are refused here; `projection` routes are served
    // with `values` false, which leaves every value out.
    const values = this.valueRead(req);
    if ((req.method === "GET" || req.method === "HEAD") && urlPath.startsWith("/api/") && !values && readAccessOf(urlPath, this.readRoutes) === "admin") {
      this.log(`denied GET ${urlPath}: no admin session (${req.socket.remoteAddress ?? "<no address>"})`);
      json(res, 403, { error: ADMIN_SESSION_REQUIRED });
      return;
    }

    // ── Tenant (policy-surface.md §2.7 1c): one store per request ──
    // The cookie is the inspector's choice; a product request never reads it
    // (tenant.ts, dashboard.md §6.y).
    const asked = requestedTenant(url, req.headers, urlPath);
    if (asked.tenant === null) {
      json(res, 400, { error: "tenant must be 'live' or 'test'" });
      return;
    }
    let tenant: Tenant = asked.tenant;
    let t: TenantState | undefined = tenant === "test" ? this.testTenant : this.liveState();
    if (!t) {
      // A test tenant nobody configured: an EXPLICIT ask is answered honestly;
      // a stale cookie falls back to live rather than blanking the page.
      if (asked.explicit) {
        json(res, 404, { error: "no test tenant on this dashboard — the control plane runs the test-tenant arbiter" });
        return;
      }
      tenant = "live";
      t = this.liveState();
    }
    if (urlPath === "/api/tenants") {
      json(res, 200, { tenants: this.tenants(), current: tenant });
      return;
    }
    // A tenant whose arbiter is down answers 503 with what is down (tenant.ts),
    // never the bare 500 below: the state of the stack, not the request.
    try {
      await this.handleTenant(urlPath, url, req, res, t, tenant, values);
    } catch (err) {
      if (!isArbiterUnreachable(err) || res.headersSent) throw err;
      this.log(`${req.method} ${urlPath}: ${tenant} tenant unreachable (${(err as Error).message})`);
      json(res, 503, unreachableBody(tenant, err));
    }
  }

  /** Every route served for one tenant's surfaces `t`. */
  private async handleTenant(urlPath: string, url: string, req: IncomingMessage, res: ServerResponse, t: TenantState, tenant: Tenant, values: boolean): Promise<void> {
    // ── Control plane (behind isAuthed; POSTs additionally require the CSRF
    //    header). Returns true if it handled the request. ──────────────────────
    // An extension's routes first (§4.25ac): the inspector answers its own,
    // and the session list, events and stream over its recorded runs too.
    for (const x of this.extensions) {
      if (x.route && await x.route({ urlPath, url, req, res, basePath: this.basePath, tenant: t, tenantName: tenant, values })) return;
    }
    if (await this.handleControl(urlPath, url, req, res, t)) return;

    // REST + SSE: the session list, a session's events and its live stream,
    // over the tenant's store (a read API; the product page reads Home)
    if (urlPath === "/api/sessions") return apiSessions(t.source, url, req, res);
    // The product home (§4.25): one GET composing sessions + facts + the
    // policy panel + the configured mode. Per-tenant like everything else.
    // The History page's rows (§4.25ae), Answered earlier past its newest 20
    // (§4.25 *Past the newest 20*) and a step's whole original (admin,
    // read-gate.ts) read the same deps.
    if ((urlPath === "/api/home" || urlPath === "/api/home/agent" || urlPath === "/api/home/history" || urlPath === "/api/home/answered" || urlPath === "/api/home/original") && req.method === "GET") {
      const facts = this.homeFactsFor(t.source);
      const deps = { source: t.source, facts, approvals: t.approvalsArbiter, prompt: t.policyDocArbiter, proposals: t.policyDocArbiter, ...this.sessionRuns(), env: this.configEnv, home: this.fileBrowserHome, dev: this.hasDev };
      if (urlPath === "/api/home") return apiHome(deps, res);
      if (urlPath === "/api/home/history") return apiHomeHistory(deps, url, res);
      if (urlPath === "/api/home/answered") return apiHomeAnswered(deps, url, res);
      // Admin only: the read gate refused it signed out before this ran.
      if (urlPath === "/api/home/original") return values ? apiHomeOriginal(deps, url, res) : json(res, 403, { error: ADMIN_SESSION_REQUIRED });
      return apiHomeAgent(deps, url, res, values);
    }
    // "Show the real value" on the product's agent page (§4.25b): ONE
    // secret's value, of a secret the session recorded, named by its opaque
    // ref. A POST: the global gate above required the CSRF header and the
    // admin session (secret-reveal-routes.ts).
    if (urlPath === "/api/home/reveal" && req.method === "POST") {
      return postSecretReveal(t.source, req, res, this.log);
    }
    // "Where your data lives" on the product page (on-disk-layout.md §9.2):
    // each location of the path table, `stat`ed only (metadata; never opened
    // or listed), resolved with this process's MANDU_HOME / HOME. The same for
    // every tenant: it describes this machine, not a session store.
    if (urlPath === "/api/data-locations" && req.method === "GET") {
      json(res, 200, buildDataLocations(this.configEnv, homeOf(this.configEnv)));
      return;
    }
    if (urlPath === "/api/events") return apiEvents(t.source, this.log, url, res, values);
    // The waiting cards' words read the asking sessions' records (§4.34
    // "Read before it was marked"), through the facts Home caches.
    if (urlPath === "/api/policy/panel") return apiPolicyPanel(t.source, t.approvalsArbiter, res, readFirstLookup(this.homeFactsFor(t.source), () => t.source.listSessions()), this.fileBrowserHome ?? homedir());
    // The Rules page's per-principal view (§4.25aa; read-only, no CSRF).
    if (urlPath === "/api/policy/by-who" && req.method === "GET") return apiPolicyByWho(t.source, t.secretsArbiter, res, this.fileBrowserHome ?? homedir());
    if (urlPath === "/api/stream") return apiStream(t.source, url, req, res, values);

    // Static UI — the PRODUCT at `/` (publicDir, dashboard.md §4.25) and
    // each extension under its mount (§4.25ac: the DEVELOPER inspector at
    // `/dev/` where the build carries it). They share the base-path meta, so
    // their API calls resolve to the one `/api/` root. Pages are PATHS
    // (§4.25v, page-routes.ts): the product's index.html answers exactly its
    // route table, GET/HEAD only; a retired query-string page URL is a 302
    // to its path form; every other path is a static file or a 404.
    const pageVerb = req.method === "GET" || req.method === "HEAD";
    const legacy = pageVerb ? legacyRedirect(url) : null;
    if (legacy !== null) return redirectTo(this.basePath, legacy, res);
    const ext = extensionFor(urlPath, this.extensions);
    if (ext) return ext.handle({ urlPath, url, req, res, basePath: this.basePath });
    // No developer view in this build: its pages say so (still a 404), its
    // files stay a plain 404 below.
    if (pageVerb && isDevPagePath(urlPath)) return serveDevAbsent(this.basePath, res);
    const front = pageVerb ? pageFor(urlPath) : null;
    // The product page's `~` (home.js shortPath) is this folder only, the one
    // the server's own words shorten (dashboard.md §4.34 "`~` is the
    // dashboard's home"); `extensions` names the front-ends it may link
    // into (home.js leaves out a link into one this build does not serve).
    if (front === "product") {
      return serveIndex(this.publicDir, this.basePath, res, { "home-dir": this.fileBrowserHome ?? homedir(), extensions: this.extensions.map((x) => x.name).join(" ") });
    }
    return serveStatic(this.publicDir, urlPath, res, req);
  }

  // ── Control plane: supervisor + agent-runner (NEW, dashboard.md control) ──────
  //
  // All routes here sit behind the isAuthed gate (same-origin cookie session).
  // A GET/SSE route that carries a log or a run's output is `admin` in the
  // read gate (read-gate.ts): the session cookie plus the CSRF header or the
  // browser's same-origin Sec-Fetch-Site (an EventSource cannot set a header).
  // Every POST is mutating, so it must carry the X-Mandu-Control header — an
  // attacker page can't set a custom header on a cross-site form/fetch, so this
  // is a sufficient CSRF guard on top of the SameSite=Strict session cookie.

  /** Returns true once it has fully handled (and responded to) the request. */
  private async handleControl(
    urlPath: string,
    url: string,
    req: IncomingMessage,
    res: ServerResponse,
    t: TenantState,
  ): Promise<boolean> {
    // The product page's one-row projection of the same snapshot (§4.25
    // Settings; view-model/service-summary.ts): the inspector keeps the rows.
    if (urlPath === "/api/control/summary" && req.method === "GET") {
      if (!this.supervisor) return controlDisabled(res), true;
      json(res, 200, { summary: buildServiceSummary(this.supervisor.status(), { dev: this.hasDev }) });
      return true;
    }

    // Start or restart one service (Settings; the inspector's extension
    // has stop, replace and the logs).
    const ctl = urlPath.match(/^\/api\/control\/([^/]+)\/(start|restart)$/);
    if (ctl) {
      const service = decodeURIComponent(ctl[1]!);
      const action = ctl[2]! as "start" | "restart";
      if (!this.supervisor) return controlDisabled(res), true;
      if (!isServiceId(service)) {
        json(res, 404, { error: `unknown service '${service}'` });
        return true;
      }
      if (req.method !== "POST") {
        json(res, 405, { error: "method not allowed" });
        return true;
      }
      if (!requireCsrf(req, res)) return true;
      await controlAction(this.supervisor, service, action, res);
      return true;
    }

    // ── /api/prompt-filters/* — a held message (confidentiality-plan-15
    //    §8.1): its reveal, the answer and "let it through" are POSTs, held by
    //    the global gate (CSRF + admin session); every write rides the admin
    //    channel. The inspector's extension has the panel's own routes. ──
    if (urlPath === "/api/prompt-filters/reveal" && req.method === "POST") {
      await postPromptReveal(t.source, req, res);
      return true;
    }
    // Plan 15 phase 3 (§7, §13.6): the held prompts carry the human's own
    // found text (human plane), so the GET is gated like the packs'; the
    // answer and "let it through" are POSTs (the global gate) on the admin
    // channel.
    if (urlPath === "/api/prompt-filters/holds" && req.method === "GET") {
      if (!this.requireAdminRead(req, res, urlPath)) return true;
      await getPromptHolds(t.policyDocArbiter, res);
      return true;
    }
    if (urlPath === "/api/prompt-filters/holds/answer" && req.method === "POST") {
      await postPromptHoldAnswer(t.policyDocArbiter, req, res);
      return true;
    }
    if (urlPath === "/api/prompt-filters/let-through" && req.method === "POST") {
      await postPromptLetThrough(t.policyDocArbiter, t.source, req, res);
      return true;
    }

    // ── /api/secrets (the confidentiality standing-release surface, §6) ───────
    if (urlPath === "/api/secrets" && req.method === "GET") {
      if (!t.secretsArbiter) return arbiterDisabled(res), true;
      await getSecrets(t.secretsArbiter, res);
      return true;
    }
    // The LABELING ACT (plan 6) — the only producer of `any-model` and `local-model`. Both
    // are mutating, so both carry the SAME CSRF guard as an egress verdict: a
    // cross-origin page must not be able to declassify a file by forging a form
    // POST at a dashboard that happens to be open.
    if (urlPath === "/api/secrets/label" && req.method === "POST") {
      if (!t.secretsArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await setSecretLabel(t.secretsArbiter, req, res);
      return true;
    }
    // The Rules page's file browser (dashboard.md §4.25m). The listing is a
    // GET, and a GET is open to any same-host process (the agent's too), so
    // it is served only with the CSRF header AND the admin session, like a
    // labeling act; anyone with the dashboard may browse, remote or not.
    if ((urlPath === "/api/files/list" || urlPath === "/api/files/why") && req.method === "GET") {
      if (!this.requireAdminRead(req, res, urlPath)) return true;
      const deps = { secrets: t.secretsArbiter, policyDoc: t.policyDocArbiter, home: this.fileBrowserHome };
      await (urlPath === "/api/files/list" ? getFileList(deps, url, res) : getFileWhy(deps, url, res));
      return true;
    }
    // A preview and the move are POSTs: the global gate (CSRF + admin) holds them.
    if (urlPath === "/api/files/impact" && req.method === "POST") {
      await postFileImpact({ secrets: t.secretsArbiter, policyDoc: t.policyDocArbiter, home: this.fileBrowserHome }, req, res);
      return true;
    }
    if (urlPath === "/api/files/move-page-rules" && req.method === "POST") {
      await postMovePageRules({ secrets: t.secretsArbiter, policyDoc: t.policyDocArbiter, home: this.fileBrowserHome }, res);
      return true;
    }
    if (urlPath === "/api/files/labels" && req.method === "POST") {
      if (!requireCsrf(req, res)) return true;
      await postFileLabels({ secrets: t.secretsArbiter, policyDoc: t.policyDocArbiter, home: this.fileBrowserHome }, req, res);
      return true;
    }
    // The explorer's Suggested view (dashboard.md §4.25r, plan 14 §5.4). The
    // GET names paths where keys were found, so it is served like the file
    // browser's listing: CSRF header AND admin session. The POSTs sit behind
    // the global gate (CSRF + admin); "Not a secret" also rides the arbiter's
    // admin channel, and so does Save (resolvePolicyProposal).
    if (urlPath === "/api/suggestions" || urlPath.startsWith("/api/suggestions/")) {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      const deps: SuggestionRouteDeps = {
        arbiter: t.policyDocArbiter,
        home: this.fileBrowserHome,
        workspaces: () => {
          const facts = this.homeFactsFor(t.source);
          return recentWorkspaces({ source: t.source, facts, ...this.sessionRuns() });
        },
        ...(this.suggestScanWaitMs !== undefined ? { waitMs: this.suggestScanWaitMs } : {}),
        ...(this.policyModelOffered !== undefined ? { modelOffered: this.policyModelOffered } : {}),
      };
      if (urlPath === "/api/suggestions" && req.method === "GET") {
        if (!this.requireAdminRead(req, res, urlPath)) return true;
        await getSuggestions(deps, res);
        return true;
      }
      if (req.method === "POST" && urlPath === "/api/suggestions/scan") return await postSuggestionScan(deps, req, res), true;
      if (req.method === "POST" && urlPath === "/api/suggestions/apply") return await postSuggestionApply(deps, req, res), true;
      if (req.method === "POST" && urlPath === "/api/suggestions/dismiss") return await postSuggestionDismiss(deps, req, res), true;
      // The model picker (plan 14 §14.5, §14.11; dashboard.md §4.25t):
      // behind the global mutating gate like Scan, and refused unless this
      // server runs with MANDU_EXPERIMENTAL_POLICY_MODEL=1.
      if (req.method === "POST" && urlPath === "/api/suggestions/model/preview") return await postModelPreview(deps, req, res), true;
      if (req.method === "POST" && urlPath === "/api/suggestions/model/send") return await postModelSend(deps, req, res), true;
      json(res, 404, { error: "not found" });
      return true;
    }
    // The Rules page's row buttons (dashboard.md §4.25c): the browser names a
    // row and an action, the edit is planned here from the law in force.
    if (urlPath === "/api/policy/rules/change" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await postRuleChange(t.policyDocArbiter, req, res);
      return true;
    }
    // Settings › Models (dashboard.md §4.25l): add / edit / remove a declared
    // model through the edit grammar, and test one by name. Both POST, so the
    // global gate above already required CSRF + the admin session.
    if (urlPath === "/api/policy/models/change" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await postModelChange(t.policyDocArbiter, req, res);
      return true;
    }
    // Settings › Sensitivity labels (dashboard.md §4.25s, plan 14 §14.1):
    // the GET reports what the last scan found, so it is served like the
    // Suggested view's listing (CSRF header AND admin session); the POST sits
    // behind the global gate and applies on the admin channel.
    if (urlPath === "/api/policy/sensitivity-labels" && req.method === "GET") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      if (!this.requireAdminRead(req, res, urlPath)) return true;
      await getSensitivityLabels(t.policyDocArbiter, res);
      return true;
    }
    // Settings › Prompt filters (dashboard.md §4.25y, plan 15 §13.7): the
    // panel's projection in the product's words. An exception may hold words
    // the person typed, so the GET is served like the Suggested view's
    // listing (CSRF header AND admin session); the POST sits behind the
    // global gate and applies on the admin channel.
    if (urlPath === "/api/policy/prompt-filters" && req.method === "GET") {
      if (!this.requireAdminRead(req, res, urlPath)) return true;
      await getPromptSettings(t.policyDocArbiter, res);
      return true;
    }
    if (urlPath === "/api/policy/prompt-filters/change" && req.method === "POST") {
      await postPromptSettingsChange(t.policyDocArbiter, req, res);
      return true;
    }
    if (urlPath === "/api/policy/sensitivity-labels/change" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await postSensitivityLabelChange(t.policyDocArbiter, req, res);
      return true;
    }
    if (urlPath === "/api/policy/models/test" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await postModelTest(t.policyDocArbiter, req, res, this.modelProbeDeps);
      return true;
    }
    // "Show in policy.yaml" on a Rules row (dashboard.md §4.25g): read-only.
    if (urlPath === "/api/policy/rules/source" && req.method === "GET") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await getRuleSource(t.policyDocArbiter, req.url ?? "", res);
      return true;
    }
    if (urlPath === "/api/policy/export-labels" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await postExportLabels(t.policyDocArbiter, req, res);
      return true;
    }
    // ── rule-change requests from the agent + their history (policy-agent-
    //    surface.md §4.2, §6). GETs are projections; the POSTs are human
    //    decisions (the global mutating gate above already required CSRF +
    //    the admin session) enacted over the arbiter's admin channel. ──
    if (urlPath === "/api/policy/proposals" && req.method === "GET") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await getProposals(t.policyDocArbiter, new URL(url, "http://local"), res, this.adminRead(req), this.fileBrowserHome ?? homedir());
      return true;
    }
    {
      const m = /^\/api\/policy\/proposals\/([^/]+)$/.exec(urlPath);
      if (m && req.method === "POST") {
        if (!t.policyDocArbiter) return arbiterDisabled(res), true;
        if (!requireCsrf(req, res)) return true;
        await postProposalVerdict(t.policyDocArbiter, decodeURIComponent(m[1]!), req, res);
        return true;
      }
    }
    // Who put each Rules row there (dashboard.md §4.25i): a projection.
    if (urlPath === "/api/policy/rules/origins" && req.method === "GET") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await getRuleOrigins(t.policyDocArbiter, res);
      return true;
    }
    if (urlPath === "/api/policy/changes" && req.method === "GET") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      await getChanges(t.policyDocArbiter, new URL(url, "http://local"), res, this.adminRead(req), this.fileBrowserHome ?? homedir());
      return true;
    }
    {
      const m = /^\/api\/policy\/changes\/([^/]+)\/undo$/.exec(urlPath);
      if (m && req.method === "POST") {
        if (!t.policyDocArbiter) return arbiterDisabled(res), true;
        if (!requireCsrf(req, res)) return true;
        await postUndoChange(t.policyDocArbiter, decodeURIComponent(m[1]!), res);
        return true;
      }
    }
    // "Describe what you want" (policy-surface.md §8.5.2): both POSTs sit
    // behind the global mutating gate (the first spends model budget, the
    // second changes the law) and requireCsrf, like the other policy writes.
    if (urlPath === "/api/policy/assistant" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await postSuggest(t.policyDocArbiter, this.assistantModel, req, res, this.fileBrowserHome ?? homedir());
      return true;
    }
    if (urlPath === "/api/policy/assistant/try" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await postTry(t.policyDocArbiter, req, res);
      return true;
    }
    if (urlPath === "/api/policy/assistant/apply" && req.method === "POST") {
      if (!t.policyDocArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await postApply(t.policyDocArbiter, req, res);
      return true;
    }
    // ── /api/config/axes (the Protection drawer's durable axis setup, §4.19 ②):
    //    the integrity/confidentiality keys in the launcher's config.toml.
    //    GET is a read (no CSRF); POST is a configuration ACT — CSRF-gated like
    //    every other human decision. No arbiter NEEDED: this is a file surface,
    //    and it must work exactly when the arbiter is down for the restart the
    //    edit is about — but when one IS connected, an applied change emits the
    //    best-effort config_change audit event and GET carries the who/when
    //    attribution back. ───────────────────────────────────────────────────
    if (urlPath === "/api/config/axes" && req.method === "GET") {
      await getConfigAxes(this.configEnv, t.auditArbiter, res);
      return true;
    }
    if (urlPath === "/api/config/axes" && req.method === "POST") {
      if (!requireCsrf(req, res)) return true;
      await postConfigAxes(this.configEnv, t.auditArbiter, req, res, this.log);
      return true;
    }
    // ── /api/egress/approvals* (egress-approval queue) ─────────────────────────
    if (urlPath === "/api/egress/approvals" && req.method === "GET") {
      if (!t.approvalsArbiter) return arbiterDisabled(res), true;
      await listApprovals(t.approvalsArbiter, url, res);
      return true;
    }
    // Four verbs: approve / approve-once (a single-use verdict, policy-
    // visibility.md §8.7) / deny / send-without ("Send without it", a
    // one-shot denial whose use sends the request with a marker where the
    // secret was: dashboard.md §4.34). Anything else falls off the regex → 404.
    const approvalVerdict = urlPath.match(
      /^\/api\/egress\/approvals\/([^/]+)\/(approve|approve-once|deny|send-without)$/,
    );
    if (approvalVerdict && req.method === "POST") {
      if (!t.approvalsArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      const verb = approvalVerdict[2]!;
      await resolveApproval(
        t.approvalsArbiter,
        decodeURIComponent(approvalVerdict[1]!),
        verb === "approve" || verb === "approve-once",
        res,
        verb === "approve-once" || verb === "send-without" ? "once" : undefined,
        verb === "send-without" ? { strip: true } : undefined,
      );
      return true;
    }
    // One *Always* of a holder's send question (confidentiality plan 13
    // §5.4, §9 R2; dashboard.md §4.34 "A send names every file"): that
    // file's rule gains the destination, applied as the person's loosening
    // on the admin channel. Never a verdict on the row.
    const alwaysSourceMatch = urlPath.match(/^\/api\/egress\/approvals\/([^/]+)\/always-source$/);
    if (alwaysSourceMatch && req.method === "POST") {
      if (!t.approvalsArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await alwaysSource(t.approvalsArbiter, t.policyDocArbiter, decodeURIComponent(alwaysSourceMatch[1]!), req, res);
      return true;
    }
    // Forget a past answer (dashboard.md §4.25c, the Rules page's Remove on an
    // answered ask): the pair is asked again next time. Admin-only op.
    const approvalForget = urlPath.match(/^\/api\/egress\/approvals\/([^/]+)\/forget$/);
    if (approvalForget && req.method === "POST") {
      if (!t.approvalsArbiter) return arbiterDisabled(res), true;
      if (!requireCsrf(req, res)) return true;
      await forgetApproval(t.approvalsArbiter, decodeURIComponent(approvalForget[1]!), res);
      return true;
    }

    return false;
  }

}

/**
 * Strip the dashboard's base path from a request URL, only at a path-segment
 * boundary: with basePath "/mandu", "/mandu", "/mandu/x" and "/mandu?q" are
 * prefixed, but "/mandu.css" (the shared stylesheet, requested unprefixed when
 * a front such as the cloudflared tunnel forwards the root as-is) is not. A
 * bare prefix match turned it into ".css" and the product page lost its styles.
 */
export function stripBasePath(url: string, basePath: string): string {
  if (!basePath || !url.startsWith(basePath)) return url;
  const next = url[basePath.length];
  if (next !== undefined && next !== "/" && next !== "?") return url;
  const rest = url.slice(basePath.length);
  return rest.startsWith("/") ? rest : `/${rest}`;
}
