/**
 * server/extension — the dashboard's plug-in hook (dashboard.md §4.25ac).
 *
 * The product page at `/` is the dashboard every build serves. A front-end
 * beyond it (the developer view at `/dev/`) is an extension: a module the
 * server is handed at construction. It answers the requests under its mount
 * (its pages and files) and may answer routes of its own elsewhere (its
 * `/api/` routes), each after every gate of DashboardServer.handle (source
 * IP, Host, auth, CSRF + admin session, read gate, tenant) has run. A build
 * without one serves the product only: its mount answers 404, its routes
 * are not there, and the product page, told by the `extensions` meta its
 * index carries, leaves out the links into it.
 */

import { type IncomingMessage, type ServerResponse } from "node:http";

import { type EventSource } from "../event-source.js";
import { type Supervisor } from "../supervisor/supervisor.js";
import { type SidebarTestRun, type SidebarWatchRun } from "../session-batches.js";
import { type Tenant, type TenantState } from "./options.js";
import { type ReadRoute } from "./read-gate.js";
import { type WarmResult } from "./cache-warmup.js";

/** One request, as an extension sees it: past every gate, base path stripped. */
export interface ExtensionRequest {
  /** The path, base path and query stripped (`/dev/sessions/abc`). */
  urlPath: string;
  /** The path with its query, base path stripped. */
  url: string;
  req: IncomingMessage;
  res: ServerResponse;
  /** The reverse-proxy prefix (no trailing slash), for a redirect or a `<base>`. */
  basePath: string;
}

/** A request outside the mount, with the tenant it is served for. */
export interface ExtensionRouteRequest extends ExtensionRequest {
  /** The tenant's store and arbiter surfaces (§2.7 1c). */
  tenant: TenantState;
  /** Which tenant that is. */
  tenantName: Tenant;
  /** The read may carry a real value (read-gate.ts `valueRead`). */
  values: boolean;
}

/** What the server lends an extension (`attach`, once, at construction). */
export interface ExtensionHost {
  log(msg: string): void;
  /** The live tenant's store. */
  liveSource: EventSource;
  /** The process supervisor, when this dashboard runs the services. */
  supervisor?: Supervisor;
  /** The env the config-path resolution reads (config-axes.ts). */
  configEnv: Record<string, string | undefined>;
  /** The CSRF header AND the admin session, as Settings' guarded reads
   *  need; false once refused (the 403 is answered). */
  requireAdminRead(req: IncomingMessage, res: ServerResponse, urlPath: string): boolean;
  hasAdminSession(req: IncomingMessage): boolean;
}

/** The runs that sort the session list (session-batches.ts): a test run's
 *  and a drill run's sessions are not the person's own. */
export interface SessionRuns {
  testRuns: SidebarTestRun[];
  watchRuns: SidebarWatchRun[];
}

export interface DashboardExtension {
  /** Its name in the product page's `extensions` meta and in logs (`inspector`). */
  readonly name: string;
  /** The path it owns, no trailing slash (`/dev`): the path itself and
   *  every path under it come here, and nothing else does. */
  readonly mount: string;
  /** Answer a request under the mount. Every one is the extension's to
   *  answer, a 404 included. */
  handle(r: ExtensionRequest): Promise<void> | void;
  /** Answer one of its routes outside the mount (its `/api/` routes); false
   *  leaves the request to the product's routes. Asked before them, so it
   *  may also answer a shared route with more (the inspector's session
   *  list knows the recorded runs). */
  route?(r: ExtensionRouteRequest): Promise<boolean> | boolean;
  /** The read gate's rows for its GET routes (read-gate.ts). A GET it
   *  answers that no row names is `admin`. */
  readonly readRoutes?: readonly ReadRoute[];
  /** The runs that are not the person's own sessions (Home leaves them out). */
  sessionRuns?(): SessionRuns;
  /** Called once by the server's constructor. */
  attach?(host: ExtensionHost): void;
  /** Before the server listens (a cache to load). */
  start?(): void;
  /** Once the server listens (a warm-up to start). */
  listening?(): void;
  /** Its boot warm-up, started once (a test awaits it). */
  warmup?(): Promise<WarmResult[]>;
  /** On the server's close, before its own sources and services. */
  close?(): Promise<void>;
}

/** Is `urlPath` under the mount (the mount itself, or below it)? */
export function underMount(urlPath: string, mount: string): boolean {
  return urlPath === mount || urlPath.startsWith(mount + "/");
}

/** The extension owning `urlPath`, if one does (the first mount wins). */
export function extensionFor(urlPath: string, extensions: readonly DashboardExtension[]): DashboardExtension | undefined {
  return extensions.find((x) => underMount(urlPath, x.mount));
}
