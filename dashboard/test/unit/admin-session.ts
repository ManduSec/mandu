/**
 * admin-session — the ONE admin session every dashboard test uses
 * (policy-surface.md §2.6; src/server.ts DashboardServerOptions
 * adminToken / sessionSecret).
 *
 * Every mutating route needs an admin session. A test pins the token and the
 * cookie-derivation secret on the servers it starts (`...ADMIN_OPTS`) and
 * sends the precomputed cookie (`ADMIN_COOKIE`) with the CSRF header. Tests
 * that assert the missing-header 403 keep sending no headers — the CSRF gate
 * runs first, so their wording is unchanged; the admin-session gate has its
 * own suite (admin-session.test.ts).
 */
import { createHash } from "node:crypto";

export const ADMIN_TOKEN = "test-admin-token";
export const SESSION_SECRET = "test-session-secret";

/** Spread into DashboardServer options. */
export const ADMIN_OPTS = { adminToken: ADMIN_TOKEN, sessionSecret: SESSION_SECRET } as const;

/** `sha256((password || adminToken) + sessionSecret)` — server.ts token(). */
export const ADMIN_COOKIE = `mandu_session=${createHash("sha256")
  .update(ADMIN_TOKEN + SESSION_SECRET)
  .digest("hex")}`;

/** CSRF header + admin cookie: what a mutating request from the real page carries. */
export const CSRF_ADMIN: Record<string, string> = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE };
