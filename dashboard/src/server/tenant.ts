/**
 * server/tenant — which tenant's store a request is served from, and how a
 * tenant whose arbiter is down answers (policy-surface.md §2.7 1c;
 * dashboard.md §6.y). Mandu-new, pure: server.ts reads the request and acts.
 *
 * THE RULE. `?tenant=` (explicit) wins; else the `mandu_tenant` cookie, else
 * live. The cookie is the INSPECTOR's choice (its 🧪 Tests view sets it, so
 * every fetch and SSE stream of that page follows it with no per-call
 * plumbing), and it is scoped to the inspector: a request from the PRODUCT
 * page (dashboard.md §4.25) never reads it. The product is the person's own
 * agents, which live in the live store; a cookie left behind by a visit to the
 * inspector's Tests view must not swap the person's Home for the test
 * harness's store (2026-10-03: with the test arbiter down it read "Not
 * connected (home → 500)"). A product request is
 *   - one to a route only the product reads (`/api/home`, `/api/home/agent`),
 *     whatever it carries, or
 *   - one carrying `X-Mandu-Front: product`, which every fetch of
 *     public/js/home.js sends (the routes it shares with the inspector, such
 *     as /api/policy/panel or /api/egress/approvals, cannot tell otherwise).
 * An explicit `?tenant=` still wins for both: the choice is visible in the
 * URL, so it is never a leftover.
 *
 * Not a security boundary: both stores sit behind the same gates and either
 * is served to the same signed-in person. The header only says which page
 * asked; a page that forges it gets the live store, as with no cookie.
 *
 * THE UNREACHABLE TENANT. An event source whose arbiter is down throws
 * "arbiter connection failed (<sock>): connect ENOENT …" (or the human plane
 * is missing). That is the state of the stack, not the request, so it is
 * answered 503 with a body the page can show (`unreachableBody`), never the
 * handler's bare 500 "Internal error".
 */

import { type IncomingMessage } from "node:http";
import { type Tenant } from "./options.js";

export const TENANT_COOKIE = "mandu_tenant";
/** The request header the product page's fetches carry (node lowercases). */
export const FRONT_HEADER = "x-mandu-front";

/** Routes only the product page reads: served for the live tenant unless the
 *  URL names one, whatever the cookie or header says. */
export const PRODUCT_ONLY_ROUTES: ReadonlySet<string> = new Set(["/api/home", "/api/home/agent"]);

/** True when the product page asked (see the module comment). */
export function isProductRequest(urlPath: string, headers: IncomingMessage["headers"]): boolean {
  if (PRODUCT_ONLY_ROUTES.has(urlPath)) return true;
  const h = headers[FRONT_HEADER];
  return (Array.isArray(h) ? h[0] : h) === "product";
}

/** The `mandu_tenant` cookie's value, or null when absent / not a tenant. */
export function tenantCookie(cookieHeader: string | undefined): Tenant | null {
  for (const part of (cookieHeader ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === TENANT_COOKIE) {
      const val = v.join("=");
      if (val === "test" || val === "live") return val;
    }
  }
  return null;
}

/**
 * Which tenant a request asks for. `tenant: null` = an explicit but invalid
 * `?tenant=` (answered 400). `explicit` = named in the URL (a missing test
 * tenant is then 404, never a silent fallback).
 */
export function requestedTenant(
  url: string,
  headers: IncomingMessage["headers"],
  urlPath: string = url.split("?")[0]!,
): { tenant: Tenant | null; explicit: boolean } {
  const q = new URLSearchParams(url.split("?")[1] ?? "").get("tenant");
  if (q !== null) return { tenant: q === "live" || q === "test" ? q : null, explicit: true };
  if (isProductRequest(urlPath, headers)) return { tenant: "live", explicit: false };
  return { tenant: tenantCookie(headers.cookie) ?? "live", explicit: false };
}

/** An error that means the tenant's arbiter cannot be reached (the event
 *  source's connect failed, the socket closed before a reply, or the arbiter
 *  names no human plane). */
export function isArbiterUnreachable(err: unknown): boolean {
  const msg = String((err as Error)?.message ?? err);
  return /^arbiter connection (failed|closed)\b/.test(msg) || /^human plane unavailable\b/.test(msg);
}

/** The 503 body for a tenant whose arbiter is down: what is down and what to
 *  do, in the inspector's words (the product page shows its own sentence off
 *  `unreachable`). */
export function unreachableBody(tenant: Tenant, err: unknown): { error: string; tenant: Tenant; unreachable: true } {
  const detail = String((err as Error)?.message ?? err);
  const error = tenant === "test"
    ? `the test tenant's arbiter is not reachable (${detail}): start test-arbiter under Services, or leave the Tests view for the live store`
    : `the arbiter is not reachable (${detail}): start it under Services`;
  return { error, tenant, unreachable: true };
}
