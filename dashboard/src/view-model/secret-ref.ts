/**
 * view-model/secret-ref — the opaque name a product page gives a secret it
 * can show on a click (dashboard.md §4.25b "Showing a real value").
 * Mandu-new.
 *
 * The product page never carries a `$MDU:` token (home.ts vocabulary rule),
 * yet a signed-in person's click must name ONE secret of ONE session. The
 * page carries `secretRef(session, token)` instead; the reveal route
 * (server/secret-reveal-routes.ts) recomputes it over the secrets that
 * session recorded and resolves only a match. Not a secret itself: the
 * reveal needs the admin session whatever ref it is sent.
 */
import { createHash } from "node:crypto";

/** 24 hex characters of sha256(session NUL token). */
export function secretRef(sessionId: string, token: string): string {
  return createHash("sha256").update(`${sessionId}\u0000${token}`).digest("hex").slice(0, 24);
}

export const SECRET_REF_RE = /^[0-9a-f]{24}$/;
