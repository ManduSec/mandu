/**
 * server/http-util — request/response plumbing shared by the dashboard's route
 * modules (extracted VERBATIM from src/server.ts in the server.ts decomposition;
 * see server.ts for the route map and security posture).
 */

import { createHash } from "node:crypto";
import { type IncomingMessage, type ServerResponse } from "node:http";
import { gzip } from "node:zlib";

export function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c: Buffer) => (data += c.toString()));
    req.on("end", () => resolve(data));
  });
}

/**
 * Read + parse a JSON request body. Returns the parsed value, or `undefined` on
 * a parse error (the caller maps that to 400). An empty body parses as `{}` so a
 * route can read optional fields without special-casing it.
 */
export async function readJson(req: IncomingMessage): Promise<unknown> {
  const raw = await readBody(req);
  if (raw.trim() === "") return {};
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

export function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

/**
 * The admin channel is how the dashboard reaches the arbiter's human-decision
 * ops (approvals, labels, posture, session deletion — policy-surface.md
 * §2.6). It exists only when THIS dashboard spawned the arbiter (an inherited
 * fd); an adopted arbiter has none. Write adapters throw an error carrying
 * this prefix; the routes map it to 503 with the message intact, so the UI
 * can say what to do (restart the services from here) instead of "arbiter
 * error".
 */
export const ADMIN_UNAVAILABLE_PREFIX = "admin channel unavailable";

export function adminUnavailableError(detail: string): Error {
  return new Error(`${ADMIN_UNAVAILABLE_PREFIX}: ${detail}`);
}

/** True for the two admin-boundary failures a write route can see: no admin
 *  channel (adopted arbiter), or an op that reached the arbiter on the data
 *  socket and was refused there ("admin-only"). Both are 503 — the state of the
 *  stack, not the request — never 404/502. */
export function isAdminBoundaryError(err: unknown): boolean {
  const msg = String((err as Error)?.message ?? err);
  return msg.startsWith(ADMIN_UNAVAILABLE_PREFIX) || msg.startsWith("admin-only:");
}

/** CSRF: a mutating POST must carry the X-Mandu-Control header (node
 *  lowercases header names). Returns false (and responds 403) if absent. */
export function requireCsrf(req: IncomingMessage, res: ServerResponse): boolean {
  if (req.headers["x-mandu-control"] === undefined) {
    json(res, 403, { error: "missing X-Mandu-Control" });
    return false;
  }
  return true;
}

// ── conditional + compressed responses (dashboard.md §4.30) ──────────────────
// Used by the large, polled /api/sessions, the test-data listings
// (/api/replay, /api/drill-matrix, /api/coverage, /api/drills/scenarios) and
// the static assets; not by the approval, policy or secret routes (§4.30
// "Payload budgets" says why). Every
// caller sits behind the same source-IP / auth gates as before (server.ts
// handle): these change how the bytes travel, never which bytes a client gets.

/** A body smaller than this goes out uncompressed (gzip would not pay). */
export const GZIP_MIN_BYTES = 1024;

/** Does the request accept a gzip body? (`gzip;q=0` refuses it.) */
export function acceptsGzip(req: IncomingMessage): boolean {
  const ae = req.headers["accept-encoding"];
  if (typeof ae !== "string") return false;
  return ae.split(",").some((part) => {
    const [coding, ...params] = part.trim().toLowerCase().split(";");
    const c = (coding ?? "").trim();
    if (c !== "gzip" && c !== "*") return false;
    const q = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
    return q === undefined || Number(q.slice(2)) > 0;
  });
}

/** A weak validator of a body's exact bytes. */
export function weakEtag(body: string | Buffer): string {
  return `W/"${createHash("sha1").update(body).digest("base64url")}"`;
}

/** Does If-None-Match name `etag`? (the weak comparison a GET allows) */
export function etagMatches(req: IncomingMessage, etag: string): boolean {
  const inm = req.headers["if-none-match"];
  if (typeof inm !== "string" || !inm.trim()) return false;
  if (inm.trim() === "*") return true;
  const opaque = (t: string): string => t.trim().replace(/^W\//, "");
  return inm.split(",").some((t) => opaque(t) === opaque(etag));
}

/** The last few gzipped bodies by ETag, so an identical answer (two tabs, the
 *  first poll after a change) is compressed once. */
const gzipByEtag = new Map<string, Buffer>();
const GZIP_CACHE_MAX = 32;

/**
 * Send `body` with `headers`, gzipped when the client accepts it and the body
 * is worth it. Compression runs in libuv's thread pool, off the event loop.
 * `etag` (when given) keys the small cache of compressed bodies.
 */
export function sendBody(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  headers: Record<string, string>,
  body: string | Buffer,
  etag?: string,
): Promise<void> {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const plain = (): void => {
    res.writeHead(status, { ...headers, Vary: "Accept-Encoding", "Content-Length": String(buf.length) });
    res.end(buf);
  };
  if (buf.length < GZIP_MIN_BYTES || !acceptsGzip(req)) {
    plain();
    return Promise.resolve();
  }
  const send = (gz: Buffer): void => {
    res.writeHead(status, { ...headers, Vary: "Accept-Encoding", "Content-Encoding": "gzip", "Content-Length": String(gz.length) });
    res.end(gz);
  };
  const cached = etag !== undefined ? gzipByEtag.get(etag) : undefined;
  if (cached) {
    send(cached);
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    gzip(buf, (err, gz) => {
      if (err) plain();
      else {
        if (etag !== undefined) {
          gzipByEtag.set(etag, gz);
          while (gzipByEtag.size > GZIP_CACHE_MAX) gzipByEtag.delete(gzipByEtag.keys().next().value!);
        }
        send(gz);
      }
      resolve();
    });
  });
}

/**
 * A JSON answer with an ETag over its exact bytes: a request whose
 * If-None-Match names it gets 304 and no body; otherwise the body goes out,
 * gzipped when accepted. It stays `no-store` like every other API answer (the
 * browser keeps no copy): the client that wants the 304 keeps its own last
 * body and sends If-None-Match itself (dev/js/app.js loadSessions).
 */
export function jsonConditional(req: IncomingMessage, res: ServerResponse, body: unknown): Promise<void> {
  const text = JSON.stringify(body);
  const etag = weakEtag(text);
  if (etagMatches(req, etag)) {
    res.writeHead(304, { ETag: etag, "Cache-Control": "no-store", Vary: "Accept-Encoding" });
    res.end();
    return Promise.resolve();
  }
  return sendBody(req, res, 200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ETag: etag }, text, etag);
}
