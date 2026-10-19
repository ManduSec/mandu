/**
 * page-fetch.ts — the fetch a served page (run in jsdom against the real
 * DashboardServer, in the test's own process) is bridged to.
 *
 * Every request goes on a socket of its own, opened for it and closed after
 * it (node:http with no agent), never through fetch's shared connection pool.
 * jsdom runs the whole home.js synchronously, so on a loaded CI guest the
 * event loop is blocked for seconds. A request the page makes in that block
 * that is given an idle keep-alive socket from the pool is lost once the
 * block outlasts the server's keep-alive timeout (Node's 5 s): after the
 * block the server's timer runs first and drops the socket under the
 * request (`fetch failed` / `read ECONNRESET`), so Home rendered "Could not
 * check which agents are running" (pipelines 10057, 10066, 10069;
 * test-organization.md §8.4).
 *
 * Until 2026-10-11 this sent `Connection: close` through the global fetch.
 * That closes the socket after the request, but the pool still hands the
 * request an idle socket another fetch left: the test's own fetch of the
 * page's HTML and home.js, a moment before the block. The flake kept
 * failing pipelines (10185, 10250, 10251, 10258, 10353, 10354), each test
 * over 6.5 s, and a 9 s block before the page's script reproduced it every
 * time. A socket of its own has no idle time to lose, whatever else in the
 * process fetched from the server.
 */

import { request } from "node:http";
import { Readable } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export async function pageFetch(input: string | URL, init: RequestInit = {}, hops = 0): Promise<Response> {
  const res = await once(input, init);
  // As fetch does: follow a redirect (unless asked not to), a 303's, or a
  // POST's 301 or 302, as a GET without its body; the answer says it was.
  const location = res.headers.get("location");
  if (!REDIRECTS.has(res.status) || !location || init.redirect === "manual" || hops >= 20) return res;
  if (init.redirect === "error") throw new TypeError("fetch failed", { cause: new Error("redirect") });
  await res.body?.cancel();
  const method = (init.method ?? "GET").toUpperCase();
  const asGet = res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST");
  const next = await pageFetch(new URL(location, String(input)), asGet ? { ...init, method: "GET", body: undefined } : init, hops + 1);
  Object.defineProperty(next, "redirected", { value: true });
  return next;
}

async function once(input: string | URL, init: RequestInit): Promise<Response> {
  // The Request normalizes what fetch would: the method, the headers (a
  // string body's content type), and the body as bytes.
  const req = new Request(input, { ...init, redirect: "manual" });
  const body = req.body ? Buffer.from(await req.arrayBuffer()) : undefined;
  const headers: Record<string, string> = {};
  req.headers.forEach((v, k) => { headers[k] = v; });
  headers.connection = "close";
  if (body) headers["content-length"] = String(body.length);
  const url = new URL(req.url);
  return new Promise<Response>((resolve, reject) => {
    const r = request(url, { method: req.method, headers, agent: false, signal: init.signal ?? undefined }, (res) => {
      const status = res.statusCode ?? 0;
      const out = new Headers();
      for (let i = 0; i < res.rawHeaders.length; i += 2) out.append(res.rawHeaders[i]!, res.rawHeaders[i + 1]!);
      const empty = req.method === "HEAD" || status === 204 || status === 304;
      if (empty) res.resume();
      // As fetch does: a compressed body is read decoded, its header kept.
      const enc = String(res.headers["content-encoding"] ?? "").trim().toLowerCase();
      const decode = enc === "gzip" || enc === "x-gzip" ? createGunzip() : enc === "deflate" ? createInflate() : enc === "br" ? createBrotliDecompress() : null;
      const body: Readable = decode ? res.pipe(decode) : res;
      if (decode) res.on("error", (e) => decode.destroy(e));
      const answer = new Response(empty ? null : (Readable.toWeb(body) as ReadableStream<Uint8Array>), { status, statusText: res.statusMessage, headers: out });
      Object.defineProperty(answer, "url", { value: url.href });
      resolve(answer);
    });
    // As fetch does: a request that never got an answer rejects with a
    // TypeError naming its cause; an aborted one with the abort's reason.
    r.on("error", (e) => reject(init.signal?.aborted ? init.signal.reason : new TypeError("fetch failed", { cause: e })));
    r.end(body);
  });
}
