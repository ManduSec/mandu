/**
 * recording-relay — a verbatim HTTP relay that RECORDS every request and
 * response body it carries, for the live drills that must assert on the
 * bytes a model endpoint actually received (plan 11 §4 live row, §8 row 1).
 *
 * The local-model drill (local-model.test.ts) puts one of these in front
 * of each model endpoint whose wire it must see:
 *   - the T-LLM vendor wire: the launcher's model proxy gets it as its
 *     upstream (MANDU_UPSTREAM=http://127.0.0.1:<port>; the proxy speaks plain
 *     http only to a literal loopback address) and the relay forwards to
 *     https://api.anthropic.com, so every request the vendor receives from the
 *     proxy, side calls included, is on record;
 *   - the default U-LLM vendor wire: the launcher's U-LLM forwarder relays to
 *     MANDU_ULLM_BASE_URL, which the drill points at a second relay;
 *   - the declared local model: the relay IS the `models:` entry's url and
 *     forwards to the Ollama on this host.
 *
 * What it does NOT do: parse, rewrite, symbolize or authenticate. Auth
 * headers pass verbatim (agent-sign-in.md §1: never normalize them), only
 * hop-by-hop headers are dropped and `host` names the target. The recorded
 * copy is decoded (gzip / deflate / br / zstd) so a canary grep sees plain
 * text; the forwarded bytes are the original ones.
 *
 * Mandu-new test plumbing (no reference origin); the header handling mirrors
 * launcher/src/services/ullm-forwarder.ts without importing it (a relay this
 * small is cheaper to own than to couple the harness to the launcher's).
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import type { AddressInfo } from "node:net";
import * as zlib from "node:zlib";

/** One relayed exchange, bodies decoded for grepping. */
export interface WireRecord {
  method: string;
  path: string;
  /** The request body as text (decoded when content-encoded). */
  reqBody: string;
  /** The upstream's status, or 502 when the relay could not reach it. */
  status: number;
  /** The response body as text (decoded when content-encoded); SSE stays SSE. */
  resBody: string;
  /** Set when the upstream leg failed (connect error, reset). */
  error?: string;
  /** The request's `user-agent` (the agent CLI and its version, which the
   *  drill recorder names in a recorded script's origin). The only header
   *  recorded: auth headers never reach a record. */
  userAgent?: string;
  /** When the request body was complete (epoch ms): orders the records of
   *  several relays (model-capture.ts). */
  at?: number;
}

export interface RecordingRelay {
  /** http://127.0.0.1:<port> */
  url: string;
  port: number;
  /** Every exchange, in arrival order (the entry is pushed when the request
   *  body is complete; resBody/status fill in as the response finishes). */
  records: WireRecord[];
  /** Resolves when every exchange started so far has finished. */
  settle: () => Promise<void>;
  close: () => Promise<void>;
}

const DROP_REQUEST_HEADERS = new Set([
  "host", "connection", "proxy-connection", "keep-alive", "upgrade",
  "transfer-encoding", "te", "trailer", "content-length",
]);
const DROP_RESPONSE_HEADERS = new Set([
  "connection", "keep-alive", "transfer-encoding", "trailer", "upgrade",
]);

/** Decode a body for the RECORD only. Unknown or failing encodings fall back
 *  to the raw bytes as latin1-safe utf8, so a grep still runs over something. */
export function decodeBody(buf: Buffer, encoding: string | string[] | undefined): string {
  const enc = (Array.isArray(encoding) ? encoding[0] : encoding ?? "").trim().toLowerCase();
  try {
    if (enc === "gzip" || enc === "x-gzip") return zlib.gunzipSync(buf).toString("utf8");
    if (enc === "deflate") return zlib.inflateSync(buf).toString("utf8");
    if (enc === "br") return zlib.brotliDecompressSync(buf).toString("utf8");
    if (enc === "zstd") {
      const z = (zlib as unknown as { zstdDecompressSync?: (b: Buffer) => Buffer }).zstdDecompressSync;
      if (z) return z(buf).toString("utf8");
    }
  } catch {
    /* fall through to the raw bytes */
  }
  return buf.toString("utf8");
}

/**
 * Start a relay on 127.0.0.1:<ephemeral> that forwards every request to
 * `target` (an origin, http or https) and records it.
 */
export async function startRecordingRelay(target: string): Promise<RecordingRelay> {
  const upstream = new URL(target);
  const isHttps = upstream.protocol === "https:";
  const doRequest = isHttps ? httpsRequest : httpRequest;
  const upstreamPort = upstream.port ? Number(upstream.port) : isHttps ? 443 : 80;
  const records: WireRecord[] = [];
  const inflight = new Set<Promise<void>>();

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    let done!: () => void;
    const finished = new Promise<void>((r) => { done = r; });
    inflight.add(finished);
    void finished.then(() => inflight.delete(finished));
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("error", () => done());
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const rec: WireRecord = {
        method: req.method ?? "GET",
        path: req.url ?? "/",
        reqBody: decodeBody(body, req.headers["content-encoding"]),
        status: 0,
        resBody: "",
        ...(typeof req.headers["user-agent"] === "string" ? { userAgent: req.headers["user-agent"] } : {}),
        at: Date.now(),
      };
      records.push(rec);
      const headers: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined || DROP_REQUEST_HEADERS.has(k.toLowerCase())) continue;
        headers[k] = v;
      }
      headers["host"] = upstream.host;
      headers["content-length"] = String(body.length);
      // One retry when the upstream leg fails before any response byte (a
      // transient connect failure to the vendor showed up live as a 502
      // AggregateError the client then had to retry itself).
      const attempt = (retriesLeft: number): void => {
      let responded = false;
      const up = doRequest(
        {
          protocol: upstream.protocol,
          hostname: upstream.hostname,
          port: upstreamPort,
          method: req.method,
          path: req.url,
          headers,
        },
        (upRes) => {
          responded = true;
          rec.status = upRes.statusCode ?? 502;
          const out: Record<string, string | string[]> = {};
          for (const [k, v] of Object.entries(upRes.headers)) {
            if (v === undefined || DROP_RESPONSE_HEADERS.has(k.toLowerCase())) continue;
            out[k] = v;
          }
          res.writeHead(rec.status, out);
          const resChunks: Buffer[] = [];
          upRes.on("data", (c: Buffer) => { resChunks.push(c); res.write(c); });
          upRes.on("end", () => {
            rec.resBody = decodeBody(Buffer.concat(resChunks), upRes.headers["content-encoding"]);
            res.end();
            done();
          });
          upRes.on("error", (e) => {
            rec.error = String(e);
            rec.resBody = decodeBody(Buffer.concat(resChunks), upRes.headers["content-encoding"]);
            res.destroy();
            done();
          });
        },
      );
      up.on("error", (e) => {
        if (!responded && retriesLeft > 0) { attempt(retriesLeft - 1); return; }
        rec.status = 502;
        rec.error = String(e);
        if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
        res.end(`recording-relay: upstream ${upstream.origin} failed: ${String(e)}`);
        done();
      });
      up.end(body);
      };
      attempt(1);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    records,
    settle: async () => { await Promise.all([...inflight]); },
    close: () =>
      new Promise<void>((r) => {
        server.close(() => r());
        server.closeAllConnections();
      }),
  };
}

/** Every recorded byte of a relay (requests and responses), for a grep. */
export function wireText(records: readonly WireRecord[]): string {
  return records.map((r) => `${r.method} ${r.path}\n${r.reqBody}\n--- ${r.status}\n${r.resBody}`).join("\n");
}
