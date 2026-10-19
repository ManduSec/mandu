/**
 * services/ullm-forwarder — a VERBATIM loopback→api.anthropic.com relay for the
 * quarantined U-LLM (docs/design/integrity/exec-routing.md §7.1 "the U-LLM / 443 crux").
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. The header/stream handling mirrors the anthropic-proxy's
 *   verbatim-relay primitives (interceptors/anthropic-proxy/src/proxy.ts
 *   sanitizeHeaders / responseHeaders / forwardAndStream(sniff=false)) without
 *   importing them (cross-package src imports are against the launcher's
 *   drive-as-subprocess pattern; this relay is small enough to own).
 *
 * WHY THIS EXISTS. The whole-agent Landlock TCP wrap (--landlock-net) is
 * port-only — allowing :443 for the U-LLM's direct api.anthropic.com dial also
 * allows ANY :443 exfil. This forwarder runs IN the launcher process, which sits
 * OUTSIDE the Landlock wrap (the wrap confines only the spawned agent tree), and
 * relays verbatim to the real Anthropic endpoint. The U-LLM (inspect-mcp, a
 * stdio child INSIDE the wrap) is pointed at http://127.0.0.1:<port> instead of
 * dialing :443 — so the strong posture (deny in-agent 443) keeps a working
 * U-LLM, and the reachable egress DESTINATION is pinned to api.anthropic.com
 * (the thing a port-only allow-list cannot express).
 *
 * WHAT THIS IS NOT (the invariant that keeps it legal): the U-LLM channel must
 * NEVER route through the INSTRUMENTED anthropic-proxy (CONTRIBUTING.md; the U-LLM is
 * a separate quarantined channel). This relay does NOT touch the arbiter, does
 * NOT symbolize, does NOT inject prompts, does NOT parse bodies — it forwards
 * bytes. inspect-mcp's loopback guard (assertNonProxyBaseUrl) stays fail-closed
 * for every loopback URL EXCEPT the one the launcher pins via
 * MANDU_ULLM_FORWARDER, which names exactly this relay.
 *
 * THE CODEX FORM (2026-10-04, agent-sign-in.md §2.11): a Codex U-LLM is a
 * cut-down `codex exec`, pointed at this relay by a provider override; it
 * relays a model call only, to one of the fixed OpenAI pair, chosen per
 * request (`codexRelayRoute`).
 *
 * THE KEY, PUT BACK HERE (2026-10-11, agent-sign-in.md §3.8): in the
 * Anthropic form the launcher may hand the U-LLM a stand-in for its API key
 * (`apiKey.standIn`, a random token) instead of the key, which then never
 * enters the agent's world through the inspect server's entry (.mcp.json,
 * OpenCode's config, OpenClaw's plugin config). On `POST /v1/messages` only,
 * an `x-api-key` whose whole value is the stand-in is replaced with the key
 * (`apiKey.key`, the launcher's own copy: this relay runs in the launcher,
 * which read it from the human's environment) toward the fixed upstream, and
 * only when that upstream is https or a literal loopback stand-in. Any other
 * path, header or value is relayed as it came: the stand-in, which the
 * provider refuses. No arbiter is asked: nothing here releases a value the
 * U-LLM did not already hold before 2026-10-11.
 *
 * The Codex form does the same for Codex's saved key (§3.9): the quarantined
 * `codex exec` reads `auth.json` from the agent's world, where the launch
 * twinned it, and sends `Authorization: Bearer <placeholder>`. Once the
 * launcher knows the placeholder (after the twins, `setApiKey`), a request
 * relayed to the API origin (never the ChatGPT base) whose bearer is exactly
 * that placeholder gets the launcher's own copy of the key, read from the
 * human's `auth.json`.
 *
 * UTILITY-CLASS degrade: a forwarder that cannot start only warns — the U-LLM
 * then keeps its direct :443 dial and the landlock-net port set keeps 443 open
 * (the weak-but-working posture this replaces).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { URL } from "node:url";
import { randomBytes } from "node:crypto";

/** The identity shape served at GET /_mandu/identity (mirrors the proxies'
 *  ProxyIdentity so services/primitives.ts probeIdentity parses it as-is). */
export const ULLM_FORWARDER_SERVICE = "ullm-forwarder";

/** Hop-by-hop request headers we must not forward (node re-frames the body, and
 *  `host` must name the upstream for SNI/virtual-hosting). Auth headers pass
 *  VERBATIM — agent-sign-in.md §1: never normalize the auth header. */
const DROP_REQUEST_HEADERS = new Set([
  "host", "connection", "proxy-connection", "keep-alive", "upgrade",
  "transfer-encoding", "te", "trailer",
]);
/** Hop-by-hop response headers node manages itself on the downstream leg. */
const DROP_RESPONSE_HEADERS = new Set([
  "connection", "keep-alive", "transfer-encoding", "trailer", "upgrade",
]);

export interface UllmForwarderOptions {
  /** The REAL upstream origin (https://api.anthropic.com; tests point at a mock). */
  upstream: string;
  /** The U-LLM's API key, put back here (see the header): the stand-in the
   *  U-LLM was handed, and the key that replaces it. */
  apiKey?: { standIn: string; key: string };
}

/** A fresh stand-in for the U-LLM's key: random per launch, never derived
 *  from the key, header-safe. */
export function ullmKeyStandIn(): string {
  return `mandu-ullm-key-${randomBytes(24).toString("hex")}`;
}

/** The path the stand-in is replaced on: the U-LLM's model call. */
const ULLM_MESSAGES_PATH = "/v1/messages";

/** Header-safe (no CR, LF or other control character): what a stand-in and
 *  a key put back must be. */
const HEADER_SAFE_RE = /^[\x21-\x7e]+$/;

/**
 * The request headers with the U-LLM's key put back, or as they came: only
 * for `POST /v1/messages` (any query), only an `x-api-key` whose whole value
 * is the stand-in, only when the key is header-safe. Pure.
 */
export function restoreUllmKey(
  method: string | undefined,
  url: string | undefined,
  headers: Record<string, string | string[]>,
  apiKey: { standIn: string; key: string } | undefined,
): { headers: Record<string, string | string[]>; restored: boolean } {
  if (!apiKey || method !== "POST") return { headers, restored: false };
  const u = url ?? "";
  const q = u.indexOf("?");
  if ((q < 0 ? u : u.slice(0, q)) !== ULLM_MESSAGES_PATH) return { headers, restored: false };
  if (!HEADER_SAFE_RE.test(apiKey.key) || !HEADER_SAFE_RE.test(apiKey.standIn)) return { headers, restored: false };
  const name = Object.keys(headers).find((k) => k.toLowerCase() === "x-api-key");
  if (name === undefined || headers[name] !== apiKey.standIn) return { headers, restored: false };
  return { headers: { ...headers, [name]: apiKey.key }, restored: true };
}

/**
 * The Codex quarantine's relay (2026-10-04, agent-sign-in.md §2.11): the
 * `codex exec` child is pointed at this relay (a provider override with
 * `requires_openai_auth`), and every request goes to ONE of a fixed pair,
 * chosen per request as the openai-proxy chooses (`chooseUpstream` there):
 * the ChatGPT backend's Codex base for a request on a ChatGPT sign-in (it
 * carries `chatgpt-account-id`), else the OpenAI API origin. Only a model
 * call is relayed (`codexRelayRoute`): anything else is refused here and
 * nothing is sent, so the relay is no door to the rest of either host.
 */
export interface CodexUllmForwarderOptions {
  /** Codex's saved key, put back as the bearer of a request to the API
   *  origin (see the header); usually set later, with `setApiKey`. */
  apiKey?: { standIn: string; key: string };
  codex: {
    /** The OpenAI API origin (https://api.openai.com; tests a stand-in). */
    api: string;
    /** The ChatGPT backend's Codex base URL (https://chatgpt.com/backend-api/codex). */
    chatgpt: string;
  };
}

/** The real pair (the openai-proxy's constants, not imported: the launcher
 *  drives the proxies as subprocesses). */
export const CODEX_ULLM_API_UPSTREAM = "https://api.openai.com";
export const CODEX_ULLM_CHATGPT_UPSTREAM = "https://chatgpt.com/backend-api/codex";
const CHATGPT_ACCOUNT_HEADER = "chatgpt-account-id";

/**
 * Where one request of the Codex quarantine goes, or null (refused, nothing
 * sent). Relayed: `POST /v1/responses` (the model turn) and `GET
 * /v1/models` (Codex's model listing), each with an optional query. The
 * ChatGPT base takes the path after `/v1` (`/v1/responses` →
 * `/backend-api/codex/responses`); the API origin takes it whole. Pure.
 */
export function codexRelayRoute(
  method: string | undefined,
  url: string | undefined,
  headers: Record<string, string | string[] | undefined>,
  upstreams: CodexUllmForwarderOptions["codex"],
): { target: URL; path: string } | null {
  const u = url ?? "";
  const q = u.indexOf("?");
  const pathname = q < 0 ? u : u.slice(0, q);
  const query = q < 0 ? "" : u.slice(q);
  const ok = (method === "POST" && pathname === "/v1/responses") || (method === "GET" && pathname === "/v1/models");
  if (!ok) return null;
  const v = headers[CHATGPT_ACCOUNT_HEADER];
  const signedIn = (Array.isArray(v) ? v : [v]).some((x) => typeof x === "string" && x.trim() !== "");
  if (signedIn) {
    const target = new URL(upstreams.chatgpt);
    return { target, path: target.pathname.replace(/\/+$/, "") + pathname.slice(3) + query };
  }
  const target = new URL(upstreams.api);
  return { target, path: target.pathname.replace(/\/+$/, "") + pathname + query };
}

/** How the relay reaches an upstream: TLS for `https:`, plain HTTP only to
 *  a LITERAL loopback address (a test's or a replay's stand-in), anything
 *  else refused (the openai-proxy's `upstreamTransport` rule). Pure. */
export function relayTransport(url: URL): "https" | "http" | "refuse" {
  if (url.protocol === "https:") return "https";
  if (url.protocol !== "http:") return "refuse";
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "::1") return "http";
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return m && m.slice(1).every((o) => Number(o) <= 255) ? "http" : "refuse";
}

/**
 * The Codex form's request headers with the saved key put back, or as they
 * came: only an `Authorization` whose whole value is `Bearer <stand-in>`,
 * only when the key is header-safe. The caller asks only for a request it
 * relays to the API origin (`codexRelayRoute` already admits only the model
 * call and the model listing). Pure.
 */
export function restoreCodexBearer(
  headers: Record<string, string | string[]>,
  apiKey: { standIn: string; key: string } | undefined,
): { headers: Record<string, string | string[]>; restored: boolean } {
  if (!apiKey || !HEADER_SAFE_RE.test(apiKey.key) || !HEADER_SAFE_RE.test(apiKey.standIn)) return { headers, restored: false };
  const name = Object.keys(headers).find((k) => k.toLowerCase() === "authorization");
  if (name === undefined || headers[name] !== `Bearer ${apiKey.standIn}`) return { headers, restored: false };
  return { headers: { ...headers, [name]: `Bearer ${apiKey.key}` }, restored: true };
}

/** Relay one request verbatim to `target` at `path`, with the U-LLM's key
 *  put back by `restore` when given. */
function relay(
  req: IncomingMessage, res: ServerResponse, target: URL, path: string, plainHttp: boolean,
  restore?: (headers: Record<string, string | string[]>) => Record<string, string | string[]>,
): void {
  const isHttps = target.protocol === "https:" && !plainHttp;
  const doRequest = isHttps ? httpsRequest : httpRequest;
  const port = target.port ? Number(target.port) : isHttps ? 443 : 80;
  const headers: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined || DROP_REQUEST_HEADERS.has(k.toLowerCase())) continue;
    headers[k] = v;
  }
  headers["host"] = target.host;
  const sent = restore ? restore(headers) : headers;

  const up = doRequest(
    { hostname: target.hostname, port, method: req.method, path, headers: sent },
    (upRes) => {
      const outHeaders: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(upRes.headers)) {
        if (v === undefined || DROP_RESPONSE_HEADERS.has(k.toLowerCase())) continue;
        outHeaders[k] = v;
      }
      res.writeHead(upRes.statusCode ?? 502, outHeaders);
      upRes.pipe(res);
    },
  );
  // A dead/unreachable upstream is a plain 502 — the U-LLM call fails visibly
  // (inspect_symbol surfaces the error); nothing here may fall back to another
  // endpoint (that would un-pin the destination the relay exists to pin).
  up.on("error", (e) => {
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `ullm-forwarder upstream failed: ${e.message}` }));
    } else {
      res.destroy();
    }
  });
  req.on("error", () => up.destroy());
  res.on("close", () => up.destroy());
  req.pipe(up);
}

function refuse(res: ServerResponse, status: number, error: string): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ error }));
}

/**
 * Build the relay server (not yet listening). Anthropic form: every request
 * is forwarded verbatim to the upstream origin — same method, path, headers
 * (minus hop-by-hop), streaming both directions (SSE rides through
 * unbuffered). Codex form: only a model call, to one of its fixed pair
 * (`codexRelayRoute`). The ONLY served path is GET /_mandu/identity, so the
 * launcher's identity probe can tell this relay apart from a foreign server
 * on the port.
 */
export function createUllmForwarder(
  opts: UllmForwarderOptions | CodexUllmForwarderOptions,
  /** Where the key is read per request (startUllmForwarder's `setApiKey`
   *  writes it); absent: `opts.apiKey`, fixed. */
  keyRef: { value?: { standIn: string; key: string } } = { ...(opts.apiKey ? { value: opts.apiKey } : {}) },
): Server {
  const codex = "codex" in opts ? opts.codex : null;
  const fixed = codex === null ? new URL((opts as UllmForwarderOptions).upstream) : null;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method === "GET" && req.url === "/_mandu/identity") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        mandu: true,
        service: ULLM_FORWARDER_SERVICE,
        ...(codex === null ? { upstream: (opts as UllmForwarderOptions).upstream } : { codex }),
      }));
      return;
    }
    if (fixed !== null) {
      // The key goes back only toward https or a literal loopback stand-in.
      const key = keyRef.value !== undefined && relayTransport(fixed) !== "refuse" ? keyRef.value : undefined;
      relay(req, res, fixed, req.url ?? "/", fixed.protocol === "http:",
        key !== undefined ? (h) => restoreUllmKey(req.method, req.url, h, key).headers : undefined);
      return;
    }
    const route = codexRelayRoute(req.method, req.url, req.headers, codex!);
    if (route === null) {
      req.resume();
      refuse(res, 403, "ullm-forwarder: only the quarantined model's call is relayed (POST /v1/responses, GET /v1/models)");
      return;
    }
    const how = relayTransport(route.target);
    if (how === "refuse") {
      req.resume();
      refuse(res, 502, "ullm-forwarder: the upstream is neither https nor a loopback stand-in");
      return;
    }
    // Codex's saved key goes back only toward the API origin, never the
    // ChatGPT base (a sign-in's bearer is its own token, relayed as written).
    // codexRelayRoute's own test: a request without the account header goes
    // to the API origin.
    const acct = req.headers[CHATGPT_ACCOUNT_HEADER];
    const toApi = !(Array.isArray(acct) ? acct : [acct]).some((x) => typeof x === "string" && x.trim() !== "");
    const key = toApi ? keyRef.value : undefined;
    relay(req, res, route.target, route.path, how === "http", key !== undefined ? (h) => restoreCodexBearer(h, key).headers : undefined);
  });
  // SSE responses are long-lived: node 18+ enforces requestTimeout on receiving
  // the REQUEST (fine), but keep-alive/headers timeouts must not sever an open
  // stream mid-response. 0 disables the per-request cap; sockets still close on
  // server.close() at teardown.
  server.requestTimeout = 0;
  return server;
}

export interface UllmForwarderResult {
  host: string;
  port: number;
  /** The base URL to hand the U-LLM (http://host:port). */
  url: string;
  stop: () => Promise<void>;
  /** Set (or replace) the key put back from now on (agent-sign-in.md §3.9:
   *  Codex's placeholder is known only after the twins). */
  setApiKey?: (k: { standIn: string; key: string }) => void;
}

/**
 * Start the relay in-process on a loopback port. Port 0 (the default) lets the
 * OS pick a free per-session port — the forwarder is session-scoped (it dies
 * with the launcher), so there is nothing to start-or-reuse across sessions and
 * ephemeral ports remove the conflict class entirely. MANDU_ULLM_FORWARDER_PORT
 * pins it (tests / firewall setups).
 */
export function startUllmForwarder(
  opts: (UllmForwarderOptions | CodexUllmForwarderOptions) & { host?: string; port?: number },
): Promise<UllmForwarderResult> {
  const host = opts.host ?? "127.0.0.1";
  const keyRef: { value?: { standIn: string; key: string } } = opts.apiKey ? { value: opts.apiKey } : {};
  const server = createUllmForwarder(opts, keyRef);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, host, () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") {
        server.close();
        reject(new Error("ullm-forwarder: no bound address"));
        return;
      }
      resolve({
        host,
        port: addr.port,
        url: `http://${host}:${addr.port}`,
        setApiKey: (k) => { keyRef.value = k; },
        stop: () =>
          new Promise<void>((done) => {
            // Sever open (SSE) sockets too — close() alone waits for them.
            server.closeAllConnections?.();
            server.close(() => done());
          }),
      });
    });
  });
}
