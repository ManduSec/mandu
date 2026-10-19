/**
 * proxy — the Mandu Track A OpenAI Responses-API reverse proxy (HTTP server).
 *
 * Mandu Track A (interceptors/openai-proxy). A reverse proxy the Codex CLI
 * points at via a custom model_provider base_url. It forwards to
 * https://api.openai.com, or, for a request made on a ChatGPT sign-in (one
 * carrying `chatgpt-account-id`), to the fixed ChatGPT backend
 * https://chatgpt.com/backend-api/codex (chooseUpstream,
 * docs/design/agents/agent-sign-in.md §2.4); the sign-in's bearer is relayed as
 * Codex sent it, never stored, refreshed or made up here. Either way it
 * transforms POST .../responses:
 *
 *   request  (agent→model): rewriteRequest() — classify + symbolize untrusted
 *                           function_call_output spans, prepend the handling
 *                           prompt to `instructions` (src/rewrite-request.ts).
 *                           FAILS CLOSED on arbiter err. With a view map (P4):
 *                           AgentView paths in function_call_output text /
 *                           echoed function_call args are reverse-mapped to
 *                           HumanView (src/view-map.ts) after symbolization.
 *   response (model→agent): without a view map, streamed back UNCHANGED,
 *                           byte-for-byte (symbolization is request-side only).
 *                           With a view map (P4), the SSE response runs through
 *                           the function_call-argument forward rewriter
 *                           (src/sse-rewrite.ts) so absolute HumanView paths in
 *                           the model's shell command map into the AgentView.
 *                           Reply row reservation (reply-row-reservation.md
 *                           §11.7): a multi-line or wrapping `$MDU:` token
 *                           may reach Codex as an N-row reserve block
 *                           (src/sse-reserve-expand.ts), collapsed back on the
 *                           next request (src/reserve-request.ts).
 *
 * POST .../chat/completions (2026-09-29) gets the same guarantees: the body is
 * read as the Responses request it carries (src/chat-wire.ts), masked by the
 * same rewriteRequest, written back; the answer's tool calls go through the
 * same arguments transform (src/chat-sse.ts). A bodyless GET/HEAD is relayed
 * verbatim; every other request is refused
 * (403) and never sent (src/route.ts). The upstream transport is injectable
 * (UpstreamFetcher) so tests drive a fake Responses upstream with no network /
 * API key.
 *
 * FAIL-CLOSED (mandu.md invariant / CONTRIBUTING.md): if the request rewrite throws
 * RewriteRefusal (arbiter unreachable or classify/symbolize/handlingPrompt
 * error), we respond 502 and DO NOT forward — un-symbolized untrusted content
 * never reaches the model. An unparseable Responses body is refused (400).
 */

import { checkLiteralHost, type TlsMaterial, tlsOptions } from "./endpoint-tls.js";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";

import type { Arbiter, ArbiterEvent } from "./arbiter-client.js";
import { rewriteRequest, RewriteRefusal, RewriteBlocked, RewriteAbandoned, ownForwardedText, forwardedToolOutputText, callCommandText, cellGuardKeep, codexSessionCwd, codexToolName, type RewriteResult } from "./rewrite-request.js";
import { gateUnmappedUploadCell, gateUnmappedUploadToolUse, uploadLegApplies, withheldPath, UploadNotices, UploadTurn, type WithheldPath } from "./unmapped-upload.js";
import { clientGone, PromptBlockLedger, PromptEventLedger, type PromptFilterReport } from "./prompt-filter.js";
import { ViewMap, reverseMapRequestPaths } from "./view-map.js";
import { ChatTextRepacker, ResponsesTextRepacker } from "./text-repack.js";
import { ChatWireError, chatProviderRefusal, chatShadow, type ChatShadow } from "./chat-wire.js";
import { segmentAgentFor } from "./prompt-filter.js";
import { ChatArgsRewriter, gateChatJson, type ChatRewriterOptions } from "./chat-sse.js";
import { ResponsesArgsRewriter, composeArgsTransform, transformOutputItems, type ArgsTransform, type CallContext, type RewriterOptions } from "./sse-rewrite.js";
import { ExecGateNotices, gateFunctionCallArguments } from "./exec-gate.js";
import { ExecGateHistory } from "./exec-history.js";
import { ClearResultLedger, arbiterClearResultStore } from "./after-the-fact.js";
import { ResponseSniffer, summarizeOutputItems, summarizeResponsesRequest } from "./transcript.js";
import { advertisedTools, type ResponsesRequest } from "./responses-types.js";
import { cellCallsIdentified, cellsAreIsolated } from "./mcp-cell.js";
import { guardCell } from "./cell-guard.js";
import { classifyRoute } from "./route.js";
import { isCloudBackedModel } from "./cloud-model.js";
import { ResponsesReserveExpander } from "./sse-reserve-expand.js";
import { ReserveEligibility } from "./reserve-eligibility.js";
import { parseReserveMax, RESERVE_MAX_ROWS } from "./reserve-block.js";
import { reserveRequestPass, type ReserveRequestPass } from "./reserve-request.js";
import { substituteAuthHeaders, upstreamDestination } from "./auth-substitution.js";
import {
  type EventContext,
  type SymbolRef,
  type TllmCallShape,
  makeTllmCall,
  makeToolResult,
  makeToolUse,
  makeSymbolize,
  makeExecGate,
  makeFsGate,
  makeReserveExpand,
  makeReserveResidual,
  makePromptFilter,
  symbolRef,
  survivingResult,
} from "./events.js";

/** One response's state for the unmapped upload leg (unmapped-upload.ts):
 *  the calls in stream order (the window rule) and the directory a relative
 *  path under a path-like key is placed in (Codex's session cwd, HumanView). */
interface UploadExchange {
  turn: UploadTurn;
  launchDir?: string;
}

/** An exchange's `tllm_call`, built at request time and sent when the
 *  response body ends (emitTllmCall). */
interface PendingTllmCall {
  ctx: EventContext;
  model: string;
  inputSymbolized: string;
  inputSymbols: SymbolRef[];
  survivor: string | null;
  callShape: TllmCallShape;
  emitted?: boolean;
}

/** A minimal upstream response the proxy understands. */
export interface UpstreamResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  /** Response body as a readable byte stream (SSE or buffered JSON). */
  body: Readable;
}

/** Forward a rewritten request upstream. Injectable for tests. */
export type UpstreamFetcher = (args: {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}) => Promise<UpstreamResponse>;

export interface ProxyOptions {
  arbiter: Arbiter;
  /** Upstream transport. Defaults to a real https fetcher to api.openai.com. */
  upstream?: UpstreamFetcher;
  /** Upstream origin for the default fetcher. */
  upstreamOrigin?: string;
  /**
   * `upstreamOrigin` is the model_provider base_url Codex would have used
   * (plan 11 §7.2: a main model declared under policy.yaml `models:`, by the
   * OpenAI convention ending in `/v1`). The proxy is Codex's base URL `…/v1`,
   * so each request path's leading `/v1` is REPLACED by the upstream's path
   * instead of being prefixed with it (`/v1/responses` → `<base>/responses`).
   * Default false: the origin's path, if any, prefixes the request path, and
   * the default origin has none (env `MANDU_UPSTREAM_IS_BASE_URL=1`).
   */
  upstreamIsBaseUrl?: boolean;
  /**
   * Where a request made on a ChatGPT sign-in goes (agent-sign-in.md §2
   * §4): the transport for a request carrying `chatgpt-account-id`, used
   * unless `upstreamIsBaseUrl` (a declared main model is the only upstream).
   * Tests inject it; absent, a request is sent to `chatgptOrigin` when
   * `upstream` is the default fetcher, and to the injected `upstream`
   * otherwise (a test that injects one transport never reaches chatgpt.com).
   */
  chatgptUpstream?: UpstreamFetcher;
  /** The ChatGPT base URL for the default fetcher (CHATGPT_UPSTREAM_BASE;
   *  env `MANDU_CHATGPT_UPSTREAM`, which a test points at a stand-in). */
  chatgptOrigin?: string;
  /**
   * The upstream is a main model the operator declared `local: true` in
   * policy.yaml `models:` (env `MANDU_UPSTREAM_LOCAL=1`, set by the launcher;
   * plan 11 §8 item 3, §7.2 for Codex). A Responses request whose `model` is
   * cloud-backed (Ollama's `:cloud` tags run on the vendor's servers behind
   * the same loopback API) is then refused with a 400 and nothing is sent.
   */
  /** Plan 12 D3: the declared main model's `tls:` checks (its CA, pins,
   *  client certificate), applied to every upstream connection
   *  (endpoint-tls.ts; env `MANDU_UPSTREAM_TLS`, set by the launcher). */
  upstreamTls?: TlsMaterial;
  upstreamLocal?: boolean;
  /** Optional session key threaded into arbiter calls. */
  sessionKey?: string;
  /** Optional handling-prompt mode. */
  handlingMode?: string;
  /** The session's secret posture (src/secret-posture.ts; env
   *  MANDU_SECRET_POSTURE, set by the launcher), reported with every
   *  handling-prompt request. Absent ⇒ nothing reported (byte-identical). */
  secretPosture?: string;
  /** Logger; defaults to console.error. Set to a no-op in tests. */
  log?: (msg: string) => void;
  /** Max request body bytes (defense against unbounded buffering). */
  maxBodyBytes?: number;
  /**
   * HumanView↔AgentView prefix map (fs-sync.md §1.3, P4). When active,
   * the SHELL COMMAND of each response function_call is forward-mapped into the
   * AgentView worktree, and AgentView paths in the agent→model request
   * (function_call_output text + echoed function_call args) are reverse-mapped
   * so T-LLM only ever sees HumanView paths. Absent/inactive → the response
   * relays byte-verbatim exactly as before.
   */
  viewMap?: ViewMap;
  /**
   * Phase-0 exec gate (exec-routing.md §3). When enabled (DEFAULT), a Codex
   * shell function_call in the model→agent response is submitted to the
   * arbiter's `execGate` op; a command carrying an untrusted symbol in
   * command/execution position is rewritten to a benign `exit 77` sentinel on
   * the wire (fail-closed). Independent of the view map. Set false to disable
   * (test-only affordance — verbatim relay of command function_calls).
   */
  execGate?: boolean;
  /**
   * Reply row reservation (reply-row-reservation.md §11.7): a `$MDU:` token
   * whose value takes more than one screen row may reach Codex as an N-row
   * reserve block, when the arbiter's human plane reports this session
   * relayed through a PTY by a filter that paints reserve blocks (the
   * arbiter's `sessionRelay` / `symbolShape`, keyed on `sessionKey`).
   * `enabled: false` is the kill switch (server-main:
   * MANDU_REPLY_RESERVE=0); `maxRows` the cap (MANDU_REPLY_RESERVE_MAX,
   * 2..200, default 40). The request-side collapse and strip always run.
   */
  replyReserve?: { enabled?: boolean; maxRows?: number; timeoutMs?: number; relayTtlMs?: number };
  /**
   * Self-describing identity served at `GET /_mandu/identity` so a launcher
   * can verify a listening proxy is THIS session's before adopting it. Carries
   * the security-relevant routing the reuse decision keys on — the arbiter
   * socket and the view-map roots. Absent → the endpoint reports
   * `{ mandu:false }` and a launcher refuses to adopt it.
   */
  identity?: ProxyIdentity;
}

/** The identity a proxy publishes at `/_mandu/identity` (see ProxyOptions). */
export interface ProxyIdentity {
  service: "anthropic-proxy" | "openai-proxy";
  sessionKey?: string;
  arbiterSock?: string;
  viewMap?: Array<{ human: string; agent: string }>;
}

/** The path the identity endpoint answers on (loopback admin, never forwarded). */
export const IDENTITY_PATH = "/_mandu/identity";

const DEFAULT_UPSTREAM_ORIGIN = "https://api.openai.com";

/**
 * The ChatGPT backend's Codex base URL (agent-sign-in.md §2.4 item 2):
 * where Codex's own built-in provider sends a ChatGPT sign-in's model turns.
 * A base URL (`/v1/responses` → `/backend-api/codex/responses`), fixed here:
 * nothing the agent sends can name another host.
 */
export const CHATGPT_UPSTREAM_BASE = "https://chatgpt.com/backend-api/codex";

/** The header Codex adds to every request made on a ChatGPT sign-in, and
 *  never on a key (agent-sign-in.md §2.2, the spike table). */
export const CHATGPT_ACCOUNT_HEADER = "chatgpt-account-id";

/**
 * Which of the two fixed upstreams one request goes to (agent-sign-in.md §2
 * §4 item 2). `chatgpt` when the request carries a non-empty
 * `chatgpt-account-id` (Codex on a ChatGPT sign-in), else `api`
 * (api.openai.com, or the ambient MANDU_UPSTREAM a test points at a stand-in).
 * `declared` when the upstream is a main model the operator declared under
 * policy.yaml `models:` (MANDU_UPSTREAM_IS_BASE_URL): it is the only upstream,
 * and a ChatGPT sign-in is refused there rather than handed to that server
 * (its bearer is the user's ChatGPT session). Pure.
 */
export function chooseUpstream(
  headers: Record<string, string | string[] | undefined>,
  declared: boolean,
): "api" | "chatgpt" | "declared-refuse" | "declared" {
  const v = headers[CHATGPT_ACCOUNT_HEADER];
  const signedIn = (Array.isArray(v) ? v : [v]).some((s) => typeof s === "string" && s.trim() !== "");
  if (declared) return signedIn ? "declared-refuse" : "declared";
  return signedIn ? "chatgpt" : "api";
}

/**
 * The path the default fetcher requests upstream (plan 11 §7.2). Without
 * base-URL semantics the upstream's own path (normally none) prefixes the
 * request path. With them (`isBaseUrl`, a declared main model whose url is
 * the model_provider base_url Codex would have used), the request path's
 * leading `/v1` segment, which is the proxy's own base, is replaced by the
 * upstream's path: `/v1/responses` at base `http://127.0.0.1:11434/v1` is
 * `/v1/responses`, at base `https://gw.example/openai` it is
 * `/openai/responses`. A path outside `/v1` keeps the prefix rule. Pure.
 */
export function upstreamRequestPath(path: string, upstream: URL, isBaseUrl: boolean): string {
  const basePath = upstream.pathname.replace(/\/+$/, "");
  if (!isBaseUrl) return basePath + path;
  const m = /^\/v1(?=$|[/?])/.exec(path);
  return m ? basePath + path.slice(3) : basePath + path;
}

/**
 * How the default fetcher reaches an upstream origin (README "Upstream
 * transport"; the same rule as anthropic-proxy's `upstreamTransport`).
 * `https:` → TLS: every real deployment. `http:` → plain HTTP ONLY when the
 * host is a LITERAL loopback address (127.0.0.0/8 or ::1): a stand-in model on
 * this machine, which is how the fresh-agents VM suite drives a real Codex
 * with no key (docs/design/testing/os-test-matrix.md §10.14). Any other `http:`
 * origin, including the NAME `localhost` (a hosts file can point it anywhere),
 * and every other scheme is `refuse`: the default fetcher then fails each
 * request (the proxy's 502) and sends nothing, so the model conversation never
 * crosses a network in the clear. Pure.
 */
export function upstreamTransport(url: URL): "https" | "http" | "refuse" {
  if (url.protocol === "https:") return "https";
  if (url.protocol !== "http:") return "refuse";
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "::1") return "http";
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return m && m.slice(1).every((o) => Number(o) <= 255) ? "http" : "refuse";
}
const DEFAULT_MAX_BODY = 64 * 1024 * 1024; // 64 MiB
/** Ceiling for recording a call's delivered command (plan 13 D9 follow-up);
 *  a slower arbiter leaves the call unbound (masked, fail-closed). */
const DELIVERED_COMMAND_TIMEOUT_MS = 5000;

/** Request headers we accept as a stable session id, in priority order. */
const SESSION_ID_HEADERS = ["x-mandu-session-id", "x-mandu-session", "x-session-id"];

/** Truncate a string to `max` chars, marking elision (for event summaries). */
function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}…[+${s.length - max} chars]`;
}

/**
 * Compute the structural shape of the forwarded request for the `tllm_call`
 * event — the dashboard's side-call detection seam (dashboard.md §4.2c): the
 * agent conversation loop carries the agent's tool battery; harness side calls
 * send zero tools. Responses-API spellings: the token budget is
 * `max_output_tokens` (via the index signature; non-numeric records as null),
 * and user turns are `input[]` message items with role "user" (a bare-string
 * `input` is the API's one-user-message shorthand).
 */
function requestCallShape(req: ResponsesRequest): TllmCallShape {
  const maxTokens = req["max_output_tokens"];
  let userMessages = 0;
  if (typeof req.input === "string") {
    userMessages = 1;
  } else if (Array.isArray(req.input)) {
    for (const item of req.input) {
      if (item && item.type === "message" && (item as { role?: unknown }).role === "user") {
        userMessages++;
      }
    }
  }
  return {
    // Either wire's battery: `tools`, or the `additional_tools` item's
    // namespaces (codex ≥ 0.154 sends no `tools` at all — a battery of 0
    // there made every Codex turn look like a side call, 2026-09-24).
    toolCount: advertisedTools(req).length,
    maxTokens: typeof maxTokens === "number" ? maxTokens : null,
    userMessages,
  };
}

/** Case-insensitive header lookup over a header bag, returning the first value. */
function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const lname = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lname) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

/**
 * Make a header-supplied session id safe to use as the arbiter's per-session
 * NDJSON filename component (mirrors arbiter EventStore `isSafeSessionId`):
 * strip path separators / NUL, cap length, and replace the reserved "."/".."
 * forms. Defense in depth — the arbiter also validates — so a malformed header
 * still yields a usable, capturable session id rather than silently dropping
 * every event for that session.
 */
function sanitizeSessionId(s: string): string {
  const cleaned = s.replace(/[/\\\0]/g, "_").slice(0, 256);
  return cleaned === "" || cleaned === "." || cleaned === ".." ? "_sess" : cleaned;
}

export class OpenAiProxy {
  private readonly arbiter: Arbiter;
  private readonly upstream: UpstreamFetcher;
  private readonly upstreamOrigin: string;
  /** Where a ChatGPT sign-in's requests go (ProxyOptions.chatgptOrigin). */
  private readonly chatgptOrigin: string;
  private readonly sessionKey?: string;
  private readonly handlingMode?: string;
  private readonly secretPosture?: string;
  private readonly log: (msg: string) => void;
  private readonly maxBodyBytes: number;
  /** Active HumanView↔AgentView prefix map, or null (no rewriting). */
  private readonly viewMap: ViewMap | null;
  /** Phase-0 exec gate on/off (exec-routing.md §3). Default on. */
  private readonly execGateEnabled: boolean;
  /** Self-describing identity for the launcher's reuse safety check, or null. */
  private readonly identity: ProxyIdentity | null;
  private server?: Server;

  /** The upstream is a declared `local: true` main model (ProxyOptions.upstreamLocal). */
  private readonly upstreamLocal: boolean;
  /** The upstream is a declared main model (ProxyOptions.upstreamIsBaseUrl):
   *  the only upstream; a ChatGPT sign-in is refused (chooseUpstream). */
  private readonly declaredUpstream: boolean;

  /** Per-process session id base, used when no session header is present. The
   *  external Codex CLI does not send x-mandu-session-id, so this stable
   *  per-proxy-instance id is the session the dashboard discovers + reads. */
  private readonly fallbackSessionId: string;
  /** Per-session monotonic turn counter (one /v1/responses exchange = one turn). */
  private readonly turnBySession = new Map<string, number>();
  /** In-flight best-effort emits, awaited at close() so tests/shutdown are clean. */
  private readonly pendingEmits = new Set<Promise<void>>();
  /** Reply row reservation: the arbiter-backed eligibility (relay mode,
   *  kill switch, shapes) and the row cap. */
  private readonly reserve: ReserveEligibility;
  private readonly reserveCap: number;

  constructor(opts: ProxyOptions) {
    this.arbiter = opts.arbiter;
    this.upstreamOrigin = opts.upstreamOrigin ?? DEFAULT_UPSTREAM_ORIGIN;
    this.upstreamLocal = opts.upstreamLocal === true;
    const declared = opts.upstreamIsBaseUrl === true;
    this.declaredUpstream = declared;
    const api = opts.upstream ?? this.makeHttpsFetcher(this.upstreamOrigin, declared, opts.upstreamTls);
    this.chatgptOrigin = opts.chatgptOrigin ?? CHATGPT_UPSTREAM_BASE;
    // A ChatGPT sign-in's base is a base URL (`/v1` replaced by its path).
    const chatgpt = opts.chatgptUpstream ??
      (opts.upstream ?? this.makeHttpsFetcher(this.chatgptOrigin, true));
    this.upstream = this.withAgentKey(OpenAiProxy.switchingFetcher(api, chatgpt, declared), declared);
    this.sessionKey = opts.sessionKey;
    this.handlingMode = opts.handlingMode;
    if (opts.secretPosture) this.secretPosture = opts.secretPosture;
    this.log = opts.log ?? ((m) => console.error(`[openai-proxy] ${m}`));
    // Kept in the arbiter too, so a resumed conversation gets its note
    // (confidentiality.md §7.1, "Masked after the fact", across a resume).
    this.clearResults = new ClearResultLedger(undefined, { store: arbiterClearResultStore(this.arbiter), log: this.log });
    this.maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
    this.viewMap = opts.viewMap?.active ? opts.viewMap : null;
    this.execGateEnabled = opts.execGate ?? true;
    this.identity = opts.identity ?? null;
    this.fallbackSessionId =
      opts.sessionKey ?? `oap_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
    this.reserve = new ReserveEligibility(this.arbiter, {
      enabled: opts.replyReserve?.enabled ?? true,
      ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
      ...(opts.replyReserve?.timeoutMs !== undefined ? { timeoutMs: opts.replyReserve.timeoutMs } : {}),
      ...(opts.replyReserve?.relayTtlMs !== undefined ? { relayTtlMs: opts.replyReserve.relayTtlMs } : {}),
    });
    this.reserveCap = opts.replyReserve?.maxRows !== undefined
      ? parseReserveMax(String(opts.replyReserve.maxRows))
      : RESERVE_MAX_ROWS;
  }

  /** Build a Node request handler (exposed for in-process tests). */
  handler(): (req: IncomingMessage, res: ServerResponse) => void {
    return (req, res) => {
      this.onRequest(req, res).catch((err) => {
        this.log(`unhandled error: ${(err as Error).message}`);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
        }
        if (!res.writableEnded) {
          res.end(JSON.stringify({ error: { type: "proxy_error", message: "internal proxy error" } }));
        }
      });
    };
  }

  async listen(port: number, host = "127.0.0.1"): Promise<number> {
    this.server = createServer(this.handler());
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, () => {
        this.server!.off("error", reject);
        resolve();
      });
    });
    const addr = this.server.address();
    const boundPort = typeof addr === "object" && addr ? addr.port : port;
    this.log(`listening on http://${host}:${boundPort} → ${this.upstreamOrigin} (a ChatGPT sign-in → ${this.chatgptOrigin})`);
    return boundPort;
  }

  async close(): Promise<void> {
    if (this.server) {
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
      this.server = undefined;
    }
    // Drain any best-effort emits so the process / test exits cleanly. These
    // are already swallowed (safeEmit), so this never rejects.
    await Promise.allSettled([...this.pendingEmits]);
  }

  /** The per-process fallback session id used when the request carries no
   *  session header (the case for the external Codex CLI). Exposed so callers /
   *  tests can correlate emitted events without a session header. */
  get sessionId(): string {
    return this.fallbackSessionId;
  }

  // ── observability event emission (BEST-EFFORT, off the security path) ───────

  /**
   * Derive a stable session id for this exchange: prefer an explicit request
   * header (so a launcher can thread its scope id), else the per-process
   * fallback. Same id across turns of one connection/session.
   */
  private sessionIdFor(headers: IncomingMessage["headers"]): string {
    for (const h of SESSION_ID_HEADERS) {
      const v = headers[h];
      const s = Array.isArray(v) ? v[0] : v;
      if (typeof s === "string" && s.trim() !== "") return sanitizeSessionId(s.trim());
    }
    return this.fallbackSessionId;
  }

  /** Allocate the next monotonic turn index for a session (0-based). */
  private nextTurn(sessionId: string): number {
    const t = this.turnBySession.get(sessionId) ?? 0;
    this.turnBySession.set(sessionId, t + 1);
    return t;
  }

  /**
   * Fire an event at the arbiter, BEST-EFFORT. A failed or slow emit is swallowed
   * — it can never block or fail the request, and we never read anything back
   * toward T-LLM. Tracked in pendingEmits so close() can drain it cleanly.
   */
  private safeEmit(event: ArbiterEvent): void {
    const p = (async () => {
      try {
        await this.arbiter.emit(event);
      } catch (err) {
        this.log(`emit failed (non-fatal, off security path): ${(err as Error).message}`);
      }
    })().finally(() => {
      this.pendingEmits.delete(p);
    });
    this.pendingEmits.add(p);
  }

  /**
   * Emit the observability events for one /v1/responses exchange (best-effort,
   * off the security path). Symbolization is request-side (the SSE is at most
   * path-rewritten in flight), so the ingress events derive from the rewrite +
   * the forwarded body:
   *   - a `symbolize` event per minted symbol;
   *   - a `tool_result` event per function_call_output re-entering context,
   *     carrying BOTH representations (raw `original` + `symbolized`) and the
   *     per-result §9 invariant flag;
   *   - and it RETURNS the pending `tllm_call`: the `▸ role` transcript of the
   *     forwarded (symbolized) request and the whole-request §9 invariant flag
   *     (the model NEVER sees a raw untrusted byte once the symbol tokens are
   *     stripped). `emitTllmCall` sends it once the response body ended, with
   *     the model's answer (transcript.ts, 2026-09-26).
   */
  /** Plan 15 §7: the blocked prompt spans this proxy refused once; a later
   *  request carrying them is forwarded with the arbiter's safe text. */
  private readonly promptBlocks = new PromptBlockLedger();
  /** The exec gate's block notices by call id: an output that is exactly its
   *  call's sentinel output reaches the model in clear (exec-gate.ts
   *  ExecGateNotices; confidentiality plan 10 §11.8). */
  private readonly execGateNotices = new ExecGateNotices();
  /** The exec gate's rewrites by call id (a block's sentinel, a requoted
   *  placeholder): the model reads back the call it wrote, not the rewrite
   *  Codex echoes (exec-history.ts; confidentiality.md §4, "What the model
   *  reads back"). Utility-only, in memory. */
  private readonly execGateHistory = new ExecGateHistory();
  /** The unmapped upload leg's notices by call id (unmapped-upload.ts
   *  UploadNotices): a call whose path it withheld has its output replaced
   *  by the notice in the next request (rewrite-request.ts). */
  private readonly uploadNotices = new UploadNotices();
  /** The call ids whose output body went to the model in clear: an output
   *  masked later gets the "masked after the fact" note (after-the-fact.ts;
   *  confidentiality.md §7.1). */
  private readonly clearResults: ClearResultLedger;

  /** The `prompt_filter` events of a request the prompt filter blocked
   *  (best-effort: the refusal never waits on them). */
  private emitBlockedPrompt(req: IncomingMessage, report: PromptFilterReport): void {
    try {
      const sessionId = this.sessionIdFor(req.headers);
      this.emitPromptFilterEvents({ sessionId, turn: this.nextTurn(sessionId) }, report);
    } catch { /* events are off the security path */ }
  }

  /** What this proxy last recorded per segment (session × text hash): the
   *  agents resend every turn, so an event is recorded when a segment's
   *  outcome changes, its last finding gone included (PromptEventLedger). */
  private readonly promptEvents = new PromptEventLedger();

  /**
   * `prompt_filter` events (confidentiality-plan-15 §8, §13.7): one per
   * segment with a finding or a value the prompt floor let through, each
   * time its outcome differs from the one this proxy last recorded in the
   * session; and one with no findings when a segment recorded with one is
   * now answered with none (an exception, a kind set to pass), so the note
   * under the message clears. Best-effort; the detail carries offsets,
   * categories and symbols, never the value.
   */
  private emitPromptFilterEvents(ctx: EventContext, pf: PromptFilterReport | undefined): void {
    if (!pf) return;
    for (const s of pf.segments) {
      const rec = this.promptEvents.next(ctx.sessionId, s);
      if (rec === null) continue;
      this.safeEmit(makePromptFilter(ctx, {
        agent: pf.agent, segmentId: s.id, origin: s.origin,
        action: s.action === "rewrite" || s.action === "block" ? s.action : "pass",
        findings: s.findings.map((f) => ({
          filterId: f.filterId, category: f.category, action: f.action, start: f.start, end: f.end,
          ...(f.symbol ? { symbol: f.symbol } : {}), ...(f.how ? { how: f.how } : {}),
          // Plan 15 §7 (phase 3): the span's reference, a verdict that let
          // it through, an ask's hold. Never the span.
          ...(f.ref ? { ref: f.ref } : {}), ...(f.let ? { let: f.let } : {}),
          ...(f.hold ? { hold: { state: f.hold.state, ...(f.hold.approvalId ? { approvalId: f.hold.approvalId } : {}) } } : {}),
          // The arbiter's lock (a locked administrator's ask row): this message only.
          ...(f.onceOnly === true ? { onceOnly: true as const } : {}),
        })),
        ...(rec.turn ? { turn: rec.turn } : {}),
        skipped: s.skipped, enforcing: pf.enforcing, digest: pf.digest,
      }));
    }
  }

  private emitIngressEvents(ctx: EventContext, rw: RewriteResult, model: string, agentInstructions: string | undefined): PendingTllmCall {
    this.emitPromptFilterEvents(ctx, rw.promptFilter);
    const inputSymbols: SymbolRef[] = [];
    // §9 oracle scope: the forwarded tool outputs, not the whole body (a raw
    // value that also occurs in the user's prompt is not a leak), and per
    // result a short span counts only inside its own block (survivingResult).
    const haystack = forwardedToolOutputText(rw.request);
    let requestSurvivor: string | null = null;

    for (const r of rw.rewrites) {
      // A value-only release (backstop-value-only.md): one symbol per
      // replaced registered value, each resolving to that value.
      const symbols: SymbolRef[] = r.valueOnly
        ? r.valueOnly.map((v) => symbolRef(v.symbol, r.tool, v.value, r.origin ?? null, null, r.confidentiality))
        : r.symbolized && r.symbol
          ? [symbolRef(r.symbol, r.tool, r.value, r.origin ?? null)]
          : [];
      // Per-result invariant: did THIS result's raw bytes leak verbatim into the
      // forwarded request? For a symbolized result the span the symbol replaced
      // must be gone (a split result's header survives by design).
      const survivor = r.symbolized
        ? survivingResult(ownForwardedText(r), haystack, r.valueOnly ? r.valueOnly.map((v) => v.value) : [r.symbolizedSpan ?? r.value])
        : null;
      requestSurvivor ??= survivor;

      if (r.valueOnly) {
        for (const v of r.valueOnly) {
          inputSymbols.push(symbolRef(v.symbol, r.tool, v.value, r.origin ?? null));
          this.safeEmit(makeSymbolize({
            ctx, callId: r.callId, tool: r.tool, symbol: v.symbol, original: v.value, origin: r.origin ?? null,
            ...(r.confidentiality ? { confidentiality: r.confidentiality } : {}),
          }));
        }
      } else if (r.symbolized && r.symbol) {
        inputSymbols.push(symbolRef(r.symbol, r.tool, r.value, r.origin ?? null));
        this.safeEmit(
          makeSymbolize({
            ctx,
            callId: r.callId,
            tool: r.tool,
            symbol: r.symbol,
            original: r.value,
            origin: r.origin ?? null,
            // Confidentiality level (plan 5): rides onto the SymbolRef so the
            // dashboard badges it and the §12 oracle can assert on it.
            ...(r.confidentiality ? { confidentiality: r.confidentiality } : {}),
          }),
        );
      }

      this.safeEmit(
        makeToolResult({
          ctx,
          callId: r.callId,
          tool: r.tool,
          original: r.value,
          // What T-LLM saw: the forwarded text (envelope split: header +
          // symbol; plan 10: with the [mandu:secret] note), the symbol when
          // whole-result symbolized, else the raw value (TRUSTED passthrough —
          // original === symbolized, differs=false).
          symbolized: r.forwardedText ?? (r.symbolized && r.symbol ? r.symbol : r.value),
          symbols,
          trust: r.trust,
          reason: r.reason,
          ...(r.confidentiality ? { confidentiality: r.confidentiality } : {}),
          ...(r.secretTaint ? { secretTaint: { level: r.secretTaint.level, files: r.secretTaint.files, apps: r.secretTaint.apps, rule: r.secretTaint.rule, maskWhole: r.secretTaint.maskWhole, denied: r.secretTaint.denied } } : {}),
          ...(r.secretNote ? { secretNote: r.secretNote } : {}),
          violatedInvariant: survivor !== null,
        }),
      );
    }

    // The whole-request §9 oracle: NO raw untrusted byte may survive un-symbolized
    // in the forwarded request: the first result that failed its own check.
    const survivor = requestSurvivor;
    return {
      ctx,
      model,
      // The readable transcript of what was forwarded (symbolized). The
      // per-result events carry the originals.
      inputSymbolized: summarizeResponsesRequest(rw.request, agentInstructions),
      inputSymbols,
      survivor,
      // Structural request shape — the side-call detection seam (dashboard.md
      // §4.2c). Computed from the SAME rewritten request that was forwarded.
      callShape: requestCallShape(rw.request),
    };
  }

  /** Emit an exchange's `tllm_call` once, with the model's answer (or the
   *  reason there is none). */
  private emitTllmCall(p: PendingTllmCall, outputText: string): void {
    if (p.emitted) return;
    p.emitted = true;
    this.safeEmit(
      makeTllmCall({
        ctx: p.ctx,
        model: p.model,
        inputSymbolized: p.inputSymbolized,
        inputOriginal: null,
        inputSymbols: p.inputSymbols,
        outputText,
        violatedInvariant: p.survivor !== null,
        invariantDetail: p.survivor
          ? `un-symbolized untrusted span survived in forwarded request: ${truncate(p.survivor, 120)}`
          : undefined,
        callShape: p.callShape,
      }),
    );
  }

  /** The output text for a finished response: the answer, or for an upstream
   *  error the explainer the dashboard keeps out of the delivered reply. */
  private static answerText(status: number, sniffed: { text: string; error: string | null }): string {
    if (status >= 400) return `⚠ no model response — upstream HTTP ${status}${sniffed.error ? `: ${sniffed.error}` : ""}`;
    if (!sniffed.text && sniffed.error) return `⚠ no model response — ${sniffed.error}`;
    return sniffed.text;
  }

  // ── request handling ──────────────────────────────────────────────────────

  private async onRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const path = req.url ?? "/";

    // Local admin: the launcher's start-or-reuse identity probe. Answered here
    // (never forwarded upstream) so a listening proxy can be checked as THIS
    // session's before it is adopted. GET only; no body.
    if (method === "GET" && (path.split("?")[0] ?? "") === IDENTITY_PATH) {
      this.serveIdentity(res);
      return;
    }

    const body = await this.readBody(req, res);
    if (body == null) return; // readBody already responded (e.g. 413)

    // A ChatGPT sign-in (agent-sign-in.md §2.5) bound for a declared main
    // model: its bearer is the user's ChatGPT session, which that server must
    // never receive, and the header cannot re-point the proxy. The launcher
    // never builds this shape (a declared model keeps the env_key provider),
    // so this answers only a hand-made request. 403, not 401: an invented
    // 401 would make Codex refresh its sign-in for nothing.
    if (chooseUpstream(req.headers, this.declaredUpstream) === "declared-refuse") {
      this.log(`FAIL-CLOSED refusing ${method} ${path.split("?")[0]}: a ChatGPT sign-in is not sent to the declared main model`);
      this.refuse(res, 403,
        "mandu: refusing a request made on a ChatGPT sign-in: this session's main model is one declared under " +
        "policy.yaml models:, and Mandu does not send your ChatGPT sign-in to it. Use that server's own key.");
      return;
    }

    // Which requests may go upstream (src/route.ts, fail-closed): POST
    // …/responses is rewritten below, a bodyless GET/HEAD is relayed as is, and
    // everything else is refused here and never sent, since another generation
    // wire would reach the model with its tool output unmasked.
    const route = classifyRoute(method, path, body.length);
    if (route.kind === "relay") {
      await this.forwardAndStream(method, path, req.headers, body, res, /*ctx*/ null);
      return;
    }
    if (route.kind === "refuse") {
      this.log(`FAIL-CLOSED refusing ${method} ${path.split("?")[0]}: not a route the proxy can mask`);
      this.refuse(res, 403, route.message!);
      return;
    }
    if (route.kind === "chat") {
      await this.onChatRequest(req, res, method, path, body);
      return;
    }

    // ── Parse the request body. ──
    let parsed: ResponsesRequest;
    try {
      parsed = JSON.parse(body.toString("utf8")) as ResponsesRequest;
    } catch (err) {
      // A POST .../responses with an unparseable body: we cannot inspect it for
      // untrusted content, so we FAIL CLOSED rather than forward blindly.
      this.refuse(res, 400, `unparseable Responses request body: ${(err as Error).message}`);
      return;
    }

    // A cloud-backed model at a declared LOCAL upstream (plan 11 §8 item 3,
    // §7.2 for Codex): the local server would relay the conversation to its
    // vendor, so refuse before any arbiter call and send nothing. 400 (not
    // the fail-closed 502): the request itself is what cannot go, and Codex
    // retries a 5xx.
    if (this.refuseCloudModel(res, method, path, parsed.model)) return;

    // Reply row reservation, request side (reply-row-reservation.md §3.4,
    // §11.7): collapse each reserve block in the assistant's own text back to
    // its token, then strip every leftover fragment from every text the model
    // reads. ALWAYS on (whatever the expansion switch says), and BEFORE
    // rewriteRequest, so every later step reads the bytes actually forwarded.
    // Never throws.
    const reservePass = this.reservePass(parsed);

    // ── Security-critical rewrite (fail-closed). ──
    let rewritten;
    try {
      rewritten = await rewriteRequest(parsed, { ...this.rewriteOptions(), signal: clientGone(res) });
    } catch (err) {
      if (err instanceof RewriteAbandoned) {
        // Plan 15 §13.6 item 13: Codex went away while its prompt was held.
        // Nothing was sent, and nobody is there to read a refusal.
        this.log(`prompt filter: ${err.message}`);
        return;
      }
      if (err instanceof RewriteBlocked) {
        // Plan 15 §7: the prompt filter's policy blocks this prompt: a 400
        // invalid_request_error Codex shows without retrying; the reason
        // names categories, never a value.
        this.log(`prompt filter BLOCKED the request: ${err.message}`);
        this.emitBlockedPrompt(req, err.report);
        this.refuse(res, 400, err.message, "invalid_request_error");
        return;
      }
      if (err instanceof RewriteRefusal) {
        this.log(`FAIL-CLOSED refusing request: ${err.message}`);
        this.refuse(res, 502, err.message);
        return;
      }
      throw err;
    }

    const symbolized = rewritten.rewrites.filter((r) => r.symbolized).length;
    this.log(
      `POST ${path}: ${rewritten.rewrites.length} tool output(s), ${symbolized} symbolized`,
    );

    // Exec-gate history (confidentiality.md §4, "What the model reads back"):
    // a call the exec gate rewrote on its way to Codex (the block sentinel, a
    // requoted placeholder) is echoed back in that form; put the model's OWN
    // call back so it does not read, and then repeat, a call it never wrote.
    // AFTER the rewrite (its output was classified against what ran) and
    // BEFORE the reverse map (the echo is compared with what was delivered).
    this.restoreExecHistory(rewritten.request);

    // fs prefix map, request side (P4): reverse-map AgentView paths back to
    // HumanView in the function_call_output text + echoed function_call args.
    // AFTER symbolization (untrusted output is already an opaque symbol; the
    // symbol table keeps the true original) and BEFORE serialization + events.
    if (this.viewMap) reverseMapRequestPaths(rewritten.request, this.viewMap);

    const outBody = Buffer.from(JSON.stringify(rewritten.request), "utf8");

    // ── Observability events (BEST-EFFORT, off the security path). ──
    // Derive the per-exchange context and emit symbolize + tool_result + a
    // tllm_call for what the rewrite did. Every emit is swallowed — a failing or
    // slow emit can never block or change the forwarded request below.
    const sessionId = this.sessionIdFor(req.headers);
    const ctx: EventContext = { sessionId, turn: this.nextTurn(sessionId) };
    const pending = this.emitIngressEvents(
      ctx, rewritten, rewritten.request.model ?? "",
      typeof parsed.instructions === "string" ? parsed.instructions : undefined,
    );
    if (reservePass.removed > 0) {
      this.safeEmit(makeReserveResidual(ctx, { removed: reservePass.removed, where: reservePass.where, route: "responses" }));
    }

    // The response is transformed (Phase-0 exec gate + P4 forward path-map) when
    // the exec gate or a view map is active; otherwise it streams back verbatim.
    // The unmapped upload leg places a relative path under a path-like key in
    // the session's directory, as Codex's own context names it (HumanView).
    const cwd = codexSessionCwd(Array.isArray(parsed.input) ? parsed.input : []);
    const launchDir = cwd !== null ? (this.viewMap ? this.viewMap.mapText(cwd, "reverse") : cwd) : undefined;
    await this.forwardAndStream(method, path, req.headers, outBody, res, ctx, pending, cellsAreIsolated(advertisedTools(parsed)), launchDir);
  }

  /** A cloud-backed model at a declared LOCAL upstream (plan 11 §8 item 3,
   *  §7.2 for Codex): the local server would relay the conversation to its
   *  vendor, so refuse before any arbiter call and send nothing. 400 (not
   *  the fail-closed 502): the request itself is what cannot go, and agents
   *  retry a 5xx. True when it refused. */
  private refuseCloudModel(res: ServerResponse, method: string, path: string, model: unknown): boolean {
    if (!this.upstreamLocal || typeof model !== "string" || !isCloudBackedModel(model)) return false;
    this.log(`refusing ${method} ${path.split("?")[0]}: model ${model} is cloud-backed and the upstream is a declared local model`);
    this.refuse(
      res, 400,
      `mandu: refusing model ${model}: it runs on the vendor's servers (a cloud model), and your main model is declared ` +
        "local: true in policy.yaml models:, so nothing was sent. Choose a model that runs on this machine " +
        "(codex -m <name>), then try again.",
      "invalid_request_error",
    );
    return true;
  }

  /** The reserve-block collapse + residual strip over a parsed Responses
   *  body (reserve-request.ts). Never throws: the pass is pure string work
   *  over type-checked fields; this catch is defense in depth (whatever it
   *  changed before a throw was a removal). */
  private reservePass(parsed: ResponsesRequest): ReserveRequestPass {
    try {
      const r = reserveRequestPass(parsed);
      if (r.collapsed > 0 || r.removed > 0) {
        this.log(`reply reserve: collapsed ${r.collapsed} block(s), stripped ${r.removed} residual fragment(s)`);
      }
      return r;
    } catch (err) {
      this.log(`reply reserve pass error (non-fatal): ${(err as Error).message}`);
      return { collapsed: 0, removed: 0, where: [] };
    }
  }

  /** The request rewrite's options, the same for both wires. */
  private rewriteOptions(): Parameters<typeof rewriteRequest>[1] {
    return {
      arbiter: this.arbiter,
      promptBlockLedger: this.promptBlocks,
      execGateNotices: this.execGateNotices,
      uploadNotices: this.uploadNotices,
      clearResults: this.clearResults,
      sessionKey: this.sessionKey,
      handlingMode: this.handlingMode,
      // The session's secret posture rides every handling-prompt request.
      ...(this.secretPosture ? { secretPosture: this.secretPosture } : {}),
      log: this.log,
      // The LEVEL must be derived from the arbiter's own spelling (HumanView,
      // Plan 9): Codex's origin is the recovered shell command, which under a
      // view map names the AgentView twin, while the label stores are keyed in
      // HumanView. Trust is untouched — the arbiter reads `originHuman` only in
      // the confidentiality derivation.
      ...(this.viewMap
        ? { toHumanView: (o: string) => this.viewMap!.mapText(o, "reverse") }
        : {}),
    };
  }

  /**
   * POST …/chat/completions (route.ts `chat`; chat-wire.ts, 2026-09-29): the
   * same guarantees as the Responses route. The body is read as the
   * Responses request it carries (the shadow), masked by the SAME rewrite
   * (fail-closed: an arbiter failure is a 502 and nothing is sent), written
   * back onto the agent's body, and the answer's tool calls go through the
   * SAME arguments transform (chat-sse.ts), its text through the token
   * repacker. A shape the reader cannot vouch for is a 400, never sent.
   */
  private async onChatRequest(req: IncomingMessage, res: ServerResponse, method: string, path: string, body: Buffer): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch (err) {
      this.refuse(res, 400, `unparseable Chat Completions request body: ${(err as Error).message}`);
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      this.refuse(res, 400, "the Chat Completions request body is not a JSON object");
      return;
    }
    const chat = parsed as Record<string, unknown>;
    const refusal = chatProviderRefusal(chat);
    if (refusal) {
      this.log(`FAIL-CLOSED refusing ${method} ${path.split("?")[0]}: ${refusal}`);
      this.refuse(res, 400, `mandu: refusing this request: ${refusal}. Nothing was sent.`);
      return;
    }
    if (this.refuseCloudModel(res, method, path, chat["model"])) return;
    let wire: ChatShadow;
    try {
      wire = chatShadow(chat);
    } catch (err) {
      if (err instanceof ChatWireError) {
        this.log(`FAIL-CLOSED refusing ${method} ${path.split("?")[0]}: ${err.message}`);
        this.refuse(res, 400, `mandu: refusing this request: ${err.message}. Nothing was sent.`);
        return;
      }
      throw err;
    }

    // ── Security-critical rewrite (fail-closed), on the shadow. ──
    let rewritten: RewriteResult;
    try {
      rewritten = await rewriteRequest(wire.shadow, { ...this.rewriteOptions(), promptAgent: segmentAgentFor(wire.shadow, "chat"), signal: clientGone(res) });
    } catch (err) {
      if (err instanceof RewriteAbandoned) {
        this.log(`prompt filter: ${err.message} (Chat Completions)`);
        return;
      }
      if (err instanceof RewriteBlocked) {
        this.log(`prompt filter BLOCKED the request: ${err.message}`);
        this.emitBlockedPrompt(req, err.report);
        this.refuse(res, 400, err.message, "invalid_request_error");
        return;
      }
      if (err instanceof RewriteRefusal) {
        this.log(`FAIL-CLOSED refusing request: ${err.message}`);
        this.refuse(res, 502, err.message);
        return;
      }
      throw err;
    }
    this.log(`POST ${path}: ${rewritten.rewrites.length} tool output(s), ${rewritten.rewrites.filter((r) => r.symbolized).length} symbolized`);
    this.restoreExecHistory(rewritten.request);
    if (this.viewMap) reverseMapRequestPaths(rewritten.request, this.viewMap);
    const outBody = Buffer.from(JSON.stringify(wire.apply(rewritten.request)), "utf8");

    const sessionId = this.sessionIdFor(req.headers);
    const ctx: EventContext = { sessionId, turn: this.nextTurn(sessionId) };
    const pending = this.emitIngressEvents(ctx, rewritten, rewritten.request.model ?? "", wire.agentInstructions || undefined);
    await this.forwardChat(method, path, req.headers, outBody, res, ctx, pending, chat["stream"] === true);
  }

  /**
   * Relay a masked Chat Completions request and gate its answer: every tool
   * call through the arguments transform (the exec gate and the forward path
   * map, whichever is active), reported as a `tool_use` event; the text
   * through the token repacker. A 2xx answer that cannot be read is a 502,
   * never relayed; an upstream error relays as sent.
   */
  private async forwardChat(
    method: string,
    path: string,
    headers: IncomingMessage["headers"],
    body: Buffer,
    res: ServerResponse,
    ctx: EventContext,
    pending: PendingTllmCall,
    stream: boolean,
  ): Promise<void> {
    let upstream: UpstreamResponse;
    try {
      upstream = await this.upstream({ method, path, headers: this.sanitizeHeaders(headers, body.length), body });
    } catch (err) {
      this.log(`upstream error: ${(err as Error).message}`);
      this.emitTllmCall(pending, `⚠ no model response — upstream request failed: ${(err as Error).message}`);
      this.refuse(res, 502, `upstream request failed: ${(err as Error).message}`);
      return;
    }
    if (upstream.status >= 400) {
      const sniffer = new ResponseSniffer("json");
      res.writeHead(upstream.status, this.responseHeaders(upstream.headers));
      upstream.body.on("data", (c: Buffer | string) => sniffer.feed(c));
      const answered = (): void => this.emitTllmCall(pending, OpenAiProxy.answerText(upstream.status, sniffer.finish()));
      upstream.body.on("end", answered);
      upstream.body.on("error", answered);
      upstream.body.pipe(res);
      await this.finished(res);
      return;
    }

    const transform = this.buildArgsTransform(ctx, { turn: new UploadTurn() });
    const texts: string[] = [];
    const calls: Array<{ name: string; args: string }> = [];
    const opts: ChatRewriterOptions = {
      unparseable: this.execGateEnabled ? "block" : "keep",
      log: this.log,
      onText: (t) => { texts.push(t); },
      onCall: (c) => {
        calls.push({ name: c.name, args: c.argumentsJson });
        this.safeEmit(makeToolUse({ ctx, callId: c.callId ?? c.itemId, name: c.name, argumentsJson: c.argumentsJson }));
      },
    };
    const answer = (): string => summarizeOutputItems([
      { type: "message", role: "assistant", content: [{ type: "output_text", text: texts.join("") }] },
      ...calls.map((c) => ({ type: "function_call", name: c.name, arguments: c.args })),
    ]);
    const ctype = headerValue(upstream.headers, "content-type") ?? "";

    // A JSON answer is read whole even under a stream request (a provider may
    // ignore `stream`); the stream rewriter also ends on anything that is not
    // an event stream, so an ungated call never relays either way.
    const sse = ctype.includes("text/event-stream") || (stream && !ctype.includes("application/json"));
    if (!sse) {
      const chunks: Buffer[] = [];
      await new Promise<void>((resolve) => {
        upstream.body.on("data", (c: Buffer | string) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        upstream.body.on("end", resolve);
        upstream.body.on("error", () => resolve());
      });
      let buf = Buffer.concat(chunks);
      try {
        const v: unknown = JSON.parse(buf.toString("utf8"));
        if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not a JSON object");
        if (await gateChatJson(v as Record<string, unknown>, transform, opts)) buf = Buffer.from(JSON.stringify(v), "utf8");
      } catch (err) {
        // A 2xx answer carries the model's calls: it goes out only as read.
        this.log(`FAIL-CLOSED: the model's Chat Completions answer could not be read (${(err as Error).message})`);
        this.emitTllmCall(pending, "⚠ no model response — the provider's answer could not be read");
        this.refuse(res, 502, `mandu: the model provider's answer could not be read (${(err as Error).message}); it was not relayed`);
        return;
      }
      this.emitTllmCall(pending, answer());
      res.writeHead(upstream.status, this.responseHeaders(upstream.headers, { dropContentLength: true }));
      res.end(buf);
      return;
    }

    res.writeHead(upstream.status, this.responseHeaders(upstream.headers, { dropContentLength: true }));
    const rewriter = new ChatArgsRewriter(transform, opts);
    const repacker = new ChatTextRepacker();
    const src = upstream.body;
    src.setEncoding("utf8");
    let broken = false;
    // The transform awaits an arbiter verdict: chain the chunks to keep order.
    // A rewriter fault ends the relay: nothing ungated goes out after it.
    const step = async (fn: () => Promise<string>): Promise<void> => {
      if (broken) return;
      try {
        const out = await fn();
        if (out !== "") res.write(out);
      } catch (err) {
        broken = true;
        this.log(`FAIL-CLOSED: the Chat response rewriter failed (${(err as Error).message}); ending the stream`);
      }
    };
    await new Promise<void>((resolve) => {
      let chain: Promise<void> = Promise.resolve();
      const enqueue = (fn: () => Promise<void>): void => { chain = chain.then(fn, fn); };
      src.on("data", (chunk: string) => enqueue(() => step(async () => repacker.feed(await rewriter.feed(chunk)))));
      const finish = (): void => enqueue(async () => {
        await step(async () => repacker.feed(await rewriter.end()) + repacker.end());
        this.emitTllmCall(pending, answer());
        res.end();
        resolve();
      });
      src.on("end", finish);
      src.on("error", (err) => { this.log(`upstream stream error: ${err.message}`); finish(); });
    });
  }

  /** Read the full request body, enforcing the max-size cap. */
  private readBody(req: IncomingMessage, res: ServerResponse): Promise<Buffer | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let aborted = false;
      req.on("data", (c: Buffer) => {
        if (aborted) return;
        size += c.length;
        if (size > this.maxBodyBytes) {
          aborted = true;
          this.refuse(res, 413, `request body exceeds ${this.maxBodyBytes} bytes`);
          resolve(null);
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        if (!aborted) resolve(Buffer.concat(chunks));
      });
      req.on("error", () => {
        if (!aborted) {
          aborted = true;
          this.refuse(res, 400, "error reading request body");
          resolve(null);
        }
      });
    });
  }

  /**
   * Build the model→agent function_call arguments transform: the Phase-0 exec
   * gate (BLOCK a symbol-in-command-position → `exit 77` sentinel, fail-closed)
   * composed with the P4 forward path-map. Null when neither is active (verbatim
   * relay). The exec-gate closure also emits an `exec_action` event per gated
   * command (best-effort, off the security path).
   */
  /**
   * The stream/JSON rewriter's per-exchange options: a script cell whose exec
   * arguments the gate cannot read is BLOCKED while the gate is on (fail
   * closed) and left alone otherwise (path-map rule 3); every assembled call
   * is narrated as a `tool_use` event (best-effort, off the security path) —
   * the decision as the model wrote it, so the dashboard and the drill
   * oracles see Codex's tool calls the way they see Claude's.
   */
  private rewriterOptions(ctx: EventContext, cellsIsolated = false, ex?: UploadExchange): RewriterOptions {
    return {
      unparseable: this.execGateEnabled ? "block" : "keep",
      log: this.log,
      // The window rule's order (unmapped-upload.ts UploadTurn): each call
      // item as the stream carries it, before its payload is gated.
      ...(ex ? { onItem: (c: CallContext) => ex.turn.record(c.itemId ?? c.callId ?? null, codexToolName(c.name, c.namespace)) } : {}),
      // The unmapped upload leg over a code cell: a file a call of the cell
      // would send is held, and the whole cell becomes the sentinel cell.
      ...(this.execGateEnabled && ex
        ? {
            cellUploadGate: async (src: string, call: CallContext | undefined): Promise<string | null> => {
              const key = call?.itemId ?? call?.callId ?? null;
              const priorWriter = ex.turn.priorWriter(key);
              ex.turn.record(key, call?.name ?? "exec");
              const hold = await gateUnmappedUploadCell(src, {
                arbiter: this.arbiter, sessionKey: this.sessionKey ?? ctx.sessionId, log: this.log, cellsIsolated,
                ...(ex.launchDir !== undefined ? { launchDir: ex.launchDir } : {}),
                ...(priorWriter !== undefined ? { priorWriter } : {}),
              });
              if (hold === null) return null;
              this.emitUploadHolds(ctx, call?.callId ?? "", hold.tool, hold.withheld);
              return hold.notice;
            },
          }
        : {}),
      onCall: (c) => this.safeEmit(makeToolUse({ ctx, callId: c.callId ?? c.itemId, name: c.name, argumentsJson: c.argumentsJson })),
      cellsIsolated,
      // Plan 10 §11.18, the cell guard (cell-guard.ts): a code cell the
      // grammar cannot identify call by call runs with every nested tool
      // Mandu has not mapped switched off. No guard (the axis off, an
      // arbiter that cannot say) keeps the request side's text rules.
      cellGuard: async (src: string): Promise<string | null> => {
        if (cellsIsolated && cellCallsIdentified(src)) return null;
        const keep = await cellGuardKeep(this.arbiter, src, ctx.sessionId, this.log);
        return keep === null ? null : guardCell(src, keep);
      },
      // Plan 10 §11.13 path (a): a cell whose calls the grammar cannot all
      // identify is gated AS A WHOLE, its source as the command, before the
      // per-literal gate: in a HIGH session (or on an untrusted symbol, or an
      // arbiter that does not answer) it is replaced by the sentinel cell, so
      // an exec the literal scanner never saw cannot run ungated.
      ...(this.execGateEnabled
        ? {
            cellGate: async (src: string): Promise<string | null> => {
              const r = await gateFunctionCallArguments(JSON.stringify({ cmd: src }), { arbiter: this.arbiter, sessionKey: ctx.sessionId, log: this.log });
              if (r.outcome) {
                this.safeEmit(makeExecGate({
                  ctx, callId: "", decision: r.outcome.decision, reason: r.outcome.reason,
                  symbols: r.outcome.symbols, evasion: r.outcome.evasion, shell: r.outcome.shell, sentinel: r.outcome.sentinel,
                }));
              }
              return r.outcome?.decision === "block" ? r.outcome.reason : null;
            },
            // The !545 leftover (plan 10 §11.8): a cell replaced WHOLE by the
            // sentinel cell keeps its notice by the cell's own call id, so its
            // output reaches the model as Mandu's notice, not one symbol.
            onCellBlocked: (callId: string | null, notice: string) => {
              this.execGateNotices.remember(callId ?? undefined, notice, { wholeCell: true });
              this.execGateHistory.markGated(callId);
            },
            // the model reads back its own cell when the gate rewrote it
            onCellDelivered: (callId: string | null, original: string, delivered: string) =>
              this.execGateHistory.delivered("custom_tool_call", callId, original, delivered),
          }
        : {}),
    };
  }

  /** Put the model's own calls back into a request's history (exec-history.ts).
   *  Utility-only: never throws, never refuses. */
  private restoreExecHistory(request: ResponsesRequest): void {
    const restored = this.execGateHistory.restore(request);
    if (restored.length) this.log(`exec-gate: restored the model's own call on ${restored.length} rewritten call(s) in history`);
  }

  private buildArgsTransform(ctx: EventContext, ex: UploadExchange = { turn: new UploadTurn() }): ArgsTransform | null {
    const map = this.viewMap;
    if (!this.execGateEnabled && !map) return null;
    // The unmapped upload leg (unmapped-upload.ts; guarantees.md §3): a call
    // of a tool codex does not map (an MCP server's, a new release's) has
    // every local path in its arguments judged by the arbiter's upload gate
    // in its unmapped form; a held path becomes one that names no file, and
    // the call's output becomes the notice. FIRST: it judges the paths the
    // model wrote (HumanView), before the exec gate and the forward map.
    const uploadGate = async (argsJson: string, call: CallContext | undefined): Promise<string | null> => {
      if (!call || call.inCell === true) return null;
      const name = codexToolName(call.name, call.namespace);
      const key = call.itemId ?? call.callId ?? null;
      const priorWriter = ex.turn.priorWriter(key);
      ex.turn.record(key, name);
      if (!uploadLegApplies(name)) return null;
      let input: unknown;
      try { input = JSON.parse(argsJson); } catch { return null; } // codex runs no call it cannot parse
      const r = await gateUnmappedUploadToolUse(name, input, {
        arbiter: this.arbiter, sessionKey: this.sessionKey ?? ctx.sessionId, log: this.log,
        ...(ex.launchDir !== undefined ? { launchDir: ex.launchDir } : {}),
        ...(priorWriter !== undefined ? { priorWriter } : {}),
      });
      if (r.outcome?.decision !== "block") return null;
      this.uploadNotices.remember(call.callId, r.outcome.notice);
      // the model reads back the call it wrote (exec-history.ts)
      this.execGateHistory.markGated(call.callId);
      this.emitUploadHolds(ctx, call.callId ?? "", name, r.outcome.withheld);
      return JSON.stringify(r.input);
    };
    const execGate: ArgsTransform | undefined = this.execGateEnabled
      ? async (argsJson, call) => {
          const r = await gateFunctionCallArguments(argsJson, {
            arbiter: this.arbiter,
            // ctx is a REQUIRED param of this method (not optional emit state),
            // so the session id is on the security path here.
            sessionKey: ctx.sessionId,
            log: this.log,
            // plan 13 D9 follow-up: the call's gate time and command
            ...(call?.callId ? { callId: call.callId } : {}),
            // A secret placeholder Codex's shell would expand to nothing is
            // delivered requoted (confidentiality.md §7).
            ...(call?.name ? { toolName: call.name } : {}),
            requote: true,
          });
          // the gate rewrote this call (a block, a requote): the model reads
          // back what it wrote (exec-history.ts)
          if (r.arguments !== null) this.execGateHistory.markGated(call?.callId);
          if (r.outcome) {
            if (r.outcome.decision === "block") this.execGateNotices.remember(call?.callId ?? undefined, r.outcome.notice);
            this.safeEmit(
              makeExecGate({
                ctx, callId: "",
                decision: r.outcome.decision, reason: r.outcome.reason,
                symbols: r.outcome.symbols, evasion: r.outcome.evasion,
                shell: r.outcome.shell, sentinel: r.outcome.sentinel,
              }),
            );
          }
          return r.arguments; // null ⇒ allow / nothing to gate
        }
      : undefined;
    const argsGate: ArgsTransform | undefined = execGate
      ? async (argsJson, call) => {
          const held = await uploadGate(argsJson, call);
          const gated = await execGate(held ?? argsJson, call);
          return gated ?? held;
        }
      : undefined;
    const composed = composeArgsTransform(map, argsGate);
    // Plan 13 D9 follow-up: after the gate and the map, record the command
    // Codex is about to receive, by the call's id, on the human plane, BEFORE
    // the call is relayed. The arbiter binds the call to Codex's shell by it,
    // never by the arguments Codex echoes back next turn.
    return async (argsJson, call) => {
      const out = await composed(argsJson, call);
      // A function_call's own arguments, beside what Codex receives (a cell's
      // literal is recorded as its cell, onCellDelivered).
      if (out !== null && call?.inCell !== true) this.execGateHistory.delivered("function_call", call?.callId, argsJson, out);
      await this.recordDeliveredCommand(out ?? argsJson, call, ctx.sessionId);
      return out;
    };
  }

  /** One `fs_action` per path the unmapped upload leg withheld
   *  (best-effort, off the security path). */
  private emitUploadHolds(ctx: EventContext, callId: string, tool: string, withheld: readonly WithheldPath[]): void {
    for (const w of withheld) {
      this.safeEmit(makeFsGate({
        ctx, callId, tool, field: w.loc.join(".") || "input",
        path: w.path, sentinel: w.path === "" ? "(withheld whole)" : withheldPath(w.path), reason: w.reason,
        requiresApproval: w.requiresApproval, ruleRef: w.ruleRef,
        ...(w.approvalId ? { approvalId: w.approvalId } : {}),
      }));
    }
  }

  /** The D9 follow-up's record (see buildArgsTransform). Never throws and
   *  never changes the call: a failed record leaves the call bound by its
   *  execGate record alone, and a call bound by nothing is masked while the
   *  session holds a raw read (fail-closed). */
  private async recordDeliveredCommand(argsJson: string, call: CallContext | undefined, sessionKey: string | undefined): Promise<void> {
    if (!call?.callId || !this.arbiter.recordCallCommand) return;
    let args: unknown;
    try { args = JSON.parse(argsJson); } catch { return; }
    if (args === null || typeof args !== "object" || Array.isArray(args)) return;
    const command = callCommandText(call.name, args as Record<string, unknown>);
    if (command === null) return;
    const ms = DELIVERED_COMMAND_TIMEOUT_MS;
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        this.arbiter.recordCallCommand({ callId: call.callId, command, ...(sessionKey ? { sessionKey } : {}) }),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms); }),
      ]);
    } catch (err) {
      this.log(`recordCallCommand failed for ${call.callId}: ${(err as Error).message} (its result is masked while the session holds a raw read)`);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Forward `body` upstream and stream the response back to `res`. On
   * non-Responses paths, and for a non-SSE body with neither the exec gate nor
   * a view map active, the model→agent direction passes through byte-for-byte.
   * A Responses success stream always goes through the text-delta token
   * repacker (text-repack.ts: only where text is cut between deltas moves).
   * With the gate or a map active the response
   * is run through the function_call-argument transform: the Phase-0 exec gate
   * (a blocked command → `exit 77` sentinel) then the P4 forward path-map (so
   * HumanView paths in the model's shell command reach the AgentView worktree).
   * A non-SSE (e.g. JSON error) body still passes through unchanged.
   */
  private async forwardAndStream(
    method: string,
    path: string,
    headers: IncomingMessage["headers"],
    body: Buffer,
    res: ServerResponse,
    ctx: EventContext | null,
    pending: PendingTllmCall | null = null,
    cellsIsolated = false,
    launchDir?: string,
  ): Promise<void> {
    const fwdHeaders = this.sanitizeHeaders(headers, body.length);

    let upstream: UpstreamResponse;
    try {
      upstream = await this.upstream({ method, path, headers: fwdHeaders, body });
    } catch (err) {
      this.log(`upstream error: ${(err as Error).message}`);
      if (pending) this.emitTllmCall(pending, `⚠ no model response — upstream request failed: ${(err as Error).message}`);
      this.refuse(res, 502, `upstream request failed: ${(err as Error).message}`);
      return;
    }

    const ctype = headerValue(upstream.headers, "content-type") ?? "";
    // A null ctx (non-Responses passthrough) never transforms; a Responses
    // exchange builds the exec-gate + path-map transform for success bodies.
    // One response, one model turn: the unmapped upload leg's calls in order.
    const ex: UploadExchange = { turn: new UploadTurn(), ...(launchDir !== undefined ? { launchDir } : {}) };
    const transform = ctx !== null && upstream.status < 400 ? this.buildArgsTransform(ctx, ex) : null;
    const canRewrite = transform !== null;
    const isJson = ctype.includes("application/json");
    // A 2xx Responses answer that is not JSON is read as the event stream
    // Codex reads it as, whatever its content-type says. The ChatGPT backend
    // answers `…/codex/responses` with NO content-type (observed 2026-09-30,
    // agent-sign-in.md §2.8 item 6); keyed on the header alone, that
    // stream went out verbatim: no exec gate, no path map, no repacker, no
    // tllm_call. Fail-closed: the gate reads what the agent will read.
    const isSse = ctype.includes("text/event-stream") || (ctx !== null && upstream.status < 400 && !isJson);
    // The model's answer for the exchange's tllm_call: a passive reader of the
    // body as relayed (never changes a byte), emitted when the body ends.
    const sniffer = pending ? new ResponseSniffer(isSse ? "sse" : "json") : null;
    const answered = (): void => {
      if (pending && sniffer) this.emitTllmCall(pending, OpenAiProxy.answerText(upstream.status, sniffer.finish()));
    };

    if (canRewrite && !isSse && isJson) {
      // Non-streaming (stream:false) success body — the JSON twin of the SSE
      // rewriter. Without this, function_call commands relay un-gated and with
      // HumanView paths, and Codex runs them against the user's real tree.
      await this.bufferAndRewriteJson(upstream, res, transform!, this.rewriterOptions(ctx!, cellsIsolated, ex), (raw) => {
        sniffer?.feed(raw);
        answered();
      });
      return;
    }

    // The text-delta token repacker (text-repack.ts) runs on every Responses
    // success stream, gated or not: a `$MDU:` token split across two
    // output_text deltas reaches the agent whole in one.
    const repack = ctx !== null && upstream.status < 400 && isSse;
    if (!repack && (!canRewrite || !isSse)) {
      res.writeHead(upstream.status, this.responseHeaders(upstream.headers));
      if (sniffer) {
        // Listeners before pipe(): the event is queued in the same tick the
        // relay ends, so a caller that saw the response sees the event.
        upstream.body.on("data", (c: Buffer | string) => sniffer.feed(c));
        upstream.body.on("end", answered);
        upstream.body.on("error", answered);
      }
      upstream.body.pipe(res);
      await this.finished(res);
      return;
    }

    // Rewriting changes the body length → drop content-length, chunk the relay.
    res.writeHead(upstream.status, this.responseHeaders(upstream.headers, { dropContentLength: true }));
    const rewriter = canRewrite ? new ResponsesArgsRewriter(transform!, this.rewriterOptions(ctx!, cellsIsolated, ex)) : null;
    const repacker = new ResponsesTextRepacker();
    // Reply row reservation (reply-row-reservation.md §11.7): chained AFTER
    // the repacker (a token arrives whole). The sniffer taps the raw upstream
    // chunks, so the tllm_call records the model's real text, never a block.
    // Only built when expansion can fire (kill switch off, a session key, an
    // arbiter with the human-plane ops); otherwise the stream is as before.
    const expander = ctx !== null && this.reserve.possible
      ? new ResponsesReserveExpander({
          lines: this.reserve.lines,
          layout: this.reserve.layout,
          shape: this.reserve.shape,
          register: this.reserve.register,
          cap: this.reserveCap,
          onExpand: (x) => {
            this.safeEmit(makeReserveExpand(ctx, {
              hash: x.hash, rows: x.rows, token: x.token,
              ...(x.width !== undefined && x.first !== undefined ? { width: x.width, first: x.first } : {}),
            }));
          },
        })
      : null;
    const src = upstream.body;
    src.setEncoding("utf8");
    // The transform AWAITS an arbiter verdict (the exec gate) at block
    // boundaries, so chunk processing is CHAINED to preserve output order. Each
    // link catches, so the chain never rejects; the gate's await is bounded by
    // DEFAULT_EXEC_GATE_TIMEOUT_MS (exec-gate.ts) — a wedged arbiter fails closed
    // to a sentinel — so a slow/failed link can only bounded-delay, never wedge.
    await new Promise<void>((resolve) => {
      let chain: Promise<void> = Promise.resolve();
      const enqueue = (fn: () => Promise<void>): void => {
        chain = chain.then(fn, fn);
      };
      src.on("data", (chunk: string) => {
        sniffer?.feed(chunk);
        enqueue(async () => {
          let outChunk: string;
          try {
            outChunk = rewriter ? await rewriter.feed(chunk) : chunk;
          } catch (err) {
            // Fail-safe for the path-map (view-consistency); the exec gate is
            // fail-closed INSIDE the transform, so a raw relay here cannot leak a
            // gate decision — only degrade view spelling.
            this.log(`sse rewrite error (non-fatal, relaying raw): ${(err as Error).message}`);
            outChunk = chunk;
          }
          let relay = repacker.feed(outChunk); // pure string work, never throws
          // Reserve blocks (text only; never rejects, never drops an event).
          if (expander && relay !== "") relay = await expander.feed(relay);
          if (relay !== "") res.write(relay);
        });
      });
      src.on("end", () => {
        enqueue(async () => {
          let tail = "";
          try { tail = rewriter ? await rewriter.end() : ""; }
          catch (err) { this.log(`sse rewrite flush error (non-fatal): ${(err as Error).message}`); }
          tail = repacker.feed(tail) + repacker.end(); // never swallow a held event
          if (expander) tail = (await expander.feed(tail)) + (await expander.end());
          if (tail !== "") res.write(tail);
          answered();
          res.end();
          resolve();
        });
      });
      src.on("error", (err) => {
        enqueue(async () => {
          this.log(`upstream stream error: ${err.message}`);
          let tail = "";
          try { tail = rewriter ? await rewriter.end() : ""; } catch { /* non-fatal */ }
          tail = repacker.feed(tail) + repacker.end();
          if (expander) tail = (await expander.feed(tail)) + (await expander.end());
          if (tail !== "") res.write(tail);
          answered();
          res.end();
          resolve();
        });
      });
    });
  }

  /**
   * Non-streaming (stream:false) success path: buffer the JSON Response body and
   * run each `output[]` call item (a function_call's arguments, a script
   * cell's exec literals) through the SAME transform as the SSE path (exec
   * gate → forward path-map). The JSON twin of the SSE
   * rewriter — without it a stream:false exchange hands Codex un-gated commands
   * / un-mapped HumanView paths. An unparseable body relays raw (conservative
   * rule 3 for the map; the exec gate never reached it, and un-gated raw bytes
   * are the model's own opaque symbols, which cannot leak).
   */
  private async bufferAndRewriteJson(
    upstream: UpstreamResponse,
    res: ServerResponse,
    transform: ArgsTransform,
    opts: RewriterOptions = {},
    /** Sees the body as the MODEL wrote it, before the transform. */
    onRaw?: (raw: Buffer) => void,
  ): Promise<void> {
    const chunks: Buffer[] = [];
    const src = upstream.body;
    await new Promise<void>((resolve) => {
      src.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      src.on("end", resolve);
      src.on("error", () => resolve());
    });
    let buf = Buffer.concat(chunks);
    onRaw?.(buf);
    try {
      const obj = JSON.parse(buf.toString("utf8")) as Record<string, unknown>;
      const output = obj["output"];
      if (Array.isArray(output)) {
        const changed = await transformOutputItems(output, transform, opts);
        if (changed) buf = Buffer.from(JSON.stringify(obj), "utf8");
      }
    } catch (err) {
      this.log(`json rewrite error (non-fatal, relaying raw): ${(err as Error).message}`);
    }
    // The body length can change → drop content-length, send our own.
    res.writeHead(upstream.status, this.responseHeaders(upstream.headers, { dropContentLength: true }));
    res.end(buf);
  }

  // ── header / response helpers ─────────────────────────────────────────────

  private sanitizeHeaders(
    headers: IncomingMessage["headers"],
    contentLength: number,
  ): Record<string, string | string[] | undefined> {
    const out: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(headers)) {
      const lk = k.toLowerCase();
      // Drop hop-by-hop + length/encoding headers; we set our own length and
      // do not re-encode bodies.
      if (lk === "host" || lk === "content-length" || lk === "connection" ||
          lk === "transfer-encoding" || lk === "accept-encoding") continue;
      // Mandu's own headers (x-mandu-session-id, -batch-id, -tenant) are read
      // here and stay here: the model provider has no use for them, and they
      // name the user's session, batch and tenant (2026-09-29).
      if (lk.startsWith("x-mandu-")) continue;
      out[k] = v;
    }
    out["content-length"] = String(contentLength);
    // We forward an identity body; refuse compressed upstream responses so the
    // client gets identical plaintext bytes back.
    out["accept-encoding"] = "identity";
    return out;
  }

  private responseHeaders(
    headers: Record<string, string | string[] | undefined>,
    opts: { dropContentLength?: boolean } = {},
  ): Record<string, string | string[]> {
    const out: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(headers)) {
      if (v == null) continue;
      const lk = k.toLowerCase();
      if (lk === "connection" || lk === "transfer-encoding") continue;
      // The view-map rewrite can change the body length; chunked relay instead.
      if (opts.dropContentLength && lk === "content-length") continue;
      out[k] = v;
    }
    return out;
  }

  /**
   * Serve the identity document for the launcher's reuse check. `{mandu:true}`
   * plus the configured identity when set, else `{mandu:false}` (an
   * unidentified proxy a launcher must not adopt). Loopback admin — never
   * carries secrets (the arbiter socket path + workspace roots are already in
   * the launcher's own env).
   */
  private serveIdentity(res: ServerResponse): void {
    const body = this.identity
      ? { mandu: true, ...this.identity }
      : { mandu: false };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }

  private refuse(res: ServerResponse, status: number, message: string, type = "mandu_fail_closed"): void {
    if (res.headersSent) return;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { type, message } }));
  }

  private finished(res: ServerResponse): Promise<void> {
    return new Promise((resolve) => {
      if (res.writableEnded) return resolve();
      res.on("finish", resolve);
      res.on("close", resolve);
    });
  }

  /** What withAgentKey has logged (header, host, outcome), once each. */
  private readonly agentKeyLogged = new Set<string>();

  /**
   * Agent-sign-in.md §3.9: the agent's own key (Codex's saved key, twinned in
   * `auth.json`) put back into the auth header of a request to the API
   * origin (or a declared main model), when the egress gate releases its
   * placeholder at that origin's host. A ChatGPT sign-in's request is never
   * touched (its bearer is the sign-in's own token, relayed as written,
   * §2.4). Every other header, the body and every failure are left as they
   * are: the provider answers 401 (auth-substitution.ts). The headers are
   * copied, never mutated in place. Never logs a value.
   */
  private withAgentKey(inner: UpstreamFetcher, declared: boolean): UpstreamFetcher {
    return async (args) => {
      const route = chooseUpstream(args.headers, declared);
      if (route !== "api" && route !== "declared") return inner(args);
      const arbiter = this.arbiter;
      const source = arbiter.authCredential ? { authCredential: arbiter.authCredential.bind(arbiter) } : undefined;
      const dest = upstreamDestination(this.upstreamOrigin);
      const headers = { ...args.headers };
      const subs = await substituteAuthHeaders(headers, dest, source, this.sessionKey);
      for (const s of subs) {
        const key = `${s.header}\u0000${dest?.host ?? ""}\u0000${s.symbol}\u0000${s.restored}`;
        if (this.agentKeyLogged.has(key)) continue;
        this.agentKeyLogged.add(key);
        this.log(s.restored
          ? `agent key: put the key back in ${s.header} for ${dest?.host} (agent-sign-in.md §3.9)`
          : `agent key: ${s.header} keeps its placeholder for ${dest?.host ?? "an unknown host"} (${s.reason}); the provider will refuse it`);
      }
      return inner({ ...args, headers });
    };
  }

  /** One transport per request, chosen by chooseUpstream from the headers
   *  actually forwarded (agent-sign-in.md §2.4 item 2). A ChatGPT
   *  sign-in bound for a declared main model never leaves: onRequest refuses
   *  it first, and this throws (→ 502, nothing sent) should that ever be
   *  bypassed. */
  private static switchingFetcher(api: UpstreamFetcher, chatgpt: UpstreamFetcher, declared: boolean): UpstreamFetcher {
    return (args) => {
      switch (chooseUpstream(args.headers, declared)) {
        case "chatgpt": return chatgpt(args);
        case "declared-refuse": return Promise.reject(new Error("a ChatGPT sign-in is never sent to a declared main model"));
        default: return api(args);
      }
    };
  }

  /** The default upstream fetcher: a real HTTPS request to the origin, or
   *  plain HTTP when the origin is an `http:` LITERAL LOOPBACK address
   *  (upstreamTransport). Any other origin is refused per request (→ 502),
   *  never sent. */
  private makeHttpsFetcher(origin: string, isBaseUrl: boolean, tlsMaterial?: TlsMaterial): UpstreamFetcher {
    const url = new URL(origin);
    const transport = upstreamTransport(url);
    // Plan 12 D3: a declared main model's checks run in every handshake, on
    // an agent of their own (so no connection is shared with another origin).
    const agentP = tlsMaterial && transport === "https"
      ? import("node:https").then((h) => new h.Agent({ keepAlive: true, ...tlsOptions(tlsMaterial) } as import("node:https").AgentOptions))
      : null;
    return async ({ method, path, headers, body }) => {
      if (transport === "refuse") {
        throw new Error(`upstream ${url.protocol}//${url.host} refused: plain http is allowed only to a loopback address (127.0.0.0/8, ::1); use https`);
      }
      // Plan 12 D4: a literal address is never looked up, so the agent's
      // perimeter lookup cannot see it; check it here, before any connection.
      const outside = tlsMaterial ? checkLiteralHost(url.hostname, tlsMaterial.perimeter) : null;
      if (outside) throw outside;
      const https = transport === "http" ? await import("node:http") : await import("node:https");
      const agent = agentP ? await agentP : undefined;
      return new Promise<UpstreamResponse>((resolve, reject) => {
        const r = https.request(
          {
            protocol: url.protocol,
            hostname: url.hostname.replace(/^\[|\]$/g, ""),
            port: url.port || (transport === "http" ? 80 : 443),
            ...(agent ? { agent } : {}),
            method,
            path: upstreamRequestPath(path, url, isBaseUrl),
            headers: { ...headers, host: url.host },
          },
          (upRes) => {
            resolve({
              status: upRes.statusCode ?? 502,
              headers: upRes.headers,
              body: upRes,
            });
          },
        );
        r.on("error", reject);
        r.end(body);
      });
    };
  }
}
