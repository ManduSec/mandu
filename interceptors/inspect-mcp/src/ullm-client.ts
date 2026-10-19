/**
 * ullm-client — the QUARANTINED model (U-LLM) seam.
 *
 * Mandu M4 cooperative U-LLM path (interceptors/inspect-mcp). DUALVIEW routes
 * untrusted-data processing to a quarantined model — paper U-LLM (repo:
 * quarantined LLM). This module defines the NARROW interface inspect_symbol
 * calls (`UllmClient`) plus THREE implementations:
 *   - `AnthropicUllmClient`: a DIRECT Anthropic Messages API call (needs a key,
 *                             except at a declared endpoint, Plan 11 D5).
 *   - `OpenAiChatUllmClient`: one OpenAI chat-completions call, for a declared
 *                             `wire: openai-chat` endpoint (Ollama, vLLM;
 *                             Plan 11 D5).
 *   - `CliUllmClient`       — a fresh `claude -p` (or `codex exec`) subprocess
 *                             that REUSES the user's logged-in Claude Code auth
 *                             (no separate API key), in a SEPARATE session/process
 *                             with NO tools and a CLEAN cwd.
 *
 * Provenance: the subprocess SHAPE (system+user prompt, isolated context,
 * tool-less; the `claude -p --output-format json` / `codex exec --json` argv;
 * the `parseClaudeCliJson` / `parseCodexCliJsonl` output parsing) is lifted from
 *   https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-inspect-symbol.ts
 *   (`invokeCLI` / `parseClaudeCliJson` / `parseCodexCliJsonl`).
 * The reference invokes the quarantined model as an isolated `claude -p`
 * subprocess so it inherits the user's Claude auth without a separate key;
 * `CliUllmClient` replicates that. `AnthropicUllmClient` remains for the case
 * where an explicit U-LLM API key is configured.
 *
 * SECURITY: a UllmClient call carries NO T-LLM history, NO T-LLM system prompt,
 * and NO tools — only the fixed quarantine system prompt + the instruction +
 * the single raw value. The CLI client additionally runs the child in a fresh
 * temp cwd (so it never loads the project `.mcp.json` that would recursively
 * register this very inspect server, nor any project tools/config), disables ALL
 * tools (`--tools ""` for claude), and points the child at the REAL Anthropic
 * endpoint — NEVER the Mandu anthropic-proxy. The seam is injectable so tests use
 * a MOCK and the suite never makes a network call, runs a real claude/codex, or
 * needs a key (the default runner's own tests drive it with plain `node`).
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** One quarantined model call. Stateless: each call is a fresh, isolated context. */
export interface UllmCall {
  /** The fixed quarantine system prompt (no T-LLM context). */
  system: string;
  /** The single user message: instruction + the raw (desymbolized) value. */
  user: string;
}

export interface UllmResult {
  /** The model's response text. This is UNTRUSTED — it MUST be re-symbolized
   *  by the caller before returning to T-LLM. */
  text: string;
  /** The model id that produced the result (for the ullm_call event). */
  model: string;
}

/**
 * The quarantined-model dependency inspect_symbol calls. Anything satisfying it
 * — the real Anthropic client or a mock — can drive the tool.
 */
export interface UllmClient {
  /** Run one isolated, tool-less, history-less model call. */
  complete(call: UllmCall): Promise<UllmResult>;
}

export interface AnthropicUllmClientOptions {
  /** Anthropic API key. Required for the real client unless `requireApiKey`
   *  is false (a declared endpoint with no `tokenEnv`, Plan 11 D5), in which
   *  case an empty key sends no `x-api-key` header. */
  apiKey: string;
  /** Default true. False only for a declared model endpoint. */
  requireApiKey?: boolean;
  /** Default true: a non-2xx error carries up to 500 chars of the response
   *  body. False at a declared endpoint (Plan 11 D5): an arbitrary local
   *  server may echo the request (local-model bytes) in an error body, and
   *  an error string travels back to T-LLM. */
  errorDetail?: boolean;
  /** Default false. True at a declared endpoint (Plan 11 §8 item 4): a 2xx
   *  body without a Messages `content` array is an error, not an empty
   *  answer, so a garbage reply refuses like an unreachable endpoint. */
  requireContent?: boolean;
  /** Plan 11 D5: origins of the DECLARED model endpoints the loopback guard
   *  also accepts (already stripped of the proxy's and the forwarder's
   *  origin by `sanctionedEndpointOrigins`). */
  sanctionedOrigins?: readonly string[];
  /** Base URL. Defaults to https://api.anthropic.com. Honors ANTHROPIC_BASE_URL.
   *  NOTE: this should point at the REAL Anthropic endpoint, NOT the Mandu
   *  model-API MITM proxy — the U-LLM is a SEPARATE quarantined channel and must
   *  not be routed back through T-LLM's instrumented path. */
  baseUrl?: string;
  /** The launcher-pinned loopback forwarder (MANDU_ULLM_FORWARDER) — the ONE
   *  loopback base URL the guard accepts (see assertNonProxyBaseUrl). */
  forwarderUrl?: string;
  /** Model id for the quarantined call. Defaults to a small/cheap Claude model. */
  model?: string;
  /** Max tokens for the response. */
  maxTokens?: number;
  /** Per-call timeout (ms). Defaults to 60s, mirroring the reference. */
  timeoutMs?: number;
  /** Anthropic API version header. */
  anthropicVersion?: string;
  /** Injectable fetch (testing / custom transport). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

const DEFAULT_MODEL = "claude-haiku-4-5";
const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_ANTHROPIC_VERSION = "2023-06-01";

/**
 * Reject a U-LLM base URL that points at the local Mandu anthropic-proxy.
 *
 * SECURITY (core invariant): the quarantined U-LLM is a SEPARATE channel and must
 * hit the REAL Anthropic endpoint. The anthropic-proxy listens on loopback (e.g.
 * 127.0.0.1:8788); routing the U-LLM through it loops untrusted data back through
 * T-LLM's instrumented path. We therefore REFUSE any loopback host as a U-LLM
 * base URL (fail closed) rather than silently use it. The CLI client already drops
 * an inherited loopback ANTHROPIC_BASE_URL (see CliUllmClient.buildChildEnv); this
 * is the matching guard for the api-mode (direct HTTP) path.
 *
 * THE ONE SANCTIONED LOOPBACK (`forwarderUrl`): the launcher may run a VERBATIM
 * loopback→api.anthropic.com relay (launcher/src/services/ullm-forwarder.ts) so
 * the whole-agent Landlock TCP wrap can deny direct :443 without breaking the
 * U-LLM. It pins that relay's URL into our env as MANDU_ULLM_FORWARDER; a
 * base URL is accepted iff its ORIGIN equals the pin exactly. The relay is not
 * instrumented (no arbiter, no symbolization, no prompt injection — bytes
 * through), so the separate-channel invariant holds; every OTHER loopback —
 * above all the instrumented proxy, which lives on a different port — stays
 * refused fail-closed.
 *
 * THE DECLARED ENDPOINTS (`sanctionedOrigins`, Plan 11 D5): a model endpoint
 * the operator declared in policy.yaml `models:` (read from the arbiter, never
 * from env) is addressed directly, often over loopback (an Ollama on
 * 127.0.0.1:11434). Its origin is accepted too, but only after
 * `sanctionedEndpointOrigins` removed any declared entry whose origin equals
 * the model proxy's or the forwarder's: the arbiter refuses those at
 * validation (D2), and this is the belt to that suspender.
 *
 * Returns the (trimmed) url if it is acceptable; throws a clear config error if it
 * resolves to a loopback host.
 */
export function assertNonProxyBaseUrl(
  rawUrl: string,
  forwarderUrl?: string,
  sanctionedOrigins: readonly string[] = [],
): string {
  const url = rawUrl.trim();
  if (!url) return url;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Not a parseable absolute URL — leave validation/handling to the caller
    // (the default endpoint is used when no base URL is configured at all).
    return url;
  }
  const host = parsed.hostname.toLowerCase();
  // Strip IPv6 brackets ("[::1]" → "::1") for the literal comparison.
  const bare = host.replace(/^\[|\]$/g, "");
  const isLoopback =
    bare === "localhost" ||
    bare === "::1" ||
    bare === "0.0.0.0" ||
    bare.startsWith("127.");
  if (isLoopback) {
    // Origin comparison (protocol + host + port, default ports normalized):
    // the pin names ONE relay endpoint, not a loopback class.
    if (forwarderUrl) {
      try {
        if (new URL(forwarderUrl.trim()).origin === parsed.origin) return url;
      } catch {
        // Unparseable pin — fall through to the refusal (fail closed).
      }
    }
    if (sanctionedOrigins.includes(parsed.origin)) return url;
    throw new Error(
      `U-LLM ANTHROPIC_BASE_URL points at a loopback host (${host}) — refusing: ` +
        `the quarantined U-LLM must hit the REAL Anthropic endpoint (or the launcher's ` +
        `pinned MANDU_ULLM_FORWARDER relay), never the Mandu anthropic-proxy. ` +
        `Unset ANTHROPIC_BASE_URL or point it at the real endpoint (fail closed).`,
    );
  }
  return url;
}

/** `new URL(u).origin`, or null when `u` is absent or unparseable. */
export function originOf(u: string | undefined): string | null {
  if (!u || !u.trim()) return null;
  try {
    const o = new URL(u.trim()).origin;
    return o === "null" ? null : o;
  } catch {
    return null;
  }
}

/** The addresses a declared endpoint must never equal (Plan 11 D2/D5): the
 *  launcher's U-LLM forwarder (a verbatim relay to an EXTERNAL vendor) and
 *  every model-proxy address this process can know (the instrumented T-LLM
 *  path). */
export interface EndpointGuard {
  forwarderUrl?: string;
  proxyUrls?: readonly string[];
}

/** The origins of the forbidden addresses in `guard` (unparseable ones drop). */
export function forbiddenEndpointOrigins(guard: EndpointGuard): Set<string> {
  const out = new Set<string>();
  for (const u of [guard.forwarderUrl, ...(guard.proxyUrls ?? [])]) {
    const o = originOf(u);
    if (o) out.add(o);
  }
  return out;
}

/**
 * The origins of the declared endpoints the loopback guard accepts: every
 * endpoint the arbiter returned, MINUS any whose origin equals the model
 * proxy's or the forwarder's. Unparseable URLs drop out (fail closed: no
 * client can be built for them).
 */
export function sanctionedEndpointOrigins(
  endpoints: ReadonlyArray<{ url: string }>,
  guard: EndpointGuard,
): string[] {
  const forbidden = forbiddenEndpointOrigins(guard);
  const out: string[] = [];
  for (const ep of endpoints) {
    const o = originOf(ep.url);
    if (o && !forbidden.has(o) && !out.includes(o)) out.push(o);
  }
  return out;
}

/** Where a declared endpoint sits (plan 12 D1): `host` when its host is a
 *  loopback spelling (`localhost`, `*.localhost`, 127.0.0.0/8, `::1`, the
 *  unspecified addresses), else `network`; null when the url is not http(s)
 *  with a host. MIRROR of arbiter/policy/model-placement.ts
 *  `endpointPlacement` and launcher/src/model-endpoints.ts; pinned together by
 *  tests/stack/model-placement-parity.test.ts. Pure. */
export function endpointPlacement(url: string): "host" | "network" | null {
  let u: URL;
  try { u = new URL(url.trim()); } catch { return null; }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.hostname === "") return null;
  let h = u.hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (mapped) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    h = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  if (h === "localhost" || h.endsWith(".localhost")) return "host";
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return "host";
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.every((n) => n <= 255) && (o[0] === 127 || o.every((n) => n === 0))) return "host";
  }
  return "network";
}

/**
 * Throw unless a declared endpoint URL is usable: parseable http(s), and not
 * the proxy's or the forwarder's origin, and (plan 12 D2) not plain http to
 * another machine unless the entry opted out with `allow_plain_http: true`
 * (carried as `allowPlainHttp`). Run BEFORE any client is built for the
 * endpoint, so no raw byte is sent to a refused address. The plain-http
 * refusal is the belt for an arbiter older than the load rule, which would
 * serve such an entry; an arbiter that never sends `allowPlainHttp` leaves
 * this refusing (fail-closed).
 */
export function assertDeclaredEndpointUrl(
  name: string,
  rawUrl: string,
  guard: EndpointGuard,
  opts: { allowPlainHttp?: boolean } = {},
): string {
  const o = originOf(rawUrl);
  if (!o || !/^https?:$/.test(new URL(rawUrl.trim()).protocol)) {
    throw new Error(`declared model endpoint '${name}' has no usable http(s) url (fail closed)`);
  }
  if (new URL(rawUrl.trim()).protocol === "http:" && endpointPlacement(rawUrl) === "network" && opts.allowPlainHttp !== true) {
    throw new Error(
      `declared model endpoint '${name}' is plain http on another machine, so the data would cross the network ` +
        `unencrypted; refusing (fail closed). Use https, a loopback tunnel, or allow_plain_http: true in policy.yaml`,
    );
  }
  if (forbiddenEndpointOrigins(guard).has(o)) {
    throw new Error(
      `declared model endpoint '${name}' is the model proxy's or the U-LLM forwarder's address; ` +
        `refusing: bytes sent there reach an external model (fail closed)`,
    );
  }
  return rawUrl.trim();
}

/**
 * Real U-LLM client: posts a single isolated message to the Anthropic Messages
 * API. NO conversation history, NO tools, NO T-LLM system prompt — only the
 * quarantine system + the one user message the caller built.
 */
export class AnthropicUllmClient implements UllmClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly model: string;
  private readonly maxTokens: number;
  private readonly timeoutMs: number;
  private readonly anthropicVersion: string;
  private readonly fetchImpl: typeof fetch;
  private readonly errorDetail: boolean;
  private readonly requireContent: boolean;

  constructor(opts: AnthropicUllmClientOptions) {
    if (!opts.apiKey && opts.requireApiKey !== false) {
      throw new Error("AnthropicUllmClient: apiKey is required");
    }
    this.apiKey = opts.apiKey ?? "";
    // SECURITY: refuse a loopback base URL (the Mandu anthropic-proxy). The U-LLM
    // is a separate quarantined channel and must hit the REAL Anthropic endpoint —
    // or the launcher's pinned verbatim forwarder, the one sanctioned loopback.
    const base = opts.baseUrl ?? "https://api.anthropic.com";
    this.baseUrl = assertNonProxyBaseUrl(base, opts.forwarderUrl, opts.sanctionedOrigins).replace(/\/+$/, "");
    this.model = opts.model ?? DEFAULT_MODEL;
    this.maxTokens = opts.maxTokens ?? DEFAULT_MAX_TOKENS;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.anthropicVersion = opts.anthropicVersion ?? DEFAULT_ANTHROPIC_VERSION;
    this.errorDetail = opts.errorDetail !== false;
    this.requireContent = opts.requireContent === true;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== "function") {
      throw new Error("AnthropicUllmClient: no fetch implementation available");
    }
  }

  async complete(call: UllmCall): Promise<UllmResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(this.apiKey ? { "x-api-key": this.apiKey } : {}),
            "anthropic-version": this.anthropicVersion,
          },
          body: JSON.stringify({
            model: this.model,
            max_tokens: this.maxTokens,
            // The fixed quarantine system prompt — NOT T-LLM's system prompt.
            system: call.system,
            // A single, history-less user turn. NO tools are offered.
            messages: [{ role: "user", content: call.user }],
          }),
          signal: controller.signal,
        });
      } catch (err) {
        throw transportError(err, controller.signal, this.timeoutMs);
      }

      if (!res.ok) {
        const detail = this.errorDetail ? await safeText(res) : "";
        throw new Error(`U-LLM request failed: ${res.status} ${res.statusText} ${detail}`.trim());
      }

      // Without detail, a JSON parse error must not quote the body either
      // (V8's SyntaxError message carries a snippet of the text).
      const payload: unknown = this.errorDetail ? await res.json() : await parseJsonQuiet(res, controller.signal, this.timeoutMs);
      if (this.requireContent && !(isRecord(payload) && Array.isArray(payload.content))) {
        throw new Error("U-LLM response carried no content array");
      }
      const text = extractAnthropicText(payload);
      const model = extractAnthropicModel(payload) ?? this.model;
      return { text, model };
    } finally {
      clearTimeout(timer);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpenAiChatUllmClient: a declared `wire: openai-chat` endpoint (Plan 11 D5).
// ─────────────────────────────────────────────────────────────────────────────

export interface OpenAiChatUllmClientOptions {
  /** The declared endpoint's base URL (policy.yaml `models[].url`). The call
   *  goes to `{baseUrl}/v1/chat/completions`. */
  baseUrl: string;
  /** Model id (policy.yaml `models[].model`). Required: every OpenAI-shaped
   *  server (Ollama, vLLM) needs one. */
  model: string;
  /** Optional bearer token (the value of `process.env[tokenEnv]`). */
  token?: string;
  /** Origins the loopback guard accepts (see assertNonProxyBaseUrl). A
   *  declared endpoint passes its own, already guard-filtered origin. */
  sanctionedOrigins?: readonly string[];
  /** The forwarder pin. Deliberately NOT sanctioned for this client: the
   *  forwarder relays to an external vendor and speaks Anthropic. Accepted
   *  only so a caller cannot sanction it by omission. */
  forwarderUrl?: string;
  maxTokens?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * U-LLM client for an OpenAI chat-completions endpoint. Same quarantine shape
 * as the Anthropic client: ONE request, the fixed quarantine system prompt as
 * the system message, the single user turn, NO tools, NO history.
 * Returns `choices[0].message.content`.
 */
export class OpenAiChatUllmClient implements UllmClient {
  private readonly baseUrl: string;
  private readonly model: string;
  private readonly token: string | undefined;
  private readonly maxTokens: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: OpenAiChatUllmClientOptions) {
    if (!opts.model || !opts.model.trim()) {
      throw new Error("OpenAiChatUllmClient: a model id is required (policy.yaml models[].model)");
    }
    // The forwarder is never a sanctioned target here: pass no forwarder pin
    // to the guard, and strip its origin from the sanctioned set.
    const fwd = originOf(opts.forwarderUrl);
    const sanctioned = (opts.sanctionedOrigins ?? []).filter((o) => o !== fwd);
    this.baseUrl = assertNonProxyBaseUrl(opts.baseUrl, undefined, sanctioned).replace(/\/+$/, "");
    if (!this.baseUrl) throw new Error("OpenAiChatUllmClient: baseUrl is required");
    this.model = opts.model.trim();
    this.token = opts.token && opts.token.trim() ? opts.token.trim() : undefined;
    this.maxTokens = opts.maxTokens ?? DEFAULT_MAX_TOKENS;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== "function") {
      throw new Error("OpenAiChatUllmClient: no fetch implementation available");
    }
  }

  async complete(call: UllmCall): Promise<UllmResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.fetchImpl(`${this.baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
          },
          body: JSON.stringify({
            model: this.model,
            max_tokens: this.maxTokens,
            stream: false,
            // The fixed quarantine system prompt, then ONE user turn. NO tools.
            messages: [
              { role: "system", content: call.system },
              { role: "user", content: call.user },
            ],
          }),
          signal: controller.signal,
        });
      } catch (err) {
        throw transportError(err, controller.signal, this.timeoutMs);
      }

      // NO response body in any error: a declared endpoint is an arbitrary
      // server that may echo the request (local-model bytes), and an error
      // string travels back to T-LLM.
      if (!res.ok) {
        throw new Error(`U-LLM request failed: ${res.status} ${res.statusText}`.trim());
      }

      const payload: unknown = await parseJsonQuiet(res, controller.signal, this.timeoutMs);
      const text = extractOpenAiChatText(payload);
      if (text === null) throw new Error("U-LLM response carried no choices[0].message.content");
      const model = isRecord(payload) && typeof payload.model === "string" ? payload.model : this.model;
      return { text, model };
    } finally {
      clearTimeout(timer);
    }
  }
}

/** `choices[0].message.content` (string, or an array of text parts), trimmed;
 *  null when the shape is absent. */
function extractOpenAiChatText(payload: unknown): string | null {
  if (!isRecord(payload) || !Array.isArray(payload.choices) || payload.choices.length === 0) return null;
  const first = payload.choices[0];
  if (!isRecord(first) || !isRecord(first.message)) return null;
  const content = first.message.content;
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content
      .map((p) => (isRecord(p) && typeof p.text === "string" ? p.text : ""))
      .join("")
      .trim();
  }
  return null;
}

/**
 * The error for a request that produced no response (Plan 11 §8 item 4): the
 * timeout names itself, and a connection failure names its errno code
 * (`ECONNREFUSED`, `ENOTFOUND`, `EACCES` from a kernel confine…) instead of
 * undici's bare "fetch failed". Nothing here can carry a response body: no
 * response exists.
 */
export function transportError(err: unknown, signal: AbortSignal, timeoutMs: number): Error {
  if (signal.aborted) return new Error(`U-LLM request timed out after ${timeoutMs}ms`);
  const cause = isRecord(err) ? (err as { cause?: unknown }).cause : undefined;
  const code = isRecord(cause) && typeof cause.code === "string" ? cause.code : null;
  if (code !== null && /^[A-Z0-9_]{1,40}$/.test(code)) {
    return new Error(`U-LLM request could not reach the endpoint (${code})`);
  }
  return err instanceof Error ? err : new Error(String(err));
}

/** `res.json()` whose failure message never quotes the body. A body that
 *  stalls past the deadline reads as the timeout it is. */
async function parseJsonQuiet(res: Response, signal?: AbortSignal, timeoutMs?: number): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    if (signal?.aborted) throw new Error(`U-LLM request timed out after ${timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`);
    throw new Error("U-LLM response was not valid JSON");
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 500);
  } catch {
    return "";
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Extract the concatenated text from an Anthropic Messages API response. */
function extractAnthropicText(payload: unknown): string {
  if (!isRecord(payload) || !Array.isArray(payload.content)) return "";
  const parts: string[] = [];
  for (const block of payload.content) {
    if (isRecord(block) && block.type === "text" && typeof block.text === "string") {
      parts.push(block.text);
    }
  }
  return parts.join("").trim();
}

function extractAnthropicModel(payload: unknown): string | null {
  if (isRecord(payload) && typeof payload.model === "string") return payload.model;
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// CliUllmClient — the SUBPROCESS U-LLM (reuses the user's Claude Code auth).
// ─────────────────────────────────────────────────────────────────────────────

/** Which CLI to drive. `auto` picks claude vs codex from the model id (adfi rule). */
export type UllmCliBinary = "claude" | "codex" | "auto";

/** Result of the injectable exec seam (mirrors child_process.spawnSync's shape). */
export interface CliExecResult {
  /** Process exit code (null if the process was terminated by a signal). */
  status: number | null;
  /** Signal that terminated the process, if any (e.g. "SIGTERM" on timeout). */
  signal?: NodeJS.Signals | null;
  /** Captured stdout (the JSON / JSONL payload we parse). */
  stdout: string;
  /** Captured stderr (surfaced in error messages on failure). */
  stderr: string;
  /** An error object if the spawn itself failed (binary not found, timeout). */
  error?: Error;
}

/** One subprocess invocation. */
export interface CliExecSpec {
  /** The binary to spawn (resolved: "claude" or "codex", never "auto"). */
  file: string;
  /** Argv (without the binary). */
  args: string[];
  /** The combined prompt, written to the child's STDIN. */
  input: string;
  /** The child's working directory — a fresh, clean temp dir. */
  cwd: string;
  /**
   * The child's environment. Inherits the parent (so the user's logged-in
   * credentials carry through — that's the whole point), with ANTHROPIC_BASE_URL
   * forced to the REAL endpoint (never the Mandu proxy).
   */
  env: NodeJS.ProcessEnv;
  /** Per-call timeout (ms). */
  timeoutMs: number;
  /** Max captured-output size (bytes). */
  maxBuffer: number;
}

/** Injectable subprocess runner. Defaults to the ASYNC spawn-based
 *  `defaultCliExec`. May return the result synchronously (test seams do) or as
 *  a Promise (the default does). A sync seam is fine for canned results, but a
 *  production runner MUST be async: a synchronous child wait (spawnSync) blocks
 *  the event loop the MCP server shares with its arbiter IPC client, starving
 *  every pending deadline-armed IPC reply — see defaultCliExec. */
export type CliExec = (spec: CliExecSpec) => CliExecResult | Promise<CliExecResult>;

export interface CliUllmClientOptions {
  /**
   * Which CLI to use. Defaults to "auto": codex for OpenAI/gpt/o* model ids
   * (per the adfi prefix rule), otherwise claude.
   */
  binary?: UllmCliBinary;
  /** Model id for the quarantined call. Defaults to a small/cheap Claude model
   *  for claude, and to Codex's own default model for codex (no `-m`). */
  model?: string;
  /**
   * The REAL Anthropic endpoint the child should hit. Used to set the child's
   * ANTHROPIC_BASE_URL. MUST be the real endpoint (or api.anthropic.com),
   * NEVER the Mandu anthropic-proxy — the U-LLM is a separate quarantined channel.
   * If left at the default api.anthropic.com we DELETE ANTHROPIC_BASE_URL from
   * the child so claude uses its own logged-in config.
   */
  baseUrl?: string;
  /** Per-call timeout (ms). Defaults to 60s, mirroring the reference. */
  timeoutMs?: number;
  /** Injectable subprocess runner (testing). Defaults to spawnSync. */
  exec?: CliExec;
  /** Injectable temp-dir factory (testing). Returns a fresh, empty dir. */
  mkTempDir?: () => string;
  /** Injectable temp-dir cleanup (testing). */
  rmTempDir?: (dir: string) => void;
  /** Injectable file write into the temp dir (testing). */
  writeTempFile?: (path: string, content: string) => void;
  /** The launcher's U-LLM forwarder (MANDU_ULLM_FORWARDER). For codex the
   *  child's provider points at it (`codexForwarderProvider`); claude reaches
   *  it through `baseUrl`. */
  forwarderUrl?: string;
}

const REAL_ANTHROPIC_BASE = "https://api.anthropic.com";
const CLI_MAX_BUFFER = 8 * 1024 * 1024;

/** adfi's rule: OpenAI/gpt/o* model ids route to codex; everything else to claude. */
function isOpenAiModel(model: string): boolean {
  return model.startsWith("openai/") || model.startsWith("gpt-") || model.startsWith("o");
}

/** Resolve "auto" → "claude" | "codex" from the model id (adfi rule). */
export function resolveCliBinary(binary: UllmCliBinary, model: string): "claude" | "codex" {
  if (binary === "claude" || binary === "codex") return binary;
  return isOpenAiModel(model) ? "codex" : "claude";
}

/**
 * Build the argv for a quarantined CLI call.
 *
 * claude: `-p --model <m> --output-format json --tools "" --setting-sources project,local
 *          --system-prompt <quarantine prompt>`
 *   - `-p`               : print mode (non-interactive, exit after one turn).
 *   - `--output-format json`: a single JSON result we parse for `.result`/`.usage`.
 *   - `--tools ""`       : disables ALL built-in tools (verified via `claude --help`:
 *                          "Use \"\" to disable all tools"). NO tool use is possible.
 *   - `--setting-sources project,local`: load ONLY project/local settings (which do
 *                          not exist in the fresh temp cwd), excluding USER settings.
 *                          A user-global `apiKeyHelper` outranks the OAuth login in
 *                          CC's auth order; excluding the user source keeps the
 *                          quarantined child on the logged-in SUBSCRIPTION. (The
 *                          matching env-var scrub is in `buildChildEnv`.) Auth itself
 *                          is read independently of settings, so OAuth still works.
 *   - `--system-prompt <system>`: the quarantine prompt REPLACES Claude Code's
 *                          own system prompt, so the child boots AS the data
 *                          processor instead of as an agent whose identity a
 *                          user message then tries to rewrite. Delivering the
 *                          quarantine framing as user text is what made live
 *                          U-LLMs read it as a jailbreak and refuse (the
 *                          refusal utility gap). Fixed text — never untrusted
 *                          data — so argv is safe; the USER message (which
 *                          carries the untrusted DATA) stays on STDIN.
 *
 * codex: `codex exec` is a whole agent (a shell, code-mode cells, apply_patch,
 *   apps, plugins, MCP servers from the user's config), so it is CUT DOWN to
 *   a quarantined, tool-less model call (`codexQuarantineArgs`, measured on
 *   codex-cli 0.136.0, 0.144.1 and 0.160.0 against a stand-in backend whose
 *   first answer calls every tool: none ran). The quarantine prompt REPLACES
 *   Codex's own instructions (`model_instructions_file`, written into the
 *   temp cwd: `files`), the user message rides STDIN (`-`), never argv,
 *   where any process of the user could read it from /proc. No `-m` without
 *   an explicit model: the default model id is a Claude id, which Codex
 *   cannot serve, so Codex picks its own default.
 */
export function buildCliArgs(
  resolved: "claude" | "codex",
  model: string | undefined,
  system: string,
  user: string,
  workDir = "",
  forwarderUrl?: string,
): CliInvocation {
  if (resolved === "codex") {
    return {
      args: codexQuarantineArgs(model, join(workDir, CODEX_INSTRUCTIONS_FILE), forwarderUrl),
      useStdin: true,
      input: user,
      files: [{ name: CODEX_INSTRUCTIONS_FILE, content: system }],
    };
  }
  // claude: user message on stdin; ALL tools disabled via the empty --tools list;
  // settings limited to project,local so a user-global apiKeyHelper can't divert
  // the quarantined child off the subscription (see buildChildEnv for the env scrub).
  return {
    args: [
      "-p", "--model", model || DEFAULT_MODEL, "--output-format", "json",
      "--tools", "", "--setting-sources", "project,local",
      "--system-prompt", system,
    ],
    useStdin: true,
    input: user,
    files: [],
  };
}

/** One quarantined CLI invocation (`buildCliArgs`). */
export interface CliInvocation {
  args: string[];
  /** True: `input` is written to the child's stdin. */
  useStdin: boolean;
  input: string;
  /** Files written into the fresh temp cwd before the child starts (fixed
   *  text only: the quarantine prompt, never the data). */
  files: Array<{ name: string; content: string }>;
}

/** The file in the temp cwd holding the quarantine prompt for Codex. */
export const CODEX_INSTRUCTIONS_FILE = "quarantine-instructions.md";

/** Codex features that give the model a tool, each present (so `--disable`
 *  accepts it) from codex-cli 0.136.0 through 0.160.0. `--disable` of a name
 *  Codex does not know is an error, so a renamed feature fails the call
 *  closed rather than leaving the tool on. */
export const CODEX_DISABLED_FEATURES = [
  "shell_tool", "unified_exec", "apps", "plugins", "multi_agent", "browser_use",
  "computer_use", "image_generation", "hooks", "goals", "tool_suggest",
] as const;

/** Codex features off by `-c features.<name>=false`, which an older Codex
 *  ignores: `code_mode_host` (the code-mode cell, since 0.154; with the shell
 *  off it has no tool to call anyway), `view_image` (since 0.160; before
 *  it, view_image stays on, reading only what the agent's own world can read,
 *  and that world shows a labelled file as its symbol), `sleep_tool`,
 *  `skill_search`. */
export const CODEX_SOFT_DISABLED_FEATURES = ["code_mode_host", "view_image", "sleep_tool", "skill_search"] as const;

/**
 * The `codex exec` argv of a quarantined call:
 *   - `--skip-git-repo-check`: the temp cwd is no repository, and Codex
 *     refuses an untrusted directory without it (the failure every Codex
 *     `inspect_symbol` hit before 2026-10-04);
 *   - `--ephemeral`: no session file, so the raw value is never written
 *     under CODEX_HOME;
 *   - `--ignore-user-config`, `--ignore-rules`: no user config (its MCP
 *     servers, provider, hooks, notify command), no exec-policy rules; the
 *     sign-in still comes from CODEX_HOME. With no user config the provider
 *     is Codex's built-in one, the vendor's real endpoint, never Mandu's
 *     openai-proxy (the launcher routes the agent's Codex there by argv
 *     overrides this child never sees);
 *   - `-s read-only`, `approval_policy="never"`: a tool that survives the
 *     cuts below could neither write nor ask;
 *   - the quarantine prompt as the model instructions, no environment
 *     context, no apps or collaboration-mode instructions, no project docs,
 *     no bundled skills, no web search, every tool feature off.
 */
export function codexQuarantineArgs(model: string | undefined, instructionsPath: string, forwarderUrl?: string): string[] {
  const args = [
    "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules",
    "-s", "read-only",
    "-c", 'approval_policy="never"',
    "-c", `model_instructions_file=${JSON.stringify(instructionsPath)}`,
    "-c", "include_environment_context=false",
    "-c", "include_apps_instructions=false",
    "-c", "include_collaboration_mode_instructions=false",
    "-c", "project_doc_max_bytes=0",
    "-c", "skills.bundled.enabled=false",
    "-c", 'web_search="disabled"',
  ];
  // Codex's own usage events to the ChatGPT backend: nothing of the data,
  // but no reason for the quarantine to dial out beyond its model call.
  args.push("-c", "analytics.enabled=false");
  // The launcher's U-LLM forwarder (MANDU_ULLM_FORWARDER, agent-sign-in.md
  // §2.11): the model call goes to the relay, which sends it on to the fixed
  // OpenAI pair, so the quarantine works with :443 denied in the agent's
  // world. `requires_openai_auth` makes Codex send its own sign-in (the
  // relay forwards it verbatim, never stores it).
  if (forwarderUrl !== undefined) args.push(...codexForwarderProvider(forwarderUrl));
  for (const f of CODEX_SOFT_DISABLED_FEATURES) args.push("-c", `features.${f}=false`);
  for (const f of CODEX_DISABLED_FEATURES) args.push("--disable", f);
  // Strip the provider prefix (e.g. "openai/gpt-5.4-mini" → "gpt-5.4-mini").
  if (model) args.push("-m", model.replace(/^openai\//, ""));
  args.push("--color", "never", "--json", "-");
  return args;
}

/** The provider the quarantined `codex exec` uses behind the forwarder. */
export const CODEX_ULLM_PROVIDER = "mandu_ullm";

/** The `-c` overrides pointing the quarantined `codex exec` at the
 *  launcher's forwarder: an http(s) origin, the pin itself (anything else
 *  throws: fail closed, the call is not made). Pure. */
export function codexForwarderProvider(forwarderUrl: string): string[] {
  const origin = originOf(forwarderUrl);
  if (origin === null || !/^https?:/.test(origin)) {
    throw new Error("CliUllmClient: MANDU_ULLM_FORWARDER is not an http(s) URL — refusing the codex quarantine call (fail closed)");
  }
  const table = `{name=${JSON.stringify(CODEX_ULLM_PROVIDER)},base_url=${JSON.stringify(`${origin}/v1`)},wire_api="responses",requires_openai_auth=true,supports_websockets=false}`;
  return ["-c", `model_provider=${JSON.stringify(CODEX_ULLM_PROVIDER)}`, "-c", `model_providers.${CODEX_ULLM_PROVIDER}=${table}`];
}

/**
 * Parse a Claude Code `-p --output-format json` payload.
 * Shape (relevant fields): `{ result: string, model?: string }`.
 * Lifted from adfi-inspect-symbol.ts `parseClaudeCliJson` (usage stripped — the
 * inspect-mcp core does not consume token usage; we return only {text, model}).
 */
export function parseClaudeCliJson(stdout: string, fallbackModel: string): UllmResult {
  const trimmed = stdout.trim();
  if (!trimmed) throw new Error("CliUllmClient: claude returned empty output");
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("CliUllmClient: claude output was not valid JSON");
  }
  if (!isRecord(parsed)) {
    throw new Error("CliUllmClient: claude output was not a JSON object");
  }
  // A CLI-level error surfaces as `{ is_error: true, result: "<message>" }`.
  if (parsed.is_error === true) {
    const detail = typeof parsed.result === "string" ? parsed.result : "unknown error";
    throw new Error(`CliUllmClient: claude reported an error: ${detail}`.slice(0, 500));
  }
  const text = typeof parsed.result === "string" ? parsed.result.trim() : "";
  const model = typeof parsed.model === "string" ? parsed.model : fallbackModel;
  return { text, model };
}

/**
 * Parse a Codex `exec --json` JSONL event stream.
 * The last `item.completed` with `item.type === "agent_message"` holds the text.
 * Lifted from adfi-inspect-symbol.ts `parseCodexCliJsonl` (usage stripped).
 */
export function parseCodexCliJsonl(stdout: string, fallbackModel: string): UllmResult {
  let text = "";
  let model = fallbackModel;
  let sawEvent = false;
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("Reading additional input from stdin")) continue;
    let event: unknown;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!isRecord(event)) continue;
    sawEvent = true;
    if (event.type === "item.completed" && isRecord(event.item)) {
      const item = event.item;
      if (item.type === "agent_message" && typeof item.text === "string") {
        text = item.text;
      }
    }
    if (typeof event.model === "string") model = event.model;
  }
  if (!sawEvent) throw new Error("CliUllmClient: codex produced no JSON events");
  return { text: text.trim(), model };
}

/** The part of a failed `codex exec`'s stderr worth reporting: its notice
 *  that it reads stdin dropped. Pure. */
export function codexStderrDetail(stderr: string): string {
  return stderr.split(/\r?\n/).filter((l) => !l.startsWith("Reading additional input from stdin")).join("\n");
}

/**
 * Subprocess U-LLM client: spawns a fresh `claude -p` (or `codex exec`) child
 * that inherits the user's logged-in Claude Code auth — NO separate API key.
 *
 * The child runs in a CLEAN temp cwd (no project `.mcp.json` → no recursive
 * inspect-server registration, no project tools/config), with ALL tools
 * disabled, pointed at the REAL Anthropic endpoint (never the Mandu proxy).
 * Stateless: each call is its own process and session.
 */
export class CliUllmClient implements UllmClient {
  private readonly binary: UllmCliBinary;
  /** The configured model; undefined = the CLI's own default for codex
   *  (DEFAULT_MODEL, a Claude id, for claude). */
  private readonly model: string | undefined;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly exec: CliExec;
  private readonly mkTempDir: () => string;
  private readonly rmTempDir: (dir: string) => void;
  private readonly writeTempFile: (path: string, content: string) => void;
  private readonly forwarderUrl: string | undefined;

  constructor(opts: CliUllmClientOptions = {}) {
    this.binary = opts.binary ?? "auto";
    this.model = opts.model || undefined;
    this.baseUrl = (opts.baseUrl ?? REAL_ANTHROPIC_BASE).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.exec = opts.exec ?? defaultCliExec;
    this.mkTempDir = opts.mkTempDir ?? defaultMkTempDir;
    this.rmTempDir = opts.rmTempDir ?? defaultRmTempDir;
    this.writeTempFile = opts.writeTempFile ?? ((p, c) => writeFileSync(p, c, { mode: 0o600 }));
    this.forwarderUrl = opts.forwarderUrl || undefined;
  }

  async complete(call: UllmCall): Promise<UllmResult> {
    const resolved = resolveCliBinary(this.binary, this.model ?? DEFAULT_MODEL);
    // The label of the model that answered when the CLI does not name it.
    const fallbackModel = this.model ?? (resolved === "codex" ? "codex-default" : DEFAULT_MODEL);

    const cwd = this.mkTempDir();
    try {
      // claude: quarantine prompt in the real system slot (--system-prompt);
      // codex: as its model instructions, from a file in the temp cwd. The
      // user message rides stdin for both.
      const { args, useStdin, input, files } = buildCliArgs(
        resolved, this.model, call.system, call.user, cwd, this.forwarderUrl,
      );
      for (const f of files) this.writeTempFile(join(cwd, f.name), f.content);
      const result = await this.exec({
        file: resolved,
        args,
        input: useStdin ? input : "",
        cwd,
        env: this.buildChildEnv(resolved, cwd),
        timeoutMs: this.timeoutMs,
        maxBuffer: CLI_MAX_BUFFER,
      });

      if (result.error) {
        throw new Error(
          `CliUllmClient: ${resolved} spawn failed: ${result.error.message}`,
        );
      }
      if (result.signal) {
        throw new Error(
          `CliUllmClient: ${resolved} terminated by ${result.signal} (timeout?)`,
        );
      }
      if (result.status !== 0) {
        // codex: stderr only. Its stdout is the event stream, which holds the
        // model's (untrusted) answer, and this message reaches T-LLM.
        const raw = resolved === "codex" ? codexStderrDetail(result.stderr) : (result.stderr || result.stdout || "");
        const detail = raw.trim().slice(0, 500);
        throw new Error(
          `CliUllmClient: ${resolved} exited ${result.status}${detail ? `: ${detail}` : ""}`,
        );
      }

      const parsed =
        resolved === "codex"
          ? parseCodexCliJsonl(result.stdout, fallbackModel)
          : parseClaudeCliJson(result.stdout, fallbackModel);
      if (!parsed.text) {
        throw new Error(`CliUllmClient: ${resolved} returned no response text`);
      }
      return parsed;
    } finally {
      this.rmTempDir(cwd);
    }
  }

  /**
   * Build the child env: inherit the parent (carrying the user's logged-in
   * credentials) but (1) pin ANTHROPIC_BASE_URL to the REAL endpoint, and
   * (2) scrub the env-var keys that outrank the subscription login.
   *
   * (1) If the configured base is the default api.anthropic.com we DELETE the var
   *     so claude falls back to its own logged-in config — and, critically, so the
   *     child is NEVER routed through the Mandu anthropic-proxy the parent set.
   * (2) cli-mode means "reuse the logged-in SUBSCRIPTION, no key". CC's auth order
   *     puts ANTHROPIC_AUTH_TOKEN and ANTHROPIC_API_KEY ABOVE the OAuth/keychain
   *     login, so an inherited key/token would silently bill the metered API
   *     instead of the subscription. We drop both. (A user-global apiKeyHelper,
   *     which also outranks OAuth, is excluded via the claude argv's
   *     `--setting-sources project,local` — see buildCliArgs.)
   */
  private buildChildEnv(resolved: "claude" | "codex", cwd: string): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env };
    if (this.baseUrl && this.baseUrl !== REAL_ANTHROPIC_BASE) {
      env.ANTHROPIC_BASE_URL = this.baseUrl;
    } else {
      // Default endpoint → drop any inherited (possibly proxy) base URL so claude
      // uses its own config. NEVER inherit a 127.0.0.1 anthropic-proxy URL.
      delete env.ANTHROPIC_BASE_URL;
    }
    // Force the SUBSCRIPTION login: a stray API key/token in the parent env would
    // outrank OAuth and silently divert the quarantined child onto metered API use.
    delete env.ANTHROPIC_API_KEY;
    delete env.ANTHROPIC_AUTH_TOKEN;
    // (3) codex: an OPENAI_BASE_URL re-points the built-in provider on the
    //     Codex versions that read it; the quarantined child dials the
    //     vendor's own endpoint, so none is inherited.
    if (resolved === "codex") delete env.OPENAI_BASE_URL;
    // (4) codex: its temp files (the sandbox's mount-target directory) go
    //     into the call's own temp cwd, removed with it, never the shared
    //     TMPDIR.
    if (resolved === "codex") env.TMPDIR = cwd;
    return env;
  }
}

/** Default exec: ASYNC node:child_process spawn, capturing stdout/stderr as
 *  utf-8 — deliberately NOT spawnSync. The inspect MCP server, its arbiter IPC
 *  client, and this runner all share one event loop; spawnSync would freeze
 *  the loop for the child's whole runtime (many seconds of `claude -p`), so a
 *  deadline-armed IPC request pending across that window (client.ts
 *  DEFAULT_REQUEST_TIMEOUT_MS) loses the loop-resume race to its own expired
 *  timer — libuv runs the timers phase before poll I/O — and a HEALTHY arbiter
 *  reads as "timed out — fail closed". That was the live claude-e2e
 *  inspect-verdict-retry failure (2026-07-14).
 *
 *  Semantics mirror the old spawnSync runner: timeout → SIGTERM, reported via
 *  `signal`; output past maxBuffer → kill + `error`; spawn failure (ENOENT) →
 *  `error`. Exported for its own unit tests. */
export function defaultCliExec(spec: CliExecSpec): Promise<CliExecResult> {
  return new Promise((resolve) => {
    const child = spawn(spec.file, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let error: Error | undefined;
    let timedOut = false;
    let settled = false;
    const settle = (r: CliExecResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, spec.timeoutMs);

    const overflow = (which: string) => {
      if (!error) {
        error = new Error(`${which} exceeded maxBuffer (${spec.maxBuffer} bytes)`);
        child.kill("SIGTERM");
      }
    };
    child.stdout.setEncoding("utf-8");
    child.stderr.setEncoding("utf-8");
    child.stdout.on("data", (d: string) => {
      stdout += d;
      if (stdout.length > spec.maxBuffer) overflow("stdout");
    });
    child.stderr.on("data", (d: string) => {
      stderr += d;
      if (stderr.length > spec.maxBuffer) overflow("stderr");
    });

    // Spawn failure (binary not found, EACCES): 'close' may never deliver an
    // exit code — settle with the error, mirroring spawnSync's `error` field.
    child.on("error", (err) => settle({ status: null, signal: null, stdout, stderr, error: err }));
    child.on("close", (status, signal) =>
      settle({
        status,
        // Mirror spawnSync: a timeout kill surfaces as the terminating signal.
        signal: timedOut ? (signal ?? "SIGTERM") : signal,
        stdout,
        stderr,
        error,
      }),
    );

    // EPIPE if the child exits before the prompt finishes writing — the close
    // handler already reports the real failure; don't crash the process.
    child.stdin.on("error", () => {});
    child.stdin.end(spec.input);
  });
}

/** Default temp-dir factory: a fresh mkdtemp under the OS tmp dir. */
function defaultMkTempDir(): string {
  return mkdtempSync(join(tmpdir(), "mandu-ullm-"));
}

/** Default cleanup: recursively remove the temp dir (best-effort). */
function defaultRmTempDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup; a leftover empty temp dir is harmless.
  }
}
