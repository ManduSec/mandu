/**
 * egress — the PURE egress/ingress data-usage transforms for the forward proxy.
 *
 * PURE / unit-tested. The proxy server (src/proxy.ts) feeds these in-memory text
 * buffers; all of the symbolization/desymbolization POLICY lives here so it is
 * testable without a live socket or root.
 *
 * Ported faithfully from interceptors/net-supervisor/src/transform.rs:
 *   - EGRESS (agent → external): `gateRequest` — per symbol call the arbiter's
 *     `desymbolizationDecision` (the data-usage gate). On allow → resolve +
 *     substitute the raw value; on deny → leave the symbol symbolic + mark
 *     withheld; arbiter miss / any deny → FAIL-CLOSED block (the secret is NOT
 *     exfiltrated). A request with NO symbols passes through unchanged.
 *   - INGRESS (external → agent): `observeResponse` (renamed from symbolizeResponse,
 *     Plan 7) — classify the response body; UNTRUSTED → return the RAW body and
 *     best-effort taintProcess the connecting process (observe-and-tag); TRUSTED →
 *     return unchanged; arbiter miss → an opaque marker, NEVER raw untrusted bytes.
 *     The T-LLM invariant is enforced SOLELY at the model-API proxy (spec §1.1).
 *   - "Send without it" (confidentiality.md §4): a symbol the human answered
 *     so is never resolved; THIS request goes with `SEND_WITHOUT_MARKER` in
 *     its place (`gateRequest`), checked again by the proxy's value scan.
 *   - `isModelHost` — the exclusion predicate; model-API hosts are owned by the
 *     anthropic-proxy / openai-proxy under a different policy, so this proxy never
 *     gates them.
 *
 * SECURITY INVARIANT (mandu.md): un-symbolized untrusted data must never leave
 * via a desymbolized egress without a positive gate decision. The T-LLM invariant
 * (untrusted data reaches T-LLM only as a symbol) is enforced at the model-API proxy;
 * the net layer enforces fail-closed egress and observe-and-tag on ingress.
 * Egress is FAIL-CLOSED on arbiter error; ingress arbiter-miss is also fail-closed
 * (opaque marker); a SUCCESSFUL untrusted classify now returns the RAW body (Plan 7).
 */

import type { Arbiter, EgressRefusalKind, RequestPosition, RuleRef, SessionSecretTaint, TaintedProcessBindings } from "./arbiter-client.js";
import { NETWORK_BOUNDARY } from "./arbiter-client.js";
import { randomUUID } from "node:crypto";
import type { ProcHolder } from "./conn-attr.js";
import { destinationMatchesBindings } from "./host-bindings.js";

/** The kind of an egress refusal, from a gate's reason (below), for the
 *  arbiter's record (plan 10 §11.8, "Refused connections"). The reason
 *  itself is never sent: it names the destination. */
export function refusalKindOf(reason: string): EgressRefusalKind {
  if (reason.includes(SHELL_EXPANDED_RULE)) return "shell-expanded";
  if (/could not be attributed|tainted-process-unattributed/.test(reason)) return "unattributed";
  // confidentiality.md §4, "A held command's refused connection": before
  // `tainted` (the reason says that too).
  if (reason.includes(HELD_SESSION_ASKED)) return "session-asked";
  if (reason.includes(HELD_SESSION_BLOCKED)) return "session-blocked";
  if (/tainted process|secret-tainted/.test(reason)) return "tainted";
  if (/symbol/.test(reason)) return "symbol";
  return "fail-closed";
}

/**
 * The `$MDU:*` symbol pattern, mirrored from arbiter/symbol-table/
 * symbol-table.ts `SYMBOL_PATTERN`. The proxy is dependency-free of the arbiter
 * package, so we keep it in sync here. Two alternatives: a base symbol with an
 * optional dotted field path, or a bare base symbol.
 *
 * Returns a FRESH RegExp each call (the global flag carries mutable lastIndex
 * state; callers must not share one instance).
 */
export function symbolPattern(): RegExp {
  return /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*|\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;
}

/** All `$MDU:*` symbols appearing in `text`, in order of appearance,
 * de-duplicated (first occurrence wins). Empty for symbol-free text. */
export function findSymbols(text: string): string[] {
  if (!text) return [];
  const re = symbolPattern();
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of text.matchAll(re)) {
    const s = m[0];
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out;
}

/** Replace every WHOLE symbol token in `text` (a match of `symbolPattern`,
 *  exactly what `findSymbols` reports) that `resolved` has a value for.
 *  Never a substring: `$MDU:x[ab].tok` allowed in the Authorization header
 *  is not spliced into a longer token `$MDU:x[ab].tokZ` in the body, which
 *  a literal replace would turn into the value followed by `Z` (plan 10
 *  §11.13.1, 2026-10-09: the gate decided each token where it sits). */
function substituteTokens(text: string, resolved: ReadonlyMap<string, string>): string {
  if (resolved.size === 0 || !text.includes("$MDU:")) return text;
  return text.replace(symbolPattern(), (m) => resolved.get(m) ?? m);
}

// ── A placeholder a shell emptied (confidentiality.md §7) ────────────────────
//
// A script the agent wrote to a file (no exec gate sees it) with
// `curl -H "Authorization: Bearer $MDU:nomodel_Read[de31].KEY"` sends
// `Bearer :nomodel_Read[de31].KEY`: the shell read `$MDU` as an unset
// variable. The request holds neither the value nor a placeholder, so the
// per-symbol gate has nothing to judge and the service answers 401 with no
// hint why. The text that is left is recognized here, confirmed against the
// symbol table by the arbiter (`strippedPlaceholders`: free text that only
// looks alike is never refused), and the request is REFUSED with how to quote
// the placeholder. It is never filled in: the stripped text is not a
// placeholder, and putting a value back where the program did not write one
// would be a release the per-symbol gate never decided.

/** The rule id the refusal carries (arbiter rule-ref.ts). */
export const SHELL_EXPANDED_RULE = "egress:shell-expanded-placeholder";

/** A labelled placeholder's tail after its marker: `<tag>[<hash>]` and an
 *  optional field path (the symbol grammar, `symbolPattern`). */
const TAIL = String.raw`[a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*`;
/** The forms a shell leaves: bash, dash, sh and zsh (for `nomodel_`) drop
 *  `$MDU` and keep the `:`; zsh reads `$MDU:a…` and `$MDU:l…` as modifiers on
 *  the empty variable and drops the `:a` / `:l` too. Each maps back to the
 *  placeholder name it came from. Not after `$MDU` (a whole placeholder is
 *  the per-symbol gate's). */
const STRIPPED_FORMS: ReadonlyArray<{ re: RegExp; rebuild: (m: RegExpExecArray) => string }> = [
  { re: new RegExp(String.raw`(?<!\$MDU):((?:nomodel|anymodel|localmodel)_${TAIL})`, "g"), rebuild: (m) => `$MDU:${m[1]}` },
  { re: new RegExp(String.raw`(?<![A-Za-z0-9_:$])nymodel_(${TAIL})`, "g"), rebuild: (m) => `$MDU:anymodel_${m[1]}` },
  { re: new RegExp(String.raw`(?<![A-Za-z0-9_:$])ocalmodel_(${TAIL})`, "g"), rebuild: (m) => `$MDU:localmodel_${m[1]}` },
];

/** The most candidates one request asks the arbiter about (its op's cap). */
const STRIPPED_MAX = 64;

/** `text` percent-decoded, or "" when it does not decode (or has no `%`). */
function percentDecoded(text: string): string {
  if (!text.includes("%")) return "";
  try { return decodeURIComponent(text.replace(/\+/g, " ")); } catch { return ""; }
}

/**
 * The shell-stripped placeholder forms in a request, as rebuilt placeholder
 * name → the text the request carried (the first seen). Scans the URL, the
 * body (each also percent-decoded), every header and the decoded pair of a
 * Basic credential. Pure; the arbiter decides which names are real.
 */
export function strippedPlaceholderCandidates(
  input: Pick<GateInput, "url" | "headers" | "bodyText">,
): Map<string, string> {
  const out = new Map<string, string>();
  const scan = (text: string): void => {
    if (!text || !/model_/.test(text)) return;
    for (const { re, rebuild } of STRIPPED_FORMS) {
      re.lastIndex = 0;
      for (let m = re.exec(text); m && out.size < STRIPPED_MAX; m = re.exec(text)) {
        const name = rebuild(m);
        if (!out.has(name)) out.set(name, m[0]);
      }
    }
  };
  scan(input.url);
  scan(percentDecoded(input.url));
  scan(input.bodyText);
  scan(percentDecoded(input.bodyText));
  for (const v of Object.values(input.headers)) scan(headerText(v));
  for (const pair of basicPairs(input.headers)) scan(pair);
  return out;
}

/** The refusal's words: what the request carried, why, and the fix. */
export function shellExpandedReason(hits: ReadonlyArray<{ symbol: string; carried: string }>): string {
  const first = hits[0]!;
  const more = hits.length > 1 ? ` (and ${hits.length - 1} more)` : "";
  return (
    `the request carried ${first.carried}${more}, which is the placeholder ${first.symbol} after a shell expanded "$MDU" ` +
    "to nothing (the placeholder was in double quotes or unquoted in a command or script), so the request held neither " +
    "the secret nor its placeholder, and nothing was sent. Put the placeholder in single quotes " +
    `('${first.symbol}') where the shell reads it and run it again [${SHELL_EXPANDED_RULE}]`
  );
}

/**
 * Refuse a request that carries a shell-stripped placeholder the arbiter
 * knows (a block result), or null. A utility check, not a release gate: an
 * arbiter without the op, or one that does not answer, leaves the request
 * to the gates as before (the stripped text holds no value either way).
 */
async function shellExpandedRefusal(input: GateInput): Promise<GateResult | null> {
  const candidates = strippedPlaceholderCandidates(input);
  if (candidates.size === 0 || !input.arbiter.strippedPlaceholders) return null;
  let answer;
  try {
    answer = await input.arbiter.strippedPlaceholders({
      candidates: [...candidates.keys()],
      ...(input.sessionKey !== undefined ? { sessionKey: input.sessionKey } : {}),
    });
  } catch {
    return null;
  }
  const hits = (answer.found ?? []).filter((s) => candidates.has(s)).map((symbol) => ({ symbol, carried: candidates.get(symbol)! }));
  if (hits.length === 0) return null;
  const reason = shellExpandedReason(hits);
  const ruleRef = answer.ruleRef ?? { source: "rule" as const, id: SHELL_EXPANDED_RULE };
  return {
    action: "block",
    reason,
    withheld: hits.map((h) => ({ symbol: h.symbol, requiresApproval: false, reason, ruleRef })),
  };
}

// ── "Send without it" (confidentiality.md §4, 2026-10-17) ────────────────────
//
// The human's fourth answer to a card about a secret's symbol in a request:
// the NEXT such request goes, with a neutral marker where the symbol was,
// never the value and never the `$MDU:` token. Plain ASCII with no quote, no
// backslash, no line break and no `:`, so it keeps a JSON string, a header
// and a Basic `user:password` pair whole; in a URL and an
// `application/x-www-form-urlencoded` body it goes percent-encoded, so the
// URL stays sendable and the form field decodes to the marker.

/** The marker a withheld symbol is replaced by. */
export const SEND_WITHOUT_MARKER = "[hidden by Mandu]";
/** {@link SEND_WITHOUT_MARKER} percent-encoded (a URL, a form body). */
export const SEND_WITHOUT_MARKER_ENCODED = encodeURIComponent(SEND_WITHOUT_MARKER);

/** Is the body `application/x-www-form-urlencoded`? */
function isFormBody(headers: GateInput["headers"]): boolean {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== "content-type" || v == null) continue;
    if (/^\s*application\/x-www-form-urlencoded\b/i.test(headerText(v))) return true;
  }
  return false;
}

/** The request with every token in `values` replaced, each position by its
 *  own map (`url`, `body`, every header, a Basic pair inside Authorization),
 *  and a `Content-Length` header the agent sent set to the new body's
 *  length (the legs re-derive it too: proxy.ts, mitm.ts). */
function substituteRequest(
  input: Pick<GateInput, "url" | "headers" | "bodyText">,
  maps: { url: ReadonlyMap<string, string>; body: ReadonlyMap<string, string>; header: ReadonlyMap<string, string> },
): { url: string; headers: Record<string, string | string[] | undefined>; bodyText: string } {
  const url = substituteTokens(input.url, maps.url);
  const bodyText = substituteTokens(input.bodyText, maps.body);
  const headers: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(input.headers)) headers[k] = v;

  // A symbol inside a Basic credential first (§11.13.1): decode, put back,
  // re-encode. A Basic value that is not base64 (npm's `_auth` symbol sent as
  // written) is left to the plain substitution below.
  for (const [k, v] of Object.entries(headers)) {
    if (v == null || !isAuthorizationHeader(k)) continue;
    headers[k] = Array.isArray(v) ? v.map((x) => substituteInBasic(x, maps.header)) : substituteInBasic(v, maps.header);
  }

  for (const [k, v] of Object.entries(headers)) {
    if (v == null) continue;
    headers[k] = Array.isArray(v) ? v.map((x) => substituteTokens(x, maps.header)) : substituteTokens(v, maps.header);
  }
  if (bodyText !== input.bodyText) {
    for (const k of Object.keys(headers)) {
      if (k.toLowerCase() === "content-length" && headers[k] != null) headers[k] = String(Buffer.byteLength(bodyText, "utf8"));
    }
  }
  return { url, headers, bodyText };
}

// ── EGRESS gate ──────────────────────────────────────────────────────────────

/** A per-symbol withholding record surfaced for approval / the emitted event. */
export interface WithheldSymbol {
  symbol: string;
  requiresApproval: boolean;
  reason: string;
  /** The arbiter rule that withheld it (policy-surface.md §9.3). This is what
   *  tells `egress:secret-bound-approval` (the datum IS bound here; the flow
   *  was untrusted-influenced, so ONE approval makes it standing) from
   *  `egress:secret-unbound` (a declassification) — two blocks that used to
   *  read identically in the trace (live watch C13 at the default posture). */
  ruleRef?: RuleRef;
  /** The approval-queue row the arbiter filed for it (`egr-<n>`): for the
   *  event only, never the agent's 403 body (`agentWithheld`). */
  approvalId?: string;
}

/** The withheld list as the AGENT's 403 body carries it: without the queue
 *  id, which is the dashboard's join key and means nothing to the agent. */
export function agentWithheld(withheld: readonly WithheldSymbol[]): Omit<WithheldSymbol, "approvalId">[] {
  return withheld.map(({ approvalId: _id, ...w }) => w);
}

/** The request fields the gate inspects + rewrites. */
export interface GateInput {
  method: string;
  /** The destination host (host[:port]) the gate checks against the URL trust
   * category. Used as `destination` in the desymbolization request. */
  destinationHost: string;
  /** The full request URL (absolute-form) — symbols here are gated + rewritten. */
  url: string;
  /** Request headers as a flat string→string(|string[]) bag. */
  headers: Record<string, string | string[] | undefined>;
  /** The request body as text (already decoded), or "" if none/binary. */
  bodyText: string;
  arbiter: Arbiter;
  /**
   * The source process key (Plan 3 taint-egress). When present and the proc is
   * tainted, an untrusted destination blocks the request even with no symbols.
   * Attribution is resolved by proxy.ts from req.socket (Plan 6.5, the /proc
   * baseline); undefined (unattributable) → branch skipped, fail-soft. This
   * INTEGRITY leg is frozen (protection-modes.md §10): only the plain-HTTP leg
   * passes it, as before; the TLS legs do not.
   */
  procKey?: string;
  /**
   * Plan 13 D6, the SECRET-taint leg: every process holding the client's end
   * of the connection, with its ancestors (conn-attr.ts `attributeHolders`).
   * `[]` = the connection could not be attributed: refused while any process
   * of the session holds a secret. Absent → falls back to `procKey` alone
   * (a caller predating D6), or no secret-taint check when that is absent
   * too. Every leg of the proxy passes it (plain HTTP, TLS-inspected HTTPS).
   */
  holders?: readonly ProcHolder[];
  /**
   * ATTRIBUTION-ONLY session key forwarded on each `desymbolizationDecision`
   * request (never a decision input) — lets the arbiter attribute the
   * approval-queue row a deny may create to the session. Threaded by proxy.ts
   * from the SAME source its net_action event emission uses (the proxy's
   * sessionId, i.e. MANDU_SESSION_KEY when launched by the launcher), so
   * queue rows and events attribute identically. Omitted → not sent.
   */
  sessionKey?: string;
  /**
   * The scheme this request travels in: `http` on the plain forward-proxy
   * leg, `https` on the TLS-inspected leg. Rides on every
   * `desymbolizationDecision`: the arbiter never puts a wire-twin credential
   * declared for https into a request that is not HTTPS (plan 10 §11.13.1,
   * 2026-10-03). Omitted → not sent (such a credential is then refused).
   */
  scheme?: "http" | "https";
  /**
   * The destination is a model service a program in the session calls
   * itself (`MANDU_NET_PROXY_MODEL_SERVICES`, the launcher's
   * PROVIDER_KEY_HOSTS: jev's TypeSafe and OpenRouter; agent-sign-in.md
   * §3.12). A placeholder anywhere but the Authorization header is what such
   * a model is meant to read, so it leaves as it is: never asked about,
   * never resolved, never withheld (`keptOpaque`). One in the Authorization
   * header (the service's own key) is decided as everywhere. The tripwire
   * still refuses a raw registered value.
   */
  modelService?: boolean;
}

/** Is `host` (host[:port]) one of the model services, or under one? Pure. */
export function isModelService(host: string, services: readonly string[]): boolean {
  const h = host.trim().toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  return services.some((s) => {
    const x = s.trim().toLowerCase().replace(/\.$/, "");
    return x !== "" && (h === x || h.endsWith(`.${x}`));
  });
}

/** The gate verdict. */
export type GateResult =
  | {
      action: "forward";
      /** When symbols were resolved, the rewritten request to send on the wire.
       * Absent when there were no symbols (forward unchanged). */
      rewritten?: { url: string; headers: Record<string, string | string[] | undefined>; bodyText: string };
      /** Symbols that were resolved (for the emitted event). */
      resolved?: string[];
      /** At a model service (GateInput.modelService): the placeholders sent
       *  as they are, never resolved. */
      keptOpaque?: string[];
      /** "Send without it" (confidentiality.md §4): the symbols the human
       *  answered so, sent as `SEND_WITHOUT_MARKER` and never resolved. */
      sentWithout?: string[];
      /** With `sentWithout`: the request as the agent sent it with ONLY
       *  those symbols replaced (any allowed symbol still a token). The
       *  proxy runs its value scan over it and refuses the request unless
       *  the scan ran and found nothing (`fingerprintTripwire`, strict). */
      sentWithoutView?: { url: string; headers: Record<string, string | string[] | undefined>; bodyText: string };
      /** The request was held for the human's answer (`EgressHold`). */
      held?: HeldFor;
    }
  | {
      action: "block";
      reason: string;
      /** Symbols that were withheld (denied / unresolvable / arbiter miss). */
      withheld: WithheldSymbol[];
      /** The request was held for the human's answer (`EgressHold`). */
      held?: HeldFor;
    };

/** How long a held request waited, whether the card was answered, and the
 *  cards it waited on. */
export interface HeldFor {
  ms: number;
  answered: boolean;
  /** The Approvals cards the request was held for (the first gate's
   *  withheld symbols), each with the rule that filed it. The answer's own
   *  decision names only the human's verdict (`verdict:<id>`), so this is
   *  what tells, in the trace, which rule asked the human (egress-hold.md,
   *  "The trace"). Ids and rule ids only, never a value. */
  cards: HeldCard[];
}

/** One card a held request waited on. */
export interface HeldCard {
  approvalId: string;
  /** The arbiter rule that filed it (`egress:secret-unbound`, …). */
  rule?: string;
}

/** The cards a block waits on (its withheld symbols' rows), for HeldFor. */
function heldCardsOf(gate: GateResult): HeldCard[] {
  if (gate.action !== "block") return [];
  const out: HeldCard[] = [];
  for (const w of gate.withheld) {
    if (typeof w.approvalId !== "string" || w.approvalId === "" || out.some((c) => c.approvalId === w.approvalId)) continue;
    out.push({ approvalId: w.approvalId, ...(typeof w.ruleRef?.id === "string" ? { rule: w.ruleRef.id } : {}) });
  }
  return out;
}

/** The `heldFor` field of a held request's `net_action` event (forwarded or
 *  blocked): the cards it waited on, each with the rule that filed it.
 *  Undefined when the request was not held. */
export function heldForEvent(held: HeldFor | undefined): HeldCard[] | undefined {
  return held && held.cards.length > 0 ? held.cards.map((c) => ({ ...c })) : undefined;
}

/** ` [rule-a, rule-b]` — the distinct deciding rules, for the block reason. */
function withheldRuleSuffix(withheld: readonly WithheldSymbol[]): string {
  const ids = [...new Set(withheld.map((w) => w.ruleRef?.id).filter((id): id is string => typeof id === "string"))];
  return ids.length > 0 ? ` [${ids.join(", ")}]` : "";
}

/**
 * The `policy` block of a blocked request's `net_action` event, in the shape
 * the model-context net gate already emits (`{usage, reason, ruleRef}`): the
 * FIRST withheld symbol's own arbiter reason and rule, plus the approval-queue
 * id when a symbol was queued for the human. Absent when nothing was
 * withheld by a rule (arbiter unreachable, resolve failure).
 */
export function withheldPolicy(
  withheld: readonly WithheldSymbol[],
): { usage: "deny"; reason: string; ruleRef: RuleRef; approvalId?: string } | undefined {
  const first = withheld.find((w) => w.ruleRef);
  // The queue row the block filed (the first withheld symbol that asked),
  // the dashboard's join from an answer back to this moment (§4.25h).
  const asked = withheld.find((w) => w.approvalId)?.approvalId;
  return first?.ruleRef
    ? { usage: "deny", reason: first.reason, ruleRef: first.ruleRef, ...(asked ? { approvalId: asked } : {}) }
    : undefined;
}

/** Stringify a header value for symbol scanning. */
function headerText(v: string | string[] | undefined): string {
  if (v == null) return "";
  return Array.isArray(v) ? v.join("\n") : v;
}

// ── HTTP Basic credentials (plan 10 §11.13.1, 2026-10-03) ────────────────────
//
// npm (an `.npmrc` `_password`) and pip (a `pip.conf` index URL's user and
// password) read the twin and send the TOKEN inside HTTP Basic:
// `Authorization: Basic base64(user:token)`. A symbol there is invisible to a
// scan of the header's text, so the gate decodes the credential and gates a
// symbol inside it like one anywhere else in the request, at the
// `authorization` position: per destination (its bindings), resolved and
// re-encoded only when allowed; any other destination blocks the whole
// request (fail-closed).

/** `Basic <base64>` (the scheme in any case, then whitespace). */
const BASIC_RE = /^(\s*basic\s+)([A-Za-z0-9+/]+={0,2})(\s*)$/i;

/** The decoded `user:password` of an HTTP Basic header value, as latin1 (one
 *  char per byte, so re-encoding gives the same bytes), or null. Pure. */
export function basicCredential(value: string): { prefix: string; pair: string; suffix: string } | null {
  const m = BASIC_RE.exec(value);
  if (!m) return null;
  const buf = Buffer.from(m[2]!, "base64");
  if (buf.length === 0) return null;
  return { prefix: m[1]!, pair: buf.toString("latin1"), suffix: m[3]! };
}

/** The header names whose Basic credential is decoded: the request's own
 *  `Authorization` (never `Proxy-Authorization`, which is this proxy's). */
function isAuthorizationHeader(name: string): boolean {
  return name.toLowerCase() === "authorization";
}

/** Every Basic-decoded pair in the request's Authorization header(s). */
function basicPairs(headers: GateInput["headers"]): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (!isAuthorizationHeader(k) || v == null) continue;
    for (const one of Array.isArray(v) ? v : [v]) {
      const c = basicCredential(one);
      if (c) out.push(c.pair);
    }
  }
  return out;
}

/** One Authorization value with every resolved symbol inside its Basic pair
 *  substituted (the value's UTF-8 bytes, which npm and curl send) and the
 *  pair re-encoded; unchanged when it is not Basic or holds no symbol. */
function substituteInBasic(value: string, resolved: ReadonlyMap<string, string>): string {
  const c = basicCredential(value);
  if (!c || findSymbols(c.pair).length === 0) return value;
  const latin1 = new Map<string, string>();
  for (const [symbol, raw] of resolved) latin1.set(symbol, Buffer.from(raw, "utf8").toString("latin1"));
  const pair = substituteTokens(c.pair, latin1);
  return `${c.prefix}${Buffer.from(pair, "latin1").toString("base64")}${c.suffix}`;
}

/**
 * Every symbol in the request, in order of first appearance (URL, host,
 * body, headers, Basic pairs, as before), with EVERY position it sits in
 * (plan 10 §11.13.1, 2026-10-09): `url` (the URL or the destination host),
 * `body`, `authorization` (the request's `Authorization` header, its text or
 * the decoded pair of `Basic`; never `Proxy-Authorization`), `header` (any
 * other header). The arbiter puts a credential bound only by its own config
 * file or an auth grant back only when every position is `authorization`.
 * Pure.
 */
export function requestSymbolPositions(
  input: Pick<GateInput, "url" | "destinationHost" | "headers" | "bodyText">,
): Map<string, Set<RequestPosition>> {
  const out = new Map<string, Set<RequestPosition>>();
  const note = (text: string, position: RequestPosition): void => {
    for (const s of findSymbols(text)) {
      let at = out.get(s);
      if (!at) out.set(s, (at = new Set()));
      at.add(position);
    }
  };
  note(input.url, "url");
  note(input.destinationHost, "url");
  note(input.bodyText, "body");
  for (const [k, v] of Object.entries(input.headers)) note(headerText(v), isAuthorizationHeader(k) ? "authorization" : "header");
  for (const pair of basicPairs(input.headers)) note(pair, "authorization");
  return out;
}

/** A position set in the order the arbiter names them. */
const POSITION_ORDER: readonly RequestPosition[] = ["authorization", "url", "header", "body"];
function orderedPositions(at: ReadonlySet<RequestPosition>): RequestPosition[] {
  return POSITION_ORDER.filter((p) => at.has(p));
}

/**
 * EGRESS gate: decide whether an outbound request carrying untrusted symbols may
 * be sent, and if so with what (resolved) bytes.
 *
 * Ported from net-supervisor `egress_transform`:
 *   - NO symbols → `{action:"forward"}` (pass through unchanged).
 *   - For each symbol, call `desymbolizationDecision({symbol, boundary:"network",
 *     destination: destinationHost, asCommand:false, scheme, positions})`,
 *     `positions` being every place the symbol sits (`requestSymbolPositions`;
 *     plan 10 §11.13.1: a credential bound only by its own config file or an
 *     auth grant is refused anywhere but the Authorization header).
 *   - ALL allow → `resolve` each + substitute each whole token into a
 *     rewritten url/headers/body → `{action:"forward", rewritten}`.
 *   - ANY deny → `{action:"block", withheld}` (FAIL-CLOSED: the secret is NOT
 *     resolved, so it is NEVER exfiltrated; the whole request is dropped).
 *   - Arbiter throw (unreachable) → `{action:"block", reason:"arbiter unreachable"}`
 *     (FAIL-CLOSED).
 *
 * Note: unlike the Rust net-supervisor (which keeps allowed symbols flowing and only
 * withholds denied ones on the wire), a FORWARD proxy is request-atomic — we
 * cannot partially deliver an HTTP request. So ANY withheld symbol blocks the
 * ENTIRE request (strictly safer: no secret can leak).
 *
 * `hold` (confidentiality.md §4, "A held request"): a block that waits only
 * on the human's answer to a per-symbol card is held and asked again until
 * the card is answered or the hold's deadline passes (`holdForAnswer`).
 */
export async function gateRequest(input: GateInput, hold?: EgressHold): Promise<GateResult> {
  const refused = await gatePrelude(input);
  if (refused) return refused;
  // The answers this request has already got (an allow, a Send without it),
  // kept while it is held so a once is spent once (see holdForAnswer).
  const carried: CarriedAnswers = new Map();
  // One id for this request, on every ask it makes, held or not
  // (egress-hold.md "One card per file"): a human's once on the card of a
  // file is spent by the request, so it answers every placeholder of that
  // file in it, and the next request asks again.
  const requestId = randomUUID();
  const first = await gateSymbols(input, carried, requestId);
  if (!hold || !(hold.ms > 0) || !awaitsAnswer(first)) return first;
  return holdForAnswer(input, first, carried, hold, requestId);
}

/** The legs before the per-symbol gate: the (frozen) integrity taint gate,
 *  the secret-taint verdict of the sending processes, and a shell-emptied
 *  placeholder. A block, or null when the per-symbol gate decides. */
async function gatePrelude(input: GateInput): Promise<GateResult | null> {
  const arbiter = input.arbiter;

  // ── Taint-driven destination gate (Plan 3, spec §3.3): runs BEFORE the symbol
  //    gate / no-symbols fast-return. A tainted source process sending to an
  //    untrusted destination is blocked even with NO symbols (content-agnostic
  //    exfil gate). Only meaningful when the source proc is attributable. ──
  if (input.procKey !== undefined) {
    let tainted: boolean;
    try {
      const t = await arbiter.isProcessTainted(input.procKey);
      tainted = t.tainted;
    } catch (err) {
      // Fail-closed: unknown provenance → assume tainted, gate the destination.
      void err;
      tainted = true;
    }
    if (tainted) {
      let destUntrusted: boolean;
      try {
        const c = await arbiter.classify({
          tool: "net_egress",
          value: input.destinationHost,
          boundary: NETWORK_BOUNDARY,
          origin: input.destinationHost,
        });
        destUntrusted = c.trust === "UNTRUSTED";
      } catch (err) {
        // Fail-closed: cannot classify the destination → treat as untrusted.
        void err;
        destUntrusted = true;
      }
      if (destUntrusted) {
        return {
          action: "block",
          reason: `tainted process → untrusted destination ${input.destinationHost} → approval required (content-agnostic taint gate)`,
          withheld: [
            {
              symbol: `<taint:${input.procKey}→${input.destinationHost}>`,
              requiresApproval: true,
              reason: "tainted-source egress to untrusted destination (no symbols required)",
            },
          ],
        };
      }
    }
  }

  // ── Plan 10 §4.3, the network exit of a SECRET-tainted process (a reader,
  //    or a descendant of one): the destination must be one of the bindings
  //    of the secrets it holds; anything else needs the human. Content-agnostic
  //    like the integrity gate above: the value may be in the request in any
  //    encoding, or not at all. Unreachable ⇒ block (fail-closed). Plan 13
  //    D6: every holder of the connection is judged, and an unattributed
  //    connection is refused while the session holds a secret. ──
  const holders = input.holders ?? (input.procKey !== undefined ? [{ procKey: input.procKey, ancestors: [] }] : undefined);
  if (holders !== undefined) {
    const v = await secretTaintVerdict({ arbiter, holders, destinationHost: input.destinationHost, sessionKey: input.sessionKey });
    if (v.action === "block") return v;
  }

  // A secret's placeholder a shell emptied (`:nomodel_…[h]`): refused with
  // how to quote it, never filled in (confidentiality.md §7). Before the
  // per-symbol gate: the request is refused whole whatever else it carries.
  const expanded = await shellExpandedRefusal(input);
  if (expanded) return expanded;
  return null;
}

/**
 * The per-symbol gate (the body of `gateRequest`, header above). `carried`
 * holds the answers an earlier pass over THIS request got (a held request's
 * re-asks, `holdForAnswer`): a symbol in it is not asked again. Only an
 * allow (with its resolved value) and a Send without it are carried; a
 * denial ends the request and a pending ask is asked again.
 */
async function gateSymbols(input: GateInput, carried: CarriedAnswers, requestId: string): Promise<GateResult> {
  const arbiter = input.arbiter;
  const symbols = requestSymbolPositions(input);
  // A model service (GateInput.modelService): the placeholders outside the
  // Authorization header go as they are, so only the header's are judged.
  const keptOpaque: string[] = [];
  if (input.modelService === true) {
    for (const [symbol, at] of [...symbols]) {
      if (at.has("authorization")) continue;
      keptOpaque.push(symbol);
      symbols.delete(symbol);
    }
  }
  if (symbols.size === 0) {
    return keptOpaque.length > 0 ? { action: "forward", keptOpaque } : { action: "forward" };
  }
  const withheld: WithheldSymbol[] = [];
  const resolvedValues = new Map<string, string>();
  const requestSymbols = [...symbols.keys()].slice(0, REQUEST_SYMBOLS_SENT_MAX);
  // "Send without it": never resolved; the marker goes in their place.
  const sentWithout: string[] = [];

  for (const [symbol, at] of symbols) {
    const kept = carried.get(symbol);
    if (kept?.kind === "strip") {
      sentWithout.push(symbol);
      continue;
    }
    if (kept?.kind === "allow") {
      resolvedValues.set(symbol, kept.value);
      continue;
    }
    let decision;
    try {
      decision = await arbiter.desymbolizationDecision({
        symbol,
        boundary: NETWORK_BOUNDARY,
        destination: input.destinationHost,
        asCommand: false,
        ...(input.sessionKey !== undefined ? { sessionKey: input.sessionKey } : {}),
        ...(input.scheme !== undefined ? { scheme: input.scheme } : {}),
        // Every place it sits: the allow below covers exactly these, and the
        // substitution puts the value back only in whole tokens found there.
        positions: orderedPositions(at),
        // egress-hold.md "One card per file": the request's id, and every
        // placeholder it carries (a file's several placeholders ask on the
        // file's one card).
        requestId,
        requestSymbols,
      });
    } catch (err) {
      // Arbiter unreachable → fail-closed block (never resolve / leak).
      return {
        action: "block",
        reason: `arbiter unreachable: ${(err as Error).message} → block (fail-closed)`,
        withheld: [
          {
            symbol,
            requiresApproval: true,
            reason: "gate unreachable → withhold (fail-closed)",
          },
        ],
      };
    }

    if (decision.strip === true) {
      // "Send without it" (confidentiality.md §4): the human's one-shot
      // answer, spent by this ask. NEVER resolved, whatever `allow` says:
      // the marker goes in its place below.
      sentWithout.push(symbol);
      carried.set(symbol, { kind: "strip" });
    } else if (decision.allow) {
      // Allowed → resolve. If resolve fails / returns null, withhold (fail-closed).
      let value: string | null;
      try {
        value = await arbiter.resolve(symbol);
      } catch (err) {
        withheld.push({
          symbol,
          requiresApproval: true,
          reason: `resolve failed after allow: ${(err as Error).message} → withhold (fail-closed)`,
        });
        continue;
      }
      if (value == null) {
        // Unknown to the table → nothing to leak; leave the literal in place.
        // (Mirrors the arbiter's "unknown symbol → no-op" allow.) Not withheld.
        resolvedValues.set(symbol, symbol);
      } else {
        resolvedValues.set(symbol, value);
      }
      carried.set(symbol, { kind: "allow", value: resolvedValues.get(symbol)! });
    } else {
      withheld.push({
        symbol,
        requiresApproval: decision.requiresApproval,
        reason: decision.reason,
        ...(decision.ruleRef ? { ruleRef: decision.ruleRef } : {}),
        ...(decision.approvalId ? { approvalId: decision.approvalId } : {}),
      });
    }
  }

  if (withheld.length > 0) {
    // FAIL-CLOSED: any denied/unresolvable symbol drops the whole request.
    return {
      action: "block",
      reason: `egress withheld ${withheld.length} symbol(s) → block (fail-closed)${withheldRuleSuffix(withheld)}`,
      withheld,
    };
  }

  // All symbols allowed → substitute resolved values into a rewritten request,
  // each whole token where it was found and judged (`substituteTokens`).
  if (sentWithout.length === 0) {
    return {
      action: "forward",
      rewritten: substituteRequest(input, { url: resolvedValues, body: resolvedValues, header: resolvedValues }),
      resolved: [...resolvedValues.keys()],
      ...(keptOpaque.length > 0 ? { keptOpaque } : {}),
    };
  }

  // "Send without it" (confidentiality.md §4). A symbol in the destination
  // host itself has no place a marker could go: refused (fail-closed).
  const without = (reason: string): GateResult => ({
    action: "block",
    reason: `${reason} → block (fail-closed)`,
    withheld: sentWithout.map((symbol) => ({ symbol, requiresApproval: false, reason })),
  });
  if (sentWithout.some((sym) => input.destinationHost.includes(sym))) {
    return without("a placeholder you chose to send without sits in the destination host, where no marker can go");
  }
  const plain = new Map(sentWithout.map((sym) => [sym, SEND_WITHOUT_MARKER] as const));
  const encoded = new Map(sentWithout.map((sym) => [sym, SEND_WITHOUT_MARKER_ENCODED] as const));
  const bodyMarks = isFormBody(input.headers) ? encoded : plain;
  const merge = (marks: ReadonlyMap<string, string>): Map<string, string> => new Map([...resolvedValues, ...marks]);
  const rewritten = substituteRequest(input, { url: merge(encoded), body: merge(bodyMarks), header: merge(plain) });
  const sentWithoutView = substituteRequest(input, { url: encoded, body: bodyMarks, header: plain });
  // Self-check: no token of a symbol sent without is left anywhere the gate
  // reads (URL, body, headers, Basic pairs). Fail-closed.
  for (const view of [rewritten, sentWithoutView]) {
    const left = requestSymbolPositions({ ...view, destinationHost: input.destinationHost });
    if (sentWithout.some((sym) => left.has(sym))) return without("a placeholder you chose to send without was still in the request after it was replaced");
  }
  return {
    action: "forward",
    rewritten,
    resolved: [...resolvedValues.keys()],
    sentWithout,
    sentWithoutView,
  };
}

// ── A held request (confidentiality.md §4, "A held request", 2026-10-17) ─────
//
// With a hold configured (`MANDU_EGRESS_HOLD_MS`, default 0 = off), a request
// whose only obstacle is a card the human has not answered yet (every
// withheld symbol a `$MDU:` placeholder the arbiter filed a pending row for)
// is not refused at once: the proxy keeps the client waiting and asks again
// until the card is answered or the hold's deadline passes. The answer then
// decides THIS request, through the same per-symbol gate: Allow once /
// Always allow resolve, Send without it puts the marker in the symbol's
// place (and the strict value scan runs over it, proxy.ts / mitm.ts), Block
// refuses. Nothing is released by holding: every outcome is one the same
// request, sent again after the answer, would get today. Fail-closed:
//   - the deadline passes → refused (403) as before, the card left waiting
//     (an answer given later decides the next try);
//   - the arbiter unreachable during the hold → the re-ask throws → refused;
//   - any other block (a denial, a program holding a secret, an
//     unattributed connection, a symbol in the host) is never held;
//   - the client gone during the hold → refused, nothing sent.
// `awaitingApprovals` (a read of the queue) only paces the re-asks, so the
// row's count is not bumped by every poll; the decision is always the
// re-ask's. Without it the hold re-asks on every poll.

/** How long a request may be held, at most, whatever is configured (ms). */
export const EGRESS_HOLD_MAX_MS = 300_000;
/** How many of a request's placeholders ride on each ask as
 *  `requestSymbols` (the arbiter reads at most as many). */
export const REQUEST_SYMBOLS_SENT_MAX = 512;
/** Between two looks at the queue while held (ms). */
export const EGRESS_HOLD_POLL_MS = 500;
/** The marker a held request's refusal carries when nobody answered. */
export const EGRESS_HELD_TIMEOUT = "egress:held-unanswered";

/** How the per-symbol gate waits for the human's answer (see above). */
export interface EgressHold {
  /** The longest one request is held (ms; capped by EGRESS_HOLD_MAX_MS).
   *  0 or less: no hold. */
  ms: number;
  /** Between two looks (ms; default EGRESS_HOLD_POLL_MS). */
  pollMs?: number;
  /** The client went away: stop holding, send nothing. */
  aborted?: () => boolean;
  log?: (msg: string) => void;
  /** Seams for tests. */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

/** The hold's length from its setting (`MANDU_EGRESS_HOLD_MS`): a whole
 *  number of ms, capped; anything else (absent, empty, negative, not a
 *  number) is 0, no hold. Pure. */
export function egressHoldMs(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return 0;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Math.floor(n), EGRESS_HOLD_MAX_MS);
}

/** An answer a request already got, kept across its hold's re-asks. */
type CarriedAnswers = Map<string, { kind: "allow"; value: string } | { kind: "strip" }>;

/**
 * Does this block wait only on the human? True when every withheld symbol
 * is a whole `$MDU:` placeholder with a pending card (`requiresApproval`
 * and the row's id): the per-symbol cards, Send without it's among them.
 * A denial (`requiresApproval: false`), a failed resolve or an arbiter
 * miss (no row), and every content-agnostic block (`<secret-taint:…>`,
 * `<taint:…>`) are final. Pure.
 */
export function awaitsAnswer(gate: GateResult): boolean {
  if (gate.action !== "block" || gate.withheld.length === 0) return false;
  return gate.withheld.every((w) =>
    w.requiresApproval === true &&
    typeof w.approvalId === "string" && w.approvalId !== "" &&
    findSymbols(w.symbol).length === 1 && findSymbols(w.symbol)[0] === w.symbol);
}

async function holdForAnswer(input: GateInput, first: GateResult, carried: CarriedAnswers, hold: EgressHold, requestId: string): Promise<GateResult> {
  const now = hold.now ?? (() => Date.now());
  const sleep = hold.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const pollMs = Math.max(10, hold.pollMs ?? EGRESS_HOLD_POLL_MS);
  const started = now();
  const deadline = started + Math.min(hold.ms, EGRESS_HOLD_MAX_MS);
  const cards = heldCardsOf(first);
  // One card may stand for several placeholders (the arbiter files a file's
  // placeholders under one card): each id once.
  const ids = (g: GateResult): string[] => (g.action === "block" ? [...new Set(g.withheld.map((w) => w.approvalId!).filter(Boolean))] : []);
  hold.log?.(`HELD ${input.method} ${input.destinationHost} for the human's answer (${ids(first).join(", ")}; up to ${Math.round((deadline - started) / 1000)} s)`);
  let gate = first;
  while (awaitsAnswer(gate) && now() < deadline) {
    await sleep(Math.min(pollMs, Math.max(0, deadline - now())));
    if (hold.aborted?.()) break;
    // Only a card no longer waiting is worth an ask (the ask is what
    // decides; a failed look just asks).
    if (input.arbiter.awaitingApprovals) {
      try {
        const waiting = await input.arbiter.awaitingApprovals(ids(gate));
        if (ids(gate).every((id) => waiting.has(id))) continue;
      } catch { /* ask below */ }
    }
    gate = await gateSymbols(input, carried, requestId);
  }
  const heldMs = Math.max(0, now() - started);
  if (hold.aborted?.()) {
    // Nothing is sent to a client that is gone (an answer spent by this
    // request is lost, as for any refused request).
    return {
      action: "block",
      reason: "the client went away while the request was held for the human's answer → nothing sent (fail-closed)",
      withheld: gate.action === "block" ? gate.withheld : [],
      held: { ms: heldMs, answered: !awaitsAnswer(gate), cards },
    };
  }
  if (awaitsAnswer(gate) && gate.action === "block") {
    hold.log?.(`HELD ${input.method} ${input.destinationHost}: nobody answered in ${Math.round(heldMs / 1000)} s → block`);
    return {
      ...gate,
      reason: `${gate.reason}; held ${Math.round(heldMs / 1000)} s for an answer on Mandu's Approvals page and nobody answered; the question is still waiting there, so answer it, then send the request again (${EGRESS_HELD_TIMEOUT})`,
      held: { ms: heldMs, answered: false, cards },
    };
  }
  hold.log?.(`HELD ${input.method} ${input.destinationHost}: answered after ${Math.round(heldMs / 1000)} s → ${gate.action}`);
  return { ...gate, held: { ms: heldMs, answered: true, cards } };
}

// ── The secret-taint verdict for one connection (plan 10 §4.3, plan 13 D6) ────

/** The markers a held command's refusal carries in its reason
 *  (`refusalKindOf`): the user was asked, or had blocked the host. */
export const HELD_SESSION_ASKED = "egress:held-session-asked";
export const HELD_SESSION_BLOCKED = "egress:held-session-blocked";

/** The verdict of `secretTaintVerdict`: `tainted` says whether some holder
 *  holds a secret (every one of them admitted at this destination). */
export type SecretTaintVerdict =
  | { action: "allow"; tainted: boolean }
  | { action: "block"; reason: string; withheld: WithheldSymbol[] };

/** The key a human's answer to a holder's send is granted under for one
 *  connection (`secretTaintVerdict`'s `granted`): the set of files held. */
export function holderFilesKey(files: readonly string[]): string {
  return JSON.stringify([...new Set(files)].sort());
}

/**
 * May the processes holding a proxied connection send to `destinationHost`?
 * The ONE check every leg of the proxy runs (plain HTTP per request, the
 * TLS-inspected leg per decrypted request, a blind CONNECT at the tunnel and
 * again before each chunk it carries):
 *
 *   - each holder (its own taint and its ancestors') that holds a secret must
 *     find the destination among its secrets' bindings; one that does not →
 *     block (approval required);
 *   - the arbiter cannot answer for a holder → block (fail-closed: unknown
 *     provenance is treated as holding a secret bound nowhere);
 *   - NO holder (the connection could not be attributed): blocked while any
 *     process of the session holds a secret, since the sender may be that
 *     process; the session question unanswerable → block. An arbiter with no
 *     process secret taint at all (predating plan 10) → allow, as before.
 *
 * Plan 13 §5.4 (2026-10-11): a holder the destination is not bound for is
 * asked about once more, naming the destination, so the arbiter consults the
 * human's answer for {session, the files it holds} × destination (*Allow
 * once* is spent by this ask, *Allow this session* stands) or files the
 * question that names every file, whose id rides on the block. `granted`
 * (one connection's, a blind tunnel's) remembers the file sets an answer let
 * through at the CONNECT, so the tunnel's later chunks are not asked again
 * for them (a once is spent by the CONNECT, which is one send); a holder
 * holding more than an answered set is a new question.
 */
export async function secretTaintVerdict(args: {
  arbiter: Arbiter;
  holders: readonly ProcHolder[];
  destinationHost: string;
  sessionKey?: string;
  granted?: Set<string>;
}): Promise<SecretTaintVerdict> {
  const { arbiter, holders, destinationHost } = args;
  if (!arbiter.taintedProcessBindings) return { action: "allow", tainted: false };
  const session = args.sessionKey !== undefined ? { session: args.sessionKey } : {};
  if (holders.length === 0) {
    let st: SessionSecretTaint;
    try {
      if (!arbiter.sessionSecretTaint) throw new Error("the arbiter has no sessionSecretTaint op");
      st = await arbiter.sessionSecretTaint(session);
    } catch (err) {
      void err;
      st = { tainted: true, level: "no-model", files: [] };
    }
    if (!st.tainted) return { action: "allow", tainted: false };
    const files = st.files.map((f) => f.split("/").pop()).join(", ") || "a secret";
    return {
      action: "block",
      reason: `the connection to ${destinationHost} could not be attributed to a process, and a process of this session holds a secret (${files}) → approval required (plan 13 D6, fail-closed)`,
      withheld: [
        {
          symbol: `<secret-taint:unattributed→${destinationHost}>`,
          requiresApproval: true,
          reason: `egress:tainted-process-unattributed: the sender is unknown and the session holds ${st.files.join(", ") || "a secret"}`,
        },
      ],
    };
  }
  let tainted = false;
  for (const h of holders) {
    let st: TaintedProcessBindings;
    try {
      st = await arbiter.taintedProcessBindings({
        procKey: h.procKey,
        ...(h.ancestors.length > 0 ? { ancestors: [...h.ancestors] } : {}),
        ...session,
      });
    } catch (err) {
      void err;
      st = { tainted: true, level: "no-model", files: [], bindings: [] };
    }
    if (!st.tainted) continue;
    tainted = true;
    if (hostIsBound(destinationHost, st.bindings)) continue;
    if (args.granted?.has(holderFilesKey(st.files))) continue;
    // Plan 13 §5.4: the human's answer, or the question that names every
    // file. Unanswerable ⇒ no answer (the block below stands).
    let asked: TaintedProcessBindings | null = null;
    try {
      asked = await arbiter.taintedProcessBindings({ procKey: h.procKey, ...(h.ancestors.length > 0 ? { ancestors: [...h.ancestors] } : {}), ...session, destination: destinationHost });
    } catch (err) {
      void err;
    }
    const ask = asked?.tainted ? asked.ask : undefined;
    if (ask?.status === "approved") {
      args.granted?.add(holderFilesKey(asked!.files));
      continue;
    }
    // confidentiality.md §4, "A held command's refused connection"
    // (2026-10-12): a HIGH session's command, held by what the session read.
    // The arbiter asked the session's own question; the reason (the 403 the
    // program prints) says the user was asked and the command may run again
    // after they answer, or that the user blocked it.
    if (ask?.question === "session") {
      const denied = ask.status === "denied";
      return {
        action: "block",
        reason: denied
          ? `a command of this session holds what the session read; the user blocked this session's requests to ${destinationHost}, do not retry (${HELD_SESSION_BLOCKED})`
          : `a command of this session holds what the session read, and ${destinationHost} is not a place it may go: Mandu stopped the request and asked the user on its Approvals page; run the command again after they allow it once (${HELD_SESSION_ASKED})`,
        withheld: [
          {
            symbol: `<secret-taint:${h.procKey}→${destinationHost}>`,
            requiresApproval: !denied,
            reason: `${denied ? HELD_SESSION_BLOCKED : HELD_SESSION_ASKED}: what this session read may leave only to ${st.bindings.join(", ") || "no host"}`,
            approvalId: ask.approvalId,
          },
        ],
      };
    }
    return {
      action: "block",
      reason: `secret-tainted process (read ${st.files.map((f) => f.split("/").pop()).join(", ") || "a secret"}) → ${destinationHost} is not a bound host → ${ask?.status === "denied" ? "blocked by your answer" : "approval required"} (plan 10 §4.3)`,
      withheld: [
        {
          symbol: `<secret-taint:${h.procKey}→${destinationHost}>`,
          requiresApproval: ask?.status !== "denied",
          reason: `egress:tainted-process-unbound: ${st.files.join(", ") || "a secret"} may leave only to ${st.bindings.join(", ") || "no host"}`,
          ...(ask ? { approvalId: ask.approvalId } : {}),
        },
      ],
    };
  }
  return { action: "allow", tainted };
}

// ── INGRESS response observe-and-tag ─────────────────────────────────────────

/** A short deterministic tag from a string (FNV-1a, hex). Used only for stable
 * opaque markers; not security-sensitive. Ported from net-supervisor `stable_tag`. */
function stableTag(s: string): string {
  let h = 0xcbf29ce484222325n;
  const mask = 0xffffffffffffffffn;
  for (const b of Buffer.from(s, "utf8")) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & mask;
  }
  return (h & 0xffffffffn).toString(16).padStart(8, "0");
}

/** Result of observing/tagging a response body. */
export interface ResponseSymbolResult {
  /** What the agent sees (raw body for both trusted and untrusted; opaque marker on arbiter miss). */
  agentVisible: string;
  trust: "TRUSTED" | "UNTRUSTED";
  /**
   * Post-Plan-7: net ingress allocates NO symbol for untrusted bodies — always undefined.
   * Kept on the struct for event-shape stability; may be set by callers that do symbolize
   * (e.g. future code paths) but this function never sets it.
   */
  symbol?: string;
  reason: string;
  /** True iff the arbiter was unreachable → opaque fail-closed marker served. */
  arbiterMiss: boolean;
}

/**
 * INGRESS (spec §2.1, post-Plan-7): classify a (plaintext) response body from
 * `origin` and observe-and-tag the connecting process. Renamed from `symbolizeResponse`.
 *
 * FLIP (Plan 7): net ingress NO LONGER symbolizes untrusted bodies. The agent now
 * sees the RAW body; the T-LLM invariant is enforced SOLELY at the model-API proxy.
 * We KEEP the observe-and-tag: when the host is UNTRUSTED and an (optional) `procKey`
 * is provided, best-effort `taintProcess` the connecting process so a later file
 * write / outbound send is recognized as untrusted-by-origin (the at-rest/exfil
 * backstop, spec §1.1).
 *
 * FAIL-CLOSED on arbiter MISS is UNCHANGED: a classify error still substitutes the
 * synthetic opaque marker via `failClosedIngress` (never raw on a arbiter miss).
 * This is the deliberate distinction: a *successful* UNTRUSTED classify now serves
 * RAW (the flip); a *arbiter-unreachable* classify still serves the opaque marker.
 *
 * (Applies to plaintext HTTP responses only — HTTPS/CONNECT bodies are opaque to a
 * non-MITM proxy; see proxy.ts. MITM path calls through the same function.)
 */
export async function observeResponse(
  bodyBuf: Buffer,
  opts: { arbiter: Arbiter; origin: string; tool?: string; procKey?: string },
): Promise<{ body: Buffer; meta: ResponseSymbolResult }> {
  const body = bodyBuf.toString("utf8");
  const tool = opts.tool ?? "web_fetch";

  let classify;
  try {
    classify = await opts.arbiter.classify({
      tool,
      value: body,
      boundary: NETWORK_BOUNDARY,
      origin: opts.origin,
    });
  } catch (err) {
    return failClosedIngress(bodyBuf, opts.origin, (err as Error).message);
  }

  if (classify.trust === "TRUSTED") {
    return {
      body: bodyBuf,
      meta: {
        agentVisible: body,
        trust: "TRUSTED",
        reason: classify.reason,
        arbiterMiss: false,
      },
    };
  }

  // ── FLIP (Plan 7): net ingress NO LONGER symbolizes untrusted bodies. Return the
  //    RAW body; the T-LLM invariant is enforced at the model proxy. KEEP the
  //    observe-and-tag: best-effort taint the connecting process when attributable. ──
  if (opts.procKey !== undefined) {
    try {
      await opts.arbiter.taintProcess({ procKey: opts.procKey, originHost: opts.origin });
    } catch {
      // swallow — best-effort; the model proxy backstops T-LLM regardless.
    }
  }

  return {
    body: bodyBuf, // RAW (was Buffer.from(symbol) pre-Plan-7)
    meta: {
      agentVisible: body, // the decoded raw string
      trust: "UNTRUSTED",
      // no `symbol` — net ingress allocates none post-flip
      reason: classify.reason,
      arbiterMiss: false,
    },
  };
}

/**
 * @deprecated Use `observeResponse` (Plan 7 rename). This alias is kept temporarily
 * so any import that predates the rename continues to compile — remove after all
 * callers have been updated.
 */
export const symbolizeResponse = observeResponse;

/** Arbiter miss on ingress: serve an opaque marker, NEVER the raw untrusted body. */
function failClosedIngress(
  bodyBuf: Buffer,
  origin: string,
  err: string,
): { body: Buffer; meta: ResponseSymbolResult } {
  const marker = `$MDU_OPAQUE_INGRESS[${stableTag(origin)}]`;
  return {
    body: Buffer.from(marker, "utf8"),
    meta: {
      agentVisible: marker,
      trust: "UNTRUSTED",
      reason: `arbiter unreachable (${err}) → fail-closed opaque ingress (no raw bytes to agent)`,
      arbiterMiss: true,
    },
  };
}

// ── Model-host exclusion ─────────────────────────────────────────────────────

/** Hosts whose traffic this proxy must NOT touch (the model-API proxies own
 * them). Suffix-matched so subdomains count. Ported from net-supervisor
 * MODEL_HOST_SUFFIXES. */
export const MODEL_HOST_SUFFIXES = ["api.anthropic.com", "api.openai.com"] as const;

/**
 * True iff `host` is a model-API host this proxy must exclude. Extra hosts (e.g.
 * a local inference server) can be passed in `extra`. Strips a `:port` suffix and
 * matches case-insensitively. Ported from net-supervisor `is_model_host`.
 */
export function isModelHost(host: string, extra: readonly string[] = []): boolean {
  const h = host.trim().toLowerCase().split(":")[0] ?? "";
  const match = (suffix: string): boolean => {
    const s = suffix.toLowerCase();
    return h === s || h.endsWith(`.${s}`);
  };
  return MODEL_HOST_SUFFIXES.some(match) || extra.some(match);
}

/** Plan 10 §4.3: does `host` (optionally `host:port`) fall under one of the
 *  bindings? The one binding rule (host-bindings.ts, the arbiter's to the
 *  character): a bare host admits itself and every host under it, `*.suffix`
 *  every host under the suffix but not the suffix itself, `host:port` only
 *  that port. IP/CIDR bindings are the guard's concern (it sees addresses);
 *  here a literal IP binding matches only itself, a CIDR nothing. */
export function hostIsBound(destination: string, bindings: readonly string[]): boolean {
  return destinationMatchesBindings(destination, bindings);
}

