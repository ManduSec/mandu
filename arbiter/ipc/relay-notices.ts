/**
 * relay-notices — the DevTools relay's refusals, kept until the browser
 * agent's next model call (docs/design/agents/devtools-relay.md §3.4).
 * Mandu-new (no reference origin).
 *
 * WHY. When the relay refuses a placeholder the agent typed (a hash the
 * model made up, a site the secret is not bound to, the gate down), it
 * answers the DevTools command with an error. Some agents never show that
 * error to their model: browser-use swallows a command's error, and its
 * key-by-key typing puts the refusal on the next input command, whose error
 * it swallows too. Live (2026-10-19, the expense-report demo) the model saw
 * an empty field, typed the same made-up placeholder again, and submitted
 * without the card. So the relay also reports each refusal here
 * (`relayNotice`), and the egress proxy, on the agent's next Chat
 * Completions call to its model service, takes the session's pending ones
 * (`takeRelayNotices`) and appends them as one message the model reads
 * (interceptors/net-proxy/src/relay-notice.ts). Taking clears: each is told
 * once.
 *
 * WHAT A NOTICE CARRIES. Structured fields only, each checked here: a kind
 * and a cause from fixed lists, the page's host, and placeholder NAMES
 * (`$MDU:kind[hash].NAME`). Never free text, never a value: the proxy builds
 * the sentence from these, so whoever reports one (the relay, or any client
 * of the data socket) can make the model read only what Mandu's own
 * refusals say. A malformed notice is refused whole. A placeholder
 * LOOKALIKE the agent typed (the placeholder's shape with a code no
 * placeholder has, such as a UUID) is the kind `malformed` and names no
 * placeholder of its own: its code is free text, so it is never quoted.
 *
 * WHERE. In the arbiter's memory (the hub both clients reach, keyed by the
 * session key both are started with: the launch's scope id). Not persisted:
 * a notice is for the very next model call, and an arbiter restart losing
 * one costs only a hint. Bounded: RELAY_NOTICES_PER_SESSION per session (the
 * oldest dropped first; a repeat of a pending notice replaces it),
 * RELAY_NOTICE_SESSIONS sessions (the least recently reported dropped
 * first), and a notice older than RELAY_NOTICE_TTL_MS is never told.
 */
import { WHY_SYMBOL_RE } from "../prompt-filter/why-symbol.js";

/** What the relay refused, in Mandu's words (relay-notice.ts renders them). */
export const RELAY_NOTICE_KINDS = ["unknown", "malformed", "not-allowed", "needs-approval", "declined", "failed"] as const;
export type RelayNoticeKind = (typeof RELAY_NOTICE_KINDS)[number];

/** Why a `failed` refusal happened. */
export const RELAY_NOTICE_CAUSES = ["no-field", "page-moved", "frame", "no-page", "page-refused", "unavailable"] as const;
export type RelayNoticeCause = (typeof RELAY_NOTICE_CAUSES)[number];

/** One refusal, on the wire (protocol.ts `RelayNoticeOpRequest`). */
export interface RelayNoticeWire {
  kind: RelayNoticeKind;
  /** The page's host, as Chrome named its main frame (absent: no page). */
  page?: string;
  /** The placeholders the refusal is about (unknown: the ones that name
   *  nothing; malformed: none, always empty; otherwise the one the gate
   *  refused). */
  symbols: string[];
  /** unknown, malformed: the nearest placeholders the pages showed the
   *  agent. */
  shown?: string[];
  /** failed: why. */
  cause?: RelayNoticeCause;
}

/** Pending notices per session. */
export const RELAY_NOTICES_PER_SESSION = 8;
/** Sessions with pending notices. */
export const RELAY_NOTICE_SESSIONS = 64;
/** A notice older than this is dropped untold. */
export const RELAY_NOTICE_TTL_MS = 10 * 60_000;
/** Names per notice. */
export const RELAY_NOTICE_MAX_SYMBOLS = 8;
/** A host as Chrome names one: letters, digits, dots, dashes; an IPv6
 *  literal in brackets. */
const HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])$/;

/** The notice, checked field by field, or why it is refused. Pure. */
export function parseRelayNotice(x: unknown): RelayNoticeWire | string {
  if (typeof x !== "object" || x === null || Array.isArray(x)) return "notice must be an object";
  const o = x as Record<string, unknown>;
  const kind = o["kind"];
  if (typeof kind !== "string" || !(RELAY_NOTICE_KINDS as readonly string[]).includes(kind)) return `kind must be one of ${RELAY_NOTICE_KINDS.join(", ")}`;
  const names = (v: unknown, what: string, min: number): string[] | string => {
    if (!Array.isArray(v) || v.length < min || v.length > RELAY_NOTICE_MAX_SYMBOLS) return `${what} must be ${min}-${RELAY_NOTICE_MAX_SYMBOLS} placeholders`;
    for (const s of v) if (typeof s !== "string" || !WHY_SYMBOL_RE.test(s)) return `${what} must be placeholder names only`;
    return [...new Set(v as string[])];
  };
  // A lookalike's notice quotes nothing the agent typed (its code is free
  // text): it names no placeholder of its own.
  if (kind === "malformed" && o["symbols"] !== undefined && !(Array.isArray(o["symbols"]) && o["symbols"].length === 0)) return "a malformed notice names no placeholder";
  const symbols = kind === "malformed" ? [] : names(o["symbols"], "symbols", 1);
  if (typeof symbols === "string") return symbols;
  const out: RelayNoticeWire = { kind: kind as RelayNoticeKind, symbols };
  if (o["page"] !== undefined) {
    if (typeof o["page"] !== "string" || !HOST_RE.test(o["page"])) return "page must be a host name";
    out.page = o["page"].toLowerCase();
  }
  if (o["shown"] !== undefined) {
    if (kind !== "unknown" && kind !== "malformed") return "shown is for an unknown placeholder or a lookalike only";
    const shown = names(o["shown"], "shown", 0);
    if (typeof shown === "string") return shown;
    if (shown.length > 0) out.shown = shown;
  }
  if (o["cause"] !== undefined || kind === "failed") {
    const cause = o["cause"];
    if (kind !== "failed") return "cause is for a failed refusal only";
    if (typeof cause !== "string" || !(RELAY_NOTICE_CAUSES as readonly string[]).includes(cause)) return `cause must be one of ${RELAY_NOTICE_CAUSES.join(", ")}`;
    out.cause = cause as RelayNoticeCause;
  }
  return out;
}

function sameNotice(a: RelayNoticeWire, b: RelayNoticeWire): boolean {
  return a.kind === b.kind && a.page === b.page && a.cause === b.cause && a.symbols.join(" ") === b.symbols.join(" ");
}

/** The pending notices of every session (one per arbiter, in memory). */
export class RelayNoticeQueue {
  /** Insertion order is recency of the last report. */
  private readonly bySession = new Map<string, Array<{ notice: RelayNoticeWire; at: number }>>();

  /** Keep a checked notice for `session` until it is taken. */
  add(session: string, notice: RelayNoticeWire, now: number = Date.now()): void {
    const list = (this.bySession.get(session) ?? []).filter((p) => !sameNotice(p.notice, notice) && now - p.at <= RELAY_NOTICE_TTL_MS);
    list.push({ notice, at: now });
    while (list.length > RELAY_NOTICES_PER_SESSION) list.shift();
    this.bySession.delete(session);
    this.bySession.set(session, list);
    while (this.bySession.size > RELAY_NOTICE_SESSIONS) this.bySession.delete(this.bySession.keys().next().value!);
  }

  /** The session's pending notices, oldest first, and none left after. */
  take(session: string, now: number = Date.now()): RelayNoticeWire[] {
    const list = this.bySession.get(session);
    if (list === undefined) return [];
    this.bySession.delete(session);
    return list.filter((p) => now - p.at <= RELAY_NOTICE_TTL_MS).map((p) => p.notice);
  }

  /** How many sessions hold notices (tests). */
  get sessions(): number {
    return this.bySession.size;
  }
}
