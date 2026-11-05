/**
 * view-model/browser-story — "On web pages", the session page's account of a
 * browser agent run through Mandu's DevTools relay (dashboard.md §4.25af;
 * docs/design/agents/devtools-relay.md §5.1).
 *
 * Built from the relay's `browser_action` events (what it masked in what
 * Chrome sent the agent, what the agent typed and where, which commands it
 * stopped) and the egress proxy's `net_action` events to the model services
 * the agent called itself (`keptOpaque`: the secrets that left masked).
 * Pure. Names only: a secret is its short name (the field of its
 * placeholder, `STRIPE_SECRET_KEY`), never a value and never a placeholder.
 */
import type { ManduEvent } from "../event-model.js";
import { secretShortName } from "./secret-story.js";

export interface BrowserTyped {
  /** The secret's short name ("a secret" when it has none; for `unknown`,
   *  UNKNOWN_SECRET: a placeholder that names nothing names no secret). */
  secret: string;
  /** The page's host, when the relay names it: a filled value's page, or a
   *  refusal's host read from its reason (`not-allowed`, `needs-approval`). */
  site: string | null;
  /** `unknown`: the agent typed a placeholder the arbiter does not know (a
   *  mistyped or made-up one); nothing was typed and the agent was told
   *  (devtools-relay.md §3.2, the relay's reason `unknown placeholder`). */
  outcome: "filled" | "refused" | "unknown";
  /** A refusal's cause (`refusalCause`), null for a filled or unknown one
   *  and for a reason the page does not know (an older relay's). */
  why: RefusalWhy | null;
  /** How many times. */
  count: number;
}

/** Why the relay typed nothing, its notice kinds (devtools-relay.md §3.4):
 *  `not-allowed` the site may not have it; `needs-approval` it may with the
 *  person's OK, and a question is open; `declined` the person answered Send
 *  without it; `failed` Mandu could not check (fail-closed). */
export type RefusalWhy = "not-allowed" | "needs-approval" | "declined" | "failed";

export interface BrowserService {
  host: string;
  requests: number;
  /** The secrets that went to it masked (short names). */
  masked: string[];
}

export interface BrowserStory {
  /** Reads (messages from Chrome) Mandu masked something in. */
  maskedReads: number;
  /** The secrets kept out of what the agent read (short names, sorted). */
  secrets: string[];
  typed: BrowserTyped[];
  /** Commands Mandu never sent the browser, in plain words, with counts. */
  stopped: Array<{ what: string; count: number }>;
  /** Reads Mandu did not pass on at all (it could not check them). */
  withheld: number;
  /** The AI services the agent called itself, with what left them masked. */
  services: BrowserService[];
}

const PLAIN_COMMAND: Record<string, string> = {
  "Page.captureScreenshot": "screenshot",
  "Page.startScreencast": "screen recording",
  "Page.printToPDF": "PDF capture",
  "Network.getCookies": "cookie read",
  "Network.getAllCookies": "cookie read",
  "Storage.getCookies": "cookie read",
  "Target.exposeDevToolsProtocol": "debugging access",
  "Target.sendMessageToTarget": "debugging access",
};

/** The `secret` of an `unknown` line: its name is not one of the person's. */
export const UNKNOWN_SECRET = "an unknown masked value";

/** The relay's reason for a placeholder the arbiter does not know
 *  (cdp-relay release.ts UNKNOWN_PLACEHOLDER). */
const UNKNOWN_REASON = "unknown placeholder";

/** The relay's refusal reasons (cdp-relay release.ts `release`,
 *  `checkTyped`): a fixed prefix, then the cause in fixed words. */
const REFUSED_PREFIX = "Mandu: the placeholder was not typed: ";
const NOT_ALLOWED = /^\S+ may not go to (.*?) \(/;
const NEEDS_APPROVAL = /^(.*?) may not have \S+ without the person's approval in Mandu;/;
const DECLINED = "you chose to go on without ";
/** Mandu could not check: the gate, the value or the page could not be
 *  read, or the page has no origin (`frameOrigin`'s words, whole). */
const FAILED = [
  /^the release gate could not be asked \(/,
  /^the value could not be read \(/,
  /^it could not be looked up \(/,
  /^Chrome did not name the page \(/,
  /^Chrome named no main frame$/,
  /^(the|an? \S+) page has no origin a secret can be released to$/,
];
/** A host name only: letters, digits, `-`, `.`, an optional port. */
const HOST = /^[A-Za-z0-9.-]+(:\d{1,5})?$/;

/** A refusal's cause and site, read from the relay's stored reason (each
 *  cause anchored after the prefix, so a host cannot spell another). Only
 *  the cause and a host name are kept, never the text or its placeholder;
 *  an unknown reason is `why: null` (the page's older sentence). Pure. */
export function refusalCause(reason: unknown): { why: RefusalWhy | null; site: string | null } {
  if (typeof reason !== "string" || !reason.startsWith(REFUSED_PREFIX)) return { why: null, site: null };
  const text = reason.slice(REFUSED_PREFIX.length);
  const host = (h: string | undefined): string | null => (h !== undefined && HOST.test(h) ? h : null);
  const denied = NOT_ALLOWED.exec(text);
  if (denied) return { why: "not-allowed", site: host(denied[1]) };
  const ask = NEEDS_APPROVAL.exec(text);
  if (ask) return { why: "needs-approval", site: host(ask[1]) };
  if (text.startsWith(DECLINED)) return { why: "declined", site: null };
  if (FAILED.some((re) => re.test(text))) return { why: "failed", site: null };
  return { why: null, site: null };
}

/** A secret's short name, from its placeholder's name. */
function nameOf(symbol: unknown): string {
  return (typeof symbol === "string" ? secretShortName(symbol, null) : null) ?? "a secret";
}

const field = (e: ManduEvent, k: string): unknown => (e as unknown as Record<string, unknown>)[k];
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** The story, or null for a session with no browser connection. */
export function browserStory(events: readonly ManduEvent[]): BrowserStory | null {
  const relay = events.filter((e) => e.kind === "browser_action");
  if (relay.length === 0) return null;
  let maskedReads = 0;
  let withheld = 0;
  const secrets = new Set<string>();
  const typed = new Map<string, BrowserTyped>();
  const stopped = new Map<string, number>();
  for (const e of relay) {
    const action = field(e, "action");
    const symbols = strings(field(e, "symbols"));
    if (action === "masked") {
      maskedReads++;
      for (const s of symbols) secrets.add(nameOf(s));
    } else if (action === "withheld") {
      withheld++;
    } else if (action === "refused" && (field(e, "reason") === UNKNOWN_REASON || strings(field(e, "unknown")).length > 0)) {
      // Names nothing: one line however it was spelled, never its name.
      const k = "unknown";
      const t = typed.get(k) ?? { secret: UNKNOWN_SECRET, site: null, outcome: "unknown" as const, why: null, count: 0 };
      t.count++;
      typed.set(k, t);
    } else if (action === "released" || action === "refused") {
      const outcome = action === "released" ? "filled" : "refused";
      // A refusal's event has no page: its host is in the reason, if at all.
      const cause = outcome === "refused" ? refusalCause(field(e, "reason")) : { why: null, site: null };
      const site = outcome === "filled" ? (typeof field(e, "page") === "string" ? String(field(e, "page")) : null) : cause.site;
      for (const s of symbols.length ? symbols : [null]) {
        const secret = nameOf(s);
        const k = `${outcome}\u0000${cause.why ?? ""}\u0000${site ?? ""}\u0000${secret}`;
        const t = typed.get(k) ?? { secret, site, outcome, why: cause.why, count: 0 };
        t.count++;
        typed.set(k, t);
      }
    } else if (action === "blocked") {
      const method = String(field(e, "method") ?? "");
      const what = PLAIN_COMMAND[method] ?? "browser command";
      stopped.set(what, (stopped.get(what) ?? 0) + 1);
    }
  }
  // The model services: hosts a request reached with secrets left masked.
  const services = new Map<string, BrowserService>();
  for (const e of events) {
    if (e.kind !== "net_action" || field(e, "action") !== "forwarded") continue;
    const host = String(field(e, "destination") ?? "");
    const kept = strings(field(e, "keptOpaque"));
    if (!host || (kept.length === 0 && !services.has(host))) continue;
    const s = services.get(host) ?? { host, requests: 0, masked: [] };
    s.requests++;
    for (const k of kept) if (!s.masked.includes(nameOf(k))) s.masked.push(nameOf(k));
    services.set(host, s);
  }
  return {
    maskedReads,
    secrets: [...secrets].sort(),
    typed: [...typed.values()],
    stopped: [...stopped].map(([what, count]) => ({ what, count })),
    withheld,
    services: [...services.values()].map((s) => ({ ...s, masked: s.masked.sort() })),
  };
}
