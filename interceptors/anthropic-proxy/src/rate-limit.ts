/**
 * rate-limit — what an upstream throttle (429) or overload (529) says about
 * itself, read off its response HEADERS only (docs/design/architecture/
 * mandu.md §4.1, "Upstream throttles and plan limits").
 *
 * Anthropic answers a request a plan's quota no longer admits with a 429 and
 * a family of `anthropic-ratelimit-unified-*` headers: which window decided
 * (`representative-claim`: `five_hour`, `seven_day`, …), each window's status
 * and utilization, when the decisive window resets, and a `retry-after` in
 * seconds. Live 2026-10-28 (a subscription at its weekly limit): status
 * `rejected`, claim `seven_day`, 7d utilization 1.0, reset 21:00 UTC,
 * retry-after 45151, and `x-should-retry: true` all the same.
 *
 * Two uses, both off the security path:
 *   - the proxy's retry loop must not absorb a QUOTA rejection as if it were
 *     a transient spike (`isHardLimit`): before 2026-10-28 it re-knocked twelve
 *     times over about three minutes, so the agent sat on a spinner with no
 *     answer and the drill runner timed the turn out;
 *   - the relayed turn's `tllm_call` carries the parsed limit
 *     (`upstreamLimit`), so the dashboard and the drill runner can say
 *     "rate-limited until …" at once.
 *
 * Only these named headers are read, each value held to its expected shape
 * (a number, a short lower-case word); nothing else of the response, and no
 * request header (the auth headers among them), is ever looked at. Pure.
 */

export type HeaderBag = Record<string, string | string[] | undefined>;

/** One window of the plan's quota (`5h`, `7d`). */
export interface LimitWindow {
  /** `allowed` / `allowed_warning` / `rejected` as the API said it. */
  status?: string;
  /** 0..1 (1 = used up). */
  utilization?: number;
  /** When the window resets, ISO 8601. */
  resetsAt?: string;
}

/** The upstream limit an answer carried (mirrors dashboard/src/event-model.ts
 *  `UpstreamLimit` field for field). */
export interface UpstreamLimit {
  /** The upstream HTTP status: 429 (rate-limited) or 529 (overloaded). */
  status: number;
  /** The overall unified status (`rejected` when the plan's quota refused). */
  unifiedStatus?: string;
  /** The window that decided (`five_hour`, `seven_day`, …). */
  claim?: string;
  fiveHour?: LimitWindow;
  sevenDay?: LimitWindow;
  /** Whether the plan's extra usage could take over (`rejected`, …). */
  overageStatus?: string;
  /** When the decisive limit resets, ISO 8601. */
  resetsAt?: string;
  /** The answer's Retry-After, in seconds. */
  retryAfterS?: number;
  /** A quota the next minutes will not lift (isHardLimit): relayed at once. */
  hard: boolean;
}

/** A limit this far away (or farther) is no transient spike. */
export const HARD_LIMIT_S = 300;

const WORD_RE = /^[a-z][a-z0-9_]{0,31}$/;
const P = "anthropic-ratelimit-unified-";

function one(headers: HeaderBag, name: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== name) continue;
    const s = Array.isArray(v) ? v[0] : v;
    return typeof s === "string" ? s.trim() : undefined;
  }
  return undefined;
}
function word(headers: HeaderBag, name: string): string | undefined {
  const s = one(headers, name)?.toLowerCase();
  return s !== undefined && WORD_RE.test(s) ? s : undefined;
}
function fraction(headers: HeaderBag, name: string): number | undefined {
  const s = one(headers, name);
  if (s === undefined || !/^\d{1,3}(?:\.\d{1,6})?$/.test(s)) return undefined;
  const n = Number(s);
  return n >= 0 && n <= 100 ? n : undefined;
}
/** An epoch-seconds header as ISO 8601 (a plausible date only). */
function epoch(headers: HeaderBag, name: string): string | undefined {
  const s = one(headers, name);
  if (s === undefined || !/^\d{9,11}$/.test(s)) return undefined;
  return new Date(Number(s) * 1000).toISOString();
}
/** Retry-After in whole seconds: delta-seconds or an HTTP date. */
export function retryAfterSeconds(headers: HeaderBag, nowMs: number): number | undefined {
  const s = one(headers, "retry-after");
  if (s === undefined || s === "") return undefined;
  if (/^\d{1,9}$/.test(s)) return Number(s);
  // an IMF-fixdate ("Wed, 28 Oct 2026 21:00:00 GMT") only
  if (!/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(s)) return undefined;
  const when = Date.parse(s);
  return Number.isNaN(when) ? undefined : Math.max(0, Math.round((when - nowMs) / 1000));
}

function window(headers: HeaderBag, w: "5h" | "7d"): LimitWindow | undefined {
  const status = word(headers, `${P}${w}-status`);
  const utilization = fraction(headers, `${P}${w}-utilization`);
  const resetsAt = epoch(headers, `${P}${w}-reset`);
  if (status === undefined && utilization === undefined && resetsAt === undefined) return undefined;
  return { ...(status !== undefined ? { status } : {}), ...(utilization !== undefined ? { utilization } : {}), ...(resetsAt !== undefined ? { resetsAt } : {}) };
}

/** Whether a limit is a quota the next minutes will not lift: the plan's
 *  quota refused (`unified-status: rejected`) with its reset at least
 *  HARD_LIMIT_S away, or a Retry-After that long. A short-window throttle
 *  (Retry-After of seconds, the "temporarily limiting requests" spike) is
 *  not: the proxy keeps absorbing those. */
export function isHardLimit(l: Omit<UpstreamLimit, "hard">, nowMs: number): boolean {
  if (l.retryAfterS !== undefined && l.retryAfterS >= HARD_LIMIT_S) return true;
  if (l.unifiedStatus !== "rejected") return false;
  if (l.resetsAt === undefined) return l.retryAfterS === undefined;
  return Date.parse(l.resetsAt) - nowMs >= HARD_LIMIT_S * 1000;
}

/** The limit an upstream 429 / 529 answer carried, or null for any other
 *  status. Reads the named headers above and nothing else. */
export function parseUpstreamLimit(status: number, headers: HeaderBag, nowMs: number = Date.now()): UpstreamLimit | null {
  if (status !== 429 && status !== 529) return null;
  const unifiedStatus = word(headers, `${P}status`);
  const claim = word(headers, `${P}representative-claim`);
  const fiveHour = window(headers, "5h");
  const sevenDay = window(headers, "7d");
  const overageStatus = word(headers, `${P}overage-status`);
  const resetsAt = epoch(headers, `${P}reset`)
    ?? (claim === "seven_day" ? sevenDay?.resetsAt : claim === "five_hour" ? fiveHour?.resetsAt : undefined);
  const retryAfterS = retryAfterSeconds(headers, nowMs);
  const l: Omit<UpstreamLimit, "hard"> = {
    status,
    ...(unifiedStatus !== undefined ? { unifiedStatus } : {}),
    ...(claim !== undefined ? { claim } : {}),
    ...(fiveHour !== undefined ? { fiveHour } : {}),
    ...(sevenDay !== undefined ? { sevenDay } : {}),
    ...(overageStatus !== undefined ? { overageStatus } : {}),
    ...(resetsAt !== undefined ? { resetsAt } : {}),
    ...(retryAfterS !== undefined ? { retryAfterS } : {}),
  };
  return { ...l, hard: isHardLimit(l, nowMs) };
}

/** One line for a person: "rate-limited until 2026-10-28 21:00 UTC (seven_day
 *  window)", "overloaded". */
export function describeUpstreamLimit(l: UpstreamLimit): string {
  const what = l.status === 529 ? "overloaded" : "rate-limited";
  const until = l.resetsAt !== undefined ? ` until ${l.resetsAt.slice(0, 16).replace("T", " ")} UTC`
    : l.retryAfterS !== undefined ? ` (retry after ${l.retryAfterS}s)` : "";
  const claim = l.claim !== undefined ? ` (${l.claim.replace(/_/g, "-")} limit)` : "";
  return `${what}${until}${claim}`;
}
