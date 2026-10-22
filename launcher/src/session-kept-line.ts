/**
 * session-kept-line — the last line a `mandu <agent>` session prints: what
 * Mandu kept from the AI in it (packaging.md §5 "Launch display policy",
 * *The session's last line*; dashboard.md §4.25ah). Mandu-new (no reference
 * origin).
 *
 *   mandu: in this session: 2 secrets masked before the AI saw them
 *   (DB_PASSWORD in ~/proj/.env and the file ~/.aws/credentials) · 1 send
 *   with a real value filled in (api.stripe.com) · details: `mandu dashboard`
 *
 * (one line on the terminal). The launcher does not count anything itself:
 * it asks the dashboard, which counts the session by the same facts its
 * Home row and its page show (home-routes.ts `HomeFacts`), so the three
 * always agree, and words it in the product's vocabulary. The question goes
 * over the dashboard's human-plane socket (`sessionKept`, beside the
 * sign-in op; dashboard-sign-in.ts), the newest live dashboard of this
 * runtime first, then the next, until one knows the session.
 *
 * Off the security path, and best-effort: no dashboard, an older one
 * without the op, a socket outside the human-plane directory, no answer
 * within SESSION_KEPT_TIMEOUT_MS, a session it does not know, or an answer
 * that is not one line saying `mandu: …` all print nothing. The answer is
 * printed with every control character replaced (printablePath), so no
 * name in it can drive the terminal; it never holds a value (the dashboard
 * builds it from names, paths, hosts and counts).
 *
 * Opt-out: `--no-session-summary` or MANDU_SESSION_SUMMARY=0 (parse.ts).
 */
import { dashboardSocketCall, trustedDashboardSock, type SignInDashboard } from "./dashboard-sign-in.js";
import { printablePath } from "./twin-writes.js";

/** The dashboard socket's op (dashboard/src/sign-in.ts SESSION_KEPT_OP). */
export const SESSION_KEPT_OP = "sessionKept";
/** The whole wait, over every dashboard asked: the person's prompt comes
 *  back after it, so it is short. */
export const SESSION_KEPT_TIMEOUT_MS = 4_000;
/** Dashboards asked at most (newest first). */
export const SESSION_KEPT_DASHBOARDS = 2;
/** The longest line printed; a longer answer is cut. */
export const SESSION_KEPT_LINE_MAX = 600;

/** The line an answer carries, printable, or null: not found, refused,
 *  malformed, more than one line, or not a `mandu: ` line. Pure. */
export function keptLineOf(answer: unknown): string | null {
  const a = answer as { ok?: unknown; found?: unknown; line?: unknown } | null;
  if (a === null || typeof a !== "object" || a.ok !== true || a.found !== true || typeof a.line !== "string") return null;
  if (/[\r\n]/.test(a.line) || !a.line.startsWith("mandu: ")) return null;
  const line = printablePath(a.line);
  return line.length > SESSION_KEPT_LINE_MAX ? line.slice(0, SESSION_KEPT_LINE_MAX - 1) + "…" : line;
}

export interface SessionKeptAsk {
  /** The session (the launch's scope id). */
  session: string;
  /** This runtime's live dashboards, newest first (subcommands.ts liveDashboards). */
  dashboards: readonly SignInDashboard[];
  /** The runtime base whose human-plane directory the socket must be in. */
  runtimeBase: string;
  /** The round trip (dashboard-sign-in.ts dashboardSocketCall); tests pass a fake. */
  call?: (sock: string, req: Record<string, unknown>, timeoutMs: number) => Promise<unknown>;
  timeoutMs?: number;
  now?: () => number;
}

/** The session's last line, or null (see the header). Never throws. */
export async function sessionKeptLine(ask: SessionKeptAsk): Promise<string | null> {
  const call = ask.call ?? dashboardSocketCall;
  const now = ask.now ?? Date.now;
  const deadline = now() + (ask.timeoutMs ?? SESSION_KEPT_TIMEOUT_MS);
  for (const dash of ask.dashboards.slice(0, SESSION_KEPT_DASHBOARDS)) {
    const left = deadline - now();
    if (left <= 0) break;
    const trusted = trustedDashboardSock(dash, ask.runtimeBase);
    if ("why" in trusted) continue;
    try {
      const line = keptLineOf(await call(trusted.sock, { op: SESSION_KEPT_OP, session: ask.session }, left));
      if (line !== null) return line;
    } catch {
      /* this dashboard did not answer: the next */
    }
  }
  return null;
}
