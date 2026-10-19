/**
 * view-model/session-exit — whether a session's agent has exited, by its
 * recorded `session_exit` (dashboard.md §4.10.4, §4.25). Mandu-new (no
 * reference origin). OBSERVABILITY ONLY: nothing here is on the security
 * path, and nothing read out of an event leaves this module but a boolean.
 *
 * One rule for every view: the product's Home and session page
 * (agent-page.ts, home-routes.ts), and the developer view's session list,
 * whose event sources set `SessionRef.exited` from it where they already
 * read the session's events, so `session-batches.ts` `sessionStatus` stops
 * calling an ended session "running".
 */
import type { ManduEvent } from "../event-model.js";

/** Agent activity: a model call or a tool step. A `session_exit` after the
 *  last of these is the end; one followed by more (a resumed session writing
 *  to the same log) is not. */
const ACTIVITY = new Set(["tllm_call", "tool_use", "tool_result"]);

/**
 * The session's agent exited: its launcher recorded `session_exit` and no
 * agent activity came after it. The listing's "running" was recent activity
 * only, so a session closed with `/exit` a minute ago read "running now";
 * the recorded exit outranks it.
 */
export function sessionExited(events: readonly ManduEvent[]): boolean {
  let exitTs: string | null = null;
  let lastActivity: string | null = null;
  for (const e of events) {
    if (e.kind === "session_exit") { if (exitTs === null || e.ts > exitTs) exitTs = e.ts; }
    else if (ACTIVITY.has(e.kind) && (lastActivity === null || e.ts > lastActivity)) lastActivity = e.ts;
  }
  return exitTs !== null && (lastActivity === null || exitTs >= lastActivity);
}

/** The `SessionRef` field the event sources spread into a row: `exited`
 *  only when it is true, so a session with no recorded exit adds nothing. */
export function withExited(events: readonly ManduEvent[]): { exited?: true } {
  return sessionExited(events) ? { exited: true } : {};
}
