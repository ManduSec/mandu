/**
 * events — what the relay tells the session's trace
 * (docs/design/agents/devtools-relay.md §5.1): one `browser_action` event per
 * thing it did to the agent's browser connection, sent to the arbiter's
 * event store (best-effort, off the security path; the dashboard's session
 * page reads them). Names only: a placeholder, a method, a page's host and a
 * reason; never a value, never page text.
 *
 *   masked    Chrome's message reached the agent with these placeholders
 *             in place of the values (a read)
 *   withheld  Chrome's message did not reach the agent (the filter could not
 *             answer, or held it; or bytes the relay cannot read)
 *   released  a placeholder the agent typed became its value on this page
 *   refused   a placeholder the agent typed was not typed (why; `unknown
 *             placeholder`, with `unknown`, for one the arbiter does not know)
 *   blocked   a command the relay never sends Chrome (pixels, cookies, …)
 *
 * Mandu-new (no reference origin).
 */
import { findSymbols } from "./symbols.js";

export type BrowserAction = "masked" | "withheld" | "released" | "refused" | "blocked";

/** The fields one event carries beside its action. */
export interface BrowserEventFields {
  method?: string;
  /** The page's host (a typed placeholder's destination). */
  page?: string;
  /** Placeholder names (masked, released, refused). */
  symbols?: string[];
  reason?: string;
  /** refused: the typed placeholders the arbiter does not know, and the
   *  lookalikes of one, which name nothing (reason
   *  `unknown placeholder`, release.ts UNKNOWN_PLACEHOLDER). */
  unknown?: string[];
}

/** The canonical event (dashboard/src/event-model.ts ManduEvent). */
export function browserEvent(session: string | undefined, action: BrowserAction, fields: BrowserEventFields, now: number = Date.now()): Record<string, unknown> {
  const sessionId = session ?? "cdp-relay";
  return {
    kind: "browser_action",
    sessionId,
    id: `${sessionId}:cdp:${now.toString(36)}:${Math.floor(Math.random() * 1e6).toString(36)}`,
    ts: new Date(now).toISOString(),
    turn: 0,
    callId: null,
    parentId: null,
    view: "AgentView",
    // A read is what reaches the agent (and its model); a typed value
    // leaves for a website.
    boundary: action === "released" || action === "refused" ? "network" : "model_context",
    emitter: "cdp-relay",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    action,
    ...fields,
  };
}

/** The placeholders the masked message has that Chrome's did not: what the
 *  filter put in. Sorted, each once. */
export function addedSymbols(before: unknown, after: unknown): string[] {
  const had = new Set(findSymbols(JSON.stringify(before ?? null)));
  return [...new Set(findSymbols(JSON.stringify(after ?? null)))].filter((s) => !had.has(s)).sort();
}
