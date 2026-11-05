/**
 * view-model/discarded-writes — the secret files whose change stayed in the
 * masked copy, for the product's session page (dashboard.md §4.25b,
 * *Changes Mandu did not apply to your files*). Mandu-new (no reference
 * origin).
 *
 * The agent works on masked copies of the registered secret files (the
 * twins, launcher secret-twins.ts). A write to one lands in the copy, which
 * goes with the session, and Mandu never copies it back to the real file
 * (confidentiality-plan-10-flow-taint.md §4.1). The launcher names each such
 * file on its `session_exit` event, field `discardedWrites` (by path, never
 * content; launcher services/observe.ts `sessionExitEvent`). The page lists
 * them, so a person learns of the lost change before their program fails.
 *
 * Only a BELIEVED exit counts (`believedEvents`, arbiter-human-plane.md
 * §10.2): a claim, sent from the agent's own tree, never makes the page list
 * a file. The event holds paths only, not whether the real file changed by
 * some other way meanwhile, so nothing here says it is unchanged.
 * OBSERVABILITY ONLY: nothing here is on the security path.
 */
import { believedEvents, type ManduEvent } from "../event-model.js";
import { tildePath } from "./rule-words.js";

/** How many files the block lists; past it, "and N more files". */
export const DISCARDED_CAP = 20;

export interface DiscardedWrites {
  /** `~/…` under the home folder, else absolute; control and format
   *  characters as `?`. In the launcher's order, at most DISCARDED_CAP. */
  files: string[];
  /** Files past the cap. */
  more: number;
}

/** A path as one line: control characters (C0, DEL, C1), the line and
 *  paragraph separators and the format characters (a bidi override would
 *  reorder the line) become `?`, as the launcher's `printablePath` does. */
function printable(p: string): string {
  return p.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/gu, "?");
}

/**
 * The files the last believed `session_exit` of the launcher names, or null
 * when there is no such exit or it names none. Entries that are not a
 * non-empty string are dropped; the same path twice is one. Pure.
 */
export function discardedWritesOf(events: readonly ManduEvent[], home: string): DiscardedWrites | null {
  let last: ManduEvent | undefined;
  for (const e of believedEvents(events)) {
    if (e.kind === "session_exit" && e.emitter === "launcher" && (last === undefined || e.ts >= last.ts)) last = e;
  }
  const raw = (last as { discardedWrites?: unknown } | undefined)?.discardedWrites;
  if (!Array.isArray(raw)) return null;
  const all: string[] = [];
  for (const p of raw) {
    if (typeof p !== "string" || p === "") continue;
    const shown = printable(tildePath(p, home));
    if (!all.includes(shown)) all.push(shown);
  }
  if (!all.length) return null;
  return { files: all.slice(0, DISCARDED_CAP), more: Math.max(0, all.length - DISCARDED_CAP) };
}
