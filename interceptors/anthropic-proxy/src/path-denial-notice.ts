/**
 * path-denial-notice — a call whose every path Mandu denied explains itself
 * to the model (confidentiality plan 10 §11.8, "Path denials").
 *
 * The sensitive-path gate (fs-gate.ts, `/mandu/denied/<reason>/<path>`) and
 * the derived-label hook (fs-label.ts, `/dev/null/mandu-unlabeled/<path>`)
 * deny a path by rewriting it to a sentinel the tool fails on. The tool's
 * error then came back as the result, and the classify verdict's path scan
 * read the sentinel: a denied `.env` or `id_rsa` made the error a
 * `$MDU:nomodel_…` symbol (live probe, 2026-10-04), and any other path left
 * the harness's bare error. Neither says why.
 *
 * So when EVERY path value of a call is a Mandu sentinel, the proxy records a
 * notice built from its own decision (the path as the model wrote it, after
 * normalization, and the arbiter's reason), and the request side replaces
 * the whole result with it ({@link ResultNotices}). No byte of the
 * tool's output is forwarded: the tool ran against paths that do not exist,
 * and what it said about them is discarded, not filtered. A call with any
 * path left real is not recorded, so its output takes the classify path as
 * before.
 */

import { DENIED_NAMESPACE } from "./fs-gate.js";
import { UNLABELABLE_SENTINEL_ROOT } from "./fs-label.js";
import type { PathToolFields } from "./gate-surface.js";

/** One denied path, as the gate or the label hook decided it. */
export interface PathDenial {
  field: string;
  path: string;
  reason: string;
}

/** Is `v` one of Mandu's path sentinels? */
export function isPathSentinel(v: string): boolean {
  return v.startsWith(`${DENIED_NAMESPACE}/`) || v.startsWith(`${UNLABELABLE_SENTINEL_ROOT}/`);
}

/**
 * True when the tool's input holds at least one path value and every one is
 * a Mandu sentinel: the tool can have touched no real file through its path
 * fields. Unknown tool (no path fields) ⇒ false.
 */
export function everyPathDenied(input: unknown, entry: PathToolFields | undefined): boolean {
  if (!entry || entry.fields.length === 0) return false;
  if (!input || typeof input !== "object" || Array.isArray(input)) return false;
  const src = input as Record<string, unknown>;
  let seen = 0;
  for (const field of entry.fields) {
    const v = src[field];
    const values = typeof v === "string" ? [v] : Array.isArray(v) ? v : [];
    for (const el of values) {
      if (typeof el !== "string" || el === "") continue;
      if (!isPathSentinel(el)) return false;
      seen++;
    }
  }
  return seen > 0;
}

/** The denial in plain words, keyed on the reason; the reason follows as
 *  `detail:` so nothing is lost. */
export function plainDenialWords(reason: string): string {
  if (/→ pending$/.test(reason)) {
    return "using this path needs your OK: answer it on the dashboard's Approvals page (mandu dashboard), then try again";
  }
  if (/^REFUSED: the session is HIGH/.test(reason)) {
    return "this session has read a secret, so Mandu labels every file it writes, and this path cannot be labeled; name the file by its absolute path";
  }
  if (/arbiter unreachable/.test(reason)) {
    return "the Mandu service is not answering, so the path could not be checked (mandu status shows the service)";
  }
  if (/leaves the agent's working directory/.test(reason)) return "name the file by its absolute path";
  return "Mandu rules do not allow this tool to use this path (the dashboard lists them: mandu dashboard)";
}

/** The notice the model reads in place of the tool's result. One line per
 *  denied path. */
export function pathDenialNotice(tool: string, denials: readonly PathDenial[]): string {
  return denials
    .map((d) => `mandu-fs-gate: denied, nothing was read or written: ${plainDenialWords(d.reason)}. path: ${d.path} (${tool}.${d.field}). detail: ${d.reason}`)
    .join("\n");
}

/** The notice for a call Mandu refused whole (`refusedToolInput`, a
 *  dispatcher refusal): its input became one the tool rejects, so nothing
 *  ran. `why` is the refusal's own text, already in the model's history as
 *  the rewritten input; a notice that already names its gate (the net
 *  gate's `mandu-net-gate: …`) is kept as it is. */
export function refusalNotice(why: string): string {
  return why.startsWith("mandu-") ? why : `mandu: refused, nothing ran: ${why}`;
}

/** How many notices {@link ResultNotices} keeps (oldest out). */
export const RESULT_NOTICES_MAX = 1024;

/** The notices that REPLACE a call's whole result, by tool_use id: a call
 *  whose every path Mandu denied (above), a network call the net gate
 *  blocked (net-gate.ts `notice`), and a call Mandu refused whole
 *  (`refusedToolInput`, a dispatcher refusal): in each the tool reached
 *  nothing real, so nothing it said is forwarded. In memory only: a
 *  restarted proxy has none, and the result is classified as before. */
export class ResultNotices {
  private readonly notices = new Map<string, string>();

  remember(callId: string | undefined, notice: string | undefined): void {
    if (!callId || !notice) return;
    this.notices.delete(callId);
    this.notices.set(callId, notice);
    while (this.notices.size > RESULT_NOTICES_MAX) {
      const oldest = this.notices.keys().next().value;
      if (oldest === undefined) break;
      this.notices.delete(oldest);
    }
  }

  noticeFor(callId: string): string | undefined {
    return this.notices.get(callId);
  }
}
