/**
 * exec-twin-store — the box→proxy symbol-twin hint store
 * (docs/design/integrity/symbol-twin-shell-blindness.md §4.1 v2). Mandu-new, no
 * reference origin. Sibling of exec-decision-store.ts (proxy→supervisor) and
 * exec-clean-verdicts.ts (supervisor→classify); this store carries the exec
 * box's OWN observation back to the proxy: "this boxed leaf, in this cwd,
 * named these AgentView paths whose twin is solely symbol tokens".
 *
 * WHY A SEPARATE, SIGNATURE-KEYED STORE: a pipeline leaf (`cat notes.md` of
 * `cat notes.md | grep X`) and a post-`cd` leaf reach the box one shim at a
 * time with their own argv + cwd, and their signature never equals the
 * proxy's recorded whole-command signature — so the callId leg of the
 * clean-verdict path (`execDecisionFor(argv)` → callId) MISSES for exactly
 * the cases v2 exists for. The proxy therefore asks by COMMAND, and the store
 * answers with the recent leaf reports that plausibly belong to it.
 *
 * TRUST (design §3/§4.2): a hint is a CANDIDATE PATH, never a verdict. The
 * proxy re-applies the twin predicate over the AgentView twin's bytes under
 * ITS OWN view-map roots before any note is built, so a stale, mis-correlated
 * or foreign-session hint can at most name a path that IS a symbolic twin in
 * this session's AgentView — a truth a `Read` would reveal anyway — and a path
 * outside the roots, or whose twin is not symbolic, yields nothing. No byte
 * of any file content passes through here: `abs` and `asTyped` are path
 * spellings the box derived from the leaf's argv, and `abs` is only ever used
 * as a lookup key on the proxy's side.
 *
 * NON-PERSISTENT + BOUNDED + RECENT, like its siblings: a hint is a
 * within-run fact consumed by the tool_result classify that follows the
 * command; entries older than `maxAgeMs` never match, and the insertion-
 * ordered map evicts oldest-first. Single-threaded (Node event loop).
 */

import { basename } from "./exec-identifier.js";
import { execSignature, execSignatureForArgv } from "./exec-signature.js";

/** One path a boxed leaf named whose AgentView twin is solely symbol tokens. */
export interface ExecTwinCandidate {
  /** The path as the leaf's argv spelled it (what the note will show). */
  asTyped: string;
  /** The absolute AgentView twin path the box resolved (cwd-joined). */
  abs: string;
}

/** What the exec box reports for one AgentShell leaf BEFORE it runs it. */
export interface ExecTwinReport {
  /** The leaf's argv as observed by the box (signature-normalized here). */
  argv: string[];
  /** The leaf's cwd (the shim's `$PWD`) — observability only. */
  cwd?: string;
  /** The symbolic twins the leaf named (already predicate-filtered box-side;
   *  the proxy re-verifies). At most `TWIN_HINT_MAX_PATHS` are kept. */
  twins: ExecTwinCandidate[];
  /** Path-like words the leaf named beyond `twins` (symbolic twins past the
   *  cap + words past the box's scan bound). A count the note reports as
   *  "N more file(s) not listed" — never the names. */
  more?: number;
}

/** The recorded entry (tests / observability). */
export interface RecordedExecTwins {
  signature: string;
  /** argv[0] basename — the program word used for the loose match. */
  program: string;
  cwd?: string;
  twins: ExecTwinCandidate[];
  more: number;
  /** Wall-clock record time (ms) — the recency gate. */
  at: number;
  /** Insertion epoch (monotonic counter — ordering only). */
  seq: number;
}

/** Per report AND per answer: mirrors the proxy's TWIN_MAX_PATHS (design §4.1). */
export const TWIN_HINT_MAX_PATHS = 8;

/** A hint older than this never matches (a leaf's tool_result classify follows
 *  its run within a turn; ten minutes bounds even a slow pipeline). */
export const TWIN_HINT_MAX_AGE_MS = 10 * 60 * 1000;

const SEPARATORS = new Set([" ", ";", "|", "&", "(", ")", "<", ">", "`"]);

/** Is `needle` a token-bounded substring of `hay` (a shell separator or the
 *  string edge on both sides)? `cat notes.md` in `cat notes.md | grep X` yes;
 *  in `cat notes.md.bak` no. */
export function containsAtTokenBoundary(hay: string, needle: string): boolean {
  if (needle === "" || hay === "") return false;
  let from = 0;
  for (;;) {
    const i = hay.indexOf(needle, from);
    if (i < 0) return false;
    const end = i + needle.length;
    const beforeOk = i === 0 || SEPARATORS.has(hay[i - 1]!);
    const afterOk = end === hay.length || SEPARATORS.has(hay[end]!);
    if (beforeOk && afterOk) return true;
    from = i + 1;
  }
}

/** Does the command signature mention `program` as a whole word? (`sed` in
 *  `cd docs && sed -n 3p x.md` yes; in `used` no.) */
export function mentionsProgram(commandSignature: string, program: string): boolean {
  if (program === "") return false;
  return commandSignature
    .split(/[\s;|&()<>`]+/)
    .some((w) => w === program || basename(w) === program);
}

export class ExecTwinStore {
  private readonly entries = new Map<number, RecordedExecTwins>();
  private seq = 0;
  private readonly capacity: number;
  private readonly maxAgeMs: number;
  private readonly now: () => number;

  constructor(opts: { capacity?: number; maxAgeMs?: number; now?: () => number } = {}) {
    this.capacity = Math.max(1, opts.capacity ?? 512);
    this.maxAgeMs = Math.max(0, opts.maxAgeMs ?? TWIN_HINT_MAX_AGE_MS);
    this.now = opts.now ?? Date.now;
  }

  /** Record one leaf's report. A report with no twins, no argv, or an empty
   *  signature records nothing (nothing to hint). Returns how many candidates
   *  were kept (≤ TWIN_HINT_MAX_PATHS). */
  record(report: ExecTwinReport): number {
    const argv = Array.isArray(report?.argv) ? report.argv.filter((a) => typeof a === "string") : [];
    const signature = execSignatureForArgv(argv);
    const twins = (Array.isArray(report?.twins) ? report.twins : [])
      .filter((t) => t && typeof t.asTyped === "string" && typeof t.abs === "string" && t.abs !== "")
      .map((t) => ({ asTyped: t.asTyped, abs: t.abs }))
      .slice(0, TWIN_HINT_MAX_PATHS);
    if (signature === "" || twins.length === 0) return 0;
    const seq = ++this.seq;
    const more = Number.isFinite(report.more) && (report.more as number) > 0 ? Math.floor(report.more as number) : 0;
    this.entries.set(seq, {
      signature,
      program: basename(argv[0] ?? ""),
      ...(typeof report.cwd === "string" && report.cwd !== "" ? { cwd: report.cwd } : {}),
      twins,
      more,
      at: this.now(),
      seq,
    });
    while (this.entries.size > this.capacity) {
      const oldest = this.entries.keys().next().value as number | undefined;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    return twins.length;
  }

  /**
   * The candidate twins for a model-authored command: newest-first over the
   * entries still inside the recency window, an entry matches when its leaf
   * signature sits token-bounded inside the command's signature (pipelines,
   * `cd x && …`, `;` chains) OR — because shell expansion (`*.md`, `$f`,
   * `xargs`, `find -exec`) rewrites the leaf beyond containment — when the
   * command mentions the leaf's program word. Unique by `abs`, at most
   * TWIN_HINT_MAX_PATHS; `more` = the largest `more` any matched leaf
   * reported plus every matched twin the cap left out. Pure read: nothing is
   * consumed (the proxy caches its answer per callId so history re-sends
   * never re-ask).
   */
  twinsFor(command: string): { signature: string; twins: ExecTwinCandidate[]; more: number } {
    const signature = execSignature(command);
    const out: ExecTwinCandidate[] = [];
    let more = 0;
    if (signature === "") return { signature, twins: out, more };
    const seen = new Set<string>();
    const cutoff = this.now() - this.maxAgeMs;
    const newestFirst = [...this.entries.values()].reverse();
    for (const e of newestFirst) {
      if (e.at < cutoff) continue;
      const hit =
        e.signature === signature ||
        containsAtTokenBoundary(signature, e.signature) ||
        mentionsProgram(signature, e.program);
      if (!hit) continue;
      more = Math.max(more, e.more);
      for (const t of e.twins) {
        if (seen.has(t.abs)) continue;
        seen.add(t.abs);
        if (out.length >= TWIN_HINT_MAX_PATHS) { more += 1; continue; }
        out.push(t);
      }
    }
    return { signature, twins: out, more };
  }

  /** Entry count (tests / observability). */
  size(): number {
    return this.entries.size;
  }
}
