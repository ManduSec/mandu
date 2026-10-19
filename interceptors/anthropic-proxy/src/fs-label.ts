/**
 * fs-label — the ON-DISK label a HIGH session's write leaves behind
 * (Plan 9; confidentiality.md §4 bullet 2, §8, §7 ②).
 *
 * Mandu-new (no reference origin). The fourth tool_use hook, alongside the fs
 * gate (typed path fields), the exec gate (a symbol in command position) and the
 * net gate (the watermark's network chokepoint). This one is the watermark's
 * FILESYSTEM chokepoint — and unlike the other three it does not BLOCK anything
 * in the normal case. It writes a label.
 *
 * ── WHY IT EXISTS: the watermark dies at session end ────────────────────────
 *
 * Plan 8's watermark is session state. A high session writes a file derived from
 * the secret it read; the session ends; the watermark is gone; the next session
 * reads that file, the catalog finds no match, and it classifies PUBLIC — raw
 * into T-LLM, free to egress anywhere. Everything the watermark confined walks
 * out of the NEXT conversation. §4 says the file is "labeled at the watermark on
 * disk, before fs-sync exposes them anywhere public — persisting into future
 * sessions' classification"; this is the hook that does it.
 *
 * ── WHY NOT INSIDE THE fs GATE, WHICH ALREADY SEES EVERY WRITE PATH ─────────
 *
 * Because `gateToolUseInput` only runs when the VIEW MAP is active (it needs the
 * workspace roots), and the view map is not the default posture. A labeling hook
 * hidden behind it would be DEAD exactly where everyone runs — the same bug the
 * exec/net watermark wiring already had to be rescued from. So: a sibling hook,
 * no view-map prerequisite, ordered AFTER the fs gate (a path the gate denied is
 * not labeled — nothing will be written there) and BEFORE the forward map
 * (labels are keyed on HumanView paths, like every other arbiter path surface).
 *
 * ── FAIL-CLOSED: an arbiter we cannot reach means a write we must not allow ──
 *
 * We cannot know whether the session is high without asking, and cannot record
 * the label if the answer never comes. So an unreachable/wedged arbiter DENIES
 * the write (the tool fails, the model reads its own error, the session
 * continues) — as does an arbiter that answers "this session is HIGH and that
 * path cannot be labeled" (`refused`). "We could not check" and "we could not
 * record" must never resolve to "write it unlabeled" — that is the laundering
 * hole with extra steps. In practice the unreachable case costs nothing: a dead
 * arbiter already fails the request-side classify, so no tool_use comes back.
 */

import { posix } from "node:path";

import type { Arbiter } from "./arbiter-client.js";
import { DENIED_NAMESPACE } from "./fs-gate.js";
import { CLAUDE_CODE_PATH_FIELDS, FS_MODE_BY_TOOL, type ViewMap } from "./view-map.js";
import type { PathToolFields } from "./gate-surface.js";

/**
 * Where an UNLABELABLE write is sent to die.
 *
 * Deliberately NOT the fs gate's `/mandu/denied/…`: that namespace is a deny
 * only because the agent cannot write to `/`. An agent running as root (the
 * Docker e2e image does) would happily `mkdir -p /mandu/denied/…` and the
 * secret-derived bytes would land on disk — unlabeled, which is precisely what
 * this hook exists to prevent — while the model is told the write succeeded.
 *
 * `/dev/null` is a CHARACTER DEVICE, so any path *below* it can never be created:
 * the kernel answers ENOTDIR for root and non-root alike. The deny is a property
 * of the filesystem, not of the agent's privileges. (The reason still rides in
 * the path, so the model reads it in its own tool error and can react.)
 */
export const UNLABELABLE_SENTINEL_ROOT = "/dev/null/mandu-unlabeled";

/** Fail-closed ceiling for one arbiter labelWrittenPath. Same rationale and value
 *  as the fs/exec/net gates: a wedged arbiter must be able to DENY, never to
 *  stall the turn. */
export const DEFAULT_LABEL_TIMEOUT_MS = 5000;

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e as Error); },
    );
  });
}

/** One labeled (or denied) write, for events/logging. */
export interface LabeledWrite {
  tool: string;
  field: string;
  /** The HumanView path the model asked to write. */
  path: string;
  /** Was a derived label actually recorded? False in a public session — the
   *  overwhelmingly common case, and a no-op. */
  labeled: boolean;
  /** The level a FUTURE session will now classify this path at. */
  level: string;
  reason: string;
  /** Set only when the write was DENIED — the arbiter was unreachable, or it
   *  REFUSED (a high session writing a path it cannot key). Fail-closed either
   *  way: an unlabeled write from a possibly-high session is the hole. */
  sentinel?: string;
}

export interface FsLabelResult {
  /** The (possibly rewritten) input — a fresh object only when a write was denied. */
  input: Record<string, unknown>;
  /** Writes we told the arbiter about. Empty ⇒ nothing to report. */
  writes: LabeledWrite[];
}

export interface FsLabelOptions {
  arbiter: Pick<Arbiter, "labelWrittenPath">;
  /** The session whose watermark decides. ABSENT ⇒ no session to attribute a
   *  watermark to, so there is nothing to persist and nothing to fail closed
   *  about — the same rule every other session-scoped decision follows. */
  sessionKey?: string;
  /** Present only when the view map is active; used solely to normalize the path
   *  the same way the fs gate did. Absent ⇒ the raw string is used (the arbiter
   *  normalizes, and refuses what it cannot). */
  viewMap?: ViewMap;
  log?: (m: string) => void;
  timeoutMs?: number;
  /** The session agent's path-bearing tools (gate-surface.ts). Default:
   *  Claude Code's (view-map.ts). */
  pathTools?: Readonly<Record<string, PathToolFields>>;
  /** The absolute HumanView directory the agent resolves relative paths
   *  against, when known (fs-gate.ts gateToolUseInput `relativeBase`). */
  relativeBase?: string;
}

/** Lexical normalization when no view map is active. */
const PLAIN = { normalize: (p: string): string => posix.normalize(p) };

/**
 * Record the on-disk label for every write-mode path field of one tool_use.
 *
 * NEVER THROWS. Returns null when the tool writes no typed path field (nothing
 * to label — a `Bash` redirect is the exec chokepoint's turf, and in a high
 * session the exec gate blocks the command outright).
 */
export async function labelWrittenPaths(
  toolName: string,
  input: unknown,
  opts: FsLabelOptions,
): Promise<FsLabelResult | null> {
  const entry = opts.pathTools
    ? (Object.prototype.hasOwnProperty.call(opts.pathTools, toolName) ? opts.pathTools[toolName] : undefined)
    : undefined;
  if ((opts.pathTools ? entry?.mode : FS_MODE_BY_TOOL[toolName]) !== "write") return null;
  const fields = opts.pathTools ? entry?.fields : CLAUDE_CODE_PATH_FIELDS[toolName];
  if (!fields || fields.length === 0) return null;
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (!opts.sessionKey) return null;
  // An arbiter predating Plan 9 has no derived-label store: there is nothing to
  // record, and nothing to fail closed ABOUT (the absence of the op means the
  // label cannot exist, not that we failed to read it — the same argument the net
  // gate makes for a pre-Plan-8 arbiter).
  if (!opts.arbiter.labelWrittenPath) return null;

  const src = input as Record<string, unknown>;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_LABEL_TIMEOUT_MS;
  let out: Record<string, unknown> | null = null;
  const writes: LabeledWrite[] = [];

  for (const field of fields) {
    const v = src[field];
    if (typeof v !== "string" || v === "") continue;
    // A relative path joins the agent's launch directory when the agent
    // resolves against it (fs-gate.ts resolveRelative): the label is then
    // keyed on the file the write lands in. Otherwise it goes as written.
    const norm = opts.relativeBase !== undefined && !v.trim().startsWith("/") && !v.trim().startsWith("~")
      ? (opts.viewMap ?? PLAIN).normalize(`${opts.relativeBase}/${v.trim()}`)
      : opts.viewMap ? opts.viewMap.normalize(v) : v;
    // A path the fs gate already DENIED. Nothing will be written there, so there
    // is nothing to label — and labeling the sentinel would litter the store with
    // paths that cannot exist.
    if (norm.startsWith(DENIED_NAMESPACE)) continue;
    // Everything else goes to the arbiter, INCLUDING a `~/…` spelling (it expands
    // it) and including a RELATIVE path — which it cannot key, and therefore
    // REFUSES when the session is high (`refused`, below). Filtering relatives out
    // here would look like the fs gate's "CWD scoping's job" skip, but it is not
    // the same act: the fs gate's skip declines to GATE a path, while a skip here
    // would decline to LABEL a write from a high session — a silent hole with the
    // shape of a style choice.

    let verdict: {
      labeled: boolean; refused?: boolean; level: string; bindings: string[]; reason: string;
    };
    try {
      verdict = await withTimeout(
        opts.arbiter.labelWrittenPath({ sessionKey: opts.sessionKey, path: norm, tool: toolName }),
        timeoutMs,
        `arbiter labelWrittenPath timed out after ${timeoutMs}ms — fail closed`,
      );
    } catch (err) {
      // We could not learn the session's watermark and could not record a label.
      // DENY the write: an unlabeled write from a possibly-high session IS the
      // laundering hole this hook exists to close.
      const reason = `arbiter unreachable — fail closed: ${(err as Error).message}`;
      const sentinel = denySentinel(norm);
      out = out ?? { ...src };
      out[field] = sentinel;
      writes.push({
        tool: toolName, field, path: norm, labeled: false, level: "unknown", reason, sentinel,
      });
      opts.log?.(`fs-label: DENIED ${toolName}.${field} → ${norm} (${reason})`);
      continue;
    }

    if (verdict.refused) {
      // The arbiter answered, and the answer is "this session is HIGH and I cannot
      // label that path". An unlabeled write from a high session is the hole; the
      // write does not happen.
      const sentinel = denySentinel(norm);
      out = out ?? { ...src };
      out[field] = sentinel;
      writes.push({
        tool: toolName, field, path: norm, labeled: false, level: "unknown",
        reason: verdict.reason, sentinel,
      });
      opts.log?.(`fs-label: DENIED ${toolName}.${field} → ${norm} (${verdict.reason})`);
      continue;
    }

    if (!verdict.labeled) continue; // public session / OFF axis / already covered
    writes.push({
      tool: toolName, field, path: norm,
      labeled: true, level: verdict.level, reason: verdict.reason,
    });
    opts.log?.(
      `fs-label: ${toolName}.${field} → ${norm} labeled ${verdict.level} (${verdict.reason})`,
    );
  }

  return { input: out ?? src, writes };
}

/** A path that CANNOT be created — see UNLABELABLE_SENTINEL_ROOT. The original is
 *  preserved inside it, so the model's own tool error names the file it failed to
 *  write (and the event stays legible). */
function denySentinel(norm: string): string {
  return `${UNLABELABLE_SENTINEL_ROOT}${norm.startsWith("/") ? norm : `/${norm}`}`;
}
