/**
 * fs-gate — proxy-side enforcement of the sensitive-path gate (P3,
 * fs-sync.md §1.4.1).
 *
 * Mandu Track A (interceptors/anthropic-proxy). At the SAME response-side
 * tool_use hook as the P2 prefix map (after its forward rewrite), every typed
 * path field of a registry tool that is ABSOLUTE is submitted to the arbiter's
 * fs data-usage policy (`fsPathDecision`, wrapped by the interactive approval
 * queue). In-workspace paths are submitted too — NOT short-circuited here — so
 * the arbiter's sensitive-path deny-precedence (fs-outbound.ts rule 1) reaches
 * a sensitive path nested inside a workspace root; the arbiter allows an
 * ordinary in-workspace path via its rule 2. The verdict is enforced ON THE
 * WIRE:
 *
 *   allow  → the field passes through unchanged;
 *   deny   → the field is rewritten into the reserved namespace
 *            `/mandu/denied/<reason>/<orig>` — the tool then FAILS at
 *            execution (nothing exists under /mandu), the error tool_result
 *            rides back to T-LLM naming the sentinel, and the session
 *            continues. No stream abort, no client-compat risk; the original
 *            object is never touched (a *gate*, not a redirect).
 *   arbiter unreachable → the SAME sentinel with reason `unreachable`. The
 *            gate FAILS CLOSED (the repo invariant); it never falls through
 *            to the raw path.
 *
 * SCOPE (conservative, documented residue in fs-sync.md §1.4.1): typed
 * path fields only (Bash.command strings are the exec chokepoint's turf),
 * each a string or an array of strings (every element gated; a denied one
 * becomes the sentinel in a copy of the array), media references read the
 * way the tool reads them (`refs: "media"`, mediaRefPath), absolute paths,
 * and relative ones where the gate can place them (resolveRelative: joined
 * to the agent's launch directory when the agent resolves against it,
 * denied when they escape an unknown base with `..`, otherwise not gated
 * here), and only when the view map is active (the map is how the proxy
 * knows the workspace roots). A patch
 * tool's header paths reach this gate as synthetic fields (proxy.ts, the
 * patch leg).
 */

import { fileURLToPath } from "node:url";

import type { Arbiter, FsPathDecision, RuleRef } from "./arbiter-client.js";
import { CLAUDE_CODE_PATH_FIELDS, FS_MODE_BY_TOOL, type ViewMap } from "./view-map.js";
import type { PathToolFields } from "./gate-surface.js";

/** The reserved namespace denied paths are rewritten into. Nothing may ever
 * exist under it; the launcher/docs reserve it (a created `/mandu` would need
 * root, and an attacker with root is past this tier's threat model). */
export const DENIED_NAMESPACE = "/mandu/denied";

/**
 * Fail-closed ceiling for a single arbiter fsPathDecision. The gate runs on the
 * SSE relay chain, so an arbiter that is alive-but-unresponsive (blocked on disk
 * I/O, SIGSTOPped) with its socket still open would otherwise make the awaited
 * verdict hang forever and wedge the whole model turn. On timeout the path is
 * treated exactly like an unreachable arbiter — the denied sentinel — so a
 * wedged link can only DENY, never stall (the fail-closed invariant).
 */
export const DEFAULT_GATE_TIMEOUT_MS = 5000;

/** Reject with `message` if `p` has not settled within `ms`, else settle with
 * `p`. The timer is NOT unref'd: it is the fail-closed safety valve and MUST be
 * able to fire even if it is momentarily the only thing on the loop (an unref'd
 * timer could be skipped, re-opening the very wedge this guards against). It is
 * cleared as soon as `p` settles, so it adds no lingering delay in the common
 * (fast) case. */
function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e as Error); },
    );
  });
}

/** One gated (denied) field, for events/logging. */
export interface GatedField {
  tool: string;
  field: string;
  /** The normalized path the model asked for. */
  path: string;
  /** The sentinel the field was rewritten to. */
  sentinel: string;
  /** The arbiter verdict, or null when the arbiter was unreachable. */
  decision: FsPathDecision | null;
  /** Why the field was gated (policy reason, or the unreachable error). */
  reason: string;
  /** Decision provenance: the arbiter's ruleRef, or the proxy-side fail-closed
   * ref when the arbiter was unreachable (policy-surface.md §9.3). */
  ruleRef: RuleRef;
  /** The approval-queue row this deny created/bumped (`egr-<n>`), when the
   * arbiter queued one — the Pending-tab join (policy-surface.md §9.5). */
  approvalId?: string;
}

export interface GateResult {
  /** The (possibly rewritten) input — a fresh object when anything was gated. */
  input: Record<string, unknown>;
  /** The denied fields, in field order. Empty ⇒ input passed through as-is. */
  gated: GatedField[];
}

/**
 * Apply the sensitive-path gate to one tool_use input. Returns null when the
 * tool has no typed path fields (nothing to gate — Bash/unknown tools fall to
 * the other chokepoints). NEVER throws: an arbiter error is enforced as a
 * denied-sentinel (fail-closed), not propagated.
 */
export async function gateToolUseInput(
  toolName: string,
  input: unknown,
  opts: {
    arbiter: Pick<Arbiter, "fsPathDecision">;
    viewMap: ViewMap;
    /** ATTRIBUTION-ONLY session key forwarded on the arbiter request (never a
     * decision input) — lets the arbiter attribute the approval-queue row this
     * gate may create to the session. Omitted → not sent. */
    sessionKey?: string;
    log?: (msg: string) => void;
    /** Per-decision fail-closed timeout (ms). Default DEFAULT_GATE_TIMEOUT_MS.
     * A verdict not returned in time is treated as unreachable (sentinel). */
    arbiterTimeoutMs?: number;
    /** The session agent's path-bearing tools (gate-surface.ts
     *  GateSurface.paths: `read.filePath` on opencode, `read.path` on
     *  openclaw). Default: Claude Code's (view-map.ts). */
    pathTools?: Readonly<Record<string, PathToolFields>>;
    /** The absolute HumanView directory the agent resolves relative paths
     *  against, when it is known (gate-surface.ts `relativeBase: "launch"`
     *  and the launcher's MANDU_AGENT_CWD). Absent: unknown (resolveRelative). */
    relativeBase?: string;
  },
): Promise<GateResult | null> {
  const entry = opts.pathTools
    ? (Object.prototype.hasOwnProperty.call(opts.pathTools, toolName) ? opts.pathTools[toolName] : undefined)
    : undefined;
  const fields = opts.pathTools ? entry?.fields : CLAUDE_CODE_PATH_FIELDS[toolName];
  if (!fields || fields.length === 0) return null;
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  // unknown mode → the stricter one
  const mode = (opts.pathTools ? entry?.mode : FS_MODE_BY_TOOL[toolName]) ?? "write";
  const src = input as Record<string, unknown>;
  const workspaceRoots = opts.viewMap.roots().flatMap((r) => [r.human, r.agent]);

  let out: Record<string, unknown> | null = null;
  const gated: GatedField[] = [];
  const media = opts.pathTools ? entry?.refs === "media" : false;

  // Every path the fields hold: a string field, or each string of an array
  // field (browser `paths`, image `images`), with the key an event names.
  const targets: Array<{ field: string; key: string; index: number | null; raw: string }> = [];
  for (const field of fields) {
    const v = src[field];
    if (typeof v === "string") targets.push({ field, key: field, index: null, raw: v });
    else if (Array.isArray(v)) {
      v.forEach((el, i) => { if (typeof el === "string") targets.push({ field, key: `${field}[${i}]`, index: i, raw: el }); });
    }
  }

  const deny = (field: string, key: string, index: number | null, path: string, sentinel: string, decision: FsPathDecision | null, reason: string, ruleRef: RuleRef): void => {
    out = out ?? { ...src };
    if (index === null) out[field] = sentinel;
    else {
      // a fresh copy of the array, once, then the denied element replaced
      if (out[field] === src[field]) out[field] = [...(src[field] as unknown[])];
      (out[field] as unknown[])[index] = sentinel;
    }
    const approvalId = decision && decision.allow === false ? decision.approvalId : undefined;
    gated.push({
      tool: toolName, field: key, path, sentinel, decision, reason, ruleRef,
      ...(approvalId ? { approvalId } : {}),
    });
    opts.log?.(`fs-gate: DENIED ${toolName}.${key} → ${path} (${reason})`);
  };

  for (const { field, key, index, raw } of targets) {
    const v = media ? mediaRefPath(raw) : raw;
    if (v === null || v === "") continue;
    // ABSOLUTE paths ALL go to the arbiter — including in-workspace ones. The
    // workspace roots ride along in `workspaceRoots`, so the arbiter allows an
    // ordinary in-workspace path (fs-outbound rule 2) but its rule 1
    // (sensitive-path deny-precedence, "a workspace rooted at ~ must still
    // gate ~/.ssh") STILL fires for a sensitive path that happens to sit
    // inside a workspace root. A proxy-side withinRoots() short-circuit here
    // would make that deny-precedence unreachable — the exact bypass
    // fs-outbound.ts warns about. A RELATIVE path is resolved against the
    // agent's known base, or denied when it escapes an unknown one
    // (resolveRelative).
    const r = resolveRelative(opts.viewMap, v, opts.relativeBase);
    if (r.kind === "unresolved") continue;
    if (r.kind === "escape") {
      deny(field, key, index, r.path, `${DENIED_NAMESPACE}/unresolved/${r.path}`, null,
        `the relative path '${r.path}' leaves the agent's working directory, which the gate does not know for this agent, ` +
          "so the file it names cannot be checked — fail closed; name the file by its absolute path",
        { source: "fail-closed", id: "proxy:relative-escape" });
      continue;
    }
    const norm = r.path;

    let decision: FsPathDecision | null = null;
    let unreachable: string | null = null;
    const timeoutMs = opts.arbiterTimeoutMs ?? DEFAULT_GATE_TIMEOUT_MS;
    try {
      decision = await withTimeout(
        opts.arbiter.fsPathDecision({
          tool: toolName, path: norm, mode, workspaceRoots,
          ...(opts.sessionKey !== undefined ? { sessionKey: opts.sessionKey } : {}),
        }),
        timeoutMs,
        `arbiter fsPathDecision timed out after ${timeoutMs}ms — fail closed`,
      );
    } catch (err) {
      unreachable = (err as Error).message;
    }

    if (decision?.allow) continue;

    // Deny (or unreachable): rewrite into the reserved denied namespace.
    const slug = decision ? "policy" : "unreachable";
    const sentinel = `${DENIED_NAMESPACE}/${slug}${norm}`;
    const reason = decision
      ? decision.reason
      : `arbiter unreachable (${unreachable}) — fail closed`;
    const ruleRef: RuleRef =
      decision?.ruleRef ?? { source: "fail-closed", id: "proxy:arbiter-unreachable" };
    deny(field, key, index, norm, sentinel, decision, reason, ruleRef);
  }

  return { input: out ?? src, gated };
}

/**
 * Where a path a tool field names lands, as far as the gate can know
 * (fs-sync.md §1.4.1, "Relative paths"). Pure.
 *
 *   absolute    `~` expanded, `.`/`..` resolved: the path itself.
 *   relative, base known (the agent resolves against its launch directory,
 *               gate-surface.ts `relativeBase`, and the proxy was told that
 *               directory): base joined and normalized, then gated like any
 *               absolute path. Exact, because the agent joins the same base.
 *   relative, base unknown, escaping (`..` leads after normalization): the
 *               file lies OUTSIDE the agent's working directory, somewhere
 *               the gate cannot name: "escape", and the caller denies it.
 *   relative, base unknown, not escaping: the file lies under the agent's
 *               working directory, which the gate does not know: "unresolved"
 *               and not gated here (the documented residue; what backs it is
 *               in fs-sync.md §1.4.1).
 */
export function resolveRelative(
  viewMap: Pick<ViewMap, "normalize">,
  raw: string,
  base: string | undefined,
): { kind: "absolute"; path: string } | { kind: "escape"; path: string } | { kind: "unresolved"; path: string } {
  const norm = viewMap.normalize(raw);
  if (norm.startsWith("/") || /^[A-Za-z]:[\\/]/.test(norm) || norm.startsWith("\\\\")) return { kind: "absolute", path: norm };
  if (base !== undefined && base.startsWith("/")) return { kind: "absolute", path: viewMap.normalize(`${base}/${raw.trim()}`) };
  if (norm === ".." || norm.startsWith("../") || norm.startsWith("..\\")) return { kind: "escape", path: norm };
  return { kind: "unresolved", path: norm };
}

/**
 * The local path a MEDIA REFERENCE names, as OpenClaw's media loader reads
 * it (image / view_image; openclaw 2026.6.35 createImageTool and
 * media-reference.ts): trimmed, a leading `@` dropped, a `MEDIA:` prefix
 * dropped, a `file:` URL decoded to its path (`file:///x/%2Essh` is
 * `/x/.ssh`; one that does not decode keeps its text minus the scheme, gated
 * all the same). An `http(s)://`, `data:` or `media://` (OpenClaw's own
 * media store) reference is no local path: null, and the net gate reads the
 * URLs. Anything else is returned as written and gated like any path (a
 * relative one is CWD scoping's job). Pure.
 */
export function mediaRefPath(raw: string): string | null {
  let s = raw.trim();
  if (s.startsWith("@")) s = s.slice(1).trim();
  if (!/^media:\/\//i.test(s)) s = s.replace(/^\s*MEDIA\s*:\s*/i, "").trim();
  if (/^(https?:\/\/|data:|media:\/\/)/i.test(s)) return null;
  if (/^file:/i.test(s)) {
    try {
      return fileURLToPath(s);
    } catch {
      return s.replace(/^file:(\/\/)?/i, "");
    }
  }
  return s;
}
