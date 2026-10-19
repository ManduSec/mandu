/**
 * session-paths — PURE per-session path facts derived from a session's events:
 * the agent process CWD and the AgentView/HumanView root dirs, "when known".
 *
 * Mandu-new (NO reference origin). Same design rule as test-setup.ts /
 * view-model.ts: pure `events → data`, no DOM/no I/O, so it unit-tests under
 * `node --test`. Two consumers:
 *   - test-setup.ts folds all three facts into the TEST-session setup banner;
 *   - inspector/fs-git-routes.ts resolves /api/git's session→workspace root from
 *     `sessionViewRoots(...).humanViewRoot`.
 *
 * TRUTHFULNESS RULE (the cc0c04a posture): every fact here is DERIVED from data
 * the session actually recorded — never guessed from the dashboard's own
 * environment. When the events don't carry it, the answer is null and the UI
 * says "not recorded", it does not invent a plausible path.
 *
 *   - CWD comes from the agent's OWN system-prompt environment block on the
 *     session's tllm_call `fullInput` (source:"agent" blocks ONLY — a poisoned
 *     tool_result lives in source:"conversation" blocks and can never forge it).
 *   - View roots come from the dual-view chokepoints' own events: fs_action
 *     Redirects (fs-supervisor: input.symbolized = AgentView path,
 *     input.original = HumanView path) and path_rewrite typed-path fields
 *     (anthropic-proxy P2 ViewMap: rewrite.agent / rewrite.human spellings).
 *     A Track-A-only session (model-context chokepoint only, no dual-view FS
 *     layer) records neither → both roots are null, honestly.
 */

import { dirname } from "node:path";

import type { ManduEvent } from "./event-model.js";

/** The deepest directory that is an ancestor of (or equal to) every input dir.
 *  null for an empty list. (Moved here from server.ts so test-setup.ts and the
 *  /api/git resolver share ONE implementation.) */
export function commonDirPrefix(dirs: string[]): string | null {
  if (dirs.length === 0) return null;
  let segs = dirs[0]!.split("/");
  for (const d of dirs.slice(1)) {
    const other = d.split("/");
    let i = 0;
    while (i < segs.length && i < other.length && segs[i] === other[i]) i++;
    segs = segs.slice(0, i);
  }
  const prefix = segs.join("/");
  return prefix.length > 0 ? prefix : "/";
}

/** The Claude Code system-prompt environment line naming the agent's CWD.
 *  Format varies by agent version — both observed spellings are matched:
 *    ` - Primary working directory: /path`   (Claude Code "# Environment" list)
 *    `Working directory: /path`              (Claude Code `<env>` block)
 *  Absolute paths only; the value runs to end-of-line. */
const CWD_LINE =
  /(?:^|\n)[ \t]*(?:-[ \t]*)?(?:primary[ \t]+|current[ \t]+)?working directory:[ \t]*(\/[^\n]*)/i;

/**
 * The agent process working directory (the workspace the session ran in), parsed
 * from the agent's own system prompt on the session's model calls. Reads ONLY
 * `fullInput` blocks tagged source:"agent" — the agent's own prompt text — so
 * untrusted conversation content (tool_results) can never forge it. Returns the
 * first match, or null when no model call recorded an environment block
 * (offline replays, non-Claude agents): "not recorded", never a guess.
 */
export function sessionCwd(events: ManduEvent[]): string | null {
  for (const e of events) {
    // A claimed event (arbiter-human-plane.md §10.2) is the sender's word:
    // its "agent" block could name any folder (the Scan reads this cwd).
    if (e.claimed === true) continue;
    if ((e.kind !== "tllm_call" && e.kind !== "ullm_call") || !e.fullInput) continue;
    for (const b of e.fullInput.blocks) {
      if (b.source !== "agent") continue;
      const m = CWD_LINE.exec(b.text);
      if (m) return m[1]!.trim();
    }
  }
  return null;
}

export interface SessionViewRoots {
  /** Deepest common ancestor of the AgentView-side paths the session's dual-view
   *  events recorded, or null when it recorded none. */
  agentViewRoot: string | null;
  /** Deepest common ancestor of the HumanView-side paths (the real user
   *  workspace files), or null. This is also /api/git's workspace root. */
  humanViewRoot: string | null;
}

/**
 * Derive the AgentView / HumanView root dirs from the session's own dual-view
 * events. Two sources, both authoritative for their layer:
 *
 *   - `fs_action` (kernel layer, fs-supervisor events.rs): a Redirect carries
 *     input.symbolized = the AgentView twin path and input.original = the real
 *     HumanView path, both bare absolute paths. Gated on `original` being an
 *     absolute path so Passthrough rows ("(untracked path)", original:null) and
 *     the anthropic-proxy fs-gate's "Tool.field → path" strings are excluded.
 *   - `path_rewrite` (wrapper layer, anthropic-proxy P2 ViewMap): rewrite.human /
 *     rewrite.agent are the two spellings of one path. TYPED path fields only —
 *     field "command" (Bash text), "content" (tool_result free text) and "text"
 *     (conversation free text) carry prose or root-pair reports, not bare
 *     paths, and a null field is uncorrelated text; all skipped.
 *
 * Each path contributes its dirname; the root is the common ancestor. Fail-soft:
 * a session with neither event kind (a Track-A-only run) yields both null.
 */
export function sessionViewRoots(events: ManduEvent[]): SessionViewRoots {
  const agent: string[] = [];
  const human: string[] = [];
  for (const e of events) {
    // Claimed events (arbiter-human-plane.md §10.2) never pick the repository
    // /api/git runs on.
    if (e.claimed === true) continue;
    if (e.kind === "fs_action") {
      const orig = e.input?.original;
      if (typeof orig !== "string" || !orig.startsWith("/")) continue;
      human.push(dirname(orig));
      const sym = e.input?.symbolized;
      if (typeof sym === "string" && sym.startsWith("/")) agent.push(dirname(sym));
    } else if (e.kind === "path_rewrite" && e.rewrite) {
      const { field, human: h, agent: a } = e.rewrite;
      if (field === null || field === "command" || field === "content" || field === "text") continue;
      if (h.startsWith("/") && a.startsWith("/")) {
        human.push(dirname(h));
        agent.push(dirname(a));
      }
    }
  }
  return { agentViewRoot: commonDirPrefix(agent), humanViewRoot: commonDirPrefix(human) };
}
