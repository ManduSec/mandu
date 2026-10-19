/**
 * tools — the three mandu-policy tools and how each arbiter answer becomes
 * an envelope (docs/design/ui/policy-surface.md §8.5.1).
 *
 * Mandu-new. Pure mapping over a PolicyArbiter; no I/O of its own. Every
 * success goes through envelope.ts `toolResult`, so the result the model sees
 * is token-only (see that file's header for why).
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { posix } from "node:path";

import type { PolicyArbiter, ProposeAnswer, TestFlowArgs } from "./arbiter-client.js";
import { FIXED_MESSAGES, toolResult } from "./envelope.js";

export interface PolicyToolDeps {
  arbiter: PolicyArbiter;
  /** The agent session (MANDU_SCOPE_ID): attribution + per-session caps. */
  sessionKey?: string;
  /** The project directory the session was launched in (MANDU_PROJECT_DIR,
   *  the launcher's HumanView launch directory): a relative path in an edit
   *  is read there. Absent: a relative path is refused with a problem. */
  projectDir?: string;
  /** Does this path exist? (tests; default `existsSync`). */
  exists?: (path: string) => boolean;
  /** The home directory a `~/` path is checked in (tests; default `homedir()`). */
  home?: string;
}

const BOUNDARIES = new Set(["network", "filesystem", "shell", "model_context"]);

export const READ_TOOL = {
  name: "mandu_policy_read",
  description:
    "Read the Mandu protection rules for this machine as structured data: secret files and their levels, " +
    "trusted and untrusted sources, release rules, allowed destinations, the models the user declared " +
    "(name, address, whether it is the user's own model, and the NAME of the variable holding its key, never the key), " +
    "and the rule changes still waiting for the user. Values that are not plain paths or hosts are shown as (withheld).",
  inputSchema: { type: "object" as const, additionalProperties: false, properties: {} },
} as const;

export const TEST_TOOL = {
  name: "mandu_policy_test",
  description:
    "Ask Mandu what would happen to data, without doing anything: would content from `source` reach you " +
    "masked, and could it be sent to `destination` (allow, ask the user, or block)? Nothing is recorded.",
  inputSchema: {
    type: "object" as const,
    additionalProperties: false,
    properties: {
      source: {
        type: "object",
        additionalProperties: false,
        properties: {
          tool: { type: "string", description: "The tool that produced the data (default WebFetch)." },
          origin: { type: "string", description: "Where it came from: a URL, a file path, or a channel." },
        },
      },
      destination: { type: "string", description: "Where it would go: a URL or host." },
      boundary: { type: "string", enum: ["network", "filesystem", "shell", "model_context"] },
    },
  },
} as const;

const PROPOSE_DESCRIPTION =
  "Change the Mandu protection rules with a list of typed edits (never YAML). " +
  "A change that only TIGHTENS protection is applied at once and the user can undo it; the locks applied " +
  "directly are lock-path at no-model (no bindings) and lock-blob above public (an old file version, by its " +
  "id, hidden from the agent's git history). Anything that LOOSENS protection (trusting a source, " +
  "allowing a destination, a lock below no-model, removing a lock, an allow rule) is NOT applied: it waits for the user to " +
  "approve it on the Mandu dashboard's Approvals page. Never tell the user a waiting change is done; say it is waiting for them. " +
  "One call is judged whole: if any edit in it loosens protection, ALL of its edits wait, so propose the tightenings in a call " +
  "of their own and the loosenings in another. Write a project file as its FULL absolute path, your working directory " +
  "followed by the file (for example `/home/me/proj/.env` and `/home/me/proj/keys`), or as a pattern starting with `**/`; " +
  "`/.env` or `/keys` would name a path at the root of the machine, not the project's. " +
  "A relative path (`.env`, `config/keys`) is read in the project directory, and the result's `resolved` gives the full path it was read as: " +
  "tell the user that path. A file to lock must exist (use a `**/` pattern for files not created yet). " +
  "The declared models cannot be changed with this tool (Mandu refuses it); if the user wants a model added, " +
  "changed or removed, tell them to do it in Mandu's Settings › Models. " +
  "Give a short plain `reason`; the user sees it next to the change.";

/** The propose tool, with the edit schema embedded when the arbiter gave one. */
export function proposeTool(editsSchema: unknown | undefined) {
  return {
    name: "mandu_policy_propose",
    description: editsSchema === undefined
      ? PROPOSE_DESCRIPTION
      : `${PROPOSE_DESCRIPTION}\n\nThe edits follow this JSON Schema:\n${JSON.stringify(editsSchema)}`,
    inputSchema: {
      type: "object" as const,
      required: ["edits", "reason"],
      additionalProperties: false,
      properties: {
        edits: editsSchema !== undefined ? editsSchema : { type: "array", minItems: 1, items: { type: "object" } },
        reason: { type: "string", maxLength: 280, description: "Why, in one short sentence for the user." },
      },
    },
  };
}

export async function runRead(deps: PolicyToolDeps) {
  const law = await deps.arbiter.policyExplain({ audience: "agent", ...(deps.sessionKey ? { sessionKey: deps.sessionKey } : {}) });
  return toolResult({ tool: "mandu_policy_read", law });
}

export async function runTest(deps: PolicyToolDeps, args: Record<string, unknown>) {
  const req: TestFlowArgs = {};
  const src = args.source;
  if (src !== undefined && src !== null && typeof src === "object" && !Array.isArray(src)) {
    const s = src as Record<string, unknown>;
    req.source = {
      ...(typeof s.tool === "string" ? { tool: s.tool } : {}),
      ...(typeof s.origin === "string" ? { origin: s.origin } : {}),
    };
  }
  if (typeof args.destination === "string") req.destination = args.destination;
  if (typeof args.boundary === "string" && BOUNDARIES.has(args.boundary)) req.boundary = args.boundary as TestFlowArgs["boundary"];
  if (req.destination !== undefined && req.boundary === undefined) req.boundary = "network";
  const r = await deps.arbiter.testFlow(req);
  const d = r.egress?.decision;
  // The caller's source and destination are never echoed back.
  return toolResult({
    tool: "mandu_policy_test",
    masked: r.inbound.trust === "UNTRUSTED",
    level: r.probe.level,
    egress: d === undefined ? null : d.allow ? "allow" : d.requiresApproval ? "ask" : "block",
    stage: r.egress?.stage ?? null,
    rule: d?.ruleRef?.id ?? null,
  });
}

const rows = (l: ReadonlyArray<{ facet: string; subject: string }> | undefined) =>
  (l ?? []).map((c) => ({ facet: c.facet, subject: c.subject }));

/** Map a PolicyProposeResult onto the propose envelope. `detail` prose is dropped. */
export function proposeEnvelope(r: ProposeAnswer): Record<string, unknown> {
  const tool = "mandu_policy_propose";
  if ("refused" in r) {
    const message = r.refused === "invalid" ? FIXED_MESSAGES.invalid : r.refused === "stale" ? FIXED_MESSAGES.stale : FIXED_MESSAGES.proposalCap;
    return { tool, applied: false, message, ...(r.refused !== "proposal-cap" ? { problems: r.problems ?? [] } : {}) };
  }
  if (r.applied) {
    if (r.changeId === null) return { tool, applied: true, message: FIXED_MESSAGES.noChange };
    return { tool, applied: true, message: FIXED_MESSAGES.applied, changeId: r.changeId, tightens: rows(r.delta) };
  }
  const message = r.duplicate ? FIXED_MESSAGES.duplicate : r.why === "tightening-cap" ? FIXED_MESSAGES.pendingCap : FIXED_MESSAGES.pendingRelax;
  return { tool, applied: false, message, proposalId: r.proposalId, relaxes: rows(r.relaxes) };
}

/** The ops whose `path` names a file or folder (policy-edit-schema.ts). */
const PATH_OPS: ReadonlySet<string> = new Set(["lock-path", "unlock-path"]);

/** A gitignore-style pattern, as the arbiter tells one from a path
 *  (arbiter/policy/path-glob.ts `hasGlobMeta`). */
function hasGlobMeta(p: string): boolean {
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "\\") { i++; continue; }
    if (c === "*" || c === "?" || c === "[") return true;
  }
  return false;
}

/** What `resolveEditPaths` made of a propose call's edits. */
export interface ResolvedEdits {
  /** The edits as the arbiter gets them: each relative `path` replaced by
   *  its absolute form. */
  edits: unknown;
  /** Each relative path and the absolute path it was read as, stated back
   *  so the model (and through it the user) sees what was labelled. */
  resolved: Array<{ from: string; path: string }>;
  /** Why the call is refused before it reaches the arbiter (none: sent). */
  problems: string[];
}

/**
 * The paths of a propose call, read the way the user means them
 * (2026-10-04, policy-surface.md §8.5.1). Pure over `deps.exists`.
 *
 *   - A RELATIVE path (`.env`, `config/keys`, `./x`, `src/*.pem`) is read in
 *     the project directory (`deps.projectDir`): the edit goes to the arbiter
 *     with the absolute path, and the result states it back. One that climbs
 *     out of the project (`../x`) is refused: a path outside the project is
 *     written whole, so the user sees on the review exactly what it names.
 *     With no project directory known, a relative path is refused with a
 *     problem saying how to write it.
 *   - A path that does NOT EXIST is refused for `lock-path` (a pattern is
 *     not checked): the model meant some file, and labelling a path nothing
 *     is at protects nothing while the model reports the file protected.
 *     `/.env` (an absolute path at the root of the machine) is the case
 *     seen live: the problem names the project's file when one is there
 *     ("did you mean"), and otherwise says to write an existing file's full
 *     path or a `**`-pattern for files not created yet. `unlock-path` is
 *     not checked: a lock may outlive its file.
 *   - Absolute, `~/` and `**` paths are otherwise passed as written; every
 *     other check stays the arbiter's (the validator, the tightening rule).
 */
export function resolveEditPaths(edits: unknown, deps: Pick<PolicyToolDeps, "projectDir" | "exists" | "home">): ResolvedEdits {
  const out: ResolvedEdits = { edits, resolved: [], problems: [] };
  if (!Array.isArray(edits)) return out;
  const exists = deps.exists ?? existsSync;
  const home = deps.home ?? homedir();
  const project = typeof deps.projectDir === "string" && deps.projectDir.startsWith("/")
    ? posix.normalize(deps.projectDir).replace(/(.)\/+$/, "$1")
    : undefined;
  const where = project !== undefined ? ` (the project directory is ${project})` : "";
  out.edits = edits.map((e, i) => {
    if (e === null || typeof e !== "object" || Array.isArray(e)) return e;
    const edit = e as Record<string, unknown>;
    if (typeof edit.op !== "string" || !PATH_OPS.has(edit.op) || typeof edit.path !== "string" || edit.path === "") return e;
    const raw = edit.path;
    const at = `edits[${i}].path`;
    let path = raw;
    // `~…` and `**…` are the arbiter's to read (or refuse: `~bob/x`).
    if (!raw.startsWith("/") && !raw.startsWith("~") && !raw.startsWith("**")) {
      if (project === undefined) {
        out.problems.push(`${at}: ${raw} is a relative path and Mandu does not know the project directory here; write the file's full path, e.g. /home/me/proj/${raw.replace(/^\.\//, "")}`);
        return e;
      }
      path = posix.normalize(posix.join(project, raw)).replace(/(.)\/+$/, "$1");
      if (path !== project && !path.startsWith(project === "/" ? "/" : `${project}/`)) {
        out.problems.push(`${at}: ${raw} leaves the project directory ${project}; write the full path of a file outside it`);
        return e;
      }
      out.resolved.push({ from: raw, path });
    }
    if (edit.op === "lock-path" && !hasGlobMeta(path) && !exists(path === "~" ? home : path.startsWith("~/") ? posix.join(home, path.slice(2)) : path)) {
      const inProject = project !== undefined && path.startsWith("/") && path !== project && !path.startsWith(`${project}/`)
        ? posix.join(project, path.replace(/^\/+/, ""))
        : undefined;
      out.problems.push(inProject !== undefined && exists(inProject)
        ? `${at}: ${path} does not exist; did you mean ${inProject}? A path starting with / is read from the root of the machine, not the project`
        : `${at}: ${path} does not exist${where}; write the full path of an existing file, or a pattern such as **/${posix.basename(path)} for files not created yet`);
      return e;
    }
    return path === raw ? e : { ...edit, path };
  });
  return out;
}

export async function runPropose(deps: PolicyToolDeps, args: Record<string, unknown>) {
  const paths = resolveEditPaths(args.edits, deps);
  if (paths.problems.length > 0) {
    return toolResult({ tool: "mandu_policy_propose", applied: false, message: FIXED_MESSAGES.invalid, problems: paths.problems });
  }
  const r = await deps.arbiter.policyPropose({
    edits: paths.edits,
    ...(typeof args.reason === "string" ? { reason: args.reason } : {}),
    ...(deps.sessionKey ? { sessionKey: deps.sessionKey } : {}),
  });
  return toolResult({ ...proposeEnvelope(r), ...(paths.resolved.length > 0 ? { resolved: paths.resolved } : {}) });
}
