/**
 * unmapped-upload — the local files a tool NO gate table names may send off
 * this computer (guarantees.md §3, "A tool that uploads a local file by its
 * path"; supported-agents.md §2, "The unmapped upload leg").
 *
 * Mandu-new (no reference origin). upload-gate.ts gates the upload tools
 * Mandu has mapped (Claude Code's DesignSync and Artifact tools): their
 * bytes never enter the model context, so the PATH the model wrote is
 * judged. Until 2026-10-17 a tool nobody had mapped was not judged at all:
 * an MCP server's `upload_file{path}`, a claude.ai connector's attachment
 * (Claude Code 2.1.302's Chrome `file_upload{paths}`, a managed agent's
 * `start_task{files}`), a built-in a new release adds before Mandu maps it.
 * Its result is masked whole while unmapped, but the file it sends was kept
 * home only by the confinement, and where the agent's own process reads the
 * file (every client-side attachment does) and sends it to a model API host
 * the egress proxy never carries, by nothing at all under `gated`.
 *
 * THE LEG. For a tool the session's gate surface does not name, every
 * string of its input that names a LOCAL path (absolute, `~/`, a `file://`
 * URL; a relative one only under a path-like key, placed against the
 * agent's launch directory: over-gating is safe) goes to the arbiter's
 * `fileUploadDecision` in its UNMAPPED form (file-upload.ts rule 0 and
 * 4a/5a), on the human plane:
 *   - a tool the session maps after all (its inbound spec names it, a
 *     harness tool, Mandu's own) keeps its own legs: allowed, nothing read;
 *   - a tool of an MCP server the launcher registered as a local process, in
 *     a session the file guard confines, is allowed: that server is a
 *     program the guard and the egress proxy confine like any the agent runs
 *     (so a local filesystem server reading a labelled file keeps working
 *     under `confined`, its result masked as before);
 *   - otherwise the file is judged as a mapped upload's is, with NO host
 *     (the tool's destination is unknown, so no binding releases anything):
 *     a sensitive path, a secret label, a registered secret value in the
 *     bytes, a file of a process, or bytes the arbiter could not read are
 *     held for the person's OK (an Approvals row `fs:<tool>:upload` × path);
 *     nothing at the path (a remote API's `/v1/items`) or a folder with no
 *     secret label passes.
 * A held path's string becomes a path under Mandu's denied namespace
 * (`/mandu/denied/upload/<path>`), which names no file: the tool cannot read
 * the file, whatever its schema accepts, and every other argument is left as
 * the model wrote it. The model reads why in place of the tool's result,
 * and its own call back in its history.
 *
 * THE WINDOW (file-upload.ts). A path judged by its bytes (anything but an
 * exempt tool's) in a call that follows, in the same model turn, a call that
 * may write files is withheld too (`proxy:upload-after-write`): the agent
 * runs the earlier call first, which can put a secret where a clean file, or
 * nothing, was judged a moment ago.
 *
 * FAIL-CLOSED: an arbiter without the op, one that throws or does not
 * answer in time, or more path-like strings than the bound withholds every
 * candidate path of the call.
 *
 * The core is unmapped-upload-core.ts (byte-equal with the openai-proxy's
 * copy, which runs the same leg for Codex); this module adds what is Claude
 * Code's and OpenCode's: which tools the session's gate surface maps, and
 * which earlier calls of a turn may write files. Pure; never throws.
 */

import type { GateSurface } from "./gate-surface.js";

// The pure core (the paths, the arbiter asks, the withheld spelling, the
// notices) is one text in both proxies: unmapped-upload-core.ts.
export * from "./unmapped-upload-core.js";

const own = (o: object | undefined, k: string): boolean => !!o && Object.prototype.hasOwnProperty.call(o, k);

/** Does any table of the session's gate surface name `tool`? (The upload
 *  table too: a mapped upload tool is upload-gate.ts's.) The leg runs only
 *  where this is false. Pure. */
export function surfaceNamesTool(surface: GateSurface, tool: string): boolean {
  return own(surface.exec, tool) || own(surface.execOutput, tool) || own(surface.net, tool) || own(surface.paths, tool)
    || own(surface.dispatch, tool) || own(surface.refuse, tool) || own(surface.refuseArgs, tool) || own(surface.stdin, tool)
    || own(surface.patch, tool) || own(surface.upload, tool);
}

/** Tools that write no file of the person's (their effect is the agent's
 *  own bookkeeping, a question, a notification, a reply text): not a
 *  "possible writer" for the window rule. Names off the captured wires
 *  (arbiter claude-code-inbound.ts, the OpenCode fixtures). */
export const NON_WRITING_TOOLS: ReadonlySet<string> = new Set([
  "TodoWrite", "ToolSearch", "AskUserQuestion", "ExitPlanMode", "EnterPlanMode", "PushNotification",
  "EndConversation", "SendFeedback", "ListMcpResourcesTool", "ReadMcpResourceTool",
  // the same bookkeeping on OpenCode's and Codex's wires
  "todowrite", "todoread", "question", "skill", "update_plan",
  // upload tools that save nothing here (Artifact `read` and ArtifactData
  // `out_dir` do write: they stay writers)
  "DesignSync", "ArtifactComments",
]);

/**
 * May a call of `tool`, earlier in the same model turn, change a local file
 * before a later call of that turn reads it? THE WINDOW rule
 * (upload-gate.ts, this module): true unless the surface names it as a
 * read-only path tool or a network fetch, or it is one of
 * NON_WRITING_TOOLS. A shell, a write tool, a patch, a dispatcher, a
 * subagent and every tool Mandu has not mapped may. Pure.
 */
export function possibleWriter(tool: string, surface: GateSurface): boolean {
  const p = own(surface.paths, tool) ? surface.paths[tool] : undefined;
  if (p !== undefined) return p.mode === "write";
  if (own(surface.exec, tool) || own(surface.stdin, tool) || own(surface.patch, tool) || own(surface.dispatch, tool)) return true;
  if (own(surface.net, tool)) return false;
  return !NON_WRITING_TOOLS.has(tool);
}
