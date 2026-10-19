/**
 * services/exec-box-shims — write the PATH-shadow shim dir whose commands route
 * through `mandu-exec-box` (docs/design/integrity/exec-routing.md §7).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code; mirrors services/exec-shims.ts (the exec-wrap shim writer).
 *   The difference is the target: an exec-box shim execs the committed
 *   `mandu-exec-box` bin (interceptors/exec-supervisor/src/bin/mandu-exec-box.rs),
 *   which BOXES it in the net-off AgentShell — vs the exec-wrap shim, which only
 *   GATES a symbol-as-command via the arbiter. The bin strips its own shim dir
 *   (MANDU_EXEC_BOX_SHIM_DIR) from PATH before it re-searches for the real
 *   command, so a boxed `cat` cannot recurse back into the shim.
 *
 * VIEW WIRING (the fs-view co-design, exec-routing.md §7.2): when the launcher's
 * fs-view service is active the shims BAKE the session's HumanView↔AgentView
 * pair (MANDU_AGENTVIEW_ROOT / MANDU_WORKSPACE), so the box RW-binds the
 * AgentView BOTH over the workspace path AND at its own path (the identity
 * bind). fs-view cwd's the live agent INTO the AgentView worktree, so the
 * identity bind is what makes a boxed command's own cwd writable (`sed -i`,
 * `sort -o`, `xargs mv` inside the workspace work); writes land in the
 * AgentView worktree, where the fs-sync watcher already syncs them back —
 * boxed writes and unboxed agent writes take the same path, nothing
 * double-applies. Baked UNCONDITIONALLY (not default-preserving like the
 * arbiter sock): the pair is per-session identity — an ambient override could
 * point a boxed write into ANOTHER session's view. Without a view pair (non-git
 * workspace) the box stays RO-root with only /tmp writable; the shims then
 * bake the launch's project directory alone as MANDU_WORKSPACE (and unset
 * any ambient MANDU_AGENTVIEW_ROOT, so an inherited one cannot pair with
 * it), which the box uses to re-bind a project under /tmp read-only over
 * its fresh /tmp (checklist a7) — or, when the launcher found the integrity
 * axis OFF (`secrets`, `off`: the HumanView is the agent's only view), to
 * bind the project WRITABLE at its own path (MANDU_EXEC_BOX_WORKSPACE_RW=1),
 * so boxed in-place writers (`sed -i`, `sort -o`) work there as they do
 * unboxed (exec-routing.md §7.2, "The workspace without an AgentView").
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { publishFile } from "../safe-file.js";

/** The session view pair the shims bake (from plan.viewMap / fs-view). */
export interface ExecBoxView {
  /** The AgentView worktree root (the agent's rewritten cwd lives under it). */
  agentViewRoot: string;
  /** The HumanView workspace root the AgentView is bound over in-box. */
  workspace: string;
}

export function writeExecBoxShims(
  cmds: string[],
  boxBinPath: string,
  arbiterSock: string,
  scopeRunDir: string,
  view?: ExecBoxView,
  landlockApply?: string,
  /** The rung-2 clean-box posture (exec-routing.md §8.5). `true` bakes
   *  `MANDU_EXEC_CLEAN_BOX="1"`, `false` bakes `"0"` — a HARD export either
   *  way (the launcher decided; ambient env must not flip a session's
   *  posture). `undefined` bakes nothing (the bin's own default: off). */
  cleanBox?: boolean,
  /** The launch's project directory (realpath), baked as MANDU_WORKSPACE
   *  when there is NO view pair: the box re-binds it read-only over its
   *  fresh /tmp when it lives there (sandbox.rs `tmpfs_keep_binds`,
   *  open-source-release checklist a7), else every boxed command in a
   *  `/tmp/…` project died `bwrap: Can't chdir`. Ignored with a view pair
   *  (the pair's workspace wins). */
  projectRoot?: string,
  /** exec-routing.md §8.5.3: the session guard's clean-run socket, baked
   *  as `MANDU_EXEC_CLEAN_SOCK` (the box then asks the guard to run the clean
   *  attempt instead of running it in the agent's tree). */
  cleanSock?: string,
  /** exec-routing.md §7.2, "The workspace without an AgentView": with NO
   *  view pair, `true` bakes `MANDU_EXEC_BOX_WORKSPACE_RW="1"` so the box
   *  binds `projectRoot` WRITABLE at its own path (the launcher decides it:
   *  integrity axis OFF). Anything else bakes `unset` — HARD both ways, so
   *  an ambient value never makes an integrity session's workspace writable. */
  workspaceWritable?: boolean,
  /** exec-routing.md §4, "The bwrap probe, kept by content": the sha256 of
   *  a bubblewrap the launcher saw advertise `--disable-userns`
   *  (exec-box-setup.ts `keptBwrapDisableUserns`), baked as
   *  `MANDU_BWRAP_DISABLE_USERNS_SHA256`; the box then skips its own
   *  `bwrap --help` when the bubblewrap it resolved has exactly those bytes.
   *  Absent: a HARD unset (the box probes for itself). */
  bwrapDisableUsernsSha256?: string,
): string {
  const clean = cmds.map((c) => c.trim()).filter(Boolean);
  if (clean.length === 0) throw new Error("mandu: --exec-box given no commands to shadow");

  const shimDir = join(scopeRunDir, "exec-box-shims");
  mkdirSync(shimDir, { recursive: true });

  const viewExports = view
    ? `export MANDU_AGENTVIEW_ROOT="${view.agentViewRoot}"\n` +
      `export MANDU_WORKSPACE="${view.workspace}"\n`
    : projectRoot
      ? `unset MANDU_AGENTVIEW_ROOT\nexport MANDU_WORKSPACE="${projectRoot}"\n`
      : "";
  const workspaceRwExport = !view && projectRoot && workspaceWritable === true
    ? `export MANDU_EXEC_BOX_WORKSPACE_RW="1"\n`
    : "unset MANDU_EXEC_BOX_WORKSPACE_RW\n";
  // Pin the in-box Landlock applier path (a HARD export, like the view pair:
  // the box bin's sibling-of-exe fallback probes existence on the HOST, which
  // cannot see the AgentView bind shadowing the path inside the box's mount ns).
  const applyExport = landlockApply ? `export MANDU_LANDLOCK_APPLY="${landlockApply}"\n` : "";
  const cleanExport = (cleanBox === undefined ? "" : `export MANDU_EXEC_CLEAN_BOX="${cleanBox ? "1" : "0"}"\n`) +
    (cleanSock ? `export MANDU_EXEC_CLEAN_SOCK="${cleanSock}"\n` : "unset MANDU_EXEC_CLEAN_SOCK\n");
  const bwrapKeptExport = bwrapDisableUsernsSha256 !== undefined && /^[0-9a-f]{64}$/.test(bwrapDisableUsernsSha256)
    ? `export MANDU_BWRAP_DISABLE_USERNS_SHA256="${bwrapDisableUsernsSha256}"\n`
    : "unset MANDU_BWRAP_DISABLE_USERNS_SHA256\n";
  for (const cmd of clean) {
    const shim = join(shimDir, cmd);
    // Default-preserving arbiter-sock (parity: exec-shims.ts) so a shim invoked
    // outside the launcher's env still finds the socket the launcher baked in.
    // MANDU_EXEC_BOX_SHIM_DIR lets the bin de-shim the PATH (no recursion).
    const body =
      `#!/usr/bin/env bash\n` +
      `export MANDU_ARBITER_SOCK="\${MANDU_ARBITER_SOCK:-${arbiterSock}}"\n` +
      `export MANDU_EXEC_BOX_SHIM_DIR="${shimDir}"\n` +
      viewExports +
      workspaceRwExport +
      applyExport +
      cleanExport +
      bwrapKeptExport +
      `exec "${boxBinPath}" --cwd "$PWD" -- "${cmd}" "$@"\n`;
    // Never through a planted link (safe-file.ts; exec-shims.ts).
    publishFile(shim, body, { mode: 0o755 });
  }
  return shimDir;
}
