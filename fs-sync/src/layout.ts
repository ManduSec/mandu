/**
 * layout — view physical layout (workspace id + repo/agentview/lock paths).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-paths.ts
 *   Purpose: the canonical "$HOME/.mandu/workspaces/<workspace-id>/" layout
 *   (repo.git/ agentview/ workspace.json commit.lock conflicts.log) described in
 *   docs/adfi-reference/design/fs-level-tracking.md.
 *
 * Adaptation for Mandu (OpenClaw coupling stripped):
 *   - adfi-dualview hardcoded the state base to `$HOME/.mandu`. The OS-level
 *     fs-supervisor (Wave 4) needs to place view state per-scope / per-agent
 *     and tests need a temp dir, so the base is now an explicit `stateBase`
 *     argument threaded through a `ViewLayout` value object instead of a
 *     module-level homedir() default. (`defaultStateBase()` gives the path
 *     table's default for standalone use.)
 *   - The `dualviewSymbolDbPath()` helper is REMOVED: the arbiter owns the symbol
 *     DB, fs-sync never opens it (it goes through src/arbiter-client.ts).
 *   - The `workspaceId` (state-dir name) was `encodeURIComponent(canonicalPath)`
 *     in the reference (docs/adfi-reference/design/on-demand-tracking.md). Mandu
 *     uses `<basename>-<sha256(path)[:12]>` instead: percent-encoding expands every
 *     `/` to `%2F`, collapsing the whole absolute path into ONE filename component
 *     that can exceed NAME_MAX (255 bytes) on deep real workspaces → ENAMETOOLONG
 *     when the state dir is created. The hash is bounded + collision-free and the
 *     basename keeps the dir human-recognizable. Reversibility is unaffected — the
 *     canonical path is persisted in workspace.json (`workspacePath`); nothing
 *     decodes the dir name (the dashboard resolves workspaces from event paths).
 *   - Pure path math otherwise; no OpenClaw imports existed here to remove.
 */

import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, posix, resolve } from "node:path";

import { type ManduPathEnv, manduPath } from "./generated/mandu-paths.js";

export const VIEW_SCHEMA_VERSION = 1;

export interface ViewWorkspaceMetadata {
  schemaVersion: number;
  /** Canonical absolute HumanView (real workspace) path. */
  workspacePath: string;
  /** Filesystem-safe state-dir name: `<basename>-<sha256(workspacePath)[:12]>`. */
  workspaceId: string;
}

/** Return the canonical absolute workspace path used for view identity. */
export function canonicalWorkspacePath(workspacePath: string): string {
  const resolved = resolve(workspacePath);
  try {
    return realpathSync(resolved);
  } catch {
    return resolved;
  }
}

/**
 * Encode a canonical workspace path as a single, filesystem-safe, BOUNDED-length
 * directory name: `<sanitized-basename>-<sha256(path)[:12]>`.
 *
 * The basename is cosmetic — it tells a human which workspace a state dir belongs
 * to at a glance; the 12-hex sha256 prefix carries identity + collision-freedom.
 * Two distinct absolute paths never collide (the hash is over the full path, not
 * the basename). Nothing reverses this name: the canonical path is stored in
 * workspace.json (`workspacePath`). Total length is bounded (≤ ~53 chars), so it
 * cannot exceed NAME_MAX the way the old `encodeURIComponent` scheme could.
 */
export function workspaceIdFor(workspacePath: string): string {
  const canonical = canonicalWorkspacePath(workspacePath);
  const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
  const base = basename(canonical).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 40);
  return `${base || "root"}-${hash}`;
}

/** The default view state base when the caller does not specify one: the
 *  path table's `view-state`, the Mandu home's `state/` (`~/.mandu/state`
 *  unless MANDU_HOME moves the home; docs/design/architecture/on-disk-layout.md §5).
 *  Pure for an explicit `env` and `home`.
 *  MIRRORED by the arbiter's secret walk (`arbiter/policy/secret-discovery.ts`
 *  `defaultStateBase`, which prunes it and reads `workspace.json` below it to
 *  find the AgentView worktrees): change the metadata shape here and there
 *  together. */
export function defaultStateBase(env: ManduPathEnv = process.env, home: string = homedir()): string {
  return manduPath("view-state", env, home);
}

/** The name of Mandu's own directory under a home (`.mandu`), from the
 *  path table. A workspace walk never enters a directory of this name
 *  (ignored.ts, the human-edit clock). */
export const MANDU_HOME_DIR_NAME: string = posix.basename(manduPath("mandu-home", {}, "/"));

/**
 * Resolved view layout for one tracked workspace. All physical state lives
 * OUTSIDE the workspace: the workspace itself stays the pristine HumanView.
 */
export class ViewLayout {
  /** Canonical HumanView path (the user's real workspace dir). */
  readonly humanPath: string;
  readonly workspaceId: string;
  /** `<stateBase>/workspaces/<workspace-id>/`. */
  readonly workspaceDir: string;

  constructor(workspacePath: string, stateBase: string = defaultStateBase()) {
    this.humanPath = canonicalWorkspacePath(workspacePath);
    this.workspaceId = workspaceIdFor(this.humanPath);
    this.workspaceDir = join(stateBase, "workspaces", this.workspaceId);
  }

  /** The SHADOW substrate repo (fs-sync.md §3): a bare repo addressed
   * with GIT_WORK_TREE=<workspace> that owns ALL fs-sync git state — tracking
   * commits, mdu-main/mdu-trusted refs, the agentview worktree registration.
   * The workspace's own .git (if any) is never touched. */
  get gitDir(): string {
    return join(this.workspaceDir, "repo.git");
  }

  /** The AgentView git worktree (symbolized content the agent sees). */
  get agentViewPath(): string {
    return join(this.workspaceDir, "agentview");
  }

  get workspaceJsonPath(): string {
    return join(this.workspaceDir, "workspace.json");
  }

  get commitLockPath(): string {
    return join(this.workspaceDir, "commit.lock");
  }

  /** The ignored-file manifest (ignored.ts): per path the HumanView and
   *  AgentView hashes of the twins fs-sync keeps OUTSIDE git. */
  get ignoredManifestPath(): string {
    return join(this.workspaceDir, "ignored.json");
  }

  get conflictsLogPath(): string {
    return join(this.workspaceDir, "conflicts.log");
  }

  metadata(): ViewWorkspaceMetadata {
    return {
      schemaVersion: VIEW_SCHEMA_VERSION,
      workspacePath: this.humanPath,
      workspaceId: this.workspaceId,
    };
  }
}
