# Design: On-Demand DualView Tracking

## Goal

Enable Mandu file tracking on directories the agent reads or writes without
placing file-tracking state inside the Human File System.

## Canonical Storage

All on-demand tracking state lives under:

```text
$HOME/.dualview/workspaces/<workspace-id>/
  repo.git/
  agentview/
  workspace.json
  commit.lock
  conflicts.log
```

`workspace-id` is `encodeURIComponent(canonicalAbsPath)`.

Examples:

```text
/tmp/a-b/c                              -> %2Ftmp%2Fa-b%2Fc
/tmp/a/b-c                              -> %2Ftmp%2Fa%2Fb-c
/tmp/pinchbench/0001/agent_workspace    -> %2Ftmp%2Fpinchbench%2F0001%2Fagent_workspace
```

The workspace id is a single directory name. It is not a nested mirror of the
workspace path.

## Filesystem Views

```text
<workspace>/                            Human File System
  src/App.tsx                           resolved/raw content

$HOME/.dualview/workspaces/<id>/
  repo.git/                             Mandu git database
  agentview/                            Agent File System
    src/App.tsx                         symbolized content
```

Mandu git commands use `repo.git` as `GIT_DIR` and either the Human File System
or `agentview` as `GIT_WORK_TREE`, depending on the operation.

## Identity

Workspace identity is derived from the canonical absolute path:

1. `resolve(workspacePath)`
2. `realpath` if it succeeds
3. `encodeURIComponent(canonicalPath)`

`workspace.json` stores the canonical path and encoded id so registry loading
does not have to infer identity from directory structure.

## Registry

The in-memory registry maps canonical workspace paths to:

```typescript
interface TrackedRoot {
  workTree: string;      // Human File System root
  gitDir: string;        // $HOME/.dualview/workspaces/<id>/repo.git
  trustedPath: string;   // $HOME/.dualview/workspaces/<id>/agentview
}
```

`trustedPath` is a compatibility field name in the TypeScript API. Its value is
always the canonical `agentview` path.

On startup, Mandu scans `$HOME/.dualview/workspaces/*/workspace.json` and loads
entries that have both `repo.git` and `agentview`.

## On-Demand Algorithm

When a file path needs tracking:

1. Walk upward from the path and reuse any registered ancestor root.
2. Otherwise, use the file's parent directory as the candidate root.
3. If no child roots exist, initialize a new DualView workspace.
4. If one child root exists, migrate it upward while preserving history.
5. If multiple child roots exist, merge them into the new parent root.

The invariant is that one root-to-leaf path has at most one active Mandu root.

## Exclusions

Mandu never initializes roots in `/proc`, `/sys`, `/dev`, or `/run`.

`/tmp` is excluded by default. Explicit policy-untrusted paths may allow a
temporary workspace, such as a PinchBench task root, because that path is a
configured trust boundary rather than arbitrary scratch space.

## Commit Flow

`write` and `edit` initialize roots when needed, then rewrite file paths into
`agentview`.

`read` does not initialize a new root. It rewrites only when a matching tracked
root already exists and policy requires the Agent File System view.

After a write-capable tool call, Mandu:

1. detects changed files in `agentview`;
2. commits symbolized content as `[MDU-TRUSTED]`;
3. syncs safe changed paths into the Human File System;
4. commits the symbolized human-side twin as `[MDU-TRUSTED]`;
5. resolves symbols in the Human File System;
6. commits resolved/raw content as `[MDU-UNTRUSTED]`.

## Cleanup

If a canonical workspace path no longer exists, its registry entry is ignored
on startup. Future cleanup may remove orphaned `$HOME/.dualview/workspaces/*`
directories after an explicit retention policy is defined.
