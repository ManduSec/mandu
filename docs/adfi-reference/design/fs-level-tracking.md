# Git-Based FS-Level Data Flow Tracking

## Goal

Track file-level provenance with separate Human File System and Agent File
System views.

The Human File System is the user's workspace. It contains resolved/raw file
contents. The Agent File System is `agentview`. It contains symbolized content
that can include `$MDU:...` tokens.

## Canonical Layout

For workspace `/tmp/pinchbench/0001/agent_workspace`, the workspace id is:

```text
%2Ftmp%2Fpinchbench%2F0001%2Fagent_workspace
```

Mandu file-tracking state lives under the user's home directory:

```text
$HOME/.dualview/workspaces/<workspace-id>/
  repo.git/
  agentview/
  workspace.json
  commit.lock
  conflicts.log
```

`workspace.json` records:

```json
{
  "schemaVersion": 1,
  "workspacePath": "/absolute/canonical/workspace",
  "workspaceId": "<encodeURIComponent(workspacePath)>"
}
```

No file-tracking state is created inside the workspace. The workspace remains
the Human File System.

## Strategy

`ondemand` is the default strategy. It initializes a canonical DualView
workspace when file tools first need a tracked root.

`fixed` means a single configured root policy. It uses the same canonical
DualView physical layout; it is not a workspace-local layout.

On-demand tracking does not initialize arbitrary roots in pseudo/system
filesystems (`/proc`, `/sys`, `/dev`, `/run`) or temporary scratch space
(`/tmp`) unless a configured policy path explicitly allows that temporary root.

## Commit Flow

When the agent writes a file:

1. The file tool path is rewritten from the Human File System to `agentview`.
2. The tool writes symbolized content to `agentview`.
3. Mandu commits that state as `[MDU-TRUSTED]` on the `aos-trusted` lineage.
4. Mandu copies the changed paths to the Human File System unless doing so
   would overwrite uncommitted human edits.
5. Mandu commits the symbolized human-side twin as `[MDU-TRUSTED]`.
6. Mandu resolves symbols in the Human File System.
7. Mandu commits the resolved/raw state as `[MDU-UNTRUSTED]`.

The `aos-trusted` ref always points to the latest fully symbolized Agent File
System state. The Human File System history contains paired trusted and
untrusted commits so normal git tooling can inspect the transition.

## Restricted Exec

Unrestricted `exec` runs in the Human File System and sees resolved/raw files.

Restricted `exec` (`env.RESTRICTED=1`) runs with symbols preserved and mounts
each active `agentview` over its Human File System root for the subprocess.
The parent gateway and the user's workspace are not modified by the mount.

## Concurrency

Git operations are serialized by `commit.lock` in the canonical DualView
workspace directory. Race detections are appended to `conflicts.log` in the
same directory.

## Binary Files

Binary files are detected by null bytes in the first 8KB. They are copied and
committed, but symbol resolution is skipped.
