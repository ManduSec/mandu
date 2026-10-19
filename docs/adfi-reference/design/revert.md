# Design: Mandu Revert — Filesystem State Rollback

## Goal

Allow the user to roll the entire filesystem back to a specific point in the
Mandu commit history. The rollback is a full-state reset: every file returns to
exactly how it was at the chosen moment.

## Tracking Strategy Limitation

**Revert currently only works with `fileTrackingStrategy: "fixed"`.**

The revert algorithm assumes a single, stable `gitRoot` with a linear commit
history. On-demand tracking (`fileTrackingStrategy: "ondemand"`) can use
multiple canonical DualView workspaces, each with its own `repo.git` history.
Adapting revert for multi-root on-demand tracking is WIP; it requires resolving
which tracked root(s) the revert applies to and coordinating rollback across
potentially multiple DualView repos.

Until on-demand revert is implemented, `adfi_history` and `adfi_revert` tools
are only registered when using the fixed strategy (see `plugin/adfi/index.ts`).

## Model

Each agent write produces a commit pair:

```
T(n) = [MDU-TRUSTED]   — symbolized content (Agent File System)
U(n) = [MDU-UNTRUSTED] — raw content (human-view)
```

A typical history looks like:

```
init ── T1 ── U1 ── T2 ── U2 ── T3 ── U3
                                  |     |
                          aos-trusted  HEAD
```

Reverting to "after write #1" means resetting the entire state to `U1` / `T1`:

```
init ── T1 ── U1    (T2, U2, T3, U3 abandoned)
         |     |
 aos-trusted  HEAD
```

## Algorithm

```
Input: target write cycle N (identified by number, callId, or commit hash)

1. Find U(N) — the [MDU-UNTRUSTED] commit for write cycle N
2. Find T(N) — the [MDU-TRUSTED] commit for write cycle N
3. git reset --hard U(N)
4. git update-ref refs/heads/aos-trusted T(N)
5. git -C $HOME/.dualview/workspaces/<workspace-id>/agentview reset --hard aos-trusted
```

Three git commands. No inverse diffs. No merge. No conflict resolution.

Abandoned commits remain in git's reflog and are recoverable for ~90 days
(default git gc expiry).

## Identifying the Target

The user may specify the target as:

- **write number**: "go back to after write #2"
- **callId**: the `callId` from the commit message metadata
- **commit hash**: a specific commit hash

To resolve a write number, walk the commit history and count `[MDU-UNTRUSTED]`
commits from oldest to newest.

```typescript
function findWriteCycleByNumber(gitRoot: string, n: number): { trusted: string; untrusted: string } {
  // List all Mandu-UNTRUSTED commits oldest-first
  const result = gitExecSync([
    "log", "--fixed-strings", "--reverse", "--format=%H",
    "--grep=[MDU-UNTRUSTED]",
  ], { cwd: gitRoot });

  const untrustedCommits = result.stdout.trim().split("\n").filter(Boolean);
  if (n < 1 || n > untrustedCommits.length) {
    throw new Error(`Write #${n} not found (${untrustedCommits.length} writes exist)`);
  }

  const untrusted = untrustedCommits[n - 1];
  // The trusted commit is always the parent of the untrusted commit
  const { stdout: trusted } = gitExecSync(["rev-parse", `${untrusted}~1`], { cwd: gitRoot });

  return { trusted: trusted.trim(), untrusted };
}
```

## UX Flow

### List recent writes

```
User:   show me recent writes

Agent:  Recent writes:
        #3  notes.md     created    2 min ago
        #2  report.md    created    5 min ago
        #1  readme.md    created   10 min ago
```

### Revert with confirmation

```
User:   go back to after write #1

Agent:  This will restore the filesystem to the state after write #1.

          KEEP:    readme.md
          REMOVE:  report.md, notes.md

        Writes #2 and #3 will be abandoned.
        Proceed? (yes / no)

User:   yes

Agent:  Done. Filesystem restored to state after write #1.
```

### Revert to initial state (before any writes)

```
User:   undo everything

Agent:  This will remove all agent-written files and restore
        the filesystem to its initial state.

          REMOVE:  readme.md, report.md, notes.md

        Proceed?
```

## Security

The `adfi_revert` tool is classified as TRUSTED. It cannot be triggered by
untrusted tool output or prompt injection — only by direct user instruction
through the chat interface.

## Worktree Consistency

After revert:

- `HEAD` points to `U(N)` — human-view is raw content at write #N
- `aos-trusted` points to `T(N)` — Agent File System is symbolized at write #N
- `agentview` is reset to `aos-trusted`

Both views are consistent.

## Symbol Table

The symbol table is append-only and is not affected by revert. Symbols
from abandoned writes remain in the table but are harmless — they simply
have no corresponding file content anymore.

## TODO

- **Partial revert**: undo a specific write cycle (e.g., only T2/U2) while
  keeping later writes. Requires computing inverse diffs or using
  `git revert --no-commit`. Deferred for now.
- **Revert marker commit**: record the revert action as an explicit
  `[Mandu-REVERT]` commit in the history for auditability, instead of
  relying on reflog. Deferred for now.
- **Per-file revert**: undo changes to a specific file from a specific
  write cycle without affecting other files. Deferred for now.
- **Provenance-based revert**: undo all writes derived from a specific
  untrusted source (e.g., a particular `web_fetch` call). Deferred.
- **On-demand strategy revert**: adapt revert for multi-root on-demand
  tracking (`fileTrackingStrategy: "ondemand"`). Requires per-root
  history enumeration and coordinated rollback across shadow repos.
  Deferred — revert currently requires `fileTrackingStrategy: "fixed"`.

## Implementation Steps

| Step | What | Files |
|------|------|-------|
| 1 | `findWriteCycleByNumber()` | `plugin/adfi/adfi-git.ts` |
| 2 | `revertToWriteCycle()` — the 3-command reset | `plugin/adfi/adfi-revert.ts` |
| 3 | `listWriteCycles()` — for the "show recent writes" UX | `plugin/adfi/adfi-git.ts` |
| 4 | `adfi_revert` tool registration | `plugin/adfi/index.ts` |
| 5 | `adfi_history` tool registration (list writes) | `plugin/adfi/index.ts` |
| 6 | Dry-run / confirmation support | `plugin/adfi/adfi-revert.ts` |
| 7 | Unit tests | `test/unit/unit_revert.ts` |

## Reference

- FS-level tracking: `docs/design/fs-level-tracking.md`
- PFI paper: https://arxiv.org/abs/2503.15547 (Section 4.1 Agent Isolation)
