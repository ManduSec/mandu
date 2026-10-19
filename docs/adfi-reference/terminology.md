# Mandu Terminology

Vocabulary decisions for consistent use across docs, code comments, and the paper.

## Decided

| Term | Definition | Replaces |
| --- | --- | --- |
| **Agent inbound data** | Data entering the agent context (tool results, webhook payloads) | "tool output", "webhook data" |
| **Agent outbound data** | Data leaving the agent context (tool params, outbound messages) | "tool input" |
| **Inbound data spec** | Per-tool/webhook classification of inbound fields as TRUSTED/UNTRUSTED | "tool output spec", "data classification policy", "webhook data spec" |
| **Outbound data spec** | Per-tool resolution policy for symbols in outbound fields (resolve / not resolve) | "input resolution spec", "symbolization policy" |
| **Symbol** | Opaque `$MDU:*` placeholder for untrusted values | "token" |
| **File tracking** | Git-based file provenance across trusted and human-view worktrees | "trust ledger" |
| **Output classification** | Tool-level TRUSTED/UNTRUSTED classification | "trust classification", "tool trust" |
| **Re-symbolize** | Replace raw untrusted values with existing or derived symbols | "re-mask" |

## To Decide

### Data flow tracking levels

What to call the two levels of data flow tracking:

| Current (tentative) | Alternative | Notes |
| --- | --- | --- |
| Agent context-level data flow tracking | Context-level DFI? Session-level taint tracking? | Symbols in tool results, resolution in messages |
| FS-level data flow tracking | File-level DFI? Git-based provenance tracking? | Dual worktree tracking with trusted and human-view commits |

### Filesystem views / modes

| Candidate | Definition | Notes |
| --- | --- | --- |
| **Agent-view** | Files contain symbols instead of raw untrusted values | exec RESTRICTED=1, read, sessions_spawn all operate on this view |
| **Human-view** | Files contain resolved real values | What the user sees in their editor |
| **Worktree mode** | Agent-view and human-view are separate git worktrees | Physical isolation between views |

### Trust level / data classification

What to call the TRUSTED/UNTRUSTED classification applied to inbound data?

| Current usage | Where | Notes |
| --- | --- | --- |
| "trust level" | fs-level-tracking.md, design-doc.md | Historical term; prefer data classification for inbound fields and commit attribution for file history |
| "TRUSTED / UNTRUSTED" | git commit tags, inbound data spec | `[MDU-TRUSTED]`, `[MDU-UNTRUSTED]` |
| "output classification" | architecture.md, AGENTS.md | Tool-level and field-level |
| "data classification" | inbound-outbound-spec.md | Per-field trust in tool results |

Questions:
- Is "trust level" the right term, or should it be "data classification", "taint label", or something else?
- Should the git commit tags use the same vocabulary as the inbound data spec?
