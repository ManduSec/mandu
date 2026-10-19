# Architecture — adfi-openclaw

## Execution Flow

Mandu tracks data flow at two levels:

### 1. Agent Context-Level Data Flow Tracking

Taint propagation within the LLM session — symbols in tool results, resolution in outbound messages.

#### Tool call flow

```
User message
    │
    ▼
hook:before_prompt_build
    └─ Append symbol guidance to T-LLM system prompt
    │
    ▼
LLM generates tool_call (e.g., web_fetch)
    │
    ▼
hook:before_tool_call
    ├─ Resolve symbols in agent outbound data (based on outbound data spec)
    └─ If exec RESTRICTED=1: set up symbolic exec environment
    │
    ▼
Tool executes, returns raw result
    │
    ▼
hook:tool_result
    ├─ Classify agent inbound data (TRUSTED/UNTRUSTED) based on inbound data spec
    ├─ Per-field symbolization/labeling
    └─ Store symbol → value mappings in global symbol table
    │
    ▼
LLM sees symbolized result (symbols, not raw content)
    │
    ▼
LLM generates reply (may contain $MDU: symbols)
    │
    ▼
hook:message_sending
    └─ Resolve symbols to real values for user-facing reply
```

#### Webhook flow

```
External webhook (GitHub, CI, etc.)
    │
    ▼
hook:transform_webhook_content
    ├─ Find JSON payload in message
    ├─ Resolve per-field schema (payload security field > config > default)
    ├─ Three paths:
    │    template+data → render template with symbolized data
    │    flat JSON     → apply schema labeling, output as tagged JSON
    │    non-JSON      → symbolize entire text as single variable
    └─ Write audit trail
    │
    ▼
Agent sees symbolized webhook content
```

#### Logging

| Hook | Purpose |
|------|---------|
| `llm_input` | Log LLM requests to audit JSONL (for dashboard) |
| `session_end` | Remove session's symbols from global map |

### 2. FS-Level Data Flow Tracking

Git-based file provenance. The agent and the human see different filesystem states:

- **Agent view**: files contain symbols (untrusted values replaced)
- **Human view**: files contain resolved real values

DualView tracking is the supported file-tracking path. The Human File System
is the workspace, and the Agent File System is `agentview` under
`$HOME/.dualview/workspaces/<workspace-id>/`. Read/write/edit paths are
rewritten to `agentview` when policy requires the symbolized view.
De-symbolization happens inline in the commit handler.

```
Agent writes file (content may include symbols)
    │
    ▼
hook:before_tool_call → rewrite file path to agent worktree
    │
    ▼
hook:after_tool_call → WorktreeFileCommit
    ├─ Commit to agent worktree (symbols intact)
    └─ Copy + resolve symbols → commit to main worktree (human view)
```

## Dependencies

- Built on OpenClaw `v2026.03.12` (the DualView authors' fork). Mandu adds the plugin hook system (`on()`, `registerHook()`, `registerTool()`) and the `transform_webhook_content` hook to the gateway.
- **better-sqlite3**: Persistent symbol table (`$HOME/.dualview/symbols.db`)
- **Docker** (test only): E2E tests run in containers by default
