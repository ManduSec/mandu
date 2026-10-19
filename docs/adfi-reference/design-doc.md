# Mandu OpenClaw Design Document

## 0. Background

### What is Secure OpenClaw?

Secure OpenClaw is a security layer for AI coding agents (like Claude Code, Codex CLI, etc.). AI coding agents use tools to interact with the real world. The problem is that **agent inbound data can contain untrusted content** (e.g., web search results, Slack messages from strangers), and a malicious actor can embed **prompt injection attacks** inside that content. If the agent blindly trusts inbound data and acts on it (e.g., writing malicious code, exfiltrating secrets), the user's system is compromised.

### What is DFI (Data Flow Integrity)?

DFI tracks the **trust level of every piece of data** flowing through the agent's context. Data originating from the user or the agent's own reasoning is **trusted**. Data originating from external sources (web pages, emails, Slack messages, other agents) is **untrusted**. DFI ensures that untrusted data cannot silently influence trusted actions.

### What is Mandu (Agent Data Flow Integrity)?

Mandu is the plugin that implements DFI within the OpenClaw gateway. It operates in two modes:

- **Inline mode** (`taintMode: "inline"`): Wraps untrusted content with `<<<AOS_UNTRUSTED>>>` markers. The LLM sees the raw content but with explicit trust boundaries.
- **Symbolize mode** (`taintMode: "symbolize"`): Replaces untrusted values with opaque symbols (e.g., `$MDU:web_fetch[a1b2].title`). The LLM never sees raw untrusted content.

## 1. Design Principles

### 1. The agent (T-LLM) never sees untrusted data

In symbolize mode, all untrusted values in agent inbound data are replaced with `$MDU:` symbols before the LLM context. The T-LLM reasons using symbols and never has access to raw attacker-controlled content. This eliminates prompt injection at the data flow level.

### 2. The human reads original data

When the agent writes files that contain untrusted data, the human should be able to read the original content using their normal tools (Obsidian, VS Code, `cat`, etc.). The files on disk must contain real values, not symbols.

### Agent-view and Human-view

These two principles create a tension: the agent must see symbols, the human must see real values. Mandu resolves this by maintaining two views of the filesystem:

- **Agent-view**: files contain symbols. The agent reads and writes through this view.
- **Human-view**: files contain resolved real values. The human browses this view with their normal tools.

See [fs-level-tracking.md](design/fs-level-tracking.md) for how these views are implemented with worktree tracking.

## 2. Architecture Overview

Mandu tracks data flow at two levels:

1. **Agent context-level**: symbolization of inbound data, resolution of outbound data, symbol management within the LLM session. See [architecture.md](architecture.md).
2. **FS-level**: git-based file provenance maintaining Agent File System and Human File System views. See [fs-level-tracking.md](design/fs-level-tracking.md).

### Hooks

Mandu hooks sit at multiple points in the OpenClaw agent loop. See [`openclaw-hook-design.md`](design/openclaw-hook-design.md) for the hook lifecycle.

| Hook | Purpose |
|------|---------|
| `before_tool_call` | Resolve symbols in agent outbound data (based on outbound data spec) |
| `tool_result` | Symbolize/label agent inbound data (based on inbound data spec) |
| `after_tool_call` | File tracking: commit file changes |
| `message_sending` | Resolve symbols for user-facing reply |
| `before_prompt_build` | Append symbol guidance to T-LLM system prompt |
| `transform_webhook_content` | Symbolize webhook payloads |
| `llm_input` | Log LLM requests to audit JSONL |
| `session_end` / `command:reset` / `command:new` | Clear session symbols from global map |

## 3. Detailed Design Docs

| Topic | Document |
|-------|----------|
| Execution flow and two-level tracking | [architecture.md](architecture.md) |
| Inbound/outbound data spec (per-tool classification) | [inbound-outbound-spec.md](design/inbound-outbound-spec.md) |
| Mandu Symbol (format, storage, API) | [symbol.md](design/symbol.md) |
| FS-level data flow tracking (worktree mode) | [fs-level-tracking.md](design/fs-level-tracking.md) |
| Symbolic exec (RESTRICTED=1) | [exec-with-symbols.md](design/exec-with-symbols.md) |
| Webhook symbolization | [webhook.md](design/webhook.md) |
| Vocabulary decisions | [terminology.md](terminology.md) |

## 4. Inspect Symbol (Dual-LLM Architecture)

The `inspect_symbol` tool enables the T-LLM to extract structured information from symbolized untrusted data without ever seeing raw values.

1. T-LLM calls `inspect_symbol` with symbol names, an output schema, and a prompt
2. The tool resolves symbols to raw values via the global symbol map
3. Raw values are sent to an **untrusted LLM** (U-LLM) via a named OpenClaw subagent (default: `ullm`) or a `claude -p` subprocess. The U-LLM has no tools.
4. The U-LLM produces structured JSON matching the output schema
5. Each output field is re-symbolized as a derived symbol (e.g., `$MDU:web_fetch[a1b2].body.title`)
6. Derived symbols are persisted to the symbol table
7. The T-LLM receives only symbol names

### Security Properties

- The U-LLM runs without tools
- The T-LLM never sees raw untrusted content, only derived symbols
- Provenance is preserved: derived symbols inherit the parent's `tool` and `origin` fields

> Implementation: `plugin/adfi/adfi-inspect-symbol.ts`

## 5. Configuration

Plugin configuration in `openclaw.json` under `plugins.entries.adfi.config`:

| Key | Values | Default | Purpose |
|-----|--------|---------|---------|
| `taintMode` | `inline`, `symbolize` | `inline` | Inline markers vs symbols |
| `labelMode` | `both`, `untrusted_only`, `trusted_only`, `none` | `both` | Which result classes to process for taint marking; trusted results are audited but not text-prefixed |
| `verbose` | boolean | `false` | Post notifications to `notifyChannel` |
| `auditTrail` | boolean | `true` | Write JSONL audit log |
| `targetChannels` | string[] | `[]` | Only run hooks for these channels |
| `targetSessionIds` | string[] | `[]` | Only run hooks for these session key fragments |
| `fileTrackingEnabled` | boolean | `false` | Enable git-based file tracking |
| `fileTrackingGitRoot` | string | auto-detect | Git root for file tracking |
| `fileTrackingStrategy` | `fixed`, `ondemand` | `ondemand` | Single fixed git root vs dynamic on-demand tracked roots |
| `inspectSubagent` | string | `ullm` | Named subagent or `cli` for U-LLM |
| `inspectModel` | string | `sonnet` | Model for U-LLM |

## 6. Implementation Status

### Done

- Agent context-level data flow tracking (inline + symbolize modes)
- Inbound/outbound data spec with per-field schemas
- Global symbol table (in-memory + persistent SQLite)
- FS-level data flow tracking (worktree mode)
- Inspect symbol (dual-LLM architecture)
- Webhook symbolization with per-field schemas
- Audit trail and test dashboard

### TODO

- Symbol garbage collection
- Separate git database ownership details are covered by [fs-level-tracking.md](design/fs-level-tracking.md)
- Alternative symbol formats for utility and cost efficiency

## 7. Open Questions

1. **Symbol DB location**: centralized at `~/.dualview/symbols.db`. Trade-offs between central (shared, survives project deletion) vs per-workspace (isolated, but raw untrusted data near workspace state).
2. **Symbol garbage collection**: when to clean up old symbols from the persistent table.
3. **User file modification policy**: when a user (not agent) edits files containing untrusted data. Currently handled by worktree human-edit reconciliation.
