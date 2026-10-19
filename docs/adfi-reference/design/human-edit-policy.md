# Design: Manual Human Edit Policy for FS-Level Tracking

Issue: #197

## Problem

Mandu FS-level tracking assumes only agents edit files. The current
agent-write flow (worktree mode) produces paired commits:

```
1. Symbolized write on Agent File System
2. Trusted commit (T') on Agent File System (aos-trusted branch)
3. Copy content to human-view worktree
4. Trusted twin commit (T) on human-view worktree (main branch)
5. De-symbolize contents on human-view worktree
6. Untrusted commit (U) on human-view worktree (main branch)
```

Human edits to the human-view are invisible to the agent unless they are
reconciled into `agentview`. This is Open
Question #3 in `docs/design-doc.md`.

## Two Scenarios

### Scenario 1: Human Edits Trusted Content

Lines that are identical in both views (no symbols involved). The human
modifies agent-authored or previously human-authored content.

**Current behavior:** Trusted worktree does not reflect the change. Agent
reads stale data from `agentview`.

**Example:**
```
Human-view:     const x = 5   →   const x = 10  (human edits)
Trusted worktree: const x = 5                     (stale — agent sees old value)
```

### Scenario 2: Human Edits Untrusted Content

Lines that contain resolved raw values in human-view but symbols in the
trusted worktree. The human modifies de-symbolized content.

**Current behavior:** Trusted worktree still has old symbols pointing to
old values. Agent sees the original symbol, unaware of the human's edit.

**Example:**
```
Human-view:     Buy Cheap Viagra   →   Product Page Title  (human edits)
Trusted worktree: $MDU:web_fetch[9f3e].title          (stale symbol)
```

## Trust Model

### Current Model (Agent-Only)

```
Trust hierarchy:
  TRUSTED   — user prompts, agent reasoning, agent-authored code
  UNTRUSTED — external sources (web, email, Slack, webhook)

Actor:      Agent (sole filesystem mutator)
Principal:  Human (trust authority, read-only consumer of human-view)
```

### Extended Model (Agent + Human)

```
Trust hierarchy (unchanged):
  TRUSTED   — user prompts, agent reasoning, agent/human-authored content
  UNTRUSTED — external sources

Actors:     Agent + Human (both mutate filesystem)
Principal:  Human (trust authority in Mandu threat model)
```

**Key determination: human = trusted actor.** Mandu's threat model is
prompt injection against the agent, not social engineering against the
human. If the human is compromised (socially engineered into pasting
untrusted content), no filesystem-level defense helps — that is out of
scope. Human edits are trusted by definition.

The nuance is provenance, not trust level. When a human edits untrusted
content, the result is trusted (human-authored), but the system records
that trust promotion occurred and which symbol was obsoleted.

### Why NOT Revised Symbol State

Creating a new symbol for human edits (e.g.,
`$MDU:HUMAN_web_fetch[9f3e].title`) would:

1. **Contradict the trust model.** Symbols represent untrusted external
   data. Human-authored content is trusted. Symbolizing it hides the
   human's intent from the agent.
2. **Create a third trust tier.** "Human-reviewed" is still trusted.
   Adding a tier between TRUSTED and UNTRUSTED adds complexity without
   security benefit.
3. **Break agent utility.** If the agent cannot read the human's
   replacement text, it cannot act on human intent. The human edited the
   file precisely so the agent would use the new content.

## Default Policy

**Human edits are trusted with provenance-preserving trust promotion.**

### Policy by Edit Target

| Human edits... | Trust result | Trusted worktree action | Symbol table action |
|---|---|---|---|
| Trusted content | Trusted | Copy human's literal text | None |
| Entire untrusted block | Full trust promotion | Replace symbol with human's literal text | Obsolete symbol |
| **Part of untrusted block** | **Symbol splitting** | **Split symbol around human edit** | **Obsolete original, allocate derived symbols for untouched portions** |
| New file | Trusted | Copy entire file | None |
| Deleted file | N/A | Remove file | None |
| Mixed (trusted + untrusted lines) | Per-line classification | Per-line: copy literal or split symbol | Per-symbol as needed |

**Granularity: line-level.** The reconciliation map operates at line
granularity. If a human changes any part of a line, the entire line is
treated as human-authored. For multi-line symbols, partial edits trigger
symbol splitting (see below) rather than promoting the entire untrusted block.

### Trust Promotion: Simple Case (Single-Line Symbol)

| View | Before | After human edit |
|---|---|---|
| Human-view | `Buy Cheap Viagra` | `Product Page Title` |
| Trusted worktree | `$MDU:web_fetch[9f3e].title` | `Product Page Title` |

The symbol `$MDU:web_fetch[9f3e].title` is obsoleted. The literal
text `Product Page Title` appears in both views.

### Trust Promotion: Multi-Line Symbol (Symbol Splitting)

A single symbol can represent a multi-line block. When the human edits
only part of the block, the untouched portions must remain untrusted.

**Example:** `$MDU:web_fetch[8ec1]` represents 101 lines of web
content (lines 10-110 in the human-view). Human edits lines 40-45.

Before:
```
Trusted worktree:           Human-view:
line 1                      line 1
...                         ...
line 9                      line 9
$MDU:web_fetch[8ec1]  line 10  (untrusted)
                            line 11  (untrusted)
                            ...
                            line 110 (untrusted)
line 111                    line 111
```

After reconciliation — the symbol is **split** around the human edit:
```
Trusted worktree:           Human-view:
line 1                      line 1
...                         ...
line 9                      line 9
$MDU:web_fetch[9fa3].__aos_split[0]  line 10  (untrusted, unchanged)
                            ...
                            line 39  (untrusted, unchanged)
line 40 (human literal)     line 40  (human-edited, trusted)
line 41 (human literal)     line 41  (human-edited, trusted)
line 42 (human literal)     line 42  (human-edited, trusted)
line 43 (human literal)     line 43  (human-edited, trusted)
line 44 (human literal)     line 44  (human-edited, trusted)
line 45 (human literal)     line 45  (human-edited, trusted)
$MDU:web_fetch[9fa4].__aos_split[1]  line 46  (untrusted, unchanged)
                            ...
                            line 110 (untrusted, unchanged)
line 111                    line 111
```

Symbol table after:
```
$MDU:web_fetch[8ec1] → obsoleted (was: lines 10-110)
$MDU:web_fetch[9fa3].__aos_split[0] → raw content of lines 10-39  (derived from 8ec1)
$MDU:web_fetch[9fa4].__aos_split[1] → raw content of lines 46-110 (derived from 8ec1)
```

**Why splitting is necessary:** Without it, editing 6 lines within a
101-line untrusted block would promote all 101 lines to trusted. The
human only reviewed and changed lines 40-45. Lines 10-39 and 46-110
remain unreviewed attacker-controlled content.

## Detection Mechanism

### When

Two trigger points, no daemon required:

1. **`session_start`** — catch edits made between agent sessions.
2. **`before_tool_call`** for filesystem tools (`read`, `write`, `edit`)
   — catch edits made during a session before the agent interacts with
   the filesystem.

### How

`git status --porcelain` in human-view (main worktree). If uncommitted
changes exist, reconciliation fires before the agent's tool call proceeds.

### Why Not Filesystem Watcher

A filesystem watcher (inotify/fsevents) adds daemon dependency and
complexity. Hook-based detection is sufficient: human edits only matter
when the agent is about to interact with the filesystem. Real-time
detection can be added later if latency becomes a concern.

## Line-Number Mapping

A symbol in the trusted worktree occupies 1 line but its resolved value
in the human-view may span N lines. The two views have different line
counts. Reconciliation requires a **line map** to translate human-view
line numbers to symbol positions.

### Building the Line Map

```
Input: trusted worktree file content, symbol table

For each line in trusted worktree:
  If line contains a symbol S:
    value = symbolTable.get(S)
    value_line_count = value.split("\n").length
    Record: human-view lines [offset .. offset + value_line_count - 1]
            → symbol S, trusted worktree line N
    offset += value_line_count
  Else (literal line):
    Record: human-view line [offset] → literal, trusted worktree line N
    offset += 1
```

### Example

```
Trusted worktree (4 lines):        Human-view (124 lines):
  1: line 1                          1: line 1
  2: $MDU:[aaaa].title         2: The Page Title        (1 line)
  3: $MDU:[bbbb].body          3-102: <100 lines>       (100 lines)
  4: line 103                         103: line 103
  5: $MDU:[cccc]               104-123: <20 lines>      (20 lines)

Line map:
  human 1       → literal (trusted line 1)
  human 2       → symbol [aaaa].title (trusted line 2), offset 0
  human 3-102   → symbol [bbbb].body  (trusted line 3), offset 0-99
  human 103     → literal (trusted line 4)
  human 104-123 → symbol [cccc]       (trusted line 5), offset 0-19
```

## Symbol Splitting Algorithm

When the human edits part of a multi-line symbol, the symbol is split
into untouched portions (new derived symbols) and human-edited portions
(literal text).

```
Input:
  S          — the symbol being split
  value      — S's resolved value (multi-line string)
  edits      — list of (start_offset, end_offset) ranges within value
               that the human changed (0-indexed line offsets within value)

Algorithm:
  value_lines = value.split("\n")
  segments = []           -- ordered list of (type, content) pairs
  cursor = 0
  derived_index = 0

  append_split_field(field, i):
    suffix = "__aos_split[" + i + "]"
    return field ? field + "." + suffix : suffix

  For each edit range [a, b] in order:
    1. Pre-edit untouched portion: value_lines[cursor .. a-1]
       If non-empty:
         new_sym = allocateSymbol(tool=S.tool, derived_from=S.name,
                                  field=append_split_field(S.field, derived_index),
                                  value=lines.join("\n"))
         derived_index += 1
         segments.push(("symbol", new_sym))
    2. Human-edited portion: read from human-view diff
       segments.push(("literal", human_edited_lines))
    3. cursor = b + 1

  After all edits:
    Remaining untouched: value_lines[cursor .. end]
    If non-empty:
      new_sym = allocateSymbol(tool=S.tool, derived_from=S.name,
                                field=append_split_field(S.field, derived_index),
                                value=lines.join("\n"))
      segments.push(("symbol", new_sym))

  Mark S as obsoleted.
  Return segments (to write into trusted worktree).
```

### Multiple Edit Ranges Within One Symbol

If the human edits lines 20-25 AND lines 80-85 within a 101-line block:

```
Before:  $MDU:web_fetch[8ec1]  (lines 10-110)

After:   $MDU:web_fetch[a1b2].__aos_split[0]  (lines 10-19,  derived from 8ec1)
         lines 20-25                  (human literal)
         $MDU:web_fetch[c3d4].__aos_split[1]  (lines 26-79,  derived from 8ec1)
         lines 80-85                  (human literal)
         $MDU:web_fetch[e5f6].__aos_split[2]  (lines 86-110, derived from 8ec1)
```

Three derived symbols, two human-literal ranges.

Derived symbol names append an explicit split segment to the parent field
path. A parent ending in `.text` yields `.text.__aos_split[0]`,
`.text.__aos_split[1]`, etc. A parent already ending in a split segment
is nested, e.g. `.text.__aos_split[1].__aos_split[0]`. A fieldless
symbol uses `.__aos_split[n]` as its field path.

### Edge Cases

| Case | Result |
|---|---|
| Human edits start of block (lines 10-15) | No pre-symbol. Post-symbol for lines 16-110. |
| Human edits end of block (lines 105-110) | Pre-symbol for lines 10-104. No post-symbol. |
| Human edits entire block (lines 10-110) | No derived symbols. Full trust promotion. Original obsoleted. |
| Human deletes lines within block | Split around deleted range. No human-literal lines inserted. |
| Human inserts lines within block | Split at insertion point. New human-literal lines between symbols. |
| Single-line symbol (e.g., `title` field) | No splitting possible. Whole symbol promoted or replaced. |
| Human edit spans two adjacent symbols | Each symbol split independently at the boundary. |

## Reconciliation Flow (Worktree Mode)

```
Human edits file(s) in human-view
    |
    v
before_tool_call fires (for read/write/edit)
    |
    v
git status in human-view -> uncommitted changes detected?
    | No -> proceed normally
    | Yes v
    v
For each changed file:
    |
    v
  1. Build line map
    +-- Read trusted worktree version of file
    +-- For each symbol, look up resolved value line count
    +-- Build human-view line → (symbol, offset) mapping
    |
    v
  2. Classify changes
    +-- git diff HEAD -- <file> in human-view
    |   -> identify which lines the human changed
    +-- For each changed line, look up in line map:
        +-- Maps to literal line (trusted content)
        |   -> "trusted edit" (copy literal text)
        +-- Maps to symbol S at offset O
            -> "symbol edit" (needs splitting)
    |
    v
  3. Split affected symbols
    +-- Group edits by symbol
    +-- For each affected symbol S:
        +-- If human edited ALL lines of S -> full promotion (obsolete S)
        +-- If human edited PART of S -> run split algorithm:
            +-- Allocate derived symbols for untouched ranges
            +-- Mark original S as obsoleted
    |
    v
  4. Rewrite trusted worktree file
    +-- Replace each affected symbol line with:
        [pre-symbol?] + human-literal-lines + [post-symbol?]
    +-- Copy literal text for trusted-content edits
    |
    v
  5. Commit both views
    +-- Trusted worktree: commit on aos-trusted branch
    +-- Human-view: commit as [MDU-HUMAN] on main
    |
    v
  6. Persist symbol table changes
    +-- Write derived symbols (with derived_from, line_range)
    +-- Mark obsoleted symbols
    |
    v
Proceed with original tool call
```

### On-Demand Tracking

Same reconciliation flow, using the canonical DualView `repo.git` with
`GIT_DIR` + `GIT_WORK_TREE`:

```bash
GIT_DIR=$HOME/.dualview/workspaces/<workspace-id>/repo.git \
GIT_WORK_TREE=/home/john/projects/react \
git status --porcelain
```

The human-view IS the user's real project directory. Detection checks
uncommitted changes against Mandu's shadow git database.

## Commit Semantics

### New Commit Type

Current types:
```
[MDU-TRUSTED]    — agent write, symbols intact (Agent File System snapshot)
[MDU-UNTRUSTED]  — agent write, symbols resolved (human-view snapshot)
```

Proposed addition:
```
[MDU-HUMAN]      — human edit, literal text (same in both views)
```

### Commit Message Format

```
[MDU-HUMAN] mdu: source=human files=<paths> promoted=<symbol-list|none>
```

Examples:
```
[MDU-HUMAN] mdu: source=human files=report.md promoted=none
[MDU-HUMAN] mdu: source=human files=summary.md promoted=$MDU:web_fetch[9f3e].title
```

No `callId` or `runId` — not from a tool call. No `toolName` — no tool
involved.

### Why Single Commit, Not T/U Pair

Agent writes produce a T/U pair because the agent operates on symbolized
content that must be de-symbolized for the human:

```
Agent write:  T (symbols) -> U (resolved)   — two representations
Human write:  H (literal)                   — one representation
```

Human-authored text has no "symbolized version." A single `[MDU-HUMAN]`
commit correctly represents the edit. Fabricating a T/U pair would put
symbols the human never wrote into the commit history.

### Commit Graph

Before human edit:
```
aos-trusted:  T'1 -- T'2 -- T'3
main:          T1 -- U1 -- T2 -- U2 -- T3 -- U3  <- HEAD
```

After human edit reconciliation:
```
aos-trusted:  T'1 -- T'2 -- T'3 -- H'
main:          T1 -- U1 -- T2 -- U2 -- T3 -- U3 -- H  <- HEAD
```

`H` and `H'` have identical content for human-edited lines. Lines
untouched by the human retain their respective representations (symbols
in `H'`, resolved values in `H`).

### aos-trusted Ref

`aos-trusted` advances to include `H'`. The trusted worktree resets to
`H'` after reconciliation. The agent reads the human's changes on the
next `read` tool call.

## Symbol Table Updates

### Schema Migration

```sql
-- Obsolescence tracking
ALTER TABLE symbols ADD COLUMN obsoleted_at INTEGER;
ALTER TABLE symbols ADD COLUMN obsoleted_by TEXT;     -- 'human' or commit hash

-- Derived symbol provenance (for symbol splitting)
ALTER TABLE symbols ADD COLUMN derived_from TEXT;      -- parent symbol name
ALTER TABLE symbols ADD COLUMN line_range TEXT;         -- "0:29" offset within parent value
```

Obsoleted symbols remain in the table for audit. Active queries filter on
`obsoleted_at IS NULL`. Existing functions (`findSymbolsByCallId`,
`findSymbolsByValue`) skip obsoleted entries.

### Derived Symbol Properties

Derived symbols inherit key fields from the parent:

| Field | Value |
|---|---|
| `tool` | Same as parent (e.g., `web_fetch`) |
| `field` | Parent field plus `.__aos_split[n]` (or `__aos_split[n]` when the parent has no field) |
| `call_id` | Same as parent |
| `origin` | Same as parent |
| `session_key` | Same as parent |
| `value` | Subset of parent's value (line range) |
| `derived_from` | Parent symbol name |
| `line_range` | `"start:end"` — 0-indexed line offsets within parent value |

The provenance chain is fully reconstructible:
`derived symbol → parent symbol → original tool call`.

## Interaction with Existing Mechanisms

### Revert

The revert algorithm (`docs/design/revert.md`) walks T/U pairs.
`[MDU-HUMAN]` commits are not pairs. The algorithm must be updated:

- Reverting past a human edit discards `H` and `H'`.
- Reverting to a human edit restores `H` as HEAD, `H'` as aos-trusted.

### parseAosCommitMessage

Must be updated to recognize `[MDU-HUMAN]` as a valid Mandu commit type.
Return `{ trusted: true, source: "human", ... }`.

### Concurrency

Human edits reconciled before agent action proceeds. Serialized by the
DualView commit lock at `$HOME/.dualview/workspaces/<workspace-id>/commit.lock`.

## Design Alternatives

### Alt A: Unconditional Trust, No Provenance

All human edits trusted. No distinction between editing trusted vs
untrusted lines. Single `[MDU-HUMAN]` commit, no symbol tracking.

| | |
|---|---|
| Pros | Simplest implementation. Minimal code changes. Respects human authority. |
| Cons | No audit trail for trust promotions. Cannot reconstruct which symbols were obsoleted. |
| Complexity | Low |
| When appropriate | Prototyping, when audit trail is not required |

### Alt B: Trust Promotion with Provenance (Recommended)

Human edits trusted. Edits to untrusted lines tagged as promotions.
Obsoleted symbols tracked. Different commit metadata for trusted-edits
vs promotions.

| | |
|---|---|
| Pros | Full auditability. Human authority preserved. Promotion history reconstructible. Compatible with revert design. |
| Cons | More complex reconciliation. Slightly heavier before_tool_call hook. |
| Complexity | Medium |
| When appropriate | Production use, academic evaluation, security-critical deployments |

### Alt C: Explicit Promotion Required

Human edits to trusted lines auto-trusted. Edits to untrusted lines held
as `[Mandu-HUMAN-PENDING]` until explicit `adfi promote` command.

| | |
|---|---|
| Pros | Maximum safety. No accidental trust promotion. |
| Cons | High friction. Breaks normal editing workflow. Human must learn Mandu-specific commands. Agent reads stale data until promotion. Philosophically incoherent — requiring the trust authority to prove trust. |
| Complexity | Medium-high |
| When appropriate | High-security environments with trained Mandu operators |

### Alt D: Content-Similarity Heuristic

Analyze whether edit is "substantial" (rewrite, promote) vs "cosmetic"
(formatting, keep untrusted).

| | |
|---|---|
| Pros | Theoretically optimal. |
| Cons | "Substantial" is undefined. Any threshold is arbitrary. Would need an LLM to judge intent — introducing a trust boundary inside the trust decision itself. |
| Complexity | High |
| When appropriate | Not recommended — ambiguity in a security-critical decision |

### Alt E: Dual-Commit Pair (Mirror Agent Flow)

Human edits produce T/U pairs like agent writes.

| | |
|---|---|
| Pros | Uniform commit model. |
| Cons | Semantically wrong. Human writes literal text — no "symbolized version" exists. Fabricating a T commit with symbols the human never wrote is a lie in the history. |
| Complexity | Medium |
| When appropriate | Not recommended — violates commit semantics |

## Configuration

```json
{
  "fileTrackingEnabled": true,
  "humanEditPolicy": "auto"
}
```

| Value | Behavior |
|---|---|
| `"auto"` (default) | Trust promotion with provenance (Alt B) |
| `"explicit"` | Edits to untrusted lines pending until `adfi promote` (Alt C) |
| `"ignore"` | Human edits not reconciled. Agent reads stale trusted worktree. Testing only. |

## Scope Boundaries

This design does NOT address:

1. **Human pastes untrusted content from clipboard.** Out of scope. Mandu
   protects against prompt injection through the agent, not human
   clipboard actions.
2. **Human edits Agent File System directly.** Unsupported. `agentview`
   is an internal implementation detail. Human edits go through the
   human-view only.
3. **Real-time detection.** Deferred. Hook-based detection at
   `before_tool_call` is sufficient for now.

## Invariants Preserved

| Invariant | Status |
|---|---|
| Every `[MDU-TRUSTED]` commit = fully symbolized Agent File System | Preserved. Human edits create `[MDU-HUMAN]`, not `[MDU-TRUSTED]`. |
| `aos-trusted` ref = latest trusted state | Extended. Now includes human edits (which are trusted). |
| Agent reads symbols for untrusted data from trusted worktree | Preserved. Human lines are literal text (trusted). Untouched untrusted lines remain symbols. |
| Human-view contains no symbols | Preserved. `[MDU-HUMAN]` commits contain literal text. |
| Symbol table maps symbol to raw untrusted value | Preserved. Obsoleted symbols flagged, not deleted. |

## Recommendation

**Alternative B: Trust Promotion with Provenance.**

- Human edits to trusted content sync to trusted branch as literal text.
- Human edits to untrusted content trigger trust promotion: symbol
  replaced with literal text, old symbol marked obsoleted.
- Single `[MDU-HUMAN]` commit type (not T/U pair).
- Detection at `before_tool_call` + `session_start`.
- `humanEditPolicy` config flag for environments needing explicit
  promotion (Alt C).

## Implementation Steps

| Step | What | Files |
|------|------|-------|
| 1 | Human-edit detection in `before_tool_call` | `plugin/adfi/index.ts` |
| 2 | Line-number mapping (trusted worktree ↔ human-view) | `plugin/adfi/adfi-human-edit.ts` (new) |
| 3 | Symbol splitting algorithm | `plugin/adfi/adfi-human-edit.ts` |
| 4 | Reconciliation orchestrator (detect → map → classify → split → rewrite) | `plugin/adfi/adfi-human-edit.ts` |
| 5 | Trusted worktree rewrite after split | `plugin/adfi/adfi-human-edit.ts` |
| 6 | `[ADFI-HUMAN]` commit creation | `plugin/adfi/adfi-git.ts` |
| 7 | `parseAdfiCommitMessage()` update for `[ADFI-HUMAN]` | `plugin/adfi/adfi-git.ts` |
| 8 | Symbol obsolescence (`obsoleted_at`, `obsoleted_by`) | `plugin/adfi/adfi-symbol-table.ts` |
| 9 | Derived symbol support (`derived_from`, `line_range`) | `plugin/adfi/adfi-symbol-table.ts` |
| 10 | `humanEditPolicy` config support | `plugin/adfi/index.ts`, `openclaw.plugin.json` |
| 11 | Revert algorithm update for non-paired commits | `plugin/adfi/adfi-revert.ts` |
| 12 | Unit tests: symbol splitting, line mapping, edge cases | `test/unit/unit_human_edit.ts` (new) |
| 13 | Close Open Question #3 in design-doc.md | `docs/design-doc.md` |

## References

- FS-level tracking: `docs/design/fs-level-tracking.md`
- Revert design: `docs/design/revert.md`
- On-demand tracking: `docs/design/on-demand-tracking.md`
- Symbol design: `docs/design/symbol.md`
- Main design doc, Open Question #3: `docs/design-doc.md`
