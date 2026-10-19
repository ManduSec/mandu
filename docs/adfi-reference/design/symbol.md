# Mandu Symbol

## Purpose

Symbols are opaque placeholders that replace untrusted values in the agent
context. When Mandu intercepts untrusted inbound data (e.g., `web_fetch`
results), it replaces raw values with `$MDU:` symbols so the LLM never
sees attacker-controlled content directly.

Symbols are resolved back to real values when needed: in agent outbound data
(tool params, user-facing messages) and in the human-view (file commits).

See [architecture.md](../architecture.md) for how symbols fit into agent
context-level data flow tracking.

## Symbol Format

The default format:

```
$MDU:<tool>[<hash>].<field>
```

- `<tool>` -- the tool that produced the value (e.g., `web_fetch`, `exec`)
- `<hash>` -- 4-char random hex, collision-checked against existing symbols
- `<field>` -- optional field path (e.g., `title`, `results[0].description`)

Examples:
```
$MDU:web_fetch[9f3e].title
$MDU:web_fetch[71a5].text
$MDU:exec[a2b1]                (no field, whole output)
$MDU:web_fetch[a1b2].body.title (derived symbol from inspect_symbol)
```

The format is pluggable. `adfi-symbol-format.ts` defines the `SymbolFormat`
interface. Alternative formats can be registered via `setActiveFormat()` before
the plugin initializes.

**TODO: compare alternative symbol formats for utility and cost efficiency.**

## Storage

Symbols are stored in two places.

### In-Memory Symbol Table

At runtime, symbols live in a module-level `globalSymbols` map shared across
all sessions and all `register()` calls. OpenClaw calls `register()` in both
the `[gateway]` and `[plugins]` phases, creating separate plugin instances.
Without a shared module-level map, symbols stored by hooks would be invisible
to tools (and vice versa).

```typescript
const globalSymbols: SymbolMap = { symbols: new Map<string, SymbolEntry>() };
```

Each `SymbolEntry` stores the raw value, tool name, field path, origin,
session key, and call ID.

The map is global (not per-session) so that webhook symbols are resolvable
from any session context. Per-session cleanup happens on `session_end`,
`command:reset`, and `command:new` by filtering entries on `session_key`.

All hook handlers (`before_tool_call`, `tool_result`, `message_sending`) read
from and write to this in-memory table. The persistent SQLite table was added
later for cross-process access (file tracking). The in-memory table remains
the primary store because it is shared across OpenClaw's gateway and plugins
phases (which create separate plugin instances but share module-level state).

**TODO: check if the in-memory symbol table is still necessary, or if all
reads could go through SQLite directly.**

### Persistent Symbol Table (SQLite)

The persistent symbol table is stored at:

```
$HOME/.dualview/symbols.db
```

### Schema

```sql
CREATE TABLE symbols (
  sym_name    TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  tool        TEXT NOT NULL,
  field       TEXT,
  call_id     TEXT,
  origin      TEXT,
  session_key TEXT,
  created_at  INTEGER NOT NULL
);

CREATE INDEX idx_symbols_value ON symbols(value);
CREATE INDEX idx_symbols_call_id ON symbols(call_id);
```

- **WAL mode** enabled for concurrent read safety (commit and human-edit
  handlers read while plugin hooks write).
- **Value index** allows fast reverse lookups (`findSymbolsByValue`).
- **call_id index** allows targeted provenance lookups.
- The DB is created on first access. Schema migrations are automatic
  (`call_id` column added if missing).

### How the two tables stay in sync

Every `allocateSymbol` call writes to both the in-memory table and the
persistent table (via `persistSymbol`) immediately. They are always consistent
for writes.

For reads, the in-memory table is used by plugin hooks (same process, fast).
The persistent table is used by worktree commit handlers and human-edit
reconciliation when they need durable symbol values.

### Why SQLite over JSON

The previous implementation used a JSON symbol table.

| Concern | JSON file | SQLite |
|---|---|---|
| Concurrent access | Unsafe (read-modify-write race) | WAL mode handles concurrent readers |
| Reverse lookup (value -> symbol) | Full scan O(n) | Indexed O(log n) |
| Large tables | Entire file parsed on load | Can query selectively |
| Atomic writes | Manual tmp+rename | Built-in transactions |

## Agent Context-Level Data Flow Tracking

Symbols flow through the agent context via a global in-memory map
(`globalSymbols`) shared across all sessions. The persistent SQLite DB is used
for durable symbol lookups by file-tracking handlers.

```
hook:tool_result (symbolize mode)
  -> allocateSymbol(globalSymbols, {...})    in-memory
  -> persistSymbol(symName, entry)           write to DB

hook:before_tool_call
  -> deepResolveSymbols(params, globalSymbols.symbols)
     resolve symbols to real values in agent outbound data

hook:message_sending
  -> deepResolveSymbols(content, globalSymbols.symbols)
     resolve symbols for user-facing reply

Worktree file commit handler
  -> loadSymbolMap()                         reads from DB
  -> resolveAllSymbols(text, symbolMap)      resolve symbols in files
```

## API

All functions exported from `plugin/adfi/adfi-symbol-table.ts`.

### In-memory operations

| Function | Description |
|---|---|
| `allocateSymbol(map, opts)` | Create a new symbol entry. Returns the symbol name. |
| `resolveSymbol(map, symName)` | Look up a symbol -> raw value. Returns `null` if unknown. |
| `findSymbolsByValue(map, rawValue)` | Reverse lookup: find all symbols for a given raw value. |
| `findSymbolsByCallId(map, callId)` | Find all symbols associated with a tool call ID. |
| `resolveAllSymbols(text, map)` | Replace all symbols in a string with raw values. |
| `hasSymbols(text)` | Check if a string contains any symbol references. |

### Persistence

| Function | Description |
|---|---|
| `getSymbolDbPath()` | Returns the default DB path |
| `loadSymbolMap(dbPath?)` | Open the DB, read all rows into a `SymbolMap`, close. |
| `saveSymbolMap(map, dbPath?)` | Upsert all entries in a transaction. |
| `persistSymbol(symName, entry, dbPath?)` | Upsert a single symbol (incremental write). |
| `openSymbolDb(dbPath?)` | Open/create the DB, apply schema. Returns the handle. |

`loadSymbolMap` and `saveSymbolMap` open and close the DB each call. No
long-lived connection. This is safe because `better-sqlite3` opens are fast
(~1ms) and the symbol table is small.

## Inspecting the DB

```bash
ADFI_DB=~/.dualview/symbols.db

# List all symbols
sqlite3 -header -column $ADFI_DB "SELECT * FROM symbols;"

# Count entries
sqlite3 $ADFI_DB "SELECT COUNT(*) FROM symbols;"

# Search by tool name
sqlite3 -header -column $ADFI_DB \
  "SELECT sym_name, value FROM symbols WHERE tool='web_fetch';"

# Find symbols by call ID
sqlite3 -header -column $ADFI_DB \
  "SELECT sym_name, value FROM symbols WHERE call_id='abc123';"

# JSON output
sqlite3 -json $ADFI_DB "SELECT * FROM symbols;"
```

## File Location

```
plugin/adfi/adfi-symbol-table.ts    implementation
plugin/adfi/adfi-symbol-format.ts   pluggable symbol format interface
```
