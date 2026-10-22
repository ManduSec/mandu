#!/usr/bin/env node
// transcript-shapes.mjs — turn real agent transcripts into a test fixture that
// keeps their STRUCTURE and none of their content
// (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md §6).
//
//   node scripts/transcript-shapes.mjs <out.jsonl> <in>... [--per-shape N]
//
// An input is a JSONL transcript (Claude Code, Codex, OpenClaw before 9.x,
// Goose's older sessions and its request log, Gemini CLI's chats since 0.39,
// Copilot CLI's events), a whole-file JSON one (Gemini CLI's older chats:
// its header, then each message), or an agent's SQLite store
// (`.db`, `.sqlite`: OpenCode's opencode.db, Goose's sessions.db, OpenClaw
// 9.x's openclaw-agent.sqlite). A store is opened read-only and immutable (no
// lock, no file created, transcript-stores.ts `openAgentStore`), and each row
// of the tables the scan reads becomes a record `{table, ...columns}` with
// its JSON columns parsed.
//
// Each record's shape is its keys and value types, with the values of a few
// structural keys (`type`, `role`, a block's `type`, …) kept. The fixture keeps
// at most N records (default 2) of each shape, in their first order, and in
// them replaces every other string with a synthetic one: ids by stable
// stand-ins (`id-1`, so a tool call and its result stay linked), times by an
// ascending clock, a tool's name by itself when it is a known built-in tool
// and `mcp__server__tool` otherwise, a working directory by
// `/home/user/project`, and any other text by `<text>` (never a value a
// schema field holds, so a test can tell content from structure). Numbers and booleans are
// kept (counts, flags). Nothing the agent read, ran, wrote or was told
// survives; the unit tests then mark every string field and check which ones
// the scan's readers treat as sent to the model.
//
// PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const perAt = args.indexOf("--per-shape");
const perShape = perAt >= 0 ? Number(args.splice(perAt, 2)[1]) : 2;
const [out, ...inputs] = args;
if (!out || inputs.length === 0 || !Number.isInteger(perShape) || perShape < 1) {
  process.stderr.write("usage: transcript-shapes.mjs <out.jsonl> <in.jsonl|in.db|in.sqlite>... [--per-shape N]\n");
  process.exit(2);
}

/** Keys whose string value is structure, kept when it reads as a token. */
const ENUM_KEYS = new Set([
  "type", "role", "status", "subtype", "level", "stop_reason", "userType", "entrypoint", "commandMode", "permissionMode", "mode", "phase", "decision",
  "table", "action", "goose_mode", "session_type", "customType", "stopReason", "notificationType", "reason", "finish", "agent", "audience",
  "kind", "agentMode", "delivery", "code", "infoType", "producer",
]);
/** Keys holding an id; equal ids stay equal. */
const ID_KEYS = new Set([
  "id", "uuid", "parentUuid", "tool_use_id", "call_id", "sessionId", "session_id", "requestId", "promptId", "messageId", "leafUuid", "logicalParentUuid", "turn_id", "agentId", "source_uuid", "delivery_id", "runId", "taskId",
  "parentId", "toolCallId", "callID", "messageID", "sessionID", "parentID", "message_id", "parent_id", "parent_session_id", "current_session_id", "previous_session_id", "session_key", "firstKeptEntryId", "project_id",
  "interactionId", "turnId", "reasoningId", "clientRequestId", "serviceRequestId", "apiCallId", "$rewindTo", "projectHash",
]);
/** Keys holding a time. */
const TIME_KEYS = new Set(["timestamp", "ts", "created_at", "started_at", "updated_at", "archived_at", "startTime", "lastUpdated", "resumeTime"]);
/** Keys holding a working directory or a path. */
const PATH_KEYS = new Set(["cwd", "file_path", "path", "filename", "displayPath", "outputFilePath", "transcript_path", "directory", "working_dir", "worktree", "filePath", "root", "dir_path", "gitRoot"]);
/** Built-in tool names kept as they are (Claude Code, Codex, OpenCode, Goose, OpenClaw). */
const TOOLS = new Set([
  "Bash", "BashOutput", "KillShell", "Monitor", "Read", "Write", "Edit", "MultiEdit", "NotebookRead", "NotebookEdit", "Grep", "Glob", "LS",
  "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite", "ToolSearch", "Skill", "SendMessage", "AskUserQuestion",
  "exec", "shell", "exec_command", "write_stdin", "apply_patch", "update_plan", "view_image", "wait", "local_shell",
  "bash", "read", "write", "edit", "grep", "glob", "list", "webfetch", "websearch", "task", "todowrite", "skill", "patch", "subagent", "question",
  "developer__shell", "tree", "analyze", "delegate", "load", "process", "web_fetch", "web_search", "ls", "browser", "message",
  "run_shell_command", "read_file", "read_many_files", "grep_search", "search_file_content", "list_directory", "google_web_search", "write_file", "replace",
  "powershell", "read_bash", "write_bash", "view", "create", "str_replace_editor",
]);
/** Keys whose value names a tool. */
const TOOL_KEYS = new Set(["name", "tool", "toolName"]);
/** A SQLite column holding JSON. */
const JSON_COLUMNS = new Set(["data", "content_json", "metadata_json", "event_json", "permission", "extension_data", "model_config_json", "recipe_json", "entry_json"]);
/** The tables of each store the scan reads. */
const STORE_TABLES = ["session", "session_v2", "message", "part", "session_message", "sessions", "messages", "session_windows", "transcript_events"];
const TOKEN_RE = /^[A-Za-z_][A-Za-z0-9_.:-]{0,40}$/;

const ids = new Map();
let clock = Date.parse("2026-01-01T00:00:00.000Z");
const idOf = (v) => {
  if (!ids.has(v)) ids.set(v, `id-${ids.size + 1}`);
  return ids.get(v);
};

/** The structural values of a record (every `type`, `role`, `status`,
 *  `table`, a built-in tool's name) to a small depth: the kinds a reader
 *  judges it by. */
function kinds(v, depth = 0, acc = new Set()) {
  if (depth > 5 || v === null || typeof v !== "object") return acc;
  for (const [k, x] of Object.entries(v)) {
    if ((k === "type" || k === "role" || k === "status" || k === "table") && typeof x === "string") acc.add(`${k}=${x}`);
    else if (TOOL_KEYS.has(k) && typeof x === "string" && TOOLS.has(x)) acc.add(`tool=${x}`);
    else if (typeof x === "object") kinds(x, depth + 1, acc);
  }
  return acc;
}

/** The record's shape: its kind in the conversation (its `type`, an
 *  attachment's or a payload's `type`, the message's role, the content
 *  blocks' types with a built-in tool call's name, whether it carries a
 *  local tool result) and its top-level keys. Fine enough to keep every kind
 *  of record the readers judge, coarse enough to keep the fixture small. */
function shape(rec) {
  if (rec === null || typeof rec !== "object" || Array.isArray(rec)) return typeof rec;
  if (typeof rec.table === "string") return JSON.stringify([Object.keys(rec).sort(), [...kinds(rec)].sort()]);
  // A Gemini CLI message is its own message; its parts have no `type`, so a
  // part is told by its keys.
  const msg = rec.message ?? rec.payload ?? (Array.isArray(rec.content) ? rec : {});
  const blocks = Array.isArray(msg.content)
    ? [...new Set(msg.content.map((b) => (b && typeof b === "object" ? `${b.type ?? Object.keys(b).sort().join("+")}${b.type === "tool_use" && TOOLS.has(b.name) ? `:${b.name}` : ""}:${typeof b.content}` : typeof b)))].sort()
    : [typeof msg.content];
  const pname = rec.payload?.name;
  return JSON.stringify([
    Object.keys(rec).sort(), rec.type, rec.attachment?.type, rec.payload?.type, msg.role, blocks,
    typeof rec.toolUseResult, typeof pname === "string" && TOOLS.has(pname) ? pname : typeof pname, typeof rec.payload?.output,
    [...kinds(rec)].sort(),
    // A Copilot CLI event's data keys (a call that succeeded and one that failed differ there).
    rec.data !== null && typeof rec.data === "object" && !Array.isArray(rec.data) ? Object.keys(rec.data).sort() : null,
  ]);
}

/** A key that is data, not schema (an environment variable's name, an MCP
 *  server's, a path), replaced by a stand-in; schema keys are lower or camel
 *  case words. */
const keyIds = new Map();
const KEY_RE = /^[a-z_][A-Za-z0-9_]{0,40}$/;
const keyOf = (k) => {
  // An id used as a key (`toolu_01…`) has digits in a long random run.
  if (KEY_RE.test(k) && !/mcp/i.test(k) && !/[0-9][A-Za-z0-9]{8,}/.test(k)) return k;
  // Gemini CLI's update lines (`$set`, `$patch`, `$rewindTo`).
  if (/^\$[a-zA-Z]{2,16}$/.test(k)) return k;
  if (!keyIds.has(k)) keyIds.set(k, `key_${keyIds.size + 1}`);
  return keyIds.get(k);
};

/** The record with its content replaced. */
function scrub(v, key) {
  if (Array.isArray(v)) return v.map((x) => scrub(x, key));
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [keyOf(k), scrub(x, k)]));
  if (typeof v !== "string") return v;
  if (ENUM_KEYS.has(key) && TOKEN_RE.test(v)) return v;
  if ((key === "mime" || key === "mimeType") && /^[a-z]+\/[a-z0-9.+-]+$/.test(v)) return v;
  // A permission rule's wildcard (OpenCode's `{permission, pattern, action}`).
  if ((key === "permission" || key === "pattern") && v === "*") return v;
  if (ID_KEYS.has(key)) return idOf(v);
  if (TIME_KEYS.has(key)) return new Date((clock += 1000)).toISOString();
  if (PATH_KEYS.has(key)) return "/home/user/project";
  if (TOOL_KEYS.has(key)) return TOOLS.has(v) ? v : "mcp__server__tool";
  if (key === "version" || key === "cli_version") return /^\d+\.\d+\.\d+$/.test(v) ? v : "0.0.0";
  return "<text>";
}

/** The rows of a SQLite store's tables the scan reads, as records, read
 *  without a lock or a write. */
async function storeRecords(file) {
  const { DatabaseSync } = await import("node:sqlite");
  const url = pathToFileURL(file);
  url.searchParams.set("immutable", "1");
  const db = new DatabaseSync(url.href, { readOnly: true }); // a URI string: Node 22.15 or later
  try {
    const have = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name));
    const recs = [];
    for (const table of STORE_TABLES) {
      if (!have.has(table)) continue;
      for (const row of db.prepare(`SELECT * FROM "${table}"`).iterate()) {
        const rec = { table };
        for (const [k, v] of Object.entries(row)) {
          if (v instanceof Uint8Array) { rec[k] = "<bytes>"; continue; }
          if (typeof v === "bigint") { rec[k] = Number(v); continue; }
          if (JSON_COLUMNS.has(k) && typeof v === "string") { try { rec[k] = JSON.parse(v); continue; } catch { /* text */ } }
          rec[k] = v;
        }
        recs.push(rec);
      }
    }
    return recs;
  } finally {
    db.close();
  }
}

/** A whole-file JSON transcript (Gemini CLI's `chats/session-*.json`, a
 *  checkpoint): an array is its records; an object with a `messages` list
 *  is its header (the object without the list) and then each message. */
function jsonRecords(file) {
  const v = JSON.parse(readFileSync(file, "utf8"));
  if (Array.isArray(v)) return v;
  if (v !== null && typeof v === "object" && Array.isArray(v.messages)) {
    const { messages, ...header } = v;
    return [{ ...header, messages: [] }, ...messages];
  }
  return [v];
}

async function recordsOf(file) {
  if (/\.(?:db|sqlite)$/.test(file)) return storeRecords(file);
  if (/\.json$/.test(file)) return jsonRecords(file);
  const recs = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (line === "") continue;
    try { recs.push(JSON.parse(line)); } catch { /* a torn line */ }
  }
  return recs;
}

const kept = new Map();
const records = [];
for (const file of inputs) {
  for (const rec of await recordsOf(file)) {
    const s = shape(rec);
    const n = kept.get(s) ?? 0;
    if (n >= perShape) continue;
    kept.set(s, n + 1);
    records.push(JSON.stringify(scrub(rec)));
  }
}
writeFileSync(out, records.join("\n") + "\n");
process.stderr.write(`transcript-shapes: ${records.length} records, ${kept.size} shapes -> ${out}\n`);
