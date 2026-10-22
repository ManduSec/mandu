/**
 * transcript-unwrapped — the session stores of agents Mandu does not run,
 * read (Gemini CLI, Copilot CLI) or only counted (Cursor) by the
 * past-sessions scan
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 item 3, §4 phase 3).
 *
 * The scan is most useful here: these are agents Mandu cannot protect yet,
 * and the record shows the person the same risk. Each reader states its
 * rule for which fields of a record the agent puts in its model requests,
 * yields only those (with how each got there), and gives the session's tool
 * calls with how each ended, as transcript-readers.ts does for the wrapped
 * agents. The rules were read off each agent's own code, not off docs:
 *
 *   - Gemini CLI (`@google/gemini-cli`, open source; 0.29.7, 0.53.1 and
 *     0.65.0 read): `GeminiChat.sendMessageStream` records the user turn's
 *     parts exactly as sent and each tool call's `result` as the
 *     functionResponse parts sent; `displayContent`, `resultDisplay` and the
 *     `info`/`warning`/`error` notices are the person's copies.
 *   - Copilot CLI (`@github/copilot`): see {@link copilotSentTexts}.
 *   - Cursor: its editor's `state.vscdb` and its CLI's `store.db` hold
 *     undocumented, server-written blobs that have changed shape several
 *     times; they are counted, never read ({@link countCursorChats}).
 *
 * Pure but for the file layer at the end, which reads each store read-only
 * (a SQLite store through `openAgentStore`). PROVENANCE (CONTRIBUTING.md
 * reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, statSync, type Stats } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { ModelProvider, SentHow, SentText, SessionMeta, TranscriptAgent } from "./transcript-scan.js";
import type { CallEnd, SessionActs, ToolCall } from "./transcript-acts.js";
import { isoTime } from "./transcript-readers.js";
import { openAgentStore, readJsonlRecords, type StoreItem } from "./transcript-stores.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const json = (v: unknown): string => (typeof v === "string" ? v : v === undefined ? "" : JSON.stringify(v));
const at = (t: string | undefined): { at?: string } => (t !== undefined ? { at: t } : {});
const toolOf = (t: string | undefined): { tool?: string } => (t !== undefined ? { tool: t } : {});
const callOf = (tool: string | undefined, input: unknown): { call?: { tool: string; input: unknown } } => (tool !== undefined ? { call: { tool, input } } : {});

/** Mandu's fail-closed answer, as its proxies write it into a tool's output. */
const MANDU_STOP_RE = /mandu_fail_closed/;

/** How a tool's result reached the model, from the tool's name. */
function toolHow(name: string | undefined, fileTools: ReadonlySet<string>, shellTools: ReadonlySet<string>): SentHow {
  if (name !== undefined && fileTools.has(name)) return "read-file";
  if (name !== undefined && shellTools.has(name)) return "command-output";
  return "tool-result";
}

/** Every string under `v` (a tool's response object), media left out. */
function stringsUnder(v: unknown, depth = 0): string[] {
  if (depth > 16) return [];
  if (typeof v === "string") return v === "" ? [] : [v];
  if (Array.isArray(v)) return v.flatMap((x) => stringsUnder(x, depth + 1));
  if (!isObj(v)) return [];
  const out: string[] = [];
  for (const [k, x] of Object.entries(v)) {
    if (k === "inlineData" || k === "fileData" || k === "mimeType") continue;
    out.push(...stringsUnder(x, depth + 1));
  }
  return out;
}

// ── Gemini CLI ──────────────────────────────────────────────────────────────

/** Gemini CLI's tools that return a file's content. */
const GEMINI_FILE_TOOLS: ReadonlySet<string> = new Set(["read_file", "read_many_files", "glob", "grep_search", "search_file_content", "list_directory"]);
/** Gemini CLI's shell tool. */
const GEMINI_SHELL_TOOLS: ReadonlySet<string> = new Set(["run_shell_command"]);
/** The answer Gemini CLI sends for a call the person declined, or the rest
 *  of a batch they declined (scheduler.js, state-manager.js). */
const GEMINI_REFUSED_RE = /\[Operation Cancelled\] Reason: User (?:denied execution|cancelled operation)/;
/** Its shell's line for a non-zero exit (shell.js). */
const GEMINI_EXIT_RE = /(?:^|\n)Exit Code: [1-9]/;
/** The marker before the files an `@path` in the person's message attached
 *  (atCommandProcessor.ts), and each file's head. */
const GEMINI_FILES_START = "\n--- Content from referenced files ---";
const GEMINI_FILES_END = "\n--- End of content ---";
const GEMINI_FILE_HEAD_RE = /^\nContent from @(.+):\n$/;

/** A call's id as the model's functionCall and its functionResponse carry
 *  it: from 0.53 the record keeps a `<name>__` prefix the agent strips
 *  before sending. */
const geminiCallId = (id: unknown, name: string | undefined): string | undefined => {
  const s = str(id);
  if (s === undefined) return undefined;
  return name !== undefined && s.startsWith(`${name}__`) ? s.slice(name.length + 2) : s;
};

/** The model a Gemini message names, as a provider: Google for `gemini-*`
 *  (the Gemini API or Vertex), another otherwise. */
function geminiProvider(model: unknown): ModelProvider | undefined {
  if (typeof model !== "string" || model === "") return undefined;
  return /^gemini-/.test(model) ? "google" : "other";
}

/** The records of one Gemini CLI chat file as its reader takes them: each
 *  line of a `.jsonl` (0.39 and later: the metadata line, message lines, and
 *  `$set` / `$patch` / `$rewindTo` lines), or, for an older whole-file
 *  `.json`, the object itself (its `messages` inside). */
export type GeminiRecord = unknown;

/**
 * The texts of one Gemini CLI session that went to the model. Every line of
 * the file is read, not the view a resume rebuilds: a message rewound or a
 * result masked later was still sent before. The rule
 * (`GeminiChat.sendMessageStream`, `recordCompletedToolCalls`):
 *
 *   - a `user` message's `content` is the parts sent: its text is the
 *     person's (a `!` command's output among it), the files an `@path`
 *     attached (after the `--- Content from referenced files ---` marker)
 *     and the agent's own `<session_context>` / `<hook_context>` turns are
 *     context, a `functionResponse` part is the tool's result (every string
 *     of its `response`);
 *   - a `gemini` message's `content` (its text, its functionCalls' `args`),
 *     its `thoughts` and each `toolCalls[].args` the model wrote; each
 *     `toolCalls[].result` is the functionResponse parts sent back;
 *   - `$set.messages` (a full snapshot, 0.39 to 0.63) and `$patch` updates
 *     (0.64 and later) are read the same way.
 *
 * Never `displayContent` (the person's raw query), a call's `resultDisplay`
 * (the person's copy: a diff holds a whole file the model may never have
 * read), `description`, `displayName`, the `info` / `warning` / `error`
 * notices, `tokens`, `summary` or `memoryScratchpad`, nor media. `meta`
 * collects the provider from the messages' `model` and the cwd from a
 * subagent's `directories`. Pure.
 */
export function* geminiSentTexts(records: Iterable<GeminiRecord>, meta: SessionMeta = {}): Generator<SentText> {
  const calls = new Map<string, { name: string; args: unknown }>();
  const types = new Map<string, string>();
  const noteCall = (c: Obj): void => {
    const name = str(c["name"]);
    const id = geminiCallId(c["id"], name);
    if (name !== undefined && id !== undefined) calls.set(id, { name, args: c["args"] });
  };
  function* response(p: Obj, t: string | undefined): Generator<SentText> {
    const fr = p["functionResponse"];
    if (!isObj(fr)) return;
    const name = str(fr["name"]);
    const call = calls.get(geminiCallId(fr["id"], name) ?? "");
    const tool = name ?? call?.name;
    for (const text of stringsUnder(fr["response"])) {
      yield { how: toolHow(tool, GEMINI_FILE_TOOLS, GEMINI_SHELL_TOOLS), text, ...toolOf(tool), ...at(t), ...(call !== undefined ? callOf(call.name, call.args) : {}) };
    }
  }
  function* userContent(content: unknown, t: string | undefined): Generator<SentText> {
    if (typeof content === "string") {
      if (content !== "") yield { how: /^<(?:session|hook)_context>/.test(content) ? "context" : "your-message", text: content, ...at(t) };
      return;
    }
    let inFiles = false;
    let path: string | undefined;
    for (const p of arr(content)) {
      if (!isObj(p)) continue;
      if (isObj(p["functionResponse"])) { yield* response(p, t); continue; }
      const text = str(p["text"]);
      if (text === undefined || text === "") continue;
      if (text === GEMINI_FILES_START) { inFiles = true; continue; }
      if (text === GEMINI_FILES_END) { inFiles = false; path = undefined; continue; }
      const head = inFiles ? GEMINI_FILE_HEAD_RE.exec(text) : null;
      if (head !== null) { path = head[1]; continue; }
      if (inFiles) yield { how: "context", text, ...at(t), ...(path !== undefined ? { path } : {}) };
      else yield { how: /^<(?:session|hook)_context>/.test(text) ? "context" : "your-message", text, ...at(t) };
    }
  }
  function* geminiContent(content: unknown, t: string | undefined): Generator<SentText> {
    if (typeof content === "string") { if (content !== "") yield { how: "ai-wrote", text: content, ...at(t) }; return; }
    for (const p of arr(content)) {
      if (!isObj(p)) continue;
      const text = str(p["text"]);
      if (text !== undefined && text !== "") { yield { how: "ai-wrote", text, ...at(t) }; continue; }
      const fc = p["functionCall"];
      if (isObj(fc) && fc["args"] !== undefined) {
        noteCall(fc);
        const name = str(fc["name"]);
        yield { how: "ai-wrote", text: json(fc["args"]), ...toolOf(name), ...at(t), ...callOf(name, fc["args"]) };
      }
    }
  }
  function* toolCalls(list: unknown, t: string | undefined): Generator<SentText> {
    for (const c of arr(list)) {
      if (!isObj(c)) continue;
      noteCall(c);
      const name = str(c["name"]);
      const ct = isoTime(c["timestamp"]) ?? t;
      if (c["args"] !== undefined) yield { how: "ai-wrote", text: json(c["args"]), ...toolOf(name), ...at(ct), ...callOf(name, c["args"]) };
      for (const p of arr(c["result"])) if (isObj(p)) yield* response(p, ct);
    }
  }
  function* message(m: Obj): Generator<SentText> {
    const id = str(m["id"]);
    const type = str(m["type"]) ?? (id !== undefined ? types.get(id) : undefined);
    if (id !== undefined && type !== undefined) types.set(id, type);
    const t = isoTime(m["timestamp"]);
    if (type === "user") {
      if ("content" in m) yield* userContent(m["content"], t);
    } else if (type === "gemini") {
      if (meta.provider === undefined) { const p = geminiProvider(m["model"]); if (p !== undefined) meta.provider = p; }
      // The calls first: the content's functionCalls carry the same ids.
      yield* toolCalls(m["toolCalls"], t);
      if ("content" in m) yield* geminiContent(m["content"], t);
      for (const th of arr(m["thoughts"])) {
        if (!isObj(th)) continue;
        const text = [str(th["subject"]), str(th["description"])].filter((x) => x !== undefined && x !== "").join("\n");
        if (text !== "") yield { how: "ai-wrote", text, ...at(isoTime(th["timestamp"]) ?? t) };
      }
    }
  }
  for (const r of records) {
    if (!isObj(r)) continue;
    if (meta.cwd === undefined && typeof r["sessionId"] === "string") {
      const dirs = arr(r["directories"]).filter((d): d is string => typeof d === "string" && d.startsWith("/"));
      if (dirs[0] !== undefined) meta.cwd = dirs[0];
    }
    if (Array.isArray(r["messages"])) for (const m of r["messages"]) if (isObj(m)) yield* message(m);
    const set = r["$set"];
    if (isObj(set) && Array.isArray(set["messages"])) for (const m of set["messages"]) if (isObj(m)) yield* message(m);
    const patch = r["$patch"];
    if (isObj(patch)) {
      for (const u of [patch, ...arr(patch["updates"])]) {
        if (!isObj(u) || typeof u["id"] !== "string") continue;
        yield* message({ id: u["id"], ...("content" in u ? { content: u["content"] } : {}), ...(Array.isArray(u["toolCalls"]) ? { toolCalls: u["toolCalls"] } : {}) });
      }
    }
    if (typeof r["id"] === "string" && !("$patch" in r)) yield* message(r);
  }
}

/** How a Gemini CLI tool call ended: a declined call (`cancelled`, the
 *  person's "no", or the rest of the batch they declined), an error, a
 *  shell's non-zero `Exit Code`, Mandu's stop. */
function geminiEnd(c: Obj): CallEnd | undefined {
  const text = stringsUnder(arr(c["result"]).map((p) => (isObj(p) ? p["functionResponse"] : undefined))).join("\n");
  if (MANDU_STOP_RE.test(text)) return "stopped-by-mandu";
  if (c["status"] === "cancelled") return GEMINI_REFUSED_RE.test(text) ? "refused" : "failed";
  if (c["status"] === "error") return "failed";
  return GEMINI_EXIT_RE.test(text) ? "failed" : undefined;
}

/** A Gemini CLI session's tool calls (each `gemini` message's `toolCalls`,
 *  the last record of a call winning) with how each ended. Gemini CLI keeps
 *  no record of its approval mode (`--yolo`, `--approval-mode`): the call
 *  records leave it out, so prompts off is never counted. Pure. */
export function geminiActs(records: Iterable<GeminiRecord>): SessionActs {
  const byId = new Map<string, ToolCall>();
  const anon: ToolCall[] = [];
  const add = (list: unknown, t: string | undefined): void => {
    for (const c of arr(list)) {
      if (!isObj(c)) continue;
      const tool = str(c["name"]);
      if (tool === undefined) continue;
      const end = geminiEnd(c);
      const call: ToolCall = { tool, input: c["args"], ...at(isoTime(c["timestamp"]) ?? t), ...(end ? { end } : {}) };
      const id = str(c["id"]);
      if (id !== undefined) byId.set(id, call); else anon.push(call);
    }
  };
  const msg = (m: unknown): void => { if (isObj(m) && (m["type"] === "gemini" || m["type"] === undefined)) add(m["toolCalls"], isoTime(m["timestamp"])); };
  for (const r of records) {
    if (!isObj(r)) continue;
    for (const m of arr(r["messages"])) msg(m);
    if (isObj(r["$set"])) for (const m of arr(r["$set"]["messages"])) msg(m);
    if (typeof r["id"] === "string" && r["type"] === "gemini") msg(r);
  }
  return { calls: [...byId.values(), ...anon], skippedPrompts: false };
}

// ── Copilot CLI ─────────────────────────────────────────────────────────────

/** Copilot CLI's tools that return a file's content. */
const COPILOT_FILE_TOOLS: ReadonlySet<string> = new Set(["view", "str_replace_editor", "grep", "glob"]);
/** Its shell tools and the ones that read a running shell's output. */
const COPILOT_SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "powershell", "read_bash", "write_bash", "read_powershell", "write_powershell"]);
/** Its answers for a call the person, a rule or a hook turned down. */
const COPILOT_REFUSED_RE = /user rejected this tool call|denied by the user|Permission to run this tool was denied|Permission denied|Access denied: .* excluded by/i;
/** Its shell's line for a non-zero exit. */
const COPILOT_EXIT_RE = /<exited with (?:exit code [1-9]\d*|error:)/;

/** The model provider of a Copilot CLI session: its requests go to GitHub
 *  Copilot's service, whatever model serves them, unless the session names
 *  a provider of its own (`providerId`). */
function copilotProvider(id: unknown): ModelProvider {
  return typeof id === "string" && id !== "" && !/github|copilot/i.test(id) ? "other" : "github";
}

/** The working directory a Copilot CLI event's context names. */
function copilotCwd(data: Obj): string | undefined {
  const c = data["context"];
  const cwd = isObj(c) ? str(c["cwd"]) : str(data["cwd"]);
  return cwd !== undefined && cwd.startsWith("/") ? cwd : undefined;
}

/**
 * The texts of one Copilot CLI session (its `events.jsonl`, one event a
 * line: `{id, timestamp, parentId, type, data}`) that went to the model.
 * The rule (the session's projection of its events into chat messages,
 * `processEventForState`, read in 0.0.343, 0.0.373 and 1.0.44 and held by
 * the same strings and schema in 1.0.79 and 1.0.101):
 *
 *   - `user.message`: `transformedContent` when present (what the model
 *     got: the prompt with its date, reminders and a selection inlined),
 *     else `content`; an attached file is only named there, its content
 *     read by a tool, an image sent as media;
 *   - `assistant.message`: `content`, each `toolRequests[].arguments` and
 *     `reasoningText` the model wrote; `assistant.reasoning`'s `content`;
 *   - `tool.execution_complete`: a call that succeeded sends
 *     `result.content`, one that failed `error.message`, unless
 *     `isUserRequested` (the person's own `!` command, which the agent
 *     leaves out of the request);
 *   - `system.message`, `system.notification` and `skill.invoked`'s
 *     `content` as context; `session.compaction_complete`'s
 *     `summaryContent` (the model wrote it); a `session.handoff`'s text
 *     `context`.
 *
 * Never `result.detailedContent` (the person's copy: a whole diff),
 * `result.contents`, `toolTelemetry`, `tool.execution_start` (its arguments
 * repeat the request's), `tool.user_requested`, the `permission.*`,
 * `hook.*`, `session.info` / `warning` / `error` / `shutdown` events,
 * `reasoningOpaque` or `encryptedContent`, nor a binary asset. A
 * subagent's events (`agentId`, `parentToolCallId`) went to its own model
 * and are read the same way. `meta` collects the cwd from the session's
 * context and the provider. Pure.
 */
export function* copilotSentTexts(records: Iterable<unknown>, meta: SessionMeta = {}): Generator<SentText> {
  const calls = new Map<string, { name: string; args: unknown }>();
  let provider: unknown;
  for (const r of records) {
    if (!isObj(r) || !isObj(r["data"])) continue;
    const d = r["data"];
    const t = isoTime(r["timestamp"]);
    switch (r["type"]) {
      case "session.start":
      case "session.resume":
      case "session.context_changed": {
        const cwd = copilotCwd(d);
        if (cwd !== undefined && meta.cwd === undefined) meta.cwd = cwd;
        if (provider === undefined && typeof d["providerId"] === "string") provider = d["providerId"];
        break;
      }
      case "user.message": {
        const text = str(d["transformedContent"]) ?? str(d["content"]);
        if (text) yield { how: "your-message", text, ...at(t) };
        break;
      }
      case "assistant.message": {
        if (provider === undefined && typeof d["providerId"] === "string") provider = d["providerId"];
        const text = str(d["content"]);
        if (text) yield { how: "ai-wrote", text, ...at(t) };
        const reasoning = str(d["reasoningText"]);
        if (reasoning) yield { how: "ai-wrote", text: reasoning, ...at(t) };
        for (const q of arr(d["toolRequests"])) {
          if (!isObj(q)) continue;
          const name = str(q["name"]);
          const id = str(q["toolCallId"]);
          if (id !== undefined && name !== undefined) calls.set(id, { name, args: q["arguments"] });
          if (q["arguments"] !== undefined) yield { how: "ai-wrote", text: json(q["arguments"]), ...toolOf(name), ...at(t), ...callOf(name, q["arguments"]) };
        }
        break;
      }
      case "assistant.reasoning": {
        const text = str(d["content"]);
        if (text) yield { how: "ai-wrote", text, ...at(t) };
        break;
      }
      case "tool.execution_complete": {
        if (d["isUserRequested"] === true) break;
        const call = calls.get(str(d["toolCallId"]) ?? "");
        const res = isObj(d["result"]) ? d["result"] : {};
        const err = isObj(d["error"]) ? str(d["error"]["message"]) : undefined;
        const text = d["success"] === true ? str(res["content"]) : err ?? (d["success"] === false ? undefined : str(res["content"]));
        if (text) yield { how: toolHow(call?.name, COPILOT_FILE_TOOLS, COPILOT_SHELL_TOOLS), text, ...toolOf(call?.name), ...at(t), ...(call !== undefined ? callOf(call.name, call.args) : {}) };
        break;
      }
      case "system.message":
      case "system.notification":
      case "skill.invoked": {
        const text = str(d["content"]);
        if (text) yield { how: "context", text, ...at(t) };
        break;
      }
      case "session.compaction_complete": {
        const text = str(d["summaryContent"]);
        if (text) yield { how: "ai-wrote", text, ...at(t) };
        break;
      }
      case "session.handoff": {
        const text = str(d["context"]);
        if (text) yield { how: "context", text, ...at(t) };
        break;
      }
      default:
        break;
    }
  }
  meta.provider = copilotProvider(provider);
}

/** Did a Copilot CLI session run with its prompts off? Its record says so
 *  from 1.0.79 on: a `session.permissions_changed` to allow-all (1.0.79's
 *  `allowAllPermissions`, 1.0.101's `mode: "allow-all"`), or a request made
 *  under that mode. `--allow-all-tools` and `--allow-tool` rules alone are
 *  never recorded, so such a session is not counted. */
function copilotSkipsPrompts(events: readonly Obj[]): boolean {
  let on = false;
  for (const r of events) {
    const d = isObj(r["data"]) ? r["data"] : {};
    if (r["type"] === "session.permissions_changed") {
      if (d["allowAllPermissions"] === true || d["mode"] === "allow-all") on = true;
    } else if (r["type"] === "permission.requested" && d["permissionMode"] === "allow-all") on = true;
  }
  return on;
}

/** A Copilot CLI session's tool calls (each assistant message's
 *  `toolRequests`) with how each ended: a refusal at the prompt, by a rule
 *  or a hook (`success: false` with the refusal's words or code), a failure,
 *  a shell's non-zero exit (`shellExecution.exitCode`, or the
 *  `<exited with exit code N>` line), Mandu's stop. Pure. */
export function copilotActs(records: Iterable<unknown>): SessionActs {
  const events = [...records].filter(isObj);
  const done = new Map<string, Obj>();
  for (const r of events) if (r["type"] === "tool.execution_complete" && isObj(r["data"]) && typeof r["data"]["toolCallId"] === "string") done.set(r["data"]["toolCallId"], r["data"]);
  const calls: ToolCall[] = [];
  for (const r of events) {
    if (r["type"] !== "assistant.message" || !isObj(r["data"])) continue;
    const t = isoTime(r["timestamp"]);
    for (const q of arr(r["data"]["toolRequests"])) {
      if (!isObj(q)) continue;
      const tool = str(q["name"]);
      if (tool === undefined) continue;
      const d = done.get(str(q["toolCallId"]) ?? "");
      let end: CallEnd | undefined;
      if (d !== undefined) {
        const res = isObj(d["result"]) ? d["result"] : {};
        const err = isObj(d["error"]) ? d["error"] : {};
        const text = `${str(res["content"]) ?? ""}\n${str(err["message"]) ?? ""}`;
        const exit = isObj(d["shellExecution"]) ? d["shellExecution"]["exitCode"] : undefined;
        end = MANDU_STOP_RE.test(text) ? "stopped-by-mandu"
          : d["success"] === false ? (COPILOT_REFUSED_RE.test(text) || err["code"] === "rejected" || err["code"] === "denied" ? "refused" : "failed")
            : (typeof exit === "number" && exit !== 0) || COPILOT_EXIT_RE.test(text) ? "failed" : undefined;
      }
      calls.push({ tool, input: q["arguments"], ...at(t), ...(end ? { end } : {}) });
    }
  }
  return { calls, skippedPrompts: copilotSkipsPrompts(events) };
}

// ── The stores ──────────────────────────────────────────────────────────────

/** The kinds of the stores of this module. */
export type UnwrappedKind =
  /** Gemini CLI's `<base>/.gemini/tmp/<project>/chats/`. */
  | "gemini-chats"
  /** Copilot CLI's `session-state/<id>/events.jsonl`. */
  | "copilot-events"
  /** Cursor's editor `state.vscdb` (counted only). */
  | "cursor-editor"
  /** The `cursor-agent` CLI's `chats/<hash>/<chat>/store.db` (counted only). */
  | "cursor-cli";

/** The kinds whose sessions are counted, never read. */
export const COUNT_ONLY_KINDS: ReadonlySet<UnwrappedKind> = new Set(["cursor-editor", "cursor-cli"]);

const ls = (d: string): string[] => { try { return readdirSync(d); } catch { return []; } };
const statOf = (p: string): Stats | undefined => { try { return statSync(p); } catch { return undefined; } };
const lstatOf = (p: string): Stats | undefined => { try { return lstatSync(p); } catch { return undefined; } };

/** Is `path` a file of a source of `kind` rooted at `root`? Pure. */
export function isUnwrappedStoreFile(kind: UnwrappedKind, root: string, path: string): boolean {
  if (!path.startsWith(`${root}/`) && path !== root) return false;
  const rel = path.slice(root.length + 1).split("/");
  switch (kind) {
    case "gemini-chats":
      // <project>/chats/<file>.json(l), or a subagent's <project>/chats/<parent>/<file>.jsonl
      return rel[1] === "chats" && ((rel.length === 3 && /\.jsonl?$/.test(rel[2]!)) || (rel.length === 4 && rel[3]!.endsWith(".jsonl")));
    case "copilot-events":
      // <id>/events.jsonl, or an older flat <id>.jsonl (0.0.343 to 0.0.373)
      return (rel.length === 2 && rel[1] === "events.jsonl") || (rel.length === 1 && rel[0]!.endsWith(".jsonl"));
    case "cursor-editor":
      return path === root;
    case "cursor-cli":
      return rel.length === 3 && rel[2] === "store.db";
  }
}

/** The project directory of a Gemini CLI project folder: its `.project_root`
 *  marker (0.29 and later), else the path `projects.json` maps to it, else
 *  the path whose sha256 names it (0.28's folders). */
function geminiProjects(tmp: string): (dir: string) => string | undefined {
  const byName = new Map<string, string>();
  try {
    const reg = JSON.parse(readFileSync(join(dirname(tmp), "projects.json"), "utf8")) as unknown;
    const projects = isObj(reg) && isObj(reg["projects"]) ? reg["projects"] : {};
    for (const [path, slug] of Object.entries(projects)) {
      if (!path.startsWith("/")) continue;
      if (typeof slug === "string") byName.set(slug, path);
      byName.set(createHash("sha256").update(path).digest("hex"), path);
    }
  } catch { /* none */ }
  return (dir) => {
    try {
      const p = readFileSync(join(dir, ".project_root"), "utf8").trim();
      if (p.startsWith("/") && !p.includes("\n")) return p;
    } catch { /* none */ }
    return byName.get(basename(dir));
  };
}

/** One Gemini CLI chat file's records: a `.jsonl`'s lines, or an older
 *  whole-file `.json` (an object holding `messages`). */
async function geminiRecords(file: string): Promise<unknown[]> {
  if (file.endsWith(".jsonl")) return readJsonlRecords(file);
  try { return [JSON.parse(readFileSync(file, "utf8")) as unknown]; } catch { return []; }
}

/**
 * The scan's units for one source of this module: a Gemini CLI chat file
 * per session (a subagent's file counts with its parent's, which names the
 * first eight characters of the parent's id), a Copilot CLI session's
 * `events.jsonl`. At most `max` per source (`overflow` counts the rest).
 * The count-only kinds give none ({@link countCursorChats} counts them).
 */
export function unwrappedItems(src: { agent: TranscriptAgent; kind: UnwrappedKind; root: string }, max: number, overflow: { n: number }): StoreItem[] {
  const out: StoreItem[] = [];
  const push = (it: StoreItem): void => { if (out.length >= max) overflow.n++; else out.push(it); };
  if (src.kind === "gemini-chats") {
    const project = geminiProjects(src.root);
    for (const p of ls(src.root)) {
      const dir = join(src.root, p);
      const chats = join(dir, "chats");
      const cwd = project(dir);
      const names = ls(chats);
      const item = (file: string, st: Stats, session: string): StoreItem => ({
        agent: src.agent, path: file, mtimeMs: st.mtimeMs, size: st.size, session,
        read: async () => {
          const recs = await geminiRecords(file);
          const meta: SessionMeta = cwd !== undefined ? { cwd } : {};
          return { texts: [...geminiSentTexts(recs, meta)], meta, acts: geminiActs(recs) };
        },
      });
      for (const n of names) {
        const f = join(chats, n);
        const st = statOf(f);
        if (st === undefined) continue;
        if (st.isFile() && /\.jsonl?$/.test(n)) { push(item(f, st, f)); continue; }
        if (!st.isDirectory()) continue;
        // A subagent's chats, under its parent session's id.
        const parent = names.find((x) => /\.jsonl?$/.test(x) && x.replace(/\.jsonl?$/, "").endsWith(`-${n.slice(0, 8)}`));
        for (const s of ls(f)) {
          const sf = join(f, s);
          const sst = statOf(sf);
          if (sst?.isFile() === true && s.endsWith(".jsonl")) push(item(sf, sst, parent !== undefined ? join(chats, parent) : f));
        }
      }
    }
  }
  if (src.kind === "copilot-events") {
    // Copilot CLI's move of its state out of `$XDG_STATE_HOME/.copilot`
    // leaves links behind: a linked folder is the other source's, not read twice.
    if (lstatOf(src.root)?.isSymbolicLink() === true) return out;
    for (const n of ls(src.root)) {
      const p = join(src.root, n);
      const l = lstatOf(p);
      if (l === undefined || l.isSymbolicLink()) continue;
      const file = l.isDirectory() ? join(p, "events.jsonl") : n.endsWith(".jsonl") ? p : undefined;
      const st = file !== undefined ? lstatOf(file) : undefined;
      if (file === undefined || st?.isFile() !== true) continue;
      push({
        agent: src.agent, path: file, mtimeMs: st.mtimeMs, size: st.size, session: file,
        read: async () => {
          const recs = await readJsonlRecords(file);
          const meta: SessionMeta = {};
          return { texts: [...copilotSentTexts(recs, meta)], meta, acts: copilotActs(recs) };
        },
      });
    }
  }
  return out;
}

/**
 * How many Cursor chats a source holds, read without a value: the editor's
 * `cursorDiskKV` rows keyed `composerData:<id>` (one per chat, a key range,
 * never a value), or the `cursor-agent` CLI's `chats/<hash>/<chat>/store.db`
 * files. A database is opened read-only through `openAgentStore`; null when
 * it cannot be (the scan counts it unreadable). 0 when there is none.
 */
export function countCursorChats(kind: "cursor-editor" | "cursor-cli", root: string): number | null {
  if (kind === "cursor-cli") {
    let n = 0;
    for (const h of ls(root)) for (const c of ls(join(root, h))) if (statOf(join(root, h, c, "store.db"))?.isFile() === true) n++;
    return n;
  }
  if (statOf(root)?.isFile() !== true) return 0;
  let db;
  try { db = openAgentStore(root).db; } catch { return null; }
  try {
    const has = db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'cursorDiskKV'").get() as { n: number };
    if (Number(has.n) === 0) return 0;
    // `;` is the character after `:`: an exact prefix range on the key.
    const r = db.prepare("SELECT count(*) AS n FROM cursorDiskKV WHERE key >= 'composerData:' AND key < 'composerData;'").get() as { n: number | bigint };
    return Number(r.n);
  } catch {
    return null;
  } finally {
    try { db.close(); } catch { /* closed */ }
  }
}
