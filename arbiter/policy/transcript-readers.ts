/**
 * transcript-readers — what OpenCode, Goose and OpenClaw put in their model
 * requests, read from the records they keep on disk
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 items 3, 4 and 10, §4).
 *
 * Each reader states its rule for which fields of a record the agent sends
 * to its model, yields only those (with how each got there), and gives the
 * session's tool calls with how each ended, so the riskier sessions and the
 * HTTP sends (transcript-acts.ts) work for these agents as for Claude Code
 * and Codex. The rules were read off each agent's own code that builds its
 * requests (OpenCode 1.18.13 `MessageV2.toModelMessages`, OpenCode 2.0.26's
 * session-message projection, Goose 1.5x's provider formats and its
 * `MessageMetadata`, OpenClaw's pi-agent `convertToLlm`), not off docs.
 *
 * The records come in already parsed: a JSONL line, or a row of the agent's
 * SQLite store with its JSON columns parsed (transcript-stores.ts reads
 * those). Pure: no file, no network. PROVENANCE (CONTRIBUTING.md reuse
 * policy): NEW Mandu code (no reference origin).
 */
import { fileURLToPath } from "node:url";
import type { ModelProvider, SentHow, SentText, SessionMeta, Turn } from "./transcript-scan.js";
import type { CallEnd, SessionActs, ToolCall } from "./transcript-acts.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Mandu's fail-closed answer, as its proxies write it into a tool's output. */
const MANDU_STOP_RE = /mandu_fail_closed/;

/** A model response's id as the scan keeps it: a short run of id characters
 *  (`msg_…`, `resp_…`, `chatcmpl-…`), never anything else from the record;
 *  the charset Mandu's proxies keep on `tllm_call` (`responseIdOf`). */
export const RESPONSE_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;

/** Keep one of a session's response ids (plan 17 §3 item 6), when it is
 *  well formed. */
export function noteResponseId(meta: SessionMeta, v: unknown): void {
  if (typeof v !== "string" || !RESPONSE_ID_RE.test(v)) return;
  (meta.responseIds ??= new Set()).add(v);
}

/** A response id when it is well formed, else undefined. */
export const responseIdOf = (v: unknown): string | undefined => (typeof v === "string" && RESPONSE_ID_RE.test(v) ? v : undefined);

/** An OpenCode session id as the scan keeps it (`ses_` and id characters):
 *  the id OpenCode sends with every model request (`X-Session-Id`, 2.x also
 *  `x-opencode-session-id`) and keeps as the session's row id; the shape
 *  Mandu's anthropic-proxy keeps on `tllm_call` (`agentSessionIdOf`). */
export const AGENT_SESSION_ID_RE = /^ses_[A-Za-z0-9]{8,120}$/;

/** An agent session id when it is well formed, else undefined. */
export const agentSessionIdOf = (v: unknown): string | undefined => (typeof v === "string" && AGENT_SESSION_ID_RE.test(v) ? v : undefined);

/**
 * The requests of one session, in order (plan 17 §3 item 6), so the scan
 * joins each text to Mandu's records, not the session as a whole. A text
 * the agent put in a request (the person's, a tool's result, context) goes
 * in the open request (`sent`) and takes the id of the response that
 * answers it: the next response the record keeps (`answered`). A text the
 * model wrote goes with the request its own response answered (`wrote`):
 * the value was in the model's context there. Another record of the
 * response just answered (Claude Code writes one per content block) closes
 * nothing, so a tool's result written between two of them waits for the
 * next response. A response with no well-formed id (none kept, or one the
 * agent made up) closes the request without one. The ids also go in
 * `meta.responseIds`, as {@link noteResponseId} keeps them. `sessionId`:
 * the agent's own id of the session, which every request of it carried
 * (OpenCode's `X-Session-Id`): each request gets it (`Turn.sessionId`), and
 * `meta.agentSessionId` too, when it is well formed.
 */
export class Turns {
  private readonly sessionId: string | undefined;
  private open: Turn;
  private last: { id: string; turn: Turn } | undefined;
  constructor(private readonly meta: SessionMeta, sessionId?: string) {
    this.sessionId = agentSessionIdOf(sessionId);
    if (this.sessionId !== undefined) meta.agentSessionId = this.sessionId;
    this.open = this.fresh();
  }

  private fresh(): Turn {
    return this.sessionId !== undefined ? { sessionId: this.sessionId } : {};
  }

  /** A text that went in the open request. */
  sent<T extends SentText>(t: T): T {
    return Turns.put(this.open, t);
  }

  /** A response came (its id, when the record keeps one): it answers the
   *  open request, which it returns, for the texts it wrote. */
  answered(id: unknown): Turn {
    const rid = responseIdOf(id);
    if (rid !== undefined && this.last?.id === rid) return this.last.turn;
    const t = this.open;
    this.open = this.fresh();
    if (rid === undefined) {
      this.last = undefined;
      return t;
    }
    t.responseId = rid;
    noteResponseId(this.meta, rid);
    this.last = { id: rid, turn: t };
    return t;
  }

  /** A text the model wrote in the response that answered `turn`. */
  wrote<T extends SentText>(turn: Turn, t: T): T {
    return Turns.put(turn, t);
  }

  private static put<T extends SentText>(turn: Turn, t: T): T {
    if (t.at !== undefined && (turn.at === undefined || t.at < turn.at)) turn.at = t.at;
    t.turn = turn;
    return t;
  }
}

/** An ISO time from a number of ms (or seconds, for a value too small to be
 *  ms) or a string the records hold. */
export function isoTime(v: unknown): string | undefined {
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return new Date(v < 1e11 ? v * 1000 : v).toISOString();
  if (typeof v === "string" && v !== "") {
    // SQLite's CURRENT_TIMESTAMP form (`2026-10-01 12:00:00`) is UTC.
    const t = Date.parse(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(v) ? `${v.replace(" ", "T")}Z` : v);
    return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
  }
  return undefined;
}

/** The text items of a content list (`{type:"text",text}` and strings). */
function textItems(content: unknown): string[] {
  if (typeof content === "string") return content === "" ? [] : [content];
  const out: string[] = [];
  for (const b of arr(content)) {
    if (typeof b === "string") { if (b !== "") out.push(b); } else if (isObj(b) && b["type"] === "text" && typeof b["text"] === "string" && b["text"] !== "") out.push(b["text"]);
  }
  return out;
}

const json = (v: unknown): string => (typeof v === "string" ? v : v === undefined ? "" : JSON.stringify(v));

/** How a tool's result reached the model, from the tool's name: a tool that
 *  reads files, one that runs a shell command, or another tool. */
function toolHow(name: string | undefined, fileTools: ReadonlySet<string>, shellTools: ReadonlySet<string>): SentHow {
  if (name !== undefined && fileTools.has(name)) return "read-file";
  if (name !== undefined && shellTools.has(name)) return "command-output";
  return "tool-result";
}

const at = (t: string | undefined): { at?: string } => (t !== undefined ? { at: t } : {});
const toolOf = (t: string | undefined): { tool?: string } => (t !== undefined ? { tool: t } : {});
/** The tool call a text belongs to (its input, or the call its result
 *  answers): the scanner shows its command or file, redacted. */
const callOf = (tool: string | undefined, input: unknown): { call?: { tool: string; input: unknown } } => (tool !== undefined ? { call: { tool, input } } : {});

/** The model provider a record names (OpenCode's `providerID`, Goose's
 *  `provider_name`, OpenClaw's `provider`): Anthropic, OpenAI, or another
 *  (a gateway, a local model); undefined when the record names none. */
export function providerOf(v: unknown): ModelProvider | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  return v === "anthropic" ? "anthropic" : v === "openai" ? "openai" : "other";
}

/** Keep the first provider a session's records name. */
function noteProvider(meta: SessionMeta, v: unknown): void {
  if (meta.provider !== undefined) return;
  const p = providerOf(v);
  if (p !== undefined) meta.provider = p;
}

// ── OpenCode ────────────────────────────────────────────────────────────────

/** OpenCode's tools that return a file's content (1.x and 2.x). */
const OPENCODE_FILE_TOOLS: ReadonlySet<string> = new Set(["read", "grep", "glob", "list"]);
/** OpenCode's tools that run a shell command: `bash` (1.x), `shell` (2.x). */
const OPENCODE_SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "shell"]);
/** OpenCode's words for a call the person (or a permission rule) turned
 *  down: PermissionRejectedError, PermissionCorrectedError,
 *  PermissionDeniedError, a dismissed question. */
const OPENCODE_REFUSED_RE = /rejected permission|specified a rule which prevents|user dismissed|QuestionRejectedError|permission\.(?:rejected|denied)/;

/** One OpenCode 1.x message of the `message` table with its `part` rows,
 *  each `data` column parsed. */
export interface OpencodeV1Message {
  id?: string;
  time_created?: number;
  data: unknown;
  parts: unknown[];
}

/** Is an OpenCode 1.x assistant message one the agent leaves out of its
 *  requests? It does for a message that ended in an error, unless the
 *  person stopped it after it had produced something. */
function opencodeV1Dropped(info: Obj, parts: readonly unknown[]): boolean {
  const err = info["error"];
  if (err === undefined || err === null) return false;
  const aborted = isObj(err) && err["name"] === "MessageAbortedError";
  return !(aborted && parts.some((p) => isObj(p) && p["type"] !== "step-start" && p["type"] !== "reasoning"));
}

/**
 * The texts of one OpenCode 1.x session (the `message` and `part` tables)
 * that went to the model, in order. The rule (`MessageV2.toModelMessages`):
 * a user message's text parts unless `ignored` (the person's text as
 * theirs; a `synthetic` part, the agent's own addition such as an attached
 * file's content, as context); an assistant message's text and reasoning
 * parts and each tool part's `state.input`, and its result: a completed
 * call's `state.output` (unless `state.time.compacted`, which the agent
 * replaces with a fixed line), a failed call's `state.error`, or the
 * `state.metadata.output` of a call the person interrupted. An assistant
 * message that ended in an error is left out, as the agent leaves it out.
 * Never `state.metadata` otherwise (the tool's local record, a shell's full
 * output among it), `state.title`, the message's own `data` (model, tokens,
 * paths), step, snapshot and patch parts, or file parts (binary media; a
 * text file's content arrives as a synthetic text part). No response id:
 * OpenCode 1.x keeps the provider's id nowhere (its step-finish part holds
 * the tokens and cost only). It sends its session's id with every request
 * instead (`X-Session-Id`, `sessionId`: the session's row id), so each text
 * carries its request (`turn`, plan 17 §3 item 6): an assistant message is
 * one step, one request; its texts and tool inputs go with it, its tools'
 * results in the next step's request. Pure.
 */
export function* opencodeV1SentTexts(messages: Iterable<OpencodeV1Message>, meta: SessionMeta = {}, sessionId?: string): Generator<SentText> {
  const turns = new Turns(meta, sessionId);
  for (const m of messages) {
    const info = isObj(m.data) ? m.data : {};
    const t = isoTime(m.time_created) ?? isoTime(isObj(info["time"]) ? info["time"]["created"] : undefined);
    const role = info["role"];
    if (meta.cwd === undefined && isObj(info["path"]) && typeof info["path"]["cwd"] === "string") meta.cwd = info["path"]["cwd"];
    if (role === "assistant") noteProvider(meta, info["providerID"]);
    if (role === "user") {
      for (const p of m.parts) {
        if (!isObj(p) || p["type"] !== "text" || p["ignored"] === true) continue;
        const text = str(p["text"]);
        if (text) yield turns.sent({ how: p["synthetic"] === true ? "context" : "your-message", text, ...at(t) });
      }
      continue;
    }
    if (role !== "assistant" || opencodeV1Dropped(info, m.parts)) continue;
    const own = turns.answered(undefined);
    for (const p of m.parts) {
      if (!isObj(p)) continue;
      const type = p["type"];
      if ((type === "text" || type === "reasoning") && typeof p["text"] === "string" && p["text"] !== "") {
        yield turns.wrote(own, { how: "ai-wrote", text: p["text"], ...at(t) });
      } else if (type === "tool" && isObj(p["state"])) {
        const tool = str(p["tool"]);
        const s = p["state"];
        if (s["input"] !== undefined) yield turns.wrote(own, { how: "ai-wrote", text: json(s["input"]), ...toolOf(tool), ...at(t), ...callOf(tool, s["input"]) });
        const md = isObj(s["metadata"]) ? s["metadata"] : {};
        const compacted = isObj(s["time"]) && s["time"]["compacted"] !== undefined && s["time"]["compacted"] !== null;
        const out = s["status"] === "completed" ? (compacted ? undefined : str(s["output"]))
          : s["status"] === "error" ? (md["interrupted"] === true && typeof md["output"] === "string" ? md["output"] : str(s["error"]))
            : undefined;
        if (out) yield turns.sent({ how: toolHow(tool, OPENCODE_FILE_TOOLS, OPENCODE_SHELL_TOOLS), text: out, ...toolOf(tool), ...at(t), ...callOf(tool, s["input"]) });
      }
    }
  }
}

/** A shell call's exit code in OpenCode's local record of it. */
function opencodeExit(state: Obj): number | undefined {
  const md = state["metadata"];
  if (!isObj(md)) return undefined;
  const e = md["exit"] ?? md["exitCode"];
  return typeof e === "number" ? e : undefined;
}

/** How an OpenCode tool call ended, from its state (either generation). */
function opencodeEnd(state: Obj, resultText: string): CallEnd | undefined {
  if (MANDU_STOP_RE.test(resultText)) return "stopped-by-mandu";
  if (state["status"] === "error") return OPENCODE_REFUSED_RE.test(resultText) ? "refused" : "failed";
  if (state["status"] !== "completed") return "failed"; // interrupted before it ended
  const exit = opencodeExit(state);
  return exit !== undefined && exit !== 0 ? "failed" : undefined;
}

/**
 * Whether an OpenCode session ran with its permission prompts off: its own
 * stored rules (the session's `permission` column, a list of `{permission,
 * pattern, action}`, the last match winning) end with a rule that allows
 * every permission on every pattern and is not followed by an `ask`.
 * OpenCode does not store its config's defaults with the session, so a
 * session the config alone let run without prompts is not counted. Pure.
 */
export function opencodeSkipsPrompts(permission: unknown): boolean {
  const rules = arr(permission).filter(isObj);
  const all = rules.map((r) => r["permission"] === "*" && r["pattern"] === "*" && r["action"] === "allow").lastIndexOf(true);
  return all >= 0 && !rules.slice(all + 1).some((r) => r["action"] === "ask");
}

/** An OpenCode 1.x session's tool calls (each `tool` part of an assistant
 *  message) with how each ended. Pure. */
export function opencodeV1Acts(messages: Iterable<OpencodeV1Message>, permission?: unknown): SessionActs {
  const calls: ToolCall[] = [];
  for (const m of messages) {
    const info = isObj(m.data) ? m.data : {};
    if (info["role"] !== "assistant") continue;
    const t = isoTime(m.time_created);
    for (const p of m.parts) {
      if (!isObj(p) || p["type"] !== "tool" || !isObj(p["state"])) continue;
      const tool = str(p["tool"]);
      if (tool === undefined) continue;
      const s = p["state"];
      const end = opencodeEnd(s, `${str(s["output"]) ?? ""}\n${str(s["error"]) ?? ""}`);
      calls.push({ tool, input: s["input"], ...at(t), ...(end ? { end } : {}) });
    }
  }
  return { calls, skippedPrompts: opencodeSkipsPrompts(permission) };
}

/** One OpenCode 2.x `session_message` row, `data` parsed. */
export interface OpencodeV2Row {
  type: string;
  seq?: number;
  time_created?: number;
  data: unknown;
}

/** The text an OpenCode 2.x file attachment puts in a request: a text
 *  file's or a directory listing's content (base64 in `data`); images and
 *  PDFs go as media and are not read. */
function opencodeV2FileText(f: Obj): string | undefined {
  if (f["mime"] !== "text/plain" && f["mime"] !== "application/x-directory") return undefined;
  const d = str(f["data"]);
  if (d === undefined || d === "") return undefined;
  try { return Buffer.from(d, "base64").toString("utf8"); } catch { return undefined; }
}

/** The text items of an OpenCode 2.x tool's result content. */
const v2Content = (content: unknown): string[] => textItems(content);

/**
 * The texts of one OpenCode 2.x session (its `session_message` rows, by
 * `seq`) that went to the model. The rule (the 2.x projection of messages
 * into a request): a `user` row's `text` (the person's), its skills' `text`
 * and its text-file attachments' content (context); a `synthetic`, `skill`
 * or `system` row's `text` (context); a `shell` row's `command` and
 * `output.output` (the person's own `!` command) unless it ran in the
 * background; a `location-switched` row's directory; an `assistant` row's
 * text and reasoning, each tool's `state.input` and its result (a completed
 * call's `state.content` text, a failed one's `state.error.message` and
 * content); a completed `compaction` row's `summary` (the model wrote it).
 * Never a row's `metadata`, a tool's `state.metadata` or `providerState`, a
 * compaction's `recent` (it repeats earlier messages), a model or agent
 * switch, or media. `meta` collects the response ids (plan 17 §3 item 6):
 * an assistant row's `providerState` is the step's provider metadata, which
 * holds `responseId` on the Responses API (`resp_…`) and Gemini; OpenCode
 * keeps none from Chat Completions or Anthropic, but every request carries
 * the session's id (`x-opencode-session-id`, `sessionId`: the row's
 * `session_id`) whatever the wire. Each text carries its request (`turn`):
 * an assistant row's id answers the rows before it and goes with the row's
 * own text and tool inputs; its tools' results went in the next step's
 * request. Pure.
 */
export function* opencodeV2SentTexts(rows: Iterable<OpencodeV2Row>, meta: SessionMeta = {}, sessionId?: string): Generator<SentText> {
  const turns = new Turns(meta, sessionId);
  for (const r of rows) {
    const d = isObj(r.data) ? r.data : {};
    const t = isoTime(r.time_created) ?? isoTime(isObj(d["time"]) ? d["time"]["created"] : undefined);
    switch (r.type) {
      case "user": {
        const text = str(d["text"]);
        if (text) yield turns.sent({ how: "your-message", text, ...at(t) });
        for (const s of arr(d["skills"])) if (isObj(s) && typeof s["text"] === "string" && s["text"] !== "") yield turns.sent({ how: "context", text: s["text"], ...at(t) });
        for (const f of arr(d["files"])) {
          const ft = isObj(f) ? opencodeV2FileText(f) : undefined;
          const src = isObj(f) && isObj(f["source"]) ? str(f["source"]["uri"]) : undefined;
          let path: string | undefined;
          if (src !== undefined && src.startsWith("file:")) { try { path = fileURLToPath(src); } catch { /* not a path */ } }
          if (ft) yield turns.sent({ how: "context", text: ft, ...at(t), ...(path !== undefined ? { path } : {}) });
        }
        break;
      }
      case "synthetic":
      case "skill":
      case "system": {
        const text = str(d["text"]);
        if (text) yield turns.sent({ how: "context", text, ...at(t) });
        break;
      }
      case "shell": {
        if (isObj(d["metadata"]) && d["metadata"]["background"] === true) break;
        const out = isObj(d["output"]) ? str(d["output"]["output"]) : undefined;
        const text = [str(d["command"]), out].filter((x) => x !== undefined && x !== "").join("\n");
        if (text) yield turns.sent({ how: "your-message", text, ...at(t) });
        break;
      }
      case "location-switched": {
        const dir = isObj(d["location"]) ? str(d["location"]["directory"]) : undefined;
        if (dir) yield turns.sent({ how: "context", text: dir, ...at(t) });
        if (dir && meta.cwd === undefined) meta.cwd = dir;
        break;
      }
      case "compaction": {
        const summary = str(d["summary"]);
        if (d["status"] === "completed" && summary) yield turns.sent({ how: "ai-wrote", text: summary, ...at(t) });
        break;
      }
      case "assistant": {
        noteProvider(meta, isObj(d["model"]) ? d["model"]["providerID"] : undefined);
        // The step's provider state keeps the response's id where the
        // provider's wire has one OpenCode reads (the Responses API, Gemini).
        // A tool's result in the row went in the next step's request.
        const own = turns.answered(isObj(d["providerState"]) ? d["providerState"]["responseId"] : undefined);
        for (const p of arr(d["content"])) {
          if (!isObj(p)) continue;
          if ((p["type"] === "text" || p["type"] === "reasoning") && typeof p["text"] === "string" && p["text"] !== "") {
            yield turns.wrote(own, { how: "ai-wrote", text: p["text"], ...at(t) });
            continue;
          }
          if (p["type"] !== "tool" || !isObj(p["state"])) continue;
          const tool = str(p["name"]) ?? str(p["tool"]);
          const s = p["state"];
          if (s["input"] !== undefined) yield turns.wrote(own, { how: "ai-wrote", text: json(s["input"]), ...toolOf(tool), ...at(t), ...callOf(tool, s["input"]) });
          const how = toolHow(tool, OPENCODE_FILE_TOOLS, OPENCODE_SHELL_TOOLS);
          if (s["status"] === "completed" || s["status"] === "error") {
            const err = isObj(s["error"]) ? str(s["error"]["message"]) : str(s["error"]);
            for (const text of [...(s["status"] === "error" && err ? [err] : []), ...v2Content(s["content"])]) yield turns.sent({ how, text, ...toolOf(tool), ...at(t), ...callOf(tool, s["input"]) });
          }
        }
        break;
      }
      default:
        break;
    }
  }
}

/** An OpenCode 2.x session's tool calls (each `tool` item of an assistant
 *  row's content) with how each ended. Pure. */
export function opencodeV2Acts(rows: Iterable<OpencodeV2Row>, permission?: unknown): SessionActs {
  const calls: ToolCall[] = [];
  for (const r of rows) {
    if (r.type !== "assistant") continue;
    const d = isObj(r.data) ? r.data : {};
    const t = isoTime(r.time_created);
    const responseId = responseIdOf(isObj(d["providerState"]) ? d["providerState"]["responseId"] : undefined);
    for (const p of arr(d["content"])) {
      if (!isObj(p) || p["type"] !== "tool" || !isObj(p["state"])) continue;
      const tool = str(p["name"]) ?? str(p["tool"]);
      if (tool === undefined) continue;
      const s = p["state"];
      const err = isObj(s["error"]) ? `${str(s["error"]["type"]) ?? ""} ${str(s["error"]["message"]) ?? ""}` : str(s["error"]) ?? "";
      const end = opencodeEnd(s, `${v2Content(s["content"]).join("\n")}\n${err}`);
      calls.push({ tool, input: s["input"], ...at(t), ...(end ? { end } : {}), ...(responseId ? { responseId } : {}) });
    }
  }
  return { calls, skippedPrompts: opencodeSkipsPrompts(permission) };
}

// ── Goose ───────────────────────────────────────────────────────────────────

/** Goose's tools that run a shell command (`shell`, older `developer__shell`).
 *  Goose has no file-read tool: it reads a file through `shell`. */
const GOOSE_SHELL_TOOLS: ReadonlySet<string> = new Set(["shell", "developer__shell"]);
const GOOSE_FILE_TOOLS: ReadonlySet<string> = new Set(["tree"]);
/** Goose's answer to a call the person declined (agents/agent.rs). */
const GOOSE_REFUSED_RE = /^The user has declined to run this tool/;
/** Goose's shell answer for a non-zero exit. */
const GOOSE_FAILED_RE = /\bCommand exited with code [1-9]/;

/** One Goose message: a `messages` row (`role`, `content_json` and
 *  `metadata_json` parsed, `created_timestamp`) or a line of an older
 *  `sessions/<id>.jsonl` (`role`, `content`, `metadata`, `created`). */
export interface GooseMessage {
  /** The message's id (the row's `message_id`, the line's `id`). */
  id?: unknown;
  role?: unknown;
  content?: unknown;
  metadata?: unknown;
  created?: unknown;
}

/** An id Goose made up for a message the provider gave none
 *  (`Message::with_generated_id`, the session manager's insert, its
 *  migration's `'msg_' || session_id || '_' || id`): never a provider's. */
const GOOSE_OWN_ID_RE = /^msg_(?:.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|.+_\d+)$/i;

/** A Goose assistant message's id when it is the provider's: Goose sets
 *  the message id from the response (`message_start`'s `msg_…`, the Chat
 *  chunks' `chatcmpl-…`, the Responses API's `resp_…`) and makes one up
 *  only when the provider sent none. */
const gooseProviderId = (id: unknown): string | undefined => (typeof id === "string" && !GOOSE_OWN_ID_RE.test(id) ? id : undefined);

/** Keep a Goose assistant message's id when it is the provider's. */
function noteGooseId(meta: SessionMeta, role: unknown, id: unknown): void {
  if (role === "assistant") noteResponseId(meta, gooseProviderId(id));
}

/** Does Goose put this message in its requests? Not when its metadata says
 *  the agent cannot see it (`agentVisible: false`, the messages a
 *  summarization replaced, Goose's own notices). */
const gooseAgentVisible = (m: GooseMessage): boolean => !(isObj(m.metadata) && m.metadata["agentVisible"] === false);

/** The model-bound text of a tool response's result: each content item
 *  whose audience includes the model (an item for the person only, such as
 *  the shell's formatted copy of its output, stays local), from Goose's
 *  `CallToolResult` (`{content, isError}`) or its older bare list; never
 *  `structuredContent`. An error result is sent as its message. */
function gooseResultTexts(result: unknown): { texts: string[]; error: boolean } {
  if (!isObj(result)) return { texts: [], error: false };
  if (result["status"] === "error") {
    const e = str(result["error"]) ?? json(result["error"]);
    return { texts: e ? [e] : [], error: true };
  }
  const value = result["value"];
  const items = isObj(value) ? arr(value["content"]) : arr(value);
  const texts: string[] = [];
  for (const it of items) {
    if (!isObj(it)) continue;
    const ann = isObj(it["annotations"]) ? it["annotations"] : undefined;
    const audience = ann !== undefined && Array.isArray(ann["audience"]) ? ann["audience"] : undefined;
    if (audience !== undefined && !audience.includes("assistant")) continue;
    if (it["type"] === "text" && typeof it["text"] === "string" && it["text"] !== "") texts.push(it["text"]);
    else if (it["type"] === "resource" && isObj(it["resource"]) && typeof it["resource"]["text"] === "string") texts.push(it["resource"]["text"]);
  }
  return { texts, error: isObj(value) && value["isError"] === true };
}

/** A Goose tool request's name and arguments, when the model's call parsed. */
function gooseCall(c: Obj): { name?: string; args?: unknown } {
  const call = c["toolCall"];
  if (!isObj(call) || call["status"] !== "success" || !isObj(call["value"])) return {};
  const name = str(call["value"]["name"]);
  return { ...(name !== undefined ? { name } : {}), args: call["value"]["arguments"] };
}

/**
 * The texts of one Goose session that went to the model, in order. The
 * rule (Goose's provider formats): messages the agent can see (not
 * `metadata.agentVisible: false`); in each, `text` items (the person's
 * message, or the model's text; a user message the person never sees,
 * `userVisible: false`, is Goose's own context, such as the
 * `<turn-context>` it adds to each turn: found on a store Goose 1.53.0
 * wrote, plan 17 §6), `thinking` (the model's), a tool request's
 * `toolCall.value.arguments` (the model wrote them), and a tool response's
 * result items meant for the model (an item whose `annotations.audience`
 * leaves the model out is the person's copy and stays local; so does
 * `structuredContent`). Never `redactedThinking`, images, the confirmation
 * prompts, `actionRequired` or `systemNotification` items (Goose's own
 * notices to the person), the session's own columns (name, recipe,
 * extension data, model config) or the token counts. `meta` collects the
 * response ids (plan 17 §3 item 6): an assistant message's id is the
 * provider's response id, unless Goose made it up (GOOSE_OWN_ID_RE). Each
 * text carries its request (`turn`): an assistant message answers the
 * messages before it and goes with its own items. Pure.
 */
export function* gooseSentTexts(messages: Iterable<GooseMessage>, meta: SessionMeta = {}): Generator<SentText> {
  const calls = new Map<string, { name: string; args: unknown }>();
  const turns = new Turns(meta);
  for (const m of messages) {
    // An older `.jsonl` file's first line is the session's metadata.
    const wd = (m as Obj)["working_dir"];
    if (m.role === undefined && typeof wd === "string" && meta.cwd === undefined) meta.cwd = wd;
    // A response's id, even on a message a summary later hid from the model.
    const own = m.role === "assistant" ? turns.answered(gooseProviderId(m.id)) : undefined;
    if (!gooseAgentVisible(m)) continue;
    const t = isoTime(m.created);
    const role = m.role;
    const put = (x: SentText): SentText => (own !== undefined ? turns.wrote(own, x) : turns.sent(x));
    // A user message the person never sees is Goose's own addition (its
    // `<turn-context>` of time and working directory, `turnContext: true`),
    // not theirs: context.
    const hiddenFromPerson = isObj(m.metadata) && m.metadata["userVisible"] === false;
    for (const c of arr(m.content)) {
      if (!isObj(c)) continue;
      const type = c["type"];
      if (type === "text" && typeof c["text"] === "string" && c["text"] !== "") {
        yield put({ how: role === "assistant" ? "ai-wrote" : hiddenFromPerson ? "context" : "your-message", text: c["text"], ...at(t) });
      } else if (type === "thinking" && typeof c["thinking"] === "string" && c["thinking"] !== "") {
        yield put({ how: "ai-wrote", text: c["thinking"], ...at(t) });
      } else if (type === "toolRequest" || type === "frontendToolRequest") {
        const { name, args } = gooseCall(c);
        const id = str(c["id"]);
        if (id !== undefined && name !== undefined) calls.set(id, { name, args });
        if (args !== undefined) yield put({ how: "ai-wrote", text: json(args), ...toolOf(name), ...at(t), ...callOf(name, args) });
      } else if (type === "toolResponse") {
        const call = calls.get(str(c["id"]) ?? "");
        const name = call?.name;
        for (const text of gooseResultTexts(c["toolResult"]).texts) yield put({ how: toolHow(name, GOOSE_FILE_TOOLS, GOOSE_SHELL_TOOLS), text, ...toolOf(name), ...at(t), ...callOf(name, call?.args) });
      }
    }
  }
}

/** A Goose session's tool calls with how each ended (an error result or
 *  `isError`, the shell's non-zero exit line, the person's decline, Mandu's
 *  stop), and whether its prompts were off: the session's `goose_mode` of
 *  `auto` (Goose's default: every tool runs without asking). Pure. */
export function gooseActs(messages: Iterable<GooseMessage>, gooseMode?: unknown): SessionActs {
  const list = [...messages];
  const results = new Map<string, { texts: string[]; error: boolean }>();
  for (const m of list) {
    for (const c of arr(m.content)) {
      if (isObj(c) && c["type"] === "toolResponse" && typeof c["id"] === "string") results.set(c["id"], gooseResultTexts(c["toolResult"]));
    }
  }
  const calls: ToolCall[] = [];
  for (const m of list) {
    if (m.role !== "assistant") continue;
    const t = isoTime(m.created);
    const responseId = responseIdOf(gooseProviderId(m.id));
    for (const c of arr(m.content)) {
      if (!isObj(c) || (c["type"] !== "toolRequest" && c["type"] !== "frontendToolRequest")) continue;
      const { name, args } = gooseCall(c);
      if (name === undefined) continue;
      const res = results.get(str(c["id"]) ?? "");
      const text = res?.texts.join("\n") ?? "";
      const end: CallEnd | undefined = res === undefined ? undefined
        : MANDU_STOP_RE.test(text) ? "stopped-by-mandu"
          : GOOSE_REFUSED_RE.test(text) ? "refused"
            : res.error || GOOSE_FAILED_RE.test(text) ? "failed" : undefined;
      calls.push({ tool: name, input: args, ...at(t), ...(end ? { end } : {}), ...(responseId ? { responseId } : {}) });
    }
  }
  return { calls, skippedPrompts: gooseMode === "auto" };
}

/** The roles of a provider request's messages, as how their text got there. */
function requestRoleHow(role: unknown): SentHow {
  if (role === "user") return "your-message";
  if (role === "assistant" || role === "model") return "ai-wrote";
  if (role === "tool" || role === "function") return "tool-result";
  return "context";
}

/** Every string under `v`, with how it got there: in a message (`role`),
 *  by its role; a tool result block (`tool_result`, `function_call_output`,
 *  `role: tool`) as a tool's result; anything else as context. */
function* requestStrings(v: unknown, how: SentHow, t: { at?: string }, depth = 0): Generator<SentText> {
  if (depth > 32) return;
  if (typeof v === "string") { if (v !== "") yield { how, text: v, ...t }; return; }
  if (Array.isArray(v)) { for (const x of v) yield* requestStrings(x, how, t, depth + 1); return; }
  if (!isObj(v)) return;
  let h = how;
  if ("role" in v) h = requestRoleHow(v["role"]);
  if (v["type"] === "tool_result" || v["type"] === "function_call_output" || v["type"] === "tool_response") h = "tool-result";
  for (const [k, x] of Object.entries(v)) {
    // Structure, not content: a block's type, a role, an id, a status
    // (Goose's answer record's `toolCall.status`).
    if (k === "type" || k === "role" || k === "id" || k === "tool_use_id" || k === "tool_call_id" || k === "call_id" || k === "status") continue;
    yield* requestStrings(x, h, t, depth + 1);
  }
}

/**
 * The texts of Goose's request log (`<state>/logs/llm_request.*.jsonl`): the
 * last requests Goose sent, whole, as each provider's payload. The rule:
 * the first record's `input` IS the request, so every string in it was sent
 * (the system prompt and the tool list as context, each message by its
 * role); a later record's `data` is the model's answer (it wrote it). Never
 * `model_config`, `usage` or an `error` record (Goose's own notes). The log
 * holds no times: `at` is the file's last write. `meta` collects the
 * response ids: a `data` record is the answer as Goose's `Message`, whose
 * `id` is the provider's (as in the session's own messages). Each file is
 * one request and its answer, so the request's texts and the answer's carry
 * the answer's id (`turn`). Pure.
 */
export function* gooseRequestLogTexts(records: Iterable<unknown>, fileTime?: string, meta: SessionMeta = {}): Generator<SentText> {
  const t = at(fileTime);
  const turns = new Turns(meta);
  let own: Turn | undefined;
  for (const r of records) {
    if (!isObj(r)) continue;
    if ("input" in r) for (const x of requestStrings(r["input"], "context", t)) yield turns.sent(x);
    if ("data" in r) {
      const d = r["data"];
      own ??= turns.answered(isObj(d) && d["role"] === "assistant" ? gooseProviderId(d["id"]) : undefined);
      for (const x of requestStrings(d, "ai-wrote", t)) yield turns.wrote(own, x);
    }
  }
}

// ── OpenClaw ────────────────────────────────────────────────────────────────

/** OpenClaw's tools that return a file's content. */
const OPENCLAW_FILE_TOOLS: ReadonlySet<string> = new Set(["read", "ls"]);
/** OpenClaw's tools that run a shell command or read a running one. */
const OPENCLAW_SHELL_TOOLS: ReadonlySet<string> = new Set(["exec", "process", "bash"]);
/** OpenClaw's answer for a command its exec approval turned down. */
const OPENCLAW_REFUSED_RE = /\b(?:denied by (?:the )?user|user denied|approval (?:was )?denied|exec denied|not approved)\b/i;

/**
 * The texts of one OpenClaw session (its pi-agent session entries, from a
 * `<session>.jsonl` or the 9.x agent database's `transcript_events`) that
 * went to the model, in order. The rule (`convertToLlm`): a `message`
 * entry's message by role: a `user` message's text, an `assistant`
 * message's text, thinking and each `toolCall`'s `arguments`, a
 * `toolResult` message's text content (with its `toolName`), a
 * `bashExecution` message's command and output (the person's `!` command)
 * unless `excludeFromContext`, a `custom` message's content (context), a
 * branch or compaction summary; a `custom_message` entry's content; a
 * `compaction` or `branch_summary` entry's summary (the model wrote it).
 * Never a tool result's `details` (the tool's local record), a message's
 * `details` or `display`, a `custom` entry's `data` (an extension's own
 * state), the model and thinking-level changes, labels or session info.
 * `meta` collects the cwd from the `session` entry and each assistant
 * message's `responseId` (plan 17 §3 item 6): the provider's id as
 * OpenClaw's transports keep it (`message_start`'s `msg_…`, the first Chat
 * chunk's `chatcmpl-…`, `response.created`'s `resp_…`). Each text carries
 * its request (`turn`): an assistant message answers the entries before it
 * and goes with its own blocks. Pure.
 */
export function* openclawSentTexts(records: Iterable<unknown>, meta: SessionMeta = {}): Generator<SentText> {
  const calls = new Map<string, { name: string; args: unknown }>();
  const turns = new Turns(meta);
  for (const r of records) {
    if (!isObj(r)) continue;
    const t = isoTime(r["timestamp"]);
    const type = r["type"];
    if (type === "session" && meta.cwd === undefined && typeof r["cwd"] === "string") meta.cwd = r["cwd"];
    if (type === "custom_message") {
      for (const text of textItems(r["content"])) yield turns.sent({ how: "context", text, ...at(t) });
      continue;
    }
    if (type === "compaction" || type === "branch_summary") {
      const s = str(r["summary"]);
      if (s) yield turns.sent({ how: "ai-wrote", text: s, ...at(t) });
      continue;
    }
    if (type !== "message" || !isObj(r["message"])) continue;
    const m = r["message"];
    const mt = t ?? isoTime(m["timestamp"]);
    switch (m["role"]) {
      case "user":
        for (const text of textItems(m["content"])) yield turns.sent({ how: "your-message", text, ...at(mt) });
        break;
      case "assistant": {
        noteProvider(meta, m["provider"]);
        const own = turns.answered(m["responseId"]);
        for (const b of arr(m["content"])) {
          if (!isObj(b)) continue;
          if (b["type"] === "text" && typeof b["text"] === "string" && b["text"] !== "") yield turns.wrote(own, { how: "ai-wrote", text: b["text"], ...at(mt) });
          else if (b["type"] === "thinking" && typeof b["thinking"] === "string" && b["thinking"] !== "" && b["redacted"] !== true) yield turns.wrote(own, { how: "ai-wrote", text: b["thinking"], ...at(mt) });
          else if (b["type"] === "toolCall" && b["arguments"] !== undefined) {
            const name = str(b["name"]);
            const id = str(b["id"]);
            if (id !== undefined && name !== undefined) calls.set(id, { name, args: b["arguments"] });
            yield turns.wrote(own, { how: "ai-wrote", text: json(b["arguments"]), ...toolOf(name), ...at(mt), ...callOf(name, b["arguments"]) });
          }
        }
        break;
      }
      case "toolResult": {
        const call = calls.get(str(m["toolCallId"]) ?? "");
        const tool = str(m["toolName"]) ?? call?.name;
        for (const text of textItems(m["content"])) yield turns.sent({ how: toolHow(tool, OPENCLAW_FILE_TOOLS, OPENCLAW_SHELL_TOOLS), text, ...toolOf(tool), ...at(mt), ...(call !== undefined ? callOf(call.name, call.args) : {}) });
        break;
      }
      case "bashExecution": {
        if (m["excludeFromContext"] === true) break;
        const text = [str(m["command"]), str(m["output"])].filter((x) => x !== undefined && x !== "").join("\n");
        if (text) yield turns.sent({ how: "your-message", text, ...at(mt) });
        break;
      }
      case "custom":
        for (const text of textItems(m["content"])) yield turns.sent({ how: "context", text, ...at(mt) });
        break;
      case "branchSummary":
      case "compactionSummary": {
        const s = str(m["summary"]);
        if (s) yield turns.sent({ how: "ai-wrote", text: s, ...at(mt) });
        break;
      }
      default:
        break;
    }
  }
}

/** An OpenClaw session's tool calls (each `toolCall` of an assistant
 *  message) with how each ended (its result's `isError`, an exec approval's
 *  refusal, Mandu's stop). OpenClaw keeps its approval settings in its
 *  config, not in the session, so whether prompts were off is not known
 *  from the record (never counted). Pure. */
export function openclawActs(records: Iterable<unknown>): SessionActs {
  const list = [...records].filter(isObj);
  const results = new Map<string, { error: boolean; text: string }>();
  for (const r of list) {
    const m = r["message"];
    if (r["type"] !== "message" || !isObj(m) || m["role"] !== "toolResult") continue;
    const id = str(m["toolCallId"]);
    if (id !== undefined) results.set(id, { error: m["isError"] === true, text: textItems(m["content"]).join("\n") });
  }
  const calls: ToolCall[] = [];
  for (const r of list) {
    const m = r["message"];
    if (r["type"] !== "message" || !isObj(m) || m["role"] !== "assistant") continue;
    const t = isoTime(r["timestamp"]) ?? isoTime(m["timestamp"]);
    const responseId = responseIdOf(m["responseId"]);
    for (const b of arr(m["content"])) {
      if (!isObj(b) || b["type"] !== "toolCall") continue;
      const tool = str(b["name"]);
      if (tool === undefined) continue;
      const res = results.get(str(b["id"]) ?? "");
      const end: CallEnd | undefined = res === undefined ? undefined
        : MANDU_STOP_RE.test(res.text) ? "stopped-by-mandu"
          : res.error && OPENCLAW_REFUSED_RE.test(res.text) ? "refused"
            : res.error ? "failed" : undefined;
      calls.push({ tool, input: b["arguments"], ...at(t), ...(end ? { end } : {}), ...(responseId ? { responseId } : {}) });
    }
  }
  return { calls, skippedPrompts: false };
}
