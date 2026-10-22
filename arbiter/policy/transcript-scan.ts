/**
 * transcript-scan — find the secrets an agent already sent to its model, in
 * the transcripts the agent keeps on disk
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md).
 *
 * Claude Code writes each session's messages to
 * `~/.claude/projects/<project>/<session>.jsonl` (a subagent's to
 * `<session>/subagents/*.jsonl`), Codex to
 * `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`; OpenCode, Goose and
 * OpenClaw keep theirs in their own stores, SQLite in their later versions
 * (transcript-stores.ts reads those, transcript-readers.ts holds their
 * readers), and so do two agents Mandu does not run, Gemini CLI and
 * Copilot CLI, whose readers are in transcript-unwrapped.ts (which also
 * counts Cursor's chats, never read). A value in the part of a record the agent puts in its requests
 * was in a request to the model. This module reads those parts (the
 * readers below, one per agent, plan 17 §3 item 3), finds
 * credential-shaped values in them with the detector the
 * git-history scan uses (`findSecretValues`, secret-detectors.ts) and values
 * the caller already knows by exact match (the person's own secrets found on
 * disk, item 5), and groups what it found by secret.
 *
 * It enforces nothing and writes nothing. Like the git-history scan
 * (secret-history-scan.ts), a finding carries the detector's kind and a
 * fixed mask, never a character of a value's body, and no length or hash of
 * it: a value is told from another by an HMAC under a key made for this one
 * scan, held in this process's memory only (item 2).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHmac, randomBytes } from "node:crypto";
import { createReadStream, readdirSync, statSync, openSync, readSync, closeSync, type Stats } from "node:fs";
import { createInterface } from "node:readline";
import type { Agent, ScanOnlyAgent } from "../src/generated/agents.js";
import { join, basename, dirname } from "node:path";
import { findSecretValues, isStandIn, looksLikeSecretValue, type SecretShape } from "./secret-detectors.js";
import { redactShown, shownToolName, shownUrl, type RedactValue } from "./transcript-redact.js";
import { envSecretNameMatches } from "./secret-extract.js";
import { claudeCodeActs, codexActs, fetchedUrlOf, httpUrlsIn, sendsOf, type SendChannel, isEnvDump, isLocalHost, shellCommandsOf, type SessionActs, type ToolCall } from "./transcript-acts.js";
import { closeStores, isStoreFile, storeItems, type OpenStores, type StoreItem, type StoreKind } from "./transcript-stores.js";
import { claudeCodeSetting, codexSetting, resolveProvider, type ProviderSetting, type ProviderSettings } from "./transcript-providers.js";
import { COUNT_ONLY_KINDS, countCursorChats, isUnwrappedStoreFile, unwrappedItems, type UnwrappedKind } from "./transcript-unwrapped.js";
import { RESPONSE_ID_RE, Turns } from "./transcript-readers.js";
import { looksLikeTestValue } from "./transcript-test-values.js";

// ── What reached the model ──────────────────────────────────────────────────

/** The agents whose transcripts the scan reads: every agent of the
 *  registry (src/generated/agents.ts), Claude Code by the id the scan's
 *  answer has always used, and the agents only the scan knows (Mandu does
 *  not run them; the registry's scan-only table, plan 17 §4 phase 3). */
export type TranscriptAgent = "claude-code" | Exclude<Agent, "claude"> | ScanOnlyAgent;

/** How a text got into a request (plan 17 §3 item 4). */
export type SentHow =
  /** A tool that reads files returned it (Read, Grep, …). */
  | "read-file"
  /** A shell command printed it. */
  | "command-output"
  /** Another tool returned it (a web fetch, an MCP server, …). */
  | "tool-result"
  /** The person's own message: typed, pasted, or a `!` command's output. */
  | "your-message"
  /** The model wrote it (its text, its reasoning, a tool call's input). */
  | "ai-wrote"
  /** Context the agent added on its own (an attached file, instructions). */
  | "context";

/** One piece of text the agent put in a request to its model. */
export interface SentText {
  how: SentHow;
  /** The tool's name, for `read-file`, `command-output` and `tool-result`. */
  tool?: string;
  text: string;
  /** The record's time (ISO 8601), when it has one. */
  at?: string;
  /** The tool call: for a tool's result, the call it answers (matched by
   *  its id, as transcript-acts.ts matches them); for a call's input, the
   *  call itself. The scanner reads its command or file for the example it
   *  shows, redacted (transcript-redact.ts); it never leaves the arbiter. */
  call?: { tool: string; input: unknown };
  /** An attached file's path, for `context`. */
  path?: string;
  /** The request it went in (plan 17 §3 item 6), from a reader that tells
   *  the session's requests apart (`Turns`, transcript-readers.ts); the
   *  texts of one request share the object. The reader fills its
   *  `responseId` when the response comes, so it is final once the reader
   *  is done. */
  turn?: Turn;
}

/** One request to the model and the response that answered it, as far as
 *  the transcript says (plan 17 §3 item 6). */
export interface Turn {
  /** The id of the response that answered it, when the record keeps a
   *  well-formed one: what the per-text join looks up in Mandu's records. */
  responseId?: string;
  /** The agent's own id of its session, which the request carried
   *  (OpenCode's `X-Session-Id`, `AGENT_SESSION_ID_RE`): Mandu's proxy
   *  records it too, so the per-text join looks it up, with the text's time,
   *  in the Mandu sessions that recorded it. */
  sessionId?: string;
  /** The earliest time of a text in it (ISO 8601). */
  at?: string;
}

/** Who served the session's model, as far as the record says. */
export type ModelProvider = "anthropic" | "openai" | "google" | "github" | "other";

/** What a reader learns about the session besides its texts. */
export interface SessionMeta {
  /** The working directory the session ran in. */
  cwd?: string;
  /** The ids of the model's responses the record keeps (plan 17 §3 item 6):
   *  Claude Code's assistant `message.id`, Codex's `token_usage_record`
   *  `response_id`, OpenClaw's assistant `responseId`, OpenCode 2's
   *  `providerState.responseId`, Goose's assistant message id (the
   *  provider's, not one Goose made up). Mandu's model proxies record the
   *  same ids on their `tllm_call` events, so the scan can tell a session
   *  under Mandu exactly. A reader that knows none leaves it unset. */
  responseIds?: Set<string>;
  /** The agent's own id of the session, which it sends with every model
   *  request (OpenCode 1.x and 2.x: the session's row id, the
   *  `X-Session-Id` header): Mandu's anthropic-proxy records it on its
   *  `tllm_call` events (`model.agentSessionId`), so the scan joins a
   *  session whose record keeps no response id exactly too, per request at
   *  the request's time (plan 17 §3 item 6). */
  agentSessionId?: string;
  /** Claude Code: the provider its model names point to (`claude-*` is
   *  Anthropic's); Codex: its `model_provider`. Absent when the record
   *  does not say. */
  provider?: ModelProvider;
  /** Not a session of its own (Goose's request log, a record of many
   *  sessions' requests): its findings count it, the sessions read do not. */
  uncounted?: boolean;
}

export { RESPONSE_ID_RE };

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/** Claude Code's tools that return a file's content. */
const CLAUDE_FILE_TOOLS = new Set(["Read", "NotebookRead", "Grep", "Glob", "LS"]);
/** Claude Code's tools that return a shell command's output. */
const CLAUDE_SHELL_TOOLS = new Set(["Bash", "BashOutput", "Monitor", "KillShell", "KillBash"]);
/** Claude Code's attachments whose text the agent puts in a request. Every
 *  other attachment type is the agent's own bookkeeping (a prompt snapshot,
 *  a token count, a tool list) and is not read. */
const CLAUDE_SENT_ATTACHMENTS: Readonly<Record<string, readonly string[]>> = {
  file: ["content"],
  edited_text_file: ["snippet"],
  queued_command: ["prompt"],
};

/** The text of a content block list (strings, `{type:"text",text}`,
 *  `{type:"input_text",text}`, `{type:"output_text",text}`); images and
 *  other blocks are skipped. */
function blockText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const b of content) {
    if (typeof b === "string") parts.push(b);
    else if (isObj(b) && typeof b["text"] === "string") parts.push(b["text"]);
  }
  return parts.join("\n");
}

/** How a Claude Code tool's result reached the model. */
function claudeToolHow(name: string | undefined): SentHow {
  if (name !== undefined && CLAUDE_FILE_TOOLS.has(name)) return "read-file";
  if (name !== undefined && CLAUDE_SHELL_TOOLS.has(name)) return "command-output";
  return "tool-result";
}

/**
 * The texts of one Claude Code transcript that went to the model, in order
 * (plan 17 §3 item 3): a `user` record's `message.content` (the person's
 * text, and each `tool_result` with the name of the `tool_use` it answers),
 * an `assistant` record's text, thinking and `tool_use` input, and the
 * attachments of {@link CLAUDE_SENT_ATTACHMENTS}. Never `toolUseResult`,
 * Claude Code's local copy of a tool's full output. Records it does not
 * know are skipped. Pure over the parsed records; `meta` collects the cwd.
 * Each text carries its request (`turn`, plan 17 §3 item 6): the next
 * assistant `message.id` answers what the person, a tool or an attachment
 * put in it; an assistant record's own texts go with its `message.id`. A
 * `<synthetic>` message (Claude Code's own, such as an API error) is no
 * response.
 */
export function* claudeCodeSentTexts(records: Iterable<unknown>, meta: SessionMeta = {}): Generator<SentText> {
  const calls = new Map<string, { tool: string; input: unknown }>();
  const turns = new Turns(meta);
  for (const r of records) {
    if (!isObj(r)) continue;
    const at = str(r["timestamp"]);
    if (meta.cwd === undefined && typeof r["cwd"] === "string") meta.cwd = r["cwd"];
    const type = r["type"];
    if (type === "assistant" && meta.provider === undefined && isObj(r["message"])) {
      const model = str(r["message"]["model"]);
      if (model !== undefined && model !== "<synthetic>") meta.provider = /^claude-/.test(model) ? "anthropic" : "other";
    }
    if (type === "attachment" && isObj(r["attachment"])) {
      const a = r["attachment"];
      const fields = CLAUDE_SENT_ATTACHMENTS[str(a["type"]) ?? ""];
      for (const f of fields ?? []) {
        // A file attachment holds `{type, file: {filePath, content, …}}`:
        // the agent sends the path and the content, not the line counts.
        const v = a[f];
        const file = isObj(v) && isObj(v["file"]) ? v["file"] : null;
        const text = str(v) ?? (file !== null ? [str(file["filePath"]), str(file["content"])].filter(Boolean).join("\n") : undefined);
        const path = file !== null ? str(file["filePath"]) : undefined;
        if (text) yield turns.sent({ how: "context", text, ...(at ? { at } : {}), ...(path ? { path } : {}) });
      }
      continue;
    }
    if (type !== "user" && type !== "assistant") continue;
    const msg = r["message"];
    if (!isObj(msg)) continue;
    const own = type === "assistant" && msg["model"] !== "<synthetic>" ? turns.answered(msg["id"]) : undefined;
    const put = (t: SentText): SentText => (own !== undefined ? turns.wrote(own, t) : turns.sent(t));
    const content = msg["content"];
    if (typeof content === "string") {
      if (content) yield put({ how: type === "user" ? "your-message" : "ai-wrote", text: content, ...(at ? { at } : {}) });
      continue;
    }
    if (!Array.isArray(content)) continue;
    for (const b of content) {
      if (!isObj(b)) continue;
      const bt = b["type"];
      if (bt === "text" && typeof b["text"] === "string") {
        yield put({ how: type === "user" ? "your-message" : "ai-wrote", text: b["text"], ...(at ? { at } : {}) });
      } else if (bt === "thinking" && typeof b["thinking"] === "string") {
        yield put({ how: "ai-wrote", text: b["thinking"], ...(at ? { at } : {}) });
      } else if (bt === "tool_use") {
        const id = str(b["id"]);
        const name = str(b["name"]);
        const call = name ? { tool: name, input: b["input"] } : undefined;
        if (id && call) calls.set(id, call);
        if (b["input"] !== undefined) yield put({ how: "ai-wrote", text: JSON.stringify(b["input"]), ...(name ? { tool: name } : {}), ...(at ? { at } : {}), ...(call ? { call } : {}) });
      } else if (bt === "tool_result") {
        const call = calls.get(str(b["tool_use_id"]) ?? "");
        const name = call?.tool;
        const text = blockText(b["content"]);
        if (text) yield put({ how: claudeToolHow(name), text, ...(name ? { tool: name } : {}), ...(at ? { at } : {}), ...(call ? { call } : {}) });
      }
    }
  }
}

/** Codex's tools that run a shell command. */
const CODEX_SHELL_TOOLS = new Set(["exec", "shell", "exec_command", "container.exec", "local_shell", "write_stdin"]);

/**
 * The texts of one Codex rollout that went to the model, in order (plan 17
 * §3 item 3): its `response_item` payloads: messages (the person's
 * `input_text` as theirs, the agent's developer and system messages as
 * context, the model's `output_text`), tool calls' input (the model wrote
 * it) and tool outputs, with the call's name. Never `event_msg`, Codex's
 * local event log, and never encrypted reasoning. `meta` collects the cwd
 * from `session_meta` or `turn_context`. Each text carries its request
 * (`turn`, plan 17 §3 item 6): Codex writes a response's output items
 * before its `token_usage_record`, whose `response_id` answers every text
 * since the last one, the model's own among them. Pure over the parsed
 * records.
 */
export function* codexSentTexts(records: Iterable<unknown>, meta: SessionMeta = {}): Generator<SentText> {
  const calls = new Map<string, { tool: string; input: unknown }>();
  const turns = new Turns(meta);
  for (const r of records) {
    if (!isObj(r)) continue;
    const at = str(r["timestamp"]);
    const p = r["payload"];
    if (!isObj(p)) continue;
    if ((r["type"] === "session_meta" || r["type"] === "turn_context") && meta.cwd === undefined && typeof p["cwd"] === "string") meta.cwd = p["cwd"];
    // One per model response (Codex 0.159 and later): the Responses API id.
    if (r["type"] === "token_usage_record") turns.answered(p["response_id"]);
    if (r["type"] === "session_meta" && meta.provider === undefined && typeof p["model_provider"] === "string") meta.provider = p["model_provider"] === "openai" ? "openai" : "other";
    if (r["type"] !== "response_item") continue;
    const pt = p["type"];
    if (pt === "message") {
      const role = p["role"];
      const text = blockText(p["content"]);
      if (!text) continue;
      const how: SentHow = role === "user" ? "your-message" : role === "assistant" ? "ai-wrote" : "context";
      yield turns.sent({ how, text, ...(at ? { at } : {}) });
    } else if (pt === "function_call" || pt === "custom_tool_call" || pt === "local_shell_call") {
      const id = str(p["call_id"]);
      const name = str(p["name"]) ?? (pt === "local_shell_call" ? "local_shell" : undefined);
      const input = p["arguments"] ?? p["input"] ?? p["action"];
      const call = name ? { tool: name, input } : undefined;
      if (id && call) calls.set(id, call);
      const text = typeof input === "string" ? input : input === undefined ? "" : JSON.stringify(input);
      if (text) yield turns.sent({ how: "ai-wrote", text, ...(name ? { tool: name } : {}), ...(at ? { at } : {}), ...(call ? { call } : {}) });
    } else if (pt === "function_call_output" || pt === "custom_tool_call_output" || pt === "local_shell_call_output") {
      const call = calls.get(str(p["call_id"]) ?? "");
      const name = call?.tool;
      const out = p["output"];
      const text = typeof out === "string" ? out : isObj(out) && typeof out["content"] === "string" ? out["content"] : blockText(out);
      if (!text) continue;
      const how: SentHow = name !== undefined && CODEX_SHELL_TOOLS.has(name) ? "command-output" : "tool-result";
      yield turns.sent({ how, text, ...(name ? { tool: name } : {}), ...(at ? { at } : {}), ...(call ? { call } : {}) });
    }
  }
}

// ── The scan ────────────────────────────────────────────────────────────────

/** A secret the caller already knows (plan 17 §3 item 5): a value found in a
 *  credential file on disk now, or in the person's environment. */
export interface KnownSecret {
  value: string;
  /** Where it lives now, home as `~` (or `your environment`). */
  path: string;
  /** The variable or key that holds it there, when it has one. */
  name?: string;
}

/** A known value shorter than this is not matched (too likely by chance). */
export const MIN_KNOWN_LEN = 8;

/** The words a credential's name holds (the detector's assignment rule, and
 *  a few more a config file's key uses). */
const CREDENTIAL_NAME_RE = /secret|token|passw(?:or)?d|passphrase|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|cookie|session[_-]?key|bearer/i;

/**
 * Is a value found on disk a credential the report may call one (plan 17 §3
 * item 5)? Discovery masks a whole `.env` or config file to fail closed, so
 * its values include version pins, image digests and hosts; the report must
 * not say "your secret reached the AI" for those. A value counts when its
 * own name (the last part of its key, without the index the extractor adds)
 * reads as a credential, or the value has a vendor's format. A value the
 * extractor's credential belt found by its look alone (`cred.*`) counts only
 * by format. A stand-in (`changeme`, `${TOKEN}`, `<your-key>`) never
 * counts, by the detector's own test (`isStandIn`, 2026-10-22): the word
 * test alone (`isPlaceholder`) dropped a live key whose random body held
 * `xxxx` or `dummy` by chance, which the detector still found by its shape,
 * so the report called the person's own key "not in your files now". Pure.
 */
export function knownIsCredential(k: KnownSecret): boolean {
  if (k.value.length < MIN_KNOWN_LEN || isStandIn(k.value)) return false;
  const vendor = findSecretValues(k.value).some((h) => h.shape !== "credential-assignment" && h.shape !== "url-password" && h.value === k.value);
  if (vendor) return true;
  const name = k.name ?? "";
  if (name === "" || name.startsWith("cred.")) return false;
  const last = name.split(".").pop()!.replace(/__\d+$/, "");
  return CREDENTIAL_NAME_RE.test(last);
}

/** One finding, MASKED: no value, no length, no hash. */
export interface TranscriptFinding {
  /** `known` for a value found on disk now, else the detector's shape. */
  kind: "known" | SecretShape;
  /** The fixed mask (`sk-ant-…`, `DB_PASSWORD=…`), or for a known value its
   *  name and where it lives (`STRIPE_KEY in ~/proj/.env`). */
  preview: string;
  /** For a known value: where it lives now. */
  source?: { path: string; name?: string };
  /** Sessions it appeared in, and their agents. */
  sessions: number;
  agents: TranscriptAgent[];
  /** Its first and last appearance (ISO 8601), when the records say. */
  first?: string;
  last?: string;
  /** How it got there: sessions per way. */
  how: Partial<Record<SentHow, number>>;
  /** Projects (working directories, home as `~`), at most {@link MAX_PROJECTS}. */
  projects: string[];
  /** Of `sessions`, those in which it reached the model only while Mandu
   *  ran the same agent (item 6): their local record may hold a value the
   *  model saw as a placeholder. `sessionsUnderMandu + sessionsByTime`,
   *  kept for older readers. */
  duringMandu: number;
  /** Of `sessions`, those in which every request that carried it was one
   *  Mandu's model proxy served: the response that answered it has an id in
   *  Mandu's records (exact, per request; `TranscriptScanner.requestMark`). */
  sessionsUnderMandu: number;
  /** Of `sessions`, the rest of those that ran while Mandu ran, marked by
   *  time only where no response id settles a request. The others
   *  (`sessions - duringMandu`) sent it at least once without Mandu: a
   *  session resumed under Mandu after a start outside it counts here by
   *  what its part outside Mandu sent. */
  sessionsByTime: number;
  /** Distinct projects it appeared in (`projects` lists the first few). */
  projectCount: number;
  /** What the agent did, newest first, at most {@link MAX_EXAMPLES}, one per
   *  session; at least one without Mandu when a text sent without it has
   *  one (it can be a resumed session's, beside the newer one of its part
   *  under Mandu). Each with its own request's mark. Redacted: no value
   *  (item 4, transcript-redact.ts). */
  examples?: ScanExample[];
  /** The same, per way it got there, at most {@link MAX_EXAMPLES_PER_HOW}
   *  each, newest first, one per session: the detail of `mandu scan
   *  --show`. Kept for the first {@link MAX_DETAIL_FINDINGS} findings. */
  examplesByHow?: Partial<Record<SentHow, ScanExample[]>>;
  /** The hosts outside this computer the agents' commands sent it to
   *  over the network (item 11: HTTP, ssh, git, a script; not an MCP tool;
   *  the `sends` of the answer have the detail). */
  sentToHosts?: string[];
  /** A key-shaped value that looks like a test value (item 14,
   *  `looksLikeTestValue`): reported, not counted as a leak. Never set on
   *  one of the person's own secrets. */
  looksLikeTest?: true;
}

/** One example of a finding: what the agent did in one session, REDACTED
 *  (item 4): a command, a file or a project never holds a value the scan
 *  knows (transcript-redact.ts). */
export interface ScanExample {
  /** When (ISO 8601). */
  at?: string;
  agent: TranscriptAgent;
  how: SentHow;
  /** The shell command: for `command-output` the one whose output held the
   *  value, for `ai-wrote` the one the AI wrote it into. One line, at most
   *  240 characters, every value masked. */
  command?: string;
  /** The file, home as `~`: the one the agent read (`read-file`), attached
   *  (`context`) or the AI wrote into (`ai-wrote`). */
  file?: string;
  /** The URL a web fetch (`WebFetch`, `webfetch`, `web_fetch`) fetched:
   *  for `tool-result` the fetch whose result held the value, for
   *  `ai-wrote` the fetch the AI wrote it into. Redacted like a command: a
   *  query's secrets and a URL's password masked. */
  url?: string;
  /** The tool's name (`Read`, `Bash`, `exec_command`, an MCP tool). */
  tool?: string;
  /** The session's working directory, home as `~`. */
  project?: string;
  /** The standing to Mandu of the request that carried it
   *  (`TranscriptScanner.requestMark`), else of its session
   *  (`TranscriptScanner.sessionMandu`) where the record tells no request
   *  apart. */
  mandu?: ManduStatus;
  /** Who the request went to: the agent's own provider unless the record
   *  or this computer's settings show another (`other`). */
  provider?: ModelProvider;
}

/** Projects listed per finding. */
export const MAX_PROJECTS = 5;
/** Examples per finding (`examples`). */
export const MAX_EXAMPLES = 3;
/** Examples per way, per finding (`examplesByHow`). */
export const MAX_EXAMPLES_PER_HOW = 10;
/** Findings that carry `examplesByHow` (the rest carry `examples`). */
export const MAX_DETAIL_FINDINGS = 500;
/** Projects counted per finding. */
const MAX_PROJECT_COUNT = 10_000;

/** Newest first; an example with no time last. */
function insertNewest<T extends { ex: ScanExample }>(list: T[], h: T, max: number): void {
  const at = h.ex.at ?? "";
  let i = list.findIndex((e) => (e.ex.at ?? "") < at);
  if (i < 0) i = list.length;
  if (i >= max) return;
  list.splice(i, 0, h);
  if (list.length > max) list.length = max;
}

/** Would `at` enter a newest-first list of `max`? */
const wouldEnter = (list: ReadonlyArray<{ ex: ScanExample }>, at: string | undefined, max: number): boolean =>
  list.length < max || (at ?? "") > (list[list.length - 1]!.ex.at ?? "");

/** The file a tool call names (Read's `file_path`, LS's `path`, …). */
function fileOfCall(call: { tool: string; input: unknown }): string | undefined {
  const i = call.input;
  if (!isObj(i)) return undefined;
  return str(i["file_path"]) ?? str(i["filePath"]) ?? str(i["notebook_path"]) ?? str(i["path"]) ?? str(i["dir_path"]) ?? (call.tool === "Glob" ? str(i["pattern"]) : undefined);
}
/** Distinct secrets kept; past it, more are counted, not kept. */
export const MAX_FINDINGS = 2000;

/** A Mandu session: the agent it ran and when (ms since the epoch). */
export interface ManduWindow {
  agent: TranscriptAgent;
  from: number;
  to: number;
  /** The response ids Mandu's model proxy recorded in it (`tllm_call`'s
   *  `model.responseId`). Absent or empty for a session of an older Mandu,
   *  whose events carry none: there only the time can mark a transcript. */
  responseIds?: readonly string[];
  /** The agents' own session ids its model proxy recorded (`tllm_call`'s
   *  `model.agentSessionId`, OpenCode's `X-Session-Id`). Absent for a
   *  session of an older Mandu, or of an agent that sends none. */
  agentSessionIds?: readonly string[];
}

/** How a transcript session, or one request of it, stands to Mandu (plan
 *  17 §3 item 6):
 *  - `under`: one of its response ids is in Mandu's records (exact);
 *  - `by-time`: it overlaps a Mandu session of the same agent and no id
 *    settles it (the session or that Mandu session has none);
 *  - `without`: neither, or its ids are not in the records of the Mandu
 *    sessions it overlaps, all of which recorded ids (a parallel session
 *    outside Mandu). */
export type ManduStatus = "under" | "by-time" | "without";

const MARK_RANK: Readonly<Record<ManduStatus, number>> = { without: 0, "by-time": 1, under: 2 };
/** The weaker of two marks (`without` below `by-time` below `under`). */
const weaker = (a: ManduStatus | undefined, b: ManduStatus | undefined): ManduStatus | undefined =>
  a === undefined ? b : b === undefined ? a : MARK_RANK[a] <= MARK_RANK[b] ? a : b;

/** How the texts (or calls) that carried one finding (or send) in one
 *  session stand to Mandu: the weakest mark of those joined per request,
 *  and whether one follows the session's own mark (a record that tells no
 *  request apart), read when the answer is made. */
interface SessionMark {
  key: string;
  fixed?: ManduStatus;
  follows: boolean;
}

/** Where a command sent a secret (plan 17 §3 item 11). */
export type SentTo =
  /** A host of the service the key's format names, or the host its file names. */
  | "own-service"
  /** A host the scan cannot tie to the key: not wrong in itself, but worth a look. */
  | "other-host";

/** One secret sent to one host by the agents' commands, MASKED like a
 *  finding: no value, no length, no hash. */
export interface SendFinding {
  /** `variable`: a secret-named variable whose value the scan does not know. */
  kind: "known" | SecretShape | "variable";
  /** As a finding's: `STRIPE_KEY in ~/shop/.env`, a fixed mask, or `$NAME`. */
  preview: string;
  source?: { path: string; name?: string };
  to: SentTo;
  host: string;
  /** The URLs at `host` it was sent to, at most {@link MAX_SEND_URLS},
   *  the first seen first, MASKED (transcript-redact.ts `shownUrl`): the
   *  path kept, credentials and every query value masked, at most 160
   *  characters each. Absent from an older arbiter. */
  urls?: string[];
  /** Sessions with such a request. */
  sessions: number;
  /** Of them, sessions in which one ran without an error (the rest failed,
   *  were refused at the prompt, or were stopped by Mandu). */
  ran: number;
  /** Of them, sessions in which Mandu stopped one. */
  stoppedByMandu: number;
  /** The programs that sent it (`curl`, `WebFetch`, `ssh`, `git push`,
   *  `python3`, `MCP`, …). */
  via: string[];
  /** How it left (`SendChannel`): over HTTP (an HTTP client or a web
   *  fetch), over ssh (`ssh`, `scp`, `sftp`, `rsync`), with git (a
   *  credential in its URL or header), by an inline script's HTTP call, or
   *  in an MCP tool's input (`host` is then the tool's name). Absent from an
   *  older arbiter, whose sends were all `http`. */
  channel?: SendChannel;
  /** The value looks like a test value (`looksLikeTestValue`; a key-shaped
   *  value only, never one of the person's own). */
  looksLikeTest?: true;
  /** How the command held it: the value itself (the AI wrote it out), or a
   *  variable holding it (the AI saw only the name). */
  by: Array<"value" | "variable">;
  agents: TranscriptAgent[];
  last?: string;
  /** As a finding's: `sessionsUnderMandu + sessionsByTime`. */
  duringMandu: number;
  sessionsUnderMandu: number;
  sessionsByTime: number;
}

/** Distinct (secret, host) sends kept; past it, more are counted, not kept. */
export const MAX_SENDS = 500;
/** URLs kept per send. */
export const MAX_SEND_URLS = 5;

/** The domains of the service a key's format names. A host under one, or a
 *  self-hosted install's host (`gitlab.example.org`), is the key's own. */
const SHAPE_SERVICE: Readonly<Partial<Record<SecretShape, { domains: readonly string[]; selfHosted?: RegExp }>>> = {
  "anthropic-key": { domains: ["anthropic.com"] },
  "openai-key": { domains: ["openai.com"] },
  "github-token": { domains: ["github.com", "githubusercontent.com"], selfHosted: /(?:^|\.)github\./ },
  "gitlab-token": { domains: ["gitlab.com"], selfHosted: /(?:^|\.)gitlab\./ },
  "slack-token": { domains: ["slack.com"] },
  "stripe-key": { domains: ["stripe.com"] },
  "google-api-key": { domains: ["googleapis.com", "google.com"] },
  "npm-token": { domains: ["npmjs.org", "npmjs.com"] },
  "pypi-token": { domains: ["pypi.org"] },
  "huggingface-token": { domains: ["huggingface.co", "hf.co"] },
  "aws-access-key-id": { domains: ["amazonaws.com"] },
  "aws-secret-key": { domains: ["amazonaws.com"] },
};

/** The service a variable's name points to, as the shape of that
 *  service's keys (`STRIPE_SECRET_KEY` → a Stripe key). A hint only: it
 *  can make a host the key's own, never the other way round. */
const NAME_SHAPE: ReadonlyArray<[RegExp, SecretShape]> = [
  [/STRIPE/, "stripe-key"], [/GITHUB|^GH_/, "github-token"], [/GITLAB|^GL_/, "gitlab-token"],
  [/ANTHROPIC/, "anthropic-key"], [/OPENAI/, "openai-key"], [/SLACK/, "slack-token"],
  [/^AWS_/, "aws-access-key-id"], [/GOOGLE|GEMINI/, "google-api-key"], [/^NPM_/, "npm-token"],
  [/PYPI|TWINE/, "pypi-token"], [/^HF_|HUGGING/, "huggingface-token"],
];

/** The vendor shape of a whole value, if it has one. */
function vendorShapeOf(value: string): SecretShape | undefined {
  return findSecretValues(value).find((h) => h.value === value && h.shape !== "credential-assignment" && h.shape !== "url-password")?.shape;
}

/**
 * Is `host` the key's own service? Yes when the key's format names a
 * service the host belongs to, or when the file and key that hold it name
 * the host (a CLI's `hosts.<host>.token`). Anything else is `other-host`:
 * the scan cannot tell a company's own API from somewhere the key should
 * not go, so it says which, and no more. Pure.
 */
export function sentTo(host: string, key: { shape?: SecretShape; name?: string; path?: string }): SentTo {
  const h = host.toLowerCase();
  if (`${key.path ?? ""}\n${key.name ?? ""}`.toLowerCase().includes(h)) return "own-service";
  const svc = key.shape === undefined ? undefined : SHAPE_SERVICE[key.shape];
  if (svc !== undefined && (svc.domains.some((d) => h === d || h.endsWith(`.${d}`)) || (svc.selfHosted?.test(h) ?? false))) return "own-service";
  return "other-host";
}

/** The riskier sessions (plan 17 §3 item 10), in sessions. */
export interface SessionRisk {
  /** Ran with the agent's permission prompts off. */
  skippedPrompts: number;
  /** Of them, sessions in which one of your secrets reached the AI. */
  skippedWithSecret: number;
  /** Printed the whole environment to the AI (`env`, `printenv`, …). */
  envDumps: number;
}

/** The scan's answer, before the caps (`scanAgentTranscripts` adds them). */
export interface TranscriptScanResult {
  /** Sessions read, by agent. */
  sessions: Partial<Record<TranscriptAgent, number>>;
  /** Of them, sessions that ran while Mandu ran the same agent:
   *  `sessionsUnderMandu + sessionsByTime`, kept for older readers. */
  duringMandu: number;
  /** Of them, sessions Mandu's model proxy served, in all or in part (an
   *  exact id join: one of their responses is in Mandu's records). The
   *  findings and sends are joined per request, so a session resumed under
   *  Mandu counts here while what its part outside Mandu sent does not. */
  sessionsUnderMandu: number;
  /** Of them, sessions marked by time only (no id to join). */
  sessionsByTime: number;
  /** The oldest and newest record read (ISO 8601). */
  from?: string;
  to?: string;
  findings: TranscriptFinding[];
  /** Distinct secrets past {@link MAX_FINDINGS}, counted only. */
  dropped: number;
  risk: SessionRisk;
  /** Secrets the agents' commands sent, by host (item 11). */
  sends: SendFinding[];
  /** Distinct sends past {@link MAX_SENDS}, counted only. */
  sendsDropped: number;
}

interface SendAcc {
  kind: SendFinding["kind"];
  preview: string;
  source?: { path: string; name?: string };
  to: SentTo;
  host: string;
  urls: string[];
  sessions: Set<string>;
  ran: Set<string>;
  stopped: Set<string>;
  via: Set<string>;
  channel: SendChannel;
  by: Set<"value" | "variable">;
  agents: Set<TranscriptAgent>;
  last?: string;
  /** Per session, how the calls that sent it stand to Mandu. */
  marks: Map<string, SessionMark>;
  test?: true;
}

interface Acc {
  kind: TranscriptFinding["kind"];
  preview: string;
  source?: { path: string; name?: string };
  sessions: Set<string>;
  agents: Set<TranscriptAgent>;
  first?: string;
  last?: string;
  how: Map<SentHow, Set<string>>;
  projects: Set<string>;
  /** Per session, how the texts that carried it stand to Mandu. */
  marks: Map<string, SessionMark>;
  allProjects: Set<string>;
  /** Per way, the newest example of each of the newest sessions. */
  byHow: Map<SentHow, HeldExample[]>;
  /** The newest examples of sessions without Mandu (when read). */
  withoutPool: HeldExample[];
  /** It looks like a test value (`looksLikeTestValue`). */
  test?: true;
}

/** An example as the scanner holds it: with its request's mark, or, where
 *  the record tells no request apart, its session's key, so its `mandu` is
 *  read when the answer is made (a subagent's file read later can change
 *  its parent session's mark). */
interface HeldExample {
  key: string;
  ex: ScanExample;
  mark?: ManduStatus;
}

/**
 * Accumulates the findings of many sessions. Feed each transcript file with
 * {@link TranscriptScanner.addSession} (a subagent's file under its parent's
 * session key); read the answer with {@link TranscriptScanner.result}. A
 * value lives in this object only as an HMAC under a key made for it, used
 * to tell one secret from another.
 */
export class TranscriptScanner {
  private readonly key = randomBytes(32);
  private readonly acc = new Map<string, Acc>();
  private readonly known: Array<{ value: string; id: string; k: KnownSecret; shape?: SecretShape }> = [];
  /** Known values by the name that holds them (a variable, a key's last
   *  part), for a command that names the variable. */
  private readonly knownByName = new Map<string, { value: string; id: string; k: KnownSecret; shape?: SecretShape }>();
  private readonly sends = new Map<string, SendAcc>();
  private sendsDropped = 0;
  private readonly knownIds = new Set<string>();
  private readonly sessionsOf = new Map<TranscriptAgent, Set<string>>();
  /** Each session's standing to Mandu, by `agent\0session`. */
  private readonly status = new Map<string, ManduStatus>();
  private readonly skipped = new Set<string>();
  private readonly skippedWithSecret = new Set<string>();
  private readonly envDumps = new Set<string>();
  private readonly windows: readonly ManduWindow[];
  /** Every response id Mandu recorded, by agent, with the start (ms) of the
   *  earliest Mandu session that recorded it. */
  private readonly recorded = new Map<TranscriptAgent, Map<string, number>>();
  /** Every agent session id Mandu recorded, by agent, with the Mandu
   *  sessions that recorded it. */
  private readonly recordedSessions = new Map<TranscriptAgent, Map<string, ManduWindow[]>>();
  private from: string | undefined;
  private to: string | undefined;
  private dropped = 0;
  private readonly home: string;
  /** The values an example's command is redacted of (item 4): every known
   *  credential, and every other known value that reads as random. */
  private readonly redact: RedactValue[] = [];
  /** Hosts each secret was sent to (item 11), by its id. */
  private readonly sentHosts = new Map<string, Set<string>>();
  private readonly providers: ProviderSettings;
  private readonly projectProviders: ((agent: TranscriptAgent, cwd: string | undefined) => ProviderSetting | undefined) | undefined;

  constructor(opts: {
    known?: readonly KnownSecret[]; home?: string; manduWindows?: readonly ManduWindow[];
    /** The agents' provider settings on this computer (transcript-providers.ts). */
    providers?: ProviderSettings;
    /** A project's own provider settings, by the session's directory. */
    projectProviders?: (agent: TranscriptAgent, cwd: string | undefined) => ProviderSetting | undefined;
  } = {}) {
    this.home = opts.home ?? "";
    this.windows = opts.manduWindows ?? [];
    for (const w of this.windows) {
      if (!w.responseIds?.length) continue;
      let ids = this.recorded.get(w.agent);
      if (ids === undefined) this.recorded.set(w.agent, (ids = new Map()));
      for (const id of w.responseIds) ids.set(id, Math.min(ids.get(id) ?? Infinity, w.from));
    }
    for (const w of this.windows) {
      if (!w.agentSessionIds?.length) continue;
      let ids = this.recordedSessions.get(w.agent);
      if (ids === undefined) this.recordedSessions.set(w.agent, (ids = new Map()));
      for (const id of w.agentSessionIds) {
        const l = ids.get(id);
        if (l === undefined) ids.set(id, [w]);
        else l.push(w);
      }
    }
    this.providers = opts.providers ?? {};
    this.projectProviders = opts.projectProviders;
    for (const k of opts.known ?? []) {
      const cred = knownIsCredential(k);
      if (cred || (k.value.length >= MIN_KNOWN_LEN && looksLikeSecretValue(k.value))) {
        const last = (k.name ?? "").split(".").pop()!.replace(/__\d+$/, "");
        const shown = /^[A-Za-z_][A-Za-z0-9_-]{0,40}$/.test(last) && !looksLikeSecretValue(last) && !last.startsWith("cred") ? last : "secret";
        this.redact.push({ value: k.value, mask: `‹${shown}›` });
      }
      if (!cred) continue;
      const id = this.idOf(k.value);
      if (this.knownIds.has(id)) continue;
      this.knownIds.add(id);
      const shape = vendorShapeOf(k.value);
      const entry = { value: k.value, id, k, ...(shape ? { shape } : {}) };
      this.known.push(entry);
      const name = (k.name ?? "").split(".").pop()!.replace(/__\d+$/, "");
      // Only a variable's kind of name (`STRIPE_KEY`): a config key's `token` is too common to tie a `$token` to.
      if (/^[A-Z][A-Z0-9_]*$/.test(name) && !this.knownByName.has(name)) this.knownByName.set(name, entry);
    }
  }

  /** How many known values the scan looks for. */
  get knownCount(): number {
    return this.known.length;
  }

  private idOf(value: string): string {
    return createHmac("sha256", this.key).update(value).digest("base64");
  }

  private tilde(p: string): string {
    return this.home !== "" && (p === this.home || p.startsWith(`${this.home}/`)) ? `~${p.slice(this.home.length)}` : p;
  }

  /**
   * How one transcript file stands to Mandu (plan 17 §3 item 6). An id Mandu
   * recorded is exact whatever the clocks say. Without one, the Mandu
   * sessions of the same agent that overlap [from, to] decide: none, or all
   * of them recorded ids and none is this file's (a parallel session
   * outside Mandu), is `without`; any other overlap (this file keeps no
   * ids, or a Mandu session from before the proxies recorded them) can only
   * be marked by time. The agent's own session id (`sessionId`, OpenCode's)
   * works the same way: a Mandu session that recorded it is exact. Pure
   * over the windows.
   */
  manduStatusOf(agent: TranscriptAgent, from: string | undefined, to: string | undefined, ids: ReadonlySet<string> | undefined, sessionId?: string): ManduStatus {
    const recorded = this.recorded.get(agent);
    if (ids !== undefined && recorded !== undefined) for (const id of ids) if (recorded.has(id)) return "under";
    if (sessionId !== undefined && this.recordedSessions.get(agent)?.has(sessionId) === true) return "under";
    return this.timeMark(agent, from, to, { response: ids !== undefined && ids.size > 0, session: sessionId !== undefined }, false);
  }

  /** The mark of [from, to] when no id of it is in Mandu's records: the
   *  Mandu sessions of the agent that overlap it decide. `keeps`: which ids
   *  the record keeps (response ids; the agent's session id), so a Mandu
   *  session that recorded ids of that kind and overlaps it would hold one;
   *  `ownRecorded`: one of the file's ids is in Mandu's records (its other
   *  requests ran under Mandu). */
  private timeMark(agent: TranscriptAgent, from: string | undefined, to: string | undefined, keeps: { response: boolean; session: boolean }, ownRecorded: boolean): ManduStatus {
    if (from === undefined || to === undefined) return "without";
    const a = Date.parse(from);
    const b = Date.parse(to);
    const overlap = this.windows.filter((w) => w.agent === agent && a <= w.to && b >= w.from);
    if (overlap.length === 0) return "without";
    const settles = (w: ManduWindow): boolean =>
      (keeps.response && (w.responseIds?.length ?? 0) > 0) || (keeps.session && (w.agentSessionIds?.length ?? 0) > 0);
    if (!ownRecorded && overlap.every(settles)) return "without";
    return "by-time";
  }

  /**
   * How a text (or call) in one request of a file stands to Mandu (plan 17
   * §3 item 6), from a record that tells its requests apart and keeps
   * response ids; `req.at` is the text's time. `under` when the response
   * that answered the request has an id Mandu recorded, unless the text is
   * older than the Mandu session that recorded it (a request sent outside
   * Mandu that only a response after a resume under Mandu answered: it
   * went out without Mandu first). Else its time decides (`timeMark`, at
   * the text's own time when it has one, else over the file's): an id
   * Mandu never recorded is `without` where every Mandu session it overlaps
   * recorded ids; a request no response answered (the session's last) is
   * marked by time where it overlaps a Mandu session. A request that
   * carried the agent's own session id (`req.sessionId`, OpenCode's) is
   * `under` when a Mandu session that recorded that id ran at the text's
   * time (the session's part outside Mandu, before a resume under it or
   * after, went out raw); else its time decides as above, a Mandu session
   * that recorded session ids settling it. Pure over the windows.
   */
  requestMark(agent: TranscriptAgent, req: { responseId?: string; sessionId?: string; at?: string }, file: { from?: string; to?: string; ownRecorded: boolean }): ManduStatus {
    const from = req.at ?? file.from;
    const to = req.at ?? file.to;
    if (req.responseId !== undefined) {
      const since = this.recorded.get(agent)?.get(req.responseId);
      if (since !== undefined && (req.at === undefined || !(Date.parse(req.at) < since))) return "under";
    }
    if (req.sessionId !== undefined) {
      const ws = this.recordedSessions.get(agent)?.get(req.sessionId);
      const t = req.at === undefined ? undefined : Date.parse(req.at);
      if (ws !== undefined && (t === undefined || ws.some((w) => t >= w.from && t <= w.to))) return "under";
      return this.timeMark(agent, from, to, { response: req.responseId !== undefined, session: true }, false);
    }
    return this.timeMark(agent, from, to, { response: true, session: false }, req.responseId === undefined && file.ownRecorded);
  }

  /** A session's standing to Mandu so far (its files together: `under`
   *  over `by-time` over `without`), for the session counts and for a text
   *  whose record tells no request apart. */
  sessionMandu(agent: TranscriptAgent, session: string): ManduStatus {
    return this.status.get(`${agent}\u0000${session}`) ?? "without";
  }

  /** A finding's (or send's) mark in one session, as answered. */
  private markOf(m: SessionMark): ManduStatus {
    return weaker(m.fixed, m.follows ? this.status.get(m.key) ?? "without" : undefined) ?? "without";
  }

  /** How many of a finding's (or send's) sessions are under Mandu, and how
   *  many marked by time. */
  private markCounts(marks: ReadonlyMap<string, SessionMark>): { under: number; byTime: number } {
    let under = 0;
    let byTime = 0;
    for (const m of marks.values()) {
      const st = this.markOf(m);
      if (st === "under") under++;
      else if (st === "by-time") byTime++;
    }
    return { under, byTime };
  }

  /** Read one transcript file: `session` names its session (a subagent's
   *  file shares its parent's), `texts` are its reader's output, `acts`
   *  what the session did (transcript-acts.ts), for the riskier sessions. */
  addSession(agent: TranscriptAgent, session: string, texts: Iterable<SentText>, meta: SessionMeta = {}, acts?: SessionActs): void {
    let seen = this.sessionsOf.get(agent);
    if (seen === undefined) this.sessionsOf.set(agent, (seen = new Set()));
    if (meta.uncounted !== true) seen.add(session);
    // Per finding, per request (`null`: a text of no known request), the
    // time of its earliest text there (its mark) and the newest text of
    // each way (its examples). A text is kept without its body, which no
    // example shows.
    const hits = new Map<Acc, Map<Turn | null, { first?: string; hows: Map<SentHow, SentText> }>>();
    const keep = (a: Acc | undefined, t: SentText): void => {
      if (a === undefined) return;
      let per = hits.get(a);
      if (per === undefined) hits.set(a, (per = new Map()));
      const req = t.turn ?? null;
      let e = per.get(req);
      if (e === undefined) per.set(req, (e = { hows: new Map() }));
      if (t.at !== undefined && (e.first === undefined || t.at < e.first)) e.first = t.at;
      const had = e.hows.get(t.how);
      if (had === undefined || (t.at ?? "") > (had.at ?? "")) e.hows.set(t.how, { ...t, text: "" });
    };
    let first: string | undefined;
    let last: string | undefined;
    for (const t of texts) {
      if (t.at !== undefined) {
        if (first === undefined || t.at < first) first = t.at;
        if (last === undefined || t.at > last) last = t.at;
      }
      const here: string[] = [];
      for (const k of this.known) {
        if (!t.text.includes(k.value)) continue;
        here.push(k.value);
        const name = k.k.name;
        keep(this.note(k.id, "known", name ? `${name} in ${k.k.path}` : k.k.path, agent, session, t, { path: k.k.path, ...(name ? { name } : {}) }), t);
      }
      for (const h of findSecretValues(t.text)) {
        const id = this.idOf(h.value);
        // A known value its shape also finds is reported once, as known; so
        // is a shape that found only a piece of a known value in this same
        // text (a format the detector cuts short), not as a second key.
        if (this.knownIds.has(id) || here.some((v) => v.includes(h.value))) continue;
        keep(this.note(id, h.shape, h.preview, agent, session, t, undefined, h.value), t);
      }
    }
    // The reader is done: every request's response id is filled in.
    if (first !== undefined && (this.from === undefined || first < this.from)) this.from = first;
    if (last !== undefined && (this.to === undefined || last > this.to)) this.to = last;
    const key = `${agent}\u0000${session}`;
    const touched = [...hits.keys()];
    if (acts?.skippedPrompts === true) {
      this.skipped.add(key);
      if (touched.some((a) => a.kind === "known")) this.skippedWithSecret.add(key);
    }
    if (acts?.calls.some(isEnvDump) === true) this.envDumps.add(key);
    const sendsHere = acts === undefined ? [] : this.noteSends(agent, session, acts);
    // A subagent's file shares its parent's key: the strongest mark wins.
    const here = this.manduStatusOf(agent, first, last, meta.responseIds, meta.agentSessionId);
    const before = this.status.get(key);
    const st: ManduStatus = before === "under" || here === "under" ? "under" : before === "by-time" || here === "by-time" ? "by-time" : "without";
    this.status.set(key, st);
    // Per request (plan 17 §3 item 6) where the record keeps response ids or
    // its requests carried the agent's session id; a text or call of no
    // known request, or of a record that keeps no ids, follows the
    // session's mark, read when the answer is made.
    const perRequest = (meta.responseIds !== undefined && meta.responseIds.size > 0) || meta.agentSessionId !== undefined;
    const file = { ...(first !== undefined ? { from: first } : {}), ...(last !== undefined ? { to: last } : {}), ownRecorded: here === "under" };
    // A text is marked at its own time: in a request a resume under Mandu
    // sent, a text older than that Mandu session went out before it.
    const reqMark = (req: { responseId?: string; sessionId?: string; at?: string } | null, at: string | undefined): ManduStatus | undefined => {
      if (req === null || !perRequest) return undefined;
      const when = at ?? req.at;
      return this.requestMark(agent, {
        ...(req.responseId !== undefined ? { responseId: req.responseId } : {}),
        ...(req.sessionId !== undefined ? { sessionId: req.sessionId } : {}),
        ...(when !== undefined ? { at: when } : {}),
      }, file);
    };
    const mark = (marks: Map<string, SessionMark>, m: ManduStatus | undefined): void => {
      let e = marks.get(session);
      if (e === undefined) marks.set(session, (e = { key, follows: false }));
      if (m === undefined) e.follows = true;
      else e.fixed = weaker(e.fixed, m);
    };
    for (const [a, per] of hits) for (const [req, e] of per) mark(a.marks, reqMark(req, e.first));
    // A call went in its own response; the session's id, in every request.
    const sid = meta.agentSessionId !== undefined ? { sessionId: meta.agentSessionId } : {};
    for (const { a, call } of sendsHere) mark(a.marks, reqMark({ ...(call.responseId !== undefined ? { responseId: call.responseId } : {}), ...sid }, call.at));
    // A project is shown redacted like a command (a folder can be named by
    // a random id); it is counted by its own path, which never leaves here.
    const proj = meta.cwd === undefined ? undefined : this.tilde(meta.cwd);
    const project = proj === undefined ? undefined : redactShown(proj, this.redact);
    if (proj !== undefined && project !== undefined) {
      for (const a of touched) {
        if (a.projects.size < MAX_PROJECTS) a.projects.add(project);
        if (a.allProjects.size < MAX_PROJECT_COUNT) a.allProjects.add(proj);
      }
    }
    // The examples (item 4): the newest text of each way in this session,
    // redacted only when it enters a finding's list, with its request's
    // mark (or, of no known request, its session's final mark, read when
    // the answer is made).
    // The record's provider, else the settings' pick, else the agent's own;
    // `other` where the settings send the agent's own provider elsewhere.
    const provider = resolveProvider(agent, meta.provider, this.projectProviders?.(agent, meta.cwd), this.providers[agent]);
    type Hit = { t: SentText; mark: ManduStatus | undefined };
    for (const [a, per] of hits) {
      const made = new Map<SentText, HeldExample>();
      const held = (h: Hit): HeldExample => {
        let e = made.get(h.t);
        if (e === undefined) made.set(h.t, (e = { key, ex: this.example(agent, h.t, project, provider), ...(h.mark !== undefined ? { mark: h.mark } : {}) }));
        return e;
      };
      const put = (list: HeldExample[], h: Hit, max: number): void => {
        const same = list.findIndex((e) => e.key === key);
        if (same >= 0) {
          // Another file of the same session (a subagent's): the newer stays.
          if ((list[same]!.ex.at ?? "") >= (h.t.at ?? "")) return;
          list.splice(same, 1);
        }
        if (wouldEnter(list, h.t.at, max)) insertNewest(list, held(h), max);
      };
      const newer = (x: Hit | undefined, t: SentText): boolean => x === undefined || (t.at ?? "") > (x.t.at ?? "");
      const byHow = new Map<SentHow, Hit>();
      // The newest text that went without Mandu, so `examples` can tell one
      // when every newer one ran while Mandu ran (a resumed session's part
      // outside Mandu among them).
      let without: Hit | undefined;
      for (const [req, e] of per) {
        for (const [how, t] of e.hows) {
          const m = reqMark(req, t.at);
          if (newer(byHow.get(how), t)) byHow.set(how, { t, mark: m });
          if ((m ?? st) === "without" && newer(without, t)) without = { t, mark: m };
        }
      }
      for (const [how, h] of byHow) {
        const list = a.byHow.get(how) ?? [];
        put(list, h, MAX_EXAMPLES_PER_HOW);
        if (list.length > 0) a.byHow.set(how, list);
      }
      if (without !== undefined) put(a.withoutPool, without, MAX_EXAMPLES);
    }
  }

  /** One example, REDACTED (item 4): the call's command or file through
   *  `redactShown`, never the text that held the value. */
  private example(agent: TranscriptAgent, t: SentText, project: string | undefined, provider: ModelProvider): ScanExample {
    const tool = shownToolName(t.call?.tool ?? t.tool);
    let command: string | undefined;
    let file: string | undefined;
    let url: string | undefined;
    if (t.call !== undefined) {
      const cmds = shellCommandsOf({ tool: t.call.tool, input: t.call.input });
      const fetched = fetchedUrlOf(t.call);
      if (cmds !== null && cmds.length > 0) command = redactShown(cmds.join("; "), this.redact);
      else if (fetched !== undefined) url = redactShown(fetched, this.redact);
      else if (cmds === null && (t.how === "read-file" || t.how === "ai-wrote")) {
        const f = fileOfCall(t.call);
        if (f !== undefined) file = redactShown(this.tilde(f), this.redact);
      }
    } else if (t.path !== undefined) file = redactShown(this.tilde(t.path), this.redact);
    return {
      ...(t.at ? { at: t.at } : {}), agent, how: t.how,
      ...(command ? { command } : {}), ...(file ? { file } : {}), ...(url ? { url } : {}), ...(tool ? { tool } : {}),
      ...(project ? { project } : {}), provider,
    };
  }

  /** A finding's `examples`: of its held examples, the newest of each
   *  session, the newest {@link MAX_EXAMPLES} sessions first; when none of
   *  them ran without Mandu and another held one did, that one takes the
   *  last place (the report tells a story without Mandu first). */
  private examplesOf(a: Acc): ScanExample[] {
    const bySession = new Map<string, HeldExample>();
    for (const list of a.byHow.values()) {
      for (const h of list) {
        const had = bySession.get(h.key);
        if (had === undefined || (h.ex.at ?? "") > (had.ex.at ?? "")) bySession.set(h.key, h);
      }
    }
    const all: HeldExample[] = [];
    for (const h of bySession.values()) insertNewest(all, h, Number.MAX_SAFE_INTEGER);
    const out = all.slice(0, MAX_EXAMPLES).map((h) => this.answered(h));
    if (!out.some((e) => e.mandu === "without")) {
      const w = [...all, ...a.withoutPool].find((h) => this.heldMark(h) === "without");
      if (w !== undefined) out.splice(Math.min(out.length, MAX_EXAMPLES - 1), 1, this.answered(w));
    }
    return out;
  }

  /** A held example's mark: its request's, else its session's final one. */
  private heldMark(h: HeldExample): ManduStatus {
    return h.mark ?? this.status.get(h.key) ?? "without";
  }

  /** A held example as answered: its mark filled in. */
  private answered(h: HeldExample): ScanExample {
    return { ...h.ex, mandu: this.heldMark(h) };
  }

  /** The secrets this session's calls sent on, by where they went (item
   *  11): HTTP requests, ssh, git, inline scripts, MCP tools' inputs. */
  private noteSends(agent: TranscriptAgent, session: string, acts: SessionActs): Array<{ a: SendAcc; call: ToolCall }> {
    const touched: Array<{ a: SendAcc; call: ToolCall }> = [];
    for (const call of acts.calls) {
      for (const req of sendsOf(call)) {
        // An MCP tool is no host; an ssh name with no dot is an alias.
        const hosts = req.channel === "mcp" ? req.hosts : req.hosts.filter((h) => !isLocalHost(h, { alias: req.channel === "ssh" }));
        if (hosts.length === 0) continue;
        const urls = req.urls ?? (req.channel === "http" ? httpUrlsIn(req.text) : []);
        const found = new Map<string, { kind: SendFinding["kind"]; preview: string; source?: { path: string; name?: string }; shape?: SecretShape; by: "value" | "variable"; test?: boolean }>();
        const knownHit = (e: { id: string; k: KnownSecret; shape?: SecretShape }, by: "value" | "variable"): void => {
          if (found.has(e.id) && by === "variable") return;
          const name = e.k.name;
          found.set(e.id, { kind: "known", preview: name ? `${name} in ${e.k.path}` : e.k.path, source: { path: e.k.path, ...(name ? { name } : {}) }, ...(e.shape ? { shape: e.shape } : {}), by });
        };
        for (const e of this.known) if (req.text.includes(e.value)) knownHit(e, "value");
        // The HTTP rule reads every `$NAME` of its pipeline; the others name
        // the variables the shell expanded (or a script read) themselves.
        const names = req.vars ?? [...req.text.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]!);
        for (const name of names) {
          const e = this.knownByName.get(name);
          if (e !== undefined) knownHit(e, "variable");
          else if (/^[A-Z][A-Z0-9_]*$/.test(name) && envSecretNameMatches(name)) {
            // A secret by its name alone: its value is in no file the scan read.
            const shape = NAME_SHAPE.find(([re]) => re.test(name))?.[1];
            found.set(`var:${name}`, { kind: "variable", preview: `$${name}`, ...(shape ? { shape } : {}), by: "variable" });
          }
        }
        for (const h of findSecretValues(req.text)) {
          if (h.shape === "credential-assignment") continue;
          // A URL's password is a send only where the URL's credential is
          // what went: git's (an HTTP client's URL is its own rule's).
          if (h.shape === "url-password" && req.channel !== "git") continue;
          const id = this.idOf(h.value);
          if (this.knownIds.has(id) || found.has(id)) continue;
          found.set(id, { kind: h.shape, preview: h.preview, shape: h.shape, by: "value", ...(looksLikeTestValue(h.value, h.shape, h.preview) ? { test: true } : {}) });
        }
        for (const [id, f] of found) {
          for (const host of hosts) {
            if (req.channel !== "mcp") {
              let sh = this.sentHosts.get(id);
              if (sh === undefined) this.sentHosts.set(id, (sh = new Set()));
              sh.add(host);
            }
            const k = `${id}\u0000${req.channel}\u0000${host}`;
            let a = this.sends.get(k);
            if (a === undefined) {
              if (this.sends.size >= MAX_SENDS) { this.sendsDropped++; continue; }
              const to: SentTo = req.channel === "mcp" ? "other-host" : sentTo(host, { ...(f.shape ? { shape: f.shape } : {}), ...(f.source?.name ? { name: f.source.name } : {}), ...(f.source ? { path: f.source.path } : {}) });
              a = { kind: f.kind, preview: f.preview, ...(f.source ? { source: f.source } : {}), to, host, urls: [], sessions: new Set(), ran: new Set(), stopped: new Set(), via: new Set(), channel: req.channel, by: new Set(), agents: new Set(), marks: new Map(), ...(f.test ? { test: true } : {}) };
              this.sends.set(k, a);
            }
            a.sessions.add(session);
            for (const u of urls) {
              if (u.host !== host || a.urls.length >= MAX_SEND_URLS) continue;
              const shown = shownUrl(u.url, this.redact);
              if (!a.urls.includes(shown)) a.urls.push(shown);
            }
            if (call.end === undefined) a.ran.add(session);
            if (call.end === "stopped-by-mandu") a.stopped.add(session);
            a.via.add(req.via);
            a.by.add(f.by);
            a.agents.add(agent);
            if (call.at !== undefined && (a.last === undefined || call.at > a.last)) a.last = call.at;
            touched.push({ a, call });
          }
        }
      }
    }
    return touched;
  }

  private note(id: string, kind: TranscriptFinding["kind"], preview: string, agent: TranscriptAgent, session: string, t: SentText, source?: { path: string; name?: string }, value?: string): Acc | undefined {
    let a = this.acc.get(id);
    if (a === undefined) {
      if (this.acc.size >= MAX_FINDINGS) {
        this.dropped++;
        return undefined;
      }
      // A key-shaped value that reads as a test value is marked, from its
      // value, here: the value never leaves (plan 17 §3 item 14).
      const test = kind !== "known" && value !== undefined && looksLikeTestValue(value, kind, preview);
      a = { kind, preview, ...(source ? { source } : {}), sessions: new Set(), agents: new Set(), how: new Map(), projects: new Set(), marks: new Map(), allProjects: new Set(), byHow: new Map(), withoutPool: [], ...(test ? { test: true } : {}) };
      this.acc.set(id, a);
    }
    a.sessions.add(session);
    a.agents.add(agent);
    let h = a.how.get(t.how);
    if (h === undefined) a.how.set(t.how, (h = new Set()));
    h.add(session);
    if (t.at !== undefined) {
      if (a.first === undefined || t.at < a.first) a.first = t.at;
      if (a.last === undefined || t.at > a.last) a.last = t.at;
    }
    return a;
  }

  /** The findings so far: known values first, then by sessions, most first. */
  result(): TranscriptScanResult {
    let under = 0;
    let byTime = 0;
    for (const st of this.status.values()) {
      if (st === "under") under++;
      else if (st === "by-time") byTime++;
    }
    const rows = [...this.acc].map(([id, a]): [TranscriptFinding, Acc] => {
      const hosts = this.sentHosts.get(id);
      const examples = this.examplesOf(a);
      const m = this.markCounts(a.marks);
      return [{
        kind: a.kind,
        preview: a.preview,
        ...(a.source ? { source: a.source } : {}),
        sessions: a.sessions.size,
        agents: [...a.agents].sort(),
        ...(a.first ? { first: a.first } : {}),
        ...(a.last ? { last: a.last } : {}),
        how: Object.fromEntries([...a.how].map(([k, v]) => [k, v.size])),
        projects: [...a.projects],
        duringMandu: m.under + m.byTime,
        sessionsUnderMandu: m.under,
        sessionsByTime: m.byTime,
        projectCount: a.allProjects.size,
        ...(examples.length > 0 ? { examples } : {}),
        ...(hosts !== undefined ? { sentToHosts: [...hosts].sort() } : {}),
        ...(a.test ? { looksLikeTest: true as const } : {}),
      }, a];
    });
    rows.sort(([x], [y]) => Number(y.kind === "known") - Number(x.kind === "known") || y.sessions - x.sessions || x.preview.localeCompare(y.preview));
    const findings = rows.map(([f, a], i) => (i < MAX_DETAIL_FINDINGS && a.byHow.size > 0
      ? { ...f, examplesByHow: Object.fromEntries([...a.byHow].map(([how, list]) => [how, list.map((h) => this.answered(h))])) }
      : f));
    return {
      sessions: Object.fromEntries([...this.sessionsOf].map(([k, v]) => [k, v.size])),
      duringMandu: under + byTime,
      sessionsUnderMandu: under,
      sessionsByTime: byTime,
      ...(this.from ? { from: this.from } : {}),
      ...(this.to ? { to: this.to } : {}),
      findings,
      dropped: this.dropped,
      risk: { skippedPrompts: this.skipped.size, skippedWithSecret: this.skippedWithSecret.size, envDumps: this.envDumps.size },
      sends: [...this.sends.values()].map((a): SendFinding => {
        const m = this.markCounts(a.marks);
        return {
          kind: a.kind, preview: a.preview, ...(a.source ? { source: a.source } : {}), to: a.to, host: a.host,
          ...(a.urls.length > 0 ? { urls: [...a.urls] } : {}),
          sessions: a.sessions.size, ran: a.ran.size, stoppedByMandu: a.stopped.size,
          via: [...a.via].sort(), channel: a.channel, ...(a.test ? { looksLikeTest: true as const } : {}), by: [...a.by].sort(), agents: [...a.agents].sort(),
          ...(a.last ? { last: a.last } : {}),
          duringMandu: m.under + m.byTime, sessionsUnderMandu: m.under, sessionsByTime: m.byTime,
        };
      }).sort((x, y) => Number(x.to === "own-service") - Number(y.to === "own-service") || Number(y.kind === "known") - Number(x.kind === "known") || y.sessions - x.sessions || x.preview.localeCompare(y.preview) || x.host.localeCompare(y.host)),
      sendsDropped: this.sendsDropped,
    };
  }
}

// ── Reading the files ───────────────────────────────────────────────────────

/** Where an agent keeps its transcripts: a directory of JSONL files
 *  (Claude Code's, Codex's: no `kind`), or one of the stores of
 *  transcript-stores.ts. */
export interface TranscriptSource {
  agent: TranscriptAgent;
  root: string;
  kind?: StoreKind | UnwrappedKind;
}

const isUnwrapped = (k: StoreKind | UnwrappedKind): k is UnwrappedKind => k === "gemini-chats" || k === "copilot-events" || COUNT_ONLY_KINDS.has(k as UnwrappedKind);

/** An absolute directory an environment variable names, else undefined
 *  (each agent ignores a relative one, as the XDG rules say). */
const absDir = (v: string | undefined): string | undefined => (v !== undefined && v.startsWith("/") ? v : undefined);

/**
 * The transcript stores for a home, each where the agent's own environment
 * puts it (as the launcher finds them): Claude Code's `projects` (under
 * `CLAUDE_CONFIG_DIR`), Codex's `sessions` (under `CODEX_HOME`), OpenCode's
 * `opencode.db` (under `$XDG_DATA_HOME/opencode`, default
 * `~/.local/share/opencode`), Goose's `sessions/sessions.db`, older
 * `sessions/*.jsonl` and request log `logs/llm_request.*.jsonl` (its data
 * and state directories: `<GOOSE_PATH_ROOT>/data` and `/state` when that is
 * set, else `$XDG_DATA_HOME/goose` and `$XDG_STATE_HOME/goose`, and on
 * macOS `~/Library/Application Support/Block.goose`), and OpenClaw's
 * agents' sessions (under `OPENCLAW_STATE_DIR`, default `~/.openclaw`):
 * each agent's `sessions/*.jsonl`, and 9.x's `agent/openclaw-agent.sqlite`.
 * The agents Mandu does not run (plan 17 §4 phase 3,
 * transcript-unwrapped.ts): Gemini CLI's `.gemini/tmp/<project>/chats`
 * (under `GEMINI_CLI_HOME`, which stands for the home), Copilot CLI's
 * `session-state/<id>/events.jsonl` (under `COPILOT_HOME`, default
 * `~/.copilot`; before 1.0.44 `$XDG_STATE_HOME/.copilot` when that is set),
 * and, counted only, Cursor's editor `state.vscdb` (its
 * `User/globalStorage`, under `$XDG_CONFIG_HOME` (default `~/.config`)
 * `Cursor` or `cursor`, macOS's `~/Library/Application Support/Cursor`) and
 * the `cursor-agent` CLI's `chats` (under `CURSOR_CONFIG_DIR`, else
 * `$XDG_CONFIG_HOME/cursor` when that is set, else `~/.cursor`).
 * A store that does not exist reads as no session. Pure.
 */
export function transcriptSources(home: string, env: Record<string, string | undefined> = {}): TranscriptSource[] {
  const claude = env["CLAUDE_CONFIG_DIR"] || join(home, ".claude");
  const codex = env["CODEX_HOME"] || join(home, ".codex");
  const data = absDir(env["XDG_DATA_HOME"]) ?? join(home, ".local", "share");
  const state = absDir(env["XDG_STATE_HOME"]) ?? join(home, ".local", "state");
  const gooseRoot = absDir(env["GOOSE_PATH_ROOT"]);
  const macGoose = join(home, "Library", "Application Support", "Block.goose");
  const gooseDirs: Array<[string, string]> = gooseRoot !== undefined
    ? [[join(gooseRoot, "data"), join(gooseRoot, "state")]]
    : [[join(data, "goose"), join(state, "goose")], [macGoose, macGoose]];
  const openclaw = absDir(env["OPENCLAW_STATE_DIR"]) ?? join(home, ".openclaw");
  const gemini = join(absDir(env["GEMINI_CLI_HOME"]) ?? home, ".gemini");
  const copilot = absDir(env["COPILOT_HOME"]) ?? join(home, ".copilot");
  const xdgConfig = absDir(env["XDG_CONFIG_HOME"]);
  const config = xdgConfig ?? join(home, ".config");
  const cursorCli = absDir(env["CURSOR_CONFIG_DIR"]) ?? (xdgConfig !== undefined ? join(xdgConfig, "cursor") : join(home, ".cursor"));
  const vscdb = (d: string): string => join(d, "User", "globalStorage", "state.vscdb");
  return [
    { agent: "claude-code", root: join(claude, "projects") },
    { agent: "codex", root: join(codex, "sessions") },
    { agent: "opencode", kind: "opencode-db", root: join(data, "opencode", "opencode.db") },
    ...gooseDirs.flatMap(([d, s]): TranscriptSource[] => [
      { agent: "goose", kind: "goose-db", root: join(d, "sessions", "sessions.db") },
      { agent: "goose", kind: "goose-jsonl", root: join(d, "sessions") },
      { agent: "goose", kind: "goose-request-log", root: join(s, "logs") },
    ]),
    { agent: "openclaw", kind: "openclaw-jsonl", root: join(openclaw, "agents") },
    { agent: "openclaw", kind: "openclaw-db", root: join(openclaw, "agents") },
    { agent: "gemini", kind: "gemini-chats", root: join(gemini, "tmp") },
    { agent: "copilot", kind: "copilot-events", root: join(copilot, "session-state") },
    // Copilot CLI before 1.0.44 kept its state in `$XDG_STATE_HOME/.copilot` when that was set.
    ...(absDir(env["XDG_STATE_HOME"]) !== undefined ? [{ agent: "copilot", kind: "copilot-events", root: join(state, ".copilot", "session-state") } satisfies TranscriptSource] : []),
    ...[join(config, "Cursor"), join(config, "cursor"), join(home, "Library", "Application Support", "Cursor")]
      .map((d): TranscriptSource => ({ agent: "cursor", kind: "cursor-editor", root: vscdb(d) })),
    { agent: "cursor", kind: "cursor-cli", root: join(cursorCli, "chats") },
  ];
}

/** Is `path` a transcript the scan reads (a file of one of `sources`)? The
 *  values the scan looks for are never taken from one: a transcript is
 *  where they are looked for, not where they live. Pure. */
export function isTranscriptStorePath(path: string, sources: readonly TranscriptSource[]): boolean {
  return sources.some((s) => (s.kind === undefined ? path.startsWith(`${s.root}/`) && path.endsWith(".jsonl")
    : isUnwrapped(s.kind) ? isUnwrappedStoreFile(s.kind, s.root, path) : isStoreFile(s.kind, s.root, path)));
}

/** The session a transcript file belongs to: a Claude Code subagent's file
 *  (`<project>/<session>/subagents/<agent>.jsonl`) belongs to its parent
 *  (`<project>/<session>.jsonl`); every other file is its own. Pure. */
export function sessionKeyOf(file: string): string {
  const dir = dirname(file);
  if (basename(dir) === "subagents") return `${dirname(dir)}.jsonl`;
  return file;
}

/** The scan's caps. A cap that stops the scan is counted, never silent. */
export interface TranscriptScanLimits {
  /** The whole scan's time (ms). */
  deadlineMs: number;
  /** Bytes read in all. */
  maxBytes: number;
  /** One file's size; larger files are counted, not read. */
  maxFileBytes: number;
  /** Files listed per root. */
  maxFiles: number;
}

export const DEFAULT_TRANSCRIPT_LIMITS: TranscriptScanLimits = {
  deadlineMs: 300_000,
  maxBytes: 16 * 2 ** 30,
  maxFileBytes: 512 * 2 ** 20,
  maxFiles: 50_000,
};

/** What a cap left unread, in files. */
export interface TranscriptScanCapped {
  /** Left unread because the time ran out. */
  overTime: number;
  /** Left unread because the byte budget ran out. */
  overBytes: number;
  /** Over `maxFileBytes`. */
  tooBig: number;
  /** Past `maxFiles` in a root. */
  overFiles: number;
  /** Could not be read. */
  readFailed: number;
}

/** The whole answer of {@link scanAgentTranscripts}. */
export interface TranscriptScanRun extends TranscriptScanResult {
  /** Known values looked for (the credential-like ones only). */
  known: number;
  /** Bytes read. */
  bytes: number;
  capped: TranscriptScanCapped;
  limits: TranscriptScanLimits;
  ms: number;
  /** Sessions of agents whose store the scan counts but does not read
   *  (Cursor's chats: plan 17 §4), by agent; absent when there are none. */
  notRead?: Partial<Record<TranscriptAgent, number>>;
}

/** Every `*.jsonl` under `root` (a symlinked directory is not followed), at
 *  most `max`; `overflow` counts the rest. Claude Code's and Codex's layout. */
function listJsonl(root: string, max: number, overflow: { n: number }): Array<{ path: string; st: Stats }> {
  const out: Array<{ path: string; st: Stats }> = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 8) return;
    let ents;
    try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (e.isFile() && e.name.endsWith(".jsonl")) {
        if (out.length >= max) { overflow.n++; continue; }
        try { out.push({ path: p, st: statSync(p) }); } catch { /* gone */ }
      }
    }
  };
  walk(root, 0);
  return out;
}

/** One file's records, parsed; a line that is not JSON is skipped. */
async function readRecords(file: string): Promise<unknown[]> {
  const out: unknown[] = [];
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    if (line === "") continue;
    try { out.push(JSON.parse(line)); } catch { /* a torn or foreign line */ }
  }
  return out;
}

/** A Claude Code or Codex transcript file as one unit of the scan. */
function jsonlItem(agent: TranscriptAgent, f: { path: string; st: Stats }): StoreItem {
  return {
    agent, path: f.path, mtimeMs: f.st.mtimeMs, size: f.st.size, session: sessionKeyOf(f.path),
    read: async () => {
      const recs = await readRecords(f.path);
      const meta: SessionMeta = {};
      const texts = agent === "claude-code" ? claudeCodeSentTexts(recs, meta) : codexSentTexts(recs, meta);
      return { texts, meta, acts: agent === "claude-code" ? claudeCodeActs(recs) : codexActs(recs) };
    },
  };
}

/**
 * Scan the agents' transcripts (plan 17). Units (a transcript file, or a
 * session of an agent's database) newest first, so a cap cuts the oldest;
 * `since` (ms since the epoch) skips those last written before it. A
 * database's session is sized by its rows: the per-file cap applies to the
 * session, not to the database. Read-only: it opens no network connection,
 * writes nothing, and opens an agent's database so that it neither changes
 * nor blocks it (transcript-stores.ts `openAgentStore`). A unit it cannot
 * read is counted in `capped.readFailed`, never thrown.
 */
export async function scanAgentTranscripts(opts: {
  home: string;
  sources: readonly TranscriptSource[];
  known?: readonly KnownSecret[];
  manduWindows?: readonly ManduWindow[];
  since?: number;
  limits?: Partial<TranscriptScanLimits>;
  now?: () => number;
  /** This computer's environment, for the model provider (`providersFromEnv`),
   *  when `providers` is not given. */
  env?: Record<string, string | undefined>;
  /** The agents' provider settings (transcript-providers.ts `providerSettingsOf`). */
  providers?: ProviderSettings;
  /** A project's own provider settings, by the session's directory. */
  projectProviders?: (agent: TranscriptAgent, cwd: string | undefined) => ProviderSetting | undefined;
}): Promise<TranscriptScanRun> {
  const now = opts.now ?? Date.now;
  const limits = { ...DEFAULT_TRANSCRIPT_LIMITS, ...opts.limits };
  const t0 = now();
  const scanner = new TranscriptScanner({
    home: opts.home, ...(opts.known ? { known: opts.known } : {}), ...(opts.manduWindows ? { manduWindows: opts.manduWindows } : {}),
    providers: opts.providers ?? providersFromEnv(opts.env ?? {}),
    ...(opts.projectProviders ? { projectProviders: opts.projectProviders } : {}),
  });
  const capped: TranscriptScanCapped = { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 };
  const items: StoreItem[] = [];
  const notRead: Partial<Record<TranscriptAgent, number>> = {};
  const open: OpenStores = new Map();
  try {
    for (const src of opts.sources) {
      const overflow = { n: 0 };
      const failed = { n: 0 };
      if (src.kind !== undefined && isUnwrapped(src.kind) && COUNT_ONLY_KINDS.has(src.kind)) {
        // Counted, never read (plan 17 §4: Cursor's stores).
        const n = countCursorChats(src.kind as "cursor-editor" | "cursor-cli", src.root);
        if (n === null) capped.readFailed++;
        else if (n > 0) notRead[src.agent] = (notRead[src.agent] ?? 0) + n;
        continue;
      }
      const found = src.kind === undefined
        ? listJsonl(src.root, limits.maxFiles, overflow).map((f) => jsonlItem(src.agent, f))
        : isUnwrapped(src.kind) ? unwrappedItems({ agent: src.agent, kind: src.kind, root: src.root }, limits.maxFiles, overflow)
          : storeItems({ agent: src.agent, kind: src.kind, root: src.root }, limits.maxFiles, overflow, open, failed);
      for (const it of found) if (opts.since === undefined || it.mtimeMs >= opts.since) items.push(it);
      capped.overFiles += overflow.n;
      capped.readFailed += failed.n;
    }
    items.sort((a, b) => b.mtimeMs - a.mtimeMs);
    let bytes = 0;
    for (const it of items) {
      if (now() - t0 > limits.deadlineMs) { capped.overTime++; continue; }
      if (it.size > limits.maxFileBytes) { capped.tooBig++; continue; }
      if (bytes + it.size > limits.maxBytes) { capped.overBytes++; continue; }
      let got;
      try { got = await it.read(); } catch { capped.readFailed++; continue; }
      bytes += it.size;
      scanner.addSession(it.agent, it.session, got.texts, got.meta, got.acts);
    }
    return { ...scanner.result(), known: scanner.knownCount, bytes, capped, limits, ms: now() - t0, ...(Object.keys(notRead).length > 0 ? { notRead } : {}) };
  } finally {
    closeStores(open);
  }
}

/**
 * The agents this computer's environment points at another model provider:
 * Claude Code on Bedrock, Vertex or Foundry, or with an `ANTHROPIC_BASE_URL`
 * outside `anthropic.com`; Codex with an `OPENAI_BASE_URL` outside
 * `openai.com`. The report then says "the model provider" rather than name
 * one it cannot be sure of. The agents' own settings files are read by
 * transcript-providers.ts `providerSettingsOf`, which includes this. Pure.
 */
export function providersFromEnv(env: Record<string, string | undefined>): ProviderSettings {
  const out: ProviderSettings = {};
  const cc = claudeCodeSetting(env);
  if (cc !== undefined) out["claude-code"] = cc;
  const cx = codexSetting(null, env);
  if (cx !== undefined) out.codex = cx;
  return out;
}

// ── Mandu's own sessions ────────────────────────────────────────────────────

/** The launcher's target names for the agents the scan reads. */
const TARGET_AGENT: Readonly<Record<string, TranscriptAgent>> = { claude: "claude-code", codex: "codex", opencode: "opencode", goose: "goose", openclaw: "openclaw" };

/** Bytes read from each end of an event file. */
const EVENT_EDGE_BYTES = 256 * 1024;

function readEdge(fd: number, size: number, fromEnd: boolean): string {
  const n = Math.min(size, EVENT_EDGE_BYTES);
  const buf = Buffer.alloc(n);
  readSync(fd, buf, 0, n, fromEnd ? size - n : 0);
  return buf.toString("utf8");
}

/** The first (or last) whole line of event `kind` in `text`, parsed. */
function eventLine(text: string, kind: string, last: boolean): Record<string, unknown> | null {
  const lines = text.split("\n");
  if (last) lines.reverse();
  for (const l of lines) {
    if (!l.includes(`"${kind}"`)) continue;
    try {
      const o = JSON.parse(l) as Record<string, unknown>;
      if (o["kind"] === kind) return o;
    } catch { /* a line the edge cut */ }
  }
  return null;
}

/** An event file larger than this is not read for response ids (its
 *  window is then marked by time only). */
export const EVENT_IDS_MAX_FILE_BYTES = 64 * 2 ** 20;
/** Bytes read for response ids over the whole event store; past it, the
 *  remaining windows are marked by time only. */
export const EVENT_IDS_MAX_BYTES = 1024 * 2 ** 20;

/** A `tllm_call`'s `model.responseId`, as JSON writes it. Inside a JSON
 *  string a quote is escaped, so the unescaped sequence is only ever a key:
 *  a prompt quoting this text cannot forge an id. */
const RESPONSE_ID_FIELD_RE = /"responseId":"([A-Za-z0-9_-]{8,128})"/g;
/** A `tllm_call`'s `model.agentSessionId` (OpenCode's session id), as JSON
 *  writes it; the same rule as {@link RESPONSE_ID_FIELD_RE}. */
const AGENT_SESSION_ID_FIELD_RE = /"agentSessionId":"(ses_[A-Za-z0-9]{8,120})"/g;

/** The response ids and the agents' session ids in one event file (the
 *  whole file, read once). */
function recordedIdsIn(fd: number, size: number): { responseIds: string[]; agentSessionIds: string[] } {
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = readSync(fd, buf, off, size - off, off);
    if (n === 0) break;
    off += n;
  }
  const text = buf.toString("utf8", 0, off);
  const ids = new Set<string>();
  for (const m of text.matchAll(RESPONSE_ID_FIELD_RE)) ids.add(m[1]!);
  const sessions = new Set<string>();
  for (const m of text.matchAll(AGENT_SESSION_ID_FIELD_RE)) sessions.add(m[1]!);
  return { responseIds: [...ids], agentSessionIds: [...sessions] };
}

/**
 * Mandu's sessions from its event store (`~/.mandu/events/*.ndjson`, one
 * file per session): the agent from the `launch_posture` event's `target`,
 * the start from its `ts`, the end from `session_exit` (else the file's
 * last write), and the response ids and the agents' session ids
 * (OpenCode's) its model proxy recorded on its `tllm_call` events (plan 17
 * §3 item 6). Of the events it keeps only the
 * kind, target, time and those ids; a file over
 * {@link EVENT_IDS_MAX_FILE_BYTES}, or past {@link EVENT_IDS_MAX_BYTES} in
 * all, is read at its ends only, so it gives no ids. Sessions of agents the
 * scan does not read are left out.
 */
export function manduWindowsFrom(eventsDir: string, limits: { maxFileBytes?: number; maxBytes?: number } = {}): ManduWindow[] {
  const out: ManduWindow[] = [];
  const maxFile = limits.maxFileBytes ?? EVENT_IDS_MAX_FILE_BYTES;
  let budget = limits.maxBytes ?? EVENT_IDS_MAX_BYTES;
  let names: string[];
  try { names = readdirSync(eventsDir); } catch { return out; }
  for (const n of names) {
    if (!n.endsWith(".ndjson")) continue;
    const p = join(eventsDir, n);
    let fd: number | null = null;
    try {
      const st = statSync(p);
      if (!st.isFile() || st.size === 0) continue;
      fd = openSync(p, "r");
      const launch = eventLine(readEdge(fd, st.size, false), "launch_posture", false);
      if (launch === null) continue;
      const agent = TARGET_AGENT[String(launch["target"] ?? "")];
      const from = Date.parse(String(launch["ts"] ?? ""));
      if (agent === undefined || !Number.isFinite(from)) continue;
      const exit = eventLine(readEdge(fd, st.size, true), "session_exit", true);
      const end = exit !== null ? Date.parse(String(exit["ts"] ?? "")) : st.mtimeMs;
      let ids: { responseIds: string[]; agentSessionIds: string[] } = { responseIds: [], agentSessionIds: [] };
      if (st.size <= maxFile && st.size <= budget) {
        budget -= st.size;
        ids = recordedIdsIn(fd, st.size);
      }
      out.push({
        agent, from, to: Number.isFinite(end) ? end : st.mtimeMs,
        ...(ids.responseIds.length > 0 ? { responseIds: ids.responseIds } : {}),
        ...(ids.agentSessionIds.length > 0 ? { agentSessionIds: ids.agentSessionIds } : {}),
      });
    } catch {
      /* unreadable: no window */
    } finally {
      if (fd !== null) closeSync(fd);
    }
  }
  return out;
}
