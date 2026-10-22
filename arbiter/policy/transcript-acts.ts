/**
 * transcript-acts — what a past agent session did, besides what it said:
 * the tool calls it made, how each ended, and the two session habits the
 * scan reports as riskier (plan 17 §3 item 10,
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md):
 * running with the agent's permission prompts off, and printing the whole
 * environment to the model; and what a call sent on (item 11): HTTP
 * requests, ssh, git with a credential, an inline script's HTTP call, an
 * MCP tool's input (`sendsOf`).
 *
 * It reads the structure of the records and no secret: the scanner
 * (transcript-scan.ts) finds the secrets in the texts on its own.
 *
 * Pure: no file, no network. PROVENANCE (CONTRIBUTING.md reuse policy): NEW
 * Mandu code (no reference origin).
 */

import { responseIdOf } from "./transcript-readers.js";
import { shownToolName } from "./transcript-redact.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/** How a call ended, when it did not simply run. */
export type CallEnd =
  /** The tool reported an error (a command's non-zero exit). */
  | "failed"
  /** The person said no at the permission prompt. */
  | "refused"
  /** Mandu held it back (its fail-closed answer is in the output). */
  | "stopped-by-mandu";

/** One tool call the model made, with how it ended. */
export interface ToolCall {
  tool: string;
  /** The call's input as the transcript holds it (an object, or a string). */
  input: unknown;
  at?: string;
  end?: CallEnd;
  /** The id of the model response that made the call, when the record
   *  keeps a well-formed one: the scan joins the call, as it joins a text,
   *  to the ids Mandu's model proxies recorded (plan 17 §3 item 6). */
  responseId?: string;
}

/** What a session did. */
export interface SessionActs {
  calls: ToolCall[];
  /** The session ran with the agent's permission prompts off (Claude Code's
   *  `bypassPermissions`; Codex with approvals `never` and no sandbox). */
  skippedPrompts: boolean;
}

/** Mandu's fail-closed answer, as its proxies write it into a tool's output. */
const MANDU_STOP_RE = /mandu_fail_closed/;
/** Claude Code's text for a call the person turned down. */
const CLAUDE_REFUSED_RE = /^(?:The user doesn't want to proceed|\[Request interrupted by user|Permission to use \S+ (?:has been|was) denied)/;

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

/**
 * A Claude Code transcript's tool calls (each `tool_use` of an `assistant`
 * record) with how each ended (its `tool_result`'s `is_error`, the person's
 * refusal, Mandu's stop), and whether the session skipped its permission
 * prompts (any record's `permissionMode` of `bypassPermissions`). Pure.
 */
export function claudeCodeActs(records: readonly unknown[]): SessionActs {
  const results = new Map<string, { error: boolean; text: string }>();
  let skippedPrompts = false;
  for (const r of records) {
    if (!isObj(r)) continue;
    if (r["permissionMode"] === "bypassPermissions") skippedPrompts = true;
    if (r["type"] !== "user" || !isObj(r["message"]) || !Array.isArray(r["message"]["content"])) continue;
    for (const b of r["message"]["content"]) {
      if (!isObj(b) || b["type"] !== "tool_result") continue;
      const id = str(b["tool_use_id"]);
      if (id !== undefined) results.set(id, { error: b["is_error"] === true, text: blockText(b["content"]) });
    }
  }
  const calls: ToolCall[] = [];
  for (const r of records) {
    if (!isObj(r) || r["type"] !== "assistant" || !isObj(r["message"]) || !Array.isArray(r["message"]["content"])) continue;
    const at = str(r["timestamp"]);
    const responseId = r["message"]["model"] === "<synthetic>" ? undefined : responseIdOf(r["message"]["id"]);
    for (const b of r["message"]["content"]) {
      if (!isObj(b) || b["type"] !== "tool_use") continue;
      const tool = str(b["name"]);
      if (tool === undefined) continue;
      const res = results.get(str(b["id"]) ?? "");
      const end: CallEnd | undefined = res === undefined ? undefined
        : MANDU_STOP_RE.test(res.text) ? "stopped-by-mandu"
          : res.error && CLAUDE_REFUSED_RE.test(res.text) ? "refused"
            : res.error ? "failed" : undefined;
      calls.push({ tool, input: b["input"], ...(at ? { at } : {}), ...(end ? { end } : {}), ...(responseId ? { responseId } : {}) });
    }
  }
  return { calls, skippedPrompts };
}

/** A Codex tool output that says its command failed: a non-zero exit code
 *  in the forms Codex has written (`"exit_code":1`, `Exit code: 1`,
 *  `Process exited with code 1`) or `Script failed`. */
const CODEX_FAILED_RE = /"exit_code"\s*:\s*[1-9]|\bExit code:\s*[1-9]|\bexited with code [1-9]|^Script failed/m;

/**
 * A Codex rollout's tool calls (`function_call`, `custom_tool_call`,
 * `local_shell_call`) with how each ended (its output's exit code, Mandu's
 * stop), and whether the session skipped its prompts (a `turn_context` with
 * `approval_policy` `never` and a `danger-full-access` sandbox). Pure.
 */
export function codexActs(records: readonly unknown[]): SessionActs {
  const outputs = new Map<string, string>();
  let skippedPrompts = false;
  for (const r of records) {
    if (!isObj(r) || !isObj(r["payload"])) continue;
    const p = r["payload"];
    if (r["type"] === "turn_context" && p["approval_policy"] === "never" && isObj(p["sandbox_policy"]) && p["sandbox_policy"]["type"] === "danger-full-access") skippedPrompts = true;
    if (r["type"] !== "response_item") continue;
    const pt = p["type"];
    if (pt === "function_call_output" || pt === "custom_tool_call_output" || pt === "local_shell_call_output") {
      const out = p["output"];
      const text = typeof out === "string" ? out : isObj(out) && typeof out["content"] === "string" ? out["content"] : blockText(out);
      const id = str(p["call_id"]);
      if (id !== undefined) outputs.set(id, text);
    }
  }
  const calls: ToolCall[] = [];
  // A response's calls come before its `token_usage_record`, which names it.
  let unanswered: ToolCall[] = [];
  for (const r of records) {
    if (isObj(r) && r["type"] === "token_usage_record" && isObj(r["payload"])) {
      const responseId = responseIdOf(r["payload"]["response_id"]);
      if (responseId !== undefined) for (const c of unanswered) c.responseId = responseId;
      unanswered = [];
      continue;
    }
    if (!isObj(r) || r["type"] !== "response_item" || !isObj(r["payload"])) continue;
    const p = r["payload"];
    const pt = p["type"];
    if (pt !== "function_call" && pt !== "custom_tool_call" && pt !== "local_shell_call") continue;
    const tool = str(p["name"]) ?? (pt === "local_shell_call" ? "local_shell" : undefined);
    if (tool === undefined) continue;
    const at = str(r["timestamp"]);
    const out = outputs.get(str(p["call_id"]) ?? "");
    const end: CallEnd | undefined = out === undefined ? undefined
      : MANDU_STOP_RE.test(out) ? "stopped-by-mandu" : CODEX_FAILED_RE.test(out) ? "failed" : undefined;
    const call: ToolCall = { tool, input: p["arguments"] ?? p["input"] ?? p["action"], ...(at ? { at } : {}), ...(end ? { end } : {}) };
    calls.push(call);
    unanswered.push(call);
  }
  return { calls, skippedPrompts };
}

// ── The commands in a call ──────────────────────────────────────────────────

/** Tools that run a shell command: Claude Code's `Bash`; Codex's `shell`,
 *  `exec_command`, `container.exec`, `local_shell` and code-mode `exec`;
 *  OpenCode's `bash` (1.x) and `shell` (2.x); Goose's `shell` (older
 *  `developer__shell`); OpenClaw's `exec` (older `bash`); Gemini CLI's
 *  `run_shell_command`; Copilot CLI's `bash` and `powershell`. Each takes
 *  the command as `command` (or `cmd`). */
export const SHELL_TOOLS: ReadonlySet<string> = new Set(["Bash", "shell", "exec_command", "container.exec", "local_shell", "exec", "bash", "developer__shell", "run_shell_command", "powershell"]);

/** `bash -lc "<cmd>"` and its kin: the command string. */
function argvCommand(argv: readonly unknown[]): string {
  const words = argv.filter((w): w is string => typeof w === "string");
  const c = words.findIndex((w) => /^-[a-z]*c$/.test(w));
  if (c >= 1 && /(?:^|\/)(?:ba|z|da|k)?sh$/.test(words[0]!) && words[c + 1] !== undefined) return words[c + 1]!;
  return words.join(" ");
}

/** The JavaScript string literals given to `cmd:` in a Codex code-mode
 *  `exec` input (`tools.exec_command({cmd:"…"})`). */
function codeModeCommands(code: string): string[] {
  const out: string[] = [];
  for (const m of code.matchAll(/\bcmd\s*:\s*("(?:[^"\\\n]|\\.)*")/g)) {
    try { out.push(JSON.parse(m[1]!) as string); } catch { out.push(m[1]!.slice(1, -1)); }
  }
  return out;
}

/** The shell commands a call ran, or null when it is not a shell call. */
export function shellCommandsOf(call: ToolCall): string[] | null {
  if (!SHELL_TOOLS.has(call.tool)) return null;
  let input = call.input;
  if (typeof input === "string") {
    const t = input.trim();
    if (t.startsWith("{")) { try { input = JSON.parse(t) as unknown; } catch { /* code, below */ } }
  }
  if (typeof input === "string") {
    const cmds = codeModeCommands(input);
    return cmds.length > 0 ? cmds : call.tool === "exec" ? [] : [input];
  }
  if (!isObj(input)) return [];
  const c = input["command"] ?? input["cmd"];
  if (typeof c === "string") return [c];
  if (Array.isArray(c)) return [argvCommand(c)];
  return [];
}

/**
 * A command's pipelines: split at an unquoted `;`, `&&`, `||`, `&` or new
 * line, never inside quotes or `$(…)`. A here-document's body stays with
 * the line that opened it. Rough by design: enough to name each program.
 * Pure.
 */
export function shellPipelines(cmd: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let depth = 0;
  let heredoc: string | null = null;
  const flush = (): void => {
    if (cur.trim() !== "") out.push(cur.trim());
    cur = "";
  };
  // A line ended by `\` continues on the next.
  const lines = cmd.replace(/\\\r?\n/g, " ").split("\n");
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    if (heredoc !== null) {
      cur += `\n${line}`;
      if (line.replace(/^\t+/, "") === heredoc) { heredoc = null; flush(); }
      continue;
    }
    for (let i = 0; i < line.length; i++) {
      const ch = line[i]!;
      if (quote !== null) {
        cur += ch;
        if (ch === "\\" && quote === '"' && i + 1 < line.length) cur += line[++i];
        else if (ch === quote) quote = null;
        continue;
      }
      if (ch === "\\" && i + 1 < line.length) { cur += ch + line[++i]; continue; }
      if (ch === "'" || ch === '"' || ch === "`") { quote = ch; cur += ch; continue; }
      if (ch === "$" && line[i + 1] === "(") { depth++; cur += "$("; i++; continue; }
      if (depth > 0) {
        if (ch === "(") depth++;
        else if (ch === ")") depth--;
        cur += ch;
        continue;
      }
      if (ch === "<" && line[i + 1] === "<" && line[i + 2] !== "<") {
        const m = /^<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/.exec(line.slice(i));
        if (m) { heredoc = m[2]!; cur += m[0]; i += m[0].length - 1; continue; }
      }
      if (ch === ";" || (ch === "&" && line[i - 1] !== ">" && line[i + 1] !== ">")) {
        flush();
        if (ch === "&" && line[i + 1] === "&") i++;
        continue;
      }
      if (ch === "|" && line[i + 1] === "|") { flush(); i++; continue; }
      cur += ch;
    }
    if (quote === null && depth === 0 && heredoc === null) flush();
    else if (heredoc === null) cur += "\n";
  }
  flush();
  return out;
}

/** A pipeline's commands (split at an unquoted `|`), each as its words with
 *  quotes removed, from the pipeline's first line. Pure. */
export function pipelineCommands(pipeline: string): string[][] {
  const head = pipeline.split("\n")[0]!;
  const cmds: string[][] = [];
  let words: string[] = [];
  let w = "";
  let quote: string | null = null;
  let inWord = false;
  const endWord = (): void => { if (inWord) words.push(w); w = ""; inWord = false; };
  for (let i = 0; i < head.length; i++) {
    const ch = head[i]!;
    if (quote !== null) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"' && i + 1 < head.length) w += head[++i];
      else w += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; inWord = true; continue; }
    if (ch === "\\" && i + 1 < head.length) { w += head[++i]; inWord = true; continue; }
    if (ch === "|") { endWord(); if (words.length > 0) cmds.push(words); words = []; continue; }
    if (/\s/.test(ch)) { endWord(); continue; }
    w += ch;
    inWord = true;
  }
  endWord();
  if (words.length > 0) cmds.push(words);
  return cmds;
}

/** Filters that keep only what matches; one whose pattern names no secret
 *  word turns a dump into a lookup (`env | grep PATH`). */
const FILTERS = new Set(["grep", "egrep", "fgrep", "rg", "awk", "sed", "cut", "wc"]);
const SECRETISH_RE = /key|token|secret|pass|auth|cred|cookie|session/i;

/** Does this command print every variable: `env` or `printenv` with no
 *  name, `export` or `export -p`, `set` alone, `declare -x` / `typeset -x`
 *  with flags only, or `cat` of a process's `environ`? */
function dumpsEnvironment(words: readonly string[]): boolean {
  const w = words[0] === "sudo" ? words.slice(1) : words;
  const prog = w[0]?.replace(/^.*\//, "");
  const args = w.slice(1);
  const flagsOnly = args.every((a) => a.startsWith("-"));
  switch (prog) {
    case "env":
    case "printenv":
    case "export":
      return flagsOnly;
    case "set":
      return args.length === 0;
    case "declare":
    case "typeset":
      return flagsOnly && args.length > 0;
    case "cat":
      return args.some((a) => /^\/proc\/[^/]+\/environ$/.test(a));
    default:
      return false;
  }
}

/**
 * Did this shell call print the whole environment to the model: a command
 * that prints every variable, not narrowed by a filter for something else
 * (a filter for `key`, `token`, `secret`, … keeps the dump's secrets), and
 * not failed or refused? Pure.
 */
export function isEnvDump(call: ToolCall): boolean {
  if (call.end !== undefined) return false;
  for (const cmd of shellCommandsOf(call) ?? []) {
    for (const p of shellPipelines(cmd)) {
      const cmds = pipelineCommands(p);
      if (cmds[0] === undefined || !dumpsEnvironment(cmds[0])) continue;
      const narrowed = cmds.slice(1).some((c) => FILTERS.has(c[0]?.replace(/^.*\//, "") ?? "") && !c.slice(1).some((a) => SECRETISH_RE.test(a)));
      if (!narrowed) return true;
    }
  }
  return false;
}

// ── HTTP requests a call made ───────────────────────────────────────────────

/** Programs that make an HTTP request to the URL they are given. */
const HTTP_CLIENTS = new Set(["curl", "wget", "http", "https", "xh", "xhs"]);
/** Tools that fetch a URL the model chose, in `url`: Claude Code's
 *  `WebFetch`, OpenCode's `webfetch`, OpenClaw's and Copilot CLI's
 *  `web_fetch`; Gemini CLI's `web_fetch` takes its URLs in `prompt`. */
const FETCH_TOOLS = new Set(["WebFetch", "webfetch", "web_fetch"]);
/** Words before a command's program that are not the program. */
const WRAPPERS = new Set(["sudo", "env", "command", "exec", "time", "nohup", "nice", "timeout"]);

/** A command's program (its basename), past `VAR=…` assignments and the
 *  usual wrappers. */
function programOf(words: readonly string[]): string | undefined {
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w) || WRAPPERS.has(w) || (w.startsWith("-") && i > 0)) continue;
    if (/^\d+[smhd]?$/.test(w) && words[i - 1] === "timeout") continue;
    return w.replace(/^.*\//, "");
  }
  return undefined;
}

/** The `http://` and `https://` URLs in a text, as written, each with its
 *  host (lower case). */
export function httpUrlsIn(text: string): Array<{ url: string; host: string }> {
  const out: Array<{ url: string; host: string }> = [];
  for (const m of text.matchAll(/\bhttps?:\/\/[^\s"'`<>\\)]+/gi)) {
    try {
      const h = new URL(m[0]).hostname.toLowerCase().replace(/^\[|\]$/g, "");
      if (h !== "") out.push({ url: m[0], host: h });
    } catch { /* not a URL */ }
  }
  return out;
}

/** The hosts of the `http://` and `https://` URLs in a text, lower case. */
export function httpHostsIn(text: string): string[] {
  return [...new Set(httpUrlsIn(text).map((u) => u.host))];
}

/** One HTTP request a call made: the text that held what was sent (the
 *  pipeline, or the fetched URL), the hosts it named, and the program. */
export interface HttpRequest {
  text: string;
  hosts: string[];
  via: string;
}

/** The URL a web fetch call (`WebFetch`, `webfetch`, `web_fetch`) fetched,
 *  as the call holds it (Gemini CLI's `web_fetch` names its URLs in its
 *  `prompt`: those URLs, space-separated); undefined for any other call. Pure. */
export function fetchedUrlOf(call: { tool: string; input: unknown }): string | undefined {
  if (!FETCH_TOOLS.has(call.tool) || !isObj(call.input)) return undefined;
  const url = str(call.input["url"]);
  if (url !== undefined) return url;
  const urls = (str(call.input["prompt"]) ?? "").match(/\bhttps?:\/\/[^\s"'`<>\\)]+/gi);
  return urls !== null ? urls.join(" ") : undefined;
}

/**
 * The HTTP requests a call made: each pipeline of a shell call whose
 * program is an HTTP client (`curl`, `wget`, HTTPie, `xh`) and names a URL,
 * and a web fetch's URL. Only the pipeline that runs the client counts, so
 * a value printed by an earlier command, or written into a file by a
 * here-document, is not read as sent. Pure.
 */
export function httpRequestsOf(call: ToolCall): HttpRequest[] {
  if (FETCH_TOOLS.has(call.tool)) {
    const url = fetchedUrlOf(call);
    const hosts = url === undefined ? [] : httpHostsIn(url);
    return hosts.length === 0 ? [] : [{ text: url!, hosts, via: call.tool }];
  }
  const out: HttpRequest[] = [];
  for (const cmd of shellCommandsOf(call) ?? []) {
    for (const p of shellPipelines(cmd)) {
      const via = pipelineCommands(p).map(programOf).find((x) => x !== undefined && HTTP_CLIENTS.has(x));
      if (via === undefined) continue;
      // A here-document's body is left out; a quoted value over several lines is kept.
      const text = /<<-?\s*['"]?[A-Za-z_]/.test(p) ? p.split("\n")[0]! : p;
      const hosts = httpHostsIn(text);
      if (hosts.length > 0) out.push({ text, hosts, via });
    }
  }
  return out;
}

/** This computer, its private network, or a name kept for tests: a
 *  request there did not leave for the internet, and is not reported.
 *  `alias: true` (an ssh destination) keeps a name with no dot other than
 *  `localhost`: there it is usually a `Host` of `~/.ssh/config`, a remote
 *  machine under a short name, not this one. */
export function isLocalHost(host: string, opts: { alias?: boolean } = {}): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h.includes(".") && !h.includes(":")) return opts.alias !== true || h === "localhost" || h === "";
  if (/^(?:127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$)/.test(h) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (h === "::1" || /^f[cd][0-9a-f]{2}:/.test(h) || h.startsWith("fe80:")) return true;
  return /(?:^|\.)(?:localhost|local|test|example|invalid|internal|home\.arpa)$/.test(h) || /(?:^|\.)example\.(?:com|net|org)$/.test(h);
}

// ── The other ways a call sent a value on (plan 17 §3 item 11) ──────────────

/** How a send left: an HTTP client or a web fetch (item 11's first scope),
 *  a program that connects over ssh, git with a credential in its URL or
 *  header, an interpreter's inline script, or an MCP tool's input. */
export type SendChannel = "http" | "ssh" | "git" | "script" | "mcp";

/** One way a call sent something on: the text that held what was sent,
 *  where it went (`hosts`; an MCP tool's name for `mcp`), the program, and,
 *  when the text is a shell command's, the variables the shell expands
 *  there (`vars`: a `$NAME` in single quotes or a quoted here-document is
 *  not this computer's value), plus the names a script reads from its
 *  environment. `urls` are the URLs a send names (masked when shown). */
export interface OutboundSend {
  channel: SendChannel;
  text: string;
  hosts: string[];
  via: string;
  /** The variable names whose values went with it; absent: every `$NAME`
   *  in `text` (the HTTP rule). */
  vars?: string[];
  urls?: Array<{ url: string; host: string }>;
}

/** One command of a pipeline as the shell reads it. */
export interface ShellCommand {
  /** Its words, quotes removed (`$NAME` kept as written). */
  words: string[];
  /** Its own text, quotes kept, here-document bodies left out. */
  raw: string;
  /** The variables the shell expands in its words (not in single quotes). */
  vars: string[];
  /** The here-documents it reads (`<<EOF`), with whether the shell
   *  expands their `$NAME`s (an unquoted delimiter). A here-string
   *  (`<<<`) is a word. */
  heredocs: Array<{ body: string; expands: boolean }>;
}

const VAR_RE = /\$\{?([A-Za-z_][A-Za-z0-9_]*)/g;

/**
 * A pipeline's commands (split at an unquoted `|`), read over all its lines:
 * a quoted word may span lines, a here-document's body is attached to the
 * command that opened it. Rough like {@link shellPipelines}, but it tells
 * which `$NAME`s this computer's shell expands. Pure.
 */
export function parsePipeline(text: string): ShellCommand[] {
  const out: ShellCommand[] = [];
  let cur: ShellCommand = { words: [], raw: "", vars: [], heredocs: [] };
  let w = "";
  let inWord = false;
  let quote: string | null = null;
  const pending: Array<{ delim: string; expands: boolean; strip: boolean; cmd: ShellCommand }> = [];
  const endWord = (): void => { if (inWord) cur.words.push(w); w = ""; inWord = false; };
  const endCmd = (): void => { endWord(); if (cur.words.length > 0 || cur.heredocs.length > 0) out.push(cur); cur = { words: [], raw: "", vars: [], heredocs: [] }; };
  const addVars = (s: string, into: ShellCommand = cur): void => { for (const m of s.matchAll(VAR_RE)) if (!into.vars.includes(m[1]!)) into.vars.push(m[1]!); };
  /** The one `$NAME` at `i`, if one starts there. */
  const addVarAt = (i: number): void => { const m = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)/.exec(text.slice(i, i + 130)); if (m && !cur.vars.includes(m[1]!)) cur.vars.push(m[1]!); };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote === "'") {
      cur.raw += ch;
      if (ch === "'") quote = null;
      else w += ch;
      continue;
    }
    if (quote === '"') {
      cur.raw += ch;
      if (ch === '"') { quote = null; continue; }
      if (ch === "\\" && i + 1 < text.length && /[$`"\\\n]/.test(text[i + 1]!)) { w += text[++i]; cur.raw += text[i]; continue; }
      if (ch === "$") addVarAt(i);
      w += ch;
      continue;
    }
    if (ch === "\n") {
      endWord();
      cur.raw += " ";
      if (pending.length > 0) {
        // The bodies follow, one after the other, each to its delimiter line.
        let j = i + 1;
        for (const p of pending.splice(0)) {
          const body: string[] = [];
          while (j <= text.length) {
            const nl = text.indexOf("\n", j);
            const line = text.slice(j, nl < 0 ? text.length : nl);
            j = nl < 0 ? text.length + 1 : nl + 1;
            if ((p.strip ? line.replace(/^\t+/, "") : line) === p.delim) break;
            body.push(line);
          }
          p.cmd.heredocs.push({ body: body.join("\n"), expands: p.expands });
          if (p.expands) addVars(body.join("\n"), p.cmd);
        }
        i = j - 1;
      }
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; inWord = true; cur.raw += ch; continue; }
    if (ch === "\\" && i + 1 < text.length) { w += text[i + 1]; cur.raw += ch + text[i + 1]; i++; inWord = true; continue; }
    if (ch === "$" && text[i + 1] === "(") {
      // A command substitution, kept whole as part of the word.
      let depth = 0;
      let j = i;
      for (; j < text.length; j++) {
        if (text[j] === "(") depth++;
        else if (text[j] === ")" && --depth === 0) break;
      }
      const sub = text.slice(i, j + 1);
      addVars(sub);
      w += sub;
      cur.raw += sub;
      inWord = true;
      i = j;
      continue;
    }
    if (ch === "$") addVarAt(i);
    if (ch === "<" && text[i + 1] === "<" && text[i + 2] !== "<" && text[i - 1] !== "<") {
      const m = /^<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/.exec(text.slice(i));
      if (m) {
        endWord();
        pending.push({ delim: m[3]!, expands: m[2] === "", strip: m[1] === "-", cmd: cur });
        cur.raw += m[0];
        i += m[0].length - 1;
        continue;
      }
    }
    if (ch === "|" && text[i + 1] !== "|") { cur.raw = cur.raw.trim(); endCmd(); continue; }
    cur.raw += ch;
    if (/\s/.test(ch)) { endWord(); continue; }
    if (ch === "#" && !inWord) {
      // A comment runs to the end of the line.
      const nl = text.indexOf("\n", i);
      cur.raw = cur.raw.slice(0, -1);
      i = (nl < 0 ? text.length : nl) - 1;
      continue;
    }
    w += ch;
    inWord = true;
  }
  cur.raw = cur.raw.trim();
  endCmd();
  return out;
}

/** The words of a command past its `VAR=…` assignments and the usual
 *  wrappers, from its program on. */
function fromProgram(words: readonly string[]): string[] {
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w) || WRAPPERS.has(w) || (w.startsWith("-") && i > 0)) continue;
    if (/^\d+[smhd]?$/.test(w) && words[i - 1] === "timeout") continue;
    return words.slice(i);
  }
  return [];
}

const baseName = (w: string | undefined): string => (w ?? "").replace(/^.*\//, "");

/** A host as an ssh destination names it (`user@host`, `[::1]`), lower
 *  case; undefined for a word that is no host. */
function sshHost(spec: string): string | undefined {
  const m = /^(?:ssh:\/\/|sftp:\/\/|scp:\/\/|rsync:\/\/)?(?:[^@\s/]+@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._-]*)(?::\d+)?\/?$/.exec(spec);
  if (m === null) return undefined;
  const h = m[1]!.replace(/^\[|\]$/g, "").toLowerCase();
  return h.length > 253 ? undefined : h;
}

/** ssh's and sftp's options that take a value (OpenSSH 9). */
const SSH_ARG_OPTS = new Set("BbcDEeFIiJLlmOoPpQRSWw".split(""));
const SFTP_ARG_OPTS = new Set("BbcDFiJloPRSsX".split(""));
const SCP_ARG_OPTS = new Set("cDFiJloPSX".split(""));

/** The destination of `ssh` / `sftp`: the first word that is not an
 *  option or an option's value. */
function sshDestination(args: readonly string[], argOpts: ReadonlySet<string>): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") return args[i + 1] !== undefined ? sshHost(args[i + 1]!) : undefined;
    if (a.startsWith("-") && a.length > 1) {
      const letters = a.slice(1);
      for (let j = 0; j < letters.length; j++) {
        if (argOpts.has(letters[j]!)) { if (j === letters.length - 1) i++; break; }
      }
      continue;
    }
    return sshHost(a);
  }
  return undefined;
}

/** The remote hosts of `scp` / `rsync` words: `host:path`, `user@host:path`,
 *  `host::module`, `scp://…`, `rsync://…`. A word with a `/` before its
 *  colon is a local path; a one-letter host is a drive. */
function remoteSpecHosts(args: readonly string[], argOpts: ReadonlySet<string>): string[] {
  const hosts: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("-")) {
      if (/^-[A-Za-z]+$/.test(a) && argOpts.has(a[a.length - 1]!)) i++;
      continue;
    }
    const url = /^(?:scp|rsync|sftp|ssh):\/\/([^/\s]+)/.exec(a);
    const spec = url !== null ? url[1]! : /^([^/:\s]*@)?([^/:\s]+):(?!\/\/)/.exec(a)?.[0]?.replace(/:+$/, "");
    if (spec === undefined) continue;
    const h = sshHost(spec);
    if (h !== undefined && h.length > 1 && !hosts.includes(h)) hosts.push(h);
  }
  return hosts;
}

/** The programs that connect over ssh, with the host(s) each names. */
function sshHostsOf(prog: string, args: readonly string[]): string[] {
  switch (prog) {
    case "ssh": { const h = sshDestination(args, SSH_ARG_OPTS); return h === undefined ? [] : [h]; }
    case "sftp": { const h = sshDestination(args, SFTP_ARG_OPTS); return h === undefined ? [] : [h]; }
    case "scp": return remoteSpecHosts(args, SCP_ARG_OPTS);
    case "rsync": return remoteSpecHosts(args, new Set(["e", "f", "T"]));
    default: return [];
  }
}

const SSH_PROGRAMS = new Set(["ssh", "scp", "sftp", "rsync"]);

/** What a pipeline gave a program it feeds: the commands up to and
 *  including it (their words and, for those before it, their output), and
 *  every here-document among them. A command after it gets the program's
 *  output, not this computer's input, and is left out. */
function fedTo(cmds: readonly ShellCommand[], upTo: number): { text: string; vars: string[] } {
  const parts: string[] = [];
  const vars: string[] = [];
  for (const c of cmds.slice(0, upTo + 1)) {
    parts.push(c.raw);
    for (const v of c.vars) if (!vars.includes(v)) vars.push(v);
    for (const h of c.heredocs) parts.push(h.body);
  }
  return { text: parts.join("\n"), vars };
}

/** git's options before its command that take a value. */
const GIT_ARG_OPTS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env", "--super-prefix"]);
/** git's commands that connect to a remote, and `remote add` / `set-url`,
 *  which keep the URL (credential and all) for every later fetch and push. */
const GIT_SENDING = new Set(["push", "clone", "fetch", "pull", "ls-remote"]);

/** A Basic credential's decoded `user:password`, to look for values in
 *  (never shown); empty when it is not base64. */
function decodedBasic(text: string): string {
  const out: string[] = [];
  for (const m of text.matchAll(/\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})/gi)) {
    const d = Buffer.from(m[1]!, "base64").toString("utf8");
    if (/^[\x20-\x7e]+$/.test(d)) out.push(d);
  }
  return out.join("\n");
}

/**
 * A git command's credentials and where they went: each `http(s)://` URL
 * with a user part (`https://x-access-token:…@github.com/…`, a token as the
 * user) sends that part to the URL's host; an `http.extraheader` given with
 * `-c` (`AUTHORIZATION: bearer …`, `basic <base64>`, decoded to look in)
 * goes to every `http(s)` URL the command names, or the one its key names
 * (`http.https://host/.extraheader`). Only `push`, `clone`, `fetch`,
 * `pull`, `ls-remote`, and `remote add` / `set-url` (which keep the URL for
 * every later fetch and push). A command with no URL (`git push origin`)
 * names no host, so its header is not reported. Pure.
 */
function gitSends(cmd: ShellCommand): OutboundSend[] {
  const words = fromProgram(cmd.words);
  if (baseName(words[0]) !== "git") return [];
  const headers: Array<{ value: string; url?: string }> = [];
  let i = 1;
  for (; i < words.length; i++) {
    const w = words[i]!;
    if (w === "-c" && words[i + 1] !== undefined) {
      const kv = words[++i]!;
      const m = /^http\.(?:(https?:\/\/.+?)\.)?extraheader=(.*)$/is.exec(kv);
      if (m) headers.push({ value: m[2]!, ...(m[1] !== undefined ? { url: m[1] } : {}) });
      continue;
    }
    if (GIT_ARG_OPTS.has(w)) { i++; continue; }
    if (w.startsWith("-")) continue;
    break;
  }
  const sub = words[i];
  const rest = words.slice(i + 1);
  if (sub === undefined) return [];
  const sending = GIT_SENDING.has(sub) || (sub === "remote" && (rest[0] === "add" || rest[0] === "set-url"));
  if (!sending) return [];
  const via = sub === "remote" ? "git remote" : `git ${sub}`;
  const urls = rest.filter((w) => /^https?:\/\//i.test(w)).flatMap((w) => httpUrlsIn(w).slice(0, 1));
  const out: OutboundSend[] = [];
  for (const u of urls) {
    const user = /^https?:\/\/([^/?#\s]*)@/i.exec(u.url)?.[1];
    if (user === undefined || user === "") continue;
    out.push({ channel: "git", text: `${user}\n${u.url}`, hosts: [u.host], via, vars: cmd.vars.filter((v) => user.includes(`$${v}`) || user.includes(`\${${v}`)), urls: [u] });
  }
  for (const h of headers) {
    const at = h.url !== undefined ? httpUrlsIn(h.url) : urls;
    const hosts = [...new Set(at.map((u) => u.host))];
    if (hosts.length === 0) continue;
    const decoded = decodedBasic(h.value);
    out.push({ channel: "git", text: decoded === "" ? h.value : `${h.value}\n${decoded}`, hosts, via, vars: cmd.vars.filter((v) => h.value.includes(`$${v}`) || h.value.includes(`\${${v}`)), urls: at });
  }
  return out;
}

/** The interpreters whose inline scripts are read, and the option that
 *  takes the script on the command line. */
function inlineScriptOf(words: readonly string[]): { via: string; code?: string; stdin: boolean } | undefined {
  const prog = baseName(words[0]);
  const args = words.slice(1);
  const optCode = (opts: readonly string[]): string | undefined => {
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      if (opts.includes(a)) return args[i + 1];
      const glued = opts.find((o) => o.length === 2 && a.startsWith(o) && a.length > 2 && !a.startsWith("--"));
      if (glued !== undefined) return a.slice(2);
    }
    return undefined;
  };
  // No script file named: the script comes on stdin (`python3 - <<EOF`).
  const noFile = (): boolean => args.every((a) => a.startsWith("-") || a === "-") ;
  if (/^(?:python(?:\d+(?:\.\d+)?)?|pypy3?)$/.test(prog)) {
    const code = optCode(["-c"]);
    return code !== undefined ? { via: prog, code, stdin: false } : noFile() ? { via: prog, stdin: true } : undefined;
  }
  if (prog === "node" || prog === "nodejs" || prog === "bun") {
    const code = optCode(["-e", "--eval", "-p", "--print"]);
    return code !== undefined ? { via: prog, code, stdin: false } : noFile() ? { via: prog, stdin: true } : undefined;
  }
  if (prog === "deno") {
    const e = args.indexOf("eval");
    return e >= 0 && args[e + 1] !== undefined ? { via: prog, code: args.slice(e + 1).find((a) => !a.startsWith("-")) ?? "", stdin: false } : undefined;
  }
  if (prog === "ruby" || prog === "perl") {
    const code = optCode(["-e", "-E"]);
    return code !== undefined ? { via: prog, code, stdin: false } : noFile() ? { via: prog, stdin: true } : undefined;
  }
  return undefined;
}

/** A call that makes an HTTP request, in the libraries an inline script
 *  uses: Python's `requests`, `urllib`, `http.client`, `httpx`, `aiohttp`;
 *  JavaScript's `fetch`, `axios`, `http(s).request`/`get`, `got`,
 *  `undici`; Ruby's `Net::HTTP`, `URI.open`, `HTTParty`, `Faraday`;
 *  Perl's `LWP`, `HTTP::Tiny`. */
const HTTP_CALL_RE = /\brequests\.(?:get|post|put|patch|delete|head|request|Session)\b|\burlopen\s*\(|\burllib3?\.(?:request\.)?(?:Request|PoolManager|urlopen)\b|\bHTTPS?Connection\s*\(|\bhttpx\.(?:get|post|put|patch|delete|request|Client|AsyncClient)\b|\baiohttp\.ClientSession\b|(?<![.\w])fetch\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|request|create))?\s*\(|\bhttps?\.(?:request|get)\s*\(|\bgot(?:\.(?:get|post|put|patch|delete))?\s*\(|\bundici\b|\bNet::HTTP\b|\bURI\.open\b|\bHTTParty\b|\bFaraday\b|\bLWP::|\bHTTP::Tiny\b/;

/** The environment variables a script reads by name: Python's
 *  `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")`;
 *  JavaScript's `process.env.X`, `process.env["X"]`, `Deno.env.get("X")`,
 *  `Bun.env.X`; Ruby's `ENV["X"]`, `ENV.fetch("X")`; Perl's `$ENV{X}`. */
const ENV_READ_RE = /\b(?:os\.environ(?:\.get)?\s*[[(]\s*|os\.getenv\s*\(\s*|getenv\s*\(\s*|ENV(?:\.fetch\s*\(\s*|\s*\[\s*)|Deno\.env\.get\s*\(\s*|process\.env\s*\[\s*|Bun\.env\s*\[\s*)["']([A-Za-z_][A-Za-z0-9_]*)["']|\b(?:process|Bun)\.env\.([A-Za-z_][A-Za-z0-9_]*)|\$ENV\{\s*["']?([A-Za-z_][A-Za-z0-9_]*)/g;

/** The names a script reads from its environment. Pure. */
export function scriptEnvReads(code: string): string[] {
  const out: string[] = [];
  for (const m of code.matchAll(ENV_READ_RE)) {
    const n = m[1] ?? m[2] ?? m[3];
    if (n !== undefined && !out.includes(n)) out.push(n);
  }
  return out;
}

/**
 * A pipeline's inline script that makes an HTTP request: `python3 -c`,
 * `node -e`, `deno eval`, `ruby -e`, `perl -e`, or a here-document fed to
 * an interpreter that names no script file (`python3 - <<EOF`, `cat <<EOF
 * | node`). Only when the script calls an HTTP library (requests, urllib,
 * http.client, fetch, …) AND names a literal `http(s)://` URL: those URLs'
 * hosts are where it went. What it sent is what the script holds: a value
 * written into it, a `$NAME` the shell expands into it, or a variable it
 * reads from its environment by name. A script run from a file is not in
 * the record, and a URL a script builds is not read. Pure.
 */
function scriptSends(cmds: readonly ShellCommand[]): OutboundSend[] {
  const out: OutboundSend[] = [];
  cmds.forEach((c, k) => {
    const words = fromProgram(c.words);
    const s = inlineScriptOf(words);
    if (s === undefined) return;
    const fed = s.stdin ? cmds.slice(0, k + 1).flatMap((x) => x.heredocs) : [];
    const code = s.code ?? fed.map((h) => h.body).join("\n");
    if (code === "" || !HTTP_CALL_RE.test(code)) return;
    const urls = httpUrlsIn(code);
    const hosts = [...new Set(urls.map((u) => u.host))];
    if (hosts.length === 0) return;
    // The shell's `$NAME` in the script: on the command line where it is not
    // single-quoted, in a here-document whose delimiter is not quoted.
    const shellVars = s.code !== undefined
      ? c.vars.filter((v) => s.code!.includes(`$${v}`) || s.code!.includes(`\${${v}`))
      : fed.filter((h) => h.expands).flatMap((h) => [...h.body.matchAll(VAR_RE)].map((m) => m[1]!));
    const vars = [...new Set([...shellVars, ...scriptEnvReads(code)])];
    out.push({ channel: "script", text: code, hosts, via: s.via, vars, urls });
  });
  return out;
}

/** An MCP tool, by the name Claude Code and Codex give it:
 *  `mcp__<server>__<tool>`. */
export const MCP_TOOL_RE = /^mcp__[A-Za-z0-9_.-]+?__[A-Za-z0-9_.-]+$/;

/** Every string in an MCP call's input, joined: what the tool was given. */
function inputStrings(v: unknown, out: string[], budget: { left: number }): void {
  if (budget.left <= 0) return;
  if (typeof v === "string") { out.push(v); budget.left -= v.length; return; }
  if (Array.isArray(v)) { for (const x of v) inputStrings(x, out, budget); return; }
  if (isObj(v)) for (const x of Object.values(v)) inputStrings(x, out, budget);
}

/**
 * Every way a call sent something on (plan 17 §3 item 11): its HTTP
 * requests ({@link httpRequestsOf}); in a shell call, each pipeline that
 * runs `ssh`, `scp`, `sftp` or `rsync` to a host (what the pipeline fed it:
 * its words, the commands before it, their here-documents), `git` with a
 * credential in a URL or an `http.extraheader`, and an inline script that
 * makes an HTTP request to a literal URL; and an MCP tool's input (the tool
 * is where it went: its server, wherever that runs). Pure.
 */
export function sendsOf(call: ToolCall): OutboundSend[] {
  const out: OutboundSend[] = httpRequestsOf(call).map((r) => ({ channel: "http", text: r.text, hosts: r.hosts, via: r.via }));
  if (MCP_TOOL_RE.test(call.tool)) {
    let input = call.input;
    if (typeof input === "string" && input.trim().startsWith("{")) { try { input = JSON.parse(input) as unknown; } catch { /* the string itself */ } }
    const parts: string[] = [];
    inputStrings(input, parts, { left: 1 << 20 });
    // The tool is shown as its destination: an identifier only (`shownToolName`).
    const shown = shownToolName(call.tool) ?? "mcp__…";
    if (parts.length > 0) out.push({ channel: "mcp", text: parts.join("\n"), hosts: [shown], via: "MCP", vars: [] });
    return out;
  }
  for (const cmd of shellCommandsOf(call) ?? []) {
    for (const p of shellPipelines(cmd)) {
      const cmds = parsePipeline(p);
      cmds.forEach((c, k) => {
        const words = fromProgram(c.words);
        const prog = baseName(words[0]);
        if (!SSH_PROGRAMS.has(prog)) return;
        const hosts = sshHostsOf(prog, words.slice(1));
        if (hosts.length === 0) return;
        const fed = fedTo(cmds, k);
        out.push({ channel: "ssh", text: fed.text, hosts, via: prog, vars: fed.vars });
      });
      for (const c of cmds) out.push(...gitSends(c));
      out.push(...scriptSends(cmds));
    }
  }
  return out;
}
