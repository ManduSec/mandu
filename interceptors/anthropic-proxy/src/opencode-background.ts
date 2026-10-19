/**
 * opencode-background — OpenCode 2's background-completion notices, read as
 * the TOOL OUTPUT they are (supported-agents.md §2.3 item 6).
 *
 * Mandu-new. On OpenCode 2 (npm `@opencode/cli`, probed on 2.0.23) a shell or
 * subagent that runs in the background (`background: true`, which the gate
 * surface refuses, OR one the USER moves there: the TUI's ctrl+b "Background
 * blocking tools", the server's `POST /api/session/:id/background`) returns
 * its output LATER, as a user message of its own:
 *
 *   <shell id="sh_…" state="completed" command="<the command>">
 *   <output>
 *   </shell>
 *
 *   <subagent sessionID="ses_…" state="completed" description="<description>">
 *   <the child's answer>
 *   </subagent>
 *
 * The call's own tool_result only said "Command moved to the background
 * (shell ID: sh_…)" / "The subagent is working in the background (sessionID:
 * ses_…)". So the output reached the model as USER TEXT, which no tool_result
 * leg reads (callTaint, the value backstop, the inbound spec, the path label):
 * a moved `cat .env` reached the model in clear (probed). OpenCode re-sends the
 * same text in every later request (history), byte for byte.
 *
 * What this module does (pure; rewrite-request.ts applies it):
 *   - `extractBackgroundNotices`: every user text that starts like a notice
 *     becomes, for the length of the rewrite, a tool_result block with a
 *     stable id (`mandu-bg:<the notice id>`). A notice that PARSES is tied to
 *     the call that started the work (the one tool_result that names its id),
 *     whose tool name and input the rewrite then classifies it under, with
 *     callTaint asked under that call's id. Its body is everything between
 *     the header and the closing tag.
 *   - Anything that starts like a notice and does not parse (no or several
 *     candidate calls, a header that is not exactly the call's command or
 *     description, a missing closing tag) is masked WHOLE (the rewrite mints
 *     one secret symbol for the whole text). Over-masking, never under.
 *   - `restoreBackgroundNotices`: the rewritten body goes back into its text
 *     block between the original header and closing tag, so the request keeps
 *     OpenCode's shape, the same block object (cache_control and all) and the
 *     same position (the OpenAI-wire shadow writes user texts back by
 *     position).
 *
 * OpenCode escapes nothing in the notice (a command's quotes and a `</shell>`
 * in the output appear as they are; probed), so the header is never parsed
 * for its attributes: it is REBUILT from the correlated call and compared
 * whole, and the body runs to the LAST closing tag.
 *
 * THE USER'S OWN SHELL (2026-10-05; the server's `POST /api/session/:id/
 * shell`, which the TUI's `!cmd` calls). Its output reaches the next request
 * as a user text of its own:
 *
 *   The following shell command was executed by the user:
 *   <shell id="sh_…" state="completed" command="<the command>">
 *   <output>
 *   </shell>
 *
 * The same notice behind a fixed line (probed on 2.0.23, unescaped too). It
 * is PROGRAM OUTPUT, not the human's typed text, so it is read as a shell
 * result too (the classify verdict's path-derived label on the command, the
 * value backstop, callTaint by the command's exec signature, the inbound
 * spec), under a stand-in call `{command}` of the session's shell tool. No
 * model call started it, so the command is read off the header: up to the
 * FIRST `">` + newline (a command holding that sequence is cut early, and the
 * rest is read as output, never forwarded raw for being "the command"). A
 * notice in this shape that does not parse is masked whole.
 *
 * CLAUDE CODE'S BASH MODE (2026-10-05; the human types `!cmd` in the TUI).
 * Claude Code runs the command with its own Bash tool and, unless told not to
 * (`respondToBashCommands`), sends the next request with two text blocks of
 * the user message (captured on 2.1.289 against a scripted upstream):
 *
 *   <bash-input>{the command, unescaped}</bash-input>\n
 *   <bash-stdout>{stdout, & < > escaped}</bash-stdout><bash-stderr>{stderr, escaped}</bash-stderr>
 *
 * (a failure: `<bash-stderr>Command failed: …</bash-stderr>` alone; a large
 * output: a raw `<persisted-output>` preview inside `<bash-stdout>`), re-sent
 * unchanged in every later request. The output is PROGRAM OUTPUT, not the
 * human's typed text: it is read as a `Bash` result of the command in the
 * `<bash-input>` block right before it (the classify verdict's path label,
 * callTaint by the command's exec signature, the value backstop, the inbound
 * spec), on the UNESCAPED text, and goes back escaped as Claude Code wrote it;
 * an output block forwarded unchanged goes back byte for byte. An output
 * block with no command before it, a persisted-output preview, or escaping
 * that does not round-trip is masked whole. The `<bash-input>` block (the
 * human's own command) stays the prompt filter's, as before.
 *
 * THE BACKGROUND OUTPUT FILE (§2.3 item 7). The call's "moved" result names
 * the file the output streams to (`movedOutputPath`); the rewrite registers
 * it as a session label (`sessionPathLabel`, `no-model`) before forwarding.
 */

import { createHash } from "node:crypto";
import type { ContentBlock, Message, ToolResultBlock } from "./messages-types.js";
import { isToolResultBlock } from "./messages-types.js";

export type NoticeKind = "shell" | "subagent" | "usershell" | "bashmode";

/** A notice the rewrite reads as the tool result of `callId`. */
export interface ParsedNotice {
  kind: NoticeKind;
  /** The tool_use id of the call that started the work (for the user's own
   *  shell, the stand-in's own id, filled in by `extractBackgroundNotices`). */
  callId: string;
  /** Text before the header (the user shell's fixed line), else "". */
  prefix: string;
  header: string;
  close: string;
  /** The user's shell: the stand-in call the result is read under. */
  stand?: { name: string; input: Record<string, unknown> };
  /** Bash mode: the stand-in's body (the unescaped output) and how its
   *  rewrite goes back into the text block (in place of prefix/header/close). */
  body?: string;
  render?: (rewritten: string) => string;
}

/** A notice the rewrite masks whole. */
export interface UnparsedNotice {
  kind: NoticeKind;
  unparsed: true;
  why: string;
}

export type BackgroundNotice = ParsedNotice | UnparsedNotice;

/** Where the extracted notices were, to put them back. */
export interface ExtractedNotices {
  /** virtual tool_use_id → notice */
  notices: Map<string, BackgroundNotice>;
  restore: Array<{ msg: Message; index: number; vid: string; wasString: boolean; block: ContentBlock }>;
}

/** The fixed line before the user shell's notice (2.0.23). */
export const USER_SHELL_LINE = "The following shell command was executed by the user:\n";

const NOTICE_START: ReadonlyArray<{ kind: NoticeKind; re: RegExp }> = [
  { kind: "bashmode", re: /^<bash-std(?:out|err)>/ },
  { kind: "usershell", re: /^The following shell command was executed by the user:/ },
  { kind: "shell", re: /^<shell id="/ },
  { kind: "subagent", re: /^<subagent sessionID="/ },
];
const SHELL_ID_RE = /^<shell id="(sh_[A-Za-z0-9]{1,64})" state="([a-z_-]{1,24})" command="/;
const SUB_ID_RE = /^<subagent sessionID="(ses_[A-Za-z0-9]{1,64})" state="([a-z_-]{1,24})" description="/;

/** Does this user text start like a background notice (and of which kind)? */
export function noticeKind(text: string): NoticeKind | null {
  for (const s of NOTICE_START) if (s.re.test(text)) return s.kind;
  return null;
}

/** The text of a tool_result's content, as the rewrite flattens it. */
function resultText(tr: ToolResultBlock): string {
  const c = tr.content;
  if (c == null) return "";
  if (typeof c === "string") return c;
  return c.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text as string).join("\n");
}

/** The opening line of the call's own tool_result, by kind (2.0.23). */
function movedPrefix(kind: NoticeKind, id: string): string {
  return kind === "shell"
    ? `Command moved to the background (shell ID: ${id}).`
    : `The subagent is working in the background (sessionID: ${id}).`;
}

/**
 * Read one notice text against the request's messages and calls. Pure.
 * `shellTools` names the session's shell tools and their command field
 * (GateSurface.exec): a shell notice must belong to one of them.
 */
export function parseBackgroundNotice(
  text: string,
  messages: readonly Message[],
  correlation: ReadonlyMap<string, { name: string; input: Record<string, unknown> }>,
  shellTools: Readonly<Record<string, string>>,
): BackgroundNotice | null {
  const kind = noticeKind(text);
  if (kind === null) return null;
  if (kind === "usershell") return parseUserShellNotice(text, shellTools);
  const head = (kind === "shell" ? SHELL_ID_RE : SUB_ID_RE).exec(text);
  if (!head) return { kind, unparsed: true, why: "the notice's id or state is not in the known form" };
  const [, id, state] = head as unknown as [string, string, string];
  const prefix = movedPrefix(kind, id);
  const owners: string[] = [];
  for (const msg of messages) {
    if (msg.role !== "user" || !Array.isArray(msg.content)) continue;
    for (const b of msg.content) {
      if (isToolResultBlock(b) && resultText(b as ToolResultBlock).startsWith(prefix)) owners.push((b as ToolResultBlock).tool_use_id);
    }
  }
  if (owners.length !== 1) {
    return { kind, unparsed: true, why: owners.length === 0 ? "no call in the conversation started this work" : "more than one call claims this work" };
  }
  const callId = owners[0]!;
  const ref = correlation.get(callId);
  if (!ref) return { kind, unparsed: true, why: "the call that started this work is not in the conversation" };
  let header: string;
  let close: string;
  if (kind === "shell") {
    const field = Object.prototype.hasOwnProperty.call(shellTools, ref.name) ? shellTools[ref.name]! : null;
    const command = field !== null ? ref.input[field] : undefined;
    if (typeof command !== "string") return { kind, unparsed: true, why: "the call that started this work is not a shell command" };
    header = `<shell id="${id}" state="${state}" command="${command}">`;
    close = "</shell>";
  } else {
    const description = ref.input["description"];
    if (ref.name !== "subagent" || typeof description !== "string") return { kind, unparsed: true, why: "the call that started this work is not a subagent" };
    header = `<subagent sessionID="${id}" state="${state}" description="${description}">`;
    close = "</subagent>";
  }
  if (!text.startsWith(`${header}\n`)) return { kind, unparsed: true, why: "the notice's header is not the call's own" };
  if (!text.endsWith(`\n${close}`) || text.length < header.length + close.length + 2) {
    return { kind, unparsed: true, why: "the notice does not end with its closing tag" };
  }
  return { kind, callId, prefix: "", header, close };
}

/** The user's own shell notice (module header). Pure. */
export function parseUserShellNotice(text: string, shellTools: Readonly<Record<string, string>>): BackgroundNotice {
  const kind = "usershell" as const;
  if (!text.startsWith(USER_SHELL_LINE)) return { kind, unparsed: true, why: "the user shell notice is not in the known form" };
  const rest = text.slice(USER_SHELL_LINE.length);
  const head = SHELL_ID_RE.exec(rest);
  if (!head) return { kind, unparsed: true, why: "the user shell notice's id or state is not in the known form" };
  const end = rest.indexOf('">\n', head[0].length);
  if (end < 0) return { kind, unparsed: true, why: "the user shell notice's header does not end" };
  const close = "</shell>";
  if (!rest.endsWith(`\n${close}`) || rest.length < end + 3 + close.length) return { kind, unparsed: true, why: "the user shell notice does not end with its closing tag" };
  const command = rest.slice(head[0].length, end);
  const name = Object.prototype.hasOwnProperty.call(shellTools, "shell") ? "shell" : Object.keys(shellTools)[0];
  if (name === undefined) return { kind, unparsed: true, why: "the session has no shell tool to read the output under" };
  return { kind, callId: "", prefix: USER_SHELL_LINE, header: rest.slice(0, end + 2), close, stand: { name, input: { [shellTools[name]!]: command } } };
}

/** The body of a parsed notice (between the header line and the closing tag). */
export function noticeBody(text: string, n: ParsedNotice): string {
  if (n.body !== undefined) return n.body;
  return text.slice(n.prefix.length + n.header.length + 1, text.length - n.close.length - 1);
}

/** Claude Code's escaping of bash-mode output (2.1.289: `&`, `<`, `>`). */
export function escapeBashOutput(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function unescapeBashOutput(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

/**
 * Claude Code's bash-mode output block (module header), read against the
 * text block right before it (its `<bash-input>` command). Pure.
 */
export function parseBashModeOutput(text: string, prev: string | null, shellTools: Readonly<Record<string, string>>): BackgroundNotice {
  const kind = "bashmode" as const;
  const input = prev === null ? null : /^<bash-input>([\s\S]*)<\/bash-input>\n?$/.exec(prev);
  if (!input) return { kind, unparsed: true, why: "no <bash-input> command right before the output" };
  const command = input[1]!;
  const both = /^<bash-stdout>([\s\S]*?)<\/bash-stdout><bash-stderr>([\s\S]*)<\/bash-stderr>$/.exec(text);
  const errOnly = both ? null : /^<bash-stderr>([\s\S]*)<\/bash-stderr>$/.exec(text);
  if (!both && !errOnly) return { kind, unparsed: true, why: "the output is not in the known form" };
  const rawOut = both ? both[1]! : "";
  const rawErr = both ? both[2]! : errOnly![1]!;
  if (rawOut.startsWith("<persisted-output>")) return { kind, unparsed: true, why: "a persisted-output preview (raw, not escaped)" };
  const out = unescapeBashOutput(rawOut);
  const err = unescapeBashOutput(rawErr);
  if (escapeBashOutput(out) !== rawOut || escapeBashOutput(err) !== rawErr) return { kind, unparsed: true, why: "the output's escaping does not round-trip" };
  const name = Object.prototype.hasOwnProperty.call(shellTools, "Bash") ? "Bash" : Object.keys(shellTools)[0];
  if (name === undefined) return { kind, unparsed: true, why: "the session has no shell tool to read the output under" };
  const body = err === "" ? out : out === "" ? err : `${out}\n${err}`;
  return {
    kind, callId: "", prefix: "", header: "", close: "", stand: { name, input: { [shellTools[name]!]: command } }, body,
    // unchanged: the very bytes Claude Code sent (cache-stable); rewritten:
    // escaped as Claude Code escapes, in the stdout tag
    render: (rewritten) => (rewritten === body ? text : `<bash-stdout>${escapeBashOutput(rewritten)}</bash-stdout><bash-stderr></bash-stderr>`),
  };
}

/**
 * The file a moved shell's output streams to, as its "moved" result names it
 * (2.0.23: `Command moved to the background (shell ID: sh_…).\nOutput is
 * streaming to: <path>`). `{path}`: the absolute path named; `{bad}`: the
 * result opens like one and names no absolute path (the caller masks it);
 * null: not a moved shell's result. Pure.
 */
export function movedOutputPath(text: string): { path: string } | { bad: string } | null {
  const m = /^Command moved to the background \(shell ID: (sh_[A-Za-z0-9]{1,64})\)\.\n/.exec(text);
  if (!m) return null;
  const line = /^Output is streaming to: ([^\n]*)$/m.exec(text.slice(m[0].length));
  if (!line) return { bad: "the moved result names no output file" };
  const p = line[1]!.trim();
  if (!p.startsWith("/") || p.split("/").includes("..")) return { bad: "the moved result's output file is not an absolute path" };
  return { path: p };
}

/** The id the rewrite gives a notice's stand-in tool_result: stable across
 *  turns (the notice's own id), never a real tool_use id. */
export function virtualNoticeId(text: string, kind: NoticeKind): string {
  // bash mode names no id: the output block's own hash (a repeat gets `#2`)
  if (kind === "bashmode") return `mandu-bg:bashmode:${createHash("sha256").update(text).digest("hex").slice(0, 16)}`;
  const t = kind === "usershell" && text.startsWith(USER_SHELL_LINE) ? text.slice(USER_SHELL_LINE.length) : text;
  const m = (kind === "subagent" ? /^<subagent sessionID="([^"]{1,80})"/ : /^<shell id="([^"]{1,80})"/).exec(t);
  return `mandu-bg:${kind}:${m ? m[1] : "unparsed"}`;
}

/**
 * Swap every notice in a user message for a stand-in tool_result (mutates
 * `messages`; the caller holds a clone). A text block keeps its object for
 * the restore. Two notices with one id (a repeat) get distinct stand-ins.
 */
export function extractBackgroundNotices(
  messages: Message[],
  correlation: Map<string, { name: string; input: Record<string, unknown> }>,
  shellTools: Readonly<Record<string, string>>,
  /** The kinds this session's agent sends (all of them by default). */
  kinds: ReadonlySet<NoticeKind> = ALL_NOTICE_KINDS,
): ExtractedNotices {
  const notices = new Map<string, BackgroundNotice>();
  const restore: ExtractedNotices["restore"] = [];
  const snapshot = messages.slice();
  for (const msg of messages) {
    if (msg.role !== "user") continue;
    const wasString = typeof msg.content === "string";
    const blocks: ContentBlock[] = typeof msg.content === "string" ? [{ type: "text", text: msg.content }] : Array.isArray(msg.content) ? msg.content : [];
    let changed = false;
    for (let i = 0; i < blocks.length; i++) {
      const b = blocks[i]!;
      if (b.type !== "text" || typeof (b as { text?: unknown }).text !== "string") continue;
      const text = (b as { text: string }).text;
      const kind = noticeKind(text);
      if (kind === null || !kinds.has(kind)) continue;
      const prev = i > 0 && blocks[i - 1]!.type === "text" && typeof (blocks[i - 1] as { text?: unknown }).text === "string" ? (blocks[i - 1] as { text: string }).text : null;
      const parsed = kind === "bashmode" ? parseBashModeOutput(text, prev, shellTools) : parseBackgroundNotice(text, snapshot, correlation, shellTools)!;
      let vid = virtualNoticeId(text, kind);
      for (let k = 2; notices.has(vid); k++) vid = `${virtualNoticeId(text, kind)}#${k}`;
      notices.set(vid, parsed);
      const body = "unparsed" in parsed ? text : noticeBody(text, parsed);
      if (!("unparsed" in parsed)) {
        if (parsed.stand) {
          // the user's own shell: no model call; read under a stand-in call
          parsed.callId = vid;
          correlation.set(vid, parsed.stand);
        } else {
          correlation.set(vid, correlation.get(parsed.callId)!);
        }
      }
      blocks[i] = { type: "tool_result", tool_use_id: vid, content: body } as ToolResultBlock;
      restore.push({ msg, index: i, vid, wasString, block: b });
      changed = true;
    }
    if (changed && wasString) msg.content = blocks;
  }
  return { notices, restore };
}

/** Put each notice back as text: the rewritten body between the header and
 *  the closing tag (a masked-whole notice: the rewritten text alone). */
export function restoreBackgroundNotices(x: ExtractedNotices): void {
  for (const r of x.restore) {
    const blocks = r.msg.content as ContentBlock[];
    const stand = blocks[r.index] as ToolResultBlock;
    const n = x.notices.get(r.vid)!;
    const rewritten = resultText(stand);
    const text = "unparsed" in n ? rewritten : n.render ? n.render(rewritten) : `${n.prefix}${n.header}\n${rewritten}\n${n.close}`;
    blocks[r.index] = { ...r.block, text };
  }
  for (const r of x.restore) {
    if (r.wasString && Array.isArray(r.msg.content) && r.msg.content.length === 1) {
      r.msg.content = (r.msg.content[0] as { text: string }).text;
    }
  }
}

/** The notice texts of a forwarded request (the §9 oracle reads them as
 *  tool output too: rewrite-request.ts forwardedToolResultText). */
export function noticeTexts(messages: readonly Message[]): string[] {
  const out: string[] = [];
  for (const msg of messages) {
    if (msg.role !== "user") continue;
    if (typeof msg.content === "string") {
      if (noticeKind(msg.content)) out.push(msg.content);
      continue;
    }
    if (!Array.isArray(msg.content)) continue;
    for (const b of msg.content) {
      const t = (b as { text?: unknown }).text;
      if (b.type === "text" && typeof t === "string" && noticeKind(t)) out.push(t);
    }
  }
  return out;
}

/** Every notice kind. */
export const ALL_NOTICE_KINDS: ReadonlySet<NoticeKind> = new Set<NoticeKind>(["shell", "subagent", "usershell", "bashmode"]);

/** The stand-in ids are never real tool_use ids. */
export function isVirtualNoticeId(id: string): boolean {
  return id.startsWith("mandu-bg:");
}
