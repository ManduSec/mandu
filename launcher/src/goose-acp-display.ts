/**
 * goose-acp-display — the editor-bound half of `mandu goose acp`'s relay
 * (goose-acp-relay.ts): the human-facing text of Goose's messages to the
 * editor, desymbolized over the arbiter's human plane, as the reply filter
 * does for every other agent's output (supported-agents.md §5.6 "Recipes,
 * review and ACP"; reply-row-reservation.md §15, the structured egress).
 *
 * THE RULE. The editor is the human view: it is supposed to see originals.
 * The model's side stays symbolic: only lines going Goose → editor pass
 * here; editor → Goose lines, the relay's own answers to Goose, and Goose's
 * own history (what the model reads on later turns) are never touched.
 *
 * JSON-AWARE. Each line (ACP's stdio framing: one JSON-RPC message per
 * line) is parsed into a span tree that keeps every string's source offsets,
 * the human-display strings of a known shape are desymbolized, and only those
 * strings' spans are replaced by `JSON.stringify` of the result: ids, method
 * names, numbers, keys, key order and every other byte of the line stay as
 * Goose wrote them, and the escaping keeps the line one line. Which strings
 * (ACP v1 as goose 1.53.0 emits it, captured 2026-10-07):
 *   session/update  agent_message_chunk, agent_thought_chunk: the content
 *                   block's text (`text`; a `resource`'s `resource.text`;
 *                   a `resource_link`'s `title` / `description`);
 *                   tool_call, tool_call_update: `title`; each content
 *                   item's block (as above) or a `diff`'s `oldText` /
 *                   `newText`; every string inside `rawInput` / `rawOutput`;
 *                   Goose's live output (`_meta.toolNotification.params
 *                   .chunks[].output`);
 *                   plan: each entry's `content`;
 *                   session_info_update: `title`.
 *   session/request_permission (Goose's request): its `toolCall`, as a
 *                   tool_call_update.
 *   the answer to session/list: each session's `title`.
 * NOT `user_message_chunk` (a session/load replays the human's own turns):
 * an editor can edit and resend a user message, and a symbol there must go
 * back to Goose as the symbol it was. Paths, ids, kinds and statuses are
 * never display text.
 *
 * UTILITY-ONLY (the reply filter's posture, filter.ts): any failure (no
 * human socket, the arbiter refusing or unreachable, a deadline, a line that
 * does not parse or is too large) forwards the line UNCHANGED: a symbol in
 * the editor leaks nothing. After a deadline the relay stops asking for a
 * while (BACKOFF_MS), so a wedged arbiter does not stall the editor's stream
 * line after line.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): the span parser is adapted from
 * interceptors/reply-filter/src/structured-filter.ts `parseSpans` (Mandu-new
 * there too; copied because the launcher does not import the reply-filter
 * package), with larger bounds for a tool's output; `unescapeSymbols` is
 * arbiter/symbol-table/symbol-format.ts's (the Markdown escapes a model puts
 * in a token it repeats), as the reply filter lifts it.
 */
import { ndjsonCall } from "./secret-setup.js";

/** Deep text desymbolization ($MDU:* → original), the arbiter's human-plane
 *  `desymbolize` op. */
export type Desymbolize = (text: string) => Promise<string>;

type Node =
  | { kind: "string"; value: string; start: number; end: number }
  | { kind: "object"; fields: Map<string, Node> }
  | { kind: "array"; items: Node[] }
  | { kind: "scalar" };
type StringNode = Extract<Node, { kind: "string" }>;

const MAX_DEPTH = 64;
const MAX_NODES = 200_000;
/** A line longer than this is forwarded as it is (a huge tool output). */
export const MAX_LINE_BYTES = 8 * 1024 * 1024;
/** Display strings resolved per line, at most. */
const MAX_TARGETS = 512;
/** The whole line's resolution deadline. */
export const LINE_DEADLINE_MS = 2_000;
/** After a missed deadline, lines pass unresolved for this long. */
export const BACKOFF_MS = 10_000;

const SYMBOL_MARK = "$MDU:";

/** A span tree of `source`, or throws. Every string node keeps the offsets
 *  of its quoted source. */
function parseSpans(source: string): Node {
  let pos = 0;
  let nodes = 0;
  const ws = (): void => {
    for (;;) {
      const c = source.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
      else return;
    }
  };
  const string = (): StringNode => {
    const start = pos++;
    while (pos < source.length) {
      const c = source.charCodeAt(pos++);
      if (c === 0x5c) { pos++; continue; }
      if (c === 0x22) {
        const value: unknown = JSON.parse(source.slice(start, pos));
        if (typeof value !== "string") throw new Error("string");
        return { kind: "string", value, start, end: pos };
      }
    }
    throw new Error("unterminated string");
  };
  const value = (depth: number): Node => {
    if (depth > MAX_DEPTH || ++nodes > MAX_NODES) throw new Error("bounds");
    ws();
    const c = source[pos];
    if (c === '"') return string();
    if (c === "{" || c === "[") {
      const object = c === "{";
      pos++;
      const close = object ? "}" : "]";
      const fields = new Map<string, Node>();
      const items: Node[] = [];
      ws();
      if (source[pos] !== close) {
        for (;;) {
          ws();
          if (object) {
            if (source[pos] !== '"') throw new Error("key");
            const key = string().value;
            if (fields.has(key)) throw new Error("duplicate key");
            ws();
            if (source[pos++] !== ":") throw new Error("colon");
            fields.set(key, value(depth + 1));
          } else items.push(value(depth + 1));
          ws();
          if (source[pos] !== ",") break;
          pos++;
        }
      }
      if (source[pos++] !== close) throw new Error("close");
      return object ? { kind: "object", fields } : { kind: "array", items };
    }
    const scalar = /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y;
    scalar.lastIndex = pos;
    if (!scalar.exec(source)) throw new Error("scalar");
    pos = scalar.lastIndex;
    return { kind: "scalar" };
  };
  const root = value(0);
  ws();
  if (pos !== source.length) throw new Error("trailing");
  return root;
}

const field = (n: Node | undefined, name: string): Node | undefined => (n?.kind === "object" ? n.fields.get(name) : undefined);
const str = (n: Node | undefined): StringNode | undefined => (n?.kind === "string" ? n : undefined);
const items = (n: Node | undefined): Node[] => (n?.kind === "array" ? n.items : []);
const isStr = (n: Node | undefined, v: string): boolean => n?.kind === "string" && n.value === v;

function push(out: StringNode[], n: Node | undefined): void {
  const s = str(n);
  if (s !== undefined) out.push(s);
}

/** Every string leaf under `n` (values only, never keys). */
function leaves(n: Node | undefined, out: StringNode[]): void {
  if (n === undefined) return;
  if (n.kind === "string") out.push(n);
  else if (n.kind === "array") for (const i of n.items) leaves(i, out);
  else if (n.kind === "object") for (const v of n.fields.values()) leaves(v, out);
}

/** An ACP ContentBlock's display text. */
function contentBlock(b: Node | undefined, out: StringNode[]): void {
  const type = field(b, "type");
  if (isStr(type, "text")) push(out, field(b, "text"));
  else if (isStr(type, "resource")) push(out, field(field(b, "resource"), "text"));
  else if (isStr(type, "resource_link")) { push(out, field(b, "title")); push(out, field(b, "description")); }
}

/** A ToolCall / ToolCallUpdate's display text. */
function toolCall(t: Node | undefined, out: StringNode[]): void {
  push(out, field(t, "title"));
  for (const c of items(field(t, "content"))) {
    const type = field(c, "type");
    if (isStr(type, "content")) contentBlock(field(c, "content"), out);
    else if (isStr(type, "diff")) { push(out, field(c, "oldText")); push(out, field(c, "newText")); }
  }
  leaves(field(t, "rawInput"), out);
  leaves(field(t, "rawOutput"), out);
  // Goose's live shell output (a goose extension of tool_call_update).
  const live = field(field(field(t, "_meta"), "toolNotification"), "params");
  for (const ch of items(field(live, "chunks"))) push(out, field(ch, "output"));
}

/** The human-display strings of one Goose → editor message (`answers`: the
 *  editor method a response answers, when the relay knows it). */
function displayTargets(msg: Node, answers: string | undefined): StringNode[] {
  const out: StringNode[] = [];
  const method = str(field(msg, "method"))?.value;
  const params = field(msg, "params");
  if (method === "session/update") {
    const u = field(params, "update");
    const kind = str(field(u, "sessionUpdate"))?.value;
    switch (kind) {
      case "agent_message_chunk":
      case "agent_thought_chunk":
        contentBlock(field(u, "content"), out);
        break;
      case "tool_call":
      case "tool_call_update":
        toolCall(u, out);
        break;
      case "plan":
        for (const e of items(field(u, "entries"))) push(out, field(e, "content"));
        break;
      case "session_info_update":
        push(out, field(u, "title"));
        break;
      default:
        // user_message_chunk among them: the human's own turns stay as Goose
        // holds them (an editor may resend one; see the header).
        break;
    }
  } else if (method === "session/request_permission") {
    toolCall(field(params, "toolCall"), out);
  } else if (method === undefined && answers === "session/list") {
    for (const s of items(field(field(msg, "result"), "sessions"))) push(out, field(s, "title"));
  }
  return out;
}

/** The names `display` would resolve in `line`, as strings (a test and
 *  observability helper; no resolution). Null when the line does not parse. */
export function acpDisplayStrings(line: string, answers?: string): string[] | null {
  try { return displayTargets(parseSpans(line), answers).map((n) => n.value); } catch { return null; }
}

// arbiter/symbol-table/symbol-format.ts ESCAPED_SYM_RE / unescapeSymbols.
const ESCAPED_SYM_RE = /\\?\$MDU:(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9])*\[[0-9a-f]{4,8}\](?:\.(?:\\?_|[a-zA-Z])(?:\\?_|[a-zA-Z0-9[\].])*)*/g;
function unescapeSymbols(text: string): string {
  ESCAPED_SYM_RE.lastIndex = 0;
  return text.replace(ESCAPED_SYM_RE, (m) => m.replace(/\\/g, ""));
}

export type DisplayDiagnostic = "malformed" | "too-large" | "failed" | "deadline";

export interface AcpDisplayOpts {
  /** The editor method a response answers (acpFromGoose's `answers`). */
  answers?: string;
  deadlineMs?: number;
  onDiagnostic?: (d: DisplayDiagnostic) => void;
}

/**
 * Desymbolize the human-display strings of one Goose → editor line. Returns
 * the line with only those strings' spans replaced, or the line unchanged
 * (no symbol, no resolver, a line that does not parse, any failure). Never
 * throws.
 */
export async function desymbolizeAcpLine(line: string, desymbolize: Desymbolize | null, opts: AcpDisplayOpts = {}): Promise<string> {
  // Fast path: no symbol can be in a line without the mark (Goose's JSON
  // writes `$` and `:` unescaped; a `$`-escaped token stays a symbol,
  // which leaks nothing).
  if (desymbolize === null || !line.includes(SYMBOL_MARK)) return line;
  const diag = (d: DisplayDiagnostic): void => { try { opts.onDiagnostic?.(d); } catch { /* observability only */ } };
  if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) { diag("too-large"); return line; }
  let root: Node;
  try { root = parseSpans(line); } catch { diag("malformed"); return line; }
  const targets = displayTargets(root, opts.answers).filter((n) => n.value.includes(SYMBOL_MARK));
  if (targets.length === 0) return line;
  if (targets.length > MAX_TARGETS) { diag("too-large"); return line; }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<"deadline">((r) => { timer = setTimeout(() => r("deadline"), opts.deadlineMs ?? LINE_DEADLINE_MS); });
  try {
    const resolved = await Promise.race([
      Promise.all(targets.map(async (n) => {
        const text = unescapeSymbols(n.value);
        const r = await desymbolize(text);
        if (typeof r !== "string") throw new Error("not a string");
        return r === text ? null : r;
      })),
      deadline,
    ]);
    if (resolved === "deadline") { diag("deadline"); return line; }
    const patches = targets
      .map((n, i) => ({ n, text: resolved[i] }))
      .filter((p): p is { n: StringNode; text: string } => typeof p.text === "string")
      .sort((a, b) => b.n.start - a.n.start);
    let out = line;
    for (const { n, text } of patches) out = out.slice(0, n.start) + JSON.stringify(text) + out.slice(n.end);
    return out;
  } catch {
    diag("failed");
    return line;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** The production resolver: the arbiter's `desymbolize` over the HUMAN-PLANE
 *  socket (arbiter-human-plane.md; the launcher read it from `hello`). Never
 *  the data socket: it refuses the op, and a relay that asked it would be
 *  the reach the human plane exists to close. */
export function humanPlaneDesymbolizer(
  humanSock: string,
  call: <T>(sock: string, op: string, args: Record<string, unknown>, timeoutMs: number) => Promise<T> = ndjsonCall,
): Desymbolize {
  return async (text) => {
    const r = await call<{ text?: unknown }>(humanSock, "desymbolize", { text }, LINE_DEADLINE_MS);
    if (typeof r?.text !== "string") throw new Error("desymbolize: no text in the answer");
    return r.text;
  };
}

/**
 * The editor-bound writer: lines go out in the order they were queued, each
 * through `desymbolizeAcpLine`. After a missed deadline the next BACKOFF_MS
 * pass unresolved. `drained()` settles when everything queued so far is
 * written.
 */
export class AcpEditorWriter {
  private tail: Promise<void> = Promise.resolve();
  private backoffUntil = 0;
  private told = false;
  constructor(
    private readonly write: (line: string) => void,
    private readonly desymbolize: Desymbolize | null,
    private readonly note: (m: string) => void = () => {},
    private readonly now: () => number = Date.now,
    private readonly deadlineMs: number = LINE_DEADLINE_MS,
  ) {}

  /** Queue one line (`answers`: the editor method it answers, if any;
   *  `resolve` false: write it as it is, e.g. the relay's own refusal). */
  push(line: string, answers?: string, resolve = true): void {
    this.tail = this.tail.then(async () => {
      const resolver = !resolve || this.now() < this.backoffUntil ? null : this.desymbolize;
      const out = await desymbolizeAcpLine(line, resolver, {
        ...(answers !== undefined ? { answers } : {}),
        deadlineMs: this.deadlineMs,
        onDiagnostic: (d) => this.diagnostic(d),
      });
      this.write(out);
    }).catch(() => { /* the write itself failed: the editor went away */ });
  }

  drained(): Promise<void> { return this.tail; }

  private diagnostic(d: DisplayDiagnostic): void {
    if (d === "deadline") this.backoffUntil = this.now() + BACKOFF_MS;
    if ((d === "deadline" || d === "failed") && !this.told) {
      this.told = true;
      this.note("mandu: goose acp: the arbiter did not resolve a symbol for the editor; it shows the `$MDU:` symbol instead (nothing leaks; the model's side is unchanged)");
    }
  }
}
