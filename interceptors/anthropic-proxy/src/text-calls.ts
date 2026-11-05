/**
 * text-calls — a tool call the model WRITES in its reply text, which an
 * agent runs although no gate saw it (model-wires.md, "Tool calls written as
 * text").
 *
 * Mandu-new (no reference origin). The grammar was read from OpenClaw's
 * plain-text tool-call compat layer (`createPlainTextToolCallCompatWrapper`,
 * packages/tool-call-repair's scanners, 2026.7.1 to 2026.10.7), which wraps
 * the streams of its Ollama provider (2026.7.1 and later), its LM Studio
 * provider (2026.9.9 and later) and its xAI provider, and is exported to
 * third-party provider plugins through the plugin SDK. It RUNS, as a real
 * tool call, a reply line that opens with one of:
 *   - `[name]` (then a line break, a JSON payload and `[/name]` or
 *     `[END_TOOL_REQUEST]`), or `[tool:name] {…}`;
 *   - `<function=name>…</function>` (any case);
 *   - the Harmony header `<|channel|>commentary to=name code<|message|>{…}`,
 *     or without the channel marker, `commentary|analysis|final to=name …`;
 * each at the start of a line (after its indentation), outside Markdown
 * code, `name` one of the request's tools. The model-API proxy ends a reply
 * whose text opens such a call (`textCallStart`) before the line that
 * completes it is relayed, so the agent never holds a whole one.
 *
 * Stricter than OpenClaw on purpose: the opening is enough (no payload
 * needed), Markdown code is not skipped, and with no tool list any `[name]`
 * counts. Ending a reply that only looked like a call is the fail-closed
 * direction; a reply line that starts with `[read]` (a declared tool's name
 * in brackets) or `<function=` in prose is the accepted false positive.
 *
 * Pure (no I/O).
 */

/** Why a reply with a tool call written in its text is ended. */
export const LINE_TEXT_CALL_WHY =
  "the model wrote a tool call in its reply text, which this agent would run without Mandu's gates";

const XML_FUNCTION_RE = /^[^\S\r\n]*<function=/i;
const TOOL_BRACKET_RE = /^[^\S\r\n]*\[tool:/;
const NAMED_BRACKET_RE = /^[^\S\r\n]*\[([A-Za-z0-9_-]+)\]/;
const HARMONY_RE = /^[^\S\r\n]*(?:<\|channel\|>|(?:commentary|analysis|final)[ \t]+to=)/;

/** A tool-name spelling OpenClaw maps onto a declared tool: `functions.`,
 *  `function_`, `tools/`, … before it (extensions/ollama
 *  normalizeOllamaToolCallName; the compat layer's matcher reads the
 *  declared name exactly, so this only widens the check). */
const NAME_PREFIX_RE = /^(?:functions?|tools?)[./_-]+/i;

/**
 * Whether `line` (one line of reply text, possibly still growing) opens a
 * tool call OpenClaw would run from text: `<function=`, `[tool:`, a Harmony
 * header, or `[name]` naming one of the request's tools (`names`; any name
 * when the request named none).
 */
export function textCallStart(line: string, names: ReadonlySet<string> | undefined): boolean {
  if (XML_FUNCTION_RE.test(line) || TOOL_BRACKET_RE.test(line) || HARMONY_RE.test(line)) return true;
  const m = NAMED_BRACKET_RE.exec(line);
  if (m === null) return false;
  if (names === undefined || names.size === 0) return true;
  const n = m[1]!;
  return names.has(n) || names.has(n.replace(NAME_PREFIX_RE, ""));
}

/**
 * The reply text of an answer, line by line as it grows, per run (a Chat
 * choice, a Responses content part): `add` is true once the text of a run
 * opens a call (textCallStart).
 */
export class TextCallScan {
  private readonly runs = new Map<string, { text: string; from: number }>();

  constructor(private readonly names: ReadonlySet<string> | undefined) {}

  add(run: string, delta: string): boolean {
    if (delta === "") return false;
    const r = this.runs.get(run) ?? { text: "", from: 0 };
    this.runs.set(run, r);
    r.text += delta;
    let at = r.from;
    for (;;) {
      const nl = r.text.slice(at).search(/[\r\n]/);
      const line = nl < 0 ? r.text.slice(at) : r.text.slice(at, at + nl);
      if (textCallStart(line, this.names)) return true;
      if (nl < 0) break;
      at += nl + 1;
      r.from = at;
    }
    return false;
  }
}

/** Whether a whole text (a buffered answer's) opens a call on any line. */
export function hasTextCall(text: string, names: ReadonlySet<string> | undefined): boolean {
  return new TextCallScan(names).add("", text);
}
