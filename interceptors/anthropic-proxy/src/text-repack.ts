/**
 * text-repack — a `$MDU:` symbol token is never split across two streamed
 * text deltas on an OpenAI-family model→agent wire (Chat Completions
 * `choices[0].delta.content`, Responses `response.output_text.delta`), and
 * the token grammar (`danglingTokenStart`) every repacker cuts by.
 *
 * ONE MODULE, TWO COPIES. Both model proxies read an OpenAI wire and ship
 * standalone (no workspace, no cross-package import), so this file is copied
 * VERBATIM to
 *   interceptors/anthropic-proxy/src/text-repack.ts  (the routed OpenClaw /
 *        OpenCode `openai` providers, agent-e2e-harness.md §9; its Messages
 *        repacker sse-text-repack.ts imports `danglingTokenStart` from here)
 *   interceptors/openai-proxy/src/text-repack.ts     (Codex, Kimi: Responses
 *        and Chat Completions)
 * and so is its unit suite (test/unit/text-repack.test.ts in each package).
 * tests/stack/text-repack-parity.test.ts fails unless both
 * pairs are byte-identical, and runs one table of split-token cases through
 * both packages' exports. Change the anthropic-proxy copy and copy it out
 * (architecture-map.md §9 ①, "The text-delta repacker").
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (2026-09-29, MRs !42,
 * !55); one module since 2026-09-30. The token grammar constants are a local
 * copy of arbiter/symbol-table/symbol-format.ts's `$MDU:` head and
 * continuation classes (as in interceptors/reply-filter/src/filter.ts).
 *
 * WHY: the model streams its reply at BPE boundaries, so `$MDU:inspect[695b]`
 * and `.result` can arrive in separate deltas. An agent TUI paints each delta
 * with other rows between them, and the reply filter downstream, which must
 * emit bytes in order, can only reassemble contiguous bytes. Here the token
 * is still pure text, so the boundary decision is exact.
 *
 * HOW (differs from the Messages repacker on purpose, which emits a held
 * suffix as a NEW text_delta): an OpenAI chunk carries an envelope (id,
 * created, model, system_fingerprint) and a Responses event a
 * `sequence_number` an SDK may track, so this never invents or drops an
 * event: it moves text FORWARD between consecutive text events of the same
 * choice / content part. A text event whose text ends in a possible
 * in-flight token is held (one-event lookahead) until the next data event:
 *   - the next is text of the same choice / part: the held event goes out
 *     with the text before the token (possibly ""), and the token's start is
 *     prepended to the next event's text (which may be held in turn);
 *   - anything else (a finish, a tool call, `[DONE]`, `.output_text.done`,
 *     another choice or part, an error, the stream's end): the held event
 *     goes out with ALL its text, unchanged in place.
 * Events without a data line (SSE comments, keepalives) pass through while
 * a hold is open; they carry nothing an agent renders.
 *
 * CONTENT-PRESERVING BY CONSTRUCTION: the concatenated text of each choice /
 * part is byte-identical and the event sequence is the same events in the
 * same order; only where the text is cut between them moves. An untouched
 * event relays byte-verbatim. Utility posture, like the reply filter: this is
 * not the symbolization boundary (the response text is already symbols, and
 * nothing here desymbolizes), and pure string work that never throws on a
 * malformed event: what it cannot read passes through as a non-text event. A
 * chunk with more than one choice, or text carrying `logprobs` (which index
 * the original segmentation), is never re-cut.
 *
 * Chained AFTER each proxy's tool-call rewriter, so it sees the gated,
 * re-framed stream. No imports: it must compile alone in either package.
 */

// ── the token grammar ────────────────────────────────────────────────────────

/** Literal head of every token (canonical spelling, escapes stripped). */
const TOKEN_HEAD = "$MDU:";
/** Chars that may legally continue a token after its head: tag / hash /
 *  field path (ESCAPED_SYM_RE in arbiter/symbol-table/symbol-format.ts). */
const TOKEN_CONTINUATION_RE = /^[a-zA-Z0-9_[\].]*$/;
/** Longest suffix ever held as a possible in-flight token: far above a real
 *  token's length (head 5 + tag ≤24 + [hash] ≤10 + field path, escaped
 *  spellings included). */
export const REPACK_HOLD_CAP = 256;

/**
 * Index in `text` where a dangling possible-in-flight token suffix starts, or
 * `text.length` when the text ends in nothing token-shaped. A COMPLETE token
 * is still a valid prefix of a longer one (the field grammar is open-ended:
 * `…[695b]` may grow `.result`, `.result` may grow `s`), so it dangles too:
 * the hold always ends at the run's next non-continuation char or its end.
 * Only the LAST `$` can start a still-growing token (tokens never contain
 * `$`); Markdown escapes (`\$MDU:…`, `\_`) are looked through, and a lone
 * trailing `\` dangles: it may be the escape of a `$MDU:` in the next delta.
 */
export function danglingTokenStart(text: string): number {
  const at = dollarTokenStart(text);
  if (at < text.length) return at;
  // A lone trailing escape (not an escaped backslash `\\`).
  return text.endsWith("\\") && !text.endsWith("\\\\") ? text.length - 1 : text.length;
}

/** The `$`-anchored half of danglingTokenStart. */
function dollarTokenStart(text: string): number {
  const d = text.lastIndexOf("$");
  if (d < 0) return text.length;
  const start = d > 0 && text[d - 1] === "\\" ? d - 1 : d;
  const suffix = text.slice(start).replace(/\\/g, "");
  if (suffix.length > REPACK_HOLD_CAP) return text.length;
  if (suffix.length <= TOKEN_HEAD.length) {
    return TOKEN_HEAD.startsWith(suffix) ? start : text.length;
  }
  return suffix.startsWith(TOKEN_HEAD) && TOKEN_CONTINUATION_RE.test(suffix.slice(TOKEN_HEAD.length))
    ? start
    : text.length;
}

// ── SSE framing ──────────────────────────────────────────────────────────────

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** Split a buffer into complete SSE events (terminator kept, LF or CRLF). */
class SseFramer {
  private buf = "";
  push(chunk: string): string[] {
    this.buf += chunk;
    const out: string[] = [];
    for (;;) {
      const lf = this.buf.indexOf("\n\n");
      const crlf = this.buf.indexOf("\r\n\r\n");
      const sep = lf < 0 ? crlf : crlf < 0 ? lf : Math.min(lf, crlf);
      if (sep < 0) break;
      const end = this.buf.startsWith("\r\n\r\n", sep) ? sep + 4 : sep + 2;
      out.push(this.buf.slice(0, end));
      this.buf = this.buf.slice(end);
    }
    return out;
  }
  rest(): string {
    const r = this.buf;
    this.buf = "";
    return r;
  }
}

/** The joined `data:` payload of one SSE event, or null when it has none. */
function eventData(raw: string): string | null {
  const data: string[] = [];
  for (const line of raw.split(/\r?\n/)) if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  return data.length > 0 ? data.join("\n") : null;
}

/** The event re-serialized with a new data payload, its other lines (the
 *  `event:` name, an `id:`) kept in order. */
function serialize(raw: string, obj: Json): string {
  const lines: string[] = [];
  let wrote = false;
  for (const line of raw.split(/\r?\n/)) {
    if (line === "") continue;
    if (line.startsWith("data:")) {
      if (!wrote) lines.push(`data: ${JSON.stringify(obj)}`);
      wrote = true;
      continue;
    }
    lines.push(line);
  }
  return `${lines.join("\n")}\n\n`;
}

// ── the repacker ─────────────────────────────────────────────────────────────

/** One text event as the repacker reads it. */
interface TextEvent {
  /** Which run of text it continues: the choice, or the item + part. */
  key: string;
  text: string;
  /** No text may follow it in this run (a Chat choice's finishing chunk). */
  final: boolean;
  /** Put `text` back into the parsed event. */
  withText: (text: string) => Json;
}

/** A held text event and where its text is cut. */
interface Held {
  raw: string;
  ev: TextEvent;
  /** The event's text with the carry from before it. */
  full: string;
  cut: number;
  /** Whether `full` differs from the event's own text. */
  carried: boolean;
}

abstract class TextRepacker {
  private readonly framer = new SseFramer();
  private held: Held | null = null;
  private out: string[] = [];

  /** The text this event carries, or null when it is not a re-cuttable text event. */
  protected abstract textOf(obj: Json): TextEvent | null;

  /** Feed a raw SSE chunk; returns the bytes to relay right now. */
  feed(chunk: string): string {
    for (const raw of this.framer.push(chunk)) this.handle(raw);
    return this.drain();
  }

  /** At stream end: the held event with all its text, then any partial
   *  trailing frame verbatim. Bytes are never swallowed. */
  end(): string {
    this.release(null);
    const rest = this.framer.rest();
    if (rest !== "") this.out.push(rest);
    return this.drain();
  }

  private handle(raw: string): void {
    const data = eventData(raw);
    if (data === null) {
      this.out.push(raw); // a comment / keepalive: nothing to render, the hold stays
      return;
    }
    let obj: unknown = null;
    try { obj = JSON.parse(data); } catch { obj = null; }
    const ev = isObj(obj) ? this.textOf(obj) : null;
    const carry = this.release(ev);
    if (ev === null) {
      this.out.push(raw);
      return;
    }
    const full = carry + ev.text;
    const cut = ev.final ? full.length : danglingTokenStart(full);
    if (cut < full.length) {
      this.held = { raw, ev, full, cut, carried: carry !== "" };
      return;
    }
    this.out.push(carry === "" ? raw : serialize(raw, ev.withText(full)));
  }

  /** Release the held event before `next`: cut when `next` continues its run
   *  (the token's start is returned as the carry), whole otherwise. */
  private release(next: TextEvent | null): string {
    const h = this.held;
    if (h === null) return "";
    this.held = null;
    if (next !== null && next.key === h.ev.key) {
      this.out.push(serialize(h.raw, h.ev.withText(h.full.slice(0, h.cut))));
      return h.full.slice(h.cut);
    }
    this.out.push(h.carried ? serialize(h.raw, h.ev.withText(h.full)) : h.raw);
    return "";
  }

  private drain(): string {
    if (this.out.length === 0) return "";
    const s = this.out.join("");
    this.out = [];
    return s;
  }
}

/** Chat Completions: `choices[0].delta.content` of single-choice chunks. */
export class ChatTextRepacker extends TextRepacker {
  protected textOf(obj: Json): TextEvent | null {
    const choices = obj["choices"];
    if (!Array.isArray(choices) || choices.length !== 1) return null;
    const ch = choices[0];
    if (!isObj(ch)) return null;
    const delta = ch["delta"];
    if (!isObj(delta) || typeof delta["content"] !== "string") return null;
    if (delta["tool_calls"] != null || delta["function_call"] != null) return null;
    if (ch["logprobs"] != null) return null;
    return {
      key: `choice:${typeof ch["index"] === "number" ? ch["index"] : 0}`,
      text: delta["content"] as string,
      final: ch["finish_reason"] !== null && ch["finish_reason"] !== undefined,
      withText: (text) => ({ ...obj, choices: [{ ...ch, delta: { ...delta, content: text } }] }),
    };
  }
}

/** Responses API: `response.output_text.delta`, per output item + content part. */
export class ResponsesTextRepacker extends TextRepacker {
  protected textOf(obj: Json): TextEvent | null {
    if (obj["type"] !== "response.output_text.delta" || typeof obj["delta"] !== "string") return null;
    const lp = obj["logprobs"];
    if (Array.isArray(lp) ? lp.length > 0 : lp != null) return null;
    return {
      key: `item:${String(obj["item_id"] ?? "")}\u0000${String(obj["output_index"] ?? "")}\u0000${String(obj["content_index"] ?? "")}`,
      text: obj["delta"] as string,
      final: false,
      withText: (text) => ({ ...obj, delta: text }),
    };
  }
}
