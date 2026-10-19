/**
 * reply-media-stream — the `MEDIA:` reply gate (reply-media.ts) on the
 * wire: the model→agent response of an OpenClaw session, streamed (the
 * Messages SSE, Chat Completions and Responses streams) or buffered.
 *
 * Mandu-new (no reference origin). STREAMING, without breaking it more
 * than the gate needs:
 *   - Text is relayed as it comes, except the start of a line that may
 *     still become a directive (`mediaLineState` "maybe": blanks, `M`,
 *     `ME`, …): that event is held, as the token repacker holds a dangling
 *     `$MDU:` (sse-text-repack.ts), and released with the next one once the
 *     line is decided, so a `MEDIA:` split across deltas is never half out.
 *   - The first possible directive (a colon ColonScan flags, the colon of a
 *     canonical line included) switches to HOLDING: that event and every
 *     later one are queued until the response ends. The gate then judges
 *     the whole text (what was relayed plus what was held, so a directive
 *     reads the same as OpenClaw reads it) with gateReplyTexts, and relays
 *     the queue in order: each text run's held part as ONE delta (its first
 *     held event), the other held deltas of that run emptied, and every
 *     event that carries a complete text (Responses' `.done` events and
 *     `response.completed`, a text `content_block_start`) rewritten the
 *     same way. Directives sit at the end of a reply, so most replies are
 *     not held at all and the rest only from their last lines.
 *   - Tool calls in the response (any event that starts one) are counted
 *     for the window rule; they pass through untouched.
 * An event with more than one text run (a Chat chunk with several
 * choices) switches to holding at once: the gate cannot cut it.
 *
 * Bytes are never swallowed: a partial trailing frame is relayed verbatim
 * at the end. The SSE framing is the repackers' (text-repack.ts).
 */

import { SseFramer } from "./openai-sse.js";
import {
  colonScanStart,
  colonScanStep,
  gateReplyTexts,
  hasReplyMedia,
  mediaLineState,
  MEDIA_COLON_NEUTRAL,
  type ColonScan,
  type ReplyMediaOptions,
  type ReplyMediaResult,
} from "./reply-media.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** What one SSE event says, as the gate reads it. */
export interface WireRead {
  /** Text deltas, keyed by the run they continue (a block, a choice, a part). */
  texts: Array<{ key: string; text: string }>;
  /** Tool calls the event starts or carries (their names). */
  calls: string[];
  /** Runs whose text is over after this event ("*": every run). */
  closes: string[];
  /** The event carries COMPLETE texts (snapshotTexts / mapSnapshot). */
  snapshot: boolean;
}

/** One wire format (module header). */
export interface ReplyMediaWire {
  read(raw: string): WireRead;
  /** The event with its text deltas replaced by run; "" when nothing is
   *  left worth relaying. */
  withTexts(raw: string, texts: ReadonlyMap<string, string>): string;
  snapshotTexts(raw: string): string[];
  mapSnapshot(raw: string, fn: (t: string) => string): string;
}

const NONE: WireRead = { texts: [], calls: [], closes: [], snapshot: false };

function eventData(raw: string): Json | null {
  const data: string[] = [];
  for (const line of raw.split(/\r?\n/)) if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  if (data.length === 0) return null;
  try {
    const v: unknown = JSON.parse(data.join("\n"));
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

function isDone(raw: string): boolean {
  return /(^|\n)data: ?\[DONE\]\s*$/m.test(raw);
}

/** The event re-serialized with a new data payload, its other lines kept. */
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

// ── Anthropic Messages ──────────────────────────────────────────────────────

export const ANTHROPIC_WIRE: ReplyMediaWire = {
  read(raw) {
    const d = eventData(raw);
    if (!d) return NONE;
    const t = d["type"];
    const index = typeof d["index"] === "number" ? String(d["index"]) : "?";
    if (t === "content_block_delta") {
      const delta = d["delta"];
      if (isObj(delta) && delta["type"] === "text_delta" && typeof delta["text"] === "string") {
        return { ...NONE, texts: [{ key: index, text: delta["text"] }] };
      }
      return NONE;
    }
    if (t === "content_block_start") {
      const b = d["content_block"];
      if (isObj(b) && b["type"] === "tool_use") return { ...NONE, calls: [typeof b["name"] === "string" ? b["name"] : "a tool"] };
      // a text block that opens with text (the API opens with ""): the
      // start of its run, read like a delta
      if (isObj(b) && b["type"] === "text" && typeof b["text"] === "string" && b["text"] !== "") return { ...NONE, texts: [{ key: index, text: b["text"] }] };
      return NONE;
    }
    if (t === "content_block_stop") return { ...NONE, closes: [index] };
    if (t === "message_stop") return { ...NONE, closes: ["*"] };
    return NONE;
  },
  withTexts(raw, texts) {
    const d = eventData(raw);
    if (!d) return raw;
    const key = typeof d["index"] === "number" ? String(d["index"]) : "?";
    const text = texts.get(key);
    if (text === undefined) return raw;
    if (d["type"] === "content_block_start" && isObj(d["content_block"])) {
      // the block must open even when its text moved to a later event
      return serialize(raw, { ...d, content_block: { ...d["content_block"], text } });
    }
    if (d["type"] !== "content_block_delta" || !isObj(d["delta"])) return raw;
    if (text === "") return "";
    return serialize(raw, { ...d, delta: { ...d["delta"], text } });
  },
  snapshotTexts: () => [],
  mapSnapshot: (raw) => raw,
};

// ── Chat Completions ────────────────────────────────────────────────────────

function chatKey(ch: Json, i: number): string {
  return `choice:${typeof ch["index"] === "number" ? ch["index"] : i}`;
}

export const CHAT_WIRE: ReplyMediaWire = {
  read(raw) {
    if (isDone(raw)) return { ...NONE, closes: ["*"] };
    const d = eventData(raw);
    const choices = d?.["choices"];
    if (!Array.isArray(choices)) return NONE;
    const r: WireRead = { texts: [], calls: [], closes: [], snapshot: false };
    choices.forEach((ch, i) => {
      if (!isObj(ch)) return;
      const key = chatKey(ch, i);
      const delta = ch["delta"];
      if (isObj(delta)) {
        if (typeof delta["content"] === "string" && delta["content"] !== "") r.texts.push({ key, text: delta["content"] });
        const tc = delta["tool_calls"];
        if (Array.isArray(tc) && tc.length > 0) {
          for (const c of tc) {
            const fn = isObj(c) && isObj(c["function"]) ? c["function"] : undefined;
            r.calls.push(fn && typeof fn["name"] === "string" ? fn["name"] : "a tool");
          }
        }
        if (isObj(delta["function_call"])) r.calls.push("a tool");
      }
      if (isObj(ch["message"])) r.snapshot = true;
      if (ch["finish_reason"] !== null && ch["finish_reason"] !== undefined) r.closes.push(key);
    });
    return r;
  },
  withTexts(raw, texts) {
    const d = eventData(raw);
    const choices = d?.["choices"];
    if (!d || !Array.isArray(choices)) return raw;
    let changed = false;
    const next = choices.map((ch, i) => {
      if (!isObj(ch) || !isObj(ch["delta"])) return ch;
      const t = texts.get(chatKey(ch, i));
      if (t === undefined || typeof ch["delta"]["content"] !== "string") return ch;
      changed = true;
      return { ...ch, delta: { ...ch["delta"], content: t } };
    });
    return changed ? serialize(raw, { ...d, choices: next }) : raw;
  },
  snapshotTexts(raw) {
    const choices = eventData(raw)?.["choices"];
    if (!Array.isArray(choices)) return [];
    return choices.flatMap((ch) => (isObj(ch) && isObj(ch["message"]) && typeof ch["message"]["content"] === "string" ? [ch["message"]["content"]] : []));
  },
  mapSnapshot(raw, fn) {
    const d = eventData(raw);
    const choices = d?.["choices"];
    if (!d || !Array.isArray(choices)) return raw;
    return serialize(raw, {
      ...d,
      choices: choices.map((ch) => (isObj(ch) && isObj(ch["message"]) && typeof ch["message"]["content"] === "string"
        ? { ...ch, message: { ...ch["message"], content: fn(ch["message"]["content"]) } }
        : ch)),
    });
  },
};

// ── Responses API ───────────────────────────────────────────────────────────

function responsesKey(d: Json): string {
  return `item:${String(d["item_id"] ?? "")}\u0000${String(d["output_index"] ?? "")}\u0000${String(d["content_index"] ?? "")}`;
}

/** A Responses output item a routed agent would run (function_call,
 *  custom_tool_call, local_shell_call, …): every `*_call` type counts. */
function itemCall(item: unknown): string | null {
  if (!isObj(item) || typeof item["type"] !== "string" || !item["type"].endsWith("_call")) return null;
  return typeof item["name"] === "string" ? item["name"] : item["type"];
}

/** Every text an output item (or a content part) carries, mapped. */
function mapPartTexts(part: unknown, fn: (t: string) => string): unknown {
  return isObj(part) && typeof part["text"] === "string" ? { ...part, text: fn(part["text"]) } : part;
}
function mapItemTexts(item: unknown, fn: (t: string) => string): unknown {
  if (!isObj(item) || !Array.isArray(item["content"])) return item;
  return { ...item, content: item["content"].map((p) => mapPartTexts(p, fn)) };
}
function partTexts(part: unknown): string[] {
  return isObj(part) && typeof part["text"] === "string" ? [part["text"]] : [];
}
function itemTexts(item: unknown): string[] {
  return isObj(item) && Array.isArray(item["content"]) ? item["content"].flatMap(partTexts) : [];
}

const RESPONSE_FINAL = new Set(["response.completed", "response.incomplete", "response.failed", "response.done"]);

export const RESPONSES_WIRE: ReplyMediaWire = {
  read(raw) {
    const d = eventData(raw);
    if (!d) return NONE;
    const t = d["type"];
    if (t === "response.output_text.delta" && typeof d["delta"] === "string") return { ...NONE, texts: [{ key: responsesKey(d), text: d["delta"] }] };
    if (t === "response.output_text.done") return { ...NONE, snapshot: true, closes: [responsesKey(d)] };
    if (t === "response.content_part.added" || t === "response.content_part.done") return { ...NONE, snapshot: true };
    if (t === "response.output_item.added" || t === "response.output_item.done") {
      const call = itemCall(d["item"]);
      return { ...NONE, snapshot: true, calls: call ? [call] : [] };
    }
    if (typeof t === "string" && RESPONSE_FINAL.has(t)) {
      const out = isObj(d["response"]) && Array.isArray(d["response"]["output"]) ? d["response"]["output"] : [];
      return { ...NONE, snapshot: true, closes: ["*"], calls: out.map(itemCall).filter((c): c is string => c !== null) };
    }
    return NONE;
  },
  withTexts(raw, texts) {
    const d = eventData(raw);
    if (!d || d["type"] !== "response.output_text.delta") return raw;
    const t = texts.get(responsesKey(d));
    return t === undefined ? raw : serialize(raw, { ...d, delta: t });
  },
  snapshotTexts(raw) {
    const d = eventData(raw);
    if (!d) return [];
    const t = d["type"];
    if (t === "response.output_text.done") return typeof d["text"] === "string" ? [d["text"]] : [];
    if (t === "response.content_part.added" || t === "response.content_part.done") return partTexts(d["part"]);
    if (t === "response.output_item.added" || t === "response.output_item.done") return itemTexts(d["item"]);
    if (typeof t === "string" && RESPONSE_FINAL.has(t) && isObj(d["response"]) && Array.isArray(d["response"]["output"])) {
      return d["response"]["output"].flatMap(itemTexts);
    }
    return [];
  },
  mapSnapshot(raw, fn) {
    const d = eventData(raw);
    if (!d) return raw;
    const t = d["type"];
    if (t === "response.output_text.done" && typeof d["text"] === "string") return serialize(raw, { ...d, text: fn(d["text"]) });
    if (t === "response.content_part.added" || t === "response.content_part.done") return serialize(raw, { ...d, part: mapPartTexts(d["part"], fn) });
    if (t === "response.output_item.added" || t === "response.output_item.done") return serialize(raw, { ...d, item: mapItemTexts(d["item"], fn) });
    if (typeof t === "string" && RESPONSE_FINAL.has(t) && isObj(d["response"]) && Array.isArray(d["response"]["output"])) {
      return serialize(raw, { ...d, response: { ...d["response"], output: d["response"]["output"].map((it) => mapItemTexts(it, fn)) } });
    }
    return raw;
  },
};

// ── the stream filter ───────────────────────────────────────────────────────

export interface ReplyMediaStreamOptions extends ReplyMediaOptions {
  /** Called once per response the gate changed or held anything in. */
  onResult?: (r: ReplyMediaResult) => void;
}

interface Queued { raw: string; read: WireRead; override?: Map<string, string> }
interface Carry { key: string; raw: string; read: WireRead; full: string; cut: number }

export class ReplyMediaFilter {
  private readonly framer = new SseFramer();
  private out: string[] = [];
  private holding = false;
  private readonly queue: Queued[] = [];
  private carry: Carry | null = null;
  /** The text of each run relayed so far, in first-seen order. */
  private readonly released = new Map<string, string>();
  /** Runs whose relayed text ends inside a line already decided not to be
   *  a directive. */
  private readonly mid = new Set<string>();
  private scan: ColonScan = colonScanStart();
  private readonly calls: string[] = [];

  constructor(private readonly wire: ReplyMediaWire, private readonly opts: ReplyMediaStreamOptions) {}

  /** Feed a raw SSE chunk; the bytes to relay now. Never throws. */
  feed(chunk: string): string {
    for (const raw of this.framer.push(chunk)) this.handle(raw);
    return this.drain();
  }

  /** At stream end: judge and relay what was held, then any partial frame
   *  verbatim. Never throws. */
  async end(): Promise<string> {
    if (this.holding) await this.finish();
    else this.releaseCarry();
    const rest = this.framer.rest();
    if (rest !== "") this.out.push(rest);
    return this.drain();
  }

  private drain(): string {
    if (this.out.length === 0) return "";
    const s = this.out.join("");
    this.out = [];
    return s;
  }

  private note(key: string, text: string): void {
    this.released.set(key, (this.released.get(key) ?? "") + text);
  }

  private emitText(raw: string, key: string, text: string, own: boolean): void {
    const s = own ? raw : this.wire.withTexts(raw, new Map([[key, text]]));
    if (s !== "") this.out.push(s);
    this.note(key, text);
  }

  /** Relay the held event whole (its run is over or another run began). */
  private releaseCarry(): void {
    const c = this.carry;
    if (!c) return;
    this.carry = null;
    const own = c.cut === 0 && c.full === c.read.texts[0]!.text;
    this.emitText(c.raw, c.key, c.full, own);
    this.mid.delete(c.key);
  }

  private startHolding(raw: string, read: WireRead): void {
    this.holding = true;
    if (this.carry) {
      const c = this.carry;
      this.carry = null;
      this.queue.push({ raw: c.raw, read: c.read, override: new Map([[c.key, c.full]]) });
    }
    this.queue.push({ raw, read });
  }

  private handle(raw: string): void {
    const read = this.wire.read(raw);
    this.calls.push(...read.calls);
    for (const t of read.texts) if (!this.released.has(t.key)) this.released.set(t.key, "");
    if (this.holding) {
      this.queue.push({ raw, read });
      return;
    }
    if (read.texts.length > 1 || (read.snapshot && this.wire.snapshotTexts(raw).some(hasReplyMedia))) {
      this.startHolding(raw, read);
      return;
    }
    if (read.texts.length === 0) {
      this.releaseCarry();
      if (read.snapshot || read.closes.length > 0) {
        // a run is over: the next text of any run starts a line (OpenClaw
        // joins blocks with "\n")
        for (const k of read.closes) if (k === "*") this.mid.clear(); else this.mid.delete(k);
        if (read.closes.length > 0) this.scan = colonScanStep(this.scan, "\n").next;
      }
      this.out.push(raw);
      return;
    }
    const { key, text } = read.texts[0]!;
    // 1. a possible directive anywhere in the new text: hold from here on
    let s = this.scan;
    let directive = false;
    for (const ch of text) {
      const r = colonScanStep(s, ch);
      s = r.next;
      if (r.directive) directive = true;
    }
    this.scan = s;
    if (directive) {
      this.startHolding(raw, read);
      return;
    }
    // 2. else relay all but a line start that may still become a directive
    let carried = "";
    if (this.carry) {
      if (this.carry.key === key) {
        const c = this.carry;
        this.carry = null;
        carried = c.full.slice(c.cut);
        // an emptied event still goes out where it says more than its text
        // (a block start, a Chat chunk's role); the wire drops it otherwise
        this.emitText(c.raw, c.key, c.full.slice(0, c.cut), false);
      } else {
        this.releaseCarry();
      }
    }
    const full = carried + text;
    const nl = full.lastIndexOf("\n");
    const tail = full.slice(nl + 1);
    const tailMid = nl < 0 && carried === "" && this.mid.has(key);
    const state = tailMid ? "no" : mediaLineState(tail);
    if (state !== "no" && tail !== "") {
      this.carry = { key, raw, read, full, cut: nl + 1 };
      this.mid.delete(key);
    } else {
      this.emitText(raw, key, full, carried === "");
      if (tail === "") this.mid.delete(key);
      else this.mid.add(key);
    }
    // 3. the same event may end its run (a Chat chunk with a finish_reason)
    if (read.closes.length > 0) {
      if (this.carry && (read.closes.includes("*") || read.closes.includes(this.carry.key))) this.releaseCarry();
      for (const k of read.closes) if (k === "*") this.mid.clear(); else this.mid.delete(k);
      this.scan = colonScanStep(this.scan, "\n").next;
    }
  }

  /** Judge the whole response and relay the queue (module header). */
  private async finish(): Promise<void> {
    const keys = [...this.released.keys()];
    const held = new Map<string, string>(keys.map((k) => [k, ""]));
    for (const q of this.queue) {
      for (const t of q.read.texts) held.set(t.key, (held.get(t.key) ?? "") + (q.override?.get(t.key) ?? t.text));
    }
    const fulls = keys.map((k) => (this.released.get(k) ?? "") + (held.get(k) ?? ""));
    const withCall = this.calls[0];
    let result: ReplyMediaResult;
    try {
      result = await gateReplyTexts(fulls, withCall, this.opts);
    } catch (err) {
      // gateReplyTexts never throws; if it ever did, nothing held may pass
      this.opts.log?.(`reply-media: gate failed (${(err as Error).message}); every colon of the held text is neutralized`);
      result = { texts: fulls.map((f, i) => (this.released.get(keys[i]!) ?? "") + (held.get(keys[i]!) ?? "").replace(/:/g, MEDIA_COLON_NEUTRAL)), changed: true, withheld: [], neutralized: 0 };
    }
    const newHeld = new Map<string, string>();
    keys.forEach((k, i) => {
      const before = this.released.get(k) ?? "";
      const after = result.texts[i] ?? fulls[i]!;
      newHeld.set(k, after.startsWith(before)
        ? after.slice(before.length)
        // an edit reached text already relayed (it cannot: the gate holds
        // from the first possible directive); hold the rest strictly
        : (held.get(k) ?? "").replace(/:/g, MEDIA_COLON_NEUTRAL));
    });
    // a complete text an event carries: the run it equals, else gated alone
    const byFull = new Map<string, string>();
    fulls.forEach((f, i) => byFull.set(f, result.texts[i] ?? f));
    for (const q of this.queue) {
      if (!q.read.snapshot) continue;
      for (const t of this.wire.snapshotTexts(q.raw)) {
        if (byFull.has(t)) continue;
        const r = await gateReplyTexts([t], withCall, this.opts);
        byFull.set(t, r.texts[0] ?? t);
        result.withheld.push(...r.withheld);
        result.neutralized += r.neutralized;
        if (r.changed) result.changed = true;
      }
    }
    if (result.changed || result.withheld.length > 0) this.opts.onResult?.(result);
    const sent = new Set<string>();
    for (const q of this.queue) {
      let s = q.raw;
      if (q.read.texts.length > 0) {
        const m = new Map<string, string>();
        for (const t of q.read.texts) {
          m.set(t.key, sent.has(t.key) ? "" : newHeld.get(t.key) ?? "");
          sent.add(t.key);
        }
        s = this.wire.withTexts(q.raw, m);
      }
      if (q.read.snapshot && s !== "") s = this.wire.mapSnapshot(s, (t) => byFull.get(t) ?? t);
      if (s !== "") this.out.push(s);
    }
    this.queue.length = 0;
  }
}

// ── buffered answers ────────────────────────────────────────────────────────

/** A Messages answer: its text blocks, in order. Changes `obj` in place;
 *  true when it changed. */
export async function gateMessagesJsonReply(obj: Json, opts: ReplyMediaStreamOptions): Promise<boolean> {
  const content = obj["content"];
  if (!Array.isArray(content)) return false;
  const blocks = content.filter((b): b is Json => isObj(b) && b["type"] === "text" && typeof b["text"] === "string");
  if (blocks.length === 0) return false;
  const call = content.find((b) => isObj(b) && b["type"] === "tool_use") as Json | undefined;
  const r = await gateReplyTexts(blocks.map((b) => b["text"] as string), call ? String(call["name"] ?? "a tool") : undefined, opts);
  if (r.changed || r.withheld.length > 0) opts.onResult?.(r);
  if (!r.changed) return false;
  blocks.forEach((b, i) => { b["text"] = r.texts[i]; });
  return true;
}

/** A Chat Completions answer: each choice's message content. */
export async function gateChatJsonReply(obj: Json, opts: ReplyMediaStreamOptions): Promise<boolean> {
  const choices = obj["choices"];
  if (!Array.isArray(choices)) return false;
  let changed = false;
  for (const ch of choices) {
    if (!isObj(ch) || !isObj(ch["message"])) continue;
    const msg = ch["message"];
    const tc = msg["tool_calls"];
    const call = Array.isArray(tc) && tc.length > 0 ? "a tool" : isObj(msg["function_call"]) ? "a tool" : undefined;
    const content = msg["content"];
    if (typeof content === "string") {
      const r = await gateReplyTexts([content], call, opts);
      if (r.changed || r.withheld.length > 0) opts.onResult?.(r);
      if (r.changed) { msg["content"] = r.texts[0]; changed = true; }
    } else if (Array.isArray(content)) {
      const parts = content.filter((p): p is Json => isObj(p) && typeof p["text"] === "string");
      if (parts.length === 0) continue;
      const r = await gateReplyTexts(parts.map((p) => p["text"] as string), call, opts);
      if (r.changed || r.withheld.length > 0) opts.onResult?.(r);
      if (r.changed) { parts.forEach((p, i) => { p["text"] = r.texts[i]; }); changed = true; }
    }
  }
  return changed;
}

/** A Responses answer: the text parts of its message items. */
export async function gateResponsesJsonReply(obj: Json, opts: ReplyMediaStreamOptions): Promise<boolean> {
  const output = obj["output"];
  if (!Array.isArray(output)) return false;
  const parts = output.flatMap((it) => (isObj(it) && Array.isArray(it["content"])
    ? it["content"].filter((p): p is Json => isObj(p) && typeof p["text"] === "string")
    : []));
  if (parts.length === 0) return false;
  const call = output.map(itemCall).find((c) => c !== null) ?? undefined;
  const r = await gateReplyTexts(parts.map((p) => p["text"] as string), call, opts);
  if (r.changed || r.withheld.length > 0) opts.onResult?.(r);
  if (!r.changed) return false;
  parts.forEach((p, i) => { p["text"] = r.texts[i]; });
  return true;
}
